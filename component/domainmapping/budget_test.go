package domainmapping

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type delayedProvider struct {
	started [2]chan context.Context
	release [2]chan struct{}
	calls   atomic.Int32
}

func (p *delayedProvider) Lookup(ctx context.Context, _, _ netip.Addr) (Result, error) {
	i := int(p.calls.Add(1)) - 1
	if i >= len(p.started) {
		return Result{}, errors.New("unexpected third provider call")
	}
	p.started[i] <- ctx
	// Model CPU work that does not observe cancellation until it completes.
	<-p.release[i]
	return hitResult(fmt.Sprintf("flight-%d.example", i)), nil
}

func (*delayedProvider) CloseIdleConnections() {}

func awaitBudgetTest[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("lookup did not complete within test safety limit")
		var zero T
		return zero
	}
}

func TestBudgetBoundsUncooperativeProviderAndReplacesExpiredFlight(t *testing.T) {
	p := &delayedProvider{}
	for i := range p.started {
		p.started[i] = make(chan context.Context, 1)
		p.release[i] = make(chan struct{})
	}
	var oldOnce, newOnce sync.Once
	releaseOld := func() { oldOnce.Do(func() { close(p.release[0]) }) }
	releaseNew := func() { newOnce.Do(func() { close(p.release[1]) }) }
	defer releaseOld()
	defer releaseNew()
	runtime := &Runtime{providers: []Provider{p}, timeout: 500 * time.Millisecond, maxInflight: 2, flights: make(map[lookupKey]*flight)}
	key := lookupKey{client: testClient, destination: testDestination}
	first := make(chan error, 1)
	go func() {
		_, err := runtime.Lookup(context.Background(), testClient, testDestination)
		first <- err
	}()
	awaitBudgetTest(t, p.started[0])
	runtime.mu.Lock()
	old := runtime.flights[key]
	runtime.mu.Unlock()
	if err := awaitBudgetTest(t, first); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait accepted late provider work: %v", err)
	}
	// The expired provider is still running, but a fresh caller gets a fresh budget.
	second := make(chan error, 1)
	go func() {
		result, err := runtime.Lookup(context.Background(), testClient, testDestination)
		if err == nil && result.Domain != "flight-1.example" {
			err = fmt.Errorf("wrong new-flight result: %+v", result)
		}
		second <- err
	}()
	awaitBudgetTest(t, p.started[1])
	releaseOld()
	awaitBudgetTest(t, old.done)
	if !errors.Is(old.err, context.DeadlineExceeded) || old.result.Status == "hit" {
		t.Fatalf("expired provider's hit was accepted: %+v, %v", old.result, old.err)
	}
	// Old completion must not delete the successor: another caller must share it.
	thirdCtx := &attachedContext{Context: context.Background(), attached: make(chan struct{})}
	third := make(chan error, 1)
	go func() {
		result, err := runtime.Lookup(thirdCtx, testClient, testDestination)
		if err == nil && result.Domain != "flight-1.example" {
			err = fmt.Errorf("wrong shared result: %+v", result)
		}
		third <- err
	}()
	awaitBudgetTest(t, thirdCtx.attached)
	releaseNew()
	for _, ch := range []chan error{second, third} {
		if err := awaitBudgetTest(t, ch); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.calls.Load(); got != 2 {
		t.Fatalf("provider calls = %d, want 2", got)
	}
}

type budgetRoundTripper func(*http.Request) (*http.Response, error)

func (f budgetRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type deadlineEOFReader struct {
	*bytes.Reader
	ctx context.Context
}

func (r *deadlineEOFReader) Read(dst []byte) (int, error) {
	n, err := r.Reader.Read(dst)
	if err == io.EOF {
		<-r.ctx.Done()
	}
	return n, err
}

func TestHTTPRejectsCompleteResponseWhenBudgetExpiresAtEOF(t *testing.T) {
	body, err := json.Marshal(hitResult("late.example"))
	if err != nil {
		t.Fatal(err)
	}
	p := newHTTPProvider(testConfig("http://127.0.0.1/lookup").Providers[0], DefaultTimeout, DefaultMaxConnections)
	defer p.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	p.client.Transport = budgetRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(&deadlineEOFReader{bytes.NewReader(body), ctx})}, nil
	})
	if _, err := p.Lookup(ctx, testClient, testDestination); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("complete body arriving at deadline was accepted: %v", err)
	}
}

func TestHTTPDiagnosticCandidatesDoNotExpandRoutingResult(t *testing.T) {
	response := hitResult("selected.example")
	response.Conflict = true
	for i := 0; i < 3000; i++ {
		response.Candidates = append(response.Candidates, Candidate{
			Domain: fmt.Sprintf("%04d.%s.%s.%s.example", i, strings.Repeat("a", 60), strings.Repeat("b", 60), strings.Repeat("c", 60)),
			Source: "a", ObservedAt: time.Now(), ExpiresAt: response.ExpiresAt,
		})
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 750000 || len(body) > 1<<20 {
		t.Fatalf("expected a large but allowed response, got %d bytes", len(body))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	runtime := newTestRuntime(t, testConfig(server.URL))
	result, err := runtime.Lookup(context.Background(), testClient, testDestination)
	if err != nil || result.Domain != response.Domain || !result.Conflict || result.Provider != "mosdns" {
		t.Fatalf("lost selected evidence: %+v, %v", result, err)
	}
	if len(result.Candidates) != 0 {
		t.Fatalf("decoded %d diagnostic candidates on the routing path", len(result.Candidates))
	}
}

func TestHTTPStillRejectsMalformedDiagnosticJSON(t *testing.T) {
	result, err := json.Marshal(hitResult("selected.example"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(result[:len(result)-1]) + `,"candidates":[{"domain":"x",}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	defer server.Close()
	runtime := newTestRuntime(t, testConfig(server.URL))
	if _, err := runtime.Lookup(context.Background(), testClient, testDestination); err == nil {
		t.Fatal("ignored candidate data bypassed JSON syntax validation")
	}
}
