package domainmapping

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockedProvider struct {
	started chan context.Context
	release chan struct{}
	calls   atomic.Int32
}

func (p *blockedProvider) Lookup(ctx context.Context, _, destination netip.Addr) (Result, error) {
	p.calls.Add(1)
	p.started <- ctx
	<-p.release // Model an extension that does not cooperate with cancellation.
	result := hitResult("bounded.example")
	result.IP = destination.String()
	return result, nil
}

func (*blockedProvider) CloseIdleConnections() {}

func blockedRuntime(p *blockedProvider, timeout time.Duration, limit int) *Runtime {
	return &Runtime{providers: []Provider{p}, timeout: timeout, maxInflight: limit, flights: make(map[lookupKey]*flight)}
}

func TestExpiredProviderWorkStillConsumesCapacity(t *testing.T) {
	p := &blockedProvider{started: make(chan context.Context, 4), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(p.release) })
	runtime := blockedRuntime(p, 30*time.Millisecond, 2)
	key := lookupKey{client: testClient, destination: testDestination}
	var flights []*flight
	for i := 0; i < 2; i++ {
		done := make(chan error, 1)
		go func() { _, err := runtime.Lookup(context.Background(), testClient, testDestination); done <- err }()
		awaitBudgetTest(t, p.started)
		runtime.mu.Lock()
		flights = append(flights, runtime.flights[key])
		runtime.mu.Unlock()
		if err := awaitBudgetTest(t, done); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked provider did not time out: %v", err)
		}
	}
	for i := 0; i < 10; i++ {
		result, err := runtime.Lookup(context.Background(), testClient, testDestination)
		if !errors.Is(err, ErrOverloaded) || result.Status != "overloaded" {
			t.Fatalf("expired work bypassed capacity: %+v, %v", result, err)
		}
	}
	if p.calls.Load() != 2 {
		t.Fatalf("unbounded provider calls: %d", p.calls.Load())
	}
	release.Do(func() { close(p.release) })
	for _, f := range flights {
		awaitBudgetTest(t, f.done)
		if f.result.Status == "hit" || !errors.Is(f.err, context.DeadlineExceeded) {
			t.Fatalf("accepted expired evidence: %+v, %v", f.result, f.err)
		}
	}
	if result, err := runtime.Lookup(context.Background(), testClient, testDestination); err != nil || result.Domain != "bounded.example" {
		t.Fatalf("capacity did not recover: %+v, %v", result, err)
	}
}

func TestSharingAtCapacityAndRetirement(t *testing.T) {
	p := &blockedProvider{started: make(chan context.Context, 4), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(p.release) })
	runtime := blockedRuntime(p, time.Second, 1)
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { _, err := runtime.Lookup(context.Background(), testClient, testDestination); first <- err }()
	providerCtx := awaitBudgetTest(t, p.started)
	sharedCtx := &attachedContext{Context: context.Background(), attached: make(chan struct{})}
	go func() { _, err := runtime.Lookup(sharedCtx, testClient, testDestination); second <- err }()
	awaitBudgetTest(t, sharedCtx.attached)
	if _, err := runtime.Lookup(context.Background(), testClient.Next(), testDestination); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("distinct lookup bypassed capacity: %v", err)
	}
	runtime.Retire()
	if _, err := runtime.Lookup(context.Background(), testClient, testDestination); !errors.Is(err, ErrRetired) {
		t.Fatalf("retired runtime admitted a lookup: %v", err)
	}
	if providerCtx.Err() != nil {
		t.Fatal("retirement canceled admitted work")
	}
	release.Do(func() { close(p.release) })
	for _, done := range []chan error{first, second} {
		if err := awaitBudgetTest(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if p.calls.Load() != 1 {
		t.Fatalf("shared callers used %d provider calls", p.calls.Load())
	}
}

func TestHTTPConnectionLimitBoundsBurst(t *testing.T) {
	const requests = 12
	started, release := make(chan struct{}, requests), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var connections, peak atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		result := hitResult("bounded.example")
		result.IP = r.URL.Query().Get("ip")
		_ = json.NewEncoder(w).Encode(result)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			current := connections.Add(1)
			for previous := peak.Load(); current > previous && !peak.CompareAndSwap(previous, current); previous = peak.Load() {
			}
		} else if state == http.StateClosed {
			connections.Add(-1)
		}
	}
	server.Start()
	defer func() {
		once.Do(func() { close(release) })
		server.Close()
	}()
	cfg := testConfig(server.URL)
	cfg.Timeout, cfg.MaxConnections, cfg.MaxInflight = 2000, 2, requests
	runtime := newTestRuntime(t, cfg)
	done := make(chan error, requests)
	for i := 0; i < requests; i++ {
		destination := netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
		go func() { _, err := runtime.Lookup(context.Background(), testClient, destination); done <- err }()
	}
	awaitBudgetTest(t, started)
	awaitBudgetTest(t, started)
	once.Do(func() { close(release) })
	for i := 0; i < requests; i++ {
		if err := awaitBudgetTest(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak connections = %d, want 2", got)
	}
}

func TestHTTPConnectionQueueUsesOriginalBudget(t *testing.T) {
	started, release := make(chan struct{}, 2), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(hitResult("queued.example"))
	}))
	defer func() {
		once.Do(func() { close(release) })
		server.Close()
	}()
	p := newHTTPProvider(testConfig(server.URL).Providers[0], 2*time.Second, 1)
	defer p.CloseIdleConnections()
	first := make(chan error, 1)
	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFirst()
	go func() { _, err := p.Lookup(firstCtx, testClient, testDestination); first <- err }()
	awaitBudgetTest(t, started)
	queuedCtx, cancelQueued := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelQueued()
	if _, err := p.Lookup(queuedCtx, testClient.Next(), testDestination); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued lookup escaped its initial deadline: %v", err)
	}
	once.Do(func() { close(release) })
	if err := awaitBudgetTest(t, first); err != nil {
		t.Fatal(err)
	}
	// A fresh request after releasing the connection must succeed, and the
	// expired queued request must never be replayed in between.
	if _, err := p.Lookup(firstCtx, testClient, testDestination); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expired request reached server: requests=%d", got)
	}
}

func TestTransportDetachedDialRestoresLookupCancellation(t *testing.T) {
	p := newHTTPProvider(testConfig("http://127.0.0.1:1/lookup").Providers[0], time.Second, 1)
	defer p.CloseIdleConnections()
	started, finished := make(chan context.Context, 1), make(chan error, 1)
	p.transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		ctx, cancel := restoreDialContext(ctx, time.Second)
		defer cancel()
		started <- ctx
		<-ctx.Done()
		finished <- ctx.Err()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	lookup := make(chan error, 1)
	go func() { _, err := p.Lookup(ctx, testClient, testDestination); lookup <- err }()
	bound := awaitBudgetTest(t, started)
	if _, ok := bound.Deadline(); !ok {
		t.Fatal("detached dial has no deadline")
	}
	cancel()
	if err := awaitBudgetTest(t, lookup); !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup was not canceled: %v", err)
	}
	if err := awaitBudgetTest(t, finished); !errors.Is(err, context.Canceled) {
		t.Fatalf("detached dial was not canceled with lookup: %v", err)
	}
}

func TestHTTPSHandshakeHasLookupDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted, disconnected := make(chan struct{}), make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			disconnected <- err
			return
		}
		defer conn.Close()
		close(accepted)
		_, err = io.Copy(io.Discard, conn) // Read ClientHello without responding.
		disconnected <- err
	}()
	cfg := testConfig("https://" + listener.Addr().String())
	cfg.Timeout = 50
	runtime := newTestRuntime(t, cfg)
	done := make(chan error, 1)
	go func() { _, err := runtime.Lookup(context.Background(), testClient, testDestination); done <- err }()
	awaitBudgetTest(t, accepted)
	if err := awaitBudgetTest(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled TLS handshake did not time out: %v", err)
	}
	awaitBudgetTest(t, disconnected)
}

func TestHTTPSKeepsHTTP2AndCertificateVerification(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("HTTPS negotiated %s, want HTTP/2", r.Proto)
		}
		_ = json.NewEncoder(w).Encode(hitResult("h2.example"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	runtime := newTestRuntime(t, testConfig(server.URL))
	p := runtime.providers[0].(*httpProvider)
	p.transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	if result, err := runtime.Lookup(context.Background(), testClient, testDestination); err != nil || result.Domain != "h2.example" {
		t.Fatalf("HTTP/2 lookup failed: %+v, %v", result, err)
	}
	untrusted := newTestRuntime(t, testConfig(server.URL))
	if _, err := untrusted.Lookup(context.Background(), testClient, testDestination); err == nil {
		t.Fatal("custom TLS dialer bypassed certificate verification")
	}
}
