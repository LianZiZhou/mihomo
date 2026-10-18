package domainmapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testDestination = netip.MustParseAddr("203.0.113.8")
var testClient = netip.MustParseAddr("192.168.1.12")

func testConfig(endpoint string) Config {
	return Config{Enable: true, Timeout: 1000, Providers: []ProviderConfig{{Name: "mosdns", Type: "mosdns-http-v1", Endpoint: endpoint}}}
}

func hitResult(domain string) Result {
	return Result{Version: 1, Status: "hit", IP: testDestination.String(), Domain: domain, Scope: "client", Source: "A", ExpiresAt: time.Now().Add(time.Minute)}
}

func newTestRuntime(t *testing.T, cfg Config) *Runtime {
	t.Helper()
	runtime, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Retire)
	return runtime
}

func TestHTTPContractAndNoResultCache(t *testing.T) {
	var count atomic.Int32
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/plugins/index/v1/lookup" || r.URL.Query().Get("ip") != testDestination.String() || r.URL.Query().Get("client") != testClient.String() {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		result := hitResult("FIRST.Example.")
		switch count.Add(1) {
		case 2:
			result = hitResult("second.example")
		case 3, 4:
			result.Status = "miss"
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	runtime := newTestRuntime(t, testConfig(server.URL+"/plugins/index/v1/lookup"))
	for i, expected := range []string{"first.example", "second.example", "", ""} {
		result, err := runtime.Lookup(context.Background(), testClient, testDestination)
		if err != nil || result.Domain != expected || result.Provider != "mosdns" {
			t.Fatalf("lookup %d: %+v, %v", i, result, err)
		}
	}
	if count.Load() != 4 || connections.Load() != 1 {
		t.Fatalf("requests = %d, TCP connections = %d; want 4 and 1", count.Load(), connections.Load())
	}
}

func TestHTTPInvalidEvidence(t *testing.T) {
	for _, scenario := range []struct {
		name string
		edit func(*Result)
	}{
		{"version", func(r *Result) { r.Version = 2 }},
		{"wrong IP", func(r *Result) { r.IP = "203.0.113.9" }},
		{"invalid IP", func(r *Result) { r.IP = "not-an-ip" }},
		{"status", func(r *Result) { r.Status = "unknown" }},
		{"domain", func(r *Result) { r.Domain = "bad/domain" }},
		{"empty domain", func(r *Result) { r.Domain = "" }},
		{"IP as domain", func(r *Result) { r.Domain = "1.2.3.4" }},
		{"scope", func(r *Result) { r.Scope = "other" }},
		{"expired", func(r *Result) { r.ExpiresAt = time.Now().Add(-time.Second) }},
		{"missing expiry", func(r *Result) { r.ExpiresAt = time.Time{} }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				result := hitResult("example.com")
				scenario.edit(&result)
				_ = json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			runtime := newTestRuntime(t, testConfig(server.URL))
			if _, err := runtime.Lookup(context.Background(), testClient, testDestination); err == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
	for _, scenario := range []struct {
		name   string
		status int
		body   string
	}{
		{"HTTP error", http.StatusServiceUnavailable, "unavailable"},
		{"malformed JSON", http.StatusOK, "{"},
		{"multiple JSON objects", http.StatusOK, "{}{}"},
		{"oversized", http.StatusOK, strings.Repeat(" ", (1<<20)+1)},
		{"redirect", http.StatusTemporaryRedirect, ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/other")
				w.WriteHeader(scenario.status)
				_, _ = w.Write([]byte(scenario.body))
			}))
			defer server.Close()
			runtime := newTestRuntime(t, testConfig(server.URL))
			if _, err := runtime.Lookup(context.Background(), testClient, testDestination); err == nil {
				t.Fatal("accepted invalid HTTP response")
			}
		})
	}
}

func TestTimeoutAndRecovery(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		_ = json.NewEncoder(w).Encode(hitResult("recovered.example"))
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	cfg.Timeout = 30
	runtime := newTestRuntime(t, cfg)
	start := time.Now()
	if _, err := runtime.Lookup(context.Background(), testClient, testDestination); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout did not bound lookup")
	}
	result, err := runtime.Lookup(context.Background(), testClient, testDestination)
	if err != nil || result.Domain != "recovered.example" || count.Load() != 2 {
		t.Fatalf("failure cached: %+v, %v, requests=%d", result, err, count.Load())
	}
}

// Done is evaluated only after Lookup has attached to an in-flight request.
type attachedContext struct {
	context.Context
	attached chan struct{}
	once     sync.Once
}

func (ctx *attachedContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.attached) })
	return ctx.Context.Done()
}

func TestSharedLookupSurvivesCallerCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(hitResult("shared.example"))
	}))
	defer server.Close()
	runtime := newTestRuntime(t, testConfig(server.URL))
	firstCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := runtime.Lookup(firstCtx, testClient, testDestination); first <- err }()
	<-started
	secondCtx := &attachedContext{Context: context.Background(), attached: make(chan struct{})}
	second := make(chan error, 1)
	go func() {
		result, err := runtime.Lookup(secondCtx, testClient, testDestination)
		if err == nil && result.Domain != "shared.example" {
			err = fmt.Errorf("unexpected result %+v", result)
		}
		second <- err
	}()
	<-secondCtx.attached
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Errorf("first caller: %v", err)
	}
	close(release)
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatalf("shared lookup made %d requests", count.Load())
	}
}

func TestClientScopedSharingAndIPv6(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		client := r.URL.Query().Get("client")
		if client != "2001:db8::1" && client != "2001:db8::2" {
			t.Errorf("unexpected client %q", client)
		}
		if r.URL.Query().Get("ip") != "2001:db8::10" {
			t.Errorf("unexpected IPv6 target")
		}
		result := hitResult("v6.example")
		result.IP = "2001:db8::10"
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	runtime := newTestRuntime(t, testConfig(server.URL))
	var wg sync.WaitGroup
	for _, client := range []string{"2001:db8::1", "2001:db8::2"} {
		wg.Add(1)
		go func(client string) {
			defer wg.Done()
			if _, err := runtime.Lookup(context.Background(), netip.MustParseAddr(client), netip.MustParseAddr("2001:db8::10")); err != nil {
				t.Error(err)
			}
		}(client)
	}
	wg.Wait()
	if count.Load() != 2 {
		t.Fatalf("requests = %d; different clients must not share lookups", count.Load())
	}
}

func TestReloadPreservesInflightAndRejectsInvalidConfig(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	oldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(hitResult("old.example"))
	}))
	defer oldServer.Close()
	newServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(hitResult("new.example"))
	}))
	defer newServer.Close()
	var manager Manager
	defer manager.Apply(Config{})
	if err := manager.Apply(testConfig(oldServer.URL)); err != nil {
		t.Fatal(err)
	}
	old := make(chan Result, 1)
	go func() {
		result, err := manager.Current().Lookup(context.Background(), testClient, testDestination)
		if err != nil {
			t.Error(err)
		}
		old <- result
	}()
	<-started
	if err := manager.Apply(testConfig(newServer.URL)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(testConfig("invalid://endpoint")); err == nil {
		t.Fatal("accepted invalid config")
	}
	result, err := manager.Current().Lookup(context.Background(), testClient, testDestination)
	if err != nil || result.Domain != "new.example" {
		t.Fatalf("new runtime: %+v %v", result, err)
	}
	close(release)
	if result := <-old; result.Domain != "old.example" {
		t.Fatalf("old runtime aborted: %+v", result)
	}
	if err := manager.Apply(Config{}); err != nil || manager.Current() != nil {
		t.Fatalf("disable runtime: %v", err)
	}
}

func TestConfigValidationAndDefaults(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:9091/plugins/index/v1/lookup")
	cfg.Timeout = 0
	runtime := newTestRuntime(t, cfg)
	if runtime.timeout != 50*time.Millisecond {
		t.Fatalf("unexpected default timeout %s", runtime.timeout)
	}
	for _, edit := range []func(*Config){
		func(c *Config) { c.Providers = nil },
		func(c *Config) { c.Timeout = -1 },
		func(c *Config) { c.Providers[0].Name = "" },
		func(c *Config) { c.Providers[0].Type = "unknown" },
		func(c *Config) { c.Providers[0].Endpoint = "file:///tmp/index" },
		func(c *Config) { c.Providers[0].Endpoint = "http://user:password@localhost/path" },
		func(c *Config) { c.Providers = append(c.Providers, c.Providers[0]) },
	} {
		cfg := testConfig("http://127.0.0.1:9091/plugins/index/v1/lookup")
		edit(&cfg)
		if err := Validate(cfg); err == nil {
			t.Fatalf("accepted invalid config %+v", cfg)
		}
	}
}

func TestProvidersFallThroughInConfiguredOrder(t *testing.T) {
	var requestsMu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsMu.Lock()
		requests = append(requests, r.URL.Path)
		requestsMu.Unlock()
		switch r.URL.Path {
		case "/error":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/miss":
			_ = json.NewEncoder(w).Encode(Result{Version: 1, Status: "miss", IP: testDestination.String()})
		case "/hit":
			_ = json.NewEncoder(w).Encode(hitResult("fallback.example"))
		default:
			t.Errorf("unexpected later provider %s", r.URL.Path)
		}
	}))
	defer server.Close()
	cfg := Config{Enable: true, Timeout: 1000}
	for _, name := range []string{"error", "miss", "hit", "unused"} {
		cfg.Providers = append(cfg.Providers, ProviderConfig{Name: name, Type: "mosdns-http-v1", Endpoint: server.URL + "/" + name})
	}
	runtime := newTestRuntime(t, cfg)
	result, err := runtime.Lookup(context.Background(), testClient, testDestination)
	if err != nil || result.Domain != "fallback.example" || result.Provider != "hit" {
		t.Fatalf("fallback failed: %+v %v", result, err)
	}
	requestsMu.Lock()
	defer requestsMu.Unlock()
	if strings.Join(requests, ",") != "/error,/miss,/hit" {
		t.Fatalf("wrong provider order: %v", requests)
	}
}
