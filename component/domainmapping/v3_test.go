package domainmapping

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestV3RecoveryDoesNotExpireLatestDNSHint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("view") {
			t.Error("v3 used legacy route view")
		}
		_ = json.NewEncoder(w).Encode(Result{Version: 3, Status: "hit", IP: testDestination.String(), Scope: "client", Domain: "Ordinary.Example.", ObservedAt: time.Now().Add(-30 * 24 * time.Hour), RetentionMode: "lru", CandidatesComplete: true, AllocationRecovering: true})
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	cfg.Providers[0].Type = "mosdns-http-v3"
	runtime := newTestRuntime(t, cfg)
	r, err := runtime.Lookup(context.Background(), testClient, testDestination)
	if err != nil || r.Domain != "ordinary.example" || !r.AllocationRecovering || !r.CandidatesComplete || r.Complete {
		t.Fatalf("recovery or old TTL invalidated native LRU hint: %+v %v", r, err)
	}
}

func TestV3RejectsCrossClientAndMalformedEvidence(t *testing.T) {
	base := func() Result {
		return Result{Status: "hit", Scope: "client", Domain: "a.example", ObservedAt: time.Now(), RetentionMode: "lru", CandidatesComplete: true, Domains: []string{"a.example", "b.example"}}
	}
	for _, tc := range []struct {
		name string
		edit func(*Result)
	}{
		{"global-fallback", func(r *Result) { r.Scope = "global" }},
		{"missing-observation", func(r *Result) { r.ObservedAt = time.Time{} }},
		{"duplicate", func(r *Result) { r.Domains[1] = "A.EXAMPLE." }},
		{"literal", func(r *Result) { r.Domain = "1.1.1.1" }},
		{"ambiguous-v2", func(r *Result) { r.Status = "ambiguous" }},
		{"miss-with-evidence", func(r *Result) { r.Status = "miss" }},
		{"overflow", func(r *Result) { r.Domains = make([]string, 33) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.edit(&r)
			if validateV3(&r, testClient) == nil {
				t.Fatalf("accepted invalid v3: %+v", r)
			}
		})
	}
}

func TestV3CannotReenableLegacyFallback(t *testing.T) {
	base := testConfig("http://127.0.0.1/v3/lookup")
	base.Providers[0].Type = "mosdns-http-v3"
	if err := Validate(base); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Config){
		func(c *Config) { c.ConflictFallback = "AI" },
		func(c *Config) { c.ConflictPolicy = "proxy-preferred" },
		func(c *Config) {
			c.Providers = append(c.Providers, ProviderConfig{Name: "legacy", Type: "mosdns-http-v2", Endpoint: "http://127.0.0.1/v2/lookup"})
		},
	} {
		c := base
		edit(&c)
		if Validate(c) == nil {
			t.Fatal("accepted v3 with legacy fallback semantics")
		}
	}
}
