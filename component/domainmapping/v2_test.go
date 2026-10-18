package domainmapping

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestV2AmbiguityIsTerminalAndOwnedByCaller(t *testing.T) {
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if r.URL.Query().Has("view") {
			t.Error("v2 requested legacy route view")
		}
		_ = json.NewEncoder(w).Encode(Result{Version: 2, Status: "ambiguous", IP: testDestination.String(), Scope: "client", ExpiresAt: time.Now().Add(time.Minute), Domains: []string{"A.Example.", "b.example"}, Complete: true, Total: 2, Generation: 5})
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	cfg.Providers[0].Type = "mosdns-http-v2"
	runtime := newTestRuntime(t, cfg)
	result, err := runtime.Lookup(context.Background(), testClient, testDestination)
	if err != nil || result.Status != "ambiguous" || result.Domain != "" || !result.Conflict || result.Domains[0] != "a.example" {
		t.Fatalf("invalid v2 result: %+v %v", result, err)
	}
	result.Domains[0] = "changed.example"
	next, err := runtime.Lookup(context.Background(), testClient, testDestination)
	if err != nil || next.Domains[0] != "a.example" || count != 2 {
		t.Fatalf("v2 cached or shared mutable result: %+v %v", next, err)
	}
}

func TestV2ValidationRejectsFalseCertainty(t *testing.T) {
	base := func() Result {
		return Result{Version: 2, Status: "ambiguous", IP: testDestination.String(), Scope: "client", ExpiresAt: time.Now().Add(time.Minute), Domains: []string{"a.example", "b.example"}, Complete: true, Total: 2}
	}
	for _, tc := range []struct {
		name string
		edit func(*Result)
	}{
		{"selected-domain", func(r *Result) { r.Domain = "a.example" }},
		{"truncated-complete", func(r *Result) { r.Total = 3 }},
		{"duplicate", func(r *Result) { r.Domains[1] = "A.EXAMPLE." }},
		{"literal-IP", func(r *Result) { r.Domains[0] = "1.1.1.1" }},
		{"negative-total", func(r *Result) { r.Total = -1 }},
		{"false-unique", func(r *Result) { r.Status = "hit"; r.Domain = "a.example" }},
		{"expired", func(r *Result) { r.ExpiresAt = time.Now().Add(-time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.edit(&r)
			if validateV2(&r, testClient) == nil {
				t.Fatalf("accepted invalid evidence: %+v", r)
			}
		})
	}
	r := base()
	r.Complete = false
	r.Total = 33
	if err := validateV2(&r, testClient); err != nil {
		t.Fatal(err)
	}
	r = base()
	r.Complete = false
	r.Total = 0
	r.Domains = nil
	r.Reason = "unknown-history"
	if err := validateV2(&r, testClient); err != nil {
		t.Fatal(err)
	}
}
