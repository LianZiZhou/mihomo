package domainmapping

import (
	"context"
	"testing"
	"time"
)

func TestSharedFlightRetentionTimestampsAreOwnedByCaller(t *testing.T) {
	dnsExpiry := time.Now().Add(-time.Minute)
	result := hitResult("retained.example")
	result.DNSExpiresAt = &dnsExpiry
	result.DNSStale, result.RetentionMode = true, "lru"
	result.Candidates = []Candidate{{Domain: result.Domain, DNSExpiresAt: &dnsExpiry}}
	// Hold a completed flight in the map to exercise the same result handoff
	// used by multiple waiters without depending on goroutine scheduling.
	f := &flight{done: make(chan struct{}), deadline: time.Now().Add(time.Second), result: result}
	close(f.done)
	r := &Runtime{timeout: time.Second, maxInflight: 1, flights: map[lookupKey]*flight{{client: testClient, destination: testDestination}: f}}
	first, err := r.Lookup(context.Background(), testClient, testDestination)
	if err != nil {
		t.Fatal(err)
	}
	*first.DNSExpiresAt = first.DNSExpiresAt.Add(24 * time.Hour)
	*first.Candidates[0].DNSExpiresAt = first.Candidates[0].DNSExpiresAt.Add(48 * time.Hour)
	second, err := r.Lookup(context.Background(), testClient, testDestination)
	if err != nil || second.DNSExpiresAt == nil || !second.DNSExpiresAt.Equal(dnsExpiry) || !second.Candidates[0].DNSExpiresAt.Equal(dnsExpiry) {
		t.Fatalf("one caller altered another caller's shared evidence: %+v, %v", second, err)
	}
	if second.DNSExpiresAt == second.Candidates[0].DNSExpiresAt || second.DNSExpiresAt == result.DNSExpiresAt {
		t.Fatal("retention timestamps still share mutable storage")
	}
}
