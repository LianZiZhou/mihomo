package tunnel

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/domainmapping"
)

// DNS freshness is separate from routing validity. The provider must still
// reject an expired routing lease, even when it describes LRU retention.
func TestMappingRetainedEvidenceAndExpiredLease(t *testing.T) {
	dnsExpiry := time.Now().Add(-time.Hour).UTC()
	lease := time.Now().Add(50 * time.Minute).UTC()
	var expired atomic.Bool
	enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) {
		routingExpiry := lease
		if expired.Load() {
			routingExpiry = time.Now().Add(-time.Second).UTC()
		}
		_ = json.NewEncoder(w).Encode(domainmapping.Result{
			Version: 1, Status: "hit", IP: r.URL.Query().Get("ip"),
			Domain: "retained.example", Scope: "client", Source: "a",
			ExpiresAt: routingExpiry, DNSExpiresAt: &dnsExpiry, DNSStale: true, RetentionMode: "lru",
		})
	})
	m := realMetadata()
	originalIP := m.DstIP
	if !lookupDomainMapping(context.Background(), m) || m.RuleHost() != "retained.example" {
		t.Fatalf("retained mapping rejected: %+v", m)
	}
	if m.Host != "" || m.DstIP != originalIP {
		t.Fatalf("retained mapping changed dial target: %+v", m)
	}
	d := m.DomainResolution
	if d == nil || d.DNSExpiresAt == nil || !d.DNSExpiresAt.Equal(dnsExpiry) || !d.DNSStale || d.RetentionMode != "lru" || !d.ExpiresAt.Equal(lease) {
		t.Fatalf("retention diagnostics lost: %+v", d)
	}
	// A later completed lookup must reach the provider again, not reuse the
	// successful connection's mapping or accept an expired lease via DNSStale.
	expired.Store(true)
	m = realMetadata()
	if lookupDomainMapping(context.Background(), m) || m.DomainMappingHost != "" || m.DomainResolution.LookupStatus != "error" || m.DstIP != originalIP {
		t.Fatalf("expired routing evidence accepted: %+v", m)
	}
}
