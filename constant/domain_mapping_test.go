package constant

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestDomainMappingRuleHostAndJSON(t *testing.T) {
	m := &Metadata{Host: "inbound.example", SniffHost: "payload.example", DomainMappingHost: "dns.example", DstIP: netip.MustParseAddr("203.0.113.5"), DomainResolution: &DomainResolution{Provider: "mosdns", LookupStatus: "hit", Scope: "client"}}
	if m.RuleHost() != "payload.example" || m.Clone().RuleHost() != "payload.example" {
		t.Fatal("payload evidence must correct DNS hints and survive Clone")
	}
	encoded, err := json.Marshal(m)
	if err != nil || !strings.Contains(string(encoded), `"domainMappingHost":"dns.example"`) || !strings.Contains(string(encoded), `"domainResolution":`) {
		t.Fatalf("missing connection diagnostics: %s, %v", encoded, err)
	}
	m.DomainMappingHost = ""
	if m.RuleHost() != "payload.example" {
		t.Fatal("lost existing sniff precedence")
	}
	m.SniffHost = ""
	if m.RuleHost() != "inbound.example" {
		t.Fatal("lost inbound host fallback")
	}
}
