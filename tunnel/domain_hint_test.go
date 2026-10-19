package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/domainmapping"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	ST "github.com/metacubex/mihomo/constant/sniffer"
	RC "github.com/metacubex/mihomo/rules/common"
	RW "github.com/metacubex/mihomo/rules/wrapper"
)

func nativeHintMetadata(hint string, domains ...string) *C.Metadata {
	m := realMetadata()
	m.DomainMappingHandled, m.DomainMappingNativeHint = true, true
	m.DomainMappingHost, m.DomainMappingCandidates = hint, domains
	m.DomainResolution = &C.DomainResolution{LookupStatus: "hit", CandidatesComplete: true}
	return m
}

func TestNativeHintConflictUsesOriginalRulesAndCounters(t *testing.T) {
	ai := RW.NewRuleWrapper(RC.NewDomain("gemini.google.com", "AI"))
	ordinary := RW.NewRuleWrapper(RC.NewDomain("gstatic.com", "DEFAULT"))
	final := RW.NewRuleWrapper(RC.NewMatch("DIRECT"))
	setupCandidateRules(t, []C.Rule{ai, ordinary, final}, nil)
	m := nativeHintMetadata("gemini.google.com", "gemini.google.com", "gstatic.com")
	m.DomainMappingFallback = "AI" // stale internal/config fields cannot affect v3
	ip := m.DstIP
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "DIRECT" || m.DomainMappingHost != "" || m.Host != "" || m.DstIP != ip || m.DomainResolution.Reason != "recent-conflicting-policies" {
		t.Fatalf("conflict did not follow original rules: p=%v m=%+v d=%+v err=%v", p, m, m.DomainResolution, err)
	}
	if ai.HitCount() != 0 || ordinary.HitCount() != 0 || final.HitCount() != 1 || ai.MissCount() != 1 {
		t.Fatal("speculative matching changed live counters")
	}
}

func TestNativeHintFullConnectionRulesAndSniff(t *testing.T) {
	for _, kind := range []string{"SRC-IP-CIDR", "DST-PORT", "NETWORK"} {
		t.Run(kind, func(t *testing.T) {
			payload := map[string]string{"SRC-IP-CIDR": "192.168.1.0/24", "DST-PORT": "443", "NETWORK": "TCP"}[kind]
			setupCandidateRules(t, []C.Rule{parseCandidateRule(t, kind, payload, "DEFAULT", nil), RC.NewDomain("gemini.google.com", "AI"), RC.NewMatch("DIRECT")}, nil)
			m := nativeHintMetadata("gemini.google.com", "gemini.google.com", "gstatic.com")
			p, _, err := match(m, C.RuleMatchHelper{})
			if err != nil || p.Name() != "DEFAULT" || m.DomainResolution.Decision != "dns-hint" {
				t.Fatalf("ignored current connection rules: %+v %v", m.DomainResolution, err)
			}
		})
	}
	t.Run("payload-corrects-conflict", func(t *testing.T) {
		setupCandidateRules(t, []C.Rule{RC.NewDomain("gemini.google.com", "AI"), RC.NewDomain("gstatic.com", "DEFAULT"), RC.NewMatch("DIRECT")}, nil)
		m := nativeHintMetadata("gemini.google.com", "gemini.google.com", "gstatic.com")
		m.SniffHost = "gstatic.com"
		m.DomainResolution.CandidatesComplete = false
		p, _, err := match(m, C.RuleMatchHelper{})
		if err != nil || p.Name() != "DEFAULT" || m.DomainResolution.Decision != "sniff" {
			t.Fatalf("hint defeated payload: %+v %v", m.DomainResolution, err)
		}
	})
}

func TestNativeHintRecoveryIsDiagnosticAndTruncationFallsThrough(t *testing.T) {
	setupCandidateRules(t, []C.Rule{RC.NewDomain("ordinary.example", "DEFAULT"), RC.NewMatch("DIRECT")}, nil)
	enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(domainmapping.Result{Version: 3, Status: "hit", IP: r.URL.Query().Get("ip"), Domain: "ordinary.example", Scope: "client", ObservedAt: time.Now(), RetentionMode: "lru", AllocationRecovering: true, CandidatesComplete: true})
	}, func(c *domainmapping.Config) { c.Providers[0].Type = "mosdns-http-v3" })
	m := realMetadata()
	if !lookupDomainMapping(context.Background(), m) {
		t.Fatal("recovery discarded fresh hint")
	}
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "DEFAULT" || m.DomainResolution.Decision != "dns-hint" || !m.DomainResolution.AllocationRecovering {
		t.Fatalf("recovery changed route: %+v %v", m.DomainResolution, err)
	}
	m = nativeHintMetadata("ordinary.example")
	m.DomainResolution.CandidatesComplete = false
	p, _, err = match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "DIRECT" || m.DomainResolution.Decision != "original-rules" {
		t.Fatalf("truncation picked fallback/hint: %+v %v", m.DomainResolution, err)
	}
}

func TestNativeHintMissingRuleTargetDoesNotPickCandidate(t *testing.T) {
	setupCandidateRules(t, []C.Rule{RC.NewDomain("a.example", "MISSING"), RC.NewDomain("b.example", "AI"), RC.NewMatch("DEFAULT")}, nil)
	m := nativeHintMetadata("b.example", "a.example", "b.example")
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "DEFAULT" || m.DomainResolution.Decision != "original-rules" {
		t.Fatalf("evaluation error chose AI: %+v %v", m.DomainResolution, err)
	}
}

func TestNativeHintUnavailableNeverRestoresGlobalMapping(t *testing.T) {
	for _, response := range []string{"miss", "error", "malformed", "timeout", "canceled", "retired", "replaced-after-udp-selection"} {
		t.Run(response, func(t *testing.T) {
			setupCandidateRules(t, []C.Rule{RC.NewDomain("gemini.google.com", "AI"), RC.NewMatch("DEFAULT")}, nil)
			enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) {
				if response == "error" {
					w.WriteHeader(503)
					return
				}
				version := 3
				if response == "malformed" {
					version = 2
				}
				_ = json.NewEncoder(w).Encode(domainmapping.Result{Version: version, Status: "miss", IP: r.URL.Query().Get("ip")})
			}, func(c *domainmapping.Config) { c.Providers[0].Type = "mosdns-http-v3" })
			resolver.DefaultHostMapper = mappingTestEnhancer{host: "gemini.google.com"}
			m := realMetadata()
			ctx := context.Background()
			if response == "canceled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if response == "timeout" {
				c, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				ctx = c
			}
			if response == "retired" {
				domainMapping.Current().Retire()
			}
			if response == "replaced-after-udp-selection" {
				markNativeDomainMapping(m)
				if err := UpdateDomainMapping(domainmapping.Config{}); err != nil {
					t.Fatal(err)
				}
			}
			lookupDomainMapping(ctx, m)
			if err := preHandleMetadata(m); err != nil {
				t.Fatal(err)
			}
			p, _, err := match(m, C.RuleMatchHelper{})
			if err != nil || p.Name() != "DEFAULT" || m.RuleHost() != "" || !m.DomainMappingHandled || m.DomainResolution.Decision != "original-rules" {
				t.Fatalf("v3 %s restored cross-client global hint: policy=%v host=%q diagnostic=%+v err=%v", response, p, m.RuleHost(), m.DomainResolution, err)
			}
		})
	}
}

func TestNativeUDPForceMappingSelectsWrapperWithoutLookup(t *testing.T) {
	var requests atomic.Int32
	enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(503) }, func(c *domainmapping.Config) { c.Providers[0].Type = "mosdns-http-v3" })
	d, err := sniffer.NewDispatcher(&sniffer.Config{Enable: true, ForceDnsMapping: true, Sniffers: map[ST.Type]sniffer.SnifferConfig{ST.QUIC: {}}})
	if err != nil {
		t.Fatal(err)
	}
	m := realMetadata()
	m.NetWork = C.UDP
	markNativeDomainMapping(m)
	base := newPacketSender()
	sender := d.UDPSniff(C.NewPacketAdapter(&mappingPacket{local: net.UDPAddrFromAddrPort(m.SourceAddrPort())}, m), base)
	defer sender.Close()
	if sender == base || requests.Load() != 0 || !m.DomainMappingNativeHint || m.DomainMappingHandled {
		t.Fatal("UDP receive path omitted wrapper or started lookup")
	}
	// Explicit targets and fake-IP identity remain on the native path.
	for _, explicit := range []bool{true, false} {
		x := realMetadata()
		if explicit {
			x.Host = "explicit.example"
		} else {
			resolver.DefaultHostMapper = mappingTestEnhancer{host: "fake.example"}
			x.DstIP = netip.MustParseAddr("198.18.0.9")
		}
		markNativeDomainMapping(x)
		if x.DomainMappingNativeHint || lookupDomainMapping(context.Background(), x) {
			t.Fatal("native identity opted into external mapping")
		}
		if !explicit {
			if err := preHandleMetadata(x); err != nil || x.Host != "fake.example" || x.DNSMode != C.DNSFakeIP {
				t.Fatal("external mode changed fake-IP handling")
			}
		}
	}
}

func TestNativeHintUnknownRetainsNativeEmptyHostPredicates(t *testing.T) {
	r := parseCandidateRule(t, "NOT", "((DOMAIN,ordinary.example))", "AI", nil)
	setupCandidateRules(t, []C.Rule{r, RC.NewMatch("DEFAULT")}, nil)
	m := nativeHintMetadata("ordinary.example")
	m.DomainResolution.CandidatesComplete = false
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "AI" || m.RuleHost() != "" || m.DomainResolution.Decision != "original-rules" {
		t.Fatalf("changed native empty-host rule semantics: %v %v", p, err)
	}
}

func TestNativeHintOverloadCannotRestoreGlobalMapping(t *testing.T) {
	setupCandidateRules(t, []C.Rule{RC.NewDomain("gemini.google.com", "AI"), RC.NewMatch("DEFAULT")}, nil)
	started, release := make(chan struct{}), make(chan struct{})
	enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(domainmapping.Result{Version: 3, Status: "miss", IP: r.URL.Query().Get("ip")})
	}, func(c *domainmapping.Config) { c.Providers[0].Type = "mosdns-http-v3"; c.MaxInflight = 1 })
	defer close(release)
	resolver.DefaultHostMapper = mappingTestEnhancer{host: "gemini.google.com"}
	finished := make(chan struct{})
	go func() { defer close(finished); lookupDomainMapping(context.Background(), realMetadata()) }()
	t.Cleanup(func() { <-finished })
	<-started
	m := realMetadata()
	m.SrcIP = m.SrcIP.Next()
	lookupDomainMapping(context.Background(), m)
	if err := preHandleMetadata(m); err != nil {
		t.Fatal(err)
	}
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "DEFAULT" || m.RuleHost() != "" || m.DomainResolution.LookupStatus != "overloaded" {
		t.Fatalf("overload restored global hint: %v %+v %v", p, m.DomainResolution, err)
	}
}
