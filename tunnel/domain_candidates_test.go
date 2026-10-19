package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/domainmapping"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	RW "github.com/metacubex/mihomo/rules/wrapper"
)

type candidateTestProxy struct {
	C.Proxy
	name string
	kind C.AdapterType
	udp  bool
}

func (p *candidateTestProxy) Name() string                     { return p.name }
func (p *candidateTestProxy) Type() C.AdapterType              { return p.kind }
func (p *candidateTestProxy) SupportUDP() bool                 { return p.udp }
func (p *candidateTestProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

type candidateRematchProxy struct {
	*candidateTestProxy
	target string
}

func (p *candidateRematchProxy) ApplyMetadata(m *C.Metadata) { m.SpecialRules = p.target }

func setupCandidateRules(t *testing.T, list []C.Rule, sub map[string][]C.Rule) {
	t.Helper()
	configMux.Lock()
	oldRules, oldSub, oldProxies, oldProviders := rules, subRules, proxies, ruleProviders
	rules, subRules = list, sub
	ruleProviders = map[string]P.RuleProvider{}
	proxies = map[string]C.Proxy{
		"DIRECT":  &candidateTestProxy{name: "DIRECT", kind: C.Direct, udp: true},
		"REJECT":  &candidateTestProxy{name: "REJECT", kind: C.Reject, udp: true},
		"AI":      &candidateTestProxy{name: "AI", kind: C.Vmess, udp: true},
		"DEFAULT": &candidateTestProxy{name: "DEFAULT", kind: C.Vmess, udp: true},
		"TCPONLY": &candidateTestProxy{name: "TCPONLY", kind: C.Vmess},
		"PASS":    &candidateTestProxy{name: "PASS", kind: C.Pass, udp: true},
	}
	configMux.Unlock()
	t.Cleanup(func() {
		configMux.Lock()
		rules, subRules, proxies, ruleProviders = oldRules, oldSub, oldProxies, oldProviders
		configMux.Unlock()
	})
}

func ambiguousMetadata(domains ...string) *C.Metadata {
	m := realMetadata()
	m.DomainMappingHandled = true
	m.DomainMappingCandidates = domains
	m.DomainMappingPolicy = "proxy-preferred"
	m.DomainMappingFallback = "AI"
	m.DomainResolution = &C.DomainResolution{LookupStatus: "ambiguous", Conflict: true, Complete: true, CandidateCount: len(domains)}
	return m
}

func parseCandidateRule(t *testing.T, kind, payload, target string, sub map[string][]C.Rule) C.Rule {
	t.Helper()
	r, err := R.ParseRule(kind, payload, target, nil, sub)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCandidateRoutingIndependentOfDNSOrder(t *testing.T) {
	ai := RW.NewRuleWrapper(RC.NewDomain("gemini.google.com", "AI"))
	static := RW.NewRuleWrapper(RC.NewDomain("gemini.gstatic.com", "DEFAULT"))
	setupCandidateRules(t, []C.Rule{ai, static, RC.NewMatch("DIRECT")}, nil)
	for _, domains := range [][]string{{"gemini.google.com", "gemini.gstatic.com"}, {"gemini.gstatic.com", "gemini.google.com"}} {
		m := ambiguousMetadata(domains...)
		ip := m.DstIP
		p, _, err := match(m, C.RuleMatchHelper{})
		if err != nil || p.Name() != "AI" || m.DomainResolution.Decision != "fallback" || m.DomainResolution.PolicyDomain != "gemini.google.com" || m.DomainMappingHost != "" || m.Host != "" || m.DstIP != ip {
			t.Fatalf("wrong shared decision: %+v %v", m, err)
		}
	}
	if ai.HitCount() != 2 || ai.MissCount() != 0 || static.HitCount() != 0 {
		t.Fatalf("speculative counters leaked: ai=%d/%d static=%d", ai.HitCount(), ai.MissCount(), static.HitCount())
	}
}

func TestCandidateConsensusAndProxyPreference(t *testing.T) {
	for _, policy := range []string{"proxy-preferred", "rule-priority"} {
		t.Run(policy, func(t *testing.T) {
			setupCandidateRules(t, []C.Rule{RC.NewDomain("a.example", "DIRECT"), RC.NewDomain("b.example", "AI"), RC.NewMatch("DEFAULT")}, nil)
			m := ambiguousMetadata("a.example", "b.example")
			m.DomainMappingPolicy = policy
			p, _, err := match(m, C.RuleMatchHelper{})
			want := "AI"
			if policy == "rule-priority" {
				want = "DIRECT"
			}
			if err != nil || p.Name() != want {
				t.Fatalf("policy=%s p=%v err=%v", policy, p, err)
			}
			m = ambiguousMetadata("unknown-a.example", "unknown-b.example")
			p, _, err = match(m, C.RuleMatchHelper{})
			if err != nil || p.Name() != "DEFAULT" || m.DomainResolution.Decision != "consensus" {
				t.Fatalf("unmatched changed default: %+v %v", m, err)
			}
		})
	}
}

func TestCandidateLogicDoesNotCombineDifferentHosts(t *testing.T) {
	for _, tc := range []struct{ kind, payload, want string }{
		{"AND", "((DOMAIN,a.example),(DOMAIN,b.example))", "DIRECT"},
		{"AND", "((DOMAIN,a.example),(NOT,((DOMAIN,b.example))))", "AI"},
	} {
		t.Run(tc.payload, func(t *testing.T) {
			setupCandidateRules(t, []C.Rule{parseCandidateRule(t, tc.kind, tc.payload, "AI", nil), RC.NewMatch("DIRECT")}, nil)
			m := ambiguousMetadata("a.example", "b.example")
			p, _, err := match(m, C.RuleMatchHelper{})
			if err != nil || p.Name() != tc.want {
				t.Fatalf("got %v %v, want %s", p, err, tc.want)
			}
		})
	}
}

func TestCandidateSubrulePathPrecedesCandidateOrder(t *testing.T) {
	sub := map[string][]C.Rule{"nested": {RC.NewDomain("z.example", "DEFAULT"), RC.NewDomain("a.example", "AI")}}
	outer := parseCandidateRule(t, "SUB-RULE", "(DOMAIN-SUFFIX,example)", "nested", sub)
	setupCandidateRules(t, []C.Rule{outer, RC.NewMatch("DIRECT")}, sub)
	m := ambiguousMetadata("a.example", "z.example")
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "DEFAULT" {
		t.Fatalf("subrule order lost: %v %v", p, err)
	}
}

func TestCandidatePreservesIPRulesAndUDPSkip(t *testing.T) {
	ip := parseCandidateRule(t, "IP-CIDR", "203.0.113.0/24", "DIRECT", nil)
	setupCandidateRules(t, []C.Rule{ip, RC.NewDomain("a.example", "AI"), RC.NewMatch("DEFAULT")}, nil)
	m := ambiguousMetadata("a.example", "b.example")
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "DIRECT" {
		t.Fatalf("overrode earlier IP rule: %v %v", p, err)
	}
	configMux.Lock()
	rules = []C.Rule{RC.NewDomain("a.example", "TCPONLY"), RC.NewDomain("b.example", "PASS"), RC.NewMatch("DEFAULT")}
	configMux.Unlock()
	m = ambiguousMetadata("a.example", "b.example")
	m.NetWork = C.UDP
	p, _, err = match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "DEFAULT" {
		t.Fatalf("UDP/pass semantics changed: %v %v", p, err)
	}
}

func TestCandidateIncompleteUsesExplicitFallback(t *testing.T) {
	setupCandidateRules(t, []C.Rule{RC.NewDomain("unknown.example", "DEFAULT"), RC.NewMatch("DIRECT")}, nil)
	m := ambiguousMetadata("a.example")
	m.DomainResolution.Complete = false
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "AI" || m.DomainResolution.Reason != "incomplete-candidates" {
		t.Fatalf("incomplete claimed certainty: %+v %v", m, err)
	}
}

func TestCandidateIncompletePreservesIndependentRules(t *testing.T) {
	for _, tc := range []struct{ kind, payload string }{
		{"IP-CIDR", "203.0.113.0/24"},
		{"OR", "((DOMAIN,hidden.example),(IP-CIDR,203.0.113.0/24))"},
		{"NOT", "((AND,((DOMAIN,hidden.example),(IP-CIDR,198.51.100.0/24))))"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			setupCandidateRules(t, []C.Rule{parseCandidateRule(t, tc.kind, tc.payload, "REJECT", nil), RC.NewMatch("DEFAULT")}, nil)
			m := ambiguousMetadata("a.example")
			m.DomainResolution.Complete = false
			p, _, err := match(m, C.RuleMatchHelper{})
			if err != nil || p.Name() != "REJECT" || m.DomainResolution.Reason != "domain-independent" {
				t.Fatalf("restriction bypassed: %v %v %+v", p, err, m.DomainResolution)
			}
		})
	}
}

func TestCandidateRematchCompletesBeforeComparison(t *testing.T) {
	sub := map[string][]C.Rule{"ai-sub": {RC.NewDomain("a.example", "AI"), RC.NewMatch("DEFAULT")}}
	setupCandidateRules(t, []C.Rule{RC.NewDomain("a.example", "REROUTE"), RC.NewDomain("b.example", "DEFAULT"), RC.NewMatch("DIRECT")}, sub)
	name := "ai-sub"
	proxies["REROUTE"] = &candidateRematchProxy{candidateTestProxy: &candidateTestProxy{name: "REROUTE", kind: C.Rematch, udp: true}, target: name}
	m := ambiguousMetadata("b.example", "a.example")
	p, _, err := match(m, C.RuleMatchHelper{})
	if err != nil || p.Name() != "AI" || m.SpecialRules != name || m.DomainResolution.Reason != "conflicting-policies" || m.DomainMappingHost != "" {
		t.Fatalf("unfinished rematch: %v %v %+v", p, err, m)
	}
}

func TestV2AmbiguityAllowsSniffWithoutInventingHost(t *testing.T) {
	enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(domainmapping.Result{Version: 2, Status: "ambiguous", IP: r.URL.Query().Get("ip"), Scope: "client", ExpiresAt: time.Now().Add(time.Minute), Domains: []string{"a.example", "b.example"}, Complete: true, Total: 2})
	}, func(cfg *domainmapping.Config) { cfg.Providers[0].Type = "mosdns-http-v2" })
	m := realMetadata()
	if !lookupDomainMapping(context.Background(), m) || m.DomainMappingHost != "" || !m.DomainMappingHandled {
		t.Fatalf("ambiguous was not handled: %+v", m)
	}
	m = realMetadata()
	m.NetWork = C.UDP
	sender := &mappingSniffSender{}
	if err := prepareUDPDomain(m, sender); err != nil || !sender.sniffed || sender.skipped || m.Host != "" || m.RuleHost() != "payload.example" {
		t.Fatalf("ambiguous UDP did not accept reliable payload: %+v %+v %v", m, sender, err)
	}
}

func TestCandidateProcessLookupRunsOnce(t *testing.T) {
	processRule := parseCandidateRule(t, "PROCESS-NAME", "browser", "DEFAULT", nil)
	setupCandidateRules(t, []C.Rule{processRule, RC.NewMatch("DIRECT")}, nil)
	m := ambiguousMetadata("a.example", "b.example", "c.example")
	calls := 0
	p, _, err := match(m, C.RuleMatchHelper{FindProcess: func() { calls++; m.Process = "browser" }})
	if err != nil || p.Name() != "DEFAULT" || calls != 1 {
		t.Fatalf("process lookup multiplied: %v calls=%d err=%v", p, calls, err)
	}
}

func BenchmarkSharedCandidateRouting(b *testing.B) {
	configMux.Lock()
	oldRules, oldProxies, oldSub, oldProviders := rules, proxies, subRules, ruleProviders
	rules = nil
	for i := 0; i < 600; i++ {
		rules = append(rules, RC.NewDomainSuffix(fmt.Sprintf("domain%d.example", i), "DEFAULT"))
	}
	rules = append(rules, RC.NewDomain("gemini.google.com", "AI"), RC.NewMatch("DEFAULT"))
	proxies = map[string]C.Proxy{"AI": &candidateTestProxy{name: "AI", kind: C.Vmess, udp: true}, "DEFAULT": &candidateTestProxy{name: "DEFAULT", kind: C.Vmess, udp: true}, "DIRECT": &candidateTestProxy{name: "DIRECT", kind: C.Direct, udp: true}}
	subRules = nil
	ruleProviders = nil
	configMux.Unlock()
	b.Cleanup(func() {
		configMux.Lock()
		rules, proxies, subRules, ruleProviders = oldRules, oldProxies, oldSub, oldProviders
		configMux.Unlock()
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := ambiguousMetadata("gemini.google.com", "gemini.gstatic.com")
		p, _, err := match(m, C.RuleMatchHelper{})
		if err != nil || p.Name() != "AI" {
			b.Fatal(err)
		}
	}
}
