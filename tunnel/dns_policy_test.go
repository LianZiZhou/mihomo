package tunnel

import (
	"context"
	"fmt"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/rules/wrapper"
)

type dnsPolicyTestProxy struct {
	C.Proxy
	kind C.AdapterType
}

func (p dnsPolicyTestProxy) Type() C.AdapterType { return p.kind }
func (p dnsPolicyTestProxy) SupportUDP() bool    { return true }

type dnsPolicyTestGroup struct {
	dnsPolicyTestProxy
	members []C.Proxy
}

func (p *dnsPolicyTestGroup) Adapter() C.ProxyAdapter   { return p }
func (p *dnsPolicyTestGroup) GetProxies(bool) []C.Proxy { return p.members }
func (p *dnsPolicyTestGroup) EmptyFallback() C.Proxy    { return nil }

func TestDNSPolicyGroupIsNeverFixedDirectAndPassContinues(t *testing.T) {
	dnsPolicyInstall(t, []C.Rule{
		dnsPolicyRule(t, "DOMAIN", "direct.example", "DIRECT", nil),
		dnsPolicyRule(t, "MATCH", "", "DEFAULT", nil),
		dnsPolicyRule(t, "DOMAIN", "later.example", "PROXY", nil),
		dnsPolicyRule(t, "MATCH", "", "DIRECT", nil),
	}, nil, nil)
	configMux.Lock()
	proxies["DEFAULT"] = &dnsPolicyTestGroup{dnsPolicyTestProxy: dnsPolicyTestProxy{kind: C.Selector}, members: []C.Proxy{proxies["DIRECT"]}}
	configMux.Unlock()
	first := dnsPolicyBatch(t, "direct.example", "later.example")
	if first.Results[0].ShareEligible || first.Results[1].Class != "unmatched" {
		t.Fatal(first)
	}
	configMux.Lock()
	proxies["DEFAULT"] = &dnsPolicyTestGroup{dnsPolicyTestProxy: dnsPolicyTestProxy{kind: C.Selector}, members: []C.Proxy{proxies["DIRECT"], proxies["PASS"]}}
	configMux.Unlock()
	second := dnsPolicyBatch(t, "later.example")
	if second.Results[0].Class == "unmatched" || second.Results[0].ShareEligible || first.Epoch == second.Epoch {
		t.Fatal(second)
	}
}

func dnsPolicyRule(t *testing.T, kind, payload, adapter string, subs map[string][]C.Rule) C.Rule {
	t.Helper()
	rule, err := R.ParseRule(kind, payload, adapter, nil, subs)
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func dnsPolicyInstall(t *testing.T, current []C.Rule, subs map[string][]C.Rule, currentProviders map[string]P.RuleProvider) {
	t.Helper()
	configMux.Lock()
	oldRules, oldSubs, oldProviders, oldProxies, oldMode := rules, subRules, ruleProviders, proxies, mode
	oldStatus, oldProxyProviders := Status(), providers
	OnRunning()
	rules, subRules, ruleProviders, mode = current, subs, currentProviders, Rule
	proxies = map[string]C.Proxy{
		"DIRECT":  dnsPolicyTestProxy{kind: C.Direct},
		"PROXY":   dnsPolicyTestProxy{kind: C.Vmess},
		"DEFAULT": dnsPolicyTestProxy{kind: C.Vmess},
		"REJECT":  dnsPolicyTestProxy{kind: C.Reject},
		"PASS":    dnsPolicyTestProxy{kind: C.Pass},
	}
	configMux.Unlock()
	t.Cleanup(func() {
		configMux.Lock()
		rules, subRules, ruleProviders, proxies, mode = oldRules, oldSubs, oldProviders, oldProxies, oldMode
		status.Store(oldStatus)
		providers = oldProxyProviders
		configMux.Unlock()
	})
}

func TestDNSPolicyProxyRenameWindowRemainsUnknown(t *testing.T) {
	dnsPolicyInstall(t, []C.Rule{
		dnsPolicyRule(t, "DOMAIN", "gemini.google.com", "PROXY", nil),
		dnsPolicyRule(t, "MATCH", "", "DIRECT", nil),
	}, nil, nil)
	newProxies := map[string]C.Proxy{
		"DIRECT":   dnsPolicyTestProxy{kind: C.Direct},
		"NEWPROXY": dnsPolicyTestProxy{kind: C.Vmess},
	}
	UpdateProxies(newProxies, nil)
	got := dnsPolicyBatch(t, "gemini.google.com", "other.example").Results
	if got[0].Class != "unknown" || got[0].ShareEligible || got[1].Class != "unmatched" {
		t.Fatalf("missing adapter manufactured a negative classification: %+v", got)
	}
	UpdateRules([]C.Rule{
		dnsPolicyRule(t, "DOMAIN", "gemini.google.com", "NEWPROXY", nil),
		dnsPolicyRule(t, "MATCH", "", "DIRECT", nil),
	}, nil, nil)
	if got := dnsPolicyBatch(t, "gemini.google.com").Results[0]; got.Class != "isolated" || got.ShareEligible {
		t.Fatal(got)
	}
}

func TestDNSPolicyConfigurationReloadRejectsLeases(t *testing.T) {
	dnsPolicyInstall(t, []C.Rule{dnsPolicyRule(t, "MATCH", "", "DIRECT", nil)}, nil, nil)
	request := DNSPolicyRequest{Version: 1, Queries: []DNSPolicyQuery{{Domain: "gemini.google.com", Client: "192.168.6.180"}}}
	for _, transition := range []func(){OnSuspend, OnInnerLoading} {
		transition()
		if _, err := ClassifyDNSPolicy(context.Background(), request); err == nil {
			t.Fatalf("issued sharing lease while status=%v", Status())
		}
	}
	OnRunning()
	if got := dnsPolicyBatch(t, "gemini.google.com").Results[0]; got.Class != "unmatched" || !got.ShareEligible {
		t.Fatal(got)
	}
}

func dnsPolicyBatch(t *testing.T, domains ...string) DNSPolicyResponse {
	t.Helper()
	request := DNSPolicyRequest{Version: 1}
	for _, domain := range domains {
		request.Queries = append(request.Queries, DNSPolicyQuery{Domain: domain, Client: "192.168.6.180"})
	}
	response, err := ClassifyDNSPolicy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestDNSPolicySharingMatrix(t *testing.T) {
	for _, fallback := range []string{"DEFAULT", "DIRECT"} {
		t.Run(fallback, func(t *testing.T) {
			dnsPolicyInstall(t, []C.Rule{
				dnsPolicyRule(t, "DOMAIN", "gemini.google.com", "PROXY", nil),
				dnsPolicyRule(t, "DOMAIN", "direct.example", "DIRECT", nil),
				dnsPolicyRule(t, "MATCH", "", fallback, nil),
			}, nil, nil)
			response := dnsPolicyBatch(t, "gemini.google.com", "direct.example", "unmatched.example")
			want := []DNSPolicyResult{{Class: "isolated"}, {Class: "direct", ShareEligible: fallback == "DIRECT"}, {Class: "unmatched", ShareEligible: true}}
			for i, got := range response.Results {
				if got.Class != want[i].Class || got.ShareEligible != want[i].ShareEligible {
					t.Fatalf("%s: %+v want %+v", got.Domain, got, want[i])
				}
			}
			if response.Epoch == "" || response.ValidForMS != DNSPolicyValidForMS {
				t.Fatalf("missing policy lease: %+v", response)
			}
		})
	}
}

func TestDNSPolicyUnknownApplicationFieldsAndLogic(t *testing.T) {
	tests := []struct {
		kind, payload, domain, class string
		share                        bool
	}{
		{"AND", "((DOMAIN,ai.example),(NETWORK,UDP))", "ai.example", "unknown", false},
		{"AND", "((DOMAIN,ai.example),(NETWORK,UDP))", "other.example", "unmatched", true},
		{"AND", "((DOMAIN,ai.example),(NOT,((DOMAIN,static.example))))", "ai.example", "isolated", false},
		{"AND", "((DOMAIN,ai.example),(NOT,((DOMAIN,static.example))))", "static.example", "unmatched", true},
		{"NOT", "((DOMAIN,ai.example))", "ai.example", "unmatched", true},
		{"NOT", "((DOMAIN,ai.example))", "static.example", "isolated", false},
		{"DOMAIN-REGEX", `^ai\.[a-z]+$`, "ai.example", "isolated", false},
		{"DOMAIN-REGEX", `^ai\.[a-z]+$`, "static.example", "unmatched", true},
	}
	for _, test := range tests {
		t.Run(test.kind+test.domain, func(t *testing.T) {
			dnsPolicyInstall(t, []C.Rule{dnsPolicyRule(t, test.kind, test.payload, "PROXY", nil), dnsPolicyRule(t, "MATCH", "", "DIRECT", nil)}, nil, nil)
			got := dnsPolicyBatch(t, test.domain).Results[0]
			if got.Class != test.class || got.ShareEligible != test.share {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestDNSPolicyGenericUnknownDoesNotBecomeDirect(t *testing.T) {
	dnsPolicyInstall(t, []C.Rule{
		dnsPolicyRule(t, "NETWORK", "UDP", "PROXY", nil),
		dnsPolicyRule(t, "DOMAIN", "direct.example", "DIRECT", nil),
		dnsPolicyRule(t, "MATCH", "", "DIRECT", nil),
	}, nil, nil)
	response := dnsPolicyBatch(t, "direct.example", "unmatched.example")
	if response.Results[0].ShareEligible || response.Results[0].Class == "unmatched" {
		t.Fatal(response.Results)
	}
	if got := response.Results[1]; got.Class != "unmatched" || !got.ShareEligible {
		t.Fatal(got)
	}
}

func TestDNSPolicyUnknownProviderCannotProveDefaultDirect(t *testing.T) {
	dnsPolicyInstall(t, []C.Rule{
		dnsPolicyRule(t, "DOMAIN", "direct.example", "DIRECT", nil),
		dnsPolicyRule(t, "RULE-SET", "missing", "PROXY", nil),
		dnsPolicyRule(t, "MATCH", "", "DIRECT", nil),
	}, nil, nil)
	got := dnsPolicyBatch(t, "direct.example", "other.example").Results
	if got[0].Class != "direct" || got[0].ShareEligible || got[1].Class != "unknown" {
		t.Fatal(got)
	}
}

func TestDNSPolicySubRulesAndClientScope(t *testing.T) {
	subs := map[string][]C.Rule{"lan": {
		dnsPolicyRule(t, "DOMAIN", "ai.example", "PROXY", nil),
		dnsPolicyRule(t, "DOMAIN", "direct.example", "DIRECT", nil),
		dnsPolicyRule(t, "MATCH", "", "DIRECT", nil),
	}}
	dnsPolicyInstall(t, []C.Rule{
		dnsPolicyRule(t, "SUB-RULE", "(SRC-IP-CIDR,192.168.6.0/24)", "lan", subs),
		dnsPolicyRule(t, "MATCH", "", "DEFAULT", nil),
	}, subs, nil)
	got := dnsPolicyBatch(t, "ai.example", "direct.example", "unmatched.example").Results
	if got[0].Class != "isolated" || got[1].Class != "direct" || !got[1].ShareEligible || got[2].Class != "unmatched" {
		t.Fatal(got)
	}
	response, err := ClassifyDNSPolicy(context.Background(), DNSPolicyRequest{Version: 1, Queries: []DNSPolicyQuery{{Domain: "ai.example", Client: "192.168.7.2"}}})
	if err != nil || response.Results[0].Class != "unmatched" {
		t.Fatalf("%+v %v", response, err)
	}
}

func TestDNSPolicyProviderEpochAndPureStatistics(t *testing.T) {
	provider := RP.NewInlineProvider("domains", P.Domain, []string{"ai.example"}, R.ParseRule)
	set := wrapper.NewRuleWrapper(dnsPolicyRule(t, "RULE-SET", "domains", "PROXY", nil))
	dnsPolicyInstall(t, []C.Rule{set, dnsPolicyRule(t, "MATCH", "", "DIRECT", nil)}, nil, map[string]P.RuleProvider{"domains": provider})
	first := dnsPolicyBatch(t, "ai.example", "other.example")
	if first.Results[0].Class != "isolated" || first.Results[1].Class != "unmatched" {
		t.Fatal(first)
	}
	if set.HitCount() != 0 || set.MissCount() != 0 {
		t.Fatal("classification changed routing statistics")
	}
	configMux.Lock()
	ruleProviders["domains"] = RP.NewInlineProvider("domains", P.Domain, []string{"other.example"}, R.ParseRule)
	configMux.Unlock()
	second := dnsPolicyBatch(t, "ai.example", "other.example")
	if first.Epoch == second.Epoch || second.Results[0].Class != "unmatched" || second.Results[1].Class != "isolated" {
		t.Fatalf("before %+v after %+v", first, second)
	}
	set.SetDisabled(true)
	third := dnsPolicyBatch(t, "other.example")
	if third.Epoch == second.Epoch || third.Results[0].Class != "unmatched" {
		t.Fatal(third)
	}
}

func TestDNSPolicyClassicalProviderPreservesUnknown(t *testing.T) {
	provider := RP.NewInlineProvider("mixed", P.Classical, []string{"AND,((DOMAIN,ai.example),(DST-PORT,443))"}, R.ParseRule)
	dnsPolicyInstall(t, []C.Rule{dnsPolicyRule(t, "RULE-SET", "mixed", "PROXY", nil), dnsPolicyRule(t, "MATCH", "", "DIRECT", nil)}, nil, map[string]P.RuleProvider{"mixed": provider})
	got := dnsPolicyBatch(t, "ai.example", "other.example").Results
	if got[0].Class != "unknown" || got[0].ShareEligible || got[1].Class != "unmatched" {
		t.Fatal(got)
	}
}

func TestDNSPolicyValidationAndCancellation(t *testing.T) {
	dnsPolicyInstall(t, nil, nil, nil)
	for _, q := range []DNSPolicyQuery{{Domain: "1.2.3.4", Client: "192.168.1.1"}, {Domain: "valid.example", Client: ""}, {Domain: "valid.example", Client: "::1%lo"}, {Domain: "bad domain", Client: "192.168.1.1"}} {
		if _, err := ClassifyDNSPolicy(context.Background(), DNSPolicyRequest{Version: 1, Queries: []DNSPolicyQuery{q}}); err == nil {
			t.Fatalf("accepted %+v", q)
		}
	}
	request := DNSPolicyRequest{Version: 1}
	for i := 0; i <= DNSPolicyMaxQueries; i++ {
		request.Queries = append(request.Queries, DNSPolicyQuery{Domain: fmt.Sprintf("domain%d.example", i), Client: "192.168.1.1"})
	}
	if _, err := ClassifyDNSPolicy(context.Background(), request); err == nil {
		t.Fatal("accepted oversized batch")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ClassifyDNSPolicy(ctx, DNSPolicyRequest{Version: 1, Queries: []DNSPolicyQuery{{Domain: "valid.example", Client: "192.168.1.1"}}}); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestDNSPolicyConfigLockHonorsCancellation(t *testing.T) {
	configMux.Lock()
	defer configMux.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ClassifyDNSPolicy(ctx, DNSPolicyRequest{Version: 1, Queries: []DNSPolicyQuery{{Domain: "valid.example", Client: "192.168.1.1"}}})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("snapshot blocked past deadline: %v", err)
	}
}
