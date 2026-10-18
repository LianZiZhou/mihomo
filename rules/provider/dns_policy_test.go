package provider

import (
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func dnsPolicyDomainStrategy(domain string) ruleStrategy {
	strategy := newStrategy(P.Domain, nil)
	strategy.Insert(domain)
	strategy.FinishInsert()
	return strategy
}

func TestDNSPolicySnapshotPinsPublishedProvider(t *testing.T) {
	p := &baseProvider{behavior: P.Domain}
	p.publishStrategy(dnsPolicyDomainStrategy("first.example"))
	old := p.DNSPolicySnapshot()
	p.publishStrategy(dnsPolicyDomainStrategy("second.example"))
	newer := p.DNSPolicySnapshot()
	if old.Revision == newer.Revision || !old.MatchDomain("first.example") || old.MatchDomain("second.example") || !newer.MatchDomain("second.example") {
		t.Fatal("published strategy was not frozen")
	}
	set := &RuleSet{ruleProviderName: "test", adapter: "DIRECT"}
	frozen := set.WithSnapshot(old)
	if matched, _ := frozen.Match(&C.Metadata{Host: "first.example"}, C.RuleMatchHelper{}); !matched {
		t.Fatal("frozen set fetched the new provider")
	}
}

func TestDNSPolicyConcurrentProviderSnapshots(t *testing.T) {
	p := &baseProvider{behavior: P.Domain}
	p.publishStrategy(dnsPolicyDomainStrategy("first.example"))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			domain := "first.example"
			if i%2 == 1 {
				domain = "second.example"
			}
			p.publishStrategy(dnsPolicyDomainStrategy(domain))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			snapshot := p.DNSPolicySnapshot()
			a, b := snapshot.MatchDomain("first.example"), snapshot.MatchDomain("second.example")
			if a == b {
				t.Error("snapshot mixed provider revisions")
				return
			}
			_ = p.Count()
			_ = p.Strategy()
			_ = p.Match(&C.Metadata{Host: "first.example"}, C.RuleMatchHelper{})
		}
	}()
	wg.Wait()
}
