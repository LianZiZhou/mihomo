package provider

import (
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

var policyRevision atomic.Uint64

// PolicySnapshot retains one immutable published provider strategy. The rules
// and functions remain valid after a provider update; callers must not mutate
// the rules. Revision changes even when a provider is replaced under the same
// name with an equally sized rule set.
type PolicySnapshot struct {
	Revision    uint64
	Behavior    P.RuleBehavior
	Rules       []C.Rule
	MatchDomain func(string) bool
	Match       func(*C.Metadata, C.RuleMatchHelper) bool
}

func Snapshot(p P.RuleProvider) (PolicySnapshot, bool) {
	if provider, ok := p.(interface{ DNSPolicySnapshot() PolicySnapshot }); ok {
		snapshot := provider.DNSPolicySnapshot()
		return snapshot, snapshot.Match != nil
	}
	return PolicySnapshot{}, false
}

func (bp *baseProvider) loadStrategy() ruleStrategy {
	bp.strategyMu.RLock()
	strategy := bp.strategy
	bp.strategyMu.RUnlock()
	return strategy
}

func (bp *baseProvider) publishStrategy(strategy ruleStrategy) {
	bp.strategyMu.Lock()
	bp.strategy = strategy
	bp.revision = policyRevision.Add(1)
	bp.strategyMu.Unlock()
}

func (bp *baseProvider) DNSPolicySnapshot() PolicySnapshot {
	bp.strategyMu.RLock()
	strategy, revision := bp.strategy, bp.revision
	bp.strategyMu.RUnlock()
	if strategy == nil || revision == 0 {
		return PolicySnapshot{}
	}
	if quality, ok := strategy.(interface{ PolicyComplete() bool }); !ok || !quality.PolicyComplete() {
		return PolicySnapshot{Revision: revision, Behavior: bp.behavior}
	}
	snapshot := PolicySnapshot{Revision: revision, Behavior: bp.behavior, Match: strategy.Match}
	switch strategy := strategy.(type) {
	case *domainStrategy:
		snapshot.MatchDomain = func(domain string) bool {
			return strategy.domainSet != nil && strategy.domainSet.Has(domain)
		}
	case *classicalStrategy:
		snapshot.Rules = strategy.rules
	}
	return snapshot
}

// SourceIP reports whether this rule set interprets IP rules as source rules.
func (rs *RuleSet) SourceIP() bool { return rs.isSrc }

// WithSnapshot freezes provider data while preserving source/no-resolve flags.
func (rs *RuleSet) WithSnapshot(snapshot PolicySnapshot) C.Rule {
	return &snapshotRuleSet{RuleSet: rs, snapshot: snapshot}
}

type snapshotRuleSet struct {
	*RuleSet
	snapshot PolicySnapshot
}

func (rs *snapshotRuleSet) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if rs.snapshot.Match == nil {
		return false, ""
	}
	if rs.isSrc {
		metadata.SwapSrcDst()
		defer metadata.SwapSrcDst()
		helper.ResolveIP = nil
	} else if rs.noResolveIP {
		helper.ResolveIP = nil
	}
	return rs.snapshot.Match(metadata, helper), rs.adapter
}
