package tunnel

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/component/geodata"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/rules/logic"
	RP "github.com/metacubex/mihomo/rules/provider"
)

const candidateRouteBudget = 50 * time.Millisecond

// Each connection evaluates a frozen rule/provider tree. No speculative
// candidate may change rule counters, DNS destinations or rematch metadata.
type candidateRule struct {
	original        C.Rule
	pure            C.Rule
	children        []*candidateRule
	sub             []*candidateRule
	disabled        bool
	domainDependent bool
	classical       bool
	sourceIP        bool
	regex           *regexp2.Regexp
}

type candidateFreezer struct {
	nodes     map[C.Rule]*candidateRule
	providers map[string]RP.PolicySnapshot
	deadline  time.Time
	err       error
	geoUsed   bool
}

func (f *candidateFreezer) freeze(rule C.Rule) *candidateRule {
	if f.err != nil {
		return &candidateRule{original: rule, pure: rule, disabled: true}
	}
	if n := f.nodes[rule]; n != nil {
		return n
	}
	n := &candidateRule{original: rule, pure: rule}
	f.nodes[rule] = n
	if len(f.nodes) > 65536 || !time.Now().Before(f.deadline) {
		f.err = errors.New("candidate rule snapshot budget exceeded")
		return n
	}
	if wrapper, ok := rule.(C.RuleWrapper); ok {
		n.disabled = wrapper.IsDisabled()
		rule = wrapper.Unwrap()
		n.pure = rule
	}
	switch r := rule.(type) {
	case *RC.GEOSITE:
		f.geoUsed = true
		n.domainDependent = true
		n.pure, f.err = r.Snapshot()
	case *logic.Logic:
		for _, child := range r.Rules() {
			c := f.freeze(child)
			n.children = append(n.children, c)
			n.domainDependent = n.domainDependent || c.domainDependent
		}
		if r.RuleType() == C.SubRules {
			for _, child := range r.SubRules()[r.Adapter()] {
				c := f.freeze(child)
				n.sub = append(n.sub, c)
				n.domainDependent = n.domainDependent || c.domainDependent
			}
		}
	case *RP.RuleSet:
		name := r.Payload()
		ps, ok := f.providers[name]
		if !ok {
			p, exists := ruleProviders[name]
			if !exists {
				f.err = fmt.Errorf("rule provider %q unavailable", name)
				break
			}
			ps, ok = RP.Snapshot(p)
			if !ok {
				f.err = fmt.Errorf("rule provider %q cannot be snapshotted", name)
				break
			}
			f.providers[name] = ps
		}
		n.pure = r.WithSnapshot(ps)
		// A conservative dependency flag only influences conflict preference,
		// never whether the rule actually matches this candidate.
		n.domainDependent = ps.Behavior != P.IPCIDR
		if ps.Behavior == P.Classical {
			n.classical, n.sourceIP, n.domainDependent = true, r.SourceIP(), false
			for _, child := range ps.Rules {
				c := f.freeze(child)
				n.children = append(n.children, c)
				n.domainDependent = n.domainDependent || c.domainDependent
			}
		}
	default:
		switch rule.RuleType() {
		case C.Domain, C.DomainSuffix, C.DomainKeyword, C.DomainRegex, C.DomainWildcard, C.GEOSITE:
			n.domainDependent = true
		}
	}
	if rule.RuleType() == C.DomainRegex || rule.RuleType() == C.ProcessNameRegex || rule.RuleType() == C.ProcessPathRegex {
		r, err := regexp2.Compile(rule.Payload(), regexp2.IgnoreCase)
		if err != nil {
			f.err = err
		} else {
			r.MatchTimeout = 5 * time.Millisecond
			n.regex = r
		}
	}
	return n
}

type candidateEvaluation struct {
	metadata *C.Metadata
	helper   C.RuleMatchHelper
	deadline time.Time
	steps    *int
	trace    map[C.RuleWrapper]bool
	err      error
}

func (e *candidateEvaluation) match(n *candidateRule, depth int) (bool, string, []int) {
	*e.steps++
	if depth > 128 || *e.steps > 1000000 || !time.Now().Before(e.deadline) {
		e.err = errors.New("candidate rule evaluation budget exceeded")
		return false, "", nil
	}
	if n.disabled {
		return false, "", nil
	}
	matched, adapter, path := e.matchInner(n, depth)
	if w, ok := n.original.(C.RuleWrapper); ok {
		e.trace[w] = matched
	}
	return matched, adapter, path
}

func (e *candidateEvaluation) matchInner(n *candidateRule, depth int) (bool, string, []int) {
	if n.regex != nil {
		value := e.metadata.RuleHost()
		if n.pure.RuleType() != C.DomainRegex {
			if e.helper.FindProcess != nil {
				e.helper.FindProcess()
			}
			value = e.metadata.Process
			if n.pure.RuleType() == C.ProcessPathRegex {
				value = e.metadata.ProcessPath
			}
		}
		matched, err := n.regex.MatchString(value)
		if err != nil {
			e.err = err
			return false, "", nil
		}
		return matched, n.pure.Adapter(), nil
	}
	if n.classical {
		if n.sourceIP {
			e.metadata.SwapSrcDst()
			defer e.metadata.SwapSrcDst()
		}
		for _, child := range n.children {
			if m, _, _ := e.match(child, depth+1); m {
				return true, n.pure.Adapter(), nil
			}
		}
		return false, "", nil
	}
	switch n.pure.RuleType() {
	case C.AND:
		for _, c := range n.children {
			if m, _, _ := e.match(c, depth+1); !m {
				return false, "", nil
			}
		}
		return true, n.pure.Adapter(), nil
	case C.OR:
		for _, c := range n.children {
			if m, _, _ := e.match(c, depth+1); m {
				return true, n.pure.Adapter(), nil
			}
		}
		return false, "", nil
	case C.NOT:
		if len(n.children) != 1 {
			e.err = errors.New("invalid NOT rule")
			return false, "", nil
		}
		m, _, _ := e.match(n.children[0], depth+1)
		return !m, n.pure.Adapter(), nil
	case C.SubRules:
		if len(n.children) != 1 {
			e.err = errors.New("invalid SUB-RULE condition")
			return false, "", nil
		}
		if m, _, _ := e.match(n.children[0], depth+1); !m {
			return false, "", nil
		}
		for i, c := range n.sub {
			if m, a, p := e.match(c, depth+1); m {
				if a == "PASS-RULE" || (e.helper.CheckPassRule != nil && e.helper.CheckPassRule(a)) {
					continue
				}
				return true, a, append([]int{i}, p...)
			}
		}
		return false, "", nil
	default:
		m, a := n.pure.Match(e.metadata, e.helper)
		return m, a, nil
	}
}

type candidateDecision struct {
	proxy        C.Proxy
	rule         C.Rule
	path         []int
	domain       string
	trace        map[C.RuleWrapper]bool
	rematchName  string
	specialRules string
	preferred    bool
	rejected     bool
}

func candidateEarlier(a, b candidateDecision) bool {
	for i := 0; i < len(a.path) && i < len(b.path); i++ {
		if a.path[i] != b.path[i] {
			return a.path[i] < b.path[i]
		}
	}
	if len(a.path) != len(b.path) {
		return len(a.path) < len(b.path)
	}
	return a.domain < b.domain
}

func candidateProxyKind(proxy C.Proxy, metadata *C.Metadata) (skip bool, rematch C.ProxyAdapter, rejected bool, err error) {
	var a C.ProxyAdapter = proxy
	for i := 0; a != nil; i++ {
		if i == 64 {
			return false, nil, false, errors.New("proxy unwrap cycle")
		}
		switch a.Type() {
		case C.Pass:
			return true, nil, false, nil
		case C.Rematch:
			return false, a, false, nil
		case C.Reject, C.RejectDrop:
			rejected = true
		}
		a = a.Unwrap(metadata, false)
	}
	return false, nil, rejected, nil
}

func candidateCommit(trace map[C.RuleWrapper]bool) {
	for wrapper, hit := range trace {
		if stats, ok := wrapper.(interface {
			Hit()
			Miss()
		}); ok {
			if hit {
				stats.Hit()
			} else {
				stats.Miss()
			}
		}
	}
}

// Called with configMux held. Ambiguity is policy evidence, not a detected host.
func matchDomainCandidates(metadata *C.Metadata, baseHelper C.RuleMatchHelper) (C.Proxy, C.Rule, error) {
	diagnostic := metadata.DomainResolution
	all := map[string][]C.Rule{"": rules}
	for name, list := range subRules {
		all[name] = list
	}
	processLoaded := false
	helperFor := func(m *C.Metadata) C.RuleMatchHelper {
		helper := C.RuleMatchHelper{FindProcess: func() {
			if !processLoaded && baseHelper.FindProcess != nil {
				baseHelper.FindProcess()
			}
			processLoaded = true
			m.Process, m.ProcessPath, m.Uid = metadata.Process, metadata.ProcessPath, metadata.Uid
		}}
		helper.CheckPassRule = func(name string) bool {
			var a C.ProxyAdapter = proxies[name]
			for i := 0; a != nil && i < 64; i++ {
				if a.Type() == C.PassRule {
					return true
				}
				a = a.Unwrap(m, false)
			}
			return false
		}
		return helper
	}
	commit := func(d *candidateDecision) {
		candidateCommit(d.trace)
		metadata.RematchName, metadata.SpecialRules = d.rematchName, d.specialRules
		diagnostic.Policy = d.proxy.Name()
	}
	fallback := func(reason string) (C.Proxy, C.Rule, error) {
		// An incomplete DNS history or resource error must not bypass an earlier
		// rule provably applicable to every possible domain (e.g. an IP REJECT).
		// Freeze lazily, so an unavailable later provider cannot hide that rule.
		m := candidateClone(metadata)
		m.DomainMappingHost = ""
		freezer := candidateFreezer{nodes: make(map[C.Rule]*candidateRule), providers: make(map[string]RP.PolicySnapshot), deadline: time.Now().Add(candidateRouteBudget)}
		steps := 0
		generation := geodata.GeoSiteCacheGeneration()
		if d, err := candidateEvaluate(m, "", helperFor(m), all, &freezer, &steps, true); err == nil && d != nil && (!freezer.geoUsed || (generation%2 == 0 && generation == geodata.GeoSiteCacheGeneration())) {
			commit(d)
			diagnostic.Decision, diagnostic.Reason, diagnostic.PolicyDomain = "consensus", "domain-independent", ""
			return d.proxy, d.rule, nil
		}
		diagnostic.Decision, diagnostic.Reason, diagnostic.PolicyDomain = "fallback", reason, ""
		name := metadata.DomainMappingFallback
		if name == "" {
			name = "REJECT"
		}
		p, ok := proxies[name]
		if !ok {
			return nil, nil, fmt.Errorf("domain-mapping conflict fallback %q unavailable", name)
		}
		if metadata.NetWork == C.UDP && !p.SupportUDP() {
			return nil, nil, fmt.Errorf("domain-mapping conflict fallback %q does not support UDP", name)
		}
		skip, rematch, _, err := candidateProxyKind(p, metadata)
		if err != nil || skip || rematch != nil || p.Type() == C.PassRule {
			return nil, nil, fmt.Errorf("domain-mapping conflict fallback %q is not a terminal policy", name)
		}
		diagnostic.Policy = name
		return p, nil, nil
	}
	if !diagnostic.Complete || len(metadata.DomainMappingCandidates) < 2 {
		return fallback("incomplete-candidates")
	}
	deadline := time.Now().Add(candidateRouteBudget)
	generation := geodata.GeoSiteCacheGeneration()
	if generation%2 != 0 {
		return fallback("geosite-update-in-progress")
	}
	freezer := candidateFreezer{nodes: make(map[C.Rule]*candidateRule), providers: make(map[string]RP.PolicySnapshot), deadline: deadline}
	for _, list := range all {
		for _, r := range list {
			freezer.freeze(r)
		}
	}
	if freezer.err != nil {
		return fallback(freezer.err.Error())
	}
	if freezer.geoUsed && generation != geodata.GeoSiteCacheGeneration() {
		return fallback("geosite-changed-during-snapshot")
	}
	for name, snapshot := range freezer.providers {
		current, ok := RP.Snapshot(ruleProviders[name])
		if !ok || current.Revision != snapshot.Revision {
			return fallback("provider-changed-during-snapshot")
		}
	}
	domains := append([]string(nil), metadata.DomainMappingCandidates...)
	sort.Strings(domains)
	steps := 0
	decisions := make([]candidateDecision, 0, len(domains))
	for _, domain := range domains {
		m := candidateClone(metadata)
		m.DomainMappingHost = domain
		d, err := candidateEvaluate(m, domain, helperFor(m), all, &freezer, &steps, false)
		if err != nil {
			return fallback(err.Error())
		}
		if !time.Now().Before(deadline) {
			return fallback("candidate-evaluation-timeout")
		}
		decisions = append(decisions, *d)
	}
	winner := decisions[0]
	consensus := true
	for _, d := range decisions[1:] {
		if d.proxy.Name() != decisions[0].proxy.Name() {
			consensus = false
		}
		if candidateEarlier(d, winner) {
			winner = d
		}
	}
	if !consensus && metadata.DomainMappingPolicy != "rule-priority" {
		var protected *candidateDecision
		for i := range decisions {
			d := &decisions[i]
			if !d.rejected && !d.preferred {
				continue
			}
			if protected == nil || (d.rejected && !protected.rejected) || (d.rejected == protected.rejected && candidateEarlier(*d, *protected)) {
				protected = d
			}
		}
		if protected != nil {
			winner = *protected
		}
	}
	commit(&winner)
	if consensus {
		diagnostic.Decision, diagnostic.PolicyDomain, diagnostic.Reason = "consensus", "", ""
	} else {
		diagnostic.Decision, diagnostic.Reason, diagnostic.PolicyDomain = "fallback", "conflicting-policies", winner.domain
	}
	return winner.proxy, winner.rule, nil
}
