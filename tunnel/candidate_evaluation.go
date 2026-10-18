package tunnel

import (
	"errors"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// unknownMatch proves a rule using only connection attributes. A missing DNS
// owner is not an empty hostname: all domain predicates remain unknown.
func (e *candidateEvaluation) unknownMatch(n *candidateRule, depth int) (dnsTruth, string, []int) {
	*e.steps++
	if depth > 128 || *e.steps > 1000000 || !time.Now().Before(e.deadline) {
		e.err = errors.New("candidate rule evaluation budget exceeded")
		return dnsUnknown, "", nil
	}
	if n.disabled {
		return dnsFalse, "", nil
	}
	v, a, p := e.unknownInner(n, depth)
	if w, ok := n.original.(C.RuleWrapper); ok && v != dnsUnknown {
		e.trace[w] = v == dnsTrue
	}
	return v, a, p
}

func (e *candidateEvaluation) unknownInner(n *candidateRule, depth int) (dnsTruth, string, []int) {
	kind := n.pure.RuleType()
	if n.classical || kind == C.AND || kind == C.OR {
		if n.sourceIP {
			e.metadata.SwapSrcDst()
			defer e.metadata.SwapSrcDst()
		}
		and := kind == C.AND && !n.classical
		result := dnsFalse
		if and {
			result = dnsTrue
		}
		for _, c := range n.children {
			v, _, _ := e.unknownMatch(c, depth+1)
			if and && v == dnsFalse {
				return dnsFalse, "", nil
			}
			if !and && v == dnsTrue {
				return dnsTrue, n.pure.Adapter(), nil
			}
			if v == dnsUnknown {
				result = dnsUnknown
			}
		}
		return result, n.pure.Adapter(), nil
	}
	switch kind {
	case C.NOT:
		if len(n.children) != 1 {
			return dnsUnknown, "", nil
		}
		v, _, _ := e.unknownMatch(n.children[0], depth+1)
		if v == dnsUnknown {
			return v, "", nil
		}
		if v == dnsFalse {
			return dnsTrue, n.pure.Adapter(), nil
		}
		return dnsFalse, "", nil
	case C.SubRules:
		if len(n.children) != 1 {
			return dnsUnknown, "", nil
		}
		v, _, _ := e.unknownMatch(n.children[0], depth+1)
		if v != dnsTrue {
			return v, "", nil
		}
		for i, c := range n.sub {
			v, a, p := e.unknownMatch(c, depth+1)
			if v == dnsUnknown {
				return v, "", nil
			}
			if v == dnsTrue {
				if a == "PASS-RULE" || (e.helper.CheckPassRule != nil && e.helper.CheckPassRule(a)) {
					continue
				}
				return v, a, append([]int{i}, p...)
			}
		}
		return dnsFalse, "", nil
	}
	if n.domainDependent {
		return dnsUnknown, "", nil
	}
	// New rule kinds must opt into safe unknown-domain evaluation.
	switch kind {
	case C.GEOIP, C.SrcGEOIP, C.IPASN, C.SrcIPASN, C.IPCIDR, C.SrcIPCIDR,
		C.IPSuffix, C.SrcIPSuffix, C.SrcPort, C.DstPort, C.InPort, C.DSCP,
		C.InUser, C.InName, C.InType, C.ProcessName, C.ProcessPath,
		C.ProcessNameRegex, C.ProcessPathRegex, C.ProcessNameWildcard,
		C.ProcessPathWildcard, C.RematchName, C.RuleSet, C.Network, C.Uid, C.MATCH:
		m, a, p := e.matchInner(n, depth)
		if m {
			return dnsTrue, a, p
		}
		return dnsFalse, "", nil
	default:
		return dnsUnknown, "", nil
	}
}

func candidateClone(m *C.Metadata) *C.Metadata {
	c := m.Clone()
	c.SrcGeoIP = append([]string(nil), m.SrcGeoIP...)
	c.DstGeoIP = append([]string(nil), m.DstGeoIP...)
	return c
}

// Resolve all REMATCH transitions on a private metadata copy before comparing
// terminal outcomes. Native transitions never dial or change shared state.
func candidateEvaluate(m *C.Metadata, domain string, helper C.RuleMatchHelper, all map[string][]C.Rule, freezer *candidateFreezer, steps *int, unknown bool) (*candidateDecision, error) {
	e := candidateEvaluation{metadata: m, helper: helper, deadline: freezer.deadline, steps: steps, trace: make(map[C.RuleWrapper]bool)}
	d := &candidateDecision{domain: domain, trace: e.trace}
	seen := make(map[string]bool)
	dependent := false
	for round := 0; round < 32; round++ {
		list, ok := all[m.SpecialRules]
		if !ok {
			list = all[""]
		}
		transition := false
		for i, r := range list {
			n := freezer.freeze(r)
			if freezer.err != nil {
				return nil, freezer.err
			}
			var matched bool
			var name string
			var path []int
			if unknown {
				var v dnsTruth
				v, name, path = e.unknownMatch(n, 0)
				if v == dnsUnknown {
					return nil, e.err
				}
				matched = v == dnsTrue
			} else {
				matched, name, path = e.match(n, 0)
			}
			if e.err != nil {
				return nil, e.err
			}
			if !matched {
				continue
			}
			p, ok := proxies[name]
			if !ok {
				return nil, errors.New("candidate rule target unavailable")
			}
			skip, rematch, rejected, err := candidateProxyKind(p, m)
			if err != nil {
				return nil, err
			}
			if skip || (rematch == nil && m.NetWork == C.UDP && !p.SupportUDP()) {
				continue
			}
			d.path = append(d.path, i)
			d.path = append(d.path, path...)
			dependent = dependent || n.domainDependent
			if rematch != nil {
				if seen[rematch.Name()] {
					return nil, errors.New("rematch-cycle")
				}
				seen[rematch.Name()] = true
				pure, ok := rematch.(interface{ ApplyMetadata(*C.Metadata) })
				if !ok {
					return nil, errors.New("rematch lacks pure metadata transition")
				}
				pure.ApplyMetadata(m)
				transition = true
				break
			}
			d.proxy, d.rule, d.rejected = p, n.original, rejected
			d.preferred = dependent && p.Type() != C.Direct && !rejected
			d.rematchName, d.specialRules = m.RematchName, m.SpecialRules
			return d, nil
		}
		if transition {
			continue
		}
		d.proxy = proxies["DIRECT"]
		d.path = append(d.path, len(list))
		d.rematchName, d.specialRules = m.RematchName, m.SpecialRules
		if d.proxy == nil {
			return nil, errors.New("missing-direct-policy")
		}
		return d, nil
	}
	return nil, errors.New("rematch-depth")
}
