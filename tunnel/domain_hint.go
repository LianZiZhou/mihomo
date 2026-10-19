package tunnel

import (
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	C "github.com/metacubex/mihomo/constant"
	RP "github.com/metacubex/mihomo/rules/provider"
)

// Called under configMux. Speculation only detects conflicts; the ordinary
// matcher below performs the actual selection and commits counters exactly once.
// A recovering allocator is deliberately absent from this decision.
func prepareNativeDomainHint(metadata *C.Metadata, baseHelper C.RuleMatchHelper) {
	diagnostic := metadata.DomainResolution
	if diagnostic == nil {
		return
	}
	if metadata.SniffHost != "" {
		diagnostic.Decision, diagnostic.Reason, diagnostic.PolicyDomain = "sniff", "payload-domain", metadata.SniffHost
		return
	}
	if diagnostic.LookupStatus != "hit" {
		diagnostic.Decision, diagnostic.Reason, diagnostic.PolicyDomain = "original-rules", "no-dns-hint", ""
		return
	}
	original := func(reason string) {
		metadata.DomainMappingHost = ""
		diagnostic.Decision, diagnostic.Reason, diagnostic.PolicyDomain = "original-rules", reason, ""
	}
	if !diagnostic.CandidatesComplete {
		original("recent-candidates-truncated")
		return
	}
	hint := metadata.DomainMappingHost
	if hint == "" {
		return
	}
	domains := []string{hint}
	for _, domain := range metadata.DomainMappingCandidates {
		if domain != hint {
			domains = append(domains, domain)
		}
	}
	if len(domains) > 1 {
		if reason := recentDomainConflict(metadata, domains, baseHelper); reason != "" {
			original(reason)
			return
		}
	}
	diagnostic.Decision, diagnostic.Reason, diagnostic.PolicyDomain = "dns-hint", "latest-dns-observation", hint
}

func recentDomainConflict(metadata *C.Metadata, domains []string, baseHelper C.RuleMatchHelper) string {
	deadline := time.Now().Add(candidateRouteBudget)
	generation := geodata.GeoSiteCacheGeneration()
	freezer := candidateFreezer{nodes: make(map[C.Rule]*candidateRule), providers: make(map[string]RP.PolicySnapshot), deadline: deadline}
	all := map[string][]C.Rule{"": rules}
	for name, list := range subRules {
		all[name] = list
	}
	steps, processLoaded := 0, false
	var policy string
	conflict := false
	for _, domain := range domains {
		m := candidateClone(metadata)
		m.DomainMappingHost = domain
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
		d, err := candidateEvaluate(m, domain, helper, all, &freezer, &steps, false)
		if err != nil {
			return "candidate-evaluation-unavailable"
		}
		if !time.Now().Before(deadline) {
			return "candidate-evaluation-timeout"
		}
		if policy == "" {
			policy = d.proxy.Name()
		} else if policy != d.proxy.Name() {
			conflict = true
		}
	}
	if freezer.geoUsed && (generation%2 != 0 || generation != geodata.GeoSiteCacheGeneration()) {
		return "geosite-changed-during-snapshot"
	}
	for name, snapshot := range freezer.providers {
		current, ok := RP.Snapshot(ruleProviders[name])
		if !ok || current.Revision != snapshot.Revision {
			return "provider-changed-during-snapshot"
		}
	}
	if conflict {
		return "recent-conflicting-policies"
	}
	return ""
}
