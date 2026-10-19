package domainmapping

import (
	"errors"
	"net/netip"
	"strings"
)

// V3's latest observation is an LRU hint, not an expiring routing lease and
// not proof that a real CDN address belongs exclusively to that hostname.
func validateV3(result *Result, clientIP netip.Addr) error {
	if len(result.Domains) > 32 {
		return errors.New("domain-mapping v3 exceeds recent candidate limit")
	}
	if result.Status == "miss" {
		if result.Domain != "" || len(result.Domains) != 0 {
			return errors.New("domain-mapping miss contains domain evidence")
		}
		return nil
	}
	if result.Status != "hit" || result.RetentionMode != "lru" {
		return errors.New("invalid domain-mapping v3 status or retention mode")
	}
	// A global response must never replace another client's scoped evidence.
	if (clientIP.IsValid() && result.Scope != "client") || (!clientIP.IsValid() && result.Scope != "global") {
		return errors.New("domain-mapping v3 scope does not match query")
	}
	result.Domain = strings.ToLower(strings.TrimSuffix(result.Domain, "."))
	if !validDomain(result.Domain) || result.ObservedAt.IsZero() {
		return errors.New("invalid domain-mapping v3 hint")
	}
	seen := make(map[string]bool, len(result.Domains))
	for i, domain := range result.Domains {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if !validDomain(domain) || seen[domain] {
			return errors.New("invalid or duplicate domain-mapping v3 candidate")
		}
		seen[domain] = true
		result.Domains[i] = domain
	}
	// Old completeness/lease fields cannot smuggle v2 routing semantics into v3.
	result.Complete = false
	result.Total = len(result.Domains)
	result.Conflict = len(result.Domains) > 1
	return nil
}
