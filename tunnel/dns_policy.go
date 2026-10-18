package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/component/geodata"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/rules/logic"
	RP "github.com/metacubex/mihomo/rules/provider"
	M "github.com/metacubex/sing/common/metadata"
)

const (
	DNSPolicyMaxQueries = 64
	DNSPolicyValidForMS = 5000
	dnsPolicyMaxNodes   = 16384
	dnsPolicyMaxDepth   = 32
	dnsPolicyMaxSteps   = 1 << 20
)

var dnsPolicyBootID = func() [16]byte {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}()

type DNSPolicyQuery struct {
	Domain string `json:"domain"`
	Client string `json:"client"`
}

type DNSPolicyRequest struct {
	Version int              `json:"version"`
	Queries []DNSPolicyQuery `json:"queries"`
}

type DNSPolicyResult struct {
	Domain        string `json:"domain"`
	Client        string `json:"client"`
	Class         string `json:"class"`
	ShareEligible bool   `json:"share_eligible"`
}

type DNSPolicyResponse struct {
	Version    int               `json:"version"`
	Epoch      string            `json:"epoch"`
	ValidForMS int               `json:"valid_for_ms"`
	Results    []DNSPolicyResult `json:"results"`
}

// ValidateDNSPolicyRequest canonicalizes a bounded batch. A missing or malformed
// client is not a wildcard: classification is always for one effective client.
func ValidateDNSPolicyRequest(request *DNSPolicyRequest) error {
	if request.Version != 1 || len(request.Queries) == 0 || len(request.Queries) > DNSPolicyMaxQueries {
		return errors.New("version 1 and 1..64 queries are required")
	}
	for i := range request.Queries {
		query := &request.Queries[i]
		query.Domain = strings.ToLower(strings.TrimSuffix(query.Domain, "."))
		if len(query.Domain) == 0 || len(query.Domain) > 253 || !M.IsDomainName(query.Domain) {
			return errors.New("invalid domain")
		}
		if _, err := netip.ParseAddr(query.Domain); err == nil {
			return errors.New("domain must not be an IP address")
		}
		client, err := netip.ParseAddr(query.Client)
		if err != nil || client.Zone() != "" || client.IsUnspecified() || client.IsMulticast() {
			return errors.New("invalid client address")
		}
		query.Client = client.Unmap().String()
	}
	return nil
}

type dnsTruth uint8

const (
	dnsFalse dnsTruth = iota
	dnsTrue
	dnsUnknown
)

type dnsPolicyNode struct {
	kind        C.RuleType
	adapter     string
	domain      bool
	other       bool
	unsupported bool
	children    []*dnsPolicyNode
	sub         []*dnsPolicyNode
	test        func(*C.Metadata) dnsTruth
}

type dnsPolicyAction struct {
	direct  bool
	skip    bool
	maySkip bool
	unknown bool
}

type dnsPolicySnapshot struct {
	rules   []*dnsPolicyNode
	actions map[string]dnsPolicyAction
	epoch   string
	mode    TunnelMode
}

type dnsPolicyCompiler struct {
	ctx             context.Context
	digest          hash.Hash
	count           int
	providers       map[string]RP.PolicySnapshot
	providerMissing map[string]bool
	active          map[C.Rule]bool
	actionCache     map[C.Proxy]dnsPolicyAction
}

func (c *dnsPolicyCompiler) step(depth int) error {
	c.count++
	if depth > dnsPolicyMaxDepth || c.count > dnsPolicyMaxNodes {
		return errors.New("DNS policy rule graph exceeds limits")
	}
	return c.ctx.Err()
}

// snapshotDNSPolicy copies only immutable predicates while holding configMux.
// Provider strategies are separately pinned; their revisions are part of epoch.
func snapshotDNSPolicy(ctx context.Context) (*dnsPolicySnapshot, error) {
	for !configMux.TryRLock() {
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	defer configMux.RUnlock()
	if Status() != Running {
		return nil, errors.New("DNS policy unavailable while configuration is loading")
	}
	geoGeneration := geodata.GeoSiteCacheGeneration()
	if geoGeneration%2 != 0 {
		return nil, errors.New("DNS policy unavailable while geosite is loading")
	}
	c := &dnsPolicyCompiler{ctx: ctx, digest: sha256.New(), providers: make(map[string]RP.PolicySnapshot),
		providerMissing: make(map[string]bool), active: make(map[C.Rule]bool), actionCache: make(map[C.Proxy]dnsPolicyAction)}
	c.digest.Write(dnsPolicyBootID[:])
	fmt.Fprintf(c.digest, "geosite-generation:%d;", geoGeneration)
	fmt.Fprintf(c.digest, "mode:%d;", mode)
	providerNames := make([]string, 0, len(ruleProviders))
	for name := range ruleProviders {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	for _, name := range providerNames {
		snapshot, ok := RP.Snapshot(ruleProviders[name])
		if !ok {
			c.providerMissing[name] = true
		} else {
			c.providers[name] = snapshot
		}
		fmt.Fprintf(c.digest, "provider:%q:%d:%t;", name, snapshot.Revision, ok)
	}
	snapshot := &dnsPolicySnapshot{mode: mode, actions: make(map[string]dnsPolicyAction)}
	proxyNames := make([]string, 0, len(proxies))
	for name := range proxies {
		proxyNames = append(proxyNames, name)
	}
	sort.Strings(proxyNames)
	for _, name := range proxyNames {
		action, err := c.action(proxies[name], make(map[C.Proxy]bool), 0)
		if err != nil {
			return nil, err
		}
		snapshot.actions[name] = action
		fmt.Fprintf(c.digest, "proxy:%q:%v;", name, action)
	}
	var err error
	snapshot.rules, err = c.list(rules, 0)
	if err != nil {
		return nil, err
	}
	// Configured subrule graphs affect the epoch even if they are currently
	// unreachable. Their predicates are compiled only when referenced.
	keys := make([]string, 0, len(subRules))
	for name := range subRules {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		fmt.Fprintf(c.digest, "sub:%q;", name)
		if _, err := c.list(subRules[name], 0); err != nil {
			return nil, err
		}
	}
	for name, before := range c.providers {
		after, ok := RP.Snapshot(ruleProviders[name])
		if !ok || after.Revision != before.Revision {
			return nil, errors.New("DNS policy provider changed during snapshot")
		}
	}
	if Status() != Running {
		return nil, errors.New("DNS policy configuration changed during snapshot")
	}
	if geodata.GeoSiteCacheGeneration() != geoGeneration {
		return nil, errors.New("DNS policy geosite changed during snapshot")
	}
	snapshot.epoch = hex.EncodeToString(c.digest.Sum(nil))
	return snapshot, nil
}

// Groups are not fixed DIRECT policies, even while selecting a DIRECT member.
// Inspect all possible members, not the current selection: PASS, REMATCH and
// UDP-ineligible adapters can let later domain rules participate in routing.
func (c *dnsPolicyCompiler) action(proxy C.Proxy, active map[C.Proxy]bool, depth int) (result dnsPolicyAction, err error) {
	if cached, ok := c.actionCache[proxy]; ok {
		return cached, nil
	}
	defer func() {
		if err == nil {
			c.actionCache[proxy] = result
		}
	}()
	if err := c.step(depth); err != nil {
		return dnsPolicyAction{}, err
	}
	if active[proxy] {
		return dnsPolicyAction{unknown: true}, nil
	}
	active[proxy] = true
	defer delete(active, proxy)
	kind := proxy.Type()
	fmt.Fprintf(c.digest, "member:%p:%d;", proxy, kind)
	switch kind {
	case C.Pass:
		return dnsPolicyAction{skip: true}, nil
	case C.PassRule, C.Rematch:
		return dnsPolicyAction{unknown: true}, nil
	case C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		group, ok := proxy.Adapter().(interface {
			GetProxies(bool) []C.Proxy
			EmptyFallback() C.Proxy
		})
		if !ok {
			return dnsPolicyAction{unknown: true}, nil
		}
		members := group.GetProxies(false)
		// Empty fallback can become relevant after a provider update. Include it
		// even while the group is non-empty so classification stays conservative.
		if fallback := group.EmptyFallback(); fallback != nil {
			members = append(append([]C.Proxy(nil), members...), fallback)
		}
		if len(members) == 0 {
			return dnsPolicyAction{unknown: true}, nil
		}
		result = dnsPolicyAction{}
		for _, member := range members {
			child, err := c.action(member, active, depth+1)
			if err != nil {
				return dnsPolicyAction{}, err
			}
			result.unknown = result.unknown || child.unknown
			result.maySkip = result.maySkip || child.skip || child.maySkip
		}
		// A group's own disable-udp flag is reflected by SupportUDP; inspecting
		// it has no destination-dependent or network side effects.
		if !result.unknown {
			result.maySkip = result.maySkip || !proxy.SupportUDP()
		}
		return result, nil
	default:
		return dnsPolicyAction{direct: kind == C.Direct, maySkip: !proxy.SupportUDP()}, nil
	}
}

func (c *dnsPolicyCompiler) list(rules []C.Rule, depth int) ([]*dnsPolicyNode, error) {
	result := make([]*dnsPolicyNode, 0, len(rules))
	for _, rule := range rules {
		node, err := c.compile(rule, depth)
		if err != nil {
			return nil, err
		}
		result = append(result, node)
	}
	return result, nil
}

func (c *dnsPolicyCompiler) compile(rule C.Rule, depth int) (*dnsPolicyNode, error) {
	if err := c.step(depth); err != nil {
		return nil, err
	}
	if c.active[rule] {
		return nil, errors.New("cyclic DNS policy rules")
	}
	c.active[rule] = true
	defer delete(c.active, rule)
	if wrapped, ok := rule.(C.RuleWrapper); ok {
		disabled := wrapped.IsDisabled()
		fmt.Fprintf(c.digest, "wrapper:%p:%t;", wrapped, disabled)
		if disabled {
			return &dnsPolicyNode{test: func(*C.Metadata) dnsTruth { return dnsFalse }}, nil
		}
		return c.compile(wrapped.Unwrap(), depth+1)
	}
	node := &dnsPolicyNode{kind: rule.RuleType(), adapter: rule.Adapter()}
	fmt.Fprintf(c.digest, "rule:%p:%d:%q:%q;", rule, node.kind, rule.Payload(), node.adapter)
	if logical, ok := rule.(*logic.Logic); ok {
		var err error
		node.children, err = c.list(logical.Rules(), depth+1)
		if err != nil {
			return nil, err
		}
		for _, child := range node.children {
			node.domain = node.domain || child.domain
			node.other = node.other || child.other
			node.unsupported = node.unsupported || child.unsupported
		}
		if node.kind == C.SubRules {
			node.sub, err = c.list(logical.SubRules()[node.adapter], depth+1)
		}
		return node, err
	}
	if set, ok := rule.(*RP.RuleSet); ok {
		provider, found := c.providers[set.Payload()]
		fmt.Fprintf(c.digest, "source:%t;", set.SourceIP())
		if !found {
			node.domain, node.unsupported = true, true
			return node, nil
		}
		switch provider.Behavior {
		case P.Domain:
			node.domain = true
			if provider.MatchDomain == nil {
				node.unsupported = true
			} else {
				node.test = func(metadata *C.Metadata) dnsTruth { return dnsBool(provider.MatchDomain(metadata.RuleHost())) }
			}
		case P.Classical:
			// Source mode can swap the meaning of nested source/destination
			// IP predicates. Leave it unknown rather than mis-folding either.
			if set.SourceIP() {
				node.domain, node.unsupported = true, true
				break
			}
			node.kind = C.OR
			var err error
			node.children, err = c.list(provider.Rules, depth+1)
			if err != nil {
				return nil, err
			}
			for _, child := range node.children {
				node.domain = node.domain || child.domain
				node.other = node.other || child.other
				node.unsupported = node.unsupported || child.unsupported
			}
		case P.IPCIDR:
			node.other = true
			if set.SourceIP() {
				node.test = func(metadata *C.Metadata) dnsTruth {
					copy := *metadata
					copy.DstIP = metadata.SrcIP
					return dnsBool(provider.Match(&copy, C.RuleMatchHelper{}))
				}
			}
		default:
			node.domain, node.unsupported = true, true
		}
		return node, nil
	}
	switch node.kind {
	case C.Domain, C.DomainSuffix, C.DomainKeyword, C.DomainWildcard:
		node.domain = true
		node.test = func(metadata *C.Metadata) dnsTruth {
			matched, _ := rule.Match(metadata, C.RuleMatchHelper{})
			return dnsBool(matched)
		}
	case C.DomainRegex:
		node.domain = true
		if len(rule.Payload()) > 4096 {
			node.unsupported = true
			break
		}
		regex, err := regexp2.Compile(rule.Payload(), regexp2.IgnoreCase)
		if err != nil {
			node.unsupported = true
			break
		}
		regex.MatchTimeout = 5 * time.Millisecond
		node.test = func(metadata *C.Metadata) dnsTruth {
			matched, err := regex.MatchString(metadata.RuleHost())
			if err != nil {
				return dnsUnknown
			}
			return dnsBool(matched)
		}
	case C.GEOSITE:
		node.domain = true
		geosite, ok := rule.(*common.GEOSITE)
		if !ok {
			node.unsupported = true
			break
		}
		matcher, err := geosite.GetDomainMatcher()
		if err != nil {
			node.unsupported = true
			break
		}
		fmt.Fprintf(c.digest, "geosite:%p;", matcher)
		node.test = func(metadata *C.Metadata) dnsTruth { return dnsBool(matcher.ApplyDomain(metadata.RuleHost())) }
	case C.SrcIPCIDR, C.SrcIPSuffix:
		node.other = true
		node.test = func(metadata *C.Metadata) dnsTruth {
			matched, _ := rule.Match(metadata, C.RuleMatchHelper{})
			return dnsBool(matched)
		}
	case C.MATCH:
		node.test = func(*C.Metadata) dnsTruth { return dnsTrue }
	case C.GEOIP, C.SrcGEOIP, C.IPASN, C.SrcIPASN, C.IPCIDR, C.IPSuffix,
		C.SrcPort, C.DstPort, C.InPort, C.DSCP, C.InUser, C.InName, C.InType,
		C.ProcessName, C.ProcessPath, C.ProcessNameRegex, C.ProcessPathRegex,
		C.ProcessNameWildcard, C.ProcessPathWildcard, C.RematchName, C.Network, C.Uid:
		node.other = true // DNS transport metadata is not application metadata.
	default:
		node.domain, node.unsupported = true, true
	}
	return node, nil
}

func dnsBool(value bool) dnsTruth {
	if value {
		return dnsTrue
	}
	return dnsFalse
}

type dnsPolicyEvaluation struct {
	ctx   context.Context
	steps int
}

func (e *dnsPolicyEvaluation) step() bool {
	e.steps++
	return e.steps <= dnsPolicyMaxSteps && e.ctx.Err() == nil
}

func (e *dnsPolicyEvaluation) predicate(node *dnsPolicyNode, metadata *C.Metadata) dnsTruth {
	if !e.step() || node.unsupported {
		return dnsUnknown
	}
	if node.test != nil {
		return node.test(metadata)
	}
	switch node.kind {
	case C.AND:
		result := dnsTrue
		for _, child := range node.children {
			value := e.predicate(child, metadata)
			if value == dnsFalse {
				return dnsFalse
			}
			if value == dnsUnknown {
				result = dnsUnknown
			}
		}
		return result
	case C.OR:
		result := dnsFalse
		for _, child := range node.children {
			value := e.predicate(child, metadata)
			if value == dnsTrue {
				return dnsTrue
			}
			if value == dnsUnknown {
				result = dnsUnknown
			}
		}
		return result
	case C.NOT:
		if len(node.children) != 1 {
			return dnsUnknown
		}
		value := e.predicate(node.children[0], metadata)
		if value == dnsUnknown {
			return value
		}
		return dnsBool(value == dnsFalse)
	case C.SubRules:
		if len(node.children) != 1 {
			return dnsUnknown
		}
		return e.predicate(node.children[0], metadata)
	}
	return dnsUnknown
}

type dnsPolicyOutcome struct{ domain, direct, unknown bool }

// outcomes deliberately over-approximates unknown connection fields. Branches
// are never filled with zero ports or empty process names to manufacture a miss.
func (e *dnsPolicyEvaluation) outcomes(snapshot *dnsPolicySnapshot, nodes []*dnsPolicyNode, metadata *C.Metadata, baseline, inherited bool, depth int) ([]dnsPolicyOutcome, bool) {
	if depth > dnsPolicyMaxDepth || !e.step() {
		return []dnsPolicyOutcome{{unknown: true}}, true
	}
	var outcomes []dnsPolicyOutcome
	for _, node := range nodes {
		if !e.step() {
			return append(outcomes, dnsPolicyOutcome{unknown: true}), true
		}
		predicate := e.predicate(node, metadata)
		if baseline && node.domain {
			if !node.other && !node.unsupported {
				continue
			}
			predicate = dnsUnknown // mixed conditions may still match an unmatched domain
		}
		if predicate == dnsFalse {
			continue
		}
		domain := inherited || node.domain
		if baseline {
			domain = false
		}
		if node.kind == C.SubRules {
			children, fallsThrough := e.outcomes(snapshot, node.sub, metadata, baseline, domain, depth+1)
			if node.domain && predicate == dnsUnknown && !baseline {
				for i := range children {
					children[i].unknown = true
				}
			}
			outcomes = append(outcomes, children...)
			if predicate == dnsTrue && !fallsThrough {
				return outcomes, false
			}
			continue
		}
		action, exists := snapshot.actions[node.adapter]
		if !exists {
			// Reload publishes proxies and rules separately. A missing adapter
			// cannot prove that this potentially matching rule is harmless.
			outcomes = append(outcomes, dnsPolicyOutcome{domain: domain, unknown: true})
			continue
		}
		if action.skip {
			continue
		}
		outcomes = append(outcomes, dnsPolicyOutcome{domain: domain, direct: action.direct,
			unknown: action.unknown || node.unsupported || (node.domain && predicate == dnsUnknown)})
		if predicate == dnsTrue && !action.maySkip {
			return outcomes, false
		}
	}
	return outcomes, true
}

func (snapshot *dnsPolicySnapshot) classify(e *dnsPolicyEvaluation, query DNSPolicyQuery) DNSPolicyResult {
	result := DNSPolicyResult{Domain: query.Domain, Client: query.Client, Class: "unknown"}
	if snapshot.mode != Rule {
		return result
	}
	metadata := &C.Metadata{Host: query.Domain, SrcIP: netip.MustParseAddr(query.Client)}
	outcomes, fallsThrough := e.outcomes(snapshot, snapshot.rules, metadata, false, false, 0)
	if fallsThrough {
		outcomes = append(outcomes, dnsPolicyOutcome{direct: true})
	}
	anyDomain, allDirect := false, true
	for _, outcome := range outcomes {
		if outcome.unknown {
			return result
		}
		anyDomain = anyDomain || outcome.domain
		allDirect = allDirect && outcome.direct
	}
	if !anyDomain {
		result.Class, result.ShareEligible = "unmatched", true
		return result
	}
	result.Class = "isolated"
	if !allDirect {
		return result
	}
	result.Class = "direct"
	baseline, falls := e.outcomes(snapshot, snapshot.rules, metadata, true, false, 0)
	if falls {
		baseline = append(baseline, dnsPolicyOutcome{direct: true})
	}
	result.ShareEligible = true
	for _, outcome := range baseline {
		if !outcome.direct || outcome.unknown {
			result.ShareEligible = false
			break
		}
	}
	return result
}

// ClassifyDNSPolicy performs no network access, process discovery or mutation
// of rule statistics. All results in a batch refer to one immutable snapshot.
func ClassifyDNSPolicy(ctx context.Context, request DNSPolicyRequest) (DNSPolicyResponse, error) {
	if err := ValidateDNSPolicyRequest(&request); err != nil {
		return DNSPolicyResponse{}, err
	}
	snapshot, err := snapshotDNSPolicy(ctx)
	if err != nil {
		return DNSPolicyResponse{}, err
	}
	response := DNSPolicyResponse{Version: 1, Epoch: snapshot.epoch, ValidForMS: DNSPolicyValidForMS,
		Results: make([]DNSPolicyResult, 0, len(request.Queries))}
	evaluation := &dnsPolicyEvaluation{ctx: ctx}
	for _, query := range request.Queries {
		if ctx.Err() != nil {
			return DNSPolicyResponse{}, ctx.Err()
		}
		result := snapshot.classify(evaluation, query)
		if evaluation.steps > dnsPolicyMaxSteps || ctx.Err() != nil {
			result.Class, result.ShareEligible = "unknown", false
		}
		response.Results = append(response.Results, result)
	}
	if Status() != Running {
		return DNSPolicyResponse{}, errors.New("DNS policy configuration changed during classification")
	}
	return response, nil
}
