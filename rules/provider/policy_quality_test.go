package provider

import (
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
)

func TestPolicySnapshotDistinguishesUnloadedAndExplicitEmpty(t *testing.T) {
	p := &baseProvider{behavior: P.Domain}
	p.publishStrategy(newStrategy(P.Domain, nil))
	if p.DNSPolicySnapshot().Match != nil {
		t.Fatal("unloaded provider is authoritative")
	}
	for _, text := range []string{"payload: []", "rules: []\n", "# empty provider\npayload: []\n", "payload:\n"} {
		strategy, err := rulesParse([]byte(text), newStrategy(P.Domain, nil), P.YamlRule)
		if err != nil {
			t.Fatalf("explicit empty provider %q: %v", text, err)
		}
		p.publishStrategy(strategy)
		snapshot := p.DNSPolicySnapshot()
		if snapshot.Match == nil || snapshot.MatchDomain == nil || snapshot.MatchDomain("gemini.google.com") {
			t.Fatalf("explicit empty provider %q is not a complete negative", text)
		}
	}
}

func TestPolicyParserRejectsMissingPayloadAndRetainsMalformedState(t *testing.T) {
	for _, text := range []string{"", "# comment\n", "invalid: [\nnext: bad\n", "unknown: []\nanother: value\n", "payload: [unterminated"} {
		if _, err := rulesParse([]byte(text), newStrategy(P.Domain, nil), P.YamlRule); err == nil {
			t.Fatalf("accepted missing or malformed payload %q", text)
		}
	}
	for _, text := range []string{"payload:\n  - good.example\n  - [broken\n", "payload:\n  - good.example\n  - bad/example\n"} {
		strategy, err := rulesParse([]byte(text), newStrategy(P.Domain, nil), P.YamlRule)
		if err != nil {
			t.Fatal(err)
		}
		p := &baseProvider{behavior: P.Domain}
		p.publishStrategy(strategy)
		if p.DNSPolicySnapshot().Match != nil {
			t.Fatalf("partial provider became authoritative: %q", text)
		}
	}
}

func TestPolicyParserAcceptsFlowAndBlockPayloads(t *testing.T) {
	for _, text := range []string{"payload: [first.example, second.example]", "payload:\n  - first.example\n  - second.example", "rules: [first.example, second.example]\n"} {
		strategy, err := rulesParse([]byte(text), newStrategy(P.Domain, nil), P.YamlRule)
		if err != nil {
			t.Fatal(err)
		}
		p := &baseProvider{behavior: P.Domain}
		p.publishStrategy(strategy)
		snapshot := p.DNSPolicySnapshot()
		if snapshot.Match == nil || !snapshot.MatchDomain("first.example") || !snapshot.MatchDomain("second.example") {
			t.Fatalf("lost payload entries: %q", text)
		}
	}
}
