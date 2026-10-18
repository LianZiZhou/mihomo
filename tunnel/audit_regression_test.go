package tunnel

import (
	"context"
	"os"
	"testing"

	GD "github.com/metacubex/mihomo/component/geodata"
	GR "github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
)

type regressionGeoLoader struct {
	GD.LoaderImplementation
	domains *[]*GR.Domain
	onLoad  func(string)
}

func (l regressionGeoLoader) LoadSiteByPath(_ string, list string) ([]*GR.Domain, error) {
	if l.onLoad != nil {
		l.onLoad(list)
	}
	return *l.domains, nil
}

func TestDNSPolicyGeoSiteGenerationRejectsMixedSnapshot(t *testing.T) {
	oldHome, oldLoader := C.Path.HomeDir(), GD.LoaderName()
	C.SetHomeDir(t.TempDir())
	if err := os.WriteFile(C.Path.GeoSite(), []byte("offline fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	domains := []*GR.Domain{{Type: GR.Domain_Full, Value: "unused.example"}}
	armed := false
	GD.RegisterGeoDataLoaderImplementationCreator("generation-regression", func() GD.LoaderImplementation {
		return regressionGeoLoader{domains: &domains, onLoad: func(list string) {
			if armed && list == "second" {
				armed = false
				GD.ClearGeoSiteCache()
			}
		}}
	})
	GD.SetLoader("generation-regression")
	GD.ClearGeoSiteCache()
	t.Cleanup(func() {
		C.SetHomeDir(oldHome)
		GD.SetLoader(oldLoader)
		GD.ClearGeoSiteCache()
	})
	first, err := RC.NewGEOSITE("first", "PROXY")
	if err != nil {
		t.Fatal(err)
	}
	second, err := RC.NewGEOSITE("second", "PROXY")
	if err != nil {
		t.Fatal(err)
	}
	dnsPolicyInstall(t, []C.Rule{first, second, RC.NewMatch("DIRECT")}, nil, nil)
	GD.ClearGeoSiteCache()
	armed = true
	request := DNSPolicyRequest{Version: 1, Queries: []DNSPolicyQuery{{Domain: "gemini.google.com", Client: "192.168.6.180"}}}
	if _, err := ClassifyDNSPolicy(context.Background(), request); err == nil || armed {
		t.Fatal("classification accepted a snapshot crossing two geosite generations")
	}
	if err := GD.UpdateGeoSiteCache(func() error {
		if _, err := ClassifyDNSPolicy(context.Background(), request); err == nil {
			t.Error("classification issued a lease while geosite was being replaced")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type regressionFlipRule struct {
	C.Rule
	flip func()
}

func (r *regressionFlipRule) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) {
	r.flip()
	return false, ""
}

func TestCandidateGEOSITEReloadUsesFrozenMatcher(t *testing.T) {
	oldHome, oldLoader := C.Path.HomeDir(), GD.LoaderName()
	C.SetHomeDir(t.TempDir())
	if err := os.WriteFile(C.Path.GeoSite(), []byte("offline fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	domains := []*GR.Domain{{Type: GR.Domain_Full, Value: "unused.example"}}
	GD.RegisterGeoDataLoaderImplementationCreator("candidate-snapshot-regression", func() GD.LoaderImplementation {
		return regressionGeoLoader{domains: &domains}
	})
	GD.SetLoader("candidate-snapshot-regression")
	GD.ClearGeoSiteCache()
	t.Cleanup(func() {
		C.SetHomeDir(oldHome)
		GD.SetLoader(oldLoader)
		GD.ClearGeoSiteCache()
	})
	geosite, err := RC.NewGEOSITE("regression", "AI")
	if err != nil {
		t.Fatal(err)
	}
	flipped := false
	flip := &regressionFlipRule{Rule: RC.NewDomain("never.example", "DIRECT"), flip: func() {
		if !flipped {
			flipped = true
			domains = []*GR.Domain{{Type: GR.Domain_Full, Value: "a.example"}, {Type: GR.Domain_Full, Value: "b.example"}}
			GD.ClearGeoSiteCache()
		}
	}}
	setupCandidateRules(t, []C.Rule{geosite, flip, RC.NewMatch("DEFAULT")}, nil)
	metadata := ambiguousMetadata("a.example", "b.example")
	proxy, _, err := match(metadata, C.RuleMatchHelper{})
	if err != nil || !flipped || proxy.Name() != "DEFAULT" || metadata.DomainResolution.Decision != "consensus" {
		t.Fatalf("candidate evaluation mixed geosite revisions: proxy=%v result=%+v error=%v", proxy, metadata.DomainResolution, err)
	}
	// The next connection sees the newly published data consistently as well.
	metadata = ambiguousMetadata("a.example", "b.example")
	proxy, _, err = match(metadata, C.RuleMatchHelper{})
	if err != nil || proxy.Name() != "AI" || metadata.DomainResolution.Decision != "consensus" {
		t.Fatalf("new geosite data was not used by the next snapshot: proxy=%v result=%+v error=%v", proxy, metadata.DomainResolution, err)
	}
}
