package common

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
)

type snapshotGeoLoader struct {
	geodata.LoaderImplementation
	domains *[]*router.Domain
	err     *error
}

func (l snapshotGeoLoader) LoadSiteByPath(string, string) ([]*router.Domain, error) {
	return *l.domains, *l.err
}

func TestGEOSITESnapshotPinsMatcherAcrossCacheReload(t *testing.T) {
	previous := geodata.LoaderName()
	domains := []*router.Domain{{Type: router.Domain_Full, Value: "first.example"}}
	var loadErr error
	geodata.RegisterGeoDataLoaderImplementationCreator("snapshot-test", func() geodata.LoaderImplementation {
		return snapshotGeoLoader{domains: &domains, err: &loadErr}
	})
	geodata.SetLoader("snapshot-test")
	geodata.ClearGeoSiteCache()
	t.Cleanup(func() { geodata.SetLoader(previous); geodata.ClearGeoSiteCache() })
	rule := &GEOSITE{country: "snapshot", adapter: "AI"}
	frozen, err := rule.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	domains = []*router.Domain{{Type: router.Domain_Full, Value: "second.example"}}
	geodata.ClearGeoSiteCache()
	current, err := rule.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		rule C.Rule
		host string
		want bool
	}{{frozen, "first.example", true}, {frozen, "second.example", false}, {current, "first.example", false}, {current, "second.example", true}} {
		matched, adapter := check.rule.Match(&C.Metadata{Host: check.host}, C.RuleMatchHelper{})
		if matched != check.want || adapter != "AI" || check.rule.Payload() != "snapshot" || check.rule.RuleType() != C.GEOSITE {
			t.Fatalf("snapshot mismatch for %s: %v %s", check.host, matched, adapter)
		}
	}
	loadErr = errors.New("unavailable geosite fixture")
	geodata.ClearGeoSiteCache()
	if _, err := rule.Snapshot(); err == nil {
		t.Fatal("snapshot converted a failed load into a negative match")
	}
	if matched, _ := frozen.Match(&C.Metadata{Host: "first.example"}, C.RuleMatchHelper{}); !matched {
		t.Fatal("previous snapshot was invalidated by a subsequent load failure")
	}
}
