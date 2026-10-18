package config_test

import (
	"fmt"
	"testing"

	"github.com/metacubex/mihomo/config"
	_ "github.com/metacubex/mihomo/hub/executor" // implements temporaryUpdateGeneral
)

func TestParseDomainMappingWithoutDNS(t *testing.T) {
	cfg, err := config.Parse([]byte(`dns:
  enable: false
domain-mapping:
  enable: true
  timeout: 50
  max-connections: 3
  max-inflight: 9
  providers:
    - name: mosdns
      type: mosdns-http-v1
      endpoint: http://127.0.0.1:9091/plugins/domain_index/v1/lookup
rules:
  - DOMAIN,mapped.example,DIRECT
  - MATCH,REJECT
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Enable || !cfg.DomainMapping.Enable || cfg.DomainMapping.Timeout != 50 || cfg.DomainMapping.MaxConnections != 3 || cfg.DomainMapping.MaxInflight != 9 || len(cfg.DomainMapping.Providers) != 1 {
		t.Fatalf("DNS-independent mapping was not parsed: %+v", cfg.DomainMapping)
	}
	if _, err := config.Parse([]byte("domain-mapping:\n  enable: true\n")); err == nil {
		t.Fatal("accepted enabled mapping without a provider")
	}
}

func TestParseDomainMappingRejectsNegativeResourceLimits(t *testing.T) {
	for _, field := range []string{"max-connections", "max-inflight"} {
		t.Run(field, func(t *testing.T) {
			if _, err := config.Parse([]byte(fmt.Sprintf("domain-mapping:\n  %s: -1\n", field))); err == nil {
				t.Fatalf("accepted negative %s", field)
			}
		})
	}
}
