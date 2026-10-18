package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/domainmapping"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
	ST "github.com/metacubex/mihomo/constant/sniffer"
	icontext "github.com/metacubex/mihomo/context"
	R "github.com/metacubex/mihomo/rules/common"
)

func enableMappingTest(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	old := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = nil // dns.enable=false
	t.Cleanup(func() {
		resolver.DefaultHostMapper = old
		_ = UpdateDomainMapping(domainmapping.Config{})
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	if err := UpdateDomainMapping(domainmapping.Config{
		Enable: true, Timeout: 1000,
		Providers: []domainmapping.ProviderConfig{{Name: "mosdns", Type: "mosdns-http-v1", Endpoint: server.URL}},
	}); err != nil {
		t.Fatal(err)
	}
}

func mappingHitHandler(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(domainmapping.Result{
		Version: 1, Status: "hit", IP: r.URL.Query().Get("ip"),
		Domain: "mapped.example", Scope: "client", Source: "A", Conflict: true,
		ExpiresAt: time.Now().Add(time.Minute),
	})
}

func realMetadata() *C.Metadata {
	return &C.Metadata{NetWork: C.TCP, Type: C.REDIR, SrcIP: netip.MustParseAddr("192.168.1.8"), SrcPort: 12345, DstIP: netip.MustParseAddr("203.0.113.20"), DstPort: 443}
}

type mappingTestEnhancer struct {
	resolver.Enhancer
	host string
}

func (e mappingTestEnhancer) MappingEnabled() bool { return true }
func (e mappingTestEnhancer) IsFakeIP(ip netip.Addr) bool {
	return netip.MustParsePrefix("198.18.0.0/16").Contains(ip)
}
func (e mappingTestEnhancer) FindHostByIP(netip.Addr) (string, bool) {
	return e.host, e.host != ""
}

func TestMappingRuleEvidencePreservesDialTarget(t *testing.T) {
	enableMappingTest(t, mappingHitHandler)
	metadata := realMetadata()
	originalIP := metadata.DstIP
	// External evidence wins over a real-IP entry in Mihomo's internal mapper.
	resolver.DefaultHostMapper = mappingTestEnhancer{host: "internal.example"}
	if !lookupDomainMapping(context.Background(), metadata) {
		t.Fatal("mapping lookup did not hit")
	}
	if err := preHandleMetadata(metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.RuleHost() != "mapped.example" || metadata.Host != "" || metadata.DstIP != originalIP || metadata.Pure().Host != "" || metadata.AddrType() != C.AtypIPv4 {
		t.Fatalf("domain evidence changed dial metadata: %+v", metadata)
	}
	if matched, _ := R.NewDomain("mapped.example", "DIRECT").Match(metadata, C.RuleMatchHelper{}); !matched {
		t.Fatal("DOMAIN rule did not use external evidence")
	}
	if matched, _ := R.NewDomainSuffix("example", "DIRECT").Match(metadata, C.RuleMatchHelper{}); !matched {
		t.Fatal("DOMAIN-SUFFIX rule did not use external evidence")
	}
	diagnostic := metadata.DomainResolution
	if diagnostic == nil || diagnostic.Provider != "mosdns" || diagnostic.LookupStatus != "hit" || diagnostic.Scope != "client" || !diagnostic.Conflict || diagnostic.Source != "A" {
		t.Fatalf("missing diagnostics: %+v", diagnostic)
	}
}

func TestMappingPreservesExplicitHostAndFakeIPBehavior(t *testing.T) {
	var requests atomic.Int32
	enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		mappingHitHandler(w, r)
	})
	resolver.DefaultHostMapper = mappingTestEnhancer{host: "fake.example"}
	metadata := realMetadata()
	metadata.Host = "explicit.example"
	if lookupDomainMapping(context.Background(), metadata) || metadata.Host != "explicit.example" {
		t.Fatal("external evidence replaced explicit inbound host")
	}
	metadata = realMetadata()
	metadata.DstIP = netip.MustParseAddr("198.18.0.9")
	if lookupDomainMapping(context.Background(), metadata) {
		t.Fatal("looked up fake-IP address")
	}
	if err := preHandleMetadata(metadata); err != nil || metadata.Host != "fake.example" || metadata.DstIP.IsValid() || metadata.DNSMode != C.DNSFakeIP {
		t.Fatalf("changed fake-IP resolution: %+v, %v", metadata, err)
	}
	resolver.DefaultHostMapper = mappingTestEnhancer{}
	metadata = realMetadata()
	metadata.DstIP = netip.MustParseAddr("198.18.0.10")
	if lookupDomainMapping(context.Background(), metadata) {
		t.Fatal("looked up missing fake-IP entry")
	}
	if err := preHandleMetadata(metadata); err == nil {
		t.Fatal("missing fake-IP error was lost")
	}
	if requests.Load() != 0 {
		t.Fatalf("unexpected external requests: %d", requests.Load())
	}
}

func TestTCPEntryMappingSkipsSniffer(t *testing.T) {
	enableMappingTest(t, mappingHitHandler)
	previousStatus, previousSniffing, previousDispatcher := Status(), sniffingEnable, snifferDispatcher
	OnRunning()
	t.Cleanup(func() {
		status.Store(previousStatus)
		sniffingEnable, snifferDispatcher = previousSniffing, previousDispatcher
	})
	dispatcher, err := sniffer.NewDispatcher(&sniffer.Config{
		Enable: true, ParsePureIp: true,
		Sniffers: map[ST.Type]sniffer.SnifferConfig{ST.HTTP: {OverrideDest: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	UpdateSniffer(dispatcher)
	metadata := realMetadata()
	metadata.SpecialProxy = "__missing_test_proxy__" // end after domain preparation
	inbound, client := net.Pipe()
	defer client.Close()
	defer inbound.Close()
	done := make(chan struct{})
	go func() { handleTCPConn(icontext.NewConnContext(inbound, metadata)); close(done) }()
	// A sniffer would wait for the client's first payload for one second. DNS
	// evidence can route even server-first or encrypted, unrecognizable flows.
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		_ = client.Close()
		<-done
		t.Fatal("mapping hit entered payload sniffing")
	}
	if metadata.RuleHost() != "mapped.example" || metadata.SniffHost != "" || metadata.Host != "" || metadata.DstIP != realMetadata().DstIP {
		t.Fatalf("TCP mapping did not preserve target: %+v", metadata)
	}
}

type mappingSniffSender struct {
	C.PacketSender
	sniffed bool
	skipped bool
}

func (s *mappingSniffSender) SkipSniff() { s.skipped = true }
func (s *mappingSniffSender) DoSniff(metadata *C.Metadata) error {
	s.sniffed = true
	metadata.SniffHost = "payload.example"
	return nil
}

func TestUDPMappingSkipsPayloadAndFallsBackOnMissOrError(t *testing.T) {
	for _, response := range []string{"hit", "miss", "error"} {
		t.Run(response, func(t *testing.T) {
			enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) {
				if response == "hit" {
					mappingHitHandler(w, r)
				} else if response == "error" {
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					_ = json.NewEncoder(w).Encode(domainmapping.Result{Version: 1, Status: "miss", IP: r.URL.Query().Get("ip")})
				}
			})
			metadata := realMetadata()
			metadata.NetWork = C.UDP
			originalIP := metadata.DstIP
			sender := &mappingSniffSender{}
			if err := prepareUDPDomain(metadata, sender); err != nil {
				t.Fatal(err)
			}
			if response == "hit" {
				if sender.sniffed || !sender.skipped || metadata.RuleHost() != "mapped.example" {
					t.Fatalf("hit did not bypass payload sniff: %+v, %+v", metadata, sender)
				}
			} else if !sender.sniffed || sender.skipped || metadata.RuleHost() != "payload.example" || metadata.DomainResolution.LookupStatus != response {
				t.Fatalf("fallback failed: %+v, %+v", metadata, sender)
			}
			if metadata.Host != "" || metadata.DstIP != originalIP {
				t.Fatalf("unexpected destination rewrite: %+v", metadata)
			}
		})
	}
}

type mappingPacket struct {
	data    []byte
	local   net.Addr
	dropped atomic.Bool
}

func (p *mappingPacket) Data() []byte                            { return p.data }
func (p *mappingPacket) LocalAddr() net.Addr                     { return p.local }
func (p *mappingPacket) Drop()                                   { p.dropped.Store(true) }
func (p *mappingPacket) WriteBack([]byte, net.Addr) (int, error) { return 0, nil }

func TestUDPMappingRetainsQueuedPacket(t *testing.T) {
	enableMappingTest(t, mappingHitHandler)
	metadata := realMetadata()
	metadata.NetWork = C.UDP
	packet := &mappingPacket{data: []byte("opaque datagram"), local: net.UDPAddrFromAddrPort(metadata.SourceAddrPort())}
	base := newPacketSender().(*packetSender)
	defer base.Close()
	quic, err := sniffer.NewQUICSniffer(sniffer.SnifferConfig{})
	if err != nil {
		t.Fatal(err)
	}
	sender := quic.WrapperSender(base, func(metadata *C.Metadata, host string) {
		t.Error("QUIC must not replace external evidence")
	})
	sender.Send(C.NewPacketAdapter(packet, metadata))
	if err := prepareUDPDomain(metadata.Clone(), sender); err != nil {
		t.Fatal(err)
	}
	if packet.dropped.Load() || len(base.ch) != 1 || base.ctx.Err() != nil {
		t.Fatal("mapping hit closed sender or discarded queued packet")
	}
	queued := <-base.ch
	if string(queued.Data()) != "opaque datagram" {
		t.Fatal("queued packet changed")
	}
	queued.Drop()
}

func TestUDPProviderDoesNotBlockPacketEntry(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	enableMappingTest(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		mappingHitHandler(w, r)
	})
	previousStatus, previousSniffing := Status(), sniffingEnable
	OnRunning()
	sniffingEnable = false
	t.Cleanup(func() { status.Store(previousStatus); sniffingEnable = previousSniffing })
	metadata := realMetadata()
	metadata.NetWork = C.UDP
	metadata.SpecialProxy = "__missing_test_proxy__" // stop after domain preparation
	packet := &mappingPacket{data: []byte("first packet"), local: net.UDPAddrFromAddrPort(metadata.SourceAddrPort())}
	adapter := C.NewPacketAdapter(packet, metadata)
	returned := make(chan struct{})
	go func() { handleUDPConn(adapter); close(returned) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("UDP receive entry blocked on provider")
	}
	<-started
	sender, loaded := natTable.GetOrCreate(adapter.Key(), func() C.PacketSender { panic("NAT session missing") })
	if !loaded || len(sender.(*packetSender).ch) != 1 {
		close(release)
		t.Fatal("first packet was not queued while lookup was pending")
	}
	close(release)
	select {
	case <-sender.(*packetSender).ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("UDP setup did not finish after provider replied")
	}
	// This test's fake proxy fails routing, so the normal error path closes the
	// sender. Successful queue preservation is tested separately above.
}
