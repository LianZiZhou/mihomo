package sniffer

import (
	"encoding/binary"
	"errors"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	ST "github.com/metacubex/mihomo/constant/sniffer"
)

func TestECHAfterSNIIsNotTargetIdentity(t *testing.T) {
	// Reuse padding's framing to append ECH after a complete visible SNI.
	hello := makeTestClientHello("public.example", 32)
	echOffset := len(hello) - 36
	binary.BigEndian.PutUint16(hello[echOffset:], 0xfe0d)
	if _, err := ReadClientHello(hello[:echOffset]); err == nil {
		t.Fatal("accepted SNI before checking trailing ECH extension")
	}
	if _, err := ReadClientHello(hello); !errors.Is(err, errECHClientHello) {
		t.Fatalf("accepted ECH public SNI: %v", err)
	}
	if _, err := SniffTLS(makeTestTLSRecords(hello, echOffset)); !errors.Is(err, errECHClientHello) {
		t.Fatalf("fragmented TLS accepted ECH public SNI: %v", err)
	}
	q := &quicPacketSender{done: make(chan struct{})}
	defer q.close()
	if err := q.addCryptoData(0, hello); err != nil {
		t.Fatal(err)
	}
	if domain, err := q.tryAssemble(); domain != "" || !errors.Is(err, errECHClientHello) {
		t.Fatalf("QUIC accepted ECH public SNI: domain=%q err=%v", domain, err)
	}

	// Malformed lengths after SNI cannot establish absence of ECH either.
	malformed := makeTestClientHello("real.example", 8)
	binary.BigEndian.PutUint16(malformed[len(malformed)-10:], 65535)
	if _, err := ReadClientHello(malformed); err == nil {
		t.Fatal("accepted malformed extension after SNI")
	}
}

func TestECHDoesNotPoisonSharedIPSniffFailureCache(t *testing.T) {
	d, err := NewDispatcher(&Config{Enable: true, ParsePureIp: true, Sniffers: map[ST.Type]SnifferConfig{ST.TLS: {}}})
	if err != nil {
		t.Fatal(err)
	}
	hello := makeTestClientHello("public.example", 8)
	binary.BigEndian.PutUint16(hello[len(hello)-12:], 0xfe0d)
	m := &C.Metadata{NetWork: C.TCP, DstPort: 443, DomainMappingHost: "dns.example"}
	for i := 0; i < 8; i++ {
		raw := &chunkedConn{t: t, chunks: [][]byte{makeTestTLSRecords(hello)}}
		if d.TCPSniff(N.NewBufferedConn(raw), m) || m.SniffHost != "" {
			t.Fatal("ECH replaced DNS hint")
		}
	}
	raw := &chunkedConn{t: t, chunks: [][]byte{makeTestTLSRecords(makeTestClientHello("real.example", 0))}}
	if !d.TCPSniff(N.NewBufferedConn(raw), m) || m.RuleHost() != "real.example" {
		t.Fatal("ECH failures disabled later ordinary TLS sniff")
	}
}

func TestForceDNSMappingIncludesExternalHint(t *testing.T) {
	d, err := NewDispatcher(&Config{Enable: true, ForceDnsMapping: true, Sniffers: map[ST.Type]SnifferConfig{ST.TLS: {}}})
	if err != nil {
		t.Fatal(err)
	}
	m := &C.Metadata{NetWork: C.TCP, DstPort: 443, DomainMappingHandled: true, DomainMappingHost: "wrong.example"}
	raw := &chunkedConn{t: t, chunks: [][]byte{makeTestTLSRecords(makeTestClientHello("actual.example", 0))}}
	if !d.TCPSniff(N.NewBufferedConn(raw), m) || m.RuleHost() != "actual.example" {
		t.Fatal("force-dns-mapping did not correct external DNS hint without parse-pure-ip")
	}
}
