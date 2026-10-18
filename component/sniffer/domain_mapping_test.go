package sniffer

import (
	"testing"

	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
)

type skipTestSender struct {
	C.PacketSender
	closed  bool
	sniffed bool
}

func (s *skipTestSender) Close() { s.closed = true }
func (s *skipTestSender) DoSniff(*C.Metadata) error {
	s.sniffed = true
	return nil
}

func TestQUICSkipSniffReleasesStateWithoutClosingSender(t *testing.T) {
	base := &skipTestSender{}
	q := &quicPacketSender{
		PacketSender: base, done: make(chan struct{}), result: "outer-ech.example",
		buffer:        pool.Get(512),
		replaceDomain: func(*C.Metadata, string) { t.Error("skipped QUIC result replaced mapping evidence") },
	}
	q.SkipSniff()
	if !q.closed || !q.skipped || q.buffer != nil || base.closed {
		t.Fatal("SkipSniff did not release only sniff state")
	}
	q.result = "late-quic-result.example" // a decode may have completed concurrently
	if err := q.DoSniff(&C.Metadata{DomainMappingHost: "dns.example"}); err != nil {
		t.Fatal(err)
	}
	if !base.sniffed || base.closed {
		t.Fatal("underlying sender was not retained")
	}
	q.SkipSniff() // idempotent, including a completed sniff
}
