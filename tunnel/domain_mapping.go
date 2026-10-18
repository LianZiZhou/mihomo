package tunnel

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/component/domainmapping"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var domainMapping domainmapping.Manager

func UpdateDomainMapping(cfg domainmapping.Config) error { return domainMapping.Apply(cfg) }

// lookupDomainMapping runs once before real-IP metadata preprocessing. Explicit
// inbound domains and every address in a fake-IP pool (including missing pool
// entries) retain their existing behavior. A hit is never a dial destination.
func lookupDomainMapping(ctx context.Context, metadata *C.Metadata) bool {
	if metadata.DomainMappingHost != "" || metadata.DomainMappingHandled {
		return true
	}
	runtime := domainMapping.Current()
	if runtime == nil || metadata.Host != "" || !metadata.DstIP.IsValid() || resolver.IsFakeIP(metadata.DstIP) {
		return false
	}
	result, err := runtime.Lookup(ctx, metadata.SrcIP, metadata.DstIP)
	diagnostic := &C.DomainResolution{
		Provider: result.Provider, Source: result.Source, LookupStatus: result.Status,
		Scope: result.Scope, Conflict: result.Conflict, ExpiresAt: result.ExpiresAt,
		DNSExpiresAt: result.DNSExpiresAt, DNSStale: result.DNSStale, RetentionMode: result.RetentionMode,
		CandidateCount: result.Total, Complete: result.Complete, Generation: result.Generation, Reason: result.Reason,
	}
	metadata.DomainResolution = diagnostic
	if err != nil {
		diagnostic.LookupStatus = "error"
		if errors.Is(err, context.DeadlineExceeded) {
			diagnostic.LookupStatus = "timeout"
		} else if errors.Is(err, context.Canceled) {
			diagnostic.LookupStatus = "canceled"
		} else if errors.Is(err, domainmapping.ErrOverloaded) {
			diagnostic.LookupStatus = "overloaded"
		} else if errors.Is(err, domainmapping.ErrRetired) {
			diagnostic.LookupStatus = "retired"
		}
		log.Debugln("[Domain Mapping] lookup %s -> %s failed: %s", metadata.SrcIP, metadata.DstIP, err)
		return false
	}
	if result.Status == "ambiguous" {
		metadata.DomainMappingHandled = true
		metadata.DomainMappingCandidates = result.Domains
		metadata.DomainMappingPolicy, metadata.DomainMappingFallback = runtime.ConflictPolicy()
		return true
	}
	if result.Status != "hit" {
		return false
	}
	metadata.DomainMappingHost = result.Domain
	metadata.DomainMappingHandled = true
	return true
}

// prepareUDPDomain runs in the first NAT session's dial goroutine, never the
// public packet receive loop. SkipSniff releases only sniff state; the sender
// continues to own and deliver every queued datagram.
func prepareUDPDomain(metadata *C.Metadata, sender C.PacketSender) error {
	if lookupDomainMapping(context.Background(), metadata) {
		if skipper, ok := sender.(interface{ SkipSniff() }); ok {
			skipper.SkipSniff()
		}
	} else if err := sender.DoSniff(metadata); err != nil {
		return err
	}
	return preHandleMetadata(metadata)
}
