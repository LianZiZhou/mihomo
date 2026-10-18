package domainmapping

import (
	"context"
	"crypto/tls"
	"net/http/httptrace"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/sync/semaphore"
)

type headerAdmissionKey struct{}

// Serialize only the reservation/header stage. With StrictMaxConcurrentStreams,
// x/net can count later reservations against an earlier request waiting for a
// stream slot, while those later requests wait for its header lock (#70809).
// Once headers are sent, active streams can run concurrently as usual.
type headerAdmission struct {
	gate *semaphore.Weighted
	mu   sync.Mutex
	held bool
	cold bool
}

func (a *headerAdmission) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	held := a.held
	a.mu.Unlock()
	if held {
		return nil
	}
	if err := a.gate.Acquire(ctx, 1); err != nil {
		return err
	}
	a.mu.Lock()
	a.held, a.cold = true, false
	a.mu.Unlock()
	return nil
}

func (a *headerAdmission) gotConn(info httptrace.GotConnInfo) {
	conn, tlsConn := info.Conn.(*tls.Conn)
	a.mu.Lock()
	// Before the first response on a new HTTP/2 connection, the server's
	// SETTINGS might not have arrived. Keep that first reservation alone;
	// a response proves SETTINGS were processed, without an extra probe RTT.
	a.cold = !info.Reused && tlsConn && conn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS
	a.mu.Unlock()
}

func (a *headerAdmission) wroteHeaders() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cold {
		a.releaseLocked()
	}
}

func (a *headerAdmission) release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseLocked()
}

func (a *headerAdmission) releaseLocked() {
	if a.held {
		a.held = false
		a.gate.Release(1)
	}
}
