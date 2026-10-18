package domainmapping

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"golang.org/x/net/http2"
)

// A GOAWAY removes a connection from the reusable pool, but the peer need not
// close its TCP socket. Drain such connections explicitly so an idle, orphaned
// socket cannot consume the provider's last connection slot indefinitely.
type drainingPool struct {
	http2.ClientConnPool
	timeout  time.Duration
	mu       sync.Mutex
	draining map[*http2.ClientConn]struct{}
}

func newDrainingPool(pool http2.ClientConnPool, timeout time.Duration) *drainingPool {
	return &drainingPool{ClientConnPool: pool, timeout: timeout, draining: make(map[*http2.ClientConn]struct{})}
}

func (p *drainingPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	// Reacquire for HTTP/2's internal retries as well as initial requests;
	// otherwise several retrying streams can recreate the reservation cycle.
	if admission, _ := req.Context().Value(headerAdmissionKey{}).(*headerAdmission); admission != nil {
		if err := admission.acquire(req.Context()); err != nil {
			return nil, err
		}
	}
	return p.ClientConnPool.GetClientConn(req, addr)
}

func (p *drainingPool) MarkDead(conn *http2.ClientConn) {
	p.ClientConnPool.MarkDead(conn)
	p.mu.Lock()
	if _, draining := p.draining[conn]; draining {
		p.mu.Unlock()
		return
	}
	p.draining[conn] = struct{}{}
	p.mu.Unlock()
	// MarkDead can run on the frame reader. Synchronous shutdown would wait
	// for that same reader to finish existing streams. Deduplicate callbacks
	// so repeated GOAWAY frames cannot start unbounded cleanup goroutines.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
		defer cancel()
		// Shutdown sends a GOAWAY before waiting on ctx. A peer that stopped
		// reading can block that write too, so close the socket at the deadline.
		stop := contextutils.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		_ = conn.Shutdown(ctx)
		_ = conn.Close()
		p.mu.Lock()
		delete(p.draining, conn)
		p.mu.Unlock()
	}()
}
