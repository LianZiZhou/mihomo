package domainmapping

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/contextutils"
	"golang.org/x/sync/semaphore"
)

// connectionLimiter counts both pending dials and live underlying TCP
// connections. A transport may stop counting an HTTP/2 connection after its
// protocol handoff, so the socket lifetime is the authoritative limit.
type connectionLimiter struct {
	slots  *semaphore.Weighted
	ctx    context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	closed      bool
	connections map[*limitedConnection]struct{}
}

func newConnectionLimiter(limit int) *connectionLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	return &connectionLimiter{
		slots: semaphore.NewWeighted(int64(limit)), ctx: ctx, cancel: cancel,
		connections: make(map[*limitedConnection]struct{}),
	}
}

func (l *connectionLimiter) DialContext(ctx context.Context, network, address string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Keep the request's values and absolute deadline while also canceling a
	// queued or in-progress dial when this provider is permanently closed.
	dialCtx, cancel := context.WithCancel(ctx)
	stop := contextutils.AfterFunc(l.ctx, cancel)
	defer func() { stop(); cancel() }()
	if l.ctx.Err() != nil {
		return nil, ErrRetired
	}
	if err := l.slots.Acquire(dialCtx, 1); err != nil {
		if l.ctx.Err() != nil {
			return nil, ErrRetired
		}
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			l.slots.Release(1)
		}
	}()
	if err := dialCtx.Err(); err != nil {
		if l.ctx.Err() != nil {
			return nil, ErrRetired
		}
		return nil, err
	}
	conn, err := dial(dialCtx, network, address)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		if l.ctx.Err() != nil {
			return nil, ErrRetired
		}
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("domain-mapping dial returned a nil connection")
	}
	limited := &limitedConnection{Conn: conn, owner: l}
	l.mu.Lock()
	// Registration and permanent close share the lock: a dial completing
	// after shutdown must never leave an untracked live socket behind.
	if l.closed || dialCtx.Err() != nil {
		closed := l.closed
		l.mu.Unlock()
		_ = conn.Close()
		if closed {
			return nil, ErrRetired
		}
		return nil, dialCtx.Err()
	}
	l.connections[limited] = struct{}{}
	owned = false // The connection now owns this slot until Close completes.
	l.mu.Unlock()
	return limited, nil
}

// Close permanently retires the limiter. Unlike closing a transport's idle
// pool, this also closes sockets removed from that pool by an HTTP/2 GOAWAY.
func (l *connectionLimiter) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.cancel()
	connections := make([]*limitedConnection, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	var err error
	for _, conn := range connections {
		err = errors.Join(err, conn.Close())
	}
	return err
}

type limitedConnection struct {
	net.Conn
	owner *connectionLimiter
	once  sync.Once
	err   error
}

func (c *limitedConnection) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
		c.owner.slots.Release(1)
	})
	return c.err
}
