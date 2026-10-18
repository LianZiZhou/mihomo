package domainmapping

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countedCloseConn struct {
	net.Conn
	closes atomic.Int32
	err    error
}

func (c *countedCloseConn) Close() error {
	c.closes.Add(1)
	_ = c.Conn.Close()
	return c.err
}

func pipeDial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(context.Context, string, string) (net.Conn, error) {
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = remote.Close() })
		return local, nil
	}
}

func TestConnectionLimiterWaitsForSocketClose(t *testing.T) {
	limiter := newConnectionLimiter(1)
	t.Cleanup(func() { _ = limiter.Close() })
	first, err := limiter.DialContext(context.Background(), "tcp", "first", pipeDial(t))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	var dials atomic.Int32
	go func() {
		close(started)
		second, err := limiter.DialContext(context.Background(), "tcp", "second", func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return pipeDial(t)(ctx, network, address)
		})
		if err == nil {
			err = second.Close()
		}
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("second dial passed the occupied socket limit: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if dials.Load() != 0 {
		t.Fatal("dial callback ran before a socket slot was released")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("socket close did not release the next dial")
	}
}

func TestConnectionLimiterWaitDeadlineAndDialFailure(t *testing.T) {
	limiter := newConnectionLimiter(1)
	t.Cleanup(func() { _ = limiter.Close() })
	first, err := limiter.DialContext(context.Background(), "tcp", "first", pipeDial(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = limiter.DialContext(ctx, "tcp", "waiting", func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("expired queue entry reached the dialer")
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queue error = %v", err)
	}
	_ = first.Close()
	wantErr := errors.New("dial failure")
	_, err = limiter.DialContext(context.Background(), "tcp", "failure", func(context.Context, string, string) (net.Conn, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("dial error = %v", err)
	}
	next, err := limiter.DialContext(context.Background(), "tcp", "next", pipeDial(t))
	if err != nil {
		t.Fatalf("queue cancellation or dial failure leaked a slot: %v", err)
	}
	_ = next.Close()
}

func TestConnectionLimiterCloseOnce(t *testing.T) {
	limiter := newConnectionLimiter(1)
	t.Cleanup(func() { _ = limiter.Close() })
	local, remote := net.Pipe()
	defer remote.Close()
	wantErr := errors.New("close failure")
	raw := &countedCloseConn{Conn: local, err: wantErr}
	conn, err := limiter.DialContext(context.Background(), "tcp", "first", func(context.Context, string, string) (net.Conn, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := conn.Close(); !errors.Is(err, wantErr) {
				t.Errorf("close error = %v", err)
			}
		}()
	}
	group.Wait()
	if raw.closes.Load() != 1 {
		t.Fatalf("underlying Close ran %d times", raw.closes.Load())
	}
	next, err := limiter.DialContext(context.Background(), "tcp", "next", pipeDial(t))
	if err != nil {
		t.Fatalf("close failure leaked the socket slot: %v", err)
	}
	_ = next.Close()
}

func TestConnectionLimiterTerminalClose(t *testing.T) {
	limiter := newConnectionLimiter(1)
	local, remote := net.Pipe()
	defer remote.Close()
	raw := &countedCloseConn{Conn: local}
	_, err := limiter.DialContext(context.Background(), "tcp", "first", func(context.Context, string, string) (net.Conn, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := limiter.DialContext(context.Background(), "tcp", "waiting", func(context.Context, string, string) (net.Conn, error) {
			t.Error("terminally closed limiter called the dialer")
			return nil, nil
		})
		done <- err
	}()
	if err := limiter.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrRetired) {
			t.Fatalf("waiting dial error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal close did not cancel a waiting dial")
	}
	if raw.closes.Load() != 1 {
		t.Fatalf("terminal close left the connection open: closes=%d", raw.closes.Load())
	}
	_, err = limiter.DialContext(context.Background(), "tcp", "late", pipeDial(t))
	if !errors.Is(err, ErrRetired) {
		t.Fatalf("new dial after terminal close = %v", err)
	}
}

func TestConnectionLimiterRetainsDialContextAndCancelsOnClose(t *testing.T) {
	type contextKey struct{}
	limiter := newConnectionLimiter(1)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), contextKey{}, "preserved"), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := limiter.DialContext(ctx, "tcp", "first", func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			if dialCtx.Value(contextKey{}) != "preserved" {
				t.Error("dial lost request context values")
			}
			if got, ok := dialCtx.Deadline(); !ok || got != deadline {
				t.Errorf("dial deadline = %v, want %v", got, deadline)
			}
			close(started)
			<-dialCtx.Done()
			return nil, dialCtx.Err()
		})
		done <- err
	}()
	<-started
	_ = limiter.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRetired) {
			t.Fatalf("in-progress dial error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal close did not cancel in-progress dial")
	}
}

func TestConnectionLimiterRejectsLateDialCompletion(t *testing.T) {
	limiter := newConnectionLimiter(1)
	local, remote := net.Pipe()
	defer remote.Close()
	raw := &countedCloseConn{Conn: local}
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := limiter.DialContext(context.Background(), "tcp", "late", func(context.Context, string, string) (net.Conn, error) {
			close(started)
			<-release // Deliberately ignore cancellation to exercise registration.
			return raw, nil
		})
		done <- err
	}()
	<-started
	_ = limiter.Close()
	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, ErrRetired) {
			t.Fatalf("late successful dial error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("late dial did not return")
	}
	if raw.closes.Load() != 1 {
		t.Fatalf("late socket escaped terminal close: closes=%d", raw.closes.Load())
	}
	limiter.mu.Lock()
	registered := len(limiter.connections)
	limiter.mu.Unlock()
	if registered != 0 {
		t.Fatalf("terminal limiter retained %d connections", registered)
	}
	if !limiter.slots.TryAcquire(1) {
		t.Fatal("late dial leaked its socket slot")
	}
	limiter.slots.Release(1)
}

func TestConnectionLimiterRejectsCanceledDialSuccess(t *testing.T) {
	limiter := newConnectionLimiter(1)
	t.Cleanup(func() { _ = limiter.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, remote := net.Pipe()
	defer remote.Close()
	raw := &countedCloseConn{Conn: local}
	_, err := limiter.DialContext(ctx, "tcp", "canceled", func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return raw, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dial returned %v", err)
	}
	if raw.closes.Load() != 1 {
		t.Fatalf("canceled dial left the socket open: closes=%d", raw.closes.Load())
	}
	next, err := limiter.DialContext(context.Background(), "tcp", "next", pipeDial(t))
	if err != nil {
		t.Fatalf("canceled successful dial leaked the socket slot: %v", err)
	}
	_ = next.Close()
}
