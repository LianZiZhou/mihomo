package domainmapping

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type lookupKey struct {
	client      netip.Addr
	destination netip.Addr
}

type flight struct {
	done     chan struct{}
	deadline time.Time
	result   Result
	err      error
}

// Runtime shares only concurrent requests. Completed results, including misses
// and failures, are never cached: a DNS answer may change an IP's ownership
// while the previous answer's TTL is still valid.
type Runtime struct {
	providers []Provider
	timeout   time.Duration
	mu        sync.Mutex
	flights   map[lookupKey]*flight
	retired   atomic.Bool
}

func New(cfg Config) (*Runtime, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	if !cfg.Enable {
		return nil, nil
	}
	runtime := &Runtime{
		timeout: time.Duration(cfg.Timeout) * time.Millisecond,
		flights: make(map[lookupKey]*flight),
	}
	if runtime.timeout == 0 {
		runtime.timeout = DefaultTimeout
	}
	for _, cfg := range cfg.Providers {
		runtime.providers = append(runtime.providers, newHTTPProvider(cfg))
	}
	return runtime, nil
}

func (r *Runtime) Lookup(ctx context.Context, clientIP, destinationIP netip.Addr) (Result, error) {
	if r == nil {
		return Result{Status: "disabled"}, nil
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !destinationIP.IsValid() {
		return Result{}, errors.New("domain-mapping destination IP is invalid")
	}
	deadline := time.Now().Add(r.timeout)
	key := lookupKey{client: clientIP.Unmap(), destination: destinationIP.Unmap()}
	r.mu.Lock()
	f, exists := r.flights[key]
	if !exists || !time.Now().Before(f.deadline) {
		// A provider that is still finishing after its deadline must not make
		// a later request inherit an already expired flight.
		f = &flight{done: make(chan struct{}), deadline: deadline}
		r.flights[key] = f
		go r.lookup(key, f)
	}
	r.mu.Unlock()
	// Bound the wait independently of provider I/O and CPU work. Canceling
	// this context affects this caller only, never the shared provider call.
	waitCtx, cancel := context.WithDeadline(ctx, f.deadline)
	defer cancel()
	select {
	case <-waitCtx.Done():
		return Result{}, waitCtx.Err()
	case <-f.done:
		if err := lookupContextError(waitCtx); err != nil {
			return Result{}, err
		}
		result := f.result
		// Callers own the returned slice; concurrent consumers cannot mutate
		// each other's evidence after the flight has completed. The HTTP
		// provider skips candidates; custom providers may still supply them.
		result.Candidates = append([]Candidate(nil), result.Candidates...)
		if err := lookupContextError(waitCtx); err != nil {
			return Result{}, err
		}
		return result, f.err
	}
}

func (r *Runtime) lookup(key lookupKey, f *flight) {
	// A caller's cancellation must not abort another caller's shared lookup.
	// All providers together share one bounded lookup budget.
	ctx, cancel := context.WithDeadline(context.Background(), f.deadline)
	defer cancel()
	f.result = Result{Status: "miss", IP: key.destination.String()}
	for _, provider := range r.providers {
		if err := lookupContextError(ctx); err != nil {
			f.err = err
			break
		}
		result, err := provider.Lookup(ctx, key.client, key.destination)
		if budgetErr := lookupContextError(ctx); budgetErr != nil {
			f.err = budgetErr
			break
		}
		if err == nil && result.Status == "hit" {
			f.result, f.err = result, nil
			break
		}
		if err != nil {
			f.result, f.err = result, err
		} else if f.err == nil {
			f.result = result
		}
	}
	r.mu.Lock()
	if r.flights[key] == f {
		delete(r.flights, key)
	}
	close(f.done)
	r.mu.Unlock()
	if r.retired.Load() {
		r.closeIdleConnections()
	}
}

// Retire releases idle HTTP connections without canceling lookups that already
// hold this runtime. Their connections are released again when they finish.
func (r *Runtime) Retire() {
	if r != nil {
		r.retired.Store(true)
		r.closeIdleConnections()
	}
}

func (r *Runtime) closeIdleConnections() {
	for _, provider := range r.providers {
		provider.CloseIdleConnections()
	}
}

// Manager can be swapped independently of the built-in DNS host mapper.
// Its zero value is disabled and ready to use.
type Manager struct {
	current atomic.Pointer[Runtime]
}

func (m *Manager) Apply(cfg Config) error {
	next, err := New(cfg)
	if err != nil {
		return err
	}
	m.current.Swap(next).Retire()
	return nil
}

func (m *Manager) Current() *Runtime { return m.current.Load() }
