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

var (
	ErrOverloaded = errors.New("domain-mapping maximum in-flight lookups reached")
	ErrRetired    = errors.New("domain-mapping runtime has been retired")
)

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
	providers   []Provider
	timeout     time.Duration
	maxInflight int
	active      int
	mu          sync.Mutex
	flights     map[lookupKey]*flight
	retired     atomic.Bool
}

func New(cfg Config) (*Runtime, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	if !cfg.Enable {
		return nil, nil
	}
	runtime := &Runtime{
		timeout:     time.Duration(cfg.Timeout) * time.Millisecond,
		flights:     make(map[lookupKey]*flight),
		maxInflight: cfg.MaxInflight,
	}
	if runtime.timeout == 0 {
		runtime.timeout = DefaultTimeout
	}
	if runtime.maxInflight == 0 {
		runtime.maxInflight = DefaultMaxInflight
	}
	maxConnections := cfg.MaxConnections
	if maxConnections == 0 {
		maxConnections = DefaultMaxConnections
	}
	for _, cfg := range cfg.Providers {
		provider, err := newHTTPProvider(cfg, runtime.timeout, maxConnections)
		if err != nil {
			runtime.Retire()
			return nil, err
		}
		runtime.providers = append(runtime.providers, provider)
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
	if r.retired.Load() {
		r.mu.Unlock()
		return Result{Status: "retired"}, ErrRetired
	}
	f, exists := r.flights[key]
	if !exists || !time.Now().Before(f.deadline) {
		if r.active >= r.maxInflight {
			r.mu.Unlock()
			return Result{Status: "overloaded"}, ErrOverloaded
		}
		// A provider that is still finishing after its deadline must not make
		// a later request inherit an already expired flight. It continues to
		// consume capacity until it returns, even after a successor replaces
		// its map entry, so uncooperative providers cannot grow without bound.
		f = &flight{done: make(chan struct{}), deadline: deadline}
		r.flights[key] = f
		r.active++
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
	r.active--
	if r.flights[key] == f {
		delete(r.flights, key)
	}
	close(f.done)
	r.mu.Unlock()
	if r.retired.Load() {
		r.releaseConnections()
	}
}

// Retire stops admitting new lookups and releases idle HTTP connections without
// canceling existing lookups. Their connections are released again at completion.
func (r *Runtime) Retire() {
	if r != nil {
		r.mu.Lock()
		r.retired.Store(true)
		r.mu.Unlock()
		r.releaseConnections()
	}
}

func (r *Runtime) releaseConnections() {
	r.mu.Lock()
	finished := r.retired.Load() && r.active == 0
	r.mu.Unlock()
	for _, provider := range r.providers {
		if closer, ok := provider.(interface{ Close() }); ok && finished {
			closer.Close()
		} else {
			provider.CloseIdleConnections()
		}
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
