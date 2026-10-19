// Package domainmapping supplies rule-only domain evidence for real-IP flows.
// It is independent of Mihomo's DNS server and fake-IP address management.
package domainmapping

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	M "github.com/metacubex/sing/common/metadata"
	"golang.org/x/net/http2"
	"golang.org/x/sync/semaphore"
)

const (
	DefaultTimeout        = 50 * time.Millisecond
	DefaultMaxConnections = 16
	DefaultMaxInflight    = 128
)

type Config struct {
	Enable           bool             `yaml:"enable" json:"enable"`
	Timeout          int              `yaml:"timeout" json:"timeout"`                 // milliseconds; zero uses DefaultTimeout
	MaxConnections   int              `yaml:"max-connections" json:"max-connections"` // per HTTP provider; zero uses DefaultMaxConnections
	MaxInflight      int              `yaml:"max-inflight" json:"max-inflight"`       // runtime work, including timed-out work still finishing
	ConflictPolicy   string           `yaml:"conflict-policy" json:"conflict-policy"`
	ConflictFallback string           `yaml:"conflict-fallback" json:"conflict-fallback"`
	Providers        []ProviderConfig `yaml:"providers" json:"providers"`
}

type ProviderConfig struct {
	Name     string `yaml:"name" json:"name"`
	Type     string `yaml:"type" json:"type"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
}

// Provider implementations must observe ctx and return evidence without
// changing the destination address. Runtime owns timeouts and request sharing.
// Runtime can stop waiting but cannot stop a provider's goroutine; providers
// must also bound their own work and release resources after cancellation.
type Provider interface {
	Lookup(ctx context.Context, clientIP, destinationIP netip.Addr) (Result, error)
	CloseIdleConnections()
}

type Candidate struct {
	Domain        string     `json:"domain"`
	Source        string     `json:"source,omitempty"`
	ObservedAt    time.Time  `json:"observed_at,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at,omitempty"`
	DNSExpiresAt  *time.Time `json:"dns_expires_at,omitempty"`
	DNSStale      bool       `json:"dns_stale,omitempty"`
	RetentionMode string     `json:"retention_mode,omitempty"`
}

type Result struct {
	Version    int       `json:"version"`
	Status     string    `json:"status"`
	IP         string    `json:"ip"`
	Domain     string    `json:"domain,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	Source     string    `json:"source,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	// DNS freshness is diagnostic. ExpiresAt remains the routing lease checked
	// below; an expired DNS answer can still be retained by the provider's LRU.
	DNSExpiresAt  *time.Time  `json:"dns_expires_at,omitempty"`
	DNSStale      bool        `json:"dns_stale,omitempty"`
	RetentionMode string      `json:"retention_mode,omitempty"`
	Conflict      bool        `json:"conflict"`
	Candidates    []Candidate `json:"candidates,omitempty"`
	Provider      string      `json:"-"`
	Domains       []string    `json:"domains,omitempty"`
	Complete      bool        `json:"complete"`
	Total         int         `json:"total"`
	Generation    uint64      `json:"generation"`
	Reason        string      `json:"reason,omitempty"`
	// V3 retains a latest-DNS hint in a small LRU independently of allocation
	// recovery. Completeness describes recent conflict evidence, not identity.
	CandidatesComplete   bool `json:"candidates_complete"`
	AllocationRecovering bool `json:"allocation_recovering,omitempty"`
}

func Validate(cfg Config) error {
	if cfg.ConflictPolicy != "" && cfg.ConflictPolicy != "proxy-preferred" && cfg.ConflictPolicy != "rule-priority" {
		return errors.New("domain-mapping conflict-policy must be proxy-preferred or rule-priority")
	}
	if cfg.Timeout < 0 || int64(cfg.Timeout) > int64((1<<63-1)/time.Millisecond) {
		return errors.New("domain-mapping timeout must be a non-negative duration in milliseconds")
	}
	if cfg.MaxConnections < 0 || cfg.MaxInflight < 0 {
		return errors.New("domain-mapping max-connections and max-inflight must be non-negative")
	}
	if cfg.Enable && len(cfg.Providers) == 0 {
		return errors.New("domain-mapping requires at least one provider when enabled")
	}
	names := make(map[string]struct{}, len(cfg.Providers))
	native, legacy := false, false
	for _, provider := range cfg.Providers {
		if strings.TrimSpace(provider.Name) == "" {
			return errors.New("domain-mapping provider name is required")
		}
		if _, exists := names[provider.Name]; exists {
			return fmt.Errorf("duplicate domain-mapping provider name %q", provider.Name)
		}
		names[provider.Name] = struct{}{}
		if provider.Type != "mosdns-http-v1" && provider.Type != "mosdns-http-v2" && provider.Type != "mosdns-http-v3" {
			return fmt.Errorf("unsupported domain-mapping provider type %q", provider.Type)
		}
		if provider.Type == "mosdns-http-v3" {
			native = true
		} else {
			legacy = true
		}
		endpoint, err := url.Parse(provider.Endpoint)
		if err != nil || endpoint == nil || endpoint.Hostname() == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.Fragment != "" {
			return fmt.Errorf("domain-mapping provider %q requires an HTTP(S) endpoint without userinfo or a fragment", provider.Name)
		}
	}
	if native && (legacy || cfg.ConflictPolicy != "" || cfg.ConflictFallback != "") {
		return errors.New("domain-mapping v3 cannot mix legacy providers or conflict-policy/conflict-fallback; ambiguity follows original rules")
	}
	return nil
}

type httpProvider struct {
	name        string
	version     int
	endpoint    *url.URL
	client      *http.Client
	transport   *http.Transport
	h2Idle      *http2.Transport
	connections *connectionLimiter
	connectGate *semaphore.Weighted
}

func newHTTPProvider(cfg ProviderConfig, timeout time.Duration, maxConnections int) (*httpProvider, error) {
	endpoint, _ := url.Parse(cfg.Endpoint) // validated by New
	// The bridge must not depend on system HTTP proxy configuration or itself
	// enter Mihomo's proxy-selection path. Own the transport and its protocol
	// registrations instead of inheriting a mutable global DefaultTransport.
	transport := &http.Transport{
		MaxConnsPerHost: maxConnections, MaxIdleConnsPerHost: maxConnections,
		MaxIdleConns: maxConnections, IdleConnTimeout: 90 * time.Second,
		DisableCompression: true, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: timeout, ExpectContinueTimeout: time.Second,
	}
	h2, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, fmt.Errorf("configure domain-mapping HTTP/2: %w", err)
	}
	// MaxConnsPerHost alone does not bound HTTP/2 sockets. When a stream is
	// unavailable, wait on the existing connection using the request context;
	// dialing behind a socket semaphore alone would strand these requests.
	h2.StrictMaxConcurrentStreams = true
	pool := h2.ConnPool
	h2.ConnPool = newDrainingPool(pool, timeout)
	// The original pool has a private idle-close hook. Keep an explicit handle
	// to it because the lifecycle wrapper cannot implement that private method.
	h2Idle := &http2.Transport{ConnPool: pool}
	connections := newConnectionLimiter(maxConnections)
	// A request deadline does not normally cancel Transport's detached dial.
	// Restore the lookup lifetime for both TCP establishment and TLS handshakes.
	// Disable speculative IPv4/IPv6 racing: one acquired socket slot must not
	// create two simultaneous TCP connection attempts inside net.Dialer.
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, FallbackDelay: -1}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := restoreDialContext(ctx, timeout)
		defer cancel()
		return connections.DialContext(ctx, network, address, dialer.DialContext)
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := restoreDialContext(ctx, timeout)
		defer cancel()
		conn, err := connections.DialContext(ctx, network, address, dialer.DialContext)
		if err != nil {
			return nil, err
		}
		tlsConfig := &tls.Config{}
		if transport.TLSClientConfig != nil {
			tlsConfig = transport.TLSClientConfig.Clone()
		}
		tlsConfig.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = endpoint.Hostname()
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	version := 1
	if cfg.Type == "mosdns-http-v2" {
		version = 2
	} else if cfg.Type == "mosdns-http-v3" {
		version = 3
	}
	return &httpProvider{
		name: cfg.Name, version: version, endpoint: endpoint, transport: transport,
		h2Idle: h2Idle, connections: connections, connectGate: semaphore.NewWeighted(1),
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("domain-mapping redirects are not supported")
			},
		},
	}, nil
}

func (p *httpProvider) CloseIdleConnections() {
	p.transport.CloseIdleConnections()
	p.h2Idle.CloseIdleConnections()
}

// Close is terminal and is called only after a retired runtime has no admitted
// lookups left. It also covers connections removed from the HTTP/2 idle pool.
func (p *httpProvider) Close() {
	p.connections.Close()
	p.CloseIdleConnections()
}

type lookupBudgetContextKey struct{}

// Transport preserves values when detaching a dial from request cancellation.
// Retain the original shared lookup context as a value, then restore its
// cancellation and absolute deadline here. The fallback also bounds direct
// provider calls that did not originate in Runtime.
func restoreDialContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(timeout)
	original, _ := ctx.Value(lookupBudgetContextKey{}).(context.Context)
	if original != nil {
		if originalDeadline, ok := original.Deadline(); ok && originalDeadline.Before(deadline) {
			deadline = originalDeadline
		}
	}
	bound, cancel := context.WithDeadline(ctx, deadline)
	if original == nil {
		return bound, cancel
	}
	stop := contextutils.AfterFunc(original, cancel)
	if original.Err() != nil {
		cancel()
	}
	return bound, func() { stop(); cancel() }
}

// lookupContextError also checks the absolute deadline: a CPU-heavy decode can
// finish before the context timer goroutine gets scheduled to publish Err().
func lookupContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// Candidate lists are diagnostic API data. Rules use only the selected domain,
// so validate the JSON syntax without allocating or decoding every candidate.
type ignoredCandidates struct{}

func (*ignoredCandidates) UnmarshalJSON([]byte) error { return nil }

func (p *httpProvider) Lookup(ctx context.Context, clientIP, destinationIP netip.Addr) (Result, error) {
	result := Result{Provider: p.name}
	endpoint := *p.endpoint
	query := endpoint.Query()
	query.Set("ip", destinationIP.Unmap().String())
	if p.version >= 2 {
		query.Del("view")
	} else {
		query.Set("view", "route")
	}
	query.Del("client")
	if clientIP.IsValid() {
		query.Set("client", clientIP.Unmap().String())
	}
	endpoint.RawQuery = query.Encode()
	reqCtx := context.WithValue(ctx, lookupBudgetContextKey{}, ctx)
	if endpoint.Scheme == "https" {
		admission := &headerAdmission{gate: p.connectGate}
		if err := admission.acquire(ctx); err != nil {
			return result, err
		}
		defer admission.release()
		reqCtx = context.WithValue(reqCtx, headerAdmissionKey{}, admission)
		reqCtx = httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
			GotConn: admission.gotConn, WroteHeaders: admission.wroteHeaders,
			GotFirstResponseByte: admission.release,
		})
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Accept", "application/json")
	response, err := p.client.Do(req)
	if admission, _ := reqCtx.Value(headerAdmissionKey{}).(*headerAdmission); admission != nil {
		admission.release()
	}
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("domain-mapping provider %q returned HTTP %d", p.name, response.StatusCode)
	}
	const maxResponseSize = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return result, err
	}
	if len(body) > maxResponseSize {
		return result, errors.New("domain-mapping response exceeds 1 MiB")
	}
	if err := lookupContextError(ctx); err != nil {
		return result, err
	}
	// Shadow only the wire candidates field; keep Result's public structure
	// and JSON behavior unchanged for callers and custom provider extensions.
	type resultJSON Result
	wire := struct {
		*resultJSON
		Candidates ignoredCandidates `json:"candidates"`
	}{resultJSON: (*resultJSON)(&result)}
	if err = json.Unmarshal(body, &wire); err != nil {
		return result, fmt.Errorf("invalid domain-mapping JSON: %w", err)
	}
	if err := lookupContextError(ctx); err != nil {
		return result, err
	}
	if result.Version != p.version {
		return result, fmt.Errorf("unsupported domain-mapping response version %d", result.Version)
	}
	ip, err := netip.ParseAddr(result.IP)
	if err != nil || ip.Unmap() != destinationIP.Unmap() {
		return result, errors.New("domain-mapping response IP does not match query")
	}
	if p.version == 3 {
		if err := validateV3(&result, clientIP); err != nil {
			return result, err
		}
		return result, lookupContextError(ctx)
	}
	if p.version == 2 {
		if err := validateV2(&result, clientIP); err != nil {
			return result, err
		}
		return result, lookupContextError(ctx)
	}
	switch result.Status {
	case "miss":
		result.Domain = ""
	case "hit":
		result.Domain = strings.ToLower(strings.TrimSuffix(result.Domain, "."))
		if !validDomain(result.Domain) || (result.Scope != "client" && result.Scope != "global") {
			return result, errors.New("invalid domain-mapping domain or scope")
		}
		if result.ExpiresAt.IsZero() || !result.ExpiresAt.After(time.Now()) {
			return result, errors.New("domain-mapping response is missing its expiry or has expired")
		}
	default:
		return result, fmt.Errorf("invalid domain-mapping response status %q", result.Status)
	}
	if err := lookupContextError(ctx); err != nil {
		return result, err
	}
	return result, nil
}

// V2 separates a unique host from ambiguous attribution. Truncated/unknown
// ownership is usable only by the explicitly configured conflict fallback.
func validateV2(result *Result, clientIP netip.Addr) error {
	if result.Total < 0 || len(result.Domains) > 1024 || result.Total < len(result.Domains) {
		return errors.New("invalid domain-mapping candidate counts")
	}
	if result.Status == "miss" {
		if result.Domain != "" || len(result.Domains) != 0 || result.Total != 0 {
			return errors.New("domain-mapping miss contains domain evidence")
		}
		return nil
	}
	if result.Scope != "client" && result.Scope != "global" {
		return errors.New("invalid domain-mapping scope")
	}
	if result.Scope == "client" && !clientIP.IsValid() {
		return errors.New("client-scoped evidence without a client query")
	}
	if result.ExpiresAt.IsZero() || !result.ExpiresAt.After(time.Now()) {
		return errors.New("domain-mapping response is missing its expiry or has expired")
	}
	seen := make(map[string]struct{}, len(result.Domains))
	for i, domain := range result.Domains {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if !validDomain(domain) {
			return errors.New("invalid domain-mapping candidate domain")
		}
		if _, exists := seen[domain]; exists {
			return errors.New("duplicate domain-mapping candidate")
		}
		seen[domain] = struct{}{}
		result.Domains[i] = domain
	}
	switch result.Status {
	case "hit":
		result.Domain = strings.ToLower(strings.TrimSuffix(result.Domain, "."))
		if !validDomain(result.Domain) || !result.Complete || result.Total != 1 || result.Conflict || (len(result.Domains) != 0 && (len(result.Domains) != 1 || result.Domains[0] != result.Domain)) {
			return errors.New("invalid unique domain-mapping evidence")
		}
	case "ambiguous":
		if result.Domain != "" || (result.Complete && (result.Total != len(result.Domains) || result.Total < 2)) {
			return errors.New("invalid ambiguous domain-mapping evidence")
		}
		result.Conflict = true
	default:
		return fmt.Errorf("invalid domain-mapping response status %q", result.Status)
	}
	return nil
}

func validDomain(domain string) bool {
	if domain == "" || domain == "." || !M.IsDomainName(domain) {
		return false
	}
	_, err := netip.ParseAddr(domain)
	return err != nil
}
