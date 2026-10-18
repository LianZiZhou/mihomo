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
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	M "github.com/metacubex/sing/common/metadata"
)

const (
	DefaultTimeout        = 50 * time.Millisecond
	DefaultMaxConnections = 16
	DefaultMaxInflight    = 128
)

type Config struct {
	Enable         bool             `yaml:"enable" json:"enable"`
	Timeout        int              `yaml:"timeout" json:"timeout"`                 // milliseconds; zero uses DefaultTimeout
	MaxConnections int              `yaml:"max-connections" json:"max-connections"` // per HTTP provider; zero uses DefaultMaxConnections
	MaxInflight    int              `yaml:"max-inflight" json:"max-inflight"`       // runtime work, including timed-out work still finishing
	Providers      []ProviderConfig `yaml:"providers" json:"providers"`
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
	Domain     string    `json:"domain"`
	Source     string    `json:"source,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

type Result struct {
	Version    int         `json:"version"`
	Status     string      `json:"status"`
	IP         string      `json:"ip"`
	Domain     string      `json:"domain,omitempty"`
	Scope      string      `json:"scope,omitempty"`
	Source     string      `json:"source,omitempty"`
	ObservedAt time.Time   `json:"observed_at,omitempty"`
	ExpiresAt  time.Time   `json:"expires_at,omitempty"`
	Conflict   bool        `json:"conflict"`
	Candidates []Candidate `json:"candidates,omitempty"`
	Provider   string      `json:"-"`
}

func Validate(cfg Config) error {
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
	for _, provider := range cfg.Providers {
		if strings.TrimSpace(provider.Name) == "" {
			return errors.New("domain-mapping provider name is required")
		}
		if _, exists := names[provider.Name]; exists {
			return fmt.Errorf("duplicate domain-mapping provider name %q", provider.Name)
		}
		names[provider.Name] = struct{}{}
		if provider.Type != "mosdns-http-v1" {
			return fmt.Errorf("unsupported domain-mapping provider type %q", provider.Type)
		}
		endpoint, err := url.Parse(provider.Endpoint)
		if err != nil || endpoint == nil || endpoint.Hostname() == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.Fragment != "" {
			return fmt.Errorf("domain-mapping provider %q requires an HTTP(S) endpoint without userinfo or a fragment", provider.Name)
		}
	}
	return nil
}

type httpProvider struct {
	name      string
	endpoint  *url.URL
	client    *http.Client
	transport *http.Transport
}

func newHTTPProvider(cfg ProviderConfig, timeout time.Duration, maxConnections int) *httpProvider {
	endpoint, _ := url.Parse(cfg.Endpoint) // validated by New
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The bridge must not depend on system HTTP proxy configuration or itself
	// enter Mihomo's proxy-selection path.
	transport.Proxy = nil
	transport.MaxConnsPerHost = maxConnections
	transport.MaxIdleConnsPerHost = maxConnections
	transport.MaxIdleConns = maxConnections
	transport.DisableCompression = true
	// A request deadline does not normally cancel Transport's detached dial.
	// Restore the lookup lifetime for both TCP establishment and TLS handshakes.
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := restoreDialContext(ctx, timeout)
		defer cancel()
		return dialer.DialContext(ctx, network, address)
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := restoreDialContext(ctx, timeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		tlsConfig := &tls.Config{}
		if transport.TLSClientConfig != nil {
			tlsConfig = transport.TLSClientConfig.Clone()
		}
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
	// Preserve Transport's standard HTTP/2 setup. RoundTrip initializes its
	// ALPN configuration before invoking DialTLSContext, which clones it above.
	transport.ForceAttemptHTTP2 = true
	transport.TLSHandshakeTimeout = timeout
	return &httpProvider{
		name: cfg.Name, endpoint: endpoint, transport: transport,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("domain-mapping redirects are not supported")
			},
		},
	}
}

func (p *httpProvider) CloseIdleConnections() { p.transport.CloseIdleConnections() }

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
	query.Set("view", "route")
	query.Del("client")
	if clientIP.IsValid() {
		query.Set("client", clientIP.Unmap().String())
	}
	endpoint.RawQuery = query.Encode()
	reqCtx := context.WithValue(ctx, lookupBudgetContextKey{}, ctx)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Accept", "application/json")
	response, err := p.client.Do(req)
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
	if result.Version != 1 {
		return result, fmt.Errorf("unsupported domain-mapping response version %d", result.Version)
	}
	ip, err := netip.ParseAddr(result.IP)
	if err != nil || ip.Unmap() != destinationIP.Unmap() {
		return result, errors.New("domain-mapping response IP does not match query")
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

func validDomain(domain string) bool {
	if domain == "" || domain == "." || !M.IsDomainName(domain) {
		return false
	}
	_, err := netip.ParseAddr(domain)
	return err != nil
}
