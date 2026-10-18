package domainmapping

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type h2ConnectionCounts struct {
	live   atomic.Int32
	peak   atomic.Int32
	total  atomic.Int32
	closed chan struct{}
}

func newH2LimitServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *h2ConnectionCounts) {
	t.Helper()
	return newH2LimitServerWithStreams(t, 1, handler)
}

func newH2LimitServerWithStreams(t *testing.T, maxStreams uint32, handler http.HandlerFunc) (*httptest.Server, *h2ConnectionCounts) {
	t.Helper()
	counts := &h2ConnectionCounts{closed: make(chan struct{}, 64)}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("negotiated %s, want HTTP/2", r.Proto)
		}
		handler(w, r)
	}))
	server.EnableHTTP2 = true
	if err := http2.ConfigureServer(server.Config, &http2.Server{MaxConcurrentStreams: maxStreams}); err != nil {
		t.Fatal(err)
	}
	server.TLS = server.Config.TLSConfig.Clone()
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			counts.total.Add(1)
			current := counts.live.Add(1)
			for previous := counts.peak.Load(); current > previous && !counts.peak.CompareAndSwap(previous, current); previous = counts.peak.Load() {
			}
		case http.StateClosed:
			counts.live.Add(-1)
			select {
			case counts.closed <- struct{}{}:
			default:
			}
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, counts
}

func trustedLimitProvider(t *testing.T, server *httptest.Server, maxConnections int) *httpProvider {
	t.Helper()
	cfg := testConfig(server.URL)
	cfg.Timeout, cfg.MaxConnections = 2000, maxConnections
	runtime := newTestRuntime(t, cfg)
	p := runtime.providers[0].(*httpProvider)
	trusted := server.Client().Transport.(*http.Transport).TLSClientConfig
	if p.transport.TLSClientConfig == nil {
		p.transport.TLSClientConfig = trusted.Clone()
	} else {
		p.transport.TLSClientConfig.RootCAs = trusted.RootCAs
	}
	return p
}

func writeH2LimitResult(w http.ResponseWriter, r *http.Request) {
	result := hitResult("h2-limit.example")
	result.IP = r.URL.Query().Get("ip")
	_ = json.NewEncoder(w).Encode(result)
}

func startH2LimitLookup(p *httpProvider, ctx context.Context, destination netip.Addr) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := p.Lookup(ctx, testClient, destination)
		done <- err
	}()
	return done
}

func TestHTTP2StreamLimitWaitsAndReusesConnection(t *testing.T) {
	started, release := make(chan struct{}, 2), make(chan struct{})
	var releaseOnce sync.Once
	server, counts := newH2LimitServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ip") == testDestination.String() {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		} else if r.URL.Query().Get("ip") == testDestination.Next().String() {
			started <- struct{}{}
		}
		writeH2LimitResult(w, r)
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	p := trustedLimitProvider(t, server, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Finish a warm-up exchange so the peer's SETTINGS have been received.
	if _, err := p.Lookup(ctx, testClient, testDestination.Next().Next()); err != nil {
		t.Fatal(err)
	}
	first := startH2LimitLookup(p, ctx, testDestination)
	awaitBudgetTest(t, started)
	attempted := make(chan struct{}, 1)
	queued := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) {
		select {
		case attempted <- struct{}{}:
		default:
		}
	}})
	second := startH2LimitLookup(p, queued, testDestination.Next())
	awaitBudgetTest(t, attempted)
	select {
	case <-started:
		t.Fatal("second stream reached server while its only permitted connection was saturated")
	case err := <-second:
		t.Fatalf("queued stream returned before capacity was released: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if got := counts.live.Load(); got != 1 {
		t.Fatalf("max-connections=1 allowed %d live TLS connections", got)
	}
	releaseOnce.Do(func() { close(release) })
	for _, done := range []<-chan error{first, second} {
		if err := awaitBudgetTest(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if got := counts.total.Load(); got != 1 {
		t.Fatalf("queued stream did not reuse its connection: %d sockets", got)
	}
}

func TestHTTP2CanceledStreamWaitDoesNotReplayOrLeak(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			started, release := make(chan struct{}, 1), make(chan struct{})
			var releaseOnce sync.Once
			var requests atomic.Int32
			server, counts := newH2LimitServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Query().Get("ip") == testDestination.String() {
					started <- struct{}{}
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				writeH2LimitResult(w, r)
			})
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			p := trustedLimitProvider(t, server, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := p.Lookup(ctx, testClient, testDestination.Next().Next()); err != nil {
				t.Fatal(err)
			}
			first := startH2LimitLookup(p, ctx, testDestination)
			awaitBudgetTest(t, started)
			waitCtx, stopWait := context.WithCancel(ctx)
			wantErr := error(context.Canceled)
			if mode == "deadline" {
				stopWait()
				waitCtx, stopWait = context.WithTimeout(ctx, 50*time.Millisecond)
				wantErr = context.DeadlineExceeded
			}
			defer stopWait()
			attempted := make(chan struct{}, 1)
			waitCtx = httptrace.WithClientTrace(waitCtx, &httptrace.ClientTrace{GetConn: func(string) {
				select {
				case attempted <- struct{}{}:
				default:
				}
			}})
			queued := startH2LimitLookup(p, waitCtx, testDestination.Next())
			awaitBudgetTest(t, attempted)
			if mode == "cancel" {
				stopWait()
			}
			if err := awaitBudgetTest(t, queued); !errors.Is(err, wantErr) {
				t.Fatalf("stream wait returned %v, want %v", err, wantErr)
			}
			releaseOnce.Do(func() { close(release) })
			if err := awaitBudgetTest(t, first); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Lookup(ctx, testClient, testDestination.Next().Next()); err != nil {
				t.Fatalf("capacity did not recover after stream cancellation: %v", err)
			}
			if got := requests.Load(); got != 3 {
				t.Fatalf("canceled stream reached the server: %d requests, want warm-up + first + fresh", got)
			}
			if got := counts.total.Load(); got != 1 {
				t.Fatalf("canceled wait opened extra sockets: %d", got)
			}
		})
	}
}

func TestHTTP2BurstRespectsPhysicalConnectionLimit(t *testing.T) {
	const requestCount, connectionLimit = 12, 2
	for _, state := range []string{"initial", "warm", "after-idle-close"} {
		t.Run(state, func(t *testing.T) {
			started, release := make(chan struct{}, requestCount), make(chan struct{})
			var releaseOnce sync.Once
			var block atomic.Bool
			server, counts := newH2LimitServer(t, func(w http.ResponseWriter, r *http.Request) {
				if block.Load() {
					started <- struct{}{}
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				writeH2LimitResult(w, r)
			})
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			p := trustedLimitProvider(t, server, connectionLimit)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if state != "initial" {
				if _, err := p.Lookup(ctx, testClient, testDestination); err != nil {
					t.Fatal(err)
				}
			}
			if state == "after-idle-close" {
				p.CloseIdleConnections()
				awaitBudgetTest(t, counts.closed)
			}
			block.Store(true)
			var done []<-chan error
			for i := 0; i < requestCount; i++ {
				destination := netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
				done = append(done, startH2LimitLookup(p, ctx, destination))
			}
			awaitBudgetTest(t, started)
			// Keep streams blocked long enough for competing cold dials to settle.
			select {
			case <-ctx.Done():
				t.Fatal("cold burst expired before capacity could be checked")
			case <-time.After(75 * time.Millisecond):
			}
			if got := counts.peak.Load(); got > connectionLimit {
				t.Fatalf("cold burst opened %d simultaneous sockets, limit %d", got, connectionLimit)
			}
			releaseOnce.Do(func() { close(release) })
			for _, result := range done {
				if err := awaitBudgetTest(t, result); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHTTP2AvailableStreamsDoNotSerializeResponses(t *testing.T) {
	started, release := make(chan struct{}, 2), make(chan struct{})
	var releaseOnce sync.Once
	var block atomic.Bool
	server, counts := newH2LimitServerWithStreams(t, 2, func(w http.ResponseWriter, r *http.Request) {
		if block.Load() {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		writeH2LimitResult(w, r)
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	p := trustedLimitProvider(t, server, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Complete the initial exchange so both streams are available according
	// to the peer's SETTINGS, then hold both response bodies simultaneously.
	if _, err := p.Lookup(ctx, testClient, testDestination); err != nil {
		t.Fatal(err)
	}
	block.Store(true)
	first := startH2LimitLookup(p, ctx, testDestination)
	second := startH2LimitLookup(p, ctx, testDestination.Next())
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case err := <-first:
			t.Fatalf("first stream finished before both handlers were admitted: %v", err)
		case err := <-second:
			t.Fatalf("second stream finished before both handlers were admitted: %v", err)
		case <-ctx.Done():
			t.Fatal("available HTTP/2 streams serialized their responses")
		}
	}
	releaseOnce.Do(func() { close(release) })
	for _, done := range []<-chan error{first, second} {
		if err := awaitBudgetTest(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if got := counts.total.Load(); got != 1 {
		t.Fatalf("concurrent streams used %d physical connections, want 1", got)
	}
}

func TestHTTPSConnectionCapacityRecoversAfterIdleClose(t *testing.T) {
	server, counts := newH2LimitServer(t, writeH2LimitResult)
	p := trustedLimitProvider(t, server, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		if _, err := p.Lookup(ctx, testClient, testDestination); err != nil {
			t.Fatalf("lookup after closing connection %d: %v", i, err)
		}
		p.CloseIdleConnections()
		awaitBudgetTest(t, counts.closed)
	}
	if got := counts.total.Load(); got != 3 {
		t.Fatalf("idle connection was not replaced: %d sockets, want 3", got)
	}
}

func TestHTTPSHTTP1FallbackSurvivesIdleReconnect(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			t.Errorf("negotiated %s, want HTTP/1.1", r.Proto)
		}
		requests.Add(1)
		writeH2LimitResult(w, r)
	}))
	defer server.Close()
	p := trustedLimitProvider(t, server, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		if _, err := p.Lookup(ctx, testClient, testDestination); err != nil {
			t.Fatalf("HTTPS HTTP/1.1 fallback failed: %v", err)
		}
		p.CloseIdleConnections()
	}
	if requests.Load() != 3 {
		t.Fatalf("HTTP/1.1 requests = %d, want 3", requests.Load())
	}
}

func TestHTTP2GoAwayReleasesConnectionCapacity(t *testing.T) {
	server, counts := newH2LimitServer(t, func(w http.ResponseWriter, r *http.Request) {
		// x/net/http2 translates this header into GOAWAY after the response.
		w.Header().Set("Connection", "close")
		writeH2LimitResult(w, r)
	})
	p := trustedLimitProvider(t, server, 1)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := p.Lookup(ctx, testClient, testDestination)
		cancel()
		if err != nil {
			t.Fatalf("lookup %d after GOAWAY: %v", i, err)
		}
	}
	if got := counts.total.Load(); got != 2 {
		t.Fatalf("GOAWAY connection was not replaced: %d sockets, want 2", got)
	}
}

func TestHTTPSHandshakeFailureReleasesConnectionCapacity(t *testing.T) {
	server, _ := newH2LimitServer(t, writeH2LimitResult)
	cfg := testConfig(server.URL)
	cfg.Timeout, cfg.MaxConnections = 2000, 1
	runtime := newTestRuntime(t, cfg)
	p := runtime.providers[0].(*httpProvider)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := p.Lookup(ctx, testClient, testDestination); err == nil {
		t.Fatal("provider accepted an untrusted certificate")
	}
	// Correct the trust roots on the same transport: the failed handshake's
	// physical socket must have released its one permit for this retry.
	p.transport.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if _, err := p.Lookup(ctx, testClient, testDestination); err != nil {
		t.Fatalf("failed handshake leaked its connection permit: %v", err)
	}
}

func TestHTTPSConnectionAcquisitionWaitUsesOriginalContext(t *testing.T) {
	server, _ := newH2LimitServer(t, writeH2LimitResult)
	p := trustedLimitProvider(t, server, 2)
	underlyingDial := p.transport.DialTLSContext
	started := make(chan struct{})
	var dials atomic.Int32
	p.transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if dials.Add(1) == 1 {
			// Keep the first protocol negotiation incomplete. Later calls must
			// wait for its connection acquisition using their own deadlines.
			ctx, cancel := restoreDialContext(ctx, 2*time.Second)
			defer cancel()
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return underlyingDial(ctx, network, address)
	}
	firstCtx, cancelFirst := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFirst()
	first := startH2LimitLookup(p, firstCtx, testDestination)
	awaitBudgetTest(t, started)
	deadlineCtx, cancelDeadline := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelDeadline()
	if _, err := p.Lookup(deadlineCtx, testClient, testDestination); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connection acquisition wait ignored its deadline: %v", err)
	}
	cancelCtx, cancelWait := context.WithCancel(context.Background())
	defer cancelWait()
	attached := &attachedContext{Context: cancelCtx, attached: make(chan struct{})}
	canceled := startH2LimitLookup(p, attached, testDestination)
	awaitBudgetTest(t, attached.attached)
	cancelWait()
	if err := awaitBudgetTest(t, canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("connection acquisition wait ignored cancellation: %v", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("expired acquisition wait started additional dials: %d", got)
	}
	cancelFirst()
	if err := awaitBudgetTest(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("initial negotiation ignored cancellation: %v", err)
	}
	freshCtx, cancelFresh := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFresh()
	if _, err := p.Lookup(freshCtx, testClient, testDestination); err != nil {
		t.Fatalf("failed initial negotiation retained the acquisition gate: %v", err)
	}
}

type rawH2GoAwayPeer struct {
	goAway  chan struct{}
	sent    chan error
	started chan struct{}
	closed  chan struct{}
}

// Unlike http2.Server's graceful shutdown, this peer deliberately keeps its
// TCP connection open after GOAWAY. The client must retire the physical socket.
func newRawH2GoAwayServer(t *testing.T, release <-chan struct{}) (*httptest.Server, <-chan *rawH2GoAwayPeer) {
	t.Helper()
	peers := make(chan *rawH2GoAwayPeer, 8)
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.EnableHTTP2 = true
	server.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(_ *http.Server, conn *tls.Conn, _ http.Handler) {
			peer := &rawH2GoAwayPeer{goAway: make(chan struct{}, 1), sent: make(chan error, 1), started: make(chan struct{}, 8), closed: make(chan struct{})}
			peers <- peer
			defer close(peer.closed)
			defer conn.Close()
			preface := make([]byte, len(http2.ClientPreface))
			if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
				return
			}
			framer := http2.NewFramer(conn, conn)
			var writeMu sync.Mutex
			var lastStream atomic.Uint32
			if err := framer.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1}); err != nil {
				return
			}
			go func() {
				select {
				case <-peer.goAway:
					writeMu.Lock()
					peer.sent <- framer.WriteGoAway(lastStream.Load(), http2.ErrCodeNo, nil)
					writeMu.Unlock()
				case <-peer.closed:
				}
			}()
			for {
				frame, err := framer.ReadFrame()
				if err != nil {
					return
				}
				switch frame := frame.(type) {
				case *http2.SettingsFrame:
					if !frame.IsAck() {
						writeMu.Lock()
						err = framer.WriteSettingsAck()
						writeMu.Unlock()
					}
				case *http2.HeadersFrame:
					lastStream.Store(frame.StreamID)
					peer.started <- struct{}{}
					if release != nil {
						<-release
					}
					var headers bytes.Buffer
					encoder := hpack.NewEncoder(&headers)
					_ = encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					_ = encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
					body, _ := json.Marshal(hitResult("goaway.example"))
					writeMu.Lock()
					err = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: frame.StreamID, BlockFragment: headers.Bytes(), EndHeaders: true})
					if err == nil {
						err = framer.WriteData(frame.StreamID, true, body)
					}
					writeMu.Unlock()
				case *http2.PingFrame:
					if !frame.IsAck() {
						writeMu.Lock()
						err = framer.WritePing(true, frame.Data)
						writeMu.Unlock()
					}
				}
				if err != nil {
					return
				}
			}
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, peers
}

func TestHTTP2IdleGoAwayClosesPeerThatKeepsSocketOpen(t *testing.T) {
	server, peers := newRawH2GoAwayServer(t, nil)
	p := trustedLimitProvider(t, server, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := p.Lookup(ctx, testClient, testDestination); err != nil {
		t.Fatal(err)
	}
	firstPeer := awaitBudgetTest(t, peers)
	firstPeer.goAway <- struct{}{}
	if err := awaitBudgetTest(t, firstPeer.sent); err != nil {
		t.Fatal(err)
	}
	// Wait for the client, rather than the server, to dispose of the retired
	// idle socket before asking for its replacement.
	awaitBudgetTest(t, firstPeer.closed)
	if _, err := p.Lookup(ctx, testClient, testDestination); err != nil {
		t.Fatalf("idle GOAWAY retained the connection permit: %v", err)
	}
	awaitBudgetTest(t, peers)
}

func TestHTTP2ActiveGoAwayAndRetirePreserveAdmittedStream(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	server, peers := newRawH2GoAwayServer(t, release)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	cfg := testConfig(server.URL)
	cfg.Timeout, cfg.MaxConnections = 2000, 1
	runtime := newTestRuntime(t, cfg)
	p := runtime.providers[0].(*httpProvider)
	trusted := server.Client().Transport.(*http.Transport).TLSClientConfig
	if p.transport.TLSClientConfig == nil {
		p.transport.TLSClientConfig = trusted.Clone()
	} else {
		p.transport.TLSClientConfig.RootCAs = trusted.RootCAs
	}
	done := make(chan error, 1)
	go func() {
		_, err := runtime.Lookup(context.Background(), testClient, testDestination)
		done <- err
	}()
	peer := awaitBudgetTest(t, peers)
	awaitBudgetTest(t, peer.started)
	peer.goAway <- struct{}{}
	if err := awaitBudgetTest(t, peer.sent); err != nil {
		t.Fatal(err)
	}
	runtime.Retire()
	select {
	case err := <-done:
		t.Fatalf("retirement aborted an admitted stream: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	if err := awaitBudgetTest(t, done); err != nil {
		t.Fatalf("admitted stream failed after GOAWAY/retirement: %v", err)
	}
	awaitBudgetTest(t, peer.closed)
}
