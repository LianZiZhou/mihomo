package route

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/tunnel"
)

func TestDNSPolicyRouteBoundsAndAuthorization(t *testing.T) {
	runningDNSPolicyTest(t)
	const valid = `{"version":1,"queries":[{"domain":"unmatched.example","client":"192.168.6.180"}]}`
	for _, test := range []struct {
		name, body, peer, token, secret string
		status                          int
	}{
		{"authorized", valid, "127.0.0.1:1234", "secret", "secret", http.StatusOK},
		{"unauthorized", valid, "127.0.0.1:1234", "", "secret", http.StatusUnauthorized},
		{"remote", valid, "192.168.6.180:1234", "secret", "secret", http.StatusForbidden},
		{"no-secret", valid, "127.0.0.1:1234", "", "", http.StatusServiceUnavailable},
		{"unknown-field", `{"version":1,"queries":[],"credentials":true}`, "127.0.0.1:1234", "secret", "secret", http.StatusBadRequest},
		{"trailing", valid + `{}`, "127.0.0.1:1234", "secret", "secret", http.StatusBadRequest},
		{"body-limit", strings.Repeat(" ", dnsPolicyMaxBody) + valid, "127.0.0.1:1234", "secret", "secret", http.StatusBadRequest},
		{"unknown-client", `{"version":1,"queries":[{"domain":"unmatched.example","client":""}]}`, "127.0.0.1:1234", "secret", "secret", http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://localhost/dns-policy/classify", strings.NewReader(test.body))
			r.RemoteAddr = test.peer
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			if test.token != "" {
				r.Header.Set("Authorization", "Bearer "+test.token)
			}
			w := httptest.NewRecorder()
			router(false, test.secret, "", Cors{}).ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDNSPolicySlowBodyAndRejectedDrainRemainBounded(t *testing.T) {
	for _, overloaded := range []bool{false, true} {
		t.Run(fmt.Sprint("overloaded=", overloaded), func(t *testing.T) {
			if overloaded {
				for i := 0; i < cap(dnsPolicySlots); i++ {
					dnsPolicySlots <- struct{}{}
				}
				defer func() {
					for i := 0; i < cap(dnsPolicySlots); i++ {
						<-dnsPolicySlots
					}
				}()
			}
			server := httptest.NewServer(dnsPolicyRouter("secret"))
			defer server.Close()
			conn, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			start := time.Now()
			_, err = io.WriteString(conn, "POST /classify HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1024\r\n\r\n{")
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, conn)
			if elapsed := time.Since(start); elapsed > 3500*time.Millisecond {
				t.Fatalf("slow body retained connection for %s: %v", elapsed, err)
			}
		})
	}
}

func TestDNSPolicyMaximumBatchResponseAndKeepAlive(t *testing.T) {
	runningDNSPolicyTest(t)
	request := tunnel.DNSPolicyRequest{Version: 1}
	for i := 0; i < tunnel.DNSPolicyMaxQueries; i++ {
		request.Queries = append(request.Queries, tunnel.DNSPolicyQuery{Domain: fmt.Sprintf("domain-%d.%s.%s.example", i, strings.Repeat("a", 63), strings.Repeat("b", 63)), Client: "2001:db8::1234"})
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(dnsPolicyRouter("secret"))
	defer server.Close()
	client := server.Client()
	for i := 0; i < 2; i++ {
		response, err := client.Post(server.URL+"/classify", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		var got tunnel.DNSPolicyResponse
		err = json.NewDecoder(response.Body).Decode(&got)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || len(got.Results) != tunnel.DNSPolicyMaxQueries {
			t.Fatalf("status=%d results=%d error=%v", response.StatusCode, len(got.Results), err)
		}
	}
}

func runningDNSPolicyTest(t *testing.T) {
	t.Helper()
	before := tunnel.Status()
	tunnel.OnRunning()
	t.Cleanup(func() {
		switch before {
		case tunnel.Running:
			tunnel.OnRunning()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		default:
			tunnel.OnSuspend()
		}
	})
}

func TestDNSPolicyRouteRefusesConfigurationReload(t *testing.T) {
	runningDNSPolicyTest(t)
	for _, transition := range []func(){tunnel.OnSuspend, tunnel.OnInnerLoading} {
		transition()
		r := httptest.NewRequest(http.MethodPost, "http://localhost/classify", strings.NewReader(`{"version":1,"queries":[{"domain":"gemini.google.com","client":"192.168.6.180"}]}`))
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		dnsPolicyRouter("secret").ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%v returned HTTP %d", tunnel.Status(), w.Code)
		}
	}
}

func TestDNSPolicyRouteAdmissionIsBounded(t *testing.T) {
	for i := 0; i < cap(dnsPolicySlots); i++ {
		dnsPolicySlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(dnsPolicySlots); i++ {
			<-dnsPolicySlots
		}
	}()
	r := httptest.NewRequest(http.MethodPost, "http://localhost/classify", strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	dnsPolicyRouter("secret").ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", w.Code)
	}
}
