package route

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/tunnel"
)

const dnsPolicyMaxBody = 32 << 10

var dnsPolicySlots = make(chan struct{}, 4)

// The route lives inside the controller's bearer-authenticated group. It is
// additionally restricted to loopback peers and disabled without a secret.
// Forwarded/X-Forwarded-For headers are deliberately not trusted.
func dnsPolicyRouter(secret string) http.Handler {
	router := chi.NewRouter()
	router.Post("/classify", func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		deadline := time.Now().Add(2 * time.Second)
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		// Keep deadlines through net/http's final flush and unread-body drain.
		// The server resets them when it starts the next keep-alive request.
		if secret == "" {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("DNS policy classification requires a controller secret"))
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		peer, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || !peer.Unmap().IsLoopback() {
			render.Status(r, http.StatusForbidden)
			render.JSON(w, r, newError("DNS policy classification requires a loopback peer"))
			return
		}
		select {
		case dnsPolicySlots <- struct{}{}:
			defer func() { <-dnsPolicySlots }()
		default:
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("DNS policy classification is busy"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, dnsPolicyMaxBody)
		defer r.Body.Close()
		var request tunnel.DNSPolicyRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid bounded DNS policy request"))
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("request must contain one JSON object"))
			return
		}
		if err := tunnel.ValidateDNSPolicyRequest(&request); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		response, err := tunnel.ClassifyDNSPolicy(ctx, request)
		if err != nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError("DNS policy snapshot is unavailable"))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		render.JSON(w, r, response)
	})
	return router
}
