package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
)

// tunnelSession bundles a yamux session with its dedicated reverse proxy.
// Building the proxy once per session lets us reuse a single Transport.
type tunnelSession struct {
	sess  *yamux.Session
	proxy *httputil.ReverseProxy
}

// registry maps `{unique}-tunnel` labels to the live tunnel session for that
// client.
type registry struct {
	mu       sync.RWMutex
	sessions map[string]*tunnelSession
}

func newRegistry() *registry {
	return &registry{sessions: make(map[string]*tunnelSession)}
}

func (r *registry) add(label string, ts *tunnelSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[label]; ok {
		// Phase 2: a duplicate connection means another client claimed the
		// same `unique`. Refuse. Phase 3 replaces this with pubkey-authed
		// takeover.
		return fmt.Errorf("label %q already connected", label)
	}
	r.sessions[label] = ts
	return nil
}

func (r *registry) remove(label string, ts *tunnelSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.sessions[label]; ok && cur == ts {
		delete(r.sessions, label)
	}
}

func (r *registry) get(label string) *tunnelSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[label]
}

// upgradeHandler returns the http.Handler for POST /v1/connect.
func upgradeHandler(reg *registry, apex string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if !strings.EqualFold(r.Header.Get("Connection"), "upgrade") {
			http.Error(w, "Connection: Upgrade required", http.StatusBadRequest)
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), control.UpgradeProtocol) {
			http.Error(w, "Upgrade: "+control.UpgradeProtocol+" required", http.StatusBadRequest)
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			logger.Error("hijack failed", "err", err)
			return
		}

		if _, err := bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\n" +
			"Upgrade: " + control.UpgradeProtocol + "\r\n\r\n"); err != nil {
			logger.Error("write 101 failed", "err", err)
			_ = conn.Close()
			return
		}
		if err := bufrw.Flush(); err != nil {
			logger.Error("flush 101 failed", "err", err)
			_ = conn.Close()
			return
		}

		sess, err := yamux.Server(conn, nil)
		if err != nil {
			logger.Error("yamux server failed", "err", err)
			_ = conn.Close()
			return
		}
		defer sess.Close()

		stream, err := sess.AcceptStream()
		if err != nil {
			logger.Warn("accept control stream failed", "err", err)
			return
		}

		var hello control.ClientHello
		if err := control.ReadFrame(stream, &hello); err != nil {
			logger.Warn("read ClientHello failed", "err", err)
			_ = control.WriteFrame(stream, control.ServerHello{OK: false, Reason: "bad hello"})
			return
		}
		if hello.Version != control.ProtoVersion {
			_ = control.WriteFrame(stream, control.ServerHello{OK: false, Reason: "version mismatch"})
			return
		}
		if err := control.ValidateUnique(hello.Unique); err != nil {
			_ = control.WriteFrame(stream, control.ServerHello{OK: false, Reason: err.Error()})
			return
		}
		label := control.TunnelLabel(hello.Unique)
		hostname := label + "." + apex

		ts := &tunnelSession{sess: sess, proxy: newSessionProxy(sess, logger)}
		if err := reg.add(label, ts); err != nil {
			_ = control.WriteFrame(stream, control.ServerHello{OK: false, Reason: err.Error()})
			return
		}
		defer reg.remove(label, ts)

		if err := control.WriteFrame(stream, control.ServerHello{OK: true, Hostname: hostname}); err != nil {
			logger.Warn("write ServerHello failed", "err", err)
			return
		}
		logger.Info("tunnel connected", "label", label, "remote", conn.RemoteAddr().String())

		<-sess.CloseChan()
		logger.Info("tunnel disconnected", "label", label)
	})
}

// route returns the catch-all http.Handler. r.Host matching
// `{port}.{label}.{apex}` with {label} ending in `-tunnel` is reverse-proxied
// through the matching tunnel; everything else falls through to `fallback`.
func route(reg *registry, apex string, fallback http.Handler) http.Handler {
	apex = strings.ToLower(apex)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeHost(r.Host)
		rest, ok := strings.CutSuffix(host, "."+apex)
		if !ok || rest == "" {
			fallback.ServeHTTP(w, r)
			return
		}
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			// `{label}.{apex}` with no port part — fall through to apex landing.
			fallback.ServeHTTP(w, r)
			return
		}
		sessionLabel := rest[dot+1:]
		if !strings.HasSuffix(sessionLabel, "-tunnel") {
			fallback.ServeHTTP(w, r)
			return
		}
		ts := reg.get(sessionLabel)
		if ts == nil {
			tunnelOffline(w, sessionLabel)
			return
		}
		ts.proxy.ServeHTTP(w, r)
	})
}

func tunnelOffline(w http.ResponseWriter, label string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w, `<!doctype html>
<html><body style="font-family:sans-serif;padding:2em">
<h1>Tunnel offline</h1>
<p>The tunnel <code>%s</code> is registered but no client is currently connected.</p>
</body></html>`, label)
}

func newSessionProxy(sess *yamux.Session, logger *slog.Logger) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return sess.Open()
		},
		// Each browser request gets a fresh yamux stream. Streams are cheap
		// and pooling adds edge cases (stale stream after client reconnect).
		DisableKeepAlives: true,
	}
	return &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.URL.Scheme = "http"
			// URL.Host is required by net/http but ignored by our DialContext.
			req.Out.URL.Host = "tunnel.invalid"
			// Preserve the original Host header so the client can route by it.
			req.Out.Host = req.In.Host
			req.SetXForwarded()
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			logger.Warn("reverse-proxy error", "err", err, "host", r.Host, "path", r.URL.Path)
			http.Error(w, "tunnel error: "+err.Error(), http.StatusBadGateway)
		},
	}
}

func normalizeHost(s string) string {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}
