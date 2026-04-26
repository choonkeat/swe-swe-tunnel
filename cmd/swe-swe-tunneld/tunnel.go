package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
	"github.com/choonkeat/swe-swe-tunnel/internal/identity"
	"github.com/choonkeat/swe-swe-tunnel/internal/ratelimit"
)

// certEnsurer is the subset of *cert.Manager that connectHandler needs. Kept
// as an interface so tests can swap in a stub instead of running real ACME.
type certEnsurer interface {
	EnsureName(ctx context.Context, label string) error
}

// maxClockSkew bounds the acceptable distance between client-reported
// timestamps and server time. Bigger window = easier replay; smaller window =
// brittle to clock drift.
const maxClockSkew = 5 * time.Minute

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

// connectHandler returns the http.Handler for POST /v1/connect.
//
// Flow:
//  1. validate Upgrade headers, hijack, write 101 Switching Protocols
//  2. yamux.Server, accept stream 1
//  3. read Register, verify Ed25519 sig + clock skew + unique shape
//  4. apply per-IP and per-pubkey rate limits
//  5. lookup identity store; on first registration, EnsureName issues the
//     per-session cert in-line. On reclaim, run Challenge/Proof.
//  6. send RegisterOK, register session, block until session.Close
func connectHandler(
	reg *registry,
	store *identity.Store,
	certMgr certEnsurer,
	apex string,
	ipLimiter *ratelimit.SlidingWindow,
	pubkeyLimiter *ratelimit.SlidingWindow,
	logger *slog.Logger,
) http.Handler {
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

		ctx := r.Context()
		regResult, ok := handleRegister(ctx, stream, store, certMgr, ipLimiter, pubkeyLimiter, logger, conn.RemoteAddr().String())
		if !ok {
			return
		}

		ts := &tunnelSession{sess: sess, proxy: newSessionProxy(sess, logger)}
		if err := reg.add(regResult.label, ts); err != nil {
			sendDeny(stream, err.Error())
			return
		}
		defer reg.remove(regResult.label, ts)

		if err := control.WriteMessage(stream, control.KindRegisterOK, control.RegisterOK{
			Hostname: regResult.label + "." + apex,
		}); err != nil {
			logger.Warn("write RegisterOK failed", "err", err)
			return
		}
		logger.Info("tunnel connected",
			"unique", regResult.unique,
			"label", regResult.label,
			"remote", conn.RemoteAddr().String(),
			"new_registration", regResult.newRegistration,
		)

		<-sess.CloseChan()
		logger.Info("tunnel disconnected", "label", regResult.label)
	})
}

type registerResult struct {
	unique          string
	label           string
	newRegistration bool
}

// handleRegister reads the Register frame, validates it, runs identity lookup
// (with optional Challenge/Proof on pubkey mismatch), and ensures the
// per-session cert exists. Sends Deny on any failure path.
func handleRegister(
	ctx context.Context,
	stream io.ReadWriter,
	store *identity.Store,
	certMgr certEnsurer,
	ipLimiter *ratelimit.SlidingWindow,
	pubkeyLimiter *ratelimit.SlidingWindow,
	logger *slog.Logger,
	remoteAddr string,
) (registerResult, bool) {
	frame, err := control.ReadFrame(stream)
	if err != nil {
		logger.Warn("read Register failed", "err", err)
		return registerResult{}, false
	}
	if frame.Type != control.KindRegister {
		sendDeny(stream, fmt.Sprintf("expected register, got %q", frame.Type))
		return registerResult{}, false
	}
	var reg control.Register
	if err := control.DecodePayload(frame, &reg); err != nil {
		sendDeny(stream, "bad register payload")
		return registerResult{}, false
	}
	if reg.Version != control.ProtoVersion {
		sendDeny(stream, fmt.Sprintf("unsupported protocol version %d", reg.Version))
		return registerResult{}, false
	}
	if err := control.ValidateUnique(reg.Unique); err != nil {
		sendDeny(stream, err.Error())
		return registerResult{}, false
	}

	// Per-IP rate limit (cheap; check before crypto). The remoteAddr from
	// http.Server is host:port, so split.
	ipKey := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ipKey = h
	}
	if ipLimiter != nil && !ipLimiter.Allow(ipKey) {
		logger.Warn("register denied: ip rate limit", "remote", remoteAddr, "unique", reg.Unique)
		sendDeny(stream, "rate_limited:ip")
		return registerResult{}, false
	}

	pub, err := base64.RawStdEncoding.DecodeString(reg.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		sendDeny(stream, "bad pubkey")
		return registerResult{}, false
	}
	sig, err := base64.RawStdEncoding.DecodeString(reg.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		sendDeny(stream, "bad sig")
		return registerResult{}, false
	}

	now := time.Now().UTC()
	ts := time.Unix(reg.Timestamp, 0).UTC()
	if d := now.Sub(ts); d > maxClockSkew || -d > maxClockSkew {
		sendDeny(stream, "timestamp out of range")
		return registerResult{}, false
	}

	if !ed25519.Verify(pub, control.RegisterSigningPayload(pub, reg.Unique, reg.Timestamp), sig) {
		sendDeny(stream, "signature invalid")
		return registerResult{}, false
	}

	// Per-pubkey rate limit (sig is verified now, so the pubkey claim is
	// honest). Cap how many distinct uniques one keypair can register/day.
	if pubkeyLimiter != nil && !pubkeyLimiter.Allow(string(pub)) {
		logger.Warn("register denied: pubkey rate limit", "remote", remoteAddr, "unique", reg.Unique)
		sendDeny(stream, "rate_limited:pubkey")
		return registerResult{}, false
	}

	label := control.TunnelLabel(reg.Unique)

	existing, err := store.Get(ctx, reg.Unique)
	switch {
	case errors.Is(err, identity.ErrNotFound):
		// New unique → claim it. Issue cert FIRST (may fail; if so, the
		// store stays clean).
		if err := certMgr.EnsureName(ctx, label); err != nil {
			logger.Error("ensure-cert failed for new register",
				"unique", reg.Unique, "label", label, "remote", remoteAddr, "err", err)
			sendDeny(stream, "cert issuance failed")
			return registerResult{}, false
		}
		if err := store.Put(ctx, reg.Unique, pub, now); err != nil {
			logger.Error("identity put failed", "unique", reg.Unique, "err", err)
			sendDeny(stream, "store error")
			return registerResult{}, false
		}
		return registerResult{unique: reg.Unique, label: label, newRegistration: true}, true

	case err != nil:
		logger.Error("identity get failed", "unique", reg.Unique, "err", err)
		sendDeny(stream, "store error")
		return registerResult{}, false
	}

	// Existing entry — pubkey match → idempotent reconnect.
	if bytes.Equal(existing.Pubkey, pub) {
		_ = store.Touch(ctx, reg.Unique, now)
		return registerResult{unique: reg.Unique, label: label, newRegistration: false}, true
	}

	// Existing entry, different pubkey → challenge & require proof from the
	// stored key.
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		sendDeny(stream, "internal error")
		return registerResult{}, false
	}
	if err := control.WriteMessage(stream, control.KindChallenge, control.Challenge{
		Nonce: base64.RawStdEncoding.EncodeToString(nonce[:]),
	}); err != nil {
		logger.Warn("write challenge failed", "err", err)
		return registerResult{}, false
	}

	proofFrame, err := control.ReadFrame(stream)
	if err != nil {
		logger.Warn("read proof failed", "err", err)
		return registerResult{}, false
	}
	if proofFrame.Type != control.KindProof {
		sendDeny(stream, fmt.Sprintf("expected proof, got %q", proofFrame.Type))
		return registerResult{}, false
	}
	var proof control.Proof
	if err := control.DecodePayload(proofFrame, &proof); err != nil {
		sendDeny(stream, "bad proof payload")
		return registerResult{}, false
	}
	proofSig, err := base64.RawStdEncoding.DecodeString(proof.Sig)
	if err != nil || len(proofSig) != ed25519.SignatureSize {
		sendDeny(stream, "bad proof sig")
		return registerResult{}, false
	}
	if !ed25519.Verify(existing.Pubkey, control.ProofSigningPayload(nonce[:]), proofSig) {
		logger.Warn("proof failed", "unique", reg.Unique, "remote", remoteAddr)
		sendDeny(stream, "key_mismatch")
		return registerResult{}, false
	}
	// Successful proof → rotate to new pubkey.
	if err := store.Rotate(ctx, reg.Unique, pub, now); err != nil {
		logger.Error("rotate failed", "unique", reg.Unique, "err", err)
		sendDeny(stream, "store error")
		return registerResult{}, false
	}
	logger.Info("identity key rotated", "unique", reg.Unique, "remote", remoteAddr)
	return registerResult{unique: reg.Unique, label: label, newRegistration: false}, true
}

func sendDeny(w io.Writer, reason string) {
	_ = control.WriteMessage(w, control.KindDeny, control.Deny{Reason: reason})
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
