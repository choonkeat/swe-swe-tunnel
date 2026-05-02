package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/choonkeat/swe-swe-tunnel/internal/allowlist"
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

// preRegisterTimeout bounds the pre-Register phase of a connection:
// from Hijack through yamux handshake, AcceptStream, and the first
// frame read inside handleRegister. Any peer that doesn't make it that
// far gets its conn torn down — closing the slow-loris DoS where a
// hostile (or buggy) client holds a TCP slot indefinitely without ever
// reaching the IP rate limit (which is checked *inside* handleRegister).
//
// var rather than const so tests can shorten it (a 10s default is too
// slow to assert against in unit-test land).
var preRegisterTimeout = 10 * time.Second

// tunnelSession bundles a yamux session with its dedicated reverse proxy.
// Building the proxy once per session lets us reuse a single Transport.
type tunnelSession struct {
	sess  *yamux.Session
	proxy *httputil.ReverseProxy
}

// registry maps `{unique}-tunnel` labels to the live tunnel session for that
// client. A parallel byPubkey index lets RevokeMissing find every session
// owned by a given key without scanning the label map.
type registry struct {
	mu       sync.RWMutex
	sessions map[string]*tunnelSession
	byPubkey map[[32]byte]map[string]*tunnelSession // pubkey → label → session
}

func newRegistry() *registry {
	return &registry{
		sessions: make(map[string]*tunnelSession),
		byPubkey: make(map[[32]byte]map[string]*tunnelSession),
	}
}

func (r *registry) add(label string, pub []byte, ts *tunnelSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[label]; ok {
		return fmt.Errorf("label %q already connected", label)
	}
	r.sessions[label] = ts
	var k [32]byte
	copy(k[:], pub)
	if r.byPubkey[k] == nil {
		r.byPubkey[k] = make(map[string]*tunnelSession)
	}
	r.byPubkey[k][label] = ts
	return nil
}

func (r *registry) remove(label string, pub []byte, ts *tunnelSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.sessions[label]; ok && cur == ts {
		delete(r.sessions, label)
	}
	var k [32]byte
	copy(k[:], pub)
	if m := r.byPubkey[k]; m != nil {
		if cur, ok := m[label]; ok && cur == ts {
			delete(m, label)
		}
		if len(m) == 0 {
			delete(r.byPubkey, k)
		}
	}
}

func (r *registry) get(label string) *tunnelSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[label]
}

// RevokeMissing closes every live session whose authenticated pubkey is no
// longer in allow. The yamux Close happens *outside* the registry lock —
// Close writes a GoAway frame and waits briefly for ACK, so blocking
// add/remove callers behind it would stall the control plane during a
// reload. The eventual reg.remove triggered by connectHandler's deferred
// cleanup (when <-sess.CloseChan() fires) prunes the index entry the
// normal way.
//
// Safe to call when allow is nil (gate disabled) — no-op.
func (r *registry) RevokeMissing(allow *allowlist.Set, logger *slog.Logger) {
	if allow == nil {
		return
	}
	type victim struct {
		label string
		fp    string
		ts    *tunnelSession
	}
	var victims []victim
	r.mu.RLock()
	for k, byLabel := range r.byPubkey {
		if !allow.Contains(k[:]) {
			fp := fingerprint(k[:])
			for label, ts := range byLabel {
				victims = append(victims, victim{label: label, fp: fp, ts: ts})
			}
		}
	}
	r.mu.RUnlock()
	for _, v := range victims {
		logger.Warn("session terminated: revoked",
			"label", v.label, "pubkey_fp", v.fp)
		_ = v.ts.sess.Close()
	}
}

// connectHandler returns the http.Handler for POST /v1/connect.
//
// Flow:
//  1. validate Upgrade headers, hijack, write 101 Switching Protocols
//  2. yamux.Server, accept stream 1
//  3. read Register, verify Ed25519 sig + clock skew + unique shape
//  4. apply per-IP rate limit (cheap, before crypto)
//  5. lookup identity store; on first registration, apply per-pubkey
//     rate limit (anti-hoarding) and EnsureName issues the per-session
//     cert in-line. On reclaim, run Challenge/Proof.
//  6. send RegisterOK, register session, block until session.Close
func connectHandler(
	reg *registry,
	store *identity.Store,
	certMgr certEnsurer,
	apex string,
	ipLimiter *ratelimit.SlidingWindow,
	pubkeyLimiter *ratelimit.SlidingWindow,
	allow *allowlist.Set,
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

		// Bound the entire pre-Register phase. After Hijack, the
		// http.Server's ReadHeaderTimeout no longer governs this conn,
		// so without an explicit deadline an attacker who completes
		// Upgrade but never opens a stream (or never sends Register)
		// holds a goroutine + FD + yamux state forever. yamux itself
		// does not set deadlines on the underlying conn, so this
		// timeout doesn't conflict with its keepalive/read loop —
		// it strictly applies to "no progress at all".
		preRegisterDeadline := time.Now().Add(preRegisterTimeout)
		if err := conn.SetDeadline(preRegisterDeadline); err != nil {
			logger.Warn("set pre-register deadline failed", "err", err)
			_ = conn.Close()
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

		acceptCtx, cancelAccept := context.WithDeadline(r.Context(), preRegisterDeadline)
		stream, err := sess.AcceptStreamWithContext(acceptCtx)
		cancelAccept()
		if err != nil {
			logger.Warn("accept control stream failed", "err", err, "remote", conn.RemoteAddr().String())
			return
		}

		ctx := r.Context()
		regResult, ok := handleRegister(ctx, stream, store, certMgr, ipLimiter, pubkeyLimiter, allow, logger, conn.RemoteAddr().String())
		if !ok {
			return
		}

		// Register completed: clear the conn deadline so the long-
		// lived data plane (browser-driven yamux streams) isn't torn
		// down at preRegisterTimeout.
		if err := conn.SetDeadline(time.Time{}); err != nil {
			logger.Warn("clear post-register deadline failed", "err", err)
			return
		}

		ts := &tunnelSession{sess: sess, proxy: newSessionProxy(sess, logger)}
		if err := reg.add(regResult.label, regResult.pubkey, ts); err != nil {
			sendDeny(stream, err.Error())
			return
		}
		defer reg.remove(regResult.label, regResult.pubkey, ts)

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

		// Run the post-RegisterOK control loop. Returns when the client hangs
		// up the control stream OR when a successful Deregister has been
		// processed (in which case we tear down the session).
		deregistered := runControlLoop(ctx, stream, store, regResult.unique, regResult.pubkey, logger)
		if deregistered {
			_ = sess.Close()
		}
		<-sess.CloseChan()
		logger.Info("tunnel disconnected",
			"label", regResult.label,
			"deregistered", deregistered,
		)
	})
}

type registerResult struct {
	unique          string
	label           string
	newRegistration bool
	// pubkey is the Ed25519 key the session is authenticated as. After a
	// Challenge/Proof+Rotate flow this is the *new* key; on idempotent
	// reconnect it equals the stored key. The control loop uses it to
	// verify post-RegisterOK frames (e.g. Deregister) without re-reading
	// the store on every frame.
	pubkey ed25519.PublicKey
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
	_ *allowlist.Set,
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
		retry := int(ipLimiter.RetryAfter(ipKey).Seconds()) + 1
		logger.Warn("register denied: ip rate limit",
			"remote", remoteAddr, "unique", reg.Unique, "retry_after_sec", retry)
		sendRateLimitDeny(stream, "rate_limited:ip", retry)
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

	label := control.TunnelLabel(reg.Unique)

	existing, err := store.Get(ctx, reg.Unique)
	switch {
	case errors.Is(err, identity.ErrNotFound):
		// New unique → claim it. The per-pubkey rate limit applies only
		// here (anti-hoarding: cap how many distinct uniques one keypair
		// can register/day). Idempotent reconnects to an already-owned
		// unique do not consume the budget — they allocate no new
		// resource. The IP rate limit (above) still throttles
		// connect-spam regardless.
		if pubkeyLimiter != nil && !pubkeyLimiter.Allow(string(pub)) {
			retry := int(pubkeyLimiter.RetryAfter(string(pub)).Seconds()) + 1
			logger.Warn("register denied: pubkey rate limit",
				"remote", remoteAddr, "unique", reg.Unique, "retry_after_sec", retry)
			sendRateLimitDeny(stream, "rate_limited:pubkey", retry)
			return registerResult{}, false
		}
		// Issue cert FIRST (may fail; if so, the store stays clean).
		if err := certMgr.EnsureName(ctx, label); err != nil {
			logger.Error("ensure-cert failed for new register",
				"unique", reg.Unique, "label", label, "remote", remoteAddr, "err", err)
			// Refund the IP and pubkey budget tokens we consumed above:
			// cert issuance failed for server-side reasons (ACME / DNS
			// propagation / LE rate limit), nothing the client did. Without
			// this refund a transient cert flake would lock the operator's
			// IP and key out for a full window — a self-inflicted DoS each
			// time DNSimple's edge is slow.
			if ipLimiter != nil {
				ipLimiter.CancelLatest(ipKey)
			}
			if pubkeyLimiter != nil {
				pubkeyLimiter.CancelLatest(string(pub))
			}
			sendDeny(stream, "cert issuance failed")
			return registerResult{}, false
		}
		if err := store.Put(ctx, reg.Unique, pub, now); err != nil {
			logger.Error("identity put failed", "unique", reg.Unique, "err", err)
			sendDeny(stream, "store error")
			return registerResult{}, false
		}
		return registerResult{unique: reg.Unique, label: label, newRegistration: true, pubkey: pub}, true

	case err != nil:
		logger.Error("identity get failed", "unique", reg.Unique, "err", err)
		sendDeny(stream, "store error")
		return registerResult{}, false
	}

	// Existing entry — pubkey match → idempotent reconnect.
	if bytes.Equal(existing.Pubkey, pub) {
		_ = store.Touch(ctx, reg.Unique, now)
		return registerResult{unique: reg.Unique, label: label, newRegistration: false, pubkey: pub}, true
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
	return registerResult{unique: reg.Unique, label: label, newRegistration: false, pubkey: pub}, true
}

func sendDeny(w io.Writer, reason string) {
	_ = control.WriteMessage(w, control.KindDeny, control.Deny{Reason: reason})
}

// fingerprint returns a short, copy-pasteable identifier for an Ed25519
// pubkey: the first 6 bytes of its SHA-256 as hex (12 chars). Same shape
// the client emits at boot so an operator can cross-reference deny logs
// against a friend's reported boot fingerprint without needing the full
// pubkey.
func fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:6])
}

// sendRateLimitDeny is sendDeny + a server-supplied retry-after hint
// (seconds until the offending limiter has spare capacity again). The
// client uses this to back off precisely instead of relying on its
// hardcoded RateLimitFloor.
func sendRateLimitDeny(w io.Writer, reason string, retryAfterSec int) {
	_ = control.WriteMessage(w, control.KindDeny, control.Deny{
		Reason:        reason,
		RetryAfterSec: retryAfterSec,
	})
}

// runControlLoop dispatches inbound control frames after RegisterOK.
// Returns true iff a successful Deregister has been processed (in which
// case the caller should close the yamux session). Returns false on EOF /
// session shutdown / peer hangup, which is the normal disconnect path.
//
// Non-Deregister frames receive a Deny but the loop continues, so a
// confused peer can't unilaterally tear us down by sending stray frames.
func runControlLoop(
	ctx context.Context,
	stream io.ReadWriter,
	store *identity.Store,
	sessUnique string,
	sessPubkey ed25519.PublicKey,
	logger *slog.Logger,
) (deregistered bool) {
	for {
		frame, err := control.ReadFrame(stream)
		if err != nil {
			// EOF / yamux shutdown / etc. — peer closed the control stream.
			// This is the dominant disconnect path.
			return false
		}
		if frame.Type == control.KindDeregister {
			if handleDeregister(ctx, stream, frame, store, sessUnique, sessPubkey, logger) {
				return true
			}
			// Validation failed → Deny was already sent; keep listening.
			continue
		}
		sendDeny(stream, fmt.Sprintf("unexpected post-register frame %q", frame.Type))
	}
}

// handleDeregister validates a Deregister frame and, on success, deletes
// the identity row + writes DeregisterOK. Returns true on success.
//
// Validation chain (any failure → Deny + return false, session preserved):
//  1. Payload decodes.
//  2. Claimed unique matches the unique this session is authenticated as.
//     Defense-in-depth: even with a sig-verify bug elsewhere, you cannot
//     deregister a name other than the one you registered as.
//  3. Timestamp within ±maxClockSkew of server time (replay window).
//  4. Sig is well-formed and verifies against the *session's* authenticated
//     pubkey via DeregisterSigningPayload (domain-separated from Register
//     and Proof).
func handleDeregister(
	ctx context.Context,
	stream io.Writer,
	frame control.Frame,
	store *identity.Store,
	sessUnique string,
	sessPubkey ed25519.PublicKey,
	logger *slog.Logger,
) (success bool) {
	var d control.Deregister
	if err := control.DecodePayload(frame, &d); err != nil {
		sendDeny(stream, "bad deregister payload")
		return false
	}

	if d.Unique != sessUnique {
		logger.Warn("deregister denied: unique mismatch",
			"session_unique", sessUnique, "claimed_unique", d.Unique)
		sendDeny(stream, "unique mismatch")
		return false
	}

	now := time.Now().UTC()
	ts := time.Unix(d.Timestamp, 0).UTC()
	if delta := now.Sub(ts); delta > maxClockSkew || -delta > maxClockSkew {
		sendDeny(stream, "timestamp out of range")
		return false
	}

	sig, err := base64.RawStdEncoding.DecodeString(d.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		sendDeny(stream, "bad sig")
		return false
	}
	if !ed25519.Verify(sessPubkey, control.DeregisterSigningPayload(d.Unique, d.Timestamp), sig) {
		logger.Warn("deregister denied: signature invalid", "unique", d.Unique)
		sendDeny(stream, "signature invalid")
		return false
	}

	if err := store.Delete(ctx, d.Unique); err != nil {
		logger.Error("deregister: store.Delete failed", "unique", d.Unique, "err", err)
		sendDeny(stream, "store error")
		return false
	}
	if err := control.WriteMessage(stream, control.KindDeregisterOK, control.DeregisterOK{}); err != nil {
		// Row is already gone. The client may not learn about success on
		// this attempt; a retry will Deny "not registered" or land on a
		// fresh registration. Either way, the row release stuck.
		logger.Warn("write DeregisterOK failed", "unique", d.Unique, "err", err)
	}
	logger.Info("identity deregistered", "unique", d.Unique)
	return true
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
