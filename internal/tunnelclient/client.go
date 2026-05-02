// Package tunnelclient implements the client side of the swe-swe-tunnel
// control protocol: dial the server with HTTP Upgrade, run yamux on the
// hijacked conn, sign and send Register, optionally answer a Challenge, and
// then serve incoming yamux streams as HTTP requests proxied to a local
// service.
//
// Split out of cmd/swe-swe-tunnel so it can be exercised by in-process e2e
// tests that don't want to shell out to the binary.
package tunnelclient

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
)

// DenyError wraps a server-sent Deny.Reason. Connect and Deregister
// return one of these when the server replies with a Deny frame; the
// Run loop pulls it out via errors.As to make backoff and retry
// decisions per reason (rate-limit → long delay; permanent → fatal).
type DenyError struct {
	// Reason is the raw Deny.Reason string from the wire.
	Reason string
	// Op is "register" or "deregister", whichever flow surfaced this.
	Op string
	// RetryAfter is the server's hint for how long to wait before
	// retrying. Set only on rate_limited:* denies; zero otherwise.
	// Run uses this in preference to RunOptions.RateLimitFloor when
	// non-zero. Old servers don't populate the field and clients fall
	// back to the floor.
	RetryAfter time.Duration
}

// Error formats the deny for human-readable error chains.
func (e *DenyError) Error() string {
	if e.Op != "" {
		return fmt.Sprintf("server denied %s: %s", e.Op, e.Reason)
	}
	return fmt.Sprintf("server denied: %s", e.Reason)
}

// IsRateLimit reports whether the deny is one of the server's
// rate_limited:* reasons (currently :ip and :pubkey).
func (e *DenyError) IsRateLimit() bool {
	return strings.HasPrefix(e.Reason, "rate_limited:")
}

// IsPermanent reports whether the deny reason is a client-side
// configuration error that retrying cannot fix. Callers should treat
// these as fatal rather than looping.
func (e *DenyError) IsPermanent() bool {
	switch e.Reason {
	case "bad pubkey", "bad sig", "key_mismatch", "unique mismatch",
		"bad register payload", "bad deregister payload",
		"bad proof payload", "bad proof sig", "signature invalid":
		return true
	}
	if strings.HasPrefix(e.Reason, "unsupported protocol version") ||
		strings.HasPrefix(e.Reason, "invalid unique") ||
		strings.HasPrefix(e.Reason, "expected ") {
		return true
	}
	return false
}

// Options configures a single Connect call.
type Options struct {
	// ServerURL is the tunneld base URL, e.g. "https://tunnel.example.com".
	ServerURL string
	// Unique is the requested name; the server stores it as `{Unique}-tunnel`.
	Unique string
	// PrivateKey signs the Register and any subsequent Proof.
	PrivateKey ed25519.PrivateKey
	// TLSConfig is the TLS config for dialing the server. If nil, a default
	// is built using ServerName from ServerURL. Tests may pass an
	// httptest.Server's TLS config to trust its self-signed cert.
	TLSConfig *tls.Config
	// DialTimeout for the TCP connection. Zero = 30s default.
	DialTimeout time.Duration
	// Logger receives info/error events. Optional; defaults to slog.Default().
	Logger *slog.Logger
	// Emitter publishes structured lifecycle events for a parent supervisor.
	// Optional; defaults to NoopEmitter (no stdout output).
	Emitter Emitter
}

// Session is the established post-Register tunnel.
type Session struct {
	yamux        *yamux.Session
	hostname     string
	unique       string             // bare label sent in Register (without the "-tunnel" suffix)
	registeredAt time.Time          // captured when RegisterOK arrives
	priv         ed25519.PrivateKey // retained so Deregister can sign the request
	ctrl         *yamux.Stream      // stream-1 control channel; reused for post-RegisterOK frames
	conn         net.Conn           // TLS conn underlying the yamux session; closed on Close
	emitter      Emitter            // captured from Options; never nil (NoopEmitter sentinel)
}

// Hostname returns the server-assigned hostname, e.g. "alpha-tunnel.example.com".
func (s *Session) Hostname() string { return s.hostname }

// Yamux returns the underlying yamux session for tests / advanced use.
func (s *Session) Yamux() *yamux.Session { return s.yamux }

// Close shuts the yamux session and the TCP connection.
func (s *Session) Close() error {
	err := s.yamux.Close()
	_ = s.conn.Close()
	return err
}

// CloseChan signals when the session has shut down (server-initiated or
// otherwise).
func (s *Session) CloseChan() <-chan struct{} { return s.yamux.CloseChan() }

// Connect dials, runs the HTTP→yamux upgrade, and completes the Register
// flow. It does NOT start serving — call Serve on the returned Session.
func Connect(ctx context.Context, opts Options) (*Session, error) {
	if opts.PrivateKey == nil {
		return nil, errors.New("tunnelclient: PrivateKey required")
	}
	if err := control.ValidateUnique(opts.Unique); err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	em := opts.Emitter
	if em == nil {
		em = NoopEmitter{}
	}

	u, err := url.Parse(opts.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parse ServerURL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("ServerURL must use https:// (got %q)", u.Scheme)
	}
	addr := u.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	connectURL := *u
	connectURL.Path = strings.TrimRight(connectURL.Path, "/") + "/v1/connect"

	tlsCfg := opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	} else {
		tlsCfg = tlsCfg.Clone()
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = u.Hostname()
		}
	}

	dialTimeout := opts.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 30 * time.Second
	}

	logger.Info("dialing", "addr", addr, "sni", tlsCfg.ServerName)
	dialer := &net.Dialer{Timeout: dialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	// closeOnCancel: from here until Connect returns, ctx cancellation
	// closes rawConn. That cascades to TLS Read/Write, the HTTP upgrade
	// I/O, yamux, and the control-stream Register dance — none of which
	// are ctx-aware on their own. Without this watcher, a SIGINT during
	// (e.g.) the multi-minute Register wait while tunneld provisions a
	// new LE wildcard would leave the goroutine parked in a syscall the
	// runtime cannot preempt, and the process appears hung.
	//
	// On a successful return the watcher exits without closing —
	// ownership of rawConn passes to the returned Session. On any error
	// path Connect already calls tlsConn.Close itself; a late watcher
	// fire is a no-op on an already-closed conn.
	connectDone := make(chan struct{})
	defer close(connectDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConn.Close()
		case <-connectDone:
		}
	}()

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, connectURL.String(), http.NoBody)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", control.UpgradeProtocol)
	req.Header.Set("User-Agent", "swe-swe-tunnel/"+strconv.Itoa(control.ProtoVersion))
	if err := req.Write(tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}

	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = tlsConn.Close()
		return nil, fmt.Errorf("expected 101, got %s: %s", resp.Status, string(body))
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), control.UpgradeProtocol) {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("server upgraded to %q, expected %q",
			resp.Header.Get("Upgrade"), control.UpgradeProtocol)
	}

	muxConn := &bufferedConn{r: br, Conn: tlsConn}
	yam, err := yamux.Client(muxConn, nil)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("yamux client: %w", err)
	}

	stream, err := yam.OpenStream()
	if err != nil {
		_ = yam.Close()
		_ = tlsConn.Close()
		return nil, fmt.Errorf("open control stream: %w", err)
	}

	logger.Info("awaiting RegisterOK from server",
		"unique", opts.Unique,
		"hint", "first-time uniques can take 1-3 min while the server provisions a wildcard cert")
	hostname, err := registerWithServer(stream, opts.Unique, opts.PrivateKey, logger)
	if err != nil {
		_ = yam.Close()
		_ = tlsConn.Close()
		return nil, fmt.Errorf("register: %w", err)
	}
	logger.Info("registered", "hostname", hostname)
	em.Emit(EventRegisterOK, RegisterOKData{Hostname: hostname, Unique: opts.Unique})

	return &Session{
		yamux:        yam,
		hostname:     hostname,
		unique:       opts.Unique,
		registeredAt: time.Now(),
		priv:         opts.PrivateKey,
		ctrl:         stream,
		conn:         tlsConn,
		emitter:      em,
	}, nil
}

// Deregister releases ownership of this session's unique on the server.
// The server validates a signed Deregister frame, deletes the identity
// row, replies with DeregisterOK, and closes the session.
//
// On success the caller should call Close(); after a successful
// Deregister the next Register from any pubkey will be a fresh
// registration (no Challenge required, since the row is gone).
//
// On a server-side Deny (rare — usually means the session lost auth
// somehow) the error wraps the Deny.Reason. On any other failure
// (network, malformed reply) the session may be in an indeterminate
// state and should be closed regardless.
func (s *Session) Deregister(ctx context.Context) error {
	if s.priv == nil || s.ctrl == nil {
		return errors.New("tunnelclient: session is not Deregister-capable (was it built outside Connect?)")
	}

	ts := time.Now().Unix()
	sig := ed25519.Sign(s.priv, control.DeregisterSigningPayload(s.unique, ts))
	if err := control.WriteMessage(s.ctrl, control.KindDeregister, control.Deregister{
		Unique:    s.unique,
		Timestamp: ts,
		Sig:       base64.RawStdEncoding.EncodeToString(sig),
	}); err != nil {
		return fmt.Errorf("write Deregister: %w", err)
	}

	// Translate ctx cancellation into a forced read deadline so the read
	// returns instead of blocking forever.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.ctrl.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	frame, err := control.ReadFrame(s.ctrl)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("read Deregister response: %w", ctxErr)
		}
		return fmt.Errorf("read Deregister response: %w", err)
	}
	switch frame.Type {
	case control.KindDeregisterOK:
		if s.emitter != nil {
			s.emitter.Emit(EventDeregisterOK, DeregisterOKData{Unique: s.unique})
		}
		return nil
	case control.KindDeny:
		var d control.Deny
		_ = control.DecodePayload(frame, &d)
		return &DenyError{
			Reason:     d.Reason,
			Op:         "deregister",
			RetryAfter: time.Duration(d.RetryAfterSec) * time.Second,
		}
	default:
		return fmt.Errorf("unexpected frame %q in Deregister response", frame.Type)
	}
}

// Serve runs an http.Server on the yamux session's accept side, dispatching
// to handler. Returns when the session closes or ctx is canceled.
func Serve(ctx context.Context, sess *Session, handler http.Handler) error {
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	listener := &yamuxListener{sess: sess.yamux}

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpSrv.Serve(listener) }()

	select {
	case <-ctx.Done():
	case <-sess.CloseChan():
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, yamux.ErrSessionShutdown) {
			return fmt.Errorf("http serve: %w", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return nil
}

// PortDispatchHandler returns an http.Handler that derives the destination
// port from the leftmost label of the request's Host header and reverse-
// proxies to `{target}:{port}`. X-Forwarded-* headers from the upstream
// (the public-facing tunneld) pass through unchanged.
//
// As of the server-side port allowlist (see
// tasks/2026-05-02-server-side-port-allowlist.md), the policy decision
// lives entirely on the tunneld server: the apex operator picks one
// allowlist that applies across all tenants, and the client
// unconditionally proxies whatever the server sends. This handler
// therefore performs no port gating beyond shape validation
// (well-formed numeric port label).
func PortDispatchHandler(target string, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			port := portFromHost(req.In.Host)
			req.Out.URL.Scheme = "http"
			req.Out.URL.Host = net.JoinHostPort(target, port)
			req.Out.Host = req.In.Host
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				if v := req.In.Header.Get(h); v != "" {
					req.Out.Header.Set(h, v)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			logger.Warn("upstream error", "err", err, "host", r.Host, "path", r.URL.Path)
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		port := portFromHost(r.Host)
		if port == "" {
			http.Error(w, "missing port label in Host", http.StatusBadRequest)
			return
		}
		if _, err := strconv.Atoi(port); err != nil {
			http.Error(w, "non-numeric port label", http.StatusBadRequest)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// registerWithServer drives Register → optional Challenge → Proof →
// RegisterOK on stream 1.
func registerWithServer(stream io.ReadWriter, unique string, priv ed25519.PrivateKey, logger *slog.Logger) (string, error) {
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Now().Unix()
	sig := ed25519.Sign(priv, control.RegisterSigningPayload(pub, unique, now))

	if err := control.WriteMessage(stream, control.KindRegister, control.Register{
		Version:   control.ProtoVersion,
		Unique:    unique,
		Pubkey:    base64.RawStdEncoding.EncodeToString(pub),
		Timestamp: now,
		Sig:       base64.RawStdEncoding.EncodeToString(sig),
	}); err != nil {
		return "", fmt.Errorf("write Register: %w", err)
	}

	frame, err := control.ReadFrame(stream)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if frame.Type == control.KindChallenge {
		var ch control.Challenge
		if err := control.DecodePayload(frame, &ch); err != nil {
			return "", fmt.Errorf("decode Challenge: %w", err)
		}
		nonce, err := base64.RawStdEncoding.DecodeString(ch.Nonce)
		if err != nil {
			return "", fmt.Errorf("decode nonce: %w", err)
		}
		logger.Info("challenge received — proving with stored key", "nonce_bytes", len(nonce))
		proofSig := ed25519.Sign(priv, control.ProofSigningPayload(nonce))
		if err := control.WriteMessage(stream, control.KindProof, control.Proof{
			Sig: base64.RawStdEncoding.EncodeToString(proofSig),
		}); err != nil {
			return "", fmt.Errorf("write Proof: %w", err)
		}
		frame, err = control.ReadFrame(stream)
		if err != nil {
			return "", fmt.Errorf("read post-Proof response: %w", err)
		}
	}

	switch frame.Type {
	case control.KindRegisterOK:
		var ok control.RegisterOK
		if err := control.DecodePayload(frame, &ok); err != nil {
			return "", fmt.Errorf("decode RegisterOK: %w", err)
		}
		return ok.Hostname, nil
	case control.KindDeny:
		var d control.Deny
		_ = control.DecodePayload(frame, &d)
		return "", &DenyError{
			Reason:     d.Reason,
			Op:         "register",
			RetryAfter: time.Duration(d.RetryAfterSec) * time.Second,
		}
	default:
		return "", fmt.Errorf("unexpected frame type %q", frame.Type)
	}
}

func portFromHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	dot := strings.IndexByte(h, '.')
	if dot < 0 {
		return ""
	}
	return h[:dot]
}

// bufferedConn wraps a net.Conn so reads come from a bufio.Reader (which may
// hold bytes already read past the upgrade response) before falling through
// to the underlying conn.
type bufferedConn struct {
	r io.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// yamuxListener adapts a yamux.Session to net.Listener for http.Server.
type yamuxListener struct{ sess *yamux.Session }

func (y *yamuxListener) Accept() (net.Conn, error) { return y.sess.Accept() }
func (y *yamuxListener) Close() error              { return y.sess.Close() }
func (y *yamuxListener) Addr() net.Addr            { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "yamux" }
func (dummyAddr) String() string  { return "yamux" }
