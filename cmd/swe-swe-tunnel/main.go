// Command swe-swe-tunnel is the client side of the swe-swe-tunnel pair.
//
// It dials the tunneld server with HTTP Upgrade, runs yamux on the hijacked
// connection, registers a `unique` name, and reverse-proxies incoming streams
// to local TCP services. The leftmost label of each request's Host header
// selects the local port: `1977.test-tunnel.example.com` → `{target}:1977`.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
)

func main() {
	var (
		server   = flag.String("server", "", "tunnel server URL, e.g. https://tunnel.example.com (required)")
		unique   = flag.String("unique", "", "requested name (required); server stores it as {unique}-tunnel")
		target   = flag.String("target", "127.0.0.1", "default forward target host (port comes from Host header label)")
		insecure = flag.Bool("insecure", false, "skip TLS verification (testing only)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if *server == "" {
		*server = os.Getenv("SWE_TUNNEL_SERVER")
	}
	if *unique == "" {
		*unique = os.Getenv("SWE_TUNNEL_UNIQUE")
	}
	if *server == "" || *unique == "" {
		flag.Usage()
		logger.Error("--server and --unique are required (or SWE_TUNNEL_SERVER / SWE_TUNNEL_UNIQUE)")
		os.Exit(2)
	}
	if err := control.ValidateUnique(*unique); err != nil {
		logger.Error("invalid --unique", "err", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *server, *unique, *target, *insecure, logger); err != nil {
		logger.Error("tunnel failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, server, unique, target string, insecure bool, logger *slog.Logger) error {
	u, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("parse --server: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("--server must use https:// (got %q)", u.Scheme)
	}
	addr := u.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}
	connectURL := *u
	connectURL.Path = strings.TrimRight(connectURL.Path, "/") + "/v1/connect"

	logger.Info("dialing", "addr", addr, "sni", u.Hostname())
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("tls handshake: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, connectURL.String(), http.NoBody)
	if err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", control.UpgradeProtocol)
	req.Header.Set("User-Agent", "swe-swe-tunnel/"+strconv.Itoa(control.ProtoVersion))

	if err := req.Write(tlsConn); err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("write request: %w", err)
	}

	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = tlsConn.Close()
		return fmt.Errorf("expected 101, got %s: %s", resp.Status, string(body))
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), control.UpgradeProtocol) {
		_ = tlsConn.Close()
		return fmt.Errorf("server upgraded to %q, expected %q", resp.Header.Get("Upgrade"), control.UpgradeProtocol)
	}

	muxConn := &bufferedConn{r: br, Conn: tlsConn}
	sess, err := yamux.Client(muxConn, nil)
	if err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("yamux client: %w", err)
	}
	defer sess.Close()

	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	if err := control.WriteFrame(stream, control.ClientHello{
		Version: control.ProtoVersion,
		Unique:  unique,
	}); err != nil {
		return fmt.Errorf("write ClientHello: %w", err)
	}

	var hello control.ServerHello
	if err := control.ReadFrame(stream, &hello); err != nil {
		return fmt.Errorf("read ServerHello: %w", err)
	}
	if !hello.OK {
		return fmt.Errorf("server rejected: %s", hello.Reason)
	}
	logger.Info("registered", "hostname", hello.Hostname)

	httpSrv := &http.Server{
		Handler:           proxyHandler(target, logger),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	listener := &yamuxListener{sess: sess}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpSrv.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case <-sess.CloseChan():
		logger.Info("session closed by server")
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

func proxyHandler(target string, logger *slog.Logger) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			port := portFromHost(req.In.Host)
			req.Out.URL.Scheme = "http"
			req.Out.URL.Host = net.JoinHostPort(target, port)
			req.Out.Host = req.In.Host
			// Pass the public-facing tunneld's X-Forwarded-* headers through
			// unchanged. Rewrite strips them by default, and SetXForwarded
			// would derive new values from the yamux hop (which has no TLS
			// state and a non-host:port RemoteAddr) — we'd lose the real
			// browser IP and "https" proto.
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
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
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
// hold bytes already read past the upgrade response) before falling through to
// the underlying conn.
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
