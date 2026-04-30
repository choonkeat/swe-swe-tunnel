// Package tunneldfake is a small in-process fake of swe-swe-tunneld for
// tests. It speaks just enough of the protocol — the HTTP /v1/connect
// upgrade, yamux, the Register/RegisterOK frames, and an optional
// Deregister round-trip — for a real tunnelclient.Connect to succeed.
//
// It does NOT implement Challenge/Proof; tests must use a fresh key per
// `unique`. It is intended for harnesses that already test the real
// tunneld elsewhere (cmd/swe-swe-tunneld/e2e_test.go) and want a
// lighter-weight peer for client-side lifecycle assertions.
//
// This package lives outside *_test.go so it can be shared between the
// internal/tunnelclient package tests and the cmd/swe-swe-tunnel
// binary subprocess tests.
package tunneldfake

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/yamux"

	"github.com/choonkeat/swe-swe-tunnel/internal/control"
)

// Server is a running fake tunneld with a TLS endpoint.
type Server struct {
	httptest *httptest.Server
	apex     string
	tlsCfg   *tls.Config

	registers atomic.Int32

	mu        sync.Mutex
	killAfter int      // 1-indexed nth registration to drop after RegisterOK
	denyQueue []string // FIFO of Deny.Reason strings to send on the next Register frames
	logf      func(format string, args ...any)
}

// Options configures the fake tunneld.
type Options struct {
	// Apex is the DNS suffix the fake appends to the {unique}-tunnel
	// label when constructing the registered hostname. Defaults to
	// "tunnel.test" if empty.
	Apex string
	// Logf, if set, receives diagnostic messages. Defaults to
	// silently dropping them. Pass t.Logf in tests.
	Logf func(format string, args ...any)
}

// Start launches a TLS-fronted fake tunneld and returns a *Server bound
// to it. Callers must call Close on the returned server.
func Start(opts Options) (*Server, error) {
	apex := opts.Apex
	if apex == "" {
		apex = "tunnel.test"
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	s := &Server{
		apex: apex,
		logf: logf,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/connect", s.handleConnect)
	srv := httptest.NewTLSServer(mux)
	s.httptest = srv

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	u, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		return nil, fmt.Errorf("parse fake URL %q: %w", srv.URL, err)
	}
	s.tlsCfg = &tls.Config{
		RootCAs:    roots,
		ServerName: u.Hostname(),
		MinVersion: tls.VersionTLS12,
	}
	return s, nil
}

// Close stops the fake server.
func (s *Server) Close() {
	if s.httptest != nil {
		s.httptest.Close()
	}
}

// URL is the public https:// endpoint clients should dial.
func (s *Server) URL() string { return s.httptest.URL }

// TLSConfig is a tls.Config trusting the fake's self-signed cert; pass
// it as Options.TLSConfig on the client.
func (s *Server) TLSConfig() *tls.Config { return s.tlsCfg }

// Certificate returns the fake's TLS cert; useful when constructing a
// CA bundle file for a subprocess client (which can't share an in-
// process *tls.Config).
func (s *Server) Certificate() []byte {
	if s.httptest == nil {
		return nil
	}
	return s.httptest.Certificate().Raw
}

// Apex returns the configured apex domain.
func (s *Server) Apex() string { return s.apex }

// Registrations returns the count of successful Register frames seen.
func (s *Server) Registrations() int { return int(s.registers.Load()) }

// KillNextSession arms the fake to drop the TCP conn immediately after
// the next RegisterOK. Used by tests that exercise the client's
// reconnect path.
func (s *Server) KillNextSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killAfter = int(s.registers.Load()) + 1
}

// DenyNextRegister queues a Deny.Reason to send back on the next
// incoming Register frame instead of RegisterOK. Calls stack: each
// queued reason is consumed in FIFO order. After the queue drains,
// subsequent Registers succeed normally.
//
// Used by tests that exercise the client's deny-handling paths
// (rate-limit backoff, permanent-fatal exit).
func (s *Server) DenyNextRegister(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denyQueue = append(s.denyQueue, reason)
}

// nextDenyReason pops one queued deny reason; ok=false means none queued.
func (s *Server) nextDenyReason() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.denyQueue) == 0 {
		return "", false
	}
	r := s.denyQueue[0]
	s.denyQueue = s.denyQueue[1:]
	return r, true
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), control.UpgradeProtocol) {
		http.Error(w, "upgrade", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: " + control.UpgradeProtocol + "\r\n" +
		"Connection: Upgrade\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		s.logf("tunneldfake: write 101: %v", err)
		_ = conn.Close()
		return
	}
	if err := brw.Flush(); err != nil {
		s.logf("tunneldfake: flush 101: %v", err)
		_ = conn.Close()
		return
	}

	yam, err := yamux.Server(conn, nil)
	if err != nil {
		s.logf("tunneldfake: yamux server: %v", err)
		_ = conn.Close()
		return
	}
	defer yam.Close()

	stream, err := yam.AcceptStream()
	if err != nil {
		s.logf("tunneldfake: accept stream: %v", err)
		return
	}

	frame, err := control.ReadFrame(stream)
	if err != nil {
		s.logf("tunneldfake: read register: %v", err)
		return
	}
	if frame.Type != control.KindRegister {
		s.logf("tunneldfake: want Register, got %q", frame.Type)
		return
	}
	var reg control.Register
	if err := control.DecodePayload(frame, &reg); err != nil {
		s.logf("tunneldfake: decode register: %v", err)
		return
	}
	if reason, ok := s.nextDenyReason(); ok {
		if err := control.WriteMessage(stream, control.KindDeny, control.Deny{
			Reason: reason,
		}); err != nil {
			s.logf("tunneldfake: write deny: %v", err)
		}
		return
	}
	hostname := control.TunnelLabel(reg.Unique) + "." + s.apex
	if err := control.WriteMessage(stream, control.KindRegisterOK, control.RegisterOK{
		Hostname: hostname,
	}); err != nil {
		s.logf("tunneldfake: write register_ok: %v", err)
		return
	}

	registered := s.registers.Add(1)

	s.mu.Lock()
	shouldKill := s.killAfter != 0 && int(registered) == s.killAfter
	s.mu.Unlock()
	if shouldKill {
		_ = conn.Close()
		return
	}

	for {
		fr, err := control.ReadFrame(stream)
		if err != nil {
			return
		}
		if fr.Type == control.KindDeregister {
			if err := control.WriteMessage(stream, control.KindDeregisterOK, control.DeregisterOK{}); err != nil {
				s.logf("tunneldfake: write deregister_ok: %v", err)
			}
			return
		}
	}
}
