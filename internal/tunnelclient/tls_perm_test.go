package tunnelclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestIsPermanentTLSError is the table-level contract. Connect wraps
// the TLS handshake error with "tls handshake: %w" (and may layer
// "dial:" / "register:" above), so the classifier matches on
// substrings of the wrapped chain rather than typed errors -- Go's
// tls package returns string-only sentinels for most handshake
// alerts.
func TestIsPermanentTLSError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Permanent: server rejected the client cert / no cert / wrong CA.
		// These are operator misconfigurations; retrying without a fix
		// just pings a server that will keep alerting.
		{"bad_certificate alert", errors.New("remote error: tls: bad certificate"), true},
		{"certificate_required alert", errors.New("remote error: tls: certificate required"), true},
		{"unknown_certificate alert", errors.New("remote error: tls: unknown certificate"), true},
		{"unknown_ca alert", errors.New("remote error: tls: unknown certificate authority"), true},
		{"x509 unknown authority", errors.New("x509: certificate signed by unknown authority"), true},
		{"expired", errors.New("x509: certificate has expired or is not yet valid"), true},
		{"revoked", errors.New("remote error: tls: certificate revoked"), true},

		// Operator-side cert/key file errors -- never resolve themselves.
		{"PEM not found", errors.New("tls: failed to find any PEM data in certificate input"), true},
		{"key cert mismatch", errors.New("tls: private key does not match public key"), true},

		// Wrapped through the Connect error chain.
		{"wrapped dial", fmt.Errorf("dial: %w", errors.New("remote error: tls: bad certificate")), true},
		{"wrapped tls handshake", fmt.Errorf("tls handshake: %w", errors.New("remote error: tls: bad certificate")), true},

		// Transient -- retry should help.
		{"timeout", errors.New("read tcp 1.2.3.4:443: i/o timeout"), false},
		{"connection refused", errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), false},
		{"EOF", errors.New("EOF"), false},
		{"DNS failure", errors.New("dial tcp: lookup tunnel.example.com: no such host"), false},

		// Not a TLS thing at all.
		{"register: store error (server-side)", errors.New("register: server denied: store error"), false},

		// Edge cases.
		{"nil", nil, false},
		{"empty", errors.New(""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPermanentTLSError(tc.err); got != tc.want {
				t.Errorf("isPermanentTLSError(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestE2E_Run_PermanentTLSErrorEmitsFatal proves the classifier is
// wired into the supervisor: pointing Run at an mTLS-enabled server
// with no client cert must terminate with EventFatal as the last
// event, not loop forever pinging a server that will reject every
// retry the same way.
func TestE2E_Run_PermanentTLSErrorEmitsFatal(t *testing.T) {
	// Build a TLS server gated by RequireAndVerifyClientCert. The
	// ClientCAs pool is non-nil but empty — every client cert (or
	// absence thereof) fails verification, which is what we want to
	// drive the permanent-TLS-error code path.
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  x509.NewCertPool(),
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		RootCAs:    roots,
		ServerName: u.Hostname(),
		MinVersion: tls.VersionTLS12,
		// No Certificates — the server will reject the handshake.
	}

	cap := &captureBuffer{}
	em := NewJSONLEmitter(cap)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := Run(ctx, RunOptions{
		Connect: Options{
			ServerURL:  srv.URL,
			Unique:     "permtls",
			PrivateKey: freshKey(t),
			TLSConfig:  tlsCfg,
			Logger:     logger,
			Emitter:    em,
		},
		Handler:    http.NotFoundHandler(),
		BackoffMin: 5 * time.Millisecond,
		BackoffMax: 10 * time.Millisecond,
		// MaxAttempts=0 (unlimited) — proves the TLS-permanent arm
		// bypasses retries regardless of the attempt cap.
	})
	if runErr == nil {
		t.Fatal("Run: want non-nil error on TLS permanent failure")
	}
	kinds := readEventKinds(t, cap.Bytes())
	if len(kinds) == 0 {
		t.Fatalf("no events emitted; stream:\n%s", cap.Bytes())
	}
	if last := kinds[len(kinds)-1]; last != EventFatal {
		t.Errorf("last event = %q, want %q; full stream:\n%s",
			last, EventFatal, cap.Bytes())
	}
}
