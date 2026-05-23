package tunnelclient

import "strings"

// isPermanentTLSError reports whether err looks like a TLS handshake
// failure that retrying without operator intervention will not fix.
// The two canonical buckets are:
//
//   - Server-side alerts surfaced to the client when our cert is
//     missing, malformed, signed by the wrong CA, expired, or
//     revoked: "bad certificate", "certificate required",
//     "unknown certificate authority", etc. Looping in this state
//     just keeps consuming the daemon's TLS-handshake budget while
//     waiting for the operator to swap the cert.
//
//   - Local cert/key parsing errors: "failed to find any PEM data",
//     "private key does not match public key". These never resolve
//     on their own.
//
// Connect wraps the underlying error with "tls handshake: %w" and
// "dial: %w", so the classifier matches on substrings of the
// error's full message -- Go's tls package returns string-only
// sentinels for most alerts. Transient network errors (timeout,
// connection refused, EOF, DNS failure) are NOT classified as
// permanent: those resolve on their own with a retry.
//
// Caller is the supervisor in run.go; symmetric with the existing
// DenyError.IsPermanent arm.
func isPermanentTLSError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if msg == "" {
		return false
	}
	// TLS alerts (server -> client) that mean the operator must
	// reissue / install a cert before retrying.
	permanent := []string{
		"tls: bad certificate",
		"tls: certificate required",
		"tls: unknown certificate authority",
		"tls: unknown certificate",
		"tls: certificate revoked",
		"tls: certificate expired",
	}
	for _, p := range permanent {
		if strings.Contains(msg, p) {
			return true
		}
	}
	// Local x509 / cert-load failures.
	localPermanent := []string{
		"x509: certificate signed by unknown authority",
		"x509: certificate has expired",
		"failed to find any PEM data",
		"private key does not match public key",
	}
	for _, p := range localPermanent {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
