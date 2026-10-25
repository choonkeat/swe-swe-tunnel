package cert

import (
	"errors"
	"strings"

	"github.com/go-acme/lego/v4/acme"
)

// ErrOrderLimit is returned by Manager.EnsureName when the server-wide
// cap on new ACME orders is reached (too many per hour, or too many
// running at once). It protects the operator's Let's Encrypt account
// from being driven into its own per-account limits by Register floods.
var ErrOrderLimit = errors.New("acme order limit reached")

// acmeRateLimited is the ACME problem type Let's Encrypt returns when
// one of its rate limits is hit (RFC 8555 section 6.7).
const acmeRateLimited = "urn:ietf:params:acme:error:rateLimited"

// IsPermanent reports whether a cert failure will not go away by
// retrying soon. Register does not refund the caller's rate-limit
// budget for these, because a refund would let an attacker loop on
// them for free.
//
// Permanent: our own order cap, Let's Encrypt rate limits, and
// --no-acme "cert not provisioned" (only the operator can fix it).
func IsPermanent(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrOrderLimit) {
		return true
	}
	var pd *acme.ProblemDetails
	if errors.As(err, &pd) && pd.Type == acmeRateLimited {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, acmeRateLimited) ||
		strings.HasPrefix(msg, "cert not provisioned")
}
