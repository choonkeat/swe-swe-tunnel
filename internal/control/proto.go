// Package control defines the wire protocol for the tunnel control channel.
//
// After the HTTP `Upgrade: swe-swe-tunnel/1` handshake on POST /v1/connect, the
// hijacked connection is wrapped in yamux. Stream 1 carries length-prefixed
// JSON Frames (this package) — every message is a typed envelope:
//
//	[4 bytes big-endian length] [JSON: { "type": "<kind>", "payload": {...} }]
//
// Other yamux streams (server-initiated, client-accepted) carry HTTP/1.1 for
// the data plane.
//
// Phase 2 ClientHello/ServerHello have been retired; the wire is now typed
// throughout. Phase 3 messages: Register, RegisterOK, Challenge, Proof, Deny,
// Deregister.
package control

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const (
	// ProtoVersion is bumped when frame layout changes incompatibly.
	ProtoVersion = 1

	// MaxFrameBytes caps a single control frame to prevent a misbehaving peer
	// from forcing unbounded allocation. JSON frames in this protocol are
	// small (well under 1 KiB even with base64-encoded keys).
	MaxFrameBytes = 64 * 1024

	// UpgradeProtocol is the value sent in `Upgrade:` and matched by the
	// server. Bump alongside ProtoVersion.
	UpgradeProtocol = "swe-swe-tunnel/1"
)

// Kind is the discriminator for Frame.Type. Add new values here when extending
// the wire protocol; downstream switches should fall through to a Deny on
// unknown kinds.
type Kind string

const (
	KindRegister     Kind = "register"
	KindRegisterOK   Kind = "register_ok"
	KindChallenge    Kind = "challenge"
	KindProof        Kind = "proof"
	KindDeny         Kind = "deny"
	KindDeregister   Kind = "deregister"
	KindDeregisterOK Kind = "deregister_ok"
)

// Frame is the typed envelope on stream 1.
type Frame struct {
	Type    Kind            `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Register is the first message a client sends after stream-1 open. Pubkey is
// base64-RawStd-encoded Ed25519 (32 bytes); Sig is base64-RawStd of the
// Ed25519 signature over RegisterSigningPayload(pubkey, unique, timestamp).
type Register struct {
	Version   int    `json:"version"`
	Unique    string `json:"unique"`
	Pubkey    string `json:"pubkey"`
	Timestamp int64  `json:"timestamp"`
	Sig       string `json:"sig"`
}

// RegisterOK is the server's terminal "you're in" reply.
type RegisterOK struct {
	Hostname string `json:"hostname"`
}

// Challenge is sent when the requested unique already exists with a different
// pubkey. The client must Proof with the *stored* private key.
type Challenge struct {
	Nonce string `json:"nonce"` // base64 RawStd, 32 random bytes
}

// Proof is the client's reply to Challenge: signature of the nonce by the
// previously-registered (stored) private key.
type Proof struct {
	Sig string `json:"sig"` // base64 RawStd Ed25519(stored_priv, nonce_bytes)
}

// Deny is a terminal failure reply.
//
// RetryAfterSec is the server's hint for how long the client should
// wait before retrying. It is set only on rate_limited:* denies (zero
// otherwise) and is populated from the relevant SlidingWindow's
// RetryAfter, so the client can back off exactly long enough instead
// of guessing. Backwards-compatible: old clients ignore the field;
// new clients seeing zero from older servers fall back to their own
// RateLimitFloor.
type Deny struct {
	Reason        string `json:"reason"`
	RetryAfterSec int    `json:"retry_after_seconds,omitempty"`
}

// Deregister releases ownership of a unique. Sig must verify against the
// stored pubkey.
type Deregister struct {
	Unique    string `json:"unique"`
	Timestamp int64  `json:"timestamp"`
	Sig       string `json:"sig"`
}

// DeregisterOK is the server's terminal "row deleted" reply to Deregister.
// Empty struct: presence of the frame on the wire IS the success signal.
type DeregisterOK struct{}

// Domain separators prevent cross-protocol signature reuse. Format:
// "<package>/<purpose>/v<n>\n" + canonical fields.
const (
	domainRegister   = "swe-swe-tunnel/register/v1\n"
	domainProof      = "swe-swe-tunnel/proof/v1\n"
	domainDeregister = "swe-swe-tunnel/deregister/v1\n"
)

// RegisterSigningPayload returns the bytes a client signs for Register.
// Format: domain || pubkey (32 bytes) || unique (UTF-8) || timestamp (8 bytes BE).
func RegisterSigningPayload(pubkey []byte, unique string, timestamp int64) []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))
	out := make([]byte, 0, len(domainRegister)+len(pubkey)+len(unique)+8)
	out = append(out, domainRegister...)
	out = append(out, pubkey...)
	out = append(out, []byte(unique)...)
	out = append(out, ts[:]...)
	return out
}

// ProofSigningPayload returns the bytes a client signs for Proof.
// Format: domain || nonce (raw bytes).
func ProofSigningPayload(nonce []byte) []byte {
	out := make([]byte, 0, len(domainProof)+len(nonce))
	out = append(out, domainProof...)
	out = append(out, nonce...)
	return out
}

// DeregisterSigningPayload returns the bytes a client signs for Deregister.
// Format: domain || unique || timestamp (8 bytes BE).
func DeregisterSigningPayload(unique string, timestamp int64) []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))
	out := make([]byte, 0, len(domainDeregister)+len(unique)+8)
	out = append(out, domainDeregister...)
	out = append(out, []byte(unique)...)
	out = append(out, ts[:]...)
	return out
}

// uniqueRe enforces the `unique` shape from docs/design.md. Length 3–54 keeps
// `{unique}-tunnel` (+7) under the 63-char DNS label limit.
var uniqueRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,52}[a-z0-9]$`)

// ValidateUnique returns nil if s is a valid `unique` per the protocol.
func ValidateUnique(s string) error {
	if !uniqueRe.MatchString(s) {
		return fmt.Errorf("invalid unique %q: must match ^[a-z][a-z0-9-]{1,52}[a-z0-9]$", s)
	}
	return nil
}

// TunnelLabel returns the DNS label the server stores for the given unique
// (e.g. "abc" → "abc-tunnel"). The hostname is `{label}.{apex}`.
func TunnelLabel(unique string) string {
	return unique + "-tunnel"
}

// WriteFrame length-prefixes and writes one raw JSON envelope.
func WriteFrame(w io.Writer, f Frame) error {
	payload, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("control: marshal: %w", err)
	}
	if len(payload) > MaxFrameBytes {
		return fmt.Errorf("control: frame too large (%d > %d)", len(payload), MaxFrameBytes)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("control: write header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("control: write payload: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed JSON envelope.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, fmt.Errorf("control: read header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return Frame{}, errors.New("control: empty frame")
	}
	if n > MaxFrameBytes {
		return Frame{}, fmt.Errorf("control: frame too large (%d > %d)", n, MaxFrameBytes)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Frame{}, fmt.Errorf("control: read payload: %w", err)
	}
	var f Frame
	if err := json.Unmarshal(buf, &f); err != nil {
		return Frame{}, fmt.Errorf("control: unmarshal: %w", err)
	}
	return f, nil
}

// WriteMessage marshals payload as JSON and writes a Frame with the given Kind.
func WriteMessage(w io.Writer, k Kind, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("control: marshal payload: %w", err)
	}
	return WriteFrame(w, Frame{Type: k, Payload: raw})
}

// DecodePayload unmarshals the Frame's payload into v.
func DecodePayload(f Frame, v any) error {
	if len(f.Payload) == 0 {
		return errors.New("control: empty payload")
	}
	return json.Unmarshal(f.Payload, v)
}
