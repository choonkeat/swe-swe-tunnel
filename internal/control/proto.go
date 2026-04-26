// Package control defines the wire protocol for the tunnel control channel.
//
// After the HTTP `Upgrade: swe-swe-tunnel/1` handshake on POST /v1/connect, the
// hijacked connection is wrapped in yamux. Stream 1 carries length-prefixed
// JSON control frames (this package). All other streams carry forwarded HTTP
// requests, opened server→client per public-side request.
//
// Frame format:
//
//	[4 bytes big-endian length][JSON payload]
//
// Phase 2 only defines ClientHello / ServerHello. Phase 3 will add Challenge,
// Proof, Deny, Deregister.
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
	// small (well under 1 KiB).
	MaxFrameBytes = 64 * 1024

	// UpgradeProtocol is the value sent in `Upgrade:` and matched by the
	// server. Bump alongside ProtoVersion.
	UpgradeProtocol = "swe-swe-tunnel/1"
)

// ClientHello is the first frame the client sends on stream 1.
type ClientHello struct {
	Version int    `json:"version"`
	Unique  string `json:"unique"`
}

// ServerHello is the server's reply on stream 1. OK=false carries Reason.
type ServerHello struct {
	OK       bool   `json:"ok"`
	Hostname string `json:"hostname,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// WriteFrame length-prefixes and writes a JSON-encoded message.
func WriteFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
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

// ReadFrame reads a length-prefixed JSON frame into v.
func ReadFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("control: read header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return errors.New("control: empty frame")
	}
	if n > MaxFrameBytes {
		return fmt.Errorf("control: frame too large (%d > %d)", n, MaxFrameBytes)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("control: read payload: %w", err)
	}
	if err := json.Unmarshal(buf, v); err != nil {
		return fmt.Errorf("control: unmarshal: %w", err)
	}
	return nil
}
