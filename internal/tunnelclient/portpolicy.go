package tunnelclient

import (
	"fmt"
	"strconv"
	"strings"
)

// PortPolicy decides which destination ports PortDispatchHandler is
// allowed to forward to. Without a policy the client would gladly proxy
// the public Internet to every TCP port on the target host (SSH, Redis,
// Docker daemon, etc.) — see docs/design.md non-goal "Arbitrary 1–65535
// ports on the public side".
//
// A zero PortPolicy permits nothing. Use AllowAllPorts() to disable the
// gate, or ParsePortPolicy to build one from a comma/range spec like
// "1977,3000-3099,8080".
type PortPolicy struct {
	all    bool
	single map[int]struct{}
	ranges []portRange
}

type portRange struct{ lo, hi int }

// AllowAllPorts returns a PortPolicy that permits every port. Convenient
// for tests and for operators who explicitly opt out of the allowlist
// (`--ports=all`). Production use is strongly discouraged.
func AllowAllPorts() *PortPolicy {
	return &PortPolicy{all: true}
}

// DefaultPortSpec is the conservative default — covers the ports
// docs/design.md mentions (1977, 3000, 4000, …) plus the common dev/web
// ranges. Operators with services outside this set must override
// `--ports` explicitly.
const DefaultPortSpec = "1977,3000-3099,4000-4099,5000-5099,5173,8000-8099,8080,8081"

// ParsePortPolicy builds a PortPolicy from a comma-separated spec.
// Each element is either a single port (`8080`) or an inclusive range
// (`3000-3099`). The literal string "all" returns AllowAllPorts(); an
// empty spec returns the zero policy (deny-all).
//
// Returns an error on malformed input rather than silently dropping
// entries — a typo in `--ports` should fail loudly, not be a permissive
// surprise.
func ParsePortPolicy(spec string) (*PortPolicy, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return &PortPolicy{}, nil
	}
	if strings.EqualFold(spec, "all") {
		return AllowAllPorts(), nil
	}
	p := &PortPolicy{single: make(map[int]struct{})}
	for _, raw := range strings.Split(spec, ",") {
		piece := strings.TrimSpace(raw)
		if piece == "" {
			continue
		}
		if dash := strings.IndexByte(piece, '-'); dash > 0 {
			lo, err := parsePort(piece[:dash])
			if err != nil {
				return nil, fmt.Errorf("port range %q: %w", piece, err)
			}
			hi, err := parsePort(piece[dash+1:])
			if err != nil {
				return nil, fmt.Errorf("port range %q: %w", piece, err)
			}
			if lo > hi {
				return nil, fmt.Errorf("port range %q: lo > hi", piece)
			}
			p.ranges = append(p.ranges, portRange{lo: lo, hi: hi})
			continue
		}
		port, err := parsePort(piece)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", piece, err)
		}
		p.single[port] = struct{}{}
	}
	return p, nil
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not an integer")
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("out of TCP port range")
	}
	return n, nil
}

// Permits reports whether port may be forwarded.
func (p *PortPolicy) Permits(port int) bool {
	if p == nil {
		return false
	}
	if p.all {
		return true
	}
	if _, ok := p.single[port]; ok {
		return true
	}
	for _, r := range p.ranges {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

// String returns a human-readable summary suitable for startup logs.
func (p *PortPolicy) String() string {
	if p == nil {
		return "deny-all (nil policy)"
	}
	if p.all {
		return "all ports (unrestricted)"
	}
	parts := make([]string, 0, len(p.single)+len(p.ranges))
	for n := range p.single {
		parts = append(parts, strconv.Itoa(n))
	}
	for _, r := range p.ranges {
		parts = append(parts, fmt.Sprintf("%d-%d", r.lo, r.hi))
	}
	if len(parts) == 0 {
		return "deny-all (empty policy)"
	}
	return strings.Join(parts, ",")
}
