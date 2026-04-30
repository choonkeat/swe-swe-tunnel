// Package ratelimit implements a sliding-window event counter used to bound
// the rate of REGISTER attempts per source IP and per Ed25519 pubkey.
//
// One event per Allow call. Within `window`, no more than `max` events
// per key are admitted; the (max+1)-th in the same window is rejected.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// SlidingWindow tracks per-key event timestamps. Allow is O(events-in-window).
type SlidingWindow struct {
	max     int
	window  time.Duration
	maxKeys int
	now     func() time.Time

	mu   sync.Mutex
	seen map[string][]time.Time
}

// DefaultMaxKeys is the conservative ceiling on distinct tracked keys.
// Without a cap, an attacker with many source IPs (trivially obtainable
// from a single IPv6 /64) can grow `seen` without bound and OOM the
// process. 100k keys × ~250B/entry ≈ 25 MB worst case.
const DefaultMaxKeys = 100_000

// New returns a SlidingWindow accepting at most `max` events per key per
// `window`. A zero or negative max disables the limit (Allow always returns
// true). The map is bounded to DefaultMaxKeys distinct keys; use
// SetMaxKeys to override.
func New(max int, window time.Duration) *SlidingWindow {
	return &SlidingWindow{
		max:     max,
		window:  window,
		maxKeys: DefaultMaxKeys,
		now:     time.Now,
		seen:    make(map[string][]time.Time),
	}
}

// SetMaxKeys bounds the distinct-key map size. Insertions past the cap
// trigger an opportunistic prune (drop keys whose timestamps have all
// aged out); if pruning doesn't free a slot, one expired-or-oldest key
// is evicted. A non-positive value disables the cap (NOT recommended in
// production — unbounded keys is the DoS vector this exists to close).
func (s *SlidingWindow) SetMaxKeys(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxKeys = n
}

// Allow records an event for key at the current time and returns true if it
// fits within the window's capacity.
func (s *SlidingWindow) Allow(key string) bool {
	return s.AllowAt(key, s.now())
}

// AllowAt is the deterministic variant used by tests.
func (s *SlidingWindow) AllowAt(key string, now time.Time) bool {
	if s.max <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-s.window)
	samples := s.seen[key]

	// Drop entries that are at or before the cutoff (i.e. older than window).
	i := 0
	for i < len(samples) && !samples[i].After(cutoff) {
		i++
	}
	if i > 0 {
		samples = samples[i:]
	}

	if len(samples) >= s.max {
		// Persist pruned slice so callers don't accumulate stale entries.
		s.seen[key] = samples
		return false
	}

	// New-key insertion path: bound the map size. Without this an attacker
	// rotating source IPs (or pubkeys) can grow `seen` without bound.
	if _, exists := s.seen[key]; !exists && s.maxKeys > 0 && len(s.seen) >= s.maxKeys {
		// Try a cheap sweep first — anything entirely aged out is free
		// to drop.
		s.pruneLocked(now)
		if len(s.seen) >= s.maxKeys {
			// Still over the cap. Evict one key to make room. Map
			// iteration order is randomized, so the choice is
			// effectively random-eviction; that's acceptable for a
			// rate-limit map (worst case: an attacker briefly gets a
			// fresh budget). The alternative — refusing the new key —
			// would let an attacker DoS legitimate clients by
			// pre-filling the cap.
			for k := range s.seen {
				delete(s.seen, k)
				break
			}
		}
	}

	samples = append(samples, now)
	s.seen[key] = samples
	return true
}

// Prune walks the map and removes entries whose timestamp lists are entirely
// older than the window. Call this periodically from a background goroutine if
// the key cardinality is unbounded.
func (s *SlidingWindow) Prune() {
	s.PruneAt(s.now())
}

// PruneAt is the deterministic variant.
func (s *SlidingWindow) PruneAt(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
}

// pruneLocked is the inner implementation; caller must hold s.mu.
func (s *SlidingWindow) pruneLocked(now time.Time) {
	cutoff := now.Add(-s.window)
	for k, samples := range s.seen {
		i := 0
		for i < len(samples) && !samples[i].After(cutoff) {
			i++
		}
		if i == len(samples) {
			delete(s.seen, k)
			continue
		}
		if i > 0 {
			s.seen[k] = samples[i:]
		}
	}
}

// RunPruner blocks, pruning the map every `interval` until ctx is
// canceled. Wire this from main alongside the limiter creation so the
// bound on `seen` doesn't depend on the eviction path inside Allow
// alone — long-idle keys ought to drop without waiting for cap pressure.
func (s *SlidingWindow) RunPruner(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Prune()
		}
	}
}

// Size returns the number of distinct keys currently tracked. Useful for
// monitoring or test assertions.
func (s *SlidingWindow) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// RetryAfter returns how long until the next call to Allow(key) can
// possibly succeed: i.e. the time until the oldest sample currently in
// the window ages out. Returns zero when the window has spare capacity
// (Allow would already succeed) or when limits are disabled.
//
// Used by the server to populate Deny.RetryAfterSec, so a rate-limited
// client can back off exactly long enough instead of guessing.
func (s *SlidingWindow) RetryAfter(key string) time.Duration {
	return s.RetryAfterAt(key, s.now())
}

// RetryAfterAt is the deterministic variant used by tests.
func (s *SlidingWindow) RetryAfterAt(key string, now time.Time) time.Duration {
	if s.max <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-s.window)
	samples := s.seen[key]

	// Drop entries older than the window so the count below is accurate.
	i := 0
	for i < len(samples) && !samples[i].After(cutoff) {
		i++
	}
	if i > 0 {
		samples = samples[i:]
		s.seen[key] = samples
	}

	if len(samples) < s.max {
		// Spare capacity → no wait required.
		return 0
	}
	// Window is full; the oldest sample expires `window` after it was
	// recorded. d may be <= 0 in pathological clock-skew cases; clamp.
	d := samples[0].Add(s.window).Sub(now)
	if d < 0 {
		return 0
	}
	return d
}
