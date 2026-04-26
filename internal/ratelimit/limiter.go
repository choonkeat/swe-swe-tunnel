// Package ratelimit implements a sliding-window event counter used to bound
// the rate of REGISTER attempts per source IP and per Ed25519 pubkey.
//
// One event per Allow call. Within `window`, no more than `max` events
// per key are admitted; the (max+1)-th in the same window is rejected.
package ratelimit

import (
	"sync"
	"time"
)

// SlidingWindow tracks per-key event timestamps. Allow is O(events-in-window).
type SlidingWindow struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu   sync.Mutex
	seen map[string][]time.Time
}

// New returns a SlidingWindow accepting at most `max` events per key per
// `window`. A zero or negative max disables the limit (Allow always returns
// true).
func New(max int, window time.Duration) *SlidingWindow {
	return &SlidingWindow{
		max:    max,
		window: window,
		now:    time.Now,
		seen:   make(map[string][]time.Time),
	}
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

// Size returns the number of distinct keys currently tracked. Useful for
// monitoring or test assertions.
func (s *SlidingWindow) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}
