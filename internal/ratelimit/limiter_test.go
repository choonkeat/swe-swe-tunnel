package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSlidingWindow_Basic(t *testing.T) {
	lim := New(3, time.Hour)
	t0 := time.Unix(1714137600, 0)

	for i := 0; i < 3; i++ {
		if !lim.AllowAt("ip", t0.Add(time.Duration(i)*time.Minute)) {
			t.Errorf("call %d should be allowed", i+1)
		}
	}
	if lim.AllowAt("ip", t0.Add(4*time.Minute)) {
		t.Error("4th call within window should be denied")
	}
}

func TestSlidingWindow_Window(t *testing.T) {
	lim := New(2, time.Hour)
	t0 := time.Unix(1714137600, 0)

	if !lim.AllowAt("ip", t0) {
		t.Fatal("1 should be allowed")
	}
	if !lim.AllowAt("ip", t0.Add(30*time.Minute)) {
		t.Fatal("2 should be allowed")
	}
	if lim.AllowAt("ip", t0.Add(45*time.Minute)) {
		t.Fatal("3 within window should be denied")
	}
	// One hour after t0, the first sample falls out of the window.
	if !lim.AllowAt("ip", t0.Add(time.Hour+time.Second)) {
		t.Error("3 should be allowed once oldest sample expires")
	}
}

func TestSlidingWindow_DistinctKeys(t *testing.T) {
	lim := New(1, time.Hour)
	t0 := time.Unix(1714137600, 0)

	if !lim.AllowAt("a", t0) {
		t.Fatal("a/1 should be allowed")
	}
	if !lim.AllowAt("b", t0) {
		t.Fatal("b/1 should be allowed (different key)")
	}
	if lim.AllowAt("a", t0) {
		t.Error("a/2 should be denied")
	}
	if lim.AllowAt("b", t0) {
		t.Error("b/2 should be denied")
	}
}

func TestSlidingWindow_Disabled(t *testing.T) {
	lim := New(0, time.Hour)
	t0 := time.Unix(1714137600, 0)
	for i := 0; i < 1000; i++ {
		if !lim.AllowAt("k", t0) {
			t.Fatalf("max=0 should disable the limit, but call %d was denied", i)
		}
	}
}

func TestSlidingWindow_Prune(t *testing.T) {
	lim := New(5, time.Hour)
	t0 := time.Unix(1714137600, 0)

	for _, k := range []string{"a", "b", "c"} {
		_ = lim.AllowAt(k, t0)
	}
	if got, want := lim.Size(), 3; got != want {
		t.Fatalf("Size = %d, want %d", got, want)
	}

	// 90 minutes later, all events are outside the 1-hour window.
	lim.PruneAt(t0.Add(90 * time.Minute))
	if got := lim.Size(); got != 0 {
		t.Errorf("after prune, Size = %d, want 0", got)
	}
}

func TestSlidingWindow_RetryAfter_ZeroWhenSpareCapacity(t *testing.T) {
	lim := New(3, time.Hour)
	t0 := time.Unix(1714137600, 0)

	// Empty: trivially zero.
	if d := lim.RetryAfterAt("k", t0); d != 0 {
		t.Errorf("RetryAfter on empty key = %v, want 0", d)
	}
	// One sample, capacity 3: still has spare.
	_ = lim.AllowAt("k", t0)
	if d := lim.RetryAfterAt("k", t0); d != 0 {
		t.Errorf("RetryAfter with 1/3 used = %v, want 0", d)
	}
	// Two samples: still has spare.
	_ = lim.AllowAt("k", t0.Add(5*time.Minute))
	if d := lim.RetryAfterAt("k", t0.Add(5*time.Minute)); d != 0 {
		t.Errorf("RetryAfter with 2/3 used = %v, want 0", d)
	}
}

func TestSlidingWindow_RetryAfter_FullWindow(t *testing.T) {
	lim := New(2, time.Hour)
	t0 := time.Unix(1714137600, 0)

	_ = lim.AllowAt("k", t0)
	_ = lim.AllowAt("k", t0.Add(15*time.Minute))

	// Window is full; oldest sample at t0 expires at t0+1h.
	// At t0+30min, retry-after should be 30min (until oldest expires).
	if got, want := lim.RetryAfterAt("k", t0.Add(30*time.Minute)), 30*time.Minute; got != want {
		t.Errorf("RetryAfter at t0+30min = %v, want %v", got, want)
	}
	// At t0+59min, retry-after is 1min.
	if got, want := lim.RetryAfterAt("k", t0.Add(59*time.Minute)), 1*time.Minute; got != want {
		t.Errorf("RetryAfter at t0+59min = %v, want %v", got, want)
	}
	// Past expiry of the oldest sample: capacity returns, retry-after = 0.
	if got := lim.RetryAfterAt("k", t0.Add(time.Hour+time.Second)); got != 0 {
		t.Errorf("RetryAfter past first sample expiry = %v, want 0", got)
	}
}

func TestSlidingWindow_RetryAfter_DisabledReturnsZero(t *testing.T) {
	lim := New(0, time.Hour)
	t0 := time.Unix(1714137600, 0)
	if d := lim.RetryAfterAt("k", t0); d != 0 {
		t.Errorf("RetryAfter on max=0 limiter = %v, want 0", d)
	}
}

func TestSlidingWindow_RetryAfter_DistinctKeys(t *testing.T) {
	lim := New(1, time.Hour)
	t0 := time.Unix(1714137600, 0)

	_ = lim.AllowAt("a", t0)
	// "a" is full, "b" is empty.
	if got, want := lim.RetryAfterAt("a", t0.Add(10*time.Minute)), 50*time.Minute; got != want {
		t.Errorf("RetryAfter('a') = %v, want %v", got, want)
	}
	if got := lim.RetryAfterAt("b", t0.Add(10*time.Minute)); got != 0 {
		t.Errorf("RetryAfter('b', no samples) = %v, want 0", got)
	}
}

// Allow + RetryAfter agree: when Allow returns false, RetryAfter must be
// strictly positive; when Allow returns true, RetryAfter may be zero
// (immediately) or positive (after consuming the Nth slot).
func TestSlidingWindow_RetryAfter_AgreesWithAllow(t *testing.T) {
	lim := New(2, time.Hour)
	t0 := time.Unix(1714137600, 0)

	_ = lim.AllowAt("k", t0)
	_ = lim.AllowAt("k", t0.Add(10*time.Minute))
	// Window full now: Allow must deny, RetryAfter must be positive.
	if lim.AllowAt("k", t0.Add(20*time.Minute)) {
		t.Fatal("Allow: want false on full window")
	}
	if d := lim.RetryAfterAt("k", t0.Add(20*time.Minute)); d <= 0 {
		t.Errorf("RetryAfter on denied call = %v, want > 0", d)
	}
}

// TestSlidingWindow_KeyCapBounded verifies the security fix for the
// memory-exhaustion DoS: with a cap of N, an attacker submitting M >> N
// distinct keys cannot grow Size() past N. Without this cap a single
// IPv6 /64 source pool would let an attacker OOM the server.
func TestSlidingWindow_KeyCapBounded(t *testing.T) {
	lim := New(5, time.Hour)
	lim.SetMaxKeys(50)
	t0 := time.Unix(1714137600, 0)

	// Insert 1000 distinct keys; samples never age out within this
	// window so pruning can't recover slots.
	for i := 0; i < 1000; i++ {
		lim.AllowAt(fmt.Sprintf("ip-%d", i), t0)
	}
	if got := lim.Size(); got > 50 {
		t.Errorf("Size = %d, want <= 50 (cap)", got)
	}
}

// TestSlidingWindow_KeyCapPrunesFirst checks the cap path's behavior
// when keys have aged out: the cheap prune sweep should free slots
// without forcing eviction of live keys. This means a steady stream of
// short-lived keys doesn't constantly evict each other.
func TestSlidingWindow_KeyCapPrunesFirst(t *testing.T) {
	lim := New(5, time.Hour)
	lim.SetMaxKeys(10)
	t0 := time.Unix(1714137600, 0)

	// Fill with 10 keys at t0 (cap reached but not yet exceeded).
	for i := 0; i < 10; i++ {
		lim.AllowAt(fmt.Sprintf("old-%d", i), t0)
	}
	if got := lim.Size(); got != 10 {
		t.Fatalf("setup: Size = %d, want 10", got)
	}

	// 90 minutes later, all 10 are aged out (window=1h). Inserting a
	// new key should trigger the prune sweep, dropping all 10 and
	// admitting the new one without eviction pressure.
	lim.AllowAt("fresh", t0.Add(90*time.Minute))
	if got := lim.Size(); got != 1 {
		t.Errorf("Size after insert past expiry = %d, want 1 (10 stale pruned)", got)
	}
}

// TestSlidingWindow_KeyCapZeroDisablesCap is the escape hatch: setting
// the cap to <=0 must restore the old unbounded behavior. Tests that
// rely on the legacy semantic shouldn't need rewriting just because
// the default cap is now finite.
func TestSlidingWindow_KeyCapZeroDisablesCap(t *testing.T) {
	lim := New(5, time.Hour)
	lim.SetMaxKeys(0)
	t0 := time.Unix(1714137600, 0)
	for i := 0; i < 500; i++ {
		lim.AllowAt(fmt.Sprintf("k-%d", i), t0)
	}
	if got := lim.Size(); got != 500 {
		t.Errorf("Size = %d, want 500 (cap disabled)", got)
	}
}

// TestSlidingWindow_RunPruner_DropsAgedKeys ensures the production
// janitor goroutine actually shrinks the map. Without RunPruner being
// wired from main, idle keys live forever even with the cap (the cap
// only triggers on insert pressure).
func TestSlidingWindow_RunPruner_DropsAgedKeys(t *testing.T) {
	// Use a real wall-clock window short enough that the test finishes
	// quickly. now is the wall clock; we can't override mid-test
	// because RunPruner uses time.Ticker. Use a 50ms window and a
	// 20ms prune interval — fast enough for CI but >0 to make the
	// scheduler happy.
	lim := New(5, 50*time.Millisecond)

	// Insert 100 keys at "now"; they age out 50ms later.
	for i := 0; i < 100; i++ {
		lim.Allow(fmt.Sprintf("k-%d", i))
	}
	if lim.Size() != 100 {
		t.Fatalf("setup: Size=%d, want 100", lim.Size())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go lim.RunPruner(ctx, 20*time.Millisecond)

	// Wait for one full prune cycle past expiry.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if lim.Size() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := lim.Size(); got != 0 {
		t.Errorf("Size after expiry + prune ticks = %d, want 0", got)
	}
}

// TestSlidingWindow_RunPruner_StopsOnContextCancel verifies the
// goroutine exits cleanly — otherwise restarting the server in tests
// or under hot-reload would leak goroutines.
func TestSlidingWindow_RunPruner_StopsOnContextCancel(t *testing.T) {
	lim := New(5, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		lim.RunPruner(ctx, 10*time.Millisecond)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunPruner did not exit within 1s of ctx cancel")
	}
}

func TestSlidingWindow_CancelLatest_RefundsBudget(t *testing.T) {
	lim := New(2, time.Hour)
	t0 := time.Unix(1714137600, 0)

	if !lim.AllowAt("k", t0) {
		t.Fatal("1 should be allowed")
	}
	if !lim.AllowAt("k", t0.Add(10*time.Minute)) {
		t.Fatal("2 should be allowed")
	}
	// Window full — 3rd would be denied.
	if lim.AllowAt("k", t0.Add(20*time.Minute)) {
		t.Fatal("3rd should be denied at full window")
	}

	// Refund the latest. Now 2/2 → 1/2 used, so a fresh attempt fits.
	lim.CancelLatest("k")
	if !lim.AllowAt("k", t0.Add(20*time.Minute)) {
		t.Error("after CancelLatest, the next Allow should fit in spare capacity")
	}
}

func TestSlidingWindow_CancelLatest_NoOpWhenEmpty(t *testing.T) {
	lim := New(3, time.Hour)
	// Cancelling an absent key must not panic and must not poison the map.
	lim.CancelLatest("never-seen")
	if got := lim.Size(); got != 0 {
		t.Errorf("Size after cancel of unknown key = %d, want 0", got)
	}
	// Cancel more times than Allow — still fine.
	lim.AllowAt("k", time.Unix(1, 0))
	lim.CancelLatest("k")
	lim.CancelLatest("k") // extra cancel, no-op
	if got := lim.Size(); got != 0 {
		t.Errorf("Size after over-cancel = %d, want 0", got)
	}
}

func TestSlidingWindow_CancelLatest_DistinctKeys(t *testing.T) {
	lim := New(1, time.Hour)
	t0 := time.Unix(1714137600, 0)
	_ = lim.AllowAt("a", t0)
	_ = lim.AllowAt("b", t0)
	// Cancelling on "a" must not refund "b".
	lim.CancelLatest("a")
	if lim.AllowAt("b", t0) {
		t.Error("CancelLatest('a') must not free budget on 'b'")
	}
	if !lim.AllowAt("a", t0) {
		t.Error("CancelLatest('a') should free budget on 'a'")
	}
}

func TestSlidingWindow_CancelLatest_DisabledNoOp(t *testing.T) {
	lim := New(0, time.Hour) // disabled
	// CancelLatest on a disabled limiter is a benign no-op (no map entries
	// were ever recorded; just confirm we don't panic).
	lim.CancelLatest("k")
}

func TestSlidingWindow_CancelLatest_AffectsRetryAfter(t *testing.T) {
	lim := New(2, time.Hour)
	t0 := time.Unix(1714137600, 0)
	_ = lim.AllowAt("k", t0)
	_ = lim.AllowAt("k", t0.Add(10*time.Minute))
	// Full window: RetryAfter is positive.
	if d := lim.RetryAfterAt("k", t0.Add(10*time.Minute)); d == 0 {
		t.Fatal("expected non-zero RetryAfter at full window")
	}
	lim.CancelLatest("k")
	// Now 1/2 used → spare capacity → RetryAfter must be 0.
	if d := lim.RetryAfterAt("k", t0.Add(10*time.Minute)); d != 0 {
		t.Errorf("RetryAfter after CancelLatest = %v, want 0 (spare capacity)", d)
	}
}

func TestSlidingWindow_Concurrent(t *testing.T) {
	lim := New(100, time.Hour)
	var wg sync.WaitGroup
	const goroutines = 10
	const perGoroutine = 100
	allowed := make([]int, goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if lim.Allow("shared") {
					allowed[g]++
				}
			}
		}()
	}
	wg.Wait()

	total := 0
	for _, n := range allowed {
		total += n
	}
	if total != 100 {
		t.Errorf("total allowed = %d under contention, want exactly 100", total)
	}
}
