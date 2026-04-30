package ratelimit

import (
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
