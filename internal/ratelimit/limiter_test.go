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
