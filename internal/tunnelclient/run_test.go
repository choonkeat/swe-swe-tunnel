package tunnelclient

import (
	"context"
	"testing"
	"time"
)

func TestBackoffDuration(t *testing.T) {
	min := 100 * time.Millisecond
	max := 1 * time.Second
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, min}, // attempt < 1 normalizes to 1
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1 * time.Second}, // capped
		{10, 1 * time.Second},
	}
	for _, tc := range cases {
		got := backoffDuration(tc.attempt, min, max)
		if got != tc.want {
			t.Errorf("backoffDuration(attempt=%d, min=%v, max=%v) = %v, want %v",
				tc.attempt, min, max, got, tc.want)
		}
	}
}

func TestSleepCtxReturnsTrueAfterDuration(t *testing.T) {
	ctx := context.Background()
	start := time.Now()
	if !sleepCtx(ctx, 20*time.Millisecond) {
		t.Errorf("sleepCtx: want true (slept full duration)")
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Errorf("sleepCtx returned too early: %v", elapsed)
	}
}

func TestSleepCtxReturnsFalseOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if sleepCtx(ctx, 5*time.Second) {
		t.Errorf("sleepCtx: want false (canceled)")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("sleepCtx didn't return promptly on cancel: %v", elapsed)
	}
}

func TestSleepCtxZeroDurationRespectsCanceledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepCtx(ctx, 0) {
		t.Errorf("sleepCtx with already-canceled ctx and 0 duration: want false")
	}
}
