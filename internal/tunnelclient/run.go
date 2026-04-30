package tunnelclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// RunOptions configures the long-running connect-serve-reconnect loop.
//
// The loop owns the supervisor event lifecycle: it emits `starting`
// once, `connecting` per attempt, then `register_ok` (via Connect),
// then `disconnected`/`reconnecting` on session loss, and
// `deregister_ok` (via Session.Deregister) on graceful shutdown.
type RunOptions struct {
	// Connect carries the dial/register parameters; its Emitter is the
	// channel for all lifecycle events.
	Connect Options

	// Handler serves incoming yamux streams as HTTP requests. Required.
	Handler http.Handler

	// PostRegister is called once after every successful Register, before
	// Serve. Typical use: write the state file. A non-nil error is
	// surfaced as an EventError(retryable=false) but does not abort the
	// session — the tunnel still works without the state file.
	PostRegister func(*Session) error

	// BackoffMin is the first reconnect delay. Zero defaults to 1s.
	BackoffMin time.Duration

	// BackoffMax caps the reconnect delay. Zero defaults to 30s.
	BackoffMax time.Duration

	// RateLimitFloor is the minimum delay used after a server Deny with
	// reason "rate_limited:*". The default exponential schedule is
	// useless against the server's per-IP (1h) and per-pubkey (24h)
	// windows, so we floor at a longer wait. Zero defaults to 5min.
	// Commit-2 will override this with a server-supplied retry_after
	// when present.
	RateLimitFloor time.Duration

	// MaxAttempts caps consecutive connect failures before Run gives up
	// and emits `fatal`. Zero means unlimited (default production
	// behavior; production tunnels reconnect forever).
	MaxAttempts int

	// DeregisterTimeout bounds the graceful Deregister round-trip. Zero
	// defaults to 5s.
	DeregisterTimeout time.Duration
}

// Run drives the connect-serve-reconnect lifecycle, emitting events for
// the supervisor protocol described in
// tasks/2026-04-29-supervisor-event-protocol.md.
//
// Returns nil on graceful shutdown (ctx canceled). Returns a non-nil
// error if Run gave up after MaxAttempts; in that case it emitted
// `fatal` as the last event.
func Run(ctx context.Context, ro RunOptions) error {
	em := ro.Connect.Emitter
	if em == nil {
		em = NoopEmitter{}
		ro.Connect.Emitter = em
	}
	logger := ro.Connect.Logger
	if logger == nil {
		logger = slog.Default()
	}
	backoffMin := ro.BackoffMin
	if backoffMin <= 0 {
		backoffMin = time.Second
	}
	backoffMax := ro.BackoffMax
	if backoffMax <= 0 {
		backoffMax = 30 * time.Second
	}
	rateLimitFloor := ro.RateLimitFloor
	if rateLimitFloor <= 0 {
		rateLimitFloor = 5 * time.Minute
	}
	deregTimeout := ro.DeregisterTimeout
	if deregTimeout <= 0 {
		deregTimeout = 5 * time.Second
	}

	em.Emit(EventStarting, StartingData{
		Unique:    ro.Connect.Unique,
		ServerURL: ro.Connect.ServerURL,
	})

	attempt := 1
	for {
		em.Emit(EventConnecting, ConnectingData{
			ServerURL: ro.Connect.ServerURL,
			Attempt:   attempt,
		})

		sess, err := Connect(ctx, ro.Connect)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil
			}
			// Permanent server denies (bad pubkey, bad sig, key_mismatch,
			// version mismatch, invalid unique, ...) cannot be fixed by
			// retrying — emit `fatal` and exit instead of pinging the
			// server forever.
			var denyErr *DenyError
			if errors.As(err, &denyErr) && denyErr.IsPermanent() {
				em.Emit(EventFatal, FatalData{
					Message:  fmt.Sprintf("permanent server deny: %v", err),
					ExitCode: 1,
				})
				return err
			}

			em.Emit(EventError, ErrorData{Message: err.Error(), Retryable: true})
			if ro.MaxAttempts > 0 && attempt >= ro.MaxAttempts {
				em.Emit(EventFatal, FatalData{
					Message:  fmt.Sprintf("gave up after %d attempts: %v", attempt, err),
					ExitCode: 1,
				})
				return err
			}
			// rate_limited:* denies override the exponential schedule.
			// Prefer the server-supplied RetryAfter when present — the
			// server knows exactly when the offending window frees up,
			// so its hint is authoritative. Fall back to
			// RunOptions.RateLimitFloor for older servers that don't
			// populate the field.
			//
			// The default schedule (capped at BackoffMax = 30s) is
			// useless against tunneld's hour- and day-scale windows;
			// pinging at 30s just keeps the budget exhausted.
			delay := backoffDuration(attempt, backoffMin, backoffMax)
			if errors.As(err, &denyErr) && denyErr.IsRateLimit() {
				switch {
				case denyErr.RetryAfter > 0:
					delay = denyErr.RetryAfter
				case delay < rateLimitFloor:
					delay = rateLimitFloor
				}
			}
			attempt++
			em.Emit(EventReconnecting, ReconnectingData{
				AfterMs: int(delay / time.Millisecond),
				Attempt: attempt,
			})
			if !sleepCtx(ctx, delay) {
				return nil
			}
			continue
		}

		// Connect already emitted register_ok.
		attempt = 1

		if ro.PostRegister != nil {
			if err := ro.PostRegister(sess); err != nil {
				logger.Warn("post-register hook failed", "err", err)
				em.Emit(EventError, ErrorData{Message: err.Error(), Retryable: false})
			}
		}

		// Serve runs in a child context so we can stop it AFTER a
		// graceful Deregister round-trip. Serve's httpSrv.Shutdown
		// closes the yamux listener, which closes the session — that
		// would kill the control stream Deregister needs. So when the
		// outer ctx cancels, we Deregister first, then cancel serveCtx.
		serveCtx, cancelServe := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- Serve(serveCtx, sess, ro.Handler) }()

		select {
		case <-ctx.Done():
			// Graceful: deregister with the control stream still alive.
			// SIGKILL never reaches us, so this branch only runs on
			// SIGTERM/SIGINT.
			derCtx, derCancel := context.WithTimeout(context.Background(), deregTimeout)
			if err := sess.Deregister(derCtx); err != nil {
				em.Emit(EventError, ErrorData{
					Message:   "deregister: " + err.Error(),
					Retryable: false,
				})
			}
			derCancel()
			cancelServe()
			<-serveDone
			_ = sess.Close()
			return nil

		case serveErr := <-serveDone:
			// Session ended without ctx cancellation: unexpected
			// disconnect. Surface it and reconnect.
			cancelServe()
			reason := "session closed"
			if serveErr != nil {
				reason = serveErr.Error()
			}
			em.Emit(EventDisconnected, DisconnectedData{Reason: reason})
			_ = sess.Close()
		}

		delay := backoffDuration(attempt, backoffMin, backoffMax)
		attempt++
		em.Emit(EventReconnecting, ReconnectingData{
			AfterMs: int(delay / time.Millisecond),
			Attempt: attempt,
		})
		if !sleepCtx(ctx, delay) {
			return nil
		}
	}
}

// backoffDuration returns an exponential backoff with the configured
// min/max bounds. attempt is 1-based: 1st failure waits min, 2nd waits
// 2*min, ..., capped at max.
func backoffDuration(attempt int, min, max time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := min
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	return d
}

// sleepCtx waits for d, returning false if ctx canceled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
