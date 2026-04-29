package tunnelclient

import (
	"context"
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
			em.Emit(EventError, ErrorData{Message: err.Error(), Retryable: true})
			if ro.MaxAttempts > 0 && attempt >= ro.MaxAttempts {
				em.Emit(EventFatal, FatalData{
					Message:  fmt.Sprintf("gave up after %d attempts: %v", attempt, err),
					ExitCode: 1,
				})
				return err
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

		serveErr := Serve(ctx, sess, ro.Handler)

		if ctx.Err() != nil {
			// Graceful path: the parent signaled shutdown. Try to
			// Deregister with a fresh context, emitting deregister_ok on
			// success. SIGKILL never reaches us, so this branch only
			// runs on SIGTERM/SIGINT.
			derCtx, cancel := context.WithTimeout(context.Background(), deregTimeout)
			derErr := sess.Deregister(derCtx)
			cancel()
			if derErr != nil {
				em.Emit(EventError, ErrorData{
					Message:   "deregister: " + derErr.Error(),
					Retryable: false,
				})
			}
			_ = sess.Close()
			return nil
		}

		// Session ended without ctx cancellation: this is an unexpected
		// disconnect. Surface it and reconnect.
		reason := "session closed"
		if serveErr != nil {
			reason = serveErr.Error()
		}
		em.Emit(EventDisconnected, DisconnectedData{Reason: reason})
		_ = sess.Close()

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
