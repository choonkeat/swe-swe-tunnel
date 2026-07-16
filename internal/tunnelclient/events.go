package tunnelclient

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Emitter publishes lifecycle events for a parent supervisor process.
//
// Implementations are concurrency-safe: the connect, reconnect, and serve
// goroutines may all call Emit on the same emitter.
type Emitter interface {
	Emit(kind string, data any)
}

// Event kind names. The supervisor protocol is documented in
// tasks/2026-04-29-supervisor-event-protocol.md.
const (
	EventStarting     = "starting"
	EventConnecting   = "connecting"
	EventRegisterOK   = "register_ok"
	EventRelabel      = "relabel"
	EventDisconnected = "disconnected"
	EventReconnecting = "reconnecting"
	EventDeregisterOK = "deregister_ok"
	EventError        = "error"
	EventFatal        = "fatal"
)

// EventSchemaVersion is the value written into the "v" field of every
// event. Bumping this is reserved for incompatible breaks; additive
// changes keep v=1.
const EventSchemaVersion = 1

// StartingData is the payload of an EventStarting event.
type StartingData struct {
	Unique    string `json:"unique"`
	ServerURL string `json:"server_url"`
}

// ConnectingData is the payload of an EventConnecting event.
type ConnectingData struct {
	ServerURL string `json:"server_url"`
	Attempt   int    `json:"attempt"`
}

// RegisterOKData is the payload of an EventRegisterOK event.
type RegisterOKData struct {
	Hostname string `json:"hostname"`
	Unique   string `json:"unique"`
}

// RelabelData is the payload of an EventRelabel event (reserved).
type RelabelData struct {
	Hostname    string `json:"hostname"`
	OldHostname string `json:"old_hostname"`
}

// DisconnectedData is the payload of an EventDisconnected event.
type DisconnectedData struct {
	Reason string `json:"reason"`
}

// ReconnectingData is the payload of an EventReconnecting event.
type ReconnectingData struct {
	AfterMs int `json:"after_ms"`
	Attempt int `json:"attempt"`
}

// DeregisterOKData is the payload of an EventDeregisterOK event.
type DeregisterOKData struct {
	Unique string `json:"unique"`
}

// ErrorData is the payload of an EventError event.
type ErrorData struct {
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// FatalData is the payload of an EventFatal event.
//
// Reason is a short machine-readable slug (e.g. "identity_generated",
// "unique_required") that a supervisor can switch on; the swe-swe-server
// tunnel supervisor reads this field to decide it must stop rather than
// restart. Message is the human-readable detail.
type FatalData struct {
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message"`
	ExitCode int    `json:"exit_code"`
}

// NoopEmitter discards events. Used when reporting is disabled (the
// default --report-format=none case).
type NoopEmitter struct{}

// Emit drops the event on the floor.
func (NoopEmitter) Emit(string, any) {}

// envelope is the wire shape: {"v":1,"ts":...,"kind":...,"data":{...}}.
type envelope struct {
	V    int             `json:"v"`
	TS   string          `json:"ts"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

// JSONLEmitter writes one JSON object per line to its writer.
//
// If the writer implements `interface{ Flush() error }` (e.g. a wrapped
// *bufio.Writer), Flush is called after every event so a parent reading
// off a pipe sees events promptly. Pipe buffering is the most common
// cause of "supervisor never saw register_ok" bugs.
type JSONLEmitter struct {
	w      io.Writer
	mu     sync.Mutex
	now    func() time.Time
	onErr  func(kind string, err error)
	logger *slog.Logger
}

// NewJSONLEmitter returns an emitter that writes events as JSON-lines to
// w. Pass os.Stdout in production; pass a *bufio.Writer-wrapped buffer in
// tests that want to assert Flush is called.
func NewJSONLEmitter(w io.Writer) *JSONLEmitter {
	return &JSONLEmitter{w: w, now: time.Now}
}

// WithLogger overrides the slog logger used for write/flush failures.
// The default logs to slog.Default().
func (e *JSONLEmitter) WithLogger(l *slog.Logger) *JSONLEmitter {
	e.logger = l
	return e
}

// Emit serializes and writes a single event.
//
// Write or flush failures are reported via the configured logger (or
// slog.Default()) and Emit returns. We deliberately do not propagate the
// error — the parent supervisor is gone or its pipe is broken, but the
// tunnel itself may still be useful for whoever finds the orphan.
func (e *JSONLEmitter) Emit(kind string, data any) {
	if data == nil {
		// Spec requires a data object on every kind. A nil here is a
		// programmer error — surface it on stderr instead of silently
		// emitting `"data":null`.
		e.report(kind, fmt.Errorf("Emit called with nil data"))
		return
	}
	rawData, err := json.Marshal(data)
	if err != nil {
		e.report(kind, fmt.Errorf("marshal data: %w", err))
		return
	}
	line, err := json.Marshal(envelope{
		V:    EventSchemaVersion,
		TS:   e.now().UTC().Format(time.RFC3339Nano),
		Kind: kind,
		Data: rawData,
	})
	if err != nil {
		e.report(kind, fmt.Errorf("marshal envelope: %w", err))
		return
	}
	line = append(line, '\n')

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.w.Write(line); err != nil {
		e.report(kind, fmt.Errorf("write: %w", err))
		return
	}
	if f, ok := e.w.(flusher); ok {
		if err := f.Flush(); err != nil {
			e.report(kind, fmt.Errorf("flush: %w", err))
		}
	}
}

type flusher interface {
	Flush() error
}

func (e *JSONLEmitter) report(kind string, err error) {
	if e.onErr != nil {
		e.onErr(kind, err)
		return
	}
	l := e.logger
	if l == nil {
		l = slog.Default()
	}
	l.Error("tunnelclient event emit failed", "kind", kind, "err", err)
}
