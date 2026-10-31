// Package audit records security-relevant events in a structured, machine-
// readable form. It never records raw client IPs or webhook secrets.
package audit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event types. These are stable strings used in logs and tests.
const (
	EventConfigLoaded      = "config.loaded"
	EventServiceStarted    = "service.started"
	EventServiceStopped    = "service.stopped"
	EventStateTransition   = "detector.state_transition"
	EventAlertGenerated    = "alert.generated"
	EventAlertDelivered    = "alert.delivered"
	EventAlertFailed       = "alert.failed"
	EventAlertDeduplicated = "alert.deduplicated"
	EventStorageError      = "storage.error"
)

// Event is one audit record.
type Event struct {
	Time    time.Time         `json:"time"`
	Type    string            `json:"type"`
	Service string            `json:"service,omitempty"`
	Level   string            `json:"level,omitempty"` // warning | critical | info
	Message string            `json:"message,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// Logger writes audit events. A nil Logger is safe: all methods are no-ops.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	fanout []*Logger
	now    func() time.Time // injected clock; time.Now when nil
}

// New returns a Logger writing JSON Lines to w.
func New(w io.Writer) *Logger {
	if w == nil {
		return nil
	}
	return &Logger{w: w, now: func() time.Time { return time.Now().UTC() }}
}

// clock returns the current time from the injected clock.
func (l *Logger) clock() time.Time {
	if l.now == nil {
		return time.Now().UTC()
	}
	return l.now().UTC()
}

// Log writes one event. It never returns an error: audit failures must not
// crash the pipeline.
func (l *Logger) Log(ev Event) {
	if l == nil {
		return
	}
	if len(l.fanout) > 0 {
		for _, f := range l.fanout {
			f.Log(ev)
		}
		return
	}
	if l.w == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = l.clock()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}

// ConfigLoaded records a successful config load.
func (l *Logger) ConfigLoaded(dir string) {
	l.Log(Event{Type: EventConfigLoaded, Fields: map[string]string{"dir": dir}})
}

// ServiceStarted records a service start.
func (l *Logger) ServiceStarted(service, binary string) {
	l.Log(Event{Type: EventServiceStarted, Service: service, Fields: map[string]string{"binary": binary}})
}

// ServiceStopped records a service stop.
func (l *Logger) ServiceStopped(service, binary, reason string) {
	l.Log(Event{Type: EventServiceStopped, Service: service, Fields: map[string]string{"binary": binary, "reason": reason}})
}

// StateTransition records a detector state change.
func (l *Logger) StateTransition(service string, from, to string, windowEnd time.Time) {
	l.Log(Event{
		Type:    EventStateTransition,
		Service: service,
		Fields: map[string]string{
			"from":       from,
			"to":         to,
			"window_end": windowEnd.UTC().Format(time.RFC3339),
		},
	})
}

// AlertGenerated records that an alert was constructed.
func (l *Logger) AlertGenerated(service, severity, alertID string) {
	l.Log(Event{
		Type:    EventAlertGenerated,
		Service: service,
		Level:   severity,
		Fields:  map[string]string{"alert_id": alertID},
	})
}

// AlertDelivered records successful delivery to one channel.
func (l *Logger) AlertDelivered(service, alertID, channel string) {
	l.Log(Event{
		Type:    EventAlertDelivered,
		Service: service,
		Fields:  map[string]string{"alert_id": alertID, "channel": channel},
	})
}

// AlertFailed records a failed delivery attempt.
func (l *Logger) AlertFailed(service, alertID, channel, reason string) {
	l.Log(Event{
		Type:    EventAlertFailed,
		Service: service,
		Level:   "warning",
		Message: reason,
		Fields:  map[string]string{"alert_id": alertID, "channel": channel},
	})
}

// StorageError records a storage-layer error.
func (l *Logger) StorageError(service, op, reason string) {
	l.Log(Event{
		Type:    EventStorageError,
		Service: service,
		Level:   "warning",
		Message: reason,
		Fields:  map[string]string{"op": op},
	})
}

// WithContext is a convenience for callers that already have a context.
func (l *Logger) WithContext(ctx context.Context, ev Event) {
	if err := ctx.Err(); err != nil {
		return
	}
	l.Log(ev)
}