// Package notifier consumes detector decisions and dispatches alerts without
// blocking detection. A bounded queue sits between the detector and the
// dispatch worker. When the queue is full, decisions are dropped and counted
// instead of stalling the detector.
package notifier

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/alert"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/audit"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/detector"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/runbook"
)

// Severities maps alertable states to the severity labels from configuration.
// Normal and warming_up never alert.
type Severities struct {
	Suspicious   string
	AttackLikely string
	Unknown      string
}

// Options configures a Notifier. Zero values get defaults where noted.
type Options struct {
	// Service is the service name written into every alert.
	Service string
	// Severities must be non-empty for every alertable state.
	Severities Severities
	// DocsURL, if set, is appended to runbook text.
	DocsURL string
	// Manager performs dedup, delivery and retry. Required.
	Manager *alert.Manager
	// Audit records state transitions and alert generation. May be nil.
	Audit *audit.Logger
	// QueueSize is the queue capacity. Default 64.
	QueueSize int
	// DrainTimeout bounds how long Run keeps delivering after shutdown starts.
	// Default 5s.
	DrainTimeout time.Duration
	// Now is the injected clock. Default: UTC time.Now.
	Now func() time.Time
	// Logger receives operational logs. Default: slog.Default().
	Logger *slog.Logger
}

// SubmitResult says what Submit did with a decision.
type SubmitResult int

const (
	// Queued means the decision was accepted for processing.
	Queued SubmitResult = iota
	// Skipped means the decision did not change state, so it was not queued.
	Skipped
	// Dropped means the queue was full and the decision was discarded.
	Dropped
)

// Notifier is the bridge between detector decisions and the alert manager.
type Notifier struct {
	opts    Options
	queue   chan detector.Decision
	dropped atomic.Uint64
}

// New validates opts and returns a Notifier. It does not start the worker;
// call Run for that.
func New(o Options) (*Notifier, error) {
	switch {
	case o.Service == "":
		return nil, errors.New("notifier: service is empty")
	case o.Manager == nil:
		return nil, errors.New("notifier: manager is nil")
	case o.Severities.Suspicious == "", o.Severities.AttackLikely == "", o.Severities.Unknown == "":
		return nil, errors.New("notifier: a severity for suspicious, attack_likely and unknown is required")
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 64
	}
	if o.DrainTimeout <= 0 {
		o.DrainTimeout = 5 * time.Second
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Notifier{opts: o, queue: make(chan detector.Decision, o.QueueSize)}, nil
}

// Submit offers one decision to the worker. It never blocks. Only decisions
// that changed state are queued.
func (n *Notifier) Submit(d detector.Decision) SubmitResult {
	if !d.Changed {
		return Skipped
	}
	select {
	case n.queue <- d:
		return Queued
	default:
		n.dropped.Add(1)
		n.opts.Logger.Warn("notifier queue full; decision dropped",
			"service", n.opts.Service, "state", d.State.String())
		return Dropped
	}
}

// Dropped returns how many decisions were discarded because the queue was full.
func (n *Notifier) Dropped() uint64 { return n.dropped.Load() }

// Run processes queued decisions until ctx is cancelled. On cancellation it
// drains what is already queued, bounded by DrainTimeout, then returns nil.
func (n *Notifier) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			n.drain()
			return nil
		case d := <-n.queue:
			n.handle(ctx, d)
		}
	}
}

func (n *Notifier) drain() {
	dctx, cancel := context.WithTimeout(context.Background(), n.opts.DrainTimeout)
	defer cancel()
	for {
		select {
		case d := <-n.queue:
			if dctx.Err() != nil {
				n.opts.Logger.Warn("notifier drain timed out; decisions not delivered",
					"service", n.opts.Service, "remaining", len(n.queue)+1)
				return
			}
			n.handle(dctx, d)
		default:
			return
		}
	}
}

func (n *Notifier) handle(ctx context.Context, d detector.Decision) {
	n.opts.Audit.StateTransition(n.opts.Service, d.Previous.String(), d.State.String(), d.WindowEnd)

	sev := n.severityFor(d.State)
	if sev == "" {
		return
	}
	text := runbook.ForState(d.State, d.Results, runbook.Options{
		Service: n.opts.Service,
		DocsURL: n.opts.DocsURL,
	})
	a := alert.Build(n.opts.Service, sev, text, d, n.opts.Now())
	n.opts.Audit.AlertGenerated(n.opts.Service, sev, a.ID)

	if err := n.opts.Manager.Dispatch(ctx, a); err != nil {
		n.opts.Logger.Error("alert dispatch failed",
			"service", n.opts.Service, "alert_id", a.ID, "err", err)
	}
}

func (n *Notifier) severityFor(s detector.State) string {
	switch s {
	case detector.StateSuspicious:
		return n.opts.Severities.Suspicious
	case detector.StateAttackLikely:
		return n.opts.Severities.AttackLikely
	case detector.StateUnknown:
		return n.opts.Severities.Unknown
	default:
		return ""
	}
}