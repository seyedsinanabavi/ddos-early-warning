package notifier

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/alert"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/detector"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
)

var t0 = time.Date(2026, 10, 31, 3, 0, 0, 0, time.UTC)

// recordingChannel stores delivered alerts. With block set, Deliver waits for
// the context to end, which simulates a hung webhook.
type recordingChannel struct {
	mu    sync.Mutex
	got   []alert.Alert
	block bool
}

func (r *recordingChannel) Name() string { return "rec" }

func (r *recordingChannel) Deliver(ctx context.Context, a alert.Alert) error {
	if r.block {
		<-ctx.Done()
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, a)
	return nil
}

func (r *recordingChannel) alerts() []alert.Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]alert.Alert(nil), r.got...)
}

func newNotifier(t *testing.T, ch alert.Channel, queue int, drain time.Duration) *Notifier {
	t.Helper()
	m := &alert.Manager{Channels: []alert.Channel{ch}, Now: func() time.Time { return t0 }}
	n, err := New(Options{
		Service:      "public-web",
		Severities:   Severities{Suspicious: "warning", AttackLikely: "critical", Unknown: "warning"},
		Manager:      m,
		QueueSize:    queue,
		DrainTimeout: drain,
		Now:          func() time.Time { return t0 },
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func decision(prev, state detector.State, changed bool) detector.Decision {
	return detector.Decision{
		Service:     "public-web",
		WindowStart: t0,
		WindowEnd:   t0.Add(10 * time.Second),
		State:       state,
		Previous:    prev,
		Changed:     changed,
		Results:     []signals.Result{{Name: "rate", Fired: true}},
	}
}

// drainAll submits the decisions, cancels the context, and runs the worker.
// Run then drains the queue and returns.
func drainAll(t *testing.T, n *Notifier, ds ...detector.Decision) {
	t.Helper()
	for _, d := range ds {
		n.Submit(d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := n.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNew_Validation(t *testing.T) {
	m := &alert.Manager{}
	ok := Severities{Suspicious: "warning", AttackLikely: "critical", Unknown: "warning"}
	cases := []struct {
		name string
		opts Options
	}{
		{"no service", Options{Manager: m, Severities: ok}},
		{"no manager", Options{Service: "s", Severities: ok}},
		{"missing suspicious severity", Options{Service: "s", Manager: m, Severities: Severities{AttackLikely: "critical", Unknown: "warning"}}},
		{"missing unknown severity", Options{Service: "s", Manager: m, Severities: Severities{Suspicious: "warning", AttackLikely: "critical"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestSubmit_UnchangedIsSkipped(t *testing.T) {
	ch := &recordingChannel{}
	n := newNotifier(t, ch, 8, time.Second)
	if r := n.Submit(decision(detector.StateSuspicious, detector.StateSuspicious, false)); r != Skipped {
		t.Fatalf("got %v want Skipped", r)
	}
	drainAll(t, n)
	if len(ch.alerts()) != 0 {
		t.Fatal("unchanged decision must not alert")
	}
}

func TestSuspiciousTransitionUsesConfiguredSeverity(t *testing.T) {
	ch := &recordingChannel{}
	n := newNotifier(t, ch, 8, time.Second)
	drainAll(t, n, decision(detector.StateNormal, detector.StateSuspicious, true))
	got := ch.alerts()
	if len(got) != 1 {
		t.Fatalf("want 1 alert, got %d", len(got))
	}
	if got[0].Severity != "warning" || got[0].State != "suspicious" || got[0].PreviousState != "normal" {
		t.Fatalf("alert: %+v", got[0])
	}
	if got[0].Runbook == "" {
		t.Fatal("runbook text must be attached")
	}
}

func TestAttackLikelyUsesCriticalSeverity(t *testing.T) {
	ch := &recordingChannel{}
	n := newNotifier(t, ch, 8, time.Second)
	drainAll(t, n, decision(detector.StateSuspicious, detector.StateAttackLikely, true))
	got := ch.alerts()
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want one critical alert, got %+v", got)
	}
}

func TestUnknownStateAlerts(t *testing.T) {
	ch := &recordingChannel{}
	n := newNotifier(t, ch, 8, time.Second)
	drainAll(t, n, decision(detector.StateNormal, detector.StateUnknown, true))
	got := ch.alerts()
	if len(got) != 1 || got[0].State != "unknown" {
		t.Fatalf("unknown must alert, got %+v", got)
	}
}

func TestNormalTransitionDoesNotAlert(t *testing.T) {
	ch := &recordingChannel{}
	n := newNotifier(t, ch, 8, time.Second)
	if r := n.Submit(decision(detector.StateSuspicious, detector.StateNormal, true)); r != Queued {
		t.Fatalf("recovery transition should be queued for audit, got %v", r)
	}
	drainAll(t, n)
	if len(ch.alerts()) != 0 {
		t.Fatal("transition to normal must not send an alert")
	}
}

func TestQueueFullDropsWithoutBlocking(t *testing.T) {
	ch := &recordingChannel{}
	n := newNotifier(t, ch, 1, time.Second)
	d := decision(detector.StateNormal, detector.StateSuspicious, true)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if r := n.Submit(d); r != Queued {
			t.Errorf("first submit: %v", r)
		}
		if r := n.Submit(d); r != Dropped {
			t.Errorf("second submit must be dropped, got %v", r)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked on a full queue")
	}
	if n.Dropped() != 1 {
		t.Fatalf("dropped count: %d", n.Dropped())
	}
}

func TestRunDrainsQueueOnShutdown(t *testing.T) {
	ch := &recordingChannel{}
	n := newNotifier(t, ch, 8, time.Second)
	drainAll(t, n,
		decision(detector.StateNormal, detector.StateSuspicious, true),
		decision(detector.StateSuspicious, detector.StateAttackLikely, true),
		decision(detector.StateAttackLikely, detector.StateNormal, true),
	)
	if len(ch.alerts()) != 2 {
		t.Fatalf("want 2 alerts from queued decisions, got %d", len(ch.alerts()))
	}
}

func TestRunDeliversLiveDecisions(t *testing.T) {
	ch := &recordingChannel{}
	n := newNotifier(t, ch, 8, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- n.Run(ctx) }()

	n.Submit(decision(detector.StateNormal, detector.StateSuspicious, true))

	deadline := time.Now().Add(2 * time.Second)
	for len(ch.alerts()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	if len(ch.alerts()) != 1 {
		t.Fatalf("live decision not delivered: %d alerts", len(ch.alerts()))
	}
}

func TestDrainTimeoutBoundsShutdown(t *testing.T) {
	ch := &recordingChannel{block: true}
	n := newNotifier(t, ch, 8, 50*time.Millisecond)
	n.Submit(decision(detector.StateNormal, detector.StateSuspicious, true))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return: a hung channel blocked shutdown")
	}
}