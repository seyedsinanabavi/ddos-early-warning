package detector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/baseline"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
)

// fakeSignal returns a fixed result for each window, based on the total.
type fakeSignal struct {
	name string
	fn   func(agg ingest.Aggregate) (signals.Result, error)
}

func (f fakeSignal) Name() string { return f.name }
func (f fakeSignal) Eval(_ context.Context, agg ingest.Aggregate, _ signals.Baseline) (signals.Result, error) {
	return f.fn(agg)
}

// rateAbove fires when the window total is at least limit.
func rateAbove(limit int64) fakeSignal {
	return fakeSignal{name: "rate", fn: func(a ingest.Aggregate) (signals.Result, error) {
		return signals.Result{Name: "rate", Fired: a.Total >= limit}, nil
	}}
}

func window(start time.Time, total int64) ingest.Aggregate {
	return ingest.Aggregate{
		WindowStart: start,
		Window:      10 * time.Second,
		Total:       total,
		PathCounts:  map[string]int64{"/": total},
	}
}

func newTestEngine(t *testing.T, sigs []signals.Signal, warmupUntil time.Time) (*Engine, *baseline.Profile) {
	t.Helper()
	prof, err := baseline.NewProfile(0.5, 1)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewHysteresis(Params{EnterRequired: 1, ExitRequired: 0, MinSuspicious: 10 * time.Second, MinAttackLikely: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine("svc", prof, sigs, m, 1, warmupUntil)
	if err != nil {
		t.Fatal(err)
	}
	return e, prof
}

func TestEngine_WarmupThenEscalation(t *testing.T) {
	warmupEnd := t0.Add(30 * time.Second)
	e, prof := newTestEngine(t, []signals.Signal{rateAbove(100)}, warmupEnd)
	ctx := context.Background()

	// Windows start at t0, +10s, +20s, +30s, +40s, +50s.
	type want struct {
		total int64
		state State
	}
	steps := []want{
		{10, StateWarmingUp}, // end t0+10
		{10, StateWarmingUp}, // end t0+20
		{10, StateNormal},    // end t0+30: warm-up over, quiet
		{500, StateNormal},   // end t0+40: hot starts
		{500, StateSuspicious},
		{500, StateAttackLikely},
	}
	var prev State
	for i, s := range steps {
		start := t0.Add(time.Duration(i) * 10 * time.Second)
		d, err := e.Step(ctx, window(start, s.total))
		if err != nil {
			t.Fatal(err)
		}
		if d.State != s.state {
			t.Fatalf("window %d: state=%s want %s", i, d.State, s.state)
		}
		if i > 0 && d.Previous != prev {
			t.Fatalf("window %d: previous=%s want %s", i, d.Previous, prev)
		}
		prev = d.State
	}

	// Hot windows must not be learned: the bucket mean stays at the quiet value.
	mean, _, ok := prof.RateStats(t0)
	if !ok || mean != 10 {
		t.Fatalf("baseline learned from attack traffic: mean=%v ok=%v", mean, ok)
	}
}

func TestEngine_ChangedFlag(t *testing.T) {
	e, _ := newTestEngine(t, []signals.Signal{rateAbove(100)}, time.Time{})
	ctx := context.Background()

	d1, _ := e.Step(ctx, window(t0, 10)) // first window: always changed
	if !d1.Changed {
		t.Fatal("first decision must be Changed")
	}
	d2, _ := e.Step(ctx, window(t0.Add(10*time.Second), 10))
	if d2.Changed {
		t.Fatal("normal -> normal must not be Changed")
	}
}

func TestEngine_SignalErrorIsUnknownNotNormal(t *testing.T) {
	failing := fakeSignal{name: "rate", fn: func(ingest.Aggregate) (signals.Result, error) {
		return signals.Result{}, errors.New("boom")
	}}
	e, _ := newTestEngine(t, []signals.Signal{failing}, time.Time{})
	d, err := e.Step(context.Background(), window(t0, 10))
	if err != nil {
		t.Fatal(err)
	}
	if d.State != StateUnknown {
		t.Fatalf("signal error must yield unknown, got %s", d.State)
	}
	if !d.Results[0].Missing {
		t.Fatal("erroring signal must be recorded as Missing")
	}
}

func TestEngine_CancelledContext(t *testing.T) {
	e, _ := newTestEngine(t, []signals.Signal{rateAbove(1)}, time.Time{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Step(ctx, window(t0, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestNewEngine_Validation(t *testing.T) {
	prof, _ := baseline.NewProfile(0.5, 1)
	m, _ := NewHysteresis(Params{EnterRequired: 1, ExitRequired: 0, MinSuspicious: time.Second, MinAttackLikely: time.Second})
	sigs := []signals.Signal{rateAbove(1)}
	if _, err := NewEngine("", prof, sigs, m, 1, time.Time{}); err == nil {
		t.Fatal("empty service must fail")
	}
	if _, err := NewEngine("s", nil, sigs, m, 1, time.Time{}); err == nil {
		t.Fatal("nil profile must fail")
	}
	if _, err := NewEngine("s", prof, nil, m, 1, time.Time{}); err == nil {
		t.Fatal("no signals must fail")
	}
	if _, err := NewEngine("s", prof, sigs, nil, 1, time.Time{}); err == nil {
		t.Fatal("nil machine must fail")
	}
}
