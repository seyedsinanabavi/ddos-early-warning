package detector

import (
	"context"
	"errors"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/baseline"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
)

// Decision is the engine's output for one window.
type Decision struct {
	Service     string
	WindowStart time.Time
	WindowEnd   time.Time
	State       State // reported state (may be unknown or warming_up)
	Level       State // escalation level (normal, suspicious, attack_likely)
	Previous    State // reported state before this window
	Changed     bool  // State differs from Previous (always true for the first window)
	Results     []signals.Result
}

// Engine runs signals, the hysteresis machine and baseline learning for one
// service. It is not safe for concurrent use.
type Engine struct {
	Service string
	Profile *baseline.Profile
	Signals []signals.Signal
	Machine *Hysteresis
	// TopK is the K used for the top-share baseline. It must match the
	// endpoint_skew top_k in configuration. Values below 1 are treated as 1.
	TopK int
	// WarmupUntil: windows ending before this time report warming_up, do not
	// move the machine, and always update the baseline.
	WarmupUntil time.Time

	prev    State
	started bool
}

// NewEngine validates the wiring and returns an Engine. Signals keep
// hysteresis memory, so a signal instance must not be shared between engines.
func NewEngine(service string, prof *baseline.Profile, sigs []signals.Signal, m *Hysteresis, topK int, warmupUntil time.Time) (*Engine, error) {
	switch {
	case service == "":
		return nil, errors.New("detector: service name is empty")
	case prof == nil:
		return nil, errors.New("detector: profile is nil")
	case m == nil:
		return nil, errors.New("detector: machine is nil")
	case len(sigs) == 0:
		return nil, errors.New("detector: no signals enabled")
	}
	if topK < 1 {
		topK = 1
	}
	return &Engine{
		Service:     service,
		Profile:     prof,
		Signals:     sigs,
		Machine:     m,
		TopK:        topK,
		WarmupUntil: warmupUntil,
	}, nil
}

// Step evaluates one closed aggregate window. Time comes from the aggregate,
// never from the wall clock, so replays are deterministic.
func (e *Engine) Step(ctx context.Context, agg ingest.Aggregate) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	end := agg.WindowStart.Add(agg.Window)

	results := make([]signals.Result, 0, len(e.Signals))
	for _, s := range e.Signals {
		r, err := s.Eval(ctx, agg, e.Profile)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Decision{}, ctxErr
			}
			r = signals.Result{Name: s.Name(), Missing: true, Reason: "error: " + err.Error()}
		}
		if r.Name == "" {
			r.Name = s.Name()
		}
		results = append(results, r)
	}

	warming := end.Before(e.WarmupUntil)
	var state, level State
	if warming {
		state, level = StateWarmingUp, StateNormal
	} else {
		state = e.Machine.Step(end, results)
		level = e.Machine.Level()
	}

	// Learn only from quiet windows (and all warm-up windows), so an attack
	// does not become the new normal.
	if warming || e.Machine.Quiet() {
		e.learn(agg)
	}

	prev := e.prev
	if !e.started {
		prev = StateWarmingUp
	}
	d := Decision{
		Service:     e.Service,
		WindowStart: agg.WindowStart,
		WindowEnd:   end,
		State:       state,
		Level:       level,
		Previous:    prev,
		Changed:     !e.started || state != prev,
		Results:     results,
	}
	e.prev = state
	e.started = true
	return d, nil
}

// learn feeds one window into the baseline. An empty window contributes a zero
// error share instead of a division by zero.
func (e *Engine) learn(agg ingest.Aggregate) {
	errShare := 0.0
	if agg.Total > 0 {
		errShare = float64(agg.Errors5xx) / float64(agg.Total)
	}
	k := e.TopK
	if k < 1 {
		k = 1
	}
	top := signals.TopKShare(agg.PathCounts, k, agg.Total)
	e.Profile.Update(agg.WindowStart, float64(agg.Total), top, errShare)
}
