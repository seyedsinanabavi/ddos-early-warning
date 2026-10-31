package detector

import (
	"errors"
	"fmt"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
)

// Params controls the N-of-M rule and the timing of the state machine.
//
// Rule per window (evaluated on the enabled signals only):
//   - fired >= EnterRequired                  -> hot
//   - any signal Missing (and not hot)        -> unknown
//   - fired <= ExitRequired                   -> cool
//   - otherwise                               -> neutral (holds current state)
//
// Timing, measured on window end times:
//   - normal -> suspicious after MinSuspicious of continuous hot windows.
//   - suspicious -> attack_likely after MinAttackLikely more time in suspicious
//     while still hot.
//   - attack_likely -> suspicious, and suspicious -> normal, each after
//     MinSuspicious of continuous cool windows.
//   - unknown and neutral windows neither advance nor reset the timers.
type Params struct {
	EnterRequired   int
	ExitRequired    int
	MinSuspicious   time.Duration
	MinAttackLikely time.Duration
}

// Validate checks the parameters. The engine refuses to start with invalid ones.
func (p Params) Validate() error {
	switch {
	case p.EnterRequired < 1:
		return fmt.Errorf("detector: enter_required must be >= 1, got %d", p.EnterRequired)
	case p.ExitRequired < 0:
		return fmt.Errorf("detector: exit_required must be >= 0, got %d", p.ExitRequired)
	case p.ExitRequired >= p.EnterRequired:
		return fmt.Errorf("detector: exit_required (%d) must be < enter_required (%d)", p.ExitRequired, p.EnterRequired)
	case p.MinSuspicious <= 0:
		return errors.New("detector: min_duration_suspicious must be > 0")
	case p.MinAttackLikely <= 0:
		return errors.New("detector: min_duration_attack_likely must be > 0")
	}
	return nil
}

type verdict int

const (
	vNeutral verdict = iota
	vHot
	vCool
	vUnknown
)

// classify applies the N-of-M rule to one window's results.
func classify(p Params, results []signals.Result) verdict {
	if len(results) == 0 {
		return vUnknown
	}
	fired, missing := 0, 0
	for _, r := range results {
		switch {
		case r.Missing:
			missing++
		case r.Fired:
			fired++
		}
	}
	switch {
	case fired >= p.EnterRequired:
		return vHot
	case missing > 0:
		// A signal that could not run means "we do not know", not "quiet".
		return vUnknown
	case fired <= p.ExitRequired:
		return vCool
	default:
		return vNeutral
	}
}

// Hysteresis is the state machine that owns the level (normal, suspicious,
// attack_likely) and its timers. It is not safe for concurrent use.
type Hysteresis struct {
	p Params

	level           State
	lastVerdict     verdict
	hotSince        time.Time
	coolSince       time.Time
	suspiciousSince time.Time
}

// NewHysteresis validates p and returns a machine at level normal.
func NewHysteresis(p Params) (*Hysteresis, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &Hysteresis{p: p, level: StateNormal}, nil
}

// Step feeds one window ending at now and returns the reported state.
// The reported state is StateUnknown for a window with missing data. Use Level
// for the underlying escalation level.
func (h *Hysteresis) Step(now time.Time, results []signals.Result) State {
	v := classify(h.p, results)
	h.lastVerdict = v

	switch v {
	case vHot:
		h.coolSince = time.Time{}
		if h.hotSince.IsZero() {
			h.hotSince = now
		}
		if h.level == StateNormal && now.Sub(h.hotSince) >= h.p.MinSuspicious {
			h.level = StateSuspicious
			h.suspiciousSince = now
		}
		if h.level == StateSuspicious && now.Sub(h.suspiciousSince) >= h.p.MinAttackLikely {
			h.level = StateAttackLikely
		}

	case vCool:
		h.hotSince = time.Time{}
		if h.level != StateNormal {
			if h.coolSince.IsZero() {
				h.coolSince = now
			}
			if now.Sub(h.coolSince) >= h.p.MinSuspicious {
				switch h.level {
				case StateAttackLikely:
					h.level = StateSuspicious
					h.suspiciousSince = now
				case StateSuspicious:
					h.level = StateNormal
				}
				h.coolSince = now
			}
		}

	case vNeutral, vUnknown:
		// Hold all timers and the level.
	}

	if v == vUnknown {
		return StateUnknown
	}
	return h.level
}

// Level returns the escalation level (normal, suspicious or attack_likely),
// even while the reported state is unknown.
func (h *Hysteresis) Level() State { return h.level }

// Quiet reports whether the last window was cool. The engine learns baselines
// only from quiet windows, so an attack does not become the new normal.
func (h *Hysteresis) Quiet() bool { return h.lastVerdict == vCool }
