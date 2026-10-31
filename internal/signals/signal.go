// Package signals computes individual detector signals from one aggregate
// window plus the current baseline. Each signal is independent and reports a
// Result. A Missing result means the signal could not be evaluated; the detector
// must treat that as unknown, never as normal.
//
// Privacy: signals see only aggregates (counts, path counts, shares). They never
// receive raw client IPs.
package signals

import (
	"context"
	"errors"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
)

// ErrNotImplemented is returned by signals that are reserved extension points.
var ErrNotImplemented = errors.New("signals: not implemented in MVP")

// Result is the outcome of evaluating one signal on one window.
//
// Fired and Missing are mutually exclusive: a Missing result never fires.
type Result struct {
	Name     string
	Value    float64 // signal-specific scalar (z-score, share, ratio)
	Baseline float64 // reference value used, when available
	Fired    bool
	Missing  bool
	Reason   string
}

// Baseline is the read-only view of the baseline a signal needs. It is
// implemented by baseline.Profile.
type Baseline interface {
	// RateStats returns the mean and standard deviation of the request count per
	// window for the bucket containing at.
	RateStats(at time.Time) (mean, std float64, ok bool)
	// TopShare returns the baseline top-K endpoint share for the bucket
	// containing at.
	TopShare(at time.Time) (share float64, ok bool)
}

// Signal evaluates one window. Implementations may keep hysteresis memory
// between calls; a Signal must therefore be used by one engine only.
type Signal interface {
	Name() string
	Eval(ctx context.Context, agg ingest.Aggregate, b Baseline) (Result, error)
}

// missing builds a Missing result with a short reason.
func missing(name, reason string) Result {
	return Result{Name: name, Missing: true, Reason: reason}
}

// hysteresisThreshold returns the enter threshold, or the exit threshold when
// the signal is already fired. It is the per-signal half of hysteresis.
func hysteresisThreshold(fired bool, enter, exit float64) float64 {
	if fired {
		return exit
	}
	return enter
}
