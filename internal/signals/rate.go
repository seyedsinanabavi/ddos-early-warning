package signals

import (
	"context"
	"fmt"
	"math"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
)

// Rate compares the request count of a window with the seasonal baseline as a
// z-score. It fires on a high side deviation only.
type Rate struct {
	// MinVolumeFloor is the minimum request count per window. Below it the
	// window is too noisy to judge and the result is Missing.
	MinVolumeFloor float64
	// ZEnter is the z-score at which the signal fires. ZExit is the z-score it
	// must drop below to clear. ZExit must be < ZEnter.
	ZEnter, ZExit float64

	fired bool
}

// Name returns "rate".
func (r *Rate) Name() string { return "rate" }

// Eval computes the z-score of a.Total against the baseline for a.WindowStart.
//
// The standard deviation is floored at max(1, 10% of the mean). Without the
// floor, a very stable baseline gives a near-zero deviation and any small
// change looks like an extreme z-score.
func (r *Rate) Eval(ctx context.Context, a ingest.Aggregate, b Baseline) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if float64(a.Total) < r.MinVolumeFloor {
		return missing("rate", "below min volume floor"), nil
	}
	mean, std, ok := b.RateStats(a.WindowStart)
	if !ok {
		return missing("rate", "baseline not warm for this hour"), nil
	}
	std = math.Max(std, math.Max(1, 0.1*mean))
	z := (float64(a.Total) - mean) / std

	fired := z >= hysteresisThreshold(r.fired, r.ZEnter, r.ZExit)
	r.fired = fired
	return Result{
		Name:     "rate",
		Value:    z,
		Baseline: mean,
		Fired:    fired,
		Reason:   fmt.Sprintf("z=%.2f count=%d mean=%.1f std=%.1f", z, a.Total, mean, std),
	}, nil
}
