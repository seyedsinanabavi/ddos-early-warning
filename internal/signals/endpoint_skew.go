package signals

import (
	"context"
	"fmt"
	"sort"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
)

// EndpointSkew measures how much of the window's traffic lands on the top-K
// paths. A single path that takes most of the traffic is a common sign of a
// targeted request flood.
type EndpointSkew struct {
	TopK           int
	MinVolumeFloor float64
	// RatioEnter and RatioExit are absolute shares in [0,1]. RatioExit < RatioEnter.
	RatioEnter, RatioExit float64

	fired bool
}

// Name returns "endpoint_skew".
func (s *EndpointSkew) Name() string { return "endpoint_skew" }

// Eval fires when the top-K share is at or above the enter threshold.
// The baseline top-K share is reported in Result.Baseline for context. It is
// not used for the decision, so a service whose normal traffic is already
// concentrated still needs a tuned RatioEnter.
func (s *EndpointSkew) Eval(ctx context.Context, a ingest.Aggregate, b Baseline) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if float64(a.Total) < s.MinVolumeFloor || a.Total == 0 {
		return missing("endpoint_skew", "below min volume floor"), nil
	}
	base, ok := b.TopShare(a.WindowStart)
	if !ok {
		return missing("endpoint_skew", "baseline not warm for this hour"), nil
	}
	share := TopKShare(a.PathCounts, s.TopK, a.Total)

	fired := share >= hysteresisThreshold(s.fired, s.RatioEnter, s.RatioExit)
	s.fired = fired
	return Result{
		Name:     "endpoint_skew",
		Value:    share,
		Baseline: base,
		Fired:    fired,
		Reason:   fmt.Sprintf("top%d share=%.2f baseline=%.2f", s.TopK, share, base),
	}, nil
}

// TopKShare returns the fraction of total that the k largest path counts
// account for. total must be the sum of counts (the window's Total). It returns
// 0 when total is 0 or k is not positive. Ties do not affect the result.
func TopKShare(counts map[string]int64, k int, total int64) float64 {
	if total <= 0 || k <= 0 || len(counts) == 0 {
		return 0
	}
	vals := make([]int64, 0, len(counts))
	for _, c := range counts {
		vals = append(vals, c)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] > vals[j] })
	if k > len(vals) {
		k = len(vals)
	}
	var sum int64
	for _, v := range vals[:k] {
		sum += v
	}
	return float64(sum) / float64(total)
}
