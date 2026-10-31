// Package baseline maintains EWMA and seasonal (hour-of-week) profiles for
// request rate, top-endpoint share and 5xx error share.
package baseline

import "math"

// EWMA is an exponentially weighted moving average with configurable alpha.
// It also tracks an exponentially weighted variance (West/Finch form), so the
// standard deviation can be used for z-scores.
type EWMA struct {
	Alpha float64
	value float64
	n     int
	m2    float64 // exponentially weighted variance
}

// Update feeds a new observation. NaN and Inf are ignored.
func (e *EWMA) Update(x float64) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return
	}
	if e.n == 0 {
		e.value = x
		e.m2 = 0
	} else {
		d := x - e.value // deviation from the previous mean
		incr := e.Alpha * d
		e.value += incr
		e.m2 = (1 - e.Alpha) * (e.m2 + d*incr)
	}
	e.n++
}

// Value returns (mean, ok). ok is false before the first observation.
func (e *EWMA) Value() (float64, bool) { return e.value, e.n > 0 }

// MeanStd returns (mean, stddev, ok). stddev is 0 when only one sample exists.
func (e *EWMA) MeanStd() (float64, float64, bool) {
	if e.n == 0 {
		return 0, 0, false
	}
	if e.n == 1 {
		return e.value, 0, true
	}
	return e.value, math.Sqrt(e.m2), true
}

// Samples returns the number of accepted updates.
func (e *EWMA) Samples() int { return e.n }
