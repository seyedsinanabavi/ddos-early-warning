package baseline

import "time"

// Seasonal keeps 168 EWMA buckets: weekday (0=Sunday..6=Saturday) × hour.
type Seasonal struct {
	Buckets [168]EWMA
	MinN    int
}

// NewSeasonal creates a Seasonal with alpha applied to every bucket.
func NewSeasonal(alpha float64, minN int) *Seasonal {
	s := &Seasonal{MinN: minN}
	for i := range s.Buckets {
		s.Buckets[i].Alpha = alpha
	}
	return s
}

func bucketIndex(t time.Time) int {
	return int(t.Weekday())*24 + t.Hour()
}

// Update feeds one observation at the given (logical) time.
func (s *Seasonal) Update(at time.Time, x float64) {
	i := bucketIndex(at)
	s.Buckets[i].Update(x)
}

// Get returns (mean, ok) for the bucket corresponding to at.
func (s *Seasonal) Get(at time.Time) (float64, bool) {
	b := &s.Buckets[bucketIndex(at)]
	v, ok := b.Value()
	return v, ok && b.Samples() >= s.MinN
}

// MeanStd returns (mean, std, ok) for the bucket at `at`.
func (s *Seasonal) MeanStd(at time.Time) (float64, float64, bool) {
	b := &s.Buckets[bucketIndex(at)]
	if b.Samples() < s.MinN {
		return 0, 0, false
	}
	return b.MeanStd()
}
