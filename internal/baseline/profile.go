package baseline

import (
	"errors"
	"fmt"
	"time"
)

// Profile is the per-service baseline. It holds three seasonal series, one
// value per hour-of-week bucket: request count per window, top-K endpoint
// traffic share, and 5xx error share.
//
// Profile is not safe for concurrent use; the engine owns it.
type Profile struct {
	rate     *Seasonal
	topShare *Seasonal
	errShare *Seasonal
}

// NewProfile creates a Profile. alpha is the EWMA smoothing factor in (0,1]
// applied per update of a bucket. minN is the number of updates a bucket needs
// before its value is considered valid.
func NewProfile(alpha float64, minN int) (*Profile, error) {
	if alpha <= 0 || alpha > 1 {
		return nil, fmt.Errorf("baseline: alpha %v outside (0,1]", alpha)
	}
	if minN < 1 {
		return nil, fmt.Errorf("baseline: min samples %d must be >= 1", minN)
	}
	return &Profile{
		rate:     NewSeasonal(alpha, minN),
		topShare: NewSeasonal(alpha, minN),
		errShare: NewSeasonal(alpha, minN),
	}, nil
}

// Update feeds one closed window observed at time at.
func (p *Profile) Update(at time.Time, rate, topShare, errShare float64) {
	p.rate.Update(at, rate)
	p.topShare.Update(at, topShare)
	p.errShare.Update(at, errShare)
}

// RateStats returns the mean and standard deviation of the request count for
// the bucket containing at. It satisfies signals.Baseline.
func (p *Profile) RateStats(at time.Time) (float64, float64, bool) {
	return p.rate.MeanStd(at)
}

// TopShare returns the baseline top-K endpoint share for the bucket containing
// at. It satisfies signals.Baseline.
func (p *Profile) TopShare(at time.Time) (float64, bool) {
	return p.topShare.Get(at)
}

// ErrShare returns the baseline 5xx share for the bucket containing at.
func (p *Profile) ErrShare(at time.Time) (float64, bool) {
	return p.errShare.Get(at)
}

// profileStateVersion is bumped whenever ProfileState changes incompatibly.
const profileStateVersion = 1

// ProfileState is the serializable form of a Profile.
type ProfileState struct {
	Version  int         `json:"version"`
	Alpha    float64     `json:"alpha"`
	MinN     int         `json:"min_n"`
	Rate     [168]Bucket `json:"rate"`
	TopShare [168]Bucket `json:"top_share"`
	ErrShare [168]Bucket `json:"err_share"`
}

// State returns the serializable snapshot of p.
func (p *Profile) State() ProfileState {
	return ProfileState{
		Version:  profileStateVersion,
		Alpha:    p.rate.Buckets[0].Alpha,
		MinN:     p.rate.MinN,
		Rate:     exportBuckets(p.rate),
		TopShare: exportBuckets(p.topShare),
		ErrShare: exportBuckets(p.errShare),
	}
}

// RestoreProfile rebuilds a Profile from a snapshot. It rejects unknown
// versions and invalid parameters instead of guessing.
func RestoreProfile(st ProfileState) (*Profile, error) {
	if st.Version != profileStateVersion {
		return nil, fmt.Errorf("baseline: unsupported state version %d", st.Version)
	}
	p, err := NewProfile(st.Alpha, st.MinN)
	if err != nil {
		return nil, err
	}
	if !validBuckets(st.Rate) || !validBuckets(st.TopShare) || !validBuckets(st.ErrShare) {
		return nil, errors.New("baseline: corrupt bucket values in state")
	}
	importBuckets(p.rate, st.Rate)
	importBuckets(p.topShare, st.TopShare)
	importBuckets(p.errShare, st.ErrShare)
	return p, nil
}

func exportBuckets(s *Seasonal) [168]Bucket {
	var out [168]Bucket
	for i, b := range s.Buckets {
		out[i] = Bucket{Value: b.value, N: b.n, M2: b.m2}
	}
	return out
}

func importBuckets(s *Seasonal, in [168]Bucket) {
	for i, b := range in {
		s.Buckets[i].value = b.Value
		s.Buckets[i].n = b.N
		s.Buckets[i].m2 = b.M2
	}
}

// validBuckets rejects NaN/Inf and negative counts, which can only come from a
// corrupted or hand-edited state file.
func validBuckets(in [168]Bucket) bool {
	for _, b := range in {
		if b.N < 0 {
			return false
		}
		if isBad(b.Value) || isBad(b.M2) {
			return false
		}
	}
	return true
}
