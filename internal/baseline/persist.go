package baseline

import (
	"encoding/json"
	"fmt"
	"math"
)

// Bucket is the serialized form of one EWMA bucket.
type Bucket struct {
	Value float64 `json:"v"`
	N     int     `json:"n"`
	M2    float64 `json:"m2"`
}

// isBad reports whether v is NaN or infinite.
func isBad(v float64) bool { return math.IsNaN(v) || math.IsInf(v, 0) }

// MarshalState serializes a ProfileState to JSON.
func MarshalState(st ProfileState) ([]byte, error) { return json.Marshal(st) }

// UnmarshalState parses JSON into a ProfileState.
func UnmarshalState(b []byte) (ProfileState, error) {
	var st ProfileState
	if err := json.Unmarshal(b, &st); err != nil {
		return ProfileState{}, fmt.Errorf("baseline: decode state: %w", err)
	}
	return st, nil
}
