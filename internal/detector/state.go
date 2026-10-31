// Package detector turns per-window signal results into a service state using
// an N-of-M rule with hysteresis, and reports transitions to alerting.
package detector

// State is the reported state of one service.
type State int

// Reported states. StateUnknown means the detector cannot judge the current
// window because of missing data. It is never reported as StateNormal.
const (
	StateNormal State = iota
	StateWarmingUp
	StateSuspicious
	StateAttackLikely
	StateUnknown
)

// String returns the stable lowercase name used in logs and config.
func (s State) String() string {
	switch s {
	case StateNormal:
		return "normal"
	case StateWarmingUp:
		return "warming_up"
	case StateSuspicious:
		return "suspicious"
	case StateAttackLikely:
		return "attack_likely"
	case StateUnknown:
		return "unknown"
	default:
		return "invalid"
	}
}
