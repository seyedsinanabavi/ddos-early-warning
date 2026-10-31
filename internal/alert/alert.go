// Package alert turns detector decisions into alerts and delivers them to
// configured channels. It never executes blocking actions.
package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/detector"
)

// Alert is one alert event. Its JSON form is what channels receive.
type Alert struct {
	ID            string          `json:"id"`
	Timestamp     time.Time       `json:"timestamp"`
	Service       string          `json:"service"`
	State         string          `json:"state"`
	PreviousState string          `json:"previous_state"`
	Severity      string          `json:"severity"`
	WindowStart   time.Time       `json:"window_start"`
	WindowEnd     time.Time       `json:"window_end"`
	Signals       []SignalSummary `json:"signals"`
	Runbook       string          `json:"runbook,omitempty"`
}

// SignalSummary is the alert-safe view of one signal result. It omits raw IPs
// (which signals never have anyway) and any internal state.
type SignalSummary struct {
	Name     string  `json:"name"`
	Value    float64 `json:"value"`
	Baseline float64 `json:"baseline"`
	Fired    bool    `json:"fired"`
	Missing  bool    `json:"missing"`
	Reason   string  `json:"reason,omitempty"`
}

// Build creates an Alert from a detector Decision and runbook text. now is the
// caller's clock reading and becomes the alert timestamp.
func Build(service, severity, runbook string, d detector.Decision, now time.Time) Alert {
	a := Alert{
		Timestamp:     now.UTC(),
		Service:       service,
		State:         d.State.String(),
		PreviousState: d.Previous.String(),
		Severity:      severity,
		WindowStart:   d.WindowStart.UTC(),
		WindowEnd:     d.WindowEnd.UTC(),
		Runbook:       runbook,
	}
	for _, r := range d.Results {
		a.Signals = append(a.Signals, SignalSummary{
			Name:     r.Name,
			Value:    r.Value,
			Baseline: r.Baseline,
			Fired:    r.Fired,
			Missing:  r.Missing,
			Reason:   r.Reason,
		})
	}
	// The id needs the signal list, so it is derived after the list is filled.
	a.ID = deriveID(a)
	return a
}

// deriveID builds a stable id from service, state and the set of fired
// signals. It deliberately excludes the window time: a situation that persists
// across windows must produce the same id so the cooldown can suppress repeats.
// Missing signals are not part of the id, because they are not fired.
func deriveID(a Alert) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|", a.Service, a.State)
	for _, s := range a.Signals {
		if s.Fired && !s.Missing {
			fmt.Fprintf(h, "%s,", s.Name)
		}
	}
	return a.Service + "-" + a.State + "-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// MarshalJSON is the default; kept for clarity.
func (a Alert) MarshalJSON() ([]byte, error) {
	type alias Alert
	return json.Marshal(alias(a))
}