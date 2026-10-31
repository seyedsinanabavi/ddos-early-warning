package alert

import (
	"testing"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/detector"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
)

var now = time.Date(2026, 10, 31, 3, 0, 0, 0, time.FixedZone("X", 3600))

func decision(results ...signals.Result) detector.Decision {
	start := time.Date(2026, 10, 31, 1, 59, 0, 0, time.UTC)
	return detector.Decision{
		Service:     "public-web",
		WindowStart: start,
		WindowEnd:   start.Add(10 * time.Second),
		State:       detector.StateSuspicious,
		Previous:    detector.StateNormal,
		Results:     results,
	}
}

func TestBuild_FieldsAndClock(t *testing.T) {
	d := decision(signals.Result{Name: "rate", Fired: true, Value: 4.5, Baseline: 100, Reason: "z=4.5"})
	a := Build("public-web", "warning", "check logs", d, now)

	if a.Service != "public-web" || a.State != "suspicious" || a.PreviousState != "normal" {
		t.Fatalf("basic fields: %+v", a)
	}
	if a.Severity != "warning" || a.Runbook != "check logs" {
		t.Fatalf("severity/runbook: %+v", a)
	}
	if !a.Timestamp.Equal(now) || a.Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp must be the injected time in UTC, got %v", a.Timestamp)
	}
	if a.WindowStart.Location() != time.UTC || !a.WindowEnd.Equal(d.WindowEnd) {
		t.Fatalf("window times: %v %v", a.WindowStart, a.WindowEnd)
	}
	if len(a.Signals) != 1 || a.Signals[0].Name != "rate" || a.Signals[0].Value != 4.5 || !a.Signals[0].Fired {
		t.Fatalf("signals: %+v", a.Signals)
	}
}

func TestBuild_IDIsStableForSameSituation(t *testing.T) {
	d := decision(signals.Result{Name: "rate", Fired: true})
	a1 := Build("svc", "warning", "", d, now)
	a2 := Build("svc", "warning", "", d, now.Add(time.Hour)) // different clock, same situation
	if a1.ID != a2.ID {
		t.Fatalf("same situation must give same id: %s vs %s", a1.ID, a2.ID)
	}
}

func TestBuild_IDChangesWithFiredSet(t *testing.T) {
	one := Build("svc", "warning", "", decision(signals.Result{Name: "rate", Fired: true}), now)
	two := Build("svc", "warning", "", decision(
		signals.Result{Name: "rate", Fired: true},
		signals.Result{Name: "endpoint_skew", Fired: true},
	), now)
	if one.ID == two.ID {
		t.Fatal("different fired sets must give different ids")
	}
}

func TestBuild_MissingSignalsDoNotChangeID(t *testing.T) {
	base := decision(signals.Result{Name: "rate", Fired: true})
	withMissing := decision(
		signals.Result{Name: "rate", Fired: true},
		signals.Result{Name: "syn_ratio", Missing: true},
	)
	a := Build("svc", "warning", "", base, now)
	b := Build("svc", "warning", "", withMissing, now)
	if a.ID != b.ID {
		t.Fatal("a missing signal is not a fired signal and must not change the id")
	}
	if len(b.Signals) != 2 || !b.Signals[1].Missing {
		t.Fatalf("missing signal must still be listed: %+v", b.Signals)
	}
}

func TestBuild_IDIncludesServiceAndState(t *testing.T) {
	d := decision(signals.Result{Name: "rate", Fired: true})
	other := d
	other.Service = "api"
	if Build("public-web", "w", "", d, now).ID == Build("api", "w", "", other, now).ID {
		t.Fatal("different services must give different ids")
	}
	d2 := d
	d2.State = detector.StateAttackLikely
	if Build("public-web", "w", "", d, now).ID == Build("public-web", "w", "", d2, now).ID {
		t.Fatal("different states must give different ids")
	}
}

func TestBuild_IDStableAcrossWindows(t *testing.T) {
	d1 := decision(signals.Result{Name: "rate", Fired: true})
	d2 := d1
	d2.WindowStart = d1.WindowStart.Add(10 * time.Second)
	d2.WindowEnd = d1.WindowEnd.Add(10 * time.Second)
	if Build("svc", "w", "", d1, now).ID != Build("svc", "w", "", d2, now).ID {
		t.Fatal("same situation in the next window must keep the same id, or dedup never works")
	}
}