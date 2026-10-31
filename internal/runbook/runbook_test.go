package runbook

import (
	"strings"
	"testing"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/detector"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
)

func results() []signals.Result {
	return []signals.Result{
		{Name: "rate", Fired: true},
		{Name: "endpoint_skew"},
		{Name: "syn_ratio", Missing: true},
	}
}

func TestForState_NoGuidanceForQuietStates(t *testing.T) {
	for _, s := range []detector.State{detector.StateNormal, detector.StateWarmingUp} {
		if got := ForState(s, results(), Options{Service: "svc"}); got != "" {
			t.Fatalf("%s: want empty guidance, got %q", s, got)
		}
	}
}

func TestForState_Suspicious(t *testing.T) {
	got := ForState(detector.StateSuspicious, results(), Options{Service: "public-web"})
	for _, want := range []string{`"public-web"`, "Signals that fired: rate", "No automatic action"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "syn_ratio") {
		t.Fatal("missing signals must not be listed as fired")
	}
}

func TestForState_AttackLikelyNeverSuggestsBlocking(t *testing.T) {
	got := ForState(detector.StateAttackLikely, results(), Options{Service: "api"})
	if !strings.Contains(got, "Attack likely") || !strings.Contains(got, "No automatic blocking") {
		t.Fatalf("unexpected text:\n%s", got)
	}
	if strings.Contains(strings.ToLower(got), "block the ip") {
		t.Fatal("guidance must not instruct IP blocking")
	}
}

func TestForState_UnknownListsMissingSignals(t *testing.T) {
	got := ForState(detector.StateUnknown, results(), Options{Service: "api"})
	if !strings.Contains(got, "Missing signals: syn_ratio") {
		t.Fatalf("missing list not shown:\n%s", got)
	}
	if !strings.Contains(got, "Do NOT assume the service is normal") {
		t.Fatalf("unknown must warn against assuming normal:\n%s", got)
	}
}

func TestListFired_NoneRecorded(t *testing.T) {
	got := ForState(detector.StateSuspicious, []signals.Result{{Name: "rate"}}, Options{Service: "s"})
	if !strings.Contains(got, "(none recorded)") {
		t.Fatalf("want (none recorded):\n%s", got)
	}
}

func TestDocsURL(t *testing.T) {
	with := ForState(detector.StateSuspicious, results(), Options{Service: "s", DocsURL: "https://docs.example/runbook"})
	if !strings.Contains(with, "Docs: https://docs.example/runbook") {
		t.Fatalf("docs link missing:\n%s", with)
	}
	without := ForState(detector.StateSuspicious, results(), Options{Service: "s"})
	if strings.Contains(without, "Docs:") {
		t.Fatal("docs line must be absent when DocsURL is empty")
	}
}

func TestDefaultRules_Posture(t *testing.T) {
	r := DefaultRules()
	found := false
	for _, n := range r.Never {
		if n == "block or drop network traffic" {
			found = true
		}
	}
	if !found {
		t.Fatal("'block or drop network traffic' must be in Never")
	}
	out := r.Render()
	if !strings.Contains(out, "Automatic:\n") || !strings.Contains(out, "Never:\n") {
		t.Fatalf("render missing sections:\n%s", out)
	}
}