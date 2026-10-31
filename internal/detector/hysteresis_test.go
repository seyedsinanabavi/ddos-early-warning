package detector

import (
	"testing"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
)

var t0 = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func defaultParams() Params {
	return Params{EnterRequired: 2, ExitRequired: 1, MinSuspicious: 20 * time.Second, MinAttackLikely: 20 * time.Second}
}

// res builds three signal results with the given fired/missing flags.
func res(fired, missing int) []signals.Result {
	out := make([]signals.Result, 0, 3)
	for i := 0; i < 3; i++ {
		out = append(out, signals.Result{Name: "s", Fired: i < fired, Missing: i >= 3-missing})
	}
	return out
}

func hot() []signals.Result     { return res(2, 0) }
func cool() []signals.Result    { return res(0, 0) }
func unknown() []signals.Result { return res(0, 1) }

func TestClassify(t *testing.T) {
	p := defaultParams()
	cases := []struct {
		name string
		in   []signals.Result
		want verdict
	}{
		{"no results", nil, vUnknown},
		{"two fired of three", res(2, 0), vHot},
		{"zero fired all present", res(0, 0), vCool},
		{"one fired all present exit=1", res(1, 0), vCool},
		{"zero fired with missing", res(0, 1), vUnknown},
		{"one fired with missing", res(1, 1), vUnknown},
		{"two fired with missing stays hot", res(2, 1), vHot},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(p, tc.in); got != tc.want {
				t.Fatalf("classify=%d want %d", got, tc.want)
			}
		})
	}
}

func TestClassify_NeutralBand(t *testing.T) {
	p := Params{EnterRequired: 3, ExitRequired: 1, MinSuspicious: time.Second, MinAttackLikely: time.Second}
	if got := classify(p, res(2, 0)); got != vNeutral {
		t.Fatalf("2 fired with enter=3 exit=1 must be neutral, got %d", got)
	}
}

type step struct {
	at   int // seconds after t0 (window end)
	in   []signals.Result
	want State
}

func runSteps(t *testing.T, p Params, steps []step) {
	t.Helper()
	m, err := NewHysteresis(p)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range steps {
		got := m.Step(t0.Add(time.Duration(s.at)*time.Second), s.in)
		if got != s.want {
			t.Fatalf("step %d (t=%ds): state=%s want %s", i, s.at, got, s.want)
		}
	}
}

func TestHysteresis_EscalateAndRecover(t *testing.T) {
	runSteps(t, defaultParams(), []step{
		{0, hot(), StateNormal},
		{10, hot(), StateNormal},
		{20, hot(), StateSuspicious},    // 20s of hot >= MinSuspicious
		{30, hot(), StateSuspicious},    // 10s in suspicious < MinAttackLikely
		{40, hot(), StateAttackLikely},  // 20s in suspicious
		{50, cool(), StateAttackLikely}, // cool run starts
		{60, cool(), StateAttackLikely}, // 10s cool
		{70, cool(), StateSuspicious},   // 20s cool steps down one level
		{80, cool(), StateSuspicious},   // hold
		{90, cool(), StateNormal},       // 20s cool steps down to normal
	})
}

func TestHysteresis_UnknownHoldsTimers(t *testing.T) {
	m, _ := NewHysteresis(defaultParams())
	m.Step(t0, hot())
	m.Step(t0.Add(10*time.Second), hot())
	if got := m.Step(t0.Add(20*time.Second), unknown()); got != StateUnknown {
		t.Fatalf("unknown window must report unknown, got %s", got)
	}
	if m.Level() != StateNormal {
		t.Fatalf("unknown must not change level, got %s", m.Level())
	}
	// Hot resumes; the timer started at t0, so 30s of hot has elapsed.
	if got := m.Step(t0.Add(30*time.Second), hot()); got != StateSuspicious {
		t.Fatalf("hot after unknown: got %s want suspicious", got)
	}
}

func TestHysteresis_CoolResetsEscalation(t *testing.T) {
	runSteps(t, defaultParams(), []step{
		{0, hot(), StateNormal},
		{10, hot(), StateNormal},
		{20, cool(), StateNormal},
		{30, hot(), StateNormal}, // hot run restarts here
		{40, hot(), StateNormal},
		{50, hot(), StateSuspicious},
	})
}

func TestHysteresis_NeutralHoldsTimers(t *testing.T) {
	p := Params{EnterRequired: 3, ExitRequired: 1, MinSuspicious: 20 * time.Second, MinAttackLikely: 20 * time.Second}
	neutral := res(2, 0) // 2 fired of 3 is neutral when enter=3, exit=1
	m, _ := NewHysteresis(p)
	hot3 := []signals.Result{{Fired: true}, {Fired: true}, {Fired: true}}
	seq := []struct {
		at   int
		in   []signals.Result
		want State
	}{
		{0, hot3, StateNormal},
		{10, neutral, StateNormal},
		{20, hot3, StateSuspicious}, // neutral did not reset the hot run
	}
	for i, s := range seq {
		if got := m.Step(t0.Add(time.Duration(s.at)*time.Second), s.in); got != s.want {
			t.Fatalf("step %d: got %s want %s", i, got, s.want)
		}
	}
}

func TestHysteresis_MissingDataNeverNormal(t *testing.T) {
	steps := make([]step, 0, 10)
	for i := 0; i < 10; i++ {
		steps = append(steps, step{i * 10, unknown(), StateUnknown})
	}
	runSteps(t, defaultParams(), steps)

	// Nothing at all is also unknown.
	m, _ := NewHysteresis(defaultParams())
	if got := m.Step(t0, nil); got != StateUnknown {
		t.Fatalf("empty results: got %s want unknown", got)
	}
}

func TestParamsValidate(t *testing.T) {
	base := defaultParams()
	cases := []struct {
		name string
		mut  func(*Params)
		ok   bool
	}{
		{"valid", func(*Params) {}, true},
		{"enter zero", func(p *Params) { p.EnterRequired = 0 }, false},
		{"exit negative", func(p *Params) { p.ExitRequired = -1 }, false},
		{"exit equal enter", func(p *Params) { p.ExitRequired = 2 }, false},
		{"suspicious zero", func(p *Params) { p.MinSuspicious = 0 }, false},
		{"attack zero", func(p *Params) { p.MinAttackLikely = 0 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mut(&p)
			_, err := NewHysteresis(p)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestStateString(t *testing.T) {
	want := map[State]string{
		StateNormal: "normal", StateWarmingUp: "warming_up", StateSuspicious: "suspicious",
		StateAttackLikely: "attack_likely", StateUnknown: "unknown", State(99): "invalid",
	}
	for s, w := range want {
		if s.String() != w {
			t.Fatalf("%d: got %q want %q", s, s.String(), w)
		}
	}
}
