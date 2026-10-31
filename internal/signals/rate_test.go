package signals

import (
	"context"
	"math"
	"testing"
)

func TestRate_Missing(t *testing.T) {
	cases := []struct {
		name string
		agg  int64
		b    fakeBaseline
	}{
		{"below floor", 3, fakeBaseline{mean: 100, std: 10, ok: true}},
		{"cold baseline", 500, fakeBaseline{ok: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Rate{MinVolumeFloor: 5, ZEnter: 4, ZExit: 2.5}
			res, err := r.Eval(context.Background(), window(tc.agg, nil), tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Missing || res.Fired {
				t.Fatalf("want missing and not fired, got %+v", res)
			}
		})
	}
}

func TestRate_ZScoreAndFloor(t *testing.T) {
	cases := []struct {
		name  string
		total int64
		mean  float64
		std   float64
		wantZ float64
	}{
		{"at mean", 100, 100, 10, 0},
		{"two sigma", 120, 100, 10, 2},
		// std 0 is floored to max(1, 10% of mean) = 10, so z = 50/10 = 5.
		{"zero std uses floor", 150, 100, 0, 5},
		// Tiny mean: floor is 1, so z = (8-2)/1 = 6.
		{"small mean floor", 8, 2, 0, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Rate{MinVolumeFloor: 1, ZEnter: 100, ZExit: 50}
			res, err := r.Eval(context.Background(), window(tc.total, nil),
				fakeBaseline{mean: tc.mean, std: tc.std, ok: true})
			if err != nil {
				t.Fatal(err)
			}
			if res.Missing || math.Abs(res.Value-tc.wantZ) > 1e-9 {
				t.Fatalf("z=%v missing=%v want %v", res.Value, res.Missing, tc.wantZ)
			}
			if res.Fired {
				t.Fatal("z below ZEnter must not fire")
			}
		})
	}
}

func TestRate_HysteresisSequence(t *testing.T) {
	// Enter at z>=4, exit when z<2.5. Baseline mean 100, std 10.
	r := &Rate{MinVolumeFloor: 5, ZEnter: 4, ZExit: 2.5}
	b := fakeBaseline{mean: 100, std: 10, ok: true}
	steps := []struct {
		total     int64
		wantFired bool
	}{
		{140, true},  // z=4 enters
		{130, true},  // z=3 stays above exit
		{120, false}, // z=2 clears
		{130, false}, // z=3 is below enter, so it does not re-fire
	}
	for i, s := range steps {
		res, err := r.Eval(context.Background(), window(s.total, nil), b)
		if err != nil {
			t.Fatal(err)
		}
		if res.Fired != s.wantFired {
			t.Fatalf("step %d total=%d: fired=%v want %v (%s)", i, s.total, res.Fired, s.wantFired, res.Reason)
		}
	}
}

func TestRate_CancelledContext(t *testing.T) {
	r := &Rate{MinVolumeFloor: 1, ZEnter: 1, ZExit: 0}
	if _, err := r.Eval(cancelledCtx(), window(10, nil), fakeBaseline{ok: true}); err == nil {
		t.Fatal("cancelled context must return an error")
	}
}
