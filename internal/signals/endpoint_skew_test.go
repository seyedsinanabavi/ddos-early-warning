package signals

import (
	"context"
	"math"
	"testing"
)

func TestTopKShare(t *testing.T) {
	counts := map[string]int64{"/a": 6, "/b": 3, "/c": 1}
	cases := []struct {
		name  string
		k     int
		total int64
		want  float64
	}{
		{"top1", 1, 10, 0.6},
		{"top2", 2, 10, 0.9},
		{"k larger than paths", 10, 10, 1.0},
		{"k zero", 0, 10, 0},
		{"total zero", 1, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TopKShare(counts, tc.k, tc.total); math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	if got := TopKShare(nil, 3, 10); got != 0 {
		t.Fatalf("nil counts: got %v", got)
	}
}

func TestEndpointSkew_MissingCases(t *testing.T) {
	s := &EndpointSkew{TopK: 1, MinVolumeFloor: 5, RatioEnter: 0.6, RatioExit: 0.4}
	res, _ := s.Eval(context.Background(), window(3, map[string]int64{"/": 3}), fakeBaseline{shareOK: true})
	if !res.Missing {
		t.Fatal("below volume floor must be missing")
	}
	res, _ = s.Eval(context.Background(), window(100, map[string]int64{"/": 100}), fakeBaseline{shareOK: false})
	if !res.Missing {
		t.Fatal("cold baseline must be missing")
	}
}

func TestEndpointSkew_HysteresisSequence(t *testing.T) {
	s := &EndpointSkew{TopK: 1, MinVolumeFloor: 5, RatioEnter: 0.6, RatioExit: 0.4}
	b := fakeBaseline{share: 0.2, shareOK: true}
	steps := []struct {
		hot    int64 // requests on "/hot"
		total  int64
		wantOn bool
	}{
		{50, 100, false}, // 0.5 below enter 0.6
		{70, 100, true},  // 0.7 enters
		{50, 100, true},  // 0.5 stays above exit 0.4
		{30, 100, false}, // 0.3 clears
	}
	for i, st := range steps {
		rest := st.total - st.hot
		paths := map[string]int64{"/hot": st.hot, "/o1": rest / 2, "/o2": rest - rest/2}
		res, err := s.Eval(context.Background(), window(st.total, paths), b)
		if err != nil {
			t.Fatal(err)
		}
		if res.Fired != st.wantOn {
			t.Fatalf("step %d: fired=%v want %v (%s)", i, res.Fired, st.wantOn, res.Reason)
		}
		if res.Baseline != 0.2 {
			t.Fatalf("baseline not reported: %v", res.Baseline)
		}
	}
}
