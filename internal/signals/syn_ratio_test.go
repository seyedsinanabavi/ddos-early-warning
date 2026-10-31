package signals

import (
	"context"
	"errors"
	"math"
	"testing"
)

func TestSYNRatio_Missing(t *testing.T) {
	cases := []struct {
		name string
		src  TCPSource
	}{
		{"no source", nil},
		{"source error", fakeTCP{err: errors.New("no /proc")}},
		{"no established", fakeTCP{c: TCPCounts{SynRecv: 5, Established: 0}}},
		{"below min established", fakeTCP{c: TCPCounts{SynRecv: 5, Established: 3}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &SYNRatio{Source: tc.src, EnterRatio: 0.3, ExitRatio: 0.2, MinEstablished: 10}
			res, err := s.Eval(context.Background(), window(0, nil), nil)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Missing || res.Fired {
				t.Fatalf("want missing, got %+v", res)
			}
		})
	}
}

func TestSYNRatio_HysteresisSequence(t *testing.T) {
	steps := []struct {
		c      TCPCounts
		wantOn bool
	}{
		{TCPCounts{SynRecv: 60, Established: 100}, true},  // 0.6 enters
		{TCPCounts{SynRecv: 25, Established: 100}, true},  // 0.25 stays above exit 0.2
		{TCPCounts{SynRecv: 10, Established: 100}, false}, // 0.1 clears
		{TCPCounts{SynRecv: 25, Established: 100}, false}, // 0.25 is below enter 0.3
	}
	// Use one signal instance across steps so the memory is kept.
	s := &SYNRatio{Source: nil, EnterRatio: 0.3, ExitRatio: 0.2, MinEstablished: 10}
	for i, st := range steps {
		s.Source = fakeTCP{c: st.c}
		res, err := s.Eval(context.Background(), window(0, nil), nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Fired != st.wantOn {
			t.Fatalf("step %d: fired=%v want %v (%s)", i, res.Fired, st.wantOn, res.Reason)
		}
		if math.IsNaN(res.Value) {
			t.Fatal("value must not be NaN")
		}
	}
}
