package baseline

import (
	"math"
	"testing"
	"time"
)

func TestEWMA_Converges(t *testing.T) {
	e := &EWMA{Alpha: 0.2}
	for i := 0; i < 200; i++ {
		e.Update(50)
	}
	v, ok := e.Value()
	if !ok || math.Abs(v-50) > 0.01 {
		t.Fatalf("want 50 got %v (ok=%v)", v, ok)
	}
}

func TestEWMA_FirstValueAndEmpty(t *testing.T) {
	e := &EWMA{Alpha: 0.2}
	if _, ok := e.Value(); ok {
		t.Fatal("empty EWMA must not be ok")
	}
	e.Update(42)
	if v, _ := e.Value(); v != 42 {
		t.Fatalf("got %v", v)
	}
}

func TestEWMA_IgnoresNaNAndInf(t *testing.T) {
	e := &EWMA{Alpha: 0.2}
	e.Update(math.NaN())
	e.Update(math.Inf(1))
	if _, ok := e.Value(); ok || e.Samples() != 0 {
		t.Fatal("NaN/Inf must be ignored")
	}
}

func TestEWMA_ConstantInputHasZeroStd(t *testing.T) {
	e := &EWMA{Alpha: 0.5}
	for i := 0; i < 4; i++ {
		e.Update(10)
	}
	_, std, ok := e.MeanStd()
	if !ok || std > 1e-9 {
		t.Fatalf("std should be ~0, got %v", std)
	}
}

func TestEWMA_AlternatingInputHasPositiveStd(t *testing.T) {
	e := &EWMA{Alpha: 0.1}
	for i := 0; i < 500; i++ {
		if i%2 == 0 {
			e.Update(0)
		} else {
			e.Update(10)
		}
	}
	mean, std, _ := e.MeanStd()
	if math.Abs(mean-5) > 0.5 {
		t.Fatalf("mean want ~5 got %v", mean)
	}
	// True standard deviation of {0,10} alternating is 5.
	if math.Abs(std-5) > 1 {
		t.Fatalf("std want ~5 got %v", std)
	}
}

func TestNewProfile_Validation(t *testing.T) {
	cases := []struct {
		name  string
		alpha float64
		minN  int
		ok    bool
	}{
		{"valid", 0.2, 5, true},
		{"alpha zero", 0, 5, false},
		{"alpha above one", 1.5, 5, false},
		{"minN zero", 0.2, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewProfile(tc.alpha, tc.minN)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestProfile_ColdAndWarm(t *testing.T) {
	p, _ := NewProfile(0.5, 2)
	at := time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC)
	if _, _, ok := p.RateStats(at); ok {
		t.Fatal("cold rate must not be ok")
	}
	if _, ok := p.TopShare(at); ok {
		t.Fatal("cold top share must not be ok")
	}
	p.Update(at, 100, 0.3, 0.01)
	p.Update(at, 120, 0.3, 0.01)
	if m, _, ok := p.RateStats(at); !ok || m < 100 || m > 120 {
		t.Fatalf("warm rate mean=%v ok=%v", m, ok)
	}
	if s, ok := p.TopShare(at); !ok || math.Abs(s-0.3) > 1e-9 {
		t.Fatalf("top share=%v ok=%v", s, ok)
	}
	if e, ok := p.ErrShare(at); !ok || math.Abs(e-0.01) > 1e-9 {
		t.Fatalf("err share=%v ok=%v", e, ok)
	}
}

func TestRestoreProfile_RejectsBadState(t *testing.T) {
	p, _ := NewProfile(0.2, 1)
	good := p.State()

	bad := good
	bad.Version = 99
	if _, err := RestoreProfile(bad); err == nil {
		t.Fatal("unknown version must fail")
	}

	bad = good
	bad.Alpha = 0
	if _, err := RestoreProfile(bad); err == nil {
		t.Fatal("alpha=0 must fail")
	}

	bad = good
	bad.Rate[3].N = -1
	if _, err := RestoreProfile(bad); err == nil {
		t.Fatal("negative count must fail")
	}

	bad = good
	bad.TopShare[5].Value = math.NaN()
	if _, err := RestoreProfile(bad); err == nil {
		t.Fatal("NaN value must fail")
	}
}
