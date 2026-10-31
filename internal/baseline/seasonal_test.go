package baseline

import (
	"testing"
	"time"
)

var (
	monday10  = time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC) // Monday 10:00
	tuesday10 = monday10.AddDate(0, 0, 1)
)

func TestSeasonal_ColdStart(t *testing.T) {
	s := NewSeasonal(0.2, 5)
	if _, ok := s.Get(monday10); ok {
		t.Fatal("cold start must be not-ok")
	}
	if _, _, ok := s.MeanStd(monday10); ok {
		t.Fatal("cold MeanStd must be not-ok")
	}
}

func TestSeasonal_MinSamplesGate(t *testing.T) {
	s := NewSeasonal(0.5, 3)
	s.Update(monday10, 10)
	s.Update(monday10, 10)
	if _, ok := s.Get(monday10); ok {
		t.Fatal("2 samples with minN=3 must not be ok")
	}
	s.Update(monday10, 10)
	if v, ok := s.Get(monday10); !ok || v != 10 {
		t.Fatalf("3 samples: v=%v ok=%v", v, ok)
	}
}

func TestSeasonal_BucketIsolation(t *testing.T) {
	s := NewSeasonal(0.5, 1)
	s.Update(monday10, 100)
	if _, ok := s.Get(tuesday10); ok {
		t.Fatal("different weekday bucket must not be warmed")
	}
	if v, ok := s.Get(monday10); !ok || v != 100 {
		t.Fatalf("monday bucket: v=%v ok=%v", v, ok)
	}
}

func TestSeasonal_SameHourDifferentMinuteSharesBucket(t *testing.T) {
	s := NewSeasonal(0.5, 1)
	s.Update(monday10.Add(5*time.Minute), 42)
	if v, ok := s.Get(monday10.Add(50 * time.Minute)); !ok || v != 42 {
		t.Fatalf("same hour must share bucket: v=%v ok=%v", v, ok)
	}
}

func TestSeasonal_RoundTripPreservesValues(t *testing.T) {
	p, err := NewProfile(0.3, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		p.Update(monday10, float64(i), 0.1, 0.0)
	}
	want, _, _ := p.RateStats(monday10)

	b, err := MarshalState(p.State())
	if err != nil {
		t.Fatal(err)
	}
	st, err := UnmarshalState(b)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreProfile(st)
	if err != nil {
		t.Fatal(err)
	}
	got, _, ok := restored.RateStats(monday10)
	if !ok || got != want {
		t.Fatalf("round-trip: want %v got %v ok=%v", want, got, ok)
	}
}
