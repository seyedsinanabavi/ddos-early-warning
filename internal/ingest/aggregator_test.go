package ingest

import (
	"testing"
	"time"
)

func TestAggregator_Bucketing(t *testing.T) {
	out := make(chan Aggregate, 16)
	agg := NewAggregator("web", 10*time.Second, out)
	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	agg.Add(Event{Time: base.Add(1 * time.Second), Path: "/a", Status: 200, Bytes: 10})
	agg.Add(Event{Time: base.Add(2 * time.Second), Path: "/a", Status: 500, Bytes: 20})
	agg.Add(Event{Time: base.Add(3 * time.Second), Path: "/b", Status: 200, Bytes: 5})
	agg.Add(Event{Time: base.Add(11 * time.Second), Path: "/a", Status: 200, Bytes: 1})

	agg.Flush(base.Add(10 * time.Second)) // closes first window only

	var got []Aggregate
	for len(out) > 0 {
		got = append(got, <-out)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 window got %d", len(got))
	}
	w := got[0]
	if w.Total != 3 || w.Errors5xx != 1 || w.PathCounts["/a"] != 2 || w.PathCounts["/b"] != 1 {
		t.Fatalf("bad window: %+v", w)
	}
	if !w.WindowStart.Equal(base) {
		t.Fatalf("window start: %v", w.WindowStart)
	}
}

func TestAggregator_EmptyWindowNeverEmitted(t *testing.T) {
	out := make(chan Aggregate, 4)
	agg := NewAggregator("web", 10*time.Second, out)
	agg.Flush(time.Now())
	if len(out) != 0 {
		t.Fatal("expected no emission for empty window")
	}
}
