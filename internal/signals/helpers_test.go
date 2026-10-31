package signals

import (
	"context"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
)

var at = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// fakeBaseline is a fixed Baseline for tests.
type fakeBaseline struct {
	mean, std float64
	ok        bool
	share     float64
	shareOK   bool
}

func (f fakeBaseline) RateStats(time.Time) (float64, float64, bool) { return f.mean, f.std, f.ok }
func (f fakeBaseline) TopShare(time.Time) (float64, bool)           { return f.share, f.shareOK }

// fakeTCP is a fixed TCPSource for tests.
type fakeTCP struct {
	c   TCPCounts
	err error
}

func (f fakeTCP) Counts() (TCPCounts, error) { return f.c, f.err }

func window(total int64, paths map[string]int64) ingest.Aggregate {
	return ingest.Aggregate{WindowStart: at, Window: 10 * time.Second, Total: total, PathCounts: paths}
}

func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
