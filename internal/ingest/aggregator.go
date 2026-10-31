package ingest

import (
	"context"
	"sync"
	"time"
)

// Aggregator buckets Events into fixed windows of Window duration and emits
// Aggregate values on the Out channel. Windows are aligned to Window-epochs
// (i.e. WindowStart = t.Truncate(Window)).
type Aggregator struct {
	Window  time.Duration
	Service string
	Out     chan<- Aggregate

	mu   sync.Mutex
	open map[time.Time]*Aggregate // window-start → aggregate
	now  func() time.Time
	tick *time.Ticker
}

// NewAggregator constructs an Aggregator. Caller owns the Out channel lifetime.
func NewAggregator(service string, window time.Duration, out chan<- Aggregate) *Aggregator {
	if window <= 0 {
		window = 10 * time.Second
	}
	return &Aggregator{
		Window:  window,
		Service: service,
		Out:     out,
		open:    map[time.Time]*Aggregate{},
		now:     time.Now,
	}
}

// Add ingests one Event into the matching window.
func (a *Aggregator) Add(ev Event) {
	start := ev.Time.Truncate(a.Window)
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.open[start]
	if !ok {
		b = &Aggregate{
			Service:       a.Service,
			WindowStart:   start,
			Window:        a.Window,
			PathCounts:    map[string]int64{},
			StatusBuckets: map[int]int64{},
		}
		a.open[start] = b
	}
	b.Total++
	b.BytesTotal += ev.Bytes
	b.PathCounts[ev.Path]++
	b.StatusBuckets[ev.Status]++
	if ev.Status >= 500 && ev.Status <= 599 {
		b.Errors5xx++
	}
}

// Flush emits all windows whose WindowStart+Window <= now and are therefore
// closed. It is safe to call concurrently with Add.
func (a *Aggregator) Flush(now time.Time) {
	a.mu.Lock()
	var ready []*Aggregate
	for start, b := range a.open {
		if start.Add(a.Window).After(now) {
			continue
		}
		ready = append(ready, b)
		delete(a.open, start)
	}
	a.mu.Unlock()
	// Emit in chronological order for deterministic downstream behavior.
	sortAggregates(ready)
	for _, b := range ready {
		select {
		case a.Out <- *b:
		default:
			// Downstream is slow; drop and keep going (backpressure is the
			// caller's choice to handle at a higher level).
		}
	}
}

// Run flushes periodically until ctx is cancelled.
func (a *Aggregator) Run(ctx context.Context) {
	t := time.NewTicker(a.Window)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.Flush(a.now())
		}
	}
}

func sortAggregates(xs []*Aggregate) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1].WindowStart.After(xs[j].WindowStart); j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}
