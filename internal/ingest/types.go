// Package ingest tails nginx/haproxy access logs, parses them into a
// normalized Event, and produces rolling windows of Aggregate values.
//
// Privacy invariant: Event.SourceIP is used only transiently inside this
// package (for entropy/prefix stubs in later versions) and MUST NOT be
// persisted or logged. Only Aggregate values leave this package downstream.
package ingest

import "time"

// Event is one parsed access-log line.
type Event struct {
	Time     time.Time
	Service  string
	Method   string
	Path     string
	Status   int
	Latency  time.Duration
	Bytes    int64
	SourceIP string // transient only; never persisted
}

// Aggregate is the per-window output emitted downstream.
// It contains no raw IPs, only counts and derived scalars.
type Aggregate struct {
	Service       string
	WindowStart   time.Time
	Window        time.Duration
	Total         int64
	Errors5xx     int64
	PathCounts    map[string]int64
	StatusBuckets map[int]int64
	BytesTotal    int64
}

// ErrMalformed is returned by parsers on unparseable input.
var ErrMalformed = errMalformed{}

type errMalformed struct{}

func (errMalformed) Error() string { return "ingest: malformed log line" }
