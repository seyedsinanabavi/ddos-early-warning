package alert

import (
	"sync"
	"time"
)

// Dedup suppresses alerts with the same ID within a cooldown window. IDs are
// derived from service, state and the set of fired signals (see deriveID).
type Dedup struct {
	Cooldown time.Duration

	mu     sync.Mutex
	lastAt map[string]time.Time
}

// NewDedup returns a Dedup with the given cooldown. A zero or negative cooldown
// disables deduplication.
func NewDedup(cooldown time.Duration) *Dedup {
	return &Dedup{Cooldown: cooldown, lastAt: map[string]time.Time{}}
}

// Allow reports whether an alert with the given id may be delivered now. If it
// returns true, the cooldown timer is reset. If false, the previous delivery
// time is returned for logging.
func (d *Dedup) Allow(id string, now time.Time) (allowed bool, previous time.Time) {
	if d.Cooldown <= 0 {
		return true, time.Time{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.lastAt[id]; ok {
		if now.Sub(t) < d.Cooldown {
			return false, t
		}
	}
	d.lastAt[id] = now
	return true, time.Time{}
}

// Purge removes entries older than now-cooldown. Call periodically to bound
// memory in a long-running process.
func (d *Dedup) Purge(now time.Time) {
	if d.Cooldown <= 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, t := range d.lastAt {
		if now.Sub(t) >= d.Cooldown {
			delete(d.lastAt, id)
		}
	}
}