package alert

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/audit"
)

// fakeChannel fails the first `fails` deliveries, then accepts.
type fakeChannel struct {
	name  string
	fails int
	calls int
	got   []Alert
}

func (f *fakeChannel) Name() string { return f.name }

func (f *fakeChannel) Deliver(_ context.Context, a Alert) error {
	f.calls++
	if f.calls <= f.fails {
		return errors.New("down")
	}
	f.got = append(f.got, a)
	return nil
}

func testAlert(id string) Alert { return Alert{ID: id, Service: "svc", State: "suspicious"} }

func TestManager_NoChannels(t *testing.T) {
	m := &Manager{}
	if err := m.Dispatch(context.Background(), testAlert("a")); err == nil {
		t.Fatal("no channels must be an error")
	}
}

func TestManager_DeliversToAllChannels(t *testing.T) {
	c1, c2 := &fakeChannel{name: "c1"}, &fakeChannel{name: "c2"}
	m := &Manager{Channels: []Channel{c1, c2}, Now: func() time.Time { return now }}
	if err := m.Dispatch(context.Background(), testAlert("a")); err != nil {
		t.Fatal(err)
	}
	if len(c1.got) != 1 || len(c2.got) != 1 {
		t.Fatalf("both channels must get the alert: %d %d", len(c1.got), len(c2.got))
	}
}

func TestManager_DedupSuppressesRepeat(t *testing.T) {
	var buf bytes.Buffer
	c := &fakeChannel{name: "c"}
	m := &Manager{
		Dedup:    NewDedup(5 * time.Minute),
		Channels: []Channel{c},
		Audit:    audit.New(&buf),
		Now:      func() time.Time { return now },
	}
	ctx := context.Background()
	if err := m.Dispatch(ctx, testAlert("a")); err != nil {
		t.Fatal(err)
	}
	if err := m.Dispatch(ctx, testAlert("a")); err != nil {
		t.Fatal(err)
	}
	if len(c.got) != 1 {
		t.Fatalf("repeat within cooldown must be suppressed, delivered %d", len(c.got))
	}
	if !strings.Contains(buf.String(), audit.EventAlertDeduplicated) {
		t.Fatalf("suppression must be audited: %s", buf.String())
	}
}

func TestManager_InjectedClockControlsCooldown(t *testing.T) {
	c := &fakeChannel{name: "c"}
	clock := now
	m := &Manager{
		Dedup:    NewDedup(5 * time.Minute),
		Channels: []Channel{c},
		Now:      func() time.Time { return clock },
	}
	ctx := context.Background()
	_ = m.Dispatch(ctx, testAlert("a"))
	clock = now.Add(5 * time.Minute)
	_ = m.Dispatch(ctx, testAlert("a"))
	if len(c.got) != 2 {
		t.Fatalf("after cooldown the alert must be delivered again, got %d", len(c.got))
	}
}

func TestManager_FailedAlertIsNotSuppressed(t *testing.T) {
	c := &fakeChannel{name: "c", fails: 1}
	m := &Manager{Dedup: NewDedup(time.Hour), Channels: []Channel{c}, Now: func() time.Time { return now }}
	ctx := context.Background()

	if err := m.Dispatch(ctx, testAlert("a")); err == nil {
		t.Fatal("all channels failed: want error")
	}
	// The failed alert must not occupy the cooldown; the next window delivers it.
	if err := m.Dispatch(ctx, testAlert("a")); err != nil {
		t.Fatalf("retry after failure should deliver: %v", err)
	}
	if len(c.got) != 1 {
		t.Fatalf("want 1 delivered, got %d", len(c.got))
	}
}

func TestManager_PartialFailureIsNotAnError(t *testing.T) {
	var buf bytes.Buffer
	bad := &fakeChannel{name: "bad", fails: 99}
	good := &fakeChannel{name: "good"}
	m := &Manager{Channels: []Channel{bad, good}, Audit: audit.New(&buf), Now: func() time.Time { return now }}
	if err := m.Dispatch(context.Background(), testAlert("a")); err != nil {
		t.Fatalf("partial failure must not be an error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, audit.EventAlertFailed) || !strings.Contains(out, audit.EventAlertDelivered) {
		t.Fatalf("audit must record both outcomes: %s", out)
	}
}

func TestManager_RetriesUntilSuccess(t *testing.T) {
	c := &fakeChannel{name: "c", fails: 2}
	m := &Manager{Channels: []Channel{c}, Retries: 2, Backoff: time.Millisecond, Now: func() time.Time { return now }}
	if err := m.Dispatch(context.Background(), testAlert("a")); err != nil {
		t.Fatal(err)
	}
	if c.calls != 3 {
		t.Fatalf("want 3 attempts, got %d", c.calls)
	}
}

func TestManager_GivesUpAfterRetries(t *testing.T) {
	c := &fakeChannel{name: "c", fails: 99}
	m := &Manager{Channels: []Channel{c}, Retries: 2, Backoff: time.Millisecond, Now: func() time.Time { return now }}
	if err := m.Dispatch(context.Background(), testAlert("a")); err == nil {
		t.Fatal("must fail after retries are exhausted")
	}
	if c.calls != 3 {
		t.Fatalf("want 3 attempts, got %d", c.calls)
	}
}

func TestManager_ContextCancelStopsRetries(t *testing.T) {
	c := &fakeChannel{name: "c", fails: 99}
	m := &Manager{Channels: []Channel{c}, Retries: 5, Backoff: 10 * time.Second, Now: func() time.Time { return now }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := m.Dispatch(ctx, testAlert("a")); err == nil {
		t.Fatal("must fail when cancelled")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation must interrupt the backoff sleep")
	}
}