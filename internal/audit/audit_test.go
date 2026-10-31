package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixed = time.Date(2026, 10, 31, 3, 0, 0, 0, time.UTC)

func newTestLogger(buf *bytes.Buffer) *Logger {
	l := New(buf)
	l.now = func() time.Time { return fixed }
	return l
}

func decodeLines(t *testing.T, buf *bytes.Buffer) []Event {
	t.Helper()
	var out []Event
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("invalid JSON line %q: %v", sc.Text(), err)
		}
		out = append(out, ev)
	}
	return out
}

func TestNilLoggerIsNoOp(t *testing.T) {
	var l *Logger
	l.Log(Event{Type: EventConfigLoaded})
	l.ConfigLoaded("/etc/x")
	l.StateTransition("svc", "normal", "suspicious", fixed)
	l.AlertFailed("svc", "id", "ch", "boom")
	l.WithContext(context.Background(), Event{Type: EventServiceStarted})
}

func TestNew_NilWriterReturnsNil(t *testing.T) {
	if New(nil) != nil {
		t.Fatal("New(nil) must return nil")
	}
}

func TestLog_WritesJSONLinesWithInjectedClock(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	l.ServiceStarted("public-web", "collector")
	l.AlertGenerated("public-web", "critical", "a1")

	evs := decodeLines(t, &buf)
	if len(evs) != 2 {
		t.Fatalf("want 2 lines, got %d", len(evs))
	}
	if evs[0].Type != EventServiceStarted || evs[0].Fields["binary"] != "collector" {
		t.Fatalf("first event: %+v", evs[0])
	}
	if !evs[0].Time.Equal(fixed) {
		t.Fatalf("time must come from injected clock, got %v", evs[0].Time)
	}
	if evs[1].Level != "critical" || evs[1].Fields["alert_id"] != "a1" {
		t.Fatalf("second event: %+v", evs[1])
	}
}

func TestLog_KeepsExplicitTime(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	want := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	l.Log(Event{Type: EventStorageError, Time: want})
	evs := decodeLines(t, &buf)
	if len(evs) != 1 || !evs[0].Time.Equal(want) {
		t.Fatalf("explicit time overwritten: %+v", evs)
	}
}

func TestStateTransition_Fields(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	end := time.Date(2026, 10, 31, 4, 30, 0, 0, time.FixedZone("X", 3600))
	l.StateTransition("svc", "normal", "suspicious", end)
	ev := decodeLines(t, &buf)[0]
	if ev.Fields["from"] != "normal" || ev.Fields["to"] != "suspicious" {
		t.Fatalf("fields: %+v", ev.Fields)
	}
	if ev.Fields["window_end"] != "2026-10-31T03:30:00Z" {
		t.Fatalf("window_end must be UTC RFC3339, got %q", ev.Fields["window_end"])
	}
}

func TestAlertFailed_IsWarning(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	l.AlertFailed("svc", "id1", "ops-webhook", "timeout")
	ev := decodeLines(t, &buf)[0]
	if ev.Type != EventAlertFailed || ev.Level != "warning" || ev.Message != "timeout" {
		t.Fatalf("event: %+v", ev)
	}
}

func TestWithContext_CancelledWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.WithContext(ctx, Event{Type: EventServiceStopped})
	if buf.Len() != 0 {
		t.Fatalf("cancelled context must not write, got %q", buf.String())
	}
}

func TestMultiWriter_FanOutAndSkipsNil(t *testing.T) {
	var a, b bytes.Buffer
	la, lb := newTestLogger(&a), newTestLogger(&b)
	m := MultiWriter(la, nil, lb)
	m.ConfigLoaded("/etc/ddos")
	if len(decodeLines(t, &a)) != 1 || len(decodeLines(t, &b)) != 1 {
		t.Fatal("both writers must receive the event")
	}
	if MultiWriter(nil, nil) != nil {
		t.Fatal("no non-nil loggers must return nil")
	}
}

func TestFileWriter_AppendsAndCreatesDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	l, closeFn, err := FileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	l.ConfigLoaded("/etc/ddos")
	l.ServiceStopped("svc", "detector", "signal")
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}

	// Reopen: the file must append, not truncate.
	l2, closeFn2, err := FileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.ConfigLoaded("/etc/ddos")
	_ = closeFn2()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "\n"); n != 3 {
		t.Fatalf("want 3 lines after reopen, got %d", n)
	}
}

func TestFileWriter_EmptyPath(t *testing.T) {
	if _, _, err := FileWriter(""); err == nil {
		t.Fatal("empty path must fail")
	}
}