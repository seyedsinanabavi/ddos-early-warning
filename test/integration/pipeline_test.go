// Package integration exercises the whole pipeline with synthetic nginx log
// lines: parse, aggregate, detect, alert, deliver, persist. It needs no
// network beyond a local httptest server and writes only to t.TempDir().
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/alert"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/baseline"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/config"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/detector"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/storage"
)

const (
	service    = "public-web"
	windowSize = 10 * time.Second
	// Documentation-only address range (RFC 5737). Used to check that no raw
	// client IP reaches alerts or the persisted baseline.
	clientPrefix = "203.0.113."
)

// t0 is aligned to the window size so window boundaries are predictable.
var t0 = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// windowSpec describes one 10-second window of synthetic traffic.
type windowSpec struct {
	start    time.Time
	requests int
}

// nginxLines produces combined-format lines spread evenly across the window.
// Client IPs and paths rotate so that the log looks like real traffic.
func nginxLines(w windowSpec) []string {
	lines := make([]string, 0, w.requests)
	for i := 0; i < w.requests; i++ {
		ts := w.start.Add(time.Duration(i) * windowSize / time.Duration(w.requests))
		lines = append(lines, fmt.Sprintf(
			`%s%d - - [%s] "GET /page/%d HTTP/1.1" 200 512 "-" "test-agent"`,
			clientPrefix, i%50, ts.Format("02/Jan/2006:15:04:05 -0700"), i%10,
		))
	}
	return lines
}

// pipeline holds the wired components for one service.
type pipeline struct {
	t     *testing.T
	agg   *ingest.Aggregator
	aggCh chan ingest.Aggregate
	eng   *detector.Engine
	mgr   *alert.Manager
	store *storage.FileBaselineStore
	dir   string
}

func newPipeline(t *testing.T, url string, warmupUntil time.Time) *pipeline {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewFileBaselineStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	prof, err := baseline.NewProfile(0.2, 30)
	if err != nil {
		t.Fatal(err)
	}

	// Only the rate signal is enabled here so the expected verdicts are easy to
	// reason about. Enter on one fired signal, exit when none fire.
	sigs := []signals.Signal{&signals.Rate{MinVolumeFloor: 5, ZEnter: 4.0, ZExit: 2.5}}
	m, err := detector.NewHysteresis(detector.Params{
		EnterRequired:   1,
		ExitRequired:    0,
		MinSuspicious:   20 * time.Second,
		MinAttackLikely: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	eng, err := detector.NewEngine(service, prof, sigs, m, 3, warmupUntil)
	if err != nil {
		t.Fatal(err)
	}

	ch, err := alert.NewWebhookChannel(config.ChannelConfig{Name: "test-hook", Type: "webhook", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	mgr := &alert.Manager{
		Dedup:    alert.NewDedup(time.Minute),
		Channels: []alert.Channel{ch},
	}

	aggCh := make(chan ingest.Aggregate, 256)
	return &pipeline{
		t:     t,
		agg:   ingest.NewAggregator(service, windowSize, aggCh),
		aggCh: aggCh,
		eng:   eng,
		mgr:   mgr,
		store: store,
		dir:   dir,
	}
}

// feed parses the lines of one window, aggregates them, flushes the closed
// window, and runs the engine on it. It returns the engine decision.
func (p *pipeline) feed(w windowSpec) detector.Decision {
	p.t.Helper()
	for _, line := range nginxLines(w) {
		ev, err := ingest.ParseNginxLine(line, service)
		if err != nil {
			p.t.Fatalf("parse %q: %v", line, err)
		}
		p.agg.Add(ev)
	}
	p.agg.Flush(w.start.Add(windowSize))

	select {
	case a := <-p.aggCh:
		d, err := p.eng.Step(context.Background(), a)
		if err != nil {
			p.t.Fatalf("engine step: %v", err)
		}
		return d
	default:
		p.t.Fatalf("window %s was not emitted by the aggregator", w.start.Format(time.RFC3339))
		return detector.Decision{}
	}
}

// dispatch builds and delivers an alert for a decision that changed state and
// is alertable. It mirrors what the notifier does for each decision.
func (p *pipeline) dispatch(d detector.Decision, severity string) {
	p.t.Helper()
	a := alert.Build(service, severity, "", d, d.WindowEnd)
	if err := p.mgr.Dispatch(context.Background(), a); err != nil {
		p.t.Fatalf("dispatch: %v", err)
	}
}

// webhookRecorder collects request bodies sent by the alert channel.
type webhookRecorder struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (r *webhookRecorder) serve(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.bodies = append(r.bodies, b)
	r.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (r *webhookRecorder) all() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.bodies...)
}

// warmupWindows returns quiet traffic that fills the baseline before detection
// starts. Each window has 20 requests.
func warmupWindows(n int) []windowSpec {
	out := make([]windowSpec, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, windowSpec{start: t0.Add(time.Duration(i) * windowSize), requests: 20})
	}
	return out
}

func TestPipeline_QuietTrafficNeverAlerts(t *testing.T) {
	rec := &webhookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.serve))
	t.Cleanup(srv.Close)

	warmEnd := t0.Add(40 * windowSize)
	p := newPipeline(t, srv.URL, warmEnd)

	for _, w := range warmupWindows(40) {
		p.feed(w)
	}
	for i := 40; i < 60; i++ {
		w := windowSpec{start: t0.Add(time.Duration(i) * windowSize), requests: 20}
		d := p.feed(w)
		if d.State == detector.StateSuspicious || d.State == detector.StateAttackLikely {
			t.Fatalf("quiet window %d escalated to %s", i, d.State)
		}
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("quiet traffic delivered %d alerts, want 0", n)
	}
}

func TestPipeline_BurstEscalatesAndAlerts(t *testing.T) {
	rec := &webhookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.serve))
	t.Cleanup(srv.Close)

	warmEnd := t0.Add(40 * windowSize)
	p := newPipeline(t, srv.URL, warmEnd)

	for _, w := range warmupWindows(40) {
		p.feed(w)
	}

	// A sustained burst, 20x the baseline volume.
	var reported []detector.State
	for i := 40; i < 46; i++ {
		w := windowSpec{start: t0.Add(time.Duration(i) * windowSize), requests: 400}
		d := p.feed(w)
		reported = append(reported, d.State)
		if d.Changed {
			switch d.State {
			case detector.StateSuspicious:
				p.dispatch(d, "warning")
			case detector.StateAttackLikely:
				p.dispatch(d, "critical")
			}
		}
	}

	wantStates := []detector.State{
		detector.StateNormal,       // first hot window, 0s of hot
		detector.StateNormal,       // 10s of hot
		detector.StateSuspicious,   // 20s of hot
		detector.StateSuspicious,   // 10s in suspicious
		detector.StateAttackLikely, // 20s in suspicious
		detector.StateAttackLikely, // held
	}
	for i := range wantStates {
		if reported[i] != wantStates[i] {
			t.Fatalf("window %d: state=%s want %s (all: %v)", i, reported[i], wantStates[i], reported)
		}
	}

	bodies := rec.all()
	if len(bodies) != 2 {
		t.Fatalf("delivered %d alerts, want 2 (suspicious, attack_likely)", len(bodies))
	}
	var got []alert.Alert
	for _, b := range bodies {
		var a alert.Alert
		if err := json.Unmarshal(b, &a); err != nil {
			t.Fatalf("alert body is not valid JSON: %v", err)
		}
		got = append(got, a)
	}
	if got[0].State != "suspicious" || got[0].Severity != "warning" {
		t.Errorf("first alert: state=%s severity=%s", got[0].State, got[0].Severity)
	}
	if got[1].State != "attack_likely" || got[1].Severity != "critical" {
		t.Errorf("second alert: state=%s severity=%s", got[1].State, got[1].Severity)
	}
	for _, a := range got {
		if a.Service != service || a.ID == "" {
			t.Errorf("alert missing service or id: %+v", a)
		}
	}

	// Privacy: no raw client IP may appear in any delivered alert.
	for _, b := range bodies {
		if strings.Contains(string(b), clientPrefix) {
			t.Fatalf("alert leaks a client address: %s", b)
		}
	}
}

func TestPipeline_BaselinePersistsWithoutClientIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)

	p := newPipeline(t, srv.URL, t0)
	for _, w := range warmupWindows(40) {
		p.feed(w)
	}

	if err := p.store.Save(service, p.eng.Profile.State()); err != nil {
		t.Fatal(err)
	}

	// Reload through the same store to prove the round trip works.
	st, ok, err := p.store.Load(service)
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if _, err := baseline.RestoreProfile(st); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Privacy: every file written to the storage dir must be free of client IPs.
	err = filepath.Walk(p.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), clientPrefix) {
			t.Fatalf("%s contains a client address", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}