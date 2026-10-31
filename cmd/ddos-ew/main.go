// Command ddos-ew runs the whole early-warning pipeline in one process:
// log tailing, aggregation, baseline and signals, detection, and alerting.
//
// It reads only the operator's own access logs and local TCP state, never
// sends traffic, and persists aggregates and baselines, not raw client IPs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/alert"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/audit"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/baseline"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/config"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/detector"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/notifier"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/storage"
)

// saveEvery is how often each service's baseline is written to disk, in
// addition to the save on shutdown.
const saveEvery = 5 * time.Minute

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ddos-ew:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgDir := flag.String("config", "configs", "directory with collector.yaml, detection.yaml and alerts.yaml")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.Load(*cfgDir)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	store, err := storage.NewFileBaselineStore(cfg.Collector.Storage.Dir)
	if err != nil {
		return err
	}
	auditLog, closeAudit, err := audit.FileWriter(filepath.Join(cfg.Collector.Storage.Dir, "audit.jsonl"))
	if err != nil {
		return err
	}
	defer func() { _ = closeAudit() }()
	auditLog.ConfigLoaded(*cfgDir)

	channels, err := alert.ChannelsFromConfig(cfg.Alerts.Channels)
	if err != nil {
		return err
	}
	mgr := newManager(cfg, channels, auditLog)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	for _, svc := range cfg.Collector.Services {
		if err := startService(ctx, &wg, svc, cfg, store, mgr, auditLog, logger); err != nil {
			stop()
			wg.Wait()
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
		auditLog.ServiceStarted(svc.Name, "ddos-ew")
		logger.Info("service started", "service", svc.Name, "logs", len(svc.LogPaths))
	}

	<-ctx.Done()
	logger.Info("shutting down")
	wg.Wait()
	logger.Info("stopped")
	return nil
}

// newManager builds the shared alert manager. Retry settings are per channel
// in config, but the manager uses one value for all channels. This takes the
// largest retry count and the first configured backoff, and documents that
// limitation.
func newManager(cfg *config.Config, channels []alert.Channel, al *audit.Logger) *alert.Manager {
	m := &alert.Manager{
		Dedup:    alert.NewDedup(cfg.Alerts.Dedup.CooldownDur),
		Channels: channels,
		Audit:    al,
		Now:      func() time.Time { return time.Now().UTC() },
	}
	for _, c := range cfg.Alerts.Channels {
		if c.MaxRetries > m.Retries {
			m.Retries = c.MaxRetries
		}
		if m.Backoff == 0 && c.BackoffBaseDur > 0 {
			m.Backoff = c.BackoffBaseDur
		}
		if m.BackoffMax == 0 && c.BackoffMaxDur > 0 {
			m.BackoffMax = c.BackoffMaxDur
		}
	}
	return m
}

// startService wires one service: tailers feed an aggregator, the aggregator
// feeds the engine, and the engine feeds a notifier. Every goroutine stops
// when ctx is cancelled.
func startService(ctx context.Context, wg *sync.WaitGroup, svc config.ServiceConfig, cfg *config.Config,
	store storage.BaselineStore, mgr *alert.Manager, al *audit.Logger, logger *slog.Logger) error {

	parse, err := parserFor(svc)
	if err != nil {
		return err
	}
	eng, err := newEngine(svc, cfg, store)
	if err != nil {
		return err
	}
	notif, err := notifier.New(notifier.Options{
		Service: svc.Name,
		Severities: notifier.Severities{
			Suspicious:   cfg.Alerts.Severity.Suspicious,
			AttackLikely: cfg.Alerts.Severity.AttackLikely,
			Unknown:      cfg.Alerts.Severity.Unknown,
		},
		Manager: mgr,
		Audit:   al,
		Logger:  logger,
		Now:     func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return err
	}

	aggCh := make(chan ingest.Aggregate, 64)
	agg := ingest.NewAggregator(svc.Name, svc.Interval, aggCh)

	wg.Add(1)
	go func() { defer wg.Done(); agg.Run(ctx) }()

	wg.Add(1)
	go func() { defer wg.Done(); _ = notif.Run(ctx) }()

	for _, path := range svc.LogPaths {
		tl := ingest.NewTailer(path)
		tl.OnLine = func(line string) error {
			ev, err := parse(line, svc.Name)
			if err != nil {
				return nil // malformed lines are skipped, not fatal
			}
			agg.Add(ev)
			return nil
		}
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			if err := tl.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("tailer stopped", "service", svc.Name, "err", err)
				al.StorageError(svc.Name, "tail", err.Error())
			}
		}(path)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		save := func() {
			if err := store.Save(svc.Name, eng.Profile.State()); err != nil {
				logger.Error("baseline save failed", "service", svc.Name, "err", err)
				al.StorageError(svc.Name, "save_baseline", err.Error())
			}
		}
		ticker := time.NewTicker(saveEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				save()
				return
			case <-ticker.C:
				save()
			case a := <-aggCh:
				d, err := eng.Step(ctx, a)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					logger.Error("detector step failed", "service", svc.Name, "err", err)
					continue
				}
				if d.Changed {
					logger.Info("state changed", "service", svc.Name,
						"from", d.Previous.String(), "to", d.State.String())
				}
				notif.Submit(d)
			}
		}
	}()
	return nil
}

// newEngine builds the detector for one service. It restores the saved
// baseline when one exists. A corrupt baseline file is an error, so the
// process refuses to start instead of silently starting cold.
func newEngine(svc config.ServiceConfig, cfg *config.Config, store storage.BaselineStore) (*detector.Engine, error) {
	b := cfg.Detection.Baseline

	var prof *baseline.Profile
	st, ok, err := store.Load(svc.Name)
	if err != nil {
		return nil, err
	}
	if ok {
		prof, err = baseline.RestoreProfile(st)
	} else {
		prof, err = baseline.NewProfile(b.EWMAAlpha, b.MinSamplesForBaseline)
	}
	if err != nil {
		return nil, err
	}

	sigs, err := buildSignals(cfg.Detection.Signals)
	if err != nil {
		return nil, err
	}

	d := cfg.Detection.Detector
	m, err := detector.NewHysteresis(detector.Params{
		EnterRequired:   d.EnterSignalsRequired,
		ExitRequired:    d.ExitSignalsRequired,
		MinSuspicious:   d.MinDurSuspicious,
		MinAttackLikely: d.MinDurAttackLikely,
		RequireAll:      d.RequireAllEnabledSignalsPresent,
	})
	if err != nil {
		return nil, err
	}

	return detector.NewEngine(svc.Name, prof, sigs, m,
		cfg.Detection.Signals.EndpointSkew.TopK, time.Now().Add(b.Warmup))
}

// buildSignals creates the enabled signals. Signal instances keep hysteresis
// memory, so they are built fresh for each service.
func buildSignals(s config.SignalsConfig) ([]signals.Signal, error) {
	var out []signals.Signal
	if s.Rate.Enabled {
		out = append(out, &signals.Rate{
			MinVolumeFloor: s.Rate.MinVolumeFloor,
			ZEnter:         s.Rate.ZThresholdEnter,
			ZExit:          s.Rate.ZThresholdExit,
		})
	}
	if s.EndpointSkew.Enabled {
		out = append(out, &signals.EndpointSkew{
			TopK:           s.EndpointSkew.TopK,
			MinVolumeFloor: s.EndpointSkew.MinVolumeFloor,
			RatioEnter:     s.EndpointSkew.RatioThresholdEnter,
			RatioExit:      s.EndpointSkew.RatioThresholdExit,
		})
	}
	if s.SYNRatio.Enabled {
		out = append(out, &signals.SYNRatio{
			Source:         signals.NewProcTCPSource(),
			EnterRatio:     s.SYNRatio.EnterRatio,
			ExitRatio:      s.SYNRatio.ExitRatio,
			MinEstablished: s.SYNRatio.MinEstablished,
		})
	}
	if len(out) == 0 {
		return nil, errors.New("no signals enabled")
	}
	return out, nil
}

// parserFor returns the line parser for the service's log type.
func parserFor(svc config.ServiceConfig) (func(string, string) (ingest.Event, error), error) {
	switch svc.Type {
	case "nginx":
		return ingest.ParseNginxLine, nil
	case "haproxy":
		return ingest.ParseHaproxyLine, nil
	default:
		return nil, fmt.Errorf("unsupported log type %q", svc.Type)
	}
}