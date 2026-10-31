# Project status

## Done and tested (go test -race passes)
- internal/baseline: EWMA with variance, seasonal hour-of-week buckets, Profile (rate, top-K share, 5xx share), state snapshot and restore with validation.
- internal/ingest: nginx and haproxy (httplog) parsers, rotation-aware tailer (inode check, drain before switch, truncation), aggregator.
- internal/signals: rate (z-score, std floor, hysteresis), endpoint_skew (top-K share, hysteresis), syn_ratio (optional, /proc/net/tcp source, degrades to missing), src_entropy and asn_concentration stubs.
- internal/detector: N-of-M classification, hysteresis state machine with timers, engine with warm-up, learning only from quiet windows, Decision output with transitions.
- internal/storage: atomic file-based baseline store with safe service names.
- Makefile: `make test` (vet + race tests).

## Not done (see the prompt for the next phase)
- internal/config: yaml.v3 dependency not yet pinned in go.mod/go.sum (run `go mod tidy`). Tests not yet run against the real yaml module. Validation of exit_signals_required must match detector rule (exit < enter).
- internal/alert, internal/runbook, internal/audit: empty.
- cmd/collector, cmd/detector, cmd/notifier: empty (no main packages yet).
- internal/alert/channels (file, webhook with retries), notifier service.
- test/fixtures and test/integration (replay pipeline, state sequence test).
- docs/: all eight files empty.
- deploy/systemd, scripts/install.sh, scripts/package-offline.sh: empty.
- README: add dependency justification.

## Known design gaps (decide before tuning)
- Seasonal buckets are updated once per window, so the EWMA memory is about 1/alpha windows (minutes), not weeks. Hour-of-week baselines need hourly aggregation or a different alpha; min_samples_for_baseline semantics depend on this.
- Below-volume-floor windows return Missing, so low-traffic hours report unknown. This is intentional under the spec but noisy.
- Windows with no requests are never emitted by the aggregator, so the detector sees a gap instead of zero. The collector must emit empty windows if zero traffic should count as quiet.
- Aggregator.Flush drops windows when the output channel is full. Backpressure policy is not decided.
