# ddos-early-warning

A **defensive**, self-hosted, offline-capable DDoS *early-warning* system.
It helps an organization's own technical team notice that an attack is
*forming* on **their own** infrastructure and get alerted with enough
context to act.

> This tool does **not** generate traffic, flood, probe, or attack anything.
> It only reads the operator's own access logs and local TCP state, computes
> aggregate signals, and emits alerts. See `docs/privacy.md` and
> `docs/limitations.md`.

## Scope (MVP)

- Tail nginx / haproxy access logs (rotation-aware).
- Per-service EWMA + seasonal (hour-of-day × weekday) baselines for request
  rate and error rate, persisted across restarts.
- Three signals: `rate`, `endpoint_skew`, `syn_ratio` (optional).
  `src_entropy` and `asn_concentration` are stubs (extension points only).
- Detector with N-of-M combination + hysteresis (enter/exit thresholds +
  minimum duration). States: `normal`, `warming_up`, `suspicious`,
  `attack_likely`, `unknown`. Missing data never silently becomes `normal`.
- Alerts to a local file and an operator-supplied webhook, with dedup
  cooldown, retries with backoff, and per-alert runbook text.
- Strict YAML config validation at startup.
- Audit log of config loads, state transitions, and alert dispatches.

## Non-goals (MVP)

ASN/prefix analysis, PDF reports, web UI, multi-node clustering, ML models,
auth UI. Clean extension points are left for ASN/prefix analysis.

## Build

```sh
make build          # produces bin/{collector,detector,notifier}
make test           # go test -race ./...
make package        # offline bundle with checksums (see scripts/)