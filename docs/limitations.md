# Known limitations

This document lists what ddos-early-warning does not do, does not do well yet,
or has not been tested for. Read it before relying on any alert. Items marked
**design** are intentional; the others are gaps that may be fixed later.

Status: the pipeline has been tested with synthetic log lines and unit tests
only. It has not yet been run against production traffic, and no throughput
benchmark exists. Thresholds in the shipped configs are examples.

## What the tool can see

- **Only traffic that reaches the access logs.** A volumetric flood absorbed
  by a CDN, upstream firewall, or ISP is invisible here. Requests rejected by
  a rate limiter before nginx or haproxy logs them are also invisible.
  **Design.** This is an application-layer view.
- **No network-layer (L3/L4) volumetric detection.** Bandwidth saturation and
  packet floods do not appear in logs.
- **No source-distribution signals.** `src_entropy` and `asn_concentration`
  are reserved and not implemented. Config validation rejects enabling them.
  Attacks spread across many sources and networks are therefore not detected
  by distribution, only by rate and path concentration.

## Signals

- **`rate`** is a z-score against the seasonal baseline. The standard
  deviation is floored at `max(1, 10% of mean)`. Windows below
  `min_volume_floor` are `missing`, not normal.
- **`endpoint_skew`** uses the share of the top-K paths. Thresholds are
  absolute shares. A service whose normal traffic is already concentrated
  needs a tuned `ratio_threshold_enter`. Paths are used as logged, including
  query strings, with no normalization. High-cardinality query strings reduce
  the sensitivity of this signal.
- **`syn_ratio`** reads host-wide TCP state from `/proc/net/tcp`. It only works
  on Linux. It cannot be enabled with more than one service, because host-wide
  state cannot be attributed to one service. On other platforms it reports
  `missing`.

## Baseline and learning

- **Seasonal memory is short.** The EWMA weight `ewma_alpha` (0.2 in the
  example) gives a memory of roughly 1/alpha samples per hour-of-week bucket,
  not weeks. The baseline tracks recent behavior in each bucket, which is not
  the same as a long-term profile.
- **Cold buckets report `missing`.** Until a bucket has
  `min_samples_for_baseline` samples, the rate and skew signals report
  `missing`. With the default `require_all_enabled_signals_present: false`, a
  hot window still counts as hot, but windows without enough data become
  `unknown`.
- **Warmup learns from everything.** During `warmup_duration`, every window
  updates the baseline, including windows during an attack. An attack that
  starts during warmup becomes part of the baseline.
- **Warmup repeats on every start.** A restored baseline still gets a new
  `warmup_duration` after each restart. Detection is off during that time. The
  hysteresis level is not persisted, so the service starts at `normal`.
- **Slow ramps are absorbed.** The baseline learns only from quiet (cool)
  windows, but a ramp that stays below the enter thresholds is treated as
  quiet and becomes the new normal over time.

## Data gaps

- **Empty windows are never emitted.** A window with zero requests produces
  no aggregate. Zero traffic appears as a gap, not as a quiet window.
- **Low traffic is noisy.** Windows below the volume floor are `unknown`. For
  low-traffic services, most windows may be unknown.
- **Overflow drops windows silently.** `Aggregator.Flush` drops closed windows
  when the channel is full. Under heavy load, the detector sees gaps.
- **Malformed lines are skipped without a count.** Lines with escaped quotes
  inside the request or user-agent fields can fail to parse and are skipped.
- **Shutdown drops the open window.** Windows that have not closed when the
  process stops are lost. The baseline is saved on shutdown and every 5
  minutes, so up to 5 minutes of learning can be lost after a crash.
- **Log rotation depends on inode numbers.** On Windows, `inodeOf` returns 0,
  so rotation may not be detected there. The supported runtime is Linux.

## Log formats

- **nginx:** only the `combined` format. Any other `nginx_format` is rejected.
- **haproxy:** the `httplog` format.
- Other log formats are not supported.

## Alerts

- **Notification queue drops under load.** The notifier queue holds 64
  decisions. When it is full, `Submit` drops the decision and counts it. There
  is no metric or endpoint that exposes the count yet.
- **One retry policy for all channels.** The manager uses the largest
  `max_retries` and the first configured backoff for every channel. Per-channel
  retry settings in config are not applied independently.
- **Recovery does not alert.** A return to `normal` is logged as a state
  change, but no alert is sent. **Design.**
- **Dedup depends on the fired signal set.** The alert id excludes the window
  time, so repeats are suppressed within the cooldown. A change in which
  signals fired creates a new id and a new alert.
- **Delivery is best effort.** An alert counts as delivered when at least one
  channel accepts it. If every channel fails, the id is not marked, and the
  next window may send it again.

## Privacy

- **Client IPs are transient.** The parser reads the IP field only to build
  the event. Aggregates, baselines, alerts and the audit log do not contain
  client IPs. **Design.**
- **The source logs still contain IPs.** The operator controls retention and
  access for those logs. This tool does not change them.

## Operations and scope

- **No mitigation.** The tool never blocks, rate-limits or changes traffic.
  **Design.**
- **Single host.** There is no clustering, replication or failover.
  Baselines live on the local disk.
- **No metrics endpoint, dashboard or UI.** Operators read the JSON logs and
  the audit file.
- **Storage is unencrypted.** Baselines and the audit log are plain files.
- **Shipped config uses Linux paths.** On Windows, change the log and storage
  paths and disable `syn_ratio`.
- **Thresholds are examples.** Tune them on real traffic before relying on
  alerts. An alert from an untuned config says nothing about attack activity.

## What has not been tested

- Real production traffic, including bots, crawlers and legitimate spikes.
- Detection accuracy: no measured false-positive or false-negative rate.
- Throughput at high request rates.
- Log rotation on Linux under real rotation tools.
- Behavior across daylight-saving changes and long outages.
- Security review by an independent party.