# 🛡️ DDoS Early Warning

### Detect. Understand. Alert. Before It Becomes an Outage.

<p align="center">
  <strong>A lightweight, modular, and defensive DDoS early-warning system written in Go.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Linux-black?logo=linux" alt="Linux">
  <img src="https://img.shields.io/badge/Architecture-Modular-blue" alt="Modular Architecture">
  <img src="https://img.shields.io/badge/Focus-Defensive%20Security-green" alt="Defensive Security">
  <img src="https://img.shields.io/badge/Made%20in-Iran-red?logo=github" alt="Made in Iran">
</p>

<p align="center">
  <em>Built with engineering, security, and resilience in mind. Proudly made in Iran 🇮🇷</em>
</p>

---

## Overview

**DDoS Early Warning** is an open-source project designed to identify abnormal traffic behavior and provide early warnings of potential Distributed Denial of Service (DDoS) attacks.

Instead of relying exclusively on fixed traffic thresholds, the system combines statistical baselines, traffic-rate analysis, endpoint distribution, TCP-state signals, and multi-signal detection logic to identify suspicious patterns.

The goal is simple:

**Detect unusual traffic behavior early, give operators meaningful context, and help them respond before availability is seriously affected.**

The project is designed for Linux-based environments and aims to integrate with existing Nginx and HAProxy deployments without requiring an intrusive network architecture.

## Why This Project?

Traditional monitoring systems often rely on static thresholds:

- Requests per second exceed a predefined value.
- CPU usage becomes unusually high.
- Network traffic crosses a fixed bandwidth limit.

These approaches can be useful, but they may produce false positives when legitimate traffic changes throughout the day or when an attack develops gradually.

DDoS Early Warning takes a different approach:

- Learn normal traffic behavior over time.
- Analyze multiple independent traffic signals.
- Detect deviations from historical patterns.
- Use multi-signal confirmation instead of relying on a single metric.
- Apply hysteresis to reduce alert flapping.
- Provide actionable alerts and operator-oriented runbooks.

## Core Capabilities

The following capabilities are present in the current codebase or are under active development. Production readiness depends on completion and verification of the relevant tests and runtime integration.

### Traffic Ingestion

- Nginx access-log parsing.
- HAProxy log parsing.
- Log tailing with rotation awareness.
- Traffic aggregation into time windows.
- Structured traffic-event processing.

### Statistical Baselines

- Exponentially Weighted Moving Average (EWMA).
- Hour-of-week seasonal profiles.
- Historical traffic profiling.
- Baseline persistence.

### Detection Engine

- Multi-signal detection.
- N-of-M signal confirmation.
- Hysteresis-based state transitions.
- Suspicious and attack-likely classification.
- Detection state management.

### Traffic Signals

- Request-rate analysis.
- Endpoint distribution and skew.
- TCP SYN-related signal analysis.

### Alerting and Operations

- File-based alert delivery.
- HTTP webhook delivery.
- Alert deduplication.
- Retry and delivery-management logic.
- Audit-event recording.
- Operator runbook rules.

> Some operational components still require further testing and end-to-end integration before they can be considered production-ready.

## Architecture

The intended end-to-end architecture is:

```text
          Nginx / HAProxy Logs
                    |
                    v
          +-------------------+
          |  Traffic Ingestion |
          | Parser + Tailer    |
          +-------------------+
                    |
                    v
          +-------------------+
          | Traffic Aggregator |
          +-------------------+
                    |
                    v
          +-------------------+
          | Baseline Engine    |
          | EWMA + Seasonality |
          +-------------------+
                    |
                    v
          +-------------------+
          | Signals Engine     |
          | Rate / Skew / TCP  |
          +-------------------+
                    |
                    v
          +-------------------+
          | Detection Engine   |
          | N-of-M + Hysteresis|
          +-------------------+
                    |
                    v
          +-------------------+
          | Alert Management   |
          +-------------------+
                    |
           +--------+--------+
           |                 |
           v                 v
      File Alerts       HTTP Webhooks
           |
           v
      Audit & Runbooks
```

The planned deployment separates responsibilities into three independent applications:

| Component | Responsibility |
|---|---|
| Collector | Read, parse, and aggregate traffic logs |
| Detector | Analyze traffic and classify abnormal behavior |
| Notifier | Deliver alerts and manage notification workflows |

Durable inter-process communication and complete end-to-end integration are part of the development roadmap.

## Detection Philosophy

The detection engine is designed around multiple complementary signals rather than one isolated threshold.

### 1. Baseline Deviation

Traffic behavior is compared against learned historical patterns.

### 2. Request-Rate Analysis

Sudden or sustained increases in request volume are evaluated.

### 3. Endpoint Distribution

Unusual concentration of requests on particular endpoints can contribute to suspicious-traffic classification.

### 4. TCP-State Analysis

TCP-state information can provide additional context about connection behavior.

### 5. Multi-Signal Confirmation

The detector uses N-of-M logic to avoid making decisions based on a single noisy indicator.

### 6. Hysteresis

State transitions use separate entry and exit requirements to reduce unstable classifications and repeated alerting.

## Project Structure

```text
ddos-early-warning/
├── configs/
│   ├── alerts.yaml
│   ├── collector.yaml
│   ├── detection.yaml
│   └── geoip/
│
├── internal/
│   ├── alert/
│   ├── audit/
│   ├── baseline/
│   ├── config/
│   ├── detector/
│   ├── ingest/
│   ├── runbook/
│   ├── signals/
│   └── storage/
│
├── scripts/
├── Makefile
├── go.mod
├── go.sum
├── STATUS.md
└── README.md
```

The `internal` directory contains the core application packages. Executable entry points, deployment files, and additional operational components are part of the planned completion work.

## Configuration

The project uses YAML configuration files to separate operational settings.

| File | Purpose |
|---|---|
| `configs/collector.yaml` | Log sources and collection settings |
| `configs/detection.yaml` | Detection signals and thresholds |
| `configs/alerts.yaml` | Alert delivery configuration |

Review these files before running or deploying the application.

Do not enable experimental or unsupported signals in production configurations.

## Development

### Requirements

- Go (version compatible with `go.mod`)
- Linux recommended for deployment
- Nginx or HAProxy logs for ingestion testing

### Clone the repository

```bash
git clone https://github.com/seyedsinanabavi/ddos-early-warning.git

cd ddos-early-warning
```

### Prepare dependencies

```bash
go mod tidy
```

### Run tests

```bash
go test ./...
```

### Run race detection

```bash
go test -race ./...
```

### Static analysis

```bash
go vet ./...
```

### Build

```bash
go build ./...
```

These commands are development and verification commands. A complete production deployment workflow will be documented when the executable applications and installation process are finalized.

## Roadmap

DDoS Early Warning is actively evolving.

- [x] Core Go package structure
- [x] Nginx and HAProxy log parsers
- [x] Traffic aggregation
- [x] EWMA baseline implementation
- [x] Seasonal baseline profiles
- [x] Multi-signal detection foundations
- [x] Hysteresis-based detection logic
- [x] Initial alert management components
- [x] Initial audit components
- [x] Initial runbook components
- [ ] Complete alert-delivery reliability and testing
- [ ] Comprehensive audit and runbook tests
- [ ] Durable inter-process communication
- [ ] Collector executable
- [ ] Detector executable
- [ ] Notifier executable
- [ ] End-to-end integration tests
- [ ] Crash recovery and delivery guarantees
- [ ] Linux systemd service integration
- [ ] Automated installation script
- [ ] Offline deployment package
- [ ] Complete production deployment documentation

See [STATUS.md](STATUS.md) for the latest implementation status.

## Security & Privacy

Security and data integrity are important design principles.

The project is intended to operate as a defensive monitoring system.

Design principles:

- Passive traffic observation.
- No attack-traffic generation.
- No automatic firewall modification.
- No automatic IP blocking.
- Explicit error handling.
- Controlled access to log and state files.
- Avoid unnecessary collection of sensitive information.
- Reliable alert delivery and auditability.

Operators should review log access permissions, retention policies, webhook credentials, and deployment privileges before production use.

## Limitations

This project is under active development and should not yet be considered a fully validated production-grade DDoS mitigation platform.

In particular:

- It is an early-warning and monitoring system, not a traffic scrubbing service.
- It does not replace upstream DDoS protection.
- TCP-state signals may represent host-level rather than individual-service behavior.
- Some planned traffic signals are not implemented yet.
- Production deployment requires completed process integration, durable delivery, and operational testing.

Use it alongside established infrastructure monitoring and DDoS protection solutions.

## Contributing

Contributions, bug reports, feature suggestions, and security improvements are welcome.

Before submitting a pull request:

1. Open an issue describing the proposed change.
2. Keep changes focused and modular.
3. Add tests for new behavior.
4. Run `go test -race ./...`.
5. Run `go vet ./...`.
6. Document configuration changes.
7. Never claim unverified functionality.

Please avoid introducing breaking changes to existing detection logic without explaining their impact.

## Responsible Use

This project is intended exclusively for defensive monitoring, early warning, and authorized infrastructure observability.

Use it only on systems and networks you own or are explicitly authorized to monitor.

## Author & Origin

**Created and developed in Iran 🇮🇷**

Built with Go and open-source engineering principles.

**Made in Iran. Built for a more resilient internet.**

## License

See the [LICENSE](LICENSE) file for licensing terms.

---

<p align="center">
  <strong>Detect earlier. Respond smarter. Stay resilient.</strong>
  <br>
  <em>DDoS Early Warning — Made in Iran 🇮🇷</em>
</p>
