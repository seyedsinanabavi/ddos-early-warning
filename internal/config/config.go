// Package config loads and validates the YAML configuration for all
// ddos-early-warning components. Validation is strict: unknown keys and
// invalid thresholds are rejected at startup with a clear error.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Supported file names inside the config directory.
const (
	fileCollector = "collector.yaml"
	fileDetection = "detection.yaml"
	fileAlerts    = "alerts.yaml"

	currentVersion = 1
)

// Config is the fully loaded and validated configuration.
type Config struct {
	Collector CollectorConfig `yaml:"-"`
	Detection DetectionConfig `yaml:"-"`
	Alerts    AlertsConfig    `yaml:"-"`
}

// CollectorConfig describes log sources and aggregate storage.
type CollectorConfig struct {
	Version  int             `yaml:"version"`
	Services []ServiceConfig `yaml:"services"`
	Storage  StorageConfig   `yaml:"storage"`
}

// ServiceConfig is a single logical service and its log sources.
type ServiceConfig struct {
	Name              string   `yaml:"name"`
	Type              string   `yaml:"type"` // nginx | haproxy
	LogPaths          []string `yaml:"log_paths"`
	AggregateInterval string   `yaml:"aggregate_interval"`
	NginxFormat       string   `yaml:"nginx_format"`

	Interval time.Duration `yaml:"-"`
}

// StorageConfig points at the embedded file-based store.
type StorageConfig struct {
	Dir string `yaml:"dir"`
}

// DetectionConfig holds baseline, signal, and detector parameters.
type DetectionConfig struct {
	Version  int            `yaml:"version"`
	Baseline BaselineConfig `yaml:"baseline"`
	Signals  SignalsConfig  `yaml:"signals"`
	Detector DetectorConfig `yaml:"detector"`
}

// BaselineConfig controls EWMA and seasonal profiles.
type BaselineConfig struct {
	EWMAAlpha             float64 `yaml:"ewma_alpha"`
	SeasonalBuckets       int     `yaml:"seasonal_buckets"`
	WarmupDuration        string  `yaml:"warmup_duration"`
	MinSamplesForBaseline int     `yaml:"min_samples_for_baseline"`

	Warmup time.Duration `yaml:"-"`
}

// SignalsConfig groups the per-signal configuration.
type SignalsConfig struct {
	Rate         RateSignalConfig         `yaml:"rate"`
	EndpointSkew EndpointSkewSignalConfig `yaml:"endpoint_skew"`
	SYNRatio     SYNRatioSignalConfig     `yaml:"syn_ratio"`
	SrcEntropy   StubSignalConfig         `yaml:"src_entropy"`
	ASNConcentr  StubSignalConfig         `yaml:"asn_concentration"`
}

// RateSignalConfig configures the request-rate signal.
type RateSignalConfig struct {
	Enabled         bool    `yaml:"enabled"`
	MinVolumeFloor  float64 `yaml:"min_volume_floor"`
	ZThresholdEnter float64 `yaml:"z_threshold_enter"`
	ZThresholdExit  float64 `yaml:"z_threshold_exit"`
}

// EndpointSkewSignalConfig configures the endpoint concentration signal.
type EndpointSkewSignalConfig struct {
	Enabled             bool    `yaml:"enabled"`
	TopK                int     `yaml:"top_k"`
	RatioThresholdEnter float64 `yaml:"ratio_threshold_enter"`
	RatioThresholdExit  float64 `yaml:"ratio_threshold_exit"`
	MinVolumeFloor      float64 `yaml:"min_volume_floor"`
}

// SYNRatioSignalConfig configures the SYN_RECV / established ratio signal.
type SYNRatioSignalConfig struct {
	Enabled        bool    `yaml:"enabled"`
	EnterRatio     float64 `yaml:"enter_ratio"`
	ExitRatio      float64 `yaml:"exit_ratio"`
	MinEstablished int     `yaml:"min_established"`
}

// StubSignalConfig is reserved for signals not implemented in MVP.
// It must remain disabled; enabling it is rejected at startup.
type StubSignalConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DetectorConfig controls the N-of-M rule and hysteresis.
type DetectorConfig struct {
	EnterSignalsRequired    int    `yaml:"enter_signals_required"`
	ExitSignalsRequired     int    `yaml:"exit_signals_required"`
	MinDurationSuspicious   string `yaml:"min_duration_suspicious"`
	MinDurationAttackLikely string `yaml:"min_duration_attack_likely"`
	// RequireAllEnabledSignalsPresent makes any missing signal mark the window
	// unknown, even when enough other signals fired.
	RequireAllEnabledSignalsPresent bool `yaml:"require_all_enabled_signals_present"`

	MinDurSuspicious   time.Duration `yaml:"-"`
	MinDurAttackLikely time.Duration `yaml:"-"`
}

// AlertsConfig controls severity mapping, dedup, and channels.
type AlertsConfig struct {
	Version  int             `yaml:"version"`
	Severity SeverityMap     `yaml:"severity"`
	Dedup    DedupConfig     `yaml:"dedup"`
	Channels []ChannelConfig `yaml:"channels"`
}

// SeverityMap maps detector states to severity labels.
type SeverityMap struct {
	Suspicious   string `yaml:"suspicious"`
	AttackLikely string `yaml:"attack_likely"`
	Unknown      string `yaml:"unknown"`
}

// DedupConfig controls alert cooldown.
type DedupConfig struct {
	Cooldown string `yaml:"cooldown"`

	CooldownDur time.Duration `yaml:"-"`
}

// ChannelConfig is a single alert delivery channel.
type ChannelConfig struct {
	Name        string             `yaml:"name"`
	Type        string             `yaml:"type"` // file | webhook
	Path        string             `yaml:"path,omitempty"`
	URL         string             `yaml:"url,omitempty"`
	Timeout     string             `yaml:"timeout,omitempty"`
	MaxRetries  int                `yaml:"max_retries,omitempty"`
	BackoffBase string             `yaml:"backoff_base,omitempty"`
	BackoffMax  string             `yaml:"backoff_max,omitempty"`
	Auth        *WebhookAuthConfig `yaml:"auth,omitempty"`

	TimeoutDur     time.Duration `yaml:"-"`
	BackoffBaseDur time.Duration `yaml:"-"`
	BackoffMaxDur  time.Duration `yaml:"-"`
}

// WebhookAuthConfig describes how to authenticate a webhook call. Secrets are
// always read from the environment; they never appear in YAML.
type WebhookAuthConfig struct {
	Type      string `yaml:"type"` // bearer | hmac
	TokenEnv  string `yaml:"token_env,omitempty"`
	SecretEnv string `yaml:"secret_env,omitempty"`
	Header    string `yaml:"header,omitempty"` // for hmac; default X-Signature
}

// Load reads and validates the three config files from dir.
func Load(dir string) (*Config, error) {
	if dir == "" {
		return nil, errors.New("config: dir is empty")
	}
	cfg := &Config{}
	if err := decodeFile(filepath.Join(dir, fileCollector), &cfg.Collector); err != nil {
		return nil, err
	}
	if err := decodeFile(filepath.Join(dir, fileDetection), &cfg.Detection); err != nil {
		return nil, err
	}
	if err := decodeFile(filepath.Join(dir, fileAlerts), &cfg.Alerts); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// decodeFile strictly decodes a single YAML file into out.
func decodeFile(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("config: %s is empty", path)
		}
		return fmt.Errorf("config: decode %s: %w", path, err)
	}
	return nil
}

// Validate checks all fields and populates parsed durations.
func (c *Config) Validate() error {
	var errs []error
	errs = append(errs, c.Collector.validate())
	errs = append(errs, c.Detection.validate())
	errs = append(errs, c.Alerts.validate())

	// Cross-section validation: syn_ratio reads host-wide TCP state and
	// cannot be attributed to one service when several are configured.
	if c.Detection.Signals.SYNRatio.Enabled && len(c.Collector.Services) > 1 {
		errs = append(errs, fmt.Errorf(
			"detection.signals.syn_ratio.enabled: cannot be enabled with %d services; "+
				"host-wide TCP state cannot be attributed to a single service (see docs/limitations.md)",
			len(c.Collector.Services)))
	}
	return errors.Join(errs...)
}

func (c *CollectorConfig) validate() error {
	var errs []error
	if c.Version != currentVersion {
		errs = append(errs, fmt.Errorf("collector.version: want %d got %d", currentVersion, c.Version))
	}
	if len(c.Services) == 0 {
		errs = append(errs, errors.New("collector.services: at least one service required"))
	}
	seen := map[string]bool{}
	for i := range c.Services {
		s := &c.Services[i]
		prefix := fmt.Sprintf("collector.services[%d]", i)
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("%s.name: empty", prefix))
		} else if seen[s.Name] {
			errs = append(errs, fmt.Errorf("%s.name: duplicate %q", prefix, s.Name))
		}
		seen[s.Name] = true
		switch s.Type {
		case "nginx", "haproxy":
		default:
			errs = append(errs, fmt.Errorf("%s.type: want nginx|haproxy got %q", prefix, s.Type))
		}
		if len(s.LogPaths) == 0 {
			errs = append(errs, fmt.Errorf("%s.log_paths: empty", prefix))
		}
		for j, p := range s.LogPaths {
			if !isAbsPath(p) {
				errs = append(errs, fmt.Errorf("%s.log_paths[%d]: must be absolute: %q", prefix, j, p))
			}
		}
		d, err := time.ParseDuration(s.AggregateInterval)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s.aggregate_interval: %w", prefix, err))
		} else if d != time.Second && d != 10*time.Second {
			errs = append(errs, fmt.Errorf("%s.aggregate_interval: want 1s or 10s got %s", prefix, d))
		} else {
			s.Interval = d
		}
		if s.Type == "nginx" {
			switch s.NginxFormat {
			case "", "combined":
			default:
				errs = append(errs, fmt.Errorf("%s.nginx_format: only 'combined' supported in MVP, got %q", prefix, s.NginxFormat))
			}
		}
	}
	if c.Storage.Dir == "" {
		errs = append(errs, errors.New("collector.storage.dir: empty"))
	} else if !isAbsPath(c.Storage.Dir) {
		errs = append(errs, fmt.Errorf("collector.storage.dir: must be absolute: %q", c.Storage.Dir))
	}
	return errors.Join(errs...)
}

func (c *DetectionConfig) validate() error {
	var errs []error
	if c.Version != currentVersion {
		errs = append(errs, fmt.Errorf("detection.version: want %d got %d", currentVersion, c.Version))
	}

	b := &c.Baseline
	if b.EWMAAlpha <= 0 || b.EWMAAlpha > 1 {
		errs = append(errs, fmt.Errorf("detection.baseline.ewma_alpha: must be in (0,1], got %v", b.EWMAAlpha))
	}
	if b.SeasonalBuckets != 168 {
		errs = append(errs, fmt.Errorf("detection.baseline.seasonal_buckets: MVP requires 168 (hour×weekday), got %d", b.SeasonalBuckets))
	}
	if d, err := time.ParseDuration(b.WarmupDuration); err != nil {
		errs = append(errs, fmt.Errorf("detection.baseline.warmup_duration: %w", err))
	} else if d <= 0 {
		errs = append(errs, fmt.Errorf("detection.baseline.warmup_duration: must be > 0, got %s", d))
	} else {
		b.Warmup = d
	}
	if b.MinSamplesForBaseline < 1 {
		errs = append(errs, fmt.Errorf("detection.baseline.min_samples_for_baseline: must be >= 1, got %d", b.MinSamplesForBaseline))
	}

	errs = append(errs, c.Signals.validate())
	errs = append(errs, c.Detector.validate(len(enabledSignals(&c.Signals))))
	return errors.Join(errs...)
}

func (s *SignalsConfig) validate() error {
	var errs []error
	r := &s.Rate
	if r.Enabled {
		if r.MinVolumeFloor < 0 {
			errs = append(errs, fmt.Errorf("detection.signals.rate.min_volume_floor: must be >= 0"))
		}
		if r.ZThresholdEnter <= r.ZThresholdExit {
			errs = append(errs, fmt.Errorf("detection.signals.rate: z_threshold_enter (%v) must be > z_threshold_exit (%v)", r.ZThresholdEnter, r.ZThresholdExit))
		}
		if r.ZThresholdExit < 0 {
			errs = append(errs, fmt.Errorf("detection.signals.rate.z_threshold_exit: must be >= 0"))
		}
	}
	k := &s.EndpointSkew
	if k.Enabled {
		if k.TopK < 1 {
			errs = append(errs, fmt.Errorf("detection.signals.endpoint_skew.top_k: must be >= 1"))
		}
		if k.RatioThresholdEnter <= k.RatioThresholdExit {
			errs = append(errs, fmt.Errorf("detection.signals.endpoint_skew: enter (%v) must be > exit (%v)", k.RatioThresholdEnter, k.RatioThresholdExit))
		}
		if k.RatioThresholdExit < 0 || k.RatioThresholdEnter > 1 {
			errs = append(errs, fmt.Errorf("detection.signals.endpoint_skew: thresholds must be within [0,1]"))
		}
		if k.MinVolumeFloor < 0 {
			errs = append(errs, fmt.Errorf("detection.signals.endpoint_skew.min_volume_floor: must be >= 0"))
		}
	}
	sr := &s.SYNRatio
	if sr.Enabled {
		if sr.EnterRatio <= sr.ExitRatio {
			errs = append(errs, fmt.Errorf("detection.signals.syn_ratio: enter (%v) must be > exit (%v)", sr.EnterRatio, sr.ExitRatio))
		}
		if sr.ExitRatio < 0 || sr.EnterRatio > 1 {
			errs = append(errs, fmt.Errorf("detection.signals.syn_ratio: ratios must be within [0,1]"))
		}
		if sr.MinEstablished < 0 {
			errs = append(errs, fmt.Errorf("detection.signals.syn_ratio.min_established: must be >= 0"))
		}
	}
	if s.SrcEntropy.Enabled {
		errs = append(errs, errors.New("detection.signals.src_entropy.enabled: not implemented in MVP; must be false/absent"))
	}
	if s.ASNConcentr.Enabled {
		errs = append(errs, errors.New("detection.signals.asn_concentration.enabled: not implemented in MVP; must be false/absent"))
	}
	return errors.Join(errs...)
}

func (d *DetectorConfig) validate(enabled int) error {
	var errs []error
	if enabled == 0 {
		errs = append(errs, errors.New("detection.detector: at least one signal must be enabled"))
		return errors.Join(errs...)
	}
	if d.EnterSignalsRequired < 1 || d.EnterSignalsRequired > enabled {
		errs = append(errs, fmt.Errorf("detection.detector.enter_signals_required: must be in [1,%d], got %d", enabled, d.EnterSignalsRequired))
	}
	if d.ExitSignalsRequired < 1 || d.ExitSignalsRequired > d.EnterSignalsRequired {
		errs = append(errs, fmt.Errorf("detection.detector.exit_signals_required: must be in [1,%d], got %d", d.EnterSignalsRequired, d.ExitSignalsRequired))
	}
	if dur, err := time.ParseDuration(d.MinDurationSuspicious); err != nil {
		errs = append(errs, fmt.Errorf("detection.detector.min_duration_suspicious: %w", err))
	} else if dur < 0 {
		errs = append(errs, fmt.Errorf("detection.detector.min_duration_suspicious: must be >= 0"))
	} else {
		d.MinDurSuspicious = dur
	}
	if dur, err := time.ParseDuration(d.MinDurationAttackLikely); err != nil {
		errs = append(errs, fmt.Errorf("detection.detector.min_duration_attack_likely: %w", err))
	} else if dur < 0 {
		errs = append(errs, fmt.Errorf("detection.detector.min_duration_attack_likely: must be >= 0"))
	} else {
		d.MinDurAttackLikely = dur
	}
	return errors.Join(errs...)
}

func (a *AlertsConfig) validate() error {
	var errs []error
	if a.Version != currentVersion {
		errs = append(errs, fmt.Errorf("alerts.version: want %d got %d", currentVersion, a.Version))
	}
	validSev := func(s string) bool { return s == "warning" || s == "critical" }
	if !validSev(a.Severity.Suspicious) {
		errs = append(errs, fmt.Errorf("alerts.severity.suspicious: want warning|critical got %q", a.Severity.Suspicious))
	}
	if !validSev(a.Severity.AttackLikely) {
		errs = append(errs, fmt.Errorf("alerts.severity.attack_likely: want warning|critical got %q", a.Severity.AttackLikely))
	}
	if !validSev(a.Severity.Unknown) {
		errs = append(errs, fmt.Errorf("alerts.severity.unknown: want warning|critical got %q", a.Severity.Unknown))
	}
	if d, err := time.ParseDuration(a.Dedup.Cooldown); err != nil {
		errs = append(errs, fmt.Errorf("alerts.dedup.cooldown: %w", err))
	} else if d < 0 {
		errs = append(errs, fmt.Errorf("alerts.dedup.cooldown: must be >= 0"))
	} else {
		a.Dedup.CooldownDur = d
	}
	if len(a.Channels) == 0 {
		errs = append(errs, errors.New("alerts.channels: at least one channel required"))
	}
	names := map[string]bool{}
	for i := range a.Channels {
		ch := &a.Channels[i]
		prefix := fmt.Sprintf("alerts.channels[%d]", i)
		if ch.Name == "" {
			errs = append(errs, fmt.Errorf("%s.name: empty", prefix))
		} else if names[ch.Name] {
			errs = append(errs, fmt.Errorf("%s.name: duplicate %q", prefix, ch.Name))
		}
		names[ch.Name] = true
		switch ch.Type {
		case "file":
			if ch.Path == "" {
				errs = append(errs, fmt.Errorf("%s.path: required for file channel", prefix))
			} else if !isAbsPath(ch.Path) {
				errs = append(errs, fmt.Errorf("%s.path: must be absolute: %q", prefix, ch.Path))
			}
		case "webhook":
			if ch.URL == "" {
				errs = append(errs, fmt.Errorf("%s.url: required for webhook channel", prefix))
			}
			if ch.Timeout != "" {
				if d, err := time.ParseDuration(ch.Timeout); err != nil {
					errs = append(errs, fmt.Errorf("%s.timeout: %w", prefix, err))
				} else if d <= 0 {
					errs = append(errs, fmt.Errorf("%s.timeout: must be > 0", prefix))
				} else {
					ch.TimeoutDur = d
				}
			}
			if ch.MaxRetries < 0 {
				errs = append(errs, fmt.Errorf("%s.max_retries: must be >= 0", prefix))
			}
			if ch.BackoffBase != "" {
				if d, err := time.ParseDuration(ch.BackoffBase); err != nil {
					errs = append(errs, fmt.Errorf("%s.backoff_base: %w", prefix, err))
				} else if d <= 0 {
					errs = append(errs, fmt.Errorf("%s.backoff_base: must be > 0", prefix))
				} else {
					ch.BackoffBaseDur = d
				}
			}
			if ch.BackoffMax != "" {
				if d, err := time.ParseDuration(ch.BackoffMax); err != nil {
					errs = append(errs, fmt.Errorf("%s.backoff_max: %w", prefix, err))
				} else if d <= 0 {
					errs = append(errs, fmt.Errorf("%s.backoff_max: must be > 0", prefix))
				} else {
					ch.BackoffMaxDur = d
				}
			}
			if ch.Auth != nil {
				switch ch.Auth.Type {
				case "bearer":
					if ch.Auth.TokenEnv == "" {
						errs = append(errs, fmt.Errorf("%s.auth.token_env: required for bearer auth", prefix))
					}
				case "hmac":
					if ch.Auth.SecretEnv == "" {
						errs = append(errs, fmt.Errorf("%s.auth.secret_env: required for hmac auth", prefix))
					}
					if ch.Auth.Header == "" {
						ch.Auth.Header = "X-Signature"
					}
				default:
					errs = append(errs, fmt.Errorf("%s.auth.type: want bearer|hmac got %q", prefix, ch.Auth.Type))
				}
			}
		default:
			errs = append(errs, fmt.Errorf("%s.type: want file|webhook got %q", prefix, ch.Type))
		}
	}
	return errors.Join(errs...)
}

// enabledSignals returns the names of enabled MVP signals.
func enabledSignals(s *SignalsConfig) []string {
	var out []string
	if s.Rate.Enabled {
		out = append(out, "rate")
	}
	if s.EndpointSkew.Enabled {
		out = append(out, "endpoint_skew")
	}
	if s.SYNRatio.Enabled {
		out = append(out, "syn_ratio")
	}
	return out
}

// isAbsPath reports whether p is absolute on any supported platform.
//
// filepath.IsAbs returns false on Windows for POSIX paths such as
// "/var/log/nginx/access.log", which are valid on the Linux deployment
// target. Accepting them keeps the same config working in dev (Windows) and
// in production (Linux).
func isAbsPath(p string) bool {
	if p == "" {
		return false
	}
	if filepath.IsAbs(p) {
		return true
	}
	return strings.HasPrefix(p, "/")
}
