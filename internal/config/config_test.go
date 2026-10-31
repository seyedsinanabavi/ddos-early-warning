package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes the three files into a temp dir and returns its path.
func writeConfig(t *testing.T, collector, detection, alerts string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"collector.yaml": collector,
		"detection.yaml": detection,
		"alerts.yaml":    alerts,
	}
	for name, content := range files {
		if content == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

const validCollector = `
version: 1
services:
  - name: web
    type: nginx
    log_paths: ["/var/log/nginx/access.log"]
    aggregate_interval: "10s"
    nginx_format: "combined"
storage:
  dir: "/var/lib/ddos-ew/store"
`

// validCollectorMulti has two services, for testing the syn_ratio rule.
const validCollectorMulti = `
version: 1
services:
  - name: web
    type: nginx
    log_paths: ["/var/log/nginx/access.log"]
    aggregate_interval: "10s"
    nginx_format: "combined"
  - name: api
    type: haproxy
    log_paths: ["/var/log/haproxy.log"]
    aggregate_interval: "10s"
storage:
  dir: "/var/lib/ddos-ew/store"
`

const validDetection = `
version: 1
baseline:
  ewma_alpha: 0.2
  seasonal_buckets: 168
  warmup_duration: "30m"
  min_samples_for_baseline: 30
signals:
  rate:
    enabled: true
    min_volume_floor: 5
    z_threshold_enter: 4.0
    z_threshold_exit: 2.5
  endpoint_skew:
    enabled: true
    top_k: 3
    ratio_threshold_enter: 0.35
    ratio_threshold_exit: 0.25
    min_volume_floor: 5
  syn_ratio:
    enabled: true
    enter_ratio: 0.30
    exit_ratio: 0.20
    min_established: 10
detector:
  enter_signals_required: 2
  exit_signals_required: 1
  min_duration_suspicious: "2m"
  min_duration_attack_likely: "1m"
`

const validAlerts = `
version: 1
severity:
  suspicious: "warning"
  attack_likely: "critical"
  unknown: "warning"
dedup:
  cooldown: "5m"
channels:
  - name: local-log
    type: file
    path: "/var/log/ddos-ew/alerts.log"
  - name: ops-webhook
    type: webhook
    url: "https://hooks.internal.example/ddos"
    timeout: "5s"
    max_retries: 3
    backoff_base: "1s"
    backoff_max: "30s"
`

func TestLoad_Valid(t *testing.T) {
	dir := writeConfig(t, validCollector, validDetection, validAlerts)
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Collector.Services[0].Interval.Seconds() != 10 {
		t.Fatalf("interval not parsed: %v", cfg.Collector.Services[0].Interval)
	}
	if cfg.Detection.Baseline.Warmup.Minutes() != 30 {
		t.Fatalf("warmup not parsed: %v", cfg.Detection.Baseline.Warmup)
	}
	if cfg.Alerts.Dedup.CooldownDur.Minutes() != 5 {
		t.Fatalf("cooldown not parsed: %v", cfg.Alerts.Dedup.CooldownDur)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	dir := t.TempDir() // no files
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for missing files")
	}
	if !strings.Contains(err.Error(), "collector.yaml") {
		t.Fatalf("error should name the missing file, got: %v", err)
	}
}

func TestLoad_UnknownKey(t *testing.T) {
	bad := validCollector + "\nbogus_key: true\n"
	dir := writeConfig(t, bad, validDetection, validAlerts)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("error should name the unknown key, got: %v", err)
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	dir := writeConfig(t, "version: [unterminated", validDetection, validAlerts)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for malformed yaml")
	}
	if !strings.Contains(err.Error(), "collector.yaml") {
		t.Fatalf("error should reference file, got: %v", err)
	}
}

func TestLoad_InvalidThreshold(t *testing.T) {
	// enter < exit is invalid for rate z-thresholds.
	bad := strings.Replace(validDetection,
		"z_threshold_enter: 4.0",
		"z_threshold_enter: 1.0", 1)
	dir := writeConfig(t, validCollector, bad, validAlerts)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for enter < exit threshold")
	}
	if !strings.Contains(err.Error(), "z_threshold_enter") {
		t.Fatalf("error should name the bad field, got: %v", err)
	}
}

// TestLoad_DurationParse mutates the file that actually contains the duration
// under test. The old version mutated validCollector for both cases, but the
// negative-duration case lives in detection.yaml, so it never took effect.
func TestLoad_DurationParse(t *testing.T) {
	cases := []struct {
		name    string
		file    string // "collector" or "detection"
		old     string
		new     string
		wantErr bool
	}{
		{"ok", "", "", "", false},
		{"bad duration", "collector", `"10s"`, `"ten seconds"`, true},
		{"negative duration", "detection", `"30m"`, `"-30m"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collector, detection := validCollector, validDetection
			switch tc.file {
			case "collector":
				collector = strings.Replace(collector, tc.old, tc.new, 1)
			case "detection":
				detection = strings.Replace(detection, tc.old, tc.new, 1)
			}
			dir := writeConfig(t, collector, detection, validAlerts)
			_, err := Load(dir)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got %v (err=%v)", tc.wantErr, err != nil, err)
			}
		})
	}
}

func TestLoad_DuplicateServiceName(t *testing.T) {
	dup := strings.Replace(validCollector,
		"  - name: web",
		"  - name: web\n    type: nginx\n    log_paths: [\"/tmp/a.log\"]\n    aggregate_interval: \"10s\"\n    nginx_format: \"combined\"\n  - name: web",
		1)
	dir := writeConfig(t, dup, validDetection, validAlerts)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for duplicate service name")
	}
}

func TestLoad_UnknownServiceType(t *testing.T) {
	bad := strings.Replace(validCollector, "type: nginx", "type: apache", 1)
	dir := writeConfig(t, bad, validDetection, validAlerts)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for unknown service type")
	}
	if !strings.Contains(err.Error(), "type") {
		t.Fatalf("error should mention type, got: %v", err)
	}
}

func TestLoad_AlphaOutOfRange(t *testing.T) {
	for _, alpha := range []string{"0", "1.5", "-0.1"} {
		bad := strings.Replace(validDetection, "ewma_alpha: 0.2", "ewma_alpha: "+alpha, 1)
		dir := writeConfig(t, validCollector, bad, validAlerts)
		if _, err := Load(dir); err == nil {
			t.Fatalf("expected error for ewma_alpha=%s", alpha)
		}
	}
}

func TestLoad_WebhookRequiresURL(t *testing.T) {
	bad := strings.Replace(validAlerts,
		`    url: "https://hooks.internal.example/ddos"`+"\n", "", 1)
	dir := writeConfig(t, validCollector, validDetection, bad)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error for webhook missing url")
	}
}

func TestLoad_FileChannelRequiresPath(t *testing.T) {
	bad := strings.Replace(validAlerts,
		`    path: "/var/log/ddos-ew/alerts.log"`+"\n", "", 1)
	dir := writeConfig(t, validCollector, validDetection, bad)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error for file channel missing path")
	}
}

func TestLoad_MissingBaseDir(t *testing.T) {
	dir := writeConfig(t, validCollector, validDetection, validAlerts)
	if err := os.Remove(filepath.Join(dir, "alerts.yaml")); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error when alerts.yaml missing")
	}
	if !strings.Contains(err.Error(), "alerts.yaml") {
		t.Fatalf("error should name alerts.yaml, got: %v", err)
	}
}

// TestLoad_SYNRatioRequiresSingleService verifies the cross-section rule:
// syn_ratio reads host-wide TCP state and cannot be attributed to one service
// when several are configured.
func TestLoad_SYNRatioRequiresSingleService(t *testing.T) {
	dir := writeConfig(t, validCollectorMulti, validDetection, validAlerts)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error: syn_ratio with multi-service")
	}
	if !strings.Contains(err.Error(), "syn_ratio") {
		t.Fatalf("error should mention syn_ratio, got: %v", err)
	}
}