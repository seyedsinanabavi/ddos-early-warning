package ingest

import (
	"testing"
	"time"
)

const haproxyValid = `10.0.0.1:51234 [31/Oct/2026:12:00:00.123] fe be/app1 0/0/1/2/3 200 512 - - ---- 1/1/0/1/0 0/0 "GET /api/items?id=7 HTTP/1.1"`

func TestParseHaproxyLine_Valid(t *testing.T) {
	ev, err := ParseHaproxyLine(haproxyValid, "hap")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ev.Method != "GET" || ev.Path != "/api/items?id=7" || ev.Status != 200 || ev.Bytes != 512 {
		t.Fatalf("unexpected: %+v", ev)
	}
	if ev.SourceIP != "10.0.0.1" {
		t.Fatalf("source: %q", ev.SourceIP)
	}
	if ev.Latency != 3*time.Millisecond {
		t.Fatalf("latency want 3ms got %v", ev.Latency)
	}
	if ev.Service != "hap" {
		t.Fatalf("service: %q", ev.Service)
	}
}

func TestParseHaproxyLine_IPv6AndPlusTimer(t *testing.T) {
	line := `[2001:db8::1]:4444 [31/Oct/2026:12:00:00] fe be/app1 +5/0/1/2/+9 404 88 - - ---- 1/1/0/1/0 0/0 "POST /x HTTP/1.1"`
	ev, err := ParseHaproxyLine(line, "hap")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ev.SourceIP != "2001:db8::1" {
		t.Fatalf("ipv6 source: %q", ev.SourceIP)
	}
	if ev.Latency != 9*time.Millisecond || ev.Status != 404 {
		t.Fatalf("unexpected: %+v", ev)
	}
}

func TestParseHaproxyLine_AbortedRequest(t *testing.T) {
	line := `10.0.0.2:1 [31/Oct/2026:12:00:00.000] fe be/app1 -1/-1/-1/-1/0 -1 0 - - CR-- 1/1/0/0/0 0/0 "GET / HTTP/1.1"`
	ev, err := ParseHaproxyLine(line, "hap")
	if err != nil {
		t.Fatalf("aborted request must parse: %v", err)
	}
	if ev.Status != 0 || ev.Latency != 0 {
		t.Fatalf("aborted: status=%d latency=%v", ev.Status, ev.Latency)
	}
}

func TestParseHaproxyLine_Malformed(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"garbage":        "not a log line at all",
		"missing quote":  `10.0.0.1:1 [31/Oct/2026:12:00:00.000] fe be/app 0/0/1/2/3 200 512 - - ---- 1/1/0/1/0 0/0 GET /x`,
		"bad date":       `10.0.0.1:1 [not-a-date] fe be/app 0/0/1/2/3 200 512 - - ---- 1/1/0/1/0 0/0 "GET / HTTP/1.1"`,
		"status 999":     `10.0.0.1:1 [31/Oct/2026:12:00:00.000] fe be/app 0/0/1/2/3 999 512 - - ---- 1/1/0/1/0 0/0 "GET / HTTP/1.1"`,
		"truncated line": `10.0.0.1:1 [31/Oct/2026:12:00:00.000] fe be/app 0/0/1/2/3 200`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHaproxyLine(line, "hap"); err == nil {
				t.Fatalf("expected malformed error for %q", line)
			}
		})
	}
}
