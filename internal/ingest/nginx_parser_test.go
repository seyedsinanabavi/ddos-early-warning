package ingest

import (
	"testing"
	"time"
)

func TestParseNginxLine_Valid(t *testing.T) {
	line := `1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] "GET /api/v1/users HTTP/1.1" 200 512 "-" "Mozilla/5.0"`
	ev, err := ParseNginxLine(line, "web")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ev.Service != "web" || ev.Method != "GET" || ev.Path != "/api/v1/users" || ev.Status != 200 || ev.Bytes != 512 {
		t.Fatalf("unexpected event: %+v", ev)
	}
	want := time.Date(2024, 10, 10, 13, 55, 36, 0, time.UTC)
	if !ev.Time.Equal(want) {
		t.Fatalf("time: got %v want %v", ev.Time, want)
	}
}

func TestParseNginxLine_Malformed(t *testing.T) {
	cases := []string{
		``,
		`garbage`,
		`1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 0 "-" "-"`,
		`1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] "GET / HTTP/1.1" 99 0 "-" "-"`,
	}
	for _, c := range cases {
		if _, err := ParseNginxLine(c, "web"); err == nil {
			t.Fatalf("want error for %q", c)
		}
	}
}
