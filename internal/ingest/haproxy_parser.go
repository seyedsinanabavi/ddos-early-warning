package ingest

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// haproxyHTTPRe matches HAProxy's default HTTP log format (option httplog):
//
//	<client>:<port> [<accept_date>] <frontend> <backend>/<server>
//	<Tq>/<Tw>/<Tc>/<Tr>/<Tt> <status> <bytes> <req_cookie> <res_cookie>
//	<termination> <counters> <queues> "<method> <path> <proto>"
//
// Timers are in milliseconds. Tt is the total time; -1 means unknown.
var haproxyHTTPRe = regexp.MustCompile(
	`^(\S+) \[([^\]]+)\] (\S+) (\S+) ([-+\d]+)/([-+\d]+)/([-+\d]+)/([-+\d]+)/([-+\d]+) (-?\d+) (\d+) \S+ \S+ \S+ \S+ \S+ "([^"]*)"`,
)

// ParseHaproxyLine parses one line in HAProxy httplog format.
//
// A status of -1 (client aborted before a response) is returned as 0 so the
// request is still counted. A negative Tt leaves Latency at zero.
func ParseHaproxyLine(line, service string) (Event, error) {
	line = strings.TrimRight(line, "\r\n")
	m := haproxyHTTPRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, ErrMalformed
	}

	ts, err := time.Parse("02/Jan/2006:15:04:05.000", m[2])
	if err != nil {
		ts, err = time.Parse("02/Jan/2006:15:04:05", m[2])
		if err != nil {
			return Event{}, ErrMalformed
		}
	}

	status, err := strconv.Atoi(m[10])
	if err != nil {
		return Event{}, ErrMalformed
	}
	switch {
	case status == -1:
		status = 0
	case status < 100 || status > 599:
		return Event{}, ErrMalformed
	}

	bytesN, err := strconv.ParseInt(m[11], 10, 64)
	if err != nil || bytesN < 0 {
		return Event{}, ErrMalformed
	}

	var latency time.Duration
	if tt, err := strconv.ParseInt(strings.TrimPrefix(m[9], "+"), 10, 64); err == nil && tt >= 0 {
		latency = time.Duration(tt) * time.Millisecond
	}

	client := m[1]
	if host, _, err := net.SplitHostPort(client); err == nil {
		client = host
	}

	method, path := splitRequestLine(m[12])
	return Event{
		Time:     ts,
		Service:  service,
		Method:   method,
		Path:     path,
		Status:   status,
		Latency:  latency,
		Bytes:    bytesN,
		SourceIP: client, // transient only; see package doc
	}, nil
}
