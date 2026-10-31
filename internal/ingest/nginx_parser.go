package ingest

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// nginx combined format:
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
//
// $remote_user may contain a hyphen for anonymous; referer/UA may contain quotes escaped, which we ignore in MVP.
var nginxCombinedRe = regexp.MustCompile(
	`^(\S+) \S+ (?:\S+|-) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"`,
)

// ParseNginxLine parses one line in nginx "combined" format.
func ParseNginxLine(line, service string) (Event, error) {
	line = strings.TrimRight(line, "\r\n")
	m := nginxCombinedRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, ErrMalformed
	}
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return Event{}, ErrMalformed
	}
	status, err := strconv.Atoi(m[4])
	if err != nil || status < 100 || status > 599 {
		return Event{}, ErrMalformed
	}
	bytesN, _ := strconv.ParseInt(m[5], 10, 64)
	method, path := splitRequestLine(m[3])
	return Event{
		Time: ts, Service: service, Method: method, Path: path,
		Status: status, Bytes: bytesN, SourceIP: m[1],
	}, nil
}

// splitRequestLine returns (method, path) from `METHOD PATH PROTO` or (_, raw).
func splitRequestLine(req string) (method, path string) {
	parts := strings.Fields(req)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return "", parts[0]
	}
	return "", ""
}
