package signals

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Linux TCP state codes as they appear in the "st" column of /proc/net/tcp.
const (
	tcpStateEstablished = "01"
	tcpStateSynRecv     = "03"
)

// ProcTCPSource reads TCP states from /proc/net/tcp and /proc/net/tcp6.
//
// These files show sockets of the current network namespace only. Inside a
// container you see the container's sockets, not the host's.
type ProcTCPSource struct {
	Paths []string
}

// NewProcTCPSource returns a source for the default IPv4 and IPv6 tables.
func NewProcTCPSource() *ProcTCPSource {
	return &ProcTCPSource{Paths: []string{"/proc/net/tcp", "/proc/net/tcp6"}}
}

// Counts implements TCPSource.
func (p *ProcTCPSource) Counts() (TCPCounts, error) {
	var c TCPCounts
	if len(p.Paths) == 0 {
		return c, fmt.Errorf("no paths configured")
	}
	for _, path := range p.Paths {
		f, err := os.Open(path)
		if err != nil {
			return TCPCounts{}, err
		}
		err = countTCPStates(f, &c)
		_ = f.Close()
		if err != nil {
			return TCPCounts{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	return c, nil
}

// countTCPStates adds the SYN_RECV and ESTABLISHED rows of one /proc/net/tcp
// table to c. The first line is the header. Each other line must have the
// state in its fourth column.
func countTCPStates(r io.Reader, c *TCPCounts) error {
	sc := bufio.NewScanner(r)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			return fmt.Errorf("short row with %d fields", len(fields))
		}
		switch fields[3] {
		case tcpStateSynRecv:
			c.SynRecv++
		case tcpStateEstablished:
			c.Established++
		}
	}
	return sc.Err()
}
