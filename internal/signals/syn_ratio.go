package signals

import (
	"context"
	"fmt"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
)

// TCPCounts is a snapshot of TCP socket states on the host.
type TCPCounts struct {
	SynRecv     int
	Established int
}

// TCPSource supplies TCP state snapshots. The Linux implementation reads
// /proc/net/tcp; tests use a fake.
type TCPSource interface {
	Counts() (TCPCounts, error)
}

// SYNRatio fires when half-open connections (SYN_RECV) are high relative to
// established connections, which is the usual footprint of a SYN flood.
//
// This signal is optional. If the source is missing or fails, the result is
// Missing, never normal.
type SYNRatio struct {
	Source                TCPSource
	EnterRatio, ExitRatio float64
	MinEstablished        int

	fired bool
}

// Name returns "syn_ratio".
func (s *SYNRatio) Name() string { return "syn_ratio" }

// Eval reads a TCP snapshot and compares SYN_RECV/ESTABLISHED with the
// hysteresis thresholds. The baseline argument is unused.
func (s *SYNRatio) Eval(ctx context.Context, _ ingest.Aggregate, _ Baseline) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if s.Source == nil {
		return missing("syn_ratio", "no tcp state source configured"), nil
	}
	c, err := s.Source.Counts()
	if err != nil {
		return missing("syn_ratio", "tcp state unavailable: "+err.Error()), nil
	}
	if c.Established == 0 || c.Established < s.MinEstablished {
		return missing("syn_ratio", fmt.Sprintf("too few established connections (%d)", c.Established)), nil
	}
	ratio := float64(c.SynRecv) / float64(c.Established)

	fired := ratio >= hysteresisThreshold(s.fired, s.EnterRatio, s.ExitRatio)
	s.fired = fired
	return Result{
		Name:   "syn_ratio",
		Value:  ratio,
		Fired:  fired,
		Reason: fmt.Sprintf("syn_recv=%d established=%d ratio=%.2f", c.SynRecv, c.Established, ratio),
	}, nil
}
