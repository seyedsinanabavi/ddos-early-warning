package signals

import (
	"context"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/ingest"
)

// SrcEntropy is a reserved extension point for source-IP entropy. It is not
// implemented in MVP. Config validation rejects enabling it.
type SrcEntropy struct{}

// Name returns "src_entropy".
func (SrcEntropy) Name() string { return "src_entropy" }

// Eval always returns ErrNotImplemented.
func (SrcEntropy) Eval(ctx context.Context, _ ingest.Aggregate, _ Baseline) (Result, error) {
	return missing("src_entropy", "not implemented in MVP"), ErrNotImplemented
}

// ASNConcentration is a reserved extension point for ASN/prefix concentration.
// It is not implemented in MVP. Config validation rejects enabling it.
type ASNConcentration struct{}

// Name returns "asn_concentration".
func (ASNConcentration) Name() string { return "asn_concentration" }

// Eval always returns ErrNotImplemented.
func (ASNConcentration) Eval(ctx context.Context, _ ingest.Aggregate, _ Baseline) (Result, error) {
	return missing("asn_concentration", "not implemented in MVP"), ErrNotImplemented
}
