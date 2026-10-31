// Package runbook produces operator-facing defensive guidance for detector
// states. It is pure logic: no I/O, no firewall actions, no blocking.
package runbook

import (
	"fmt"
	"strings"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/detector"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/signals"
)

// Options tune the generated text. Zero values are fine.
type Options struct {
	// DocsURL, if set, is appended to each guidance block.
	DocsURL string
	// Service is the service name, used in the text.
	Service string
}

// ForState returns a short, defensive guidance string for the given state and
// signal results. It never suggests automatic blocking. For states that need
// no operator action (normal, warming_up) it returns an empty string.
func ForState(state detector.State, results []signals.Result, opts Options) string {
	switch state {
	case detector.StateSuspicious:
		return suspicious(results, opts)
	case detector.StateAttackLikely:
		return attackLikely(results, opts)
	case detector.StateUnknown:
		return unknown(results, opts)
	default:
		return ""
	}
}

func suspicious(results []signals.Result, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Suspicious traffic on %q.\n", opts.Service)
	b.WriteString("Signals that fired: ")
	b.WriteString(listFired(results))
	b.WriteString(".\n")
	b.WriteString("Check the access log for the last few minutes and confirm whether the increase is expected.\n")
	b.WriteString("No automatic action has been taken.\n")
	appendDocs(&b, opts)
	return b.String()
}

func attackLikely(results []signals.Result, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Attack likely on %q.\n", opts.Service)
	b.WriteString("Signals that fired: ")
	b.WriteString(listFired(results))
	b.WriteString(".\n")
	b.WriteString("Notify the network team and follow your incident response plan.\n")
	b.WriteString("No automatic blocking has been applied. Review the runbook before acting.\n")
	appendDocs(&b, opts)
	return b.String()
}

func unknown(results []signals.Result, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Monitoring is in an unknown state for %q.\n", opts.Service)
	b.WriteString("Missing signals: ")
	b.WriteString(listMissing(results))
	b.WriteString(".\n")
	b.WriteString("Do NOT assume the service is normal. Check log collection and baseline state.\n")
	appendDocs(&b, opts)
	return b.String()
}

func listFired(results []signals.Result) string {
	var names []string
	for _, r := range results {
		if r.Fired && !r.Missing {
			names = append(names, r.Name)
		}
	}
	if len(names) == 0 {
		return "(none recorded)"
	}
	return strings.Join(names, ", ")
}

func listMissing(results []signals.Result) string {
	var names []string
	for _, r := range results {
		if r.Missing {
			names = append(names, r.Name)
		}
	}
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

func appendDocs(b *strings.Builder, opts Options) {
	if opts.DocsURL == "" {
		return
	}
	fmt.Fprintf(b, "Docs: %s\n", opts.DocsURL)
}