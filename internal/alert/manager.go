package alert

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/audit"
	"github.com/seyedsinanabavi/ddos-early-warning/internal/config"
)

// Channel is one delivery destination.
type Channel interface {
	Name() string
	Deliver(ctx context.Context, a Alert) error
}

// Manager fans out alerts to channels, applying dedup and retry.
type Manager struct {
	Dedup    *Dedup
	Channels []Channel
	// Retries is the number of extra attempts per channel after the first.
	Retries int
	// Backoff is the delay before the first retry. It doubles per attempt.
	Backoff time.Duration
	// BackoffMax caps the doubling. Zero means no cap.
	BackoffMax time.Duration
	Audit      *audit.Logger
	// Now is the injected clock. time.Now (in UTC) is used when nil.
	Now func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now == nil {
		return time.Now().UTC()
	}
	return m.Now().UTC()
}

// Dispatch delivers a to every channel.
//
// An alert whose id was delivered within the dedup cooldown is skipped and
// audited. The id is marked as delivered only when at least one channel
// accepts it, so an alert that every channel rejected is retried on the next
// window instead of being suppressed.
//
// Dispatch returns an error only when no channel is configured or every
// channel fails. Partial failures are recorded in the audit log.
func (m *Manager) Dispatch(ctx context.Context, a Alert) error {
	if len(m.Channels) == 0 {
		return errors.New("alert: no channels configured")
	}
	now := m.now()

	if m.Dedup != nil {
		if seen, prev := m.Dedup.Seen(a.ID, now); seen {
			m.Audit.Log(audit.Event{
				Type:    audit.EventAlertDeduplicated,
				Service: a.Service,
				Fields:  map[string]string{"alert_id": a.ID, "previous": prev.Format(time.RFC3339)},
			})
			return nil
		}
	}

	var failures int
	for _, ch := range m.Channels {
		if err := m.deliverWithRetry(ctx, ch, a); err != nil {
			failures++
			m.Audit.AlertFailed(a.Service, a.ID, ch.Name(), err.Error())
			continue
		}
		m.Audit.AlertDelivered(a.Service, a.ID, ch.Name())
	}
	if failures == len(m.Channels) {
		return fmt.Errorf("alert: all %d channels failed for %s", failures, a.ID)
	}
	if m.Dedup != nil {
		m.Dedup.Mark(a.ID, now)
	}
	return nil
}

func (m *Manager) deliverWithRetry(ctx context.Context, ch Channel, a Alert) error {
	attempts := m.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	backoff := m.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		err := ch.Deliver(ctx, a)
		if err == nil {
			return nil
		}
		lastErr = err
		if i == attempts-1 {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
		if m.BackoffMax > 0 && backoff > m.BackoffMax {
			backoff = m.BackoffMax
		}
	}
	return lastErr
}

// ChannelsFromConfig builds channels from validated config. Missing env vars
// are reported as errors so startup fails loudly.
func ChannelsFromConfig(cfgs []config.ChannelConfig) ([]Channel, error) {
	var out []Channel
	for _, c := range cfgs {
		switch c.Type {
		case "file":
			ch, err := NewFileChannel(c.Name, c.Path)
			if err != nil {
				return nil, fmt.Errorf("alert: channel %q: %w", c.Name, err)
			}
			out = append(out, ch)
		case "webhook":
			ch, err := NewWebhookChannel(c)
			if err != nil {
				return nil, fmt.Errorf("alert: channel %q: %w", c.Name, err)
			}
			out = append(out, ch)
		default:
			return nil, fmt.Errorf("alert: unknown channel type %q", c.Type)
		}
	}
	return out, nil
}