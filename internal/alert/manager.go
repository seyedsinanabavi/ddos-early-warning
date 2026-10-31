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
	Retries  int
	Backoff  time.Duration
	Audit    *audit.Logger
}

// Dispatch delivers a to every channel. Delivery failures are recorded in the
// audit log and never silently dropped. Dispatch returns an error only if all
// channels fail; partial failure is reported via the audit log.
func (m *Manager) Dispatch(ctx context.Context, a Alert) error {
	if m.Dedup != nil {
		if ok, prev := m.Dedup.Allow(a.ID, time.Now()); !ok {
			if m.Audit != nil {
				m.Audit.Log(audit.Event{
					Type:    "alert.deduplicated",
					Service: a.Service,
					Fields:  map[string]string{"alert_id": a.ID, "previous": prev.Format(time.RFC3339)},
				})
			}
			return nil
		}
	}
	if len(m.Channels) == 0 {
		return errors.New("alert: no channels configured")
	}

	var failures int
	for _, ch := range m.Channels {
		if err := m.deliverWithRetry(ctx, ch, a); err != nil {
			failures++
			if m.Audit != nil {
				m.Audit.AlertFailed(a.Service, a.ID, ch.Name(), err.Error())
			}
			continue
		}
		if m.Audit != nil {
			m.Audit.AlertDelivered(a.Service, a.ID, ch.Name())
		}
	}
	if failures == len(m.Channels) {
		return fmt.Errorf("alert: all %d channels failed for %s", failures, a.ID)
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
		if err := ch.Deliver(ctx, a); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
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