package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/config"
)

// WebhookChannel POSTs the alert JSON to an HTTP endpoint.
type WebhookChannel struct {
	name    string
	url     string
	client  *http.Client
	auth    *webhookAuth
}

type webhookAuth struct {
	bearerToken string
	hmacSecret  []byte
	hmacHeader  string
}

// NewWebhookChannel builds a channel from config. Auth secrets are read from
// the environment at construction time; missing env vars are errors.
func NewWebhookChannel(c config.ChannelConfig) (*WebhookChannel, error) {
	if c.URL == "" {
		return nil, fmt.Errorf("webhook: empty url")
	}
	timeout := c.TimeoutDur
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
		ch := &WebhookChannel{
		name: c.Name,
		url:  c.URL,
		client: &http.Client{
			Timeout: timeout,
			// Never follow redirects: a redirect could send the alert, and any
			// bearer token, to a host the operator did not configure.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	if c.Auth != nil {
		switch c.Auth.Type {
		case "bearer":
			tok := os.Getenv(c.Auth.TokenEnv)
			if tok == "" {
				return nil, fmt.Errorf("webhook: env %q is empty", c.Auth.TokenEnv)
			}
			ch.auth = &webhookAuth{bearerToken: tok}
		case "hmac":
			sec := os.Getenv(c.Auth.SecretEnv)
			if sec == "" {
				return nil, fmt.Errorf("webhook: env %q is empty", c.Auth.SecretEnv)
			}
			header := c.Auth.Header
			if header == "" {
				header = "X-Signature"
			}
			ch.auth = &webhookAuth{hmacSecret: []byte(sec), hmacHeader: header}
		default:
			return nil, fmt.Errorf("webhook: unknown auth type %q", c.Auth.Type)
		}
	}
	return ch, nil
}

// Name returns the configured channel name.
func (c *WebhookChannel) Name() string { return c.name }

// Deliver POSTs a as JSON.
func (c *WebhookChannel) Deliver(ctx context.Context, a Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("webhook: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.auth != nil {
		if c.auth.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+c.auth.bearerToken)
		}
		if len(c.auth.hmacSecret) > 0 {
			mac := hmac.New(sha256.New, c.auth.hmacSecret)
			mac.Write(body)
			req.Header.Set(c.auth.hmacHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("webhook: http %d", resp.StatusCode)
}