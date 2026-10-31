package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/seyedsinanabavi/ddos-early-warning/internal/config"
)

type received struct {
	header http.Header
	body   []byte
}

func recordingServer(t *testing.T, status int) (*httptest.Server, *[]received) {
	t.Helper()
	var got []received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, received{header: r.Header.Clone(), body: b})
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func chCfg(url string) config.ChannelConfig {
	return config.ChannelConfig{Name: "hook", Type: "webhook", URL: url, TimeoutDur: 2 * time.Second}
}

func TestWebhook_DeliversJSON(t *testing.T) {
	srv, got := recordingServer(t, http.StatusOK)
	ch, err := NewWebhookChannel(chCfg(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Deliver(context.Background(), testAlert("a1")); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("want 1 request, got %d", len(*got))
	}
	r := (*got)[0]
	if r.header.Get("Content-Type") != "application/json" {
		t.Fatalf("content type: %q", r.header.Get("Content-Type"))
	}
	var a Alert
	if err := json.Unmarshal(r.body, &a); err != nil || a.ID != "a1" {
		t.Fatalf("body: %v %+v", err, a)
	}
}

func TestWebhook_Non2xxIsError(t *testing.T) {
	srv, _ := recordingServer(t, http.StatusInternalServerError)
	ch, _ := NewWebhookChannel(chCfg(srv.URL))
	err := ch.Deliver(context.Background(), testAlert("a"))
	if err == nil || err.Error() != "webhook: http 500" {
		t.Fatalf("want http 500 error, got %v", err)
	}
}

func TestWebhook_BearerToken(t *testing.T) {
	t.Setenv("DDOS_TEST_TOKEN", "abc123")
	srv, got := recordingServer(t, http.StatusOK)
	c := chCfg(srv.URL)
	c.Auth = &config.WebhookAuthConfig{Type: "bearer", TokenEnv: "DDOS_TEST_TOKEN"}
	ch, err := NewWebhookChannel(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Deliver(context.Background(), testAlert("a")); err != nil {
		t.Fatal(err)
	}
	if h := (*got)[0].header.Get("Authorization"); h != "Bearer abc123" {
		t.Fatalf("authorization: %q", h)
	}
}

func TestWebhook_HMACSignature(t *testing.T) {
	t.Setenv("DDOS_TEST_SECRET", "s3cret")
	srv, got := recordingServer(t, http.StatusOK)
	c := chCfg(srv.URL)
	c.Auth = &config.WebhookAuthConfig{Type: "hmac", SecretEnv: "DDOS_TEST_SECRET", Header: "X-Sig"}
	ch, err := NewWebhookChannel(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Deliver(context.Background(), testAlert("a")); err != nil {
		t.Fatal(err)
	}
	r := (*got)[0]
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(r.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig := r.header.Get("X-Sig"); sig != want {
		t.Fatalf("signature: got %q want %q", sig, want)
	}
}

func TestWebhook_MissingSecretEnvFails(t *testing.T) {
	c := chCfg("http://127.0.0.1:1")
	c.Auth = &config.WebhookAuthConfig{Type: "bearer", TokenEnv: "DDOS_TEST_UNSET_VAR"}
	if _, err := NewWebhookChannel(c); err == nil {
		t.Fatal("empty env var must fail at construction")
	}
}

func TestWebhook_UnknownAuthTypeFails(t *testing.T) {
	c := chCfg("http://127.0.0.1:1")
	c.Auth = &config.WebhookAuthConfig{Type: "basic"}
	if _, err := NewWebhookChannel(c); err == nil {
		t.Fatal("unknown auth type must fail")
	}
}

func TestWebhook_EmptyURLFails(t *testing.T) {
	if _, err := NewWebhookChannel(config.ChannelConfig{Name: "x"}); err == nil {
		t.Fatal("empty url must fail")
	}
}

func TestWebhook_RedirectIsNotFollowed(t *testing.T) {
	target, targetGot := recordingServer(t, http.StatusOK)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	t.Setenv("DDOS_TEST_TOKEN2", "tok")
	c := chCfg(redirector.URL)
	c.Auth = &config.WebhookAuthConfig{Type: "bearer", TokenEnv: "DDOS_TEST_TOKEN2"}
	ch, _ := NewWebhookChannel(c)
	if err := ch.Deliver(context.Background(), testAlert("a")); err == nil {
		t.Fatal("a redirect must be reported as an error, not followed")
	}
	if len(*targetGot) != 0 {
		t.Fatal("the redirect target must not receive the alert or the token")
	}
}