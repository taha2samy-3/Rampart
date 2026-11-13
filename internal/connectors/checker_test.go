package connectors_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"rampart/internal/connectors"
	"rampart/internal/domain"
)

func TestDefaultChecker_Slack(t *testing.T) {
	ctx := context.Background()

	// 1. Success case: auth.test returns ok: true
	srvSuccess := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer xoxb-valid-token" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_auth"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "user_id": "U12345"})
	}))
	defer srvSuccess.Close()

	allowlist := &domain.PlatformSSRFAllowlist{AllowLoopback: true}
	checker := connectors.NewDefaultChecker(nil, allowlist)
	checker.SetSlackAuthURL(srvSuccess.URL)

	conn := domain.Connector{
		Name: "slack-test",
		Type: domain.ConnectorTypeSlack,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeSlack,
			Slack: &domain.SlackConnectorConfig{
				TokenSecretRef: domain.SecretKeyRef{Name: "sec", Key: "token"},
				DefaultChannel: "#alerts",
			},
		},
	}

	// Empty token fails
	if err := checker.Check(ctx, conn, nil); err == nil {
		t.Fatalf("expected error for empty slack token")
	}

	// Invalid token fails auth.test
	if err := checker.Check(ctx, conn, []byte("xoxb-invalid")); err == nil {
		t.Fatalf("expected error for invalid slack token")
	}

	// Valid token succeeds
	if err := checker.Check(ctx, conn, []byte("xoxb-valid-token")); err != nil {
		t.Fatalf("expected success for valid slack token, got: %v", err)
	}

	// Test webhook check
	webhookConn := domain.Connector{
		Name: "webhook-test",
		Type: domain.ConnectorTypeWebhook,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeWebhook,
			Webhook: &domain.WebhookConnectorConfig{
				URL: "https://example.com/webhook",
			},
		},
	}
	if err := checker.Check(ctx, webhookConn, []byte("secret")); err != nil {
		t.Fatalf("unexpected webhook check error: %v", err)
	}

	// Webhook with loopback blocked under strict policy
	strictChecker := connectors.NewDefaultChecker(nil, nil)
	blockedWebhook := domain.Connector{
		Name: "webhook-blocked",
		Type: domain.ConnectorTypeWebhook,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeWebhook,
			Webhook: &domain.WebhookConnectorConfig{
				URL: "http://127.0.0.1:8080/hook",
			},
		},
	}
	if err := strictChecker.Check(ctx, blockedWebhook, []byte("sec")); err == nil {
		t.Fatalf("expected SSRF error for loopback webhook")
	}
}

func TestDefaultChecker_DependencyTrack(t *testing.T) {
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "valid-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/v1/team/self" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uuid": "team-1",
				"permissions": []map[string]string{
					{"name": "VIEW_PORTFOLIO"},
					{"name": "VIEW_VULNERABILITY"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	allowlist := &domain.PlatformSSRFAllowlist{AllowLoopback: true}
	checker := connectors.NewDefaultChecker(nil, allowlist)

	conn := domain.Connector{
		Name: "dt-test",
		Type: domain.ConnectorTypeDependencyTrack,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeDependencyTrack,
			DependencyTrack: &domain.DependencyTrackConnectorConfig{
				URL: srv.URL,
				CredentialsSecretRef: domain.SecretKeyRef{
					Name: "dt-sec",
					Key:  "apiKey",
				},
			},
		},
	}

	// Empty key fails
	if err := checker.Check(ctx, conn, nil); err == nil {
		t.Fatal("expected error for empty apiKey")
	}

	// Valid key succeeds
	if err := checker.Check(ctx, conn, []byte("valid-api-key")); err != nil {
		t.Fatalf("expected check to succeed, got: %v", err)
	}

	// Missing permissions
	srvMissing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"uuid": "team-1",
			"permissions": []map[string]string{
				{"name": "VIEW_PORTFOLIO"}, // Missing VIEW_VULNERABILITY
			},
		})
	}))
	defer srvMissing.Close()

	connMissing := conn
	connMissing.Spec.DependencyTrack = &domain.DependencyTrackConnectorConfig{
		URL: srvMissing.URL,
	}
	if err := checker.Check(ctx, connMissing, []byte("valid-api-key")); err == nil {
		t.Fatal("expected error for missing VIEW_VULNERABILITY")
	}
}
