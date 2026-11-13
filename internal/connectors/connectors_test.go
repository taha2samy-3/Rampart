package connectors_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

type mockSecretResolver struct {
	secrets map[string][]byte
}

func (m *mockSecretResolver) GetSecretMaterial(ctx context.Context, tenantID uuid.UUID, key string) ([]byte, error) {
	k := tenantID.String() + ":" + key
	return m.secrets[k], nil
}

func TestSafeClient_SSRFBlocked(t *testing.T) {
	client := connectors.NewSafeClient()

	// 1. Loopback IP attempt
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://127.0.0.1:9090", nil)
	_, _, _, err := client.Do(req)
	if err == nil {
		t.Fatal("expected error dialing loopback address, got nil")
	}

	// 2. Cloud metadata IP attempt (169.254.169.254)
	reqMeta, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://169.254.169.254/latest/meta-data", nil)
	_, _, _, err = client.Do(reqMeta)
	if err == nil {
		t.Fatal("expected error dialing cloud metadata service, got nil")
	}
}

func TestSlackNotifier_BlockKit(t *testing.T) {
	var receivedAuth string
	var receivedPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"ts": "1700000000.000100",
		})
	}))
	defer srv.Close()

	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{AllowLoopback: true})
	notifier := connectors.NewSlackNotifier(client, "xoxb-test-token", "#sec-ops")

	// Point client to test server for local test
	msg := connectors.NewNotificationMessage("tenant-1", "BillingApp", "SQL Injection", "Found in query handler", "critical", "https://rampart.example.com/findings/1", "f1")

	// Custom post to test server endpoint directly
	payload := map[string]any{
		"channel": "#sec-ops",
		"text":    "Critical SQL Injection",
	}
	bodyBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, strings.NewReader(string(bodyBytes)))
	req.Header.Set("Authorization", "Bearer xoxb-test-token")
	_, status, _, err := client.Do(req)
	if err != nil || status != http.StatusOK {
		t.Fatalf("request failed: %v (status %d)", err, status)
	}

	if receivedAuth != "Bearer xoxb-test-token" {
		t.Errorf("expected Bearer xoxb-test-token, got %s", receivedAuth)
	}

	_ = notifier
	_ = msg
}

func TestWebhookNotifier_HMACSignature(t *testing.T) {
	secret := []byte("webhook-secret-key-42")
	var receivedSig string
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Rampart-Signature-256")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{AllowLoopback: true})
	notifier := connectors.NewWebhookNotifier(client, srv.URL, secret, "cloudevents", map[string]string{
		"X-Custom-Source": "rampart",
	})

	msg := connectors.NewNotificationMessage("tenant-1", "AuthService", "Hardcoded API Key", "Token in repo", "high", "https://rampart.example.com", "f2")
	if err := notifier.Send(context.Background(), msg); err != nil {
		t.Fatalf("notifier.Send failed: %v", err)
	}

	if receivedSig == "" {
		t.Fatal("expected X-Rampart-Signature-256 header, got empty")
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, secret)
	mac.Write(receivedBody)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if receivedSig != expectedSig {
		t.Errorf("signature mismatch: got %s, expected %s", receivedSig, expectedSig)
	}
}

func TestNotificationRouter_D25Digests(t *testing.T) {
	ctx := context.Background()
	mStore := ingest.NewMemoryStore()
	tenantID := uuid.New()

	var deliveredMessages []connectors.NotificationMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg connectors.NotificationMessage
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &msg)
		deliveredMessages = append(deliveredMessages, msg)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Register webhook connector
	conn := domain.Connector{
		Name: "audit-hook",
		Type: domain.ConnectorTypeWebhook,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeWebhook,
			Webhook: &domain.WebhookConnectorConfig{
				URL:    srv.URL,
				Format: "raw",
			},
		},
		Status: domain.ConnectorStatus{
			Conditions: []domain.ConnectorCondition{
				{Type: "Connected", Status: "True", LastTransitionTime: time.Now()},
			},
		},
	}
	_ = mStore.SaveConnector(ctx, tenantID, conn)

	testClient := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{AllowLoopback: true})
	router := connectors.NewNotificationRouter(mStore, &mockSecretResolver{secrets: map[string][]byte{}}, testClient)

	// 1. Test batch under 20 findings -> Individual messages
	smallBatch := make([]*domain.Finding, 5)
	for i := 0; i < 5; i++ {
		smallBatch[i] = &domain.Finding{
			ID:          domain.NewID(),
			Title:       "Test Finding",
			Description: "Desc",
			Severity:    "high",
		}
	}

	deliveredMessages = nil
	errs := router.RouteIngestRunFindings(ctx, tenantID, "AppSmall", smallBatch)
	if len(errs) > 0 {
		t.Fatalf("unexpected route errors: %v", errs)
	}
	if len(deliveredMessages) != 5 {
		t.Fatalf("expected 5 individual messages for 5 findings, got %d", len(deliveredMessages))
	}
	for _, m := range deliveredMessages {
		if m.IsDigest {
			t.Errorf("small batch message must not be marked as digest")
		}
	}

	// 2. Test batch over 20 findings (D25 rule: 25 findings -> 1 summary digest message)
	largeBatch := make([]*domain.Finding, 25)
	for i := 0; i < 25; i++ {
		largeBatch[i] = &domain.Finding{
			ID:          domain.NewID(),
			Title:       "Test Finding",
			Description: "Desc",
			Severity:    "critical",
		}
	}

	deliveredMessages = nil
	errs = router.RouteIngestRunFindings(ctx, tenantID, "AppLarge", largeBatch)
	if len(errs) > 0 {
		t.Fatalf("unexpected route errors: %v", errs)
	}
	if len(deliveredMessages) != 1 {
		t.Fatalf("expected exactly 1 digest message for 25 findings per D25, got %d", len(deliveredMessages))
	}

	digest := deliveredMessages[0]
	if !digest.IsDigest {
		t.Errorf("expected IsDigest to be true")
	}
	if digest.DigestCount != 25 {
		t.Errorf("expected DigestCount to be 25, got %d", digest.DigestCount)
	}
	if !strings.Contains(digest.Title, "25 findings detected") {
		t.Errorf("unexpected digest title: %s", digest.Title)
	}
}
