package connectors_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/workflow"
)

type mockWorkflowService struct {
	requests []domain.RiskAcceptanceRequest
}

func (m *mockWorkflowService) Request(_ context.Context, _ uuid.UUID, _ string, req domain.RiskAcceptanceRequest) (*workflow.Outcome, error) {
	m.requests = append(m.requests, req)
	return &workflow.Outcome{
		Acceptance: &domain.RiskAcceptance{
			ID:     uuid.New(),
			Status: domain.AcceptancePending,
		},
		Applied: 0,
	}, nil
}

func signPayloadSHA256(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestInboundWebhook_JiraSigned_CreatesApprovalRequest(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	connectorName := "jira-inbound"
	secretKey := "apiToken"
	webhookSecret := []byte("jira-webhook-secret-12345")

	mStore := ingest.NewMemoryStore()
	jiraConn := domain.Connector{
		Name:     connectorName,
		TenantID: tenantID,
		Type:     domain.ConnectorTypeJira,
		Spec: domain.ConnectorSpec{
			Type:      domain.ConnectorTypeJira,
			Direction: domain.DirectionBidirectional,
			Jira: &domain.JiraConnectorConfig{
				URL:                  "https://acme.atlassian.net",
				CredentialsSecretRef: domain.SecretKeyRef{Name: "sec", Key: secretKey},
			},
		},
	}
	condTrue := domain.ConnectorCondition{Type: "Ready", Status: "True"}
	jiraConn.Status.Conditions = []domain.ConnectorCondition{condTrue}
	_ = mStore.SaveConnector(context.Background(), tenantID, jiraConn)

	secResolver := &mockSecretResolver{
		secrets: map[string][]byte{
			tenantID.String() + ":connector:" + connectorName + ":" + secretKey: webhookSecret,
		},
	}

	wf := &mockWorkflowService{}
	handler := connectors.NewInboundWebhookHandler(mStore, wf, secResolver)

	payload := map[string]any{
		"webhookEvent": "jira:issue_updated",
		"issue": map[string]any{
			"id":  "1001",
			"key": "SEC-77",
			"fields": map[string]any{
				"labels": []string{"security", "rampart-finding-" + findingID.String()},
				"resolution": map[string]string{
					"name": "Won't Do",
				},
				"status": map[string]string{
					"name": "Closed",
				},
			},
		},
		"user": map[string]string{
			"displayName": "Security Lead Bob",
			"accountId":   "acc-123",
		},
	}

	bodyBytes, _ := json.Marshal(payload)
	signature := signPayloadSHA256(webhookSecret, bodyBytes)

	// 1. Success case: valid signature and Won't Do resolution submits workflow request (D27)
	reqURL := fmt.Sprintf("/api/v1/t/%s/connectors/%s/webhook", tenantID, connectorName)
	req := httptest.NewRequest(http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	req.Header.Set("X-Hub-Signature", "sha256="+signature)
	req.Header.Set("X-Atlassian-Webhook-Identifier", "deliv-101")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	if len(wf.requests) != 1 {
		t.Fatalf("expected 1 risk acceptance request created, got %d", len(wf.requests))
	}
	if len(wf.requests[0].FindingIDs) != 1 || wf.requests[0].FindingIDs[0] != findingID {
		t.Fatalf("expected findingID %s in request, got %+v", findingID, wf.requests[0].FindingIDs)
	}

	// 2. Duplicate delivery deduplicated
	wDup := httptest.NewRecorder()
	reqDup := httptest.NewRequest(http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	reqDup.Header.Set("X-Hub-Signature", "sha256="+signature)
	reqDup.Header.Set("X-Atlassian-Webhook-Identifier", "deliv-101")
	handler.ServeHTTP(wDup, reqDup)
	if wDup.Code != http.StatusOK || !bytes.Contains(wDup.Body.Bytes(), []byte("duplicate_delivery")) {
		t.Errorf("expected duplicate delivery to be skipped, got %d: %s", wDup.Code, wDup.Body.String())
	}
}

func TestInboundWebhook_InvalidSignature_Rejected(t *testing.T) {
	tenantID := uuid.New()
	connectorName := "gh-hook"
	webhookSecret := []byte("secret")

	mStore := ingest.NewMemoryStore()
	ghConn := domain.Connector{
		Name:     connectorName,
		TenantID: tenantID,
		Type:     domain.ConnectorTypeGitHub,
		Spec: domain.ConnectorSpec{
			Type:      domain.ConnectorTypeGitHub,
			Direction: domain.DirectionInbound,
			GitHub: &domain.GitHubConnectorConfig{
				Owner:                "acme",
				Repo:                 "repo",
				CredentialsSecretRef: domain.SecretKeyRef{Name: "sec", Key: "token"},
			},
		},
	}
	_ = mStore.SaveConnector(context.Background(), tenantID, ghConn)

	secResolver := &mockSecretResolver{
		secrets: map[string][]byte{
			tenantID.String() + ":connector:" + connectorName + ":token": webhookSecret,
		},
	}

	wf := &mockWorkflowService{}
	handler := connectors.NewInboundWebhookHandler(mStore, wf, secResolver)

	reqURL := fmt.Sprintf("/api/v1/t/%s/connectors/%s/webhook", tenantID, connectorName)
	req := httptest.NewRequest(http.MethodPost, reqURL, strings.NewReader(`{}`))
	req.Header.Set("X-Hub-Signature-256", "sha256=invalid-signature")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for bad signature, got %d", w.Code)
	}
}

func TestInboundWebhook_GitHubNotPlanned_CreatesApprovalRequest(t *testing.T) {
	tenantID := uuid.New()
	findingID := uuid.New()
	connectorName := "gh-inbound"
	webhookSecret := []byte("gh-secret-456")

	mStore := ingest.NewMemoryStore()
	ghConn := domain.Connector{
		Name:     connectorName,
		TenantID: tenantID,
		Type:     domain.ConnectorTypeGitHub,
		Spec: domain.ConnectorSpec{
			Type:      domain.ConnectorTypeGitHub,
			Direction: domain.DirectionBidirectional,
			GitHub: &domain.GitHubConnectorConfig{
				Owner:                "acme",
				Repo:                 "frontend",
				CredentialsSecretRef: domain.SecretKeyRef{Name: "sec", Key: "token"},
			},
		},
	}
	_ = mStore.SaveConnector(context.Background(), tenantID, ghConn)

	secResolver := &mockSecretResolver{
		secrets: map[string][]byte{
			tenantID.String() + ":connector:" + connectorName + ":token": webhookSecret,
		},
	}

	wf := &mockWorkflowService{}
	handler := connectors.NewInboundWebhookHandler(mStore, wf, secResolver)

	payload := map[string]any{
		"action": "closed",
		"issue": map[string]any{
			"number":       105,
			"state":        "closed",
			"state_reason": "not_planned", // Indicates won't fix
			"labels": []map[string]string{
				{"name": "security"},
				{"name": "rampart-finding-" + findingID.String()},
			},
		},
		"sender": map[string]string{
			"login": "octocat-maintainer",
		},
	}

	bodyBytes, _ := json.Marshal(payload)
	signature := signPayloadSHA256(webhookSecret, bodyBytes)

	reqURL := fmt.Sprintf("/api/v1/t/%s/connectors/%s/webhook", tenantID, connectorName)
	req := httptest.NewRequest(http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	req.Header.Set("X-Hub-Signature-256", "sha256="+signature)
	req.Header.Set("X-GitHub-Delivery", "gh-deliv-888")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	if len(wf.requests) != 1 {
		t.Fatalf("expected 1 approval request created for closed not_planned issue, got %d", len(wf.requests))
	}
	if wf.requests[0].FindingIDs[0] != findingID {
		t.Fatalf("expected findingID %s, got %s", findingID, wf.requests[0].FindingIDs[0])
	}
}

func TestInboundWebhook_OutboundOnlyDirection_Rejected(t *testing.T) {
	tenantID := uuid.New()
	connectorName := "slack-out"

	mStore := ingest.NewMemoryStore()
	slackConn := domain.Connector{
		Name:     connectorName,
		TenantID: tenantID,
		Type:     domain.ConnectorTypeSlack,
		Spec: domain.ConnectorSpec{
			Type:      domain.ConnectorTypeSlack,
			Direction: domain.DirectionOutbound, // strictly outbound
			Slack: &domain.SlackConnectorConfig{
				TokenSecretRef: domain.SecretKeyRef{Name: "sec", Key: "token"},
				DefaultChannel: "#general",
			},
		},
	}
	_ = mStore.SaveConnector(context.Background(), tenantID, slackConn)

	handler := connectors.NewInboundWebhookHandler(mStore, nil, nil)
	reqURL := fmt.Sprintf("/api/v1/t/%s/connectors/%s/webhook", tenantID, connectorName)
	req := httptest.NewRequest(http.MethodPost, reqURL, strings.NewReader(`{}`))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for outbound-only connector, got %d", w.Code)
	}
}
