package connectors_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

func TestJiraTracker_CreateIssueAndCheck(t *testing.T) {
	ctx := context.Background()
	var receivedPayload map[string]any
	var authHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		if r.URL.Path == "/rest/api/3/myself" {
			if !strings.HasPrefix(authHeader, "Basic ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"accountId": "12345", "displayName": "Rampart Bot"}`))
			return
		}

		if r.URL.Path == "/rest/api/3/issue" {
			_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id": "10001", "key": "SEC-42", "self": "https://jira.example.com/rest/api/3/issue/10001"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	allowlist := &domain.PlatformSSRFAllowlist{AllowLoopback: true}
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{
		Allowlist:     allowlist,
		AllowLoopback: true,
	})

	cfg := domain.JiraConnectorConfig{
		URL:            srv.URL,
		DefaultProject: "SEC",
		IssueType:      "Vulnerability",
		SeverityToPriority: map[string]string{
			"critical": "Highest",
		},
	}

	tracker, err := connectors.NewJiraTracker(cfg, client, []byte("bot@example.com:api-token-secret"), "https://rampart.example.com")
	if err != nil {
		t.Fatalf("failed to create JiraTracker: %v", err)
	}

	// 1. Check connectivity
	if err := tracker.Check(ctx); err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	// 2. Create Issue
	finding := &domain.Finding{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Title:       "Remote Code Execution via Log4Shell",
		Description: "JNDI lookup vulnerability in log4j2 library",
		Severity:    domain.SeverityCritical,
		Category:    domain.CategorySCA,
		RuleID:      "CVE-2021-44228",
		Location:    domain.Location{Code: &domain.CodeLocation{FilePath: "pom.xml"}},
	}

	ticketID, ticketURL, err := tracker.CreateIssue(ctx, finding, "Payment Gateway")
	if err != nil {
		t.Fatalf("CreateIssue failed: %v", err)
	}

	if ticketID != "SEC-42" {
		t.Errorf("expected ticketID 'SEC-42', got %q", ticketID)
	}
	expectedURL := srv.URL + "/browse/SEC-42"
	if ticketURL != expectedURL {
		t.Errorf("expected ticketURL %q, got %q", expectedURL, ticketURL)
	}

	// Verify ADF payload format
	fields, ok := receivedPayload["fields"].(map[string]any)
	if !ok {
		t.Fatalf("expected fields object in payload, got %+v", receivedPayload)
	}
	desc, ok := fields["description"].(map[string]any)
	if !ok || desc["type"] != "doc" || desc["version"] != float64(1) {
		t.Fatalf("expected valid ADF doc description, got %+v", desc)
	}
	labels, ok := fields["labels"].([]any)
	if !ok || len(labels) == 0 {
		t.Fatalf("expected labels in payload, got %+v", fields["labels"])
	}
}

func TestGitHubTracker_CreateIssueAndCheck(t *testing.T) {
	ctx := context.Background()
	var receivedPayload map[string]any
	var authHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		if r.URL.Path == "/repos/acme/backend" {
			if authHeader != "Bearer ghp_valid_token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name": "backend", "permissions": {"push": true}}`))
			return
		}

		if r.URL.Path == "/repos/acme/backend/issues" {
			_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number": 99, "html_url": "https://github.com/acme/backend/issues/99"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	allowlist := &domain.PlatformSSRFAllowlist{AllowLoopback: true}
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{
		Allowlist:     allowlist,
		AllowLoopback: true,
	})

	cfg := domain.GitHubConnectorConfig{
		Owner: "acme",
		Repo:  "backend",
		SeverityToLabels: map[string]string{
			"high": "severity/high",
		},
	}

	tracker, err := connectors.NewGitHubTracker(cfg, client, []byte("ghp_valid_token"), "https://rampart.example.com")
	if err != nil {
		t.Fatalf("failed to create GitHubTracker: %v", err)
	}
	tracker.SetAPIBaseURL(srv.URL)

	// 1. Check permissions
	if err := tracker.Check(ctx); err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	// 2. Create Issue
	finding := &domain.Finding{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Title:       "SQL Injection in user search",
		Description: "Raw query concat in search handler",
		Severity:    domain.SeverityHigh,
		Location:    domain.Location{Code: &domain.CodeLocation{FilePath: "api/search.go"}},
	}

	ticketID, ticketURL, err := tracker.CreateIssue(ctx, finding, "API Service")
	if err != nil {
		t.Fatalf("CreateIssue failed: %v", err)
	}

	if ticketID != "#99" {
		t.Errorf("expected ticketID '#99', got %q", ticketID)
	}
	if ticketURL != "https://github.com/acme/backend/issues/99" {
		t.Errorf("expected ticketURL 'https://github.com/acme/backend/issues/99', got %q", ticketURL)
	}

	// Verify labels and body
	if title, ok := receivedPayload["title"].(string); !ok || !strings.Contains(title, "SQL Injection") {
		t.Errorf("unexpected issue title: %v", receivedPayload["title"])
	}
	if body, ok := receivedPayload["body"].(string); !ok || !strings.Contains(body, "View in Rampart") {
		t.Errorf("expected body to contain Rampart link, got: %v", receivedPayload["body"])
	}
}

func TestDefaultTrackerResolver(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	mStore := ingest.NewMemoryStore()

	jiraConn := domain.Connector{
		Name:     "jira-main",
		TenantID: tenantID,
		Type:     domain.ConnectorTypeJira,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeJira,
			Jira: &domain.JiraConnectorConfig{
				URL:                  "https://jira.acme.com",
				DefaultProject:       "SEC",
				CredentialsSecretRef: domain.SecretKeyRef{Name: "jira-sec", Key: "apiToken"},
			},
		},
	}
	condTrue := domain.ConnectorCondition{Type: "Connected", Status: "True"}
	jiraConn.Status.Conditions = []domain.ConnectorCondition{condTrue}
	_ = mStore.SaveConnector(ctx, tenantID, jiraConn)

	resolverSecret := &mockSecretResolver{
		secrets: map[string][]byte{
			tenantID.String() + ":connector:jira-main:apiToken": []byte("user@acme.com:jira-token"),
		},
	}

	allowlist := &domain.PlatformSSRFAllowlist{AllowLoopback: true}
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{
		Allowlist:     allowlist,
		AllowLoopback: true,
	})

	resolver := connectors.NewDefaultTrackerResolver(mStore, resolverSecret, client, "https://rampart.example.com")
	tr, err := resolver.ResolveTracker(ctx, tenantID)
	if err != nil {
		t.Fatalf("ResolveTracker failed: %v", err)
	}
	if tr == nil {
		t.Fatalf("expected resolved Tracker, got nil")
	}

	if _, ok := tr.(*connectors.JiraTracker); !ok {
		t.Errorf("expected *JiraTracker, got %T", tr)
	}
}
