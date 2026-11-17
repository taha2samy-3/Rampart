package connectors_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/store"
)

func renewalIssue() *domain.Finding {
	return connectors.AttestationIssue(store.AttestationTicketWork{
		TenantID: uuid.New(), AttestationID: uuid.New(), FrameworkID: "acme-policy", ControlID: "TM-1",
		Application: "payments", Owner: "team:appsec", ExpiresAt: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
	})
}

// The ticket to renew an attestation is a compliance notice on whichever tracker the tenant has: not a "vulnerability
// alert" with a severity label, and not a link to a finding page that does not exist.
func TestGitHubTracker_RenewalNoticeIsNotAVulnerabilityAlert(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number": 7, "html_url": "https://github.com/acme/backend/issues/7"}`))
	}))
	defer srv.Close()
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}, AllowLoopback: true})
	tr, err := connectors.NewGitHubTracker(domain.GitHubConnectorConfig{Owner: "acme", Repo: "backend"}, client, []byte("tok"), "https://rampart.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tr.SetTenantSlug("acme")
	tr.SetAPIBaseURL(srv.URL)
	issue := renewalIssue()
	if _, _, err := tr.CreateIssue(context.Background(), issue, "payments"); err != nil {
		t.Fatal(err)
	}
	body, _ := got["body"].(string)
	if !strings.Contains(body, "Compliance notice") || strings.Contains(body, "Vulnerability Alert") || strings.Contains(body, "Severity") {
		t.Errorf("body: %q", body)
	}
	if strings.Contains(body, "/findings/") || !strings.Contains(body, "https://rampart.example.com/t/acme/compliance") {
		t.Errorf("the link goes to the Compliance page, not a finding: %q", body)
	}
	labels, _ := got["labels"].([]any)
	var joined []string
	for _, l := range labels {
		joined = append(joined, l.(string))
	}
	all := strings.Join(joined, ",")
	if !strings.Contains(all, "compliance") || strings.Contains(all, "security") || strings.Contains(all, "severity") || !strings.Contains(all, connectors.FindingLabel(issue.ID)) {
		t.Errorf("labels: %v", joined)
	}
}

func TestJiraTracker_RenewalNoticeIsNotAVulnerability(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/api/3/issue" {
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id": "1", "key": "SEC-9"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"fields": {}}`))
	}))
	defer srv.Close()
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}, AllowLoopback: true})
	tr, err := connectors.NewJiraTracker(domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}, client, []byte("bot@example.com:tok"), "https://rampart.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tr.SetTenantSlug("acme")
	issue := renewalIssue()
	if _, _, err := tr.CreateIssue(context.Background(), issue, "payments"); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	s := string(raw)
	if strings.Contains(s, "vulnerability was identified") || strings.Contains(s, "/findings/") || !strings.Contains(s, "compliance notice") || !strings.Contains(s, "/t/acme/compliance") {
		t.Errorf("payload: %s", s)
	}
	if strings.Contains(s, `"security"`) || strings.Contains(s, "severity-") {
		t.Errorf("labels must not claim a security finding: %s", s)
	}
}
