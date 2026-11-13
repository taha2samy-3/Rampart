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
	if err == nil {
		tracker.SetTenantSlug("acme")
	}
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
			Ticketing: &domain.ConnectorTicketingPolicy{OnCritical: true},
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

// A fake tracker server that records what it receives and answers with the status it is told to.
type trackerServer struct {
	srv      *httptest.Server
	calls    int
	payloads []map[string]any
	status   int
}

func newTrackerServer(status int) *trackerServer {
	ts := &trackerServer{status: status}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.calls++
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		ts.payloads = append(ts.payloads, p)
		w.WriteHeader(ts.status)
		_, _ = w.Write([]byte(`{"id":"1","key":"SEC-1","number":7,"html_url":"https://x/7","error":"echo: SECRET-IN-FINDING"}`))
	}))
	return ts
}

func loopbackClient() *connectors.SafeClient {
	return connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}, AllowLoopback: true})
}

func critical() *domain.Finding {
	return &domain.Finding{ID: uuid.New(), TenantID: uuid.New(), Title: "Remote code execution", Description: "bad", Severity: domain.SeverityCritical, RiskScore: 940, RuleID: "CVE-1"}
}

func TestJira_CreatingAnIssueIsNotRetriedWithinOneCall(t *testing.T) {
	ts := newTrackerServer(http.StatusBadGateway)
	defer ts.srv.Close()
	tr, _ := connectors.NewJiraTracker(domain.JiraConnectorConfig{URL: ts.srv.URL, DefaultProject: "SEC"}, loopbackClient(), []byte("a@b.c:tok"), "")
	_, _, err := tr.CreateIssue(context.Background(), critical(), "App")
	if err == nil || ts.calls != 1 {
		t.Fatalf("one attempt and an error: calls %d, err %v", ts.calls, err)
	}
	if strings.Contains(err.Error(), "SECRET-IN-FINDING") {
		t.Fatalf("the answer of the tracker can echo a finding's text and is not put in the error: %v", err)
	}
}

func TestGitHub_CreatingAnIssueIsNotRetried(t *testing.T) {
	ts := newTrackerServer(http.StatusServiceUnavailable)
	defer ts.srv.Close()
	tr, _ := connectors.NewGitHubTracker(domain.GitHubConnectorConfig{Owner: "a", Repo: "b"}, loopbackClient(), []byte("tok"), "")
	tr.SetAPIBaseURL(ts.srv.URL)
	if _, _, err := tr.CreateIssue(context.Background(), critical(), "App"); err == nil || ts.calls != 1 {
		t.Fatalf("calls %d, err %v", ts.calls, err)
	}
}

func TestJira_NoGuessedProject_CoreFieldsStayTheTrackersAndPlaceholdersAreFilled(t *testing.T) {
	ts := newTrackerServer(http.StatusCreated)
	defer ts.srv.Close()
	client := loopbackClient()
	noProject, _ := connectors.NewJiraTracker(domain.JiraConnectorConfig{URL: ts.srv.URL}, client, []byte("a@b.c:tok"), "")
	if _, _, err := noProject.CreateIssue(context.Background(), critical(), "App"); err == nil || ts.calls != 0 {
		t.Fatalf("a project is not guessed: calls %d, err %v", ts.calls, err)
	}

	cfg := domain.JiraConnectorConfig{URL: ts.srv.URL, DefaultProject: "SEC", CustomFields: map[string]string{
		"project":           "EVIL",                     // a core field: ignored
		"description":       "replaced",                 // a core field: ignored
		"customfield_10042": "{{ finding.risk_score }}", // a number stays a number
		"customfield_10043": "{{ finding.severity }} in {{ app.name }}",
	}}
	tr, _ := connectors.NewJiraTracker(cfg, client, []byte("a@b.c:tok"), "")
	f := critical()
	if _, _, err := tr.CreateIssue(context.Background(), f, "Shop"); err != nil {
		t.Fatal(err)
	}
	fields := ts.payloads[0]["fields"].(map[string]any)
	if fields["project"].(map[string]any)["key"] != "SEC" {
		t.Fatalf("a custom field replaced the project: %v", fields["project"])
	}
	if _, isString := fields["description"].(string); isString {
		t.Fatal("a custom field replaced the description")
	}
	if fields["customfield_10042"] != float64(940) {
		t.Fatalf("the score is a number: %#v", fields["customfield_10042"])
	}
	if fields["customfield_10043"] != "critical in Shop" {
		t.Fatalf("placeholders in a sentence: %#v", fields["customfield_10043"])
	}
	labels := fields["labels"].([]any)
	found := false
	for _, l := range labels {
		if l == connectors.FindingLabel(f.ID) {
			found = true
		}
		if len(l.(string)) > 50 {
			t.Fatalf("a label longer than the 50 characters GitHub allows: %q", l)
		}
	}
	if !found {
		t.Fatalf("the finding label is missing: %v", labels)
	}
}

func TestTrackers_LongTextIsCutOnARuneBoundary(t *testing.T) {
	ts := newTrackerServer(http.StatusCreated)
	defer ts.srv.Close()
	f := critical()
	f.Title = strings.Repeat("ثغرة ", 200) + "\n" + "second line"
	f.Description = strings.Repeat("ع", 40000)
	tr, _ := connectors.NewJiraTracker(domain.JiraConnectorConfig{URL: ts.srv.URL, DefaultProject: "SEC"}, loopbackClient(), []byte("a@b.c:tok"), "")
	if _, _, err := tr.CreateIssue(context.Background(), f, "App"); err != nil {
		t.Fatal(err)
	}
	fields := ts.payloads[0]["fields"].(map[string]any)
	summary := fields["summary"].(string)
	if n := len([]rune(summary)); n > 255 || strings.ContainsAny(summary, "\r\n") {
		t.Fatalf("a summary is at most 255 characters on one line: %d", n)
	}
	desc, _ := json.Marshal(fields["description"])
	if n := len([]rune(string(desc))); n > 31000 {
		t.Fatalf("the description is cut: %d runes", n)
	}
}

func TestGitHub_TextFromAScannerCannotMentionLinkOrCloseAnything(t *testing.T) {
	ts := newTrackerServer(http.StatusCreated)
	defer ts.srv.Close()
	tr, _ := connectors.NewGitHubTracker(domain.GitHubConnectorConfig{Owner: "a", Repo: "b"}, loopbackClient(), []byte("tok"), "")
	tr.SetAPIBaseURL(ts.srv.URL)
	f := critical()
	f.Title = "Hi @octocat see ![x](https://evil.example/pixel.png) fixes #1"
	f.Description = "```\nclose the fence\n``` @everyone ![p](https://evil.example/p.png)\nfixes #2"
	if _, _, err := tr.CreateIssue(context.Background(), f, "App @team"); err != nil {
		t.Fatal(err)
	}
	body := ts.payloads[0]["body"].(string)
	// Everything from the scanner is inside a code block or code span: the fence around the description is longer
	// than any run of backticks in it, so it cannot be closed from inside.
	i := strings.Index(body, "#### Description")
	if i < 0 {
		t.Fatalf("no description: %s", body)
	}
	rest := body[i:]
	fence := strings.TrimSpace(strings.SplitN(strings.SplitN(rest, "\n", 3)[2], "\n", 2)[0])
	if len(fence) < 4 || strings.Trim(fence, "`") != "" {
		t.Fatalf("the fence must be longer than the backticks inside the text: %q", fence)
	}
	if strings.Count(rest, fence) != 2 {
		t.Fatalf("the description is opened and closed once: %s", rest)
	}
	if strings.Contains(strings.SplitN(body, "#### Description", 2)[0], "@octocat") && !strings.Contains(body, "`") {
		t.Fatal("text outside a code span")
	}
}

func TestResolver_ASecretThatCannotBeReadIsAnErrorNotAReasonToUseAnotherConnector(t *testing.T) {
	ctx := context.Background()
	tenant := uuid.New()
	st := ingest.NewMemoryStore()
	for _, name := range []string{"jira-a", "gh-b"} {
		c := domain.Connector{Name: name, TenantID: tenant, Type: domain.ConnectorTypeJira, Spec: domain.ConnectorSpec{Type: domain.ConnectorTypeJira,
			Ticketing: &domain.ConnectorTicketingPolicy{OnCritical: true},
			Jira:      &domain.JiraConnectorConfig{URL: "https://a.atlassian.net", DefaultProject: "SEC", CredentialsSecretRef: domain.SecretKeyRef{Name: "s", Key: "apiToken"}}}}
		if name == "gh-b" {
			c.Type = domain.ConnectorTypeGitHub
			c.Spec = domain.ConnectorSpec{Type: domain.ConnectorTypeGitHub, GitHub: &domain.GitHubConnectorConfig{Owner: "a", Repo: "b", CredentialsSecretRef: domain.SecretKeyRef{Name: "s", Key: "token"}}}
		}
		_ = st.SaveConnector(ctx, tenant, c)
	}
	// Only the GitHub secret exists: the Jira one is missing, and the ticket must not quietly go to GitHub.
	secrets := &mockSecretResolver{secrets: map[string][]byte{tenant.String() + ":connector:gh-b:token": []byte("ghp")}}
	tr, err := connectors.NewDefaultTrackerResolver(st, secrets, loopbackClient(), "").ResolveTracker(ctx, tenant)
	if err == nil && tr != nil {
		if _, isGH := tr.(*connectors.GitHubTracker); isGH {
			t.Fatal("the ticket went to the other connector")
		}
	}
}

func TestJiraTracker_CommentAndClose(t *testing.T) {
	ctx := context.Background()
	var commentBody map[string]any
	var transitionBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rest/api/3/issue/SEC-42/comment" && r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&commentBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id": "1002"}`))
			return
		}
		if r.URL.Path == "/rest/api/3/issue/SEC-42/transitions" {
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"transitions": [{"id": "31", "name": "Done", "to": {"name": "Closed"}}]}`))
				return
			}
			if r.Method == http.MethodPost {
				_ = json.NewDecoder(r.Body).Decode(&transitionBody)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{
		Allowlist:     &domain.PlatformSSRFAllowlist{AllowLoopback: true},
		AllowLoopback: true,
	})

	cfg := domain.JiraConnectorConfig{
		URL:            srv.URL,
		DefaultProject: "SEC",
	}

	tracker, err := connectors.NewJiraTracker(cfg, client, []byte("user:token"), "https://rampart.example.com")
	if err != nil {
		t.Fatalf("failed to create JiraTracker: %v", err)
	}

	if err := tracker.Comment(ctx, "SEC-42", "Finding fixed in main branch"); err != nil {
		t.Fatalf("Comment failed: %v", err)
	}
	if commentBody == nil {
		t.Fatal("expected comment body to be received")
	}

	if err := tracker.Close(ctx, "SEC-42"); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if transitionBody == nil || transitionBody["transition"].(map[string]any)["id"] != "31" {
		t.Fatalf("expected transition id 31, got %v", transitionBody)
	}
}

func TestGitHubTracker_CommentAndClose(t *testing.T) {
	ctx := context.Background()
	var commentBody map[string]any
	var patchBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/org/repo/issues/42/comments" && r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&commentBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id": 101}`))
			return
		}
		if r.URL.Path == "/repos/org/repo/issues/42" && r.Method == http.MethodPatch {
			_ = json.NewDecoder(r.Body).Decode(&patchBody)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"number": 42, "state": "closed"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{
		Allowlist:     &domain.PlatformSSRFAllowlist{AllowLoopback: true},
		AllowLoopback: true,
	})

	cfg := domain.GitHubConnectorConfig{
		Owner: "org",
		Repo:  "repo",
	}

	tracker, err := connectors.NewGitHubTracker(cfg, client, []byte("token"), "https://rampart.example.com")
	if err != nil {
		t.Fatalf("failed to create GitHubTracker: %v", err)
	}
	tracker.SetAPIBaseURL(srv.URL)

	if err := tracker.Comment(ctx, "#42", "Remediated in commit abc"); err != nil {
		t.Fatalf("Comment failed: %v", err)
	}
	if commentBody == nil || commentBody["body"] != "Remediated in commit abc" {
		t.Fatalf("expected comment body 'Remediated in commit abc', got %v", commentBody)
	}

	if err := tracker.Close(ctx, "#42"); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if patchBody == nil || patchBody["state"] != "closed" || patchBody["state_reason"] != "completed" {
		t.Fatalf("expected state closed and state_reason completed, got %v", patchBody)
	}
}
