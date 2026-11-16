package connectors_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rampart/internal/connectors"
	"rampart/internal/domain"
)

// D87: Jira's Check calls Jira: the credentials, the account Rampart acts as (D70 B6), and the fields the project
// accepts (D70 B10). Before, it only checked the address and reported "verified".
func TestJiraCheckLearnsAccountAndFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/rest/api/3/myself":
			if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("bot@example.com:token")) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"accountId":"5b10ac8d82e05b22cc7d4ef5"}`))
		case r.URL.Path == "/rest/api/3/issue/createmeta/SEC/issuetypes":
			_, _ = w.Write([]byte(`{"issueTypes":[{"id":"10001","name":"Bug"}]}`))
		case r.URL.Path == "/rest/api/3/issue/createmeta/SEC/issuetypes/10001":
			_, _ = w.Write([]byte(`{"fields":[{"fieldId":"summary"},{"fieldId":"labels"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}, AllowLoopback: true})
	checker := connectors.NewDefaultChecker(client, &domain.PlatformSSRFAllowlist{AllowLoopback: true})
	conn := domain.Connector{Type: domain.ConnectorTypeJira, Spec: domain.ConnectorSpec{Type: domain.ConnectorTypeJira,
		Jira: &domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}}}

	info, err := checker.CheckDetailed(context.Background(), conn, []byte("bot@example.com:token"))
	if err != nil || info.AccountID != "5b10ac8d82e05b22cc7d4ef5" {
		t.Fatalf("check: %+v %v", info, err)
	}
	if strings.Join(info.AcceptedFields, ",") != "summary,labels" {
		t.Fatalf("accepted fields: %v (priority must not be listed: the screen lacks it)", info.AcceptedFields)
	}
	if _, err := checker.CheckDetailed(context.Background(), conn, []byte("bad:creds")); err == nil {
		t.Fatal("refused credentials must fail the check")
	}
	conn.Spec.Jira.IssueType = "Story"
	if _, err := checker.CheckDetailed(context.Background(), conn, []byte("bot@example.com:token")); err == nil {
		t.Fatal("an issue type the project lacks must fail the check")
	}
}

// D87: GitHub had no Check at all (every GitHub connector failed). It now needs the repository and push access.
func TestGitHubCheckNeedsPushAccess(t *testing.T) {
	push := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/shop" {
			http.NotFound(w, r)
			return
		}
		if push {
			_, _ = w.Write([]byte(`{"permissions":{"push":true}}`))
		} else {
			_, _ = w.Write([]byte(`{"permissions":{"push":false}}`))
		}
	}))
	defer srv.Close()
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}, AllowLoopback: true})
	checker := connectors.NewDefaultChecker(client, &domain.PlatformSSRFAllowlist{AllowLoopback: true})
	checker.SetGitHubAPI(srv.URL)
	conn := domain.Connector{Type: domain.ConnectorTypeGitHub, Spec: domain.ConnectorSpec{Type: domain.ConnectorTypeGitHub,
		GitHub: &domain.GitHubConnectorConfig{Owner: "acme", Repo: "shop"}}}
	if err := checker.Check(context.Background(), conn, []byte("ghp_x")); err != nil {
		t.Fatalf("push access: %v", err)
	}
	push = false
	if err := checker.Check(context.Background(), conn, []byte("ghp_x")); err == nil {
		t.Fatal("a token without push access must fail: GitHub drops labels silently")
	}
	conn.Spec.GitHub.Repo = "missing"
	if err := checker.Check(context.Background(), conn, []byte("ghp_x")); err == nil {
		t.Fatal("an invisible repository must fail")
	}
}

// D87, D70 B10: priority and labels are sent only where the project's create screen accepts them.
func TestJiraCreateSendsOnlyAcceptedFields(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(strings.Builder)
		_, _ = io.Copy(b, r.Body)
		body = b.String()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"1","key":"SEC-1"}`))
	}))
	defer srv.Close()
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}, AllowLoopback: true})
	tr, err := connectors.NewJiraTracker(domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}, client, []byte("bot@example.com:token"), "https://rampart.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tr.SetAcceptedFields([]string{"summary", "description", "issuetype", "project", "labels"})
	f := &domain.Finding{ID: domain.NewID(), Title: "SQL injection", Severity: domain.SeverityCritical}
	if _, _, err := tr.CreateIssue(context.Background(), f, "shop"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, `"priority"`) || !strings.Contains(body, `"labels"`) {
		t.Fatalf("priority must be left out and labels sent: %s", body)
	}
}
