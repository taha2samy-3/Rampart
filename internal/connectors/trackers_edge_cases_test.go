package connectors_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
)

// TestJira_SearchBeforeRetry_EdgeCases tests all corner cases when Jira searches
// by label before attempting to create an issue (Milestone 3.2, D70 B2).
func TestJira_SearchBeforeRetry_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("returns existing issue when search finds 1 match without creating", func(t *testing.T) {
		searchCalls := 0

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/rest/api/3/search") {
				searchCalls++
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"total": 1,
					"issues": [
						{"id": "20001", "key": "SEC-99"}
					]
				}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}
		tr, err := connectors.NewJiraTracker(cfg, loopbackClient(), []byte("user:token"), "https://rampart.example.com")
		if err != nil {
			t.Fatal(err)
		}

		f := critical()
		ticketID, ticketURL, err := tr.FindIssueByLabel(ctx, connectors.FindingLabel(f.ID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ticketID != "SEC-99" {
			t.Fatalf("expected existing ticket SEC-99, got %s", ticketID)
		}
		if !strings.Contains(ticketURL, "SEC-99") {
			t.Fatalf("expected URL to contain SEC-99, got %s", ticketURL)
		}
		if searchCalls != 1 {
			t.Fatalf("expected search to be called once, got %d", searchCalls)
		}
	})

	t.Run("returns first issue when search finds multiple matches", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/rest/api/3/search") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"total": 2,
					"issues": [
						{"id": "20001", "key": "SEC-88"},
						{"id": "20002", "key": "SEC-89"}
					]
				}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}
		tr, _ := connectors.NewJiraTracker(cfg, loopbackClient(), []byte("user:token"), "")
		ticketID, _, err := tr.FindIssueByLabel(ctx, connectors.FindingLabel(critical().ID))
		if err != nil {
			t.Fatal(err)
		}
		if ticketID != "SEC-88" {
			t.Fatalf("expected first matching issue SEC-88, got %s", ticketID)
		}
	})

	t.Run("returns empty string when search returns 0 results", func(t *testing.T) {
		searchCalls := 0

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/rest/api/3/search") {
				searchCalls++
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"total": 0, "issues": []}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}
		tr, _ := connectors.NewJiraTracker(cfg, loopbackClient(), []byte("user:token"), "")
		ticketID, ticketURL, err := tr.FindIssueByLabel(ctx, connectors.FindingLabel(critical().ID))
		if err != nil {
			t.Fatal(err)
		}
		if ticketID != "" || ticketURL != "" {
			t.Fatalf("expected empty ticket, got id=%s, url=%s", ticketID, ticketURL)
		}
		if searchCalls != 1 {
			t.Fatalf("expected 1 search call, got %d", searchCalls)
		}
	})

	t.Run("search endpoint 500 error fails safely", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/rest/api/3/search") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"errorMessages":["Internal search failure"]}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}
		tr, _ := connectors.NewJiraTracker(cfg, loopbackClient(), []byte("user:token"), "")
		_, _, err := tr.FindIssueByLabel(ctx, connectors.FindingLabel(critical().ID))
		if err == nil {
			t.Fatal("expected error when search endpoint fails with 500")
		}
	})
}

// TestGitHub_SearchBeforeRetry_EdgeCases tests GitHub issue search by label.
func TestGitHub_SearchBeforeRetry_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("returns existing issue when GitHub search finds matching issue by label", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/org/repo/issues" && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[
					{"number": 77, "html_url": "https://github.com/org/repo/issues/77", "state": "open"}
				]`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.GitHubConnectorConfig{Owner: "org", Repo: "repo"}
		tr, err := connectors.NewGitHubTracker(cfg, loopbackClient(), []byte("token"), "")
		if err != nil {
			t.Fatal(err)
		}
		tr.SetAPIBaseURL(srv.URL)

		ticketID, ticketURL, err := tr.FindIssueByLabel(ctx, connectors.FindingLabel(critical().ID))
		if err != nil {
			t.Fatal(err)
		}
		if ticketID != "#77" {
			t.Fatalf("expected existing ticket #77, got %s", ticketID)
		}
		if ticketURL != "https://github.com/org/repo/issues/77" {
			t.Fatalf("expected existing ticket URL, got %s", ticketURL)
		}
	})

	t.Run("returns empty string when GitHub search returns no issues", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/org/repo/issues" && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[]`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.GitHubConnectorConfig{Owner: "org", Repo: "repo"}
		tr, _ := connectors.NewGitHubTracker(cfg, loopbackClient(), []byte("token"), "")
		tr.SetAPIBaseURL(srv.URL)

		ticketID, ticketURL, err := tr.FindIssueByLabel(ctx, connectors.FindingLabel(critical().ID))
		if err != nil {
			t.Fatal(err)
		}
		if ticketID != "" || ticketURL != "" {
			t.Fatalf("expected empty result, got %s, %s", ticketID, ticketURL)
		}
	})
}

// TestTracker_FatalVsTransientErrors tests HTTP error status classification.
// Fatal errors (400, 401, 403, 404, 422) must be flagged as non-retryable.
// Transient errors (408, 429, 500, 502, 503, 504) must be flagged as retryable.
func TestTracker_FatalVsTransientErrors(t *testing.T) {
	ctx := context.Background()

	fatalStatuses := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusUnprocessableEntity,
	}

	for _, code := range fatalStatuses {
		t.Run(fmt.Sprintf("Jira fatal status %d", code), func(t *testing.T) {
			ts := newTrackerServer(code)
			defer ts.srv.Close()

			tr, _ := connectors.NewJiraTracker(domain.JiraConnectorConfig{URL: ts.srv.URL, DefaultProject: "SEC"}, loopbackClient(), []byte("user:token"), "")
			_, _, err := tr.CreateIssue(ctx, critical(), "App")
			if err == nil {
				t.Fatalf("expected error for status %d", code)
			}
			isFatal, _ := domain.IsFatalTrackerError(err)
			if !isFatal {
				t.Fatalf("status %d should be classified as fatal/non-retryable, got err: %v", code, err)
			}
		})

		t.Run(fmt.Sprintf("GitHub fatal status %d", code), func(t *testing.T) {
			ts := newTrackerServer(code)
			defer ts.srv.Close()

			tr, _ := connectors.NewGitHubTracker(domain.GitHubConnectorConfig{Owner: "a", Repo: "b"}, loopbackClient(), []byte("token"), "")
			tr.SetAPIBaseURL(ts.srv.URL)
			_, _, err := tr.CreateIssue(ctx, critical(), "App")
			if err == nil {
				t.Fatalf("expected error for status %d", code)
			}
			isFatal, _ := domain.IsFatalTrackerError(err)
			if !isFatal {
				t.Fatalf("status %d should be classified as fatal/non-retryable, got err: %v", code, err)
			}
		})
	}

	transientStatuses := []int{
		http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}

	for _, code := range transientStatuses {
		t.Run(fmt.Sprintf("Jira transient status %d", code), func(t *testing.T) {
			ts := newTrackerServer(code)
			defer ts.srv.Close()

			tr, _ := connectors.NewJiraTracker(domain.JiraConnectorConfig{URL: ts.srv.URL, DefaultProject: "SEC"}, loopbackClient(), []byte("user:token"), "")
			_, _, err := tr.CreateIssue(ctx, critical(), "App")
			if err == nil {
				t.Fatalf("expected error for status %d", code)
			}
			isFatal, _ := domain.IsFatalTrackerError(err)
			if isFatal {
				t.Fatalf("status %d should be transient/retryable, not fatal, got err: %v", code, err)
			}
		})
	}
}

// TestJira_CommentAndClose_EdgeCases tests edge cases for Comment and Close lifecycle methods.
func TestJira_CommentAndClose_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("Close fails when no suitable transition exists", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/transitions") && r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				// Transitions available do not include Done, Closed, or Resolved
				_, _ = w.Write([]byte(`{"transitions": [{"id": "11", "name": "In Progress", "to": {"name": "In Progress"}}]}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}
		tr, _ := connectors.NewJiraTracker(cfg, loopbackClient(), []byte("user:token"), "")
		err := tr.Close(ctx, "SEC-12")
		if err == nil {
			t.Fatal("expected error when no close transition is available")
		}
		if !strings.Contains(err.Error(), "no close transition found") && !strings.Contains(err.Error(), "transition") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("Comment handles special characters, unicode, and empty string safely", func(t *testing.T) {
		var receivedComment map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/comment") {
				_ = json.NewDecoder(r.Body).Decode(&receivedComment)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"101"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}
		tr, _ := connectors.NewJiraTracker(cfg, loopbackClient(), []byte("user:token"), "")

		// Special unicode string with RTL, emojis, and newlines
		specialText := "Finding resolved 🛡️🔒\nتفاصيل الحل:\nFixed in commit 1234abcd.\n"
		err := tr.Comment(ctx, "SEC-12", specialText)
		if err != nil {
			t.Fatalf("unexpected comment error: %v", err)
		}
		if receivedComment == nil {
			t.Fatal("expected received comment payload")
		}
	})
}

// TestGitHub_CommentAndClose_EdgeCases tests edge cases for GitHub Comment and Close.
func TestGitHub_CommentAndClose_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("Comment strips or escapes invalid characters", func(t *testing.T) {
		var receivedBody map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/comments") {
				_ = json.NewDecoder(r.Body).Decode(&receivedBody)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id": 500}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.GitHubConnectorConfig{Owner: "org", Repo: "repo"}
		tr, _ := connectors.NewGitHubTracker(cfg, loopbackClient(), []byte("token"), "")
		tr.SetAPIBaseURL(srv.URL)

		err := tr.Comment(ctx, "#42", "Testing <script>alert(1)</script> and [click](javascript:void(0))")
		if err != nil {
			t.Fatal(err)
		}
		if receivedBody["body"] == nil {
			t.Fatal("expected comment body in payload")
		}
	})

	t.Run("Close on already-closed issue succeeds idempotently", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/org/repo/issues/42" && r.Method == http.MethodPatch {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"number": 42, "state": "closed"}`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		cfg := domain.GitHubConnectorConfig{Owner: "org", Repo: "repo"}
		tr, _ := connectors.NewGitHubTracker(cfg, loopbackClient(), []byte("token"), "")
		tr.SetAPIBaseURL(srv.URL)

		err := tr.Close(ctx, "#42")
		if err != nil {
			t.Fatalf("idempotent close should succeed: %v", err)
		}
	})
}

// TestTrackers_ConcurrentIssueCreation ensures thread-safety under concurrent load.
func TestTrackers_ConcurrentIssueCreation(t *testing.T) {
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/rest/api/3/search") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"total": 0, "issues": []}`))
			return
		}
		if r.URL.Path == "/rest/api/3/issue" {
			n := atomic.AddInt32(&count, 1)
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"id": "%d", "key": "SEC-%d"}`, 1000+n, n)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := domain.JiraConnectorConfig{URL: srv.URL, DefaultProject: "SEC"}
	tr, _ := connectors.NewJiraTracker(cfg, loopbackClient(), []byte("user:token"), "")

	const concurrency = 20
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			f := &domain.Finding{
				ID:          uuid.New(),
				TenantID:    uuid.New(),
				Title:       fmt.Sprintf("Finding %d", idx),
				Description: "Concurrent test finding",
				Severity:    domain.SeverityCritical,
				RuleID:      fmt.Sprintf("RULE-%d", idx),
			}
			_, _, err := tr.CreateIssue(context.Background(), f, "App")
			if err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent issue creation error: %v", err)
	}

	if atomic.LoadInt32(&count) != concurrency {
		t.Fatalf("expected %d issues created, got %d", concurrency, count)
	}
}
