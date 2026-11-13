package connectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// Limits of the trackers' fields, so a long finding title or description cannot make the whole request fail.
const (
	jiraSummaryMax     = 255
	jiraDescriptionMax = 30000
	githubTitleMax     = 256
	githubBodyMax      = 60000
	trackerErrBodyMax  = 0 // an error body can echo what was sent (a finding's text): only the status is reported
)

// coreJiraFields are the fields a connector's customFields may not replace.
var coreJiraFields = map[string]bool{"project": true, "issuetype": true, "summary": true, "description": true, "labels": true, "reporter": true}

// truncateRunes cuts s to n runes, never in the middle of one (the findings of an Arabic-speaking team are not ASCII).
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// renderCustomField fills the placeholders docs/04 documents (`{{ finding.risk_score }}`). A value that is exactly
// one placeholder keeps its type: the score is a number, as Jira's number fields want.
func renderCustomField(v string, f *domain.Finding, appName string) any {
	t := strings.TrimSpace(v)
	if !strings.HasPrefix(t, "{{") || !strings.HasSuffix(t, "}}") || strings.Count(t, "{{") != 1 {
		return strings.NewReplacer(
			"{{ finding.severity }}", strings.ToLower(string(f.Severity)),
			"{{ finding.title }}", f.Title,
			"{{ finding.id }}", f.ID.String(),
			"{{ finding.rule_id }}", f.RuleID,
			"{{ app.name }}", appName,
		).Replace(v)
	}
	switch strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(t, "{{"), "}}")) {
	case "finding.risk_score":
		return f.RiskScore
	case "finding.severity":
		return strings.ToLower(string(f.Severity))
	case "finding.id":
		return f.ID.String()
	case "finding.title":
		return f.Title
	case "finding.rule_id":
		return f.RuleID
	case "app.name":
		return appName
	}
	return v
}

func basicAuthToken(userPass string) string {
	return base64.StdEncoding.EncodeToString([]byte(userPass))
}

// Tracker defines operations for creating and verifying issues in external trackers (Milestone 3.2, D23, D66).
type Tracker = domain.Tracker

// TrackerResolver finds the active tracker for a tenant.
type TrackerResolver = domain.TrackerResolver

// JiraTracker creates issues in Jira Cloud or Jira Data Center (D66, D69).
type JiraTracker struct {
	cfg        domain.JiraConnectorConfig
	client     *SafeClient
	authHeader string
	publicURL  string
	tenantSlug string
}

// SetTenantSlug sets the tenant as the UI names it in links (/t/<slug>/...): the slug, not the id.
func (j *JiraTracker) SetTenantSlug(s string) { j.tenantSlug = s }

func (j *JiraTracker) findingLink(f *domain.Finding) string {
	if j.publicURL == "" || j.tenantSlug == "" {
		return ""
	}
	return fmt.Sprintf("%s/t/%s/findings/%s", j.publicURL, j.tenantSlug, f.ID.String())
}

// NewJiraTracker creates a new JiraTracker instance.
func NewJiraTracker(cfg domain.JiraConnectorConfig, client *SafeClient, secret []byte, publicURL string) (*JiraTracker, error) {
	if cfg.URL == "" {
		return nil, errors.New("jira tracker: url is empty")
	}
	if client == nil {
		client = NewSafeClient()
	}

	secretStr := strings.TrimSpace(string(secret))
	if secretStr == "" {
		return nil, errors.New("jira tracker: secret credentials are empty")
	}

	// Secret can be "email:apiToken" (HTTP Basic) or personal access token (Bearer)
	authHeader := ""
	if strings.Contains(secretStr, ":") {
		authHeader = "Basic " + basicAuthToken(secretStr)
	} else {
		authHeader = "Bearer " + secretStr
	}

	return &JiraTracker{
		cfg:        cfg,
		client:     client,
		authHeader: authHeader,
		publicURL:  strings.TrimSuffix(publicURL, "/"),
	}, nil
}

// CreateIssue opens a Jira issue with Atlassian Document Format (ADF) description for Jira v3.
func (j *JiraTracker) CreateIssue(ctx context.Context, finding *domain.Finding, appName string) (string, string, error) {
	if finding == nil {
		return "", "", errors.New("finding is nil")
	}

	proj := strings.TrimSpace(j.cfg.DefaultProject)
	if proj == "" {
		return "", "", errors.New("jira: defaultProject is not set; Rampart does not guess a project")
	}
	issueType := j.cfg.IssueType
	if issueType == "" {
		issueType = "Bug"
	}

	priorityName := ""
	if len(j.cfg.SeverityToPriority) > 0 {
		priorityName = j.cfg.SeverityToPriority[strings.ToLower(string(finding.Severity))]
	}
	if priorityName == "" {
		switch strings.ToLower(string(finding.Severity)) {
		case "critical":
			priorityName = "Highest"
		case "high":
			priorityName = "High"
		case "medium":
			priorityName = "Medium"
		case "low":
			priorityName = "Low"
		default:
			priorityName = "Lowest"
		}
	}

	adfDesc := BuildJiraADF(finding, appName, j.findingLink(finding))

	labels := []string{
		"rampart",
		"security",
		"severity-" + strings.ToLower(string(finding.Severity)),
		FindingLabel(finding.ID),
	}

	fields := map[string]any{
		"project": map[string]string{
			"key": proj,
		},
		"summary":     truncateRunes(strings.NewReplacer("\r", " ", "\n", " ").Replace(fmt.Sprintf("[%s] %s in %s", strings.ToUpper(string(finding.Severity)), finding.Title, appName)), jiraSummaryMax),
		"description": adfDesc,
		"issuetype": map[string]string{
			"name": issueType,
		},
		"priority": map[string]string{
			"name": priorityName,
		},
		"labels": labels,
	}

	// Custom fields: placeholders are filled, and none may replace a field this tracker owns.
	for k, v := range j.cfg.CustomFields {
		if coreJiraFields[strings.ToLower(k)] {
			continue
		}
		fields[k] = renderCustomField(v, finding, appName)
	}

	payload := map[string]any{
		"fields": fields,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("jira: marshaling issue payload: %w", err)
	}

	endpoint := strings.TrimSuffix(j.cfg.URL, "/") + "/rest/api/3/issue"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", "", fmt.Errorf("jira: creating request: %w", err)
	}

	req.Header.Set("Authorization", j.authHeader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Creating an issue is not idempotent: a retry after a lost answer would open a second ticket. One attempt; the
	// ticket sweeper decides about another (D70).
	respBody, status, _, err := j.client.DoWithRetry(ctx, req, false)
	if err != nil {
		return "", "", fmt.Errorf("jira: issue creation failed: %w", err)
	}

	if status != http.StatusCreated && status != http.StatusOK {
		return "", "", fmt.Errorf("jira: issue creation returned status %d", status)
	}

	var res struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return "", "", fmt.Errorf("jira: unmarshaling response: %w", err)
	}

	ticketURL := fmt.Sprintf("%s/browse/%s", strings.TrimSuffix(j.cfg.URL, "/"), res.Key)
	return res.Key, ticketURL, nil
}

// Check verifies Jira connectivity and credentials. It speaks REST v3, which Jira Cloud offers; Jira Data Center
// speaks v2 and is not supported yet (D70).
func (j *JiraTracker) Check(ctx context.Context) error {
	endpoint := strings.TrimSuffix(j.cfg.URL, "/") + "/rest/api/3/myself"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("jira check: creating request: %w", err)
	}

	req.Header.Set("Authorization", j.authHeader)
	req.Header.Set("Accept", "application/json")

	_, status, _, err := j.client.DoWithRetry(ctx, req, true)
	if err != nil {
		return fmt.Errorf("jira check failed: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("jira check returned status %d", status)
	}
	return nil
}

// BuildJiraADF creates an Atlassian Document Format JSON structure for Jira v3.
func BuildJiraADF(finding *domain.Finding, appName, findingURL string) map[string]any {
	var paragraphs []map[string]any

	// 1. Overview paragraph
	overviewText := fmt.Sprintf("A %s vulnerability was identified in application %q.", strings.ToUpper(string(finding.Severity)), appName)
	paragraphs = append(paragraphs, map[string]any{
		"type": "paragraph",
		"content": []map[string]any{
			{"type": "text", "text": overviewText},
		},
	})

	// 2. Details paragraph
	if finding.Description != "" {
		paragraphs = append(paragraphs, map[string]any{
			"type": "paragraph",
			"content": []map[string]any{
				{"type": "text", "text": "Description: ", "marks": []map[string]any{{"type": "strong"}}},
				{"type": "text", "text": truncateRunes(finding.Description, jiraDescriptionMax)},
			},
		})
	}

	// 3. Location paragraph
	locStr := finding.Location.PrimaryPath()
	if locStr == "" && finding.Location.Code != nil {
		locStr = fmt.Sprintf("%s:%d", finding.Location.Code.FilePath, finding.Location.Code.StartLine)
	}
	if locStr != "" {
		paragraphs = append(paragraphs, map[string]any{
			"type": "paragraph",
			"content": []map[string]any{
				{"type": "text", "text": "Location: ", "marks": []map[string]any{{"type": "strong"}}},
				{"type": "text", "text": locStr},
			},
		})
	}

	// 4. Deep link paragraph
	if findingURL != "" {
		paragraphs = append(paragraphs, map[string]any{
			"type": "paragraph",
			"content": []map[string]any{
				{"type": "text", "text": "View in Rampart: ", "marks": []map[string]any{{"type": "strong"}}},
				{
					"type": "text",
					"text": findingURL,
					"marks": []map[string]any{
						{
							"type": "link",
							"attrs": map[string]string{
								"href": findingURL,
							},
						},
					},
				},
			},
		})
	}

	return map[string]any{
		"type":    "doc",
		"version": 1,
		"content": paragraphs,
	}
}

// GitHubTracker creates issues in GitHub repositories (D60, D66, D69).
type GitHubTracker struct {
	cfg        domain.GitHubConnectorConfig
	client     *SafeClient
	token      string
	publicURL  string
	tenantSlug string
	apiBaseURL string
}

// SetTenantSlug sets the tenant as the UI names it in links.
func (g *GitHubTracker) SetTenantSlug(s string) { g.tenantSlug = s }

// fenceFor returns a code fence longer than any run of backticks in s, so text from a scanner cannot close it.
func fenceFor(s string) string {
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := 3
	if longest >= n {
		n = longest + 1
	}
	return strings.Repeat("`", n)
}

// NewGitHubTracker creates a new GitHubTracker instance.
func NewGitHubTracker(cfg domain.GitHubConnectorConfig, client *SafeClient, secret []byte, publicURL string) (*GitHubTracker, error) {
	if cfg.Owner == "" || cfg.Repo == "" {
		return nil, errors.New("github tracker: owner and repo must be set")
	}
	token := strings.TrimSpace(string(secret))
	if token == "" {
		return nil, errors.New("github tracker: token is empty")
	}
	if client == nil {
		client = NewSafeClient()
	}

	return &GitHubTracker{
		cfg:        cfg,
		client:     client,
		token:      token,
		publicURL:  strings.TrimSuffix(publicURL, "/"),
		apiBaseURL: "https://api.github.com",
	}, nil
}

// SetAPIBaseURL overrides the GitHub API URL for GitHub Enterprise Server or tests.
func (g *GitHubTracker) SetAPIBaseURL(u string) {
	g.apiBaseURL = strings.TrimSuffix(u, "/")
}

// CreateIssue opens an issue in the target GitHub repository.
func (g *GitHubTracker) CreateIssue(ctx context.Context, finding *domain.Finding, appName string) (string, string, error) {
	if finding == nil {
		return "", "", errors.New("finding is nil")
	}

	title := truncateRunes(strings.NewReplacer("\r", " ", "\n", " ").Replace(fmt.Sprintf("[%s] %s in %s", strings.ToUpper(string(finding.Severity)), finding.Title, appName)), githubTitleMax)

	// Text from a scanner is untrusted. Written as markdown it could mention people (@name), link or load an image
	// from another host, or close another issue ("fixes #1"); inside a code block it is only text (D70).
	var bodyBuilder strings.Builder
	fmt.Fprintf(&bodyBuilder, "### Vulnerability Alert\n\n")
	fmt.Fprintf(&bodyBuilder, "- **Application**: %s\n", codeSpan(appName))
	fmt.Fprintf(&bodyBuilder, "- **Severity**: **%s**\n", strings.ToUpper(string(finding.Severity)))
	if finding.RuleID != "" {
		fmt.Fprintf(&bodyBuilder, "- **Rule**: %s\n", codeSpan(finding.RuleID))
	}
	locStr := finding.Location.PrimaryPath()
	if locStr == "" && finding.Location.Code != nil {
		locStr = fmt.Sprintf("%s:%d", finding.Location.Code.FilePath, finding.Location.Code.StartLine)
	}
	if locStr != "" {
		fmt.Fprintf(&bodyBuilder, "- **Location**: %s\n", codeSpan(locStr))
	}
	fmt.Fprintf(&bodyBuilder, "- **Finding**: %s\n", codeSpan(truncateRunes(finding.Title, 300)))
	if finding.Description != "" {
		desc := truncateRunes(finding.Description, githubBodyMax-2000)
		fence := fenceFor(desc)
		fmt.Fprintf(&bodyBuilder, "\n#### Description\n\n%s\n%s\n%s\n", fence, desc, fence)
	}
	if g.publicURL != "" && g.tenantSlug != "" {
		findingURL := fmt.Sprintf("%s/t/%s/findings/%s", g.publicURL, g.tenantSlug, finding.ID.String())
		fmt.Fprintf(&bodyBuilder, "\n[**View in Rampart**](%s)\n", findingURL)
	}

	labels := []string{"security", "rampart"}
	if len(g.cfg.DefaultLabels) > 0 {
		labels = append(labels, g.cfg.DefaultLabels...)
	}
	sevLabel := ""
	if len(g.cfg.SeverityToLabels) > 0 {
		sevLabel = g.cfg.SeverityToLabels[strings.ToLower(string(finding.Severity))]
	}
	if sevLabel != "" {
		labels = append(labels, sevLabel)
	} else {
		labels = append(labels, "severity:"+strings.ToLower(string(finding.Severity)))
	}
	labels = append(labels, FindingLabel(finding.ID))

	payload := map[string]any{
		"title":  title,
		"body":   bodyBuilder.String(),
		"labels": labels,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("github: marshaling issue payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/issues", g.apiBaseURL, g.cfg.Owner, g.cfg.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", "", fmt.Errorf("github: creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	// Not idempotent: one attempt, see JiraTracker.CreateIssue.
	respBody, status, _, err := g.client.DoWithRetry(ctx, req, false)
	if err != nil {
		return "", "", fmt.Errorf("github: issue creation failed: %w", err)
	}

	if status != http.StatusCreated {
		return "", "", fmt.Errorf("github: issue creation returned status %d", status)
	}

	var res struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return "", "", fmt.Errorf("github: unmarshaling response: %w", err)
	}

	ticketID := fmt.Sprintf("#%d", res.Number)
	return ticketID, res.HTMLURL, nil
}

// Check verifies GitHub repository write/push permissions (D60).
func (g *GitHubTracker) Check(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/repos/%s/%s", g.apiBaseURL, g.cfg.Owner, g.cfg.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("github check: creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	respBody, status, _, err := g.client.DoWithRetry(ctx, req, true)
	if err != nil {
		return fmt.Errorf("github check failed: %w", err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("github check returned status %d", status)
	}

	var repo struct {
		Permissions struct {
			Push bool `json:"push"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(respBody, &repo); err == nil {
		if !repo.Permissions.Push {
			return errors.New("github check: token lacks push/write permissions on repository")
		}
	}

	return nil
}

// DefaultTrackerResolver resolves trackers from registered Connectors in store.
type DefaultTrackerResolver struct {
	store          domainConnectorStore
	secretResolver SecretResolver
	client         *SafeClient
	publicURL      string
}

type domainConnectorStore interface {
	ListConnectors(ctx context.Context, tenantID uuid.UUID, types ...domain.ConnectorType) ([]domain.Connector, error)
}

// NewDefaultTrackerResolver builds a DefaultTrackerResolver.
func NewDefaultTrackerResolver(st domainConnectorStore, secretResolver SecretResolver, client *SafeClient, publicURL string) *DefaultTrackerResolver {
	if client == nil {
		client = NewSafeClient()
	}
	return &DefaultTrackerResolver{
		store:          st,
		secretResolver: secretResolver,
		client:         client,
		publicURL:      publicURL,
	}
}

// ResolveTracker returns the tracker of the tenant: the first tracker connector that is not known to be failing.
// A tracker whose secret cannot be read is an error, not a reason to use another connector: a ticket must not
// go to a project the owner did not choose.
func (r *DefaultTrackerResolver) ResolveTracker(ctx context.Context, tenantID uuid.UUID) (Tracker, error) {
	if r.store == nil {
		return nil, nil
	}
	connectors, err := r.store.ListConnectors(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	slug := ""
	if ts, ok := r.store.(interface {
		GetTenant(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)
	}); ok {
		if t, terr := ts.GetTenant(ctx, tenantID); terr == nil && t != nil {
			slug = t.Slug
		}
	}
	secret := func(conn domain.Connector, ref domain.SecretKeyRef) ([]byte, error) {
		if r.secretResolver == nil {
			return nil, fmt.Errorf("connector %q: no secret resolver", conn.Name)
		}
		b, serr := r.secretResolver.GetSecretMaterial(ctx, tenantID, domain.ConnectorSecretStorageKey(conn.Name, ref.Key))
		if serr != nil || len(b) == 0 {
			return nil, fmt.Errorf("connector %q: its credentials could not be read", conn.Name)
		}
		return b, nil
	}

	for _, conn := range connectors {
		if c := conn.GetCondition("Connected"); c != nil && c.Status == "False" {
			continue
		}
		switch conn.Type {
		case domain.ConnectorTypeJira:
			if conn.Spec.Jira == nil {
				continue
			}
			b, serr := secret(conn, conn.Spec.Jira.CredentialsSecretRef)
			if serr != nil {
				return nil, serr
			}
			t, terr := NewJiraTracker(*conn.Spec.Jira, r.client, b, r.publicURL)
			if terr != nil {
				return nil, terr
			}
			t.SetTenantSlug(slug)
			return t, nil

		case domain.ConnectorTypeGitHub:
			if conn.Spec.GitHub == nil {
				continue
			}
			b, serr := secret(conn, conn.Spec.GitHub.CredentialsSecretRef)
			if serr != nil {
				return nil, serr
			}
			t, terr := NewGitHubTracker(*conn.Spec.GitHub, r.client, b, r.publicURL)
			if terr != nil {
				return nil, terr
			}
			t.SetTenantSlug(slug)
			return t, nil
		}
	}

	return nil, nil
}

// codeSpan writes s as a markdown code span that s itself cannot end.
func codeSpan(s string) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		return fence + " " + s + " " + fence
	}
	return fence + s + fence
}
