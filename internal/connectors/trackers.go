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

	proj := j.cfg.DefaultProject
	if proj == "" {
		proj = "SEC"
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

	findingURL := ""
	if j.publicURL != "" {
		findingURL = fmt.Sprintf("%s/t/%s/findings/%s", j.publicURL, finding.TenantID.String(), finding.ID.String())
	}

	adfDesc := BuildJiraADF(finding, appName, findingURL)

	labels := []string{
		"rampart",
		"security",
		"severity-" + strings.ToLower(string(finding.Severity)),
		"rampart-finding-" + finding.ID.String(),
	}

	fields := map[string]any{
		"project": map[string]string{
			"key": proj,
		},
		"summary":     fmt.Sprintf("[%s] %s in %s", strings.ToUpper(string(finding.Severity)), finding.Title, appName),
		"description": adfDesc,
		"issuetype": map[string]string{
			"name": issueType,
		},
		"priority": map[string]string{
			"name": priorityName,
		},
		"labels": labels,
	}

	// Apply any custom fields configured
	for k, v := range j.cfg.CustomFields {
		fields[k] = v
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

	respBody, status, _, err := j.client.DoWithRetry(ctx, req, true)
	if err != nil {
		return "", "", fmt.Errorf("jira: issue creation failed: %w", err)
	}

	if status != http.StatusCreated && status != http.StatusOK {
		return "", "", fmt.Errorf("jira: issue creation returned status %d: %s", status, string(respBody))
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

// Check verifies Jira connectivity and credentials.
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
				{"type": "text", "text": finding.Description},
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
	apiBaseURL string
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

	title := fmt.Sprintf("[%s] %s in %s", strings.ToUpper(string(finding.Severity)), finding.Title, appName)

	var bodyBuilder strings.Builder
	fmt.Fprintf(&bodyBuilder, "### Vulnerability Alert: %s\n\n", finding.Title)
	fmt.Fprintf(&bodyBuilder, "- **Application**: `%s`\n", appName)
	fmt.Fprintf(&bodyBuilder, "- **Severity**: **%s**\n", strings.ToUpper(string(finding.Severity)))
	if finding.RuleID != "" {
		fmt.Fprintf(&bodyBuilder, "- **Rule**: `%s`\n", finding.RuleID)
	}
	locStr := finding.Location.PrimaryPath()
	if locStr == "" && finding.Location.Code != nil {
		locStr = fmt.Sprintf("%s:%d", finding.Location.Code.FilePath, finding.Location.Code.StartLine)
	}
	if locStr != "" {
		fmt.Fprintf(&bodyBuilder, "- **Location**: `%s`\n", locStr)
	}
	if finding.Description != "" {
		fmt.Fprintf(&bodyBuilder, "\n#### Description\n%s\n", finding.Description)
	}
	if g.publicURL != "" {
		findingURL := fmt.Sprintf("%s/t/%s/findings/%s", g.publicURL, finding.TenantID.String(), finding.ID.String())
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
	labels = append(labels, "rampart-finding-"+finding.ID.String())

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

	respBody, status, _, err := g.client.DoWithRetry(ctx, req, true)
	if err != nil {
		return "", "", fmt.Errorf("github: issue creation failed: %w", err)
	}

	if status != http.StatusCreated {
		return "", "", fmt.Errorf("github: issue creation returned status %d: %s", status, string(respBody))
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
		return fmt.Errorf("github check returned status %d: %s", status, string(respBody))
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

// ResolveTracker returns the first active tracker connector configured for tenant.
func (r *DefaultTrackerResolver) ResolveTracker(ctx context.Context, tenantID uuid.UUID) (Tracker, error) {
	if r.store == nil {
		return nil, nil
	}
	connectors, err := r.store.ListConnectors(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	for _, conn := range connectors {
		if !conn.IsConnected() && conn.GetCondition("Connected") != nil && conn.GetCondition("Connected").Status == "False" {
			continue
		}

		switch conn.Type {
		case domain.ConnectorTypeJira:
			if conn.Spec.Jira == nil {
				continue
			}
			secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.Jira.CredentialsSecretRef.Key)
			if conn.Spec.Jira.CredentialsSecretRef.Key == "" {
				secKey = domain.ConnectorSecretStorageKey(conn.Name, "apiToken")
			}
			var secretBytes []byte
			if r.secretResolver != nil {
				secretBytes, _ = r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey)
			}
			if len(secretBytes) == 0 {
				continue
			}
			return NewJiraTracker(*conn.Spec.Jira, r.client, secretBytes, r.publicURL)

		case domain.ConnectorTypeGitHub:
			if conn.Spec.GitHub == nil {
				continue
			}
			secKey := domain.ConnectorSecretStorageKey(conn.Name, conn.Spec.GitHub.CredentialsSecretRef.Key)
			var secretBytes []byte
			if r.secretResolver != nil {
				secretBytes, _ = r.secretResolver.GetSecretMaterial(ctx, tenantID, secKey)
			}
			if len(secretBytes) == 0 {
				continue
			}
			return NewGitHubTracker(*conn.Spec.GitHub, r.client, secretBytes, r.publicURL)
		}
	}

	return nil, nil
}
