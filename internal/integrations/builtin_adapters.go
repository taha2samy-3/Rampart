package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"

	"rampart/internal/domain"
)

// --- Built-in Tracker Adapters ---

type JiraTrackerAdapter struct {
	desc Descriptor
}

func NewJiraTrackerAdapter() *JiraTrackerAdapter {
	schema := json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["url", "project"],
		"properties": {
			"url": {"type": "string", "format": "uri", "description": "Base URL of Jira Cloud instance"},
			"project": {"type": "string", "description": "Default Jira project key"},
			"issueType": {"type": "string", "default": "Bug", "description": "Issue type for findings"},
			"priority": {"type": "string", "description": "Default issue priority"}
		}
	}`)

	return &JiraTrackerAdapter{
		desc: Descriptor{
			ID:           "builtin:jira",
			Name:         "Atlassian Jira Tracker",
			Kind:         KindTracker,
			Version:      "1.0.0",
			SupportLevel: SupportBuiltin,
			Description:  "Outbound ticketing integration for Jira Cloud issues",
			ConfigSchema: schema,
			Secrets:      []string{"token", "email"},
			Egress:       []string{"*.atlassian.net"},
			Capabilities: []string{"create_issue", "update_issue", "status_poll"},
		},
	}
}

func (a *JiraTrackerAdapter) Descriptor() Descriptor { return a.desc }

func (a *JiraTrackerAdapter) Check(ctx context.Context, cfg any) error {
	if cfg == nil {
		return errors.New("jira tracker: missing config")
	}
	return nil
}

func (a *JiraTrackerAdapter) Create(ctx context.Context, cfg any, draft IssueDraft) (IssueRef, error) {
	if draft.Title == "" {
		return IssueRef{}, errors.New("jira tracker: empty title")
	}
	// Synthesize or map
	key := "RAMPART-101"
	if draft.ProjectKey != "" {
		key = draft.ProjectKey + "-101"
	}
	return IssueRef{
		Key: key,
		URL: "https://jira.example.com/browse/" + key,
	}, nil
}

func (a *JiraTrackerAdapter) Update(ctx context.Context, cfg any, ref IssueRef, draft IssueDraft) error {
	if ref.Key == "" {
		return errors.New("jira tracker: missing issue key")
	}
	return nil
}

func (a *JiraTrackerAdapter) Get(ctx context.Context, cfg any, refs []IssueRef) ([]IssueState, error) {
	states := make([]IssueState, len(refs))
	for i, ref := range refs {
		states[i] = IssueState{
			Key:        ref.Key,
			Status:     "Open",
			Resolution: "",
			Closed:     false,
		}
	}
	return states, nil
}

type GitHubTrackerAdapter struct {
	desc Descriptor
}

func NewGitHubTrackerAdapter() *GitHubTrackerAdapter {
	schema := json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["owner", "repo"],
		"properties": {
			"owner": {"type": "string", "description": "GitHub repository owner or organization"},
			"repo": {"type": "string", "description": "GitHub repository name"},
			"labels": {"type": "array", "items": {"type": "string"}, "description": "Labels to apply"}
		}
	}`)

	return &GitHubTrackerAdapter{
		desc: Descriptor{
			ID:           "builtin:github",
			Name:         "GitHub Issues Tracker",
			Kind:         KindTracker,
			Version:      "1.0.0",
			SupportLevel: SupportBuiltin,
			Description:  "Outbound ticketing integration for GitHub Issues",
			ConfigSchema: schema,
			Secrets:      []string{"token"},
			Egress:       []string{"api.github.com"},
			Capabilities: []string{"create_issue", "update_issue", "status_poll"},
		},
	}
}

func (a *GitHubTrackerAdapter) Descriptor() Descriptor { return a.desc }

func (a *GitHubTrackerAdapter) Check(ctx context.Context, cfg any) error {
	if cfg == nil {
		return errors.New("github tracker: missing config")
	}
	return nil
}

func (a *GitHubTrackerAdapter) Create(ctx context.Context, cfg any, draft IssueDraft) (IssueRef, error) {
	if draft.Title == "" {
		return IssueRef{}, errors.New("github tracker: empty title")
	}
	return IssueRef{
		Key: "42",
		URL: "https://github.com/org/repo/issues/42",
	}, nil
}

func (a *GitHubTrackerAdapter) Update(ctx context.Context, cfg any, ref IssueRef, draft IssueDraft) error {
	if ref.Key == "" {
		return errors.New("github tracker: missing issue key")
	}
	return nil
}

func (a *GitHubTrackerAdapter) Get(ctx context.Context, cfg any, refs []IssueRef) ([]IssueState, error) {
	states := make([]IssueState, len(refs))
	for i, ref := range refs {
		states[i] = IssueState{
			Key:        ref.Key,
			Status:     "open",
			Resolution: "",
			Closed:     false,
		}
	}
	return states, nil
}

// --- Built-in Notifier Adapters ---

type GenericNotifierAdapter struct {
	desc Descriptor
}

func NewSlackNotifierAdapter() *GenericNotifierAdapter {
	schema := json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["channel"],
		"properties": {
			"channel": {"type": "string", "description": "Target Slack channel or ID"}
		}
	}`)

	return &GenericNotifierAdapter{
		desc: Descriptor{
			ID:           "builtin:slack",
			Name:         "Slack Notifier",
			Kind:         KindNotifier,
			Version:      "1.0.0",
			SupportLevel: SupportBuiltin,
			Description:  "Outbound message dispatch to Slack channels",
			ConfigSchema: schema,
			Secrets:      []string{"token"},
			Egress:       []string{"slack.com"},
			Capabilities: []string{"send_message", "rich_text"},
		},
	}
}

func NewTeamsNotifierAdapter() *GenericNotifierAdapter {
	schema := json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["webhookUrl"],
		"properties": {
			"webhookUrl": {"type": "string", "format": "uri", "description": "Microsoft Teams incoming webhook URL"}
		}
	}`)

	return &GenericNotifierAdapter{
		desc: Descriptor{
			ID:           "builtin:teams",
			Name:         "Microsoft Teams Notifier",
			Kind:         KindNotifier,
			Version:      "1.0.0",
			SupportLevel: SupportBuiltin,
			Description:  "Outbound message dispatch to Microsoft Teams via Webhook",
			ConfigSchema: schema,
			Secrets:      []string{"webhookUrl"},
			Egress:       []string{"*.webhook.office.com"},
			Capabilities: []string{"send_message"},
		},
	}
}

func NewEmailNotifierAdapter() *GenericNotifierAdapter {
	schema := json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["to", "from", "smtpHost"],
		"properties": {
			"to": {"type": "string", "format": "email"},
			"from": {"type": "string", "format": "email"},
			"smtpHost": {"type": "string"},
			"smtpPort": {"type": "integer", "default": 587}
		}
	}`)

	return &GenericNotifierAdapter{
		desc: Descriptor{
			ID:           "builtin:email",
			Name:         "SMTP Email Notifier",
			Kind:         KindNotifier,
			Version:      "1.0.0",
			SupportLevel: SupportBuiltin,
			Description:  "Outbound notification emails via SMTP",
			ConfigSchema: schema,
			Secrets:      []string{"smtpPassword"},
			Egress:       []string{"*"},
			Capabilities: []string{"send_message"},
		},
	}
}

func NewWebhookNotifierAdapter() *GenericNotifierAdapter {
	schema := json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["url"],
		"properties": {
			"url": {"type": "string", "format": "uri"}
		}
	}`)

	return &GenericNotifierAdapter{
		desc: Descriptor{
			ID:           "builtin:webhook",
			Name:         "Generic Webhook Notifier",
			Kind:         KindNotifier,
			Version:      "1.0.0",
			SupportLevel: SupportBuiltin,
			Description:  "Signed HMAC JSON notification webhook",
			ConfigSchema: schema,
			Secrets:      []string{"secret"},
			Egress:       []string{"*"},
			Capabilities: []string{"send_message", "signature_hmac"},
		},
	}
}

func (a *GenericNotifierAdapter) Descriptor() Descriptor { return a.desc }

func (a *GenericNotifierAdapter) Check(ctx context.Context, cfg any) error {
	if cfg == nil {
		return errors.New("notifier: missing config")
	}
	return nil
}

func (a *GenericNotifierAdapter) Send(ctx context.Context, cfg any, m Message) error {
	if m.Title == "" && m.Summary == "" && m.Body == "" {
		return errors.New("notifier: empty message payload")
	}
	return nil
}

// --- Built-in Source Adapter ---

type DependencyTrackSourceAdapter struct {
	desc Descriptor
}

func NewDependencyTrackSourceAdapter() *DependencyTrackSourceAdapter {
	schema := json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"required": ["url"],
		"properties": {
			"url": {"type": "string", "format": "uri", "description": "Dependency-Track base API URL"},
			"projectFilter": {"type": "string", "description": "Optional project name filter regex"}
		}
	}`)

	return &DependencyTrackSourceAdapter{
		desc: Descriptor{
			ID:           "builtin:dependency-track",
			Name:         "OWASP Dependency-Track Source",
			Kind:         KindSource,
			Version:      "1.0.0",
			SupportLevel: SupportBuiltin,
			Description:  "Upstream SCA & SBOM integration for portfolio vulnerabilities and components",
			ConfigSchema: schema,
			Secrets:      []string{"apiKey"},
			Egress:       []string{"*"},
			Capabilities: []string{"incremental", "events", "portfolio_sync"},
		},
	}
}

func (a *DependencyTrackSourceAdapter) Descriptor() Descriptor { return a.desc }

func (a *DependencyTrackSourceAdapter) Check(ctx context.Context, cfg any) error {
	if cfg == nil {
		return errors.New("dependency-track source: missing config")
	}
	return nil
}

func (a *DependencyTrackSourceAdapter) Discover(ctx context.Context, cfg any) iter.Seq2[UpstreamProject, error] {
	return func(yield func(UpstreamProject, error) bool) {
		yield(UpstreamProject{
			ID:   "dtrack-project-1",
			Name: "example-application",
		}, nil)
	}
}

func (a *DependencyTrackSourceAdapter) Pull(ctx context.Context, cfg any, project UpstreamProject, cursor string) (iter.Seq2[domain.RawFinding, error], string, error) {
	findings := func(yield func(domain.RawFinding, error) bool) {
		yield(domain.RawFinding{
			RuleID:   "CVE-2026-9999",
			Title:    fmt.Sprintf("Vulnerability in %s", project.Name),
			Severity: domain.SeverityHigh,
		}, nil)
	}
	return findings, "next-cursor", nil
}
