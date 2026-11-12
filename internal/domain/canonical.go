package domain

import (
	"github.com/google/uuid"
)

// IssueDraft is the canonical ticket draft document sent to Tracker integrations (docs/19 §3, §6).
type IssueDraft struct {
	Title        string              `json:"title"`
	Body         string              `json:"body,omitempty"`
	Priority     string              `json:"priority,omitempty"`
	Comment      string              `json:"comment,omitempty"`
	Labels       []string            `json:"labels,omitempty"`
	Assignee     string              `json:"assignee,omitempty"`
	Component    string              `json:"component,omitempty"`
	ProjectID    string              `json:"project_id,omitempty"`
	TrackerID    string              `json:"tracker_id,omitempty"`
	CustomFields map[string]any      `json:"custom_fields,omitempty"`
	FindingIDs   []uuid.UUID         `json:"finding_ids,omitempty"`
	Findings     []IssueDraftFinding `json:"findings,omitempty"`
}

// IssueDraftFinding summarizes a finding attached to an IssueDraft.
type IssueDraftFinding struct {
	ID       uuid.UUID `json:"id"`
	Title    string    `json:"title"`
	Severity string    `json:"severity,omitempty"`
	RuleID   string    `json:"rule_id,omitempty"`
	Scanner  string    `json:"scanner,omitempty"`
	URL      string    `json:"url,omitempty"`
}

// CanonicalMessage is the canonical notification message document sent to Notifier integrations (docs/19 §3, §6).
type CanonicalMessage struct {
	Title    string         `json:"title"`
	Summary  string         `json:"summary,omitempty"`
	Body     string         `json:"body,omitempty"`
	URL      string         `json:"url,omitempty"`
	Severity string         `json:"severity,omitempty"`
	Type     string         `json:"type,omitempty"`
	Items    []MessageItem  `json:"items,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// MessageItem is one item in a message digest.
type MessageItem struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title"`
	Severity string `json:"severity,omitempty"`
	Band     string `json:"band,omitempty"`
	App      string `json:"app,omitempty"`
	Link     string `json:"link,omitempty"`
}

// UpstreamProject is the canonical discovered project document for Source integrations (docs/19 §3, §5).
type UpstreamProject struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Key           string         `json:"key,omitempty"`
	URL           string         `json:"url,omitempty"`
	DefaultBranch string         `json:"default_branch,omitempty"`
	Description   string         `json:"description,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}
