package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// IngestionPolicy configures the ingestion and reimport behaviors for a ScanSource (docs/04, D22).
type IngestionPolicy struct {
	MinimumSeverity  string   `json:"minimumSeverity,omitempty"`
	CloseOldFindings *bool    `json:"closeOldFindings,omitempty"`
	CloseScope       string   `json:"closeScope,omitempty"`
	DoNotReactivate  *bool    `json:"doNotReactivate,omitempty"`
	FieldMerge       string   `json:"fieldMerge,omitempty"`
	MaxClosePercent  *float64 `json:"maxClosePercent,omitempty"`
	MinHeldClose     *int     `json:"minHeldClose,omitempty"`
	MaxReportBytes   *int64   `json:"maxReportBytes,omitempty"`
	AcceptedFormats  []string `json:"acceptedFormats,omitempty"`
	// TrackedRefs are the branches (or tags, or environments by name) whose runs change the inventory (docs/04, D10): an
	// exact name, a prefix ending in * ("release/*", "hotfix-*"), or * for every ref. Any other ref is ephemeral and
	// feeds only the CI gate. Empty: the defaults (main, master, default, release/*, prod, production). A pull request
	// is always ephemeral, whatever is listed.
	TrackedRefs []string `json:"trackedRefs,omitempty"`
}

// MaxTrackedRefs bounds the list, so a source cannot make every upload walk a long one.
const MaxTrackedRefs = 50

// Validate checks that policy values fall within allowed ranges.
func (p *IngestionPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if p.MaxClosePercent != nil {
		if *p.MaxClosePercent < 0 || *p.MaxClosePercent > 100 {
			return fmt.Errorf("maxClosePercent must be between 0 and 100, got %f", *p.MaxClosePercent)
		}
	}
	if p.MinHeldClose != nil {
		if *p.MinHeldClose < 0 {
			return fmt.Errorf("minHeldClose must be non-negative, got %d", *p.MinHeldClose)
		}
	}
	return ValidateTrackedRefs(p.TrackedRefs)
}

// ValidateTrackedRefs refuses a list that could not mean what the author meant: an empty or oversized name, a space or
// control character in it (a branch name has none), a * anywhere but the end (it would be read as a literal), more
// than MaxTrackedRefs names.
func ValidateTrackedRefs(refs []string) error {
	if len(refs) > MaxTrackedRefs {
		return fmt.Errorf("trackedRefs has at most %d entries, got %d", MaxTrackedRefs, len(refs))
	}
	for _, r := range refs {
		if r == "" || len(r) > 255 {
			return fmt.Errorf("trackedRefs: %q is empty or longer than 255 characters", r)
		}
		for i, c := range r {
			if c <= ' ' || c == 0x7f {
				return fmt.Errorf("trackedRefs: %q has a space or a control character", r)
			}
			if c == '*' && i != len(r)-1 {
				return fmt.Errorf("trackedRefs: %q has a * that is not the last character; only a trailing * is a wildcard", r)
			}
		}
	}
	return nil
}

// WithTrackedRefs returns the policy with the refs of spec.trackedRefs set (they sit beside ingestionPolicy in a
// ScanSource, as in docs/04, and are stored with it). It does not change the policy it is given.
func WithTrackedRefs(p *IngestionPolicy, refs []string) *IngestionPolicy {
	if len(refs) == 0 {
		return p
	}
	out := IngestionPolicy{}
	if p != nil {
		out = *p
	}
	out.TrackedRefs = append([]string(nil), refs...)
	return &out
}

// HeldClose records a mass-close held by the safety guard for human review (D22, Milestone 3.3).
type HeldClose struct {
	ID          uuid.UUID   `json:"id"`
	TenantID    uuid.UUID   `json:"tenant_id"`
	IngestRunID uuid.UUID   `json:"ingest_run_id"`
	Scope       CloseScope  `json:"scope"`
	FindingIDs  []uuid.UUID `json:"finding_ids"`
	CreatedAt   time.Time   `json:"created_at"`
	DecidedBy   string      `json:"decided_by,omitempty"`
	Decision    string      `json:"decision,omitempty"` // "confirmed" | "discarded" | ""
	DecidedAt   *time.Time  `json:"decided_at,omitempty"`
}

const (
	HeldCloseDecisionConfirmed = "confirmed"
	HeldCloseDecisionDiscarded = "discarded"
	// HeldCloseDecisionSuperseded: a newer run of the same scope completed, so the hold no longer describes the
	// scope and is closed without action (D83).
	HeldCloseDecisionSuperseded = "superseded"
)

// TrustRule defines CI OIDC federation rules for a ScanSource (D22).
type TrustRule struct {
	Issuer            string `json:"issuer"`
	Provider          string `json:"provider"`
	RepositoryID      string `json:"repositoryId,omitempty"`
	RepositoryOwnerID string `json:"repositoryOwnerId,omitempty"`
	ProjectID         string `json:"projectId,omitempty"`
	NamespaceID       string `json:"namespaceId,omitempty"`
	Repository        string `json:"repository,omitempty"`
}

// Validate checks that the trust rule contains valid and complete identifiers.
func (r *TrustRule) Validate() error {
	if r.Issuer == "" {
		return fmt.Errorf("issuer cannot be empty")
	}
	if r.Provider != "github" && r.Provider != "gitlab" {
		return fmt.Errorf("provider must be 'github' or 'gitlab', got %q", r.Provider)
	}
	if r.Provider == "github" && (r.RepositoryID == "" || r.RepositoryOwnerID == "") {
		return fmt.Errorf("github trust rule must specify both repositoryId and repositoryOwnerId (D22)")
	}
	if r.Provider == "gitlab" && (r.ProjectID == "" || r.NamespaceID == "") {
		return fmt.Errorf("gitlab trust rule must specify both projectId and namespaceId (D22)")
	}
	return nil
}

// TrustRuleRecord represents a stored trust rule linked to a ScanSource.
type TrustRuleRecord struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	ScanSourceID uuid.UUID `json:"scan_source_id"`
	Rule         TrustRule `json:"rule"`
	CreatedAt    time.Time `json:"created_at"`
}
