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
}

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
	return nil
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
	if r.Provider == "github" && r.RepositoryID == "" && r.RepositoryOwnerID == "" {
		return fmt.Errorf("github trust rule must specify repositoryId or repositoryOwnerId")
	}
	if r.Provider == "gitlab" && r.ProjectID == "" && r.NamespaceID == "" {
		return fmt.Errorf("gitlab trust rule must specify projectId or namespaceId")
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
