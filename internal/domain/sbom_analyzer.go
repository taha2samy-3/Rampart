package domain

import (
	"time"

	"github.com/google/uuid"
)

// SBOMAnalyzerRules specifies confidence thresholds and matching flags.
type SBOMAnalyzerRules struct {
	MinConfidence     float64 `json:"minConfidence" yaml:"minConfidence"`
	IncludePreRelease bool    `json:"includePreRelease" yaml:"includePreRelease"`
	MatchDirectOnly   bool    `json:"matchDirectOnly" yaml:"matchDirectOnly"`
}

// SBOMAnalyzerSources specifies enabled vulnerability feed sources.
type SBOMAnalyzerSources struct {
	OSV  bool `json:"osv" yaml:"osv"`
	GHSA bool `json:"ghsa" yaml:"ghsa"`
	NVD  bool `json:"nvd" yaml:"nvd"`
}

// ClusterSBOMAnalyzer represents a cluster-wide native SBOM vulnerability analyzer CRD.
type ClusterSBOMAnalyzer struct {
	ID          uuid.UUID           `json:"id"`
	Name        string              `json:"name"`
	Enabled     bool                `json:"enabled"`
	Engine      string              `json:"engine"` // hybrid, osv, in-process, advisory-db
	Description string              `json:"description,omitempty"`
	Rules       SBOMAnalyzerRules   `json:"rules"`
	Sources     SBOMAnalyzerSources `json:"sources"`
	Schedule    string              `json:"schedule,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// SBOMAnalyzer represents a tenant-scoped SBOM analyzer CRD.
type SBOMAnalyzer struct {
	ID          uuid.UUID           `json:"id"`
	TenantID    uuid.UUID           `json:"tenant_id"`
	Name        string              `json:"name"`
	Enabled     bool                `json:"enabled"`
	Engine      string              `json:"engine"`
	Description string              `json:"description,omitempty"`
	Rules       SBOMAnalyzerRules   `json:"rules"`
	Sources     SBOMAnalyzerSources `json:"sources"`
	Schedule    string              `json:"schedule,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}
