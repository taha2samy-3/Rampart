package domain

import (
	"time"

	"github.com/google/uuid"
)

// SBOMParserDetectSpec is the detection spec every parser uses (detect.go): one scale for every kind.
type SBOMParserDetectSpec = DetectSpec

// SBOMParserOptions controls optional features during SBOM parsing.
type SBOMParserOptions struct {
	BuildDependencyGraph bool `json:"buildDependencyGraph" yaml:"buildDependencyGraph"`
	// ExtractVulnerabilities makes a reader whose format carries vulnerability statements (a CycloneDX VDR) turn them into
	// findings, besides filling the inventory. Default false: an SBOM is assets, and what is found in it is the matcher's
	// work (D131). A format that states none (SPDX, Syft) is unaffected.
	ExtractVulnerabilities bool `json:"extractVulnerabilities" yaml:"extractVulnerabilities"`
}

// ClusterSBOMParser represents a cluster-wide SBOM parser CRD.
type ClusterSBOMParser struct {
	ID          uuid.UUID            `json:"id"`
	Name        string               `json:"name"`
	Format      string               `json:"format"`
	Runtime     string               `json:"runtime"` // wasm, lua, native
	Description string               `json:"description,omitempty"`
	SourceOCI   string               `json:"source_oci,omitempty"`
	SourceFile  string               `json:"source_file,omitempty"`
	Detect      SBOMParserDetectSpec `json:"detect"`
	Options     SBOMParserOptions    `json:"options"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
}

// SBOMParser represents a tenant-scoped SBOM parser CRD.
type SBOMParser struct {
	ID          uuid.UUID            `json:"id"`
	TenantID    uuid.UUID            `json:"tenant_id"`
	Name        string               `json:"name"`
	Format      string               `json:"format"`
	Runtime     string               `json:"runtime"` // wasm, lua, native
	Description string               `json:"description,omitempty"`
	SourceOCI   string               `json:"source_oci,omitempty"`
	SourceFile  string               `json:"source_file,omitempty"`
	Detect      SBOMParserDetectSpec `json:"detect"`
	Options     SBOMParserOptions    `json:"options"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
}
