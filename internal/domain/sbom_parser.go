package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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
	// ExtractVEX extracts exploitability assertions (VEX statements: status, justification, impact, action) from the document
	// (CycloneDX VEX/VDR, OpenVEX, or CSAF) and emits them in canonical format to suppress non-exploitable findings in quality gates and dashboards.
	ExtractVEX bool `json:"extractVEX" yaml:"extractVEX"`
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

// SBOMParserNamePrefix starts the name of every ClusterSBOMParser. SBOM readers and report parsers are kept in one table,
// keyed by kind and name, so the two kinds of resource must never share a name: a ClusterParser may not use this prefix
// and a ClusterSBOMParser must.
const SBOMParserNamePrefix = "sbom-"

var sbomFormatRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidateClusterSBOMParserSpec checks the spec of a ClusterSBOMParser resource. Only a WASM reader is built for SBOMs, so
// another runtime is refused here with its reason instead of being stored and failing at the first upload.
func ValidateClusterSBOMParserSpec(name string, spec []byte) error {
	if !strings.HasPrefix(name, SBOMParserNamePrefix) || len(name) == len(SBOMParserNamePrefix) {
		return fmt.Errorf("name %q: a ClusterSBOMParser name starts with %q (for example sbom-spdx), so it never shares a name with a ClusterParser", name, SBOMParserNamePrefix)
	}
	var s struct {
		Format  string `json:"format"`
		Runtime string `json:"runtime"`
	}
	if err := json.Unmarshal(spec, &s); err != nil {
		return fmt.Errorf("spec is not a valid ClusterSBOMParser spec: %w", err)
	}
	if !sbomFormatRe.MatchString(s.Format) {
		return fmt.Errorf("format %q: lower-case letters, digits and . _ -, starting with a letter or digit (for example spdx)", s.Format)
	}
	if s.Runtime != "wasm" {
		return fmt.Errorf("runtime %q: only wasm is built for an SBOM reader", s.Runtime)
	}
	return nil
}

// StoredSBOMParser is the form a ClusterSBOMParser is kept in: the whole resource, with its kind, so that the server tells an
// SBOM reader from a report parser by what is stored and not by its name. A spec that is not JSON is returned as it is (it
// is kept with the reason it was refused).
func StoredSBOMParser(name string, spec []byte) []byte {
	if !json.Valid(spec) {
		return spec
	}
	doc, err := json.Marshal(map[string]any{
		"apiVersion": "rampart.aspm.dev/v1alpha1",
		"kind":       "ClusterSBOMParser",
		"metadata":   map[string]string{"name": name},
		"spec":       json.RawMessage(spec),
	})
	if err != nil {
		return spec
	}
	return doc
}
