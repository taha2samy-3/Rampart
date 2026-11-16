package mapping

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// MappingPackage describes a declarative parser integration (docs/19 §4).
type MappingPackage struct {
	APIVersion string      `yaml:"apiVersion"`
	Kind       string      `yaml:"kind"`
	Metadata   Metadata    `yaml:"metadata"`
	Spec       MappingSpec `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type MappingSpec struct {
	Kind        string            `yaml:"kind"`
	Runtime     string            `yaml:"runtime"`
	Version     string            `yaml:"version"`
	Description string            `yaml:"description"`
	Family      string            `yaml:"family"`
	Category    string            `yaml:"category"`
	Detect      DetectSpec        `yaml:"detect"`
	Input       InputSpec         `yaml:"input"`
	Map         MapSpec           `yaml:"map"`
	SeverityMap map[string]string `yaml:"severityMap"`
	Limits      LimitsSpec        `yaml:"limits"`
}

type DetectSpec struct {
	Filenames []string    `yaml:"filenames"`
	Probes    []ProbeSpec `yaml:"probes"`
}

type ProbeSpec struct {
	JSONHasKeys []string `yaml:"jsonHasKeys"`
}

type InputSpec struct {
	Format  string `yaml:"format"`  // json | jsonl
	Records string `yaml:"records"` // JSON path selector, e.g. $.dependencies[*].vulns[*]
	Parent  string `yaml:"parent"`  // parent variable name, e.g. dep
}

type MapSpec struct {
	RuleID       string `yaml:"ruleId"`
	Title        string `yaml:"title"`
	Description  string `yaml:"description"`
	Severity     string `yaml:"severity"`
	Confidence   string `yaml:"confidence"`
	VulnIDs      string `yaml:"vulnIds"`
	ToolRecordID string `yaml:"toolRecordId"`
	Remediation  string `yaml:"remediation"`
	// CWEs is a CEL list of weakness ids ("CWE-79", "79" or 79); CVSSVector a CVSS vector string; Category a CEL
	// expression for the category of one record (sast, sca, iac, secret, dast, ...), which wins over the package's
	// category. They fill the same fields the built-in parsers fill, so a finding of a declarative parser is scored,
	// grouped and shown like any other.
	CWEs       string       `yaml:"cwes"`
	CVSSVector string       `yaml:"cvssVector"`
	Category   string       `yaml:"category"`
	Location   LocationSpec `yaml:"location"`
}

type LocationSpec struct {
	File      string      `yaml:"file"`
	StartLine string      `yaml:"startLine"`
	Package   PackageSpec `yaml:"package"`
}

type PackageSpec struct {
	Purl             string `yaml:"purl"`
	Name             string `yaml:"name"`
	InstalledVersion string `yaml:"installedVersion"`
	FixedVersion     string `yaml:"fixedVersion"`
	ManifestPath     string `yaml:"manifestPath"` // the file that declares the package: part of the fingerprint
}

type LimitsSpec struct {
	MaxRecords int `yaml:"maxRecords"`
	MaxDepth   int `yaml:"maxDepth"`
}

// LoadMappingYAML parses and validates a mapping YAML definition.
func LoadMappingYAML(data []byte) (*MappingPackage, error) {
	var pkg MappingPackage
	if err := yaml.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("mapping: failed to unmarshal YAML: %w", err)
	}

	if pkg.Spec.Kind != "parser" || pkg.Spec.Runtime != "mapping" {
		return nil, fmt.Errorf("mapping: unsupported kind=%q, runtime=%q (expected kind: parser, runtime: mapping)", pkg.Spec.Kind, pkg.Spec.Runtime)
	}
	if pkg.Spec.Input.Records == "" {
		return nil, fmt.Errorf("mapping: input.records path is required")
	}
	if pkg.Spec.Limits.MaxRecords <= 0 {
		pkg.Spec.Limits.MaxRecords = 500000
	}
	if pkg.Spec.Limits.MaxDepth <= 0 {
		pkg.Spec.Limits.MaxDepth = 64
	}

	return &pkg, nil
}

// NewParserFromSpec builds the parser of an installed IntegrationPackage (kind parser, runtime mapping; docs/19
// §4, docs/16 D98) from its spec as JSON. Decoding is strict: a misspelled field is refused, not ignored, so a
// mapping cannot silently map nothing.
func NewParserFromSpec(name string, specJSON []byte) (*MappingParser, error) {
	var spec MappingSpec
	dec := yaml.NewDecoder(bytes.NewReader(specJSON)) // JSON is YAML; the struct carries yaml tags
	dec.KnownFields(true)
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	doc, err := yaml.Marshal(MappingPackage{APIVersion: "rampart.aspm.dev/v1alpha1", Kind: "IntegrationPackage", Metadata: Metadata{Name: name}, Spec: spec})
	if err != nil {
		return nil, err
	}
	if spec.Family == "" {
		return nil, fmt.Errorf("mapping: family is required: it names the scanner the findings come from")
	}
	if spec.Map.RuleID == "" || spec.Map.Title == "" {
		return nil, fmt.Errorf("mapping: map.ruleId and map.title are required")
	}
	if len(spec.Detect.Filenames) == 0 && len(spec.Detect.Probes) == 0 {
		return nil, fmt.Errorf("mapping: detect needs filenames or probes; without them the parser is only used by name")
	}
	return NewMappingParser(doc)
}
