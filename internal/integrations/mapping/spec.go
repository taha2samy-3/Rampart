package mapping

import (
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
	RuleID       string       `yaml:"ruleId"`
	Title        string       `yaml:"title"`
	Description  string       `yaml:"description"`
	Severity     string       `yaml:"severity"`
	Confidence   string       `yaml:"confidence"`
	VulnIDs      string       `yaml:"vulnIds"`
	ToolRecordID string       `yaml:"toolRecordId"`
	Remediation  string       `yaml:"remediation"`
	Location     LocationSpec `yaml:"location"`
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
