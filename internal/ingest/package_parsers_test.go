package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/integrations/declarative"
)

// pipAuditSpec is docs/19 §4's example as an IntegrationPackage spec, the JSON the operator stores.
const pipAuditSpec = `{
  "kind": "parser", "runtime": "mapping", "version": "1.0.0", "family": "pip-audit", "category": "sca",
  "detect": {"filenames": ["pip-audit*.json"], "probes": [{"jsonHasKeys": ["dependencies", "fix_versions"]}]},
  "input": {"format": "json", "records": "$.dependencies[*].vulns[*]", "parent": "dep"},
  "map": {
    "ruleId": "rec.id",
    "title": "rec.id + \" in \" + dep.name",
    "vulnIds": "[rec.id]",
    "severity": "has(rec.severity) ? rec.severity : \"MODERATE\"",
    "location": {"package": {"name": "dep.name", "installedVersion": "dep.version",
      "purl": "\"pkg:pypi/\" + dep.name + \"@\" + dep.version"}}
  },
  "severityMap": {"HIGH": "high", "MODERATE": "medium"}
}`

const pipAuditReport = `{"dependencies":[{"name":"jinja2","version":"3.1.2","vulns":[{"id":"GHSA-h5c8-rqwp-cp95","fix_versions":["3.1.3"],"severity":"HIGH"}]},
{"name":"requests","version":"2.31.0","vulns":[{"id":"CVE-2024-35195","fix_versions":["2.32.0"]}]}]}`

// TestParserPackage covers D98: a parser installed as a package is validated like any package, parses its own
// tenant's reports by name and by detection, never another tenant's, and cannot take a built-in's name.
func TestParserPackage(t *testing.T) {
	ctx := context.Background()
	if _, err := declarative.Parse([]byte(pipAuditSpec)); err != nil {
		t.Fatalf("the docs/19 example must validate: %v", err)
	}
	for name, spec := range map[string]string{
		"a misspelled field":    strings.Replace(pipAuditSpec, `"severityMap"`, `"severityMapp"`, 1),
		"a CEL error":           strings.Replace(pipAuditSpec, `"ruleId": "rec.id"`, `"ruleId": "rec.id +"`, 1),
		"no title":              strings.Replace(pipAuditSpec, `"title": "rec.id + \" in \" + dep.name",`, ``, 1),
		"runtime declarative":   strings.Replace(pipAuditSpec, `"runtime": "mapping"`, `"runtime": "declarative"`, 1),
		"runtime wasm":          strings.Replace(pipAuditSpec, `"runtime": "mapping"`, `"runtime": "wasm"`, 1),
		"no version":            strings.Replace(pipAuditSpec, `"version": "1.0.0",`, ``, 1),
		"no detection, no name": strings.Replace(pipAuditSpec, `"detect": {"filenames": ["pip-audit*.json"], "probes": [{"jsonHasKeys": ["dependencies", "fix_versions"]}]},`, ``, 1),
	} {
		if _, err := declarative.Parse([]byte(spec)); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}

	st := NewMemoryStore()
	tenantA, tenantB := uuid.New(), uuid.New()
	_ = st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: tenantA, Name: "pip-audit", Kind: "parser", Runtime: "mapping", Version: "1.0.0", Spec: []byte(pipAuditSpec)})
	_ = st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: tenantA, Name: "broken", Kind: "parser", Runtime: "mapping", Version: "1.0.0", Spec: []byte(`{}`), Error: "invalid"})
	_ = st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: tenantA, Name: "trivy", Kind: "parser", Runtime: "mapping", Version: "1.0.0", Spec: []byte(strings.Replace(pipAuditSpec, `"pip-audit"`, `"fake-trivy"`, 1))})
	set := newParserSet(integrations.DefaultRegistry(), st)

	p := set.byName(ctx, tenantA, "pip-audit")
	if p == nil || p.Descriptor().ID != "mapping:pip-audit" {
		t.Fatalf("by name: got %v", p)
	}
	if p, score := set.detect(ctx, tenantA, []byte(pipAuditReport), "", ""); p == nil || p.Descriptor().ID != "mapping:pip-audit" || score < 40 {
		t.Fatalf("by detection: got %v (%d)", p, score)
	}
	if set.byName(ctx, tenantB, "pip-audit") != nil {
		t.Fatal("tenant B must not reach tenant A's package")
	}
	if p, score := set.detect(ctx, tenantB, []byte(pipAuditReport), "", ""); p != nil && score >= 40 && strings.HasPrefix(p.Descriptor().ID, "mapping:") {
		t.Fatalf("tenant B detected tenant A's package: %s", p.Descriptor().ID)
	}
	if p := set.byName(ctx, tenantA, "trivy"); p == nil || p.Descriptor().ID != "cluster:trivy" {
		t.Fatalf("a cluster parser owns its name; got %v", p)
	}
	if set.byName(ctx, tenantA, "broken") != nil {
		t.Fatal("a package with an error is not used")
	}

	var got []domain.RawFinding
	for f, err := range p.Parse(ctx, bytes.NewReader([]byte(pipAuditReport)), domain.ParseContext{}) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, f)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d", len(got))
	}
	if got[0].Severity != domain.SeverityHigh || got[1].Severity != domain.SeverityMedium || got[0].ScannerFamily != "pip-audit" {
		b, _ := json.Marshal(got)
		t.Fatalf("mapped wrongly: %s", b)
	}
	if got[0].Location.Package == nil || got[0].Location.Package.Purl != "pkg:pypi/jinja2@3.1.2" {
		t.Fatalf("package location: %+v", got[0].Location.Package)
	}
}

func TestClusterAndLuaParsers(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	tenantA := uuid.New()
	tenantB := uuid.New()

	// 1. Save a ClusterParser with runtime: native (wrapping native sarif)
	sarifClusterYAML := `
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterParser
metadata:
  name: sarif
spec:
  version: "2.1.0"
  family: sarif
  category: sast
  runtime: native
  native: sarif
`
	st.SaveClusterParser("sarif", []byte(sarifClusterYAML))

	// 2. Save a ClusterParser with runtime: lua
	luaClusterYAML := `
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterParser
metadata:
  name: team-scanner
spec:
  version: "1.0.0"
  family: teamscanner
  category: sast
  runtime: lua
  detect:
    filenames: ["*team*.json"]
  script: |
    function parse(input, emit)
      emit({
        rule_id = "TEAM-01",
        title = "Team scanner finding",
        severity = "HIGH"
      })
    end
`
	st.SaveClusterParser("team-scanner", []byte(luaClusterYAML))

	set := newParserSet(integrations.DefaultRegistry(), st)

	// Both tenant A and tenant B should resolve the cluster parsers
	for _, tid := range []uuid.UUID{tenantA, tenantB} {
		p := set.byName(ctx, tid, "team-scanner")
		if p == nil {
			t.Fatalf("tenant %s failed to resolve cluster parser team-scanner", tid)
		}
		// Every parser installed for the cluster has the one id the runs, the gate and the compliance report read (D141): the
		// server cannot tell a shipped parser from an administrator's own, so it does not name them differently.
		if p.Descriptor().ID != "cluster:team-scanner" {
			t.Errorf("expected cluster:team-scanner, got %s", p.Descriptor().ID)
		}

		// Detect by file name alone: 50 on the one scale every parser uses, above the 40 the ingest needs to auto-select
		detected, score := set.detect(ctx, tid, []byte(`{}`), "team-report.json", "application/json")
		if detected == nil || detected.Descriptor().ID != "cluster:team-scanner" || score < 40 {
			t.Errorf("detection failed: got %v with score %d", detected, score)
		}
	}

	// 3. A tenant may not install a script or a module: its Parser is data (mapping). A stored Lua parser of tenant A is
	// not used, and tenant A still gets the cluster parser (docs/34 F14).
	tenantOverrideYAML := `
apiVersion: rampart.aspm.dev/v1alpha1
kind: Parser
metadata:
  name: team-scanner
spec:
  version: "2.0.0"
  family: teamscanner
  category: sast
  runtime: lua
  script: |
    function parse(input, emit)
      emit({
        rule_id = "TENANT-A-01",
        title = "Tenant A overridden finding",
        severity = "CRITICAL"
      })
    end
`
	st.SaveTenantParser(tenantA, "team-scanner", []byte(tenantOverrideYAML))

	set2 := newParserSet(integrations.DefaultRegistry(), st)
	pA := set2.byName(ctx, tenantA, "team-scanner")
	if pA == nil || pA.Descriptor().Version != "1.0.0" {
		t.Fatalf("a tenant's Lua parser must be ignored; tenant A should still resolve the cluster v1.0.0, got: %v", pA)
	}
	pB := set2.byName(ctx, tenantB, "team-scanner")
	if pB == nil || pB.Descriptor().Version != "1.0.0" {
		t.Fatalf("expected tenant B to resolve cluster v1.0.0, got: %v", pB)
	}
}

// The readers of SBOM formats are SBOMParser resources, not report parsers: the parser set registers them next to the
// report parsers, and each is found by its own format (docs/34 section 0b).
func TestSBOMParsersAreDetected(t *testing.T) {
	set := newParserSet(integrations.DefaultRegistry(), nil)
	cases := []struct {
		name, filename string
		head           []byte
		want           string
	}{
		{"CycloneDX JSON", "bom.cdx.json", []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.5"}`), "cluster:sbom-cyclonedx"},
		{"CycloneDX XML", "bom.cdx.xml", []byte(`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"></bom>`), "cluster:sbom-cyclonedx"},
		{"SPDX JSON", "bom.spdx.json", []byte(`{"spdxVersion": "SPDX-2.3"}`), "cluster:sbom-spdx"},
		{"SPDX tag-value", "bom.spdx", []byte("SPDXVersion: SPDX-2.3\nPackageName: openssl"), "cluster:sbom-spdx"},
		{"OpenVEX JSON", "triage.vex.json", []byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`), "cluster:sbom-openvex"},
	}
	for _, tc := range cases {
		p, score := set.registry.DetectParser(tc.head, tc.filename, "")
		if p == nil || score < 50 {
			t.Fatalf("%s: not detected (score %d)", tc.name, score)
		}
		if got := p.Descriptor().ID; got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
