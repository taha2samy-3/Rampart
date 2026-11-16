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
	if p := set.byName(ctx, tenantA, "trivy"); p == nil || p.Descriptor().ID != "builtin:trivy" {
		t.Fatalf("a built-in owns its name; got %v", p)
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
