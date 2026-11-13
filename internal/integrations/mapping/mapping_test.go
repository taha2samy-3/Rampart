package mapping

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const pipAuditYAML = `
apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
metadata:
  name: pip-audit
spec:
  kind: parser
  runtime: mapping
  version: 1.0.0
  family: pip-audit
  category: sca
  detect:
    filenames: ["pip-audit*.json"]
    probes:
      - jsonHasKeys: [dependencies]
  input:
    format: json
    records: $.dependencies[*].vulns[*]
    parent: dep
  map:
    ruleId:        rec.id
    title:         'rec.id + " in " + dep.name'
    description:   rec.description
    vulnIds:       '[rec.id]'
    severity:      rec.severity
    toolRecordId:  'dep.name + "@" + dep.version + ":" + rec.id'
    location:
      package:
        purl:             '"pkg:pypi/" + dep.name.lowerAscii() + "@" + dep.version'
        name:             dep.name
        installedVersion: dep.version
        fixedVersion:     'size(rec.fix_versions) > 0 ? rec.fix_versions[0] : ""'
  severityMap:
    HIGH: high
    CRITICAL: critical
    MODERATE: medium
    LOW: low
  limits:
    maxRecords: 10000
    maxDepth: 64
`

func TestMappingParser_PipAudit(t *testing.T) {
	parser, err := NewMappingParser([]byte(pipAuditYAML))
	if err != nil {
		t.Fatalf("failed to create mapping parser: %v", err)
	}

	// 1. Detection
	score := parser.Detect([]byte(`{"dependencies": []}`), "pip-audit-output.json", "application/json")
	if score < 90 {
		t.Errorf("expected detection score >= 90, got %d", score)
	}

	// 2. Parse sample report
	sampleJSON := `{
		"dependencies": [
			{
				"name": "Flask",
				"version": "1.1.1",
				"vulns": [
					{
						"id": "GHSA-m2qf-hxjv-5gpq",
						"description": "Unexpected memory leak in session handling",
						"severity": "HIGH",
						"fix_versions": ["1.1.2"]
					}
				]
			},
			{
				"name": "requests",
				"version": "2.20.0",
				"vulns": [
					{
						"id": "CVE-2018-18074",
						"description": "Redirect credential leakage",
						"severity": "CRITICAL",
						"fix_versions": ["2.20.1"]
					}
				]
			}
		]
	}`

	var findings []domain.RawFinding
	for f, err := range parser.Parse(context.Background(), strings.NewReader(sampleJSON), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check finding 1
	f1 := findings[0]
	if f1.RuleID != "GHSA-m2qf-hxjv-5gpq" {
		t.Errorf("finding 0 ruleID = %s", f1.RuleID)
	}
	if f1.Title != "GHSA-m2qf-hxjv-5gpq in Flask" {
		t.Errorf("finding 0 title = %s", f1.Title)
	}
	if f1.Severity != domain.SeverityHigh {
		t.Errorf("finding 0 severity = %s", f1.Severity)
	}
	if f1.Category != domain.CategorySCA {
		t.Errorf("finding 0 category = %s", f1.Category)
	}
	if f1.Location.Package == nil || f1.Location.Package.Purl != "pkg:pypi/flask@1.1.1" {
		t.Errorf("finding 0 purl = %+v", f1.Location.Package)
	}
	if f1.Location.Package.FixedVersion != "1.1.2" {
		t.Errorf("finding 0 fixed version = %s", f1.Location.Package.FixedVersion)
	}

	// Check finding 2
	f2 := findings[1]
	if f2.RuleID != "CVE-2018-18074" {
		t.Errorf("finding 1 ruleID = %s", f2.RuleID)
	}
	if f2.Severity != domain.SeverityCritical {
		t.Errorf("finding 1 severity = %s", f2.Severity)
	}
}

func TestMappingParser_RecordErrors_AndCostLimit(t *testing.T) {
	parser, err := NewMappingParser([]byte(pipAuditYAML))
	if err != nil {
		t.Fatalf("failed to create mapping parser: %v", err)
	}

	sampleWithBadRecord := `{
		"dependencies": [
			{
				"name": "good-pkg",
				"version": "1.0",
				"vulns": [
					{"id": "CVE-GOOD-1", "severity": "LOW"}
				]
			},
			{
				"name": "bad-pkg",
				"version": "2.0",
				"vulns": [
					{"id": "", "severity": "LOW"}
				]
			}
		]
	}`

	var recordErrors []domain.RecordError
	pc := domain.ParseContext{
		RecordError: func(re domain.RecordError) {
			recordErrors = append(recordErrors, re)
		},
	}

	var findings []domain.RawFinding
	for f, err := range parser.Parse(context.Background(), strings.NewReader(sampleWithBadRecord), pc) {
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Errorf("expected 1 valid finding, got %d", len(findings))
	}
	if len(recordErrors) != 1 {
		t.Errorf("expected 1 record error, got %d", len(recordErrors))
	}
}

func TestMappingParser_LargeStreamMemoryBounds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in short mode")
	}

	largeYAML := strings.Replace(pipAuditYAML, "maxRecords: 10000", "maxRecords: 100000", 1)
	parser, err := NewMappingParser([]byte(largeYAML))
	if err != nil {
		t.Fatalf("failed to create mapping parser: %v", err)
	}

	totalRecords := 50_000

	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = pw.Close() }()
		_, _ = fmt.Fprint(pw, `{"dependencies":[`)
		for i := 0; i < totalRecords; i++ {
			if i > 0 {
				_, _ = fmt.Fprint(pw, `,`)
			}
			_, _ = fmt.Fprintf(pw, `{"name":"pkg-%d","version":"1.0.%d","vulns":[{"id":"GHSA-%05d","description":"stream test vulnerability %d","severity":"HIGH","fix_versions":["1.0.%d"]}]}`,
				i%500, i%10, i, i, (i%10)+1)
		}
		_, _ = fmt.Fprint(pw, `]}`)
	}()

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	count := 0
	for _, err := range parser.Parse(context.Background(), pr, domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("streaming error at %d: %v", count, err)
		}
		count++
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	var heapGrowthMB float64
	if memAfter.HeapAlloc > memBefore.HeapAlloc {
		heapGrowthMB = float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / (1024 * 1024)
	}
	if count != totalRecords {
		t.Errorf("expected %d records, parsed %d", totalRecords, count)
	}

	// Must be well under the 256 MiB bound (typically < 10 MB for streaming)
	if heapGrowthMB > 64.0 {
		t.Errorf("heap growth exceeded 64 MB: %.2f MB", heapGrowthMB)
	}
}
