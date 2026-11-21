package vex

import (
	"encoding/json"
	"testing"
	"time"

	"rampart/internal/domain"
)

func TestCSAF_ParseVEXDocument(t *testing.T) {
	rawCSAF := `{
		"document": {
			"category": "csaf_vex",
			"csaf_version": "2.0",
			"title": "Advisory for Acme Services",
			"publisher": {
				"category": "vendor",
				"name": "Acme Security Team"
			},
			"tracking": {
				"id": "CSAF-2026-001",
				"current_release_date": "2026-11-21T08:00:00Z"
			}
		},
		"product_tree": {
			"full_product_names": [
				{
					"product_id": "CSAFPID-0001",
					"name": "express",
					"product_identification_helper": {
						"purl": "pkg:npm/express@4.18.2"
					}
				},
				{
					"product_id": "CSAFPID-0002",
					"name": "lodash",
					"product_identification_helper": {
						"purl": "pkg:npm/lodash@4.17.21"
					}
				}
			]
		},
		"vulnerabilities": [
			{
				"cve": "CVE-2023-1111",
				"product_status": {
					"known_not_affected": ["CSAFPID-0001"],
					"known_affected": ["CSAFPID-0002"]
				},
				"flags": [
					{
						"label": "vulnerable_code_not_in_execute_path",
						"product_ids": ["CSAFPID-0001"]
					}
				],
				"threats": [
					{
						"category": "impact",
						"details": "Vulnerable parser method is never called in this distribution",
						"product_ids": ["CSAFPID-0001"]
					}
				],
				"remediations": [
					{
						"category": "mitigation",
						"details": "Upgrade to lodash 4.17.22",
						"product_ids": ["CSAFPID-0002"]
					}
				]
			}
		]
	}`

	doc, err := Parse([]byte(rawCSAF))
	if err != nil {
		t.Fatalf("unexpected error parsing CSAF: %v", err)
	}
	if doc.Format != "csaf" {
		t.Errorf("expected format csaf, got %q", doc.Format)
	}
	if doc.Author != "Acme Security Team" {
		t.Errorf("expected author 'Acme Security Team', got %q", doc.Author)
	}
	if doc.ID != "CSAF-2026-001" {
		t.Errorf("expected ID 'CSAF-2026-001', got %q", doc.ID)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(doc.Statements))
	}

	// Verify not_affected statement
	s0 := doc.Statements[0]
	if s0.State != domain.StateNotAffected {
		t.Errorf("expected s0 StateNotAffected, got %q", s0.State)
	}
	if s0.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("expected justification 'vulnerable_code_not_in_execute_path', got %q", s0.Justification)
	}
	if s0.Impact != "Vulnerable parser method is never called in this distribution" {
		t.Errorf("expected impact statement, got %q", s0.Impact)
	}
	if len(s0.Purls) != 1 || s0.Purls[0] != "pkg:npm/express@4.18.2" {
		t.Errorf("expected purl pkg:npm/express@4.18.2, got %v", s0.Purls)
	}

	// Verify affected statement
	s1 := doc.Statements[1]
	if s1.State != domain.StateAffected {
		t.Errorf("expected s1 StateAffected, got %q", s1.State)
	}
	if s1.Action != "Upgrade to lodash 4.17.22" {
		t.Errorf("expected action 'Upgrade to lodash 4.17.22', got %q", s1.Action)
	}
	if len(s1.Purls) != 1 || s1.Purls[0] != "pkg:npm/lodash@4.17.21" {
		t.Errorf("expected purl pkg:npm/lodash@4.17.21, got %v", s1.Purls)
	}
}

func TestCSAF_ExportAndRoundTrip(t *testing.T) {
	meta := Meta{
		ID:     "https://rampart.aspm.dev/vex/test/csaf",
		Author: "Rampart SecOps",
		At:     time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC),
	}

	items := []Item{
		{
			Vuln:          "CVE-2024-5555",
			Purl:          "pkg:golang/github.com/gin-gonic/gin@v1.9.0",
			State:         domain.StateNotAffected,
			Justification: "component_not_present",
			Impact:        "Feature flag disabled in build",
			At:            meta.At,
		},
		{
			Vuln:   "CVE-2024-7777",
			Purl:   "pkg:golang/golang.org/x/crypto@v0.14.0",
			State:  domain.StateFixed,
			Action: "Patched in v0.15.0",
			At:     meta.At,
		},
	}

	exported := CSAF(meta, items)
	if exported["document"] == nil {
		t.Fatal("expected document key in CSAF export")
	}

	bytes, err := json.Marshal(exported)
	if err != nil {
		t.Fatalf("failed to marshal exported CSAF: %v", err)
	}

	// Parse back the exported document
	parsed, err := Parse(bytes)
	if err != nil {
		t.Fatalf("failed to roundtrip parse exported CSAF: %v", err)
	}

	if parsed.Format != "csaf" {
		t.Errorf("expected format csaf, got %q", parsed.Format)
	}
	if parsed.Author != "Rampart SecOps" {
		t.Errorf("expected author Rampart SecOps, got %q", parsed.Author)
	}
	if len(parsed.Statements) != 2 {
		t.Fatalf("expected 2 roundtrip statements, got %d", len(parsed.Statements))
	}
}
