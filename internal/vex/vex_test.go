package vex

import (
	"encoding/json"
	"testing"
	"time"

	"rampart/internal/domain"
)

func TestParseOpenVEX_ObjectProductsSubcomponentsAndPrecedenceInputs(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://x/1", "author": "Acme PSIRT", "timestamp": "2026-11-01T10:00:00Z", "version": 1,
	  "statements": [
	    {"vulnerability": {"name": "CVE-2024-1", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
	     "products": [{"@id": "pkg:oci/app@sha256:1", "subcomponents": [{"@id": "pkg:npm/lodash@4.17.20"}]}],
	     "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "impact_statement": "never called",
	     "timestamp": "2026-11-02T00:00:00Z"},
	    {"vulnerability": {"name": "CVE-2024-2"}, "products": ["pkg:npm/a@1"], "status": "affected", "action_statement": "upgrade"},
	    {"vulnerability": {"name": "CVE-2024-3"}, "products": ["pkg:npm/a@1"], "status": "bogus"}
	  ]}`))
	if err != nil || doc.Format != "openvex" || doc.Author != "Acme PSIRT" || len(doc.Statements) != 3 {
		t.Fatalf("doc: %+v %v", doc, err)
	}
	s := doc.Statements[0]
	if len(s.Vulns) != 2 || s.Vulns[0] != "CVE-2024-1" || s.Vulns[1] != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("vulns: %v", s.Vulns)
	}
	if len(s.Purls) != 1 || s.Purls[0] != "pkg:npm/lodash@4.17.20" { // the subcomponent narrows it; the image is not a package
		t.Fatalf("purls: %v", s.Purls)
	}
	if s.State != domain.StateNotAffected || s.Justification != "vulnerable_code_not_in_execute_path" || !s.At.Equal(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("statement: %+v", s)
	}
	if got := doc.Statements[1]; got.State != domain.StateAffected || got.Action != "upgrade" || !got.At.Equal(doc.At) {
		t.Fatalf("a statement without its own time takes the document's: %+v", got)
	}
	if doc.Statements[2].Problem == "" {
		t.Fatal("an unknown status must be reported, not guessed")
	}
}

func TestParseCycloneDX_StatesJustificationsAndVDREntries(t *testing.T) {
	doc, err := Parse([]byte(`{
	  "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:1",
	  "metadata": {"timestamp": "2026-11-01T00:00:00Z", "authors": [{"name": "build"}]},
	  "components": [{"bom-ref": "c1", "purl": "pkg:npm/lodash@4.17.20"}],
	  "vulnerabilities": [
	    {"id": "CVE-1", "analysis": {"state": "not_affected", "justification": "code_not_reachable"}, "affects": [{"ref": "c1"}]},
	    {"id": "CVE-2", "analysis": {"state": "false_positive"}, "affects": [{"ref": "pkg:npm/a@1"}]},
	    {"id": "CVE-3", "analysis": {"state": "not_affected"}, "affects": [{"ref": "c1"}]},
	    {"id": "CVE-4", "analysis": {"state": "resolved"}, "affects": [{"ref": "c1"}]},
	    {"id": "CVE-5", "affects": [{"ref": "c1"}]}
	  ]}`))
	if err != nil || doc.Format != "cyclonedx" || len(doc.Statements) != 4 { // CVE-5 has no analysis: a VDR entry
		t.Fatalf("doc: %+v %v", doc, err)
	}
	if s := doc.Statements[0]; s.State != domain.StateNotAffected || s.Justification != "vulnerable_code_not_in_execute_path" || s.Purls[0] != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("not_affected: %+v", s)
	}
	if s := doc.Statements[1]; s.State != domain.StateNotAffected || s.Justification != "vulnerable_code_not_present" || s.Purls[0] != "pkg:npm/a@1" {
		t.Fatalf("false_positive: %+v", s)
	}
	if s := doc.Statements[2]; s.Problem == "" {
		t.Fatalf("not_affected without a justification must be reported: %+v", s)
	}
	if doc.Statements[3].State != domain.StateFixed {
		t.Fatalf("resolved: %+v", doc.Statements[3])
	}
}

func TestParseRefusesOtherDocuments(t *testing.T) {
	for _, in := range []string{`{"runs": []}`, `[]`, `not json`, ``} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Fatalf("%q was accepted", in)
		}
	}
}

func TestExportRoundTripsThroughBothFormats(t *testing.T) {
	at := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	items := []Item{
		{Vuln: "CVE-1", Purl: "pkg:npm/a@1", State: domain.StateNotAffected, Justification: "component_not_present", Impact: "not shipped", At: at},
		{Vuln: "CVE-2", Purl: "pkg:npm/a@1", State: domain.StateAffected, Action: "upgrade to 2", At: at},
		{Vuln: "CVE-3", Purl: "pkg:npm/b@1", State: domain.StateFixed, At: at},
		{Vuln: "CVE-4", Purl: "pkg:npm/b@1", State: domain.StateOpen, At: at},
		{Vuln: "CVE-5", Purl: "pkg:npm/b@1", State: domain.StateDuplicate, At: at}, // says nothing: left out
		{Vuln: "CVE-6", Purl: "pkg:npm/c@1", State: domain.StateNotAffected, Justification: "inline_mitigations_already_exist", At: at},
		{Vuln: "CVE-6", Purl: "pkg:npm/c@1", State: domain.StateOpen, At: at.Add(-time.Hour)}, // another instance is open: it speaks for the pair
	}
	meta := Meta{ID: "https://rampart/vex/1", Author: "Rampart", At: at}
	for name, doc := range map[string]map[string]any{"openvex": OpenVEX(meta, items), "cyclonedx": CycloneDX(meta, items)} {
		raw, _ := json.Marshal(doc)
		back, err := Parse(raw)
		if err != nil || back.Format != name {
			t.Fatalf("%s: %v %v", name, back, err)
		}
		got := map[string]Statement{}
		for _, s := range back.Statements {
			if s.Problem != "" {
				t.Fatalf("%s: the export is not readable by the import: %+v", name, s)
			}
			got[s.Vulns[0]] = s
		}
		if len(got) != 5 { // CVE-1, 2, 3, 4, 6; the duplicate is gone
			t.Fatalf("%s: statements: %v", name, got)
		}
		if g := got["CVE-1"]; g.State != domain.StateNotAffected || g.Justification != "component_not_present" || g.Impact != "not shipped" {
			t.Fatalf("%s: not_affected lost something: %+v", name, g) // lossless, including a justification CycloneDX has no word for
		}
		if g := got["CVE-2"]; g.State != domain.StateAffected || g.Action != "upgrade to 2" {
			t.Fatalf("%s: affected: %+v", name, g)
		}
		if got["CVE-3"].State != domain.StateFixed || got["CVE-4"].State != domain.StateUnderInvestigation {
			t.Fatalf("%s: fixed/open: %+v %+v", name, got["CVE-3"], got["CVE-4"])
		}
		if got["CVE-6"].State != domain.StateUnderInvestigation {
			t.Fatalf("%s: a pair with an open instance must not claim not_affected: %+v", name, got["CVE-6"])
		}
	}
}
