package query

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rampart/internal/domain"
)

// D84: a finding title, rule or path from a scanner that starts like a formula is defused in the CSV export.
func TestExportCSVDefusesFormulas(t *testing.T) {
	now := time.Now().UTC()
	w := httptest.NewRecorder()
	(&API{}).streamCSV(w, []*domain.Finding{{
		ID: domain.NewID(), Title: `=HYPERLINK("http://evil","x")`, RuleID: "+rule", RuleScannerFamily: "@fam",
		Severity: domain.SeverityHigh, State: domain.StateOpen, FirstSeen: now, LastSeen: now,
	}})
	body := w.Body.String()
	for _, want := range []string{`'=HYPERLINK`, "'+rule", "'@fam"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing defused cell %q in\n%s", want, body)
		}
	}
}

// D86: the OCSF export is class 2007 (ADR 0003) with every attribute schema 1.5.0 marks required.
func TestOCSFExportIsClass2007WithRequiredAttributes(t *testing.T) {
	now := time.Now().UTC()
	cve := "CVE-2021-44228"
	out := toOCSF(&domain.Finding{ID: domain.NewID(), ApplicationID: domain.NewID(), Title: "log4shell", Severity: domain.SeverityCritical,
		State: domain.StateRiskAccepted, Category: domain.CategorySCA, RuleScannerFamily: "trivy", VulnerabilityID: &cve, CWEs: []int{502},
		FirstSeen: now, LastSeen: now, UpdatedAt: now})
	raw, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"activity_id", "category_uid", "class_uid", "type_uid", "severity_id", "time", "cloud", "finding_info", "metadata"} {
		if _, ok := m[k]; !ok {
			t.Errorf("required attribute %s missing", k)
		}
	}
	if m["class_uid"].(float64) != 2007 || m["type_uid"].(float64) != 200701 || m["severity_id"].(float64) != 5 || m["status_id"].(float64) != 3 {
		t.Errorf("class, type, severity or status wrong: %v", m)
	}
	if m["cloud"].(map[string]any)["provider"] == "" || m["finding_info"].(map[string]any)["uid"] == "" {
		t.Error("cloud.provider and finding_info.uid are required")
	}
	meta := m["metadata"].(map[string]any)
	if meta["version"] != "1.5.0" || meta["product"] == nil {
		t.Error("metadata.version and metadata.product are required")
	}
	if m["application"] == nil && m["vulnerabilities"] == nil {
		t.Error("one of application, compliance, remediation or vulnerabilities is required")
	}
	if v := m["vulnerabilities"].([]any); len(v) != 2 {
		t.Errorf("want the CVE and the CWE as vulnerabilities, got %v", v)
	}
}
