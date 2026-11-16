package query

import (
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
