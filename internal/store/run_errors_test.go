package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query"
)

func semgrepReport(results ...string) []byte {
	return []byte(`{"version":"1.80.0","results":[` + strings.Join(results, ",") + `]}`)
}

func semgrepResult(rule, path string, line any) string {
	return fmt.Sprintf(`{"check_id":%q,"path":%q,"start":{"line":%v,"col":1},"end":{"line":%v,"col":9},"extra":{"message":"a flaw","severity":"ERROR","lines":"SECRET_VALUE_1234","metadata":{"cwe":"CWE-89"}}}`, rule, path, line, line)
}

// A record the parser cannot read does not stop the report: the rest is merged, the run says how many it could not
// read and where they are, and nothing is closed on a report that may be missing findings (docs/16 D13, D51). The
// raw report can be downloaded by a maintainer, and the download is in the audit log.
func TestRunErrors_RecordsAndRawReport(t *testing.T) {
	h := newUploadHarness(t)
	h.formatHint = "semgrep"
	uctx := domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main", Commit: "c1"}
	run := func(report []byte) domain.IngestRun {
		id := h.uploadAndComplete(report, uctx)
		return h.waitRun(id)
	}
	first := run(semgrepReport(semgrepResult("rule.a", "a.go", 3), semgrepResult("rule.b", "b.go", 4)))
	if first.Status != domain.RunCompleted || first.Stats.Created != 2 || first.Stats.RecordErrors != 0 {
		t.Fatalf("first run: %s %+v %s", first.Status, first.Stats, first.Error)
	}

	// The second report has rule.a, a record with a string where a line number goes, and no rule.b.
	bad := semgrepReport(semgrepResult("rule.a", "a.go", 3), semgrepResult("rule.x", "x.go", `"SECRET_VALUE_1234"`))
	second := run(bad)
	if second.Status != domain.RunCompletedWithErrors || second.Stats.RecordErrors != 1 || second.Stats.Closed != 0 {
		t.Fatalf("second run: %s %+v %s", second.Status, second.Stats, second.Error)
	}
	for _, f := range func() []*domain.Finding { l, _ := h.app.ListFindings(context.Background(), h.tenant); return l }() {
		if f.RuleID == "rule.b" && f.State != domain.StateOpen {
			t.Fatalf("rule.b was closed by a report that could not be read in full: %s", f.State)
		}
	}

	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	code, view := getJSON[query.RunView](t, h, viewer, "/api/v1/runs/"+second.ID.String())
	if code != http.StatusOK || len(view.RecordErrorList) != 1 || view.RecordErrorList[0].Where != "results 2" || !view.HasReport {
		t.Fatalf("run view: %d %+v", code, view.RecordErrorList)
	}
	if strings.Contains(view.RecordErrorList[0].Message, "SECRET_VALUE_1234") {
		t.Fatalf("the message must not carry the content of the record: %q", view.RecordErrorList[0].Message)
	}

	// The raw report: a viewer and a triager may not; a maintainer may, and gets the bytes the scanner wrote.
	triager := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	maint := h.tokenFor(auth.RoleMaintainer, "mona@acme.example")
	for _, tok := range []string{viewer, triager} {
		if c, _ := h.callAs(tok, "GET", "/api/v1/runs/"+second.ID.String()+"/report", nil, nil); c != http.StatusForbidden {
			t.Fatalf("a role below maintainer downloaded the raw report: %d", c)
		}
	}
	c, body := h.callAs(maint, "GET", "/api/v1/runs/"+second.ID.String()+"/report", nil, nil)
	if c != http.StatusOK || string(body) != string(bad) {
		t.Fatalf("download: %d %q", c, body)
	}
	if c, _ := h.callAs(maint, "GET", "/api/v1/runs/00000000-0000-0000-0000-000000000000/report", nil, nil); c != http.StatusNotFound {
		t.Fatalf("an unknown run: %d", c)
	}
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	_, audit := h.callAs(boss, "GET", "/api/v1/audit?action=GET%20/api/v1/runs/%7Bid%7D/report", nil, nil)
	var al struct{ Items []struct{ Actor string } }
	_ = json.Unmarshal(audit, &al)
	if len(al.Items) != 1 || al.Items[0].Actor != "user:mona@acme.example" {
		t.Fatalf("the download must be in the audit log: %s", audit)
	}
}
