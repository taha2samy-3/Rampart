package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/query"
)

func TestVEX_ImportDecidesFindingsAndExportRoundTrips(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	seedFindings(t, ctx, h.store, h.tenant, 0) // the application "shop" and its repository asset
	app, _ := h.store.LookupApplication(ctx, h.tenant, "shop")
	asset, _ := h.store.LookupAsset(ctx, h.tenant, domain.AssetRepository, "github.com/acme/shop")
	suffix := uuid.NewString()[:6]
	cveA, ghsaA, cveB := "CVE-2088-1"+suffix[:5], "GHSA-"+suffix[:4]+"-aaaa-bbbb", "CVE-2088-2"+suffix[:5]
	if _, err := h.pool.Exec(ctx, `INSERT INTO vulnerability (id, aliases) VALUES ($1, $2) ON CONFLICT DO NOTHING`, cveA, []string{ghsaA}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO vulnerability_alias (alias, vulnerability_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, ghsaA, cveA); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mk := func(i int, vuln, purl, base string) *domain.Finding {
		v := vuln
		return &domain.Finding{
			ID: uuid.New(), TenantID: h.tenant, FindingKey: fmt.Sprintf("vex-%d", i), DedupScope: "shop:main", AssetID: asset.ID, ApplicationID: app.ID, Track: "main",
			RuleScannerFamily: "trivy", RuleID: vuln, Title: vuln + " in " + purl, Category: domain.CategorySCA, Severity: domain.SeverityHigh, ToolSeverity: "high",
			VulnerabilityID: &v, Location: domain.Location{Package: &domain.PackageLocation{Purl: purl, PurlBase: base}}, State: domain.StateOpen,
			FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now,
		}
	}
	f1 := mk(1, cveA, "pkg:npm/lodash@4.17.20", "pkg:npm/lodash")
	f2 := mk(2, cveB, "pkg:npm/express@4.0.0", "pkg:npm/express")
	f3 := mk(3, cveA, "pkg:npm/lodash@4.17.21", "pkg:npm/lodash") // the same flaw in another version
	if err := h.store.UpsertFindings(ctx, h.tenant, []*domain.Finding{f1, f2, f3}); err != nil {
		t.Fatal(err)
	}

	authn := auth.NewAuthenticatorWithStore(h.store)
	api := query.NewAPIWithAuth(h.store, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	srv := httptest.NewServer(api.Audited(mux))
	defer srv.Close()
	sara := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	do := func(token, method, path, body string) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b
	}
	imp := func(token, q, doc string) (int, queryReport) {
		code, b := do(token, "POST", "/api/v1/vex"+q, doc)
		var rep queryReport
		_ = json.Unmarshal(b, &rep)
		return code, rep
	}
	openvex := func(ts string, stmts ...string) string {
		return fmt.Sprintf(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://x/%s","author":"Acme PSIRT","timestamp":%q,"version":1,"statements":[%s]}`, suffix, ts, strings.Join(stmts, ","))
	}
	stmt := func(vuln, purl, status, extra string) string {
		return fmt.Sprintf(`{"vulnerability":{"name":%q},"products":[{"@id":%q,"identifiers":{"purl":%q}}],"status":%q%s}`, vuln, purl, purl, status, extra)
	}
	past := now.Add(-48 * time.Hour).Format(time.RFC3339)
	doc := openvex(past,
		stmt(ghsaA, "pkg:npm/lodash@4.17.20", "not_affected", `,"justification":"vulnerable_code_not_in_execute_path","impact_statement":"never called"`), // by alias, one version
		stmt(cveB, "pkg:npm/express", "fixed", ""),                // a package without a version: every version
		stmt("CVE-2088-999999", "pkg:npm/nothing@1", "fixed", ""), // matches nothing
		stmt(cveA, "pkg:npm/lodash@4.17.21", "not_affected", ""),  // no justification
		stmt(cveB, "", "fixed", ""),                               // no package
		stmt(cveB, "pkg:npm/express", "maybe", ""),                // not a status
	)

	// A viewer cannot decide; garbage is refused; a dry run changes nothing.
	if code, _ := imp(viewer, "", doc); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
	if code, _ := imp(sara, "", `{"runs":[]}`); code != http.StatusBadRequest {
		t.Fatalf("not a VEX document: %d", code)
	}
	code, dry := imp(sara, "?dryRun=true", doc)
	if code != http.StatusOK || !dry.DryRun || dry.Applied != 2 || h.finding(f1.ID).State != domain.StateOpen {
		t.Fatalf("dry run: %d %+v (it must not change anything)", code, dry)
	}

	code, rep := imp(sara, "", doc)
	if code != http.StatusOK || rep.Format != "openvex" || rep.Statements != 6 || rep.Applied != 2 || rep.Unchanged != 0 || len(rep.Unmatched) != 1 || len(rep.Rejected) != 2 || len(rep.Failed) != 1 {
		t.Fatalf("import: %d %+v", code, rep)
	}
	if got := h.finding(f1.ID); got.State != domain.StateNotAffected || got.Justification != "vulnerable_code_not_in_execute_path" || got.ImpactStatement != "never called" {
		t.Fatalf("f1 (by alias, exact version): %+v", got)
	}
	if got := h.finding(f3.ID); got.State != domain.StateOpen { // another version, and the statement had no justification
		t.Fatalf("f3 must be untouched: %s", got.State)
	}
	if got := h.finding(f2.ID); got.State != domain.StateFixed {
		t.Fatalf("f2: %s", got.State)
	}
	evs, _ := h.store.GetFindingEvents(ctx, h.tenant, f1.ID)
	var found bool
	for _, e := range evs {
		if e.Type == "state_changed" && e.Actor == "vex:Acme PSIRT" && strings.Contains(e.Note, "sara@acme.example") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the timeline must say the VEX decided, and who imported it: %+v", evs)
	}

	// The same document again changes nothing.
	if _, again := imp(sara, "", doc); again.Applied != 0 || again.Unchanged != 2 {
		t.Fatalf("re-import: %+v", again)
	}

	// A person decided after the document was written: the person wins. A newer document wins over the person.
	if code, _ := do(sara, "PATCH", "/api/v1/findings/"+f2.ID.String(), `{"state":"under_investigation"}`); code != http.StatusOK {
		t.Fatalf("triage: %d", code)
	}
	if _, stale := imp(sara, "", openvex(past, stmt(cveB, "pkg:npm/express", "fixed", ""))); stale.Stale != 1 || stale.Applied != 0 || h.finding(f2.ID).State != domain.StateUnderInvestigation {
		t.Fatalf("stale: %+v", stale)
	}
	later := now.Add(time.Hour).Format(time.RFC3339)
	if _, fresh := imp(sara, "", openvex(later, stmt(cveB, "pkg:npm/express", "fixed", ""))); fresh.Applied != 1 || h.finding(f2.ID).State != domain.StateFixed {
		t.Fatalf("newer: %+v", fresh)
	}

	// Within one document the later statement wins whatever the order they are written in.
	two := openvex(past,
		stmt(cveA, "pkg:npm/lodash@4.17.21", "under_investigation", `,"timestamp":"`+later+`"`),
		stmt(cveA, "pkg:npm/lodash@4.17.21", "affected", `,"timestamp":"`+past+`","action_statement":"upgrade"`))
	imp(sara, "", two)
	if got := h.finding(f3.ID).State; got != domain.StateUnderInvestigation {
		t.Fatalf("the later statement must win: %s", got)
	}

	// CycloneDX VEX decides too, through the components it points at.
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"` + later + `","authors":[{"name":"build"}]},
	  "components":[{"bom-ref":"c1","purl":"pkg:npm/lodash@4.17.21"}],
	  "vulnerabilities":[{"id":"` + cveA + `","analysis":{"state":"exploitable"},"affects":[{"ref":"c1"}]}]}`
	if code, r := imp(sara, "", cdx); code != http.StatusOK || r.Format != "cyclonedx" || r.Applied != 1 || h.finding(f3.ID).State != domain.StateAffected {
		t.Fatalf("cyclonedx: %d %+v %s", code, r, h.finding(f3.ID).State)
	}

	// Export what is now decided, in both formats, and read it back: the same decisions, nothing to change.
	for _, format := range []string{"openvex", "cyclonedx"} {
		code, out := do(boss, "GET", "/api/v1/applications/"+app.ID.String()+"/vex?format="+format, "")
		if code != http.StatusOK || !strings.Contains(string(out), cveA) {
			t.Fatalf("export %s: %d %s", format, code, out)
		}
		if code, back := imp(sara, "?dryRun=true", string(out)); code != http.StatusOK || back.Applied != 0 || len(back.Failed) != 0 || len(back.Rejected) != 0 || back.Unchanged != 3 {
			t.Fatalf("round trip %s: %d %+v", format, code, back)
		}
	}
	if code, out := do(boss, "GET", "/api/v1/applications/"+app.ID.String()+"/vex?format=csaf", ""); code != http.StatusBadRequest || !strings.Contains(string(out), "not built") {
		t.Fatalf("csaf: %d %s", code, out)
	}
	// An asset exports the same findings; another tenant's id exports nothing.
	if code, out := do(boss, "GET", "/api/v1/assets/"+asset.ID.String()+"/vex", ""); code != http.StatusOK || !strings.Contains(string(out), cveB) {
		t.Fatalf("asset export: %d %s", code, out)
	}
	if code, out := do(boss, "GET", "/api/v1/applications/"+uuid.NewString()+"/vex", ""); code != http.StatusOK || strings.Contains(string(out), "CVE-") {
		t.Fatalf("unknown application: %d %s", code, out)
	}

	// The import is in the audit log, with who did it.
	_, ab := do(boss, "GET", "/api/v1/audit?action=POST", "")
	if !strings.Contains(string(ab), "POST /api/v1/vex") {
		t.Fatalf("audit: %s", ab)
	}

	// A VEX document uploaded as a scan report is refused with the way to send it.
	h.formatHint = ""
	run := h.waitRun(h.uploadAndComplete([]byte(doc), domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main", Commit: "c1"}))
	if run.Status != domain.RunFailed || run.Error != "vex_document" {
		t.Fatalf("a VEX document as a report: %s %q", run.Status, run.Error)
	}
}

type queryReport = query.VEXImportReport
