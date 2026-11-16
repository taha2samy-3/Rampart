package store_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/config/apply"
	"rampart/internal/query"
)

const acmePolicy = `{"displayName":"ACME secure coding","version":"2026.1","controls":[
  {"id":"SC-1","name":"No critical injection","match":{"cwes":[89],"minSeverity":"critical"}},
  {"id":"SC-2","name":"No hard-coded credentials","match":{"categories":["secret"]}},
  {"id":"SC-3","name":"A threat model is reviewed for each release","manual":true},
  {"id":"SC-4","name":"No use of rule r1","match":{"rules":[{"scannerFamily":"semgrep","ruleId":"rules.r1"}]}}]}`

// D102, end to end on PostgreSQL: a tenant's own framework is listed and read like a built-in one; minSeverity and
// rules narrow what counts; an accepted finding is an exception shown apart, not open; one application's scan does
// not clear a control for another; a framework scoped to "pci" reads only the applications that say so; a manual
// control is attested by a maintainer, never a viewer; the day's reading is kept and read back.
func TestCompliance_CustomFrameworks(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	maintainer := h.tokenFor(auth.RoleMaintainer, "lead@acme.example")
	seedFindings(t, ctx, h.store, h.tenant, 8) // app "shop": SAST findings with CWE-89, rules r0..r6
	// The seed leaves every band at low: give each finding the band of its severity, and accept one critical.
	if _, err := h.sys.Pool().Exec(ctx, `UPDATE finding SET risk_band = severity WHERE tenant_id = $1`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := h.sys.Pool().Exec(ctx, `UPDATE finding SET state = 'risk_accepted' WHERE id = (
		SELECT id FROM finding WHERE tenant_id = $1 AND severity = 'critical' AND state = 'open' ORDER BY finding_key LIMIT 1)`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if err := h.sys.SaveTenantPolicy(ctx, h.tenant, "compliance", apply.PolicyObject{Namespace: "default", Name: "acme", Spec: []byte(acmePolicy)}); err != nil {
		t.Fatal(err)
	}

	code, list := getJSON[struct{ Items []query.TaxonomyInfo }](t, h, viewer, "/api/v1/taxonomies")
	var acme *query.TaxonomyInfo
	for i := range list.Items {
		if list.Items[i].ID == "acme" {
			acme = &list.Items[i]
		}
	}
	if code != http.StatusOK || acme == nil || acme.Origin != "tenant" || acme.Controls != 4 || acme.WindowDays != 30 {
		t.Fatalf("the tenant's framework is listed: %d %+v", code, acme)
	}
	status := func(path string) (query.TaxonomyStatus, map[string]query.ControlStatus) {
		t.Helper()
		code, st := getJSON[query.TaxonomyStatus](t, h, viewer, path)
		if code != http.StatusOK {
			t.Fatalf("%s: %d", path, code)
		}
		out := map[string]query.ControlStatus{}
		for _, c := range st.Controls {
			out[c.ID] = c
		}
		return st, out
	}

	_, c := status("/api/v1/taxonomies/acme/status")
	// 8 findings: severities cycle critical, high, medium, low; #0 and #5 are fixed, so criticals #4 is open and #0
	// fixed; the open critical is the one accepted. Only critical counts for SC-1.
	if sc1 := c["SC-1"]; sc1.Open != 0 || sc1.Accepted != 1 || sc1.Bands["high"] != 0 {
		t.Fatalf("SC-1 counts critical only, and the accepted one apart: %+v", sc1)
	}
	if !strings.Contains(c["SC-1"].Reason, "risk-accepted") {
		t.Fatalf("the exception is said in words: %q", c["SC-1"].Reason)
	}
	if sc4 := c["SC-4"]; sc4.Open == 0 || sc4.Status != "open" || sc4.QueryExact != true || !strings.Contains(sc4.Query, "rule:rules.r1") {
		t.Fatalf("SC-4 matches by rule: %+v", sc4)
	}
	if sc2 := c["SC-2"]; sc2.Status != "not_assessed" || !strings.Contains(sc2.Reason, "No secret scan ran in the last 30 days") {
		t.Fatalf("SC-2 with no secret scan: %+v", sc2)
	}
	if sc3 := c["SC-3"]; sc3.Status != "not_assessed" || !sc3.Manual || sc3.Reason != "A person attests this control, and nobody has yet." {
		t.Fatalf("SC-3 before any attestation: %+v", sc3)
	}

	// A SAST scan of another application: OWASP A10 has no findings; tenant-wide it is assessed in that application
	// only, so it is not clear.
	ingestRules(t, h, map[string]string{"rule.z": "2.0"}, "main")
	_, o := status("/api/v1/taxonomies/owasp-top10-2021/status")
	if a10 := o["A10:2021"]; a10.Status != "not_assessed" || a10.AssessedApps != 1 || a10.TotalApps < 2 || !strings.HasPrefix(a10.Reason, "Assessed in 1 of ") {
		t.Fatalf("one application's scan must not clear the control for the others: %+v", a10)
	}

	// Attestation: a viewer may not; a maintainer may; a failed one reads open; an expiry in the past is refused.
	attest := func(token, body string) int {
		code, _ := h.callAs(token, "POST", "/api/v1/taxonomies/acme/controls/SC-3/attestations", json.RawMessage(body), map[string]string{"Content-Type": "application/json"})
		return code
	}
	if code := attest(viewer, `{"status":"passed","note":"reviewed"}`); code != http.StatusForbidden {
		t.Fatalf("a viewer attests: %d", code)
	}
	if code := attest(maintainer, `{"status":"passed","note":""}`); code != http.StatusBadRequest {
		t.Fatalf("an attestation without a note: %d", code)
	}
	if code := attest(maintainer, `{"status":"passed","note":"x","expires_at":"2020-01-01T00:00:00Z"}`); code != http.StatusBadRequest {
		t.Fatalf("an attestation already expired: %d", code)
	}
	if code, _ := h.callAs(maintainer, "POST", "/api/v1/taxonomies/acme/controls/SC-1/attestations", json.RawMessage(`{"status":"passed","note":"x"}`), nil); code != http.StatusConflict {
		t.Fatalf("a matched control cannot be attested: %d", code)
	}
	if code := attest(maintainer, `{"status":"passed","note":"Threat model of release 4.2 reviewed with the team","evidence_url":"https://wiki.acme.example/tm/4.2"}`); code != http.StatusCreated {
		t.Fatalf("a maintainer attests: %d", code)
	}
	_, c = status("/api/v1/taxonomies/acme/status")
	if sc3 := c["SC-3"]; sc3.Status != "clear" || sc3.Attestation == nil || sc3.Attestation.AttestedBy == "" || !strings.Contains(sc3.Reason, "attested on") {
		t.Fatalf("SC-3 after a passed attestation: %+v", sc3)
	}
	if code := attest(maintainer, `{"status":"failed","note":"Release 4.3 shipped without a review"}`); code != http.StatusCreated {
		t.Fatal(code)
	}
	if _, c = status("/api/v1/taxonomies/acme/status"); c["SC-3"].Status != "open" {
		t.Fatalf("the newest attestation is the reading: %+v", c["SC-3"])
	}

	// Scope: a framework for "pci" reads only the applications whose complianceScope lists it.
	scoped := strings.Replace(acmePolicy, `"version":"2026.1",`, `"version":"2026.1","appliesTo":{"complianceScope":"pci"},`, 1)
	if err := h.sys.SaveTenantPolicy(ctx, h.tenant, "compliance", apply.PolicyObject{Namespace: "default", Name: "acme-pci", Spec: []byte(scoped)}); err != nil {
		t.Fatal(err)
	}
	if _, c = status("/api/v1/taxonomies/acme-pci/status"); c["SC-4"].Status != "not_assessed" || c["SC-4"].Open != 0 || c["SC-4"].Reason != "No application is in this framework's scope." {
		t.Fatalf("no application lists pci: %+v", c["SC-4"])
	}
	if _, err := h.sys.Pool().Exec(ctx, `UPDATE application SET compliance_scope = '{pci}' WHERE tenant_id = $1 AND slug = 'shop'`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, c = status("/api/v1/taxonomies/acme-pci/status"); c["SC-4"].Open == 0 || c["SC-4"].TotalApps != 1 {
		t.Fatalf("shop lists pci: %+v", c["SC-4"])
	}

	// The day's reading is kept, listed and read back as it was; an application filter is refused on a past day.
	api := query.NewAPIWithAuth(h.store, nil, auth.NewAuthenticatorWithStore(h.store))
	if kept := api.SnapshotCompliance(ctx, []uuid.UUID{h.tenant}, time.Now().UTC(), slog.Default()); kept < 8 {
		t.Fatalf("a reading per framework: kept %d", kept)
	}
	day := time.Now().UTC().Format("2006-01-02")
	code, hist := getJSON[struct{ Days []string }](t, h, viewer, "/api/v1/taxonomies/acme/history")
	if code != http.StatusOK || len(hist.Days) != 1 || hist.Days[0] != day {
		t.Fatalf("history: %d %+v", code, hist)
	}
	st, c := status("/api/v1/taxonomies/acme/status?at=" + day)
	if !st.Historical || c["SC-3"].Status != "open" {
		t.Fatalf("the kept reading: %+v", st)
	}
	if code, _ := h.callAs(viewer, "GET", "/api/v1/taxonomies/acme/status?at=1999-01-01", nil, nil); code != http.StatusNotFound {
		t.Fatalf("a day with no reading: %d", code)
	}
	csvCode, csv := h.callAs(viewer, "GET", "/api/v1/taxonomies/acme/status?format=csv", nil, nil)
	if csvCode != http.StatusOK || !strings.Contains(string(csv), ",accepted,assessed_applications,") || !strings.Contains(string(csv), "lead@acme.example") {
		t.Fatalf("csv: %d %.300s", csvCode, csv)
	}
}
