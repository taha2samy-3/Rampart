package store_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/objectstore"
	"rampart/internal/query"
	"rampart/internal/retention"
	"rampart/internal/store"
)

// Retention (docs/16 D53) removes exactly what is past its time, for one tenant at a time, and leaves evidence:
// stale occurrences, findings fixed long ago, old run results, raw reports (sooner when they name secrets), and
// uploads that were never completed. Everything a person still needs stays.
func TestRetention_TenantSweep(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)
	h.formatHint = "" // detected: Semgrep and Gitleaks
	repo := domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}

	// rule.a and rule.b, then rule.a alone: rule.b is fixed and its occurrence is no longer present.
	run1 := h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.a", "a.go", 3), semgrepResult("rule.b", "b.go", 4)), repo))
	run2 := h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.a", "a.go", 3)), repo))
	if run2.Stats.Closed != 1 || run1.HoldsSecrets || run2.HoldsSecrets {
		t.Fatalf("setup: closed %d, secrets %v %v", run2.Stats.Closed, run1.HoldsSecrets, run2.HoldsSecrets)
	}
	leaks, err := os.ReadFile("../parsers/gitleaks/testdata/repo-8.18.json")
	if err != nil {
		t.Fatal(err)
	}
	run3 := h.waitRun(h.uploadAndComplete(leaks, repo))
	if run3.Status != domain.RunCompleted || !run3.HoldsSecrets {
		t.Fatalf("a Gitleaks run must be marked as holding secrets: %s %v", run3.Status, run3.HoldsSecrets)
	}
	// An upload created and never completed.
	abandoned, _ := h.uploadWith(semgrepReport(), "", repo)

	ruleB := findingByRule(t, h, "rule.b")
	ruleA := findingByRule(t, h, "rule.a")

	// Age the data, as the system role (it bypasses row-level security). Defaults: occurrences 180 days, resolved
	// findings 730, run results 30, raw reports 90, secret reports 7.
	days := func(n int) time.Time { return time.Now().UTC().Add(-time.Duration(n) * 24 * time.Hour) }
	// Every tenant's data is aged, not only this one's: the tenants the other tests of the package left behind
	// then hold expired data too, and sweeping this tenant must not touch any of it.
	mustExec(t, h.pool, `UPDATE occurrence SET last_seen = $1 WHERE NOT present`, days(200))
	mustExec(t, h.pool, `UPDATE finding SET resolved_at = $1 WHERE state = 'fixed'`, days(800))
	mustExec(t, h.pool, `UPDATE ingest_run_result SET created_at = $1`, days(40))
	mustExec(t, h.pool, `UPDATE ingest_run SET finished_at = $1 WHERE finished_at IS NOT NULL AND tenant_id <> $2`, days(100), h.tenant)
	othersBefore := otherTenantRows(t, h)
	mustExec(t, h.pool, `UPDATE ingest_run SET finished_at = $2 WHERE id = $1`, run1.ID, days(100)) // past 90
	mustExec(t, h.pool, `UPDATE ingest_run SET finished_at = $2 WHERE id = $1`, run2.ID, days(10))  // kept
	mustExec(t, h.pool, `UPDATE ingest_run SET finished_at = $2 WHERE id = $1`, run3.ID, days(8))   // secrets: past 7
	mustExec(t, h.pool, `UPDATE upload SET created_at = $2 WHERE id = $1`, uuid.MustParse(abandoned), days(2))

	// A long-fixed finding that another finding names as its duplicate is kept, so that link never dangles.
	dupTarget := ruleA.ID
	mustExec(t, h.pool, `UPDATE finding SET state = 'fixed', resolved_at = $2 WHERE id = $1`, dupTarget, days(800))
	mustExec(t, h.pool, `UPDATE occurrence SET present = false WHERE finding_id = $1`, dupTarget) // not reported, but seen recently
	mustExec(t, h.pool, `UPDATE finding SET duplicate_of_id = $2 WHERE tenant_id = $1 AND id <> $2 AND rule_id <> 'rule.b' AND id = (
		SELECT id FROM finding WHERE tenant_id = $1 AND id <> $2 AND rule_id <> 'rule.b' ORDER BY id LIMIT 1)`, h.tenant, dupTarget)

	appStore := h.store
	sw := retention.New(appStore, h.sys.ListTenantIDs, h.objects, nil, domain.DefaultRetentionPolicy(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	res, err := sw.SweepTenant(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if res.Occurrences != 1 || res.ResolvedFindings != 1 || res.Reports != 2 || res.AbandonedUploads != 1 || res.RunResults == 0 {
		t.Fatalf("removed %+v", res)
	}

	// rule.b is gone with its timeline; rule.a (fixed long ago, but someone's duplicate target) is kept.
	if n := count(t, h.pool, `SELECT count(*) FROM finding WHERE id = $1`, ruleB.ID); n != 0 {
		t.Fatal("the long-fixed finding is still there")
	}
	if n := count(t, h.pool, `SELECT count(*) FROM finding_event WHERE finding_id = $1`, ruleB.ID); n != 0 {
		t.Fatal("its timeline is still there")
	}
	if n := count(t, h.pool, `SELECT count(*) FROM finding WHERE id = $1`, dupTarget); n != 1 {
		t.Fatal("a finding another finding duplicates was deleted")
	}

	// Raw reports: run1 (90 days) and run3 (secrets, 7 days) are gone from storage and say so; run2 stays.
	maint := h.tokenFor(auth.RoleMaintainer, "mona@acme.example")
	for _, r := range []domain.IngestRun{run1, run3} {
		code, body := h.callAs(maint, "GET", "/api/v1/runs/"+r.ID.String()+"/report", nil, nil)
		if code != http.StatusNotFound || !strings.Contains(string(body), "retention") {
			t.Fatalf("an expired report: %d %s", code, body)
		}
		_, view := getJSON[query.RunView](t, h, maint, "/api/v1/runs/"+r.ID.String())
		if view.HasReport || view.ReportPurgedAt == nil {
			t.Fatalf("the run page still offers the expired report: %+v", view.ReportPurgedAt)
		}
		up := uploadOf(t, h, r.ID)
		if _, err := h.objects.Stat(ctx, up); err != objectstore.ErrNotFound {
			t.Fatalf("the object of an expired report is still stored: %v", err)
		}
	}
	if code, _ := h.callAs(maint, "GET", "/api/v1/runs/"+run2.ID.String()+"/report", nil, nil); code != http.StatusOK {
		t.Fatalf("a report inside its retention period: %d", code)
	}
	// The abandoned upload cannot be completed any more.
	if code, body := h.call("POST", "/ingest/v1/uploads/"+abandoned+"/complete", map[string]any{"sha256": sha(semgrepReport())}, nil); code != http.StatusGone {
		t.Fatalf("completing an expired upload: %d %s", code, body)
	}

	// No other tenant was touched.
	if after := otherTenantRows(t, h); after != othersBefore {
		t.Fatalf("other tenants changed: before %v, after %v", othersBefore, after)
	}

	// A second pass finds nothing more.
	again, err := sw.SweepTenant(ctx, h.tenant)
	if err != nil || again != (retention.TenantResult{}) {
		t.Fatalf("second pass: %+v %v", again, err)
	}

	// The sweep left evidence of what it deleted in the tenant's audit log (ISO/IEC 27001 A.8.10), once.
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	_, body := h.callAs(boss, "GET", "/api/v1/audit?action=retention.purge", nil, nil)
	var al struct {
		Items []struct {
			Actor  string          `json:"actor"`
			Detail json.RawMessage `json:"detail"`
		} `json:"items"`
	}
	_ = json.Unmarshal(body, &al)
	if len(al.Items) != 1 || al.Items[0].Actor != "system:retention" || !strings.Contains(string(al.Items[0].Detail), `"resolved_findings":1`) {
		t.Fatalf("audit entry: %s", body)
	}
}

// The policy refuses values that would delete evidence sooner than the standards it rests on allow.
func TestRetention_PolicyMinimums(t *testing.T) {
	if err := domain.DefaultRetentionPolicy().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]domain.RetentionPolicy{
		"audit under a year (PCI DSS 10.5.1)": {AuditDays: 90},
		"timeline under a year":               {EventsDays: 30},
		"resolved findings under 180 days":    {ResolvedFindingsDays: 30},
		"negative":                            {RawReportsDays: -1},
	} {
		if err := p.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := (domain.RetentionPolicy{}).Validate(); err != nil {
		t.Fatalf("zero keeps everything for ever and is allowed: %v", err)
	}
}

// The owner drops months of the event and audit logs once all of the month is past retention, and creates the
// months ahead (D4). The current months are never dropped.
func TestRetention_Partitions(t *testing.T) {
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, sharedDirectURL)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	setupStores(t, ctx) // the schema exists
	old := time.Date(2020, 1, 15, 0, 0, 0, 0, time.UTC)
	if err := store.MaintainPartitions(ctx, owner, old); err != nil { // 2020-01 .. 2020-04
		t.Fatal(err)
	}
	cutoff := time.Date(2020, 3, 10, 0, 0, 0, 0, time.UTC) // January and February are wholly older; March is not
	dropped, err := store.DropExpiredPartitions(ctx, owner, cutoff, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"finding_event_y2020_m01": true, "finding_event_y2020_m02": true,
		"audit_event_y2020_m01": true, "audit_event_y2020_m02": true,
	}
	for _, p := range dropped.Partitions {
		if !want[p] {
			t.Fatalf("dropped %s, which is not wholly past the cutoff", p)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Fatalf("not dropped: %v", want)
	}
	for _, p := range []string{"finding_event_y2020_m03", "audit_event_y2020_m03"} {
		if n := count(t, owner, `SELECT count(*) FROM pg_class WHERE relname = $1`, p); n != 1 {
			t.Fatalf("%s should still exist", p)
		}
	}
	// Running it with the real clock creates the coming months and keeps the current one.
	now := time.Now().UTC()
	if err := retention.MaintainLogs(ctx, owner, domain.DefaultRetentionPolicy(), now, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	ahead := now.AddDate(0, 3, 0)
	for _, p := range []string{
		"finding_event_y" + now.Format("2006") + "_m" + now.Format("01"),
		"audit_event_y" + ahead.Format("2006") + "_m" + ahead.Format("01"),
	} {
		if n := count(t, owner, `SELECT count(*) FROM pg_class WHERE relname = $1`, p); n != 1 {
			t.Fatalf("%s is missing", p)
		}
	}
	// Clean up the old months this test made.
	for _, p := range []string{"finding_event_y2020_m03", "finding_event_y2020_m04", "audit_event_y2020_m03", "audit_event_y2020_m04"} {
		mustExec(t, owner, `DROP TABLE IF EXISTS `+p)
	}
}

// otherTenantRows counts, outside the harness tenant, what a sweep could remove.
func otherTenantRows(t *testing.T, h *uploadHarness) [4]int {
	t.Helper()
	return [4]int{
		count(t, h.pool, `SELECT count(*) FROM occurrence WHERE tenant_id <> $1`, h.tenant),
		count(t, h.pool, `SELECT count(*) FROM finding WHERE tenant_id <> $1`, h.tenant),
		count(t, h.pool, `SELECT count(*) FROM ingest_run_result WHERE tenant_id <> $1`, h.tenant),
		count(t, h.pool, `SELECT count(*) FROM upload WHERE tenant_id <> $1 AND status = 'purged'`, h.tenant),
	}
}

func findingByRule(t *testing.T, h *uploadHarness, rule string) *domain.Finding {
	t.Helper()
	list, err := h.app.ListFindings(context.Background(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if f.RuleID == rule {
			return f
		}
	}
	t.Fatalf("no finding for %s", rule)
	return nil
}

func uploadOf(t *testing.T, h *uploadHarness, runID uuid.UUID) string {
	t.Helper()
	var ref string
	if err := h.pool.QueryRow(context.Background(), `SELECT u.object_ref FROM upload u JOIN ingest_run r ON r.upload_id = u.id WHERE r.id = $1`, runID).Scan(&ref); err != nil {
		t.Fatal(err)
	}
	return ref
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func count(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}
