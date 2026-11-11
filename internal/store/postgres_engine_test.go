package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/jobs"
	"rampart/internal/store"
)

func newTenant(t *testing.T, ctx context.Context, sys *store.PostgresStore, slug string) uuid.UUID {
	t.Helper()
	tn := &domain.Tenant{ID: uuid.New(), Slug: slug + "-" + uuid.NewString()[:8], DisplayName: slug}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	return tn.ID
}

// D4/D19: rampart_app reads tenants and global intelligence but never writes them.
func TestPostgres_AppRoleLeastPrivilege(t *testing.T) {
	ctx := context.Background()
	app, _ := setupStores(t, ctx)
	if err := app.CreateTenant(ctx, &domain.Tenant{ID: uuid.New(), Slug: "x-" + uuid.NewString()[:6], DisplayName: "x"}); err == nil {
		t.Error("rampart_app must not be able to create tenants")
	}
	if _, err := app.Pool().Exec(ctx, `INSERT INTO vulnerability (id) VALUES ('CVE-0000-0000')`); err == nil {
		t.Error("rampart_app must not write global intelligence tables")
	}
}

// D4/D8: a token is only found under its own tenant, and a session with no tenant sees no tokens.
func TestPostgres_TokensAreTenantScoped(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)
	a, b := newTenant(t, ctx, sys, "ta"), newTenant(t, ctx, sys, "tb")

	raw, rec, err := auth.GenerateToken(a, auth.RoleAdmin, "svc", []string{"*"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.SaveToken(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if got, err := app.LookupTokenByHash(ctx, a, auth.HashToken(raw)); err != nil || got.TenantID != a {
		t.Fatalf("own tenant lookup: %v %v", got, err)
	}
	if _, err := app.LookupTokenByHash(ctx, b, auth.HashToken(raw)); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("tenant B must not see tenant A's token, got %v", err)
	}
	var n int
	if err := app.Pool().QueryRow(ctx, `SELECT count(*) FROM api_token`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("no tenant context must see zero tokens, got %d (%v)", n, err)
	}
}

// D13: a batch is one transaction. When a later step fails, nothing from the batch survives.
func TestPostgres_MergeBatchRollsBackAsUnit(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)
	tenant := newTenant(t, ctx, sys, "tx")
	r := resolveFixture(t, ctx, app, tenant)

	eng := ingest.NewEngine(app)
	rec := ingest.StagedRecord{FindingKey: "k-rollback", Category: domain.CategorySAST, RuleID: "r", Title: "t",
		Severity: domain.SeverityHigh, ToolSeverity: "error", ContentHash: "h", SeenAt: time.Now().UTC(),
		Location: domain.Location{Code: &domain.CodeLocation{FilePath: "a.go", StartLine: 1}}}
	// The run row does not exist: UpsertFindings succeeds, UpsertOccurrences then violates its FK.
	_, err := eng.MergeBatch(ctx, r.scope, uuid.New(), r.appID, []ingest.StagedRecord{rec})
	if err == nil {
		t.Fatal("expected the batch to fail on the occurrence FK")
	}
	got, _ := app.GetFindingsByKeys(ctx, tenant, []string{"k-rollback"})
	if len(got) != 0 {
		t.Fatalf("finding survived a failed batch: transaction was not shared")
	}
}

// Full lifecycle on Postgres: create, untouched rescan, close with events and counters.
func TestPostgres_EngineLifecycle(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)
	tenant := newTenant(t, ctx, sys, "life")
	r := resolveFixture(t, ctx, app, tenant)
	eng := ingest.NewEngine(app)

	mk := func(key string) ingest.StagedRecord {
		return ingest.StagedRecord{FindingKey: key, Category: domain.CategorySAST, RuleID: "r", Title: key,
			Severity: domain.SeverityHigh, ToolSeverity: "error", ContentHash: "h-" + key, SeenAt: time.Now().UTC(),
			Location: domain.Location{Code: &domain.CodeLocation{FilePath: key + ".go", StartLine: 1}}}
	}
	run := func() uuid.UUID { return r.newRun(t, ctx, app) }

	out, err := eng.MergeBatch(ctx, r.scope, run(), r.appID, []ingest.StagedRecord{mk("a"), mk("b")})
	if err != nil || out.Created != 2 {
		t.Fatalf("create: %+v %v", out, err)
	}
	out, err = eng.MergeBatch(ctx, r.scope, run(), r.appID, []ingest.StagedRecord{mk("a"), mk("b")})
	if err != nil || out.Untouched != 2 || out.Created != 0 {
		t.Fatalf("rescan must be untouched: %+v %v", out, err)
	}
	// third run reports only "a": "b" must be closed
	third := run()
	if _, err := eng.MergeBatch(ctx, r.scope, third, r.appID, []ingest.StagedRecord{mk("a")}); err != nil {
		t.Fatal(err)
	}
	res, err := eng.CloseScopeStepWithGuard(ctx, r.scope, third, true)
	if err != nil || res.Closed != 1 {
		t.Fatalf("close: %+v %v", res, err)
	}

	f, _ := app.GetFindingsByKeys(ctx, tenant, []string{"a", "b"})
	if f["b"].State != domain.StateFixed || f["b"].Resolution == nil || f["b"].ResolvedAt == nil || f["b"].PreviousState != domain.StateOpen {
		t.Errorf("b not closed correctly: %+v", f["b"])
	}
	if f["a"].State != domain.StateOpen || f["a"].OccurrenceCount != 1 {
		t.Errorf("a must stay open with 1 occurrence: %+v", f["a"])
	}
	if f["b"].OccurrenceCount != 0 {
		t.Errorf("b occurrence_count must be recomputed to 0, got %d", f["b"].OccurrenceCount)
	}
	evs, _ := app.GetFindingEvents(ctx, tenant, f["b"].ID)
	if len(evs) != 2 || evs[0].Type != "created" || evs[1].Type != "closed_by_rescan" {
		t.Errorf("events for b: %+v", evs)
	}
}

// End to end over HTTP on Postgres: the same report uploaded twice dedups (D10, D11).
func TestPostgres_GatewayRescanDedups(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)
	tenant := newTenant(t, ctx, sys, "gw")
	raw, rec, _ := auth.GenerateToken(tenant, auth.RoleAdmin, "ci", []string{"*"}, time.Hour)
	if err := app.SaveToken(ctx, rec); err != nil {
		t.Fatal(err)
	}
	gw := ingest.NewGatewayWithDeps(jobs.NewInMemJobQueue(), app, nil, nil)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	report, err := os.ReadFile("../parsers/sarif/testdata/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}
	upload := func() ingest.DirectReportResponse {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("repository", "https://github.com/acme/shop.git")
		_ = mw.WriteField("branch", "main")
		fw, _ := mw.CreateFormFile("file", "whatever-name.sarif")
		_, _ = fw.Write(report)
		_ = mw.Close()
		req := httptest.NewRequest("POST", "/ingest/v1/reports", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+raw)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
		}
		var out ingest.DirectReportResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out
	}
	first := upload()
	if first.Created == 0 {
		t.Fatalf("first upload must create findings: %+v", first)
	}
	second := upload()
	if second.Created != 0 || second.Untouched != first.Created {
		t.Fatalf("rescan must dedup: first=%+v second=%+v", first, second)
	}
	// the run is persisted and readable through the API
	req := httptest.NewRequest("GET", "/ingest/v1/runs/"+second.IngestRunID, nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get run: %d %s", rr.Code, rr.Body.String())
	}
}

// fixture: application, asset, scan source and a way to create run rows (FKs are real).
type fixture struct {
	scope store.CloseScope
	appID uuid.UUID
	asset *domain.Asset
	src   uuid.UUID
	tn    uuid.UUID
}

func resolveFixture(t *testing.T, ctx context.Context, app *store.PostgresStore, tenant uuid.UUID) *fixture {
	t.Helper()
	a := &domain.Application{ID: uuid.New(), TenantID: tenant, Slug: "app", Name: "app", BusinessCriticality: "high", Lifecycle: "production"}
	if err := app.CreateApplication(ctx, a); err != nil {
		t.Fatal(err)
	}
	as := &domain.Asset{ID: uuid.New(), TenantID: tenant, ApplicationID: &a.ID, Type: domain.AssetRepository, Key: "repo", Active: true}
	if err := app.CreateAsset(ctx, as); err != nil {
		t.Fatal(err)
	}
	src, err := app.EnsureScanSource(ctx, tenant, "")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{tn: tenant, appID: a.ID, asset: as, src: src,
		scope: store.CloseScope{TenantID: tenant, ScanSourceID: src, ScannerFamily: "semgrep", AssetID: as.ID, Track: "main"}}
}

func (f *fixture) newRun(t *testing.T, ctx context.Context, app *store.PostgresStore) uuid.UUID {
	t.Helper()
	run := &domain.IngestRun{ID: uuid.New(), TenantID: f.tn, ScanSourceID: f.src, ApplicationID: f.appID, AssetID: f.asset.ID,
		Track: "main", ScannerFamily: "semgrep", Format: "sarif", Status: domain.RunMerging}
	if err := app.CreateIngestRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	return run.ID
}
