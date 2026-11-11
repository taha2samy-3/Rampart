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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/config/apply"
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

// River lives in its own schema (doc 12), is usable by rampart_app, and a parse job is
// unique by its arguments (D2).
func TestPostgres_RiverQueueInOwnSchema(t *testing.T) {
	ctx := context.Background()
	app, _ := setupStores(t, ctx)
	q, err := jobs.NewRiverQueue(ctx, app.Pool(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	args := jobs.ParseJobArgs{IngestRunID: uuid.New(), TenantID: uuid.New()}
	for i := 0; i < 2; i++ { // second insert must be deduplicated
		if err := q.EnqueueParse(ctx, args); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	var n int
	err = app.Pool().QueryRow(ctx, `SELECT count(*) FROM river.river_job WHERE kind = 'parse' AND args->>'ingest_run_id' = $1`,
		args.IngestRunID.String()).Scan(&n)
	if err != nil || n != 1 {
		t.Fatalf("want exactly 1 parse job in schema river, got %d (%v)", n, err)
	}
}

// D20: namespace ownership is a control-plane fact written by rampart_system only, and a
// namespace has exactly one owner.
func TestPostgres_NamespaceBinding(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)
	a, b := newTenant(t, ctx, sys, "na"), newTenant(t, ctx, sys, "nb")
	ns := "payments-" + uuid.NewString()[:6]

	if err := app.ClaimNamespace(ctx, a, ns); err == nil {
		t.Fatal("rampart_app must not be able to bind namespaces")
	}
	if err := sys.ClaimNamespace(ctx, a, ns); err != nil {
		t.Fatal(err)
	}
	if err := sys.ClaimNamespace(ctx, a, ns); err != nil { // idempotent
		t.Fatalf("re-claim by the owner: %v", err)
	}
	if err := sys.ClaimNamespace(ctx, b, ns); !errors.Is(err, apply.ErrNamespaceOwned) {
		t.Fatalf("a second tenant must not take the namespace, got %v", err)
	}
	got, err := app.GetTenantByNamespace(ctx, ns)
	if err != nil || got == nil || got.ID != a {
		t.Fatalf("the app role reads the binding: %+v %v", got, err)
	}
	if none, _ := app.GetTenantByNamespace(ctx, "nobody-"+uuid.NewString()[:6]); none != nil {
		t.Fatal("an unlisted namespace has no tenant")
	}
}

// Sessions and memberships under row-level security (D8, doc 14).
func TestPostgres_IdentityAndSessions(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)
	a, b := newTenant(t, ctx, sys, "ida"), newTenant(t, ctx, sys, "idb")
	uid, err := app.UpsertUser(ctx, auth.User{Issuer: "https://idp", Subject: "sub-" + uuid.NewString()[:6], Email: "p@example.com", Name: "P"})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := app.UpsertUser(ctx, auth.User{Issuer: "https://idp", Subject: "x", Email: "q@example.com"})
	if again == uid {
		t.Fatal("different subjects are different people")
	}
	if err := app.UpsertMember(ctx, a, uid, auth.RoleTriager); err != nil {
		t.Fatal(err)
	}
	if role, ok, _ := app.GetMemberRole(ctx, a, uid); !ok || role != auth.RoleTriager {
		t.Fatalf("member role: %q %v", role, ok)
	}
	if _, ok, _ := app.GetMemberRole(ctx, b, uid); ok {
		t.Fatal("no membership in tenant B")
	}

	sm, _ := auth.NewSessionManager(app, auth.SessionConfig{Key: []byte(strings.Repeat("k", 32))})
	value, rec, err := sm.Create(ctx, a, uid)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sm.CookieName(), Value: value})
	p, err := sm.Principal(req)
	if err != nil || p.Role != auth.RoleTriager || p.Email != "p@example.com" {
		t.Fatalf("principal: %+v %v", p, err)
	}

	// the secret is never stored: only its hash
	var stored string
	if err := sys.Pool().QueryRow(ctx, `SELECT token_hash FROM session WHERE id = $1`, rec.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(value, stored) || stored != auth.HashToken(value[strings.Index(value, ".")+1:]) {
		t.Fatalf("session secret must be stored as its SHA-256 only")
	}
	// no tenant context sees no sessions (RLS)
	var n int
	_ = app.Pool().QueryRow(ctx, `SELECT count(*) FROM session`).Scan(&n)
	if n != 0 {
		t.Fatalf("a session with no tenant context saw %d rows", n)
	}
	// a session of tenant A cannot be looked up as tenant B
	if _, err := app.LookupSession(ctx, b, rec.TokenHash); err == nil {
		t.Fatal("tenant B must not see tenant A's session")
	}

	// the person sees their own tenants across RLS, and only theirs
	_ = app.UpsertMember(ctx, b, uid, auth.RoleViewer)
	list, err := app.ListUserTenants(ctx, uid)
	if err != nil || len(list) != 2 {
		t.Fatalf("tenants: %v %v", list, err)
	}
	other, _ := app.ListUserTenants(ctx, again)
	if len(other) != 0 {
		t.Fatalf("another person must not see these memberships: %v", other)
	}

	// removing the membership revokes the session at once (no role, no session)
	if _, err := sys.Pool().Exec(ctx, `DELETE FROM tenant_member WHERE tenant_id = $1 AND user_id = $2`, a, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := sm.Principal(req); err == nil {
		t.Fatal("a session must die when the membership is removed")
	}
	// a disabled user is revoked too
	_ = app.UpsertMember(ctx, a, uid, auth.RoleViewer)
	if _, err := sm.Principal(req); err != nil {
		t.Fatalf("membership restored: %v", err)
	}
	if _, err := sys.Pool().Exec(ctx, `UPDATE app_user SET status = 'disabled' WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := sm.Principal(req); err == nil {
		t.Fatal("a disabled user's session must not authenticate")
	}
}
