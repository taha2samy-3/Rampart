package ingest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"

	"github.com/google/uuid"
)

// sarifOf is a small SARIF report of one result, the shape Trivy, Semgrep and Checkov write with --format sarif.
func sarifOf(tool string) string {
	return `{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"` + tool +
		`","rules":[{"id":"R1"}]}},"results":[{"ruleId":"R1","level":"error","message":{"text":"bad"},` +
		`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{"startLine":3}}}]}]}]}`
}

func postReport(t *testing.T, mux *http.ServeMux, token string, fields map[string]string, filename, body string) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	part, _ := w.CreateFormFile("file", filename)
	_, _ = part.Write([]byte(body))
	_ = w.Close()
	req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// A SARIF file sent with the name of a JSON-only parser (what the demo pipeline did: parser=trivy on a SARIF
// report) used to be read as an empty scan: HTTP 201, nothing staged, and the close step closed the real
// findings of the scope. It must be refused, and name the format the file really is.
func TestDirectUpload_ReportOfAnotherFormatIsRefused(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	// First a real SARIF scan, so there is a finding that a wrong upload must not close.
	if rec := postReport(t, mux, token, map[string]string{"format": "sarif", "track": "main"}, "a.sarif", sarifOf("x")); rec.Code != http.StatusCreated {
		t.Fatalf("baseline sarif upload: %d %s", rec.Code, rec.Body.String())
	}

	for _, format := range []string{"trivy", "cluster:trivy", "semgrep", "checkov", "grype", "gitleaks"} {
		rec := postReport(t, mux, token, map[string]string{"format": format, "track": "main"}, "r.sarif", sarifOf("x"))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("format=%s on a SARIF file: want 400, got %d: %s", format, rec.Code, rec.Body.String())
			continue
		}
		var p struct{ Type, Detail string }
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		if !strings.HasSuffix(p.Type, "/format-mismatch") && !strings.Contains(rec.Body.String(), "parse_error") {
			t.Errorf("format=%s: want a format-mismatch problem, got %s", format, rec.Body.String())
		}
	}

	findings, _ := gw.Store().ListFindings(t.Context(), tenantID)
	if len(findings) != 1 || findings[0].State != "open" {
		t.Fatalf("a refused upload must not touch the inventory: %d findings, %+v", len(findings), findings)
	}

	// The right name for the file, and no name at all, still work.
	for _, fields := range []map[string]string{{"format": "sarif"}, {}} {
		fields["track"] = "main"
		if rec := postReport(t, mux, token, fields, "r.sarif", sarifOf("x")); rec.Code != http.StatusCreated {
			t.Errorf("fields %v: want 201, got %d: %s", fields, rec.Code, rec.Body.String())
		}
	}
}

// A NUL byte in a report (raw or as the JSON escape \u0000) failed the merge in PostgreSQL, which stores neither
// in text or jsonb: the upload answered HTTP 500 "Ingest failed". It is replaced on the way in instead.
func TestDirectUpload_NULInReportIsReplacedNotFatal(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	report := strings.NewReplacer(`"bad"`, `"nul \u0000 and a raw one `+"\x00"+`"`, `"R1"`, `"U\u0000N"`).Replace(sarifOf("x"))
	rec := postReport(t, mux, token, map[string]string{"format": "sarif", "track": "main"}, "r.sarif", report)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a NUL in a report must not fail the upload: %d %s", rec.Code, rec.Body.String())
	}
	findings, _ := gw.Store().ListFindings(t.Context(), tenantID)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	for _, s := range []string{findings[0].Title, findings[0].Description, findings[0].RuleID} {
		if strings.ContainsRune(s, 0) || strings.Contains(s, `\u0000`) {
			t.Errorf("a NUL survived into the stored finding: %q", s)
		}
	}
}

// A report over the direct-upload limit answers 413 (it answered 400 for a multipart body, 500 for a raw one).
func TestDirectUpload_OversizeIs413(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	big := strings.Repeat("x", ingest.MaxDirectReportBytes+1024)
	if rec := postReport(t, mux, token, map[string]string{"format": "sarif"}, "big.sarif", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("multipart: want 413, got %d: %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest("POST", "/ingest/v1/reports?format=sarif", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("raw body: want 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

// An asset that belongs to an application stays in it (D10), but the answer must say so: a report that named
// another application used to be filed under the first one with no word.
func TestDirectUpload_SaysWhichApplicationItWasFiledUnder(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	// The repository the report is filed on already belongs to "shop" (what PostgreSQL keeps after a first scan).
	ctx := t.Context()
	shop := &domain.Application{ID: domain.NewID(), TenantID: tenantID, Slug: "shop", Name: "Shop"}
	if err := gw.Store().CreateApplication(ctx, shop); err != nil {
		t.Fatal(err)
	}
	asset := &domain.Asset{ID: domain.NewID(), TenantID: tenantID, Type: domain.AssetRepository, Key: ingest.DeriveAssetKey(domain.AssetRepository, domain.UploadContext{}), Active: true, ApplicationID: &shop.ID}
	if err := gw.Store().CreateAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}

	send := func(app string) ingest.DirectReportResponse {
		rec := postReport(t, mux, token, map[string]string{"format": "sarif", "track": "main", "application": app}, "r.sarif", sarifOf("x"))
		var out ingest.DirectReportResponse
		if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	if same := send("shop"); same.Application != "shop" || len(same.Warnings) != 0 {
		t.Fatalf("the application it belongs to is no warning: %+v", same)
	}
	other := send("billing")
	if other.Application != "shop" || len(other.Warnings) != 1 || !strings.Contains(other.Warnings[0], `"billing"`) {
		t.Errorf("a different application must be reported as not used: %+v", other)
	}
}

// An upload that names an application that does not exist used to make a new empty one, so a typo in a pipeline
// (rampart-demo-appp) made an application nobody asked for. As in DefectDojo (auto_create_context) and Veracode
// (create profile), creating one is now the caller's explicit choice, and needs a maintainer or a CI token.
func TestDirectUpload_CreatingAnApplicationIsAnExplicitChoice(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	admin := authn.DefaultAdminToken(tenantID)
	mint := func(secret string, role auth.Role) string {
		raw := auth.FormatToken(tenantID, secret)
		authn.RegisterToken(raw, &auth.TokenRecord{TenantID: tenantID, Role: role, Subject: "qa", ExpiresAt: time.Now().Add(time.Hour)})
		return raw
	}
	triager, ci := mint("triager-secret", auth.RoleTriager), mint("ci-secret", auth.RoleIngest)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	var seq int
	send := func(token string, fields map[string]string) (*httptest.ResponseRecorder, ingest.DirectReportResponse) {
		seq++
		fields["track"], fields["format"] = "main", "sarif"
		fields["repository"] = fmt.Sprintf("github.com/acme/repo-%d", seq) // a new asset each time, so no asset already has an application
		rec := postReport(t, mux, token, fields, "r.sarif", sarifOf("x"))
		var out ingest.DirectReportResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}
	exists := func(slug string) bool {
		a, err := gw.Store().LookupApplication(t.Context(), tenantID, slug)
		return err == nil && a != nil
	}

	// createApplication=false: a name that does not exist is a 404 that says what to do, and nothing is made.
	rec, _ := send(admin, map[string]string{"application": "rampart-demo-appp", "createApplication": "false"})
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "application-not-found") || !strings.Contains(rec.Body.String(), "createApplication=true") {
		t.Fatalf("a missing application with createApplication=false: want 404 application-not-found, got %d %s", rec.Code, rec.Body.String())
	}
	if exists("rampart-demo-appp") {
		t.Fatal("a refused upload must not make the application")
	}

	// createApplication=true by a maintainer or an admin: made, said so, no warning.
	rec, out := send(admin, map[string]string{"application": "billing", "createApplication": "true"})
	if rec.Code != http.StatusCreated || !out.ApplicationCreated || out.Application != "billing" || len(out.Warnings) != 0 || !exists("billing") {
		t.Fatalf("explicit create: %d %+v", rec.Code, out)
	}
	// A CI token may NEVER create an application (GitOps governance: applications must be declared via CRD).
	rec, _ = send(ci, map[string]string{"application": "payments", "createApplication": "true"})
	if rec.Code != http.StatusForbidden || exists("payments") {
		t.Fatalf("a CI token creating: want 403 and nothing made, got %d %s", rec.Code, rec.Body.String())
	}
	// A triager may not: it decides about findings, it does not add applications.
	rec, _ = send(triager, map[string]string{"application": "shadow", "createApplication": "true"})
	if rec.Code != http.StatusForbidden || exists("shadow") {
		t.Fatalf("a triager creating: want 403 and nothing made, got %d %s", rec.Code, rec.Body.String())
	}

	// An application that exists is used, whatever createApplication says.
	for _, v := range []string{"false", "true", ""} {
		rec, out = send(admin, map[string]string{"application": "billing", "createApplication": v})
		if rec.Code != http.StatusCreated || out.ApplicationCreated || out.Application != "billing" || len(out.Warnings) != 0 {
			t.Errorf("createApplication=%q on an existing application: %d %+v", v, rec.Code, out)
		}
	}

	// A CI token reporting to an existing application succeeds.
	rec, out = send(ci, map[string]string{"application": "billing"})
	if rec.Code != http.StatusCreated || out.ApplicationCreated || out.Application != "billing" {
		t.Fatalf("CI reporting to existing application: %d %+v", rec.Code, out)
	}

	// Without createApplication=true, a missing application is refused (fail-closed, no accidental creations).
	rec, _ = send(admin, map[string]string{"application": "legacy-pipeline"})
	if rec.Code != http.StatusNotFound || exists("legacy-pipeline") {
		t.Fatalf("missing application without explicit create flag: want 404, got %d %s", rec.Code, rec.Body.String())
	}
	// CI token reporting to a missing application is refused with 404.
	rec, _ = send(ci, map[string]string{"application": "legacy-ci-svc"})
	if rec.Code != http.StatusNotFound || exists("legacy-ci-svc") {
		t.Fatalf("CI reporting to missing application: want 404, got %d %s", rec.Code, rec.Body.String())
	}

	// No application named at all is Unassigned, which is never a creation the caller has to ask for.
	if rec, out = send(admin, map[string]string{"createApplication": "false"}); rec.Code != http.StatusCreated || out.ApplicationCreated {
		t.Errorf("no application named: %d %+v", rec.Code, out)
	}
}

// docs/04 spec.trackedRefs, end to end: a branch the source lists changes the inventory, another does not, and a
// source that lists nothing keeps the defaults. Before, develop and staging were ephemeral for everyone.
func TestDirectUpload_TrackedRefsOfTheSourceDecideWhatChangesTheInventory(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)
	mem := gw.Store().(*ingest.MemoryStore)

	listing, plain := uuid.New(), uuid.New() // two sources: one lists develop and staging, one lists nothing
	mem.SetIngestionPolicy(tenantID, listing, domain.WithTrackedRefs(nil, []string{"develop", "staging"}))

	count := func() int {
		fs, _ := gw.Store().ListFindings(t.Context(), tenantID)
		return len(fs)
	}
	send := func(source uuid.UUID, branch, repo string) {
		t.Helper()
		rec := postReport(t, mux, token, map[string]string{"format": "sarif", "source": source.String(), "branch": branch, "repository": repo}, "r.sarif", sarifOf("x"))
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s on %s: %d %s", branch, source, rec.Code, rec.Body.String())
		}
	}

	for _, c := range []struct {
		name    string
		source  uuid.UUID
		branch  string
		repo    string
		changes bool
	}{
		{"a listed branch changes the inventory", listing, "develop", "github.com/acme/a", true},
		{"another listed one", listing, "staging", "github.com/acme/b", true},
		{"a branch the source does not list is ephemeral", listing, "feature/login", "github.com/acme/c", false},
		{"listing develop replaces the defaults: main is ephemeral for this source", listing, "main", "github.com/acme/d", false},
		{"a source that lists nothing keeps the defaults: main is tracked", plain, "main", "github.com/acme/e", true},
		{"and develop is ephemeral for it", plain, "develop", "github.com/acme/f", false},
		{"a pull request is ephemeral for every source", listing, "pr/42", "github.com/acme/g", false},
	} {
		before := count()
		send(c.source, c.branch, c.repo)
		if got := count() > before; got != c.changes {
			t.Errorf("%s: the inventory changed=%v, want %v", c.name, got, c.changes)
		}
	}
}
