package ingest_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	for _, format := range []string{"trivy", "builtin:trivy", "semgrep", "checkov", "grype", "gitleaks"} {
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
