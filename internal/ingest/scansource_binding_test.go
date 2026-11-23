package ingest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/objectstore"
)

// Helper to set up gateway fixture
func setupBindingTest(t *testing.T) (*ingest.Gateway, *http.ServeMux, uuid.UUID, string) {
	t.Helper()
	gw := ingest.NewGateway(nil)
	objects := objectstore.NewMemory()
	gw.SetObjectStore(objects)

	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	return gw, mux, tenantID, token
}

func TestGateway_ApplicationMismatch_Returns403(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	// 1. Create target application
	appID := domain.NewID()
	app := &domain.Application{
		ID:                  appID,
		TenantID:            tenantID,
		Slug:                "payments-service",
		Name:                "payments-service",
		Branch:              "main",
		BusinessCriticality: "high",
		Lifecycle:           "production",
		Version:             1,
		CreatedAt:           time.Now().UTC(),
	}
	if err := gw.Store().CreateApplication(ctx, app); err != nil {
		t.Fatalf("failed to create application: %v", err)
	}

	// 2. Create ScanSource bound to payments-service
	srcID := domain.NewID()
	src := &domain.ScanSource{
		ID:             srcID,
		TenantID:       tenantID,
		Name:           "payments-ci",
		ApplicationID:  appID,
		ApplicationRef: domain.ApplicationRef{Name: "payments-service"},
		Categories:     []string{"all"},
		Type:           "upload",
	}
	if _, err := gw.Store().SaveScanSourceRecord(ctx, src); err != nil {
		t.Fatalf("failed to save scan source: %v", err)
	}

	sarifData, err := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")
	if err != nil {
		t.Fatalf("failed to read sarif: %v", err)
	}

	// 3. Attempt upload specifying mismatched application
	var bMismatch bytes.Buffer
	wMismatch := multipart.NewWriter(&bMismatch)
	_ = wMismatch.WriteField("format", "sarif")
	_ = wMismatch.WriteField("source", srcID.String())
	_ = wMismatch.WriteField("app", "fraud-detection") // Mismatched!
	partMismatch, _ := wMismatch.CreateFormFile("file", "report.sarif")
	_, _ = partMismatch.Write(sarifData)
	_ = wMismatch.Close()

	reqMismatch := httptest.NewRequest("POST", "/ingest/v1/reports", &bMismatch)
	reqMismatch.Header.Set("Content-Type", wMismatch.FormDataContentType())
	reqMismatch.Header.Set("Authorization", "Bearer "+token)
	recMismatch := httptest.NewRecorder()
	mux.ServeHTTP(recMismatch, reqMismatch)

	if recMismatch.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on application mismatch, got %d: %s", recMismatch.Code, recMismatch.Body.String())
	}
	if !strings.Contains(recMismatch.Body.String(), "application_mismatch") {
		t.Errorf("expected error detail to mention 'application_mismatch', got: %s", recMismatch.Body.String())
	}

	// 4. Attempt upload matching application -> 201 Created
	var bMatch bytes.Buffer
	wMatch := multipart.NewWriter(&bMatch)
	_ = wMatch.WriteField("format", "sarif")
	_ = wMatch.WriteField("source", srcID.String())
	_ = wMatch.WriteField("app", "payments-service") // Exact match
	partMatch, _ := wMatch.CreateFormFile("file", "report.sarif")
	_, _ = partMatch.Write(sarifData)
	_ = wMatch.Close()

	reqMatch := httptest.NewRequest("POST", "/ingest/v1/reports", &bMatch)
	reqMatch.Header.Set("Content-Type", wMatch.FormDataContentType())
	reqMatch.Header.Set("Authorization", "Bearer "+token)
	recMatch := httptest.NewRecorder()
	mux.ServeHTTP(recMatch, reqMatch)

	if recMatch.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on matching application, got %d: %s", recMatch.Code, recMatch.Body.String())
	}
	var res ingest.DirectReportResponse
	_ = json.NewDecoder(recMatch.Body).Decode(&res)
	if res.Application != "payments-service" {
		t.Errorf("expected application 'payments-service', got %q", res.Application)
	}
}

func TestGateway_CategoryEnforcement_PermittedAndRejected(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	// Create ScanSource limited strictly to SAST
	sastSourceID := domain.NewID()
	src := &domain.ScanSource{
		ID:         sastSourceID,
		TenantID:   tenantID,
		Name:       "sast-only-pipeline",
		Categories: []string{"sast"},
		Type:       "upload",
	}
	if _, err := gw.Store().SaveScanSourceRecord(ctx, src); err != nil {
		t.Fatalf("failed to save scan source: %v", err)
	}

	// 1. Upload SAST report (Semgrep SARIF) -> Must succeed
	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")
	var bSAST bytes.Buffer
	wSAST := multipart.NewWriter(&bSAST)
	_ = wSAST.WriteField("format", "sarif")
	_ = wSAST.WriteField("source", sastSourceID.String())
	partSAST, _ := wSAST.CreateFormFile("file", "report.sarif")
	_, _ = partSAST.Write(sarifData)
	_ = wSAST.Close()

	reqSAST := httptest.NewRequest("POST", "/ingest/v1/reports", &bSAST)
	reqSAST.Header.Set("Content-Type", wSAST.FormDataContentType())
	reqSAST.Header.Set("Authorization", "Bearer "+token)
	recSAST := httptest.NewRecorder()
	mux.ServeHTTP(recSAST, reqSAST)

	if recSAST.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for permitted category SAST, got %d: %s", recSAST.Code, recSAST.Body.String())
	}

	// 2. Upload SCA report (CycloneDX SBOM) to SAST-only source -> Must fail 403 Forbidden
	xmlData, _ := os.ReadFile("../testdata/reports/sbom-cyclonedx/sample.cdx.xml")
	reqSCA := httptest.NewRequest("POST", "/ingest/v1/sbom?source="+sastSourceID.String(), bytes.NewReader(xmlData))
	reqSCA.Header.Set("Content-Type", "application/vnd.cyclonedx+xml")
	reqSCA.Header.Set("Authorization", "Bearer "+token)
	recSCA := httptest.NewRecorder()
	mux.ServeHTTP(recSCA, reqSCA)

	if recSCA.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disallowed category SCA, got %d: %s", recSCA.Code, recSCA.Body.String())
	}
	if !strings.Contains(recSCA.Body.String(), "category_not_permitted") {
		t.Errorf("expected detail to mention 'category_not_permitted', got: %s", recSCA.Body.String())
	}
}

func TestGateway_CategoryAll_PermitsAllDisciplines(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	// Create ScanSource with "all" categories
	allSourceID := domain.NewID()
	src := &domain.ScanSource{
		ID:         allSourceID,
		TenantID:   tenantID,
		Name:       "omni-pipeline",
		Categories: []string{"all"},
		Type:       "upload",
	}
	if _, err := gw.Store().SaveScanSourceRecord(ctx, src); err != nil {
		t.Fatalf("failed to save scan source: %v", err)
	}

	// 1. Upload SAST -> 201 Created
	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")
	var bSAST bytes.Buffer
	wSAST := multipart.NewWriter(&bSAST)
	_ = wSAST.WriteField("format", "sarif")
	_ = wSAST.WriteField("source", allSourceID.String())
	partSAST, _ := wSAST.CreateFormFile("file", "report.sarif")
	_, _ = partSAST.Write(sarifData)
	_ = wSAST.Close()

	reqSAST := httptest.NewRequest("POST", "/ingest/v1/reports", &bSAST)
	reqSAST.Header.Set("Content-Type", wSAST.FormDataContentType())
	reqSAST.Header.Set("Authorization", "Bearer "+token)
	recSAST := httptest.NewRecorder()
	mux.ServeHTTP(recSAST, reqSAST)

	if recSAST.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for SAST on 'all' source, got %d: %s", recSAST.Code, recSAST.Body.String())
	}

	// 2. Upload SBOM (SCA) -> 201 Created
	xmlData, _ := os.ReadFile("../testdata/reports/sbom-cyclonedx/sample.cdx.xml")
	reqSCA := httptest.NewRequest("POST", "/ingest/v1/sbom?source="+allSourceID.String(), bytes.NewReader(xmlData))
	reqSCA.Header.Set("Content-Type", "application/vnd.cyclonedx+xml")
	reqSCA.Header.Set("Authorization", "Bearer "+token)
	recSCA := httptest.NewRecorder()
	mux.ServeHTTP(recSCA, reqSCA)

	if recSCA.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for SCA on 'all' source, got %d: %s", recSCA.Code, recSCA.Body.String())
	}
}

func TestGateway_BranchBaseline_Ephemerality(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	// Application defines production baseline branch "main" (D140)
	appID := domain.NewID()
	app := &domain.Application{
		ID:                  appID,
		TenantID:            tenantID,
		Slug:                "auth-service",
		Name:                "auth-service",
		Branch:              "main",
		BusinessCriticality: "critical",
		Lifecycle:           "production",
		Version:             1,
		CreatedAt:           time.Now().UTC(),
	}
	if err := gw.Store().CreateApplication(ctx, app); err != nil {
		t.Fatalf("failed to create application: %v", err)
	}

	srcID := domain.NewID()
	src := &domain.ScanSource{
		ID:            srcID,
		TenantID:      tenantID,
		Name:          "auth-ci",
		ApplicationID: appID,
		Categories:    []string{"all"},
		Type:          "upload",
	}
	if _, err := gw.Store().SaveScanSourceRecord(ctx, src); err != nil {
		t.Fatalf("failed to save scan source: %v", err)
	}

	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")

	// 1. Upload on baseline branch "main" -> Production run
	var bMain bytes.Buffer
	wMain := multipart.NewWriter(&bMain)
	_ = wMain.WriteField("format", "sarif")
	_ = wMain.WriteField("source", srcID.String())
	_ = wMain.WriteField("branch", "main")
	partMain, _ := wMain.CreateFormFile("file", "report.sarif")
	_, _ = partMain.Write(sarifData)
	_ = wMain.Close()

	reqMain := httptest.NewRequest("POST", "/ingest/v1/reports", &bMain)
	reqMain.Header.Set("Content-Type", wMain.FormDataContentType())
	reqMain.Header.Set("Authorization", "Bearer "+token)
	recMain := httptest.NewRecorder()
	mux.ServeHTTP(recMain, reqMain)

	if recMain.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on main branch, got %d: %s", recMain.Code, recMain.Body.String())
	}

	var resMain ingest.DirectReportResponse
	_ = json.NewDecoder(recMain.Body).Decode(&resMain)
	if resMain.Created != 1 {
		t.Errorf("expected 1 finding created on main branch, got %d", resMain.Created)
	}

	// 2. Upload on PR branch "feature/oauth2" -> Ephemeral run (does not create persistent findings)
	var bPR bytes.Buffer
	wPR := multipart.NewWriter(&bPR)
	_ = wPR.WriteField("format", "sarif")
	_ = wPR.WriteField("source", srcID.String())
	_ = wPR.WriteField("branch", "feature/oauth2")
	partPR, _ := wPR.CreateFormFile("file", "report.sarif")
	_, _ = partPR.Write(sarifData)
	_ = wPR.Close()

	reqPR := httptest.NewRequest("POST", "/ingest/v1/reports", &bPR)
	reqPR.Header.Set("Content-Type", wPR.FormDataContentType())
	reqPR.Header.Set("Authorization", "Bearer "+token)
	recPR := httptest.NewRecorder()
	mux.ServeHTTP(recPR, reqPR)

	if recPR.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on PR branch, got %d: %s", recPR.Code, recPR.Body.String())
	}
}

func TestGateway_CreateUpload_CategoryAndAppMismatch(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	appID := domain.NewID()
	app := &domain.Application{
		ID:        appID,
		TenantID:  tenantID,
		Slug:      "core-backend",
		Name:      "core-backend",
		Branch:    "main",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	_ = gw.Store().CreateApplication(ctx, app)

	srcID := domain.NewID()
	src := &domain.ScanSource{
		ID:            srcID,
		TenantID:      tenantID,
		Name:          "backend-sast",
		ApplicationID: appID,
		Categories:    []string{"sast"},
		Type:          "upload",
	}
	_, _ = gw.Store().SaveScanSourceRecord(ctx, src)

	// 1. Test Application Mismatch on presigned upload request
	reqBodyMismatch, _ := json.Marshal(ingest.CreateUploadRequest{
		ScanSourceID: srcID.String(),
		FormatHint:   "sarif",
		SizeBytes:    1024,
		Context: domain.UploadContext{
			Application: "frontend-spa", // Mismatched!
		},
	})
	reqMismatch := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(reqBodyMismatch))
	reqMismatch.Header.Set("Authorization", "Bearer "+token)
	recMismatch := httptest.NewRecorder()
	mux.ServeHTTP(recMismatch, reqMismatch)

	if recMismatch.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on presigned upload app mismatch, got %d: %s", recMismatch.Code, recMismatch.Body.String())
	}

	// 2. Test Category Disallowed on presigned upload request (cyclonedx is SCA, source allows SAST only)
	reqBodyCatMismatch, _ := json.Marshal(ingest.CreateUploadRequest{
		ScanSourceID: srcID.String(),
		FormatHint:   "cyclonedx", // SCA! Disallowed
		SizeBytes:    1024,
		Context: domain.UploadContext{
			Application: "core-backend",
		},
	})
	reqCatMismatch := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(reqBodyCatMismatch))
	reqCatMismatch.Header.Set("Authorization", "Bearer "+token)
	recCatMismatch := httptest.NewRecorder()
	mux.ServeHTTP(recCatMismatch, reqCatMismatch)

	if recCatMismatch.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on presigned upload category mismatch, got %d: %s", recCatMismatch.Code, recCatMismatch.Body.String())
	}
}

func TestGateway_ScanSource_Disabled_Returns403(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	disabledTime := time.Now().UTC().Add(-1 * time.Hour)
	srcID := domain.NewID()
	src := &domain.ScanSource{
		ID:         srcID,
		TenantID:   tenantID,
		Name:       "retired-pipeline",
		Categories: []string{"all"},
		DisabledAt: &disabledTime,
		Type:       "upload",
	}
	_, _ = gw.Store().SaveScanSourceRecord(ctx, src)

	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("format", "sarif")
	_ = w.WriteField("source", srcID.String())
	part, _ := w.CreateFormFile("file", "report.sarif")
	_, _ = part.Write(sarifData)
	_ = w.Close()

	req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// A disabled source returns 403 Forbidden
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disabled source, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_ScanSource_BypassAttemptWithUnassigned_ForcesBoundApp(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	appID := domain.NewID()
	app := &domain.Application{
		ID:        appID,
		TenantID:  tenantID,
		Slug:      "billing-app",
		Name:      "billing-app",
		Branch:    "main",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	_ = gw.Store().CreateApplication(ctx, app)

	srcID := domain.NewID()
	src := &domain.ScanSource{
		ID:            srcID,
		TenantID:      tenantID,
		Name:          "billing-ci",
		ApplicationID: appID,
		Categories:    []string{"all"},
		Type:          "upload",
	}
	_, _ = gw.Store().SaveScanSourceRecord(ctx, src)

	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")

	// Client sends app="unassigned" in attempt to escape the binding
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("format", "sarif")
	_ = w.WriteField("source", srcID.String())
	_ = w.WriteField("app", "unassigned")
	part, _ := w.CreateFormFile("file", "report.sarif")
	_, _ = part.Write(sarifData)
	_ = w.Close()

	req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var res ingest.DirectReportResponse
	_ = json.NewDecoder(rec.Body).Decode(&res)
	// Must be filed under the bound application "billing-app", not unassigned
	if res.Application != "billing-app" {
		t.Fatalf("expected report to be filed under bound app 'billing-app', got %q", res.Application)
	}
}

func TestGateway_ScanSource_DanglingAppReference_Returns404(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	// ScanSource references non-existent Application ID
	danglingAppID := domain.NewID()
	srcID := domain.NewID()
	src := &domain.ScanSource{
		ID:            srcID,
		TenantID:      tenantID,
		Name:          "orphaned-source",
		ApplicationID: danglingAppID,
		Categories:    []string{"all"},
		Type:          "upload",
	}
	_, _ = gw.Store().SaveScanSourceRecord(ctx, src)

	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("format", "sarif")
	_ = w.WriteField("source", srcID.String())
	part, _ := w.CreateFormFile("file", "report.sarif")
	_, _ = part.Write(sarifData)
	_ = w.Close()

	req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for dangling application reference, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_ScanSource_MultipleCategories_PermitsAndRejects(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	srcID := domain.NewID()
	src := &domain.ScanSource{
		ID:         srcID,
		TenantID:   tenantID,
		Name:       "multi-cat-source",
		Categories: []string{"sast", "secret"}, // Allows sast and secret, forbids sca
		Type:       "upload",
	}
	_, _ = gw.Store().SaveScanSourceRecord(ctx, src)

	// 1. Upload SAST -> 201 Created
	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")
	var bSAST bytes.Buffer
	wSAST := multipart.NewWriter(&bSAST)
	_ = wSAST.WriteField("format", "sarif")
	_ = wSAST.WriteField("source", srcID.String())
	partSAST, _ := wSAST.CreateFormFile("file", "report.sarif")
	_, _ = partSAST.Write(sarifData)
	_ = wSAST.Close()

	reqSAST := httptest.NewRequest("POST", "/ingest/v1/reports", &bSAST)
	reqSAST.Header.Set("Content-Type", wSAST.FormDataContentType())
	reqSAST.Header.Set("Authorization", "Bearer "+token)
	recSAST := httptest.NewRecorder()
	mux.ServeHTTP(recSAST, reqSAST)

	if recSAST.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for permitted SAST, got %d: %s", recSAST.Code, recSAST.Body.String())
	}

	// 2. Upload SCA (CycloneDX) -> 403 Forbidden
	xmlData, _ := os.ReadFile("../testdata/reports/sbom-cyclonedx/sample.cdx.xml")
	reqSCA := httptest.NewRequest("POST", "/ingest/v1/sbom?source="+srcID.String(), bytes.NewReader(xmlData))
	reqSCA.Header.Set("Content-Type", "application/vnd.cyclonedx+xml")
	reqSCA.Header.Set("Authorization", "Bearer "+token)
	recSCA := httptest.NewRecorder()
	mux.ServeHTTP(recSCA, reqSCA)

	if recSCA.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disallowed SCA, got %d: %s", recSCA.Code, recSCA.Body.String())
	}
}

func TestGateway_ScanSource_TokenBoundToDifferentSource_Returns403(t *testing.T) {
	gw, mux, tenantID, _ := setupBindingTest(t)
	ctx := context.Background()

	sourceA := domain.NewID()
	sourceB := domain.NewID()
	_, _ = gw.Store().SaveScanSourceRecord(ctx, &domain.ScanSource{ID: sourceA, TenantID: tenantID, Name: "source-a", Categories: []string{"all"}})
	_, _ = gw.Store().SaveScanSourceRecord(ctx, &domain.ScanSource{ID: sourceB, TenantID: tenantID, Name: "source-b", Categories: []string{"all"}})

	// Create scoped token bound to sourceA
	rawToken, tokenRec, err := auth.GenerateToken(tenantID, auth.RoleIngest, "bound-user", nil, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	tokenRec.ScanSourceID = &sourceA
	if st, ok := gw.Store().(*ingest.MemoryStore); ok {
		_ = st.SaveToken(ctx, tokenRec)
	}

	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("format", "sarif")
	_ = w.WriteField("source", sourceB.String()) // Different source!
	part, _ := w.CreateFormFile("file", "report.sarif")
	_, _ = part.Write(sarifData)
	_ = w.Close()

	req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for token bound to different source, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_ScanSource_CaseInsensitiveApplicationMatching(t *testing.T) {
	gw, mux, tenantID, token := setupBindingTest(t)
	ctx := context.Background()

	appID := domain.NewID()
	app := &domain.Application{
		ID:        appID,
		TenantID:  tenantID,
		Slug:      "user-service",
		Name:      "User-Service",
		Branch:    "main",
		Version:   1,
		CreatedAt: time.Now().UTC(),
	}
	_ = gw.Store().CreateApplication(ctx, app)

	srcID := domain.NewID()
	src := &domain.ScanSource{
		ID:            srcID,
		TenantID:      tenantID,
		Name:          "user-ci",
		ApplicationID: appID,
		Categories:    []string{"all"},
		Type:          "upload",
	}
	_, _ = gw.Store().SaveScanSourceRecord(ctx, src)

	sarifData, _ := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")

	// Client sends app="USER-SERVICE" (differing in case)
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("format", "sarif")
	_ = w.WriteField("source", srcID.String())
	_ = w.WriteField("app", "USER-SERVICE")
	part, _ := w.CreateFormFile("file", "report.sarif")
	_, _ = part.Write(sarifData)
	_ = w.Close()

	req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for case-insensitive match, got %d: %s", rec.Code, rec.Body.String())
	}
}
