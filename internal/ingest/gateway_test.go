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

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/jobs"
	"rampart/internal/objectstore"
	"rampart/internal/wasmstore"

	"github.com/google/uuid"
)

func TestGatewayUploadFlow(t *testing.T) {
	queue := jobs.NewInMemJobQueue()
	gw := ingest.NewGateway(queue)
	objects := objectstore.NewMemory()
	gw.SetObjectStore(objects)

	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	// 0. Verify Unauthenticated request returns 401 Unauthorized (Security A)
	createReq := ingest.CreateUploadRequest{
		ScanSourceID: "01931f6a-0000-7000-8000-000000000001",
		FormatHint:   "sarif",
		SizeBytes:    1024,
	}
	bodyBytes, _ := json.Marshal(createReq)

	reqUnauth := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(bodyBytes))
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated request, got %d", recUnauth.Code)
	}

	// 1. Create Upload with valid Bearer token
	req := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", "test-key-123")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var createRes ingest.CreateUploadResponse
	if err := json.NewDecoder(rec.Body).Decode(&createRes); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}
	if createRes.UploadID == "" {
		t.Fatal("expected non-empty uploadId")
	}

	// 2. Test Idempotency with exact same key and payload -> 200 OK with identical UploadID (D9)
	reqIdem := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(bodyBytes))
	reqIdem.Header.Set("Authorization", "Bearer "+token)
	reqIdem.Header.Set("Idempotency-Key", "test-key-123")
	recIdem := httptest.NewRecorder()
	mux.ServeHTTP(recIdem, reqIdem)

	if recIdem.Code != http.StatusOK {
		t.Errorf("expected 200 OK on idempotent retry, got %d", recIdem.Code)
	}

	var resIdem ingest.CreateUploadResponse
	_ = json.NewDecoder(recIdem.Body).Decode(&resIdem)
	if resIdem.UploadID != createRes.UploadID {
		t.Errorf("expected idempotent upload ID %s, got %s", createRes.UploadID, resIdem.UploadID)
	}

	// 2b. Test Idempotency Conflict (D9): same key with DIFFERENT payload -> 409 Conflict
	conflictReq := ingest.CreateUploadRequest{
		ScanSourceID: "01931f6a-0000-7000-8000-000000000001",
		FormatHint:   "cyclonedx", // altered payload
		SizeBytes:    2048,
	}
	conflictBytes, _ := json.Marshal(conflictReq)
	reqConflict := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(conflictBytes))
	reqConflict.Header.Set("Authorization", "Bearer "+token)
	reqConflict.Header.Set("Idempotency-Key", "test-key-123")
	recConflict := httptest.NewRecorder()
	mux.ServeHTTP(recConflict, reqConflict)

	if recConflict.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for reused idempotency key with different payload, got %d", recConflict.Code)
	}

	// 3a. Completing before the object arrived is refused (D9).
	early, _ := json.Marshal(ingest.CompleteUploadRequest{SHA256: strings.Repeat("a", 64)})
	reqEarly := httptest.NewRequest("POST", "/ingest/v1/uploads/"+createRes.UploadID+"/complete", bytes.NewReader(early))
	reqEarly.Header.Set("Authorization", "Bearer "+token)
	recEarly := httptest.NewRecorder()
	mux.ServeHTTP(recEarly, reqEarly)
	if recEarly.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 before the object is uploaded, got %d", recEarly.Code)
	}
	objects.Put(strings.TrimPrefix(createRes.PutURL, objects.Base), make([]byte, 1024))

	// 3. Complete Upload
	completeReq := ingest.CompleteUploadRequest{
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	completeBytes, _ := json.Marshal(completeReq)

	reqComplete := httptest.NewRequest("POST", "/ingest/v1/uploads/"+createRes.UploadID+"/complete", bytes.NewReader(completeBytes))
	reqComplete.Header.Set("Authorization", "Bearer "+token)
	recComplete := httptest.NewRecorder()
	mux.ServeHTTP(recComplete, reqComplete)

	if recComplete.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on complete, got %d: %s", recComplete.Code, recComplete.Body.String())
	}

	var completeRes ingest.CompleteUploadResponse
	_ = json.NewDecoder(recComplete.Body).Decode(&completeRes)
	if completeRes.IngestRunID == "" {
		t.Fatal("expected non-empty ingestRunId")
	}

	// Verify job was placed on parse queue (D2)
	select {
	case job := <-queue.ParseJobs:
		if job.IngestRunID.String() != completeRes.IngestRunID {
			t.Errorf("expected job for run %s, got %s", completeRes.IngestRunID, job.IngestRunID)
		}
	default:
		t.Error("expected ParseJob to be enqueued in queue")
	}

	// 4. Query Ingest Run status
	reqRun := httptest.NewRequest("GET", "/ingest/v1/runs/"+completeRes.IngestRunID, nil)
	reqRun.Header.Set("Authorization", "Bearer "+token)
	recRun := httptest.NewRecorder()
	mux.ServeHTTP(recRun, reqRun)

	if recRun.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get run, got %d: %s", recRun.Code, recRun.Body.String())
	}
}

func TestGatewayDirectReportUpload(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	sarifData, err := os.ReadFile("../testdata/reports/sarif/semgrep.sarif")
	if err != nil {
		t.Fatalf("failed to read sarif fixture: %v", err)
	}

	// Prepare multipart form
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	_ = w.WriteField("format", "sarif")
	_ = w.WriteField("track", "main")
	part, err := w.CreateFormFile("file", "semgrep.sarif")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write(sarifData)
	_ = w.Close()

	req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on reports upload, got %d: %s", rec.Code, rec.Body.String())
	}

	var res ingest.DirectReportResponse
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode report response: %v", err)
	}
	if res.Status != "completed" {
		t.Errorf("expected status 'completed', got %q", res.Status)
	}
	if res.Created != 1 {
		t.Errorf("expected 1 finding created, got %d", res.Created)
	}

	// Verify findings in store
	findings, _ := gw.Store().ListFindings(req.Context(), tenantID)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding stored, got %d", len(findings))
	}

	// 2. Rescan: upload identical file again. Verifies D10 asset resolution & D13 dedup (0 created, 1 untouched)
	var b2 bytes.Buffer
	w2 := multipart.NewWriter(&b2)
	_ = w2.WriteField("format", "sarif")
	_ = w2.WriteField("track", "main")
	part2, _ := w2.CreateFormFile("file", "semgrep.sarif")
	_, _ = part2.Write(sarifData)
	_ = w2.Close()

	req2 := httptest.NewRequest("POST", "/ingest/v1/reports", &b2)
	req2.Header.Set("Content-Type", w2.FormDataContentType())
	req2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on rescan upload, got %d", rec2.Code)
	}

	var res2 ingest.DirectReportResponse
	_ = json.NewDecoder(rec2.Body).Decode(&res2)
	if res2.Created != 0 {
		t.Errorf("expected 0 new findings on rescan, got %d (deduplication broken!)", res2.Created)
	}
	if res2.Untouched != 1 {
		t.Errorf("expected 1 untouched finding on rescan, got %d", res2.Untouched)
	}
}

func TestGatewaySBOMUploadCycloneDX(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	xmlData, err := os.ReadFile("../testdata/reports/sbom-cyclonedx/sample.cdx.xml")
	if err != nil {
		t.Fatalf("failed to read CycloneDX XML fixture: %v", err)
	}

	req := httptest.NewRequest("POST", "/ingest/v1/sbom", bytes.NewReader(xmlData))
	req.Header.Set("Content-Type", "application/vnd.cyclonedx+xml")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on sbom upload, got %d: %s", rec.Code, rec.Body.String())
	}

	var res ingest.DirectReportResponse
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode sbom response: %v", err)
	}
	if res.ComponentCount != 1 {
		t.Errorf("expected 1 component extracted, got %d", res.ComponentCount)
	}
	// An SBOM is assets, not findings (docs/34 C2): the fixture names a vulnerability and none is created from it.
	if res.Created != 0 {
		t.Errorf("an SBOM upload created %d finding(s); it must create none", res.Created)
	}
	// The client named no parser, so the server chose one and says which.
	if res.Parser != "cyclonedx" || !res.Detected {
		t.Errorf("the response must name the parser the server detected: parser=%q detected=%v", res.Parser, res.Detected)
	}

	// With a name, the same file is read by that parser and the response says it was not detected.
	req = httptest.NewRequest("POST", "/ingest/v1/sbom?parser=cyclonedx", bytes.NewReader(xmlData))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a named parser: %d %s", rec.Code, rec.Body.String())
	}
	var named ingest.DirectReportResponse
	_ = json.NewDecoder(rec.Body).Decode(&named)
	if named.Parser != "cyclonedx" || named.Detected {
		t.Errorf("a named parser must not be reported as detected: parser=%q detected=%v", named.Parser, named.Detected)
	}
}

// A name the server does not know is refused with the names it does know, taken from what is installed.
func TestGatewayUnknownParserListsTheAvailableOnes(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/ingest/v1/reports?parser=no-such-parser", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown parser = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, name := range []string{"no-such-parser", "sarif", "trivy", "cyclonedx", "spdx"} {
		if !strings.Contains(body, name) {
			t.Errorf("the refusal does not mention %q: %s", name, body)
		}
	}
	if strings.Contains(body, "cluster:") || strings.Contains(body, "sbom-") {
		t.Errorf("the names must be the ones a client sends, without internal prefixes: %s", body)
	}
}

// The SBOM endpoint takes an SBOM only. A scanner report sent to it is refused, not stored as a "SBOM".
func TestGatewaySBOMEndpointRefusesAScanReport(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`
	req := httptest.NewRequest("POST", "/ingest/v1/sbom?format=sarif", strings.NewReader(sarif))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a scan report sent to the SBOM endpoint = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not an SBOM") {
		t.Errorf("the refusal does not say why: %s", rec.Body.String())
	}
}

func TestGatewaySBOMUploadSPDXTagValue(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	spdxData, err := os.ReadFile("../testdata/reports/sbom-spdx/sample.spdx")
	if err != nil {
		t.Fatalf("failed to read SPDX Tag-Value fixture: %v", err)
	}

	req := httptest.NewRequest("POST", "/ingest/v1/sbom?format=spdx", bytes.NewReader(spdxData))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on spdx sbom upload, got %d: %s", rec.Code, rec.Body.String())
	}

	var res ingest.DirectReportResponse
	_ = json.NewDecoder(rec.Body).Decode(&res)
	if res.ComponentCount != 1 {
		t.Errorf("expected 1 component from SPDX, got %d", res.ComponentCount)
	}
}

func TestGateway_RoleAuthZEnforcement(t *testing.T) {
	queue := jobs.NewInMemJobQueue()
	gw := ingest.NewGateway(queue)
	objects := objectstore.NewMemory()
	gw.SetObjectStore(objects)

	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	gw.SetAuthenticator(authn)

	// Create tokens: viewer token and admin token
	viewerToken, _, err := auth.GenerateToken(tenantID, auth.RoleViewer, "viewer@acme.com", []string{"tenant"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = gw.Store().(*ingest.MemoryStore).SaveToken(context.Background(), &auth.TokenRecord{
		TokenHash: auth.HashToken(viewerToken), TenantID: tenantID, Role: auth.RoleViewer,
	})

	adminToken := authn.DefaultAdminToken(tenantID)

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	createReq := ingest.CreateUploadRequest{
		ScanSourceID: "01931f6a-0000-7000-8000-000000000001",
		FormatHint:   "sarif",
		SizeBytes:    1024,
	}
	bodyBytes, _ := json.Marshal(createReq)

	// 1. Viewer cannot create upload -> 403 Forbidden
	reqViewerCreate := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(bodyBytes))
	reqViewerCreate.Header.Set("Authorization", "Bearer "+viewerToken)
	recViewerCreate := httptest.NewRecorder()
	mux.ServeHTTP(recViewerCreate, reqViewerCreate)
	if recViewerCreate.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer creating upload, got %d", recViewerCreate.Code)
	}

	// 2. Viewer cannot directly upload reports -> 403 Forbidden
	reqViewerDirect := httptest.NewRequest("POST", "/ingest/v1/reports", bytes.NewReader([]byte("{}")))
	reqViewerDirect.Header.Set("Authorization", "Bearer "+viewerToken)
	reqViewerDirect.Header.Set("Content-Type", "application/json")
	recViewerDirect := httptest.NewRecorder()
	mux.ServeHTTP(recViewerDirect, reqViewerDirect)
	if recViewerDirect.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer uploading report directly, got %d", recViewerDirect.Code)
	}

	// 3. Admin creates an upload
	reqAdminCreate := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(bodyBytes))
	reqAdminCreate.Header.Set("Authorization", "Bearer "+adminToken)
	recAdminCreate := httptest.NewRecorder()
	mux.ServeHTTP(recAdminCreate, reqAdminCreate)
	if recAdminCreate.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for admin creating upload, got %d", recAdminCreate.Code)
	}
	var createRes ingest.CreateUploadResponse
	_ = json.NewDecoder(recAdminCreate.Body).Decode(&createRes)

	// Put object so complete upload has something to find
	objects.Put("tenants/"+tenantID.String()+"/uploads/"+createRes.UploadID, make([]byte, 1024))

	completeReq := ingest.CompleteUploadRequest{
		SHA256: strings.Repeat("a", 64),
	}
	compBytes, _ := json.Marshal(completeReq)

	// 4. Viewer cannot complete upload -> 403 Forbidden
	reqViewerComp := httptest.NewRequest("POST", "/ingest/v1/uploads/"+createRes.UploadID+"/complete", bytes.NewReader(compBytes))
	reqViewerComp.Header.Set("Authorization", "Bearer "+viewerToken)
	reqViewerComp.Header.Set("Content-Type", "application/json")
	recViewerComp := httptest.NewRecorder()
	mux.ServeHTTP(recViewerComp, reqViewerComp)
	if recViewerComp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer completing upload, got %d", recViewerComp.Code)
	}

	// 5. Scoped token bound to another ScanSource cannot complete this upload -> 403 Forbidden
	otherSourceID := uuid.New()
	boundToken, _, err := auth.GenerateToken(tenantID, auth.RoleIngest, "ci@acme.com", []string{"tenant"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = gw.Store().(*ingest.MemoryStore).SaveToken(context.Background(), &auth.TokenRecord{
		TokenHash: auth.HashToken(boundToken), TenantID: tenantID, Role: auth.RoleIngest, ScanSourceID: &otherSourceID,
	})

	reqBoundComp := httptest.NewRequest("POST", "/ingest/v1/uploads/"+createRes.UploadID+"/complete", bytes.NewReader(compBytes))
	reqBoundComp.Header.Set("Authorization", "Bearer "+boundToken)
	reqBoundComp.Header.Set("Content-Type", "application/json")
	recBoundComp := httptest.NewRecorder()
	mux.ServeHTTP(recBoundComp, reqBoundComp)
	if recBoundComp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for token bound to different scan source, got %d", recBoundComp.Code)
	}
}

// An SBOM from a pull request or a feature branch changes nothing in the inventory (D10). It was saved all the same
// and replaced the SBOM of the real branch, so the inventory showed what the last pull request would install.
func TestGatewaySBOM_AnEphemeralRunLeavesTheInventoryAlone(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	xmlData, err := os.ReadFile("../testdata/reports/sbom-cyclonedx/sample.cdx.xml")
	if err != nil {
		t.Fatal(err)
	}
	send := func(query string) ingest.DirectReportResponse {
		req := httptest.NewRequest("POST", "/ingest/v1/sbom?repository=github.com/acme/shop&"+query, bytes.NewReader(xmlData))
		req.Header.Set("Content-Type", "application/vnd.cyclonedx+xml")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out ingest.DirectReportResponse
		if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("%s: %d %s", query, rec.Code, rec.Body.String())
		}
		return out
	}
	assetID := func() uuid.UUID {
		a, err := gw.Store().LookupAsset(t.Context(), tenantID, domain.AssetRepository, ingest.DeriveAssetKey(domain.AssetRepository, domain.UploadContext{Repository: "github.com/acme/shop"}))
		if err != nil || a == nil {
			t.Fatalf("the asset: %v", err)
		}
		return a.ID
	}

	if res := send("branch=main"); res.ComponentCount != 1 {
		t.Fatalf("a tracked branch saves its SBOM: %+v", res)
	}
	main, _, _ := gw.Store().GetSBOM(t.Context(), tenantID, assetID())
	if main == nil || main.Track != "main" {
		t.Fatalf("the SBOM of main is saved on the track main: %+v", main)
	}

	for _, branch := range []string{"feature/login", "pr/42", "refs/pull/7/merge"} {
		if res := send("branch=" + branch); res.ComponentCount != 0 {
			t.Errorf("%s is ephemeral: its SBOM must not be saved, got %d components", branch, res.ComponentCount)
		}
	}
	after, _, _ := gw.Store().GetSBOM(t.Context(), tenantID, assetID())
	if after == nil || after.ID != main.ID {
		t.Fatalf("the SBOM of main must still be the asset's: %+v", after)
	}
}

// A parser whose module is not installed refuses the upload before anything is created: no application, no asset and no run are left behind
// (docs/34 item 21, W3: the dev cluster's failed SBOM upload had made an empty application).
func TestGatewayUploadWithoutTheParsersModuleCreatesNothing(t *testing.T) {
	prev := wasmstore.Default()
	wasmstore.SetDefault(&wasmstore.Store{Dir: t.TempDir(), Digests: map[string]string{"x": strings.Repeat("0", 64)}}) // strict, empty
	t.Cleanup(func() { wasmstore.SetDefault(prev) })

	gw := ingest.NewGateway(nil)
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	xmlData, err := os.ReadFile("../testdata/reports/sbom-cyclonedx/sample.cdx.xml")
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "bom.cdx.xml")
	_, _ = fw.Write(xmlData)
	_ = mw.WriteField("format", "cyclonedx")
	_ = mw.WriteField("application", "brand-new-app")
	_ = mw.WriteField("createApplication", "true")
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/v1/uploads/direct", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "parser_unavailable") {
		// the route may be on the gateway under another path: try the SBOM endpoint the other test uses
		body2 := bytes.NewReader(xmlData)
		req2 := httptest.NewRequest("POST", "/ingest/v1/sbom?application=brand-new-app&createApplication=true", body2)
		req2.Header.Set("Content-Type", "application/vnd.cyclonedx+xml")
		req2.Header.Set("Authorization", "Bearer "+token)
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req2)
	}
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "parser_unavailable") {
		t.Fatalf("want 503 parser_unavailable, got %d: %s", rec.Code, rec.Body.String())
	}
	if app, _ := gw.Store().LookupApplication(context.Background(), tenantID, "brand-new-app"); app != nil {
		t.Fatalf("an application was created for an upload that could not be read: %+v", app)
	}
	if runs, _ := gw.Store().ListIngestRuns(context.Background(), tenantID, 10, nil); len(runs) != 0 {
		t.Fatalf("a failed run was left behind: %d", len(runs))
	}
}
