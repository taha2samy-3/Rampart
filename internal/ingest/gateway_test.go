package ingest_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/ingest"
	"rampart/internal/jobs"

	"github.com/google/uuid"
)

func TestGatewayUploadFlow(t *testing.T) {
	queue := jobs.NewInMemJobQueue()
	gw := ingest.NewGateway(queue)

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

	sarifData, err := os.ReadFile("../parsers/sarif/testdata/semgrep.sarif")
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

	xmlData, err := os.ReadFile("../parsers/cyclonedx/testdata/sample.cdx.xml")
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
	if res.Created != 1 {
		t.Errorf("expected 1 VDR vulnerability created, got %d", res.Created)
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

	spdxData, err := os.ReadFile("../parsers/spdx/testdata/sample.spdx")
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
