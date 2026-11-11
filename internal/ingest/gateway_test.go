package ingest_test

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"rampart/internal/ingest"
	"rampart/internal/jobs"

	"github.com/google/uuid"
)

func TestGatewayUploadFlow(t *testing.T) {
	queue := jobs.NewInMemJobQueue()
	gw := ingest.NewGateway(queue)

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	// 1. Create Upload
	createReq := ingest.CreateUploadRequest{
		ScanSourceID: "01931f6a-0000-7000-8000-000000000001",
		FormatHint:   "sarif",
		SizeBytes:    1024,
	}
	bodyBytes, _ := json.Marshal(createReq)

	req := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(bodyBytes))
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

	// 2. Test Idempotency with same key -> returns 200 OK with identical UploadID (D2)
	reqIdem := httptest.NewRequest("POST", "/ingest/v1/uploads", bytes.NewReader(bodyBytes))
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

	// 3. Complete Upload
	completeReq := ingest.CompleteUploadRequest{
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	completeBytes, _ := json.Marshal(completeReq)

	reqComplete := httptest.NewRequest("POST", "/ingest/v1/uploads/"+createRes.UploadID+"/complete", bytes.NewReader(completeBytes))
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
	recRun := httptest.NewRecorder()
	mux.ServeHTTP(recRun, reqRun)

	if recRun.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get run, got %d: %s", recRun.Code, recRun.Body.String())
	}
}

func TestGatewayDirectReportUpload(t *testing.T) {
	gw := ingest.NewGateway(nil)
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
	req.Header.Set("X-Tenant-ID", "01931f6a-0000-7000-8000-000000000000")
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
	findings, _ := gw.Store().ListFindings(req.Context(), uuid.MustParse("01931f6a-0000-7000-8000-000000000000"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding stored, got %d", len(findings))
	}
}

func TestGatewaySBOMUploadCycloneDX(t *testing.T) {
	gw := ingest.NewGateway(nil)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	xmlData, err := os.ReadFile("../parsers/cyclonedx/testdata/sample.cdx.xml")
	if err != nil {
		t.Fatalf("failed to read CycloneDX XML fixture: %v", err)
	}

	req := httptest.NewRequest("POST", "/ingest/v1/sbom", bytes.NewReader(xmlData))
	req.Header.Set("Content-Type", "application/vnd.cyclonedx+xml")
	req.Header.Set("X-Tenant-ID", "01931f6a-0000-7000-8000-000000000000")
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
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	spdxData, err := os.ReadFile("../parsers/spdx/testdata/sample.spdx")
	if err != nil {
		t.Fatalf("failed to read SPDX Tag-Value fixture: %v", err)
	}

	req := httptest.NewRequest("POST", "/ingest/v1/sbom?format=spdx", bytes.NewReader(spdxData))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Tenant-ID", "01931f6a-0000-7000-8000-000000000000")
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
