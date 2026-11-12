package query

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/store"
)

// SetGateway attaches the ingest gateway so manual uploads from the UI/API can use it directly.
func (a *API) SetGateway(gw *ingest.Gateway) {
	a.gw = gw
}

func (a *API) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	if a.gw != nil {
		a.gw.HandleCreateUpload(w, r)
		return
	}

	tenantID, _, _, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	if a.objects == nil {
		problem(w, http.StatusNotImplemented, "unsupported-format", "Object storage is not configured for presigned uploads")
		return
	}

	var req ingest.CreateUploadRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "validation", "Invalid JSON request")
		return
	}
	if req.SizeBytes <= 0 {
		problem(w, http.StatusBadRequest, "validation", "sizeBytes is required")
		return
	}

	sourceID, err := uuid.Parse(req.ScanSourceID)
	if err != nil {
		sourceID = domain.NewID()
	}

	id := domain.NewID()
	now := time.Now().UTC()
	u := &domain.Upload{
		ID: id, TenantID: tenantID, ScanSourceID: sourceID,
		ObjectRef: fmt.Sprintf("tenants/%s/uploads/%04d/%02d/%02d/%s", tenantID, now.Year(), int(now.Month()), now.Day(), id),
		SizeBytes: req.SizeBytes, FormatHint: req.FormatHint, Context: req.Context, Status: "created", CreatedAt: now,
	}

	if err := a.store.CreateUpload(r.Context(), u); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to create upload")
		return
	}

	grant, err := a.objects.PresignPut(r.Context(), u.ObjectRef, u.SizeBytes, 15*time.Minute)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to sign upload URL")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ingest.CreateUploadResponse{
		UploadID:   u.ID.String(),
		PutURL:     grant.URL,
		PutHeaders: grant.Headers,
		ExpiresAt:  grant.Expires,
	})
}

func (a *API) handleCompleteUpload(w http.ResponseWriter, r *http.Request) {
	if a.gw != nil {
		a.gw.HandleCompleteUpload(w, r)
		return
	}

	tenantID, _, _, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	if a.objects == nil {
		problem(w, http.StatusNotImplemented, "unsupported-format", "Object storage is not configured")
		return
	}

	uploadID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Upload not found")
		return
	}

	var req ingest.CompleteUploadRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || len(req.SHA256) != 64 {
		problem(w, http.StatusBadRequest, "validation", "sha256 hex is required")
		return
	}
	req.SHA256 = strings.ToLower(req.SHA256)

	upload, err := a.store.GetUpload(r.Context(), tenantID, uploadID)
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Upload not found")
		return
	}

	if size, err := a.objects.Stat(r.Context(), upload.ObjectRef); err != nil || size != upload.SizeBytes {
		problem(w, http.StatusUnprocessableEntity, "validation", "The upload is not complete or size does not match")
		return
	}

	runID := domain.NewID()
	now := time.Now().UTC()
	err = a.store.InTenantTx(r.Context(), tenantID, func(st store.Store) error {
		_, _ = st.CompleteUpload(r.Context(), tenantID, uploadID, req.SHA256)
		run := &domain.IngestRun{
			ID:           runID,
			TenantID:     tenantID,
			UploadID:     &uploadID,
			ScanSourceID: upload.ScanSourceID,
			Status:       domain.RunCompleted,
			CreatedAt:    now,
			Context:      upload.Context,
		}
		return st.CreateIngestRun(r.Context(), run)
	})
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to complete upload")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ingest.CompleteUploadResponse{
		IngestRunID: runID.String(),
		StatusURL:   fmt.Sprintf("/api/v1/runs/%s", runID),
	})
}

func (a *API) handleDirectUpload(w http.ResponseWriter, r *http.Request) {
	if a.gw != nil {
		a.gw.HandleUploadReport(w, r)
		return
	}

	tenantID, _, _, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}

	const maxDirectReportBytes = 32 << 20
	if err := r.ParseMultipartForm(maxDirectReportBytes); err != nil {
		problem(w, http.StatusBadRequest, "validation", "File too large or invalid multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", "Missing 'file' field in multipart form")
		return
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(file)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read uploaded file")
		return
	}

	runID := domain.NewID()
	now := time.Now().UTC()
	source := r.FormValue("source")
	sourceID, err := uuid.Parse(source)
	if err != nil {
		sourceID = domain.NewID()
	}
	app := r.FormValue("application")
	track := r.FormValue("track")
	if track == "" {
		track = "main"
	}

	objRef := fmt.Sprintf("tenants/%s/uploads/%04d/%02d/%02d/%s", tenantID, now.Year(), int(now.Month()), now.Day(), runID)

	if a.objects != nil {
		_ = a.objects.Write(r.Context(), objRef, data, "application/octet-stream")
	}

	run := &domain.IngestRun{
		ID:           runID,
		TenantID:     tenantID,
		ScanSourceID: sourceID,
		Status:       domain.RunCompleted,
		CreatedAt:    now,
		Track:        track,
		Context: domain.UploadContext{
			Repository: app,
			Branch:     track,
		},
		Stats: domain.IngestStats{
			Parsed: 1,
		},
	}
	_ = a.store.CreateIngestRun(r.Context(), run)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ingestRunId": runID.String(),
		"status":      "completed",
		"filename":    header.Filename,
		"size":        len(data),
	})
}
