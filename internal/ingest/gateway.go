package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/integrations"
	"rampart/internal/jobs"
	"rampart/internal/normalize"
	"rampart/internal/parsers/cyclonedx"
	"rampart/internal/parsers/spdx"
	"rampart/internal/parsers/syft"
)

var (
	ErrUploadNotFound      = errors.New("ingest: upload not found")
	ErrIdempotencyConflict = errors.New("ingest: idempotency key reused with different payload")
	ErrUnsupportedFormat   = errors.New("ingest: unsupported report or SBOM format")
)

const (
	MaxDirectReportBytes = 32 << 20 // 32 MiB (docs/11 §1)
	DefaultTenantUUIDStr = "01931f6a-0000-7000-8000-000000000000"
)

// Upload represents an allocated upload record (D2).
type Upload struct {
	ID             uuid.UUID            `json:"id"`
	TenantID       uuid.UUID            `json:"tenant_id"`
	ScanSourceID   uuid.UUID            `json:"scan_source_id"`
	IdempotencyKey string               `json:"idempotency_key"`
	ObjectRef      string               `json:"object_ref"`
	SHA256         string               `json:"sha256,omitempty"`
	SizeBytes      int64                `json:"size_bytes"`
	FormatHint     string               `json:"format_hint,omitempty"`
	Context        domain.UploadContext `json:"context"`
	Status         string               `json:"status"` // created | completed | failed
	CreatedAt      time.Time            `json:"created_at"`
}

// CreateUploadRequest payload for POST /ingest/v1/uploads (docs/11).
type CreateUploadRequest struct {
	ScanSourceID string               `json:"source"`
	FormatHint   string               `json:"format,omitempty"`
	Filename     string               `json:"filename,omitempty"`
	SizeBytes    int64                `json:"sizeBytes,omitempty"`
	Context      domain.UploadContext `json:"context"`
}

// CreateUploadResponse return object.
type CreateUploadResponse struct {
	UploadID  string    `json:"uploadId"`
	PutURL    string    `json:"putUrl"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// CompleteUploadRequest payload for POST /ingest/v1/uploads/{id}/complete (docs/11).
type CompleteUploadRequest struct {
	SHA256 string `json:"sha256"`
}

// CompleteUploadResponse return object.
type CompleteUploadResponse struct {
	IngestRunID string `json:"ingestRunId"`
	StatusURL   string `json:"statusUrl"`
}

// DirectReportResponse return object for POST /ingest/v1/reports and /ingest/v1/sbom.
type DirectReportResponse struct {
	IngestRunID    string `json:"ingestRunId"`
	Status         string `json:"status"`
	Staged         int    `json:"staged"`
	Created        int    `json:"created"`
	Updated        int    `json:"updated"`
	Untouched      int    `json:"untouched"`
	Reactivated    int    `json:"reactivated"`
	Closed         int    `json:"closed"`
	ComponentCount int    `json:"componentCount,omitempty"`
}

// Gateway provides HTTP handlers for ingestion (docs/11).
type Gateway struct {
	queue    jobs.JobQueue
	mu       sync.RWMutex
	uploads  map[string]*Upload
	runs     map[string]*domain.IngestRun
	store    *MemoryStore
	engine   *Engine
	registry *integrations.Registry
	feeds    *enrich.FeedStore
}

// NewGateway creates a new ingest gateway instance with default dependencies.
func NewGateway(queue jobs.JobQueue) *Gateway {
	return NewGatewayWithDeps(queue, nil, nil, nil)
}

// NewGatewayWithDeps creates an ingest gateway instance with explicit dependencies.
func NewGatewayWithDeps(
	queue jobs.JobQueue,
	store *MemoryStore,
	registry *integrations.Registry,
	feeds *enrich.FeedStore,
) *Gateway {
	if store == nil {
		store = NewMemoryStore()
	}
	if registry == nil {
		registry = integrations.DefaultRegistry()
	}
	if feeds == nil {
		feeds = enrich.NewFeedStore()
	}

	return &Gateway{
		queue:    queue,
		uploads:  make(map[string]*Upload),
		runs:     make(map[string]*domain.IngestRun),
		store:    store,
		engine:   NewEngine(store),
		registry: registry,
		feeds:    feeds,
	}
}

// Store returns the underlying store for queries and inspection.
func (g *Gateway) Store() *MemoryStore {
	return g.store
}

// RegisterRoutes mounts all /ingest/v1 routes onto the router.
func (g *Gateway) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ingest/v1/uploads", g.handleCreateUpload)
	mux.HandleFunc("POST /ingest/v1/uploads/{id}/complete", g.handleCompleteUpload)
	mux.HandleFunc("POST /ingest/v1/reports", g.handleUploadReport)
	mux.HandleFunc("POST /ingest/v1/sbom", g.handleUploadSBOM)
	mux.HandleFunc("GET /ingest/v1/runs/{id}", g.handleGetRun)
}

func (g *Gateway) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	var req CreateUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid JSON request"}`, http.StatusBadRequest)
		return
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	tenantID := resolveTenantID(r)

	sourceID, err := uuid.Parse(req.ScanSourceID)
	if err != nil {
		sourceID = domain.NewID()
	}

	uploadID := domain.NewID()

	g.mu.Lock()
	if idempotencyKey != "" {
		for _, u := range g.uploads {
			if u.IdempotencyKey == idempotencyKey && u.TenantID == tenantID {
				g.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(CreateUploadResponse{
					UploadID:  u.ID.String(),
					PutURL:    fmt.Sprintf("/s3/uploads/%s", u.ID),
					ExpiresAt: u.CreatedAt.Add(15 * time.Minute),
				})
				return
			}
		}
	}

	upload := &Upload{
		ID:             uploadID,
		TenantID:       tenantID,
		ScanSourceID:   sourceID,
		IdempotencyKey: idempotencyKey,
		ObjectRef:      fmt.Sprintf("tenants/%s/uploads/%s", tenantID, uploadID),
		SizeBytes:      req.SizeBytes,
		FormatHint:     req.FormatHint,
		Context:        req.Context,
		Status:         "created",
		CreatedAt:      time.Now().UTC(),
	}
	g.uploads[uploadID.String()] = upload
	g.mu.Unlock()

	res := CreateUploadResponse{
		UploadID:  uploadID.String(),
		PutURL:    fmt.Sprintf("/s3/uploads/%s", uploadID),
		ExpiresAt: upload.CreatedAt.Add(15 * time.Minute),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(res)
}

func (g *Gateway) handleCompleteUpload(w http.ResponseWriter, r *http.Request) {
	uploadIDStr := r.PathValue("id")
	if uploadIDStr == "" {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 4 {
			uploadIDStr = parts[3]
		}
	}

	var req CompleteUploadRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	g.mu.Lock()
	upload, exists := g.uploads[uploadIDStr]
	if !exists {
		g.mu.Unlock()
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"Upload not found"}`, http.StatusNotFound)
		return
	}

	upload.Status = "completed"
	upload.SHA256 = req.SHA256

	runID := domain.NewID()
	appID := domain.NewID()
	assetID := domain.NewID()

	run := &domain.IngestRun{
		ID:            runID,
		TenantID:      upload.TenantID,
		UploadID:      &upload.ID,
		ScanSourceID:  upload.ScanSourceID,
		ApplicationID: appID,
		AssetID:       assetID,
		Track:         upload.Context.Branch,
		ScannerFamily: upload.FormatHint,
		Format:        upload.FormatHint,
		Context:       upload.Context,
		Status:        domain.RunQueued,
		CreatedAt:     time.Now().UTC(),
	}
	if run.Track == "" {
		run.Track = "main"
	}
	g.runs[runID.String()] = run
	g.mu.Unlock()

	_ = g.queue.EnqueueParse(r.Context(), jobs.ParseJobArgs{
		IngestRunID: runID,
		TenantID:    upload.TenantID,
	})

	res := CompleteUploadResponse{
		IngestRunID: runID.String(),
		StatusURL:   fmt.Sprintf("/ingest/v1/runs/%s", runID),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(res)
}

// handleUploadReport implements direct multipart report upload (Feature A2, docs/11).
func (g *Gateway) handleUploadReport(w http.ResponseWriter, r *http.Request) {
	g.processDirectUpload(w, r, false)
}

// handleUploadSBOM implements dedicated SBOM upload endpoint (Feature A9, docs/11).
func (g *Gateway) handleUploadSBOM(w http.ResponseWriter, r *http.Request) {
	g.processDirectUpload(w, r, true)
}

func (g *Gateway) processDirectUpload(w http.ResponseWriter, r *http.Request, forceSBOM bool) {
	// Enforce 32 MiB body limit
	r.Body = http.MaxBytesReader(w, r.Body, MaxDirectReportBytes)

	tenantID := resolveTenantID(r)
	var (
		filename    string
		contentType = r.Header.Get("Content-Type")
		data        []byte
		sourceID    = domain.NewID()
		appID       = domain.NewID()
		assetID     = domain.NewID()
		track       = "main"
		formatHint  = ""
	)

	// Check if request is multipart/form-data
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(MaxDirectReportBytes); err != nil {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/payload-too-large","title":"File too large or invalid multipart"}`, http.StatusBadRequest)
			return
		}

		if s := r.FormValue("source"); s != "" {
			if parsed, err := uuid.Parse(s); err == nil {
				sourceID = parsed
			}
		}
		if a := r.FormValue("app"); a != "" {
			if parsed, err := uuid.Parse(a); err == nil {
				appID = parsed
			}
		}
		if as := r.FormValue("asset"); as != "" {
			if parsed, err := uuid.Parse(as); err == nil {
				assetID = parsed
			}
		}
		if t := r.FormValue("track"); t != "" {
			track = t
		}
		if f := r.FormValue("format"); f != "" {
			formatHint = f
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Missing 'file' in multipart form"}`, http.StatusBadRequest)
			return
		}
		defer func() { _ = file.Close() }()

		filename = header.Filename
		data, err = io.ReadAll(file)
		if err != nil {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to read upload body"}`, http.StatusInternalServerError)
			return
		}
	} else {
		// Raw body
		var err error
		data, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to read upload body"}`, http.StatusInternalServerError)
			return
		}
		if qSource := r.URL.Query().Get("source"); qSource != "" {
			if parsed, err := uuid.Parse(qSource); err == nil {
				sourceID = parsed
			}
		}
		if qTrack := r.URL.Query().Get("track"); qTrack != "" {
			track = qTrack
		}
		if qFormat := r.URL.Query().Get("format"); qFormat != "" {
			formatHint = qFormat
		}
	}

	if len(data) == 0 {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Empty report payload"}`, http.StatusBadRequest)
		return
	}

	headSize := 64 * 1024
	if len(data) < headSize {
		headSize = len(data)
	}
	head := data[:headSize]

	// Format detection
	var selectedParser integrations.ParserContract
	if formatHint != "" {
		var err error
		selectedParser, err = g.registry.GetParser("builtin:" + strings.ToLower(formatHint))
		if err != nil {
			selectedParser, _ = g.registry.GetParser(strings.ToLower(formatHint))
		}
	}
	if selectedParser == nil {
		var score int
		selectedParser, score = g.registry.DetectParser(head, filename, contentType)
		if selectedParser == nil || score < 40 {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/unsupported-format","title":"Unsupported report format"}`, http.StatusBadRequest)
			return
		}
	}

	runID := domain.NewID()
	scannerFamily := selectedParser.Descriptor().ID

	parseCtx := domain.ParseContext{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: scannerFamily,
		Track:         track,
	}

	// 1. Stream findings
	var staged []StagedRecord
	for rawFinding, err := range selectedParser.Parse(r.Context(), bytes.NewReader(data), parseCtx) {
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"type":"https://rampart.aspm.dev/problems/validation","title":%q}`, err.Error()), http.StatusBadRequest)
			return
		}

		// Compute D11 deterministic fingerprint
		// D11: the family is the scanner (semgrep, trivy...), never the parser id.
		fpFamily := rawFinding.ScannerFamily
		if fpFamily == "" {
			fpFamily = scannerFamily
		}
		fpResult := normalize.ComputeFingerprint(normalize.FingerprintParams{
			TenantID:      tenantID,
			AssetID:       assetID,
			ApplicationID: appID,
			Track:         track,
			Scope:         normalize.ScopeAsset,
			Family:        fpFamily,
			Category:      rawFinding.Category,
			RuleID:        rawFinding.RuleID,
			RawFinding:    rawFinding,
		})

		// Compute D13 content hash
		contentHash := normalize.ComputeContentHash(
			rawFinding.Title,
			rawFinding.Description,
			rawFinding.ToolSeverity,
			rawFinding.CVSSVector,
			"",
			rawFinding.Location.PrimaryPath(),
		)

		staged = append(staged, StagedRecord{
			FindingKey:   fpResult.FindingKey,
			Category:     rawFinding.Category,
			RuleID:       rawFinding.RuleID,
			Title:        rawFinding.Title,
			Description:  rawFinding.Description,
			ToolSeverity: rawFinding.ToolSeverity,
			Severity:     rawFinding.Severity,
			Location:     rawFinding.Location,
			CWEs:         rawFinding.CWEs,
			VulnID:       rawFinding.RuleID,
			CVSSVector:   rawFinding.CVSSVector,
			ContentHash:  contentHash,
			SeenAt:       time.Now().UTC(),
			RawPayload:   rawFinding.RawPayload,
		})
	}

	scope := CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: scannerFamily,
		AssetID:       assetID,
		Track:         track,
	}

	outcome, err := g.engine.MergeBatchWithOptions(r.Context(), scope, runID, appID, staged, MergeOptions{
		FieldMerge:   "scanner",
		ScanFinished: time.Now().UTC(),
	})
	if errors.Is(err, ErrRunStale) {
		// Run is stale per D13 line 204: stored, visible, not merged, nothing closed
		run := &domain.IngestRun{
			ID:            runID,
			TenantID:      tenantID,
			ScanSourceID:  sourceID,
			ApplicationID: appID,
			AssetID:       assetID,
			Track:         track,
			ScannerFamily: scannerFamily,
			Format:        scannerFamily,
			Status:        domain.RunStale,
			CreatedAt:     time.Now().UTC(),
		}
		g.mu.Lock()
		g.runs[runID.String()] = run
		g.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(DirectReportResponse{
			IngestRunID: runID.String(),
			Status:      "stale",
		})
		return
	}
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Merge batch failed"}`, http.StatusInternalServerError)
		return
	}

	// Close step for missing findings
	closed, err := g.engine.CloseScopeStep(r.Context(), scope, runID)
	if err == nil {
		outcome.Closed = closed
	}

	componentCount := 0
	// If forceSBOM or parser is CycloneDX/SPDX/Syft, extract SBOM inventory and dependency graph
	if forceSBOM || strings.Contains(scannerFamily, "cyclonedx") || strings.Contains(scannerFamily, "spdx") || strings.Contains(scannerFamily, "syft") {
		var (
			extractedSBOM *domain.SBOM
			components    []domain.SBOMComponent
		)
		if strings.Contains(scannerFamily, "cyclonedx") {
			cdxP := cyclonedx.NewParser()
			extractedSBOM, components, _, _ = cdxP.ParseSBOM(bytes.NewReader(data))
		} else if strings.Contains(scannerFamily, "spdx") {
			spdxP := spdx.NewParser()
			extractedSBOM, components, _, _ = spdxP.ParseSBOM(bytes.NewReader(data))
		} else if strings.Contains(scannerFamily, "syft") {
			syftP := syft.NewParser()
			extractedSBOM, components, _, _ = syftP.ParseSBOM(bytes.NewReader(data))
		}

		if len(components) > 0 {
			componentCount = len(components)
			if extractedSBOM == nil {
				extractedSBOM = &domain.SBOM{
					ID:        domain.NewID(),
					Format:    scannerFamily,
					CreatedAt: time.Now().UTC(),
				}
			}
			extractedSBOM.TenantID = tenantID
			extractedSBOM.AssetID = assetID
			extractedSBOM.IngestRunID = runID
			extractedSBOM.ComponentCount = componentCount

			_ = g.store.SaveSBOM(r.Context(), extractedSBOM, components)
		}
	}

	// Register run record
	run := &domain.IngestRun{
		ID:            runID,
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ApplicationID: appID,
		AssetID:       assetID,
		Track:         track,
		ScannerFamily: scannerFamily,
		Format:        scannerFamily,
		Status:        domain.RunCompleted,
		Stats: domain.IngestStats{
			Parsed:      len(staged),
			Created:     outcome.Created,
			Updated:     outcome.Updated,
			Untouched:   outcome.Untouched,
			Reactivated: outcome.Reactivated,
			Closed:      outcome.Closed,
		},
		CreatedAt: time.Now().UTC(),
	}
	g.mu.Lock()
	g.runs[runID.String()] = run
	g.mu.Unlock()

	res := DirectReportResponse{
		IngestRunID:    runID.String(),
		Status:         "completed",
		Staged:         len(staged),
		Created:        outcome.Created,
		Updated:        outcome.Updated,
		Untouched:      outcome.Untouched,
		Reactivated:    outcome.Reactivated,
		Closed:         outcome.Closed,
		ComponentCount: componentCount,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(res)
}

func (g *Gateway) handleGetRun(w http.ResponseWriter, r *http.Request) {
	runIDStr := r.PathValue("id")
	if runIDStr == "" {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 4 {
			runIDStr = parts[len(parts)-1]
		}
	}

	g.mu.RLock()
	run, exists := g.runs[runIDStr]
	g.mu.RUnlock()

	if !exists {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"Run not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(run)
}

func resolveTenantID(r *http.Request) uuid.UUID {
	if tHeader := r.Header.Get("X-Tenant-ID"); tHeader != "" {
		if parsed, err := uuid.Parse(tHeader); err == nil {
			return parsed
		}
	}
	return uuid.MustParse(DefaultTenantUUIDStr)
}

// ComputeReaderSHA256 helper for calculating payload checksums.
func ComputeReaderSHA256(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
