package ingest

import (
	"bytes"
	"context"
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
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/integrations"
	"rampart/internal/jobs"
	"rampart/internal/normalize"
	"rampart/internal/parsers/cyclonedx"
	"rampart/internal/parsers/spdx"
	"rampart/internal/parsers/syft"
	"rampart/internal/store"
	"rampart/internal/telemetry"
)

var (
	ErrUploadNotFound      = errors.New("ingest: upload not found")
	ErrIdempotencyConflict = errors.New("ingest: idempotency key reused with different payload")
	ErrUnsupportedFormat   = errors.New("ingest: unsupported report or SBOM format")
)

const (
	MaxDirectReportBytes = 32 << 20  // 32 MiB (docs/11 §1)
	MaxReportBytesLimit  = 512 << 20 // 512 MiB (docs/16 D6, D9)
	DefaultTenantUUIDStr = "01931f6a-0000-7000-8000-000000000000"
)

// Upload represents an allocated upload record (D2, D9).
type Upload struct {
	ID             uuid.UUID            `json:"id"`
	TenantID       uuid.UUID            `json:"tenant_id"`
	ScanSourceID   uuid.UUID            `json:"scan_source_id"`
	IdempotencyKey string               `json:"idempotency_key"`
	PayloadHash    string               `json:"payload_hash"`
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
	store    Store
	engine   *Engine
	registry *integrations.Registry
	feeds    *enrich.FeedStore
	authn    *auth.Authenticator
}

// NewGateway creates a new ingest gateway instance with default dependencies.
func NewGateway(queue jobs.JobQueue) *Gateway {
	return NewGatewayWithDeps(queue, nil, nil, nil)
}

// NewGatewayWithDeps creates an ingest gateway instance with explicit dependencies.
func NewGatewayWithDeps(
	queue jobs.JobQueue,
	s Store,
	registry *integrations.Registry,
	feeds *enrich.FeedStore,
) *Gateway {
	if s == nil {
		s = NewMemoryStore()
	}
	if registry == nil {
		registry = integrations.DefaultRegistry()
	}
	if feeds == nil {
		feeds = enrich.NewFeedStore()
	}

	authn := auth.NewAuthenticatorWithStore(s)

	return &Gateway{
		queue:    queue,
		uploads:  make(map[string]*Upload),
		store:    s,
		engine:   NewEngine(s),
		registry: registry,
		feeds:    feeds,
		authn:    authn,
	}
}

// SetAuthenticator binds an explicit authenticator to the gateway.
func (g *Gateway) SetAuthenticator(a *auth.Authenticator) {
	g.authn = a
}

// Store returns the underlying store for queries and inspection.
func (g *Gateway) Store() Store {
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

func (g *Gateway) resolveTenant(r *http.Request) (uuid.UUID, error) {
	if tid, err := auth.TenantFromContext(r.Context()); err == nil && tid != domain.NilID {
		return tid, nil
	}
	if g.authn != nil {
		if u, err := g.authn.AuthenticateRequest(r); err == nil && u != nil && u.TenantID != domain.NilID {
			return u.TenantID, nil
		}
	}
	return domain.NilID, auth.ErrUnauthorized
}

func (g *Gateway) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	tenantID, err := g.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Failed to read request body"}`, http.StatusBadRequest)
		return
	}

	var req CreateUploadRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid JSON request"}`, http.StatusBadRequest)
		return
	}

	// D9: reject sizes above tenant limit
	if req.SizeBytes > MaxReportBytesLimit {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/payload-too-large","title":"Declared size exceeds maximum allowed upload size"}`, http.StatusBadRequest)
		return
	}

	// D9: Idempotency-Key hash comparison
	idempotencyKey := r.Header.Get("Idempotency-Key")
	payloadHashBytes := sha256.Sum256(rawBody)
	payloadHash := hex.EncodeToString(payloadHashBytes[:])

	sourceID, err := uuid.Parse(req.ScanSourceID)
	if err != nil {
		sourceID = domain.NewID()
	}

	uploadID := domain.NewID()

	g.mu.Lock()
	if idempotencyKey != "" {
		for _, u := range g.uploads {
			if u.IdempotencyKey == idempotencyKey && u.TenantID == tenantID {
				if u.PayloadHash != payloadHash {
					g.mu.Unlock()
					http.Error(w, `{"type":"https://rampart.aspm.dev/problems/conflict","title":"Idempotency-Key reused with different payload"}`, http.StatusConflict)
					return
				}
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
		PayloadHash:    payloadHash,
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
	tenantID, err := g.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

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
	if !exists || upload.TenantID != tenantID {
		g.mu.Unlock()
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"Upload not found"}`, http.StatusNotFound)
		return
	}

	upload.Status = "completed"
	upload.SHA256 = req.SHA256

	runID := domain.NewID()

	// D10 deterministic asset, application, and track resolution
	assetType := DetermineAssetType(domain.CategorySAST, upload.Context)
	assetKey := DeriveAssetKey(assetType, upload.Context)
	asset, err := ResolveAsset(r.Context(), g.store, upload.TenantID, assetType, assetKey)
	if err != nil {
		g.mu.Unlock()
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to resolve asset"}`, http.StatusInternalServerError)
		return
	}

	appID, err := ResolveApplication(r.Context(), g.store, upload.TenantID, asset, "")
	if err != nil {
		g.mu.Unlock()
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to resolve application"}`, http.StatusInternalServerError)
		return
	}

	track := ResolveTrack(upload.Context)
	run := &domain.IngestRun{
		ID:            runID,
		TenantID:      upload.TenantID,
		UploadID:      &upload.ID,
		ScanSourceID:  upload.ScanSourceID,
		ApplicationID: appID,
		AssetID:       asset.ID,
		Track:         track,
		ScannerFamily: upload.FormatHint,
		Format:        upload.FormatHint,
		Context:       upload.Context,
		Status:        domain.RunQueued,
		CreatedAt:     time.Now().UTC(),
	}
	g.mu.Unlock()
	if err := g.store.CreateIngestRun(r.Context(), run); err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to create ingest run"}`, http.StatusInternalServerError)
		return
	}

	// Enqueue parse job for background worker
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

	tenantID, err := g.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

	var (
		filename    string
		contentType = r.Header.Get("Content-Type")
		data        []byte
		get         func(string) string // form field for multipart, query string otherwise
	)

	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(MaxDirectReportBytes); err != nil {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/payload-too-large","title":"File too large or invalid multipart"}`, http.StatusBadRequest)
			return
		}
		get = r.FormValue

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
		var err error
		data, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to read upload body"}`, http.StatusInternalServerError)
			return
		}
		get = r.URL.Query().Get
	}

	declaredApp := get("app")
	scannerOverride := strings.ToLower(strings.TrimSpace(get("scanner")))
	formatHint := get("format")
	// D10: the canonical upload context decides asset, version and track. The file
	// name is never an asset key.
	uploadCtx := domain.UploadContext{
		Repository:  get("repository"),
		Branch:      firstNonEmpty(get("branch"), get("track")),
		Commit:      get("commit"),
		ImageRef:    get("imageRef"),
		ImageDigest: get("imageDigest"),
		Environment: get("environment"),
		Service:     get("service"),
		Version:     get("version"),
		BuildID:     get("buildId"),
		PipelineURL: get("pipelineUrl"),
	}
	scanFinished := parseScanFinished(get("scanFinished"))
	uploadCtx.ScanFinished = scanFinished

	sourceID, err := g.store.EnsureScanSource(r.Context(), tenantID, get("source"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"Scan source not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to resolve scan source"}`, http.StatusInternalServerError)
		return
	}
	track := ""

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

	// D10: Asset, Application & Track Resolution
	primaryCategory := domain.CategorySAST
	if forceSBOM || strings.Contains(scannerFamily, "cyclonedx") || strings.Contains(scannerFamily, "spdx") || strings.Contains(scannerFamily, "syft") {
		primaryCategory = domain.CategorySCA
	}
	assetType := DetermineAssetType(primaryCategory, uploadCtx)
	assetKey := DeriveAssetKey(assetType, uploadCtx)

	asset, err := ResolveAsset(r.Context(), g.store, tenantID, assetType, assetKey)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to resolve asset"}`, http.StatusInternalServerError)
		return
	}

	appID, err := ResolveApplication(r.Context(), g.store, tenantID, asset, declaredApp)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to resolve application"}`, http.StatusInternalServerError)
		return
	}

	if track == "" {
		track = ResolveTrack(uploadCtx)
	}

	// D10: ephemeral is decided by the ref (PRs, feature branches), not by the track name.
	isEphemeral := IsEphemeral(uploadCtx.Branch, nil)

	parseCtx := domain.ParseContext{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: scannerFamily,
		Track:         track,
		UploadContext: uploadCtx,
	}

	// 1. Stream findings
	var staged []StagedRecord
	for rawFinding, err := range selectedParser.Parse(r.Context(), bytes.NewReader(data), parseCtx) {
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"type":"https://rampart.aspm.dev/problems/validation","title":%q}`, err.Error()), http.StatusBadRequest)
			return
		}

		// Compute D11 deterministic fingerprint
		fpFamily := firstNonEmpty(scannerOverride, rawFinding.ScannerFamily, scannerFamily)
		fpResult := normalize.ComputeFingerprint(normalize.FingerprintParams{
			TenantID:      tenantID,
			AssetID:       asset.ID,
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
			ScannerFamily: fpFamily,
			FindingKey:    fpResult.FindingKey,
			Category:      rawFinding.Category,
			RuleID:        rawFinding.RuleID,
			Title:         rawFinding.Title,
			Description:   rawFinding.Description,
			ToolSeverity:  rawFinding.ToolSeverity,
			Severity:      rawFinding.Severity,
			Location:      rawFinding.Location,
			CWEs:          rawFinding.CWEs,
			VulnID:        canonicalVulnID(rawFinding),
			CVSSVector:    rawFinding.CVSSVector,
			ContentHash:   contentHash,
			SeenAt:        scanFinished,
			RawPayload:    rawFinding.RawPayload,
		})
	}

	// D13: the close scope is (source, scanner family, asset, track). A SARIF file from
	// Trivy must never close what Semgrep reported, so records are grouped by scanner.
	// A report with no findings has no scanner to read; the `scanner` parameter names
	// it, otherwise the scope is the parser id and a clean rescan closes nothing.
	var families []string
	byFamily := make(map[string][]StagedRecord)
	for _, rec := range staged {
		if _, seen := byFamily[rec.ScannerFamily]; !seen {
			families = append(families, rec.ScannerFamily)
		}
		byFamily[rec.ScannerFamily] = append(byFamily[rec.ScannerFamily], rec)
	}
	if len(families) == 0 {
		families = []string{firstNonEmpty(scannerOverride, scannerFamily)}
	}
	runFamily := families[0]

	// D2: the run exists (and is visible) before any finding is touched. The stale check
	// only looks at completed runs, so registering the scopes first is safe.
	run := &domain.IngestRun{
		ID:            runID,
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ApplicationID: appID,
		AssetID:       asset.ID,
		Track:         track,
		ScannerFamily: runFamily,
		Format:        scannerFamily,
		Context:       uploadCtx,
		ScanFinished:  scanFinished,
		Status:        domain.RunMerging,
		CreatedAt:     time.Now().UTC(),
	}
	if err := g.store.CreateIngestRun(r.Context(), run); err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to create ingest run"}`, http.StatusInternalServerError)
		return
	}
	scopeOf := func(family string) CloseScope {
		return CloseScope{TenantID: tenantID, ScanSourceID: sourceID, ScannerFamily: family, AssetID: asset.ID, Track: track}
	}
	for _, fam := range families {
		if err := g.store.RecordRunScope(r.Context(), &domain.IngestRunScope{
			IngestRunID: runID, TenantID: tenantID, ScanSourceID: sourceID,
			ScannerFamily: fam, AssetID: asset.ID, Track: track,
		}); err != nil {
			g.finishRun(r.Context(), run, domain.RunFailed, "record_scope_failed")
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to record run scope"}`, http.StatusInternalServerError)
			return
		}
	}

	var outcome MergeOutcome
	finalStatus, finalReason := domain.RunCompleted, ""
	staleScopes := 0
	for _, fam := range families {
		scope := scopeOf(fam)
		out, err := g.engine.MergeBatchWithOptions(r.Context(), scope, runID, appID, byFamily[fam], MergeOptions{
			FieldMerge:   "scanner",
			ScanFinished: scanFinished,
			IsEphemeral:  isEphemeral,
		})
		if errors.Is(err, ErrRunStale) {
			staleScopes++
			continue // stored, visible, not merged, nothing closed for this scope (D13)
		}
		if err != nil {
			g.finishRun(r.Context(), run, domain.RunFailed, "merge_failed")
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Merge batch failed"}`, http.StatusInternalServerError)
			return
		}
		outcome.Created += out.Created
		outcome.Updated += out.Updated
		outcome.Untouched += out.Untouched
		outcome.Reactivated += out.Reactivated

		// Close step (skipped for ephemeral runs, D10). The mass-close guard (D22) holds a
		// suspicious close for a maintainer instead of fixing half the inventory.
		if !isEphemeral {
			closeRes, err := g.engine.CloseScopeStepWithGuard(r.Context(), scope, runID, true)
			if err != nil {
				g.finishRun(r.Context(), run, domain.RunFailed, "close_failed")
				http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Close step failed"}`, http.StatusInternalServerError)
				return
			}
			outcome.Closed += closeRes.Closed
			if closeRes.HeldForConfirmation {
				finalStatus, finalReason = domain.RunCompletedWithErrors, "close_held"
			}
		}
	}
	if staleScopes == len(families) {
		g.finishRun(r.Context(), run, domain.RunStale, "")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(DirectReportResponse{IngestRunID: runID.String(), Status: "stale"})
		return
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
			extractedSBOM.AssetID = asset.ID
			extractedSBOM.IngestRunID = runID
			extractedSBOM.ComponentCount = componentCount

			_ = g.store.SaveSBOM(r.Context(), extractedSBOM, components)
		}
	}

	run.Stats = domain.IngestStats{
		Parsed:      len(staged),
		Created:     outcome.Created,
		Updated:     outcome.Updated,
		Untouched:   outcome.Untouched,
		Reactivated: outcome.Reactivated,
		Closed:      outcome.Closed,
	}
	g.finishRun(r.Context(), run, finalStatus, finalReason)

	res := DirectReportResponse{
		IngestRunID:    runID.String(),
		Status:         string(finalStatus),
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
	tenantID, err := g.resolveTenant(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}

	runIDStr := r.PathValue("id")
	if runIDStr == "" {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 4 {
			runIDStr = parts[len(parts)-1]
		}
	}

	runID, perr := uuid.Parse(runIDStr)
	if perr != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/validation","title":"Invalid run id"}`, http.StatusBadRequest)
		return
	}
	run, gerr := g.store.GetIngestRun(r.Context(), tenantID, runID)
	if gerr != nil || run == nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"Run not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(run)
}

// ComputeReaderSHA256 helper for calculating payload checksums.
func ComputeReaderSHA256(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseScanFinished implements D2: first_seen/last_seen use context.scanFinished when
// supplied and not in the future, otherwise the ingest time.
func parseScanFinished(v string) time.Time {
	now := time.Now().UTC()
	if v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil && !t.After(now) {
			return t.UTC()
		}
	}
	return now
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// canonicalVulnID is the vulnerability identifier of a finding, empty for non-SCA
// findings: a SAST rule id is not a vulnerability id (D14, D11).
func canonicalVulnID(f domain.RawFinding) string {
	if len(f.VulnIDs) > 0 {
		return f.VulnIDs[0]
	}
	return ""
}

// finishRun records the final status of a run. A failure to record is logged by the
// caller's response path only; the run row stays in its last known status.
func (g *Gateway) finishRun(ctx context.Context, run *domain.IngestRun, status domain.IngestRunStatus, reason string) {
	now := time.Now().UTC()
	run.Status = status
	run.Error = reason
	run.FinishedAt = &now
	_ = g.store.UpdateIngestRun(ctx, run)
	telemetry.RecordIngestRun(ctx, string(status))
	telemetry.RecordIngestOutcome(ctx, "created", run.Stats.Created)
	telemetry.RecordIngestOutcome(ctx, "updated", run.Stats.Updated)
	telemetry.RecordIngestOutcome(ctx, "untouched", run.Stats.Untouched)
	telemetry.RecordIngestOutcome(ctx, "reactivated", run.Stats.Reactivated)
	telemetry.RecordIngestOutcome(ctx, "closed", run.Stats.Closed)
}
