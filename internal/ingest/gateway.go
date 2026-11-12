package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"rampart/internal/normalize"
	"rampart/internal/objectstore"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/integrations"
	"rampart/internal/jobs"
	"rampart/internal/store"
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

// CreateUploadRequest payload for POST /ingest/v1/uploads (docs/11).
type CreateUploadRequest struct {
	ScanSourceID string               `json:"source"`
	FormatHint   string               `json:"format,omitempty"`
	Filename     string               `json:"filename,omitempty"`
	SizeBytes    int64                `json:"sizeBytes,omitempty"`
	Context      domain.UploadContext `json:"context"`
}

// CreateUploadResponse is what a client needs to upload: send PUT to PutURL with exactly PutHeaders.
type CreateUploadResponse struct {
	UploadID   string            `json:"uploadId"`
	PutURL     string            `json:"putUrl"`
	PutHeaders map[string]string `json:"putHeaders,omitempty"`
	ExpiresAt  time.Time         `json:"expiresAt"`
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
	queue     jobs.JobQueue
	store     Store
	processor *Processor
	registry  *integrations.Registry
	feeds     *enrich.FeedStore
	authn     *auth.Authenticator
	objects   objectstore.Store // nil: presigned uploads are unavailable (POST /reports still works)

	maxReportBytes int64
	presignTTL     time.Duration
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
	return &Gateway{
		queue: queue, store: s, registry: registry, feeds: feeds,
		authn:          auth.NewAuthenticatorWithStore(s),
		processor:      NewProcessor(s, registry, nil, nil),
		maxReportBytes: MaxReportBytesLimit,
		presignTTL:     15 * time.Minute, // D9
	}
}

// SetObjectStore enables presigned uploads (D9) and lets the processor read them back.
func (g *Gateway) SetObjectStore(o objectstore.Store) {
	g.objects = o
	g.processor.objects = o
}

// UseProcessor shares one Processor between the gateway (direct uploads) and the River worker.
func (g *Gateway) UseProcessor(p *Processor) {
	g.processor = p
	if g.objects != nil {
		p.objects = g.objects
	}
}

// SetLimits applies ingest.maxReportBytes and ingest.batchRows.
func (g *Gateway) SetLimits(maxReportBytes int64, batchRows int) {
	if maxReportBytes > 0 {
		g.maxReportBytes = maxReportBytes
	}
	g.processor.SetLimits(batchRows, maxReportBytes)
}

// Processor returns the report processor, which the ingest worker runs.
func (g *Gateway) Processor() *Processor { return g.processor }

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

func problemJSON(w http.ResponseWriter, status int, typ, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{"type": "https://rampart.aspm.dev/problems/" + typ, "title": title, "status": status}
	if detail != "" {
		body["detail"] = detail
	}
	_ = json.NewEncoder(w).Encode(body)
}

// idempotencyWindow is how long an Idempotency-Key is remembered per tenant (D2).
const idempotencyWindow = 7 * 24 * time.Hour

// handleCreateUpload allocates an upload and returns a presigned PUT whose Content-Length is signed in,
// so the object store itself refuses a body of another size (D9).
func (g *Gateway) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	tenantID, err := g.resolveTenant(r)
	if err != nil {
		problemJSON(w, http.StatusUnauthorized, "unauthorized", "Authentication required", "")
		return
	}
	if g.objects == nil {
		problemJSON(w, http.StatusNotImplemented, "unsupported-format", "Presigned uploads are not available",
			"Object storage is not configured. Send the report to POST /ingest/v1/reports instead.")
		return
	}
	rawBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		problemJSON(w, http.StatusBadRequest, "validation", "Failed to read the request body", "")
		return
	}
	var req CreateUploadRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		problemJSON(w, http.StatusBadRequest, "validation", "Invalid JSON request", "")
		return
	}
	if req.SizeBytes <= 0 {
		problemJSON(w, http.StatusBadRequest, "validation", "sizeBytes is required", "The size is signed into the upload URL, so declare the exact size of the report.")
		return
	}
	if req.SizeBytes > g.maxReportBytes { // D9: above the tenant limit
		problemJSON(w, http.StatusRequestEntityTooLarge, "payload-too-large", "The report is larger than the upload limit", fmt.Sprintf("The limit is %d bytes.", g.maxReportBytes))
		return
	}
	sourceID, err := g.store.EnsureScanSource(r.Context(), tenantID, req.ScanSourceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problemJSON(w, http.StatusNotFound, "not-found", "Scan source not found", "")
			return
		}
		problemJSON(w, http.StatusInternalServerError, "internal", "Failed to resolve the scan source", "")
		return
	}

	sum := sha256.Sum256(rawBody)
	reqHash := hex.EncodeToString(sum[:])
	key := r.Header.Get("Idempotency-Key")
	respond := func(u *domain.Upload, status int) {
		grant, perr := g.objects.PresignPut(r.Context(), u.ObjectRef, u.SizeBytes, g.presignTTL)
		if perr != nil {
			problemJSON(w, http.StatusInternalServerError, "internal", "Failed to sign the upload URL", "")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(CreateUploadResponse{UploadID: u.ID.String(), PutURL: grant.URL, PutHeaders: grant.Headers, ExpiresAt: grant.Expires})
	}

	// D2: the same key with an identical body returns the original upload; with another body, 409.
	if key != "" {
		if prev, err := g.store.FindUploadByKey(r.Context(), tenantID, key); err == nil && prev != nil {
			switch {
			case time.Since(prev.CreatedAt) > idempotencyWindow:
				_ = g.store.DeleteUpload(r.Context(), tenantID, prev.ID) // expired: the key is free again
			case prev.RequestHash != reqHash:
				problemJSON(w, http.StatusConflict, "idempotency-key-reused", "This Idempotency-Key was used with a different request", "")
				return
			default:
				respond(prev, http.StatusOK)
				return
			}
		}
	}

	id := domain.NewID()
	now := time.Now().UTC()
	u := &domain.Upload{
		ID: id, TenantID: tenantID, ScanSourceID: sourceID, IdempotencyKey: key, RequestHash: reqHash,
		ObjectRef: fmt.Sprintf("tenants/%s/uploads/%04d/%02d/%02d/%s", tenantID, now.Year(), int(now.Month()), now.Day(), id), // D9
		SizeBytes: req.SizeBytes, FormatHint: req.FormatHint, Context: req.Context, Status: "created", CreatedAt: now,
	}
	if err := g.store.CreateUpload(r.Context(), u); err != nil {
		if errors.Is(err, store.ErrUploadExists) { // lost a race with the same key
			if prev, ferr := g.store.FindUploadByKey(r.Context(), tenantID, key); ferr == nil && prev != nil && prev.RequestHash == reqHash {
				respond(prev, http.StatusOK)
				return
			}
			problemJSON(w, http.StatusConflict, "idempotency-key-reused", "This Idempotency-Key was used with a different request", "")
			return
		}
		problemJSON(w, http.StatusInternalServerError, "internal", "Failed to create the upload", "")
		return
	}
	respond(u, http.StatusCreated)
}

// handleCompleteUpload checks the object arrived with the declared size, then in ONE transaction marks
// the upload completed, creates the ingest run and inserts the parse job (D2). It is idempotent: a
// repeated call returns the same run.
func (g *Gateway) handleCompleteUpload(w http.ResponseWriter, r *http.Request) {
	tenantID, err := g.resolveTenant(r)
	if err != nil {
		problemJSON(w, http.StatusUnauthorized, "unauthorized", "Authentication required", "")
		return
	}
	if g.objects == nil {
		problemJSON(w, http.StatusNotImplemented, "unsupported-format", "Presigned uploads are not available", "Object storage is not configured.")
		return
	}
	uploadID, perr := uuid.Parse(r.PathValue("id"))
	if perr != nil {
		problemJSON(w, http.StatusNotFound, "not-found", "Upload not found", "")
		return
	}
	var req CompleteUploadRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil || len(req.SHA256) != 64 || strings.Trim(req.SHA256, "0123456789abcdefABCDEF") != "" {
		problemJSON(w, http.StatusBadRequest, "validation", "sha256 is required", "Send the 64-character hexadecimal SHA-256 of the report.")
		return
	}
	req.SHA256 = strings.ToLower(req.SHA256)

	upload, err := g.store.GetUpload(r.Context(), tenantID, uploadID)
	if err != nil {
		problemJSON(w, http.StatusNotFound, "not-found", "Upload not found", "")
		return
	}
	respondRun := func(runID uuid.UUID) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(CompleteUploadResponse{IngestRunID: runID.String(), StatusURL: fmt.Sprintf("/ingest/v1/runs/%s", runID)})
	}
	if upload.Status != "created" { // a repeated call
		if run, _ := g.store.FindRunByUpload(r.Context(), tenantID, uploadID); run != nil {
			respondRun(run.ID)
			return
		}
	}
	if size, serr := g.objects.Stat(r.Context(), upload.ObjectRef); serr != nil || size != upload.SizeBytes {
		detail := "The report was not uploaded yet. PUT it to the upload URL first."
		if serr == nil {
			detail = fmt.Sprintf("The stored object is %d bytes, but %d were declared.", size, upload.SizeBytes)
		}
		problemJSON(w, http.StatusUnprocessableEntity, "validation", "The upload is not complete", detail)
		return
	}

	// D10: asset, application and track from the declared context. Without a parsed report the asset is
	// a repository, or an image when the context names one.
	cat := g.categoryOf(r.Context(), upload)
	var runID uuid.UUID
	err = g.store.InTenantTx(r.Context(), tenantID, func(st Store) error {
		won, err := st.CompleteUpload(r.Context(), tenantID, uploadID, req.SHA256)
		if err != nil {
			return err
		}
		if !won { // another request completed it between our read and now
			if run, _ := st.FindRunByUpload(r.Context(), tenantID, uploadID); run != nil {
				runID = run.ID
			}
			return nil
		}
		assetType := DetermineAssetType(cat, upload.Context)
		asset, err := ResolveAsset(r.Context(), st, tenantID, assetType, DeriveAssetKey(assetType, upload.Context))
		if err != nil {
			return err
		}
		appID, err := ResolveApplication(r.Context(), st, tenantID, asset, "")
		if err != nil {
			return err
		}
		runID = domain.NewID()
		run := &domain.IngestRun{
			ID: runID, TenantID: tenantID, UploadID: &upload.ID, ScanSourceID: upload.ScanSourceID, ApplicationID: appID,
			AssetID: asset.ID, Track: ResolveTrack(upload.Context), ScannerFamily: upload.FormatHint, Format: upload.FormatHint,
			Context: upload.Context, ScanFinished: scanFinishedOf(upload.Context), Status: domain.RunQueued, CreatedAt: time.Now().UTC(),
		}
		if err := st.CreateIngestRun(r.Context(), run); err != nil {
			return err
		}
		args := jobs.ParseJobArgs{IngestRunID: runID, TenantID: tenantID}
		// The job commits with the run: no queued run without a job, no job without a run (D2).
		if enq, ok := g.queue.(jobs.TxParseEnqueuer); ok {
			if tx, ok := st.(interface{ PgxTx() pgx.Tx }); ok && tx.PgxTx() != nil {
				return enq.EnqueueParseTx(r.Context(), tx.PgxTx(), args)
			}
		}
		return nil
	})
	if err != nil {
		problemJSON(w, http.StatusInternalServerError, "internal", "Failed to complete the upload", "")
		return
	}
	if runID == uuid.Nil {
		problemJSON(w, http.StatusConflict, "conflict-version", "The upload was completed by another request", "")
		return
	}
	// Without a transactional queue (in-memory mode and tests) the job is enqueued after the commit.
	if _, tx := g.queue.(jobs.TxParseEnqueuer); !tx && g.queue != nil {
		_ = g.queue.EnqueueParse(r.Context(), jobs.ParseJobArgs{IngestRunID: runID, TenantID: tenantID})
	}
	respondRun(runID)
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

	// D2: the run exists (and is visible) before any finding is touched.
	isSBOM := forceSBOM || strings.Contains(scannerFamily, "cyclonedx") || strings.Contains(scannerFamily, "spdx") || strings.Contains(scannerFamily, "syft")
	run := &domain.IngestRun{
		ID: runID, TenantID: tenantID, ScanSourceID: sourceID, ApplicationID: appID, AssetID: asset.ID, Track: track,
		ScannerFamily: firstNonEmpty(scannerOverride, scannerFamily), Format: scannerFamily, Context: uploadCtx,
		ScanFinished: scanFinished, Status: domain.RunMerging, CreatedAt: time.Now().UTC(),
	}
	if err := g.store.CreateIngestRun(r.Context(), run); err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to create ingest run"}`, http.StatusInternalServerError)
		return
	}

	res, err := g.processor.Process(r.Context(), ProcessParams{
		Run: run, Parser: selectedParser, ScannerOverride: scannerOverride, ScanFinished: scanFinished,
		IsEphemeral: isEphemeral, IsSBOM: isSBOM,
		Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
	})
	if err != nil {
		var perm *jobs.PermanentError
		if errors.As(err, &perm) {
			g.processor.Finish(r.Context(), run, domain.RunFailed, perm.Code)
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type": "https://rampart.aspm.dev/problems/validation", "title": "The report could not be parsed",
				"status": http.StatusBadRequest, "detail": perm.Err.Error(), "code": perm.Code, "ingestRunId": runID.String(),
			})
			return
		}
		g.processor.Finish(r.Context(), run, domain.RunFailed, ErrCodeMergeFailed)
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Ingest failed"}`, http.StatusInternalServerError)
		return
	}
	if res.Status == domain.RunStale {
		g.processor.Finish(r.Context(), run, domain.RunStale, "")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(DirectReportResponse{IngestRunID: runID.String(), Status: "stale"})
		return
	}
	run.Stats = res.Stats
	g.processor.Finish(r.Context(), run, res.Status, res.Reason)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(DirectReportResponse{
		IngestRunID: runID.String(), Status: string(res.Status), Staged: res.Stats.Parsed, Created: res.Stats.Created,
		Updated: res.Stats.Updated, Untouched: res.Stats.Untouched, Reactivated: res.Stats.Reactivated,
		Closed: res.Stats.Closed, ComponentCount: res.Components,
	})
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
	return normalize.CanonicalVulnID(f.VulnIDs)
}

// categoryOf says what kind of findings an upload will hold, so the asset can be chosen before the report is parsed
// (D10): from the format the client declared, else from the parser that recognises the first 64 KiB of the object,
// the same detection the worker will use. SCA reports of an image go to an image asset, code reports to a repository.
func (g *Gateway) categoryOf(ctx context.Context, u *domain.Upload) domain.FindingCategory {
	var parser integrations.ParserContract
	if hint := strings.ToLower(u.FormatHint); hint != "" {
		if p, err := g.registry.GetParser("builtin:" + hint); err == nil {
			parser = p
		}
	}
	if parser == nil && g.objects != nil {
		if rc, err := g.objects.Open(ctx, u.ObjectRef); err == nil {
			head := make([]byte, 64<<10)
			n, _ := io.ReadFull(rc, head)
			_ = rc.Close()
			if p, score := g.registry.DetectParser(head[:n], "", ""); p != nil && score >= 40 {
				parser = p
			}
		}
	}
	if parser == nil {
		return domain.CategorySAST
	}
	switch id := parser.Descriptor().ID; {
	case strings.Contains(id, "trivy"), strings.Contains(id, "grype"), strings.Contains(id, "cyclonedx"), strings.Contains(id, "spdx"), strings.Contains(id, "syft"), strings.Contains(id, "openvex"):
		return domain.CategorySCA
	case strings.Contains(id, "gitleaks"), strings.Contains(id, "trufflehog"):
		return domain.CategorySecret
	}
	return domain.CategorySAST
}
