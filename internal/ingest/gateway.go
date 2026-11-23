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
	"net/url"
	"rampart/internal/normalize"
	"rampart/internal/objectstore"
	"rampart/internal/sbom"
	"rampart/internal/wasmstore"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/connectors"
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
	// Parser is the parser that read the document, by the name a client sends in "parser". Detected is true when the
	// client did not name one and the server chose it from the content.
	Parser   string `json:"parser,omitempty"`
	Detected bool   `json:"detected,omitempty"`
	// Application is the slug the report was filed under. It can differ from the one the client named: an asset
	// that already belongs to an application stays there (D10), which Warnings says.
	Application        string   `json:"application,omitempty"`
	ApplicationCreated bool     `json:"applicationCreated,omitempty"` // the application did not exist and this upload made it
	Warnings           []string `json:"warnings,omitempty"`
}

// Gateway provides HTTP handlers for ingestion (docs/11).
type Gateway struct {
	queue     jobs.JobQueue
	store     Store
	processor *Processor
	registry  *integrations.Registry
	parsers   *parserSet
	feeds     *enrich.FeedStore
	authn     *auth.Authenticator
	objects   objectstore.Store // nil: presigned uploads are unavailable (POST /reports still works)

	maxReportBytes int64
	presignTTL     time.Duration

	safeClient *connectors.SafeClient
	jwksCache  *JWKSCache
	publicURL  string
	publicHost string
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
		queue: queue, store: s, registry: registry, feeds: feeds, parsers: newParserSet(registry, s),
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

// SetPublicURL sets the public base URL of Rampart for federation audience checks (D22).
func (g *Gateway) SetPublicURL(publicURL string) {
	g.publicURL = publicURL
	if u, err := url.Parse(publicURL); err == nil && u.Host != "" {
		g.publicHost = u.Host
	} else {
		g.publicHost = ""
	}
}

// SetSafeClient binds a safe client to the gateway (e.g. for testing with loopback).
func (g *Gateway) SetSafeClient(sc *connectors.SafeClient) {
	g.safeClient = sc
	g.jwksCache = NewJWKSCache(sc)
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
	mux.HandleFunc("POST /ingest/v1/t/{tenant}/token", g.handleTokenExchange)
}

// HandleCreateUpload is exported for query-api (manual uploads from the Web UI, docs/13 §1).
func (g *Gateway) HandleCreateUpload(w http.ResponseWriter, r *http.Request) {
	g.handleCreateUpload(w, r)
}

// HandleCompleteUpload is exported for query-api.
func (g *Gateway) HandleCompleteUpload(w http.ResponseWriter, r *http.Request) {
	g.handleCompleteUpload(w, r)
}

// HandleUploadReport is exported for query-api.
func (g *Gateway) HandleUploadReport(w http.ResponseWriter, r *http.Request) {
	g.handleUploadReport(w, r)
}

func (g *Gateway) resolveCaller(r *http.Request) (*auth.ContextUser, error) {
	if u, ok := auth.FromContext(r.Context()); ok && u != nil && u.TenantID != domain.NilID {
		return u, nil
	}
	if g.authn != nil {
		if u, err := g.authn.AuthenticateRequest(r); err == nil && u != nil && u.TenantID != domain.NilID {
			return u, nil
		}
	}
	if tid, err := auth.TenantFromContext(r.Context()); err == nil && tid != domain.NilID {
		return &auth.ContextUser{TenantID: tid, Role: auth.RoleOwner}, nil
	}
	return nil, auth.ErrUnauthorized
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
	caller, err := g.resolveCaller(r)
	if err != nil {
		problemJSON(w, http.StatusUnauthorized, "unauthorized", "Authentication required", "")
		return
	}
	if caller.Role == auth.RoleViewer || caller.Role == "" {
		problemJSON(w, http.StatusForbidden, "forbidden", "Viewer role cannot create uploads", "")
		return
	}
	tenantID := caller.TenantID
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
	// D80: a federated token states the repository, branch and commit; the request may not state others.
	if err := BindUploadContext(caller.Scopes, &req.Context); err != nil {
		problemJSON(w, http.StatusForbidden, "forbidden", "The upload context does not match the CI token", err.Error())
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

	sourceParam := req.ScanSourceID
	if caller.ScanSourceID != nil && *caller.ScanSourceID != uuid.Nil && sourceParam == "" {
		sourceParam = caller.ScanSourceID.String()
	}

	sourceID, err := g.store.EnsureScanSource(r.Context(), tenantID, sourceParam)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problemJSON(w, http.StatusNotFound, "not-found", "Scan source not found", "")
			return
		}
		if errors.Is(err, store.ErrSourceDisabled) {
			problemJSON(w, http.StatusForbidden, "forbidden", "This scan source is disabled", "Its resource was deleted. Apply it again to enable it.")
			return
		}
		problemJSON(w, http.StatusInternalServerError, "internal", "Failed to resolve the scan source", "")
		return
	}

	if caller.ScanSourceID != nil && *caller.ScanSourceID != uuid.Nil && sourceID != *caller.ScanSourceID {
		problemJSON(w, http.StatusForbidden, "forbidden", "Token is bound to another scan source", "Federated token cannot ingest to a different scan source.")
		return
	}

	scanSrc, _ := g.store.GetScanSource(r.Context(), tenantID, sourceID)
	if scanSrc != nil {
		if scanSrc.ApplicationID != domain.NilID && req.Context.Application != "" && strings.ToLower(req.Context.Application) != "unassigned" {
			boundApp, _ := g.store.GetApplication(r.Context(), tenantID, scanSrc.ApplicationID)
			if boundApp != nil && !strings.EqualFold(req.Context.Application, boundApp.Slug) && req.Context.Application != scanSrc.ApplicationID.String() {
				problemJSON(w, http.StatusForbidden, "forbidden", "Application mismatch",
					fmt.Sprintf("ScanSource %q is bound to application %q, cannot ingest to declared application %q", scanSrc.Name, boundApp.Slug, req.Context.Application))
				return
			}
		}
		if req.FormatHint != "" {
			cat := g.categoryOf(r.Context(), &domain.Upload{TenantID: tenantID, FormatHint: req.FormatHint})
			if !scanSrc.PermitsCategory(cat) {
				problemJSON(w, http.StatusForbidden, "forbidden", "Category not permitted for this scan source",
					fmt.Sprintf("ScanSource %q does not permit security category %q (allowed: %s)", scanSrc.Name, cat, strings.Join(scanSrc.Categories, ", ")))
				return
			}
		}
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
		SizeBytes: req.SizeBytes, FormatHint: req.FormatHint, Context: req.Context, Options: TokenOptions(caller.Scopes),
		Status: "created", CreatedAt: now,
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
	caller, err := g.resolveCaller(r)
	if err != nil {
		problemJSON(w, http.StatusUnauthorized, "unauthorized", "Authentication required", "")
		return
	}
	if caller.Role == auth.RoleViewer || caller.Role == "" {
		problemJSON(w, http.StatusForbidden, "forbidden", "Viewer role cannot complete uploads", "")
		return
	}
	tenantID := caller.TenantID
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
	if caller.ScanSourceID != nil && *caller.ScanSourceID != domain.NilID && upload.ScanSourceID != *caller.ScanSourceID {
		problemJSON(w, http.StatusForbidden, "forbidden", "Token is bound to another scan source", "Federated token cannot complete upload for a different scan source.")
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
	if upload.Status == "purged" { // never completed, and removed by retention a day later (D53)
		problemJSON(w, http.StatusGone, "not-found", "The upload expired", "It was not completed within a day and its object was removed. Create a new upload.")
		return
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
	if upload.ScanSourceID != uuid.Nil {
		if src, err := g.store.GetScanSource(r.Context(), tenantID, upload.ScanSourceID); err == nil && src != nil {
			if !src.PermitsCategory(cat) {
				problemJSON(w, http.StatusForbidden, "forbidden", "Category not permitted for this scan source",
					fmt.Sprintf("ScanSource %q does not permit security category %q (allowed: %s)", src.Name, cat, strings.Join(src.Categories, ", ")))
				return
			}
		}
	}
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

		var appID uuid.UUID
		var scanSrc *domain.ScanSource
		if upload.ScanSourceID != uuid.Nil {
			scanSrc, _ = st.GetScanSource(r.Context(), tenantID, upload.ScanSourceID)
		}
		if scanSrc != nil && scanSrc.ApplicationID != domain.NilID {
			boundApp, _ := st.GetApplication(r.Context(), tenantID, scanSrc.ApplicationID)
			if upload.Context.Application != "" && strings.ToLower(upload.Context.Application) != "unassigned" && boundApp != nil {
				if !strings.EqualFold(upload.Context.Application, boundApp.Slug) && upload.Context.Application != scanSrc.ApplicationID.String() {
					return fmt.Errorf("application mismatch: scan source %q is bound to %q", scanSrc.Name, boundApp.Slug)
				}
			}
			appID = scanSrc.ApplicationID
			if sel, ok := st.(selectorStore); ok {
				_, _ = sel.MoveAssetToApplication(r.Context(), tenantID, asset.ID, appID)
			}
			asset.ApplicationID = &appID
		} else {
			var appErr error
			appID, _, appErr = ResolveApplicationWith(r.Context(), st, tenantID, asset, upload.Context.Application, false)
			if appErr != nil {
				return appErr
			}
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
		if errors.Is(err, ErrApplicationNotFound) {
			problemJSON(w, http.StatusNotFound, "application-not-found", "No such application",
				fmt.Sprintf("There is no application %q in this tenant. Applications must be declared declaratively via Application CRD or created by an administrator.", strings.ToLower(upload.Context.Application)))
			return
		}
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

	caller, err := g.resolveCaller(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}
	if caller.Role == auth.RoleViewer || caller.Role == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/forbidden","title":"Viewer role cannot upload reports"}`))
		return
	}
	tenantID := caller.TenantID

	var (
		filename    string
		contentType = r.Header.Get("Content-Type")
		data        []byte
		get         func(string) string // form field for multipart, query string otherwise
	)

	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(MaxDirectReportBytes); err != nil {
			status := http.StatusBadRequest
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				status = http.StatusRequestEntityTooLarge
			}
			w.Header().Set("Content-Type", "application/problem+json")
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/payload-too-large","title":"File too large or invalid multipart","status":`+strconv.Itoa(status)+`}`, status)
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
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, `{"type":"https://rampart.aspm.dev/problems/payload-too-large","title":"The report is larger than the limit of a direct upload","status":413}`, http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to read upload body"}`, http.StatusInternalServerError)
			return
		}
		get = r.URL.Query().Get
	}

	declaredApp := strings.TrimSpace(firstNonEmpty(get("app"), get("application")))
	scannerOverride := strings.ToLower(strings.TrimSpace(get("scanner")))
	formatHint := strings.TrimSpace(firstNonEmpty(get("format"), get("parser")))
	// D10: the canonical upload context decides asset, version and track. The file
	// name is never an asset key.
	uploadCtx := domain.UploadContext{
		Application: declaredApp,
		Repository:  firstNonEmpty(get("repository"), get("repo")),
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
	// D80: a federated token states the repository, branch and commit; the request may not state others.
	if err := BindUploadContext(caller.Scopes, &uploadCtx); err != nil {
		problemJSON(w, http.StatusForbidden, "forbidden", "The upload context does not match the CI token", err.Error())
		return
	}

	sourceParam := get("source")
	if caller.ScanSourceID != nil && *caller.ScanSourceID != domain.NilID && sourceParam == "" {
		sourceParam = caller.ScanSourceID.String()
	}

	sourceID, err := g.store.EnsureScanSource(r.Context(), tenantID, sourceParam)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/not-found","title":"Scan source not found"}`, http.StatusNotFound)
			return
		}
		if errors.Is(err, store.ErrSourceDisabled) {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/forbidden","title":"This scan source is disabled"}`, http.StatusForbidden)
			return
		}
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to resolve scan source"}`, http.StatusInternalServerError)
		return
	}

	if caller.ScanSourceID != nil && *caller.ScanSourceID != domain.NilID && sourceID != *caller.ScanSourceID {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/forbidden","title":"Token is bound to another scan source"}`, http.StatusForbidden)
		return
	}
	scanSrc, _ := g.store.GetScanSource(r.Context(), tenantID, sourceID)
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
	parsers := g.parsers
	selectedParser := parsers.byName(r.Context(), tenantID, formatHint)
	if selectedParser == nil {
		if formatHint != "" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":   "https://rampart.aspm.dev/problems/unsupported-format",
				"title":  "Unsupported or unknown parser",
				"status": http.StatusBadRequest,
				"detail": fmt.Sprintf("Unknown parser %q. Available parsers: %s", formatHint, strings.Join(parsers.available(r.Context(), tenantID), ", ")),
			})
			return
		}
		var score int
		selectedParser, score = parsers.detect(r.Context(), tenantID, head, filename, contentType)
		if selectedParser == nil || score < 40 {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/unsupported-format","title":"Unsupported report format"}`, http.StatusBadRequest)
			return
		}
	}

	if actual, bad := parsers.formatMismatch(r.Context(), tenantID, selectedParser, head, filename, contentType); bad {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "https://rampart.aspm.dev/problems/format-mismatch", "title": "The report is not in the format named",
			"status": http.StatusBadRequest, "detail": mismatchDetail(selectedParser, actual),
		})
		return
	}

	runID := domain.NewID()
	scannerFamily := selectedParser.Descriptor().ID

	// D10: Asset, Application & Track Resolution
	// One rule for "is this an SBOM": the parser is an SBOM reader (sbom.IsReader), whatever its name or the endpoint.
	isSBOM := sbom.IsReader(selectedParser)
	if forceSBOM && !isSBOM {
		problemJSON(w, http.StatusBadRequest, "unsupported-format", "The document is not an SBOM",
			fmt.Sprintf("%q is not an SBOM format: send it to POST /api/v1/reports.", selectedParser.Descriptor().ID))
		return
	}
	primaryCategory := domain.CategorySAST
	if isSBOM {
		primaryCategory = domain.CategorySCA
	} else if selectedParser != nil {
		rawCat := strings.ToLower(strings.TrimSpace(selectedParser.Descriptor().Category))
		switch rawCat {
		case "sca", "sbom":
			primaryCategory = domain.CategorySCA
		case "secret", "secrets":
			primaryCategory = domain.CategorySecret
		default:
			fc := domain.FindingCategory(rawCat)
			if fc.IsValid() {
				primaryCategory = fc
			}
		}
	}

	if scanSrc != nil && !scanSrc.PermitsCategory(primaryCategory) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":   "https://rampart.aspm.dev/problems/forbidden",
			"title":  "Category not permitted for this scan source",
			"status": http.StatusForbidden,
			"detail": fmt.Sprintf("ScanSource %q does not permit security category %q (allowed: %s)", scanSrc.Name, primaryCategory, strings.Join(scanSrc.Categories, ", ")),
			"code":   "category_not_permitted",
		})
		return
	}

	// Before anything is created: a parser whose module is not on this server cannot read the file, and the upload must not leave an application, an
	// asset and a failed run behind for it (docs/34 item 21, W3).
	if mr, ok := selectedParser.(interface{ RequiredModules() []string }); ok {
		if names := mr.RequiredModules(); len(names) > 0 && !wasmstore.Default().Has(names...) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type": "https://rampart.aspm.dev/problems/parser-unavailable", "title": "The parser cannot run on this server", "status": http.StatusServiceUnavailable,
				"detail": fmt.Sprintf("%s needs a WASM module that is not installed here (parsers.delivery in the chart). Nothing was created.", selectedParser.Descriptor().ID),
				"code":   "parser_unavailable",
			})
			return
		}
	}
	assetType := DetermineAssetType(primaryCategory, uploadCtx)
	assetKey := DeriveAssetKey(assetType, uploadCtx)

	asset, err := ResolveAsset(r.Context(), g.store, tenantID, assetType, assetKey)
	if err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to resolve asset"}`, http.StatusInternalServerError)
		return
	}

	var appID uuid.UUID
	var appCreated bool
	var scanApp *domain.Application
	createChoice := strings.ToLower(strings.TrimSpace(get("createApplication")))

	if scanSrc != nil && scanSrc.ApplicationID != domain.NilID {
		var appErr error
		scanApp, appErr = g.store.GetApplication(r.Context(), tenantID, scanSrc.ApplicationID)
		if appErr != nil || scanApp == nil {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":   "https://rampart.aspm.dev/problems/application-not-found",
				"status": http.StatusNotFound,
				"title":  "Bound application not found",
				"detail": fmt.Sprintf("ScanSource %q references application %s which does not exist", scanSrc.Name, scanSrc.ApplicationID),
			})
			return
		}

		if declaredApp != "" && strings.ToLower(declaredApp) != "unassigned" {
			if !strings.EqualFold(declaredApp, scanApp.Slug) && declaredApp != scanSrc.ApplicationID.String() {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"type":   "https://rampart.aspm.dev/problems/forbidden",
					"status": http.StatusForbidden,
					"title":  "Application mismatch",
					"detail": fmt.Sprintf("ScanSource %q is bound to application %q, cannot ingest to declared application %q", scanSrc.Name, scanApp.Slug, declaredApp),
					"code":   "application_mismatch",
				})
				return
			}
		}

		appID = scanSrc.ApplicationID
		if asset != nil {
			if sel, ok := g.store.(selectorStore); ok {
				_, _ = sel.MoveAssetToApplication(r.Context(), tenantID, asset.ID, appID)
			}
			asset.ApplicationID = &appID
		}
	} else {
		// Creating an application from an upload is restricted. CI tokens and automated ingestion can NEVER create applications
		// (GitOps governance: applications must be declared declaratively via Application CRD).
		// Only maintainers or admins can explicitly pass createApplication=true.
		// Without createApplication=true, createMissing defaults to false (fail-closed: missing application returns 404).
		createMissing := false
		if createChoice == "true" || createChoice == "1" || createChoice == "yes" {
			if caller.Role == auth.RoleIngest {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"type":   "https://rampart.aspm.dev/problems/forbidden",
					"status": http.StatusForbidden,
					"title":  "CI tokens cannot create applications",
					"detail": "Applications must be declared declaratively via Application CRD. Ingestion tokens are restricted to reporting against existing applications.",
				})
				return
			}
			if caller.Role.Rank() < auth.RoleMaintainer.Rank() {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"type":   "https://rampart.aspm.dev/problems/forbidden",
					"status": http.StatusForbidden,
					"title":  "Creating an application needs the maintainer or admin role",
				})
				return
			}
			createMissing = true
		}
		var err error
		appID, appCreated, err = ResolveApplicationWith(r.Context(), g.store, tenantID, asset, declaredApp, createMissing)
		if errors.Is(err, ErrApplicationNotFound) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			detail := fmt.Sprintf("There is no application %q in this tenant. Applications must be declared declaratively via Application CRD or created by an administrator.", strings.ToLower(declaredApp))
			if caller.Role.Rank() >= auth.RoleMaintainer.Rank() && caller.Role != auth.RoleIngest {
				detail = fmt.Sprintf("There is no application %q in this tenant. Check the name, create it via CRD, or send createApplication=true.", strings.ToLower(declaredApp))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":   "https://rampart.aspm.dev/problems/application-not-found",
				"status": http.StatusNotFound,
				"title":  "No such application",
				"detail": detail,
			})
			return
		}
		if err != nil {
			http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to resolve application"}`, http.StatusInternalServerError)
			return
		}
	}

	// D10: an asset that already belongs to an application stays in it, whatever the upload names. Say so, instead
	// of filing the report under another application than the one the client asked for without a word.
	filedUnder, warnings := "", []string(nil)
	if appCreated && createChoice == "" {
		warnings = append(warnings, fmt.Sprintf("application %q did not exist and was created; send createApplication=false to refuse that, or createApplication=true to say it is meant", strings.ToLower(declaredApp)))
	}
	if scanApp != nil {
		filedUnder = scanApp.Slug
	} else if app, err := g.store.GetApplication(r.Context(), tenantID, appID); err == nil && app != nil {
		filedUnder = app.Slug
		if want := strings.ToLower(declaredApp); want != "" && want != app.Slug {
			warnings = append(warnings, fmt.Sprintf("application %q was not used: this asset already belongs to %q (D10); move the asset to change it", want, app.Slug))
		}
	}

	if track == "" {
		track = ResolveTrack(uploadCtx)
	}

	// D10 / D140: ephemeral is decided by the ref (PRs, feature branches).
	// When an application is bound and has a branch configured, that branch is the production baseline (D140).
	isEphemeral := false
	if scanApp != nil && strings.TrimSpace(scanApp.Branch) != "" {
		isEphemeral = strings.TrimSpace(uploadCtx.Branch) != strings.TrimSpace(scanApp.Branch)
	} else {
		isEphemeral = IsEphemeralFor(r.Context(), g.store, tenantID, sourceID, uploadCtx.Branch)
	}

	// D2: the run exists (and is visible) before any finding is touched.
	run := &domain.IngestRun{
		ID: runID, TenantID: tenantID, ScanSourceID: sourceID, ApplicationID: appID, AssetID: asset.ID, Track: track,
		ScannerFamily: firstNonEmpty(scannerOverride, scannerFamily), Format: scannerFamily, Context: uploadCtx,
		ScanFinished: scanFinished, Status: domain.RunMerging, CreatedAt: time.Now().UTC(),
	}
	if err := g.store.CreateIngestRun(r.Context(), run); err != nil {
		http.Error(w, `{"type":"https://rampart.aspm.dev/problems/internal","title":"Failed to create ingest run"}`, http.StatusInternalServerError)
		return
	}

	opts := TokenOptions(caller.Scopes)
	minSeverity, noClose := opts.MinSeverity, opts.NoClose

	res, err := g.processor.Process(r.Context(), ProcessParams{
		Run: run, Parser: selectedParser, ScannerOverride: scannerOverride, ScanFinished: scanFinished,
		IsEphemeral: isEphemeral, NoClose: noClose, MinSeverity: minSeverity, IsSBOM: isSBOM,
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
		_ = json.NewEncoder(w).Encode(DirectReportResponse{IngestRunID: runID.String(), Status: "stale", Parser: parserName(selectedParser), Detected: formatHint == ""})
		return
	}
	run.Stats = res.Stats
	g.processor.Finish(r.Context(), run, res.Status, res.Reason)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(DirectReportResponse{
		IngestRunID: runID.String(), Status: string(res.Status), Staged: res.Stats.Parsed, Created: res.Stats.Created,
		Updated: res.Stats.Updated, Untouched: res.Stats.Untouched, Reactivated: res.Stats.Reactivated,
		Closed: res.Stats.Closed, ComponentCount: res.Components, Parser: parserName(selectedParser), Detected: formatHint == "",
		Application: filedUnder, ApplicationCreated: appCreated, Warnings: warnings,
	})
}

func (g *Gateway) handleGetRun(w http.ResponseWriter, r *http.Request) {
	caller, err := g.resolveCaller(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/unauthorized","title":"Authentication required"}`))
		return
	}
	tenantID := caller.TenantID

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
	parsers := g.parsers
	parser := parsers.byName(ctx, u.TenantID, u.FormatHint)
	if parser == nil && g.objects != nil {
		if rc, err := g.objects.Open(ctx, u.ObjectRef); err == nil {
			head := make([]byte, 64<<10)
			n, _ := io.ReadFull(rc, head)
			_ = rc.Close()
			if p, score := parsers.detect(ctx, u.TenantID, head[:n], "", ""); p != nil && score >= 40 {
				parser = p
			}
		}
	}
	if parser == nil {
		return domain.CategorySAST
	}
	rawCat := strings.ToLower(strings.TrimSpace(parser.Descriptor().Category))
	switch rawCat {
	case "sca", "sbom":
		return domain.CategorySCA
	case "secret", "secrets":
		return domain.CategorySecret
	default:
		fc := domain.FindingCategory(rawCat)
		if fc.IsValid() {
			return fc
		}
	}
	return domain.CategorySAST
}
