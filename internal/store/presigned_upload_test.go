package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/jobs"
	"rampart/internal/objectstore"
	"rampart/internal/query"
	"rampart/internal/scoring"
	"rampart/internal/store"
)

// uploadHarness is the real pipeline: PostgreSQL (RLS, rampart_app), River, the gateway and the
// processor. The object store is SeaweedFS when RAMPART_TEST_S3_ENDPOINT is set (CI), and an
// in-process store otherwise.
type uploadHarness struct {
	t       *testing.T
	server  *httptest.Server
	token   string
	tenant  uuid.UUID
	objects objectstore.Store
	mem     *objectstore.Memory
	timeout time.Duration
	pool    *pgxpool.Pool
	store   *store.PostgresStore
	sys     *store.PostgresStore
	scorer  *scoring.Scorer
	syncer  *enrich.FeedSyncer
	app     interface {
		ListFindings(ctx context.Context, tenantID uuid.UUID) ([]*domain.Finding, error)
	}
}

func newUploadHarness(t *testing.T) *uploadHarness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sysStore := setupStores(t, ctx)

	tenant := &domain.Tenant{ID: uuid.New(), Slug: "up-" + uuid.NewString()[:8], DisplayName: "Upload Test", CreatedAt: time.Now().UTC()}
	if err := sysStore.CreateTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}

	h := &uploadHarness{t: t, tenant: tenant.ID, app: appStore, pool: sysStore.Pool(), store: appStore, sys: sysStore} // the system role bypasses RLS: the check sees every row
	if ep := os.Getenv("RAMPART_TEST_S3_ENDPOINT"); ep != "" {
		s3, err := objectstore.NewS3(ctx, objectstore.S3Config{
			Endpoint: ep, Bucket: "rampart-upload-tests", // one shared bucket: every bucket costs the object store volumes
			AccessKey: os.Getenv("RAMPART_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("RAMPART_TEST_S3_SECRET_KEY"), UsePathStyle: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := s3.EnsureBucket(ctx); err != nil {
			t.Fatal(err)
		}
		h.objects = s3
	} else {
		h.mem = objectstore.NewMemory()
		h.objects = h.mem
	}

	h.syncer = enrich.NewFeedSyncer(sysStore.Pool())
	h.scorer = scoring.New(appStore, h.syncer, scoring.NewDBPolicy(appStore))
	processor := ingest.NewProcessor(appStore, nil, h.objects, nil)
	processor.SetScorer(h.scorer)
	queue, err := jobs.NewRiverQueue(ctx, appStore.Pool(), "", jobs.NewWorkers(processor.HandleParse))
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = queue.Stop(stop)
	})

	gw := ingest.NewGatewayWithDeps(queue, appStore, nil, nil)
	gw.SetObjectStore(h.objects)
	gw.UseProcessor(processor)
	authn := auth.NewAuthenticatorWithStore(appStore)
	h.token = authn.DefaultAdminToken(tenant.ID)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)
	api := query.NewAPIWithAuth(appStore, enrich.NewFeedStore(), authn) // the gate lives on the query API (D26)
	api.SetScorer(h.scorer)
	api.SetIntelSource(h.syncer)
	api.RegisterRoutes(mux)
	h.server = httptest.NewServer(mux)
	t.Cleanup(h.server.Close)
	return h
}

func (h *uploadHarness) call(method, path string, body any, headers map[string]string) (int, []byte) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.server.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+h.token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// upload runs create + PUT and returns the upload id. It returns the PUT status as well.
func (h *uploadHarness) upload(payload []byte, key string) (uploadID string, putStatus int) {
	h.t.Helper()
	return h.uploadWith(payload, key, domain.UploadContext{Repository: "github.com/acme/up-test", Branch: "main"})
}

func (h *uploadHarness) uploadWith(payload []byte, key string, uctx domain.UploadContext) (uploadID string, putStatus int) {
	h.t.Helper()
	headers := map[string]string{}
	if key != "" {
		headers["Idempotency-Key"] = key
	}
	code, body := h.call("POST", "/ingest/v1/uploads", ingest.CreateUploadRequest{
		ScanSourceID: "default", FormatHint: "sarif", SizeBytes: int64(len(payload)),
		Context: uctx,
	}, headers)
	if code != http.StatusCreated && code != http.StatusOK {
		h.t.Fatalf("create upload: %d %s", code, body)
	}
	var res ingest.CreateUploadResponse
	_ = json.Unmarshal(body, &res)
	if h.mem != nil {
		h.mem.Put(strings.TrimPrefix(res.PutURL, h.mem.Base), payload)
		return res.UploadID, http.StatusOK
	}
	req, _ := http.NewRequest(http.MethodPut, res.PutURL, bytes.NewReader(payload))
	for k, v := range res.PutHeaders {
		req.Header.Set(k, v)
	}
	req.ContentLength = int64(len(payload))
	pr, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = pr.Body.Close() }()
	pb, _ := io.ReadAll(pr.Body)
	if pr.StatusCode >= 300 {
		h.t.Logf("PUT %s -> %d %s", res.PutURL, pr.StatusCode, pb)
	}
	return res.UploadID, pr.StatusCode
}

func (h *uploadHarness) waitRun(runID string) domain.IngestRun {
	h.t.Helper()
	deadline := time.Now().Add(h.runTimeout())
	for time.Now().Before(deadline) {
		code, body := h.call("GET", "/ingest/v1/runs/"+runID, nil, nil)
		if code == http.StatusOK {
			var run domain.IngestRun
			_ = json.Unmarshal(body, &run)
			if run.Status.IsTerminal() {
				return run
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	h.t.Fatalf("run %s did not finish in time", runID)
	return domain.IngestRun{}
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestPresignedUpload_EndToEnd(t *testing.T) {
	h := newUploadHarness(t)
	report, err := os.ReadFile("../parsers/sarif/testdata/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}

	id, putStatus := h.upload(report, "key-"+uuid.NewString())
	if putStatus != http.StatusOK {
		t.Fatalf("PUT to the presigned URL: %d", putStatus)
	}
	code, body := h.call("POST", "/ingest/v1/uploads/"+id+"/complete", ingest.CompleteUploadRequest{SHA256: sha(report)}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("complete: %d %s", code, body)
	}
	var done ingest.CompleteUploadResponse
	_ = json.Unmarshal(body, &done)

	// A repeated complete returns the same run (D2).
	code2, body2 := h.call("POST", "/ingest/v1/uploads/"+id+"/complete", ingest.CompleteUploadRequest{SHA256: sha(report)}, nil)
	var again ingest.CompleteUploadResponse
	_ = json.Unmarshal(body2, &again)
	if code2 != http.StatusAccepted || again.IngestRunID != done.IngestRunID {
		t.Fatalf("repeated complete: %d, run %s != %s", code2, again.IngestRunID, done.IngestRunID)
	}

	run := h.waitRun(done.IngestRunID)
	if run.Status != domain.RunCompleted {
		t.Fatalf("run status %q, error %q", run.Status, run.Error)
	}
	findings, err := h.app.ListFindings(context.Background(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("the worker finished but no findings were written")
	}
	// D36: the foreign keys to asset and application are gone from finding, so the application upholds them.
	var orphans int
	if err := h.pool.QueryRow(ctx0(), `
		SELECT count(*) FROM finding f WHERE f.tenant_id = $1
		  AND (NOT EXISTS (SELECT 1 FROM asset a WHERE a.id = f.asset_id)
		    OR NOT EXISTS (SELECT 1 FROM application p WHERE p.id = f.application_id))`, h.tenant).Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if orphans != 0 {
		t.Fatalf("%d findings point at an asset or application that does not exist", orphans)
	}
	t.Logf("%d findings from the uploaded report; run stats %+v", len(findings), run.Stats)
}

func TestPresignedUpload_ShaMismatchFailsTheRun(t *testing.T) {
	h := newUploadHarness(t)
	report, _ := os.ReadFile("../parsers/sarif/testdata/semgrep.sarif")
	id, _ := h.upload(report, "")
	code, body := h.call("POST", "/ingest/v1/uploads/"+id+"/complete", ingest.CompleteUploadRequest{SHA256: strings.Repeat("0", 64)}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("complete: %d %s", code, body)
	}
	var done ingest.CompleteUploadResponse
	_ = json.Unmarshal(body, &done)
	run := h.waitRun(done.IngestRunID)
	if run.Status != domain.RunFailed || run.Error != ingest.ErrCodeSHA256Mismatch {
		t.Fatalf("want failed/%s, got %s/%q", ingest.ErrCodeSHA256Mismatch, run.Status, run.Error)
	}
	if f, _ := h.app.ListFindings(context.Background(), h.tenant); len(f) != 0 {
		t.Fatalf("a report whose hash did not match merged %d findings", len(f))
	}
}

func TestPresignedUpload_Idempotency(t *testing.T) {
	h := newUploadHarness(t)
	key := "idem-" + uuid.NewString()
	create := func(size int64) (int, ingest.CreateUploadResponse) {
		code, body := h.call("POST", "/ingest/v1/uploads", ingest.CreateUploadRequest{ScanSourceID: "default", FormatHint: "sarif", SizeBytes: size}, map[string]string{"Idempotency-Key": key})
		var r ingest.CreateUploadResponse
		_ = json.Unmarshal(body, &r)
		return code, r
	}
	c1, r1 := create(100)
	c2, r2 := create(100)
	c3, _ := create(200)
	if c1 != http.StatusCreated || c2 != http.StatusOK || r1.UploadID != r2.UploadID {
		t.Fatalf("same key and body: %d/%d, ids %s/%s", c1, c2, r1.UploadID, r2.UploadID)
	}
	if c3 != http.StatusConflict {
		t.Fatalf("same key, other body: want 409, got %d", c3)
	}
}

func TestPresignedUpload_RefusesWrongSizeAndOversize(t *testing.T) {
	h := newUploadHarness(t)
	// An oversize declaration is refused before anything is signed (D9).
	code, _ := h.call("POST", "/ingest/v1/uploads", ingest.CreateUploadRequest{ScanSourceID: "default", FormatHint: "sarif", SizeBytes: ingest.MaxReportBytesLimit + 1}, nil)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: want 413, got %d", code)
	}
	if h.mem != nil {
		t.Skip("the size signed into the URL is enforced by the object store; needs the S3 run")
	}
	// A body of another size than the declared one is refused by the object store itself.
	code, body := h.call("POST", "/ingest/v1/uploads", ingest.CreateUploadRequest{ScanSourceID: "default", FormatHint: "sarif", SizeBytes: 10}, nil)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var res ingest.CreateUploadResponse
	_ = json.Unmarshal(body, &res)
	req, _ := http.NewRequest(http.MethodPut, res.PutURL, strings.NewReader(strings.Repeat("x", 11)))
	for k, v := range res.PutHeaders {
		req.Header.Set(k, v)
	}
	req.ContentLength = 11
	pr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = pr.Body.Close()
	if pr.StatusCode < 400 {
		t.Fatalf("the object store accepted %d bytes for a 10-byte URL (status %d)", 11, pr.StatusCode)
	}
	// And completing something that was never uploaded is refused.
	code, body = h.call("POST", "/ingest/v1/uploads/"+res.UploadID+"/complete", ingest.CompleteUploadRequest{SHA256: strings.Repeat("a", 64)}, nil)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("complete without an object: want 422, got %d %s", code, body)
	}
}

// runTimeout is how long waitRun waits; the benchmark raises it.
func (h *uploadHarness) runTimeout() time.Duration {
	if h.timeout > 0 {
		return h.timeout
	}
	return 45 * time.Second
}

func ctx0() context.Context { return context.Background() }
