package query_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/objectstore"
	"rampart/internal/query"
)

type memObjectStore struct {
	data map[string][]byte
}

func newMemObjectStore() *memObjectStore {
	return &memObjectStore{data: make(map[string][]byte)}
}

func (m *memObjectStore) Write(ctx context.Context, key string, data []byte, contentType string) error {
	m.data[key] = data
	return nil
}

func (m *memObjectStore) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	d, ok := m.data[key]
	if !ok {
		return nil, objectstore.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(d)), nil
}

func (m *memObjectStore) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *memObjectStore) Stat(ctx context.Context, key string) (int64, error) {
	d, ok := m.data[key]
	if !ok {
		return 0, objectstore.ErrNotFound
	}
	return int64(len(d)), nil
}

func (m *memObjectStore) EnsureBucket(ctx context.Context) error {
	return nil
}

func (m *memObjectStore) PresignPut(ctx context.Context, key string, size int64, ttl time.Duration) (objectstore.Presigned, error) {
	return objectstore.Presigned{
		URL:     "http://objectstore.local/" + key,
		Headers: map[string]string{"Content-Type": "application/octet-stream"},
		Expires: time.Now().Add(ttl),
	}, nil
}

func TestQueryAPI_UploadEndpoints(t *testing.T) {
	store := ingest.NewMemoryStore()
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(store)
	token := authn.DefaultAdminToken(tenantID)

	api := query.NewAPIWithAuth(store, enrich.NewFeedStore(), authn)
	objs := newMemObjectStore()
	api.SetObjectStore(objs)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// 1. POST /api/v1/uploads (Create upload)
	reqBody := `{"source":"01931f6a-0000-7000-8000-000000000000","format":"sarif","sizeBytes":128,"context":{"repository":"github.com/acme/shop"}}`
	req := httptest.NewRequest("POST", "/api/v1/uploads", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create upload: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var createResp struct {
		UploadID string `json:"uploadId"`
		PutURL   string `json:"putUrl"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create upload response: %v", err)
	}
	if createResp.UploadID == "" || createResp.PutURL == "" {
		t.Fatalf("expected uploadId and putUrl, got: %+v", createResp)
	}

	// Fake PUT to object store
	fakeData := make([]byte, 128)
	uID := uuid.MustParse(createResp.UploadID)
	up, err := store.GetUpload(context.Background(), tenantID, uID)
	if err != nil {
		t.Fatalf("get upload from store: %v", err)
	}
	_ = objs.Write(context.Background(), up.ObjectRef, fakeData, "application/octet-stream")

	// 2. POST /api/v1/uploads/{id}/complete
	completeBody := `{"sha256":"` + strings.Repeat("a", 64) + `"}`
	reqComplete := httptest.NewRequest("POST", "/api/v1/uploads/"+createResp.UploadID+"/complete", strings.NewReader(completeBody))
	reqComplete.Header.Set("Authorization", "Bearer "+token)
	reqComplete.Header.Set("Content-Type", "application/json")
	wComplete := httptest.NewRecorder()
	mux.ServeHTTP(wComplete, reqComplete)

	if wComplete.Code != http.StatusAccepted {
		t.Fatalf("complete upload: expected 202, got %d: %s", wComplete.Code, wComplete.Body.String())
	}

	// 3. POST /api/v1/uploads/direct (Multipart upload)
	var mpBody bytes.Buffer
	writer := multipart.NewWriter(&mpBody)
	part, err := writer.CreateFormFile("file", "test-report.sarif")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	_, _ = part.Write([]byte(`{"version":"2.1.0","runs":[]}`))
	_ = writer.WriteField("application", "payments-api")
	_ = writer.WriteField("track", "main")
	_ = writer.Close()

	reqDirect := httptest.NewRequest("POST", "/api/v1/uploads/direct", &mpBody)
	reqDirect.Header.Set("Authorization", "Bearer "+token)
	reqDirect.Header.Set("Content-Type", writer.FormDataContentType())
	wDirect := httptest.NewRecorder()
	mux.ServeHTTP(wDirect, reqDirect)

	if wDirect.Code != http.StatusCreated {
		t.Fatalf("direct upload: expected 201, got %d: %s", wDirect.Code, wDirect.Body.String())
	}
}
