package ratelimit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/config"
	"rampart/internal/domain"
	"rampart/internal/ratelimit"
)

type mockQuotaStore struct {
	mu    sync.Mutex
	usage map[string]int64
}

func (m *mockQuotaStore) IncrementQuota(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time, amount int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mapKey := tenantID.String() + ":" + key + ":" + windowStart.Format(time.RFC3339)
	m.usage[mapKey] += amount
	return m.usage[mapKey], nil
}

func (m *mockQuotaStore) GetQuotaUsage(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mapKey := tenantID.String() + ":" + key + ":" + windowStart.Format(time.RFC3339)
	return m.usage[mapKey], nil
}

func TestAPIRateLimit_Middleware(t *testing.T) {
	cfg := config.LimitsConfig{
		APIPerSecond:     5,
		IngestPerHour:    10,
		ReportBytes:      1024,
		WebhookPerMinute: 60,
	}
	store := &mockQuotaStore{usage: make(map[string]int64)}
	authn := auth.NewAuthenticator()

	tenantID := domain.NewID()
	rawToken := auth.FormatToken(tenantID, "rate_limit_test_secret_123456")
	authn.RegisterToken(rawToken, &auth.TokenRecord{
		ID:        domain.NewID(),
		TenantID:  tenantID,
		Subject:   "test-user",
		Role:      auth.RoleViewer,
		CreatedAt: time.Now().UTC(),
	})

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mw := ratelimit.NewMiddleware(cfg, store, authn)
	handler := mw.Wrap(backend)

	// First 5 requests should pass (burst 10 by default)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
		req.Header.Set("Authorization", "Bearer "+rawToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("request %d failed with code %d", i, w.Code)
		}
		if w.Header().Get("RateLimit-Limit") == "" {
			t.Fatalf("request %d missing RateLimit-Limit header", i)
		}
	}

	// Exhaust the burst limit (burst is 10 for rate 5)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
		req.Header.Set("Authorization", "Bearer "+rawToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("burst request %d failed: %d", i, w.Code)
		}
	}

	// 11th request immediately should return 429 Too Many Requests
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on 429")
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("expected application/problem+json Content-Type, got %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "rate-limit-exceeded") {
		t.Fatalf("expected problem type rate-limit-exceeded, got: %s", w.Body.String())
	}
}

func TestTokenSpecific_RateLimit(t *testing.T) {
	cfg := config.LimitsConfig{
		APIPerSecond:  50, // default is high
		IngestPerHour: 100,
	}
	store := &mockQuotaStore{usage: make(map[string]int64)}
	authn := auth.NewAuthenticator()

	tenantID := domain.NewID()
	rawToken := auth.FormatToken(tenantID, "throttled_token_secret_123456")
	customRate := 2 // token restricted to 2 req/sec
	authn.RegisterToken(rawToken, &auth.TokenRecord{
		ID:        domain.NewID(),
		TenantID:  tenantID,
		Subject:   "throttled-client",
		Role:      auth.RoleViewer,
		RateLimit: &customRate,
		CreatedAt: time.Now().UTC(),
	})

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := ratelimit.NewMiddleware(cfg, store, authn)
	handler := mw.Wrap(backend)

	// Burst capacity for rate 2 is max(5, 2) = 5
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
		req.Header.Set("Authorization", "Bearer "+rawToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d should be allowed: got %d", i, w.Code)
		}
	}

	// 6th request should be rate-limited according to custom rate
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for custom token rate limit, got %d", w.Code)
	}
}

func TestIngestQuota_Middleware(t *testing.T) {
	cfg := config.LimitsConfig{
		APIPerSecond:  100,
		IngestPerHour: 2, // low quota: 2 uploads per hour
		ReportBytes:   500,
	}
	store := &mockQuotaStore{usage: make(map[string]int64)}
	authn := auth.NewAuthenticator()

	tenantID := domain.NewID()
	rawToken := auth.FormatToken(tenantID, "ingest_token_secret_123456789")
	authn.RegisterToken(rawToken, &auth.TokenRecord{
		ID:        domain.NewID(),
		TenantID:  tenantID,
		Subject:   "ci-uploader",
		Role:      auth.RoleIngest,
		CreatedAt: time.Now().UTC(),
	})

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"run_id":"test"}`))
	})

	mw := ratelimit.NewMiddleware(cfg, store, authn)
	handler := mw.Wrap(backend)

	// Upload 1: allowed
	req1 := httptest.NewRequest(http.MethodPost, "/ingest/v1/reports", strings.NewReader("small-report"))
	req1.Header.Set("Authorization", "Bearer "+rawToken)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("upload 1 should succeed: %d", w1.Code)
	}

	// Upload 2: allowed (reaches limit 2)
	req2 := httptest.NewRequest(http.MethodPost, "/ingest/v1/reports", strings.NewReader("small-report"))
	req2.Header.Set("Authorization", "Bearer "+rawToken)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusAccepted {
		t.Fatalf("upload 2 should succeed: %d", w2.Code)
	}

	// Upload 3: quota exceeded -> 429
	req3 := httptest.NewRequest(http.MethodPost, "/ingest/v1/reports", strings.NewReader("small-report"))
	req3.Header.Set("Authorization", "Bearer "+rawToken)
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("upload 3 should be blocked with 429, got %d", w3.Code)
	}
	if !strings.Contains(w3.Body.String(), "quota-exceeded") {
		t.Fatalf("expected quota-exceeded problem, got: %s", w3.Body.String())
	}
	if w3.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on quota exceeded")
	}

	// Payload too large check
	largeBody := strings.Repeat("A", 1000) // 1000 bytes > 500 ReportBytes limit
	reqLarge := httptest.NewRequest(http.MethodPost, "/ingest/v1/reports", strings.NewReader(largeBody))
	reqLarge.Header.Set("Authorization", "Bearer "+rawToken)
	wLarge := httptest.NewRecorder()
	handler.ServeHTTP(wLarge, reqLarge)
	if wLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Payload Too Large, got %d", wLarge.Code)
	}
}
