package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type memoryQuotaStore struct {
	mu    sync.Mutex
	usage map[string]int64
}

func newMemoryQuotaStore() *memoryQuotaStore {
	return &memoryQuotaStore{usage: make(map[string]int64)}
}

func (m *memoryQuotaStore) IncrementQuota(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time, amount int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mapKey := tenantID.String() + ":" + key + ":" + windowStart.Format(time.RFC3339)
	m.usage[mapKey] += amount
	return m.usage[mapKey], nil
}

func (m *memoryQuotaStore) GetQuotaUsage(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mapKey := tenantID.String() + ":" + key + ":" + windowStart.Format(time.RFC3339)
	return m.usage[mapKey], nil
}

func TestLimiter_BurstAndRecovery(t *testing.T) {
	cur := time.Now()
	l := NewLimiter(10, 5) // 10 tokens/sec, burst 5
	l.now = func() time.Time { return cur }

	key := "user-1"
	// First 5 requests should succeed (burst capacity 5)
	for i := 0; i < 5; i++ {
		allowed, retryAfter, _, rem := l.Allow(key, 10, 5)
		if !allowed {
			t.Fatalf("request %d should be allowed", i)
		}
		if retryAfter != 0 {
			t.Fatalf("request %d unexpected retryAfter %v", i, retryAfter)
		}
		if rem != 4-i {
			t.Fatalf("request %d expected remaining %d, got %d", i, 4-i, rem)
		}
	}

	// 6th request immediately should fail
	allowed, retryAfter, _, _ := l.Allow(key, 10, 5)
	if allowed {
		t.Fatalf("request 6 should be rate limited")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retryAfter, got %v", retryAfter)
	}

	// Advance time by 200ms -> should refill 2 tokens (10 tokens/sec * 0.2s = 2 tokens)
	cur = cur.Add(200 * time.Millisecond)
	allowed, _, _, rem := l.Allow(key, 10, 5)
	if !allowed {
		t.Fatalf("request after 200ms should be allowed")
	}
	if rem != 1 {
		t.Fatalf("expected remaining 1, got %d", rem)
	}

	allowed, _, _, rem = l.Allow(key, 10, 5)
	if !allowed {
		t.Fatalf("second request after 200ms should be allowed")
	}
	if rem != 0 {
		t.Fatalf("expected remaining 0, got %d", rem)
	}

	// 3rd request should fail
	allowed, _, _, _ = l.Allow(key, 10, 5)
	if allowed {
		t.Fatalf("3rd request should be rate limited")
	}
}

func TestLimiter_IsolationBetweenKeys(t *testing.T) {
	l := NewLimiter(5, 2)
	l.now = time.Now

	// Exhaust key A
	l.Allow("keyA", 5, 2)
	l.Allow("keyA", 5, 2)
	allowedA, _, _, _ := l.Allow("keyA", 5, 2)
	if allowedA {
		t.Fatalf("keyA should be limited")
	}

	// Key B should still be allowed
	allowedB, _, _, _ := l.Allow("keyB", 5, 2)
	if !allowedB {
		t.Fatalf("keyB should not be affected by keyA")
	}
}

func TestQuota_ReplicasShareUsage(t *testing.T) {
	store := newMemoryQuotaStore()
	tenantA := uuid.New()
	tenantB := uuid.New()
	now := time.Date(2026, 11, 13, 14, 0, 0, 0, time.UTC)
	window := time.Hour
	limit := int64(10)

	// Replica 1 ingests 6 uploads
	allowed, _, used, err := CheckAndIncrementQuota(context.Background(), store, tenantA, "ingest:uploads", window, limit, 6, now)
	if err != nil || !allowed || used != 6 {
		t.Fatalf("replica 1: allowed=%v, used=%d, err=%v", allowed, used, err)
	}

	// Replica 2 ingests 4 uploads -> total 10 (at limit)
	allowed, _, used, err = CheckAndIncrementQuota(context.Background(), store, tenantA, "ingest:uploads", window, limit, 4, now)
	if err != nil || !allowed || used != 10 {
		t.Fatalf("replica 2: allowed=%v, used=%d, err=%v", allowed, used, err)
	}

	// Replica 1 attempts 1 more upload -> exceeds limit (11 > 10)
	allowed, retryAfter, used, err := CheckAndIncrementQuota(context.Background(), store, tenantA, "ingest:uploads", window, limit, 1, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatalf("expected quota rejection")
	}
	if used != 11 {
		t.Fatalf("expected used=11, got %d", used)
	}
	if retryAfter != time.Hour {
		t.Fatalf("expected retryAfter 1h, got %v", retryAfter)
	}

	// Tenant B is isolated and has full quota
	allowedB, _, usedB, err := CheckAndIncrementQuota(context.Background(), store, tenantB, "ingest:uploads", window, limit, 5, now)
	if err != nil || !allowedB || usedB != 5 {
		t.Fatalf("tenant B should be isolated: allowed=%v, used=%d, err=%v", allowedB, usedB, err)
	}
}

func BenchmarkLimiter_RejectedCallZeroDB(b *testing.B) {
	fixedTime := time.Now()
	l := NewLimiter(10, 1)
	l.now = func() time.Time { return fixedTime }
	key := "hot-key"
	// exhaust bucket
	l.Allow(key, 10, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		allowed, _, _, _ := l.Allow(key, 10, 1)
		if allowed {
			b.Fatal("should not be allowed")
		}
	}
}
