package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
)

func TestQuota_PostgresScenarios(t *testing.T) {
	ctx := context.Background()
	app, sys := setupStores(t, ctx)

	tenantA := newTenant(t, ctx, sys, "quota-tenant-a")
	tenantB := newTenant(t, ctx, sys, "quota-tenant-b")

	windowStart := time.Now().UTC().Truncate(time.Hour)

	t.Run("Increment and Get Quota Usage", func(t *testing.T) {
		used, err := app.IncrementQuota(ctx, tenantA, "ingest:uploads", windowStart, 5)
		if err != nil {
			t.Fatalf("increment failed: %v", err)
		}
		if used != 5 {
			t.Fatalf("expected used=5, got %d", used)
		}

		got, err := app.GetQuotaUsage(ctx, tenantA, "ingest:uploads", windowStart)
		if err != nil {
			t.Fatalf("get failed: %v", err)
		}
		if got != 5 {
			t.Fatalf("expected got=5, got %d", got)
		}

		// Increment again
		used, err = app.IncrementQuota(ctx, tenantA, "ingest:uploads", windowStart, 3)
		if err != nil {
			t.Fatalf("second increment failed: %v", err)
		}
		if used != 8 {
			t.Fatalf("expected used=8, got %d", used)
		}
	})

	t.Run("RLS Tenant Isolation on Quota Usage", func(t *testing.T) {
		// Tenant B should read 0 for tenant A's key
		gotB, err := app.GetQuotaUsage(ctx, tenantB, "ingest:uploads", windowStart)
		if err != nil {
			t.Fatalf("tenant B get failed: %v", err)
		}
		if gotB != 0 {
			t.Fatalf("tenant B should see 0 usage, got %d", gotB)
		}

		// Increment for tenant B
		usedB, err := app.IncrementQuota(ctx, tenantB, "ingest:uploads", windowStart, 12)
		if err != nil {
			t.Fatalf("tenant B increment failed: %v", err)
		}
		if usedB != 12 {
			t.Fatalf("expected usedB=12, got %d", usedB)
		}

		// Recheck tenant A: still 8
		gotA, err := app.GetQuotaUsage(ctx, tenantA, "ingest:uploads", windowStart)
		if err != nil || gotA != 8 {
			t.Fatalf("tenant A usage changed unexpectedly: %d, %v", gotA, err)
		}
	})

	t.Run("Concurrent Increments Accumulate Correctly", func(t *testing.T) {
		const goroutines = 10
		const perGoroutine = 5
		var wg sync.WaitGroup
		wg.Add(goroutines)

		key := "concurrent-test"
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < perGoroutine; j++ {
					_, err := app.IncrementQuota(ctx, tenantA, key, windowStart, 1)
					if err != nil {
						t.Errorf("concurrent increment failed: %v", err)
					}
				}
			}()
		}
		wg.Wait()

		total, err := app.GetQuotaUsage(ctx, tenantA, key, windowStart)
		if err != nil {
			t.Fatalf("failed to get concurrent total: %v", err)
		}
		expected := int64(goroutines * perGoroutine)
		if total != expected {
			t.Fatalf("expected total %d, got %d", expected, total)
		}
	})

	t.Run("Token RateLimit and Quota Persistence", func(t *testing.T) {
		rawToken := "rpt_test_token_with_limits"
		rateLimit := 120
		quota := int64(50000)
		rec := &auth.TokenRecord{
			ID:        domain.NewID(),
			Subject:   "ci-pipeline",
			TenantID:  tenantA,
			Role:      auth.RoleIngest,
			TokenHash: auth.HashToken(rawToken),
			Scopes:    []string{"read"},
			RateLimit: &rateLimit,
			Quota:     &quota,
			CreatedAt: time.Now().UTC(),
		}

		if err := app.SaveToken(ctx, rec); err != nil {
			t.Fatalf("failed to save token: %v", err)
		}

		loaded, err := app.LookupTokenByHash(ctx, tenantA, rec.TokenHash)
		if err != nil {
			t.Fatalf("failed to lookup token: %v", err)
		}
		if loaded.RateLimit == nil || *loaded.RateLimit != rateLimit {
			t.Fatalf("expected rate limit %d, got %v", rateLimit, loaded.RateLimit)
		}
		if loaded.Quota == nil || *loaded.Quota != quota {
			t.Fatalf("expected quota %d, got %v", quota, loaded.Quota)
		}
	})
}
