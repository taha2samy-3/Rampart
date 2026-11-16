package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// docs/23 R1, D99: housekeeping, as rampart_system, removes spent replay ids and old quota windows across tenants
// and keeps what is still inside its window.
func TestHousekeeping_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, sys := setupStores(t, ctx)
	tn := &domain.Tenant{ID: uuid.New(), Slug: "hk-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pool := sys.Pool()
	mark := uuid.NewString()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO federation_jti (issuer, jti, expires_at) VALUES ($1, 'old', $2), ($1, 'live', $3)`, mark, now.Add(-time.Minute), now.Add(time.Hour))
	exec(`INSERT INTO webhook_delivery (tenant_id, connector, delivery_id, expires_at) VALUES ($1, 'c', 'old', $2), ($1, 'c', 'live', $3)`, tn.ID, now.Add(-time.Minute), now.Add(time.Hour))
	exec(`INSERT INTO quota_usage (tenant_id, key, window_start, used) VALUES ($1, 'k', $2, 1), ($1, 'k', $3, 1)`, tn.ID, now.Add(-store.QuotaKeep-time.Hour), now.Truncate(time.Hour))

	res, err := store.Housekeeping(ctx, pool, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"federation_jti", "webhook_delivery", "quota_usage"} {
		if res[table] < 1 {
			t.Errorf("%s: want the spent row removed, result %v", table, res)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM federation_jti WHERE issuer = $1`, mark); n != 1 {
		t.Errorf("federation_jti: want the live id kept, have %d rows", n)
	}
	if n := count(`SELECT count(*) FROM webhook_delivery WHERE tenant_id = $1`, tn.ID); n != 1 {
		t.Errorf("webhook_delivery: want the live id kept, have %d rows", n)
	}
	if n := count(`SELECT count(*) FROM quota_usage WHERE tenant_id = $1`, tn.ID); n != 1 {
		t.Errorf("quota_usage: want the current window kept, have %d rows", n)
	}
}
