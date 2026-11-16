package store_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/enrich"
)

// D94: the API (application role) stages a pushed feed; the syncer (system role) loads it into the global
// exploitation table. Nothing staged yet keeps the feed's earlier rows.
func TestFeedPush_OnPostgreSQL(t *testing.T) {
	ctx := context.Background()
	appStore, sys := setupStores(t, ctx)
	none := httptest.NewServer(http.NotFoundHandler()) // KEV and EPSS are not what this test reads
	defer none.Close()
	mirror := &domain.FeedMirrorSpec{Custom: []domain.CustomFeed{{Name: "vulndb-push", Format: domain.CustomFeedIntelJSONL, PushTokenFile: "/var/run/x"}}}
	cfg := enrich.FeedConfig{KEVURL: none.URL, EPSSURL: none.URL, NVDURL: none.URL, Mirror: func(context.Context) (*domain.FeedMirrorSpec, error) { return mirror, nil }}
	syncer := enrich.NewFeedSyncer(sys.Pool())
	_, _ = sys.Pool().Exec(ctx, `DELETE FROM feed_push WHERE feed = 'vulndb-push'`)
	_ = syncer.SyncAll(ctx, cfg, slog.Default()) // nothing staged: no error from this feed, nothing written

	body := []byte(`{"id":"CVE-2099-7777","exploited":true,"maturity":"weaponized","reportedAt":"2099-01-01","evidence":"vendor"}` + "\n")
	if err := appStore.StageFeedPush(ctx, "vulndb-push", body, "x", 1); err != nil {
		t.Fatalf("the application role stages: %v", err)
	}
	_ = syncer.SyncAll(ctx, cfg, slog.Default())
	var maturity string
	if err := sys.Pool().QueryRow(ctx, `SELECT e.maturity FROM vulnerability_exploitation e WHERE e.source = 'vulndb-push' AND e.vulnerability_id = 'CVE-2099-7777'`).Scan(&maturity); err != nil || maturity != "weaponized" {
		t.Fatalf("the pushed record is loaded by the syncer: %q %v", maturity, err)
	}
	if _, err := appStore.Pool().Exec(ctx, `INSERT INTO vulnerability_exploitation (vulnerability_id, source, exploited, maturity) VALUES ('CVE-2099-7777', 'forged', true, 'weaponized')`); err == nil {
		t.Fatal("the application role must not write the exploitation table itself (D19)")
	}
}
