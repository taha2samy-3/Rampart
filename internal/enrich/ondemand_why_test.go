package enrich

import (
	"context"
	"log/slog"
	"testing"

	"rampart/internal/domain"
)

// Why names the two reasons only the server's configuration decides, and nothing else.
func TestOnDemandWhy(t *testing.T) {
	log := slog.Default()
	none := NewOnDemand(context.Background(), nil, FeedConfig{NVDDisabled: true}, log)
	if got := none.Why(context.Background(), "nvd"); got != FeedOffServerConfig {
		t.Errorf("NVD switched off in the configuration: %q", got)
	}
	if got := none.Why(context.Background(), "osv"); got != FeedOffNoEcosystem {
		t.Errorf("OSV with no ecosystem: %q", got)
	}
	for _, feed := range []string{"cisa_kev", "first_epss", "vulnrichment", "custom"} {
		if got := none.Why(context.Background(), feed); got != "" {
			t.Errorf("%s: only NVD and OSV can be off by the configuration, got %q", feed, got)
		}
	}

	ok := NewOnDemand(context.Background(), nil, FeedConfig{OSVEcosystems: []string{"Go"}}, log)
	if got := ok.Why(context.Background(), "osv"); got != "" || ok.Why(context.Background(), "nvd") != "" {
		t.Errorf("OSV with an ecosystem and NVD left on run: %q", got)
	}

	// the ClusterFeed can name the ecosystems, and then OSV runs
	fromResource := NewOnDemand(context.Background(), nil, FeedConfig{Mirror: func(context.Context) (*domain.FeedMirrorSpec, error) {
		return &domain.FeedMirrorSpec{OSV: &domain.OSVSource{Ecosystems: []string{"PyPI"}}}, nil
	}}, log)
	if got := fromResource.Why(context.Background(), "osv"); got != "" {
		t.Errorf("OSV with an ecosystem from the ClusterFeed runs: %q", got)
	}
}
