package enrich

import (
	"log/slog"
	"testing"

	"rampart/internal/domain"
)

// D86: a mirror replaces the feed URLs; with egress deny a feed without a mirror is not read.
func TestApplyMirror(t *testing.T) {
	cfg := FeedConfig{OSVEcosystems: []string{"Go"}}
	cfg.defaults()
	skipKEV, skipEPSS := cfg.applyMirror(&domain.FeedMirrorSpec{KEV: &domain.FeedMirrorSource{URL: "https://m/kev.json"}, Egress: "deny"}, slog.Default())
	if skipKEV || cfg.KEVURL != "https://m/kev.json" {
		t.Errorf("KEV must be read from its mirror: skip=%v url=%s", skipKEV, cfg.KEVURL)
	}
	if !skipEPSS || !cfg.NVDDisabled || len(cfg.OSVEcosystems) != 0 {
		t.Errorf("egress deny: feeds without a mirror must not be read (epss skip %v, nvd off %v, osv %v)", skipEPSS, cfg.NVDDisabled, cfg.OSVEcosystems)
	}
	open := FeedConfig{}
	open.defaults()
	if k, e := open.applyMirror(&domain.FeedMirrorSpec{NVD: &domain.FeedMirrorSource{URL: "https://m/nvd"}}, slog.Default()); k || e || open.NVDURL != "https://m/nvd" || open.KEVURL != DefaultKEVURL {
		t.Error("egress allow: mirrored feeds move, the others keep their public address")
	}
}
