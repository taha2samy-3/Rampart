package enrich

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	if k, e := open.applyMirror(&domain.FeedMirrorSpec{NVD: &domain.NVDSource{URL: "https://m/nvd"}}, slog.Default()); k || e || open.NVDURL != "https://m/nvd" || open.KEVURL != DefaultKEVURL {
		t.Error("egress allow: mirrored feeds move, the others keep their public address")
	}
}

func writeSecret(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A token file is read only from the directory kept for feed secrets, with symbolic links resolved: a Kubernetes Secret
// mount is made of links, and a link that leads out of the directory is not a token.
func TestReadFeedToken(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir() // the server's own secrets
	tok := writeSecret(t, dir, "nvd/api-key", "  key-123\n")
	if got, err := ReadFeedToken(tok, dir); err != nil || got != "key-123" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := ReadFeedToken("", dir); err != nil || got != "" {
		t.Errorf("no path is no token: %q %v", got, err)
	}
	secret := writeSecret(t, other, "session.key", "SESSION")

	// the way a Kubernetes mount is laid out: name -> ..data/name -> ..2026/name, all inside the directory
	real := writeSecret(t, dir, "k8s/..2026_11_18/token", "mounted")
	if err := os.Symlink("..2026_11_18", filepath.Join(dir, "k8s", "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "token"), filepath.Join(dir, "k8s", "token")); err != nil {
		t.Fatal(err)
	}
	_ = real
	if got, err := ReadFeedToken(filepath.Join(dir, "k8s", "token"), dir); err != nil || got != "mounted" {
		t.Errorf("a Secret mount layout was refused: %q %v", got, err)
	}

	if err := os.Symlink(secret, filepath.Join(dir, "evil")); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"outside the directory": secret,
		"a link out of it":      filepath.Join(dir, "evil"),
		"relative":              "nvd/api-key",
		"not clean":             dir + "/nvd/../nvd/api-key",
		"a prefix lookalike":    dir + "-other/token",
		"a directory":           filepath.Join(dir, "nvd"),
		"missing":               filepath.Join(dir, "nope"),
	} {
		if got, err := ReadFeedToken(p, dir); err == nil {
			t.Errorf("%s: the file was read (%q)", name, got)
		}
	}
}

func TestApplyMirrorNVDTokenAndOSVEcosystems(t *testing.T) {
	dir := t.TempDir()
	tok := writeSecret(t, dir, "nvd-key", "from-resource\n")
	cfg := FeedConfig{SecretsDir: dir, NVDAPIKey: "from-server-config", OSVEcosystems: []string{"Go"}}
	cfg.defaults()
	cfg.applyMirror(&domain.FeedMirrorSpec{
		NVD: &domain.NVDSource{TokenFile: tok},
		OSV: &domain.OSVSource{Ecosystems: []string{"npm", "PyPI"}},
	}, slog.Default())
	if cfg.NVDAPIKey != "from-resource" {
		t.Errorf("the resource's key must win over the server's: %q", cfg.NVDAPIKey)
	}
	if cfg.NVDURL != DefaultNVDURL || cfg.NVDDisabled {
		t.Errorf("a block with only a token keeps the public address: %s disabled=%v", cfg.NVDURL, cfg.NVDDisabled)
	}
	if got := strings.Join(cfg.OSVEcosystems, ","); got != "npm,PyPI" || cfg.OSVBaseURL != DefaultOSVBaseURL {
		t.Errorf("osv ecosystems %q url %s", got, cfg.OSVBaseURL)
	}

	// an unreadable token leaves the key the server had, and the feed on
	bad := FeedConfig{SecretsDir: dir, NVDAPIKey: "from-server-config"}
	bad.defaults()
	bad.applyMirror(&domain.FeedMirrorSpec{NVD: &domain.NVDSource{TokenFile: filepath.Join(dir, "missing")}}, slog.Default())
	if bad.NVDAPIKey != "from-server-config" || bad.NVDDisabled {
		t.Errorf("a missing token file changed the key or stopped NVD: %q %v", bad.NVDAPIKey, bad.NVDDisabled)
	}

	// without ecosystems in the resource, the server's list stays
	keep := FeedConfig{OSVEcosystems: []string{"Go"}}
	keep.defaults()
	keep.applyMirror(&domain.FeedMirrorSpec{OSV: &domain.OSVSource{URL: "https://m/osv/"}}, slog.Default())
	if keep.OSVBaseURL != "https://m/osv" || len(keep.OSVEcosystems) != 1 || keep.OSVEcosystems[0] != "Go" {
		t.Errorf("a mirror without ecosystems changed the list: %v %s", keep.OSVEcosystems, keep.OSVBaseURL)
	}
}

// Egress deny: a block with no address has no mirror, so the feed is off; ecosystems alone do not turn OSV on.
func TestApplyMirrorDenyWithoutAddress(t *testing.T) {
	cfg := FeedConfig{}
	cfg.defaults()
	cfg.applyMirror(&domain.FeedMirrorSpec{Egress: "deny", NVD: &domain.NVDSource{}, OSV: &domain.OSVSource{Ecosystems: []string{"Go"}}}, slog.Default())
	if !cfg.NVDDisabled || len(cfg.OSVEcosystems) != 0 {
		t.Errorf("deny without a mirror address must switch both off: nvd off=%v osv=%v", cfg.NVDDisabled, cfg.OSVEcosystems)
	}
	mirrored := FeedConfig{}
	mirrored.defaults()
	mirrored.applyMirror(&domain.FeedMirrorSpec{Egress: "deny", OSV: &domain.OSVSource{URL: "http://repo.internal/osv", Ecosystems: []string{"Go"}}}, slog.Default())
	if len(mirrored.OSVEcosystems) != 1 || mirrored.OSVBaseURL != "http://repo.internal/osv" {
		t.Errorf("deny with a mirror must read it: %v %s", mirrored.OSVEcosystems, mirrored.OSVBaseURL)
	}
}

// The token of an optional source is read from the feed secrets directory only.
func TestOptionalSourcesReadTokensFromTheSecretsDirectory(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	good := writeSecret(t, dir, "vc", "vc-token")
	bad := writeSecret(t, other, "session.key", "SESSION")
	srcs, keep, errs := optionalSources(&domain.FeedMirrorSpec{VulnCheckKEV: &domain.FeedSource{TokenFile: good}}, dir)
	if len(errs) != 0 || len(srcs) != 1 || srcs[0].token != "vc-token" || len(keep) != 1 {
		t.Fatalf("srcs %+v keep %v errs %v", srcs, keep, errs)
	}
	srcs, keep, errs = optionalSources(&domain.FeedMirrorSpec{VulnCheckKEV: &domain.FeedSource{TokenFile: bad}}, dir)
	if len(errs) != 1 || len(srcs) != 0 || len(keep) != 1 {
		t.Fatalf("a token outside the directory must fail the source and keep its rows: srcs %+v keep %v errs %v", srcs, keep, errs)
	}
}

func off() *bool { f := false; return &f }

// A feed switched off in the resource is not read; the others are unaffected. storageMode full does not turn OSV back on.
func TestApplyMirrorSwitchedOffFeeds(t *testing.T) {
	cfg := FeedConfig{OSVEcosystems: []string{"Go"}}
	cfg.defaults()
	skipKEV, skipEPSS := cfg.applyMirror(&domain.FeedMirrorSpec{
		StorageMode: "full",
		KEV:         &domain.FeedMirrorSource{URL: "https://m/kev.json", Enabled: off()},
		EPSS:        &domain.FeedMirrorSource{URL: "https://m/epss.gz", Enabled: off()},
		NVD:         &domain.NVDSource{Enabled: off()},
		OSV:         &domain.OSVSource{Ecosystems: []string{"npm"}, Enabled: off()},
	}, slog.Default())
	if !skipKEV || !skipEPSS || !cfg.NVDDisabled || len(cfg.OSVEcosystems) != 0 {
		t.Errorf("kev skip %v, epss skip %v, nvd off %v, osv %v: every feed with enabled false must be off", skipKEV, skipEPSS, cfg.NVDDisabled, cfg.OSVEcosystems)
	}
	if cfg.KEVURL != DefaultKEVURL {
		t.Errorf("a switched-off feed's mirror address was taken: %s", cfg.KEVURL)
	}

}

// A source switched off is not resolved, and it is not kept: the rows it wrote are removed.
func TestOptionalSourcesSkipSwitchedOff(t *testing.T) {
	srcs, keep, errs := optionalSources(&domain.FeedMirrorSpec{
		Vulnrichment: &domain.FeedSource{},
		ExploitDB:    &domain.FeedSource{Enabled: off()},
		EUVD:         &domain.FeedSource{Enabled: off()},
		Custom: []domain.CustomFeed{
			{Name: "a", URL: "https://m/a", Format: domain.CustomFeedOSVZip},
			{Name: "b", URL: "https://m/b", Format: domain.CustomFeedOSVZip, Enabled: off()},
		},
	}, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	names := map[string]bool{}
	for _, s := range srcs {
		names[s.name] = true
	}
	if !names[SourceVulnrichment] || !names["a"] || len(srcs) != 2 {
		t.Errorf("sources = %v", names)
	}
	for _, n := range keep {
		if n == SourceExploitDB || n == SourceEUVD || n == "b" {
			t.Errorf("%s is switched off but kept, so its rows would stay", n)
		}
	}
}
