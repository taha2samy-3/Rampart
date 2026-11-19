package domain

import (
	"strings"
	"testing"
)

// D86: a ClusterFeedMirror is validated; what this version does not do is refused, not ignored.
func TestParseFeedMirrorSpec(t *testing.T) {
	if s, err := ParseFeedMirrorSpec([]byte(`{"nvd":{"url":"https://mirror.internal/nvd"},"kev":{"url":"http://mirror.internal/kev.json"},"egress":"deny","storageMode":"full"}`)); err != nil || s.Egress != "deny" || s.StorageMode != "full" || s.NVD.URL == "" {
		t.Fatalf("a valid mirror was refused: %v", err)
	}
	for name, raw := range map[string]string{
		"schedule":         `{"nvd":{"url":"https://m/nvd","schedule":"0 2 * * *"}}`,
		"cwe":              `{"cwe":{"url":"https://m/cwe.zip"}}`,
		"bad egress":       `{"egress":"sometimes"}`,
		"bad storage mode": `{"storageMode":"unknown"}`,
		"not a url":        `{"kev":{"url":"ftp://m/kev"}}`,
		"unknown field":    `{"nvdd":{"url":"https://m"}}`,
	} {
		if _, err := ParseFeedMirrorSpec([]byte(raw)); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// D88: optional sources are switched on by their block; tokens are files; custom feeds have a known format and a
// name that cannot pass for a built-in feed.
func TestParseFeedMirrorSpec_OptionalSources(t *testing.T) {
	ok := `{"vulnrichment":{},"exploitdb":{},"metasploit":{"url":"https://m/msf.json"},"euvd":{},
		"vulncheckKev":{"tokenFile":"/etc/rampart/feed-secrets/vulncheck"},
		"custom":[{"name":"vulndb","url":"https://proxy.internal/vulndb.jsonl","format":"intel-jsonl","tokenFile":"/etc/rampart/feed-secrets/vulndb"}]}`
	s, err := ParseFeedMirrorSpec([]byte(ok))
	if err != nil || s.Vulnrichment == nil || s.Metasploit.URL == "" || len(s.Custom) != 1 {
		t.Fatalf("a valid spec was refused: %v", err)
	}
	for name, raw := range map[string]string{
		"vulncheck without a token": `{"vulncheckKev":{}}`,
		"relative token file":       `{"vulncheckKev":{"tokenFile":"token"}}`,
		"unclean token file":        `{"exploitdb":{"tokenFile":"/var/run/../etc/passwd"}}`,
		"custom unknown format":     `{"custom":[{"name":"x","url":"https://m/x","format":"csv"}]}`,
		"custom takes nvd's name":   `{"custom":[{"name":"nvd","url":"https://m/x","format":"osv-zip"}]}`,
		"custom duplicate":          `{"custom":[{"name":"a","url":"https://m/x","format":"osv-zip"},{"name":"a","url":"https://m/y","format":"osv-zip"}]}`,
		"custom bad name":           `{"custom":[{"name":"Vuln DB","url":"https://m/x","format":"osv-zip"}]}`,
		"optional bad url":          `{"euvd":{"url":"file:///etc"}}`,
	} {
		if _, err := ParseFeedMirrorSpec([]byte(raw)); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

// The CRD takes the keys doc 33 describes: nvd.tokenFile and osv.ecosystems. Both blocks can leave the address out.
func TestParseFeedMirrorSpec_NVDTokenAndOSVEcosystems(t *testing.T) {
	s, err := ParseFeedMirrorSpec([]byte(`{"nvd":{"tokenFile":"/etc/rampart/feed-secrets/nvd/api-key"},
		"osv":{"ecosystems":["Go","npm","PyPI","Maven","crates.io","GitHub Actions","Debian:12"]}}`))
	if err != nil {
		t.Fatalf("a valid spec was refused: %v", err)
	}
	if s.NVD.TokenFile == "" || s.NVD.URL != "" || len(s.OSV.Ecosystems) != 7 {
		t.Errorf("nvd %+v, osv %+v", s.NVD, s.OSV)
	}
	for name, raw := range map[string]string{
		"nvd token outside the feed secrets":  `{"nvd":{"tokenFile":"/etc/rampart/secrets/session.key"}}`,
		"nvd token by a path that climbs out": `{"nvd":{"tokenFile":"/etc/rampart/feed-secrets/../secrets/session.key"}}`,
		"nvd token relative":                  `{"nvd":{"tokenFile":"nvd-key"}}`,
		"optional source token outside":       `{"euvd":{"tokenFile":"/etc/rampart/secrets/admin-password"}}`,
		"custom pull token outside":           `{"custom":[{"name":"x","url":"https://m/x","format":"osv-zip","tokenFile":"/proc/self/environ"}]}`,
		"push token outside":                  `{"custom":[{"name":"x","format":"intel-jsonl","pushTokenFile":"/etc/rampart/secrets/session.key"}]}`,
		"ecosystem with a path":               `{"osv":{"ecosystems":["../etc"]}}`,
		"ecosystem with a slash":              `{"osv":{"ecosystems":["Go/all"]}}`,
		"ecosystem duplicated":                `{"osv":{"ecosystems":["Go","Go"]}}`,
		"ecosystem empty":                     `{"osv":{"ecosystems":[""]}}`,
		"osv url not http":                    `{"osv":{"url":"file:///x"}}`,
		"nvd url not http":                    `{"nvd":{"url":"ftp://x"}}`,
		"kev still needs a url":               `{"kev":{}}`,
		"osv schedule":                        `{"osv":{"schedule":"0 1 * * *"}}`,
		"too many ecosystems":                 `{"osv":{"ecosystems":[` + strings.TrimSuffix(strings.Repeat(`"e0",`, 1), ",") + `,` + manyEcosystems(70) + `]}}`,
	} {
		if _, err := ParseFeedMirrorSpec([]byte(raw)); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if _, err := ParseFeedMirrorSpec([]byte(`{"custom":[{"name":"x","format":"intel-jsonl","pushTokenFile":"/var/run/rampart/feeds/x/token"}]}`)); err != nil {
		t.Errorf("a push token in the push token directory was refused: %v", err)
	}
}

func manyEcosystems(n int) string {
	var b []string
	for i := 0; i < n; i++ {
		b = append(b, `"eco`+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+`"`)
	}
	return strings.Join(b, ",")
}

// Egress deny means "read only from your own mirror": naming a public address in a block is refused, so a spec cannot
// say deny and still reach NIST, CISA or FIRST.
func TestParseFeedMirrorSpec_DenyRefusesPublicAddresses(t *testing.T) {
	for name, raw := range map[string]string{
		"kev":          `{"egress":"deny","kev":{"url":"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}}`,
		"epss":         `{"egress":"deny","epss":{"url":"https://epss.cyentia.com/epss_scores-current.csv.gz"}}`,
		"nvd":          `{"egress":"deny","nvd":{"url":"https://services.nvd.nist.gov/rest/json/cves/2.0"}}`,
		"osv":          `{"egress":"deny","osv":{"url":"https://osv-vulnerabilities.storage.googleapis.com"}}`,
		"vulnrichment": `{"egress":"deny","vulnrichment":{"url":"https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip"}}`,
		"exploitdb":    `{"egress":"deny","exploitdb":{"url":"https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"}}`,
		"uppercase":    `{"egress":"deny","kev":{"url":"https://WWW.CISA.GOV/x.json"}}`,
	} {
		_, err := ParseFeedMirrorSpec([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), "public address") {
			t.Errorf("%s: err = %v, want the public address refused", name, err)
		}
	}
	ok := `{"egress":"deny","kev":{"url":"https://mirror.corp/kev.json"},"nvd":{"url":"http://repo.internal/nvd"},
		"osv":{"url":"http://repo.internal/osv","ecosystems":["Go"]},"vulnrichment":{"url":"https://mirror.corp/vr.zip"}}`
	if _, err := ParseFeedMirrorSpec([]byte(ok)); err != nil {
		t.Errorf("a deny spec with mirrors was refused: %v", err)
	}
	// with egress allow the public address is simply the default
	if _, err := ParseFeedMirrorSpec([]byte(`{"egress":"allow","kev":{"url":"https://www.cisa.gov/x.json"}}`)); err != nil {
		t.Errorf("a public address with egress allow was refused: %v", err)
	}
}

func TestFeedMirrorRedactedHidesTokenPaths(t *testing.T) {
	s, err := ParseFeedMirrorSpec([]byte(`{"nvd":{"url":"https://m/nvd","tokenFile":"/etc/rampart/feed-secrets/nvd"},
		"vulncheckKev":{"tokenFile":"/etc/rampart/feed-secrets/vc"},
		"custom":[{"name":"a","url":"https://m/a","format":"osv-zip","tokenFile":"/etc/rampart/feed-secrets/a"},
		          {"name":"b","format":"intel-jsonl","pushTokenFile":"/var/run/rampart/feeds/b/token"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := s.Redacted()
	if r.NVD.TokenFile != "(set)" || r.VulnCheckKEV.TokenFile != "(set)" || r.Custom[0].TokenFile != "(set)" || r.Custom[1].PushTokenFile != "(set)" {
		t.Errorf("a token path was left in the copy: %+v %+v %+v", r.NVD, r.VulnCheckKEV, r.Custom)
	}
	if r.NVD.URL != "https://m/nvd" {
		t.Error("the address must stay: the page shows it")
	}
	// the original is untouched: the sync reads the real path from it
	if s.NVD.TokenFile != "/etc/rampart/feed-secrets/nvd" || s.VulnCheckKEV.TokenFile == "(set)" || s.Custom[0].TokenFile == "(set)" {
		t.Error("Redacted changed the resource it was called on")
	}
	var none *FeedMirrorSpec
	if none.Redacted() != nil {
		t.Error("a nil spec must stay nil")
	}
}

// Every feed has a switch. A source switched off needs nothing it would need to run: VulnCheck without a token is fine
// while it is off.
func TestParseFeedMirrorSpec_EnabledSwitch(t *testing.T) {
	s, err := ParseFeedMirrorSpec([]byte(`{"kev":{"enabled":false,"url":"https://m/kev.json"},"epss":{"enabled":true,"url":"https://m/e.gz"},
		"nvd":{"enabled":false},"osv":{"enabled":false,"ecosystems":["Go"]},
		"euvd":{"enabled":false},"vulncheckKev":{"enabled":false},
		"custom":[{"name":"x","url":"https://m/x","format":"osv-zip","enabled":false}]}`))
	if err != nil {
		t.Fatalf("a spec with switched-off feeds was refused: %v", err)
	}
	if On(s.KEV.Enabled) || !On(s.EPSS.Enabled) || On(s.NVD.Enabled) || On(s.OSV.Enabled) || !s.EUVD.Off() || !s.VulnCheckKEV.Off() || !s.Custom[0].Off() {
		t.Errorf("the switches were not read: %+v", s)
	}
	if !On(nil) || (&FeedSource{}).Off() || (*FeedSource)(nil).Off() {
		t.Error("absent must be on, and a missing block is not switched off")
	}
	if _, err := ParseFeedMirrorSpec([]byte(`{"vulncheckKev":{"enabled":true}}`)); err == nil {
		t.Error("VulnCheck switched on without a token must be refused")
	}
	// under deny, a switched-off feed may keep a public address: it is not read
	if _, err := ParseFeedMirrorSpec([]byte(`{"egress":"deny","kev":{"enabled":false,"url":"https://www.cisa.gov/x.json"}}`)); err != nil {
		t.Errorf("a switched-off feed with a public address under deny was refused: %v", err)
	}
	if _, err := ParseFeedMirrorSpec([]byte(`{"egress":"deny","kev":{"enabled":true,"url":"https://www.cisa.gov/x.json"}}`)); err == nil {
		t.Error("the same address, switched on, must still be refused")
	}
}
