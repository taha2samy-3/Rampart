package domain

import "testing"

// D86: a ClusterFeedMirror is validated; what this version does not do is refused, not ignored.
func TestParseFeedMirrorSpec(t *testing.T) {
	if s, err := ParseFeedMirrorSpec([]byte(`{"nvd":{"url":"https://mirror.internal/nvd"},"kev":{"url":"http://mirror.internal/kev.json"},"egress":"deny"}`)); err != nil || s.Egress != "deny" || s.NVD.URL == "" {
		t.Fatalf("a valid mirror was refused: %v", err)
	}
	for name, raw := range map[string]string{
		"schedule":      `{"nvd":{"url":"https://m/nvd","schedule":"0 2 * * *"}}`,
		"cwe":           `{"cwe":{"url":"https://m/cwe.zip"}}`,
		"bad egress":    `{"egress":"sometimes"}`,
		"not a url":     `{"kev":{"url":"ftp://m/kev"}}`,
		"unknown field": `{"nvdd":{"url":"https://m"}}`,
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
		"vulncheckKev":{"tokenFile":"/var/run/rampart/feeds/vulncheck"},
		"custom":[{"name":"vulndb","url":"https://proxy.internal/vulndb.jsonl","format":"intel-jsonl","tokenFile":"/var/run/rampart/feeds/vulndb"}]}`
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
