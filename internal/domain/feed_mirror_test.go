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
