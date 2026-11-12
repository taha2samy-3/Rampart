package normalize_test

import (
	"testing"

	"rampart/internal/normalize"
)

func TestCanonicalPURL(t *testing.T) {
	tests := []struct {
		raw          string
		wantCanon    string
		wantPurlBase string
	}{
		{
			raw:          "pkg:npm/%40angular/animation@12.3.1?arch=x86#dist",
			wantCanon:    "pkg:npm/%40angular/animation@12.3.1?arch=x86#dist",
			wantPurlBase: "pkg:npm/%40angular/animation",
		},
		{
			raw:          "pkg:golang/github.com/golang-jwt/jwt/v5@v5.2.0",
			wantCanon:    "pkg:golang/github.com/golang-jwt/jwt/v5@v5.2.0",
			wantPurlBase: "pkg:golang/github.com/golang-jwt/jwt/v5",
		},
		{
			raw:          "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			wantCanon:    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			wantPurlBase: "pkg:maven/org.apache.logging.log4j/log4j-core",
		},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			canon, base, err := normalize.CanonicalPURL(tt.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if canon != tt.wantCanon {
				t.Errorf("got canon %q, want %q", canon, tt.wantCanon)
			}
			if base != tt.wantPurlBase {
				t.Errorf("got purlBase %q, want %q", base, tt.wantPurlBase)
			}
		})
	}
}

func TestCleanPathAndURL(t *testing.T) {
	if got := normalize.CleanPath(".\\src\\main.go"); got != "src/main.go" {
		t.Errorf("unexpected CleanPath: %q", got)
	}

	if got := normalize.NormalizeURL("https://example.com:8443/api/v1/user?token=secret#section"); got != "https://example.com:8443/api/v1/user" {
		t.Errorf("unexpected NormalizeURL: %q", got)
	}
}

func TestCanonicalVulnID(t *testing.T) {
	cases := []struct {
		ids  []string
		want string
	}{
		{[]string{"GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"}, "CVE-2021-44228"}, // a CVE beats the id Grype matched on
		{[]string{"cve-2021-44228"}, "CVE-2021-44228"},                        // upper-cased
		{[]string{"CVE-2022-2", "CVE-2021-9", "GHSA-aaaa-bbbb-cccc"}, "CVE-2021-9"},
		{[]string{"GHSA-ZZZZ-aaaa-bbbb", "GHSA-AAAA-bbbb-cccc"}, "GHSA-aaaa-bbbb-cccc"}, // the smallest GHSA, lower-cased body
		{[]string{"PYSEC-2021-1", "OSV-2020-1"}, "PYSEC-2021-1"},                        // else the first, as written
		{[]string{"", "  ", "RUSTSEC-2020-0001"}, "RUSTSEC-2020-0001"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := normalize.CanonicalVulnID(c.ids); got != c.want {
			t.Errorf("CanonicalVulnID(%v) = %q, want %q", c.ids, got, c.want)
		}
	}
}
