package enrich

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func rowsOf(t *testing.T, affected string) []affectedRow {
	t.Helper()
	return affectedRows(json.RawMessage(affected))
}

// The events of an OSV range become one row per interval. introduced is included, fixed is excluded, last_affected is
// included; "0" is the first version.
func TestAffectedRowsIntervals(t *testing.T) {
	rows := rowsOf(t, `[{"package":{"ecosystem":"npm","name":"Lodash"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.12"},{"introduced":"5.0.0"},{"last_affected":"5.2.0"},{"introduced":"6.0.0"}]}]}]`)
	type iv struct{ in, fixed, last string }
	var got []iv
	for _, r := range rows {
		if r.RangeType != rangeSemver || r.NameNormalised != "lodash" || r.Name != "Lodash" || r.Ecosystem != "npm" {
			t.Fatalf("row = %+v", r)
		}
		got = append(got, iv{r.Introduced, r.Fixed, r.LastAffected})
	}
	want := []iv{{"0", "4.17.12", ""}, {"5.0.0", "", "5.2.0"}, {"6.0.0", "", ""}} // the last one is open: no fix yet
	if !reflect.DeepEqual(got, want) {
		t.Errorf("intervals = %v, want %v", got, want)
	}
}

func TestAffectedRowsFixedWithoutIntroduced(t *testing.T) {
	// some records give only the fix: everything before it is affected
	rows := rowsOf(t, `[{"package":{"ecosystem":"Go","name":"example.com/a/b"},"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1.2.3"}]}]}]`)
	if len(rows) != 1 || rows[0].Introduced != "0" || rows[0].Fixed != "1.2.3" || rows[0].RangeType != rangeEcosystem {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].PurlBase != "pkg:golang/example.com/a/b" || rows[0].NameNormalised != "example.com/a/b" {
		t.Errorf("purl base %q, normalised %q (Go keeps its case and path)", rows[0].PurlBase, rows[0].NameNormalised)
	}
}

func TestAffectedRowsLimitAppliesToTheOpenInterval(t *testing.T) {
	rows := rowsOf(t, `[{"package":{"ecosystem":"PyPI","name":"Foo_Bar"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"limit":"2.0"}]}]}]`)
	if len(rows) != 1 || rows[0].Limit != "2.0" || rows[0].Fixed != "" || rows[0].NameNormalised != "foo-bar" {
		t.Fatalf("rows = %+v", rows)
	}
}

// A GIT range holds commits, which a component with a version cannot be compared to: it is not stored. The explicit
// versions list is, as one row of its own.
func TestAffectedRowsGitRangeAndVersions(t *testing.T) {
	rows := rowsOf(t, `[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},
		"ranges":[{"type":"GIT","repo":"https://github.com/apache/logging-log4j2","events":[{"introduced":"0"},{"fixed":"abc123"}]},
		          {"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}],
		"versions":["2.0-beta9","2.14.1"]}]`)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want the ECOSYSTEM interval and the versions row", rows)
	}
	if rows[0].RangeType != rangeEcosystem || rows[0].Introduced != "2.0-beta9" || rows[0].Fixed != "2.15.0" {
		t.Errorf("interval = %+v", rows[0])
	}
	if rows[1].RangeType != rangeVersions || !reflect.DeepEqual(rows[1].Versions, []string{"2.0-beta9", "2.14.1"}) || rows[1].Introduced != "" {
		t.Errorf("versions row = %+v", rows[1])
	}
	if rows[0].PurlBase != "pkg:maven/org.apache.logging.log4j/log4j-core" {
		t.Errorf("maven purl base = %q", rows[0].PurlBase)
	}
}

func TestAffectedRowsSkipsWhatCannotBeUsed(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":        ``,
		"not json":     `{`,
		"no package":   `[{"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]`,
		"unknown type": `[{"package":{"ecosystem":"npm","name":"x"},"ranges":[{"type":"WEIRD","events":[{"introduced":"0"}]}]}]`,
		"no ranges":    `[{"package":{"ecosystem":"npm","name":"x"}}]`,
		"no name":      `[{"package":{"ecosystem":"npm","name":""},"versions":["1"]}]`,
	} {
		if rows := affectedRows(json.RawMessage(raw)); len(rows) != 0 {
			t.Errorf("%s: rows = %+v, want none", name, rows)
		}
	}
	// the same interval twice is one row
	rows := rowsOf(t, `[{"package":{"ecosystem":"npm","name":"x"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1"}]},{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1"}]}]}]`)
	if len(rows) != 1 {
		t.Errorf("a repeated interval was stored %d times", len(rows))
	}
}

func TestNormalisePackageName(t *testing.T) {
	cases := []struct{ eco, in, want string }{
		{"PyPI", "Django", "django"},
		{"PyPI", "typing_extensions", "typing-extensions"},
		{"PyPI", "Foo.Bar__baz", "foo-bar-baz"},
		{"npm", "@Scope/Pkg", "@scope/pkg"},
		{"NuGet", "Newtonsoft.Json", "newtonsoft.json"},
		{"Packagist", "Symfony/Console", "symfony/console"},
		{"crates.io", "Serde_Json", "serde-json"},
		{"Go", "github.com/Foo/Bar", "github.com/Foo/Bar"},
		{"Maven", "Org.Apache:Thing", "Org.Apache:Thing"},
		{"Debian:12", "OpenSSL", "OpenSSL"},
		{"PyPI", "  padded  ", "padded"},
	}
	for _, c := range cases {
		if got := NormalisePackageName(c.eco, c.in); got != c.want {
			t.Errorf("%s %q = %q, want %q", c.eco, c.in, got, c.want)
		}
	}
}

func TestPurlBaseOf(t *testing.T) {
	cases := []struct{ eco, name, purl, want string }{
		{"npm", "lodash", "", "pkg:npm/lodash"},
		{"npm", "@angular/core", "", "pkg:npm/%40angular/core"},
		{"PyPI", "Django", "", "pkg:pypi/django"},
		{"crates.io", "serde", "", "pkg:cargo/serde"},
		{"RubyGems", "rails", "", "pkg:gem/rails"},
		{"Packagist", "symfony/console", "", "pkg:composer/symfony/console"},
		{"NuGet", "Newtonsoft.Json", "", "pkg:nuget/newtonsoft.json"},
		{"Maven", "com.google.guava:guava", "", "pkg:maven/com.google.guava/guava"},
		{"Debian:12", "openssl", "", ""}, // a distro package needs a distro namespace the record does not give
		{"Go", "golang.org/x/crypto", "", "pkg:golang/golang.org/x/crypto"},
		{"npm", "x", "pkg:npm/lodash@4.17.21?foo=bar", "pkg:npm/lodash"}, // a purl in the record wins, without version or qualifiers
	}
	for _, c := range cases {
		if got := PurlBaseOf(c.eco, c.name, c.purl); !strings.EqualFold(got, c.want) {
			t.Errorf("%s %q %q = %q, want %q", c.eco, c.name, c.purl, got, c.want)
		}
	}
}

// One record naming several CVEs must not merge them: the smallest is canonical (not the first listed), the others are
// listed but never registered as aliases.
func TestCanonicalVulnID(t *testing.T) {
	canon, all, reg := canonicalVulnID("GHSA-aaaa-bbbb-cccc", []string{"CVE-2024-9999", "PYSEC-2024-1", "CVE-2024-0001", "GO-2024-5"})
	if canon != "CVE-2024-0001" {
		t.Errorf("canonical = %s, want the smallest CVE regardless of the order listed", canon)
	}
	if !reflect.DeepEqual(reg, []string{"GHSA-aaaa-bbbb-cccc", "PYSEC-2024-1", "GO-2024-5"}) {
		t.Errorf("registered aliases = %v: the other CVE must not be one", reg)
	}
	hasOther := false
	for _, a := range all {
		if a == "CVE-2024-9999" {
			hasOther = true
		}
	}
	if !hasOther {
		t.Errorf("the other CVE must be listed on the row: %v", all)
	}
	// the same set in another order gives the same answer
	c2, _, r2 := canonicalVulnID("GHSA-aaaa-bbbb-cccc", []string{"CVE-2024-0001", "GO-2024-5", "PYSEC-2024-1", "CVE-2024-9999"})
	if c2 != canon || len(r2) != len(reg) {
		t.Errorf("order changed the answer: %s %v", c2, r2)
	}
	// no CVE: the OSV id is canonical
	canon, all, reg = canonicalVulnID("GHSA-xxxx", []string{"PYSEC-1"})
	if canon != "GHSA-xxxx" || !reflect.DeepEqual(all, []string{"PYSEC-1"}) || !reflect.DeepEqual(reg, []string{"PYSEC-1"}) {
		t.Errorf("no CVE: %s %v %v", canon, all, reg)
	}
	// a lower-case CVE is still a CVE
	if canon, _, _ := canonicalVulnID("GHSA-y", []string{"cve-2024-0002"}); canon != "CVE-2024-0002" {
		t.Errorf("canonical = %s", canon)
	}
}

func TestOSVCVSS(t *testing.T) {
	entries, best := osvCVSS([]osvSeverity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{Type: "Ubuntu", Score: "high"},
		{Type: "CVSS_V3", Score: "not a vector"},
	}, "osv")
	if len(entries) != 3 || !strings.HasPrefix(best, "CVSS:4.0/") {
		t.Fatalf("entries %v best %q: the newest version is best and what is not a vector is dropped", entries, best)
	}
	if entries[1]["version"] != "3.1" || entries[1]["source"] != "osv" {
		t.Errorf("entry = %v", entries[1])
	}
	if _, has := entries[0]["score"]; has {
		t.Error("no score may be invented: Rampart has no CVSS calculator")
	}
	if e, b := osvCVSS(nil, "osv"); len(e) != 0 || b != "" {
		t.Error("no severity gives nothing")
	}
}

func TestParseWithdrawn(t *testing.T) {
	if parseWithdrawn("2024-03-01T00:00:00Z") == nil || parseWithdrawn("") != nil || parseWithdrawn("yesterday") != nil {
		t.Error("withdrawn parsing")
	}
}
