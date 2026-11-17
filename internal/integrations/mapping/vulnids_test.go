package mapping

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"rampart/internal/domain"
)

// vulnIds: '[rec.id]' is the example in docs/19 and docs/25. A CEL list written in the expression came back as one string,
// "[ACME-1]", with the brackets, so no CVE ever matched: no KEV, no EPSS, no CVE page.
func TestMappingParser_VulnIDsAreTheItemsOfTheList(t *testing.T) {
	for name, expr := range map[string]string{
		"a list literal":        `[rec.id]`,
		"two items":             `[rec.id, rec.alias]`,
		"a list from the input": `rec.ids`,
		"a computed list":       `rec.ids.map(i, i.lowerAscii())`,
		"a plain string":        `rec.id`,
	} {
		yaml := strings.Replace(richYAML, "vulnIds: '[rec.id]'", "vulnIds: '"+expr+"'", 1)
		p, err := NewMappingParser([]byte(yaml))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		doc := `{"issues":[{"id":"CVE-2021-44228","alias":"GHSA-jfh8-c2jp-5v3q","ids":["cve-2021-44228","ghsa-jfh8-c2jp-5v3q"],"title":"t","sev":"HIGH"}]}`
		var got []domain.RawFinding
		for f, err := range p.Parse(context.Background(), strings.NewReader(doc), domain.ParseContext{}) {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			got = append(got, f)
		}
		if len(got) != 1 {
			t.Fatalf("%s: %d findings", name, len(got))
		}
		for _, id := range got[0].VulnIDs {
			if strings.ContainsAny(id, "[]") {
				t.Errorf("%s (%s): %q has brackets: the list was turned into a string", name, expr, id)
			}
		}
		want := map[string][]string{
			`[rec.id]`: {"CVE-2021-44228"}, `[rec.id, rec.alias]`: {"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"},
			`rec.ids`: {"cve-2021-44228", "ghsa-jfh8-c2jp-5v3q"}, `rec.ids.map(i, i.lowerAscii())`: {"cve-2021-44228", "ghsa-jfh8-c2jp-5v3q"},
			`rec.id`: {"CVE-2021-44228"},
		}[expr]
		if !reflect.DeepEqual(got[0].VulnIDs, want) {
			t.Errorf("%s (%s): VulnIDs %q, want %q", name, expr, got[0].VulnIDs, want)
		}
	}
}
