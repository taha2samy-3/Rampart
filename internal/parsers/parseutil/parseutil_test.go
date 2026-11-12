package parseutil_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/parsers/parseutil"
)

func TestSeverity(t *testing.T) {
	cases := []struct {
		tool  string
		score float64
		want  domain.Severity
	}{
		{"CRITICAL", 0, domain.SeverityCritical},
		{"High", 0, domain.SeverityHigh},
		{"Medium", 0, domain.SeverityMedium},
		{"Negligible", 0, domain.SeverityInfo},
		{"UNKNOWN", 9.8, domain.SeverityCritical}, // the CVSS score fills in what the tool did not say
		{"", 7.2, domain.SeverityHigh},
		{"", 4.0, domain.SeverityMedium},
		{"", 0.1, domain.SeverityLow},
		{"UNKNOWN", 0, domain.SeverityUnknown},
		{"ERROR", 0, domain.SeverityHigh},
	}
	for _, c := range cases {
		if got := parseutil.Severity(c.tool, c.score); got != c.want {
			t.Errorf("Severity(%q, %v) = %q, want %q", c.tool, c.score, got, c.want)
		}
	}
}

func TestCWEs(t *testing.T) {
	got := parseutil.CWEs("CWE-79: Improper Neutralization", "cwe-79", "CWE787", "nothing", "CWE-0")
	if len(got) != 2 || got[0] != 79 || got[1] != 787 {
		t.Fatalf("got %v, want [79 787] (deduplicated, no CWE-0)", got)
	}
}

func TestWalk(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"skip":{"deep":[1,2,{"x":[]}]},"items":[{"a":1},{"a":2}],"n":null,"list":null}`))
	var as []int
	err := parseutil.Object(dec, func(key string) error {
		switch key {
		case "items":
			return parseutil.Array(dec, func() error {
				var v struct{ A int }
				if _, err := parseutil.Element(dec, &v); err != nil {
					return err
				}
				as = append(as, v.A)
				return nil
			})
		case "list":
			return parseutil.Array(dec, func() error { t.Fatal("null is an empty array"); return nil })
		}
		return parseutil.Skip(dec)
	})
	if err != nil || len(as) != 2 || as[0] != 1 || as[1] != 2 {
		t.Fatalf("walk: %v %v", err, as)
	}
}

func TestSkipRefusesDeepNesting(t *testing.T) {
	deep := strings.Repeat("[", parseutil.MaxDepth+10) + strings.Repeat("]", parseutil.MaxDepth+10)
	if err := parseutil.Skip(json.NewDecoder(strings.NewReader(deep))); !errors.Is(err, parseutil.ErrTooDeep) {
		t.Fatalf("a document nested %d deep must be refused, got %v", parseutil.MaxDepth+10, err)
	}
}
