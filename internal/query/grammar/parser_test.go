package grammar_test

import (
	"strings"
	"testing"

	"rampart/internal/query/grammar"
)

func TestParseQuery(t *testing.T) {
	input := `severity:critical,high state:open cve:CVE-2024-* score:>500 -state:fixed "sql injection"`

	q, err := grammar.Parse(input)
	if err != nil {
		t.Fatalf("failed to parse query: %v", err)
	}

	if len(q.Terms) != 6 {
		t.Fatalf("expected 6 terms, got %d", len(q.Terms))
	}

	// 1. severity:critical,high
	t0 := q.Terms[0]
	if t0.Field != "severity" || len(t0.Values) != 2 {
		t.Errorf("expected 2 severity values, got %+v", t0)
	}

	// 2. state:open
	t1 := q.Terms[1]
	if t1.Field != "state" || t1.Values[0].Raw != "open" {
		t.Errorf("expected state:open, got %+v", t1)
	}

	// 3. cve:CVE-2024-*
	t2 := q.Terms[2]
	if !t2.Values[0].IsWildcard || t2.Values[0].Prefix != "CVE-2024-" {
		t.Errorf("expected wildcard CVE-2024-, got %+v", t2.Values[0])
	}

	// 4. score:>500
	t3 := q.Terms[3]
	if !t3.Values[0].IsRange || t3.Values[0].RangeOp != ">" || t3.Values[0].RangeVal != "500" {
		t.Errorf("expected range > 500, got %+v", t3.Values[0])
	}

	// 5. -state:fixed (negated)
	t4 := q.Terms[4]
	if !t4.Negated || t4.Field != "state" || t4.Values[0].Raw != "fixed" {
		t.Errorf("expected negated state:fixed, got %+v", t4)
	}

	// 6. "sql injection" (full text search)
	t5 := q.Terms[5]
	if t5.Field != "" || t5.Text != "sql injection" {
		t.Errorf("expected free text 'sql injection', got %+v", t5)
	}
}

func TestBuildSQLWhere(t *testing.T) {
	input := `severity:critical,high state:open score:>=600 -state:fixed`
	q, err := grammar.Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	sqlWhere, args := q.BuildSQLWhere(1)

	if !strings.Contains(sqlWhere, "(severity = $1 OR severity = $2)") {
		t.Errorf("expected severity OR clause, got %s", sqlWhere)
	}
	if !strings.Contains(sqlWhere, "state = $3") {
		t.Errorf("expected state clause, got %s", sqlWhere)
	}
	if !strings.Contains(sqlWhere, "risk_score >= $4") {
		t.Errorf("expected risk_score range clause, got %s", sqlWhere)
	}
	if !strings.Contains(sqlWhere, "NOT (state = $5)") {
		t.Errorf("expected negated state clause, got %s", sqlWhere)
	}

	if len(args) != 5 {
		t.Fatalf("expected 5 args, got %d: %v", len(args), args)
	}
	if args[0] != "critical" || args[1] != "high" || args[2] != "open" || args[3] != "600" || args[4] != "fixed" {
		t.Errorf("unexpected arg values: %v", args)
	}
}

// FuzzParse: a filter is user input that reaches SQL through the builder; any string parses or is refused,
// never panics, and a parsed field is always a known one (D59, D61).
func FuzzParse(f *testing.F) {
	f.Add(`severity:critical,high -state:fixed age:>30d cve:CVE-2024-* "sql injection"`)
	f.Add(`owner:me ownr:none`)
	f.Add(`"unterminated`)
	f.Fuzz(func(t *testing.T, q string) {
		parsed, err := Parse(q)
		if err != nil {
			return
		}
		for _, term := range parsed.Terms {
			if term.Field != "" && !isKnownField(term.Field) {
				t.Fatalf("parsed an unknown field %q from %q", term.Field, q)
			}
		}
	})
}
