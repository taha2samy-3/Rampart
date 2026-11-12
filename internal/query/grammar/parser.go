package grammar

import (
	"fmt"
	"strings"
	"unicode"
)

// Value represents an individual criterion value in a field filter (D16).
type Value struct {
	Raw        string
	IsRange    bool
	RangeOp    string // >, >=, <, <=
	RangeVal   string
	IsWildcard bool   // true if prefix match like "CVE-2024-*"
	Prefix     string // string before '*'
}

// Term represents an atomic query condition.
type Term struct {
	Negated bool
	Field   string  // empty if full-text search
	Values  []Value // OR list within a field
	Text    string  // full-text search content
}

// Query represents the complete parsed query AST.
type Query struct {
	Terms []Term
}

// KnownFields are the fields of D16, the same list as KNOWN_FIELDS in web/src/lib/grammar.ts.
var KnownFields = []string{"state", "severity", "risk", "score", "category", "scanner", "rule", "cve", "cwe", "app", "asset",
	"assettype", "env", "track", "path", "purl", "tag", "owner", "kev", "fix", "sla", "age", "seen", "source", "run", "hierarchy"}

func isKnownField(f string) bool {
	for _, k := range KnownFields {
		if k == f {
			return true
		}
	}
	return false
}

// Parse turns a query string into a structured Query AST per normative D16 EBNF. An unknown field is an error,
// never ignored: an ignored term widens the match, and a bulk change by filter would then reach findings the
// person did not mean (D59). Free text that contains a colon (a URL) is written in quotes.
func Parse(q string) (Query, error) {
	var terms []Term
	tokens := tokenize(q)

	for _, tok := range tokens {
		if tok == "" {
			continue
		}

		negated := false
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			negated = true
			tok = tok[1:]
		}

		// Check if it's a field term: field:val1,val2
		colonIdx := strings.Index(tok, ":")
		if colonIdx != -1 {
			field := strings.ToLower(tok[:colonIdx])
			if !isKnownField(field) {
				return Query{}, fmt.Errorf("unknown field %q (known: %s); put free text that contains a colon in quotes", field, strings.Join(KnownFields, ", "))
			}
			valStr := tok[colonIdx+1:]
			values := parseValues(valStr)

			terms = append(terms, Term{
				Negated: negated,
				Field:   field,
				Values:  values,
			})
		} else {
			// Free text search term
			terms = append(terms, Term{
				Negated: negated,
				Text:    tok,
			})
		}
	}

	return Query{Terms: terms}, nil
}

func parseValues(s string) []Value {
	rawValues := splitValues(s)
	var values []Value

	for _, v := range rawValues {
		val := Value{Raw: v}

		// Check range: >, >=, <, <=
		if strings.HasPrefix(v, ">=") {
			val.IsRange = true
			val.RangeOp = ">="
			val.RangeVal = v[2:]
		} else if strings.HasPrefix(v, "<=") {
			val.IsRange = true
			val.RangeOp = "<="
			val.RangeVal = v[2:]
		} else if strings.HasPrefix(v, ">") {
			val.IsRange = true
			val.RangeOp = ">"
			val.RangeVal = v[1:]
		} else if strings.HasPrefix(v, "<") {
			val.IsRange = true
			val.RangeOp = "<"
			val.RangeVal = v[1:]
		} else if strings.HasSuffix(v, "*") {
			// Wildcard prefix match
			val.IsWildcard = true
			val.Prefix = strings.TrimSuffix(v, "*")
		}

		values = append(values, val)
	}

	return values
}

func tokenize(input string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(input); i++ {
		ch := rune(input[i])

		if ch == '"' {
			inQuote = !inQuote
			continue
		}

		if unicode.IsSpace(ch) && !inQuote {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

func splitValues(s string) []string {
	var values []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		ch := rune(s[i])
		if ch == '"' {
			inQuote = !inQuote
			continue
		}

		if ch == ',' && !inQuote {
			if current.Len() > 0 {
				values = append(values, current.String())
				current.Reset()
			}
		} else {
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		values = append(values, current.String())
	}

	return values
}

// BuildSQLWhere translates the Query AST into parameterized SQL with $1, $2, ... positional args (D16).
func (q Query) BuildSQLWhere(paramStartIndex int) (string, []any) {
	if len(q.Terms) == 0 {
		return "", nil
	}

	var clauses []string
	var args []any
	paramIdx := paramStartIndex

	for _, term := range q.Terms {
		if term.Field != "" {
			clause, termArgs, nextIdx := buildFieldClause(term, paramIdx)
			if clause != "" {
				clauses = append(clauses, clause)
				args = append(args, termArgs...)
				paramIdx = nextIdx
			}
		} else if term.Text != "" {
			// Text full-text search: title ILIKE or description ILIKE
			pattern := "%" + term.Text + "%"
			op := "ILIKE"
			notPrefix := ""
			if term.Negated {
				notPrefix = "NOT "
			}
			clauses = append(clauses, fmt.Sprintf("%s(title %s $%d OR description %s $%d)", notPrefix, op, paramIdx, op, paramIdx))
			args = append(args, pattern)
			paramIdx++
		}
	}

	if len(clauses) == 0 {
		return "", nil
	}

	return strings.Join(clauses, " AND "), args
}

func buildFieldClause(term Term, startIdx int) (string, []any, int) {
	colName := mapFieldToColumn(term.Field)
	if colName == "" {
		return "", nil, startIdx
	}

	var orClauses []string
	var args []any
	curIdx := startIdx

	for _, val := range term.Values {
		if val.IsRange {
			orClauses = append(orClauses, fmt.Sprintf("%s %s $%d", colName, val.RangeOp, curIdx))
			args = append(args, val.RangeVal)
			curIdx++
		} else if val.IsWildcard {
			orClauses = append(orClauses, fmt.Sprintf("%s ILIKE $%d", colName, curIdx))
			args = append(args, val.Prefix+"%")
			curIdx++
		} else {
			orClauses = append(orClauses, fmt.Sprintf("%s = $%d", colName, curIdx))
			args = append(args, val.Raw)
			curIdx++
		}
	}

	if len(orClauses) == 0 {
		return "", nil, startIdx
	}

	combined := strings.Join(orClauses, " OR ")
	if len(orClauses) > 1 {
		combined = "(" + combined + ")"
	}

	if term.Negated {
		combined = "NOT (" + combined + ")"
	}

	return combined, args, curIdx
}

func mapFieldToColumn(field string) string {
	switch strings.ToLower(field) {
	case "state":
		return "state"
	case "severity":
		return "severity"
	case "risk":
		return "risk_score"
	case "score":
		return "risk_score"
	case "category":
		return "category"
	case "scanner":
		return "rule_scanner_family"
	case "rule":
		return "rule_id"
	case "cve":
		return "vulnerability_id"
	case "track":
		return "track"
	case "detection":
		return "detection"
	default:
		return ""
	}
}
