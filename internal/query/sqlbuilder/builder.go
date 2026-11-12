package sqlbuilder

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/query/grammar"
)

// Cursor represents the keyset pagination cursor (D16).
type Cursor struct {
	SortKey string `json:"sort_key"`
	SortVal string `json:"sort_val"`
	ID      string `json:"id"`
	Filter  string `json:"filter,omitempty"`
}

// Encode signs the cursor using HMAC-SHA256 and returns a URL-safe opaque string.
func (c *Cursor) Encode(secret []byte) string {
	raw, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, secret)
	mac.Write(raw)
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(raw) + "." + sig
}

// DecodeCursor validates and parses an HMAC-signed cursor token.
func DecodeCursor(token string, secret []byte) (*Cursor, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("sqlbuilder: malformed cursor")
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("sqlbuilder: invalid cursor base64: %w", err)
	}

	sig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("sqlbuilder: invalid cursor signature: %w", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(raw)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, errors.New("sqlbuilder: cursor signature mismatch")
	}

	var cur Cursor
	if err := json.Unmarshal(raw, &cur); err != nil {
		return nil, fmt.Errorf("sqlbuilder: unmarshaling cursor: %w", err)
	}

	return &cur, nil
}

// BuildFindingQuery generates parameterized SQL for finding search with keyset pagination (D16, D28).
func BuildFindingQuery(
	tenantID uuid.UUID,
	findingCols string,
	q *grammar.Query,
	sortKey string,
	limit int,
	cursor *Cursor,
) (string, []any, error) {
	if sortKey == "" {
		sortKey = "-score"
	}
	if limit <= 0 {
		limit = 50
	}

	var whereClauses []string
	var args []any
	paramIdx := 1

	// 1. Mandatory tenant isolation filter (RLS / D19)
	whereClauses = append(whereClauses, fmt.Sprintf("tenant_id = $%d", paramIdx))
	args = append(args, tenantID)
	paramIdx++

	// 2. Query grammar filters
	if q != nil {
		for _, term := range q.Terms {
			clause, termArgs, nextIdx := buildTermClause(term, paramIdx)
			if clause != "" {
				whereClauses = append(whereClauses, clause)
				args = append(args, termArgs...)
				paramIdx = nextIdx
			}
		}
	}

	// 3. Keyset cursor clause
	if cursor != nil && cursor.SortKey == sortKey && cursor.ID != "" {
		curClause, curArgs, _ := buildCursorClause(cursor, paramIdx)
		if curClause != "" {
			whereClauses = append(whereClauses, curClause)
			args = append(args, curArgs...)
		}
	}

	// 4. Order By clause
	orderClause := buildOrderByClause(sortKey)

	// 5. Limit (fetch limit + 1 to detect next page)
	fetchLimit := limit + 1
	limitClause := fmt.Sprintf("LIMIT %d", fetchLimit)

	sqlStr := fmt.Sprintf("SELECT %s FROM finding WHERE %s %s %s",
		findingCols,
		strings.Join(whereClauses, " AND "),
		orderClause,
		limitClause,
	)

	return sqlStr, args, nil
}

// BuildCountQuery generates SQL for counting matches.
func BuildCountQuery(tenantID uuid.UUID, q *grammar.Query) (string, []any) {
	var whereClauses []string
	var args []any
	paramIdx := 1

	whereClauses = append(whereClauses, fmt.Sprintf("tenant_id = $%d", paramIdx))
	args = append(args, tenantID)
	paramIdx++

	if q != nil {
		for _, term := range q.Terms {
			clause, termArgs, nextIdx := buildTermClause(term, paramIdx)
			if clause != "" {
				whereClauses = append(whereClauses, clause)
				args = append(args, termArgs...)
				paramIdx = nextIdx
			}
		}
	}

	sqlStr := fmt.Sprintf("SELECT COUNT(*) FROM finding WHERE %s", strings.Join(whereClauses, " AND "))
	return sqlStr, args
}

func buildTermClause(term grammar.Term, startIdx int) (string, []any, int) {
	if term.Text != "" {
		// Full-text search
		pattern := "%" + strings.ToLower(term.Text) + "%"
		idx := startIdx
		clause := fmt.Sprintf("(LOWER(title) LIKE $%d OR LOWER(description) LIKE $%d OR LOWER(rule_id) LIKE $%d OR LOWER(COALESCE(vulnerability_id, '')) LIKE $%d)", idx, idx, idx, idx)
		if term.Negated {
			clause = "NOT (" + clause + ")"
		}
		return clause, []any{pattern}, idx + 1
	}

	field := strings.ToLower(term.Field)
	var orClauses []string
	var args []any
	curIdx := startIdx

	switch field {
	case "state":
		for _, v := range term.Values {
			orClauses = append(orClauses, fmt.Sprintf("state = $%d", curIdx))
			args = append(args, v.Raw)
			curIdx++
		}
	case "severity":
		for _, v := range term.Values {
			orClauses = append(orClauses, fmt.Sprintf("severity = $%d", curIdx))
			args = append(args, v.Raw)
			curIdx++
		}
	case "risk":
		for _, v := range term.Values {
			orClauses = append(orClauses, fmt.Sprintf("risk_band = $%d", curIdx))
			args = append(args, v.Raw)
			curIdx++
		}
	case "score":
		for _, v := range term.Values {
			if v.IsRange {
				val, err := strconv.Atoi(v.RangeVal)
				if err == nil {
					orClauses = append(orClauses, fmt.Sprintf("risk_score %s $%d", v.RangeOp, curIdx))
					args = append(args, val)
					curIdx++
				}
			} else {
				val, err := strconv.Atoi(v.Raw)
				if err == nil {
					orClauses = append(orClauses, fmt.Sprintf("risk_score = $%d", curIdx))
					args = append(args, val)
					curIdx++
				}
			}
		}
	case "category":
		for _, v := range term.Values {
			orClauses = append(orClauses, fmt.Sprintf("category = $%d", curIdx))
			args = append(args, v.Raw)
			curIdx++
		}
	case "scanner":
		for _, v := range term.Values {
			orClauses = append(orClauses, fmt.Sprintf("rule_scanner_family = $%d", curIdx))
			args = append(args, v.Raw)
			curIdx++
		}
	case "rule":
		for _, v := range term.Values {
			if v.IsWildcard {
				orClauses = append(orClauses, fmt.Sprintf("rule_id ILIKE $%d", curIdx))
				args = append(args, v.Prefix+"%")
				curIdx++
			} else {
				orClauses = append(orClauses, fmt.Sprintf("rule_id = $%d", curIdx))
				args = append(args, v.Raw)
				curIdx++
			}
		}
	case "cve":
		// docs/16 D19: the id or any alias of it (a GHSA finding matches its CVE and the other way round).
		for _, v := range term.Values {
			if v.IsWildcard {
				orClauses = append(orClauses, fmt.Sprintf("(vulnerability_id ILIKE $%[1]d OR vulnerability_id IN (SELECT vulnerability_id FROM vulnerability_alias WHERE alias ILIKE $%[1]d))", curIdx))
				args = append(args, v.Prefix+"%")
			} else {
				orClauses = append(orClauses, fmt.Sprintf(`(vulnerability_id = $%[1]d
					OR vulnerability_id IN (SELECT vulnerability_id FROM vulnerability_alias WHERE alias = $%[1]d)
					OR vulnerability_id IN (SELECT alias FROM vulnerability_alias WHERE vulnerability_id = UPPER($%[1]d)))`, curIdx))
				args = append(args, v.Raw)
			}
			curIdx++
		}
	case "cwe":
		for _, v := range term.Values {
			val, err := strconv.Atoi(v.Raw)
			if err == nil {
				orClauses = append(orClauses, fmt.Sprintf("$%d = ANY(cwes)", curIdx))
				args = append(args, val)
				curIdx++
			}
		}
	case "app":
		for _, v := range term.Values {
			if uid, err := uuid.Parse(v.Raw); err == nil {
				orClauses = append(orClauses, fmt.Sprintf("application_id = $%d", curIdx))
				args = append(args, uid)
				curIdx++
			} else {
				orClauses = append(orClauses, fmt.Sprintf("application_id IN (SELECT id FROM application WHERE slug = $%d)", curIdx))
				args = append(args, v.Raw)
				curIdx++
			}
		}
	case "asset":
		for _, v := range term.Values {
			if uid, err := uuid.Parse(v.Raw); err == nil {
				orClauses = append(orClauses, fmt.Sprintf("asset_id = $%d", curIdx))
				args = append(args, uid)
				curIdx++
			} else {
				orClauses = append(orClauses, fmt.Sprintf("asset_id IN (SELECT id FROM asset WHERE key ILIKE $%d)", curIdx))
				args = append(args, v.Raw+"%")
				curIdx++
			}
		}
	case "track":
		for _, v := range term.Values {
			orClauses = append(orClauses, fmt.Sprintf("track = $%d", curIdx))
			args = append(args, v.Raw)
			curIdx++
		}
	case "env":
		for _, v := range term.Values {
			orClauses = append(orClauses, fmt.Sprintf("(environment_kind = $%d OR track = $%d)", curIdx, curIdx))
			args = append(args, v.Raw)
			curIdx++
		}
	case "path":
		for _, v := range term.Values {
			prefix := v.Raw
			if v.IsWildcard {
				prefix = v.Prefix
			}
			orClauses = append(orClauses, fmt.Sprintf("(file_path ILIKE $%d OR location->>'path' ILIKE $%d)", curIdx, curIdx))
			args = append(args, prefix+"%")
			curIdx++
		}
	case "purl":
		for _, v := range term.Values {
			prefix := v.Raw
			if v.IsWildcard {
				prefix = v.Prefix
			}
			orClauses = append(orClauses, fmt.Sprintf("(purl_base ILIKE $%d OR location->'package'->>'purl_base' ILIKE $%d)", curIdx, curIdx))
			args = append(args, prefix+"%")
			curIdx++
		}
	case "tag":
		for _, v := range term.Values {
			orClauses = append(orClauses, fmt.Sprintf("$%d = ANY(tags)", curIdx))
			args = append(args, v.Raw)
			curIdx++
		}
	case "kev":
		for _, v := range term.Values {
			val := strings.EqualFold(v.Raw, "true") || v.Raw == "1"
			// Known-exploited status lives in the global vulnerability table (D19), not on the finding.
			orClauses = append(orClauses, fmt.Sprintf("(EXISTS (SELECT 1 FROM vulnerability v WHERE v.kev_date_added IS NOT NULL AND (v.id = UPPER(finding.vulnerability_id) OR v.id IN (SELECT a.vulnerability_id FROM vulnerability_alias a WHERE a.alias = finding.vulnerability_id)))) = $%d", curIdx))
			args = append(args, val)
			curIdx++
		}
	case "fix":
		for _, v := range term.Values {
			val := strings.EqualFold(v.Raw, "true") || v.Raw == "1"
			orClauses = append(orClauses, fmt.Sprintf("fix_available = $%d", curIdx))
			args = append(args, val)
			curIdx++
		}
	case "sla":
		for _, v := range term.Values {
			if strings.EqualFold(v.Raw, "breached") {
				orClauses = append(orClauses, "sla_due_date IS NOT NULL AND sla_due_date < NOW() AND state IN ('open', 'affected')")
			} else if strings.HasPrefix(v.Raw, "due:") {
				dStr := strings.TrimPrefix(v.Raw, "due:")
				if dur, err := parseDurationStr(dStr); err == nil {
					orClauses = append(orClauses, fmt.Sprintf("sla_due_date BETWEEN NOW() AND NOW() + $%d::interval", curIdx))
					args = append(args, fmt.Sprintf("%d seconds", int(dur.Seconds())))
					curIdx++
				}
			}
		}
	case "age":
		for _, v := range term.Values {
			op := ">"
			rawVal := v.Raw
			if v.IsRange {
				op = v.RangeOp
				rawVal = v.RangeVal
			}
			if dur, err := parseDurationStr(rawVal); err == nil {
				// age > 30d means first_seen < NOW() - 30d
				sqlOp := flipAgeOp(op)
				orClauses = append(orClauses, fmt.Sprintf("first_seen %s NOW() - $%d::interval", sqlOp, curIdx))
				args = append(args, fmt.Sprintf("%d seconds", int(dur.Seconds())))
				curIdx++
			}
		}
	case "seen":
		for _, v := range term.Values {
			op := ">"
			rawVal := v.Raw
			if v.IsRange {
				op = v.RangeOp
				rawVal = v.RangeVal
			}
			if dur, err := parseDurationStr(rawVal); err == nil {
				sqlOp := flipAgeOp(op)
				orClauses = append(orClauses, fmt.Sprintf("last_seen %s NOW() - $%d::interval", sqlOp, curIdx))
				args = append(args, fmt.Sprintf("%d seconds", int(dur.Seconds())))
				curIdx++
			}
		}
	case "source":
		for _, v := range term.Values {
			if uid, err := uuid.Parse(v.Raw); err == nil {
				orClauses = append(orClauses, fmt.Sprintf("EXISTS (SELECT 1 FROM occurrence o WHERE o.finding_id = finding.id AND o.scan_source_id = $%d)", curIdx))
				args = append(args, uid)
				curIdx++
			} else {
				orClauses = append(orClauses, fmt.Sprintf("EXISTS (SELECT 1 FROM occurrence o WHERE o.finding_id = finding.id AND o.scanner_name = $%d)", curIdx))
				args = append(args, v.Raw)
				curIdx++
			}
		}
	case "run":
		for _, v := range term.Values {
			if uid, err := uuid.Parse(v.Raw); err == nil {
				orClauses = append(orClauses, fmt.Sprintf("EXISTS (SELECT 1 FROM occurrence o WHERE o.finding_id = finding.id AND o.ingest_run_id = $%d)", curIdx))
				args = append(args, uid)
				curIdx++
			}
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

func buildOrderByClause(sortKey string) string {
	switch sortKey {
	case "score":
		return "ORDER BY risk_score ASC, id ASC"
	case "-seen":
		return "ORDER BY last_seen DESC, id DESC"
	case "seen":
		return "ORDER BY last_seen ASC, id ASC"
	case "-age":
		return "ORDER BY first_seen DESC, id DESC"
	case "age":
		return "ORDER BY first_seen ASC, id ASC"
	case "severity":
		return "ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, id DESC"
	case "-score":
		fallthrough
	default:
		return "ORDER BY risk_score DESC, id DESC"
	}
}

func buildCursorClause(cur *Cursor, startIdx int) (string, []any, int) {
	idVal, err := uuid.Parse(cur.ID)
	if err != nil {
		return "", nil, startIdx
	}

	idx := startIdx
	switch cur.SortKey {
	case "score":
		val, _ := strconv.Atoi(cur.SortVal)
		clause := fmt.Sprintf("(risk_score > $%d OR (risk_score = $%d AND id > $%d))", idx, idx, idx+1)
		return clause, []any{val, idVal}, idx + 2
	case "-seen":
		tVal, _ := time.Parse(time.RFC3339Nano, cur.SortVal)
		clause := fmt.Sprintf("(last_seen < $%d OR (last_seen = $%d AND id < $%d))", idx, idx, idx+1)
		return clause, []any{tVal, idVal}, idx + 2
	case "seen":
		tVal, _ := time.Parse(time.RFC3339Nano, cur.SortVal)
		clause := fmt.Sprintf("(last_seen > $%d OR (last_seen = $%d AND id > $%d))", idx, idx, idx+1)
		return clause, []any{tVal, idVal}, idx + 2
	case "-age":
		tVal, _ := time.Parse(time.RFC3339Nano, cur.SortVal)
		clause := fmt.Sprintf("(first_seen < $%d OR (first_seen = $%d AND id < $%d))", idx, idx, idx+1)
		return clause, []any{tVal, idVal}, idx + 2
	case "age":
		tVal, _ := time.Parse(time.RFC3339Nano, cur.SortVal)
		clause := fmt.Sprintf("(first_seen > $%d OR (first_seen = $%d AND id > $%d))", idx, idx, idx+1)
		return clause, []any{tVal, idVal}, idx + 2
	case "severity":
		val, _ := strconv.Atoi(cur.SortVal)
		clause := fmt.Sprintf("(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END < $%d OR (CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END = $%d AND id < $%d))", idx, idx, idx+1)
		return clause, []any{val, idVal}, idx + 2
	case "-score":
		fallthrough
	default:
		val, _ := strconv.Atoi(cur.SortVal)
		clause := fmt.Sprintf("(risk_score < $%d OR (risk_score = $%d AND id < $%d))", idx, idx, idx+1)
		return clause, []any{val, idVal}, idx + 2
	}
}

func parseDurationStr(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "w") {
		num, err := strconv.Atoi(strings.TrimSuffix(s, "w"))
		if err != nil {
			return 0, err
		}
		return time.Duration(num*7*24) * time.Hour, nil
	}
	if strings.HasSuffix(s, "d") {
		num, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(num*24) * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// flipAgeOp turns an age comparison into the comparison on the timestamp: "older than 30d" is
// first_seen < NOW() - 30d, so the direction flips.
func flipAgeOp(op string) string {
	switch op {
	case "<":
		return ">"
	case "<=":
		return ">="
	case ">=":
		return "<="
	}
	return "<"
}
