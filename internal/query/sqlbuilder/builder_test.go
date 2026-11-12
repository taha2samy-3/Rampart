package sqlbuilder

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/query/grammar"
)

func TestCursorEncodeDecode(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-minimum")
	cur := &Cursor{
		SortKey: "-score",
		SortVal: "850",
		ID:      uuid.New().String(),
		Filter:  "state:open",
	}

	tok := cur.Encode(secret)
	if tok == "" {
		t.Fatal("expected non-empty token")
	}

	decoded, err := DecodeCursor(tok, secret)
	if err != nil {
		t.Fatalf("failed to decode cursor: %v", err)
	}

	if decoded.SortKey != cur.SortKey || decoded.SortVal != cur.SortVal || decoded.ID != cur.ID {
		t.Fatalf("decoded cursor mismatch: got %+v, want %+v", decoded, cur)
	}

	// Test tampering signature
	tampered := tok + "x"
	_, err = DecodeCursor(tampered, secret)
	if err == nil {
		t.Fatal("expected error for tampered cursor token")
	}

	// Test wrong secret
	wrongSecret := []byte("different-secret-key-for-test")
	_, err = DecodeCursor(tok, wrongSecret)
	if err == nil {
		t.Fatal("expected signature mismatch for wrong secret")
	}
}

func TestBuildFindingQuery(t *testing.T) {
	tenantID := uuid.New()
	qStr := "state:open,affected severity:critical scanner:semgrep cve:CVE-2024-* score:>500 -rule:hardcoded-secret"
	q, err := grammar.Parse(qStr)
	if err != nil {
		t.Fatalf("grammar parse error: %v", err)
	}

	sqlStr, args, err := BuildFindingQuery(tenantID, "id, title", &q, "-score", 25, nil)
	if err != nil {
		t.Fatalf("build finding query error: %v", err)
	}

	if !strings.Contains(sqlStr, "tenant_id = $1") {
		t.Errorf("expected tenant_id filter, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "state = $") {
		t.Errorf("expected state filter, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "severity = $") {
		t.Errorf("expected severity filter, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "rule_scanner_family = $") {
		t.Errorf("expected scanner filter, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "vulnerability_id ILIKE $") {
		t.Errorf("expected cve prefix filter, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "risk_score > $") {
		t.Errorf("expected risk_score filter, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "NOT (rule_id = $") {
		t.Errorf("expected negated rule filter, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "ORDER BY risk_score DESC, id DESC") {
		t.Errorf("expected order by clause, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "LIMIT 26") {
		t.Errorf("expected LIMIT 26, got: %s", sqlStr)
	}
	if len(args) == 0 {
		t.Errorf("expected non-empty args")
	}
}

func TestBuildFindingQueryWithCursor(t *testing.T) {
	tenantID := uuid.New()
	targetID := uuid.New().String()
	cur := &Cursor{
		SortKey: "-score",
		SortVal: "750",
		ID:      targetID,
	}

	sqlStr, args, err := BuildFindingQuery(tenantID, "id", nil, "-score", 10, cur)
	if err != nil {
		t.Fatalf("build query with cursor failed: %v", err)
	}

	if !strings.Contains(sqlStr, "risk_score < $") || !strings.Contains(sqlStr, "id < $") {
		t.Errorf("expected keyset cursor clause in sql, got: %s", sqlStr)
	}
	if len(args) < 3 {
		t.Errorf("expected at least 3 args for cursor query, got %d", len(args))
	}
}

func TestBuildCountQuery(t *testing.T) {
	tenantID := uuid.New()
	q, _ := grammar.Parse("severity:high")
	sqlStr, args := BuildCountQuery(tenantID, &q)

	if !strings.HasPrefix(sqlStr, "SELECT COUNT(*)") {
		t.Errorf("expected count query, got: %s", sqlStr)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args, got %d", len(args))
	}
}

func TestDurationParsing(t *testing.T) {
	d1, err := parseDurationStr("30d")
	if err != nil || d1 != 30*24*time.Hour {
		t.Errorf("expected 30 days, got %v (%v)", d1, err)
	}
	d2, err := parseDurationStr("2w")
	if err != nil || d2 != 14*24*time.Hour {
		t.Errorf("expected 14 days, got %v (%v)", d2, err)
	}
}
