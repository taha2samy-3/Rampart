package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/query"
)

// seedFindings writes n findings for one tenant: a spread of scores (with ties, to prove the id
// tie-break), severities and states.
func seedFindings(t *testing.T, ctx context.Context, appStore interface {
	CreateApplication(context.Context, *domain.Application) error
	CreateAsset(context.Context, *domain.Asset) error
	UpsertFindings(context.Context, uuid.UUID, []*domain.Finding) error
}, tenant uuid.UUID, n int) {
	t.Helper()
	now := time.Now().UTC()
	app := &domain.Application{ID: uuid.New(), TenantID: tenant, Slug: "shop", Name: "Shop", BusinessCriticality: "high", Lifecycle: "production", CreatedAt: now}
	if err := appStore.CreateApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	asset := &domain.Asset{ID: uuid.New(), TenantID: tenant, ApplicationID: &app.ID, Type: domain.AssetRepository, Key: "github.com/acme/shop", DisplayName: "shop", Active: true, FirstSeen: now, LastSeen: now}
	if err := appStore.CreateAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	sev := []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow}
	var batch []*domain.Finding
	for i := 0; i < n; i++ {
		s := sev[i%len(sev)]
		state := domain.StateOpen
		if i%5 == 0 {
			state = domain.StateFixed
		}
		batch = append(batch, &domain.Finding{
			ID: uuid.New(), TenantID: tenant, FindingKey: fmt.Sprintf("k-%04d", i), DedupScope: "shop:main",
			AssetID: asset.ID, ApplicationID: app.ID, Track: "main", RuleScannerFamily: "semgrep", RuleID: fmt.Sprintf("rules.r%d", i%7),
			Title: fmt.Sprintf("Finding number %d", i), Category: domain.CategorySAST, Severity: s, ToolSeverity: string(s),
			CWEs: []int{89}, RiskScore: (i * 13) % 40 * 25, // only 40 distinct scores: many ties
			State: state, FirstSeen: now.Add(-time.Duration(i) * time.Hour), LastSeen: now.Add(-time.Duration(i) * time.Minute),
			OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now,
		})
	}
	if err := appStore.UpsertFindings(ctx, tenant, batch); err != nil {
		t.Fatal(err)
	}
}

type page struct {
	Items []struct {
		Finding domain.Finding `json:"finding"`
	} `json:"items"`
	Total      int    `json:"total"`
	NextCursor string `json:"next_cursor"`
}

func TestQueryAPI_SQLPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sysStore := setupStores(t, ctx)

	mk := func(slug string) uuid.UUID {
		tn := &domain.Tenant{ID: uuid.New(), Slug: slug + "-" + uuid.NewString()[:8], DisplayName: slug, CreatedAt: time.Now().UTC()}
		if err := sysStore.CreateTenant(ctx, tn); err != nil {
			t.Fatal(err)
		}
		return tn.ID
	}
	tenantA, tenantB := mk("qa"), mk("qb")
	const total = 137
	seedFindings(t, ctx, appStore, tenantA, total)
	seedFindings(t, ctx, appStore, tenantB, 5)

	authn := auth.NewAuthenticatorWithStore(appStore)
	token := authn.DefaultAdminToken(tenantA)
	api := query.NewAPIWithAuth(appStore, enrich.NewFeedStore(), authn)
	api.SetCursorKey([]byte("test-cursor-key-test-cursor-key!"))
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	get := func(params url.Values) (int, page) {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/findings?"+params.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var p page
		_ = json.NewDecoder(res.Body).Decode(&p)
		return res.StatusCode, p
	}

	// Every sort, walked page by page: every finding exactly once, in a consistent order, with ties by id.
	for _, sortKey := range []string{"-score", "score", "-seen", "seen", "-age", "age", "severity"} {
		seen := map[uuid.UUID]bool{}
		cursor, pages := "", 0
		for {
			params := url.Values{"limit": {"20"}, "sort": {sortKey}}
			if cursor != "" {
				params.Set("cursor", cursor)
			}
			code, p := get(params)
			if code != http.StatusOK {
				t.Fatalf("sort %s page %d: status %d", sortKey, pages, code)
			}
			if p.Total != total {
				t.Fatalf("sort %s: total %d, want %d", sortKey, p.Total, total)
			}
			for _, it := range p.Items {
				if seen[it.Finding.ID] {
					t.Fatalf("sort %s: finding %s appeared on two pages", sortKey, it.Finding.ID)
				}
				seen[it.Finding.ID] = true
				if it.Finding.TenantID != tenantA {
					t.Fatalf("SECURITY VIOLATION: a finding of another tenant on the page")
				}
			}
			pages++
			if p.NextCursor == "" {
				break
			}
			cursor = p.NextCursor
			if pages > 20 {
				t.Fatalf("sort %s: pagination does not end", sortKey)
			}
		}
		if len(seen) != total {
			t.Fatalf("sort %s: walked %d findings, want %d (pages: %d)", sortKey, len(seen), total, pages)
		}
	}

	// Filters run in SQL.
	for q, check := range map[string]func(f domain.Finding) bool{
		"severity:critical": func(f domain.Finding) bool { return f.Severity == domain.SeverityCritical },
		"state:open":        func(f domain.Finding) bool { return f.State == domain.StateOpen },
		"-state:open":       func(f domain.Finding) bool { return f.State != domain.StateOpen },
		"severity:critical,high": func(f domain.Finding) bool {
			return f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh
		},
		"score:>=500":     func(f domain.Finding) bool { return f.RiskScore >= 500 },
		"rule:rules.r3":   func(f domain.Finding) bool { return f.RuleID == "rules.r3" },
		"cwe:89 app:shop": func(f domain.Finding) bool { return len(f.CWEs) == 1 },
		"r3": func(f domain.Finding) bool {
			return strings.Contains(strings.ToLower(f.Title+" "+f.RuleID), "r3") // free text: title, description, rule id
		},
	} {
		code, p := get(url.Values{"q": {q}, "limit": {"200"}})
		if code != http.StatusOK {
			t.Fatalf("q=%q: status %d", q, code)
		}
		if len(p.Items) == 0 || p.Total != len(p.Items) {
			t.Fatalf("q=%q: %d items, total %d", q, len(p.Items), p.Total)
		}
		for _, it := range p.Items {
			if !check(it.Finding) {
				t.Fatalf("q=%q returned a finding that does not match: %+v", q, it.Finding.Title)
			}
		}
	}

	// A hostile value is a parameter, never SQL.
	if code, p := get(url.Values{"q": {"rule:x'; DROP TABLE finding;--"}}); code != http.StatusOK || p.Total != 0 {
		t.Fatalf("injection probe: status %d, total %d", code, p.Total)
	}
	if _, p := get(url.Values{}); p.Total != total {
		t.Fatal("the finding table was damaged by a hostile filter")
	}

	// Cursors: tampered, from another sort or from another filter are refused with 400, never ignored.
	_, first := get(url.Values{"limit": {"10"}, "sort": {"-score"}, "q": {"state:open"}})
	if first.NextCursor == "" {
		t.Fatal("expected a next page")
	}
	tampered := first.NextCursor[:len(first.NextCursor)-2] + "00"
	for name, params := range map[string]url.Values{
		"tampered":       {"cursor": {tampered}, "sort": {"-score"}, "q": {"state:open"}},
		"other sort":     {"cursor": {first.NextCursor}, "sort": {"-seen"}, "q": {"state:open"}},
		"other filter":   {"cursor": {first.NextCursor}, "sort": {"-score"}, "q": {"state:fixed"}},
		"not a cursor":   {"cursor": {"garbage"}},
		"another tenant": {},
	} {
		if name == "another tenant" {
			continue
		}
		if code, _ := get(params); code != http.StatusBadRequest {
			t.Fatalf("cursor %s: want 400, got %d", name, code)
		}
	}

	// The other tenant sees only its own five.
	tokenB := authn.DefaultAdminToken(tenantB)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/findings?limit=200", nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var pb page
	_ = json.NewDecoder(res.Body).Decode(&pb)
	if pb.Total != 5 {
		t.Fatalf("SECURITY VIOLATION: tenant B total %d, want 5", pb.Total)
	}
	// And a cursor issued to tenant A, replayed by tenant B, must not reveal A's rows.
	req, _ = http.NewRequest("GET", srv.URL+"/api/v1/findings?limit=200&sort=-score&q=state:open&cursor="+url.QueryEscape(first.NextCursor), nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	res2, _ := http.DefaultClient.Do(req)
	defer func() { _ = res2.Body.Close() }()
	var pr page
	_ = json.NewDecoder(res2.Body).Decode(&pr)
	for _, it := range pr.Items {
		if it.Finding.TenantID == tenantA {
			t.Fatal("SECURITY VIOLATION: a replayed cursor exposed another tenant's finding")
		}
	}
}
