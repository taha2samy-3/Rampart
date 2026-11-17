package query_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"
	"rampart/internal/store"

	"github.com/google/uuid"
)

type changeStore struct {
	*ingest.MemoryStore
	got struct{ from, to time.Time }
	res store.ApplicationChanges
}

func (s *changeStore) ApplicationChanges(_ context.Context, _, _ uuid.UUID, from, to time.Time) (*store.ApplicationChanges, error) {
	s.got.from, s.got.to = from, to
	r := s.res
	return &r, nil
}

func TestAPI_ApplicationChanges(t *testing.T) {
	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	mem := ingest.NewMemoryStore()
	appID := domain.NewID()
	if err := mem.CreateApplication(context.Background(), &domain.Application{ID: appID, TenantID: tenantID, Slug: "shop", Name: "Shop"}); err != nil {
		t.Fatal(err)
	}
	cs := &changeStore{MemoryStore: mem, res: store.ApplicationChanges{
		Counts: store.ChangeCounts{New: 3, Closed: 2, Reopened: 1, OpenAtStart: 10, OpenAtEnd: 11}, Previous: store.ChangeCounts{New: 5, Closed: 4},
		Days: []store.ChangeDay{{Day: "2026-11-11", New: 3}}, New: []store.FindingChange{{RuleID: "CVE-1"}}, NewMore: true,
	}}
	authn := auth.NewAuthenticatorWithStore(mem)
	token := authn.DefaultAdminToken(tenantID)
	mux := http.NewServeMux()
	query.NewAPIWithAuth(cs, nil, authn).RegisterRoutes(mux)
	get := func(q string, tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/applications/"+appID.String()+"/changes"+q, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	rec := get("?from=2026-10-11&to=2026-10-20", token)
	var out query.ApplicationChangesResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// Both days are included: the instant range is [Nov 11 00:00, Nov 21 00:00).
	if !cs.got.from.Equal(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)) || !cs.got.to.Equal(time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("range given to the store: %v to %v", cs.got.from, cs.got.to)
	}
	if out.Days != 10 || out.From != "2026-10-11" || out.To != "2026-10-20" || out.Summary.New != 3 || out.Summary.OpenAtEnd != 11 {
		t.Errorf("answer: %+v", out)
	}
	// The range before it has the same length and ends the day before.
	if p := out.Summary.Previous; p.From != "2026-10-01" || p.To != "2026-10-10" || p.New != 5 || p.Closed != 4 {
		t.Errorf("the previous range: %+v", p)
	}
	if len(out.Truncated) != 1 || out.Truncated[0] != "new" {
		t.Errorf("a cut list is named: %v", out.Truncated)
	}
	if out.Reopened == nil || out.Closed == nil || out.Open == nil || out.Daily == nil {
		t.Error("a list is [] and never null")
	}

	// Defaults: the last 30 days ending today. A future end is cut to today.
	rec = get("", token)
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Days != 30 || out.To != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("default range: %d %+v", rec.Code, out)
	}
	rec = get("?to=2099-01-01&from="+time.Now().UTC().AddDate(0, 0, -4).Format("2006-01-02"), token)
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Days != 5 || out.To != time.Now().UTC().Format("2006-01-02") {
		t.Errorf("a day that has not come is cut: %d %+v", rec.Code, out)
	}

	for name, q := range map[string]string{
		"to before from":   "?from=2026-11-20&to=2026-11-11",
		"not a day":        "?from=yesterday",
		"to not a day":     "?to=2026-13-45",
		"over a year":      "?from=2025-01-01&to=2026-11-01",
		"starts in future": "?from=2099-01-01&to=2099-02-01",
	} {
		if rec := get(q, token); rec.Code != http.StatusBadRequest {
			t.Errorf("%s (%s): want 400, got %d", name, q, rec.Code)
		}
	}
	if rec := get("", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", rec.Code)
	}
	// An application that is not there, an id that is not one, a store with no history.
	for url, want := range map[string]int{
		"/api/v1/applications/" + uuid.NewString() + "/changes": 404,
		"/api/v1/applications/nope/changes":                     400,
	} {
		req := httptest.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: want %d, got %d", url, want, rec.Code)
		}
	}
	mux2 := http.NewServeMux()
	query.NewAPIWithAuth(mem, nil, authn).RegisterRoutes(mux2)
	req := httptest.NewRequest("GET", "/api/v1/applications/"+appID.String()+"/changes", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotImplemented {
		t.Errorf("a store without history: want 501, got %d", rec2.Code)
	}
}
