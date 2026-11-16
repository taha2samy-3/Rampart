package query_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query"
)

type fakeLiveSource struct {
	mu   sync.Mutex
	rows []domain.LiveEvent
}

func (f *fakeLiveSource) add(e domain.LiveEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now()
	}
	f.rows = append(f.rows, e)
}

func (f *fakeLiveSource) ListLiveEvents(_ context.Context, after int64, limit int) ([]domain.LiveEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.LiveEvent
	for _, e := range f.rows {
		if e.ID > after && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}
func (f *fakeLiveSource) MaxLiveEventID(context.Context) (int64, error)             { return 0, nil }
func (f *fakeLiveSource) PruneLiveEvents(context.Context, time.Time) (int64, error) { return 0, nil }

type sseReader struct {
	sc *bufio.Scanner
}

// next reads one SSE message (up to the blank line) and returns its event name and id; comments are skipped.
func (r *sseReader) next(t *testing.T) (event, id, data string) {
	t.Helper()
	for r.sc.Scan() {
		line := r.sc.Text()
		switch {
		case line == "":
			if event != "" || data != "" {
				return
			}
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "id: "):
			id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		}
	}
	t.Fatalf("stream ended: %v", r.sc.Err())
	return
}

// D91 (docs/23 S1): one path, the tenant's own events only, coalesced, filtered by topic, capped per caller,
// resumed from Last-Event-ID, and 503 when no hub runs.
func TestLiveStream(t *testing.T) {
	st := newMockGroupViewStore()
	tenantA, tenantB := uuid.New(), uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	token := authn.DefaultAdminToken(tenantA)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	if w := get("/api/v1/stream"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no hub: %d", w.Code)
	}
	if w := get("/api/v1/events"); w.Code == http.StatusOK {
		t.Fatal("the old path is gone: one path name")
	}

	src := &fakeLiveSource{}
	hub := query.NewLiveHub(src, nil)
	api.SetLiveHub(hub)
	if w := get("/api/v1/stream?topics=findings,gossip"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown topic: %d", w.Code)
	}

	srv := httptest.NewServer(mux)
	defer srv.Close()
	open := func(query, lastID string) (*http.Response, *sseReader) {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/stream"+query, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res, &sseReader{bufio.NewScanner(res.Body)}
	}

	res, rd := open("?topics=findings,operations", "")
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	app := uuid.New()
	src.add(domain.LiveEvent{ID: 1, TenantID: tenantA, Topic: "findings", ApplicationID: &app})
	src.add(domain.LiveEvent{ID: 2, TenantID: tenantB, Topic: "findings", ApplicationID: &app}) // another tenant
	src.add(domain.LiveEvent{ID: 3, TenantID: tenantA, Topic: "findings", ApplicationID: &app}) // coalesced with 1
	src.add(domain.LiveEvent{ID: 4, TenantID: tenantA, Topic: "ingests", ApplicationID: &app})  // not subscribed
	src.add(domain.LiveEvent{ID: 5, TenantID: tenantA, Topic: "operations"})
	// The stream subscribes before it writes its first byte, so the hub knows it by now.
	hub.Poll(context.Background(), time.Now())

	ev, id, data := rd.next(t)
	if ev != "findings" || !strings.HasPrefix(id, "3.") || !strings.Contains(data, app.String()) {
		t.Fatalf("one coalesced findings message with the newest id: %q %q %q", ev, id, data)
	}
	ev, id, _ = rd.next(t)
	if ev != "operations" || !strings.HasPrefix(id, "5.") {
		t.Fatalf("then operations, and nothing of tenant B or of ingests: %q %q", ev, id)
	}

	// Resuming: from an id within the retention the missed rows replay (the in-memory store has none, so no
	// message); an id older than the retention gets a reset, so the client refetches instead of trusting a gap.
	res2, rd2 := open("", "3.1")
	defer func() { _ = res2.Body.Close() }()
	if ev, _, _ := rd2.next(t); ev != "reset" {
		t.Fatalf("an expired Last-Event-ID: %q", ev)
	}

	// At most five streams per caller on a replica: two are open, three more fit, the sixth is refused.
	var extra []*http.Response
	for i := 0; i < 3; i++ {
		r, _ := open("", "")
		extra = append(extra, r)
	}
	r6, _ := open("", "")
	if r6.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("sixth stream: %d", r6.StatusCode)
	}
	_ = r6.Body.Close()
	for _, r := range extra {
		_ = r.Body.Close()
	}
}

// Ids are committed out of order: a row below one already seen is still delivered, once.
func TestLiveHubOutOfOrderIDs(t *testing.T) {
	src := &fakeLiveSource{}
	hub := query.NewLiveHub(src, nil)
	tenant := uuid.New()
	ch := query.LiveHubSubscribe(hub, tenant)
	now := time.Now()
	src.add(domain.LiveEvent{ID: 1, TenantID: tenant, Topic: "findings"})
	src.add(domain.LiveEvent{ID: 3, TenantID: tenant, Topic: "findings"})
	hub.Poll(context.Background(), now)
	src.add(domain.LiveEvent{ID: 2, TenantID: tenant, Topic: "findings"}) // committed late
	hub.Poll(context.Background(), now.Add(time.Second))
	var got []int64
	for len(ch) > 0 {
		for _, e := range <-ch {
			got = append(got, e.ID)
		}
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 3 || got[2] != 2 {
		t.Fatalf("ids 1, 3, then 2, each once: %v", got)
	}
	// A hole that never fills (a rolled-back transaction) is skipped after a while.
	src.add(domain.LiveEvent{ID: 5, TenantID: tenant, Topic: "findings"})
	hub.Poll(context.Background(), now.Add(2*time.Second))
	hub.Poll(context.Background(), now.Add(5*time.Minute))
	if c := query.LiveHubCursor(hub); c != 5 {
		t.Fatalf("cursor after the hole is given up: %d", c)
	}
}
