package query_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

type pushStore struct {
	*ingest.MemoryStore
	mirror *domain.FeedMirrorSpec
	staged map[string]string
}

func (p *pushStore) GetClusterFeedMirror(context.Context) (*domain.FeedMirrorSpec, error) {
	return p.mirror, nil
}
func (p *pushStore) StageFeedPush(_ context.Context, feed string, body []byte, _ string, _ int) error {
	p.staged[feed] = string(body)
	return nil
}

// D94: a feed plugin pushes its file with its feed's token; a wrong token and an unknown feed look the same, and a
// file with one bad line is refused whole, with nothing kept.
func TestFeedPush(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &pushStore{MemoryStore: ingest.NewMemoryStore(), staged: map[string]string{},
		mirror: &domain.FeedMirrorSpec{Custom: []domain.CustomFeed{{Name: "vulndb", Format: domain.CustomFeedIntelJSONL, PushTokenFile: tok}}}}
	api := query.NewAPIWithAuth(st, nil, auth.NewAuthenticatorWithStore(st))
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	push := func(feed, token, body string) int {
		req := httptest.NewRequest("POST", "/api/v1/feeds/"+feed, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	good := `{"id":"CVE-2024-3094","exploited":true,"maturity":"weaponized","reportedAt":"2024-03-29","evidence":"vendor"}` + "\n"
	if c := push("vulndb", "wrong", good); c != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", c)
	}
	if c := push("nosuch", "s3cret", good); c != http.StatusUnauthorized {
		t.Fatalf("unknown feed: %d", c)
	}
	if c := push("vulndb", "s3cret", good+`{"id":"not-a-cve"}`+"\n"); c != http.StatusUnprocessableEntity || len(st.staged) != 0 {
		t.Fatalf("a bad line refuses the whole file: %d %v", c, st.staged)
	}
	if c := push("vulndb", "s3cret", good); c != http.StatusAccepted || st.staged["vulndb"] != good {
		t.Fatalf("a good file is staged: %d", c)
	}
}
