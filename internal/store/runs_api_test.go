package store_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"rampart/internal/domain"
	"rampart/internal/query"
)

func (h *uploadHarness) runsPage(cursor string, limit int) (int, query.ListRunsResponse) {
	h.t.Helper()
	path := "/api/v1/runs?limit=" + itoaT(limit)
	if cursor != "" {
		path += "&cursor=" + cursor
	}
	code, body := h.call("GET", path, nil, nil)
	var out query.ListRunsResponse
	_ = json.Unmarshal(body, &out)
	return code, out
}

func itoaT(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestRunsAPI_ListAndDetail(t *testing.T) {
	h := newUploadHarness(t)
	repo := "github.com/acme/up-test"
	var ids []string
	for i, branch := range []string{"main", "pr/1", "main", "release/1", "pr/2"} {
		rep := miniSARIF(map[string]string{"rule." + string(rune('a'+i)): "7.5"})
		ids = append(ids, h.uploadAndComplete(rep, domain.UploadContext{Repository: repo, Branch: branch, Commit: "c" + itoaT(i)}))
		h.waitRun(ids[i])
	}

	// Walk the pages: every run once, newest first, with a signed cursor.
	seen := map[string]bool{}
	cursor, pages := "", 0
	var prev string
	for {
		code, p := h.runsPage(cursor, 2)
		if code != http.StatusOK {
			t.Fatalf("page %d: %d", pages, code)
		}
		for _, r := range p.Items {
			if seen[r.ID.String()] {
				t.Fatalf("run %s on two pages", r.ID)
			}
			seen[r.ID.String()] = true
			if prev != "" && r.CreatedAt.After(mustTime(t, prev)) {
				t.Fatal("runs are not newest first")
			}
			prev = r.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00")
		}
		pages++
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
		if pages > 5 {
			t.Fatal("pagination does not end")
		}
	}
	if len(seen) != 5 || pages != 3 {
		t.Fatalf("walked %d runs in %d pages, want 5 in 3", len(seen), pages)
	}

	// A tampered cursor is refused, never ignored.
	_, first := h.runsPage("", 2)
	if code, _ := h.runsPage(first.NextCursor[:len(first.NextCursor)-2]+"00", 2); code != http.StatusBadRequest {
		t.Fatalf("tampered cursor: want 400, got %d", code)
	}

	// Detail: the tools in the report, the context, and whether the run was ephemeral.
	code, body := h.call("GET", "/api/v1/runs/"+ids[1], nil, nil)
	var pr query.RunView
	_ = json.Unmarshal(body, &pr)
	if code != http.StatusOK || !pr.Ephemeral || pr.Context.Branch != "pr/1" || pr.Context.Commit != "c1" || len(pr.Scanners) != 1 || pr.Scanners[0] != "semgrep" {
		t.Fatalf("pull-request run: %d %+v", code, pr)
	}
	_, body = h.call("GET", "/api/v1/runs/"+ids[0], nil, nil)
	var tracked query.RunView
	_ = json.Unmarshal(body, &tracked)
	if tracked.Ephemeral || tracked.Stats.Created != 1 {
		t.Fatalf("tracked run: ephemeral %v stats %+v", tracked.Ephemeral, tracked.Stats)
	}
	if code, _ := h.call("GET", "/api/v1/runs/not-a-uuid", nil, nil); code != http.StatusNotFound {
		t.Fatalf("bad id: want 404, got %d", code)
	}

	// Another tenant sees none of them, and cannot read one by id.
	other := newUploadHarness(t)
	if _, p := other.runsPage("", 50); len(p.Items) != 0 {
		t.Fatalf("SECURITY VIOLATION: another tenant lists %d runs", len(p.Items))
	}
	if code, _ := other.call("GET", "/api/v1/runs/"+ids[0], nil, nil); code != http.StatusNotFound {
		t.Fatalf("SECURITY VIOLATION: another tenant read a run: %d", code)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}
