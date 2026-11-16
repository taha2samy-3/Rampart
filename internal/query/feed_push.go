package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"

	"rampart/internal/domain"
	"rampart/internal/enrich"
)

// MaxFeedPushBytes bounds one pushed file. It is staged in one database row; a larger feed is pulled from a URL
// (custom[].url), as an OSV zip is.
const MaxFeedPushBytes = 64 << 20

type feedPushStore interface {
	GetClusterFeedMirror(ctx context.Context) (*domain.FeedMirrorSpec, error)
	StageFeedPush(ctx context.Context, feed string, body []byte, sha string, records int) error
}

// handleFeedPush is POST /api/v1/feeds/{name} (D89, D94): a feed plugin, a container of its own that fetches a
// vulnerability database, posts the result in intel-jsonl. It is not a user: it holds the token of one feed, read
// from the file the ClusterFeedMirror names, and can reach that feed and nothing else. The whole file is checked
// before it is accepted, so the plugin learns at once that it sent a bad file; the feed syncer loads it on its next
// round as the system role (D19). Nothing here writes the intelligence tables.
func (a *API) handleFeedPush(w http.ResponseWriter, r *http.Request) {
	st, ok := a.store.(feedPushStore)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "Feed push needs PostgreSQL")
		return
	}
	name := r.PathValue("name")
	mirror, err := st.GetClusterFeedMirror(r.Context())
	var feed *domain.CustomFeed
	if err == nil && mirror != nil {
		for i := range mirror.Custom {
			if mirror.Custom[i].Name == name && mirror.Custom[i].PushTokenFile != "" {
				feed = &mirror.Custom[i]
			}
		}
	}
	// One answer for "no such push feed" and "wrong token": the endpoint does not tell a caller which feeds exist.
	deny := func() { problem(w, http.StatusUnauthorized, "unauthorized", "Unknown feed or wrong token") }
	if feed == nil {
		deny()
		return
	}
	want, err := readSmallFile(feed.PushTokenFile)
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil || want == "" || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		deny()
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxFeedPushBytes+1))
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "The body could not be read")
		return
	}
	if len(body) > MaxFeedPushBytes {
		problem(w, http.StatusRequestEntityTooLarge, "payload-too-large", "A pushed feed is at most 64 MiB; serve a larger one at a url instead")
		return
	}
	rows, err := enrich.ParseIntelJSONL(bytes.NewReader(body))
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "validation", "Refused, nothing was kept: "+err.Error())
		return
	}
	sum := sha256.Sum256(body)
	if err := st.StageFeedPush(r.Context(), name, body, hex.EncodeToString(sum[:]), len(rows)); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "The file could not be staged")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"feed": name, "records": len(rows), "sha256": hex.EncodeToString(sum[:]),
		"status": "staged; loaded on the next feed sync"})
}

func readSmallFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 8<<10))
	return strings.TrimSpace(string(b)), err
}
