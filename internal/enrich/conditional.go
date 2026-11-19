package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// conditional is what a feed remembers of its last download so the next one can ask "has it changed?" (RFC 9110
// section 13). It is kept in feed_state.cursor as JSON, with the URL it came from: a changed mirror address must not
// be answered "not modified" by the cache of another server.
type conditional struct {
	URL          string `json:"url"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

func (c conditional) usable() bool { return c.ETag != "" || c.LastModified != "" }

// getIfChanged downloads url unless the server says it is the same as prev (304). It returns the validators of the
// answer, to be stored once the body has been applied. A server that sends neither ETag nor Last-Modified is
// downloaded every time, as before.
func (c *FeedConfig) getIfChanged(ctx context.Context, url string, max int64, prev *conditional) (body io.ReadCloser, next conditional, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, conditional{}, false, err
	}
	req.Header.Set("User-Agent", "rampart-feed-sync")
	if prev != nil && prev.URL == url {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, conditional{}, false, err
	}
	switch {
	case res.StatusCode == http.StatusNotModified && prev != nil && prev.URL == url && prev.usable():
		_ = res.Body.Close()
		return nil, *prev, true, nil
	case res.StatusCode != http.StatusOK:
		_ = res.Body.Close()
		return nil, conditional{}, false, fmt.Errorf("GET %s: status %d", redact(url), res.StatusCode)
	}
	if res.ContentLength > max {
		_ = res.Body.Close()
		return nil, conditional{}, false, fmt.Errorf("GET %s: %d bytes exceeds the %d byte limit", redact(url), res.ContentLength, max)
	}
	next = conditional{URL: url, ETag: res.Header.Get("ETag"), LastModified: res.Header.Get("Last-Modified")}
	return &limitedBody{Reader: io.LimitReader(res.Body, max+1), c: res.Body, max: max}, next, false, nil
}

// loadConditional reads what the feed remembered, or nil.
func (s *FeedSyncer) loadConditional(ctx context.Context, feed string) *conditional {
	st, err := s.GetFeedState(ctx, feed)
	if err != nil || st == nil || st.Cursor == nil || st.Status != "success" {
		return nil
	}
	var c conditional
	if json.Unmarshal([]byte(*st.Cursor), &c) != nil || !c.usable() {
		return nil
	}
	return &c
}

// saveConditional stores the validators of a download that was applied.
func (s *FeedSyncer) saveConditional(ctx context.Context, feed string, c conditional) error {
	if !c.usable() {
		return s.saveCursor(ctx, feed, nil)
	}
	b, _ := json.Marshal(c)
	cur := string(b)
	return s.saveCursor(ctx, feed, &cur)
}

// saveCursor stores what a feed needs to resume (validators, a high-water mark). It creates the row of a feed that has
// not recorded a result yet; the status of the row is the business of recordFeedSuccess and recordFeedError.
func (s *FeedSyncer) saveCursor(ctx context.Context, feed string, cursor *string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO feed_state (feed, cursor) VALUES ($1, $2)
		ON CONFLICT (feed) DO UPDATE SET cursor = EXCLUDED.cursor`, feed, cursor)
	return err
}

// recordNotModified marks a check that found nothing new: the feed is up to date as of now, with the records it had.
func (s *FeedSyncer) recordNotModified(ctx context.Context, feed string) error {
	var records int64
	err := s.pool.QueryRow(ctx, `UPDATE feed_state SET last_sync = NOW(), status = 'success', error = NULL WHERE feed = $1 RETURNING records`, feed).Scan(&records)
	if err != nil {
		return fmt.Errorf("enrich: recording an unchanged feed: %w", err)
	}
	s.note(FeedResult{Feed: feed, Records: records, NotModified: true})
	return nil
}
