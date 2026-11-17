package domain

import "time"

// FeedState records the synchronization status of an external threat intelligence feed.
type FeedState struct {
	Feed     string     `json:"feed"`
	Cursor   *string    `json:"cursor,omitempty"`
	LastSync *time.Time `json:"last_sync,omitempty"`
	Records  int64      `json:"records"`
	Status   string     `json:"status"` // idle | syncing | success | error
	Error    *string    `json:"error,omitempty"`
}
