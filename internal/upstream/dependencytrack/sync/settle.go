package sync

import (
	"bytes"
	"context"
	"time"

	dtclient "rampart/internal/upstream/dependencytrack/client"
)

// SettleChecker verifies whether vulnerability analysis on a project has settled before pulling findings (docs/21 §4.4).
type SettleChecker struct {
	client  *dtclient.Client
	backoff time.Duration
	maxWait time.Duration
}

// NewSettleChecker creates a SettleChecker.
func NewSettleChecker(client *dtclient.Client, backoff, maxWait time.Duration) *SettleChecker {
	if backoff <= 0 {
		backoff = 1 * time.Second
	}
	if maxWait <= 0 {
		maxWait = 10 * time.Second
	}
	return &SettleChecker{
		client:  client,
		backoff: backoff,
		maxWait: maxWait,
	}
}

// CheckSettled reads findings twice spaced by backoff. If identical (or metrics lastOccurrence > lastBomImport),
// returns (settled=true, findingsBytes, nil). If timeout reached, returns what was read with (settled=false).
func (s *SettleChecker) CheckSettled(ctx context.Context, projectUUID string, lastBomImport int64) (bool, []byte, error) {
	// 1. Check metrics if available
	if metrics, err := s.client.GetProjectMetrics(ctx, projectUUID); err == nil && metrics != nil {
		if lastBomImport > 0 && metrics.LastOccurrence > lastBomImport {
			// Metrics clearly newer than last BOM import: analysis is complete
			findings, err := s.client.GetFindings(ctx, projectUUID, true)
			return true, findings, err
		}
	}

	// 2. Double-read findings a backoff apart
	firstRead, err := s.client.GetFindings(ctx, projectUUID, true)
	if err != nil {
		return false, nil, err
	}

	deadline := time.Now().Add(s.maxWait)
	for {
		select {
		case <-ctx.Done():
			return false, firstRead, ctx.Err()
		case <-time.After(s.backoff):
		}

		secondRead, err := s.client.GetFindings(ctx, projectUUID, true)
		if err != nil {
			return false, firstRead, err
		}

		if bytes.Equal(firstRead, secondRead) {
			return true, secondRead, nil
		}

		if time.Now().After(deadline) {
			// Time bound reached: return what was read
			return false, secondRead, nil
		}
		firstRead = secondRead
	}
}
