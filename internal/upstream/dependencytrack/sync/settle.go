package sync

import (
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

// CheckSettled waits until Dependency-Track has analysed the project's latest BOM, then reads its findings once
// (docs/23 DT1, D84). Settled means project.lastVulnerabilityAnalysis >= project.lastBomImport: Dependency-Track
// sets the first at the end of every analysis, including the one a BOM upload starts, and sends BOM_PROCESSED
// before that analysis runs. A project with no BOM import is settled. When the bound is reached the findings are
// read anyway and settled is false; the caller marks the run and the mass-close guard still applies.
//
// This replaces two earlier signals: ProjectMetrics.lastOccurrence, which Dependency-Track updates only for
// periodic analysis, and two identical reads, which are also identical before an analysis has started.
//
// The returned count is Dependency-Track's X-Total-Count (-1 when absent), for the caller to check what it parsed.
func (s *SettleChecker) CheckSettled(ctx context.Context, projectUUID string, _ int64) (bool, []byte, int, error) {
	return s.check(ctx, projectUUID, true)
}

func (s *SettleChecker) check(ctx context.Context, projectUUID string, includeSuppressed bool) (bool, []byte, int, error) {
	deadline := time.Now().Add(s.maxWait)
	for {
		proj, err := s.client.GetProject(ctx, projectUUID)
		if err != nil {
			return false, nil, 0, err
		}
		if proj.LastBomImport == 0 || proj.LastVulnerabilityAnalysis >= proj.LastBomImport {
			findings, total, err := s.client.GetFindingsCounted(ctx, projectUUID, includeSuppressed)
			return err == nil, findings, total, err
		}
		if time.Now().After(deadline) {
			return false, nil, 0, nil // the caller decides: wait more, or read anyway once the bound has passed
		}
		select {
		case <-ctx.Done():
			return false, nil, 0, ctx.Err()
		case <-time.After(s.backoff):
		}
	}
}

// ReadAnyway reads the findings of a project that has not settled, once the bound has passed (docs/23 DT1).
func (s *SettleChecker) ReadAnyway(ctx context.Context, projectUUID string, includeSuppressed bool) ([]byte, int, error) {
	return s.client.GetFindingsCounted(ctx, projectUUID, includeSuppressed)
}
