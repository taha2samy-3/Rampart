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
func (s *SettleChecker) CheckSettled(ctx context.Context, projectUUID string, _ int64) (bool, []byte, error) {
	deadline := time.Now().Add(s.maxWait)
	for {
		proj, err := s.client.GetProject(ctx, projectUUID)
		if err != nil {
			return false, nil, err
		}
		if proj.LastBomImport == 0 || proj.LastVulnerabilityAnalysis >= proj.LastBomImport {
			findings, err := s.client.GetFindings(ctx, projectUUID, true)
			return err == nil, findings, err
		}
		if time.Now().After(deadline) {
			findings, err := s.client.GetFindings(ctx, projectUUID, true)
			return false, findings, err
		}
		select {
		case <-ctx.Done():
			return false, nil, ctx.Err()
		case <-time.After(s.backoff):
		}
	}
}
