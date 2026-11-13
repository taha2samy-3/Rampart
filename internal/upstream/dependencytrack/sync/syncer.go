package sync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/normalize"
	"rampart/internal/parsers/dependencytrack"
	"rampart/internal/store"
	dtclient "rampart/internal/upstream/dependencytrack/client"
)

// Store defines the database operations needed by the Syncer.
type Store interface {
	store.DTrackStore
	LookupAsset(ctx context.Context, tenantID uuid.UUID, assetType domain.AssetType, key string) (*domain.Asset, error)
	CreateAsset(ctx context.Context, asset *domain.Asset) error
	GetScanSourceIngestionPolicy(ctx context.Context, tenantID, sourceID uuid.UUID) (*domain.IngestionPolicy, error)
}

// MergeEngine abstracts the finding merge and closure operations.
type MergeEngine interface {
	MergeBatchWithOptions(ctx context.Context, scope ingest.CloseScope, runID, appID uuid.UUID, records []ingest.StagedRecord, opts ingest.MergeOptions) (ingest.MergeOutcome, error)
	CloseScopeStepWithGuard(ctx context.Context, scope ingest.CloseScope, currentRunID uuid.UUID, guardPolicy *domain.IngestionPolicy) (int, error)
}

// Syncer orchestrates project sync (Flow B/C) and portfolio reconciliation (Flow C) (docs/10 §2, docs/21 §4.5).
type Syncer struct {
	client  *dtclient.Client
	store   Store
	engine  MergeEngine
	mapping *MappingEngine
	settle  *SettleChecker
	parser  *dependencytrack.Parser
	logger  *slog.Logger
}

// NewSyncer creates a new Syncer.
func NewSyncer(client *dtclient.Client, st Store, engine MergeEngine, mapping *MappingEngine) *Syncer {
	return &Syncer{
		client:  client,
		store:   st,
		engine:  engine,
		mapping: mapping,
		settle:  NewSettleChecker(client, 1*time.Second, 10*time.Second),
		parser:  dependencytrack.NewParser(),
		logger:  slog.Default().With("component", "dtrack_syncer"),
	}
}

// SetSettleChecker overrides the SettleChecker (e.g. for testing).
func (s *Syncer) SetSettleChecker(sc *SettleChecker) {
	s.settle = sc
}

// SyncProject executes a single project sync run.
func (s *Syncer) SyncProject(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string) error {
	proj, err := s.client.GetProject(ctx, projectUUID)
	if errors.Is(err, dtclient.ErrNotFound) {
		s.logger.Warn("dependency-track project not found", "project", projectUUID)
		_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, nil)
		return nil
	}
	if err != nil {
		s.logger.Error("failed fetching project details", "project", projectUUID, "error", err)
		_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, err)
		return err
	}

	props, _ := s.client.GetProjectProperties(ctx, projectUUID)
	res := s.mapping.Resolve(ctx, tenantID, *proj, props)

	var lastBom *time.Time
	if proj.LastBomImport > 0 {
		t := time.UnixMilli(proj.LastBomImport).UTC()
		lastBom = &t
	}

	projRecord := domain.DTrackProjectRecord{
		TenantID:       tenantID,
		SourceID:       sourceID,
		ProjectUUID:    projectUUID,
		Name:           proj.Name,
		Version:        proj.Version,
		Purl:           proj.Purl,
		Active:         proj.Active,
		LastBomImport:  lastBom,
		ApplicationID:  res.ApplicationID,
		MappingRule:    res.MatchedRule,
		UnmappedReason: res.UnmappedReason,
	}

	if err := s.store.UpsertDTrackProject(ctx, projRecord); err != nil {
		s.logger.Error("failed upserting dtrack project record", "project", projectUUID, "error", err)
	}

	if res.ApplicationID == nil {
		// Project is unmapped: record reason, skip finding merge (docs/21 §4.5)
		s.logger.Info("project is unmapped, skipping finding ingestion", "project", proj.Name, "reason", res.UnmappedReason)
		hasTrailing, cErr := s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, nil)
		if hasTrailing {
			go func() { _ = s.SyncProject(context.Background(), tenantID, sourceID, projectUUID) }()
		}
		return cErr
	}

	// 1. Ensure Asset exists for mapped project
	assetKey := fmt.Sprintf("dtrack://%s/%s", sourceID, projectUUID)
	asset, err := s.store.LookupAsset(ctx, tenantID, domain.AssetSBOMProject, assetKey)
	if errors.Is(err, store.ErrNotFound) {
		asset = &domain.Asset{
			ID:            domain.NewID(),
			TenantID:      tenantID,
			ApplicationID: res.ApplicationID,
			Type:          domain.AssetSBOMProject,
			Key:           assetKey,
			DisplayName:   fmt.Sprintf("%s@%s", proj.Name, proj.Version),
			Active:        proj.Active,
			FirstSeen:     time.Now().UTC(),
			LastSeen:      time.Now().UTC(),
		}
		if crErr := s.store.CreateAsset(ctx, asset); crErr != nil {
			s.logger.Error("failed creating asset for project", "key", assetKey, "error", crErr)
			_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, crErr)
			return crErr
		}
	} else if err != nil {
		s.logger.Error("failed looking up asset", "key", assetKey, "error", err)
		_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, err)
		return err
	}

	// 2. Settled Analysis: verify analysis is complete or settled (docs/21 §4.4)
	settled, findingsBytes, settleErr := s.settle.CheckSettled(ctx, projectUUID, proj.LastBomImport)
	if settleErr != nil {
		s.logger.Error("settled analysis check failed", "project", projectUUID, "error", settleErr)
		_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, settleErr)
		return settleErr
	}
	if !settled {
		s.logger.Warn("project analysis did not settle within bound, proceeding with partial read", "project", projectUUID)
	}

	// 3. Parse findings via streaming parser
	var staged []ingest.StagedRecord
	now := time.Now().UTC()
	for raw, parseErr := range s.parser.Parse(ctx, bytes.NewReader(findingsBytes), domain.ParseContext{}) {
		if parseErr != nil {
			s.logger.Warn("error parsing dtrack finding record", "project", projectUUID, "error", parseErr)
			continue
		}

		fp := normalize.ComputeFingerprint(normalize.FingerprintParams{
			TenantID:      tenantID,
			AssetID:       asset.ID,
			ApplicationID: *res.ApplicationID,
			Track:         "main",
			Scope:         normalize.ScopeAsset,
			Family:        "dependency-track",
			Category:      raw.Category,
			RuleID:        raw.RuleID,
			RawFinding:    raw,
		})

		staged = append(staged, ingest.StagedRecord{
			ScannerFamily: "dependency-track",
			FindingKey:    fp.FindingKey,
			LineageKey:    fp.LineageKey,
			Category:      raw.Category,
			RuleID:        raw.RuleID,
			Title:         raw.Title,
			Description:   raw.Description,
			ToolSeverity:  raw.ToolSeverity,
			Severity:      raw.Severity,
			Location:      raw.Location,
			CWEs:          raw.CWEs,
			VulnID:        raw.RuleID,
			CVSSVector:    raw.CVSSVector,
			ContentHash:   normalize.ComputeContentHash(raw.Title, raw.Description, raw.ToolSeverity, raw.CVSSVector, "", raw.Location.PrimaryPath()),
			SeenAt:        now,
			RawPayload:    raw.RawPayload,
		})
	}

	// 4. Batch merge and scope closure
	runID := domain.NewID()
	scope := ingest.CloseScope{
		TenantID:      tenantID,
		ScanSourceID:  sourceID,
		ScannerFamily: "dependency-track",
		AssetID:       asset.ID,
		Track:         "main",
	}

	policy, _ := s.store.GetScanSourceIngestionPolicy(ctx, tenantID, sourceID)
	if s.engine != nil && len(staged) > 0 {
		if _, mErr := s.engine.MergeBatchWithOptions(ctx, scope, runID, *res.ApplicationID, staged, ingest.MergeOptions{FieldMerge: "scanner"}); mErr != nil {
			s.logger.Error("failed merging dtrack findings batch", "error", mErr)
			_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, mErr)
			return mErr
		}
	}

	// 5. Mass-close guard and absent finding closure
	if s.engine != nil {
		if _, cErr := s.engine.CloseScopeStepWithGuard(ctx, scope, runID, policy); cErr != nil {
			s.logger.Error("failed closing scope findings", "error", cErr)
			_, _ = s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, cErr)
			return cErr
		}
	}

	// 6. Complete sync and re-trigger if dirty
	hasTrailing, cErr := s.store.CompleteDTrackSync(ctx, tenantID, projectUUID, nil)
	if hasTrailing {
		go func() { _ = s.SyncProject(context.Background(), tenantID, sourceID, projectUUID) }()
	}
	return cErr
}

// SyncPortfolio pages through projects in Dependency-Track and synchronizes portfolio mapping (docs/10 §2 Flow C).
func (s *Syncer) SyncPortfolio(ctx context.Context, tenantID, sourceID uuid.UUID) error {
	page := 1
	pageSize := 100
	for {
		projects, total, err := s.client.ListProjects(ctx, page, pageSize, true)
		if err != nil {
			return fmt.Errorf("listing projects on page %d: %w", page, err)
		}
		if len(projects) == 0 {
			break
		}

		for _, proj := range projects {
			props, _ := s.client.GetProjectProperties(ctx, proj.UUID)
			res := s.mapping.Resolve(ctx, tenantID, proj, props)

			var lastBom *time.Time
			if proj.LastBomImport > 0 {
				t := time.UnixMilli(proj.LastBomImport).UTC()
				lastBom = &t
			}

			_ = s.store.UpsertDTrackProject(ctx, domain.DTrackProjectRecord{
				TenantID:       tenantID,
				SourceID:       sourceID,
				ProjectUUID:    proj.UUID,
				Name:           proj.Name,
				Version:        proj.Version,
				Purl:           proj.Purl,
				Active:         proj.Active,
				LastBomImport:  lastBom,
				ApplicationID:  res.ApplicationID,
				MappingRule:    res.MatchedRule,
				UnmappedReason: res.UnmappedReason,
			})

			if res.ApplicationID != nil {
				shouldStart, err := s.store.EnqueueDTrackSync(ctx, tenantID, sourceID, proj.UUID)
				if err == nil && shouldStart {
					go func(pUUID string) {
						_ = s.SyncProject(context.Background(), tenantID, sourceID, pUUID)
					}(proj.UUID)
				}
			}
		}

		if page*pageSize >= total {
			break
		}
		page++
	}
	return nil
}
