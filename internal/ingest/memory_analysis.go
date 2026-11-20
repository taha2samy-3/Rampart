package ingest

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"rampart/internal/analyzer/matcher"
	"rampart/internal/domain"
	"rampart/internal/store"
)

var (
	_ domain.AnalysisStore  = (*MemoryStore)(nil)
	_ matcher.AdvisoryStore = (*MemoryStore)(nil)
)

func analysisKey(tenantID, sbomID uuid.UUID, ref domain.AnalyzerRef) string {
	return tenantID.String() + "|" + sbomID.String() + "|" + ref.Kind + "|" + ref.Scope + "|" + ref.Namespace + "|" + ref.Name
}

// SetAdvisories loads the advisories the built-in matcher reads, as PostgreSQL's vulnerability_affected would.
func (m *MemoryStore) SetAdvisories(rows []matcher.Advisory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.advisoryRows = append([]matcher.Advisory(nil), rows...)
}

// FindCandidatesByPurlBase returns the loaded advisories for the package URLs.
func (m *MemoryStore) FindCandidatesByPurlBase(_ context.Context, purlBases []string) ([]matcher.Advisory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	want := make(map[string]bool, len(purlBases))
	for _, p := range purlBases {
		want[p] = true
	}
	var out []matcher.Advisory
	for _, a := range m.advisoryRows {
		if want[a.PurlBase] {
			out = append(out, a)
		}
	}
	return out, nil
}

// GetSBOMByID returns one SBOM and its components. Only the newest SBOM of an asset and track is kept in memory.
func (m *MemoryStore) GetSBOMByID(_ context.Context, tenantID, sbomID uuid.UUID) (*domain.SBOM, []domain.SBOMComponent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.sboms {
		if b.ID == sbomID && b.TenantID == tenantID {
			cp := *b
			return &cp, append([]domain.SBOMComponent(nil), m.sbomComponents[b.ID.String()]...), nil
		}
	}
	return nil, nil, store.ErrNotFound
}

// LatestSBOMs returns every SBOM held (one per asset and track), of one asset when assetID is set.
func (m *MemoryStore) LatestSBOMs(_ context.Context, tenantID uuid.UUID, assetID *uuid.UUID) ([]domain.SBOM, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.SBOM
	for _, b := range m.sboms {
		if b.TenantID == tenantID && (assetID == nil || b.AssetID == *assetID) {
			cp := *b
			cp.Dependencies = nil
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, nil
}

// ClaimSBOMAnalysis records a pending analysis unless one is pending or running and younger than staleAfter.
func (m *MemoryStore) ClaimSBOMAnalysis(_ context.Context, a domain.SBOMAnalysis, staleAfter time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sbomAnalyses == nil {
		m.sbomAnalyses = map[string]*domain.SBOMAnalysis{}
	}
	key := analysisKey(a.TenantID, a.SBOMID, a.Analyzer)
	now := time.Now().UTC()
	if cur, ok := m.sbomAnalyses[key]; ok && !cur.State.Settled() && cur.UpdatedAt.After(now.Add(-staleAfter)) {
		return false, nil
	}
	m.sbomAnalyses[key] = &domain.SBOMAnalysis{TenantID: a.TenantID, SBOMID: a.SBOMID, Analyzer: a.Analyzer, State: domain.AnalysisPending, Trigger: a.Trigger, CreatedAt: now, UpdatedAt: now}
	return true, nil
}

// SaveSBOMAnalysis writes the state of a claimed analysis.
func (m *MemoryStore) SaveSBOMAnalysis(_ context.Context, a domain.SBOMAnalysis) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sbomAnalyses == nil {
		m.sbomAnalyses = map[string]*domain.SBOMAnalysis{}
	}
	key := analysisKey(a.TenantID, a.SBOMID, a.Analyzer)
	cur, ok := m.sbomAnalyses[key]
	if !ok {
		cur = &domain.SBOMAnalysis{TenantID: a.TenantID, SBOMID: a.SBOMID, Analyzer: a.Analyzer, CreatedAt: time.Now().UTC()}
		m.sbomAnalyses[key] = cur
	}
	created := cur.CreatedAt
	*cur = a
	cur.CreatedAt, cur.UpdatedAt = created, time.Now().UTC()
	return nil
}

// GetSBOMAnalysis returns the record of an analysis.
func (m *MemoryStore) GetSBOMAnalysis(_ context.Context, tenantID, sbomID uuid.UUID, ref domain.AnalyzerRef) (*domain.SBOMAnalysis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if cur, ok := m.sbomAnalyses[analysisKey(tenantID, sbomID, ref)]; ok {
		cp := *cur
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

// ListSBOMAnalyses returns the records of all analyses for an SBOM.
func (m *MemoryStore) ListSBOMAnalyses(_ context.Context, tenantID, sbomID uuid.UUID) ([]domain.SBOMAnalysis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []domain.SBOMAnalysis
	for _, a := range m.sbomAnalyses {
		if a.TenantID == tenantID && a.SBOMID == sbomID {
			out = append(out, *a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Analyzer.Name < out[j].Analyzer.Name })
	return out, nil
}

// ListDueSBOMs follows the same rule as PostgreSQL: never analysed first, then the oldest analysis, among the newest SBOMs.
func (m *MemoryStore) ListDueSBOMs(_ context.Context, tenantID uuid.UUID, ref domain.AnalyzerRef, completedBefore, failedBefore time.Time, limit int) ([]uuid.UUID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	type due struct {
		id uuid.UUID
		at time.Time
	}
	var list []due
	for _, b := range m.sboms {
		if b.TenantID != tenantID {
			continue
		}
		cur, ok := m.sbomAnalyses[analysisKey(tenantID, b.ID, ref)]
		if !ok {
			list = append(list, due{b.ID, time.Time{}})
			continue
		}
		at := cur.UpdatedAt
		if cur.FinishedAt != nil {
			at = *cur.FinishedAt
		}
		switch {
		case (cur.State == domain.AnalysisCompleted || cur.State == domain.AnalysisCancelled || cur.State == domain.AnalysisNotApplicable) && at.Before(completedBefore):
			list = append(list, due{b.ID, at})
		case (cur.State == domain.AnalysisFailed || cur.State == domain.AnalysisTimedOut) && at.Before(failedBefore):
			list = append(list, due{b.ID, at})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if !list[i].at.Equal(list[j].at) {
			return list[i].at.Before(list[j].at)
		}
		return list[i].id.String() < list[j].id.String()
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	out := make([]uuid.UUID, len(list))
	for i, d := range list {
		out[i] = d.id
	}
	return out, nil
}

// CountAnalysesInFlight counts the analyses pending or running, in every tenant, younger than staleAfter.
func (m *MemoryStore) CountAnalysesInFlight(_ context.Context, staleAfter time.Duration) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	cutoff := time.Now().UTC().Add(-staleAfter)
	for _, a := range m.sbomAnalyses {
		if !a.State.Settled() && a.UpdatedAt.After(cutoff) {
			n++
		}
	}
	return n, nil
}

// CreateNotification keeps an in-app notification for a tenant.
func (m *MemoryStore) CreateNotification(_ context.Context, tenantID uuid.UUID, n *domain.Notification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *n
	cp.TenantID = tenantID
	m.notifications = append(m.notifications, &cp)
	return nil
}

// NotificationCount counts the notifications of a kind a tenant was sent.
func (m *MemoryStore) NotificationCount(tenantID uuid.UUID, kind string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, x := range m.notifications {
		if x.TenantID == tenantID && x.Kind == kind {
			n++
		}
	}
	return n
}

var _ domain.ParserRunStore = (*MemoryStore)(nil)

// LastRunByParser summarises the runs of a tenant by their format.
func (m *MemoryStore) LastRunByParser(_ context.Context, tenantID uuid.UUID) (map[string]domain.ParserLastRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]domain.ParserLastRun{}
	for _, r := range m.ingestRuns {
		if r.TenantID != tenantID || r.Format == "" || r.Format == "sbom-analysis" {
			continue
		}
		cur, seen := out[r.Format]
		if !seen || r.CreatedAt.After(cur.At) {
			ok := cur.LastSuccess
			cur = domain.ParserLastRun{RunID: r.ID, Status: r.Status, Error: r.Error, At: r.CreatedAt, LastSuccess: ok}
		}
		if r.Status == domain.RunCompleted || r.Status == domain.RunCompletedWithErrors {
			if cur.LastSuccess == nil || r.CreatedAt.After(*cur.LastSuccess) {
				t := r.CreatedAt
				cur.LastSuccess = &t
			}
		}
		out[r.Format] = cur
	}
	return out, nil
}
