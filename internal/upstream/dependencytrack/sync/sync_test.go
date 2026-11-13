package sync_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/store"
	dtclient "rampart/internal/upstream/dependencytrack/client"
	dtsync "rampart/internal/upstream/dependencytrack/sync"
)

type mockAssetFinder struct {
	assetsByUUID map[string]*domain.Asset
	assetsByKey  map[string]*domain.Asset
}

func (m *mockAssetFinder) FindAssetByDTrackUUID(ctx context.Context, tenantID uuid.UUID, projectUUID string) (*domain.Asset, error) {
	if a, ok := m.assetsByUUID[projectUUID]; ok {
		return a, nil
	}
	return nil, store.ErrNotFound
}

func (m *mockAssetFinder) FindAssetByKey(ctx context.Context, tenantID uuid.UUID, key string) (*domain.Asset, error) {
	if a, ok := m.assetsByKey[key]; ok {
		return a, nil
	}
	return nil, store.ErrNotFound
}

type mockAppResolver struct {
	apps map[string]*domain.Application
}

func (m *mockAppResolver) GetApplicationBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Application, error) {
	if app, ok := m.apps[slug]; ok {
		return app, nil
	}
	return nil, store.ErrNotFound
}

func TestMappingEngine_SevenRules(t *testing.T) {
	tenantID := uuid.New()
	app1 := &domain.Application{ID: uuid.New(), TenantID: tenantID, Slug: "app-prop"}
	app2 := &domain.Application{ID: uuid.New(), TenantID: tenantID, Slug: "app-tag"}
	app3 := &domain.Application{ID: uuid.New(), TenantID: tenantID, Slug: "app-asset"}
	app4 := &domain.Application{ID: uuid.New(), TenantID: tenantID, Slug: "app-purl"}
	app5 := &domain.Application{ID: uuid.New(), TenantID: tenantID, Slug: "app-parent"}
	app6 := &domain.Application{ID: uuid.New(), TenantID: tenantID, Slug: "app-cel"}
	app7 := &domain.Application{ID: uuid.New(), TenantID: tenantID, Slug: "app-default"}

	apps := &mockAppResolver{
		apps: map[string]*domain.Application{
			"app-prop":    app1,
			"app-tag":     app2,
			"app-asset":   app3,
			"app-purl":    app4,
			"app-parent":  app5,
			"app-cel":     app6,
			"app-default": app7,
		},
	}

	assets := &mockAssetFinder{
		assetsByUUID: map[string]*domain.Asset{
			"uuid-existing-asset": {ID: uuid.New(), ApplicationID: &app3.ID},
		},
		assetsByKey: map[string]*domain.Asset{
			"pkg:golang/github.com/shop/backend": {ID: uuid.New(), ApplicationID: &app4.ID},
		},
	}

	cfg := dtsync.MappingConfig{
		UseProjectProperties: true,
		TagPrefix:            "rampart-app:",
		MatchExistingAssets:  true,
		ParentAsApplication:  true,
		CELRules: []dtsync.CELRule{
			{When: `project.name.startsWith("cel-")`, Application: "app-cel"},
		},
		DefaultApplication: "app-default",
	}

	engine, err := dtsync.NewMappingEngine(cfg, assets, apps)
	if err != nil {
		t.Fatalf("failed initializing mapping engine: %v", err)
	}

	ctx := context.Background()

	// 1. Rule 1: Project property
	res1 := engine.Resolve(ctx, tenantID, dtclient.Project{Name: "p1"}, []dtclient.Property{
		{Group: "integrations", Name: "rampart.application", Value: "app-prop"},
	})
	if res1.ApplicationID == nil || *res1.ApplicationID != app1.ID || res1.MatchedRule != "property:rampart.application" {
		t.Errorf("Rule 1 failed: %+v", res1)
	}

	// 2. Rule 2: Project tag
	res2 := engine.Resolve(ctx, tenantID, dtclient.Project{
		Name: "p2",
		Tags: []dtclient.Tag{{Name: "rampart-app:app-tag"}},
	}, nil)
	if res2.ApplicationID == nil || *res2.ApplicationID != app2.ID || res2.MatchedRule != "tag:rampart-app:" {
		t.Errorf("Rule 2 failed: %+v", res2)
	}

	// 3. Rule 3: Existing asset link
	res3 := engine.Resolve(ctx, tenantID, dtclient.Project{
		UUID: "uuid-existing-asset",
		Name: "p3",
	}, nil)
	if res3.ApplicationID == nil || *res3.ApplicationID != app3.ID {
		t.Errorf("Rule 3 failed: %+v", res3)
	}

	// 4. Rule 4: Purl match
	res4 := engine.Resolve(ctx, tenantID, dtclient.Project{
		Name: "p4",
		Purl: "pkg:golang/github.com/shop/backend",
	}, nil)
	if res4.ApplicationID == nil || *res4.ApplicationID != app4.ID {
		t.Errorf("Rule 4 failed: %+v", res4)
	}

	// 5. Rule 5: Parent project
	res5 := engine.Resolve(ctx, tenantID, dtclient.Project{
		Name:   "p5-child",
		Parent: &dtclient.ParentRef{Name: "app-parent"},
	}, nil)
	if res5.ApplicationID == nil || *res5.ApplicationID != app5.ID {
		t.Errorf("Rule 5 failed: %+v", res5)
	}

	// 6. Rule 6: CEL rule
	res6 := engine.Resolve(ctx, tenantID, dtclient.Project{
		Name: "cel-microservice",
	}, nil)
	if res6.ApplicationID == nil || *res6.ApplicationID != app6.ID {
		t.Errorf("Rule 6 failed: %+v", res6)
	}

	// 7. Rule 7: Fallback to default
	res7 := engine.Resolve(ctx, tenantID, dtclient.Project{
		Name: "random-unmatched",
	}, nil)
	if res7.ApplicationID == nil || *res7.ApplicationID != app7.ID || res7.MatchedRule != "defaultApplication" {
		t.Errorf("Rule 7 default fallback failed: %+v", res7)
	}

	// 8. Unmapped when no default
	cfgNoDefault := cfg
	cfgNoDefault.DefaultApplication = ""
	engineNoDefault, _ := dtsync.NewMappingEngine(cfgNoDefault, assets, apps)
	resUnmapped := engineNoDefault.Resolve(ctx, tenantID, dtclient.Project{Name: "orphan"}, nil)
	if resUnmapped.ApplicationID != nil || resUnmapped.UnmappedReason == "" {
		t.Errorf("expected unmapped project: %+v", resUnmapped)
	}
}

type mockSyncerStore struct {
	mu           sync.Mutex
	syncs        map[string]*domain.DTrackSync
	projects     map[string]*domain.DTrackProjectRecord
	assets       map[string]*domain.Asset
	sourcePolicy *domain.IngestionPolicy
}

func newMockSyncerStore() *mockSyncerStore {
	return &mockSyncerStore{
		syncs:    make(map[string]*domain.DTrackSync),
		projects: make(map[string]*domain.DTrackProjectRecord),
		assets:   make(map[string]*domain.Asset),
	}
}

func (m *mockSyncerStore) LookupScanSource(ctx context.Context, sourceID uuid.UUID) (uuid.UUID, string, error) {
	return uuid.New(), "dtrack-main", nil
}

func (m *mockSyncerStore) EnqueueDTrackSync(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + projectUUID
	s, ok := m.syncs[key]
	if !ok || s.State == domain.DTrackSyncStateIdle {
		m.syncs[key] = &domain.DTrackSync{TenantID: tenantID, SourceID: sourceID, ProjectUUID: projectUUID, State: domain.DTrackSyncStateSyncing}
		return true, nil
	}
	s.Dirty = true
	return false, nil
}

func (m *mockSyncerStore) CompleteDTrackSync(ctx context.Context, tenantID uuid.UUID, projectUUID string, syncErr error) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + projectUUID
	s, ok := m.syncs[key]
	if !ok {
		return false, nil
	}
	if s.Dirty {
		s.Dirty = false
		s.State = domain.DTrackSyncStateSyncing
		return true, nil
	}
	s.State = domain.DTrackSyncStateIdle
	return false, nil
}

func (m *mockSyncerStore) GetDTrackSync(ctx context.Context, tenantID uuid.UUID, projectUUID string) (*domain.DTrackSync, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID.String() + ":" + projectUUID
	s, ok := m.syncs[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	return s, nil
}

func (m *mockSyncerStore) UpsertDTrackProject(ctx context.Context, proj domain.DTrackProjectRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.projects[proj.ProjectUUID] = &proj
	return nil
}

func (m *mockSyncerStore) ListUnmappedDTrackProjects(ctx context.Context, tenantID, sourceID uuid.UUID) ([]domain.DTrackProjectRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []domain.DTrackProjectRecord
	for _, p := range m.projects {
		if p.ApplicationID == nil {
			out = append(out, *p)
		}
	}
	return out, nil
}

func (m *mockSyncerStore) LookupAsset(ctx context.Context, tenantID uuid.UUID, assetType domain.AssetType, key string) (*domain.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.assets[key]; ok {
		return a, nil
	}
	return nil, store.ErrNotFound
}

func (m *mockSyncerStore) CreateAsset(ctx context.Context, asset *domain.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assets[asset.Key] = asset
	return nil
}

func (m *mockSyncerStore) GetScanSourceIngestionPolicy(ctx context.Context, tenantID, sourceID uuid.UUID) (*domain.IngestionPolicy, error) {
	return m.sourcePolicy, nil
}

type mockMergeEngine struct {
	mu            sync.Mutex
	mergedBatches int
	stagedRecords []ingest.StagedRecord
	closedScope   bool
}

func (e *mockMergeEngine) MergeBatchWithOptions(ctx context.Context, scope ingest.CloseScope, runID, appID uuid.UUID, records []ingest.StagedRecord, opts ingest.MergeOptions) (ingest.MergeOutcome, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mergedBatches++
	e.stagedRecords = append(e.stagedRecords, records...)
	return ingest.MergeOutcome{Created: len(records)}, nil
}

func (e *mockMergeEngine) CloseScopeStepWithGuard(ctx context.Context, scope ingest.CloseScope, currentRunID uuid.UUID, guardPolicy *domain.IngestionPolicy) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closedScope = true
	return 0, nil
}

func TestSyncer_SyncProject_MappedAndUnmapped(t *testing.T) {
	tenantID := uuid.New()
	sourceID := uuid.New()
	appID := uuid.New()

	findingsJSON := `[
		{
			"component": {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
			"vulnerability": {"vulnId": "CVE-2021-23337", "severity": "HIGH"}
		}
	]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/project/mapped-proj-1":
			_ = json.NewEncoder(w).Encode(dtclient.Project{
				UUID: "mapped-proj-1", Name: "payments-api", Version: "1.0.0", Active: true,
			})
		case "/api/v1/project/mapped-proj-1/property":
			_ = json.NewEncoder(w).Encode([]dtclient.Property{
				{Group: "integrations", Name: "rampart.application", Value: "payments-app"},
			})
		case "/api/v1/project/unmapped-proj-2":
			_ = json.NewEncoder(w).Encode(dtclient.Project{
				UUID: "unmapped-proj-2", Name: "orphan-proj", Version: "1.0.0", Active: true,
			})
		case "/api/v1/project/unmapped-proj-2/property":
			_ = json.NewEncoder(w).Encode([]dtclient.Property{})
		case "/api/v1/finding/project/mapped-proj-1":
			_, _ = w.Write([]byte(findingsJSON))
		case "/api/v1/metrics/project/mapped-proj-1/current":
			_ = json.NewEncoder(w).Encode(dtclient.ProjectMetrics{
				Critical: 1, Vulnerabilities: 1, LastOccurrence: time.Now().UnixMilli() + 1000,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dtClient := dtclient.NewClient(dtclient.Config{
		BaseURL:   srv.URL,
		APIKey:    "test-key",
		Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true},
	})

	st := newMockSyncerStore()
	eng := &mockMergeEngine{}
	apps := &mockAppResolver{
		apps: map[string]*domain.Application{
			"payments-app": {ID: appID, TenantID: tenantID, Slug: "payments-app"},
		},
	}
	mappingEngine, _ := dtsync.NewMappingEngine(dtsync.MappingConfig{UseProjectProperties: true}, nil, apps)

	syncer := dtsync.NewSyncer(dtClient, st, eng, mappingEngine)
	syncer.SetSettleChecker(dtsync.NewSettleChecker(dtClient, 10*time.Millisecond, 50*time.Millisecond))

	ctx := context.Background()

	// 1. Sync mapped project
	if err := syncer.SyncProject(ctx, tenantID, sourceID, "mapped-proj-1"); err != nil {
		t.Fatalf("SyncProject mapped failed: %v", err)
	}

	if eng.mergedBatches != 1 || len(eng.stagedRecords) != 1 {
		t.Fatalf("expected 1 merged batch with 1 record, got %d batches, %d records", eng.mergedBatches, len(eng.stagedRecords))
	}
	if !eng.closedScope {
		t.Error("expected scope closure to be executed")
	}

	// Verify asset was created
	assetKey := "dtrack://" + sourceID.String() + "/mapped-proj-1"
	if _, ok := st.assets[assetKey]; !ok {
		t.Errorf("expected asset %q to be created", assetKey)
	}

	// 2. Sync unmapped project
	if err := syncer.SyncProject(ctx, tenantID, sourceID, "unmapped-proj-2"); err != nil {
		t.Fatalf("SyncProject unmapped failed: %v", err)
	}

	// Engine batches shouldn't have changed
	if eng.mergedBatches != 1 {
		t.Fatalf("unmapped project must not merge findings, got %d batches", eng.mergedBatches)
	}

	// Unmapped project should be recorded in store
	unmappedList, err := st.ListUnmappedDTrackProjects(ctx, tenantID, sourceID)
	if err != nil || len(unmappedList) != 1 || unmappedList[0].ProjectUUID != "unmapped-proj-2" {
		t.Fatalf("expected 1 unmapped project recorded, got %+v", unmappedList)
	}
}
