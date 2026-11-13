package ingest_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/integrations"
)

type mockIngestRouter struct {
	tenantID uuid.UUID
	appName  string
	findings []*domain.Finding
}

func (m *mockIngestRouter) RouteIngestRunFindings(_ context.Context, tenantID uuid.UUID, appName string, findings []*domain.Finding) []error {
	m.tenantID = tenantID
	m.appName = appName
	m.findings = findings
	return nil
}

func TestProcessor_NotificationRouterWiring(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewMemoryStore()
	registry := integrations.DefaultRegistry()
	parser, err := registry.GetParser("builtin:gitleaks")
	if err != nil {
		t.Fatalf("failed to get gitleaks parser: %v", err)
	}

	processor := ingest.NewProcessor(store, registry, nil, nil)
	router := &mockIngestRouter{}
	processor.SetNotificationRouter(router)

	tenantID := uuid.New()
	appID := uuid.New()
	runID := uuid.New()
	run := &domain.IngestRun{
		ID:            runID,
		TenantID:      tenantID,
		ApplicationID: appID,
		Status:        domain.RunMerging,
	}

	report := `[{"Description": "AWS Secret Access Key", "StartLine": 1, "EndLine": 1, "File": "config.json", "Secret": "AKIAIOSFODNN7EXAMPLE", "RuleID": "aws-access-token"}]`
	open := func(_ context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(report)), nil
	}

	res, err := processor.Process(ctx, ingest.ProcessParams{
		Run:          run,
		Parser:       parser,
		ScanFinished: time.Now().UTC(),
		Open:         open,
	})
	if err != nil {
		t.Fatalf("processor.Process failed: %v", err)
	}
	if res.Stats.Created != 1 {
		t.Fatalf("expected 1 created finding, got %d", res.Stats.Created)
	}

	// Verify that router was called with the created finding
	if router.tenantID != tenantID {
		t.Fatalf("expected tenantID %v, got %v", tenantID, router.tenantID)
	}
	if len(router.findings) != 1 {
		t.Fatalf("expected 1 finding routed, got %d", len(router.findings))
	}
}
