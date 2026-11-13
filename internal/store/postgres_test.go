package store_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
)

var (
	sharedDirectURL string
	sharedAppURL    string
)

func TestMain(m *testing.M) {
	if custom := os.Getenv("RAMPART_TEST_POSTGRES_URL"); custom != "" {
		// RAMPART_TEST_POSTGRES_URL is the owner (superuser) URL. The application and
		// system roles are derived from it: a superuser bypasses RLS, so the isolation
		// tests must never run as the owner.
		sharedDirectURL = custom
		sharedAppURL = withCreds(custom, "rampart_app", "rampart_app_pw")
		os.Exit(m.Run())
	}

	// Try localhost:5433 then 5432
	candidates := []int{5433, 5432}
	for _, port := range candidates {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			sharedDirectURL = fmt.Sprintf("postgres://rampart_owner:rampart_password@127.0.0.1:%d/rampart?sslmode=disable", port)
			sharedAppURL = fmt.Sprintf("postgres://rampart_app:rampart_app_pw@127.0.0.1:%d/rampart?sslmode=disable", port)
			break
		}
	}

	var containerName string
	if sharedDirectURL == "" {
		if _, err := exec.LookPath("docker"); err == nil {
			containerName = fmt.Sprintf("rampart-pg-test-%d", time.Now().UnixNano()%100000)
			startCmd := exec.Command("docker", "run", "-d", "--rm", "--name", containerName, "-p", "5433:5432",
				"-e", "POSTGRES_USER=rampart_owner", "-e", "POSTGRES_PASSWORD=rampart_password", "-e", "POSTGRES_DB=rampart",
				"postgres:16-alpine")
			if err := startCmd.Run(); err == nil {
				deadline := time.Now().Add(25 * time.Second)
				for time.Now().Before(deadline) {
					time.Sleep(500 * time.Millisecond)
					checkCmd := exec.Command("docker", "exec", containerName, "pg_isready", "-U", "rampart_owner", "-d", "rampart")
					if err := checkCmd.Run(); err == nil {
						qCmd := exec.Command("docker", "exec", containerName, "psql", "-U", "rampart_owner", "-d", "rampart", "-c", "SELECT 1;")
						if qErr := qCmd.Run(); qErr == nil {
							sharedDirectURL = "postgres://rampart_owner:rampart_password@127.0.0.1:5433/rampart?sslmode=disable"
							sharedAppURL = "postgres://rampart_app:rampart_app_pw@127.0.0.1:5433/rampart?sslmode=disable"
							break
						}
					}
				}
			}
		}
	}

	code := m.Run()

	if containerName != "" {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}

	os.Exit(code)
}

// withCreds returns raw with its user and password replaced.
func withCreds(raw, user, password string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

func getTestPostgresURLs(t *testing.T) (directURL string, appURL string) {
	if sharedDirectURL == "" {
		t.Skip("PostgreSQL test instance not reachable on 5433 or 5432 and docker auto-start failed; skipping integration tests")
		return "", ""
	}
	return sharedDirectURL, sharedAppURL
}

// setupStores migrates as rampart_owner, provisions the login roles the way a
// platform would (the migration itself never sets passwords, D4), and returns a
// rampart_app store plus a rampart_system store (tenants are written by the operator).
func setupStores(t *testing.T, ctx context.Context) (appStore, sysStore *store.PostgresStore) {
	t.Helper()
	directURL, appURL := getTestPostgresURLs(t)
	if err := store.AutoMigrate(ctx, directURL); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}
	cfg, err := pgx.ParseConfig(directURL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("owner connect: %v", err)
	}
	for role, pw := range map[string]string{"rampart_app": "rampart_app_pw", "rampart_system": "rampart_system_pw"} {
		if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER ROLE %s LOGIN PASSWORD '%s'", role, pw)); err != nil {
			t.Fatalf("provision %s: %v", role, err)
		}
	}
	_ = conn.Close(ctx)

	appStore, err = store.ConnectPostgres(ctx, appURL)
	if err != nil {
		t.Fatalf("ConnectPostgres as rampart_app failed: %v", err)
	}
	t.Cleanup(appStore.Close)
	sysURL := withCreds(appURL, "rampart_system", "rampart_system_pw")
	sysStore, err = store.ConnectPostgres(ctx, sysURL)
	if err != nil {
		t.Fatalf("ConnectPostgres as rampart_system failed: %v", err)
	}
	t.Cleanup(sysStore.Close)
	return appStore, sysStore
}

func TestPostgresStore_Integration_RLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	appStore, sysStore := setupStores(t, ctx)

	if err := appStore.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	// 3. Create two distinct tenants (Tenant A and Tenant B)
	suffix := uuid.New().String()[:8]
	tenantA := &domain.Tenant{
		ID:          uuid.New(),
		Slug:        fmt.Sprintf("alpha-%s", suffix),
		DisplayName: "Alpha Corp",
		CreatedAt:   time.Now().UTC(),
	}
	if err := sysStore.CreateTenant(ctx, tenantA); err != nil {
		t.Fatalf("failed to create tenant A: %v", err)
	}

	tenantB := &domain.Tenant{
		ID:          uuid.New(),
		Slug:        fmt.Sprintf("beta-%s", suffix),
		DisplayName: "Beta Corp",
		CreatedAt:   time.Now().UTC(),
	}
	if err := sysStore.CreateTenant(ctx, tenantB); err != nil {
		t.Fatalf("failed to create tenant B: %v", err)
	}

	// 4. Application & Asset resolution under Tenant A
	appA := &domain.Application{
		ID:                  uuid.New(),
		TenantID:            tenantA.ID,
		Slug:                "app-alpha",
		Name:                "App Alpha",
		BusinessCriticality: "high",
		Lifecycle:           "production",
		CreatedAt:           time.Now().UTC(),
	}
	if err := appStore.CreateApplication(ctx, appA); err != nil {
		t.Fatalf("failed to create application for tenant A: %v", err)
	}

	assetA := &domain.Asset{
		ID:            uuid.New(),
		TenantID:      tenantA.ID,
		ApplicationID: &appA.ID,
		Type:          domain.AssetRepository,
		Key:           "github.com/acme/project-a",
		DisplayName:   "project-a",
		Active:        true,
		FirstSeen:     time.Now().UTC(),
		LastSeen:      time.Now().UTC(),
	}
	if err := appStore.CreateAsset(ctx, assetA); err != nil {
		t.Fatalf("failed to create asset for tenant A: %v", err)
	}

	// Lookup asset under Tenant A -> must succeed
	foundAssetA, err := appStore.LookupAsset(ctx, tenantA.ID, domain.AssetRepository, "github.com/acme/project-a")
	if err != nil || foundAssetA == nil {
		t.Fatalf("expected asset to be found under tenant A, got %v", err)
	}

	// Lookup asset under Tenant B -> must NOT be found (RLS isolation)
	foundAssetB, err := appStore.LookupAsset(ctx, tenantB.ID, domain.AssetRepository, "github.com/acme/project-a")
	if err == nil && foundAssetB != nil {
		t.Fatalf("SECURITY VIOLATION: Tenant B saw Tenant A's asset!")
	}

	// 5. Findings creation and RLS isolation
	findingA := &domain.Finding{
		ID:                uuid.New(),
		TenantID:          tenantA.ID,
		FindingKey:        "key-tenant-a-sqli-01",
		DedupScope:        "github.com/acme/project-a:main",
		AssetID:           assetA.ID,
		ApplicationID:     appA.ID,
		RuleScannerFamily: "semgrep",
		RuleID:            "rules.sql-injection",
		Title:             "SQL Injection in project A",
		Category:          domain.CategorySAST,
		Severity:          domain.SeverityCritical,
		ToolSeverity:      "critical",
		CWEs:              []int{89},
		RiskScore:         95,
		State:             domain.StateOpen,
		FirstSeen:         time.Now().UTC(),
		LastSeen:          time.Now().UTC(),
		OccurrenceCount:   1,
		Version:           1,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	if err := appStore.UpsertFindings(ctx, tenantA.ID, []*domain.Finding{findingA}); err != nil {
		t.Fatalf("failed to save finding for tenant A: %v", err)
	}

	// Query finding under Tenant A -> must succeed
	gotA, _, err := appStore.GetFinding(ctx, tenantA.ID, findingA.ID)
	if err != nil || gotA == nil {
		t.Fatalf("expected finding under tenant A, got err: %v", err)
	}
	if gotA.FindingKey != findingA.FindingKey {
		t.Errorf("expected finding key %s, got %s", findingA.FindingKey, gotA.FindingKey)
	}

	// Query finding under Tenant B -> must return nil / not found (RLS isolation)
	gotB, _, err := appStore.GetFinding(ctx, tenantB.ID, findingA.ID)
	if err == nil && gotB != nil {
		t.Fatalf("SECURITY VIOLATION: Tenant B retrieved Tenant A's finding %s!", gotB.ID)
	}

	// List findings under Tenant B -> must be empty
	listB, err := appStore.ListFindings(ctx, tenantB.ID)
	if err != nil {
		t.Fatalf("list findings for tenant B failed: %v", err)
	}
	if len(listB) != 0 {
		t.Fatalf("SECURITY VIOLATION: Tenant B list findings saw %d findings!", len(listB))
	}

	// List findings under Tenant A -> must find findingA
	listA, err := appStore.ListFindings(ctx, tenantA.ID)
	if err != nil {
		t.Fatalf("list findings for tenant A failed: %v", err)
	}
	if len(listA) == 0 {
		t.Fatalf("expected at least 1 finding under tenant A, got 0")
	}

	// 6. Direct query without app.tenant_id setting -> MUST see 0 rows under RLS
	pool := appStore.Pool()
	var countWithoutTenant int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM finding").Scan(&countWithoutTenant)
	if err != nil {
		t.Fatalf("querying without tenant context failed: %v", err)
	}
	if countWithoutTenant != 0 {
		t.Fatalf("SECURITY VIOLATION: rampart_app role without app.tenant_id saw %d rows! FORCE RLS failed.", countWithoutTenant)
	}

	// 7. Verify API Token generation and lookup
	tokenRaw, tokenRecord, err := auth.GenerateToken(tenantA.ID, auth.RoleAdmin, "default-user", []string{"*"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	if err := appStore.SaveToken(ctx, tokenRecord); err != nil {
		t.Fatalf("failed to store token in postgres: %v", err)
	}

	// Look up by hash
	tokenHash := auth.HashToken(tokenRaw)
	lookedUpToken, err := appStore.LookupTokenByHash(ctx, tenantA.ID, tokenHash)
	if err != nil || lookedUpToken == nil {
		t.Fatalf("expected token lookup by hash to succeed, got %v", err)
	}
	if lookedUpToken.TenantID != tenantA.ID {
		t.Errorf("token tenant mismatch: %s != %s", lookedUpToken.TenantID, tenantA.ID)
	}

	// 8. Ingest Run and RLS isolation
	runID := uuid.New()
	run := &domain.IngestRun{
		ID:             runID,
		TenantID:       tenantA.ID,
		ApplicationID:  appA.ID,
		AssetID:        assetA.ID,
		Track:          "default",
		ScannerFamily:  "semgrep",
		ScannerVersion: "1.45.0",
		Format:         "sarif",
		Status:         domain.RunCompleted,
		Stats:          domain.IngestStats{Parsed: 1, Created: 1},
		CreatedAt:      time.Now().UTC(),
	}
	if err := appStore.CreateIngestRun(ctx, run); err != nil {
		t.Fatalf("failed to create ingest run: %v", err)
	}

	gotRun, err := appStore.GetIngestRun(ctx, tenantA.ID, runID)
	if err != nil || gotRun == nil {
		t.Fatalf("failed to get ingest run: %v", err)
	}
	if gotRun.ID != runID {
		t.Errorf("got run ID %s, want %s", gotRun.ID, runID)
	}

	// Verify Tenant B cannot access Tenant A's ingest run (RLS)
	gotRunB, err := appStore.GetIngestRun(ctx, tenantB.ID, runID)
	if err == nil && gotRunB != nil {
		t.Fatalf("SECURITY VIOLATION: Tenant B retrieved Tenant A's ingest run!")
	}

	// 9. Occurrence upsert, present count, presence update (close logic), and RLS isolation
	occID := uuid.New()
	occ := &domain.Occurrence{
		ID:             occID,
		TenantID:       tenantA.ID,
		FindingID:      findingA.ID,
		IngestRunID:    runID,
		AssetID:        assetA.ID,
		Track:          "default",
		OccurrenceKey:  "occ-hash-01",
		ScannerFamily:  "semgrep",
		ScannerName:    "Semgrep OSS",
		ScannerVersion: "1.45.0",
		ToolSeverity:   "critical",
		Present:        true,
		SeenCount:      1,
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
	}
	if err := appStore.UpsertOccurrences(ctx, []*domain.Occurrence{occ}); err != nil {
		t.Fatalf("failed to upsert occurrence: %v", err)
	}

	count, err := appStore.CountPresentOccurrences(ctx, tenantA.ID, findingA.ID)
	if err != nil {
		t.Fatalf("failed to count occurrences: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 present occurrence, got %d", count)
	}

	// Update presence to false (D13 close step)
	if err := appStore.UpdateOccurrencesPresence(ctx, tenantA.ID, []uuid.UUID{occID}, false); err != nil {
		t.Fatalf("failed to update occurrence presence: %v", err)
	}
	countAfter, err := appStore.CountPresentOccurrences(ctx, tenantA.ID, findingA.ID)
	if err != nil {
		t.Fatalf("failed to count occurrences after presence update: %v", err)
	}
	if countAfter != 0 {
		t.Errorf("expected 0 present occurrences after close, got %d", countAfter)
	}

	// 10. Finding Events
	eventID := uuid.New()
	event := &domain.FindingEvent{
		ID:        eventID,
		FindingID: findingA.ID,
		At:        time.Now().UTC(),
		Actor:     "system:scanner",
		Type:      "closed_by_rescan",
		From:      []byte(`{"state":"open"}`),
		To:        []byte(`{"state":"fixed"}`),
		Note:      "automatically resolved via rescan",
	}
	if err := appStore.RecordFindingEvents(ctx, tenantA.ID, []*domain.FindingEvent{event}); err != nil {
		t.Fatalf("failed to record finding event: %v", err)
	}

	events, err := appStore.GetFindingEvents(ctx, tenantA.ID, findingA.ID)
	if err != nil {
		t.Fatalf("failed to get finding events: %v", err)
	}
	if len(events) == 0 {
		t.Errorf("expected at least 1 finding event, got 0")
	}

	// 11. SBOM saving, component retrieval, and RLS isolation
	sbomID := uuid.New()
	sbom := &domain.SBOM{
		ID:             sbomID,
		TenantID:       tenantA.ID,
		AssetID:        assetA.ID,
		IngestRunID:    runID,
		Format:         "cyclonedx-json",
		SpecVersion:    "1.5",
		ComponentCount: 1,
		CreatedAt:      time.Now().UTC(),
	}
	components := []domain.SBOMComponent{
		{
			TenantID: tenantA.ID,
			SBOMID:   sbomID,
			Ref:      "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			Purl:     "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			PurlBase: "pkg:golang/github.com/gin-gonic/gin",
			Name:     "gin",
			Version:  "v1.9.1",
			Direct:   true,
		},
	}
	if err := appStore.SaveSBOM(ctx, sbom, components); err != nil {
		t.Fatalf("failed to save SBOM: %v", err)
	}

	gotSBOM, gotComps, err := appStore.GetSBOM(ctx, tenantA.ID, assetA.ID)
	if err != nil {
		t.Fatalf("failed to get SBOM: %v", err)
	}
	if gotSBOM == nil || len(gotComps) != 1 {
		t.Fatalf("expected 1 SBOM component, got %d", len(gotComps))
	}

	// Verify Tenant B cannot read Tenant A's SBOM
	gotSbomB, _, err := appStore.GetSBOM(ctx, tenantB.ID, assetA.ID)
	if err == nil && gotSbomB != nil {
		t.Fatalf("SECURITY VIOLATION: Tenant B retrieved Tenant A's SBOM!")
	}

	// 12. Verify Connector table isolation under RLS (00026_connector.sql, D69)
	connA := domain.Connector{
		Name: "slack-prod",
		Type: domain.ConnectorTypeSlack,
		Spec: domain.ConnectorSpec{
			Type:      domain.ConnectorTypeSlack,
			Direction: domain.DirectionOutbound,
			Slack: &domain.SlackConnectorConfig{
				TokenSecretRef: domain.SecretKeyRef{Name: "slack-sec", Key: "token"},
				DefaultChannel: "#sec-ops",
			},
		},
	}
	// rampart_app cannot write connectors (D69: operator writes as rampart_system)
	if err := appStore.SaveConnector(ctx, tenantA.ID, connA); err == nil {
		t.Fatalf("expected appStore (rampart_app) to be denied write access to connector table")
	}

	// rampart_system writes the connector
	if err := sysStore.SaveConnector(ctx, tenantA.ID, connA); err != nil {
		t.Fatalf("failed to save connector for tenant A as rampart_system: %v", err)
	}

	// Tenant A can see it
	connsA, err := appStore.ListConnectors(ctx, tenantA.ID)
	if err != nil || len(connsA) == 0 {
		t.Fatalf("expected tenant A to list its connector, got %v (len %d)", err, len(connsA))
	}

	// Tenant B cannot see it under RLS
	connsB, err := appStore.ListConnectors(ctx, tenantB.ID)
	if err != nil {
		t.Fatalf("list connectors for tenant B failed: %v", err)
	}
	if len(connsB) != 0 {
		t.Fatalf("SECURITY VIOLATION: Tenant B saw %d connectors from Tenant A!", len(connsB))
	}

	// Direct query without app.tenant_id MUST see 0 rows
	var connCountWithoutTenant int
	err = pool.QueryRow(ctx, "SELECT count(*) FROM connector").Scan(&connCountWithoutTenant)
	if err != nil {
		t.Fatalf("querying connector without tenant context failed: %v", err)
	}
	if connCountWithoutTenant != 0 {
		t.Fatalf("SECURITY VIOLATION: rampart_app role without app.tenant_id saw %d connectors! FORCE RLS failed.", connCountWithoutTenant)
	}

	// 13. Test DeleteSecretMaterialPrefix (D49 connector and scansource cleanup)
	if err := sysStore.SaveSecretMaterial(ctx, tenantA.ID, "connector:mail:username", []byte("enc-u")); err != nil {
		t.Fatalf("failed to save secret material username: %v", err)
	}
	if err := sysStore.SaveSecretMaterial(ctx, tenantA.ID, "connector:mail:password", []byte("enc-p")); err != nil {
		t.Fatalf("failed to save secret material password: %v", err)
	}
	if err := sysStore.SaveSecretMaterial(ctx, tenantB.ID, "connector:mail:username", []byte("enc-u-b")); err != nil {
		t.Fatalf("failed to save secret material for tenant B: %v", err)
	}

	// Delete prefix for Tenant A
	if err := sysStore.DeleteSecretMaterialPrefix(ctx, tenantA.ID, "connector:mail:"); err != nil {
		t.Fatalf("failed to delete secret material prefix for tenant A: %v", err)
	}

	// Tenant A secrets must be gone
	if _, err := sysStore.GetSecretMaterial(ctx, tenantA.ID, "connector:mail:username"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for tenant A username after prefix deletion, got %v", err)
	}
	if _, err := sysStore.GetSecretMaterial(ctx, tenantA.ID, "connector:mail:password"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for tenant A password after prefix deletion, got %v", err)
	}

	// Tenant B secret must still exist (RLS & tenant isolation)
	secB, err := sysStore.GetSecretMaterial(ctx, tenantB.ID, "connector:mail:username")
	if err != nil || string(secB) != "enc-u-b" {
		t.Fatalf("expected tenant B secret to be undisturbed, got %v (%q)", err, string(secB))
	}
}
