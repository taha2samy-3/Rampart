package store_test

import (
	"context"
	"testing"

	"rampart/internal/domain"
)

// D140, end to end on PostgreSQL. An Application resource that names its type, repository, branch and environment is stored
// whole. The environment reaches the stored score: production adds the 60 points of the built-in factor to every finding of the
// application (the findings were found on main, so the branch rule gave nothing). A person who later says development takes
// them off again, a value the database does not know is refused by the database itself, and an application that says nothing is
// not described and gets no points.
func TestApplicationEnvironment_ReachesTheStoredScore_OnPostgreSQL(t *testing.T) {
	ctx := context.Background()
	h := newUploadHarness(t)
	h.formatHint = "semgrep"
	repo := domain.UploadContext{Repository: "github.com/acme/shop", Branch: "main"}
	h.waitRun(h.uploadAndComplete(semgrepReport(semgrepResult("rule.a", "a.go", 3)), repo))

	f := findingByRule(t, h, "rule.a")
	var slug string
	if err := h.pool.QueryRow(ctx, `SELECT slug FROM application WHERE id = $1`, f.ApplicationID).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	before := f.RiskScore

	// 1. the resource says production, and names what the application is
	app, err := domain.ApplicationSpec{Type: "repo", Repository: "github.com/acme/shop", Branch: "main", Environment: "production"}.ToApplication(f.ApplicationID, h.tenant, slug)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.sys.SaveApplication(ctx, app); err != nil {
		t.Fatal(err)
	}
	stored, err := h.store.GetApplication(ctx, h.tenant, f.ApplicationID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Type != "repo" || stored.Repository != "github.com/acme/shop" || stored.Branch != "main" || stored.Environment != "production" {
		t.Fatalf("the identity was not stored: %+v", stored)
	}
	if _, err := h.scorer.RecomputeSLA(ctx, h.tenant); err != nil {
		t.Fatal(err)
	}
	if got := findingByRule(t, h, "rule.a").RiskScore; got-before != 60 {
		t.Fatalf("environment production must add the 60 points of the production factor: before %d, after %d", before, got)
	}

	// 2. a person says development on an application no resource owns: the 60 points go again, and the change flags a re-score
	if _, err := h.pool.Exec(ctx, `UPDATE application SET managed_by = 'none' WHERE id = $1`, f.ApplicationID); err != nil {
		t.Fatal(err)
	}
	dev := "development"
	if _, err := h.store.UpdateApplicationContext(ctx, h.tenant, f.ApplicationID, domain.ApplicationContextUpdate{Environment: &dev}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.scorer.RecomputeSLA(ctx, h.tenant); err != nil {
		t.Fatal(err)
	}
	if got := findingByRule(t, h, "rule.a").RiskScore; got != before {
		t.Fatalf("development takes no points: before %d, after %d", before, got)
	}
	read, _ := h.store.GetApplication(ctx, h.tenant, f.ApplicationID)
	if read.Environment != "development" || read.Type != "repo" || read.Branch != "main" {
		t.Fatalf("a person's change must keep the identity: %+v", read)
	}

	// 3. saying nothing is "not described": the empty string clears it
	none := ""
	if _, err := h.store.UpdateApplicationContext(ctx, h.tenant, f.ApplicationID, domain.ApplicationContextUpdate{Environment: &none}); err != nil {
		t.Fatal(err)
	}
	if read, _ = h.store.GetApplication(ctx, h.tenant, f.ApplicationID); read.Environment != "" {
		t.Fatalf("not cleared: %+v", read)
	}

	// 4. the database refuses what the program does not know, even to a writer that skipped the program's checks
	if _, err := h.pool.Exec(ctx, `UPDATE application SET environment = 'prod' WHERE id = $1`, f.ApplicationID); err == nil {
		t.Fatal("the database accepted an environment it does not know")
	}
	if _, err := h.pool.Exec(ctx, `UPDATE application SET type = 'machine' WHERE id = $1`, f.ApplicationID); err == nil {
		t.Fatal("the database accepted a type that is not built")
	}
}
