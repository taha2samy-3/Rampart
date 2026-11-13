package store_test

import (
	"strings"
	"testing"

	"rampart/internal/store"
)

func TestMigrationsEmbedded(t *testing.T) {
	entries, err := store.MigrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("failed to read embedded migrations dir: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("expected at least one embedded migration file")
	}

	foundInitial := false
	for _, entry := range entries {
		if entry.Name() == "00001_initial_schema.sql" {
			foundInitial = true
			content, err := store.MigrationsFS.ReadFile("migrations/" + entry.Name())
			if err != nil {
				t.Fatalf("failed to read 00001_initial_schema.sql: %v", err)
			}
			contentStr := string(content)
			if !strings.Contains(contentStr, "CREATE TABLE finding") {
				t.Error("expected 00001_initial_schema.sql to contain finding table DDL")
			}
			if !strings.Contains(contentStr, "CREATE POLICY tenant_isolation") {
				t.Error("expected 00001_initial_schema.sql to contain RLS policy")
			}
			break
		}
	}

	if !foundInitial {
		t.Error("00001_initial_schema.sql not found in embedded filesystem")
	}

	contentIdP, err := store.MigrationsFS.ReadFile("migrations/00025_identity_provider.sql")
	if err != nil {
		t.Fatalf("failed to read 00025_identity_provider.sql: %v", err)
	}
	contentIdPStr := string(contentIdP)
	if !strings.Contains(contentIdPStr, "ENABLE ROW LEVEL SECURITY") {
		t.Error("expected 00025_identity_provider.sql to enable RLS")
	}
	if !strings.Contains(contentIdPStr, "CREATE POLICY tenant_isolation ON identity_provider") {
		t.Error("expected 00025_identity_provider.sql to define tenant_isolation policy")
	}
}
