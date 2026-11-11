package domain_test

import (
	"testing"
	"time"

	"rampart/internal/domain"
)

func TestUUIDv7Generation(t *testing.T) {
	id1 := domain.NewID()
	id2 := domain.NewID()

	if id1 == domain.NilID || id2 == domain.NilID {
		t.Fatal("expected non-nil UUIDs")
	}
	if id1 == id2 {
		t.Fatalf("expected unique UUIDs, got duplicates: %v", id1)
	}
	if id1.Version() != 7 {
		t.Errorf("expected UUID version 7, got %d", id1.Version())
	}

	// Verify parse
	parsed, err := domain.ParseID(id1.String())
	if err != nil {
		t.Fatalf("failed to parse valid UUID: %v", err)
	}
	if parsed != id1 {
		t.Errorf("expected %v, got %v", id1, parsed)
	}

	// Verify invalid parse
	if _, err := domain.ParseID("not-a-uuid"); err == nil {
		t.Error("expected error parsing invalid UUID string")
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct {
		raw      string
		expected domain.Severity
		rank     int
		valid    bool
	}{
		{"critical", domain.SeverityCritical, 5, true},
		{"CRITICAL", domain.SeverityCritical, 5, true},
		{"blocker", domain.SeverityCritical, 5, true},
		{"high", domain.SeverityHigh, 4, true},
		{"error", domain.SeverityHigh, 4, true},
		{"medium", domain.SeverityMedium, 3, true},
		{"warn", domain.SeverityMedium, 3, true},
		{"low", domain.SeverityLow, 2, true},
		{"info", domain.SeverityInfo, 1, true},
		{"note", domain.SeverityInfo, 1, true},
		{"unknown", domain.SeverityUnknown, 0, false},
		{"invalid", domain.SeverityUnknown, 0, false},
	}

	for _, tt := range tests {
		sev := domain.ParseSeverity(tt.raw)
		if sev != tt.expected {
			t.Errorf("ParseSeverity(%q) = %v; want %v", tt.raw, sev, tt.expected)
		}
		if sev.Rank() != tt.rank {
			t.Errorf("Severity(%v).Rank() = %d; want %d", sev, sev.Rank(), tt.rank)
		}
		if sev.Valid() != tt.valid {
			t.Errorf("Severity(%v).Valid() = %v; want %v", sev, sev.Valid(), tt.valid)
		}
	}
}

func TestFindingStateTransitions(t *testing.T) {
	// Valid transitions
	validPairs := [][2]domain.FindingState{
		{domain.StateOpen, domain.StateUnderInvestigation},
		{domain.StateOpen, domain.StateAffected},
		{domain.StateOpen, domain.StateNotAffected},
		{domain.StateOpen, domain.StateFixed},
		{domain.StateOpen, domain.StateRiskAccepted},
		{domain.StateUnderInvestigation, domain.StateAffected},
		{domain.StateUnderInvestigation, domain.StateNotAffected},
		{domain.StateUnderInvestigation, domain.StateFixed},
		{domain.StateAffected, domain.StateFixed},
		{domain.StateAffected, domain.StateRiskAccepted},
		{domain.StateFixed, domain.StateOpen},        // Reactivation by rescan
		{domain.StateRiskAccepted, domain.StateOpen}, // Expiry
		{domain.StateOpen, domain.StateOpen},         // No-op
	}

	for _, pair := range validPairs {
		if err := pair[0].CanTransitionTo(pair[1]); err != nil {
			t.Errorf("expected transition %s -> %s to be valid, got: %v", pair[0], pair[1], err)
		}
	}

	// Invalid transitions
	invalidPairs := [][2]domain.FindingState{
		{domain.StateFixed, domain.StateNotAffected},
		{domain.StateFixed, domain.StateRiskAccepted},
		{domain.StateNotAffected, domain.StateFixed},
		{domain.StateNotAffected, domain.StateRiskAccepted},
	}

	for _, pair := range invalidPairs {
		if err := pair[0].CanTransitionTo(pair[1]); err == nil {
			t.Errorf("expected transition %s -> %s to be invalid, got nil error", pair[0], pair[1])
		}
	}
}

func TestLocationPrimaryPath(t *testing.T) {
	loc1 := domain.Location{
		Code: &domain.CodeLocation{FilePath: "src/main.go"},
	}
	if loc1.PrimaryPath() != "src/main.go" {
		t.Errorf("expected primary path 'src/main.go', got %q", loc1.PrimaryPath())
	}
	if loc1.IsEmpty() {
		t.Error("expected non-empty location")
	}

	loc2 := domain.Location{
		Package: &domain.PackageLocation{PurlBase: "pkg:npm/lodash"},
	}
	if loc2.PrimaryPath() != "pkg:npm/lodash" {
		t.Errorf("expected primary path 'pkg:npm/lodash', got %q", loc2.PrimaryPath())
	}

	emptyLoc := domain.Location{}
	if !emptyLoc.IsEmpty() {
		t.Error("expected empty location to be empty")
	}
}

func TestEntityValidation(t *testing.T) {
	tenantID := domain.NewID()
	appID := domain.NewID()
	assetID := domain.NewID()
	now := time.Now().UTC()

	// Tenant
	validTenant := domain.Tenant{
		ID:        tenantID,
		Slug:      "acme-corp",
		CreatedAt: now,
	}
	if err := validTenant.Validate(); err != nil {
		t.Fatalf("valid tenant failed validation: %v", err)
	}

	invalidTenant := domain.Tenant{ID: domain.NilID}
	if err := invalidTenant.Validate(); err == nil {
		t.Error("expected invalid tenant to fail validation")
	}

	// Application
	validApp := domain.Application{
		ID:       appID,
		TenantID: tenantID,
		Slug:     "billing-service",
		Name:     "Billing Service",
	}
	if err := validApp.Validate(); err != nil {
		t.Fatalf("valid app failed validation: %v", err)
	}

	// Finding
	validFinding := domain.Finding{
		ID:            domain.NewID(),
		TenantID:      tenantID,
		FindingKey:    "sha256-hash-key",
		AssetID:       assetID,
		ApplicationID: appID,
		Severity:      domain.SeverityHigh,
		State:         domain.StateOpen,
		Detection:     domain.DetectionPresent,
	}
	if err := validFinding.Validate(); err != nil {
		t.Fatalf("valid finding failed validation: %v", err)
	}

	invalidFinding := validFinding
	invalidFinding.Severity = domain.Severity("not-a-severity")
	if err := invalidFinding.Validate(); err == nil {
		t.Error("expected invalid finding severity to fail validation")
	}
}
