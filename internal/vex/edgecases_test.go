package vex

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// memMatcher implements MatcherStore for test cases.
type memMatcher struct {
	findings map[uuid.UUID]*domain.Finding
	events   map[uuid.UUID][]*domain.FindingEvent
}

func newMemMatcher() *memMatcher {
	return &memMatcher{
		findings: make(map[uuid.UUID]*domain.Finding),
		events:   make(map[uuid.UUID][]*domain.FindingEvent),
	}
}

func (m *memMatcher) FindFindingsForVEX(ctx context.Context, tenantID uuid.UUID, vulns, purlBases []string, appID *uuid.UUID) ([]*domain.Finding, error) {
	var res []*domain.Finding
	for _, f := range m.findings {
		if f.TenantID != tenantID {
			continue
		}
		if appID != nil && f.ApplicationID != *appID {
			continue
		}
		vulnMatch := false
		for _, v := range vulns {
			if f.RuleID == v || (f.VulnerabilityID != nil && *f.VulnerabilityID == v) {
				vulnMatch = true
				break
			}
		}
		if !vulnMatch {
			continue
		}
		purlMatch := false
		fBase := ""
		if f.Location.Package != nil {
			fBase = f.Location.Package.PurlBase
		}
		for _, pb := range purlBases {
			if fBase == pb {
				purlMatch = true
				break
			}
		}
		if vulnMatch && purlMatch {
			res = append(res, f)
		}
	}
	return res, nil
}

func (m *memMatcher) GetFindingEvents(ctx context.Context, tenantID, findingID uuid.UUID) ([]*domain.FindingEvent, error) {
	return m.events[findingID], nil
}

func (m *memMatcher) UpdateFindingTriage(ctx context.Context, tenantID uuid.UUID, f *domain.Finding, oldVersion int, events []*domain.FindingEvent) error {
	m.findings[f.ID] = f
	m.events[f.ID] = append(m.events[f.ID], events...)
	return nil
}

func TestEdgeCases_ParsingAndBoundaries(t *testing.T) {
	// EC-03: Malformed JSON syntax
	t.Run("EC-03_MalformedJSON", func(t *testing.T) {
		_, err := Parse([]byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [`))
		if err == nil {
			t.Fatal("expected error for malformed JSON, got nil")
		}
	})

	// EC-04: Unrecognized schema
	t.Run("EC-04_UnrecognizedSchema", func(t *testing.T) {
		sarifPayload := `{"version": "2.1.0", "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json", "runs": []}`
		_, err := Parse([]byte(sarifPayload))
		if err != ErrUnknownFormat {
			t.Fatalf("expected ErrUnknownFormat, got %v", err)
		}
	})

	// EC-10: Mixed timestamp formats
	t.Run("EC-10_TimestampFormats", func(t *testing.T) {
		times := []string{
			"2026-11-21T08:30:00Z",
			"2026-11-21T08:30:00.123456789Z",
			"2026-11-21",
		}
		for _, s := range times {
			parsed := parseTime(s)
			if parsed.IsZero() {
				t.Errorf("failed to parse timestamp %q", s)
			}
		}
	})
}

func TestEdgeCases_PURLSemanticsAndScoping(t *testing.T) {
	f := &domain.Finding{
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl:     "pkg:npm/lodash@4.17.20",
				PurlBase: "pkg:npm/lodash",
			},
		},
	}

	// EC-11: Exact versioned PURL matches
	t.Run("EC-11_ExactVersionedPURLMatch", func(t *testing.T) {
		st := Statement{Purls: []string{"pkg:npm/lodash@4.17.20"}}
		if !StatementCovers(st, f) {
			t.Fatal("expected statement to cover exact versioned finding")
		}
	})

	// EC-12: PURL Isolation: different version must NOT match
	t.Run("EC-12_DifferentVersionMustNotMatch", func(t *testing.T) {
		st := Statement{Purls: []string{"pkg:npm/lodash@4.17.21"}}
		if StatementCovers(st, f) {
			t.Fatal("statement for 4.17.21 MUST NOT cover finding for 4.17.20")
		}
	})

	// EC-13: Base PURL Scoping: unversioned PURL covers any version
	t.Run("EC-13_BasePURLCoversAnyVersion", func(t *testing.T) {
		st := Statement{Purls: []string{"pkg:npm/lodash"}}
		if !StatementCovers(st, f) {
			t.Fatal("statement targeting unversioned base purl must cover finding")
		}
	})
}

func TestEdgeCases_LifecyclePrecedenceAndReversibility(t *testing.T) {
	ctx := context.Background()
	matcher := newMemMatcher()
	tenantID := uuid.New()
	appID := uuid.New()
	findingID := uuid.New()
	vulnID := "CVE-2024-1111"

	finding := &domain.Finding{
		ID:            findingID,
		TenantID:      tenantID,
		ApplicationID: appID,
		RuleID:        vulnID,
		VulnerabilityID: &vulnID,
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl:     "pkg:npm/lodash@4.17.20",
				PurlBase: "pkg:npm/lodash",
			},
		},
		State: domain.StateOpen,
	}
	matcher.findings[findingID] = finding

	t1 := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 21, 10, 5, 0, 0, time.UTC)

	// EC-18: Chronological ordering: statement 1 (10:00:00, affected) and statement 2 (10:05:00, not_affected)
	// Later statement must prevail even if presented in reverse order in document.
	t.Run("EC-18_ChronologicalPrecedence", func(t *testing.T) {
		doc := &Document{
			Format: "openvex",
			Author: "Acme PSIRT",
			Statements: []Statement{
				{
					Vulns:         []string{vulnID},
					Purls:         []string{"pkg:npm/lodash@4.17.20"},
					State:         domain.StateNotAffected,
					Justification: "component_not_present",
					At:            t2, // Newer
				},
				{
					Vulns:  []string{vulnID},
					Purls:  []string{"pkg:npm/lodash@4.17.20"},
					State:  domain.StateAffected,
					Action: "Remediate now",
					At:     t1, // Older
				},
			},
		}

		rep, err := Apply(ctx, matcher, doc, tenantID, ApplyOptions{AppID: &appID})
		if err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if rep.Applied == 0 {
			t.Fatalf("expected statements applied, got 0")
		}

		updated := matcher.findings[findingID]
		if updated.State != domain.StateNotAffected {
			t.Fatalf("expected finding state not_affected (from newer statement at t2), got %s", updated.State)
		}
	})

	// EC-22: Idempotency: exact same document imported consecutively results in unchanged=N, applied=0
	t.Run("EC-22_IdempotencyConsecutiveImports", func(t *testing.T) {
		doc := &Document{
			Format: "openvex",
			Author: "Acme PSIRT",
			Statements: []Statement{
				{
					Vulns:         []string{vulnID},
					Purls:         []string{"pkg:npm/lodash@4.17.20"},
					State:         domain.StateNotAffected,
					Justification: "component_not_present",
					At:            t2,
				},
			},
		}

		rep, err := Apply(ctx, matcher, doc, tenantID, ApplyOptions{AppID: &appID})
		if err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if rep.Applied != 0 || rep.Unchanged != 1 {
			t.Fatalf("expected applied=0, unchanged=1 on idempotent import; got applied=%d, unchanged=%d", rep.Applied, rep.Unchanged)
		}
	})

	// EC-21: State Reversibility: vendor subsequently issues updated VEX marking affected
	t.Run("EC-21_StateReversibilityToAffected", func(t *testing.T) {
		t3 := time.Date(2026, 11, 21, 11, 0, 0, 0, time.UTC)
		doc := &Document{
			Format: "openvex",
			Author: "Acme PSIRT",
			Statements: []Statement{
				{
					Vulns:  []string{vulnID},
					Purls:  []string{"pkg:npm/lodash@4.17.20"},
					State:  domain.StateAffected,
					Action: "Vulnerability now confirmed exploitable in this environment",
					At:     t3,
				},
			},
		}

		rep, err := Apply(ctx, matcher, doc, tenantID, ApplyOptions{AppID: &appID})
		if err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if rep.Applied != 1 {
			t.Fatalf("expected applied=1, got %d", rep.Applied)
		}

		updated := matcher.findings[findingID]
		if updated.State != domain.StateAffected {
			t.Fatalf("expected finding state reversed back to affected, got %s", updated.State)
		}
	})

	// EC-19: Human decision protection: analyst manual triage at 12:00:00 protected against older VEX statement at 11:30:00
	t.Run("EC-19_HumanTriagePrecedenceProtected", func(t *testing.T) {
		tManual := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
		matcher.events[findingID] = append(matcher.events[findingID], &domain.FindingEvent{
			ID:        domain.NewID(),
			FindingID: findingID,
			Actor:     "user:alice@acme.example",
			Type:      "state_changed",
			At:        tManual,
		})

		tOldVEX := time.Date(2026, 11, 21, 11, 30, 0, 0, time.UTC)
		doc := &Document{
			Format: "openvex",
			Author: "Supplier PSIRT",
			Statements: []Statement{
				{
					Vulns:         []string{vulnID},
					Purls:         []string{"pkg:npm/lodash@4.17.20"},
					State:         domain.StateNotAffected,
					Justification: "component_not_present",
					At:            tOldVEX,
				},
			},
		}

		rep, err := Apply(ctx, matcher, doc, tenantID, ApplyOptions{AppID: &appID})
		if err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if rep.Stale != 1 || rep.Applied != 0 {
			t.Fatalf("expected statement marked stale (human protected), got stale=%d, applied=%d", rep.Stale, rep.Applied)
		}
	})
}
