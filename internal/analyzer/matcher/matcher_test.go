package matcher_test

import (
	"context"
	"testing"

	"rampart/internal/analyzer/matcher"
	"rampart/internal/domain"
)

type mockAdvisoryStore struct {
	advisories []matcher.Advisory
}

func (s *mockAdvisoryStore) FindCandidatesByPurlBase(ctx context.Context, purlBases []string) ([]matcher.Advisory, error) {
	var candidates []matcher.Advisory
	baseSet := make(map[string]bool)
	for _, b := range purlBases {
		baseSet[b] = true
	}

	for _, a := range s.advisories {
		if baseSet[a.PurlBase] {
			candidates = append(candidates, a)
		}
	}
	return candidates, nil
}

func TestMatcher_MatchesVulnerableComponents(t *testing.T) {
	store := &mockAdvisoryStore{
		advisories: []matcher.Advisory{
			{
				ID:          "CVE-2021-23337",
				Summary:     "Command Injection in lodash",
				Severity:    "HIGH",
				CVSSScore:   7.2,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
				CWEs:        []int{78},
				PurlBase:    "pkg:npm/lodash",
				Ecosystem:   "npm",
				PackageName: "lodash",
				Introduced:  "0",
				Fixed:       "4.17.21",
			},
			{
				ID:          "CVE-2021-44228",
				Summary:     "Log4Shell",
				Severity:    "CRITICAL",
				CVSSScore:   10.0,
				PurlBase:    "pkg:maven/org.apache.logging.log4j/log4j-core",
				Ecosystem:   "maven",
				PackageName: "log4j-core",
				Introduced:  "2.0-beta9",
				Fixed:       "2.15.0",
			},
		},
	}

	m := matcher.New(store)
	ctx := context.Background()

	components := []domain.SBOMComponent{
		{
			Ref:      "pkg:npm/lodash@4.17.20",
			Name:     "lodash",
			Version:  "4.17.20",
			Purl:     "pkg:npm/lodash@4.17.20",
			PurlBase: "pkg:npm/lodash",
			Direct:   true,
		},
		{
			// Fixed lodash - should NOT match
			Ref:      "pkg:npm/lodash@4.17.21",
			Name:     "lodash",
			Version:  "4.17.21",
			Purl:     "pkg:npm/lodash@4.17.21",
			PurlBase: "pkg:npm/lodash",
			Direct:   false,
		},
		{
			// Vulnerable log4j
			Ref:      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			Name:     "log4j-core",
			Version:  "2.14.1",
			Purl:     "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			PurlBase: "pkg:maven/org.apache.logging.log4j/log4j-core",
			Direct:   false,
		},
		{
			// Completely clean library
			Ref:      "pkg:npm/express@4.18.2",
			Name:     "express",
			Version:  "4.18.2",
			Purl:     "pkg:npm/express@4.18.2",
			PurlBase: "pkg:npm/express",
			Direct:   true,
		},
	}

	findings, err := m.MatchComponents(ctx, components)
	if err != nil {
		t.Fatalf("MatchComponents failed: %v", err)
	}

	// Should match exactly 2 findings: lodash@4.17.20 and log4j-core@2.14.1
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	findingMap := make(map[string]domain.RawFinding)
	for _, f := range findings {
		findingMap[f.RuleID] = f
	}

	// 1. Verify lodash finding
	lodashFinding, ok := findingMap["CVE-2021-23337"]
	if !ok {
		t.Errorf("missing finding for CVE-2021-23337")
	} else {
		if lodashFinding.Severity != domain.SeverityHigh {
			t.Errorf("expected SeverityHigh, got %v", lodashFinding.Severity)
		}
		if lodashFinding.Location.Package.InstalledVersion != "4.17.20" {
			t.Errorf("expected installed version 4.17.20, got %s", lodashFinding.Location.Package.InstalledVersion)
		}
		if lodashFinding.Location.Package.FixedVersion != "4.17.21" {
			t.Errorf("expected fixed version 4.17.21, got %s", lodashFinding.Location.Package.FixedVersion)
		}
	}

	// 2. Verify log4j finding
	log4jFinding, ok := findingMap["CVE-2021-44228"]
	if !ok {
		t.Errorf("missing finding for CVE-2021-44228")
	} else {
		if log4jFinding.Severity != domain.SeverityCritical {
			t.Errorf("expected SeverityCritical, got %v", log4jFinding.Severity)
		}
		if log4jFinding.Location.Package.InstalledVersion != "2.14.1" {
			t.Errorf("expected installed version 2.14.1, got %s", log4jFinding.Location.Package.InstalledVersion)
		}
		if log4jFinding.Location.Package.FixedVersion != "2.15.0" {
			t.Errorf("expected fixed version 2.15.0, got %s", log4jFinding.Location.Package.FixedVersion)
		}
	}
}

func TestVersion_IsAffected(t *testing.T) {
	cases := []struct {
		v, intro, fixed string
		want            bool
	}{
		{"4.17.20", "0", "4.17.21", true},
		{"4.17.21", "0", "4.17.21", false},
		{"4.18.0", "0", "4.17.21", false},
		{"1.0.0", "1.0.0", "2.0.0", true},
		{"2.0.0", "1.0.0", "2.0.0", false},
		{"0.9.9", "1.0.0", "2.0.0", false},
	}

	for _, c := range cases {
		got := matcher.IsAffected(c.v, c.intro, c.fixed)
		if got != c.want {
			t.Errorf("IsAffected(%s, %s, %s) = %v, want %v", c.v, c.intro, c.fixed, got, c.want)
		}
	}
}
