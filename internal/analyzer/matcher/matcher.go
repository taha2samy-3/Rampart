package matcher

import (
	"context"
	"fmt"

	"rampart/internal/domain"
)

// Advisory models a candidate vulnerability definition from the vulnerability knowledge base.
type Advisory struct {
	ID          string
	Aliases     []string
	Summary     string
	Description string
	Severity    string
	CVSSScore   float64
	CVSSVector  string
	CWEs        []int
	PurlBase    string
	Ecosystem   string
	PackageName string
	RangeType   string // "SEMVER", "ECOSYSTEM"
	Introduced  string
	Fixed       string
}

// AdvisoryStore defines the repository interface for querying vulnerability definitions by PURL base.
type AdvisoryStore interface {
	FindCandidatesByPurlBase(ctx context.Context, purlBases []string) ([]Advisory, error)
}

// Matcher performs in-process component-to-vulnerability matching.
type Matcher struct {
	store AdvisoryStore
}

// New creates a new in-process matcher.
func New(store AdvisoryStore) *Matcher {
	return &Matcher{store: store}
}

// MatchComponents evaluates a list of SBOM components against candidate advisories.
func (m *Matcher) MatchComponents(ctx context.Context, components []domain.SBOMComponent) ([]domain.RawFinding, error) {
	if len(components) == 0 {
		return nil, nil
	}

	// 1. Group components by PurlBase for batched candidate lookup
	purlMap := make(map[string][]domain.SBOMComponent)
	var purlBases []string
	for _, comp := range components {
		if comp.PurlBase == "" {
			continue
		}
		if _, exists := purlMap[comp.PurlBase]; !exists {
			purlBases = append(purlBases, comp.PurlBase)
		}
		purlMap[comp.PurlBase] = append(purlMap[comp.PurlBase], comp)
	}

	if len(purlBases) == 0 {
		return nil, nil
	}

	// 2. Query candidates from local knowledge base
	advisories, err := m.store.FindCandidatesByPurlBase(ctx, purlBases)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability candidates: %w", err)
	}

	// 3. Match candidate version ranges against installed component versions
	var findings []domain.RawFinding
	for _, adv := range advisories {
		comps, ok := purlMap[adv.PurlBase]
		if !ok {
			continue
		}

		for _, comp := range comps {
			if !IsAffected(comp.Version, adv.Introduced, adv.Fixed) {
				continue
			}

			sev := domain.ParseSeverity(adv.Severity)
			if sev == domain.SeverityInfo && adv.CVSSScore > 0 {
				switch {
				case adv.CVSSScore >= 9.0:
					sev = domain.SeverityCritical
				case adv.CVSSScore >= 7.0:
					sev = domain.SeverityHigh
				case adv.CVSSScore >= 4.0:
					sev = domain.SeverityMedium
				default:
					sev = domain.SeverityLow
				}
			}

			title := adv.Summary
			if title == "" {
				title = fmt.Sprintf("Vulnerability %s in %s", adv.ID, comp.Name)
			}

			findings = append(findings, domain.RawFinding{
				RuleID:        adv.ID,
				Title:         title,
				ToolSeverity:  adv.Severity,
				Severity:      sev,
				CVSSVector:    adv.CVSSVector,
				CWEs:          adv.CWEs,
				VulnIDs:       append([]string{adv.ID}, adv.Aliases...),
				Description:   adv.Description,
				Category:      domain.CategorySCA,
				ScannerFamily: "rampart-sca",
				Location: domain.Location{
					Package: &domain.PackageLocation{
						Purl:             comp.Purl,
						ComponentName:    comp.Name,
						InstalledVersion: comp.Version,
						FixedVersion:     adv.Fixed,
					},
				},
			})
		}
	}

	return findings, nil
}
