package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// SLAPolicy says how long a finding may stay open (docs/04 SLAPolicy, docs/06 section 4). The matrix is in
// days: rows are the risk band, columns the application's business criticality.
type SLAPolicy struct {
	Matrix                    map[string]map[string]int `json:"matrix"`
	KEVDueDate                bool                      `json:"kevDueDate"` // never later than the CISA due date
	MaxDays                   int                       `json:"maxDays"`
	StartFrom                 string                    `json:"startFrom"` // firstSeen (the only one built)
	RestartOnReactivation     bool                      `json:"restartOnReactivation"`
	PauseDuringRiskAcceptance bool                      `json:"pauseDuringRiskAcceptance"`
}

// DefaultSLAPolicy is the built-in policy of docs/06 section 4, which mirrors the market medians.
func DefaultSLAPolicy() SLAPolicy {
	return SLAPolicy{
		Matrix: map[string]map[string]int{
			"critical": {"critical": 3, "high": 7, "medium": 14, "low": 30},
			"high":     {"critical": 7, "high": 14, "medium": 30, "low": 60},
			"medium":   {"critical": 30, "high": 45, "medium": 90, "low": 120},
			"low":      {"critical": 90, "high": 120, "medium": 180, "low": 365},
		},
		KEVDueDate: true, MaxDays: 365, StartFrom: "firstSeen", RestartOnReactivation: true, PauseDuringRiskAcceptance: true,
	}
}

// Days is the allowance for a band and an application criticality. An unknown criticality counts as low (the
// loosest column), an unknown band as low; info findings use the low row.
func (p SLAPolicy) Days(band Severity, criticality string) int {
	row := string(band)
	if band == SeverityInfo || p.Matrix[row] == nil {
		row = "low"
	}
	col := criticality
	if _, ok := p.Matrix[row][col]; !ok {
		col = "low"
	}
	days := p.Matrix[row][col]
	if p.MaxDays > 0 && (days <= 0 || days > p.MaxDays) {
		days = p.MaxDays
	}
	return days
}

// Due is when a finding that started at start must be resolved: the matrix allowance, or the CISA due date when
// the policy caps by it and it is earlier (FedRAMP, BOD 22-01).
func (p SLAPolicy) Due(band Severity, criticality string, start time.Time, kevDue *time.Time) time.Time {
	due := start.Add(time.Duration(p.Days(band, criticality)) * 24 * time.Hour)
	if p.KEVDueDate && kevDue != nil && !kevDue.IsZero() && kevDue.Before(due) {
		return *kevDue
	}
	return due
}

// SLAPolicySpec is the spec of an SLAPolicy object as docs/04 writes it.
type SLAPolicySpec struct {
	Matrix map[string]map[string]int `json:"matrix"`
	Caps   struct {
		KEVDueDate *bool `json:"kevDueDate"`
		MaxDays    *int  `json:"maxDays"`
	} `json:"caps"`
	StartFrom                 string          `json:"startFrom"`
	RestartOnReactivation     *bool           `json:"restartOnReactivation"`
	PauseDuringRiskAcceptance *bool           `json:"pauseDuringRiskAcceptance"`
	BusinessDays              bool            `json:"businessDays"`
	Notify                    json.RawMessage `json:"notify"`
}

// ParseSLAPolicySpec reads and checks the spec of an SLAPolicy. What it leaves out takes the built-in value. What
// it asks for and this version cannot do (business days, a start other than first seen) is refused with a message,
// not ignored: a policy that silently does something else would be worse than one that says it is not applied.
func ParseSLAPolicySpec(raw []byte) (SLAPolicy, error) {
	var spec SLAPolicySpec
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &spec); err != nil {
			return SLAPolicy{}, fmt.Errorf("the spec is not valid: %w", err)
		}
	}
	p := DefaultSLAPolicy()
	bands := []string{"critical", "high", "medium", "low"}
	for band, row := range spec.Matrix {
		if !slices.Contains(bands, band) {
			return SLAPolicy{}, fmt.Errorf("matrix: %q is not a risk band (critical, high, medium, low)", band)
		}
		for crit, days := range row {
			if !slices.Contains(bands, crit) {
				return SLAPolicy{}, fmt.Errorf("matrix.%s: %q is not an application criticality (critical, high, medium, low)", band, crit)
			}
			if days < 1 || days > 3650 {
				return SLAPolicy{}, fmt.Errorf("matrix.%s.%s: %d days is not between 1 and 3650", band, crit, days)
			}
			p.Matrix[band][crit] = days
		}
	}
	if spec.Caps.KEVDueDate != nil {
		p.KEVDueDate = *spec.Caps.KEVDueDate
	}
	if spec.Caps.MaxDays != nil {
		if *spec.Caps.MaxDays < 1 || *spec.Caps.MaxDays > 3650 {
			return SLAPolicy{}, fmt.Errorf("caps.maxDays: %d is not between 1 and 3650", *spec.Caps.MaxDays)
		}
		p.MaxDays = *spec.Caps.MaxDays
	}
	switch spec.StartFrom {
	case "", "firstSeen":
	default:
		return SLAPolicy{}, fmt.Errorf("startFrom: %q is not supported yet (only firstSeen)", spec.StartFrom)
	}
	if spec.BusinessDays {
		return SLAPolicy{}, errors.New("businessDays: counting business days is not supported yet")
	}
	if spec.RestartOnReactivation != nil {
		p.RestartOnReactivation = *spec.RestartOnReactivation
	}
	if spec.PauseDuringRiskAcceptance != nil {
		p.PauseDuringRiskAcceptance = *spec.PauseDuringRiskAcceptance
	}
	return p, nil
}
