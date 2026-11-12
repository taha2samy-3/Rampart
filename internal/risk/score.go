package risk

import (
	"time"

	"rampart/internal/domain"
)

// Factor represents an individual explainable risk factor and its point contribution.
type Factor struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
	Reason string `json:"reason"`
	// Group places the factor in the score bar: severity, threat, context or reduction (D62).
	Group string `json:"group,omitempty"`
}

// ScoreBreakdown details how a final risk score and band was computed (docs/06 §2).
type ScoreBreakdown struct {
	BaseSeverity domain.Severity `json:"base_severity"`
	BasePoints   int             `json:"base_points"`
	Factors      []Factor        `json:"factors"`
	TotalScore   int             `json:"total_score"` // 0..1000
	Band         domain.Severity `json:"band"`        // critical | high | medium | low
	HasKEV       bool            `json:"has_kev"`
	EPSSScore    float64         `json:"epss_score"`
	// Errors lists factors whose condition failed at run time; they counted as false (D62).
	Errors []string `json:"errors,omitempty"`
}

// CalculateSLADueDate calculates the SLA resolution deadline per docs/06 §4.
// Matrix (days) risk band \ app criticality:
// critical: critical=3d, high=7d, med=14d, low=30d
// high: critical=7d, high=14d, med=30d, low=60d
// medium: critical=30d, high=45d, med=90d, low=120d
// low: critical=90d, high=120d, med=180d, low=365d
func CalculateSLADueDate(band domain.Severity, appCriticality string, start time.Time, kevDueDate *time.Time) time.Time {
	return domain.DefaultSLAPolicy().Due(band, appCriticality, start, kevDueDate)
}
