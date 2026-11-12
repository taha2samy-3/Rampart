package risk

import (
	"time"

	"rampart/internal/domain"
	"rampart/internal/enrich"
)

// Factor represents an individual explainable risk factor and its point contribution.
type Factor struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
	Reason string `json:"reason"`
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
}

// Context contains contextual metadata for risk score calculation.
type Context struct {
	Environment         string // production | staging | dev
	IsInternetFacing    bool
	HasSensitiveData    bool   // PCI, PII, PHI
	BusinessCriticality string // critical | high | medium | low
	FixAvailable        bool
	IsUnreachable       bool
	SecretVerifiedLive  bool
	CompensatingControl bool
	FirstSeen           time.Time
	Now                 time.Time
}

// EvaluateRisk computes the explainable risk score according to docs/06 §2 & D14.
func EvaluateRisk(finding domain.RawFinding, vulnIDs []string, ctx Context, feeds *enrich.FeedStore) ScoreBreakdown {
	basePts := BasePointsForSeverity(finding.Severity)

	breakdown := ScoreBreakdown{
		BaseSeverity: finding.Severity,
		BasePoints:   basePts,
		Factors:      make([]Factor, 0),
	}

	total := basePts

	// Check KEV
	var kevDueDate *time.Time
	if feeds != nil {
		for _, vid := range vulnIDs {
			if entry, ok := feeds.GetKEV(vid); ok {
				breakdown.HasKEV = true
				kevDueDate = entry.DueDate
				factor := Factor{
					Name:   "KEV",
					Points: 300,
					Reason: "Vulnerability listed in CISA Known Exploited Vulnerabilities catalog",
				}
				breakdown.Factors = append(breakdown.Factors, factor)
				total += 300
				break
			}
		}

		// Check EPSS
		maxEPSS := 0.0
		for _, vid := range vulnIDs {
			if epss, ok := feeds.GetEPSS(vid); ok {
				if epss.EPSS > maxEPSS {
					maxEPSS = epss.EPSS
				}
			}
		}
		if maxEPSS > 0 {
			breakdown.EPSSScore = maxEPSS
			if maxEPSS >= 0.5 {
				factor := Factor{
					Name:   "EPSS_HIGH",
					Points: 150,
					Reason: "EPSS exploitation probability is >= 50%",
				}
				breakdown.Factors = append(breakdown.Factors, factor)
				total += 150
			} else if maxEPSS >= 0.1 {
				factor := Factor{
					Name:   "EPSS_MODERATE",
					Points: 60,
					Reason: "EPSS exploitation probability is >= 10%",
				}
				breakdown.Factors = append(breakdown.Factors, factor)
				total += 60
			}
		}
	}

	// Secret verified live (from scanner)
	if ctx.SecretVerifiedLive {
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "SECRET_VERIFIED",
			Points: 250,
			Reason: "Secret credential verified live against upstream provider",
		})
		total += 250
	}

	// Internet-facing app or env
	if ctx.IsInternetFacing {
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "INTERNET_FACING",
			Points: 100,
			Reason: "Asset or application is internet-facing",
		})
		total += 100
	}

	// Sensitive data (PCI, PII, PHI)
	if ctx.HasSensitiveData {
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "SENSITIVE_DATA",
			Points: 80,
			Reason: "Application handles sensitive data (PCI, PII, or PHI)",
		})
		total += 80
	}

	// Business criticality
	switch ctx.BusinessCriticality {
	case "critical":
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "APP_CRITICAL",
			Points: 100,
			Reason: "Application business criticality is rated Critical",
		})
		total += 100
	case "high":
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "APP_HIGH",
			Points: 50,
			Reason: "Application business criticality is rated High",
		})
		total += 50
	}

	// Production environment
	if ctx.Environment == "production" || ctx.Environment == "prod" {
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "PRODUCTION_ENV",
			Points: 60,
			Reason: "Finding detected in production environment",
		})
		total += 60
	}

	// Fix available
	if ctx.FixAvailable {
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "FIX_AVAILABLE",
			Points: 20,
			Reason: "Remediation fix or patch is readily available",
		})
		total += 20
	}

	// Age > 90 days open
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !ctx.FirstSeen.IsZero() && now.Sub(ctx.FirstSeen) > 90*24*time.Hour {
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "AGING_DEBT",
			Points: 30,
			Reason: "Finding has been open for more than 90 days",
		})
		total += 30
	}

	// Reachability = unreachable (-200)
	if ctx.IsUnreachable {
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "UNREACHABLE",
			Points: -200,
			Reason: "Static or dynamic analysis proved vulnerable code is unreachable",
		})
		total -= 200
	}

	// Compensating control (-80)
	if ctx.CompensatingControl {
		breakdown.Factors = append(breakdown.Factors, Factor{
			Name:   "COMPENSATING_CONTROL",
			Points: -80,
			Reason: "The application is behind a web application firewall or an API gateway, which inspects the HTTP requests this finding needs",
		})
		total -= 80
	}

	// Clamp to [0, 1000]
	if total < 0 {
		total = 0
	} else if total > 1000 {
		total = 1000
	}
	breakdown.TotalScore = total

	// Determine Band: critical >= 800, high >= 600, medium >= 300, low < 300
	if total >= 800 {
		breakdown.Band = domain.SeverityCritical
	} else if total >= 600 {
		breakdown.Band = domain.SeverityHigh
	} else if total >= 300 {
		breakdown.Band = domain.SeverityMedium
	} else {
		breakdown.Band = domain.SeverityLow
	}

	_ = kevDueDate // KEV due date used in SLA calculations

	return breakdown
}

// BasePointsForSeverity returns default base points per severity level.
func BasePointsForSeverity(sev domain.Severity) int {
	switch sev {
	case domain.SeverityCritical:
		return 600
	case domain.SeverityHigh:
		return 400
	case domain.SeverityMedium:
		return 200
	case domain.SeverityLow:
		return 80
	case domain.SeverityInfo:
		return 10
	default:
		return 80
	}
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
