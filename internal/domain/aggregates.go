package domain

import (
	"time"

	"github.com/google/uuid"
)

// Bands are the risk bands, from the worst.
var Bands = []string{"critical", "high", "medium", "low"}

// AppSummary is what an application looks like from its active findings (docs/13: the Applications list and the
// summary of the application page).
type AppSummary struct {
	ID             uuid.UUID `json:"id"`
	Slug           string    `json:"slug"`
	Name           string    `json:"name"`
	Criticality    string    `json:"business_criticality"`
	InternetFacing bool      `json:"internet_facing"`
	// Open counts the active findings (open, under investigation, affected) by risk band.
	Open map[string]int `json:"open"`
	// RiskScore is the highest score of an active finding (docs/06: application risk is the max).
	RiskScore int `json:"risk_score"`
	// Exposure counts the active critical and high findings.
	Exposure    int        `json:"exposure_count"`
	SLABreached int        `json:"sla_breached"`
	LastScan    *time.Time `json:"last_scan,omitempty"`
}

// SLAStanding says how a set of findings did against their deadlines over the last 90 days: those resolved in time,
// those resolved late, and those still open past their deadline. Adherence is within / (within + late + breached),
// and absent when none of them has had a deadline yet.
type SLAStanding struct {
	Within    int      `json:"within"`
	Late      int      `json:"late"`
	Breached  int      `json:"breached"`
	Adherence *float64 `json:"adherence,omitempty"`
}

// MTTR is the mean days from first seen to fixed, over the findings fixed in the last 90 days, by risk band.
type MTTR struct {
	Band  string  `json:"band"`
	Days  float64 `json:"days"`
	Fixed int     `json:"fixed"`
}

// CoverageRow is the last completed scan of one asset by one scanner (docs/13: the Coverage tab).
type CoverageRow struct {
	AssetID  uuid.UUID `json:"asset_id"`
	Asset    string    `json:"asset"`
	Scanner  string    `json:"scanner"`
	LastScan time.Time `json:"last_scan"`
}

// AppDetail is the summary of one application with what the application page adds to it.
type AppDetail struct {
	AppSummary
	SLA      SLAStanding   `json:"sla"`
	MTTR     []MTTR        `json:"mttr"`
	Coverage []CoverageRow `json:"coverage"`
}

// Changes counts what moved since a point in time (docs/13: "what changed since yesterday").
type Changes struct {
	Since    time.Time `json:"since"`
	New      int       `json:"new"`
	Reopened int       `json:"reopened"`
	Fixed    int       `json:"fixed"`
}

// OverdueFinding is an active finding past its SLA deadline.
type OverdueFinding struct {
	ID       uuid.UUID `json:"id"`
	Title    string    `json:"title"`
	Band     string    `json:"band"`
	Due      time.Time `json:"due"`
	AppSlug  string    `json:"app_slug"`
	AppName  string    `json:"app_name"`
	Severity string    `json:"severity"`
}

// Overview is the opening screen: what changed, what is overdue, how the deadlines are going, where the risk is.
type Overview struct {
	Changes      Changes          `json:"changes"`
	Open         map[string]int   `json:"open"`
	Overdue      []OverdueFinding `json:"overdue"`
	OverdueTotal int              `json:"overdue_total"`
	SLA          SLAStanding      `json:"sla"`
	TopApps      []AppSummary     `json:"top_apps"`
	// Gaps are applications that have not been scanned for 14 days, or never.
	Gaps []AppSummary `json:"coverage_gaps"`
}

// TrendPoint is the state of the inventory at the end of one day.
type TrendPoint struct {
	Day    time.Time `json:"day"`
	Open   int       `json:"open"`   // active at the end of the day
	New    int       `json:"new"`    // first seen that day
	Closed int       `json:"closed"` // fixed that day
}
