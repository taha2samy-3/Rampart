package query

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"rampart/internal/domain"
	"rampart/internal/query/grammar"
)

// handleExportFindings streams query findings in CSV, JSON or OCSF formats (docs/21 §6.3).
func (a *API) handleExportFindings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		writeJSONProblem(w, http.StatusUnauthorized, "https://rampart.aspm.dev/problems/unauthorized", "Authentication required")
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "json"
	}
	// An unknown format used to fall through to JSON, so format=sarif returned a file that was not SARIF.
	if format != "json" && format != "csv" && format != "ocsf" {
		writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/validation", fmt.Sprintf("Unknown export format %q: use json, csv or ocsf", format))
		return
	}

	qParam := r.URL.Query().Get("q")
	var parsedQuery *grammar.Query
	if qParam != "" {
		pq, err := grammar.Parse(qParam)
		if err != nil {
			writeJSONProblem(w, http.StatusBadRequest, "https://rampart.aspm.dev/problems/validation", fmt.Sprintf("Invalid query syntax: %v", err))
			return
		}
		parsedQuery = &pq
		expandMe(parsedQuery, a.callerEmail(r))
	}

	// Max export limit 50,000 records
	exportLimit := 50000

	querier, ok := a.store.(FindingQuerier)
	if !ok {
		writeJSONProblem(w, http.StatusNotImplemented, "https://rampart.aspm.dev/problems/unsupported", "Store does not support finding queries")
		return
	}

	// One more than the limit tells whether the export was cut; the client is told so (D84), never left to guess.
	findings, err := querier.QueryFindings(r.Context(), tenantID, parsedQuery, "-score", exportLimit+1, nil)
	if err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
	}
	if len(findings) > exportLimit {
		findings = findings[:exportLimit]
		w.Header().Set("X-Export-Truncated", "true")
		w.Header().Set("X-Export-Limit", fmt.Sprintf("%d", exportLimit))
	}

	switch format {
	case "csv":
		a.streamCSV(w, findings)
	case "ocsf":
		a.streamOCSF(w, findings)
	default:
		a.streamJSON(w, findings)
	}
}

func (a *API) streamCSV(w http.ResponseWriter, findings []*domain.Finding) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="findings-export.csv"`)
	w.Header().Set("X-Accel-Buffering", "no")

	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{
		"id", "rule_id", "scanner_family", "title", "severity", "category",
		"state", "location", "risk_score", "first_seen", "last_seen",
	}
	_ = writer.Write(header)

	for _, f := range findings {
		locStr := f.Location.PrimaryPath()
		// Titles, rules and paths come from scanners: a cell a spreadsheet would run as a formula is defused, as
		// the audit export does (D46, D84; CWE-1236).
		row := []string{
			f.ID.String(),
			csvSafe(f.RuleID),
			csvSafe(f.RuleScannerFamily),
			csvSafe(f.Title),
			string(f.Severity),
			string(f.Category),
			string(f.State),
			csvSafe(locStr),
			fmt.Sprintf("%d", f.RiskScore),
			f.FirstSeen.Format(time.RFC3339),
			f.LastSeen.Format(time.RFC3339),
		}
		_ = writer.Write(row)
	}
}

func (a *API) streamJSON(w http.ResponseWriter, findings []*domain.Finding) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="findings-export.json"`)
	w.Header().Set("X-Accel-Buffering", "no")

	_ = json.NewEncoder(w).Encode(map[string]any{
		"total":    len(findings),
		"findings": findings,
	})
}

// OCSF export: class 2007, Application Security Posture Finding, schema 1.5.0 (ADR 0003, D86). The required
// attributes were read from schema.ocsf.io/1.5.0: activity_id, category_uid, class_uid, type_uid, severity_id, time,
// cloud{provider}, finding_info{uid}, metadata{product, version}; and at least one of application, compliance,
// remediation or vulnerabilities.
const ocsfVersion = "1.5.0"

type ocsfFinding struct {
	ActivityID      int                 `json:"activity_id"`  // 1 Create: the record states a finding
	CategoryUID     int                 `json:"category_uid"` // 2 Findings
	ClassUID        int                 `json:"class_uid"`    // 2007 Application Security Posture Finding
	TypeUID         int                 `json:"type_uid"`     // class_uid * 100 + activity_id
	Time            int64               `json:"time"`         // epoch millis
	SeverityID      int                 `json:"severity_id"`  // 1 Informational … 5 Critical
	Severity        string              `json:"severity"`
	StatusID        int                 `json:"status_id"` // 1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 99 Other
	Status          string              `json:"status"`
	Message         string              `json:"message"`
	Cloud           ocsfCloud           `json:"cloud"`
	FindingInfo     ocsfInfo            `json:"finding_info"`
	Metadata        ocsfMeta            `json:"metadata"`
	Application     ocsfApplication     `json:"application"`
	Vulnerabilities []ocsfVulnerability `json:"vulnerabilities,omitempty"`
}

// ocsfCloud is required by the class. Rampart does not know where the scanned application is hosted; the provider
// is stated as unknown rather than guessed.
type ocsfCloud struct {
	Provider string `json:"provider"`
}

type ocsfInfo struct {
	UID           string   `json:"uid"`
	Title         string   `json:"title"`
	Desc          string   `json:"desc,omitempty"`
	Types         []string `json:"types"`
	CreatedTime   int64    `json:"created_time"`
	FirstSeenTime int64    `json:"first_seen_time"`
	LastSeenTime  int64    `json:"last_seen_time"`
}

type ocsfMeta struct {
	Version string `json:"version"`
	Product struct {
		Name    string `json:"name"`
		Vendor  string `json:"vendor_name"`
		Version string `json:"version"`
	} `json:"product"`
}

type ocsfApplication struct {
	UID string `json:"uid"`
}

type ocsfVulnerability struct {
	Title string   `json:"title,omitempty"`
	CVE   *ocsfUID `json:"cve,omitempty"`
	CWE   *ocsfUID `json:"cwe,omitempty"`
}

type ocsfUID struct {
	UID string `json:"uid"`
}

// eventTime is when the finding last changed, or when it was last seen if no change time is stored.
func eventTime(f *domain.Finding) int64 {
	if !f.UpdatedAt.IsZero() {
		return f.UpdatedAt.UnixMilli()
	}
	return f.LastSeen.UnixMilli()
}

// toOCSF maps one finding to class 2007.
func toOCSF(f *domain.Finding) ocsfFinding {
	sevID := 0
	switch f.Severity {
	case domain.SeverityCritical:
		sevID = 5
	case domain.SeverityHigh:
		sevID = 4
	case domain.SeverityMedium:
		sevID = 3
	case domain.SeverityLow:
		sevID = 2
	case domain.SeverityInfo:
		sevID = 1
	}
	statusID := 99
	switch f.State {
	case domain.StateOpen:
		statusID = 1
	case domain.StateUnderInvestigation, domain.StateAffected:
		statusID = 2
	case domain.StateRiskAccepted, domain.StateNotAffected, domain.StateOutOfScope, domain.StateDuplicate:
		statusID = 3
	case domain.StateFixed:
		statusID = 4
	}
	item := ocsfFinding{
		ActivityID: 1, CategoryUID: 2, ClassUID: 2007, TypeUID: 2007*100 + 1,
		Time: eventTime(f), SeverityID: sevID, Severity: string(f.Severity),
		StatusID: statusID, Status: string(f.State), Message: f.Title,
		Cloud: ocsfCloud{Provider: "unknown"},
		FindingInfo: ocsfInfo{
			UID: f.ID.String(), Title: f.Title, Desc: f.Description,
			Types:       []string{string(f.Category), f.RuleScannerFamily},
			CreatedTime: f.FirstSeen.UnixMilli(), FirstSeenTime: f.FirstSeen.UnixMilli(), LastSeenTime: f.LastSeen.UnixMilli(),
		},
		Application: ocsfApplication{UID: f.ApplicationID.String()},
	}
	item.Metadata.Version = ocsfVersion
	item.Metadata.Product.Name = "Rampart"
	item.Metadata.Product.Vendor = "Rampart"
	item.Metadata.Product.Version = "v1alpha1"
	if f.VulnerabilityID != nil && *f.VulnerabilityID != "" {
		item.Vulnerabilities = append(item.Vulnerabilities, ocsfVulnerability{Title: f.Title, CVE: &ocsfUID{UID: *f.VulnerabilityID}})
	}
	for _, c := range f.CWEs {
		item.Vulnerabilities = append(item.Vulnerabilities, ocsfVulnerability{Title: f.Title, CWE: &ocsfUID{UID: fmt.Sprintf("CWE-%d", c)}})
	}
	return item
}

func (a *API) streamOCSF(w http.ResponseWriter, findings []*domain.Finding) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="findings-ocsf.json"`)
	w.Header().Set("X-Accel-Buffering", "no")
	list := make([]ocsfFinding, 0, len(findings))
	for _, f := range findings {
		list = append(list, toOCSF(f))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"class":    "Application Security Posture Finding (OCSF 2007, schema 1.5.0)",
		"findings": list,
	})
}
