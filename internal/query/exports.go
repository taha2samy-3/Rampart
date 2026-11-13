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
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", "Store does not support finding queries")
		return
	}

	findings, err := querier.QueryFindings(r.Context(), tenantID, parsedQuery, "-score", exportLimit, nil)
	if err != nil {
		writeJSONProblem(w, http.StatusInternalServerError, "https://rampart.aspm.dev/problems/internal", err.Error())
		return
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
		row := []string{
			f.ID.String(),
			f.RuleID,
			f.RuleScannerFamily,
			f.Title,
			string(f.Severity),
			string(f.Category),
			string(f.State),
			locStr,
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

// OCSF Detection Finding mapping (OCSF Class 2001)
type ocsfFinding struct {
	ClassUID    int      `json:"class_uid"`    // 2001
	CategoryUID int      `json:"category_uid"` // 2 (Findings)
	ActivityID  int      `json:"activity_id"`  // 1 (Create)
	Time        int64    `json:"time"`         // epoch millis
	SeverityID  int      `json:"severity_id"`  // 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	Message     string   `json:"message"`
	FindingInfo ocsfInfo `json:"finding_info"`
	Metadata    ocsfMeta `json:"metadata"`
}

type ocsfInfo struct {
	UID         string   `json:"uid"`
	Title       string   `json:"title"`
	Desc        string   `json:"desc"`
	Types       []string `json:"types"`
	CreatedTime int64    `json:"created_time"`
}

type ocsfMeta struct {
	Product struct {
		Name    string `json:"name"`
		Vendor  string `json:"vendor_name"`
		Version string `json:"version"`
	} `json:"product"`
}

func (a *API) streamOCSF(w http.ResponseWriter, findings []*domain.Finding) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="findings-ocsf.json"`)
	w.Header().Set("X-Accel-Buffering", "no")

	ocsfList := make([]ocsfFinding, 0, len(findings))
	for _, f := range findings {
		sevID := 3
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

		item := ocsfFinding{
			ClassUID:    2001,
			CategoryUID: 2,
			ActivityID:  1,
			Time:        f.CreatedAt.UnixMilli(),
			SeverityID:  sevID,
			Severity:    string(f.Severity),
			Status:      string(f.State),
			Message:     f.Title,
			FindingInfo: ocsfInfo{
				UID:         f.ID.String(),
				Title:       f.Title,
				Desc:        f.Description,
				Types:       []string{string(f.Category), f.RuleScannerFamily},
				CreatedTime: f.FirstSeen.UnixMilli(),
			},
		}
		item.Metadata.Product.Name = "Rampart ASPM"
		item.Metadata.Product.Vendor = "Rampart"
		item.Metadata.Product.Version = "1.0.0"

		ocsfList = append(ocsfList, item)
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"class":    "Security Finding (OCSF 2001)",
		"findings": ocsfList,
	})
}
