package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/objectstore"
	"rampart/internal/query/sqlbuilder"
	"rampart/internal/store"
	"rampart/internal/telemetry"
)

// RunView is an ingest run as the UI shows it (docs/13, the ingest run page).
type RunView struct {
	domain.IngestRun
	Scanners []string `json:"scanners"` // the tools in the report
	// Ephemeral is true for a run from an untracked ref: it never changed the inventory (D10).
	Ephemeral bool `json:"ephemeral"`
	// HasReport says the raw report can be downloaded (GET /runs/{id}/report).
	HasReport bool `json:"has_report"`
	// RecordErrorList is the first records the run could not read, with where they are (GET of one run only).
	RecordErrorList []domain.RecordError `json:"record_error_list,omitempty"`
}

// ListRunsResponse is one page of runs, newest first.
type ListRunsResponse struct {
	Items      []RunView `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

func (a *API) runView(r *http.Request, tenantID uuid.UUID, run *domain.IngestRun) RunView {
	v := RunView{IngestRun: *run, Scanners: []string{}}
	if fams, err := a.store.ListRunScopes(r.Context(), tenantID, run.ID); err == nil && fams != nil {
		v.Scanners = fams
	}
	v.Ephemeral = ingest.IsEphemeral(run.Context.Branch, nil)
	v.HasReport = a.objects != nil && run.UploadID != nil && run.ReportPurgedAt == nil
	return v
}

func (a *API) handleListRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, MaxLimit)
	}
	var after *store.RunPosition
	if c := r.URL.Query().Get("cursor"); c != "" {
		cur, err := sqlbuilder.DecodeCursor(c, a.hmacKey)
		if err != nil || cur.SortKey != "-created" {
			problem(w, http.StatusBadRequest, "validation", "The cursor is invalid")
			return
		}
		at, terr := time.Parse(time.RFC3339Nano, cur.SortVal)
		id, ierr := uuid.Parse(cur.ID)
		if terr != nil || ierr != nil {
			problem(w, http.StatusBadRequest, "validation", "The cursor is invalid")
			return
		}
		after = &store.RunPosition{CreatedAt: at, ID: id}
	}
	runs, err := a.store.ListIngestRuns(r.Context(), tenantID, limit+1, after)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list runs")
		return
	}
	next := ""
	if len(runs) > limit {
		runs = runs[:limit]
		last := runs[len(runs)-1]
		next = (&sqlbuilder.Cursor{SortKey: "-created", SortVal: last.CreatedAt.UTC().Format(time.RFC3339Nano), ID: last.ID.String()}).Encode(a.hmacKey)
	}
	items := make([]RunView, 0, len(runs))
	for _, run := range runs {
		items = append(items, a.runView(r, tenantID, run))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ListRunsResponse{Items: items, NextCursor: next})
}

func (a *API) handleGetRun(w http.ResponseWriter, r *http.Request) {
	tenantID, err := a.resolveTenant(r)
	if err != nil {
		problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}
	id, perr := uuid.Parse(r.PathValue("id"))
	if perr != nil {
		problem(w, http.StatusNotFound, "not-found", "Run not found")
		return
	}
	run, err := a.store.GetIngestRun(r.Context(), tenantID, id)
	if err != nil || run == nil {
		status := http.StatusNotFound
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			status = http.StatusInternalServerError
		}
		problem(w, status, "not-found", "Run not found")
		return
	}
	view := a.runView(r, tenantID, run)
	if re, ok := a.store.(store.RunErrors); ok && run.Stats.RecordErrors > 0 {
		if list, lerr := re.ListRunErrors(r.Context(), tenantID, run.ID); lerr == nil {
			view.RecordErrorList = list
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// handleRunReport is GET /api/v1/runs/{id}/report: the report as the scanner wrote it. Raw reports can hold the
// secrets a scanner found (a secret scanner's output names them), so this takes the maintainer role on the run's
// application, and every download is in the audit log. The bytes pass through the API: they are not made public
// by a link.
func (a *API) handleRunReport(w http.ResponseWriter, r *http.Request) {
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleMaintainer)
	if !ok {
		return
	}
	id, perr := uuid.Parse(r.PathValue("id"))
	if perr != nil {
		problem(w, http.StatusNotFound, "not-found", "Run not found")
		return
	}
	run, err := a.store.GetIngestRun(r.Context(), tenantID, id)
	if err != nil || run == nil {
		problem(w, http.StatusNotFound, "not-found", "Run not found")
		return
	}
	if !scope.allows(run.ApplicationID, auth.RoleMaintainer) {
		problem(w, http.StatusForbidden, "forbidden", "Downloading a raw report needs the maintainer role on the application it belongs to")
		return
	}
	getter, gok := a.store.(interface {
		GetUpload(ctx context.Context, tenantID, id uuid.UUID) (*domain.Upload, error)
	})
	if run.ReportPurgedAt != nil {
		problem(w, http.StatusNotFound, "not-found", "The report was removed on "+run.ReportPurgedAt.UTC().Format("2006-01-02")+" by the retention policy")
		return
	}
	if a.objects == nil || !gok || run.UploadID == nil {
		problem(w, http.StatusNotFound, "not-found", "This run has no stored report")
		return
	}
	up, err := getter.GetUpload(r.Context(), tenantID, *run.UploadID)
	if err != nil || up == nil {
		problem(w, http.StatusNotFound, "not-found", "This run has no stored report")
		return
	}
	rc, err := a.objects.Open(r.Context(), up.ObjectRef)
	if err != nil {
		if errors.Is(err, objectstore.ErrNotFound) {
			problem(w, http.StatusNotFound, "not-found", "The report is no longer stored")
			return
		}
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the report")
		return
	}
	defer func() { _ = rc.Close() }()
	_ = a.store.RecordAudit(r.Context(), auth.AuditEvent{
		TenantID: tenantID, Actor: actorOf(user), Action: "GET /api/v1/runs/{id}/report", ResourceType: "runs", ResourceID: id.String(),
		Detail: map[string]any{"bytes": up.SizeBytes, "format": run.Format}, RequestID: telemetry.RequestID(r.Context()),
	})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%s.json"`, id.String()[:8]))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if up.SizeBytes > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(up.SizeBytes, 10))
	}
	_, _ = io.Copy(w, rc)
}
