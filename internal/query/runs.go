package query

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query/sqlbuilder"
	"rampart/internal/store"
)

// RunView is an ingest run as the UI shows it (docs/13, the ingest run page).
type RunView struct {
	domain.IngestRun
	Scanners []string `json:"scanners"` // the tools in the report
	// Ephemeral is true for a run from an untracked ref: it never changed the inventory (D10).
	Ephemeral bool `json:"ephemeral"`
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.runView(r, tenantID, run))
}
