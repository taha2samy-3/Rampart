package query

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query/grammar"
	"rampart/internal/store"
)

// MaxBulk is how many findings one bulk request may change. Larger bulk operations run as jobs in docs/11;
// there is no job runner for them yet, so a bigger match is refused rather than half done.
const MaxBulk = 1000

// PatchFindingRequest is a human decision on one finding (docs/11 PATCH /findings/{id}).
type PatchFindingRequest struct {
	State           string    `json:"state,omitempty"`
	Justification   string    `json:"justification,omitempty"`
	ImpactStatement string    `json:"impactStatement,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	SeverityReason  string    `json:"severityReason,omitempty"`
	Tags            *[]string `json:"tags,omitempty"`
	DuplicateOf     string    `json:"duplicateOf,omitempty"`
	Note            string    `json:"note,omitempty"`
	// Version is the version the caller read; the If-Match header says the same and wins. Without either,
	// the decision applies to the version read at the start of the request.
	Version *int `json:"version,omitempty"`
}

func (p PatchFindingRequest) toTriage() (domain.TriageRequest, error) {
	req := domain.TriageRequest{
		State: domain.FindingState(p.State), Justification: p.Justification, ImpactStatement: p.ImpactStatement,
		Severity: p.Severity, SeverityReason: p.SeverityReason, Tags: p.Tags, Note: p.Note,
	}
	if p.DuplicateOf != "" {
		id, err := uuid.Parse(p.DuplicateOf)
		if err != nil {
			return req, &domain.TriageError{Msg: "duplicateOf is not a finding id"}
		}
		req.DuplicateOf = &id
	}
	return req, nil
}

// requireRole authenticates the caller and checks it has at least min (docs/07: a viewer reads, a triager
// decides). It answers the request itself and returns false when it refuses.
func (a *API) requireRole(w http.ResponseWriter, r *http.Request, min auth.Role) (uuid.UUID, *auth.ContextUser, bool) {
	user, ok := auth.FromContext(r.Context())
	if !ok {
		var err error
		user, err = a.authn.AuthenticateRequest(r)
		if err != nil || user == nil || user.TenantID == domain.NilID {
			if errors.Is(err, auth.ErrCSRF) {
				problem(w, http.StatusForbidden, "forbidden", "Missing or invalid CSRF token")
				return uuid.Nil, nil, false
			}
			problem(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
			return uuid.Nil, nil, false
		}
	}
	if user.Role.Rank() < min.Rank() {
		problem(w, http.StatusForbidden, "forbidden", "Your role does not allow this: it needs "+string(min))
		return uuid.Nil, nil, false
	}
	return user.TenantID, user, true
}

// actorOf names who decided, for the timeline.
func actorOf(u *auth.ContextUser) string {
	switch {
	case u.Email != "":
		return "user:" + u.Email
	case u.Subject != "":
		return "user:" + u.Subject
	}
	return "user"
}

// ifMatch reads the version from If-Match ("3", W/"3" or "\"3\"").
func ifMatch(r *http.Request) (int, bool) {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	v = strings.TrimPrefix(v, "W/")
	v = strings.Trim(v, `"`)
	n, err := strconv.Atoi(v)
	return n, err == nil && v != ""
}

// triageOne applies a decision to one finding and stores it. The error is one the API maps to a status.
func (a *API) triageOne(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, p PatchFindingRequest, expected *int, actor string) (*domain.Finding, []*domain.Occurrence, error) {
	finding, occs, err := a.store.GetFinding(ctx, tenantID, id)
	if err != nil || finding == nil {
		return nil, nil, store.ErrNotFound
	}
	req, err := p.toTriage()
	if err != nil {
		return nil, nil, err
	}
	if req.DuplicateOf != nil { // the original must be another finding of this tenant
		if orig, _, derr := a.store.GetFinding(ctx, tenantID, *req.DuplicateOf); derr != nil || orig == nil {
			return nil, nil, &domain.TriageError{Msg: "duplicateOf is not a finding of this tenant"}
		}
	}
	version := finding.Version
	if expected != nil {
		version = *expected
	}
	if version != finding.Version { // the caller read an older version: say so before doing any work
		return nil, nil, store.ErrVersionConflict
	}
	events, err := domain.ApplyTriage(finding, req, actor, time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	// A decision can move the score (a severity override) and the SLA (a state that is active again): store both.
	if a.scorer != nil {
		if err := a.scorer.ScoreBatch(ctx, tenantID, finding.ApplicationID, []*domain.Finding{finding}); err != nil {
			return nil, nil, err
		}
	}
	if err := a.store.UpdateFindingTriage(ctx, tenantID, finding, version, events); err != nil {
		return nil, nil, err
	}
	return finding, occs, nil
}

func triageProblem(w http.ResponseWriter, err error) {
	var te *domain.TriageError
	switch {
	case errors.As(err, &te):
		problem(w, http.StatusBadRequest, "validation", te.Msg)
	case errors.Is(err, store.ErrNotFound):
		problem(w, http.StatusNotFound, "not-found", "Finding not found")
	case errors.Is(err, store.ErrVersionConflict):
		problem(w, http.StatusConflict, "conflict-version", "The finding was changed by someone else. Reload it and decide again.")
	default:
		problem(w, http.StatusInternalServerError, "internal", "Failed to save the decision")
	}
}

func (a *API) handlePatchFinding(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Finding not found")
		return
	}
	var p PatchFindingRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p) != nil {
		problem(w, http.StatusBadRequest, "validation", "Invalid JSON payload")
		return
	}
	expected := p.Version
	if v, ok := ifMatch(r); ok {
		expected = &v
	}
	finding, occs, err := a.triageOne(r.Context(), tenantID, id, p, expected, actorOf(user))
	if err != nil {
		triageProblem(w, err)
		return
	}
	var vulnIDs []string
	if finding.VulnerabilityID != nil {
		vulnIDs = []string{*finding.VulnerabilityID}
	}
	breakdown := a.breakdown(r.Context(), tenantID, finding, vulnIDs, a.feedsFor(r.Context(), vulnIDs), map[uuid.UUID]*domain.Application{})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"`+strconv.Itoa(finding.Version)+`"`)
	_ = json.NewEncoder(w).Encode(FindingResponse{Finding: finding, Risk: breakdown, SLADueDate: slaDue(finding, breakdown.Band), Occurrences: occs})
}

// BulkRequest is POST /findings/bulk: the same decision for the findings named by id, or matched by a filter.
type BulkRequest struct {
	IDs   []string            `json:"ids,omitempty"`
	Q     string              `json:"q,omitempty"`
	Patch PatchFindingRequest `json:"patch"`
}

// BulkFailure is one finding a bulk decision could not be applied to.
type BulkFailure struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

// BulkResponse reports what a bulk decision did. Each finding is decided on its own: one refusal does not stop the rest.
type BulkResponse struct {
	Matched   int           `json:"matched"`
	Updated   int           `json:"updated"`
	Unchanged int           `json:"unchanged"` // already in the requested state
	Failed    []BulkFailure `json:"failed"`
}

func (a *API) handleBulkTriage(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	var req BulkRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req) != nil {
		problem(w, http.StatusBadRequest, "validation", "Invalid JSON payload")
		return
	}
	if (len(req.IDs) == 0) == (req.Q == "") {
		problem(w, http.StatusBadRequest, "validation", "Give either ids or q, not both and not neither")
		return
	}
	if req.Patch.Version != nil {
		problem(w, http.StatusBadRequest, "validation", "A bulk decision has no single version; leave version out")
		return
	}
	var ids []uuid.UUID
	if len(req.IDs) > 0 {
		for _, s := range req.IDs {
			id, err := uuid.Parse(s)
			if err != nil {
				problem(w, http.StatusBadRequest, "validation", "ids holds a value that is not a finding id")
				return
			}
			ids = append(ids, id)
		}
	} else {
		matched, err := a.matchIDs(r.Context(), tenantID, req.Q)
		if err != nil {
			var ge *grammarError
			if errors.As(err, &ge) {
				problem(w, http.StatusBadRequest, "validation", ge.Error())
			} else {
				problem(w, http.StatusInternalServerError, "internal", "Failed to match findings")
			}
			return
		}
		ids = matched
	}
	if len(ids) > MaxBulk {
		problem(w, http.StatusUnprocessableEntity, "validation", "More than "+strconv.Itoa(MaxBulk)+" findings match. Narrow the filter; larger bulk operations are not supported yet.")
		return
	}
	// Validate the decision once, against a finding that does not exist, so a malformed request fails as a whole
	// instead of failing a thousand times.
	if _, err := req.Patch.toTriage(); err != nil {
		triageProblem(w, err)
		return
	}
	resp := BulkResponse{Matched: len(ids), Failed: []BulkFailure{}}
	actor := actorOf(user)
	for _, id := range ids {
		_, _, err := a.triageOne(r.Context(), tenantID, id, req.Patch, nil, actor)
		switch {
		case err == nil:
			resp.Updated++
		case errors.Is(err, domain.ErrNothingToChange):
			resp.Unchanged++
		default:
			resp.Failed = append(resp.Failed, BulkFailure{ID: id.String(), Error: failureText(err)})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func failureText(err error) string {
	var te *domain.TriageError
	switch {
	case errors.As(err, &te):
		return te.Msg
	case errors.Is(err, store.ErrNotFound):
		return "finding not found"
	case errors.Is(err, store.ErrVersionConflict):
		return "changed by someone else"
	}
	return "could not be saved"
}

type grammarError struct{ msg string }

func (e *grammarError) Error() string { return e.msg }

// matchIDs returns the ids a filter matches, at most MaxBulk+1 (one more than allowed, to know it is too many).
func (a *API) matchIDs(ctx context.Context, tenantID uuid.UUID, q string) ([]uuid.UUID, error) {
	pq, err := grammar.Parse(q)
	if err != nil {
		return nil, &grammarError{"Invalid query syntax: " + err.Error()}
	}
	var found []*domain.Finding
	if fq, ok := a.store.(FindingQuerier); ok {
		found, err = fq.QueryFindings(ctx, tenantID, &pq, "-score", MaxBulk+1, nil)
		if err != nil {
			return nil, err
		}
	} else {
		all, err := a.store.ListFindings(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, f := range all {
			if matchesQuery(f, pq) {
				found = append(found, f)
			}
		}
	}
	ids := make([]uuid.UUID, 0, len(found))
	for _, f := range found {
		ids = append(ids, f.ID)
	}
	return ids, nil
}

// EventsResponse is the timeline of a finding, oldest first.
type EventsResponse struct {
	Items []*domain.FindingEvent `json:"items"`
}

func (a *API) handleFindingEvents(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Finding not found")
		return
	}
	if f, _, err := a.store.GetFinding(r.Context(), tenantID, id); err != nil || f == nil {
		problem(w, http.StatusNotFound, "not-found", "Finding not found")
		return
	}
	events, err := a.store.GetFindingEvents(r.Context(), tenantID, id)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the timeline")
		return
	}
	if events == nil {
		events = []*domain.FindingEvent{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(EventsResponse{Items: events})
}
