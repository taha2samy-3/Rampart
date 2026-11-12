package query

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/store"
	"rampart/internal/telemetry"
)

// statusWriter remembers the status a handler wrote.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the real writer (flushing, deadlines).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Audited records every call that changes something (POST, PUT, PATCH, DELETE on /api/v1 and /ingest/v1) in the
// append-only audit log, with who did it, which route, the resource, and the answer's status (docs/07, D46).
// A call that was not authenticated has no tenant and is not recorded here. A failed write is logged and does
// not fail the request: the audit log must not be a way to take the API down.
func (a *API) Audited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMutation(r.Method) || (!strings.HasPrefix(r.URL.Path, "/api/v1/") && !strings.HasPrefix(r.URL.Path, "/ingest/v1/")) {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		a.recordCall(r, sw.status)
	})
}

func isMutation(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete
}

func (a *API) recordCall(r *http.Request, status int) {
	if a.authn == nil {
		return
	}
	user, ok := auth.FromContext(r.Context())
	if !ok {
		var err error
		if user, err = a.authn.AuthenticateRequest(r); err != nil || user == nil || user.TenantID == uuid.Nil {
			return
		}
	}
	rt := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/ingest/v1/")
	if i := strings.IndexByte(rt, '/'); i >= 0 {
		rt = rt[:i]
	}
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200]
	}
	ip := r.RemoteAddr
	if i := strings.LastIndexByte(ip, ':'); i > 0 {
		ip = strings.Trim(ip[:i], "[]")
	}
	err := a.store.RecordAudit(r.Context(), auth.AuditEvent{
		TenantID: user.TenantID, Actor: actorOf(user), Action: firstNonEmptyStr(r.Pattern, r.Method+" "+r.URL.Path),
		ResourceType: rt, ResourceID: r.PathValue("id"),
		Detail: map[string]any{"method": r.Method, "path": r.URL.Path, "status": status},
		IP:     ip, UserAgent: ua, RequestID: telemetry.RequestID(r.Context()),
	})
	if err != nil {
		slog.Error("audit write failed", "route", r.Pattern, "err", err)
	}
}

func encodeAuditCursor(at time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixNano(), 10) + "|" + id.String()))
}

func decodeAuditCursor(s string) (time.Time, uuid.UUID, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, uuid.Nil, false
	}
	ns, idStr, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, false
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	id, err2 := uuid.Parse(idStr)
	if err != nil || err2 != nil {
		return time.Time{}, uuid.Nil, false
	}
	return time.Unix(0, n).UTC(), id, true
}

// handleListAudit is GET /api/v1/audit (docs/11): an administrator reads the log, newest first, filtered by
// actor, action, resourceType and a time range. `format=csv` or `format=ndjson` exports instead of paging.
// A cursor is not signed: it carries only a position, and the tenant comes from the session, not from it.
func (a *API) handleListAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleAdmin)
	if !ok {
		return
	}
	rd, ok := a.store.(store.AuditReader)
	if !ok {
		problem(w, http.StatusNotImplemented, "unsupported", "The audit log needs PostgreSQL")
		return
	}
	q := r.URL.Query()
	f := store.AuditFilter{Actor: q.Get("actor"), Action: q.Get("action"), ResourceType: q.Get("resourceType")}
	for k, dst := range map[string]*time.Time{"from": &f.From, "to": &f.To} {
		if v := q.Get(k); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				problem(w, http.StatusBadRequest, "validation", k+" is not an RFC 3339 time")
				return
			}
			*dst = t
		}
	}
	if c := q.Get("cursor"); c != "" {
		at, id, ok := decodeAuditCursor(c)
		if !ok {
			problem(w, http.StatusBadRequest, "validation", "The cursor is not valid")
			return
		}
		f.AfterAt, f.AfterID = at, id
	}
	format := q.Get("format")
	if format != "" && format != "json" && format != "csv" && format != "ndjson" {
		problem(w, http.StatusBadRequest, "validation", "format is json, csv or ndjson")
		return
	}
	limit, max := 100, 1000
	if format == "csv" || format == "ndjson" {
		limit, max = 10000, 50000
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= max {
		limit = n
	}
	rows, err := rd.ListAudit(r.Context(), tenantID, f, limit+1)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to read the audit log")
		return
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		next = encodeAuditCursor(rows[len(rows)-1].At, rows[len(rows)-1].ID)
	}
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
		if next != "" {
			w.Header().Set("X-Next-Cursor", next)
		}
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"at", "actor", "action", "resource_type", "resource_id", "ip", "request_id", "detail"})
		for _, e := range rows {
			_ = cw.Write([]string{e.At.Format(time.RFC3339Nano), csvSafe(e.Actor), e.Action, e.ResourceType, csvSafe(e.ResourceID), e.IP, e.RequestID, string(e.Detail)})
		}
		cw.Flush()
	case "ndjson":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="audit.ndjson"`)
		if next != "" {
			w.Header().Set("X-Next-Cursor", next)
		}
		enc := json.NewEncoder(w)
		for _, e := range rows {
			_ = enc.Encode(e)
		}
	default:
		writeJSON(w, http.StatusOK, map[string]any{"items": rows, "next_cursor": next})
	}
}

// csvSafe defuses a cell a spreadsheet would run as a formula (CWE-1236): an actor name is chosen by the actor.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
