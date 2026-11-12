package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
	"rampart/internal/telemetry"
)

// proofStore is what proof files need from the store (PostgreSQL).
type proofStore interface {
	AddProof(ctx context.Context, tenantID uuid.UUID, p *domain.RiskAcceptanceProof) error
	ListProofs(ctx context.Context, tenantID, acceptanceID uuid.UUID) ([]*domain.RiskAcceptanceProof, error)
	GetProof(ctx context.Context, tenantID, acceptanceID, proofID uuid.UUID) (*domain.RiskAcceptanceProof, error)
}

func (a *API) proofs(w http.ResponseWriter) (proofStore, bool) {
	ps, ok := a.store.(proofStore)
	if !ok || a.objects == nil {
		problem(w, http.StatusNotImplemented, "internal", "Proof files need PostgreSQL and object storage")
		return nil, false
	}
	return ps, true
}

// handleAddProof is POST /api/v1/risk-acceptances/{id}/proofs, multipart with one "file" (D60). The person who
// asked for the acceptance, its owner, or a maintainer of its applications may add proof while it is pending or
// in force; a decided-and-closed acceptance is a record and stays as it was.
func (a *API) handleAddProof(w http.ResponseWriter, r *http.Request) {
	tenantID, user, scope, ok := a.requireAny(w, r, auth.RoleTriager)
	if !ok {
		return
	}
	ps, ok := a.proofs(w)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Risk acceptance not found")
		return
	}
	ra, err := a.store.GetRiskAcceptance(r.Context(), tenantID, id)
	if err != nil {
		acceptanceProblem(w, err)
		return
	}
	actor := actorOf(user)
	if ra.Requester != actor && ra.Owner != actor && !a.allowedOnFindings(r.Context(), tenantID, scope, auth.RoleMaintainer, ra.FindingIDs) {
		problem(w, http.StatusForbidden, "forbidden", "Only the person who asked for this risk acceptance, its owner, or a maintainer of its applications can add proof")
		return
	}
	if ra.Status != domain.AcceptancePending && ra.Status != domain.AcceptanceApproved {
		problem(w, http.StatusConflict, "conflict-version", fmt.Sprintf("This risk acceptance is %s; proof can be added while it is pending or approved", ra.Status))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, domain.MaxProofBytes+1<<20) // the file plus the multipart framing
	file, header, err := r.FormFile("file")
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", fmt.Sprintf("Send one file in the form field \"file\", at most %d MiB", domain.MaxProofBytes>>20))
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, domain.MaxProofBytes+1))
	if err != nil {
		problem(w, http.StatusBadRequest, "validation", "The file could not be read")
		return
	}
	name, contentType, err := domain.CheckProof(header.Filename, data[:min(len(data), 64<<10)], int64(len(data)))
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "validation", err.Error())
		return
	}
	sum := sha256.Sum256(data)
	p := &domain.RiskAcceptanceProof{
		ID: domain.NewID(), RiskAcceptanceID: ra.ID, Name: name, ContentType: contentType, SizeBytes: int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]), UploadedBy: actor,
	}
	// A name the server chose, under the tenant's prefix; the file's own name is only shown (OWASP).
	p.ObjectRef = fmt.Sprintf("tenants/%s/acceptances/%s/%s", tenantID, ra.ID, p.ID)
	if err := a.objects.Write(r.Context(), p.ObjectRef, data, contentType); err != nil {
		problem(w, http.StatusBadGateway, "upstream-unavailable", "The file could not be stored")
		return
	}
	if err := ps.AddProof(r.Context(), tenantID, p); err != nil {
		_ = a.objects.Delete(context.WithoutCancel(r.Context()), p.ObjectRef) // nothing points at it
		if errors.Is(err, store.ErrTooManyProofs) {
			problem(w, http.StatusConflict, "conflict-version", fmt.Sprintf("A risk acceptance holds at most %d proof files", domain.MaxProofs))
			return
		}
		acceptanceProblem(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// handleListProofs is GET /api/v1/risk-acceptances/{id}/proofs: anyone who may read the acceptance.
func (a *API) handleListProofs(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	ps, ok := a.proofs(w)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Risk acceptance not found")
		return
	}
	items, err := ps.ListProofs(r.Context(), tenantID, id)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", "Failed to list proof files")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleGetProof is GET /api/v1/risk-acceptances/{id}/proofs/{proof}: the file, always as a download, with the
// type the server determined, never rendered in the page; every download is in the audit log, like a raw
// report (D51).
func (a *API) handleGetProof(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	ps, ok := a.proofs(w)
	if !ok {
		return
	}
	id, err1 := uuid.Parse(r.PathValue("id"))
	pid, err2 := uuid.Parse(r.PathValue("proof"))
	if err1 != nil || err2 != nil {
		problem(w, http.StatusNotFound, "not-found", "Proof file not found")
		return
	}
	p, err := ps.GetProof(r.Context(), tenantID, id, pid)
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "Proof file not found")
		return
	}
	rc, err := a.objects.Open(r.Context(), p.ObjectRef)
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "The proof file is no longer stored")
		return
	}
	defer func() { _ = rc.Close() }()
	_ = a.store.RecordAudit(r.Context(), auth.AuditEvent{
		TenantID: tenantID, Actor: actorOf(user), Action: "GET /api/v1/risk-acceptances/{id}/proofs/{proof}",
		ResourceType: "risk-acceptances", ResourceID: id.String(),
		Detail: map[string]any{"proof": p.ID.String(), "bytes": p.SizeBytes}, RequestID: telemetry.RequestID(r.Context()),
	})
	w.Header().Set("Content-Type", p.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": p.Name}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.FormatInt(p.SizeBytes, 10))
	_, _ = io.Copy(w, rc)
}
