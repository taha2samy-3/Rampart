package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/telemetry"
)

// TenantLookup resolves tenants by slug or id. Tenant rows are global (no RLS).
type TenantLookup interface {
	GetTenantBySlug(ctx context.Context, slug string) (*domain.Tenant, error)
	GetTenant(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)
}

// HandlerDeps are the collaborators of the browser-facing auth endpoints.
type HandlerDeps struct {
	OIDC     *OIDCClient // nil: no sign-in method configured
	Sessions *SessionManager
	Identity IdentityStore
	Tenants  TenantLookup
	Authn    *Authenticator
	Policy   RolePolicy

	// Local sign-in (break-glass, D3). LocalLoginEnabled is decided by the caller: a bootstrap admin
	// exists and either no identity provider is configured or keepEnabled is set.
	LocalLoginEnabled bool
	Local             LocalAdminStore
	Audit             AuditStore
	LocalLimiter      *RateLimiter // default: 10 attempts per client address per minute

	Product string
	Version string
	Logger  *slog.Logger
}

// Handlers serves /auth/*, /api/v1/ui-config and /api/v1/me* (doc 11, doc 13 section 3, doc 14 section 2).
type Handlers struct{ HandlerDeps }

// NewHandlers applies defaults.
func NewHandlers(d HandlerDeps) *Handlers {
	if d.Product == "" {
		d.Product = "Rampart"
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.LocalLimiter == nil {
		d.LocalLimiter = NewRateLimiter(10, time.Minute)
	}
	return &Handlers{d}
}

// RegisterRoutes mounts the routes. The IdP segment is part of the path (doc 11); only "default" exists in Phase 1.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ui-config", h.uiConfig)
	mux.HandleFunc("GET /auth/login", h.login)
	mux.HandleFunc("GET /auth/oidc/{idp}/callback", h.callback)
	mux.HandleFunc("POST /auth/local/login", h.localLogin)
	mux.HandleFunc("GET /auth/session", h.session)
	mux.HandleFunc("POST /auth/logout", h.logout)
	mux.HandleFunc("POST /auth/tenant", h.switchTenant)
	mux.HandleFunc("GET /api/v1/me", h.me)
	mux.HandleFunc("GET /api/v1/me/tenants", h.meTenants)
	mux.HandleFunc("GET /api/v1/me/permissions", h.mePermissions)
}

const problemBase = "https://rampart.aspm.dev/problems/"

func problem(w http.ResponseWriter, r *http.Request, status int, typ, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": problemBase + typ, "title": title, "status": status, "detail": detail,
		"request_id": telemetry.RequestID(r.Context()),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// uiConfig is public and cacheable (doc 13 section 2): the bundle is identical in every environment.
func (h *Handlers) uiConfig(w http.ResponseWriter, r *http.Request) {
	methods := []map[string]string{}
	if h.OIDC != nil && h.Sessions != nil {
		methods = append(methods, map[string]string{"id": "default", "name": "Single sign-on", "type": "oidc"})
	}
	if h.LocalLoginEnabled && h.Sessions != nil && h.Local != nil {
		methods = append(methods, map[string]string{"id": "local", "name": "Username and password", "type": "password"})
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"product": h.Product, "version": h.Version, "features": []string{},
		"login":  map[string]any{"methods": methods},
		"locale": map[string]string{"default": "en"}, "supportUrl": "",
	})
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// login starts the authorization code flow with PKCE (doc 14 section 2, step 1).
func (h *Handlers) login(w http.ResponseWriter, r *http.Request) {
	if h.OIDC == nil || h.Sessions == nil {
		problem(w, r, http.StatusServiceUnavailable, "upstream-unavailable", "No sign-in method is configured",
			"Set auth.oidc.* and auth.session.keyFile, then restart.")
		return
	}
	// The UI adds idp=<id> when several sign-in methods exist (doc 14 section 4). Phase 1 has one.
	if idp := r.URL.Query().Get("idp"); idp != "" && idp != "default" {
		problem(w, r, http.StatusNotFound, "not-found", "Unknown sign-in method", "")
		return
	}
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		tenant = "default"
	}
	state, err1 := randomToken()
	nonce, err2 := randomToken()
	verifier, err3 := randomToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		problem(w, r, http.StatusInternalServerError, "internal", "Cannot start sign-in", "")
		return
	}
	authURL, err := h.OIDC.AuthCodeURL(r.Context(), state, nonce, verifier)
	if err != nil {
		h.Logger.Error("oidc login", "err", err)
		problem(w, r, http.StatusBadGateway, "upstream-unavailable", "The identity provider is not reachable",
			"Try again in a moment. If it persists, check the issuer URL.")
		return
	}
	st := loginState{
		State: state, Nonce: nonce, Verifier: verifier, Tenant: tenant,
		ReturnTo: SafeReturnTo(r.URL.Query().Get("return_to")), Expires: h.Sessions.now().Add(10 * 60e9),
	}
	if err := h.Sessions.setLoginState(w, st); err != nil {
		problem(w, r, http.StatusInternalServerError, "internal", "Cannot start sign-in", "")
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// loginError sends the browser back to the SPA login screen with a short code it can explain.
func loginError(w http.ResponseWriter, r *http.Request, code string) {
	telemetry.RecordLogin(r.Context(), "oidc", "failure")
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusFound)
}

func (h *Handlers) callback(w http.ResponseWriter, r *http.Request) {
	if h.OIDC == nil || h.Sessions == nil || r.PathValue("idp") != "default" {
		http.NotFound(w, r)
		return
	}
	st, err := h.Sessions.takeLoginState(w, r)
	q := r.URL.Query()
	if err != nil || q.Get("state") == "" || q.Get("state") != st.State {
		loginError(w, r, "invalid_state")
		return
	}
	if q.Get("error") != "" {
		loginError(w, r, "idp_error")
		return
	}
	claims, err := h.OIDC.Exchange(r.Context(), q.Get("code"), st.Verifier, st.Nonce)
	if err != nil {
		h.Logger.Warn("oidc callback", "err", err)
		if errors.Is(err, ErrEmailUnverified) {
			loginError(w, r, "email_unverified")
			return
		}
		loginError(w, r, "idp_error")
		return
	}
	tenant, err := h.Tenants.GetTenantBySlug(r.Context(), st.Tenant)
	if err != nil || tenant == nil {
		loginError(w, r, "tenant_not_found")
		return
	}
	userID, err := h.Identity.UpsertUser(r.Context(), User{Issuer: claims.Issuer, Subject: claims.Subject, Email: claims.Email, Name: claims.Name})
	if err != nil {
		h.Logger.Error("upsert user", "err", err)
		loginError(w, r, "internal")
		return
	}
	existing, _, err := h.Identity.GetMemberRole(r.Context(), tenant.ID, userID)
	if err != nil {
		loginError(w, r, "internal")
		return
	}
	role := h.Policy.Resolve(claims.Email, claims.Subject, claims.Groups, existing)
	if role == "" {
		loginError(w, r, "no_access")
		return
	}
	if err := h.Identity.UpsertMember(r.Context(), tenant.ID, userID, role); err != nil {
		h.Logger.Error("upsert member", "err", err)
		loginError(w, r, "internal")
		return
	}
	value, rec, err := h.Sessions.Create(r.Context(), tenant.ID, userID)
	if err != nil {
		h.Logger.Error("create session", "err", err)
		loginError(w, r, "internal")
		return
	}
	h.Sessions.SetCookie(w, value, rec.ExpiresAt)
	telemetry.RecordLogin(r.Context(), "oidc", "success")
	http.Redirect(w, r, SafeReturnTo(st.ReturnTo), http.StatusFound)
}

func (h *Handlers) principal(w http.ResponseWriter, r *http.Request) (*ContextUser, bool) {
	u, err := h.Authn.AuthenticateRequest(r)
	if errors.Is(err, ErrCSRF) {
		problem(w, r, http.StatusForbidden, "forbidden", "Missing or invalid CSRF token", "Reload the page and try again.")
		return nil, false
	}
	if err != nil || u == nil {
		problem(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", "Sign in to continue.")
		return nil, false
	}
	return u, true
}

func (h *Handlers) tenantOf(ctx context.Context, id uuid.UUID) map[string]string {
	t, err := h.Tenants.GetTenant(ctx, id)
	if err != nil || t == nil {
		return map[string]string{"id": id.String()}
	}
	return map[string]string{"id": t.ID.String(), "slug": t.Slug, "name": t.DisplayName}
}

// session returns the signed-in person, their tenant and the CSRF token (doc 13 section 3).
func (h *Handlers) session(w http.ResponseWriter, r *http.Request) {
	if h.Sessions == nil {
		problem(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", "Sign in to continue.")
		return
	}
	p, err := h.Sessions.Principal(r)
	if err != nil {
		problem(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", "Sign in to continue.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":      map[string]string{"id": p.Session.UserID.String(), "email": p.Email, "name": p.Name},
		"tenant":    h.tenantOf(r.Context(), p.Session.TenantID),
		"csrfToken": h.Sessions.CSRFToken(p.Session.ID),
		"expiresAt": p.Session.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

func (h *Handlers) logout(w http.ResponseWriter, r *http.Request) {
	if h.Sessions == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if p, err := h.Sessions.Principal(r); err == nil {
		if !h.Sessions.CheckCSRF(r, p.Session.ID) {
			problem(w, r, http.StatusForbidden, "forbidden", "Missing or invalid CSRF token", "Reload the page and try again.")
			return
		}
		_ = h.Sessions.Delete(r.Context(), p.Session)
	}
	h.Sessions.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// switchTenant moves the session to another tenant the person belongs to and rotates the session id (D8).
func (h *Handlers) switchTenant(w http.ResponseWriter, r *http.Request) {
	u, ok := h.principal(w, r)
	if !ok {
		return
	}
	if u.SessionID == uuid.Nil {
		problem(w, r, http.StatusForbidden, "forbidden", "Only browser sessions can switch tenant", "")
		return
	}
	var body struct {
		Tenant string `json:"tenant"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || body.Tenant == "" {
		problem(w, r, http.StatusBadRequest, "validation", "A tenant slug is required", "")
		return
	}
	tenant, err := h.Tenants.GetTenantBySlug(r.Context(), body.Tenant)
	if err != nil || tenant == nil {
		problem(w, r, http.StatusNotFound, "not-found", "Tenant not found", "")
		return
	}
	if _, member, err := h.Identity.GetMemberRole(r.Context(), tenant.ID, u.UserID); err != nil || !member {
		problem(w, r, http.StatusForbidden, "forbidden", "You are not a member of that tenant", "")
		return
	}
	value, rec, err := h.Sessions.Create(r.Context(), tenant.ID, u.UserID)
	if err != nil {
		problem(w, r, http.StatusInternalServerError, "internal", "Cannot switch tenant", "")
		return
	}
	_ = h.Sessions.Delete(r.Context(), SessionRecord{ID: u.SessionID, TenantID: u.TenantID})
	h.Sessions.SetCookie(w, value, rec.ExpiresAt)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) me(w http.ResponseWriter, r *http.Request) {
	u, ok := h.principal(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":   map[string]string{"id": u.UserID.String(), "email": u.Email, "name": u.Name, "subject": u.Subject},
		"tenant": h.tenantOf(r.Context(), u.TenantID), "role": u.Role,
	})
}

func (h *Handlers) meTenants(w http.ResponseWriter, r *http.Request) {
	u, ok := h.principal(w, r)
	if !ok {
		return
	}
	out := []TenantRef{}
	if u.UserID != uuid.Nil {
		list, err := h.Identity.ListUserTenants(r.Context(), u.UserID)
		if err != nil {
			problem(w, r, http.StatusInternalServerError, "internal", "Cannot list tenants", "")
			return
		}
		out = list
	} else if t, err := h.Tenants.GetTenant(r.Context(), u.TenantID); err == nil && t != nil { // API token: its own tenant only
		out = append(out, TenantRef{ID: t.ID, Slug: t.Slug, Name: t.DisplayName})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) mePermissions(w http.ResponseWriter, r *http.Request) {
	u, ok := h.principal(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": u.Role, "scopes": u.Scopes})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *Handlers) audit(r *http.Request, tenantID uuid.UUID, actor, action string, detail map[string]any) {
	if h.Audit == nil {
		return
	}
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200]
	}
	err := h.Audit.RecordAudit(r.Context(), AuditEvent{
		TenantID: tenantID, Actor: actor, Action: action, ResourceType: "session", ResourceID: "local",
		Detail: detail, IP: clientIP(r), UserAgent: ua, RequestID: telemetry.RequestID(r.Context()),
	})
	if err != nil {
		h.Logger.Error("audit write failed", "action", action, "err", err)
	}
}

// localLogin is the break-glass sign-in (D3, doc 14 section 1). It is deliberately narrow: JSON only
// (a cross-site form cannot send it), a request-size cap, a per-address rate limit, a per-account
// lockout stored in the database, identical answers for an unknown user and a wrong password, equal
// work in both cases, and an audit record for every attempt.
func (h *Handlers) localLogin(w http.ResponseWriter, r *http.Request) {
	if !h.LocalLoginEnabled || h.Sessions == nil || h.Local == nil {
		problem(w, r, http.StatusForbidden, "forbidden", "Local sign-in is turned off",
			"Sign in with single sign-on, or ask an administrator to enable the local administrator.")
		return
	}
	if mt := strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]); mt != "application/json" {
		problem(w, r, http.StatusUnsupportedMediaType, "validation", "Send the sign-in as JSON", "")
		return
	}
	if ok, wait := h.LocalLimiter.Allow(clientIP(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		telemetry.RecordLogin(r.Context(), "local", "rate_limited")
		problem(w, r, http.StatusTooManyRequests, "rate-limited", "Too many sign-in attempts", "Wait a minute and try again.")
		return
	}
	var body struct {
		Tenant   string `json:"tenant"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil ||
		body.Username == "" || body.Password == "" || len(body.Username) > 100 || len(body.Password) > 1024 {
		problem(w, r, http.StatusBadRequest, "validation", "A username and a password are required", "")
		return
	}
	if body.Tenant == "" {
		body.Tenant = "default"
	}
	invalid := func() {
		telemetry.RecordLogin(r.Context(), "local", "failure")
		problem(w, r, http.StatusUnauthorized, "unauthorized", "Wrong username or password", "Check them and try again.")
	}

	tenant, err := h.Tenants.GetTenantBySlug(r.Context(), body.Tenant)
	var admin *LocalAdmin
	if err == nil && tenant != nil {
		admin, err = h.Local.GetLocalAdmin(r.Context(), tenant.ID, body.Username)
	}
	if err != nil || tenant == nil || admin == nil {
		VerifyPassword(body.Password, dummyHash) // same work as a real check
		if tenant != nil {
			h.audit(r, tenant.ID, "anonymous", "local_login_failed", map[string]any{"reason": "unknown_user", "username": truncate(body.Username, 64)})
		}
		invalid()
		return
	}
	actor := "local:" + admin.Username
	now := h.Sessions.now()
	if admin.LockedUntil != nil && now.Before(*admin.LockedUntil) {
		w.Header().Set("Retry-After", strconv.Itoa(int(admin.LockedUntil.Sub(now).Seconds())+1))
		h.audit(r, tenant.ID, actor, "local_login_locked", map[string]any{"until": admin.LockedUntil.UTC().Format(time.RFC3339)})
		telemetry.RecordLogin(r.Context(), "local", "locked")
		problem(w, r, http.StatusTooManyRequests, "rate-limited", "This account is locked after too many wrong passwords",
			"Try again in "+strconv.Itoa(int(admin.LockedUntil.Sub(now).Minutes())+1)+" minutes, or reset the password with the CLI.")
		return
	}

	ok := VerifyPassword(body.Password, admin.PasswordHash)
	lockedUntil, rerr := h.Local.RecordLocalLogin(r.Context(), tenant.ID, admin.ID, ok, now, maxFailedAttempts, lockDuration)
	if rerr != nil {
		h.Logger.Error("recording local login", "err", rerr)
		problem(w, r, http.StatusInternalServerError, "internal", "Cannot sign in right now", "")
		return
	}
	if !ok {
		h.audit(r, tenant.ID, actor, "local_login_failed", map[string]any{"reason": "wrong_password"})
		if lockedUntil != nil {
			h.audit(r, tenant.ID, actor, "local_login_locked", map[string]any{"until": lockedUntil.UTC().Format(time.RFC3339), "reason": "too_many_failures"})
			h.Logger.Warn("local administrator locked after repeated wrong passwords", "username", admin.Username, "tenant", body.Tenant)
		}
		invalid()
		return
	}
	// The person must still belong to the tenant: removing the membership disables the account too.
	if _, member, merr := h.Identity.GetMemberRole(r.Context(), tenant.ID, admin.UserID); merr != nil || !member {
		h.audit(r, tenant.ID, actor, "local_login_failed", map[string]any{"reason": "not_a_member"})
		invalid()
		return
	}
	value, rec, err := h.Sessions.Create(r.Context(), tenant.ID, admin.UserID)
	if err != nil {
		problem(w, r, http.StatusInternalServerError, "internal", "Cannot sign in right now", "")
		return
	}
	h.Sessions.SetCookie(w, value, rec.ExpiresAt)
	h.audit(r, tenant.ID, actor, "local_login_success", nil)
	telemetry.RecordLogin(r.Context(), "local", "success")
	// Break-glass use must be noticed (doc 14 section 1: alerting on use).
	h.Logger.Warn("break-glass sign-in: the local administrator signed in", "username", admin.Username, "tenant", body.Tenant, "ip", clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
