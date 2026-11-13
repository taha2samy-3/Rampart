package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
	"rampart/internal/domain"
	"rampart/internal/telemetry"
)

// TenantLookup resolves tenants by slug or id. Tenant rows are global (no RLS).
type TenantLookup interface {
	GetTenantBySlug(ctx context.Context, slug string) (*domain.Tenant, error)
	GetTenant(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)
}

// IdPStore resolves dynamic IdentityProvider resources (D8, D27, D64).
type IdPStore interface {
	GetIdentityProvider(ctx context.Context, tenantID *uuid.UUID, name string) (*domain.IdentityProvider, error)
	ListIdentityProviders(ctx context.Context, tenantID *uuid.UUID) ([]domain.IdentityProvider, error)
}

// HandlerDeps are the collaborators of the browser-facing auth endpoints.
type HandlerDeps struct {
	OIDC     *OIDCClient // nil: no sign-in method configured
	Sessions *SessionManager
	Identity IdentityStore
	Tenants  TenantLookup
	IdPs     IdPStore
	Authn    *Authenticator
	Policy   RolePolicy

	// Local sign-in (break-glass, D3). LocalLoginEnabled is decided by the caller: a bootstrap admin
	// exists and either no identity provider is configured or keepEnabled is set.
	LocalLoginEnabled bool
	Local             LocalAdminStore
	Audit             AuditStore
	LocalLimiter      *RateLimiter // default: 10 attempts per client address per minute

	DeviceAuth *DeviceAuthManager

	Product string
	Version string
	Logger  *slog.Logger
}

// Handlers serves /auth/*, /api/v1/ui-config and /api/v1/me* (doc 11, doc 13 section 3, doc 14 section 2).
type Handlers struct {
	HandlerDeps
	oidcMu    sync.RWMutex
	oidcPool  map[string]*OIDCClient
	oidcGroup singleflight.Group
}

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
	if d.DeviceAuth == nil && d.Authn != nil {
		d.DeviceAuth = NewDeviceAuthManager(d.Authn.store)
	}
	return &Handlers{
		HandlerDeps: d,
		oidcPool:    make(map[string]*OIDCClient),
	}
}

// getOrInitOIDCClient returns a cached OIDCClient or safely discovers and constructs one.
// Caches per IdP configuration with automatic invalidation on secret rotation / update (D8, D27).
// Concurrency is coalesced with singleflight to avoid duplicate discovery stampedes.
func (h *Handlers) getOrInitOIDCClient(idpObj *domain.IdentityProvider, redirectURL string) *OIDCClient {
	secretHash := sha256.Sum256([]byte(idpObj.Spec.OIDC.ClientSecret))
	cacheKey := fmt.Sprintf("%s|%s|%s|%s|%x|%d",
		idpObj.Name,
		idpObj.Spec.OIDC.Issuer,
		idpObj.Spec.OIDC.ClientID,
		redirectURL,
		secretHash[:8],
		idpObj.UpdatedAt.UnixNano(),
	)

	h.oidcMu.RLock()
	client, ok := h.oidcPool[cacheKey]
	h.oidcMu.RUnlock()
	if ok {
		return client
	}

	v, _, _ := h.oidcGroup.Do(cacheKey, func() (any, error) {
		h.oidcMu.RLock()
		if c, exists := h.oidcPool[cacheKey]; exists {
			h.oidcMu.RUnlock()
			return c, nil
		}
		h.oidcMu.RUnlock()

		groupsClaim := idpObj.Spec.OIDC.Claims.Groups
		requireEmail := idpObj.Spec.OIDC.RequireEmailVerified
		newClient := NewOIDCClient(OIDCConfig{
			Issuer:               idpObj.Spec.OIDC.Issuer,
			ClientID:             idpObj.Spec.OIDC.ClientID,
			ClientSecret:         idpObj.Spec.OIDC.ClientSecret,
			RedirectURL:          redirectURL,
			Scopes:               idpObj.Spec.OIDC.Scopes,
			GroupsClaim:          groupsClaim,
			RequireEmailVerified: requireEmail,
		})

		h.oidcMu.Lock()
		// Drop this IdP's other cached entries (an older secret/UpdatedAt) so a rotation doesn't
		// leak one stale *OIDCClient per rotation for the life of the process.
		prefix := idpObj.Name + "|"
		for k := range h.oidcPool {
			if k != cacheKey && strings.HasPrefix(k, prefix) {
				delete(h.oidcPool, k)
			}
		}
		h.oidcPool[cacheKey] = newClient
		h.oidcMu.Unlock()
		return newClient, nil
	})

	return v.(*OIDCClient)
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

	// RFC 8628 OAuth 2.0 Device Authorization Grant (Phase 2, D8, D54)
	mux.HandleFunc("POST /auth/device/code", h.deviceCode)
	mux.HandleFunc("GET /auth/device", h.devicePage)
	mux.HandleFunc("POST /auth/device/verify", h.deviceVerify)
	mux.HandleFunc("POST /auth/device/token", h.deviceToken)
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
	if h.IdPs != nil && h.Sessions != nil {
		var tenantID *uuid.UUID
		tenantSlug := r.URL.Query().Get("tenant")
		if tenantSlug != "" && h.Tenants != nil {
			if t, err := h.Tenants.GetTenantBySlug(r.Context(), tenantSlug); err == nil && t != nil {
				tenantID = &t.ID
			}
		}
		if idps, err := h.IdPs.ListIdentityProviders(r.Context(), tenantID); err == nil {
			for _, idp := range idps {
				if idp.TenantID == nil && tenantSlug != "" && !idp.IsTenantAllowed(tenantSlug) {
					continue
				}
				if idp.Name == "default" && h.OIDC != nil {
					continue
				}
				name := idp.DisplayName
				if name == "" {
					name = idp.Name
				}
				methods = append(methods, map[string]string{
					"id":   idp.Name,
					"name": name,
					"type": string(idp.Type),
				})
			}
		}
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
	if h.Sessions == nil {
		problem(w, r, http.StatusServiceUnavailable, "upstream-unavailable", "No sign-in method is configured",
			"Set auth.oidc.* or configure an IdentityProvider, and set auth.session.keyFile, then restart.")
		return
	}
	idp := r.URL.Query().Get("idp")
	if idp == "" {
		idp = "default"
	}
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		tenant = "default"
	}

	var oidcClient *OIDCClient
	if idp == "default" && h.OIDC != nil {
		oidcClient = h.OIDC
	} else if h.IdPs != nil {
		var tenantID *uuid.UUID
		if h.Tenants != nil {
			if t, err := h.Tenants.GetTenantBySlug(r.Context(), tenant); err == nil && t != nil {
				tenantID = &t.ID
			}
		}
		idpObj, err := h.IdPs.GetIdentityProvider(r.Context(), tenantID, idp)
		if err != nil || idpObj == nil {
			problem(w, r, http.StatusNotFound, "not-found", "Unknown sign-in method", "")
			return
		}
		if idpObj.TenantID == nil && tenant != "" && !idpObj.IsTenantAllowed(tenant) {
			problem(w, r, http.StatusForbidden, "forbidden", "Tenant not permitted to use this identity provider", "")
			return
		}
		if idpObj.Type != "oidc" && idpObj.Type != "" {
			problem(w, r, http.StatusNotImplemented, "not-implemented", "Identity provider type not supported", "")
			return
		}
		if idpObj.Spec.OIDC == nil || idpObj.Spec.OIDC.Issuer == "" {
			problem(w, r, http.StatusBadRequest, "bad-request", "Identity provider OIDC configuration is incomplete", "")
			return
		}
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		host := r.Host
		if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
			host = fwd
		}
		redirectURL := fmt.Sprintf("%s://%s/auth/oidc/%s/callback", scheme, host, idp)
		oidcClient = h.getOrInitOIDCClient(idpObj, redirectURL)
	} else {
		problem(w, r, http.StatusNotFound, "not-found", "Unknown sign-in method", "")
		return
	}

	state, err1 := randomToken()
	nonce, err2 := randomToken()
	verifier, err3 := randomToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		problem(w, r, http.StatusInternalServerError, "internal", "Cannot start sign-in", "")
		return
	}
	authURL, err := oidcClient.AuthCodeURL(r.Context(), state, nonce, verifier)
	if err != nil {
		h.Logger.Error("oidc login", "err", err)
		problem(w, r, http.StatusBadGateway, "upstream-unavailable", "The identity provider is not reachable",
			"Try again in a moment. If it persists, check the issuer URL.")
		return
	}
	st := loginState{
		State: state, Nonce: nonce, Verifier: verifier, Tenant: tenant,
		ReturnTo: SafeReturnTo(r.URL.Query().Get("return_to")), Expires: h.Sessions.now().Add(10 * 60e9),
		IdP: idp,
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
	if h.Sessions == nil {
		http.NotFound(w, r)
		return
	}
	idpParam := r.PathValue("idp")
	if idpParam == "" {
		idpParam = "default"
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
	if st.IdP != "" && st.IdP != idpParam {
		loginError(w, r, "invalid_state")
		return
	}

	var oidcClient *OIDCClient
	var idpObj *domain.IdentityProvider

	if idpParam == "default" && h.OIDC != nil {
		oidcClient = h.OIDC
	} else if h.IdPs != nil {
		var tenantID *uuid.UUID
		if h.Tenants != nil {
			if t, err := h.Tenants.GetTenantBySlug(r.Context(), st.Tenant); err == nil && t != nil {
				tenantID = &t.ID
			}
		}
		var err error
		idpObj, err = h.IdPs.GetIdentityProvider(r.Context(), tenantID, idpParam)
		if err != nil || idpObj == nil {
			loginError(w, r, "idp_not_found")
			return
		}
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		host := r.Host
		if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
			host = fwd
		}
		redirectURL := fmt.Sprintf("%s://%s/auth/oidc/%s/callback", scheme, host, idpParam)
		oidcClient = h.getOrInitOIDCClient(idpObj, redirectURL)
	} else {
		http.NotFound(w, r)
		return
	}

	claims, err := oidcClient.Exchange(r.Context(), q.Get("code"), st.Verifier, st.Nonce)
	if err != nil {
		h.Logger.Warn("oidc callback", "err", err)
		if errors.Is(err, ErrEmailUnverified) {
			loginError(w, r, "email_unverified")
			return
		}
		loginError(w, r, "idp_error")
		return
	}

	// D27: domain claim verification
	if idpObj != nil && len(idpObj.Status.Domains) > 0 {
		if !idpObj.IsDomainApproved(claims.Email) {
			h.Logger.Warn("oidc login domain claim not approved", "email", claims.Email, "idp", idpObj.Name)
			loginError(w, r, "domain_unverified")
			return
		}
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

func (h *Handlers) deviceCode(w http.ResponseWriter, r *http.Request) {
	if h.DeviceAuth == nil {
		problem(w, r, http.StatusNotImplemented, "unsupported", "Device authorization is not configured", "")
		return
	}
	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			ClientID string `json:"client_id"`
			Scope    string `json:"scope"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.ClientID != "" {
			clientID = body.ClientID
		}
		if body.Scope != "" {
			scope = body.Scope
		}
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, host)
	res, err := h.DeviceAuth.CreateDeviceCode(clientID, scope, baseURL)
	if err != nil {
		problem(w, r, http.StatusInternalServerError, "internal", "Failed to create device code", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handlers) currentUser(r *http.Request) *ContextUser {
	if u, ok := FromContext(r.Context()); ok && u != nil {
		return u
	}
	if h.Authn != nil {
		if u, err := h.Authn.AuthenticateRequest(r); err == nil && u != nil {
			return u
		}
	}
	if h.Sessions != nil {
		if p, err := h.Sessions.Principal(r); err == nil && p != nil {
			return &ContextUser{
				UserID:   p.Session.UserID,
				Email:    p.Email,
				Name:     p.Name,
				TenantID: p.Session.TenantID,
				Role:     p.Role,
			}
		}
	}
	return nil
}

func (h *Handlers) devicePage(w http.ResponseWriter, r *http.Request) {
	user := h.currentUser(r)
	if user == nil {
		loginURL := "/auth/login?return_to=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// The user_code is reflected into the page from an untrusted query parameter (a link the CLI prints or a
	// QR code), so it is rendered through html/template, not fmt.Fprintf: a raw %s here let `user_code` break out
	// of the value="" attribute and inject script into a signed-in victim's session (reflected XSS, D63). The
	// code is also pre-filtered to its own alphabet, as defense in depth.
	userCode := sanitizeUserCodeForDisplay(r.URL.Query().Get("user_code"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	_ = devicePageTmpl.Execute(w, devicePageData{Email: user.Email, UserCode: userCode})
}

// devicePageData is what devicePageTmpl renders; html/template escapes both fields for their HTML context.
type devicePageData struct {
	Email    string
	UserCode string
}

var devicePageTmpl = template.Must(template.New("device").Parse(`<!DOCTYPE html>
<html>
<head><title>Authorize Rampart CLI</title>
<style>
body { font-family: sans-serif; max-width: 480px; margin: 40px auto; padding: 20px; line-height: 1.5; }
input[type="text"] { width: 100%; padding: 10px; font-size: 18px; margin: 10px 0; text-transform: uppercase; font-family: monospace; letter-spacing: 2px; box-sizing: border-box; }
button { background: #0066cc; color: #fff; border: 0; padding: 12px 24px; font-size: 16px; border-radius: 4px; cursor: pointer; width: 100%; }
</style>
</head>
<body>
<h2>Authorize Rampart CLI</h2>
<p>Signed in as <strong>{{.Email}}</strong></p>
<form method="POST" action="/auth/device/verify">
<label for="user_code">Enter user code:</label>
<input type="text" id="user_code" name="user_code" value="{{.UserCode}}" required autofocus placeholder="XXXX-XXXX" />
<button type="submit">Authorize</button>
</form>
</body>
</html>`))

// sanitizeUserCodeForDisplay keeps only the device user-code alphabet (D54's generateUserCode: 8 characters of
// BCDFGHJKLMNPQRSTVWXZ23456789, upper-cased, plus the separating '-'), capped at 9 characters, so what reaches
// the template is always shaped like a real user code even before html/template escapes it.
func sanitizeUserCodeForDisplay(raw string) string {
	raw = strings.ToUpper(raw)
	var b strings.Builder
	for _, r := range raw {
		if b.Len() >= 9 {
			break
		}
		if r == '-' || strings.ContainsRune(userCodeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (h *Handlers) deviceVerify(w http.ResponseWriter, r *http.Request) {
	if h.DeviceAuth == nil {
		problem(w, r, http.StatusNotImplemented, "unsupported", "Device authorization is not configured", "")
		return
	}
	user := h.currentUser(r)
	if user == nil {
		problem(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", "")
		return
	}

	userCode := r.FormValue("user_code")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			UserCode string `json:"user_code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.UserCode != "" {
			userCode = body.UserCode
		}
	}

	if err := h.DeviceAuth.VerifyUserCode(r.Context(), userCode, user); err != nil {
		if errors.Is(err, ErrInvalidGrant) {
			problem(w, r, http.StatusBadRequest, "invalid_grant", "Invalid or unknown user code", "")
			return
		}
		if errors.Is(err, ErrExpiredToken) {
			problem(w, r, http.StatusBadRequest, "expired_token", "User code has expired", "")
			return
		}
		problem(w, r, http.StatusInternalServerError, "internal", "Verification failed", err.Error())
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "text/html") || r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Authorization Successful</title>
<style>body { font-family: sans-serif; max-width: 480px; margin: 40px auto; padding: 20px; text-align: center; line-height: 1.5; }</style>
</head>
<body>
<h2 style="color: #2e7d32;">Authorization Successful</h2>
<p>You have approved Rampart CLI. You may now close this browser window and return to your terminal.</p>
</body>
</html>`)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "approved",
		"message": "Device authorization successful. You can close this window.",
	})
}

func (h *Handlers) deviceToken(w http.ResponseWriter, r *http.Request) {
	if h.DeviceAuth == nil {
		problem(w, r, http.StatusNotImplemented, "unsupported", "Device authorization is not configured", "")
		return
	}
	grantType := r.FormValue("grant_type")
	deviceCode := r.FormValue("device_code")
	clientID := r.FormValue("client_id")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			GrantType  string `json:"grant_type"`
			DeviceCode string `json:"device_code"`
			ClientID   string `json:"client_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.GrantType != "" {
			grantType = body.GrantType
		}
		if body.DeviceCode != "" {
			deviceCode = body.DeviceCode
		}
		if body.ClientID != "" {
			clientID = body.ClientID
		}
	}

	if grantType != "" && grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "grant_type must be urn:ietf:params:oauth:grant-type:device_code",
		})
		return
	}

	res, err := h.DeviceAuth.PollToken(deviceCode, clientID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		var errCode, errDesc string
		switch {
		case errors.Is(err, ErrAuthorizationPending):
			errCode = "authorization_pending"
			errDesc = "The authorization request is still pending."
		case errors.Is(err, ErrExpiredToken):
			errCode = "expired_token"
			errDesc = "The device code has expired."
		case errors.Is(err, ErrAccessDenied):
			errCode = "access_denied"
			errDesc = "The authorization request was denied."
		default:
			errCode = "invalid_grant"
			errDesc = "Invalid device code."
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             errCode,
			"error_description": errDesc,
		})
		return
	}

	writeJSON(w, http.StatusOK, res)
}
