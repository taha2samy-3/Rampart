package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/store"
)

const (
	GrantTypeTokenExchange   = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeJWT             = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccessToken     = "urn:ietf:params:oauth:token-type:access_token"
	FederationTokenExpirySec = 900 // 15 minutes per D22
)

// TokenExchangeResponse is the standard RFC 8693 token exchange response.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

// JWKSCache holds cached JSON Web Key Sets per issuer with safe HTTP fetching (D22, D69).
type JWKSCache struct {
	mu     sync.RWMutex
	client *connectors.SafeClient
	sets   map[string]*cachedJWKS
}

type cachedJWKS struct {
	mu          sync.Mutex
	jwks        *jose.JSONWebKeySet
	fetchedAt   time.Time
	lastRefetch time.Time
}

// NewJWKSCache creates a JWKS cache using the provided safe client.
func NewJWKSCache(client *connectors.SafeClient) *JWKSCache {
	if client == nil {
		client = connectors.NewSafeClient()
	}
	return &JWKSCache{
		client: client,
		sets:   make(map[string]*cachedJWKS),
	}
}

// GetKeySet fetches the JWKS for an issuer using OIDC discovery and SafeClient SSRF protections.
func (c *JWKSCache) GetKeySet(ctx context.Context, issuer string, forceRefetch bool) (*jose.JSONWebKeySet, error) {
	// Enforce https on issuer unless loopback test client is configured (D22, D69)
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("federation: invalid issuer URL %q: %w", issuer, err)
	}
	if u.Scheme != "https" {
		if c.client == nil || !c.client.AllowLoopback() || u.Scheme != "http" {
			return nil, fmt.Errorf("federation: issuer must use https scheme: %q", issuer)
		}
	}

	c.mu.Lock()
	entry, ok := c.sets[issuer]
	if !ok {
		entry = &cachedJWKS{}
		c.sets[issuer] = entry
	}
	c.mu.Unlock()

	// Per-issuer locking: network calls do NOT hold the cache-wide lock (Audit point 9)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.jwks != nil && !forceRefetch && time.Since(entry.fetchedAt) < 1*time.Hour {
		return entry.jwks, nil
	}

	// Rate limit forceRefetch (minimum 15-second cooldown to avoid amplification/DoS, Audit point 8)
	if forceRefetch && entry.jwks != nil && time.Since(entry.lastRefetch) < 15*time.Second {
		return entry.jwks, nil
	}

	// 1. Discover JWKS URI via .well-known/openid-configuration
	discoURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	discoU, err := url.Parse(discoURL)
	if err != nil || (discoU.Scheme != "https" && (c.client == nil || !c.client.AllowLoopback() || discoU.Scheme != "http")) {
		return nil, fmt.Errorf("federation: invalid or non-https discovery URL")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", discoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	body, status, _, err := c.client.Do(req)
	var jwksURL string
	if err == nil && status == http.StatusOK {
		var doc struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if decErr := json.Unmarshal(body, &doc); decErr == nil && doc.JWKSURI != "" {
			jwksURL = doc.JWKSURI
		}
	}

	if jwksURL == "" {
		jwksURL = strings.TrimSuffix(issuer, "/") + "/.well-known/jwks.json"
	}

	// Enforce https on jwksURL (Audit point 7)
	parsedJWKS, err := url.Parse(jwksURL)
	if err != nil || (parsedJWKS.Scheme != "https" && (c.client == nil || !c.client.AllowLoopback() || parsedJWKS.Scheme != "http")) {
		return nil, fmt.Errorf("federation: jwks_uri must use https scheme: %q", jwksURL)
	}

	// 2. Fetch JWKS via SafeClient
	jwksReq, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid jwks request: %w", err)
	}
	jwksReq.Header.Set("Accept", "application/json")

	jwksBody, jwksStatus, _, err := c.client.Do(jwksReq)
	if err != nil {
		return nil, fmt.Errorf("federation: failed to fetch jwks: %w", err)
	}
	if jwksStatus != http.StatusOK {
		return nil, fmt.Errorf("federation: jwks endpoint returned HTTP %d", jwksStatus)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBody, &set); err != nil {
		return nil, fmt.Errorf("federation: failed to parse jwks: %w", err)
	}

	now := time.Now()
	entry.jwks = &set
	entry.fetchedAt = now
	entry.lastRefetch = now

	return &set, nil
}

func oauthError(w http.ResponseWriter, status int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	})
}

// handleTokenExchange implements RFC 8693 token exchange for CI OIDC federation (D22).
func (g *Gateway) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	// 1. Size limit: 64 KiB
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form-encoded body")
		return
	}

	grantType := r.Form.Get("grant_type")
	if grantType != GrantTypeTokenExchange {
		oauthError(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("unsupported grant_type: %q", grantType))
		return
	}

	subjectTokenType := r.Form.Get("subject_token_type")
	if subjectTokenType != TokenTypeJWT {
		oauthError(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("unsupported subject_token_type: %q", subjectTokenType))
		return
	}

	subjectToken := r.Form.Get("subject_token")
	if subjectToken == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}

	// 2. Resolve tenant from URL path: /ingest/v1/t/{tenant}/token
	tenantParam := r.PathValue("tenant")
	if tenantParam == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "tenant parameter is required")
		return
	}

	var tenant *domain.Tenant
	var err error
	if tenantID, parseErr := uuid.Parse(tenantParam); parseErr == nil {
		tenant, err = g.store.GetTenant(r.Context(), tenantID)
	} else {
		tenant, err = g.store.GetTenantBySlug(r.Context(), tenantParam)
	}
	if err != nil || tenant == nil {
		slog.Warn("federation: tenant not found", "tenant", tenantParam, "error", err)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	// 3. Parse JWT header & claims without verification
	tok, err := jwt.ParseSigned(subjectToken, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		slog.Warn("federation: parse signed jwt failed", "error", err)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}
	if len(tok.Headers) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	header := tok.Headers[0]
	if header.Algorithm != string(jose.RS256) && header.Algorithm != string(jose.ES256) {
		slog.Warn("federation: unsupported algorithm", "alg", header.Algorithm)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	var rawClaims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		slog.Warn("federation: unsafe claims failed", "error", err)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	iss, _ := rawClaims["iss"].(string)
	if iss == "" {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	jti, _ := rawClaims["jti"].(string)
	if jti == "" {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	// 4. Verify public host configuration (Audit point 11: fail-closed, never fall back to r.Host)
	publicHost := g.publicHost
	if publicHost == "" {
		if u, err := url.Parse(g.publicURL); err == nil && u.Host != "" {
			publicHost = u.Host
		}
	}
	if publicHost == "" {
		slog.Error("federation: publicURL is not configured on gateway; refusing exchange (fail-closed)")
		oauthError(w, http.StatusInternalServerError, "server_error", "federation is not configured")
		return
	}

	expectedAudience := fmt.Sprintf("rampart:%s:%s", publicHost, tenant.Slug)
	if reqAudience := r.Form.Get("audience"); reqAudience != "" && reqAudience != expectedAudience {
		slog.Warn("federation: requested audience does not match expected", "req", reqAudience, "expected", expectedAudience)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	// 5. Verify issuer is named by a trust rule for this tenant
	trustRules, err := g.store.ListTrustRulesByIssuer(r.Context(), tenant.ID, iss)
	if err != nil || len(trustRules) == 0 {
		slog.Warn("federation: issuer not trusted for tenant", "issuer", iss, "tenant", tenant.Slug)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	// 6. Fetch key set via SafeClient and verify signature
	if g.jwksCache == nil {
		g.jwksCache = NewJWKSCache(g.safeClient)
	}

	keySet, err := g.jwksCache.GetKeySet(r.Context(), iss, false)
	if err != nil {
		slog.Warn("federation: failed to fetch issuer key set", "issuer", iss, "error", err)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	kid := header.KeyID
	matchingKeys := keySet.Key(kid)
	if len(matchingKeys) == 0 {
		// Key rotation: try refetching once
		keySet, err = g.jwksCache.GetKeySet(r.Context(), iss, true)
		if err == nil {
			matchingKeys = keySet.Key(kid)
		}
	}
	if len(matchingKeys) == 0 {
		slog.Warn("federation: unknown key id", "kid", kid, "issuer", iss)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	var verifiedClaims map[string]any
	var stdClaims jwt.Claims
	sigVerified := false
	for _, key := range matchingKeys {
		if err := tok.Claims(key.Key, &verifiedClaims, &stdClaims); err == nil {
			sigVerified = true
			break
		}
	}
	if !sigVerified {
		slog.Warn("federation: invalid token signature", "issuer", iss)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	// 7. Validate standard claims: exp, nbf, aud
	now := time.Now().UTC()
	if now.After(stdClaims.Expiry.Time().Add(time.Minute)) {
		slog.Warn("federation: token has expired", "exp", stdClaims.Expiry.Time())
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}
	if stdClaims.NotBefore != nil && now.Before(stdClaims.NotBefore.Time().Add(-time.Minute)) {
		slog.Warn("federation: token not yet valid (nbf)", "nbf", stdClaims.NotBefore.Time())
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	// Strict Audience check: rampart:<public-host>:<tenant> (Audit point 2, D22)
	audMatched := false
	for _, aud := range stdClaims.Audience {
		if aud == expectedAudience {
			audMatched = true
			break
		}
	}
	if !audMatched {
		slog.Warn("federation: token audience mismatch", "got", stdClaims.Audience, "expected", expectedAudience)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	// 8. Match claims against trust rules (immutable IDs per D22)
	var matchedRule *domain.TrustRuleRecord
	for _, tr := range trustRules {
		rule := tr.Rule
		if rule.Provider == "github" {
			repoID := claimStr(verifiedClaims, "repository_id")
			ownerID := claimStr(verifiedClaims, "repository_owner_id")
			repo := claimStr(verifiedClaims, "repository")

			// D22 requires matching both repository_id and repository_owner_id (Audit point 6)
			if rule.RepositoryID != "" && rule.RepositoryID != repoID {
				continue
			}
			if rule.RepositoryOwnerID != "" && rule.RepositoryOwnerID != ownerID {
				continue
			}
			if rule.Repository != "" && rule.Repository != repo {
				continue
			}
			matchedRule = &tr
			break
		} else if rule.Provider == "gitlab" {
			projID := claimStr(verifiedClaims, "project_id")
			nsID := claimStr(verifiedClaims, "namespace_id")
			projPath := claimStr(verifiedClaims, "project_path")

			// D22 requires matching both project_id and namespace_id
			if rule.ProjectID != "" && rule.ProjectID != projID {
				continue
			}
			if rule.NamespaceID != "" && rule.NamespaceID != nsID {
				continue
			}
			if rule.Repository != "" && rule.Repository != projPath {
				continue
			}
			matchedRule = &tr
			break
		}
	}

	if matchedRule == nil {
		slog.Warn("federation: claims do not match any trust rule", "claims", verifiedClaims)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token validation failed")
		return
	}

	// 9. Replay protection (Audit point 3, D22): Record (issuer, jti) ONLY after signature, audience & rules verified.
	// Cap expiration record at 1 hour from now to prevent table bloat.
	expRecordTime := stdClaims.Expiry.Time()
	if expRecordTime.IsZero() {
		expRecordTime = now.Add(15 * time.Minute)
	}
	maxExp := now.Add(1 * time.Hour)
	if expRecordTime.After(maxExp) {
		expRecordTime = maxExp
	}

	if err := g.store.RecordFederationJTI(r.Context(), iss, jti, expRecordTime.Add(time.Minute)); err != nil {
		if errors.Is(err, store.ErrJTIReplay) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "token replay detected: jti has already been exchanged")
			return
		}
		slog.Error("federation: failed to record JTI", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to record token")
		return
	}

	// 10. Tighten options (D22): clients may tighten, never loosen
	var scopes []string
	scopes = append(scopes, "ingest")
	if minSev := r.Form.Get("minimum_severity"); minSev != "" {
		sev := domain.ParseSeverity(minSev)
		if sev != domain.SeverityUnknown {
			scopes = append(scopes, "min_sev:"+string(sev))
		}
	}
	if closeOld := r.Form.Get("close_old_findings"); closeOld == "false" {
		scopes = append(scopes, "no_close")
	}

	// 11. Issue short-lived API token (role: ingest, 15 minutes, bound to scanSourceID)
	subject := claimStr(verifiedClaims, "repository")
	if subject == "" {
		subject = claimStr(verifiedClaims, "project_path")
	}
	if subject == "" {
		subject = stdClaims.Subject
	}

	rawToken, record, err := auth.GenerateToken(tenant.ID, auth.RoleIngest, fmt.Sprintf("%s:%s", matchedRule.Rule.Provider, subject), scopes, FederationTokenExpirySec*time.Second)
	if err != nil {
		slog.Error("federation: failed to generate token", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to issue ingest token")
		return
	}
	record.ScanSourceID = &matchedRule.ScanSourceID

	if err := g.store.SaveToken(r.Context(), record); err != nil {
		slog.Error("federation: failed to save token", "error", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to save ingest token")
		return
	}

	// 12. Audit token exchange
	_ = g.store.RecordAudit(r.Context(), auth.AuditEvent{
		TenantID:     tenant.ID,
		Actor:        fmt.Sprintf("%s:%s", matchedRule.Rule.Provider, subject),
		Action:       "federation.token_exchange",
		ResourceType: "scan_source",
		ResourceID:   matchedRule.ScanSourceID.String(),
		Detail: map[string]any{
			"issuer":     iss,
			"jti":        jti,
			"provider":   matchedRule.Rule.Provider,
			"repository": subject,
		},
	})

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(TokenExchangeResponse{
		AccessToken:     rawToken,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       FederationTokenExpirySec,
	})
}

func claimStr(claims map[string]any, key string) string {
	val, ok := claims[key]
	if !ok || val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case int:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
