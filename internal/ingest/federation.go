package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	sets   map[string]cachedJWKS
}

type cachedJWKS struct {
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
}

// NewJWKSCache creates a JWKS cache using the provided safe client.
func NewJWKSCache(client *connectors.SafeClient) *JWKSCache {
	if client == nil {
		client = connectors.NewSafeClient()
	}
	return &JWKSCache{
		client: client,
		sets:   make(map[string]cachedJWKS),
	}
}

// GetKeySet fetches the JWKS for an issuer using OIDC discovery and SafeClient SSRF protections.
func (c *JWKSCache) GetKeySet(ctx context.Context, issuer string, forceRefetch bool) (*jose.JSONWebKeySet, error) {
	c.mu.RLock()
	cached, ok := c.sets[issuer]
	c.mu.RUnlock()

	if ok && !forceRefetch && time.Since(cached.fetchedAt) < 1*time.Hour {
		return cached.jwks, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if !forceRefetch {
		if cached, ok := c.sets[issuer]; ok && time.Since(cached.fetchedAt) < 1*time.Hour {
			return cached.jwks, nil
		}
	}

	// 1. Discover JWKS URI via .well-known/openid-configuration
	discoURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", discoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid discovery URL: %w", err)
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

	// 2. Fetch JWKS via SafeClient
	jwksReq, err := http.NewRequestWithContext(ctx, "GET", jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid jwks URL: %w", err)
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

	c.sets[issuer] = cachedJWKS{
		jwks:      &set,
		fetchedAt: time.Now(),
	}

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
		oauthError(w, http.StatusBadRequest, "invalid_grant", "tenant not found")
		return
	}

	// 3. Parse JWT header & claims without verification
	tok, err := jwt.ParseSigned(subjectToken, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unsupported or insecure signing algorithm")
		return
	}
	if len(tok.Headers) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "missing token headers")
		return
	}

	header := tok.Headers[0]
	if header.Algorithm != string(jose.RS256) && header.Algorithm != string(jose.ES256) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unsupported signing algorithm; only RS256 and ES256 allowed")
		return
	}

	var rawClaims map[string]any
	if err := tok.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "failed to parse token claims")
		return
	}

	iss, _ := rawClaims["iss"].(string)
	if iss == "" {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "missing iss claim")
		return
	}

	jti, _ := rawClaims["jti"].(string)
	if jti == "" {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token must carry jti claim (D22)")
		return
	}

	// 4. Verify issuer is named by a trust rule for this tenant
	trustRules, err := g.store.ListTrustRulesByIssuer(r.Context(), tenant.ID, iss)
	if err != nil || len(trustRules) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "issuer is not trusted for this tenant")
		return
	}

	// 5. Replay protection: insert (issuer, jti) before issuance
	var expTime time.Time
	if expNum, ok := rawClaims["exp"].(float64); ok {
		expTime = time.Unix(int64(expNum), 0).UTC()
	} else {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "missing or invalid exp claim")
		return
	}

	if err := g.store.RecordFederationJTI(r.Context(), iss, jti, expTime.Add(time.Minute)); err != nil {
		if errors.Is(err, store.ErrJTIReplay) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "token replay detected: jti has already been exchanged")
			return
		}
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to verify token uniqueness")
		return
	}

	// 6. Fetch key set via SafeClient and verify signature
	if g.jwksCache == nil {
		g.jwksCache = NewJWKSCache(g.safeClient)
	}

	keySet, err := g.jwksCache.GetKeySet(r.Context(), iss, false)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("failed to fetch issuer key set: %v", err))
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
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown key id (kid)")
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
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid token signature")
		return
	}

	// 7. Validate standard claims: exp, nbf, aud
	now := time.Now().UTC()
	if now.After(stdClaims.Expiry.Time().Add(time.Minute)) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token has expired")
		return
	}
	if stdClaims.NotBefore != nil && now.Before(stdClaims.NotBefore.Time().Add(-time.Minute)) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token is not yet valid (nbf)")
		return
	}

	// Audience check: rampart:<public-host>:<tenant>
	publicHost := g.publicHost
	if publicHost == "" {
		if u, err := url.Parse(g.publicURL); err == nil && u.Host != "" {
			publicHost = u.Host
		} else {
			publicHost = r.Host
		}
	}

	expectedAudience := fmt.Sprintf("rampart:%s:%s", publicHost, tenant.Slug)
	reqAudience := r.Form.Get("audience")
	if reqAudience != "" && reqAudience != expectedAudience && !stdClaims.Audience.Contains(reqAudience) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "requested audience does not match token audience")
		return
	}

	audMatched := false
	for _, aud := range stdClaims.Audience {
		if aud == expectedAudience || aud == tenant.Slug || aud == "rampart" || strings.HasSuffix(aud, ":"+tenant.Slug) {
			audMatched = true
			break
		}
	}
	if !audMatched {
		oauthError(w, http.StatusBadRequest, "invalid_grant", fmt.Sprintf("token audience mismatch: expected %q", expectedAudience))
		return
	}

	// 8. Match claims against trust rules (immutable IDs)
	var matchedRule *domain.TrustRuleRecord
	for _, tr := range trustRules {
		rule := tr.Rule
		if rule.Provider == "github" {
			repoID := claimStr(verifiedClaims, "repository_id")
			ownerID := claimStr(verifiedClaims, "repository_owner_id")
			repo := claimStr(verifiedClaims, "repository")

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
		oauthError(w, http.StatusBadRequest, "invalid_grant", "token claims do not match any trust rule for this repository")
		return
	}

	// 9. Tighten options (D22): clients may tighten, never loosen
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

	// 10. Issue short-lived API token (role: ingest, 15 minutes, bound to scanSourceID)
	subject := claimStr(verifiedClaims, "repository")
	if subject == "" {
		subject = claimStr(verifiedClaims, "project_path")
	}
	if subject == "" {
		subject = stdClaims.Subject
	}

	rawToken, record, err := auth.GenerateToken(tenant.ID, auth.RoleIngest, fmt.Sprintf("%s:%s", matchedRule.Rule.Provider, subject), scopes, FederationTokenExpirySec*time.Second)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to issue ingest token")
		return
	}
	record.ScanSourceID = &matchedRule.ScanSourceID

	if err := g.store.SaveToken(r.Context(), record); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to save ingest token")
		return
	}

	// 11. Audit token exchange
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
