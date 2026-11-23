package ingest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

type fakeOIDCServer struct {
	server *httptest.Server
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	rsaKid string
	ecKid  string
}

func newFakeOIDCServer(tb testing.TB) *fakeOIDCServer {
	tb.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("failed to generate rsa key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("failed to generate ec key: %v", err)
	}

	f := &fakeOIDCServer{
		rsaKey: rsaKey,
		ecKey:  ecKey,
		rsaKid: "key-rsa-1",
		ecKid:  "key-ec-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   f.server.URL,
			"jwks_uri": f.server.URL + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		set := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       &rsaKey.PublicKey,
					KeyID:     f.rsaKid,
					Algorithm: string(jose.RS256),
					Use:       "sig",
				},
				{
					Key:       &ecKey.PublicKey,
					KeyID:     f.ecKid,
					Algorithm: string(jose.ES256),
					Use:       "sig",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(set)
	})

	f.server = httptest.NewServer(mux)
	tb.Cleanup(f.server.Close)
	return f
}

func (f *fakeOIDCServer) signRSA(claims map[string]any, std jwt.Claims) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: f.rsaKey, KeyID: f.rsaKid},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	raw, err := jwt.Signed(signer).Claims(std).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func (f *fakeOIDCServer) signEC(claims map[string]any, std jwt.Claims) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: f.ecKey, KeyID: f.ecKid},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
	raw, err := jwt.Signed(signer).Claims(std).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func setupFederationGateway(tb testing.TB) (*ingest.Gateway, *ingest.MemoryStore, *fakeOIDCServer, *domain.Tenant, uuid.UUID) {
	tb.Helper()
	idp := newFakeOIDCServer(tb)
	memStore := ingest.NewMemoryStore()

	tenant := &domain.Tenant{
		ID:          domain.NewID(),
		Slug:        "acme",
		DisplayName: "Acme Corp",
	}
	_ = memStore.CreateTenant(context.Background(), tenant)

	sourceID, err := memStore.EnsureScanSource(context.Background(), tenant.ID, "default")
	if err != nil {
		tb.Fatalf("failed to ensure scan source: %v", err)
	}

	// Save TrustRule
	rule := domain.TrustRule{
		Issuer:            idp.server.URL,
		Provider:          "github",
		RepositoryID:      "12345",
		RepositoryOwnerID: "67890",
		Repository:        "acme/backend",
	}
	_ = memStore.SaveTrustRules(context.Background(), tenant.ID, sourceID, []domain.TrustRule{rule})

	gw := ingest.NewGatewayWithDeps(nil, memStore, nil, nil)
	// Enable loopback dialing for fake idp server
	safeClient := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{
		AllowLoopback: true,
	})
	gw.SetSafeClient(safeClient)
	gw.SetPublicURL("https://rampart.example.com")

	return gw, memStore, idp, tenant, sourceID
}

func exchangeToken(mux *http.ServeMux, tenantSlug string, form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest("POST", "/ingest/v1/t/"+tenantSlug+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var res map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec, res
}

func TestFederation_TokenExchange(t *testing.T) {
	gw, memStore, idp, tenant, sourceID := setupFederationGateway(t)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	t.Run("valid GitHub token exchange succeeds", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:    idp.server.URL,
			Audience:  jwt.Audience{"rampart:rampart.example.com:acme"},
			Subject:   "repo:acme/backend:ref:refs/heads/main",
			Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
			ID:        uuid.New().String(),
		}
		claims := map[string]any{
			"repository_id":       "12345",
			"repository_owner_id": "67890",
			"repository":          "acme/backend",
			"ref":                 "refs/heads/main",
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %v", rec.Code, rec.Body.String())
		}

		tok, ok := res["access_token"].(string)
		if !ok || !strings.HasPrefix(tok, "rpt_") {
			t.Fatalf("expected access_token prefixed with rpt_, got: %v", res["access_token"])
		}
		if res["token_type"] != "Bearer" || res["issued_token_type"] != ingest.TokenTypeAccessToken {
			t.Fatalf("unexpected token metadata: %v", res)
		}
		if res["expires_in"] != float64(900) {
			t.Fatalf("expected 900 seconds expiry, got: %v", res["expires_in"])
		}

		// Verify issued token in store
		tokenHash := auth.HashToken(tok)
		saved, err := memStore.LookupTokenByHash(context.Background(), tenant.ID, tokenHash)
		if err != nil || saved == nil {
			t.Fatalf("issued token not found in store: %v", err)
		}
		if saved.Role != auth.RoleIngest {
			t.Fatalf("expected role ingest, got %q", saved.Role)
		}
		if saved.ScanSourceID == nil || *saved.ScanSourceID != sourceID {
			t.Fatalf("expected scanSourceID %v, got %v", sourceID, saved.ScanSourceID)
		}
	})

	t.Run("valid GitLab token with ES256 succeeds", func(t *testing.T) {
		glSourceID := domain.NewID()
		glRule := domain.TrustRule{
			Issuer:      idp.server.URL,
			Provider:    "gitlab",
			ProjectID:   "5555",
			NamespaceID: "6666",
			Repository:  "gitlab-org/my-project",
		}
		_ = memStore.SaveTrustRules(context.Background(), tenant.ID, glSourceID, []domain.TrustRule{glRule})

		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Subject:  "project_path:gitlab-org/my-project:ref_type:branch:ref:main",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{
			"project_id":   "5555",
			"namespace_id": "6666",
			"project_path": "gitlab-org/my-project",
		}
		rawJWT := idp.signEC(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for gitlab ES256, got %d: %v", rec.Code, rec.Body.String())
		}
		if _, ok := res["access_token"].(string); !ok {
			t.Fatalf("missing access_token in response: %v", res)
		}
	})

	t.Run("valid AWS STS token with generic boundClaims succeeds", func(t *testing.T) {
		awsSourceID := domain.NewID()
		awsRule := domain.TrustRule{
			Issuer: idp.server.URL,
			BoundClaims: map[string]string{
				"account_id": "123456789012",
				"role_arn":   "arn:aws:iam::123456789012:role/checkout-ci",
			},
		}
		_ = memStore.SaveTrustRules(context.Background(), tenant.ID, awsSourceID, []domain.TrustRule{awsRule})

		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Subject:  "arn:aws:sts::123456789012:assumed-role/checkout-ci/session",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{
			"account_id": "123456789012",
			"role_arn":   "arn:aws:iam::123456789012:role/checkout-ci",
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for AWS STS, got %d: %v", rec.Code, rec.Body.String())
		}
		tok, ok := res["access_token"].(string)
		if !ok || !strings.HasPrefix(tok, "rpt_") {
			t.Fatalf("expected valid access_token, got: %v", res["access_token"])
		}

		tokenHash := auth.HashToken(tok)
		saved, err := memStore.LookupTokenByHash(context.Background(), tenant.ID, tokenHash)
		if err != nil || saved == nil || saved.ScanSourceID == nil || *saved.ScanSourceID != awsSourceID {
			t.Fatalf("expected token bound to awsSourceID %v, got: %v", awsSourceID, saved)
		}
	})

	t.Run("valid Azure Entra ID token with boundClaims succeeds", func(t *testing.T) {
		azSourceID := domain.NewID()
		azRule := domain.TrustRule{
			Issuer: idp.server.URL,
			BoundClaims: map[string]string{
				"appid": "00000000-0000-0000-0000-000000000000",
				"tid":   "tenant-uuid-1234",
			},
		}
		_ = memStore.SaveTrustRules(context.Background(), tenant.ID, azSourceID, []domain.TrustRule{azRule})

		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Subject:  "sp-object-id",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{
			"appid": "00000000-0000-0000-0000-000000000000",
			"tid":   "tenant-uuid-1234",
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for Azure, got %d: %v", rec.Code, rec.Body.String())
		}
		if _, ok := res["access_token"].(string); !ok {
			t.Fatalf("missing access_token in Azure response: %v", res)
		}
	})

	t.Run("AWS token claim mismatch is rejected with 400 invalid_grant", func(t *testing.T) {
		mismatchSourceID := domain.NewID()
		mismatchRule := domain.TrustRule{
			Issuer: idp.server.URL,
			BoundClaims: map[string]string{
				"aws_account_id": "888888888888",
			},
		}
		_ = memStore.SaveTrustRules(context.Background(), tenant.ID, mismatchSourceID, []domain.TrustRule{mismatchRule})

		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Subject:  "attacker",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{
			"aws_account_id": "999999999999", // mismatch
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got: %v", res["error"])
		}
	})

	t.Run("AWS token missing required claim is rejected with 400 invalid_grant", func(t *testing.T) {
		missingSourceID := domain.NewID()
		missingRule := domain.TrustRule{
			Issuer: idp.server.URL,
			BoundClaims: map[string]string{
				"aws_account_id": "777777777777",
				"role_arn":       "arn:aws:iam::777777777777:role/checkout-ci",
			},
		}
		_ = memStore.SaveTrustRules(context.Background(), tenant.ID, missingSourceID, []domain.TrustRule{missingRule})

		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Subject:  "user",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{
			"aws_account_id": "777777777777",
			// role_arn missing
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got: %v", res["error"])
		}
	})

	t.Run("wrong audience is rejected", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:other-host:other-tenant"},
			Subject:  "repo:acme/backend:ref:refs/heads/main",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{"repository_id": "12345", "repository": "acme/backend"}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got %v", res)
		}
	})

	t.Run("expired token is rejected", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)), // expired
			ID:       uuid.New().String(),
		}
		claims := map[string]any{"repository_id": "12345", "repository": "acme/backend"}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got %v", res)
		}
	})

	t.Run("token with future nbf is rejected", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:    idp.server.URL,
			Audience:  jwt.Audience{"rampart:rampart.example.com:acme"},
			Expiry:    jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)), // future
			ID:        uuid.New().String(),
		}
		claims := map[string]any{"repository_id": "12345", "repository": "acme/backend"}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got %v", res)
		}
	})

	t.Run("unknown issuer is rejected", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:   "https://attacker.evil.example",
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{"repository_id": "12345"}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got %v", res)
		}
	})

	t.Run("renamed repository mismatch (repository_id differs) is rejected", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		// Attacker recreated repository with same name but different repository_id
		claims := map[string]any{
			"repository_id":       "99999", // not 12345!
			"repository_owner_id": "67890",
			"repository":          "acme/backend",
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" || res["error_description"] != "token validation failed" {
			t.Fatalf("unexpected error response (leaks details): %v", res)
		}
	})

	t.Run("missing jti claim is rejected", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			// No ID / jti
		}
		claims := map[string]any{
			"repository_id": "12345",
			"repository":    "acme/backend",
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" || res["error_description"] != "token validation failed" {
			t.Fatalf("unexpected error response (leaks details): %v", res)
		}
	})

	t.Run("token replay is rejected", func(t *testing.T) {
		replayJTI := uuid.New().String()
		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       replayJTI,
		}
		claims := map[string]any{
			"repository_id":       "12345",
			"repository_owner_id": "67890",
			"repository":          "acme/backend",
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		// First exchange succeeds
		rec1, _ := exchangeToken(mux, tenant.Slug, form)
		if rec1.Code != http.StatusOK {
			t.Fatalf("first exchange failed: %v", rec1.Body.String())
		}

		// Replay exchange with same JWT / jti must fail
		rec2, res2 := exchangeToken(mux, tenant.Slug, form)
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request on replay, got %d", rec2.Code)
		}
		if !strings.Contains(res2["error_description"].(string), "replay") {
			t.Fatalf("expected replay error description, got: %v", res2["error_description"])
		}
	})

	t.Run("alg none is rejected", func(t *testing.T) {
		// Header with alg: none
		unsigned := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJmb28ifQ."
		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {unsigned},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for alg:none, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got %v", res)
		}
	})

	t.Run("symmetric HMAC HS256 is rejected", func(t *testing.T) {
		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       []byte("super-secret-key-that-is-at-least-32-bytes!"),
		}, (&jose.SignerOptions{}).WithType("JWT"))
		if err != nil {
			t.Fatal(err)
		}
		std := jwt.Claims{Issuer: idp.server.URL, ID: uuid.New().String()}
		rawJWT, _ := jwt.Signed(signer).Claims(std).Serialize()

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for HS256, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got %v", res)
		}
	})

	t.Run("SSRF blocked when issuer points to private address", func(t *testing.T) {
		// Create a separate gateway that DOES NOT allow loopback
		gwNoLoopback := ingest.NewGatewayWithDeps(nil, memStore, nil, nil)
		gwNoLoopback.SetPublicURL("https://rampart.example.com")
		muxNoLoopback := http.NewServeMux()
		gwNoLoopback.RegisterRoutes(muxNoLoopback)

		// idp.server.URL is 127.0.0.1, which is blocked by default SafeClient
		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{"repository_id": "12345", "repository": "acme/backend"}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}

		rec, res := exchangeToken(muxNoLoopback, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for SSRF block, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" || res["error_description"] != "token validation failed" {
			t.Fatalf("unexpected error response (leaks details): %v", res)
		}
	})

	t.Run("tighten options stored in token scopes", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
			Subject:  "repo:acme/backend:ref:refs/heads/main",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{
			"repository_id":       "12345",
			"repository_owner_id": "67890",
			"repository":          "acme/backend",
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
			"minimum_severity":   {"HIGH"},
			"close_old_findings": {"false"},
		}

		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %v", rec.Code, rec.Body.String())
		}
		tok := res["access_token"].(string)
		tokenHash := auth.HashToken(tok)
		saved, _ := memStore.LookupTokenByHash(context.Background(), tenant.ID, tokenHash)
		if saved == nil {
			t.Fatal("saved token is nil")
		}

		hasMinSev := false
		hasNoClose := false
		for _, s := range saved.Scopes {
			if s == "min_sev:high" {
				hasMinSev = true
			}
			if s == "no_close" {
				hasNoClose = true
			}
		}
		if !hasMinSev || !hasNoClose {
			t.Fatalf("expected min_sev:high and no_close in scopes, got: %v", saved.Scopes)
		}
	})
}

func TestFederation_ScanSourceEnforcement(t *testing.T) {
	gw, memStore, idp, tenant, sourceID := setupFederationGateway(t)
	authn := auth.NewAuthenticatorWithStore(memStore)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	// Create a second scan source for the same tenant
	otherSourceID := domain.NewID()

	// Exchange token bound to sourceID
	std := jwt.Claims{
		Issuer:   idp.server.URL,
		Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
		Subject:  "repo:acme/backend:ref:refs/heads/main",
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		ID:       uuid.New().String(),
	}
	claims := map[string]any{
		"repository_id":       "12345",
		"repository_owner_id": "67890",
		"repository":          "acme/backend",
	}
	rawJWT := idp.signRSA(claims, std)

	form := url.Values{
		"grant_type":         {ingest.GrantTypeTokenExchange},
		"subject_token_type": {ingest.TokenTypeJWT},
		"subject_token":      {rawJWT},
	}
	rec, res := exchangeToken(mux, tenant.Slug, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %v", rec.Code, rec.Body.String())
	}
	tok := res["access_token"].(string)
	saved, _ := memStore.LookupTokenByHash(context.Background(), tenant.ID, auth.HashToken(tok))
	if saved == nil || saved.ScanSourceID == nil || *saved.ScanSourceID != sourceID {
		t.Fatalf("expected token bound to sourceID %v", sourceID)
	}

	// 1. Uploading to a mismatched source fails with 403 Forbidden
	reportJSON := `{"runs":[]}`
	req, _ := http.NewRequest("POST", "/ingest/v1/reports?source="+otherSourceID.String()+"&format=sarif", strings.NewReader(reportJSON))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for mismatched scan source, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Uploading without source query param defaults to bound scanSourceID (doesn't fail with 403)
	req2, _ := http.NewRequest("POST", "/ingest/v1/reports?format=sarif", strings.NewReader(reportJSON))
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code == http.StatusForbidden {
		t.Fatalf("unexpected 403 Forbidden when source defaults to token scanSourceID: %s", w2.Body.String())
	}
}

func TestFederation_StrictAudienceAndFailClosed(t *testing.T) {
	gw, _, idp, tenant, _ := setupFederationGateway(t)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	t.Run("loose suffix audience is rejected", func(t *testing.T) {
		std := jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{":" + tenant.Slug, tenant.Slug, "rampart"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{
			"repository_id":       "12345",
			"repository_owner_id": "67890",
			"repository":          "acme/backend",
		}
		rawJWT := idp.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}
		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for loose audience, got %d", rec.Code)
		}
		if res["error"] != "invalid_grant" {
			t.Fatalf("expected invalid_grant, got: %v", res)
		}
	})

	t.Run("empty PublicURL fails closed without falling back to r.Host", func(t *testing.T) {
		gwNoURL, _, idp2, tenant2, _ := setupFederationGateway(t)
		gwNoURL.SetPublicURL("") // cleared!
		muxNoURL := http.NewServeMux()
		gwNoURL.RegisterRoutes(muxNoURL)

		std := jwt.Claims{
			Issuer:   idp2.server.URL,
			Audience: jwt.Audience{"rampart:attacker.host:acme"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID:       uuid.New().String(),
		}
		claims := map[string]any{
			"repository_id":       "12345",
			"repository_owner_id": "67890",
			"repository":          "acme/backend",
		}
		rawJWT := idp2.signRSA(claims, std)

		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {rawJWT},
		}
		req := httptest.NewRequest("POST", "/ingest/v1/t/"+tenant2.Slug+"/token", strings.NewReader(form.Encode()))
		req.Host = "attacker.host" // attacker controlled header
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		muxNoURL.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 Server Error (fail-closed) when PublicURL not set, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestFederation_JWKSCacheRateLimiting(t *testing.T) {
	idp := newFakeOIDCServer(t)
	sc := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{AllowLoopback: true})
	cache := ingest.NewJWKSCache(sc)

	// First fetch populates cache
	ks1, err := cache.GetKeySet(context.Background(), idp.server.URL, false)
	if err != nil {
		t.Fatalf("initial GetKeySet failed: %v", err)
	}
	if len(ks1.Keys) == 0 {
		t.Fatal("expected keys in key set")
	}

	// Immediate forceRefetch within cooldown returns cached set without HTTP call
	ks2, err := cache.GetKeySet(context.Background(), idp.server.URL, true)
	if err != nil {
		t.Fatalf("rate-limited GetKeySet failed: %v", err)
	}
	if ks2 != ks1 {
		t.Fatal("expected same cached pointer due to 15s rate limit cooldown")
	}
}

func TestFederation_JTIPurge(t *testing.T) {
	_, memStore, _, _, _ := setupFederationGateway(t)
	now := time.Now().UTC()

	// 1. Record an expired JTI and an active JTI
	if err := memStore.RecordFederationJTI(context.Background(), "https://issuer.example.com", "jti-old", now.Add(-5*time.Minute)); err != nil {
		t.Fatalf("record jti failed: %v", err)
	}
	if err := memStore.RecordFederationJTI(context.Background(), "https://issuer.example.com", "jti-fresh", now.Add(5*time.Minute)); err != nil {
		t.Fatalf("record jti failed: %v", err)
	}

	// 2. Purge expired
	purged, err := memStore.PurgeExpiredFederationJTIs(context.Background(), now)
	if err != nil {
		t.Fatalf("purge failed: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 purged JTI, got %d", purged)
	}

	// 3. Re-recording jti-old should succeed now that it was purged
	if err := memStore.RecordFederationJTI(context.Background(), "https://issuer.example.com", "jti-old", now.Add(5*time.Minute)); err != nil {
		t.Fatalf("expected jti-old to be accepted after purge, got error: %v", err)
	}
}

func FuzzFederationToken(f *testing.F) {
	gw, _, _, tenant, _ := setupFederationGateway(f)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	f.Add([]byte("garbage.token.here"))
	f.Add([]byte("eyJhbGciOiJub25lIn0.eyJpc3MiOiJmb28ifQ."))
	f.Add([]byte("not-a-jwt-at-all"))
	f.Add([]byte("{}"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		form := url.Values{
			"grant_type":         {ingest.GrantTypeTokenExchange},
			"subject_token_type": {ingest.TokenTypeJWT},
			"subject_token":      {string(data)},
		}

		req := httptest.NewRequest("POST", "/ingest/v1/t/"+tenant.Slug+"/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		// Must never panic
		mux.ServeHTTP(rec, req)
	})
}

// D80: a federated token is bound to the run that exchanged it. An upload that states another branch, repository or
// commit is refused on both the direct and the presigned path; one that leaves them empty gets the token's.
func TestFederation_UploadContextIsTheTokens(t *testing.T) {
	gw, memStore, idp, tenant, _ := setupFederationGateway(t)
	gw.SetAuthenticator(auth.NewAuthenticatorWithStore(memStore))
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	sha := "0123456789abcdef0123456789abcdef01234567"
	std := jwt.Claims{
		Issuer: idp.server.URL, Audience: jwt.Audience{"rampart:rampart.example.com:acme"},
		Subject: "repo:acme/backend:ref:refs/heads/feature-x", Expiry: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		ID: uuid.New().String(),
	}
	claims := map[string]any{
		"repository_id": "12345", "repository_owner_id": "67890", "repository": "acme/backend",
		"ref": "refs/heads/feature-x", "sha": sha,
	}
	rec, res := exchangeToken(mux, tenant.Slug, url.Values{
		"grant_type": {ingest.GrantTypeTokenExchange}, "subject_token_type": {ingest.TokenTypeJWT}, "subject_token": {idp.signRSA(claims, std)},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	tok := res["access_token"].(string)

	upload := func(query string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPost, "/ingest/v1/reports?format=sarif&"+query, strings.NewReader(`{"runs":[]}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	for name, q := range map[string]string{
		"a feature-branch run claiming main": "branch=main",
		"another repository":                 "repository=https://github.com/acme/payments",
		"another commit":                     "commit=fedcba9876543210",
	} {
		if w := upload(q); w.Code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d: %s", name, w.Code, w.Body.String())
		}
	}
	for name, q := range map[string]string{
		"nothing stated":           "",
		"the same values":          "branch=feature-x&repository=git@github.com:Acme/backend.git&commit=" + sha[:10],
		"the ref in its long form": "branch=refs/heads/feature-x",
		"the repository as a URL":  "repository=https://github.com/acme/backend",
	} {
		if w := upload(q); w.Code == http.StatusForbidden {
			t.Errorf("%s: refused: %s", name, w.Body.String())
		}
	}

	// The presigned path checks the same binding when the upload is created.
	body := `{"sizeBytes":10,"context":{"branch":"main"}}`
	req, _ := http.NewRequest(http.MethodPost, "/ingest/v1/uploads", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden && w.Code != http.StatusNotImplemented {
		t.Fatalf("presigned create with branch=main: want 403, got %d: %s", w.Code, w.Body.String())
	}
}
