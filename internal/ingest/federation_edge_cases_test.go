package ingest_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// TestFederation_MalformedJWT_EdgeCases tests malformed tokens, bad algorithm attacks,
// and missing headers.
func TestFederation_MalformedJWT_EdgeCases(t *testing.T) {
	gw, _, idp, tenant, _ := setupFederationGateway(t)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	aud := "rampart:rampart.example.com:" + tenant.Slug

	exchange := func(assertion string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
			"subject_token":        {assertion},
			"audience":             {aud},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}
		rec, _ := exchangeToken(mux, tenant.Slug, form)
		return rec
	}

	t.Run("token with invalid part count rejected with 400", func(t *testing.T) {
		for _, badToken := range []string{"", "singlepart", "part1.part2", "p1.p2.p3.p4"} {
			w := exchange(badToken)
			if w.Code != http.StatusBadRequest {
				t.Errorf("token %q: expected 400, got %d", badToken, w.Code)
			}
		}
	})

	t.Run("token with non-base64 characters rejected", func(t *testing.T) {
		w := exchange("header!@#.payload!@#.sig!@#")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("alg none attack rejected", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{
			"iss": %q,
			"aud": %q,
			"sub": "repo:acme/backend",
			"repository_owner_id": "67890",
			"repository_id": "12345",
			"jti": %q,
			"exp": %d
		}`, idp.server.URL, aud, uuid.NewString(), time.Now().Add(10*time.Minute).Unix())))
		noneToken := header + "." + claims + "."
		w := exchange(noneToken)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for alg none attack, got %d", w.Code)
		}
	})

	t.Run("symmetric HMAC HS256 substitution attack rejected", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"key-rsa-1"}`))
		claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{
			"iss": %q,
			"aud": %q,
			"sub": "repo:acme/backend",
			"repository_owner_id": "67890",
			"repository_id": "12345",
			"jti": %q,
			"exp": %d
		}`, idp.server.URL, aud, uuid.NewString(), time.Now().Add(10*time.Minute).Unix())))
		fakeSig := base64.RawURLEncoding.EncodeToString([]byte("fakesignaturebytes00000000000000000000"))
		hsToken := header + "." + claims + "." + fakeSig
		w := exchange(hsToken)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for HS256 substitution, got %d", w.Code)
		}
	})

	t.Run("key from untrusted issuer rejected", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: otherKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "key-untrusted"))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := jwt.Signed(sig).Claims(map[string]any{
			"iss":                 idp.server.URL,
			"aud":                 aud,
			"repository_owner_id": "67890",
			"repository_id":       "12345",
			"jti":                 uuid.NewString(),
			"exp":                 time.Now().Add(10 * time.Minute).Unix(),
		}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		w := exchange(tok)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for untrusted key, got %d", w.Code)
		}
	})
}

// TestFederation_TemporalAndAudience_EdgeCases tests expiry caps, clock skew limits,
// and audience spoofing attempts.
func TestFederation_TemporalAndAudience_EdgeCases(t *testing.T) {
	gw, _, idp, tenant, _ := setupFederationGateway(t)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	aud := "rampart:rampart.example.com:" + tenant.Slug

	exchange := func(assertion, targetAud string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
			"subject_token":        {assertion},
			"audience":             {targetAud},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}
		rec, _ := exchangeToken(mux, tenant.Slug, form)
		return rec
	}

	t.Run("token with lifetime exceeding 1 hour is rejected", func(t *testing.T) {
		now := time.Now()
		tok := idp.signRSA(map[string]any{
			"repository_owner_id": "67890",
			"repository_id":       "12345",
			"repository":          "acme/backend",
			"jti":                 uuid.NewString(),
		}, jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{aud},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(2 * time.Hour)), // > 1h
		})
		w := exchange(tok, aud)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for lifetime > 1 hour, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("token with negative lifetime (exp < iat) rejected", func(t *testing.T) {
		now := time.Now()
		tok := idp.signRSA(map[string]any{
			"repository_owner_id": "67890",
			"repository_id":       "12345",
			"repository":          "acme/backend",
			"jti":                 uuid.NewString(),
		}, jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{aud},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(-10 * time.Minute)),
		})
		w := exchange(tok, aud)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for exp in past, got %d", w.Code)
		}
	})

	t.Run("token with future nbf beyond clock skew rejected", func(t *testing.T) {
		now := time.Now()
		tok := idp.signRSA(map[string]any{
			"repository_owner_id": "67890",
			"repository_id":       "12345",
			"repository":          "acme/backend",
			"jti":                 uuid.NewString(),
		}, jwt.Claims{
			Issuer:    idp.server.URL,
			Audience:  jwt.Audience{aud},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			Expiry:    jwt.NewNumericDate(now.Add(40 * time.Minute)),
		})
		w := exchange(tok, aud)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for future nbf, got %d", w.Code)
		}
	})

	t.Run("token targeted at different tenant slug rejected", func(t *testing.T) {
		now := time.Now()
		otherAud := "rampart:rampart.example.com:other-tenant"
		tok := idp.signRSA(map[string]any{
			"repository_owner_id": "67890",
			"repository_id":       "12345",
			"repository":          "acme/backend",
			"jti":                 uuid.NewString(),
		}, jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{otherAud},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
		})
		w := exchange(tok, otherAud)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for wrong tenant audience, got %d", w.Code)
		}
	})

	t.Run("token with prefix/suffix variation of audience rejected", func(t *testing.T) {
		now := time.Now()
		variations := []string{
			"rampart:rampart.example.com:acme-evil",
			"prefix:rampart:rampart.example.com:acme",
			"rampart:rampart.example.com",
			"acme",
		}
		for _, badAud := range variations {
			tok := idp.signRSA(map[string]any{
				"repository_owner_id": "67890",
				"repository_id":       "12345",
				"repository":          "acme/backend",
				"jti":                 uuid.NewString(),
			}, jwt.Claims{
				Issuer:   idp.server.URL,
				Audience: jwt.Audience{badAud},
				IssuedAt: jwt.NewNumericDate(now),
				Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
			})
			w := exchange(tok, badAud)
			if w.Code != http.StatusBadRequest {
				t.Errorf("audience variation %q: expected 400, got %d", badAud, w.Code)
			}
		}
	})
}

// TestFederation_ConcurrentJTIReplay tests that concurrent exchanges with identical JTI
// allow exactly 1 request to succeed.
func TestFederation_ConcurrentJTIReplay(t *testing.T) {
	gw, _, idp, tenant, _ := setupFederationGateway(t)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	aud := "rampart:rampart.example.com:" + tenant.Slug
	sharedJTI := uuid.NewString()
	now := time.Now()

	tok := idp.signRSA(map[string]any{
		"repository_owner_id": "67890",
		"repository_id":       "12345",
		"repository":          "acme/backend",
		"jti":                 sharedJTI,
	}, jwt.Claims{
		Issuer:   idp.server.URL,
		Audience: jwt.Audience{aud},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(10 * time.Minute)),
	})

	const concurrency = 15
	var wg sync.WaitGroup
	var successCount int32
	var rejectCount int32

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			form := url.Values{
				"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
				"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
				"subject_token":        {tok},
				"audience":             {aud},
				"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			}
			rec, _ := exchangeToken(mux, tenant.Slug, form)
			switch rec.Code {
			case http.StatusOK:
				atomic.AddInt32(&successCount, 1)
			case http.StatusBadRequest:
				atomic.AddInt32(&rejectCount, 1)
			}
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 exchange to succeed for JTI %s, got %d (rejects: %d)", sharedJTI, successCount, rejectCount)
	}
	if rejectCount != concurrency-1 {
		t.Fatalf("expected %d rejects, got %d", concurrency-1, rejectCount)
	}
}

// TestFederation_ScanSourceBindingAndScopes_EdgeCases tests scope filtering and scan source enforcement.
func TestFederation_ScanSourceBindingAndScopes_EdgeCases(t *testing.T) {
	gw, _, idp, tenant, sourceID := setupFederationGateway(t)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	aud := "rampart:rampart.example.com:" + tenant.Slug

	t.Run("token bound to sourceID rejects ingest request specifying different sourceID", func(t *testing.T) {
		tok := idp.signRSA(map[string]any{
			"repository_owner_id": "67890",
			"repository_id":       "12345",
			"repository":          "acme/backend",
			"jti":                 uuid.NewString(),
		}, jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{aud},
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		})

		form := url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
			"subject_token":        {tok},
			"audience":             {aud},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}
		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("token exchange failed: %v", rec.Body.String())
		}
		accessToken := res["access_token"].(string)

		// Create another scan source ref
		otherSourceID := uuid.New()

		// Upload with mismatched scan source in query param must be 403 Forbidden
		report := `{"version":"2.1.0","$schema":"http://json.schemastore.org/sarif-2.1.0","runs":[]}`
		req := httptest.NewRequest("POST", "/ingest/v1/reports?source="+otherSourceID.String(), strings.NewReader(report))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for mismatched scan source, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("token bound to sourceID defaults source when empty", func(t *testing.T) {
		tok := idp.signRSA(map[string]any{
			"repository_owner_id": "67890",
			"repository_id":       "12345",
			"repository":          "acme/backend",
			"jti":                 uuid.NewString(),
		}, jwt.Claims{
			Issuer:   idp.server.URL,
			Audience: jwt.Audience{aud},
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		})

		form := url.Values{
			"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token_type":   {"urn:ietf:params:oauth:token-type:jwt"},
			"subject_token":        {tok},
			"audience":             {aud},
			"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}
		rec, res := exchangeToken(mux, tenant.Slug, form)
		if rec.Code != http.StatusOK {
			t.Fatalf("token exchange failed: %v", rec.Body.String())
		}
		accessToken := res["access_token"].(string)

		// Upload without specifying source -> automatically bound to sourceID
		body := `{"scanner": "trivy", "report": {"findings":[]}}`
		req := httptest.NewRequest("POST", "/ingest/v1/reports", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		// Status should not be 403 (can be 200, 201 or 202 queued)
		if w.Code == http.StatusForbidden {
			t.Fatalf("expected bound source to be accepted, got 403: %s", w.Body.String())
		}
		_ = sourceID
	})
}
