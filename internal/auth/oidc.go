package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig is the static identity provider of Phase 1 (D8, D6 auth.oidc.*).
type OIDCConfig struct {
	Issuer               string
	ClientID             string
	ClientSecret         string
	RedirectURL          string
	Scopes               []string // default: openid profile email
	GroupsClaim          string   // default: groups
	RequireEmailVerified bool
}

// Claims are the mapped identity attributes (doc 14 section 3).
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
}

// OIDCClient is the OIDC relying party. Discovery is lazy and retried, so the platform can start
// before its identity provider is reachable and login recovers without a restart.
type OIDCClient struct {
	cfg OIDCConfig

	mu       sync.Mutex
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDCClient applies defaults. It does not contact the issuer.
func NewOIDCClient(cfg OIDCConfig) *OIDCClient {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	return &OIDCClient{cfg: cfg}
}

// Issuer returns the configured issuer.
func (c *OIDCClient) Issuer() string { return c.cfg.Issuer }

func (c *OIDCClient) ready(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.oauth != nil {
		return c.oauth, c.verifier, nil
	}
	p, err := oidc.NewProvider(ctx, c.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery for %s: %w", c.cfg.Issuer, err)
	}
	c.oauth = &oauth2.Config{
		ClientID: c.cfg.ClientID, ClientSecret: c.cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: c.cfg.RedirectURL, Scopes: c.cfg.Scopes,
	}
	c.verifier = p.Verifier(&oidc.Config{ClientID: c.cfg.ClientID})
	return c.oauth, c.verifier, nil
}

// AuthCodeURL builds the authorization request with state, nonce and a PKCE S256 challenge.
func (c *OIDCClient) AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	o, _, err := c.ready(ctx)
	if err != nil {
		return "", err
	}
	return o.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange trades the code (with the PKCE verifier) and validates the ID token: signature against
// the cached JWKS, iss, aud, exp and nonce (doc 14 section 2, step 3).
func (c *OIDCClient) Exchange(ctx context.Context, code, verifier, wantNonce string) (*Claims, error) {
	o, v, err := c.ready(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := o.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("token response has no id_token")
	}
	idt, err := v.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("id token: %w", err)
	}
	if idt.Nonce != wantNonce {
		return nil, errors.New("id token nonce mismatch")
	}
	var all map[string]any
	if err := idt.Claims(&all); err != nil {
		return nil, err
	}
	cl := &Claims{Issuer: idt.Issuer, Subject: idt.Subject}
	cl.Email, _ = all["email"].(string)
	cl.EmailVerified, _ = all["email_verified"].(bool)
	cl.Name, _ = all["name"].(string)
	cl.Groups = stringList(all[c.cfg.GroupsClaim])
	if c.cfg.RequireEmailVerified && cl.Email != "" && !cl.EmailVerified {
		return nil, ErrEmailUnverified
	}
	return cl, nil
}

// ErrEmailUnverified is returned when the IdP does not vouch for the email address.
var ErrEmailUnverified = errors.New("email is not verified by the identity provider")

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	}
	return nil
}
