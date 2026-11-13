package domain_test

import (
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

func TestIdentityProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		idp     domain.IdentityProvider
		wantErr error
	}{
		{
			name: "valid OIDC",
			idp: domain.IdentityProvider{
				Name: "okta",
				Type: domain.IdPOIDC,
				Spec: domain.IdentityProviderSpec{
					Type: domain.IdPOIDC,
					OIDC: &domain.IdPOIDCConfig{
						Issuer:   "https://acme.okta.com",
						ClientID: "client-123",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid type",
			idp: domain.IdentityProvider{
				Name: "ldap",
				Type: "ldap",
			},
			wantErr: domain.ErrInvalidIdPType,
		},
		{
			name: "missing issuer",
			idp: domain.IdentityProvider{
				Name: "okta",
				Type: domain.IdPOIDC,
				Spec: domain.IdentityProviderSpec{
					Type: domain.IdPOIDC,
					OIDC: &domain.IdPOIDCConfig{
						ClientID: "client-123",
					},
				},
			},
			wantErr: domain.ErrMissingIssuer,
		},
		{
			name: "missing clientId",
			idp: domain.IdentityProvider{
				Name: "okta",
				Type: domain.IdPOIDC,
				Spec: domain.IdentityProviderSpec{
					Type: domain.IdPOIDC,
					OIDC: &domain.IdPOIDCConfig{
						Issuer: "https://acme.okta.com",
					},
				},
			},
			wantErr: domain.ErrMissingClientID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.idp.Validate()
			if err != tt.wantErr {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestClusterIdentityProviderAllowedTenants(t *testing.T) {
	cidp := domain.IdentityProvider{
		Name: "corp-okta",
		Type: domain.IdPOIDC,
		Spec: domain.IdentityProviderSpec{
			AllowedTenants: []string{"acme", "fintech-payments"},
		},
	}

	if !cidp.IsTenantAllowed("acme") {
		t.Errorf("expected tenant acme to be allowed")
	}
	if !cidp.IsTenantAllowed("Fintech-Payments") {
		t.Errorf("expected case-insensitive matching to succeed")
	}
	if cidp.IsTenantAllowed("rogue-tenant") {
		t.Errorf("expected rogue-tenant to be disallowed")
	}

	// Empty allowed tenants permits all tenants
	cidpAll := domain.IdentityProvider{
		Name: "public-google",
		Type: domain.IdPOIDC,
		Spec: domain.IdentityProviderSpec{
			AllowedTenants: nil,
		},
	}
	if !cidpAll.IsTenantAllowed("any-tenant") {
		t.Errorf("expected empty allowedTenants to permit any tenant")
	}
}

func TestDomainClaimVerification(t *testing.T) {
	tenantID := uuid.New()
	idp := domain.IdentityProvider{
		ID:       uuid.New(),
		TenantID: &tenantID,
		Name:     "azure-ad",
		Type:     domain.IdPOIDC,
		Spec: domain.IdentityProviderSpec{
			Login: domain.IdPLoginConfig{
				EmailDomains: []string{"acme.com", "subsidiary.org"},
			},
		},
		Status: domain.IdentityProviderStatus{
			Domains: []domain.DomainClaimStatus{
				{Domain: "acme.com", Approved: true},
				{Domain: "subsidiary.org", Approved: false},
			},
		},
	}

	if !idp.IsDomainApproved("acme.com") {
		t.Errorf("expected acme.com to be approved")
	}
	if !idp.IsDomainApproved("alice@acme.com") {
		t.Errorf("expected alice@acme.com full email to be approved")
	}
	if !idp.IsDomainApproved("BOB@ACME.COM") {
		t.Errorf("expected BOB@ACME.COM uppercase email to be approved")
	}
	if !idp.IsDomainApproved("@acme.com") {
		t.Errorf("expected @acme.com to be approved")
	}
	if idp.IsDomainApproved("bob@subsidiary.org") {
		t.Errorf("expected unapproved subsidiary.org email to be rejected")
	}
	if idp.IsDomainApproved("subsidiary.org") {
		t.Errorf("expected unapproved subsidiary.org to be rejected")
	}
	if idp.IsDomainApproved("unclaimed.com") {
		t.Errorf("expected undeclared unclaimed.com to be rejected")
	}
	if idp.IsDomainApproved("") {
		t.Errorf("expected empty email to be rejected")
	}
	if idp.IsDomainApproved("   ") {
		t.Errorf("expected whitespace email to be rejected")
	}
}
