package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidIdPType  = errors.New("identity provider: type must be 'oidc' or 'saml'")
	ErrMissingIssuer   = errors.New("identity provider: oidc.issuer is required")
	ErrMissingClientID = errors.New("identity provider: oidc.clientId is required")
	ErrTenantNotAllowed = errors.New("identity provider: tenant not permitted by cluster allowlist")
	ErrDomainNotApproved = errors.New("identity provider: email domain claim is not approved")
)

type IdPType string

const (
	IdPOIDC IdPType = "oidc"
	IdPSAML IdPType = "saml"
)

// OIDCClaimsConfig specifies claim mappings for OIDC identity assertions.
type OIDCClaimsConfig struct {
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
	Groups string `json:"groups,omitempty"`
}

// SecretKeyRef references a Kubernetes secret key.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// IdPOIDCConfig contains OpenID Connect settings.
type IdPOIDCConfig struct {
	Issuer               string           `json:"issuer"`
	ClientID             string           `json:"clientId"`
	ClientSecret         string           `json:"clientSecret,omitempty"`
	ClientSecretRef      *SecretKeyRef    `json:"clientSecretRef,omitempty"`
	Scopes               []string         `json:"scopes,omitempty"`
	Claims               OIDCClaimsConfig `json:"claims,omitempty"`
	RequireEmailVerified bool             `json:"requireEmailVerified,omitempty"`
	PKCE                 string           `json:"pkce,omitempty"`
	AcrValues            []string         `json:"acrValues,omitempty"`
	BackchannelLogout    bool             `json:"backchannelLogout,omitempty"`
}

// IdPSAMLConfig contains SAML 2.0 configuration.
type IdPSAMLConfig struct {
	MetadataURL       string           `json:"metadataURL,omitempty"`
	MetadataXML       string           `json:"metadataXML,omitempty"`
	EntityID          string           `json:"entityID,omitempty"`
	NameIDFormat      string           `json:"nameIDFormat,omitempty"`
	Attributes        OIDCClaimsConfig `json:"attributes,omitempty"`
	AllowIdPInitiated bool             `json:"allowIdPInitiated,omitempty"`
}

// IdPLoginConfig defines login filters and domain claims (docs/14 section 7, docs/16 D27).
type IdPLoginConfig struct {
	EmailDomains   []string `json:"emailDomains,omitempty"`
	AllowedDomains []string `json:"allowedDomains,omitempty"`
	RequireGroup   string   `json:"requireGroup,omitempty"`
}

// IdPProvisioningConfig defines just-in-time user and group provisioning rules.
type IdPProvisioningConfig struct {
	JIT              bool   `json:"jit,omitempty"`
	GroupFilter      string `json:"groupFilter,omitempty"`
	StripGroupPrefix string `json:"stripGroupPrefix,omitempty"`
}

// IdPSessionConfig configures user session lifetimes.
type IdPSessionConfig struct {
	IdleTimeout        string `json:"idleTimeout,omitempty"`
	AbsoluteTimeout    string `json:"absoluteTimeout,omitempty"`
	RevalidateInterval string `json:"revalidateInterval,omitempty"`
}

// DomainClaimStatus records the verification status of a corporate email domain (docs/16 D27).
type DomainClaimStatus struct {
	Domain     string     `json:"domain"`
	Approved   bool       `json:"approved"`
	Token      string     `json:"token,omitempty"`
	VerifiedAt *time.Time `json:"verifiedAt,omitempty"`
}

// IdPCondition represents the state of an identity provider at a point in time.
type IdPCondition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"` // "True" | "False" | "Unknown"
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// IdentityProviderStatus holds controller runtime status and conditions.
type IdentityProviderStatus struct {
	ObservedGeneration int64               `json:"observedGeneration,omitempty"`
	Conditions         []IdPCondition      `json:"conditions,omitempty"`
	RedirectURI        string              `json:"redirectURI,omitempty"`
	Domains            []DomainClaimStatus `json:"domains,omitempty"`
	JWKSLastFetched    *time.Time          `json:"jwksLastFetched,omitempty"`
	Logins24h          int                 `json:"logins24h,omitempty"`
}

// IdentityProviderSpec holds the desired configuration of an IdentityProvider or ClusterIdentityProvider.
type IdentityProviderSpec struct {
	DisplayName    string                `json:"displayName,omitempty"`
	Type           IdPType               `json:"type"`
	AllowedTenants []string              `json:"allowedTenants,omitempty"` // For ClusterIdentityProvider: tenant slugs allowed to use it
	OIDC           *IdPOIDCConfig        `json:"oidc,omitempty"`
	SAML           *IdPSAMLConfig        `json:"saml,omitempty"`
	Login          IdPLoginConfig        `json:"login,omitempty"`
	Provisioning   IdPProvisioningConfig `json:"provisioning,omitempty"`
	Session        IdPSessionConfig      `json:"session,omitempty"`
}

// IdentityProvider is the domain representation of tenant-scoped or cluster-scoped identity providers.
type IdentityProvider struct {
	ID          uuid.UUID              `json:"id"`
	TenantID    *uuid.UUID             `json:"tenantId,omitempty"` // nil for ClusterIdentityProvider
	Namespace   string                 `json:"namespace,omitempty"`
	Name        string                 `json:"name"`
	DisplayName string                 `json:"displayName"`
	Type        IdPType                `json:"type"`
	Spec        IdentityProviderSpec   `json:"spec"`
	Status      IdentityProviderStatus `json:"status"`
	CreatedAt   time.Time              `json:"createdAt"`
	UpdatedAt   time.Time              `json:"updatedAt"`
}

// Validate checks spec validity.
func (idp *IdentityProvider) Validate() error {
	t := strings.ToLower(string(idp.Type))
	if t != string(IdPOIDC) && t != string(IdPSAML) {
		return ErrInvalidIdPType
	}
	if t == string(IdPOIDC) {
		if idp.Spec.OIDC == nil || strings.TrimSpace(idp.Spec.OIDC.Issuer) == "" {
			return ErrMissingIssuer
		}
		if strings.TrimSpace(idp.Spec.OIDC.ClientID) == "" {
			return ErrMissingClientID
		}
	}
	return nil
}

// IsTenantAllowed checks if a tenant slug is permitted by a ClusterIdentityProvider (docs/16 D27).
// An empty AllowedTenants list allows all tenants.
func (idp *IdentityProvider) IsTenantAllowed(tenantSlug string) bool {
	if len(idp.Spec.AllowedTenants) == 0 {
		return true
	}
	for _, t := range idp.Spec.AllowedTenants {
		if strings.EqualFold(strings.TrimSpace(t), strings.TrimSpace(tenantSlug)) {
			return true
		}
	}
	return false
}

// IsDomainApproved checks if the given email or email domain is approved for login routing (docs/16 D27).
func (idp *IdentityProvider) IsDomainApproved(emailOrDomain string) bool {
	clean := strings.ToLower(strings.TrimSpace(emailOrDomain))
	if clean == "" {
		return false
	}
	if at := strings.LastIndex(clean, "@"); at >= 0 {
		clean = clean[at+1:]
	}
	// If no emailDomains specified in spec, domain approval restriction is not triggered
	if len(idp.Spec.Login.EmailDomains) == 0 {
		return true
	}
	// Check if this domain is declared
	declared := false
	for _, d := range idp.Spec.Login.EmailDomains {
		if strings.EqualFold(strings.TrimSpace(d), clean) {
			declared = true
			break
		}
	}
	if !declared {
		return false
	}
	// Must be in status.domains with approved == true (D27)
	for _, d := range idp.Status.Domains {
		if strings.EqualFold(strings.TrimSpace(d.Domain), clean) && d.Approved {
			return true
		}
	}
	return false
}
