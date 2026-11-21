package domain

import (
	"time"
)

// VEXSourceFormat defines supported upstream VEX document formats.
type VEXSourceFormat string

const (
	VEXFormatOpenVEX   VEXSourceFormat = "openvex"
	VEXFormatCycloneDX VEXSourceFormat = "cyclonedx"
	VEXFormatCSAF      VEXSourceFormat = "csaf"
)

// ClusterVEXSourceSpec is the specification of a ClusterVEXSource CRD resource (docs/47, Phase 5).
type ClusterVEXSourceSpec struct {
	Format   VEXSourceFormat     `json:"format"`
	Schedule string              `json:"schedule"`
	Source   VEXHTTPSource       `json:"source"`
	Matching *VEXSourceMatching  `json:"matching,omitempty"`
}

// VEXHTTPSource defines upstream HTTP endpoint and authentication for a VEX source.
type VEXHTTPSource struct {
	HTTP struct {
		URL              string                 `json:"url"`
		HeadersSecretRef *SecretReferenceObject `json:"headersSecretRef,omitempty"`
	} `json:"http"`
}

// SecretReferenceObject identifies a Secret holding authentication headers.
type SecretReferenceObject struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// VEXSourceMatching defines auto-application rules and application scoping.
type VEXSourceMatching struct {
	AutoApply  bool            `json:"autoApply"`
	TrustLevel string          `json:"trustLevel,omitempty"` // authoritative_vendor | advisory | community
	Scope      *VEXSourceScope `json:"scope,omitempty"`
}

// VEXSourceScope scopes a VEX source to specific applications.
type VEXSourceScope struct {
	ApplicationSelector struct {
		MatchLabels map[string]string `json:"matchLabels,omitempty"`
		MatchNames  []string          `json:"matchNames,omitempty"`
	} `json:"applicationSelector,omitempty"`
}

// ClusterVEXSourceStatus models synchronization metrics in CRD status.
type ClusterVEXSourceStatus struct {
	LastSyncTime    *time.Time `json:"lastSyncTime,omitempty"`
	LastSyncStatus  string     `json:"lastSyncStatus,omitempty"`
	StatementsCount int        `json:"statementsCount"`
	AppliedCount    int        `json:"appliedCount"`
}
