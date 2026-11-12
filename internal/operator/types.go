package operator

import (
	"time"

	"rampart/internal/domain"
)

// Condition represents the state of a resource at a point in time (metav1.Condition).
type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"` // "True" | "False" | "Unknown"
	Reason             string    `json:"reason"`
	Message            string    `json:"message"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// CommonStatus contains shared status fields.
type CommonStatus struct {
	ObservedGeneration int64       `json:"observedGeneration,omitempty"`
	Conditions         []Condition `json:"conditions,omitempty"`
}

func (s *CommonStatus) SetCondition(condType, status, reason, message string) {
	now := time.Now().UTC()
	for i, c := range s.Conditions {
		if c.Type == condType {
			if c.Status != status || c.Reason != reason || c.Message != message {
				s.Conditions[i] = Condition{
					Type:               condType,
					Status:             status,
					Reason:             reason,
					Message:            message,
					LastTransitionTime: now,
				}
			}
			return
		}
	}
	s.Conditions = append(s.Conditions, Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}

func (s *CommonStatus) GetCondition(condType string) *Condition {
	for _, c := range s.Conditions {
		if c.Type == condType {
			return &c
		}
	}
	return nil
}

// TenantCR represents the Tenant Custom Resource.
type TenantCR struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Metadata   Metadata     `json:"metadata"`
	Spec       TenantSpec   `json:"spec"`
	Status     TenantStatus `json:"status,omitempty"`
}

type Metadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Generation  int64             `json:"generation,omitempty"`
}

type TenantSpec struct {
	DisplayName string   `json:"displayName"`
	Namespaces  []string `json:"namespaces,omitempty"`
	// DeletionPolicy is Retain (default: a tenant with data is not deleted) or Purge (docs/16 D21).
	DeletionPolicy string `json:"deletionPolicy,omitempty"`
}

type TenantStatus struct {
	CommonStatus `json:",inline"`
	TenantID     string `json:"tenantId,omitempty"`
}

// ApplicationCR represents the Application Custom Resource.
type ApplicationCR struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   Metadata          `json:"metadata"`
	Spec       ApplicationSpec   `json:"spec"`
	Status     ApplicationStatus `json:"status,omitempty"`
}

// ApplicationSpec is the shared spec (D3, D55): the operator and `rampart apply` map it the same way.
type ApplicationSpec = domain.ApplicationSpec

type ApplicationStatus struct {
	CommonStatus  `json:",inline"`
	ApplicationID string `json:"applicationId,omitempty"`
}

// ScanSourceCR represents the ScanSource Custom Resource.
type ScanSourceCR struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   Metadata         `json:"metadata"`
	Spec       ScanSourceSpec   `json:"spec"`
	Status     ScanSourceStatus `json:"status,omitempty"`
}

type SecretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type ScanSourceSpec struct {
	ScannerFamily string     `json:"scannerFamily"`
	Type          string     `json:"type,omitempty"`
	SecretRef     *SecretRef `json:"secretRef,omitempty"`
}

type ScanSourceStatus struct {
	CommonStatus `json:",inline"`
	ScanSourceID string `json:"scanSourceId,omitempty"`
}

// SLAPolicyCR represents the SLAPolicy Custom Resource (docs/04). The spec is kept as it came: the domain
// validates it, so the CRD schema and the API/CLI path share one set of rules.
type SLAPolicyCR struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Metadata   Metadata        `json:"metadata"`
	Spec       map[string]any  `json:"spec"`
	Status     SLAPolicyStatus `json:"status,omitempty"`
}

type SLAPolicyStatus struct {
	CommonStatus `json:",inline"`
}
