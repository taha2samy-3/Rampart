package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ExternalAnalyzer represents a tenant-scoped external vulnerability analyzer microservice.
type ExternalAnalyzer struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	Name           string    `json:"name"`
	Enabled        bool      `json:"enabled"`
	Protocol       string    `json:"protocol"` // "grpc" or "http"
	Endpoint       string    `json:"endpoint,omitempty"`
	ServiceName    string    `json:"service_name,omitempty"`
	Namespace      string    `json:"namespace,omitempty"`
	Port           int       `json:"port,omitempty"`
	TimeoutSeconds int       `json:"timeout_seconds,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TargetAddress returns the resolved network address for the analyzer.
func (a *ExternalAnalyzer) TargetAddress() string {
	if a.Endpoint != "" {
		return a.Endpoint
	}
	if a.ServiceName != "" && a.Port > 0 {
		ns := a.Namespace
		if ns == "" {
			ns = "default"
		}
		return fmt.Sprintf("%s.%s.svc.cluster.local:%d", a.ServiceName, ns, a.Port)
	}
	return ""
}

// ClusterExternalAnalyzer represents a cluster-wide external vulnerability analyzer microservice.
type ClusterExternalAnalyzer struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Enabled        bool      `json:"enabled"`
	Protocol       string    `json:"protocol"` // "grpc" or "http"
	Endpoint       string    `json:"endpoint,omitempty"`
	ServiceName    string    `json:"service_name,omitempty"`
	Namespace      string    `json:"namespace,omitempty"`
	Port           int       `json:"port,omitempty"`
	TimeoutSeconds int       `json:"timeout_seconds,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TargetAddress returns the resolved network address for the analyzer.
func (a *ClusterExternalAnalyzer) TargetAddress() string {
	if a.Endpoint != "" {
		return a.Endpoint
	}
	if a.ServiceName != "" && a.Port > 0 {
		ns := a.Namespace
		if ns == "" {
			ns = "default"
		}
		return fmt.Sprintf("%s.%s.svc.cluster.local:%d", a.ServiceName, ns, a.Port)
	}
	return ""
}
