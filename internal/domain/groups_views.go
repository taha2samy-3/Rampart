package domain

import (
	"time"

	"github.com/google/uuid"
)

// FindingGroup aggregates findings for ownership, correlation, or bulk action (docs/21 §6.1).
type FindingGroup struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Owner       string    `json:"owner,omitempty"`
	MemberCount int       `json:"member_count,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SavedView persists reusable search and filter criteria (docs/21 §6.2).
type SavedView struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Owner     string    `json:"owner"`
	Name      string    `json:"name"`
	Query     string    `json:"query"`
	Sort      string    `json:"sort,omitempty"`
	Scope     string    `json:"scope"` // tenant | user
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
