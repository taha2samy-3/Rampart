package domain

import (
	"time"

	"github.com/google/uuid"
)

// Notification kinds (docs/16 D45).
const (
	NotifySLABreached      = "sla_breached"
	NotifySLADueSoon       = "sla_due_soon"
	NotifyAcceptanceEnding = "acceptance_expiring"
	NotifyAcceptanceEnded  = "acceptance_expired"
)

// Notification is one message to the people of a tenant: what a sweep found, with a link to where to act.
type Notification struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"-"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Body      string    `json:"body,omitempty"`
	Link      string    `json:"link,omitempty"` // an in-app path
	CreatedAt time.Time `json:"created_at"`
	Unread    bool      `json:"unread"`
}

// DueSoon is a finding whose deadline falls within the warning window and that was not warned about yet.
type DueSoon struct {
	ID    uuid.UUID
	Title string
	Band  string
	Due   time.Time
}

// ExpiringAcceptance is an approved risk acceptance that ends soon; DaysLeft is the threshold announced (14 or 1).
type ExpiringAcceptance struct {
	ID            uuid.UUID
	Justification string
	Owner         string
	ExpiresAt     time.Time
	Findings      int
	DaysLeft      int
}

// AccessBinding is a role on an application, hierarchy subtree, or tenant for a person, group or token (docs/04, docs/16 D8, D48).
type AccessBinding struct {
	ID              uuid.UUID `json:"id"`
	Subject         string    `json:"subject"` // an e-mail, or the subject of a token
	SubjectKind     string    `json:"subject_kind,omitempty"` // user | group
	IdP             string    `json:"idp,omitempty"`
	Role            string    `json:"role"`    // viewer | triager | maintainer | owner | admin
	ApplicationID   uuid.UUID `json:"application_id,omitempty"`
	ApplicationName string    `json:"application_name,omitempty"`
	HierarchyPath   string    `json:"hierarchy_path,omitempty"` // prefix for hierarchy subtree
	TenantScope     bool      `json:"tenant_scope,omitempty"`   // true for tenant-wide role
	ManagedBy       string    `json:"managed_by"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}
