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
	// ApplicationID scopes the group to one application; nil is a tenant-wide group, which only an admin may
	// create (docs/16 D90).
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	MemberCount   int        `json:"member_count,omitempty"`
	// Ticket is the group's one outbound ticket, once requested (D90).
	Ticket    *GroupTicket `json:"ticket,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// GroupTicket is the state of a group's ticket: reserved by the API, opened by the ticket sweeper.
type GroupTicket struct {
	Status      string     `json:"status"` // reserved | done | failed
	Attempts    int        `json:"attempts,omitempty"`
	Error       string     `json:"error,omitempty"`
	RequestedBy string     `json:"requested_by,omitempty"`
	TicketID    *uuid.UUID `json:"ticket_id,omitempty"`
	ExternalRef string     `json:"external_ref,omitempty"`
	URL         string     `json:"url,omitempty"`
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

// LiveEvent says that something on a topic changed for an application (nil: tenant-wide). It carries no data:
// the client refetches what it shows, under its own permissions (docs/16 D91).
type LiveEvent struct {
	ID            int64      `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	Topic         string     `json:"topic"` // ingests | findings | operations
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	At            time.Time  `json:"at"`
}
