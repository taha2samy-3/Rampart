package domain

import (
	"time"

	"github.com/google/uuid"
)

// DTrackSyncState defines the debounce state of a project sync.
type DTrackSyncState string

const (
	DTrackSyncStateIdle    DTrackSyncState = "idle"
	DTrackSyncStateSyncing DTrackSyncState = "syncing"
)

// DTrackSync tracks synchronization and debouncing state for a Dependency-Track project (D23, Milestone 3.4).
type DTrackSync struct {
	TenantID    uuid.UUID       `json:"tenant_id"`
	ProjectUUID string          `json:"project_uuid"`
	SourceID    uuid.UUID       `json:"source_id"`
	State       DTrackSyncState `json:"state"`
	Dirty       bool            `json:"dirty"`
	LastSyncAt  *time.Time      `json:"last_sync_at,omitempty"`
	NextAt      *time.Time      `json:"next_at,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// DTrackProjectRecord tracks portfolio projects and their mapping status to Rampart applications (docs/10 §3).
type DTrackProjectRecord struct {
	TenantID       uuid.UUID  `json:"tenant_id"`
	SourceID       uuid.UUID  `json:"source_id"`
	ProjectUUID    string     `json:"project_uuid"`
	Name           string     `json:"name"`
	Version        string     `json:"version,omitempty"`
	Purl           string     `json:"purl,omitempty"`
	Active         bool       `json:"active"`
	LastBomImport  *time.Time `json:"last_bom_import,omitempty"`
	ApplicationID  *uuid.UUID `json:"application_id,omitempty"`
	MappingRule    string     `json:"mapping_rule,omitempty"`
	UnmappedReason string     `json:"unmapped_reason,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

