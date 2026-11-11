package domain

import (
	"fmt"

	"github.com/google/uuid"
)

// NilID represents an empty, unassigned UUID.
var NilID = uuid.Nil

// NewID creates a new UUIDv7 identifier (time-ordered, per normative D5).
func NewID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		// Fallback to cryptographic random UUIDv4 in the extremely unlikely event
		// of a monotonic clock or entropy read error.
		return uuid.New()
	}
	return id
}

// ParseID parses and validates a string representation of a UUID.
func ParseID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return NilID, fmt.Errorf("domain: invalid UUID string %q: %w", s, err)
	}
	if id == NilID {
		return NilID, ErrInvalidTenantID
	}
	return id, nil
}
