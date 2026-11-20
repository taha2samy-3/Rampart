package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ParserLastRun is what the Parsers page says about when a parser last worked: the last run that used it, how it ended, and the last time it
// finished well. A parser that has never been used has none.
type ParserLastRun struct {
	RunID       uuid.UUID
	Status      IngestRunStatus
	Error       string
	At          time.Time  // when the last run began
	LastSuccess *time.Time // the last run that completed, or nil if none has
}

// ParserRunStore summarises a tenant's runs by the parser (the run's format, the parser id) that read them.
type ParserRunStore interface {
	LastRunByParser(ctx context.Context, tenantID uuid.UUID) (map[string]ParserLastRun, error)
}
