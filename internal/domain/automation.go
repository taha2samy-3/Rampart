package domain

import (
	"github.com/google/uuid"
)

var (
	// PolicyTicketOnCriticalID is the deterministic UUID of the built-in ticket-on-critical automation policy (docs/09, docs/16 D25, D29).
	PolicyTicketOnCriticalID = uuid.MustParse("00000000-0000-0000-0000-000000000002")
	// ActionCreateTicket is the action ledger entry for ticket creation.
	ActionCreateTicket = "create_ticket"
)

