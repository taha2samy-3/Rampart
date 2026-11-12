package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// VEXJustifications are the five OpenVEX justifications a not_affected decision must give one of
// (docs/03, docs/05 section 8).
var VEXJustifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// TriageError is a request the rules refuse; the API answers 400 with its message.
type TriageError struct{ Msg string }

func (e *TriageError) Error() string { return e.Msg }

// ErrNothingToChange is returned for a request that would change nothing.
var ErrNothingToChange = &TriageError{Msg: "nothing to change: give a state, severity, tags or a note"}

// Limits that keep one finding's triage data bounded.
const (
	MaxTags      = 50
	MaxTagLength = 64
	MaxNote      = 4000
)

// TriageRequest is a human decision on one finding (docs/11 PATCH /findings/{id}).
type TriageRequest struct {
	State           FindingState // empty: the state stays
	Justification   string       // an OpenVEX justification, required for not_affected
	ImpactStatement string
	Severity        string // an override; SeverityReason is then required
	SeverityReason  string
	Tags            *[]string // nil: tags stay; an empty list clears them
	DuplicateOf     *uuid.UUID
	Note            string
	// ViaRiskAcceptance is set only by the risk-acceptance flow (owner, expiry, approval; docs/01 C5). It is not
	// part of any API body: a plain decision cannot accept a risk, because that would be an acceptance that never expires.
	ViaRiskAcceptance bool
}

// ApplyTriage applies a decision to f in place and returns the timeline events it produced. It enforces the
// rules of D18 and touches nothing outside the triage fields (state, previous_state, state_reason, resolution,
// justification, impact statement, duplicate_of, severity override, tags). The caller persists f and the events
// together, and bumps the version.
func ApplyTriage(f *Finding, req TriageRequest, actor string, now time.Time) ([]*FindingEvent, error) {
	var events []*FindingEvent
	event := func(typ string, from, to any, note string) {
		fj, _ := json.Marshal(from)
		tj, _ := json.Marshal(to)
		ev := &FindingEvent{ID: NewID(), FindingID: f.ID, At: now, Actor: actor, Type: typ, Note: note}
		if from != nil {
			ev.From = fj
		}
		if to != nil {
			ev.To = tj
		}
		events = append(events, ev)
	}
	if len(req.Note) > MaxNote {
		return nil, &TriageError{Msg: fmt.Sprintf("the note is longer than %d characters", MaxNote)}
	}
	note := strings.TrimSpace(req.Note)

	// Validate everything before changing anything, so a refused request leaves f untouched.
	var newSev Severity
	if req.Severity != "" {
		newSev = ParseSeverity(req.Severity)
		if newSev.Rank() == 0 {
			return nil, &TriageError{Msg: "severity must be critical, high, medium, low or info"}
		}
		if strings.TrimSpace(req.SeverityReason) == "" {
			return nil, &TriageError{Msg: "a severity override needs a reason"}
		}
	}
	var tags []string
	if req.Tags != nil {
		seen := map[string]bool{}
		for _, t := range *req.Tags {
			if t = strings.TrimSpace(t); t == "" || seen[t] {
				continue
			}
			if len(t) > MaxTagLength {
				return nil, &TriageError{Msg: fmt.Sprintf("a tag is longer than %d characters", MaxTagLength)}
			}
			seen[t] = true
			tags = append(tags, t)
		}
		if len(tags) > MaxTags {
			return nil, &TriageError{Msg: fmt.Sprintf("at most %d tags", MaxTags)}
		}
		slices.Sort(tags)
	}
	next := f.State
	stateChange := req.State != ""
	if stateChange {
		if !req.State.IsValid() {
			return nil, &TriageError{Msg: "unknown state " + string(req.State)}
		}
		if err := f.State.CanTransitionTo(req.State); err != nil {
			return nil, &TriageError{Msg: err.Error()}
		}
		if req.State == StateRiskAccepted && !req.ViaRiskAcceptance {
			return nil, &TriageError{Msg: "a risk is accepted through a risk acceptance, which needs an owner and an expiry"}
		}
		next = req.State
	}
	justification := strings.TrimSpace(req.Justification)
	if next == StateNotAffected && (stateChange || justification != "") {
		if justification == "" && f.Justification != "" && !stateChange {
			justification = f.Justification
		}
		if !slices.Contains(VEXJustifications, justification) {
			return nil, &TriageError{Msg: "not_affected needs one of the OpenVEX justifications: " + strings.Join(VEXJustifications, ", ")}
		}
	} else if justification != "" {
		return nil, &TriageError{Msg: "a justification belongs to a not_affected decision"}
	}
	if next == StateDuplicate && stateChange {
		if req.DuplicateOf == nil || *req.DuplicateOf == f.ID {
			return nil, &TriageError{Msg: "a duplicate needs the id of the finding it duplicates, and it cannot be itself"}
		}
	} else if req.DuplicateOf != nil {
		return nil, &TriageError{Msg: "duplicateOf belongs to a duplicate decision"}
	}
	changed := stateChange || req.Severity != "" || req.Tags != nil || note != "" || strings.TrimSpace(req.ImpactStatement) != ""
	if !changed || (stateChange && req.State == f.State && justification == "" && req.Severity == "" && req.Tags == nil && note == "") {
		return nil, ErrNothingToChange
	}

	// Apply.
	if stateChange && req.State != f.State {
		old := f.State
		if old.IsActive() && !next.IsActive() {
			f.PreviousState = old // where an expiry or a reactivation returns to (D18)
		} else if next.IsActive() {
			f.PreviousState = ""
		}
		f.State = next
		f.StateReason = note
		switch next {
		case StateFixed:
			r := ResolutionFixed
			f.Resolution, f.ResolvedAt = &r, &now
		case StateNotAffected:
			r := ResolutionNotAffected
			f.Resolution, f.ResolvedAt = &r, &now
		case StateRiskAccepted:
			r := ResolutionRiskAccepted
			f.Resolution, f.ResolvedAt = &r, &now
		case StateOutOfScope:
			r := ResolutionOutOfScope
			f.Resolution, f.ResolvedAt = &r, &now
		case StateDuplicate:
			r := ResolutionDuplicate
			f.Resolution, f.ResolvedAt = &r, &now
		default: // back to an active disposition
			f.Resolution, f.ResolvedAt = nil, nil
		}
		if next != StateNotAffected {
			f.Justification, f.ImpactStatement = "", ""
		}
		if next != StateDuplicate {
			f.DuplicateOfID = nil
		}
		if next == StateOpen && old == StateFixed {
			f.ReopenedCount++
		}
		event("state_changed", old, next, note)
		note = "" // the note is on the state event
	}
	if next == StateNotAffected {
		if justification != "" {
			f.Justification = justification
		}
		if s := strings.TrimSpace(req.ImpactStatement); s != "" {
			f.ImpactStatement = s
		}
	}
	if next == StateDuplicate && req.DuplicateOf != nil {
		id := *req.DuplicateOf
		f.DuplicateOfID = &id
	}
	if req.Severity != "" && newSev != f.Severity {
		old := f.Severity
		f.Severity = newSev
		reason := strings.TrimSpace(req.SeverityReason)
		f.SeverityOverrideReason = &reason
		event("severity_changed", old, newSev, reason)
	}
	if req.Tags != nil && !slices.Equal(f.Tags, tags) {
		event("tags_changed", f.Tags, tags, "")
		f.Tags = tags
	}
	if note != "" {
		event("note_added", nil, nil, note)
	}
	if len(events) == 0 {
		return nil, ErrNothingToChange
	}
	f.UpdatedAt = now
	return events, nil
}

// IsTriageError reports whether err is a refused triage request.
func IsTriageError(err error) bool {
	var te *TriageError
	return errors.As(err, &te)
}
