package domain

import (
	"fmt"
	"time"
)

// RetentionPolicy says how long each kind of data is kept, in days (docs/04 RetentionPolicy, docs/03, docs/16 D53).
// Zero means "keep for ever". Until the RetentionPolicy resource exists (Phase 5), one policy from the
// configuration applies to every tenant.
type RetentionPolicy struct {
	// OccurrencesDays: an occurrence no scanner reports any more (present = false) is deleted this long after it
	// was last seen (D12). The finding stays; only the stale evidence goes.
	OccurrencesDays int `json:"occurrencesDays" yaml:"occurrencesDays"`
	// RawReportsDays: the report as the scanner wrote it, in object storage (D51).
	RawReportsDays int `json:"rawReportsDays" yaml:"rawReportsDays"`
	// SecretReportsDays: the raw report of a run that found secrets. The stored findings never hold a secret
	// (D42), but the report does, so it goes sooner (docs/07).
	SecretReportsDays int `json:"secretReportsDays" yaml:"secretReportsDays"`
	// ResolvedFindingsDays: a finding fixed this long ago, and not reported since, is deleted with its timeline.
	ResolvedFindingsDays int `json:"resolvedFindingsDays" yaml:"resolvedFindingsDays"`
	// EventsDays: finding timelines (finding_event), dropped a month at a time.
	EventsDays int `json:"eventsDays" yaml:"eventsDays"`
	// AuditDays: the audit log (audit_event), dropped a month at a time, never row by row (D46).
	AuditDays int `json:"auditDays" yaml:"auditDays"`
	// RunResultsDays: what each run found new or fixed, kept for the CI gate (D10).
	RunResultsDays int `json:"runResultsDays" yaml:"runResultsDays"`
}

// DefaultRetentionPolicy is docs/04's RetentionPolicy example plus the two values other documents fix: secret
// reports 7 days (docs/07) and run results 30 days (D10).
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		OccurrencesDays:      180,
		RawReportsDays:       90,
		SecretReportsDays:    7,
		ResolvedFindingsDays: 730,
		EventsDays:           730,
		AuditDays:            2555, // seven years
		RunResultsDays:       30,
	}
}

// Minimums a policy may not go below (zero, "keep for ever", is always allowed). They come from what the data is
// evidence for, so a shorter value would quietly break a promise made elsewhere:
//
//   - AuditDays 365: PCI DSS 4.0.1 requirement 10.5.1 keeps audit history for at least twelve months.
//   - EventsDays 365: the finding timeline is the record of who decided what about a finding (accepted,
//     not affected), the same kind of trail.
//   - ResolvedFindingsDays 180: SLA adherence and MTTR look back 90 days and trends 180 (D43); deleting resolved
//     findings sooner would change those numbers.
//   - Every other value: one day.
const (
	MinAuditDays            = 365
	MinEventsDays           = 365
	MinResolvedFindingsDays = 180
)

// Validate refuses a policy that would delete evidence sooner than the minimums above.
func (p RetentionPolicy) Validate() error {
	check := func(name string, v, minimum int, why string) error {
		if v < 0 {
			return fmt.Errorf("retention.%s must not be negative", name)
		}
		if v != 0 && v < minimum {
			return fmt.Errorf("retention.%s is %d days; the minimum is %d (%s), or 0 to keep for ever", name, v, minimum, why)
		}
		return nil
	}
	for _, c := range []struct {
		name   string
		v, min int
		why    string
	}{
		{"auditDays", p.AuditDays, MinAuditDays, "PCI DSS 10.5.1 keeps audit history for twelve months"},
		{"eventsDays", p.EventsDays, MinEventsDays, "the finding timeline records triage decisions"},
		{"resolvedFindingsDays", p.ResolvedFindingsDays, MinResolvedFindingsDays, "trends look back 180 days"},
		{"occurrencesDays", p.OccurrencesDays, 1, "one day"},
		{"rawReportsDays", p.RawReportsDays, 1, "one day"},
		{"secretReportsDays", p.SecretReportsDays, 1, "one day"},
		{"runResultsDays", p.RunResultsDays, 1, "one day"},
	} {
		if err := check(c.name, c.v, c.min, c.why); err != nil {
			return err
		}
	}
	return nil
}

// Cutoff is the moment before which data of a kind kept for days is removed, or the zero time when days is 0.
func Cutoff(now time.Time, days int) time.Time {
	if days <= 0 {
		return time.Time{}
	}
	return now.Add(-time.Duration(days) * 24 * time.Hour)
}

// AbandonedUploadAfter is how long an upload that was created and never completed keeps its object. Its
// presigned URL lives 15 minutes (D9), so a day is generous.
const AbandonedUploadAfter = 24 * time.Hour
