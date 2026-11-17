package scoring

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// WarnWindow is how long before its deadline a finding is announced (docs/06: beforeBreach).
const WarnWindow = 24 * time.Hour

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func findingsLink(q string) string { return "/findings?q=" + url.QueryEscape(q) }

// notifyBreaches tells the tenant that findings passed their deadline. One finding gets its own title; several
// are one message, so a sweep after a long outage is not a flood.
func (s *Scorer) notifyBreaches(ctx context.Context, tenantID uuid.UUID, n int, now time.Time) {
	nt, ok := s.store.(store.Notifications)
	if !ok || n == 0 {
		return
	}
	title := fmt.Sprintf("%d %s passed their deadline", n, plural(n, "finding", "findings"))
	if n == 1 {
		title = "A finding passed its deadline"
	}
	notif := &domain.Notification{Kind: domain.NotifySLABreached, Title: title, Link: findingsLink("sla:breached"), CreatedAt: now}
	_ = nt.CreateNotification(ctx, tenantID, notif)
	if s.router != nil {
		_ = s.router.RouteInAppNotification(ctx, tenantID, notif)
	}
}

// WarnDueSoon announces the findings whose deadline falls within WarnWindow, once each. It returns how many.
func (s *Scorer) WarnDueSoon(ctx context.Context, tenantID uuid.UUID, now time.Time) (int, error) {
	nt, ok := s.store.(store.Notifications)
	if !ok {
		return 0, nil
	}
	due, err := nt.WarnSLADueSoon(ctx, tenantID, now, WarnWindow)
	if err != nil || len(due) == 0 {
		return 0, err
	}
	title := fmt.Sprintf("%d findings are due within a day", len(due))
	body := ""
	if len(due) == 1 {
		title = "A finding is due within a day"
		body = due[0].Title
	} else {
		var names []string
		for i, d := range due {
			if i == 3 {
				break
			}
			names = append(names, d.Title)
		}
		body = strings.Join(names, "; ")
	}
	notif := &domain.Notification{Kind: domain.NotifySLADueSoon, Title: title, Body: body, Link: findingsLink("sla:due:1d"), CreatedAt: now}
	err = nt.CreateNotification(ctx, tenantID, notif)
	if s.router != nil {
		_ = s.router.RouteInAppNotification(ctx, tenantID, notif)
	}
	return len(due), err
}

// WarnExpiringAcceptances announces the risk acceptances that end in 14 days, then in 1 day.
func (s *Scorer) WarnExpiringAcceptances(ctx context.Context, tenantID uuid.UUID, now time.Time) (int, error) {
	nt, ok := s.store.(store.Notifications)
	if !ok {
		return 0, nil
	}
	list, err := nt.WarnExpiringAcceptances(ctx, tenantID, now)
	for _, e := range list {
		title := fmt.Sprintf("A risk acceptance ends in %d %s", e.DaysLeft, plural(e.DaysLeft, "day", "days"))
		body := fmt.Sprintf("%s. Owner: %s. %d %s will return to the queue.", e.Justification, strings.TrimPrefix(e.Owner, "user:"), e.Findings, plural(e.Findings, "finding", "findings"))
		notif := &domain.Notification{Kind: domain.NotifyAcceptanceEnding, Title: title, Body: body, Link: "/workflow", CreatedAt: now}
		if cerr := nt.CreateNotification(ctx, tenantID, notif); cerr != nil && err == nil {
			err = cerr
		}
		if s.router != nil {
			_ = s.router.RouteInAppNotification(ctx, tenantID, notif)
		}
	}
	return len(list), err
}

// WarnExpiringAttestations announces the attestations of manual controls that end in 14 days, then in 1 day. One
// message for the sweep's finds, so a tenant with many controls gets one, not one each. The store writes it in the
// same transaction as the "announced" marker, so a reminder is never marked sent without being written.
func (s *Scorer) WarnExpiringAttestations(ctx context.Context, tenantID uuid.UUID, now time.Time) (int, error) {
	nt, ok := s.store.(store.Notifications)
	if !ok {
		return 0, nil
	}
	list, notif, err := nt.WarnExpiringAttestations(ctx, tenantID, now, func(list []domain.ExpiringAttestation) *domain.Notification {
		soonest := list[0].DaysLeft
		lines := make([]string, 0, len(list))
		for _, e := range list {
			soonest = min(soonest, e.DaysLeft)
			where := ""
			if e.Application != "" {
				where = " (" + e.Application + ")"
			}
			lines = append(lines, fmt.Sprintf("%s / %s%s: ends %s. Owner: %s.", e.FrameworkID, e.ControlID, where, e.ExpiresAt.UTC().Format("2 Jan 2006"), strings.TrimPrefix(e.Owner, "user:")))
		}
		title := fmt.Sprintf("%d %s within 14 days", len(list), plural(len(list), "attestation ends", "attestations end"))
		if soonest <= 1 {
			title = fmt.Sprintf("%d %s within 1 day", len(list), plural(len(list), "attestation ends", "attestations end"))
			for _, e := range list {
				if e.DaysLeft > 1 {
					title = fmt.Sprintf("%d %s within 14 days, the soonest within 1 day", len(list), plural(len(list), "attestation ends", "attestations end"))
					break
				}
			}
		}
		return &domain.Notification{Kind: domain.NotifyAttestationEnding, Title: title, Body: strings.Join(lines, "\n"), Link: "/compliance", CreatedAt: now}
	})
	if notif != nil && s.router != nil {
		_ = s.router.RouteInAppNotification(ctx, tenantID, notif)
	}
	return len(list), err
}
