package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// GroupTicketStore is what the group half of the ticket sweeper needs (docs/16 D90).
type GroupTicketStore interface {
	TicketStore
	store.GroupTicketOutbox
	GetFindingGroup(ctx context.Context, tenantID, id uuid.UUID) (*domain.FindingGroup, error)
	ListGroupFindings(ctx context.Context, tenantID, groupID uuid.UUID) ([]uuid.UUID, error)
}

// maxGroupTicketLines is how many members the ticket body lists; the rest are counted.
const maxGroupTicketLines = 50

// GroupIssue builds the finding a tracker turns into the group's ticket. Its ID is the group's, so the label the
// retry searches for (FindingLabel) names the group, never one member that may have its own ticket. Severity is the
// worst of the members; the description lists them, worst first.
func GroupIssue(g *domain.FindingGroup, members []*domain.Finding) *domain.Finding {
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].Severity.Rank() != members[j].Severity.Rank() {
			return members[i].Severity.Rank() > members[j].Severity.Rank()
		}
		return members[i].RiskScore > members[j].RiskScore
	})
	lead := *members[0]
	lead.ID = g.ID
	lead.Title = fmt.Sprintf("%s (%d findings)", g.Name, len(members))
	lead.RuleID = ""
	lead.Location = domain.Location{}
	var b strings.Builder
	if g.Description != "" {
		b.WriteString(g.Description)
		b.WriteString("\n\n")
	}
	for i, m := range members {
		if i == maxGroupTicketLines {
			fmt.Fprintf(&b, "... and %d more\n", len(members)-maxGroupTicketLines)
			break
		}
		where := m.Location.PrimaryPath()
		if where != "" {
			where = " (" + truncateRunes(where, 200) + ")"
		}
		fmt.Fprintf(&b, "- [%s] %s%s, finding %s\n", strings.ToUpper(string(m.Severity)), truncateRunes(m.Title, 200), where, m.ID)
	}
	lead.Description = b.String()
	return &lead
}

// ProcessGroupTickets opens the group tickets that were requested (POST /groups/{id}/ticket). As for single
// tickets, the tracker is called outside any transaction, a retry first looks for the issue by its label, and a
// failure is retried with backoff until MaxTicketAttempts.
func ProcessGroupTickets(ctx context.Context, st GroupTicketStore, tr domain.TrackerResolver, now time.Time, log *slog.Logger) (opened, failed int) {
	pending, err := st.ListPendingGroupTickets(ctx, now, ticketBatch)
	if err != nil {
		log.Warn("group tickets: listing the pending ones failed", "error", err)
		return 0, 0
	}
	for _, p := range pending {
		if ctx.Err() != nil {
			return
		}
		retry := func(err error, giveUp bool) {
			failed++
			isFatal, _ := domain.IsFatalTrackerError(err)
			giveUp = giveUp || isFatal || p.Attempts+1 >= MaxTicketAttempts
			if serr := st.RetryGroupTicket(ctx, p.TenantID, p.GroupID, SanitizeTrackerError(err), now.Add(ticketBackoff(p.Attempts+1)), giveUp); serr != nil {
				log.Warn("group tickets: recording the failure failed", "error", serr)
			}
		}
		g, err := st.GetFindingGroup(ctx, p.TenantID, p.GroupID)
		if err != nil || g == nil {
			continue // the group was deleted: its reservation went with it
		}
		ids, err := st.ListGroupFindings(ctx, p.TenantID, p.GroupID)
		if err != nil {
			retry(err, false)
			continue
		}
		var members []*domain.Finding
		for _, id := range ids {
			if f, _, ferr := st.GetFinding(ctx, p.TenantID, id); ferr == nil && f != nil && f.State.IsActive() {
				members = append(members, f)
			}
		}
		if len(members) == 0 {
			retry(fmt.Errorf("the group has no open findings"), true)
			continue
		}
		tracker, err := tr.ResolveTracker(ctx, p.TenantID)
		if err != nil {
			retry(fmt.Errorf("the tracker could not be resolved: %w", err), false)
			continue
		}
		if tracker == nil {
			retry(fmt.Errorf("no tracker is configured"), true)
			continue
		}
		connName := "tracker"
		if n := tracker.Name(); n != "" {
			connName = n
		}
		issue := GroupIssue(g, members)
		var ref, url string
		if p.Attempts > 0 {
			ref, url, err = tracker.FindIssueByLabel(ctx, FindingLabel(g.ID))
			if err != nil {
				retry(fmt.Errorf("checking for an existing issue failed: %w", err), false)
				continue
			}
		}
		if ref == "" {
			appName := "several applications"
			if g.ApplicationID != nil {
				appName = g.ApplicationID.String()
				if app, aerr := st.GetApplication(ctx, p.TenantID, *g.ApplicationID); aerr == nil && app != nil && app.Name != "" {
					appName = app.Name
				}
			}
			ref, url, err = tracker.CreateIssue(ctx, issue, appName)
			if err != nil {
				retry(err, false)
				continue
			}
		}
		if err := st.CompleteGroupTicket(ctx, p.TenantID, p.GroupID, connName, ref, url); err != nil {
			log.Error("group tickets: the ticket was opened but could not be recorded", "tenant", p.TenantID, "group", p.GroupID, "ticket", ref, "error", err)
			continue
		}
		opened++
		to, _ := json.Marshal(map[string]string{"action": "create_ticket", "status": "created", "group_id": g.ID.String(), "ticket_id": ref, "url": url, "connector": connName})
		events := make([]*domain.FindingEvent, 0, len(members))
		for _, m := range members {
			events = append(events, &domain.FindingEvent{
				ID: domain.NewID(), FindingID: m.ID, At: now, Actor: "system:policy", Type: "ticket_created",
				Note: fmt.Sprintf("Ticket %s opened for group %q", ref, g.Name), To: to,
			})
		}
		_ = st.RecordFindingEvents(ctx, p.TenantID, events)
	}
	return
}
