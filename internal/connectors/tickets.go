package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// Ticket outbox policy (docs/16 D70).
const (
	// MaxTicketAttempts is how many times a ticket is tried before it is given up and a person is told.
	MaxTicketAttempts = 8
	// TicketGrace is how long a reservation waits for a tracker to be configured. A tracker added long after a
	// finding was reserved does not get a ticket for every critical finding there ever was.
	TicketGrace = 24 * time.Hour
	// ticketBatch is how many tickets one pass opens.
	ticketBatch = 50
)

// TicketStore is what the ticket sweeper needs.
type TicketStore interface {
	store.TicketOutbox
	GetFinding(ctx context.Context, tenantID, id uuid.UUID) (*domain.Finding, []*domain.Occurrence, error)
	GetApplication(ctx context.Context, tenantID, id uuid.UUID) (*domain.Application, error)
	RecordFindingEvents(ctx context.Context, tenantID uuid.UUID, events []*domain.FindingEvent) error
}

// ticketBackoff is the wait after the n-th failed attempt: 1, 2, 4 ... minutes, at most six hours.
func ticketBackoff(attempts int) time.Duration {
	d := time.Minute << min(attempts, 9)
	if d > 6*time.Hour {
		d = 6 * time.Hour
	}
	return d
}

// ProcessTickets opens the tickets that are due. A reservation is made in the merge transaction; this is the
// other half, outside any transaction: it calls the tracker once per attempt, records the ticket on success, and
// on failure schedules another attempt. It returns how many tickets were opened and how many attempts failed.
func ProcessTickets(ctx context.Context, st TicketStore, tr domain.TrackerResolver, now time.Time, log *slog.Logger) (opened, failed int) {
	pending, err := st.ListPendingTickets(ctx, now, ticketBatch)
	if err != nil {
		log.Warn("tickets: listing the pending ones failed", "error", err)
		return 0, 0
	}
	for _, p := range pending {
		if ctx.Err() != nil {
			return
		}
		f, _, err := st.GetFinding(ctx, p.TenantID, p.FindingID)
		if err != nil || f == nil {
			_ = st.SkipTicket(ctx, p.TenantID, p.FindingID, "the finding is gone")
			continue
		}
		if !f.State.IsActive() { // fixed, accepted or decided since: nobody needs a ticket for it
			_ = st.SkipTicket(ctx, p.TenantID, p.FindingID, "the finding is no longer open")
			continue
		}
		tracker, err := tr.ResolveTracker(ctx, p.TenantID)
		if err != nil {
			failed++
			giveUpOrRetryTicket(ctx, st, p, now, log, SanitizeTrackerError(fmt.Errorf("the tracker could not be resolved: %w", err)), f)
			continue
		}
		if tracker == nil {
			if now.Sub(p.Reserved) > TicketGrace {
				_ = st.SkipTicket(ctx, p.TenantID, p.FindingID, "no tracker was configured")
			} else {
				_ = st.DeferTicket(ctx, p.TenantID, p.FindingID, now.Add(10*time.Minute))
			}
			continue
		}
		appName := f.ApplicationID.String()
		if app, aerr := st.GetApplication(ctx, p.TenantID, f.ApplicationID); aerr == nil && app != nil && app.Name != "" {
			appName = app.Name
		}
		ref, url, err := tracker.CreateIssue(ctx, f, appName)
		if err != nil {
			failed++
			giveUpOrRetryTicket(ctx, st, p, now, log, SanitizeTrackerError(err), f)
			continue
		}
		if err := st.CompleteTicket(ctx, p.TenantID, p.FindingID, ref, url); err != nil {
			// The ticket exists and its record could not be written: say so loudly, a second ticket would be the next step.
			log.Error("tickets: the ticket was opened but could not be recorded", "tenant", p.TenantID, "finding", p.FindingID, "ticket", ref, "error", err)
			continue
		}
		opened++
		to, _ := json.Marshal(map[string]string{"action": "create_ticket", "status": "created", "ticket_id": ref, "url": url})
		_ = st.RecordFindingEvents(ctx, p.TenantID, []*domain.FindingEvent{{
			ID: domain.NewID(), FindingID: p.FindingID, At: now, Actor: "system:policy", Type: "ticket_created",
			Note: fmt.Sprintf("Ticket %s opened for this critical finding", ref), To: to,
		}})
	}
	return
}

// SanitizeTrackerError keeps what is useful of a tracker error and none of what may be a secret or a finding's text.
func SanitizeTrackerError(err error) string {
	if err == nil {
		return ""
	}
	return truncateRunes(err.Error(), 300)
}

type pendingTicket = store.PendingTicket

func giveUpOrRetryTicket(ctx context.Context, st TicketStore, p pendingTicket, now time.Time, log *slog.Logger, msg string, f *domain.Finding) {
	giveUp := p.Attempts+1 >= MaxTicketAttempts
	next := now.Add(ticketBackoff(p.Attempts + 1))
	if err := st.RetryTicket(ctx, p.TenantID, p.FindingID, msg, next, giveUp); err != nil {
		log.Warn("tickets: recording the failure failed", "error", err)
		return
	}
	if giveUp {
		log.Warn("tickets: giving up", "tenant", p.TenantID, "finding", p.FindingID, "error", msg)
		to, _ := json.Marshal(map[string]string{"action": "create_ticket", "status": "failed"})
		_ = st.RecordFindingEvents(ctx, p.TenantID, []*domain.FindingEvent{{
			ID: domain.NewID(), FindingID: p.FindingID, At: now, Actor: "system:policy", Type: "ticket_failed",
			Note: fmt.Sprintf("A ticket could not be opened after %d attempts: %s", MaxTicketAttempts, msg), To: to,
		}})
		if n, ok := st.(interface {
			CreateNotification(ctx context.Context, tenantID uuid.UUID, n *domain.Notification) error
		}); ok {
			_ = n.CreateNotification(ctx, p.TenantID, &domain.Notification{
				Kind: "ticket_failed", Title: "A ticket could not be opened",
				Body: truncateRunes(fmt.Sprintf("%s: %s", f.Title, msg), 300), Link: "/findings?sel=" + p.FindingID.String(), CreatedAt: now,
			})
		}
	}
}

// RunTicketSweeper opens due tickets every interval. One replica works at a time (an advisory lock).
func RunTicketSweeper(ctx context.Context, st TicketStore, tr domain.TrackerResolver, pool *pgxpool.Pool, interval time.Duration, log *slog.Logger) {
	const lockKey = int64(0x52414d50_5449434b) // "RAMPTICK"
	pass := func() {
		if pool != nil {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return
			}
			defer conn.Release()
			var got bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil || !got {
				return
			}
			defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey) }()
		}
		if o, f := ProcessTickets(ctx, st, tr, time.Now().UTC(), log); o+f > 0 {
			log.Info("tickets processed", "opened", o, "failed", f)
		}
	}
	pass()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}

type notificationCreator interface {
	CreateNotification(ctx context.Context, tenantID uuid.UUID, n *domain.Notification) error
}

// StoreTenantNotifier writes an in-app notification to the tenant (docs/16 D45).
type StoreTenantNotifier struct{ S notificationCreator }

// NotifyTenant implements TenantNotifier.
func (n StoreTenantNotifier) NotifyTenant(ctx context.Context, tenantID uuid.UUID, title, body, link string) error {
	return n.S.CreateNotification(ctx, tenantID, &domain.Notification{Kind: "ticket_resolved", Title: title, Body: body, Link: link, CreatedAt: time.Now().UTC()})
}
