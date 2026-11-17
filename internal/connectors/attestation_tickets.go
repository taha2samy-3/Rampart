package connectors

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// AttestationTicketWindow is how long before its end a renewal ticket is opened: the first reminder (D123).
const AttestationTicketWindow = 14 * 24 * time.Hour

// AttestationTicketStore is what the attestation half of the ticket sweeper needs (docs/16 D124).
type AttestationTicketStore interface {
	store.AttestationTicketOutbox
}

// AttestationIssue builds the finding a tracker turns into the renewal ticket. Its ID is the attestation's, so the
// label a retry searches for (FindingLabel) names it. It is not a finding of any scan: the tracker only needs a title,
// a body and a severity, and the link it adds to the finding page leads nowhere for it.
func AttestationIssue(w store.AttestationTicketWork) *domain.Finding {
	where := "the whole tenant"
	if w.Application != "" {
		where = w.Application
	}
	return &domain.Finding{
		ID: w.AttestationID, TenantID: w.TenantID, Severity: domain.SeverityMedium, State: domain.StateOpen, Notice: "attestation-renewal",
		Title: fmt.Sprintf("Renew the attestation of %s / %s before %s", w.FrameworkID, w.ControlID, w.ExpiresAt.UTC().Format("2 Jan 2006")),
		Description: fmt.Sprintf("A person attested that control %s of %s is met for %s. That attestation ends on %s, and then the control reads "+
			"\"not assessed\" again.\n\nOwner: %s.\n\nRecord a new attestation in Rampart (Compliance, or Manual controls on the application page) before then; "+
			"this ticket closes by itself when you do.", w.ControlID, w.FrameworkID, where, w.ExpiresAt.UTC().Format("2 Jan 2006"), w.Owner),
	}
}

// ProcessAttestationTickets opens the renewal tickets of attestations that end within AttestationTicketWindow, and
// closes those whose attestation was renewed. It follows the group tickets (D90): the reservation is recorded before the
// tracker is called, a retry first looks for the issue by its label, a failure is retried with backoff until
// MaxTicketAttempts. A tenant with no tracker gets no ticket and no reservation: nothing waits for one to be added.
func ProcessAttestationTickets(ctx context.Context, st AttestationTicketStore, tr domain.TrackerResolver, now time.Time, log *slog.Logger) (opened, closed, failed int) {
	trackers := map[uuid.UUID]domain.Tracker{} // one resolution per tenant per pass
	resolve := func(tenant uuid.UUID) (domain.Tracker, error) {
		if t, ok := trackers[tenant]; ok {
			return t, nil
		}
		t, err := tr.ResolveTracker(ctx, tenant)
		if err == nil {
			trackers[tenant] = t
		}
		return t, err
	}

	work, err := st.ListAttestationTicketWork(ctx, now, AttestationTicketWindow, ticketBatch)
	if err != nil {
		log.Warn("attestation tickets: listing the work failed", "error", err)
		return 0, 0, 0
	}
	for _, w := range work {
		if ctx.Err() != nil {
			return
		}
		tracker, err := resolve(w.TenantID)
		if err != nil {
			log.Warn("attestation tickets: the tracker could not be resolved", "tenant", w.TenantID, "error", err)
			continue // nothing is reserved: the next pass tries again
		}
		if tracker == nil {
			continue
		}
		created, err := st.ReserveAttestationTicket(ctx, w.TenantID, w.AttestationID)
		if err != nil {
			log.Warn("attestation tickets: reserving failed", "error", err)
			continue
		}
		retry := func(err error) {
			failed++
			isFatal, _ := domain.IsFatalTrackerError(err)
			giveUp := isFatal || w.Attempts+1 >= MaxTicketAttempts
			msg := SanitizeTrackerError(err)
			if serr := st.RetryAttestationTicket(ctx, w.TenantID, w.AttestationID, msg, now.Add(ticketBackoff(w.Attempts+1)), giveUp); serr != nil {
				log.Warn("attestation tickets: recording the failure failed", "error", serr)
				return
			}
			if giveUp { // a ticket that gave up must not be silent: tell the tenant, who can send it back from the page
				if n, ok := st.(interface {
					CreateNotification(ctx context.Context, tenantID uuid.UUID, n *domain.Notification) error
				}); ok {
					_ = n.CreateNotification(ctx, w.TenantID, &domain.Notification{
						Kind: "ticket_failed", Title: "A renewal ticket could not be opened", CreatedAt: now, Link: "/compliance",
						Body: truncateRunes(fmt.Sprintf("%s / %s ends %s: %s. An administrator can try again from the application's Manual controls.", w.FrameworkID, w.ControlID, w.ExpiresAt.UTC().Format("2 Jan 2006"), msg), 300),
					})
				}
			}
		}
		connName := "tracker"
		if n := tracker.Name(); n != "" {
			connName = n
		}
		var ref, url string
		if !created || w.Attempts > 0 { // an earlier attempt, even one that died before it counted, may have created the issue
			if ref, url, err = tracker.FindIssueByLabel(ctx, FindingLabel(w.AttestationID)); err != nil {
				retry(fmt.Errorf("checking for an existing issue failed: %w", err))
				continue
			}
		}
		if ref == "" {
			appName := w.Application
			if appName == "" {
				appName = "the whole tenant"
			}
			if ref, url, err = tracker.CreateIssue(ctx, AttestationIssue(w), appName); err != nil {
				retry(err)
				continue
			}
		}
		if err := st.CompleteAttestationTicket(ctx, w.TenantID, w.AttestationID, connName, ref, url); err != nil {
			log.Error("attestation tickets: the ticket was opened but could not be recorded", "tenant", w.TenantID, "ticket", ref, "error", err)
			continue
		}
		opened++
	}

	// A renewed attestation closes its ticket. A failure leaves it open for the next pass.
	toClose, err := st.ListAttestationTicketsToClose(ctx, now, ticketBatch)
	if err != nil {
		log.Warn("attestation tickets: listing the tickets to close failed", "error", err)
		return
	}
	for _, c := range toClose {
		if ctx.Err() != nil {
			return
		}
		tracker, err := resolve(c.TenantID)
		if err != nil || tracker == nil {
			continue
		}
		if tracker.Name() != "" && c.Connector != "" && tracker.Name() != c.Connector {
			// The tenant changed tracker since: this ref belongs to the old one, which we cannot reach with this client.
			log.Warn("attestation tickets: the ticket was opened on another tracker; close it there", "ticket", c.Ref, "connector", c.Connector)
			_ = st.MarkAttestationTicketClosed(ctx, c.TenantID, c.AttestationID)
			continue
		}
		_ = tracker.Comment(ctx, c.Ref, "The attestation was renewed in Rampart. Closing this ticket.")
		if err := tracker.Close(ctx, c.Ref); err != nil {
			log.Warn("attestation tickets: closing failed", "ticket", c.Ref, "error", SanitizeTrackerError(err))
			continue
		}
		if err := st.MarkAttestationTicketClosed(ctx, c.TenantID, c.AttestationID); err == nil {
			closed++
		}
	}
	return
}
