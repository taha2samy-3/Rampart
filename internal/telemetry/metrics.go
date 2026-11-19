package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Application metrics. They use the global meter, which delegates to the provider installed by
// Setup, so they can be declared at package level and recorded before or after Setup.
var (
	meter = otel.Meter("rampart")

	// ingestRuns counts finished ingest runs by final status (rampart_ingest_runs_total).
	ingestRuns, _ = meter.Int64Counter("rampart.ingest.runs",
		metric.WithDescription("Ingest runs finished, by final status."))
	// ingestFindings counts findings touched by ingest runs, by outcome (rampart_ingest_findings_total).
	ingestFindings, _ = meter.Int64Counter("rampart.ingest.findings",
		metric.WithDescription("Findings processed by ingest runs, by outcome: created, updated, untouched, reactivated, closed."))

	// ticketOutboxDepth tracks pending tickets in outbox (rampart_ticket_outbox_depth).
	ticketOutboxDepth, _ = meter.Int64UpDownCounter("rampart.ticket.outbox_depth",
		metric.WithDescription("Pending tickets in outbox."))
	// ticketDispatches tracks ticket dispatch attempts (rampart_ticket_dispatches_total).
	ticketDispatches, _ = meter.Int64Counter("rampart.ticket.dispatches",
		metric.WithDescription("Ticket dispatch attempts by status."))

	// connectorStatus tracks connector health status (rampart_connector_status).
	connectorStatus, _ = meter.Int64UpDownCounter("rampart.connector.status",
		metric.WithDescription("Connector health status (1=connected, 0=unhealthy)."))

	// heldClosePending tracks pending mass-close batches (rampart_held_close_pending).
	heldClosePending, _ = meter.Int64UpDownCounter("rampart.held_close.pending",
		metric.WithDescription("Held close batches awaiting review."))

	// feedSyncs tracks vulnerability intelligence feed sync attempts (rampart_feed_syncs_total), by feed and status
	// (success or failure). The failure rate is rampart_feed_syncs_total{status="failure"}.
	feedSyncs, _ = meter.Int64Counter("rampart.feed.syncs",
		metric.WithDescription("Vulnerability intelligence feed sync attempts, by feed and status (success, failure)."))
	// feedSyncDuration is how long a feed's step of a round took (rampart_feed_sync_duration_seconds).
	feedSyncDuration, _ = meter.Float64Histogram("rampart.feed.sync.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of one feed's sync step, by feed."),
		metric.WithExplicitBucketBoundaries(1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800))
	// feedLastSuccess is when a feed last synced successfully (rampart_feed_last_success_seconds): the alert that catches a
	// feed that has silently stopped, which a counter of failures cannot (a feed that is never tried fails nothing).
	feedLastSuccess, _ = meter.Float64Gauge("rampart.feed.last.success",
		metric.WithUnit("s"),
		metric.WithDescription("Unix time of the last successful sync of a feed, by feed."))
	// feedRecords counts the records a feed wrote (rampart_feed_records_synced_total).
	feedRecords, _ = meter.Int64Counter("rampart.feed.records.synced",
		metric.WithDescription("Records written by feed syncs, by feed."))
	// findingsRekeyed counts findings renamed or merged after an identifier became an alias (rampart_findings_rekeyed_total).
	findingsRekeyed, _ = meter.Int64Counter("rampart.findings.rekeyed",
		metric.WithDescription("Findings re-keyed after an identifier became an alias of a CVE, by outcome (renamed, merged)."))
)

// logins counts sign-in attempts (rampart_auth_logins_total), by method and result.
var logins, _ = meter.Int64Counter("rampart.auth.logins",
	metric.WithDescription("Sign-in attempts, by method (local, oidc) and result (success, failure, locked, rate_limited)."))

// RecordLogin records a sign-in attempt.
func RecordLogin(ctx context.Context, method, result string) {
	logins.Add(ctx, 1, metric.WithAttributes(attribute.String("method", method), attribute.String("result", result)))
}

// RecordIngestRun records a finished run.
func RecordIngestRun(ctx context.Context, status string) {
	ingestRuns.Add(ctx, 1, metric.WithAttributes(attribute.String("status", status)))
}

// RecordIngestOutcome records how many findings a run created, updated, and so on.
func RecordIngestOutcome(ctx context.Context, outcome string, n int) {
	if n > 0 {
		ingestFindings.Add(ctx, int64(n), metric.WithAttributes(attribute.String("outcome", outcome)))
	}
}

// RecordTicketDispatch records an attempt to dispatch a ticket.
func RecordTicketDispatch(ctx context.Context, connector, status string) {
	ticketDispatches.Add(ctx, 1, metric.WithAttributes(
		attribute.String("connector", connector),
		attribute.String("status", status),
	))
}

// AddTicketOutboxDepth updates the pending outbox ticket count delta.
func AddTicketOutboxDepth(ctx context.Context, delta int64) {
	ticketOutboxDepth.Add(ctx, delta)
}

// RecordConnectorStatus records the health status of a connector (1 for ok, 0 for failure).
func RecordConnectorStatus(ctx context.Context, connectorName, connectorType string, connected bool) {
	val := int64(0)
	if connected {
		val = 1
	}
	connectorStatus.Add(ctx, val, metric.WithAttributes(
		attribute.String("connector_name", connectorName),
		attribute.String("connector_type", connectorType),
	))
}

// AddHeldClosePending updates the count of pending held close batches.
func AddHeldClosePending(ctx context.Context, delta int64) {
	heldClosePending.Add(ctx, delta)
}

// RecordFeedSync records an attempt to synchronize a threat feed.
func RecordFeedSync(ctx context.Context, feed, status string) {
	feedSyncs.Add(ctx, 1, metric.WithAttributes(
		attribute.String("feed", feed),
		attribute.String("status", status),
	))
}

// RecordFeedLastSuccess records when a feed last synced successfully.
func RecordFeedLastSuccess(ctx context.Context, feed string, at time.Time) {
	feedLastSuccess.Record(ctx, float64(at.Unix()), metric.WithAttributes(attribute.String("feed", feed)))
}

// RecordFeedDuration records how long one feed's step of a sync round took.
func RecordFeedDuration(ctx context.Context, feed string, d time.Duration) {
	feedSyncDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("feed", feed)))
}

// RecordFeedRecords records the records a feed wrote in a round.
func RecordFeedRecords(ctx context.Context, feed string, n int64) {
	if n > 0 {
		feedRecords.Add(ctx, n, metric.WithAttributes(attribute.String("feed", feed)))
	}
}

// RecordFindingsRekeyed records findings re-keyed by an alias change, by outcome.
func RecordFindingsRekeyed(ctx context.Context, outcome string, n int) {
	if n > 0 {
		findingsRekeyed.Add(ctx, int64(n), metric.WithAttributes(attribute.String("outcome", outcome)))
	}
}
