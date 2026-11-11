package telemetry

import (
	"context"

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
)

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
