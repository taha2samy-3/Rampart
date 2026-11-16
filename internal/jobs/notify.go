package jobs

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
)

// NotifyDeliveryArgs is one message to one connector (docs/23 K4, docs/16 D97). The message is the routed
// NotificationMessage as JSON; it carries no secret: the worker resolves the connector's secrets when it sends.
type NotifyDeliveryArgs struct {
	TenantID  uuid.UUID       `json:"tenant_id"`
	Connector string          `json:"connector"`
	Message   json.RawMessage `json:"message"`
}

// Kind returns the job kind for River.
func (NotifyDeliveryArgs) Kind() string { return "notify_delivery" }

const (
	// NotifyQueue is the delivery queue. A slow chat service holds one of its workers, never an ingest worker.
	NotifyQueue = "notify"
	// NotifyMaxAttempts matches the ticket sweeper's budget (D70 A6). River's backoff spaces them out over
	// several hours; a job that runs out is kept as discarded with its last error.
	NotifyMaxAttempts = 8
)

// NotifyDeliveryHandler sends one delivery.
type NotifyDeliveryHandler func(ctx context.Context, args NotifyDeliveryArgs) error

// NotifyDeliveryWorker runs notify_delivery jobs.
type NotifyDeliveryWorker struct {
	river.WorkerDefaults[NotifyDeliveryArgs]
	Handle NotifyDeliveryHandler
}

func (w *NotifyDeliveryWorker) Work(ctx context.Context, job *river.Job[NotifyDeliveryArgs]) error {
	if w.Handle == nil {
		return ErrNoHandler
	}
	err := w.Handle(ctx, job.Args)
	if IsPermanent(err) {
		return river.JobCancel(err)
	}
	return err
}

// Timeout bounds one send; the notifiers' own HTTP timeouts are shorter.
func (w *NotifyDeliveryWorker) Timeout(*river.Job[NotifyDeliveryArgs]) time.Duration {
	return time.Minute
}

// EnqueueDelivery inserts one delivery job.
func (q *RiverQueue) EnqueueDelivery(ctx context.Context, tenantID uuid.UUID, connector string, message []byte) error {
	_, err := q.client.Insert(ctx, NotifyDeliveryArgs{TenantID: tenantID, Connector: connector, Message: message},
		&river.InsertOpts{Queue: NotifyQueue, MaxAttempts: NotifyMaxAttempts})
	return err
}
