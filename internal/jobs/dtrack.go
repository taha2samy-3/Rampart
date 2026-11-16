package jobs

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
)

// DTrackSyncJobArgs is one Dependency-Track sync on the dtrack-sync queue (docs/10 §9, ADR 0002, docs/16 D92): a
// project when ProjectUUID is set, else the source's portfolio.
type DTrackSyncJobArgs struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	SourceID    uuid.UUID `json:"source_id"`
	ProjectUUID string    `json:"project_uuid,omitempty"`
}

// Kind returns the job kind for River.
func (DTrackSyncJobArgs) Kind() string { return "dtrack_sync" }

// DTrackQueue is the queue's name; its concurrency bounds how hard Rampart reads Dependency-Track.
const (
	DTrackQueue       = "dtrack-sync"
	DTrackMaxWorkers  = 4
	DTrackMaxAttempts = 5
)

// DTrackSyncHandler runs one sync job.
type DTrackSyncHandler func(ctx context.Context, args DTrackSyncJobArgs) error

// DTrackSyncWorker runs dtrack_sync jobs. Its handler is set after the queue starts, because the service that
// handles them needs the queue to enqueue the trailing syncs; until then its jobs fail and River retries them.
type DTrackSyncWorker struct {
	river.WorkerDefaults[DTrackSyncJobArgs]
	Handle DTrackSyncHandler
}

func (w *DTrackSyncWorker) Work(ctx context.Context, job *river.Job[DTrackSyncJobArgs]) error {
	if w.Handle == nil {
		return ErrNoHandler
	}
	err := w.Handle(ctx, job.Args)
	if IsPermanent(err) {
		return river.JobCancel(err)
	}
	return err
}

// Timeout bounds one sync: a portfolio of thousands of projects is paged, and each project is its own job.
func (w *DTrackSyncWorker) Timeout(*river.Job[DTrackSyncJobArgs]) time.Duration {
	return 15 * time.Minute
}

// EnqueueDTrackSync inserts a sync job, after delay when it is not zero. No uniqueness is asked of River: the
// dtrack_sync debounce row already lets one project sync run at a time and turns a burst into one trailing pass.
func (q *RiverQueue) EnqueueDTrackSync(ctx context.Context, args DTrackSyncJobArgs, delay time.Duration) error {
	opts := &river.InsertOpts{Queue: DTrackQueue, MaxAttempts: DTrackMaxAttempts}
	if delay > 0 {
		opts.ScheduledAt = time.Now().Add(delay)
	}
	_, err := q.client.Insert(ctx, args, opts)
	return err
}

// EnqueueDTrackProject adapts the queue to the syncer's and the webhook's Enqueuer.
func (q *RiverQueue) EnqueueDTrackProject(ctx context.Context, tenantID, sourceID uuid.UUID, projectUUID string, delay time.Duration) error {
	return q.EnqueueDTrackSync(ctx, DTrackSyncJobArgs{TenantID: tenantID, SourceID: sourceID, ProjectUUID: projectUUID}, delay)
}
