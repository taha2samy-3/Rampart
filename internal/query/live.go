package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/store"
)

// Live updates (docs/11 `GET /stream`, docs/13 §3, docs/16 D91).
//
// Writers do not know about streams. Statement-level triggers record "topic T changed for application A" in
// live_event; each replica's LiveHub polls that table once for all its streams and hands each stream its tenant's
// rows. A stream filters them by topic and by the caller's scope, coalesces them to one message per (topic,
// application) per poll, and carries no data: the client refetches with its own permissions.
const (
	LivePollInterval     = 2 * time.Second
	LiveRetention        = time.Hour
	liveBatch            = 5000
	liveGapWait          = 2 * time.Minute // a hole in the ids this old is a rolled-back transaction, not a slow one
	liveMaxStreamsPerKey = 5
	liveHeartbeat        = 15 * time.Second
	liveMaxLifetime      = 30 * time.Minute // then the client reconnects and is authenticated again
	liveWriteTimeout     = 10 * time.Second
	liveReplayLimit      = 1000
	liveSubBuffer        = 64
)

var liveTopics = map[string]bool{"ingests": true, "findings": true, "operations": true}

// ErrTooManyStreams is returned when a caller already holds the most streams one replica allows.
var ErrTooManyStreams = errors.New("too many live streams for this caller")

type liveSub struct {
	tenant   uuid.UUID
	key      string
	ch       chan []domain.LiveEvent
	overflow chan struct{}
}

// LiveHub polls live_event and fans the rows out to the streams on this replica.
type LiveHub struct {
	src      store.LiveEventSource
	interval time.Duration
	log      *slog.Logger

	mu    sync.Mutex
	subs  map[*liveSub]struct{}
	perID map[string]int

	cursor   int64
	pending  map[int64]bool // ids already delivered above the cursor, waiting for the hole below them to fill
	gapSince time.Time
}

// NewLiveHub makes a hub reading from src (the system store).
func NewLiveHub(src store.LiveEventSource, log *slog.Logger) *LiveHub {
	if log == nil {
		log = slog.Default()
	}
	return &LiveHub{src: src, interval: LivePollInterval, log: log, subs: map[*liveSub]struct{}{}, perID: map[string]int{}, pending: map[int64]bool{}}
}

// Run polls until ctx ends. It starts at the newest row: history is replayed per stream from Last-Event-ID, not here.
func (h *LiveHub) Run(ctx context.Context) {
	if id, err := h.src.MaxLiveEventID(ctx); err == nil {
		h.cursor = id
	}
	poll := time.NewTicker(h.interval)
	defer poll.Stop()
	prune := time.NewTicker(5 * time.Minute)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			h.Poll(ctx, time.Now())
		case <-prune.C:
			if _, err := h.src.PruneLiveEvents(ctx, time.Now().Add(-LiveRetention)); err != nil {
				h.log.Warn("live: pruning failed", "error", err)
			}
		}
	}
}

// Poll reads the new rows once and delivers them. Ids come from a sequence, so they are committed out of order:
// a row may appear below one already seen. The cursor therefore advances only over a run with no hole, and rows
// above a hole are remembered so they are not delivered twice; a hole older than liveGapWait is skipped.
func (h *LiveHub) Poll(ctx context.Context, now time.Time) {
	rows, err := h.src.ListLiveEvents(ctx, h.cursor, liveBatch)
	if err != nil {
		h.log.Warn("live: polling failed", "error", err)
		return
	}
	byTenant := map[uuid.UUID][]domain.LiveEvent{}
	for _, e := range rows {
		if h.pending[e.ID] {
			continue
		}
		h.pending[e.ID] = true
		byTenant[e.TenantID] = append(byTenant[e.TenantID], e)
	}
	h.advance(now)
	if len(byTenant) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.subs {
		evs := byTenant[sub.tenant]
		if len(evs) == 0 {
			continue
		}
		select {
		case sub.ch <- evs:
		default: // a stream that does not keep up is told to refetch everything, not left silently behind
			select {
			case sub.overflow <- struct{}{}:
			default:
			}
		}
	}
}

func (h *LiveHub) advance(now time.Time) {
	for h.pending[h.cursor+1] {
		delete(h.pending, h.cursor+1)
		h.cursor++
	}
	if len(h.pending) == 0 {
		h.gapSince = time.Time{}
		return
	}
	if h.gapSince.IsZero() {
		h.gapSince = now
		return
	}
	if now.Sub(h.gapSince) >= liveGapWait {
		lowest := int64(-1)
		for id := range h.pending {
			if lowest < 0 || id < lowest {
				lowest = id
			}
		}
		h.cursor = lowest - 1
		h.gapSince = time.Time{}
		h.advance(now)
	}
}

func (h *LiveHub) subscribe(tenant uuid.UUID, key string) (*liveSub, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.perID[key] >= liveMaxStreamsPerKey {
		return nil, ErrTooManyStreams
	}
	h.perID[key]++
	sub := &liveSub{tenant: tenant, key: key, ch: make(chan []domain.LiveEvent, liveSubBuffer), overflow: make(chan struct{}, 1)}
	h.subs[sub] = struct{}{}
	return sub, nil
}

func (h *LiveHub) unsubscribe(sub *liveSub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[sub]; !ok {
		return
	}
	delete(h.subs, sub)
	if h.perID[sub.key]--; h.perID[sub.key] <= 0 {
		delete(h.perID, sub.key)
	}
}

// SetLiveHub attaches the replica's hub. Without one, GET /stream answers 503 and the UI polls.
func (a *API) SetLiveHub(h *LiveHub) { a.live = h }

// liveID is the SSE id: the row id and the time it was written, so a Last-Event-ID older than the retention is
// recognised as such and answered with a reset instead of a silent gap.
func liveID(e domain.LiveEvent) string { return fmt.Sprintf("%d.%d", e.ID, e.At.Unix()) }

func parseLiveID(s string) (id int64, at time.Time, ok bool) {
	n, ts, found := strings.Cut(strings.TrimSpace(s), ".")
	if !found {
		return 0, time.Time{}, false
	}
	id, err1 := strconv.ParseInt(n, 10, 64)
	sec, err2 := strconv.ParseInt(ts, 10, 64)
	if err1 != nil || err2 != nil || id < 0 {
		return 0, time.Time{}, false
	}
	return id, time.Unix(sec, 0), true
}

func (a *API) handleStream(w http.ResponseWriter, r *http.Request) {
	tenantID, user, ok := a.requireRole(w, r, auth.RoleViewer)
	if !ok {
		return
	}
	topics := map[string]bool{}
	if q := r.URL.Query().Get("topics"); q != "" {
		for _, t := range strings.Split(q, ",") {
			t = strings.TrimSpace(t)
			if !liveTopics[t] {
				problem(w, http.StatusBadRequest, "validation", "Unknown topic "+strconv.Quote(t)+": use ingests, findings, operations")
				return
			}
			topics[t] = true
		}
	} else {
		for t := range liveTopics {
			topics[t] = true
		}
	}
	if a.live == nil {
		w.Header().Set("Retry-After", "30")
		problem(w, http.StatusServiceUnavailable, "unavailable", "Live updates are not running on this server; poll instead")
		return
	}
	key := tenantID.String() + "|" + firstNonEmptyStr(user.Email, user.Subject)
	sub, err := a.live.subscribe(tenantID, key)
	if err != nil {
		w.Header().Set("Retry-After", "30")
		problem(w, http.StatusTooManyRequests, "too-many-streams", fmt.Sprintf("At most %d live streams per user; close another tab", liveMaxStreamsPerKey))
		return
	}
	defer a.live.unsubscribe(sub)
	scope := a.scopeOf(r.Context(), tenantID, user)

	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	write := func(s string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(liveWriteTimeout)) // also lifts a server WriteTimeout for this stream
		if _, err := fmt.Fprint(w, s); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	var lastSent int64
	send := func(evs []domain.LiveEvent) bool {
		type k struct {
			topic string
			app   uuid.UUID
		}
		latest := map[k]domain.LiveEvent{}
		for _, e := range evs {
			if e.ID <= lastSent || !topics[e.Topic] {
				continue
			}
			var app uuid.UUID
			if e.ApplicationID != nil {
				app = *e.ApplicationID
				if !scope.allows(app, auth.RoleViewer) {
					continue
				}
			}
			if cur, ok := latest[k{e.Topic, app}]; !ok || e.ID > cur.ID {
				latest[k{e.Topic, app}] = e
			}
		}
		out := make([]domain.LiveEvent, 0, len(latest))
		for _, e := range latest {
			out = append(out, e)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		var b strings.Builder
		for _, e := range out {
			data, _ := json.Marshal(map[string]any{"topic": e.Topic, "application_id": e.ApplicationID})
			fmt.Fprintf(&b, "id: %s\nevent: %s\ndata: %s\n\n", liveID(e), e.Topic, data)
			lastSent = e.ID
		}
		for _, e := range evs { // ids filtered out still move the stream forward
			if e.ID > lastSent {
				lastSent = e.ID
			}
		}
		return b.Len() == 0 || write(b.String())
	}

	if !write("retry: 5000\n\n") {
		return
	}
	last := r.Header.Get("Last-Event-ID")
	if last == "" {
		last = r.URL.Query().Get("last_event_id") // a client reconnecting by hand cannot set the header
	}
	if last != "" {
		id, at, ok := parseLiveID(last)
		replay, canReplay := a.store.(store.LiveEventReplay)
		switch {
		case !ok || time.Since(at) > LiveRetention || !canReplay:
			if !write("event: reset\ndata: {}\n\n") {
				return
			}
		default:
			evs, err := replay.ListTenantLiveEvents(r.Context(), tenantID, id, liveReplayLimit)
			if err != nil || len(evs) == liveReplayLimit {
				if !write("event: reset\ndata: {}\n\n") {
					return
				}
				lastSent = id
			} else {
				lastSent = id
				if !send(evs) {
					return
				}
			}
		}
	}

	heartbeat := time.NewTicker(liveHeartbeat)
	defer heartbeat.Stop()
	end := time.NewTimer(liveMaxLifetime)
	defer end.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-end.C:
			_ = write("event: reconnect\ndata: {}\n\n")
			return
		case <-sub.overflow:
			if !write("event: reset\ndata: {}\n\n") {
				return
			}
		case evs := <-sub.ch:
			if !send(evs) {
				return
			}
		case <-heartbeat.C:
			if !write(": ping\n\n") {
				return
			}
		}
	}
}
