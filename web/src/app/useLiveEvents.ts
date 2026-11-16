import { useEffect } from 'react';
import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { qk } from '@/api/keys';

/** The one live stream (docs/11 `GET /stream`, docs/13 §3, docs/16 D91). */
export const STREAM_URL = '/api/v1/stream?topics=ingests,findings,operations';
/** While the stream is down the UI polls at this interval (docs/13 §3). */
export const POLL_MS = 30_000;

/**
 * What each topic invalidates. A message names a topic and an application and carries no data: the pages
 * refetch with the user's own permissions.
 */
export function invalidateTopic(qc: QueryClient, topic: string) {
  const inv = (queryKey: readonly unknown[]) => void qc.invalidateQueries({ queryKey });
  switch (topic) {
    case 'findings':
      inv(qk.findings.all());
      inv(qk.overview());
      inv(qk.applications.list());
      inv(qk.groups.all());
      break;
    case 'ingests':
      inv(qk.runs.all());
      inv(qk.overview());
      break;
    case 'operations':
      inv(qk.acceptances.all());
      inv(qk.heldCloses.all());
      inv(qk.notifications());
      inv(qk.groups.all());
      break;
    default: // reset: the stream could not say what changed
      void qc.invalidateQueries();
  }
}

/**
 * Keeps the open pages current. The browser's EventSource reconnects by itself and sends Last-Event-ID; when the
 * server refuses (401, 429, 503) the source closes and this hook reconnects with backoff, passing the last id in
 * the query, and polls while it waits.
 */
export function useLiveEvents(enabled = true) {
  const qc = useQueryClient();

  useEffect(() => {
    if (!enabled || typeof window === 'undefined' || typeof EventSource === 'undefined') {
      return;
    }
    let es: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let poll: ReturnType<typeof setInterval> | null = null;
    let lastId = '';
    let backoff = 5_000;
    let stopped = false;

    const startPolling = () => {
      if (!poll) poll = setInterval(() => invalidateTopic(qc, 'findings'), POLL_MS);
    };
    const stopPolling = () => {
      if (poll) clearInterval(poll);
      poll = null;
    };

    const connect = () => {
      if (stopped) return;
      const url = lastId ? `${STREAM_URL}&last_event_id=${encodeURIComponent(lastId)}` : STREAM_URL;
      es = new EventSource(url);
      es.onopen = () => {
        backoff = 5_000;
        stopPolling();
      };
      for (const topic of ['findings', 'ingests', 'operations', 'reset']) {
        es.addEventListener(topic, (ev) => {
          const id = (ev as MessageEvent).lastEventId;
          if (id) lastId = id;
          invalidateTopic(qc, topic);
        });
      }
      // The server ends a stream after a while so the session is checked again; reconnect at once.
      es.addEventListener('reconnect', () => {
        es?.close();
        connect();
      });
      es.onerror = () => {
        startPolling();
        if (es && es.readyState === EventSource.CLOSED) {
          es = null;
          retry = setTimeout(connect, backoff);
          backoff = Math.min(backoff * 2, 5 * 60_000);
        }
        // Otherwise the browser is already reconnecting with Last-Event-ID.
      };
    };

    connect();
    return () => {
      stopped = true;
      if (retry) clearTimeout(retry);
      stopPolling();
      es?.close();
    };
  }, [enabled, qc]);
}
