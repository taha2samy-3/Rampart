import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { qk } from '@/api/keys';

/**
 * Connects to the Server-Sent Events (SSE) stream at /api/v1/events (docs/21 §6.4).
 * Automatically invalidates relevant React Query caches when real-time events arrive.
 */
export function useLiveEvents(enabled = true) {
  const qc = useQueryClient();

  useEffect(() => {
    if (!enabled || typeof window === 'undefined' || typeof EventSource === 'undefined') {
      return;
    }

    let es: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;

    function cleanup() {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (es) {
        es.close();
        es = null;
      }
    }

    function connect() {
      cleanup();
      try {
        es = new EventSource('/api/v1/events');

        es.onmessage = (event) => {
          if (!event.data) return;
          try {
            const data = JSON.parse(event.data);
            handleEvent(data);
          } catch {
            // Non-JSON heartbeat or ping
          }
        };

        const invalidateFindings = () => {
          void qc.invalidateQueries({ queryKey: qk.findings.all() });
          void qc.invalidateQueries({ queryKey: qk.overview() });
        };

        es.addEventListener('run_completed', () => {
          void qc.invalidateQueries({ queryKey: qk.runs.all() });
          invalidateFindings();
        });

        es.addEventListener('finding_updated', invalidateFindings);
        es.addEventListener('findings_updated', invalidateFindings);

        es.addEventListener('notification', () => {
          void qc.invalidateQueries({ queryKey: qk.notifications() });
        });

        es.addEventListener('acceptance_updated', () => {
          void qc.invalidateQueries({ queryKey: qk.acceptances.all() });
          void qc.invalidateQueries({ queryKey: qk.heldCloses.all() });
        });

        es.onerror = () => {
          if (es) {
            es.close();
            es = null;
          }
          if (timer) {
            clearTimeout(timer);
          }
          // Reconnect with 5-second backoff
          timer = setTimeout(connect, 5000);
        };
      } catch {
        if (timer) {
          clearTimeout(timer);
        }
        timer = setTimeout(connect, 10000);
      }
    }

    function handleEvent(data: Record<string, unknown>) {
      const type = data.type || data.event || data.kind;
      if (type === 'run_completed' || type === 'ingest') {
        void qc.invalidateQueries({ queryKey: qk.runs.all() });
        void qc.invalidateQueries({ queryKey: qk.findings.all() });
        void qc.invalidateQueries({ queryKey: qk.overview() });
      } else if (type === 'finding_updated' || type === 'findings_updated' || type === 'triage') {
        void qc.invalidateQueries({ queryKey: qk.findings.all() });
        void qc.invalidateQueries({ queryKey: qk.overview() });
      } else if (type === 'notification') {
        void qc.invalidateQueries({ queryKey: qk.notifications() });
      }
    }

    connect();

    return cleanup;
  }, [enabled, qc]);
}
