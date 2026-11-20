import { useQuery } from '@tanstack/react-query';
import { getApplicationFreshness, qk, toProblem } from '@/api';
import type { ApplicationFreshness, FreshnessAnalyzer, FreshnessFeed } from '@/api/types';
import { IconWarning, ProblemMessage, Skeleton } from '@/components';
import { absoluteDateTime, relativeDays } from '@/lib/format';

function formatFreshnessDate(iso: string | undefined | null): string {
  if (!iso) return 'Never';
  const rel = relativeDays(iso);
  const abs = absoluteDateTime(iso);
  return rel ? `${rel} (${abs})` : abs;
}

function AnalyzerStateBadge({ a }: { a: FreshnessAnalyzer }) {
  switch (a.state) {
    case 'completed':
      return (
        <span
          data-testid="analyzer-state-completed"
          className="inline-flex items-center rounded px-2 py-0.5 text-11 font-medium bg-chrome border border-rule text-ink"
          title={`Completed analysis at ${absoluteDateTime(a.last_analysed_at)}`}
        >
          ✓ Completed
        </span>
      );
    case 'running':
      return (
        <span
          data-testid="analyzer-state-running"
          className="inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-11 font-medium bg-chrome border border-rule text-accent"
          title={`Running since ${absoluteDateTime(a.in_progress_since)}`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
          Running
        </span>
      );
    case 'pending':
      return (
        <span
          data-testid="analyzer-state-pending"
          className="inline-flex items-center rounded px-2 py-0.5 text-11 font-medium bg-chrome border border-rule text-ink-2"
        >
          Queued
        </span>
      );
    case 'failed':
    case 'timed_out':
      return (
        <span
          data-testid="analyzer-state-failed"
          className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-11 font-medium bg-critical/10 border border-critical/30 text-critical"
          title={a.error || 'Analysis failed'}
        >
          <IconWarning className="size-3 shrink-0" role="img" aria-label="Failed" />
          Failed
        </span>
      );
    case 'not_analysed':
    default:
      return (
        <span
          data-testid="analyzer-state-unanalysed"
          className="inline-flex items-center rounded px-2 py-0.5 text-11 font-medium bg-chrome border border-rule text-ink-3"
        >
          Not analysed yet
        </span>
      );
  }
}

function FeedStatusBadge({ f }: { f: FreshnessFeed }) {
  switch (f.status) {
    case 'success':
      return (
        <span className="inline-flex items-center rounded px-1.5 py-0.5 text-11 font-medium bg-chrome border border-rule text-ink">
          Synced
        </span>
      );
    case 'syncing':
      return (
        <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-11 font-medium bg-chrome border border-rule text-accent">
          <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
          Syncing
        </span>
      );
    case 'error':
      return (
        <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-11 font-medium bg-critical/10 border border-critical/30 text-critical" title={f.error}>
          Error
        </span>
      );
    case 'disabled':
      return (
        <span className="inline-flex items-center rounded px-1.5 py-0.5 text-11 font-medium bg-chrome border border-rule text-ink-3">
          Disabled
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center rounded px-1.5 py-0.5 text-11 font-medium bg-chrome border border-rule text-ink-2">
          {f.status}
        </span>
      );
  }
}

export function ApplicationFreshnessSection({ appId }: { appId: string }) {
  const query = useQuery<ApplicationFreshness>({
    queryKey: qk.applications.freshness(appId),
    queryFn: ({ signal }) => getApplicationFreshness(appId, signal),
    staleTime: 15_000,
  });

  if (query.isPending) {
    return (
      <div className="rounded-lg border border-rule bg-canvas p-4" role="status" aria-busy="true" aria-label="Loading freshness status">
        <Skeleton className="h-5 w-48 mb-2" />
        <Skeleton className="h-4 w-72 mb-4" />
        <div className="space-y-2">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </div>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="rounded-lg border border-rule bg-canvas p-4">
        <ProblemMessage problem={toProblem(query.error)} title="Could not load freshness details" onRetry={() => void query.refetch()} />
      </div>
    );
  }

  const data = query.data;
  if (!data) return null;

  return (
    <section aria-labelledby="app-freshness-heading" className="rounded-lg border border-rule bg-canvas p-4 text-13">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:justify-between">
        <div>
          <h3 id="app-freshness-heading" className="text-14 font-semibold text-ink">
            Application Freshness & Analyzers
          </h3>
          <p className="m-0 text-12 text-ink-2">
            Tracks when this application's SBOM was last analysed for vulnerabilities, and platform threat intelligence synchronization.
          </p>
        </div>
        {data.rescored_at && (
          <div className="text-12 text-ink-2">
            <span>Findings re-scored: </span>
            <span className="font-medium text-ink" title={absoluteDateTime(data.rescored_at)}>
              {formatFreshnessDate(data.rescored_at)}
            </span>
          </div>
        )}
      </div>

      {/* SBOM status line */}
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 rounded border border-rule bg-chrome/40 px-3 py-2 text-12">
        {data.sbom ? (
          <>
            <div>
              <span className="text-ink-2">Newest SBOM ingested: </span>
              <span className="font-medium text-ink" title={absoluteDateTime(data.sbom.at)}>
                {formatFreshnessDate(data.sbom.at)}
              </span>
            </div>
            <div>
              <span className="text-ink-2">Components: </span>
              <span className="font-medium text-ink">{data.sbom.components}</span>
            </div>
          </>
        ) : (
          <div className="text-ink-2">
            No SBOM has been uploaded for this application yet. Vulnerability analyzers require an ingested SBOM to match packages.
          </div>
        )}
      </div>

      {/* Analyzers list */}
      <div className="mt-3">
        <h4 className="text-12 font-semibold uppercase tracking-wider text-ink-2 mb-2">
          Vulnerability Analyzers ({data.analyzers.length})
        </h4>
        {data.analyzers.length === 0 ? (
          <p className="m-0 text-12 text-ink-3">No analyzers active or recorded for this application.</p>
        ) : (
          <div className="divide-y divide-rule rounded border border-rule">
            {data.analyzers.map((a) => (
              <div key={`${a.kind}-${a.name}`} className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-ink font-mono text-12">{a.name}</span>
                    <span className="text-11 text-ink-3 uppercase">({a.kind})</span>
                    <AnalyzerStateBadge a={a} />
                  </div>
                  {a.error && (
                    <p className="m-0 mt-1 text-12 text-critical truncate max-w-xl" title={a.error}>
                      Error: {a.error}
                    </p>
                  )}
                  {a.state === 'running' && a.in_progress_since && (
                    <p className="m-0 mt-1 text-12 text-accent">
                      In progress since {absoluteDateTime(a.in_progress_since)}
                    </p>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-12 sm:text-end">
                  {a.last_analysed_at && (
                    <div>
                      <span className="text-ink-2">Last analysed: </span>
                      <span className="font-medium text-ink" title={absoluteDateTime(a.last_analysed_at)}>
                        {formatFreshnessDate(a.last_analysed_at)}
                      </span>
                    </div>
                  )}
                  {a.state === 'completed' && (
                    <div>
                      <span className="text-ink-2">Findings: </span>
                      <span className="font-semibold text-ink">{a.findings}</span>
                      <span className="text-ink-3 text-11 ml-1">
                        (+{a.created} new, -{a.closed} closed)
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Global threat feeds details */}
      <details className="mt-4 group">
        <summary className="cursor-pointer text-12 font-medium text-ink-2 hover:text-ink flex items-center justify-between">
          <span>Platform Threat Intelligence Feeds ({data.feeds.length}) — shared platform-wide</span>
          <span className="text-11 text-ink-3 group-open:hidden">Show feeds ▾</span>
          <span className="text-11 text-ink-3 hidden group-open:inline">Hide feeds ▴</span>
        </summary>
        <p className="m-0 mt-1.5 mb-2 text-12 text-ink-2">
          Global threat feeds sync on a platform schedule (CISA KEV, FIRST EPSS, OSV, NVD). Updated feeds trigger automatic re-scoring of known vulnerabilities across all applications. Package matching occurs when an analyzer runs.
        </p>
        <div className="divide-y divide-rule rounded border border-rule text-12">
          {data.feeds.map((f) => (
            <div key={f.name} className="flex items-center justify-between p-2.5">
              <div className="flex items-center gap-2">
                <span className="font-medium text-ink">{f.display_name || f.name}</span>
                <FeedStatusBadge f={f} />
              </div>
              <div className="text-end text-ink-2" title={absoluteDateTime(f.last_sync)}>
                <span>Last synced: </span>
                <span className="font-medium text-ink">{formatFreshnessDate(f.last_sync)}</span>
              </div>
            </div>
          ))}
        </div>
      </details>
    </section>
  );
}
