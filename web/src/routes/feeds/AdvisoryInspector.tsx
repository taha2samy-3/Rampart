import { useState } from 'react';
import type { AdvisorySourceItem } from '@/api/types';
import { Button } from '@/components';
import { absoluteDateTime } from '@/lib/format';
import { cn } from '@/lib/cn';

const RATE_LIMIT_INFOS: Record<string, { limits: string; authDoc: string }> = {
  osv: {
    limits: 'Open GCS bulk archives (unlimited) & REST API (1,000 req/min).',
    authDoc: 'Public open source; no authentication token required.',
  },
  nvd: {
    limits: 'Without token: 5 req / 30s. With token: 50 req / 30s.',
    authDoc: 'Passes apiKey header. Token mounted under /etc/rampart/feed-secrets/nvd-api-key.',
  },
  sonatype: {
    limits: 'Batches up to 128 package purls per HTTP POST to minimize quota usage.',
    authDoc: 'Basic Auth (username + token). Mounted under /etc/rampart/feed-secrets/sonatype-token.',
  },
  snyk: {
    limits: 'Subject to enterprise organization monthly API rate limits.',
    authDoc: 'Authorization: token <KEY>. Mounted under /etc/rampart/feed-secrets/snyk-token.',
  },
  vulncheck: {
    limits: 'Incremental cursor synchronization over KEV & exploit intelligence.',
    authDoc: 'Bearer token. Mounted under /etc/rampart/feed-secrets/vulncheck-token.',
  },
  depsdev: {
    limits: 'Open REST API for direct package graph and advisory resolution.',
    authDoc: 'Public open API provided by Google Open Source Insights.',
  },
};

export function AdvisoryInspector({
  source,
  onTest,
  isTesting,
}: {
  source: AdvisorySourceItem | null;
  onTest: (name: string) => void;
  isTesting: boolean;
}) {
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  if (!source) {
    return <p className="p-4 text-13 text-ink-2">Select an advisory source to inspect its configuration and API rate limits.</p>;
  }

  const rateInfo = RATE_LIMIT_INFOS[source.name] ?? {
    limits: 'Standard rate limiting per provider specifications.',
    authDoc: source.token_required
      ? `Bearer or API key token required via ${source.token_file ?? '/etc/rampart/feed-secrets/'}`
      : 'No authentication token required.',
  };

  const sampleSnippet = `    ${source.name}:
      enabled: ${source.enabled}
      url: ${source.url}${source.token_file ? `\n      tokenFile: ${source.token_file}` : ''}`;

  const copySnippet = async () => {
    try {
      await navigator.clipboard.writeText(sampleSnippet);
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 1500);
    } catch {
      // ignore
    }
  };

  return (
    <div className="space-y-5 p-4 text-13">
      <header>
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-14 font-semibold text-ink">{source.display_name}</h3>
          <span
            className={cn(
              'inline-flex items-center rounded-full px-2 py-0.5 text-11 font-medium',
              source.enabled ? 'bg-success/15 text-success' : 'bg-surface-3 text-ink-2'
            )}
          >
            {source.enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        <p className="mt-0.5 text-ink-2">{source.description}</p>
      </header>

      {/* Provider & Category */}
      <section aria-labelledby="adv-provider">
        <h4 id="adv-provider" className="font-semibold text-ink">Provider & Intelligence Layer</h4>
        <dl className="mt-1 space-y-1 text-12">
          <div className="flex justify-between">
            <dt className="text-ink-2">Provider Organization</dt>
            <dd className="font-medium text-ink">{source.provider}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-ink-2">Source Type</dt>
            <dd className="capitalize font-medium text-ink">{source.category}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-ink-2">Total Advisory Records</dt>
            <dd className="font-mono font-medium text-ink">
              {source.records_count !== undefined ? source.records_count.toLocaleString() : '—'}
            </dd>
          </div>
        </dl>
      </section>

      {/* Endpoint URL */}
      <section aria-labelledby="adv-source">
        <h4 id="adv-source" className="font-semibold text-ink">API Endpoint URL</h4>
        <p className="mt-1 break-all font-mono text-12 text-ink-2 bg-layer-2 p-2 rounded border border-rule">
          {source.url}
        </p>
      </section>

      {/* Rate Limits & Quota Architecture */}
      <section aria-labelledby="adv-ratelimit">
        <h4 id="adv-ratelimit" className="font-semibold text-ink">Rate Limits & Quota Protections</h4>
        <p className="mt-1 text-12 text-ink-2">{rateInfo.limits}</p>
      </section>

      {/* Token & Secrets Storage */}
      <section aria-labelledby="adv-auth">
        <h4 id="adv-auth" className="font-semibold text-ink">Authentication & Secrets</h4>
        <div className="mt-1.5 flex items-center gap-2">
          <span
            className={cn(
              'inline-flex items-center rounded px-2 py-0.5 text-11 font-medium',
              source.token_required && source.token_present && 'bg-success/15 text-success',
              source.token_required && !source.token_present && 'bg-amber-500/15 text-amber-600 dark:text-amber-400',
              !source.token_required && 'bg-layer-2 text-ink-2 border border-rule'
            )}
          >
            {source.token_required
              ? source.token_present
                ? '✓ Token Present'
                : '⚠ Token Missing'
              : 'Token Not Required'}
          </span>
          {source.token_file && (
            <span className="font-mono text-11 text-ink-3 truncate max-w-xs">{source.token_file}</span>
          )}
        </div>
        <p className="mt-1.5 text-12 text-ink-2">{rateInfo.authDoc}</p>
      </section>

      {/* Last Result & Sync State */}
      <section aria-labelledby="adv-sync">
        <h4 id="adv-sync" className="font-semibold text-ink">Synchronization Status</h4>
        <p className="mt-1 capitalize text-13 text-ink">
          Status:{' '}
          <span
            className={cn(
              'font-semibold',
              source.status === 'ready' && 'text-success',
              source.status === 'error' && 'text-critical',
              source.status === 'syncing' && 'text-accent',
              source.status === 'disabled' && 'text-ink-2'
            )}
          >
            {source.status}
          </span>
        </p>
        <p className="text-12 text-ink-2">
          {source.last_sync ? `Last synchronized ${absoluteDateTime(source.last_sync)}` : 'Never synchronized'}
        </p>
        {source.error && (
          <p className="mt-1.5 break-words rounded bg-critical/10 p-2 font-mono text-12 text-critical border border-critical/20">
            {source.error}
          </p>
        )}
      </section>

      {/* CRD Configuration Snippet */}
      <section aria-labelledby="adv-yaml">
        <div className="flex items-center justify-between">
          <h4 id="adv-yaml" className="font-semibold text-ink">CRD Spec Snippet</h4>
          <button
            type="button"
            onClick={() => void copySnippet()}
            className="text-11 font-medium text-accent hover:underline"
          >
            {copiedSnippet ? 'Copied!' : 'Copy Snippet'}
          </button>
        </div>
        <pre className="mt-1.5 rounded bg-layer-2 p-2.5 font-mono text-11 text-ink border border-rule overflow-x-auto">
          <code>{sampleSnippet}</code>
        </pre>
      </section>

      {/* Actions */}
      <div className="pt-2">
        <Button
          variant="secondary"
          className="w-full text-13"
          disabled={isTesting}
          onClick={() => onTest(source.name)}
        >
          {isTesting ? 'Testing Connectivity...' : `Test ${source.display_name} API`}
        </Button>
      </div>
    </div>
  );
}
