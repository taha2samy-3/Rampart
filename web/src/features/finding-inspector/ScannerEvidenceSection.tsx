import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getFindingOccurrences, qk } from '@/api';
import type { Finding } from '@/api/types';
import { Button, MarkdownView, Spinner } from '@/components';
import { absoluteDate } from '@/lib/format';

function formatLabel(key: string): string {
  // Convert camelCase or snake_case to Title Case
  const clean = key.replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2');
  return clean.charAt(0).toUpperCase() + clean.slice(1);
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    void navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button
      variant="secondary"
      onClick={handleCopy}
      className="h-5 px-1.5 text-11 leading-none"
      title="Copy to clipboard"
    >
      {copied ? 'Copied!' : label}
    </Button>
  );
}

function AttributeValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="text-ink-3">null</span>;

  if (typeof value === 'boolean') {
    return (
      <span className={`inline-block rounded px-1.5 py-0.5 text-11 font-semibold ${value ? 'bg-success/15 text-success' : 'bg-muted/15 text-ink-2'}`}>
        {value ? 'True' : 'False'}
      </span>
    );
  }

  if (typeof value === 'number') {
    return <span className="font-mono text-12 tnum">{value}</span>;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();

    // Safe Web Link
    if (/^https?:\/\//i.test(trimmed)) {
      return (
        <a
          href={trimmed}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 font-mono text-12 text-accent hover:underline [overflow-wrap:anywhere]"
        >
          {trimmed}
          <span aria-hidden="true" className="text-10">↗</span>
        </a>
      );
    }

    // Email link
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
      return (
        <a href={`mailto:${trimmed}`} className="font-mono text-12 text-accent hover:underline">
          {trimmed}
        </a>
      );
    }

    // Long multi-line text / markdown / code
    if (trimmed.includes('\n') || trimmed.length > 120) {
      return (
        <div className="mt-1 rounded border border-rule bg-chrome p-2 text-12">
          <MarkdownView content={trimmed} />
        </div>
      );
    }

    // Hash, commit SHA, PURL, ARN, or hex string -> mono with copy
    if (
      /^[a-f0-9]{32,64}$/i.test(trimmed) ||
      trimmed.startsWith('sha256:') ||
      trimmed.startsWith('pkg:') ||
      trimmed.startsWith('arn:') ||
      trimmed.startsWith('cve-') ||
      trimmed.startsWith('ghsa-')
    ) {
      return (
        <div className="flex items-center gap-2">
          <span className="font-mono text-12 text-ink [overflow-wrap:anywhere]">{trimmed}</span>
          <CopyButton text={trimmed} />
        </div>
      );
    }

    return <span className="text-12 [overflow-wrap:anywhere]">{trimmed}</span>;
  }

  if (typeof value === 'object') {
    const jsonStr = JSON.stringify(value, null, 2);
    return (
      <div className="mt-1">
        <pre className="max-h-32 overflow-auto rounded border border-rule bg-chrome p-1.5 font-mono text-11 text-ink-2">
          {jsonStr}
        </pre>
      </div>
    );
  }

  return <span className="text-12">{String(value)}</span>;
}

export function ScannerEvidenceSection({ finding }: { finding: Finding }) {
  const [selectedIdx, setSelectedIdx] = useState(0);

  const q = useQuery({
    queryKey: [...qk.findings.occurrences(finding.id), finding.version],
    queryFn: ({ signal }) => getFindingOccurrences(finding.id, signal),
    retry: false,
  });

  const occurrences = q.data ?? [];
  if (q.isPending) {
    return (
      <div className="mt-4 flex items-center gap-2 text-12 text-ink-2">
        <Spinner size={14} />
        <span>Loading scanner evidence...</span>
      </div>
    );
  }

  if (occurrences.length === 0) {
    return null;
  }

  const activeOcc = occurrences[selectedIdx] ?? occurrences[0];
  if (!activeOcc) return null;

  const normalized = (activeOcc.normalized && typeof activeOcc.normalized === 'object' ? activeOcc.normalized : {}) as Record<string, unknown>;
  const raw = activeOcc.raw;

  // Filter out redundant location fields already shown in basic EvidenceSection
  const ignoredKeys = new Set([
    'description', 'rule_id', 'ruleid', 'file', 'file_path', 'filepath',
    'start_line', 'startline', 'end_line', 'endline', 'start_column', 'startcolumn',
    'end_column', 'endcolumn', 'snippet', 'secret_value', 'secret',
  ]);

  const attributes = Object.entries(normalized).filter(
    ([k, v]) => !ignoredKeys.has(k.toLowerCase()) && v !== null && v !== undefined && v !== ''
  );

  const rawJsonString = raw ? (typeof raw === 'string' ? raw : JSON.stringify(raw, null, 2)) : JSON.stringify(normalized, null, 2);

  return (
    <section className="mt-5 border-t border-rule pt-4" aria-labelledby="scanner-evidence-title">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 id="scanner-evidence-title" className="text-13 font-semibold text-ink">
          Scanner Evidence & Extracted Details
        </h3>
        {occurrences.length > 1 && (
          <div className="flex items-center gap-1">
            {occurrences.map((occ, idx) => (
              <button
                key={occ.id || idx}
                type="button"
                onClick={() => setSelectedIdx(idx)}
                className={`rounded px-2 py-0.5 text-11 font-medium transition-colors ${
                  idx === selectedIdx
                    ? 'bg-accent text-white'
                    : 'bg-layer-2 text-ink-2 hover:bg-layer-3 hover:text-ink'
                }`}
              >
                {occ.scanner_name || occ.scanner_family}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Scanner metadata strip */}
      <div className="mb-3 rounded border border-rule bg-layer-1 p-2 text-12">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-ink">{activeOcc.scanner_name || activeOcc.scanner_family}</span>
            {activeOcc.scanner_version && (
              <span className="rounded bg-muted/20 px-1.5 py-0.2 font-mono text-11 text-ink-2">
                v{activeOcc.scanner_version}
              </span>
            )}
            {activeOcc.tool_severity && (
              <span className="rounded border border-rule px-1.5 py-0.2 text-11 font-medium text-ink-2 uppercase">
                {activeOcc.tool_severity}
              </span>
            )}
          </div>
          <div className="text-11 text-ink-2">
            Last seen: {absoluteDate(activeOcc.last_seen || activeOcc.first_seen)}
          </div>
        </div>

        {activeOcc.tool_record_id && (
          <div className="mt-1.5 flex items-center gap-2 border-t border-rule/50 pt-1 text-11 text-ink-2">
            <span className="font-medium">Record ID:</span>
            <span className="font-mono text-ink [overflow-wrap:anywhere]">{activeOcc.tool_record_id}</span>
            <CopyButton text={activeOcc.tool_record_id} />
          </div>
        )}
      </div>

      {/* Extracted Attributes Key-Value Grid */}
      {attributes.length > 0 && (
        <dl className="m-0 mb-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-13">
          {attributes.map(([key, val]) => (
            <React.Fragment key={key}>
              <dt className="text-12 font-medium text-ink-2">{formatLabel(key)}</dt>
              <dd className="m-0 min-w-0">
                <AttributeValue value={val} />
              </dd>
            </React.Fragment>
          ))}
        </dl>
      )}

      {/* Collapsible Raw Scanner Payload Viewer */}
      {rawJsonString && rawJsonString !== '{}' && (
        <details className="group mt-3 rounded border border-rule bg-layer-1">
          <summary className="flex cursor-pointer items-center justify-between px-3 py-1.5 text-12 font-medium text-ink-2 select-none hover:text-ink">
            <span>Raw Scanner Record (JSON)</span>
            <span className="text-10 text-ink-3 group-open:rotate-180 transition-transform">▼</span>
          </summary>
          <div className="border-t border-rule p-2">
            <div className="mb-2 flex justify-end">
              <CopyButton text={rawJsonString} label="Copy Raw JSON" />
            </div>
            <pre className="m-0 max-h-56 overflow-auto rounded bg-chrome p-2 font-mono text-11 text-ink leading-relaxed">
              {rawJsonString}
            </pre>
          </div>
        </details>
      )}
    </section>
  );
}
