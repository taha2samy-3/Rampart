import { useTranslation } from 'react-i18next';
import type { Finding } from '@/api/types';
import { locationOf } from '@/lib/location';

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-ink-2">{label}</dt>
      <dd className="m-0 min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </>
  );
}

/**
 * What the scanner said about where the finding is, in the terms of its kind: a code scanner gives a file, lines, a
 * function and a snippet; a dependency scanner the manifest and the way the application reaches the package; a web
 * scanner an address, a method and a parameter; an infrastructure scanner a resource; a container scanner an image.
 * Nothing is shown that the scanner did not give. The text of a secret is never shown, and never kept (only its hash).
 */
export function EvidenceSection({ finding }: { finding: Finding }) {
  const { t } = useTranslation();
  const l = locationOf(finding.location);
  const isSecret = finding.category === 'secret';
  const lines = l.start_line ? (l.end_line && l.end_line !== l.start_line ? t('evidence.linesRange', { from: l.start_line, to: l.end_line }) : String(l.start_line)) : '';
  const rows: [string, React.ReactNode][] = [];
  if (l.file_path) rows.push([t('evidence.file'), <span key="f" className="font-mono text-12">{l.file_path}</span>]);
  if (lines) rows.push([t('evidence.lines'), lines]);
  if (l.start_column) rows.push([t('evidence.column'), String(l.start_column)]);
  if (l.logical_location) rows.push([t('evidence.in'), <span key="i" className="font-mono text-12">{l.logical_location}</span>]);
  if (l.url) rows.push([t('evidence.address'), <span key="u" className="font-mono text-12">{l.url}</span>]);
  if (l.method) rows.push([t('evidence.method'), l.method]);
  if (l.param) rows.push([t('evidence.parameter'), <span key="p" className="font-mono text-12">{l.param}</span>]);
  if (l.resource_address || l.resource_key) rows.push([t('evidence.resource'), <span key="r" className="font-mono text-12">{l.resource_address || l.resource_key}</span>]);
  if (l.resource_type) rows.push([t('evidence.resourceType'), l.resource_type]);
  if (l.image) rows.push([t('evidence.image'), <span key="im" className="font-mono text-12">{l.image}</span>]);
  if (l.manifest_path) rows.push([t('evidence.manifest'), <span key="m" className="font-mono text-12">{l.manifest_path}</span>]);
  if (finding.tool_severity) rows.push([t('evidence.toolRated'), finding.tool_severity]);

  const path = l.dependency_path ?? [];
  const snippet = !isSecret ? l.snippet : undefined;
  if (rows.length === 0 && path.length === 0 && !snippet && !isSecret) return null;

  return (
    <section className="mt-5" aria-labelledby="evidence">
      <h3 id="evidence" className="mb-1 text-13 font-semibold">{t('evidence.title')}</h3>
      {rows.length > 0 && <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-13">{rows.map(([label, value]) => <Row key={label} label={label}>{value}</Row>)}</dl>}
      {path.length > 1 && (
        <>
          <h4 className="mb-0.5 mt-3 text-12 font-semibold text-ink-2">{t('evidence.reachedThrough')}</h4>
          <ol className="m-0 list-none border-s border-rule p-0 text-13">
            {path.map((step, i) => <li key={`${step}-${i}`} style={{ paddingInlineStart: 8 + Math.min(i, 6) * 10 }} className="py-0.5 font-mono text-12">{step}</li>)}
          </ol>
        </>
      )}
      {snippet && <pre className="m-0 mt-3 max-h-40 overflow-auto border border-rule bg-chrome p-2 font-mono text-12">{snippet}</pre>}
      {isSecret && (
        <p className="m-0 mt-2 text-12 text-ink-2">
          {t('evidence.secretNote')} {finding.secret_verified ? <strong className="font-semibold text-critical">{t('evidence.secretLive')}</strong> : null}
        </p>
      )}
    </section>
  );
}
