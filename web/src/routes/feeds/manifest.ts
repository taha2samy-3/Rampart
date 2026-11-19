import type { FeedMirrorSpec } from '@/api/types';

type Sourced = { url?: string; tokenFile?: string };

/** The sources a ClusterFeed switches on by naming them, with the url or token file each carries. */
const SOURCES = ['kev', 'epss', 'nvd', 'osv', 'vulnrichment', 'exploitdb', 'metasploit', 'euvd', 'vulncheckKev'] as const;

/**
 * The ClusterFeed of what the server really has. Only what the live resource sets is printed: a source listed here is
 * switched on (the optional ones) or counts as a mirror (kev, epss, nvd, osv), and under egress deny a feed that has a url
 * is the only kind still read. Printing the public defaults would undo an air gap and turn on sources nobody chose.
 */
export function buildManifest(mirror: FeedMirrorSpec | null | undefined): string {
  const m = (mirror ?? {}) as Record<string, unknown>;
  const lines = [
    '# ClusterFeed (the ClusterFeedMirror kind is accepted too). Shown: what this server has.',
    '# Name a source to turn it on, give it a url to read it from an internal mirror.',
    '# kev, epss, nvd and osv run by default without any block.',
    'apiVersion: rampart.aspm.dev/v1alpha1',
    'kind: ClusterFeed',
    'metadata:',
    '  name: default',
    'spec:',
    `  egress: ${String(m.egress ?? 'allow')} # allow | deny: with deny only a feed that has a url (a mirror) is read`,
    `  storageMode: ${String(m.storageMode ?? 'lightweight')} # lightweight | full`,
  ];
  for (const key of SOURCES) {
    const v = m[key] as Sourced | undefined;
    if (!v) continue;
    lines.push(`  ${key}:`);
    if (v.url) lines.push(`    url: "${v.url}"`);
    if (v.tokenFile) lines.push(`    tokenFile: "${v.tokenFile}"`);
    if (!v.url && !v.tokenFile) lines.push('    {}');
  }
  const custom = (m.custom as Array<Sourced & { name: string; format: string; pushTokenFile?: string }> | undefined) ?? [];
  if (custom.length) {
    lines.push('  custom:');
    for (const c of custom) {
      lines.push(`    - name: ${c.name}`, `      format: ${c.format}`);
      if (c.url) lines.push(`      url: "${c.url}"`);
      if (c.tokenFile) lines.push(`      tokenFile: "${c.tokenFile}"`);
      if (c.pushTokenFile) lines.push(`      pushTokenFile: "${c.pushTokenFile}"`);
    }
  }
  return lines.join('\n') + '\n';
}
