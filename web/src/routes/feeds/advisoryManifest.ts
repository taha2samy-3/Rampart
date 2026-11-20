import type { ClusterAdvisorySourceSpec } from '@/api/types';

/**
 * Builds the Kubernetes Custom Resource manifest for ClusterAdvisorySource.
 */
export function buildAdvisoryManifest(spec?: ClusterAdvisorySourceSpec | null): string {
  const s = spec ?? {};
  const sources = s.sources ?? {};
  const lines = [
    '# ClusterAdvisorySource (docs/42, D141). Manages vulnerability advisory feeds,',
    '# patch notes, and upstream API tokens across global threat intelligence providers.',
    'apiVersion: rampart.aspm.dev/v1alpha1',
    'kind: ClusterAdvisorySource',
    'metadata:',
    '  name: default',
    'spec:',
    `  enabled: ${s.enabled ?? true}`,
    `  refreshInterval: ${s.refreshInterval ?? '6h'}`,
    '  sources:',
    '    osv:',
    `      enabled: ${sources.osv?.enabled ?? true}`,
    '      url: https://osv-vulnerabilities.storage.googleapis.com',
    '      ecosystems:',
    '        - npm',
    '        - PyPI',
    '        - Maven',
    '        - Go',
    '        - crates.io',
    '    nvd:',
    `      enabled: ${sources.nvd?.enabled ?? true}`,
    '      url: https://services.nvd.nist.gov/rest/json/cves/2.0',
    `      tokenFile: ${sources.nvd?.tokenFile ?? '/etc/rampart/feed-secrets/nvd-api-key'}`,
    '    sonatype:',
    `      enabled: ${sources.sonatype?.enabled ?? false}`,
    '      url: https://ossindex.sonatype.org/api/v3/component-report',
    `      username: ${sources.sonatype?.username ?? 'sec-ops@company.com'}`,
    `      tokenFile: ${sources.sonatype?.tokenFile ?? '/etc/rampart/feed-secrets/sonatype-token'}`,
    '    snyk:',
    `      enabled: ${sources.snyk?.enabled ?? false}`,
    '      url: https://api.snyk.io/rest',
    `      orgId: "${sources.snyk?.orgId ?? 'org-default'}"`,
    `      tokenFile: ${sources.snyk?.tokenFile ?? '/etc/rampart/feed-secrets/snyk-token'}`,
    '    vulncheck:',
    `      enabled: ${sources.vulncheck?.enabled ?? false}`,
    '      url: https://api.vulncheck.com/v3',
    `      tokenFile: ${sources.vulncheck?.tokenFile ?? '/etc/rampart/feed-secrets/vulncheck-token'}`,
    '    depsdev:',
    `      enabled: ${sources.depsdev?.enabled ?? true}`,
    '      url: https://api.deps.dev/v3',
  ];
  return lines.join('\n') + '\n';
}
