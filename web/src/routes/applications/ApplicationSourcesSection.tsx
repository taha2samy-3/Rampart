import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getApplicationSources, qk, toProblem } from '@/api';
import type { ApplicationPage } from '@/api/types';
import {
  Button,
  EmptyState,
  ProblemMessage,
  Skeleton,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from '@/components';
import { IconCheck, IconCopy, IconRefresh } from '@/components/icons';
import { absoluteDate } from '@/lib/format';
import { cn } from '@/lib/cn';

interface SnippetBlockProps {
  code: string;
  language?: string;
}

function SnippetBlock({ code, language = 'yaml' }: SnippetBlockProps) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard blocked
    }
  };

  return (
    <div className="relative mt-3 rounded-ctl border border-rule bg-surface font-mono text-12">
      <div className="flex items-center justify-between border-b border-rule bg-chrome/50 px-3 py-1.5 text-11 text-ink-2">
        <span>{language.toUpperCase()}</span>
        <Button variant="ghost" className="h-6 px-2 text-11" onClick={onCopy} aria-label={t('common.copy')}>
          {copied ? <IconCheck className="size-3.5 text-accent" /> : <IconCopy className="size-3.5" />}
          <span>{copied ? t('common.copied') : t('common.copy')}</span>
        </Button>
      </div>
      <pre className="overflow-x-auto p-3 text-ink leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  );
}

export function ApplicationSourcesSection({ app }: { app: ApplicationPage }) {
  const { t } = useTranslation();
  const [snippetTab, setSnippetTab] = useState<'k8s' | 'helm' | 'ci'>('k8s');

  const { data: sources, isPending, isError, error, refetch, isFetching } = useQuery({
    queryKey: qk.applications.sources(app.id),
    queryFn: ({ signal }) => getApplicationSources(app.id, signal),
    retry: false,
  });

  const appSlug = app.slug || app.name.toLowerCase().replace(/[^a-z0-9]/g, '-');
  const appBranch = app.branch || 'main';

  const k8sSnippet = `apiVersion: rampart.aspm.dev/v1alpha1
kind: ScanSource
metadata:
  name: ${appSlug}-ci
  namespace: <tenant-namespace>
spec:
  applicationRef:
    name: ${appSlug}
  type: upload
  categories:
    - sast
    - sca
    - secret
  auth:
    federation:
      issuer: https://token.actions.githubusercontent.com
      boundClaims:
        repository: <org/repo>`;

  const helmSnippet = `bootstrap:
  enabled: true
  scanSources:
    - name: ${appSlug}-ci
      type: upload
      categories: [sast, sca, secret]
      applicationRef:
        name: ${appSlug}
      auth:
        federation:
          issuer: https://token.actions.githubusercontent.com
          boundClaims:
            repository: <org/repo>`;

  const ciSnippet = `# Push scan results directly to Rampart Gateway
curl -X POST "https://<rampart-host>/api/v1/ingest" \\
  -H "Authorization: Bearer <INGEST_TOKEN>" \\
  -H "X-Rampart-Application: ${appSlug}" \\
  -H "X-Rampart-Source: ${appSlug}-ci" \\
  -H "X-Rampart-Branch: ${appBranch}" \\
  -F "file=@results.sarif"`;

  if (isPending) {
    return (
      <div className="space-y-4 p-4" aria-busy="true" aria-label={t('common.loading')}>
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  if (isError) {
    const p = toProblem(error);
    return (
      <div className="p-4">
        <ProblemMessage
          problem={p}
          title={t('apps.sourcesFailed', { defaultValue: 'Failed to load scan sources' })}
          onRetry={() => void refetch()}
        />
      </div>
    );
  }

  const hasSources = sources && sources.length > 0;

  return (
    <section aria-labelledby="sources-heading" className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule pb-3">
        <div>
          <h2 id="sources-heading" className="text-14 font-semibold text-ink">
            {t('apps.tabSources', { defaultValue: 'Scan Sources & Pipelines' })}
          </h2>
          <p className="mt-0.5 text-12 text-ink-2">
            {t('apps.sourcesSub', {
              defaultValue:
                'Pipelines, CI/CD integrations, and security scanner sources exclusively bound to this application.',
            })}
          </p>
        </div>
        <Button
          variant="secondary"
          className="h-8 text-12"
          onClick={() => void refetch()}
          disabled={isFetching}
        >
          <IconRefresh className={cn('size-3.5', isFetching && 'animate-spin')} />
          <span>{t('common.refresh', { defaultValue: 'Refresh' })}</span>
        </Button>
      </div>

      {!hasSources ? (
        <div className="rounded-ctl border border-rule bg-surface/50 p-6">
          <EmptyState
            title={t('apps.noSourcesTitle', { defaultValue: 'No Scan Sources Bound Yet' })}
            className="p-0"
          >
            <p className="mt-1 text-13 text-ink-2">
              {t('apps.noSourcesDesc', {
                defaultValue:
                  'No security scanners or CI/CD pipelines are currently connected to this application. Declare a ScanSource via Kubernetes, configure it in Helm values, or upload scans via CI.',
              })}
            </p>

            <div className="mt-6">
              <Tabs value={snippetTab} onValueChange={(v) => setSnippetTab(v as 'k8s' | 'helm' | 'ci')}>
                <TabsList label="Configuration Snippets">
                  <TabsTrigger value="k8s">Kubernetes CRD</TabsTrigger>
                  <TabsTrigger value="helm">Helm values.yaml</TabsTrigger>
                  <TabsTrigger value="ci">CI Pipeline (cURL)</TabsTrigger>
                </TabsList>

                <TabsContent value="k8s" forceMount className="data-[state=inactive]:hidden focus-visible:outline-none">
                  <SnippetBlock code={k8sSnippet} language="yaml" />
                </TabsContent>

                <TabsContent value="helm" forceMount className="data-[state=inactive]:hidden focus-visible:outline-none">
                  <SnippetBlock code={helmSnippet} language="yaml" />
                </TabsContent>

                <TabsContent value="ci" forceMount className="data-[state=inactive]:hidden focus-visible:outline-none">
                  <SnippetBlock code={ciSnippet} language="bash" />
                </TabsContent>
              </Tabs>
            </div>
          </EmptyState>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-ctl border border-rule bg-surface">
          <Table>
            <THead>
              <Tr>
                <Th>{t('apps.sourceColName', { defaultValue: 'Source / Pipeline' })}</Th>
                <Th>{t('apps.sourceColStatus', { defaultValue: 'Status' })}</Th>
                <Th>{t('apps.sourceColMode', { defaultValue: 'Mode' })}</Th>
                <Th>{t('apps.sourceColCategories', { defaultValue: 'Disciplines' })}</Th>
                <Th>{t('apps.sourceColAuth', { defaultValue: 'Authentication' })}</Th>
                <Th>{t('apps.sourceColBranch', { defaultValue: 'Baseline Branch' })}</Th>
                <Th className="text-right">{t('apps.sourceColRuns', { defaultValue: 'Total Runs' })}</Th>
                <Th className="text-right">{t('apps.sourceColLastScan', { defaultValue: 'Last Scan' })}</Th>
              </Tr>
            </THead>
            <TBody>
              {sources.map((src) => {
                const isMulti = src.auth_type === 'multi';
                const isFed = src.auth_type === 'federation';

                return (
                  <Tr key={src.id}>
                    <Td className="font-medium text-ink">
                      <div>
                        <span>{src.name}</span>
                        {src.scanner_family && (
                          <span className="ms-1.5 text-11 text-ink-2">({src.scanner_family})</span>
                        )}
                      </div>
                    </Td>
                    <Td>
                      <span className="inline-flex items-center gap-1.5 text-12">
                        <span
                          className={cn(
                            'size-2 rounded-full',
                            src.active ? 'bg-emerald-500' : 'bg-ink-3'
                          )}
                        />
                        <span className={src.active ? 'text-ink' : 'text-ink-2'}>
                          {src.active
                            ? t('common.active', { defaultValue: 'Active' })
                            : t('common.disabled', { defaultValue: 'Disabled' })}
                        </span>
                      </span>
                    </Td>
                    <Td>
                      <span className="inline-flex rounded-full bg-chrome px-2 py-0.5 text-11 font-medium text-ink">
                        {src.type || 'upload'}
                      </span>
                    </Td>
                    <Td>
                      <div className="flex flex-wrap gap-1">
                        {src.categories.map((cat: string) => (
                          <span
                            key={cat}
                            className="inline-flex rounded bg-chrome px-1.5 py-0.5 text-10 font-medium uppercase text-ink-2"
                          >
                            {cat}
                          </span>
                        ))}
                      </div>
                    </Td>
                    <Td>
                      {isMulti ? (
                        <span className="inline-flex items-center rounded-full bg-accent/10 px-2 py-0.5 text-11 font-medium text-accent">
                          Token + OIDC Federation
                        </span>
                      ) : isFed ? (
                        <span className="inline-flex items-center rounded-full bg-blue-500/10 px-2 py-0.5 text-11 font-medium text-blue-600 dark:text-blue-400">
                          OIDC Federation
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded-full bg-chrome px-2 py-0.5 text-11 font-medium text-ink-2">
                          Standard Token
                        </span>
                      )}
                    </Td>
                    <Td className="font-mono text-12 text-ink-2">
                      {appBranch}
                    </Td>
                    <Td className="text-right font-medium text-ink">
                      {src.total_runs}
                    </Td>
                    <Td className="text-right text-12 text-ink-2">
                      {src.last_scan_at ? absoluteDate(src.last_scan_at) : t('common.never', { defaultValue: 'Never' })}
                    </Td>
                  </Tr>
                );
              })}
            </TBody>
          </Table>
        </div>
      )}
    </section>
  );
}
