import { useEffect, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { listConnectors, listIntegrationPackages, qk, toProblem } from '@/api';
import type { ConnectorSummary } from '@/api/types';
import { Button, EmptyState, ProblemMessage, Spinner, Table, TBody, Td, Th, THead, Tr } from '@/components';
import { ConnectorCatalogueDialog } from '@/features/connectors/ConnectorCatalogueDialog';

/** The operator's Check result (D69), in words: connected, failing, or not checked yet. */
function checkState(c: ConnectorSummary): 'ok' | 'failing' | 'unknown' {
  const connected = c.status?.conditions?.find((cond) => cond.type === 'Connected');
  return connected?.status === 'True' ? 'ok' : connected?.status === 'False' ? 'failing' : 'unknown';
}

/**
 * Where Rampart sends messages (docs/50): the notifier connectors (Slack, Teams, email, webhooks, and plugin
 * connectors that use a package) and the notifier packages installed in the tenant. Which connector is a notifier
 * is the server's word (`kind` from the catalogue), not a list kept here. Connectors are resources (D82): the
 * catalogue writes one and checks it against the server, and nothing here creates one.
 */
export function NotifiersRoute() {
  const { t } = useTranslation();
  const [catalogueOpen, setCatalogueOpen] = useState(false);
  useEffect(() => {
    document.title = `${t('nav.notifiers')} · Rampart`;
  }, [t]);

  const connectorsQuery = useQuery({ queryKey: qk.connectors.list(), queryFn: ({ signal }) => listConnectors(signal) });
  const packagesQuery = useQuery({ queryKey: qk.connectors.packages(), queryFn: ({ signal }) => listIntegrationPackages(signal) });
  const notifiers = (connectorsQuery.data ?? []).filter((c) => c.kind === 'notifier');
  const packages = (packagesQuery.data ?? []).filter((p) => p.kind === 'notifier');

  return (
    <div className="mx-auto max-w-7xl p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex max-w-[72ch] flex-col gap-1">
          <h1 className="display text-20 font-semibold text-ink">{t('nav.notifiers')}</h1>
          <p className="text-13 text-ink-2">
            {t('notifiers.subtitle')}{' '}
            <Link to="/ticketing">{t('notifiers.trackersLink')}</Link>
          </p>
        </div>
        <Button variant="primary" onClick={() => setCatalogueOpen(true)}>{t('notifiers.add')}</Button>
      </div>

      <section aria-labelledby="notifiers-connectors" className="mt-6">
        <h2 id="notifiers-connectors" className="mb-2 text-14 font-semibold text-ink">{t('notifiers.connectorsTitle')}</h2>
        {connectorsQuery.isPending ? (
          <div className="flex items-center gap-2 py-6 text-13 text-ink-2"><Spinner size={16} /> {t('common.loading')}</div>
        ) : connectorsQuery.isError ? (
          <ProblemMessage problem={toProblem(connectorsQuery.error)} title={t('notifiers.connectorsFailed')} onRetry={() => void connectorsQuery.refetch()} />
        ) : notifiers.length === 0 ? (
          <EmptyState title={t('notifiers.emptyTitle')} className="p-0 text-left">{t('notifiers.emptyHint')}</EmptyState>
        ) : (
          <Table aria-label={t('notifiers.connectorsTitle')}>
            <THead>
              <tr>
                <Th>{t('notifiers.colName')}</Th>
                <Th>{t('notifiers.colType')}</Th>
                <Th>{t('notifiers.colStatus')}</Th>
                <Th>{t('notifiers.colMessage')}</Th>
              </tr>
            </THead>
            <TBody>
              {notifiers.map((c) => {
                const state = checkState(c);
                const message = c.status?.conditions?.find((cond) => cond.type === 'Connected')?.message;
                return (
                  <Tr key={c.name} className="h-12">
                    <Td className="font-medium text-ink">{c.name}</Td>
                    <Td className="text-13 text-ink-2">
                      {c.type === 'plugin' && c.spec?.plugin?.name ? t('notifiers.typePackage', { name: c.spec.plugin.name }) : c.type}
                    </Td>
                    {/* Words, not a coloured pill: colour is for risk (docs/13 section 6). */}
                    <Td className={state === 'failing' ? 'font-semibold text-ink' : 'text-ink-2'}>{t(`notifiers.state_${state}`)}</Td>
                    <Td className="whitespace-normal text-12 text-ink-2">{message || t('notifiers.noMessage')}</Td>
                  </Tr>
                );
              })}
            </TBody>
          </Table>
        )}
      </section>

      <section aria-labelledby="notifiers-packages" className="mt-8">
        <h2 id="notifiers-packages" className="mb-1 text-14 font-semibold text-ink">{t('notifiers.packagesTitle')}</h2>
        <p className="mb-2 max-w-[72ch] text-13 text-ink-2">{t('notifiers.packagesHelp')}</p>
        {packagesQuery.isPending ? (
          <div className="flex items-center gap-2 py-6 text-13 text-ink-2"><Spinner size={16} /> {t('common.loading')}</div>
        ) : packagesQuery.isError ? (
          <ProblemMessage problem={toProblem(packagesQuery.error)} title={t('notifiers.packagesFailed')} onRetry={() => void packagesQuery.refetch()} />
        ) : packages.length === 0 ? (
          <p className="text-13 text-ink-2">{t('notifiers.packagesEmpty')}</p>
        ) : (
          <Table aria-label={t('notifiers.packagesTitle')}>
            <THead>
              <tr>
                <Th>{t('notifiers.colPackage')}</Th>
                <Th>{t('notifiers.colRuntime')}</Th>
                <Th>{t('notifiers.colEgress')}</Th>
                <Th>{t('notifiers.colUsedBy')}</Th>
                <Th>{t('notifiers.colState')}</Th>
              </tr>
            </THead>
            <TBody>
              {packages.map((p) => (
                <Tr key={p.name}>
                  <Td className="whitespace-normal">
                    <span className="text-13 font-medium text-ink">{p.name}</span>
                    {p.description && <span className="block text-12 text-ink-2">{p.description}</span>}
                  </Td>
                  <Td className="whitespace-normal text-13 text-ink-2">
                    {p.runtime} {p.version}
                    {p.secrets.length > 0 && <span className="block text-12">{t('notifiers.needs', { secrets: p.secrets.join(', ') })}</span>}
                  </Td>
                  <Td className="font-mono text-12 text-ink-2">{p.egress.join(', ') || t('notifiers.egressNone')}</Td>
                  <Td className="text-13 text-ink-2">{p.used_by.length ? p.used_by.join(', ') : t('notifiers.usedByNone')}</Td>
                  <Td className={p.error ? 'whitespace-normal text-13 font-semibold text-ink' : 'text-13 text-ink-2'}>
                    {p.error ? t('notifiers.packageError', { error: p.error }) : t('notifiers.packageInstalled')}
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        )}
      </section>

      <ConnectorCatalogueDialog kindFilter="notifier" open={catalogueOpen} onOpenChange={setCatalogueOpen} />
    </div>
  );
}
