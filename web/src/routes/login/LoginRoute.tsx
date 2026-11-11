import { useEffect, useState } from 'react';
import { Navigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { loginUrl } from '@/api';
import { Button, Input, Logo, ProblemMessage } from '@/components';
import { safeReturnTo } from '@/lib/returnTo';
import { navigateTo } from '@/lib/nav';
import { useApp } from '@/app/session';
import type { ScoreBreakdown } from '@/api/types';
import { ScoreBar } from '@/components';

export interface LoginSearch {
  return_to?: string;
  error?: string;
  request_id?: string;
}

const SAMPLE: ScoreBreakdown = {
  base_severity: 'critical',
  base_points: 600,
  total_score: 950,
  band: 'critical',
  factors: [
    { name: 'KEV', points: 300, reason: '' },
    { name: 'INTERNET_FACING', points: 100, reason: '' },
    { name: 'COMPENSATING_CONTROL', points: -80, reason: '' },
  ],
};

export function LoginRoute({ search, tenantFromUrl }: { search: LoginSearch; tenantFromUrl?: string }) {
  const { t } = useTranslation();
  const { config, session } = useApp();
  const methods = config.login?.methods ?? [];
  const returnTo = safeReturnTo(search.return_to);
  const [tenant, setTenant] = useState(tenantFromUrl ?? '');
  const [method, setMethod] = useState(methods[0]?.id ?? '');
  useEffect(() => {
    document.title = `${t('login.title')} - Rampart`;
  }, [t]);

  if (session) return <Navigate to={returnTo as '/findings'} replace />;

  const single = methods.length === 1 ? methods[0] : undefined;
  const heading = tenantFromUrl ? t('login.tenantTitle', { tenant: tenantFromUrl }) : t('login.title');
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    navigateTo(loginUrl(tenant.trim(), returnTo, methods.length > 1 ? method : undefined));
  };

  return (
    <div className="grid min-h-dvh grid-cols-1 tablet:grid-cols-[minmax(320px,2fr)_3fr]">
      <aside className="hidden flex-col justify-between border-e border-rule bg-chrome p-8 tablet:flex">
        <Logo size={28} />
        <div className="max-w-[34ch]">
          <p className="display text-20 leading-snug">Every finding from every scanner, in one queue, with the reason for each score.</p>
          <div className="mt-5">
            <ScoreBar breakdown={SAMPLE} score={950} size="full" />
            <p className="mt-2 text-12 text-ink-2">Severity 600, known exploited 300, internet-facing 100, controls removed 80.</p>
          </div>
        </div>
        <p className="text-12 text-ink-2">{config.product} {config.version}</p>
      </aside>

      <main className="flex items-center px-6 py-10 tablet:px-16">
        <form onSubmit={submit} className="w-full max-w-[380px]" aria-labelledby="login-title">
          <div className="mb-8 tablet:hidden">
            <Logo size={28} />
          </div>
          <h1 id="login-title" className="display text-28">{heading}</h1>

          {search.error && (
            <ProblemMessage
              className="mt-5"
              title={t('login.errorTitle')}
              problem={{ type: 'about:blank', title: search.error, status: 401, request_id: search.request_id }}
              next={t('login.errorNext')}
            />
          )}

          {tenantFromUrl !== undefined && (
            <div className="mt-6">
              <label htmlFor="tenant" className="mb-1 block text-13 font-medium">{t('login.tenantField')}</label>
              <Input id="tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} autoComplete="organization" spellCheck={false} aria-describedby="tenant-help" />
              <p id="tenant-help" className="mt-1 text-12 text-ink-2">{t('login.tenantHelp')}</p>
            </div>
          )}

          {methods.length === 0 && <p className="mt-6 text-13 text-ink-2">{t('login.noMethods')}</p>}

          {methods.length > 1 && (
            <fieldset className="m-0 mt-6 border-0 p-0">
              <legend className="mb-1 p-0 text-13 font-medium">{t('login.chooser')}</legend>
              {methods.map((m) => (
                <label key={m.id} className="flex h-8 cursor-pointer items-center gap-2 text-13">
                  <input type="radio" name="idp" value={m.id} checked={method === m.id} onChange={() => setMethod(m.id)} className="accent-[var(--accent)]" />
                  {m.name}
                </label>
              ))}
            </fieldset>
          )}

          {methods.length > 0 && (
            <Button type="submit" variant="primary" className="mt-6 h-9 w-full">
              {single ? t('login.single', { name: single.name }) : t('login.continue')}
            </Button>
          )}
        </form>
      </main>
    </div>
  );
}
