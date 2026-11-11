import { useEffect, useState } from 'react';
import { Navigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { loginUrl, localLogin, toProblem } from '@/api';
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
  const sso = methods.filter((m) => m.type === 'oidc');
  const password = methods.find((m) => m.type === 'password');
  const [method, setMethod] = useState(sso[0]?.id ?? '');
  useEffect(() => {
    document.title = `${t('login.title')} - Rampart`;
  }, [t]);

  if (session) return <Navigate to={returnTo as '/findings'} replace />;

  const single = sso.length === 1 ? sso[0] : undefined;
  const heading = tenantFromUrl ? t('login.tenantTitle', { tenant: tenantFromUrl }) : t('login.title');
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    navigateTo(loginUrl(tenant.trim(), returnTo, sso.length > 1 ? method : undefined));
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
        <div className="w-full max-w-[380px]">
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

          {sso.length > 0 && (
            <form onSubmit={submit} aria-labelledby="login-title">
              {sso.length > 1 && (
                <fieldset className="m-0 mt-6 border-0 p-0">
                  <legend className="mb-1 p-0 text-13 font-medium">{t('login.chooser')}</legend>
                  {sso.map((m) => (
                    <label key={m.id} className="flex h-8 cursor-pointer items-center gap-2 text-13">
                      <input type="radio" name="idp" value={m.id} checked={method === m.id} onChange={() => setMethod(m.id)} className="accent-[var(--accent)]" />
                      {m.name}
                    </label>
                  ))}
                </fieldset>
              )}
              <Button type="submit" variant="primary" className="mt-6 h-9 w-full">
                {single ? t('login.single', { name: single.name }) : t('login.continue')}
              </Button>
            </form>
          )}

          {password && sso.length > 0 && (
            <p className="mt-8 border-t border-rule pt-4 text-13 text-ink-2">{t('login.password.or')}</p>
          )}
          {password && <PasswordForm tenant={tenantFromUrl !== undefined ? tenant.trim() : ''} returnTo={returnTo} primary={sso.length === 0} />}
        </div>
      </main>
    </div>
  );
}

/**
 * The break-glass local administrator (docs/16 D3). Primary only when it is the sole way in; next to
 * single sign-on it is secondary, so the view keeps one primary action.
 */
function PasswordForm({ tenant, returnTo, primary }: { tenant: string; returnTo: string; primary: boolean }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<{ status: number; detail?: string; requestId?: string } | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setFailure(null);
    try {
      await localLogin({ tenant: tenant || undefined, username: username.trim(), password: pw });
      navigateTo(returnTo); // a full load: the app then bootstraps with the new session
    } catch (err) {
      const p = toProblem(err);
      setPw(''); // never keep a rejected password in the field
      setFailure({ status: p.status, detail: p.detail, requestId: p.request_id });
      setBusy(false);
    }
  };

  const key = failure && ['401', '403', '429'].includes(String(failure.status)) ? String(failure.status) : 'default';
  return (
    <form onSubmit={onSubmit} className={primary ? 'mt-6' : 'mt-3'} aria-label={t('login.password.or')}>
      {primary && <p className="mb-4 text-13 text-ink-2">{t('login.password.intro')}</p>}
      {failure && (
        <ProblemMessage
          className="mb-4"
          title={t('login.password.failedTitle')}
          problem={{ type: 'about:blank', title: t(`login.password.errors.${key}`), status: failure.status, detail: key === '429' ? failure.detail : undefined, request_id: failure.requestId }}
          next={t(`login.password.next.${key}`)}
        />
      )}
      <label htmlFor="local-username" className="mb-1 block text-13 font-medium">{t('login.password.username')}</label>
      <Input id="local-username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" spellCheck={false} autoCapitalize="none" required />
      <label htmlFor="local-password" className="mb-1 mt-3 block text-13 font-medium">{t('login.password.password')}</label>
      <Input id="local-password" type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" required />
      <Button type="submit" variant={primary ? 'primary' : 'secondary'} loading={busy} className="mt-5 h-9 w-full">
        {t('login.password.submit')}
      </Button>
    </form>
  );
}
