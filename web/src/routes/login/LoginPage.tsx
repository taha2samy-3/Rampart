import { useEffect, useState } from 'react';
import { Navigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { loginUrl, localLogin, toProblem } from '@/api';
import { useApp } from '@/app/session';
import { Button, Input, Logo, ProblemMessage, ScoreBar } from '@/components';
import type { ScoreBreakdown } from '@/api/types';
import { navigateTo } from '@/lib/nav';
import { safeReturnTo } from '@/lib/returnTo';

export interface LoginSearch {
  return_to?: string;
  error?: string;
  request_id?: string;
}

const KNOWN = ['invalid_state', 'idp_error', 'email_unverified', 'tenant_not_found', 'no_access', 'internal'];

/** An illustration made of the product's own claim: a real score bar, not artwork. */
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

export function LoginPage({ tenant: tenantParam, search }: { tenant?: string; search: LoginSearch }) {
  const { t } = useTranslation();
  const { config, session } = useApp();
  const returnTo = safeReturnTo(search.return_to);
  const methods = config.login?.methods ?? [];
  const sso = methods.filter((m) => m.type === 'oidc');
  const password = methods.find((m) => m.type === 'password');
  const [tenant, setTenant] = useState(tenantParam ?? '');
  const [idp, setIdp] = useState(sso[0]?.id ?? '');
  useEffect(() => {
    document.title = `${t('login.title')} - ${config.product}`;
  }, [t, config.product]);

  if (session) return <Navigate to={returnTo} replace />;

  const code = search.error ? (KNOWN.includes(search.error) ? search.error : 'default') : undefined;
  const single = sso.length === 1 ? sso[0] : undefined;
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    navigateTo(loginUrl(tenant.trim(), returnTo, sso.length > 1 ? idp : undefined));
  };

  return (
    <div className="grid min-h-dvh grid-cols-1 tablet:grid-cols-[minmax(320px,38%)_1fr]">
      <aside className="hidden flex-col justify-between border-e border-rule bg-chrome p-8 tablet:flex">
        <Logo size={28} />
        <div className="max-w-[32ch]">
          <p className="display text-20 leading-tight">{t('login.positioning')}</p>
          <div className="mt-5">
            <ScoreBar breakdown={SAMPLE} score={950} size="full" />
          </div>
          <p className="mt-2 text-13 text-ink-2">{t('login.legend')}</p>
        </div>
        <span />
      </aside>
      <main className="flex items-center px-6 py-10 tablet:px-16">
        <div className="w-full max-w-[380px]">
          <div className="mb-8 tablet:hidden">
            <Logo size={28} />
          </div>
          <h1 className="display text-28">
            {tenantParam ? t('login.tenantTitle', { tenant: tenantParam }) : t('login.title')}
          </h1>
          {code && (
            <ProblemMessage
              className="mt-4"
              problem={{
                type: '',
                title: t('login.errorTitle'),
                status: 0,
                detail: t(`login.errors.${code}`),
                request_id: search.request_id,
              }}
              next=""
            />
          )}
          {tenantParam !== undefined && (
            <div className="mt-6">
              <label htmlFor="tenant" className="mb-1 block text-13 font-medium">
                {t('login.tenantField')}
              </label>
              <Input id="tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} autoComplete="organization" spellCheck={false} aria-describedby="tenant-help" />
              <p id="tenant-help" className="mt-1 text-12 text-ink-2">
                {t('login.tenantHelp')}
              </p>
            </div>
          )}
          {methods.length === 0 && <p className="mt-6 text-13 text-ink-2">{t('login.noMethods')}</p>}
          {sso.length > 0 && (
            <form onSubmit={submit} noValidate>
              {sso.length > 1 && (
                <fieldset className="m-0 mt-6 border-0 p-0">
                  <legend className="mb-1 p-0 text-13 font-medium">{t('login.chooser')}</legend>
                  {sso.map((m) => (
                    <label key={m.id} className="flex h-8 cursor-pointer items-center gap-2 text-13">
                      <input type="radio" name="idp" className="accent-[var(--accent)]" checked={idp === m.id} onChange={() => setIdp(m.id)} />
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
          {password && sso.length > 0 && <p className="mt-8 border-t border-rule pt-4 text-13 text-ink-2">{t('login.password.or')}</p>}
          {password && <PasswordForm tenant={tenantParam !== undefined ? tenant.trim() : ''} returnTo={returnTo} primary={sso.length === 0} />}
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
          problem={{ type: '', title: t('login.password.failedTitle'), status: failure.status, detail: t(`login.password.errors.${key}`), request_id: failure.requestId }}
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
