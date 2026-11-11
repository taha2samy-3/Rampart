import { useMemo, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getPermissions, getSession, getUiConfig, qk, toProblem } from '@/api';
import { LogoMark, ProblemMessage, Spinner } from '@/components';
import { AppCtx } from './session';

export function Splash({ label }: { label: string }) {
  return (
    <div className="grid min-h-dvh place-items-center">
      <div className="flex items-center gap-3 text-13 text-ink-2" role="status">
        <LogoMark size={28} />
        <Spinner size={14} />
        <span>{label}</span>
      </div>
    </div>
  );
}

/**
 * Bootstrap sequence (docs/13 section 3): ui-config, then the session
 * (401 means "show the login screen", not an error), then permissions, then render.
 */
export function Bootstrap({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const config = useQuery({ queryKey: qk.uiConfig(), queryFn: getUiConfig, staleTime: 5 * 60_000 });
  const session = useQuery({
    queryKey: qk.session(),
    queryFn: getSession,
    enabled: config.isSuccess,
    staleTime: 60_000,
  });
  const signedIn = !!session.data;
  const perms = useQuery({ queryKey: qk.permissions(), queryFn: getPermissions, enabled: signedIn, staleTime: 60_000 });

  const value = useMemo(
    () =>
      config.data && session.data !== undefined
        ? { config: config.data, session: session.data, permissions: perms.data ?? null }
        : null,
    [config.data, session.data, perms.data],
  );

  const failed = config.error ?? session.error ?? (signedIn ? perms.error : null);
  if (failed && !value) {
    const retry = () => void (config.error ? config.refetch() : session.error ? session.refetch() : perms.refetch());
    return (
      <div className="grid min-h-dvh place-items-center p-6">
        <div className="w-full max-w-[460px]">
          <ProblemMessage problem={toProblem(failed)} title={t('boot.failedTitle')} next={t('boot.failedNext')} onRetry={retry} />
        </div>
      </div>
    );
  }
  if (failed && signedIn && !perms.data) {
    return (
      <div className="grid min-h-dvh place-items-center p-6">
        <div className="w-full max-w-[460px]">
          <ProblemMessage problem={toProblem(failed)} title={t('boot.failedTitle')} onRetry={() => void perms.refetch()} />
        </div>
      </div>
    );
  }
  if (!value || (signedIn && !perms.data)) return <Splash label={t('boot.loading')} />;
  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>;
}
