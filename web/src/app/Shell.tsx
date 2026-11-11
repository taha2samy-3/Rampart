import { useState } from 'react';
import { Link, Outlet, useRouterState } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { IconButton, IconSidebar, Tooltip } from '@/components';
import { cn } from '@/lib/cn';
import { useMedia } from '@/lib/useMedia';
import { ErrorBoundary } from './ErrorBoundary';
import { NAV_GROUPS } from './nav';
import { TopBar } from './TopBar';

function isCurrent(pathname: string, path: string): boolean {
  const seg = path.slice(1);
  return pathname === path || pathname.startsWith(path + '/') || new RegExp(`^/t/[^/]+/${seg}(/|$)`).test(pathname);
}

function Nav({ collapsed }: { collapsed: boolean }) {
  const { t } = useTranslation();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  return (
    <nav aria-label={t('shell.navLabel')} className="flex flex-col py-2">
      {NAV_GROUPS.map((group, gi) => (
        <ul key={gi} className={cn('m-0 list-none p-0', gi > 0 && 'mt-4')}>
          {group.map((item) => {
            const current = isCurrent(pathname, item.path);
            const label = t(`nav.${item.id}`);
            const Icon = item.icon;
            const link = (
              <Link
                to={item.path as '/findings'}
                aria-current={current ? 'page' : undefined}
                aria-label={collapsed ? label : undefined}
                className={cn(
                  'flex h-8 items-center gap-2.5 border-s-[3px] text-13 text-ink no-underline hover:bg-surface/70',
                  collapsed ? 'justify-center px-0' : 'ps-[13px] pe-3',
                  current ? 'border-s-accent font-semibold' : 'border-s-transparent',
                )}
              >
                <Icon className={current ? 'text-accent' : 'text-ink-2'} />
                {!collapsed && <span>{label}</span>}
              </Link>
            );
            return <li key={item.id}>{collapsed ? <Tooltip label={label} side="right">{link}</Tooltip> : link}</li>;
          })}
        </ul>
      ))}
    </nav>
  );
}

export function Shell() {
  const { t } = useTranslation();
  const narrow = useMedia('(max-width: 899px)');
  const [userCollapsed, setUserCollapsed] = useState<boolean | null>(null);
  const collapsed = narrow || (userCollapsed ?? false);
  return (
    <div className="grid h-dvh grid-rows-[44px_minmax(0,1fr)]">
      <a
        href="#main"
        className="absolute start-2 top-2 z-[70] -translate-y-16 rounded-ctl border border-rule bg-surface px-3 py-1.5 text-13 focus:translate-y-0"
      >
        {t('common.skipToContent')}
      </a>
      <TopBar />
      <div className="flex min-h-0">
        <aside
          className={cn(
            'pane-anim flex shrink-0 flex-col justify-between border-e border-rule bg-chrome',
            collapsed ? 'w-12' : 'w-[170px]',
          )}
        >
          <Nav collapsed={collapsed} />
          {!narrow && (
            <div className={cn('p-1.5', collapsed ? 'flex justify-center' : '')}>
              <IconButton
                label={collapsed ? t('shell.expand') : t('shell.collapse')}
                aria-expanded={!collapsed}
                onClick={() => setUserCollapsed(!collapsed)}
              >
                <IconSidebar />
              </IconButton>
            </div>
          )}
        </aside>
        <main id="main" tabIndex={-1} className="min-w-0 flex-1 overflow-auto outline-none">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
