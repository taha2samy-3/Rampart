import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getNotifications, getTenants, logout, markNotificationsRead, qk, switchTenant, toProblem } from '@/api';
import {
  IconBell, IconChevronDown, Logo, Menu, MenuContent, MenuItem, MenuLabel, MenuRadioGroup, MenuRadioItem,
  MenuSeparator, MenuTrigger, SearchField, useToast,
} from '@/components';
import { shortAge } from '@/lib/format';
import { useTheme, type ThemePreference } from '@/lib/theme';
import { useSession } from './session';

function TenantSwitcher() {
  const { t } = useTranslation();
  const { session } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const tenants = useQuery({ queryKey: qk.tenants(), queryFn: getTenants, staleTime: 60_000 });
  const m = useMutation({
    mutationFn: (slug: string) => switchTenant(slug),
    onSuccess: async (_d, slug) => {
      // The session rotates on the server: drop tenant-scoped data, then refetch.
      qc.removeQueries({ queryKey: qk.findings.all() });
      await qc.invalidateQueries({ queryKey: qk.session() });
      await qc.invalidateQueries({ queryKey: qk.permissions() });
      await qc.invalidateQueries({ queryKey: qk.tenants() });
      const name = tenants.data?.find((x) => x.slug === slug)?.name ?? slug;
      toast.info(t('shell.tenantSwitched', { name }));
    },
    onError: (e) => toast.problem(toProblem(e)),
  });
  const list = tenants.data ?? [];
  return (
    <Menu>
      <MenuTrigger
        aria-label={`${t('shell.tenant')}: ${session.tenant.name}`}
        className="inline-flex h-8 items-center gap-1.5 rounded-ctl px-2 text-13 hover:bg-chrome"
      >
        <span className="max-w-[16ch] truncate font-medium">{session.tenant.name}</span>
        <IconChevronDown width={12} height={12} className="text-ink-2" />
      </MenuTrigger>
      <MenuContent align="start">
        <MenuLabel>{t('shell.tenant')}</MenuLabel>
        {list.length === 0 ? (
          <MenuItem disabled>{t('shell.noTenants')}</MenuItem>
        ) : (
          <MenuRadioGroup value={session.tenant.slug} onValueChange={(slug) => slug !== session.tenant.slug && m.mutate(slug)}>
            {list.map((x) => (
              <MenuRadioItem key={x.id} value={x.slug}>
                {x.name}
              </MenuRadioItem>
            ))}
          </MenuRadioGroup>
        )}
      </MenuContent>
    </Menu>
  );
}

/**
 * What the sweeps found: deadlines passed or near, risk acceptances ending. The count is in the label, not on a
 * badge. Closing the list marks everything read for this user; while it is open the unread ones are in bold.
 */
function Notifications() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const q = useQuery({ queryKey: qk.notifications(), queryFn: ({ signal }) => getNotifications(signal), refetchInterval: 60_000, retry: false });
  const read = useMutation({ mutationFn: markNotificationsRead, onSuccess: () => qc.invalidateQueries({ queryKey: qk.notifications() }) });
  const unread = q.data?.unread ?? 0;
  const items = q.data?.items ?? [];
  return (
    <Menu onOpenChange={(open) => { if (!open && unread > 0) read.mutate(); }}>
      <MenuTrigger
        aria-label={unread > 0 ? t('shell.notificationsUnread', { count: unread }) : t('shell.notifications')}
        className="relative inline-flex h-8 items-center gap-1 rounded-ctl px-2 text-13 hover:bg-chrome"
      >
        <IconBell width={16} height={16} />
        {unread > 0 && <span aria-hidden="true" className="font-semibold">{unread > 99 ? '99+' : unread}</span>}
      </MenuTrigger>
      <MenuContent className="w-[360px] max-w-[calc(100vw-16px)]">
        <MenuLabel>{t('shell.notifications')}</MenuLabel>
        {q.isError && <div className="px-3 py-2 text-12 text-ink-2">{t('shell.notificationsFailed')}</div>}
        {q.data && items.length === 0 && <div className="px-3 py-2 text-12 text-ink-2">{t('shell.noNotifications')}</div>}
        {items.map((n) => (
          <MenuItem
            key={n.id}
            className="h-auto! flex-col items-start! gap-0 py-1.5"
            onSelect={() => { if (n.link) void navigate({ to: n.link.split('?')[0] as '/findings', search: Object.fromEntries(new URLSearchParams(n.link.split('?')[1] ?? '')) as never }); }}
          >
            <span className={n.unread ? 'font-semibold' : ''}>{n.title}</span>
            {n.body && <span className="line-clamp-2 text-12 text-ink-2">{n.body}</span>}
            <span className="text-12 text-ink-2"><time dateTime={n.created_at}>{shortAge(n.created_at)}</time></span>
          </MenuItem>
        ))}
      </MenuContent>
    </Menu>
  );
}

function UserMenu() {
  const { t } = useTranslation();
  const { session, permissions } = useSession();
  const { preference, setPreference } = useTheme();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();
  const out = useMutation({
    mutationFn: logout,
    onSuccess: () => {
      qc.clear();
      qc.setQueryData(qk.session(), null);
      void navigate({ to: '/login', search: {} });
    },
    onError: (e) => toast.problem(toProblem(e)),
  });
  const initials = (session.user.name || session.user.email).split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((s) => s[0]?.toUpperCase()).join('');
  return (
    <Menu>
      <MenuTrigger
        aria-label={t('shell.userMenu')}
        className="grid size-8 place-items-center rounded-ctl border border-rule text-12 font-semibold hover:bg-chrome"
      >
        {initials}
      </MenuTrigger>
      <MenuContent>
        <div className="px-3 py-1.5 text-13">
          <div className="font-medium">{session.user.name}</div>
          <div className="text-12 text-ink-2">{session.user.email}</div>
          <div className="text-12 text-ink-2">{t('shell.role', { role: permissions.role })}</div>
        </div>
        <MenuSeparator />
        <MenuLabel>{t('shell.theme')}</MenuLabel>
        <MenuRadioGroup value={preference} onValueChange={(v) => setPreference(v as ThemePreference)}>
          <MenuRadioItem value="system">{t('shell.themeSystem')}</MenuRadioItem>
          <MenuRadioItem value="light">{t('shell.themeLight')}</MenuRadioItem>
          <MenuRadioItem value="dark">{t('shell.themeDark')}</MenuRadioItem>
        </MenuRadioGroup>
        <MenuSeparator />
        <MenuItem onSelect={() => out.mutate()}>{t('shell.signOut')}</MenuItem>
      </MenuContent>
    </Menu>
  );
}

function GlobalSearch() {
  const { t } = useTranslation();
  const ref = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const [value, setValue] = useState('');
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Ctrl/Cmd+K is the palette shortcut (Phase 2); until then it jumps to search.
      if (e.key.toLowerCase() === 'k' && (e.ctrlKey || e.metaKey) && !e.altKey) {
        e.preventDefault();
        ref.current?.focus();
        return;
      }
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)) return;
      e.preventDefault();
      ref.current?.focus();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  return (
    <form
      role="search"
      className="w-full max-w-[420px]"
      onSubmit={(e) => {
        e.preventDefault();
        void navigate({ to: '/findings', search: { q: value.trim() || undefined } });
      }}
    >
      <SearchField
        ref={ref}
        shortcut="/"
        aria-label={t('shell.search')}
        placeholder={t('shell.searchPlaceholder')}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => e.key === 'Escape' && ref.current?.blur()}
      />
    </form>
  );
}

export function TopBar() {
  const { t } = useTranslation();
  return (
    <header className="flex h-11 items-center gap-3 border-b border-rule bg-surface ps-3 pe-3">
      <Link to="/findings" className="inline-flex items-center rounded-ctl text-ink no-underline" aria-label="Rampart">
        <Logo size={24} />
      </Link>
      <span className="h-5 w-px bg-rule" aria-hidden="true" />
      <TenantSwitcher />
      <div className="flex min-w-0 flex-1 justify-center" aria-label={t('shell.search')}>
        <GlobalSearch />
      </div>
      <Notifications />
      <UserMenu />
    </header>
  );
}
