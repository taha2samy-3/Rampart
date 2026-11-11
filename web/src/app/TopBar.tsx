import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getTenants, logout, qk, switchTenant, toProblem } from '@/api';
import {
  IconChevronDown, Logo, Menu, MenuContent, MenuItem, MenuLabel, MenuRadioGroup, MenuRadioItem,
  MenuSeparator, MenuTrigger, SearchField, useToast,
} from '@/components';
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
      <UserMenu />
    </header>
  );
}
