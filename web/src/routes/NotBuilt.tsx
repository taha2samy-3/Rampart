import { useEffect } from 'react';
import { Link } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { EmptyState } from '@/components';
import type { NavItem } from '@/app/nav';

/** Sections that ship later say which phase ships them (docs/13 section 9). */
export function NotBuilt({ item }: { item: NavItem }) {
  const { t } = useTranslation();
  const section = t(`nav.${item.id}`);
  useEffect(() => {
    document.title = `${section} - Rampart`;
  }, [section]);
  return (
    <div className="p-6">
      <h1 className="display mb-3 text-28">{section}</h1>
      <EmptyState className="p-0" title={t('notBuilt.title')} action={<Link to="/findings">{t('notBuilt.back')}</Link>}>
        {t('notBuilt.body', { section, phase: item.phase, what: item.what })}
      </EmptyState>
    </div>
  );
}
