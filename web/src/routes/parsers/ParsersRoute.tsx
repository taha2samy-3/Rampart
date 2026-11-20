import { useEffect } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useTranslation } from 'react-i18next';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components';
import { AnalyzersView } from './AnalyzersView';
import { ParserList } from './ParserList';

export type ParsersTab = 'report' | 'sbom' | 'analyzers';
export interface ParsersSearch {
  tab?: ParsersTab;
}

/**
 * What reads and checks what is uploaded, in one place with three tabs: the parsers that read scanner reports, the SBOM parsers that read an
 * inventory, and the analyzers that look for vulnerabilities in it. Each says whether it is installed correctly and how it last worked.
 */
export function ParsersRoute({ search }: { search: ParsersSearch }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const tab: ParsersTab = search.tab ?? 'report';
  useEffect(() => {
    document.title = `${t('nav.parsers')} - Rampart`;
  }, [t]);

  return (
    <Tabs value={tab} onValueChange={(v) => void navigate({ to: '/parsers', search: { tab: v as ParsersTab }, replace: true })} className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-x-4 border-b border-rule px-4 py-2">
        <h1 className="display text-16">{t('parsers.title')}</h1>
        <TabsList label={t('parsers.tabsLabel')}>
          <TabsTrigger value="report">{t('parsers.tabReport')}</TabsTrigger>
          <TabsTrigger value="sbom">{t('parsers.tabSbom')}</TabsTrigger>
          <TabsTrigger value="analyzers">{t('parsers.tabAnalyzers')}</TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="report" className="min-h-0 flex-1 overflow-auto p-4 tablet:p-6 data-[state=inactive]:hidden">
        <ParserList family="report" />
      </TabsContent>
      <TabsContent value="sbom" className="min-h-0 flex-1 overflow-auto p-4 tablet:p-6 data-[state=inactive]:hidden">
        <ParserList family="sbom" />
      </TabsContent>
      <TabsContent value="analyzers" className="min-h-0 flex-1 overflow-auto data-[state=inactive]:hidden">
        <AnalyzersView />
      </TabsContent>
    </Tabs>
  );
}
