import { useNavigate } from '@tanstack/react-router';
import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components';
import { TrackerBindingsView } from './TrackerBindingsView';
import { TrackerContainersView } from './TrackerContainersView';
import { TicketsQueueView } from './TicketsQueueView';

export type TicketingTab = 'containers' | 'bindings' | 'queue';

export function TicketingRoute({ search }: { search?: { tab?: TicketingTab } }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const activeTab: TicketingTab = search?.tab ?? 'containers';

  useEffect(() => {
    document.title = `${t('ticketing.title')} · Rampart`;
  }, [t]);

  const setTab = (next: string) => {
    const tab = (next === 'bindings' || next === 'queue' ? next : 'containers') as TicketingTab;
    void navigate({ to: '/ticketing', search: { tab }, replace: true });
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex flex-col gap-1">
        <h1 className="display text-20 font-semibold text-ink">{t('ticketing.title')}</h1>
        <p className="text-13 text-ink-2">{t('ticketing.subtitle')}</p>
      </div>

      <Tabs value={activeTab} onValueChange={setTab} className="mt-4">
        <TabsList label={t('ticketing.tabsLabel')}>
          <TabsTrigger value="containers">{t('ticketing.tabContainers')}</TabsTrigger>
          <TabsTrigger value="bindings">{t('ticketing.tabBindings')}</TabsTrigger>
          <TabsTrigger value="queue">{t('ticketing.tabQueue')}</TabsTrigger>
        </TabsList>

        <TabsContent value="containers">
          <TrackerContainersView />
        </TabsContent>
        <TabsContent value="bindings">
          <TrackerBindingsView />
        </TabsContent>
        <TabsContent value="queue">
          <TicketsQueueView />
        </TabsContent>
      </Tabs>
    </div>
  );
}
