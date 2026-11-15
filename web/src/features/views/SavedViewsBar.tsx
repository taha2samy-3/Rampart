import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { createSavedView, deleteSavedView, findingsExportUrl, listSavedViews, qk, toProblem } from '@/api';
import type { SavedView } from '@/api/types';
import { Button, Dialog, DialogClose, DialogContent, IconChevronDown, IconX, Input, Menu, MenuContent, MenuItem, MenuLabel, MenuSeparator, MenuTrigger, ProblemMessage, useToast } from '@/components';

export function SavedViewsBar({
  q,
  onQueryChange,
  sort,
  onSortChange,
}: {
  q: string;
  onQueryChange: (q: string) => void;
  sort?: string;
  onSortChange?: (sort: string) => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const toast = useToast();
  const [saveOpen, setSaveOpen] = useState(false);
  const [viewName, setViewName] = useState('');
  const [scope, setScope] = useState<'tenant' | 'user'>('tenant');

  const { data: views = [] } = useQuery({
    queryKey: qk.views.list(),
    queryFn: ({ signal }) => listSavedViews(signal),
  });

  const createMutation = useMutation({
    mutationFn: () => createSavedView({ name: viewName, query: q, sort, scope }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.views.all() });
      toast.info(t('views.saved', { defaultValue: 'View saved successfully' }));
      setSaveOpen(false);
      setViewName('');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteSavedView(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.views.all() });
      toast.info(t('views.deleted', { defaultValue: 'View deleted' }));
    },
  });

  const currentView = views.find((v) => v.query.trim() === q.trim());

  return (
    <div className="flex items-center gap-1.5">
      {/* Saved Views Menu */}
      <Menu>
        <MenuTrigger asChild>
          <Button variant="secondary" className="h-8 gap-1.5 px-2.5 text-12 font-medium">
            <span>{currentView ? currentView.name : t('views.views', { defaultValue: 'Views' })}</span>
            <IconChevronDown width={12} height={12} className="opacity-70" />
          </Button>
        </MenuTrigger>
        <MenuContent align="start" className="w-56">
          <MenuLabel>{t('views.savedViews', { defaultValue: 'Saved Views' })}</MenuLabel>
          {views.length === 0 ? (
            <div className="px-3 py-2 text-12 text-ink-2">
              {t('views.noViews', { defaultValue: 'No saved views yet' })}
            </div>
          ) : (
            views.map((v: SavedView) => (
              <MenuItem
                key={v.id}
                onClick={() => {
                  onQueryChange(v.query);
                  if (v.sort && onSortChange) {
                    onSortChange(v.sort);
                  }
                }}
                className="flex items-center justify-between text-12"
              >
                <span className="truncate">{v.name}</span>
                <span
                  role="button"
                  tabIndex={0}
                  aria-label="Delete view"
                  onClick={(e) => {
                    e.stopPropagation();
                    deleteMutation.mutate(v.id);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      e.stopPropagation();
                      deleteMutation.mutate(v.id);
                    }
                  }}
                  className="ms-2 opacity-50 hover:opacity-100 focus:outline-none"
                >
                  <IconX width={12} height={12} />
                </span>
              </MenuItem>
            ))
          )}
          <MenuSeparator />
          <MenuItem onClick={() => setSaveOpen(true)} className="text-12 font-medium text-accent">
            {t('views.saveCurrent', { defaultValue: '+ Save current search' })}
          </MenuItem>
        </MenuContent>
      </Menu>

      {/* Export Menu (docs/21 §6.3) */}
      <Menu>
        <MenuTrigger asChild>
          <Button variant="secondary" className="h-8 gap-1.5 px-2.5 text-12 font-medium">
            <span>{t('common.export', { defaultValue: 'Export' })}</span>
            <IconChevronDown width={12} height={12} className="opacity-70" />
          </Button>
        </MenuTrigger>
        <MenuContent align="end" className="w-48">
          <MenuLabel>{t('views.exportFormat', { defaultValue: 'Export format' })}</MenuLabel>
          <MenuItem asChild>
            <a
              href={findingsExportUrl('csv', q)}
              download="findings.csv"
              className="flex items-center justify-between text-12"
            >
              <span>CSV (.csv)</span>
              <span className="text-10 text-ink-2">Spreadsheet</span>
            </a>
          </MenuItem>
          <MenuItem asChild>
            <a
              href={findingsExportUrl('json', q)}
              download="findings.json"
              className="flex items-center justify-between text-12"
            >
              <span>JSON (.json)</span>
              <span className="text-10 text-ink-2">Full dump</span>
            </a>
          </MenuItem>
          <MenuItem asChild>
            <a
              href={findingsExportUrl('ocsf', q)}
              download="findings.ocsf.json"
              className="flex items-center justify-between text-12"
            >
              <span>OCSF v1.1 (.json)</span>
              <span className="text-10 text-ink-2">Security Schema</span>
            </a>
          </MenuItem>
        </MenuContent>
      </Menu>

      {/* Save View Modal Dialog */}
      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent
          title={t('views.saveDialogTitle', { defaultValue: 'Save Current View' })}
          closeLabel={t('common.close', { defaultValue: 'Close' })}
        >
          <div className="flex flex-col gap-4">
            <p className="text-13 text-ink-2">
              {t('views.saveDialogDescription', {
                defaultValue: 'Save this search query to quickly filter your findings table anytime.',
              })}
            </p>

            <div className="flex flex-col gap-1.5">
              <label htmlFor="view-name-input" className="text-12 font-medium text-ink">
                {t('views.viewName', { defaultValue: 'View Name' })}
              </label>
              <Input
                id="view-name-input"
                autoFocus
                placeholder="e.g. Critical Unassigned, Snyk Log4j, etc."
                value={viewName}
                onChange={(e) => setViewName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && viewName.trim() && !createMutation.isPending) {
                    createMutation.mutate();
                  }
                }}
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-12 font-medium text-ink">
                {t('views.query', { defaultValue: 'Query' })}
              </label>
              <pre className="overflow-x-auto rounded border border-rule bg-canvas-2 p-2 text-11 text-ink-2 font-mono">
                {q || 'status:open'}
              </pre>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-12 font-medium text-ink">
                {t('views.visibility', { defaultValue: 'Visibility' })}
              </label>
              <div className="flex gap-4 text-13">
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="scope"
                    value="tenant"
                    checked={scope === 'tenant'}
                    onChange={() => setScope('tenant')}
                  />
                  <span>{t('views.tenantWide', { defaultValue: 'Tenant-wide (all users)' })}</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="scope"
                    value="user"
                    checked={scope === 'user'}
                    onChange={() => setScope('user')}
                  />
                  <span>{t('views.personalOnly', { defaultValue: 'Personal (only me)' })}</span>
                </label>
              </div>
            </div>

            {createMutation.isError && (
              <ProblemMessage problem={toProblem(createMutation.error)} />
            )}

            <div className="mt-2 flex justify-end gap-2">
              <DialogClose asChild>
                <Button variant="secondary">{t('common.cancel', { defaultValue: 'Cancel' })}</Button>
              </DialogClose>
              <Button
                variant="primary"
                loading={createMutation.isPending}
                disabled={!viewName.trim()}
                onClick={() => createMutation.mutate()}
              >
                {t('common.save', { defaultValue: 'Save View' })}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
