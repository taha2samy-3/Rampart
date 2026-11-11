import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { Problem } from '@/api/types';
import { IconButton } from './Button';
import { IconX } from './icons';
import { ProblemMessage } from './Problem';

interface ToastItem {
  id: number;
  kind: 'info' | 'problem';
  text?: string;
  problem?: Problem;
}
interface ToastApi {
  info: (text: string) => void;
  problem: (p: Problem) => void;
}
const Ctx = createContext<ToastApi>({ info: () => {}, problem: () => {} });
export const useToast = () => useContext(Ctx);

let seq = 0;

/** Plain rectangles docked bottom-end. Confirmations vanish; problems stay until closed. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const [items, setItems] = useState<ToastItem[]>([]);
  const drop = useCallback((id: number) => setItems((l) => l.filter((x) => x.id !== id)), []);
  const api = useMemo<ToastApi>(
    () => ({
      info: (text) => {
        const id = ++seq;
        setItems((l) => [...l, { id, kind: 'info', text }]);
        setTimeout(() => drop(id), 4000);
      },
      problem: (problem) => setItems((l) => [...l, { id: ++seq, kind: 'problem', problem }]),
    }),
    [drop],
  );
  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-4 end-4 z-[60] flex w-[360px] max-w-[calc(100vw-2rem)] flex-col gap-2">
        {items.map((i) => (
          <div key={i.id} className="pointer-events-auto flex items-start gap-2 border border-rule bg-surface p-3 text-13" role={i.kind === 'info' ? 'status' : undefined}>
            <div className="min-w-0 flex-1">
              {i.kind === 'info' ? i.text : i.problem && <ProblemMessage problem={i.problem} />}
            </div>
            <IconButton label={t('common.close')} onClick={() => drop(i.id)} className="size-6">
              <IconX width={12} height={12} />
            </IconButton>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}
