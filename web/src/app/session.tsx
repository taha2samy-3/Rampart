import { createContext, useContext } from 'react';
import type { Permissions, Session, UiConfig } from '@/api/types';

export interface AppContext {
  config: UiConfig;
  session: Session | null;
  permissions: Permissions | null;
}
export const AppCtx = createContext<AppContext | null>(null);

export function useApp(): AppContext {
  const v = useContext(AppCtx);
  if (!v) throw new Error('useApp outside Bootstrap');
  return v;
}

/** For screens behind the login guard: session and permissions are present. */
export function useSession(): { config: UiConfig; session: Session; permissions: Permissions } {
  const { config, session, permissions } = useApp();
  if (!session || !permissions) throw new Error('useSession without a session');
  return { config, session, permissions };
}
