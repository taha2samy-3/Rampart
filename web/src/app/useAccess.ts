import { useQuery } from '@tanstack/react-query';
import { getMyAccess, qk } from '@/api';
import type { MyAccess } from '@/api/types';
import { atLeast, roleAnywhere, roleOn } from '@/lib/access';
import type { Role } from '@/api/types';
import { useApp } from './session';

/**
 * What the caller may do where. Until the bindings are known, the tenant role from the session decides, so a
 * screen never offers more than the tenant role gives; the server decides in the end.
 */
export function useAccess() {
  const { permissions } = useApp();
  const q = useQuery({ queryKey: qk.access(), queryFn: ({ signal }) => getMyAccess(signal), enabled: !!permissions, staleTime: 60_000, retry: false });
  const access: MyAccess = q.data ?? { role: permissions?.role ?? 'viewer', applications: {} };
  return {
    access,
    /** The caller holds at least `min` on this application. */
    can: (app: string | undefined, min: Role) => atLeast(roleOn(access, app), min),
    /** The caller holds at least `min` on some application, or on the whole tenant. */
    canAnywhere: (min: Role) => atLeast(roleAnywhere(access), min),
  };
}
