import type { MyAccess, Role } from '@/api/types';

const RANK: Record<Role, number> = { viewer: 10, triager: 20, maintainer: 25, owner: 30, admin: 40 };
export const roleRank = (r: Role | undefined) => (r ? RANK[r] : 0);
export const ROLES_FOR_BINDING: Role[] = ['viewer', 'triager', 'maintainer', 'owner'];

/** The role the caller holds on an application: the tenant role, raised by a binding. */
export function roleOn(access: Pick<MyAccess, 'role' | 'applications'>, app: string | undefined): Role {
  const bound = app ? access.applications[app] : undefined;
  return roleRank(bound) > roleRank(access.role) ? (bound as Role) : access.role;
}
/** The highest role held anywhere: it decides which screens are offered. */
export function roleAnywhere(access: Pick<MyAccess, 'role' | 'applications'>): Role {
  return Object.values(access.applications).reduce<Role>((best, r) => (roleRank(r) > roleRank(best) ? r : best), access.role);
}
export const atLeast = (r: Role, min: Role) => roleRank(r) >= roleRank(min);
