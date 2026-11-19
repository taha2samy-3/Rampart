import type { FindingLocation } from '@/api/types';

type Nested = {
  code?: Partial<FindingLocation>;
  package?: Partial<FindingLocation> & { purl_base?: string };
  web?: { normalized_url?: string; method?: string; param?: string };
  resource?: { resource_address?: string; resource_key?: string; resource_type?: string };
  image?: string;
};

/**
 * The location of a finding, flat. The server sends it nested by kind ({ code: { file_path }, package: { purl } }); a
 * screen should not know that, so everything reads this. A flat location (an older answer, a test) passes through.
 */
export function locationOf(raw: unknown): FindingLocation {
  if (!raw || typeof raw !== 'object') return {};
  const n = raw as Nested & FindingLocation;
  const out: FindingLocation = {};
  const c = n.code;
  if (c) {
    Object.assign(out, pick(c, ['file_path', 'start_line', 'end_line', 'start_column', 'end_column', 'logical_location', 'snippet']));
  }
  const p = n.package;
  if (p) Object.assign(out, pick(p, ['purl', 'component_name', 'installed_version', 'fixed_version', 'manifest_path', 'dependency_path']));
  if (n.web) {
    if (n.web.normalized_url) out.url = n.web.normalized_url;
    if (n.web.method) out.method = n.web.method;
    if (n.web.param) out.param = n.web.param;
  }
  if (n.resource) Object.assign(out, pick(n.resource, ['resource_address', 'resource_key', 'resource_type']));
  if (typeof n.image === 'string' && n.image) out.image = n.image;
  // flat fields already on the object (the older shape) fill what the nested kinds did not
  for (const k of Object.keys(n) as (keyof FindingLocation)[]) {
    if (!(k in out) && n[k] !== undefined && !['code', 'package', 'web', 'resource'].includes(k as string)) (out as Record<string, unknown>)[k] = n[k];
  }
  return out;
}

function pick<T extends object>(from: T, keys: (keyof T)[]): Partial<T> {
  const out: Partial<T> = {};
  for (const k of keys) if (from[k] !== undefined && from[k] !== '' && from[k] !== 0 && !(Array.isArray(from[k]) && (from[k] as unknown[]).length === 0)) out[k] = from[k];
  return out;
}

/** The one line that says where it is: the package, the file and line, the address, the resource, the image. */
export function whereText(l: FindingLocation): string {
  if (l.purl) return l.purl;
  if (l.component_name) return l.installed_version ? `${l.component_name} ${l.installed_version}` : l.component_name;
  if (l.file_path) return l.start_line ? `${l.file_path}:${l.start_line}` : l.file_path;
  if (l.url) return l.method ? `${l.method} ${l.url}` : l.url;
  return l.resource_address || l.resource_key || l.image || '';
}
