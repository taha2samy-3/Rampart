import type { Problem } from './types';

/** An RFC 9457 problem, thrown by every failed call. */
export class ProblemError extends Error {
  readonly problem: Problem;
  constructor(problem: Problem) {
    super(problem.detail || problem.title);
    this.name = 'ProblemError';
    this.problem = problem;
  }
  get status(): number {
    return this.problem.status;
  }
}

export const PROBLEM_BASE = 'https://rampart.aspm.dev/problems/';

/** Normalise anything thrown into a Problem the UI can show. */
export function toProblem(err: unknown): Problem {
  if (err instanceof ProblemError) return err.problem;
  return {
    type: PROBLEM_BASE + 'internal',
    title: 'Something went wrong',
    status: 0,
    detail: err instanceof Error ? err.message : String(err),
  };
}

/** Build a Problem from a non-2xx response, tolerating bodies that are not problem+json. */
export async function problemFromResponse(res: Response): Promise<Problem> {
  let body: Partial<Problem> | null;
  try {
    const text = await res.text();
    body = text ? (JSON.parse(text) as Partial<Problem>) : null;
  } catch {
    body = null;
  }
  const fallbackTitle = res.statusText || `Request failed with status ${res.status}`;
  return {
    type: body?.type ?? PROBLEM_BASE + 'internal',
    title: body?.title ?? fallbackTitle,
    status: typeof body?.status === 'number' ? body.status : res.status,
    detail: body?.detail,
    request_id: body?.request_id ?? res.headers.get('X-Request-Id') ?? undefined,
    errors: body?.errors,
  };
}

// The CSRF token lives in memory only. It comes from GET /auth/session.
let csrfToken = '';
export function setCsrfToken(token: string): void {
  csrfToken = token;
}

type Query = Record<string, string | number | boolean | undefined | null>;
export interface RequestOptions {
  query?: Query;
  body?: unknown;
  signal?: AbortSignal;
  /** Extra request headers, for example If-Match (optimistic locking, docs/11). */
  headers?: Record<string, string>;
}

function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `${path}?${s}` : path;
}

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

export async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json, application/problem+json', ...opts.headers };
  const form = typeof FormData !== 'undefined' && opts.body instanceof FormData; // a file upload sets its own boundary
  if (opts.body !== undefined && !form) headers['Content-Type'] = 'application/json';
  if (!SAFE.has(method) && csrfToken) headers['X-CSRF-Token'] = csrfToken;

  let res: Response;
  try {
    res = await fetch(withQuery(path, opts.query), {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.body === undefined ? undefined : form ? (opts.body as FormData) : JSON.stringify(opts.body),
      signal: opts.signal,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ProblemError({
      type: PROBLEM_BASE + 'upstream-unavailable',
      title: 'Cannot reach the server',
      status: 0,
      detail: 'Check your connection and try again.',
    });
  }
  if (!res.ok) throw new ProblemError(await problemFromResponse(res));
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const get = <T>(path: string, opts?: RequestOptions) => request<T>('GET', path, opts);
export const post = <T>(path: string, body?: unknown, opts?: RequestOptions) =>
  request<T>('POST', path, { ...opts, body });
export const patch = <T>(path: string, body?: unknown, opts?: RequestOptions) =>
  request<T>('PATCH', path, { ...opts, body });
export const del = <T>(path: string, opts?: RequestOptions) => request<T>('DELETE', path, opts);
