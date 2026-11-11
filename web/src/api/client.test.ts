import { afterEach, describe, expect, it, vi } from 'vitest';
import { get, post, ProblemError, setCsrfToken, toProblem } from './client';
import { getSession, listFindings } from './endpoints';

const respond = (status: number, body?: unknown, type = 'application/json') =>
  vi.stubGlobal('fetch', vi.fn(async () => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': type } })));

afterEach(() => vi.unstubAllGlobals());

describe('api client', () => {
  it('maps RFC 9457 bodies to a ProblemError with the request id', async () => {
    respond(409, { type: 'https://rampart.aspm.dev/problems/conflict-version', title: 'Version conflict', status: 409, detail: 'Changed', request_id: 'req_7' }, 'application/problem+json');
    const err = (await get('/x').catch((e: unknown) => e)) as ProblemError;
    expect(err).toBeInstanceOf(ProblemError);
    expect(err.problem).toMatchObject({ title: 'Version conflict', status: 409, request_id: 'req_7' });
  });
  it('survives a non-JSON error body', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>bad gateway</html>', { status: 502, statusText: 'Bad Gateway' })));
    expect(toProblem(await get('/x').catch((e) => e))).toMatchObject({ status: 502, title: 'Bad Gateway' });
  });
  it('turns a network failure into a status 0 problem', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('failed'); }));
    expect(toProblem(await get('/x').catch((e) => e)).status).toBe(0);
  });
  it('sends X-CSRF-Token on mutations only', async () => {
    const f = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', f);
    setCsrfToken('tok');
    await post('/auth/logout');
    await get('/api/v1/me/tenants').catch(() => {});
    const [[, a], [, b]] = f.mock.calls as unknown as [[string, RequestInit], [string, RequestInit]];
    expect((a.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok');
    expect((b.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined();
    expect(a.credentials).toBe('same-origin');
    setCsrfToken('');
  });
  it('getSession resolves null on 401 and rethrows other errors', async () => {
    respond(401, { title: 'Authentication required', status: 401 }, 'application/problem+json');
    expect(await getSession()).toBeNull();
    respond(500, { title: 'boom', status: 500 }, 'application/problem+json');
    await expect(getSession()).rejects.toBeInstanceOf(ProblemError);
  });
  it('listFindings accepts next_cursor or nextCursor, and null items', async () => {
    respond(200, { items: null, total: 0, next_cursor: 'abc' });
    expect(await listFindings({ q: '', sort: '-score' })).toEqual({ items: [], nextCursor: 'abc', total: 0 });
    respond(200, { items: [], nextCursor: 'xyz' });
    expect((await listFindings({ q: '', sort: '-score' })).nextCursor).toBe('xyz');
  });
  it('puts q, sort, limit and cursor in the query string', async () => {
    const f = vi.fn(async () => new Response(JSON.stringify({ items: [] }), { status: 200 }));
    vi.stubGlobal('fetch', f);
    await listFindings({ q: 'risk:high', sort: '-score', cursor: 'c1', limit: 25 });
    expect(String((f.mock.calls as unknown as [string][])[0]![0])).toBe('/api/v1/findings?q=risk%3Ahigh&sort=-score&cursor=c1&limit=25');
  });
});
