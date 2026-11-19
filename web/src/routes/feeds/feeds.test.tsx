import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const feed = (over: Record<string, unknown>) => ({
  name: 'cisa_kev', display_name: 'CISA KEV', category: 'Threat Intelligence', description: 'Vulnerabilities known to be exploited', url: 'https://x.example/kev.json',
  is_mirror: false, enabled: true, status: 'success', records: 5, last_sync: '2026-11-17T10:00:00Z', ...over,
});

/** The server of the page: the feed list, the sync and the connection test, answering as a test says. */
function withFeeds(next: () => unknown[], opts: { syncStatus?: number; role?: 'admin' | 'triager'; mirror?: unknown } = {}) {
  mockFetch({ loggedIn: true, role: opts.role ?? 'admin' });
  const inner = globalThis.fetch;
  const posts: string[] = [];
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const path = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : input.url;
    const method = init?.method ?? 'GET';
    const reply = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': status < 400 ? 'application/json' : 'application/problem+json' } }));
    if (path === '/api/v1/feeds' && method === 'GET') return reply({ mirror: opts.mirror ?? null, items: next() });
    if (path.startsWith('/api/v1/feeds/sync')) {
      posts.push(path);
      return (opts.syncStatus ?? 202) === 202 ? reply({ status: 'started' }, 202) : reply({ type: 'u', title: 'Conflict', status: opts.syncStatus, detail: 'A feed sync is already running; its progress is in the table' }, opts.syncStatus);
    }
    return inner(input, init);
  });
  return posts;
}

describe('the Feeds page', () => {
  it('is in the sidebar on its own, and no longer a tab of Integrations', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/feeds');
    const nav = await screen.findByRole('navigation');
    expect(within(nav).getByRole('link', { name: 'Feeds' })).toHaveAttribute('href', '/feeds');
    expect(await screen.findByRole('heading', { level: 1, name: 'Feeds' })).toBeInTheDocument();
  });

  it('Integrations has no Feeds tab', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/integrations');
    await screen.findByRole('tab', { name: /Connectors/i });
    expect(screen.queryByRole('tab', { name: /Feeds/i })).toBeNull();
  });

  it('lists the feeds the server has, and says it in a sentence, not in tiles', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/feeds');
    const table = await screen.findByRole('table', { name: 'Feeds' });
    expect(within(table).getByText('CISA KEV')).toBeInTheDocument();
    expect(within(table).getByText('FIRST EPSS')).toBeInTheDocument();
    expect(within(table).getByText('NVD (National Vulnerability Database)')).toBeInTheDocument();
    expect(within(table).getByText('OSV (Open Source Vulnerabilities)')).toBeInTheDocument();
    expect(screen.getByText(/\d+ feeds: \d+ synced, \d+ failed, \d+ switched off\./)).toBeInTheDocument();
    expect(screen.queryByText('Total Feeds')).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('finds a feed by a word, and by its status', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/feeds');
    const table = await screen.findByRole('table', { name: 'Feeds' });
    await userEvent.type(screen.getByRole('searchbox', { name: 'Find a feed' }), 'EPSS');
    expect(within(table).getByText('FIRST EPSS')).toBeInTheDocument();
    expect(within(table).queryByText('CISA KEV')).toBeNull();
    await userEvent.clear(screen.getByRole('searchbox', { name: 'Find a feed' }));
    expect(within(table).getByText('CISA KEV')).toBeInTheDocument();
  });

  it('shows the ClusterFeed the server has, and not the public defaults, so an air gap is not undone by copying it', async () => {
    withFeeds(() => [feed({})]);
    renderApp('/feeds');
    await userEvent.click(await screen.findByRole('button', { name: 'View ClusterFeed' }));
    const dialog = await screen.findByRole('dialog');
    const yaml = within(dialog).getByText(/kind: ClusterFeed/).textContent ?? '';
    expect(yaml).toContain('egress: allow');
    expect(yaml).not.toMatch(/cisa\.gov|cyentia|nvd\.nist|googleapis|vulnrichment|exploitdb/);
    expect(within(dialog).getByText(/kubectl get clusterfeeds/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('says so when the feeds cannot be loaded, with a way to try again', async () => {
    mockFetch({ loggedIn: true, role: 'admin', feeds: 'error' });
    renderApp('/feeds');
    expect(await screen.findByText('The feeds could not be loaded')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
});

describe('Test', () => {
  it('probes every feed and shows the answer on the row it belongs to', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/feeds');
    await userEvent.click(await screen.findByRole('button', { name: 'Test all connections' }));
    const table = await screen.findByRole('table', { name: 'Feeds' });
    expect((await within(table).findAllByText(/Reachable, HTTP 200, \d+ ms/)).length).toBeGreaterThan(0);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('keeps the whole error of a failed feed, and says when the address answers but the sync failed', async () => {
    withFeeds(() => [feed({ name: 'nvd', display_name: 'NVD', status: 'error', error: 'GET https://services.nvd.nist.gov: 429 Too Many Requests', records: 0 })]);
    renderApp('/feeds');
    const table = await screen.findByRole('table', { name: 'Feeds' });
    expect(within(table).getByText(/429 Too Many Requests/)).toBeInTheDocument(); // not cut short
    await userEvent.click(within(table).getByRole('button', { name: /NVD/ }));
    const inspector = screen.getByRole('complementary', { name: 'Selected feed' });
    await userEvent.click(within(inspector).getByRole('button', { name: 'Test' }));
    expect(await within(table).findByText(/The address answers \(HTTP 200\); the failure is in the sync itself/)).toBeInTheDocument();
  });

  it('does not offer Test or Sync for a feed that is switched off, and says why', async () => {
    withFeeds(() => [feed({ name: 'nvd', display_name: 'NVD', enabled: false, status: 'disabled', records: 0 })]);
    renderApp('/feeds');
    await userEvent.click(await screen.findByRole('button', { name: /NVD/ }));
    const inspector = screen.getByRole('complementary', { name: 'Selected feed' });
    expect(within(inspector).getByRole('button', { name: 'Test' })).toBeDisabled();
    expect(within(inspector).getByRole('button', { name: 'Sync' })).toBeDisabled();
    expect(within(inspector).getByText(/It is switched off/)).toBeInTheDocument();
  });

  it('says the actual reason a feed is not run, not one reason for all', async () => {
    withFeeds(() => [
      feed({ name: 'nvd', display_name: 'NVD', enabled: false, status: 'disabled', disabled_reason: 'switched_off', records: 0 }),
      feed({ name: 'osv', display_name: 'OSV', enabled: false, status: 'disabled', disabled_reason: 'no_ecosystem', records: 0 }),
      feed({ name: 'first_epss', display_name: 'FIRST EPSS', enabled: false, status: 'disabled', disabled_reason: 'egress_denied', records: 0 }),
    ]);
    renderApp('/feeds');
    const inspector = () => screen.getByRole('complementary', { name: 'Selected feed' });
    await userEvent.click(await screen.findByRole('button', { name: /^NVD/ }));
    expect(within(inspector()).getByText(/switched off in the ClusterFeed \(enabled: false\)/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /^OSV/ }));
    expect(within(inspector()).getByText(/runs only for the ecosystems you name/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /FIRST EPSS/ }));
    expect(within(inspector()).getByText(/egress is denied and the ClusterFeed gives this feed no mirror address/)).toBeInTheDocument();
  });
});

describe('Sync', () => {
  // The status follows the server: the sync request is answered at once, the feed says "syncing" until it ends, and the
  // table then shows the result the server recorded.
  it('shows "syncing" from the server after Sync, then the result when it ends', async () => {
    let calls = 0;
    const posts = withFeeds(() => (calls++ === 0 ? [feed({})] : calls < 5 ? [feed({ status: 'syncing' })] : [feed({ records: 1781 })]));
    renderApp('/feeds');
    await userEvent.click(await screen.findByRole('button', { name: 'Sync all' }));
    expect(posts).toEqual(['/api/v1/feeds/sync']);
    expect(await screen.findByRole('status')).toHaveTextContent('Syncing CISA KEV');
    const table = await screen.findByRole('table', { name: 'Feeds' });
    expect(await within(table).findByText('1,781', {}, { timeout: 8000 })).toBeInTheDocument();
    expect(screen.queryByRole('status')).toBeNull();
  }, 20000);

  it('syncs one feed from the inspector, by its name', async () => {
    const posts = withFeeds(() => [feed({})]);
    renderApp('/feeds');
    await userEvent.click(await screen.findByRole('button', { name: /CISA KEV/ }));
    await userEvent.click(within(screen.getByRole('complementary', { name: 'Selected feed' })).getByRole('button', { name: 'Sync' }));
    expect(posts).toEqual(['/api/v1/feeds/sync?feed=cisa_kev']);
  });

  it('says why a sync could not start, and does not pretend it did', async () => {
    withFeeds(() => [feed({})], { syncStatus: 409 });
    renderApp('/feeds');
    await userEvent.click(await screen.findByRole('button', { name: 'Sync all' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('already running');
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('offers neither Sync nor a failing click to someone who is not an administrator, and says so', async () => {
    withFeeds(() => [feed({})], { role: 'triager' });
    renderApp('/feeds');
    await userEvent.click(await screen.findByRole('button', { name: /CISA KEV/ }));
    expect(screen.queryByRole('button', { name: 'Sync all' })).toBeNull();
    const inspector = screen.getByRole('complementary', { name: 'Selected feed' });
    expect(within(inspector).queryByRole('button', { name: 'Sync' })).toBeNull();
    expect(within(inspector).getByRole('button', { name: 'Test' })).toBeInTheDocument(); // testing is read-only
    expect(within(inspector).getByText('Only an administrator can start a sync.')).toBeInTheDocument();
  });

  it('does not call the feeds healthy when nothing has synced', async () => {
    withFeeds(() => [feed({ status: 'idle', records: 0, last_sync: null })]);
    renderApp('/feeds');
    expect(await screen.findByText(/None has synced yet\./)).toBeInTheDocument();
    expect(screen.queryByText('Healthy')).toBeNull();
  });
});
