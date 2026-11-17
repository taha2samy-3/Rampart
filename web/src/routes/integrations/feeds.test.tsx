import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('vulnerability feeds tab and declarative CRD', () => {
  it('displays feeds and their sync status from the server', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');

    const tab = await screen.findByRole('tab', { name: /Vulnerability Feeds/i });
    await userEvent.click(tab);

    const table = await screen.findByRole('table', { name: 'Vulnerability feeds table' });
    expect(within(table).getByText('CISA KEV')).toBeInTheDocument();
    expect(within(table).getByText('FIRST EPSS')).toBeInTheDocument();
    expect(within(table).getByText('NVD (National Vulnerability Database)')).toBeInTheDocument();
    expect(within(table).getByText('OSV (Open Source Vulnerabilities)')).toBeInTheDocument();

    // Check stats are displayed
    expect(screen.getByText('Total Feeds')).toBeInTheDocument();
    expect(screen.getByText('Synced Records')).toBeInTheDocument();
    expect(screen.getByText('Feed Health')).toBeInTheDocument();
    expect(screen.getByText('Storage Mode')).toBeInTheDocument();

    expect(await axe(container)).toHaveNoViolations();
  });

  it('filters feeds by search keyword and status', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/integrations');

    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    const table = await screen.findByRole('table', { name: 'Vulnerability feeds table' });

    const searchInput = screen.getByPlaceholderText('Search feeds...');
    await userEvent.type(searchInput, 'EPSS');

    expect(within(table).getByText('FIRST EPSS')).toBeInTheDocument();
    expect(within(table).queryByText('CISA KEV')).toBeNull();

    // Clear search
    await userEvent.clear(searchInput);
    expect(within(table).getByText('CISA KEV')).toBeInTheDocument();
  });

  it('opens and displays the declarative CRD specification modal', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');

    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    await userEvent.click(await screen.findByRole('button', { name: /Declarative CRD Spec/i }));

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Declarative ClusterFeed Specification')).toBeInTheDocument();
    expect(within(dialog).getByText(/kubectl get clusterfeeds/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/kind: ClusterFeed/i)).toBeInTheDocument();

    // Close dialog
    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));
    expect(screen.queryByRole('dialog')).toBeNull();

    expect(await axe(container)).toHaveNoViolations();
  });

  it('handles server errors gracefully without crashing the UI', async () => {
    mockFetch({ loggedIn: true, role: 'admin', feeds: 'error' });
    renderApp('/integrations');

    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/The vulnerability feeds could not be loaded/i)).toBeInTheDocument();
  });

  it('triggers live connectivity probe when clicking test button', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');

    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));

    const testAllBtn = await screen.findByRole('button', { name: /Test Live Connectivity/i });
    await userEvent.click(testAllBtn);

    expect(await screen.findByText(/Live probe verified/i)).toBeInTheDocument();
    expect(screen.getAllByText(/HTTP 200/i).length).toBeGreaterThan(0);

    expect(await axe(container)).toHaveNoViolations();
  });

  // The status column follows the server: the sync request is answered at once, the feed says "syncing" until it
  // ends, and the table then shows the result (or the error) the server recorded.
  const feed = (over: Record<string, unknown>) => ({ name: 'cisa_kev', display_name: 'CISA KEV', category: 'Threat Intelligence', description: 'd', url: 'https://x', is_mirror: false, enabled: true, status: 'success', records: 5, last_sync: '2026-11-17T10:00:00Z', ...over });
  const withFeeds = (next: () => unknown[], syncStatus = 202) => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const inner = globalThis.fetch;
    const posts: string[] = [];
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : input.url;
      if (path === '/api/v1/feeds' && (init?.method ?? 'GET') === 'GET') {
        return Promise.resolve(new Response(JSON.stringify({ mirror: null, items: next() }), { status: 200, headers: { 'content-type': 'application/json' } }));
      }
      if (path.startsWith('/api/v1/feeds/sync')) {
        posts.push(path);
        const body = syncStatus === 202 ? { status: 'started' } : { type: 'u', title: 'Conflict', status: syncStatus, detail: 'A feed sync is already running; its progress is in the table' };
        return Promise.resolve(new Response(JSON.stringify(body), { status: syncStatus, headers: { 'content-type': 'application/json' } }));
      }
      return inner(input, init);
    });
    return posts;
  };

  it('shows "syncing" from the server after Sync, then the result when it ends', async () => {
    let calls = 0;
    const posts = withFeeds(() => (calls++ === 0 ? [feed({})] : calls < 5 ? [feed({ status: 'syncing' })] : [feed({ records: 1781 })]));
    renderApp('/integrations');
    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    await userEvent.click(await screen.findByRole('button', { name: /Sync Now/i }));

    expect(posts).toEqual(['/api/v1/feeds/sync']);
    expect(await screen.findByRole('status')).toHaveTextContent('Syncing CISA KEV');
    // it ends: the banner is gone and the new count is in the table
    const table = await screen.findByRole('table', { name: 'Vulnerability feeds table' });
    expect(await within(table).findByText('1,781', {}, { timeout: 8000 })).toBeInTheDocument();
    expect(screen.queryByRole('status')).toBeNull();
  }, 20000);

  it('says why a sync could not start, and does not pretend it did', async () => {
    withFeeds(() => [feed({})], 409);
    renderApp('/integrations');
    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    await userEvent.click(await screen.findByRole('button', { name: /Sync Now/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent('already running');
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('keeps the whole error of a failed feed, and says when the address answers but the sync failed', async () => {
    withFeeds(() => [feed({ name: 'nvd', display_name: 'NVD', status: 'error', error: 'GET https://services.nvd.nist.gov: 429 Too Many Requests', records: 0 })]);
    renderApp('/integrations');
    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    const table = await screen.findByRole('table', { name: 'Vulnerability feeds table' });
    expect(within(table).getByText(/429 Too Many Requests/)).toBeInTheDocument(); // not cut at 30 characters
    await userEvent.click(within(table).getByRole('button', { name: 'Test' }));
    expect(await within(table).findByText(/The address answers \(HTTP 200\); the failure is in the sync itself/)).toBeInTheDocument();
  });

  it('shows the CRD of what the server really has, not the public defaults, so an air gap is not undone by copying it', async () => {
    withFeeds(() => [feed({})]);
    renderApp('/integrations');
    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    await userEvent.click(await screen.findByRole('button', { name: /Declarative CRD Spec/i }));
    const dialog = await screen.findByRole('dialog');
    const yaml = within(dialog).getByText(/kind: ClusterFeed/).textContent ?? '';
    expect(yaml).toContain('egress: allow');
    // no mirror is set, so no source is listed: a listed optional source is switched on, and under egress: deny a feed
    // with a url is still read
    expect(yaml).not.toMatch(/cisa\.gov|cyentia|nvd\.nist|googleapis|vulnrichment|exploitdb/);
  });

  it('offers neither Sync nor a failing click to someone who is not an administrator', async () => {
    withFeeds(() => [feed({})]);
    // the mock above is an admin; read the page as a triager
    mockFetch({ loggedIn: true, role: 'triager' });
    const inner = globalThis.fetch;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : input.url;
      if (path === '/api/v1/feeds') return Promise.resolve(new Response(JSON.stringify({ mirror: null, items: [feed({})] }), { status: 200, headers: { 'content-type': 'application/json' } }));
      return inner(input, init);
    });
    renderApp('/integrations');
    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    const table = await screen.findByRole('table', { name: 'Vulnerability feeds table' });
    expect(screen.queryByRole('button', { name: /Sync Now/i })).toBeNull();
    expect(within(table).queryByRole('button', { name: 'Sync' })).toBeNull();
    expect(within(table).getByRole('button', { name: 'Test' })).toBeInTheDocument(); // testing is read-only
  });

  it('does not offer Test or Sync for a feed that is switched off, and does not call it unreachable', async () => {
    withFeeds(() => [feed({ name: 'nvd', display_name: 'NVD', enabled: false, status: 'disabled', records: 0 })]);
    renderApp('/integrations');
    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    const table = await screen.findByRole('table', { name: 'Vulnerability feeds table' });
    expect(within(table).getByRole('button', { name: 'Test' })).toBeDisabled();
    expect(within(table).getByRole('button', { name: 'Sync' })).toBeDisabled();
  });

  it('does not call a feed list healthy when nothing has synced', async () => {
    withFeeds(() => [feed({ status: 'idle', records: 0, last_sync: null })]);
    renderApp('/integrations');
    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));
    await screen.findByRole('table', { name: 'Vulnerability feeds table' });
    expect(screen.queryByText('Healthy')).toBeNull();
    expect(screen.getByText('Not synced yet', { selector: 'span.text-18' })).toBeInTheDocument();
  });
});
