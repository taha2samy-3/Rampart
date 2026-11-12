import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const entry = (n: number, over: Record<string, unknown> = {}) => ({
  id: `a${n}`, at: new Date(Date.now() - n * 3600000).toISOString(), actor: 'user:sara@acme.example', action: 'PATCH /api/v1/findings/{id}',
  resource_type: 'findings', resource_id: `f-${n}`, detail: { method: 'PATCH', status: 200 }, ...over,
});

describe('administration: the audit log', () => {
  it('an administrator reads who did what, with the answer, and can page back and download', async () => {
    const calls = mockFetch({
      loggedIn: true, role: 'admin',
      audit: [{ items: [entry(1), entry(2, { detail: { status: 403 }, actor: 'user:omar@acme.example' })], next_cursor: 'c1' }, { items: [entry(3)] }],
    });
    renderApp('/administration');
    const table = await screen.findByRole('table', { name: 'Audit log' });
    expect(within(table).getAllByRole('row')).toHaveLength(3); // header + 2
    expect(within(table).getAllByText('PATCH findings/{id}')).toHaveLength(2);
    expect(within(table).getByText('omar@acme.example')).toBeInTheDocument();
    expect(within(table).getByText('403')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Download CSV' })).toHaveAttribute('href', '/api/v1/audit?format=csv');
    expect(await axe(table)).toHaveNoViolations();

    await userEvent.click(screen.getByRole('button', { name: 'Load older entries' }));
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'Audit log' })).getAllByRole('row')).toHaveLength(4));
    expect(screen.queryByRole('button', { name: 'Load older entries' })).toBeNull();
    expect(calls.some((c) => c.url.includes('cursor=c1'))).toBe(true);
  });

  it('filters by who and carries the filter into the download link', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin', audit: [{ items: [entry(1)] }] });
    renderApp('/administration');
    await screen.findByRole('table', { name: 'Audit log' });
    await userEvent.type(screen.getByLabelText('Filter by who'), 'user:sara@acme.example');
    await userEvent.click(screen.getByRole('button', { name: 'Filter' }));
    await waitFor(() => expect(calls.some((c) => c.url.includes('actor=user%3Asara%40acme.example'))).toBe(true));
    expect(screen.getByRole('link', { name: 'Download NDJSON' }).getAttribute('href')).toContain('actor=user%3Asara%40acme.example');
  });

  it('does not ask a non-administrator for the log', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'triager' });
    renderApp('/administration');
    expect(await screen.findByText('Only administrators can read the audit log.')).toBeInTheDocument();
    expect(calls.some((c) => c.url.startsWith('/api/v1/audit'))).toBe(false);
  });

  it('says so when nothing matches, and shows the problem when the log cannot be read', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const first = renderApp('/administration');
    expect(await screen.findByText('Nothing has been recorded that matches.')).toBeInTheDocument();
    first.unmount();
    mockFetch({ loggedIn: true, role: 'admin', audit: 'error' });
    renderApp('/administration');
    expect(await screen.findByText('The audit log could not be loaded.')).toBeInTheDocument();
  });
});
