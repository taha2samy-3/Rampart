import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const items = [
  { id: 'n1', kind: 'sla_breached', title: '3 findings passed their deadline', link: '/findings?q=sla%3Abreached', created_at: new Date().toISOString(), unread: true },
  { id: 'n2', kind: 'acceptance_expiring', title: 'A risk acceptance ends in 14 days', body: 'Behind the VPN.', link: '/workflow', created_at: new Date(Date.now() - 3 * 86400000).toISOString(), unread: false },
];

describe('notifications', () => {
  it('says how many are unread in the label, lists them, and marks them read when the list closes', async () => {
    const calls = mockFetch({ loggedIn: true, findings: [finding(1)], notifications: { items, unread: 1 } });
    renderApp('/findings');
    const bell = await screen.findByRole('button', { name: 'Notifications, 1 unread' });
    await userEvent.click(bell);
    const menu = await screen.findByRole('menu');
    expect(within(menu).getByText('3 findings passed their deadline')).toBeInTheDocument();
    expect(within(menu).getByText('Behind the VPN.')).toBeInTheDocument();
    expect(await axe(menu)).toHaveNoViolations();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.url === '/api/v1/notifications/read')).toBe(true));
  });

  it('does not mark anything read when there was nothing unread, and says so plainly when empty', async () => {
    const calls = mockFetch({ loggedIn: true, findings: [finding(1)] });
    renderApp('/findings');
    await userEvent.click(await screen.findByRole('button', { name: 'Notifications' }));
    expect(await screen.findByText('Nothing to tell you.')).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(calls.some((c) => c.url === '/api/v1/notifications/read')).toBe(false);
  });

  it('opens the finding list a message points at', async () => {
    const calls = mockFetch({ loggedIn: true, findings: [finding(1)], notifications: { items, unread: 1 } });
    renderApp('/findings');
    await userEvent.click(await screen.findByRole('button', { name: 'Notifications, 1 unread' }));
    await userEvent.click(await screen.findByText('3 findings passed their deadline'));
    await waitFor(() => expect(calls.some((c) => c.url.includes('/api/v1/findings') && c.url.includes('sla'))).toBe(true));
  });
});
