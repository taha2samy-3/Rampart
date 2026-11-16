import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { app, finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// The application column showed the first 8 characters of the application's UUID ("01a1e562"), which means
// nothing to the person reading the list.
describe('Findings table: application column', () => {
  it('names the application, and falls back to the short id only for one it cannot name', async () => {
    const known = finding(1);
    known.finding.application_id = 'app-shop-0000';
    const unknown = finding(2);
    unknown.finding.application_id = 'ffffffff-unknown';
    mockFetch({ loggedIn: true, findings: [known, unknown], apps: [app(1, { id: 'app-shop-0000', slug: 'shop', name: 'Shop' })] });
    renderApp('/findings');
    const rows = await screen.findAllByRole('row');
    const first = rows.find((r) => within(r).queryByText('Finding 1'))!;
    expect(await within(first).findByText('Shop')).toBeInTheDocument();
    expect(within(first).queryByText(/app-shop/)).toBeNull();
    const second = rows.find((r) => within(r).queryByText('Finding 2'))!;
    expect(within(second).getByText(/ffffffff/)).toBeInTheDocument();
  });
});
