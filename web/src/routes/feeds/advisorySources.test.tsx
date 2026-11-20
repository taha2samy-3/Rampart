import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('Advisory Sources in FeedsRoute', () => {
  it('renders Threat Feeds and Advisory Sources tabs', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/feeds');

    const feedsTab = await screen.findByRole('tab', { name: /Threat Feeds/i });
    const advisoriesTab = screen.getByRole('tab', { name: /Advisory Sources/i });

    expect(feedsTab).toBeInTheDocument();
    expect(advisoriesTab).toBeInTheDocument();
  });

  it('switches to Advisory Sources and inspects OSV and NVD sources', async () => {
    const user = userEvent.setup();
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/feeds');

    const advisoriesTab = await screen.findByRole('tab', { name: /Advisory Sources/i });
    await user.click(advisoriesTab);

    // Should see advisory table
    const table = await screen.findByRole('table', { name: 'Advisory Sources' });
    expect(within(table).getByText('OSV.dev & GitHub Advisories')).toBeInTheDocument();
    expect(within(table).getByText('NIST NVD API 2.0')).toBeInTheDocument();
    expect(within(table).getByText('Sonatype OSS Index')).toBeInTheDocument();

    // Inspector should show rate limits and provider info
    expect(screen.getByText(/Rate Limits & Quota Protections/)).toBeInTheDocument();
    expect(screen.getByText(/Open GCS bulk archives/)).toBeInTheDocument();

    // Click on NIST NVD
    const nvdRow = within(table).getByText('NIST NVD API 2.0');
    await user.click(nvdRow);

    expect(screen.getByText(/Without token: 5 req \/ 30s\. With token: 50 req \/ 30s\./)).toBeInTheDocument();
    expect(screen.getAllByText(/\/etc\/rampart\/feed-secrets\/nvd-api-key/).length).toBeGreaterThan(0);
  });
});
