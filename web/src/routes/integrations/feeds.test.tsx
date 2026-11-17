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

  it('triggers on-demand sync when clicking Sync Now button', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');

    await userEvent.click(await screen.findByRole('tab', { name: /Vulnerability Feeds/i }));

    const syncBtn = await screen.findByRole('button', { name: /Sync Now/i });
    await userEvent.click(syncBtn);

    expect(await screen.findByText(/Sync initiated/i)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});
