import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('ticketing route and containerized trackers', () => {
  it('renders a standalone Ticketing link in the main sidebar navigation', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/ticketing');

    const nav = await screen.findByRole('navigation');
    expect(within(nav).getByRole('link', { name: 'Ticketing' })).toHaveAttribute('href', '/ticketing');
    expect(await screen.findByRole('heading', { level: 1, name: 'Ticketing' })).toBeInTheDocument();
  });

  it('lists tracker containers, runs a probe, and displays declared secrets cleanly', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/ticketing');

    const table = await screen.findByRole('table', { name: 'Tracker containers' });
    expect(within(table).getByText('jira-tracker')).toBeInTheDocument();
    expect(within(table).getByText('jira-tracker.tools.svc.cluster.local:50051')).toBeInTheDocument();
    expect(within(table).getByText('Ready')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    expect(await screen.findByText(/Serving: Jira Container/)).toBeInTheDocument();
    expect(screen.getByText(/token \(required\)/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST' && c.url.includes('/api/v1/trackers/test'))).toBe(true);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('lists tracker bindings and validates tracker connector resources in the Bindings & Policy tab', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/ticketing?tab=bindings');

    const table = await screen.findByRole('table', { name: 'Tracker bindings table' });
    expect(within(table).getByText('jira-container-binding')).toBeInTheDocument();
    expect(within(table).getByText('jira-sec')).toBeInTheDocument();
    expect(within(table).queryByText('slack-appsec')).toBeNull();

    await userEvent.click(screen.getByRole('button', { name: '+ New Tracker Binding' }));
    const catalogue = await screen.findByRole('dialog', { name: 'Integration Catalogue' });
    expect(within(catalogue).getByText('External tracker container')).toBeInTheDocument();
    expect(within(catalogue).queryByText('Slack')).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('shows opened tickets and pending outbox items in the Tickets & Outbox tab', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/ticketing?tab=queue');

    const outbox = await screen.findByRole('table', { name: 'Ticket outbox table' });
    expect(within(outbox).getByText('SQL Injection in /checkout')).toBeInTheDocument();
    expect(within(outbox).getByText('reserved')).toBeInTheDocument();

    const opened = await screen.findByRole('table', { name: 'Opened tickets table' });
    expect(within(opened).getByText('SEC-104')).toBeInTheDocument();
    expect(within(opened).getByText('jira-container-binding')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});
