import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import type { SourceStatus } from '@/api/types';
import { app, mockFetch, renderApp } from '@/test/helpers';
import { sourceSentence } from './DependencyTrackView';

afterEach(() => vi.unstubAllGlobals());

const src = (over: Partial<SourceStatus> = {}): SourceStatus => ({
  id: 's-1', name: 'dtrack-portfolio', connector: 'dtrack', schedule_seconds: 1800, webhook_enabled: false,
  trust_upstream_decisions: false, projects: 12, unmapped: 1, pending_decisions: 1, ...over,
});

// D92: the page shows what the server recorded, never a status it assumed.
describe('Dependency-Track sources', () => {
  it('says how to add a source when there is none', async () => {
    mockFetch({ loggedIn: true, role: 'maintainer', dtSources: [] });
    renderApp('/ingestion');
    await userEvent.click(await screen.findByRole('tab', { name: 'Dependency-Track' }));
    expect(await screen.findByText('No Dependency-Track source yet')).toBeInTheDocument();
    expect(screen.getByText(/connector: dtrack/)).toBeInTheDocument();
  });

  it('shows the source, maps a project and lists decisions waiting for a person', async () => {
    const calls = mockFetch({
      loggedIn: true, role: 'maintainer', apps: [app(1)],
      dtSources: [src({ last_portfolio_sync_at: new Date(Date.now() - 12 * 60_000).toISOString() })],
      dtUnmapped: { 's-1': [{ tenant_id: 't', source_id: 's-1', project_uuid: 'p-9', name: 'payments-worker', version: '1.4.0', active: true, unmapped_reason: 'no matching rule', created_at: '', updated_at: '' }] },
      dtDecisions: { 's-1': [{ finding_id: 'f-12345678', source_id: 's-1', state: 'not_affected', justification: 'code_not_reachable', applied: false, seen_at: new Date().toISOString() }] },
    });
    const { container } = renderApp('/ingestion');
    await userEvent.click(await screen.findByRole('tab', { name: 'Dependency-Track' }));
    expect(await screen.findByText(/Portfolio synced 12 min ago, every 30 min/)).toBeInTheDocument();
    expect(screen.getByText(/Decisions made in Dependency-Track wait for a person here/)).toBeInTheDocument();

    const table = await screen.findByRole('table', { name: 'Projects without an application' });
    expect(within(table).getByText('payments-worker')).toBeInTheDocument();
    expect(await screen.findByText(/not affected/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await userEvent.click(within(table).getByRole('button', { name: 'Map to application' }));
    const dialog = await screen.findByRole('dialog', { name: 'Map payments-worker' });
    await userEvent.selectOptions(await within(dialog).findByLabelText('Application'), 'app-1');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Map project' }));
    await waitFor(() => {
      const c = calls.find((x) => x.method === 'POST' && x.url === '/api/v1/sources/s-1/map');
      expect(c && JSON.parse(c.body!)).toMatchObject({ project_uuid: 'p-9', application_id: 'app-1' });
    });
  });

  it('puts a failed sync first, in words', () => {
    expect(sourceSentence(src({ last_portfolio_error: 'connector "dtrack" is not a dependencyTrack connector' }))).toMatch(/^The last portfolio sync failed/);
    expect(sourceSentence(src())).toMatch(/^Not synced yet/);
  });
});
