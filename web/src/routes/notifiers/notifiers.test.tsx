import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// docs/50: Notifiers holds the connectors the server calls notifiers (by their catalogue kind) and the notifier
// packages. Connectors are resources (D82): the catalogue writes and checks one, and never creates it.
describe('the Notifiers page', () => {
  it('is in the sidebar under its own name and icon, where Integrations was', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/notifiers');
    const nav = await screen.findByRole('navigation');
    expect(within(nav).getByRole('link', { name: 'Notifiers' })).toHaveAttribute('href', '/notifiers');
    expect(within(nav).queryByRole('link', { name: 'Integrations' })).toBeNull();
    expect(await screen.findByRole('heading', { level: 1, name: 'Notifiers' })).toBeInTheDocument();
  });

  it('lists only the connectors whose kind is notifier, with the operator status in words', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/notifiers');
    const table = await screen.findByRole('table', { name: 'Notifier connectors' });
    expect(within(table).getByText('slack-appsec')).toBeInTheDocument();
    expect(within(table).getByText('Package google-chat')).toBeInTheDocument();
    // Trackers are on Ticketing, whatever their type is called.
    expect(within(table).queryByText('jira-sec')).toBeNull();
    expect(within(table).queryByText('jira-container-binding')).toBeNull();
    // Not checked by the operator yet: said so, never invented as Connected.
    expect(within(table).getAllByText('Not checked yet')).toHaveLength(2);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('files a connector by the kind the server sends, not by its type name', async () => {
    mockFetch({
      loggedIn: true, role: 'admin',
      connectors: [
        { name: 'pager', type: 'someNewNotifier', kind: 'notifier', direction: 'outbound', enabled: true, managed_by: 'resource', status: { conditions: [{ type: 'Connected', status: 'False', message: 'refused: 401' }] } },
        { name: 'boards', type: 'someNewTracker', kind: 'tracker', direction: 'outbound', enabled: true, managed_by: 'resource', status: { conditions: [] } },
      ],
    });
    renderApp('/notifiers');
    const table = await screen.findByRole('table', { name: 'Notifier connectors' });
    expect(within(table).getByText('pager')).toBeInTheDocument();
    expect(within(table).getByText('Failing')).toBeInTheDocument();
    expect(within(table).queryByText('boards')).toBeNull();
  });

  it('lists the notifier packages, and why one is not used; parser packages are not here', async () => {
    mockFetch({
      loggedIn: true, role: 'admin',
      packages: [
        { name: 'google-chat', kind: 'notifier', runtime: 'declarative', version: '1.0.0', egress: ['chat.googleapis.com'], secrets: ['webhookUrl'], config: [], used_by: ['chat-sec'], updated_at: '2026-11-16T10:00:00Z' },
        { name: 'pager-duty', kind: 'notifier', runtime: 'declarative', version: '0.1.0', egress: [], secrets: [], config: [], used_by: [], error: 'send.expect: does not compile', updated_at: '2026-11-16T10:00:00Z' },
        { name: 'pip-audit', kind: 'parser', runtime: 'mapping', version: '1.0.0', egress: [], secrets: [], config: [], used_by: [], updated_at: '2026-11-16T10:00:00Z' },
      ],
    });
    const { container } = renderApp('/notifiers');
    const pkgs = await screen.findByRole('table', { name: 'Notifier packages' });
    expect(within(pkgs).getByText('chat.googleapis.com')).toBeInTheDocument();
    expect(within(pkgs).getByText('chat-sec')).toBeInTheDocument();
    expect(within(pkgs).getByText('Not used: send.expect: does not compile')).toBeInTheDocument();
    expect(within(pkgs).queryByText('pip-audit')).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('says what to do when there is no notifier and no package', async () => {
    mockFetch({ loggedIn: true, role: 'admin', connectors: [], packages: [] });
    const { container } = renderApp('/notifiers');
    expect(await screen.findByText('No notifier connector')).toBeInTheDocument();
    expect(await screen.findByText(/No notifier package is installed/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('shows the problem, with Try again, when the connectors or packages cannot be loaded', async () => {
    mockFetch({ loggedIn: true, role: 'admin', connectors: 'error', packages: 'error' });
    const { container } = renderApp('/notifiers');
    expect(await screen.findByText('The connectors could not be loaded')).toBeInTheDocument();
    expect(await screen.findByText('The packages could not be loaded')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Try again' })).toHaveLength(2);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('opens the catalogue on notifier types only, and validates against the server without saving', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/notifiers');
    await userEvent.click(await screen.findByRole('button', { name: 'Add a notifier' }));
    const catalogue = await screen.findByRole('dialog', { name: 'Connector catalogue' });
    expect(within(catalogue).queryByText('Jira Cloud')).toBeNull();
    expect(within(catalogue).queryByText('External tracker container')).toBeNull();
    await userEvent.click(await within(catalogue).findByText('Slack'));

    const dialog = await screen.findByRole('dialog', { name: 'Configure Slack' });
    expect(within(dialog).queryByLabelText(/token|password|secret/i)).toBeNull();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Validate' }));
    expect(await within(dialog).findByText(/Not accepted \(InvalidSpec\)|The server accepts this resource/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/api/v1/connectors'))).toBe(false);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('a package whose lists are null does not break the page', async () => {
    mockFetch({ loggedIn: true, role: 'admin', packages: [{ name: 'old-chat', kind: 'notifier', runtime: 'declarative', version: '1', egress: null, secrets: null, config: null, used_by: null, updated_at: '2026-11-16T10:00:00Z' }] });
    renderApp('/notifiers');
    const pkgs = await screen.findByRole('table', { name: 'Notifier packages' });
    expect(within(pkgs).getByText('old-chat')).toBeInTheDocument();
    expect(within(pkgs).getByText('Nothing')).toBeInTheDocument();
    expect(within(pkgs).getByText('No connector')).toBeInTheDocument();
  });
});
