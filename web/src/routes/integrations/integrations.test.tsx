import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// D82: connectors are Kubernetes resources. The page lists what the server has, with the status the operator
// wrote; the catalogue helps write a resource and checks it against the server, and never creates one.
describe('integrations route and connector catalogue', () => {
  it('lists the server connectors with the operator status, and no invented rows', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');

    const table = await screen.findByRole('table', { name: 'Connectors table' });
    expect(within(table).getByText('jira-sec')).toBeInTheDocument();
    expect(within(table).getByText('Connected')).toBeInTheDocument();
    // A connector the operator has not checked yet is not shown as connected or as failing.
    expect(within(table).getAllByText('Not checked yet').length).toBe(2);
    expect(within(table).queryByRole('button', { name: 'Check' })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('validates a resource against the server and never saves or asks for a secret', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');

    await userEvent.click(await screen.findByRole('button', { name: '+ New Connector' }));
    const catalogue = await screen.findByRole('dialog', { name: 'Integration Catalogue' });
    await userEvent.click(await within(catalogue).findByText('Jira Cloud'));

    const dialog = await screen.findByRole('dialog', { name: 'Configure Jira Cloud' });
    const yaml = within(dialog).getByLabelText('Connector resource (YAML)');
    expect((yaml as HTMLTextAreaElement).value).toContain('kind: Connector');
    expect(within(dialog).queryByLabelText(/token|password|secret/i)).toBeNull();
    expect(within(dialog).queryByRole('button', { name: /save/i })).toBeNull();

    // The example as given lacks defaultProject in this fixture: the server says so.
    await userEvent.click(within(dialog).getByRole('button', { name: 'Validate' }));
    expect(await within(dialog).findByText(/Not accepted \(InvalidSpec\).*defaultProject/)).toBeInTheDocument();

    await userEvent.type(yaml, '  jira: {{defaultProject: SEC}');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Validate' }));
    expect(await within(dialog).findByText(/The server accepts this resource/)).toBeInTheDocument();

    const validations = calls.filter((c) => c.url.includes('/api/v1/connectors/validate'));
    expect(validations).toHaveLength(2);
    expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/api/v1/connectors'))).toBe(false);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('says how tokens are issued instead of inventing one', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/integrations');
    await userEvent.click(await screen.findByRole('tab', { name: 'API Tokens' }));
    expect(await screen.findByText(/not listed or issued from this page yet/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Generate/ })).toBeNull();
  });

  // D94: a tool installed as data shows what it may reach, what uses it, and why it is not used when it is refused.
  it('lists installed packages and the plugin connector that uses one', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');
    const connectors = await screen.findByRole('table', { name: 'Connectors table' });
    expect(within(connectors).getByText('Package google-chat')).toBeInTheDocument();
    const pkgs = await screen.findByRole('table', { name: 'Installed packages' });
    expect(within(pkgs).getByText('chat.googleapis.com')).toBeInTheDocument();
    expect(within(pkgs).getByText('chat-sec')).toBeInTheDocument();
    expect(within(pkgs).getByText(/Not used: runtime "wasm"/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  // "This screen failed to render: Cannot read properties of null (reading 'join')": a parser package has no egress
  // and no secrets, and the server wrote them as null. A page must not die on a list that is null.
  it('renders a package whose lists are null instead of failing the whole screen', async () => {
    mockFetch({ loggedIn: true, role: 'admin', packagesNull: true });
    renderApp('/integrations');
    const table = await screen.findByRole('table', { name: 'Installed packages' });
    expect(within(table).getByText('pip-audit')).toBeInTheDocument();
    expect(within(table).getByText('nothing')).toBeInTheDocument(); // reaches nothing
    expect(within(table).getByText('uploads named pip-audit, or detected')).toBeInTheDocument();
    expect(screen.queryByText('This screen failed to render')).toBeNull();
  });
});
