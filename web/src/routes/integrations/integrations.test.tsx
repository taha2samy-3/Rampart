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
    expect(within(table).getByText('Not checked yet')).toBeInTheDocument();
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
});
