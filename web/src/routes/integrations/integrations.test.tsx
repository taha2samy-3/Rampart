import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('integrations route and connector catalogue', () => {
  it('renders connectors list and verifies accessibility', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');

    expect(await screen.findByRole('heading', { name: /Integrations/i })).toBeInTheDocument();
    expect(await screen.findByRole('table', { name: 'Connectors table' })).toBeInTheDocument();
    expect(screen.getByText('jira-cloud')).toBeInTheDocument();
    expect(screen.getByText('github-issues')).toBeInTheDocument();
    expect(screen.getByText('dtrack-portfolio')).toBeInTheDocument();

    expect(await axe(container)).toHaveNoViolations();
  });

  it('switches to API tokens tab and generates a new token', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    renderApp('/integrations');

    const tokensTab = await screen.findByRole('tab', { name: 'API Tokens' });
    await userEvent.click(tokensTab);

    expect(await screen.findByRole('table', { name: 'API Tokens' })).toBeInTheDocument();
    expect(screen.getByText('ci-github-actions')).toBeInTheDocument();

    // Open Generate Token Dialog
    await userEvent.click(screen.getByRole('button', { name: '+ Generate Token' }));
    const dialog = await screen.findByRole('dialog', { name: 'Generate API Token' });
    expect(dialog).toBeInTheDocument();

    const descInput = within(dialog).getByLabelText('Token Description');
    await userEvent.type(descInput, 'k8s-operator-sync');

    await userEvent.click(within(dialog).getByRole('button', { name: 'Generate' }));

    // Shows generated secret
    expect(await within(dialog).findByText(/rampart_sec_/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));

    // Token appears in table
    expect(await screen.findByText('k8s-operator-sync')).toBeInTheDocument();
  });

  it('opens connector catalogue, selects Jira, tests connection, views YAML, and saves connector', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { container } = renderApp('/integrations');

    await screen.findByRole('heading', { name: /Integrations/i });
    const newBtn = screen.getByRole('button', { name: '+ New Connector' });
    await userEvent.click(newBtn);

    // Catalogue modal opens
    const catalogueDialog = await screen.findByRole('dialog', { name: 'Integration Catalogue' });
    expect(catalogueDialog).toBeInTheDocument();
    expect(within(catalogueDialog).getByText('Jira Cloud')).toBeInTheDocument();
    expect(within(catalogueDialog).getByText('GitHub Issues')).toBeInTheDocument();
    expect(within(catalogueDialog).getByText('Dependency-Track')).toBeInTheDocument();
    expect(within(catalogueDialog).getByText('Slack')).toBeInTheDocument();
    expect(within(catalogueDialog).getByText('Microsoft Teams')).toBeInTheDocument();
    expect(within(catalogueDialog).getByText('Generic Webhook')).toBeInTheDocument();
    expect(within(catalogueDialog).getByText('Email (SMTP)')).toBeInTheDocument();

    expect(await axe(container)).toHaveNoViolations();

    // Select Jira
    await userEvent.click(within(catalogueDialog).getByText('Jira Cloud'));

    // Config form shows
    expect(await screen.findByRole('dialog', { name: 'Configure Jira Cloud' })).toBeInTheDocument();
    const nameInput = screen.getByLabelText(/Connector Name/);
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'jira-corp');

    const urlInput = screen.getByLabelText(/Service \/ Webhook URL/);
    await userEvent.clear(urlInput);
    await userEvent.type(urlInput, 'https://jira.corp.internal');

    // Test connection
    const testBtn = screen.getByRole('button', { name: 'Test Connection' });
    await userEvent.click(testBtn);
    expect(await screen.findByText(/Connection verified/i)).toBeInTheDocument();

    // Toggle YAML preview
    const yamlBtn = screen.getByRole('button', { name: 'View YAML' });
    await userEvent.click(yamlBtn);
    expect(screen.getByText(/apiVersion: rampart.aspm.dev\/v1alpha1/)).toBeInTheDocument();

    // Save connector
    const saveBtn = screen.getByRole('button', { name: 'Save Connector' });
    await userEvent.click(saveBtn);

    // Modal closes and table shows new connector
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(await screen.findByText('jira-corp')).toBeInTheDocument();
  });
});
