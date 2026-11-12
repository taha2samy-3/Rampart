import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { app, finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const bn = (id: string, subject: string, role: string, appName: string) => ({ id, subject, role, application_id: 'app-1', application_name: appName, managed_by: 'api', created_by: 'user:boss@acme.example', created_at: '2026-11-01T00:00:00Z' });

describe('access: a role on one application', () => {
  const two = () => {
    const f1 = finding(1);
    f1.finding.application_id = 'app-1';
    const f2 = finding(2);
    f2.finding.application_id = 'app-2';
    return [f1, f2];
  };

  it('a tenant viewer who is a triager on one application is offered a decision there', async () => {
    mockFetch({ loggedIn: true, role: 'viewer', access: { 'app-1': 'triager' }, findings: two() });
    renderApp('/findings?sel=f-1');
    const insp = await screen.findByRole('complementary', { name: 'Finding details' });
    expect(await within(insp).findByRole('button', { name: 'Change state' })).toBeInTheDocument();
  });

  it('and is not offered it on another application', async () => {
    mockFetch({ loggedIn: true, role: 'viewer', access: { 'app-1': 'triager' }, findings: two() });
    renderApp('/findings?sel=f-2');
    const insp = await screen.findByRole('complementary', { name: 'Finding details' });
    await within(insp).findByRole('heading', { name: 'Finding 2' });
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Change state' })).toBeNull());
  });

  it('an owner lists, adds and removes access, and is offered only the applications they own', async () => {
    const calls = mockFetch({
      loggedIn: true, role: 'viewer', access: { 'app-1': 'owner' }, apps: [app(1), app(2)],
      bindings: [bn('bn1', 'omar@acme.example', 'triager', 'Application 1')],
    });
    renderApp('/administration');
    const table = await screen.findByRole('table', { name: 'Access bindings' });
    expect(within(table).getByText('omar@acme.example')).toBeInTheDocument();
    expect(await axe(table)).toHaveNoViolations();

    const appSelect = screen.getByRole('combobox', { name: 'Application' });
    expect(within(appSelect).getAllByRole('option').map((o) => o.textContent)).toEqual(['Choose an application', 'Application 1']);
    expect(screen.getByRole('button', { name: 'Give access' })).toBeDisabled();
    await userEvent.type(screen.getByLabelText('E-mail or token subject'), 'bob@acme.example');
    await userEvent.selectOptions(appSelect, 'app-1');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Role' }), 'maintainer');
    await userEvent.click(screen.getByRole('button', { name: 'Give access' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.url === '/api/v1/access-bindings')).toBe(true));
    const post = calls.find((c) => c.method === 'POST' && c.url === '/api/v1/access-bindings')!;
    expect(JSON.parse(post.body!)).toEqual({ subject: 'bob@acme.example', role: 'maintainer', applicationId: 'app-1' });

    await userEvent.click(within(table).getByRole('button', { name: 'Remove triager access of omar@acme.example on Application 1' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE' && c.url === '/api/v1/access-bindings/bn1')).toBe(true));
  });

  it('is not offered to someone who owns nothing', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'triager', access: { 'app-1': 'maintainer' } });
    renderApp('/administration');
    await screen.findByText('Only administrators can read the audit log.');
    expect(screen.queryByRole('heading', { name: 'Access' })).toBeNull();
    expect(calls.some((c) => c.url.startsWith('/api/v1/access-bindings'))).toBe(false);
  });
});
