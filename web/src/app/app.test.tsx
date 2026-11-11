import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { finding, mockFetch, renderApp } from '@/test/helpers';

vi.mock('@/lib/nav', () => ({ navigateTo: vi.fn() }));
import { navigateTo } from '@/lib/nav';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('bootstrap sequence', () => {
  it('calls ui-config, then session, then permissions, in that order', async () => {
    const calls = mockFetch({ loggedIn: true, findings: [] });
    renderApp('/findings');
    await screen.findByText('No findings yet');
    const order = calls.map((c) => c.url.split('?')[0]).filter((u) => ['/api/v1/ui-config', '/auth/session', '/api/v1/me/permissions'].includes(u!));
    expect(order).toEqual(['/api/v1/ui-config', '/auth/session', '/api/v1/me/permissions']);
  });

  it('401 on the session shows the login screen and remembers where you were', async () => {
    mockFetch({ loggedIn: false });
    const { history, container } = renderApp('/findings?q=risk:high');
    expect(await screen.findByRole('heading', { name: 'Sign in to Rampart' })).toBeInTheDocument();
    expect(history.location.pathname).toBe('/login');
    expect(history.location.search).toContain('return_to=');
    expect(await axe(container)).toHaveNoViolations();
  });

  it('a single identity provider skips the chooser and navigates to /auth/login', async () => {
    mockFetch({ loggedIn: false });
    renderApp('/login?return_to=%2Ffindings%3Fq%3Drisk%3Ahigh');
    await userEvent.click(await screen.findByRole('button', { name: 'Continue with Default SSO' }));
    expect(navigateTo).toHaveBeenCalledWith('/auth/login?return_to=%2Ffindings%3Fq%3Drisk%3Ahigh');
    expect(screen.queryByRole('radio')).toBeNull();
  });

  it('an unsafe return_to is replaced, and the tenant field appears on /t/<tenant>/login', async () => {
    mockFetch({ loggedIn: false });
    renderApp('/t/acme/login?return_to=https%3A%2F%2Fevil.example');
    const tenant = await screen.findByLabelText('Tenant');
    expect(tenant).toHaveValue('acme');
    await userEvent.click(screen.getByRole('button', { name: 'Continue with Default SSO' }));
    expect(navigateTo).toHaveBeenCalledWith('/auth/login?tenant=acme&return_to=%2Ffindings');
  });

  it('maps backend error codes to plain copy and never shows the code', async () => {
    mockFetch({ loggedIn: false });
    const { container } = renderApp('/login?error=no_access&request_id=req_9');
    expect(await screen.findByText(/no access to this tenant/)).toBeInTheDocument();
    expect(screen.queryByText('no_access')).toBeNull();
    expect(screen.getByText('req_9')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe('findings route', () => {
  it('empty workbench: shell, three panes and the upload command', async () => {
    mockFetch({ loggedIn: true, findings: [] });
    const { container } = renderApp('/findings');
    expect(await screen.findByText('No findings yet')).toBeInTheDocument();
    expect(screen.getByText('rampart upload --source default semgrep.sarif')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'Finding details' })).toHaveTextContent('Select a finding');
    expect(screen.getByRole('textbox', { name: 'Filter findings' })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('populated: rows with band, score, title, application, state, first seen; selecting fills the inspector', async () => {
    mockFetch({ loggedIn: true, findings: [finding(1, 'critical'), finding(2, 'high'), finding(3, 'low')] });
    const { container } = renderApp('/findings');
    const grid = await screen.findByRole('grid', { name: 'Findings' });
    await screen.findByText('Finding 1');
    const rows = within(grid).getAllByRole('row').filter((r) => r.hasAttribute('data-row-id'));
    expect(rows).toHaveLength(3);
    expect(within(rows[0]!).getByText('Finding 1')).toBeInTheDocument();
    expect(within(rows[0]!).getByText('700')).toBeInTheDocument();
    expect(within(rows[0]!).getByRole('img', { name: /^Score 700 of 1000/ })).toBeInTheDocument();
    expect(screen.getByText('3 findings')).toBeInTheDocument();
    await userEvent.click(rows[1]!);
    const insp = screen.getByRole('complementary', { name: 'Finding details' });
    await waitFor(() => expect(within(insp).getByRole('heading', { name: 'Finding 2' })).toBeInTheDocument());
    expect(within(insp).getByText('Why this score')).toBeInTheDocument();
    expect(within(insp).getAllByText('Known exploited').length).toBeGreaterThan(0);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('keyboard: j and k move the selection', async () => {
    mockFetch({ loggedIn: true, findings: [finding(1), finding(2), finding(3)] });
    const { history } = renderApp('/findings');
    await screen.findByText('Finding 1');
    const first = screen.getAllByRole('row').find((r) => r.hasAttribute('data-row-id'))!;
    first.focus();
    await userEvent.keyboard('j');
    await waitFor(() => expect(history.location.search).toContain('sel=f-1'));
    await userEvent.keyboard('j');
    await waitFor(() => expect(history.location.search).toContain('sel=f-2'));
    await userEvent.keyboard('k');
    await waitFor(() => expect(history.location.search).toContain('sel=f-1'));
  });

  it('typing in the query bar writes q into the URL and chips show the parsed terms', async () => {
    mockFetch({ loggedIn: true, findings: [finding(1)] });
    const { history } = renderApp('/findings');
    const input = await screen.findByRole('textbox', { name: 'Filter findings' });
    await userEvent.type(input, 'risk:high');
    await waitFor(() => expect(history.location.search).toContain('q=risk%3Ahigh'));
    expect(await screen.findByRole('button', { name: 'Remove filter risk:high' })).toBeInTheDocument();
  });

  it('a 500 shows the problem with its request id and a retry', async () => {
    mockFetch({ loggedIn: true, findings: 'error' });
    const { container } = renderApp('/findings');
    expect(await screen.findByText('Findings could not be loaded', undefined, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.getByText('req_1')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('other sections say which phase ships them', async () => {
    mockFetch({ loggedIn: true, findings: [] });
    renderApp('/compliance');
    expect(await screen.findByText(/ships in Phase 2/)).toBeInTheDocument();
  });

  it('mutating calls send X-CSRF-Token from the session', async () => {
    const calls = mockFetch({ loggedIn: true, findings: [] });
    renderApp('/findings');
    await screen.findByText('No findings yet');
    const { post } = await import('@/api');
    await post('/auth/tenant', { tenant: 'globex' });
    const last = calls[calls.length - 1]!;
    expect(last.method).toBe('POST');
    expect(last.headers['X-CSRF-Token']).toBe('csrf-1');
  });
});
