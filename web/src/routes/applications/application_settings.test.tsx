import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { appPage, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const context = (over: Record<string, unknown> = {}) => ({
  business_criticality: 'high', internet_facing: false, data_classification: [], compensating_controls: [], lifecycle: 'production',
  type: 'repo', repository: 'github.com/acme/shop', branch: 'main', environment: '', managed_by: 'none', ...over,
});

/** The server of the page: the application, what the score knows, and the change a person saves. Returns the changes it was sent. */
function serve(ctx: Record<string, unknown>, environments = ['production', 'staging', 'test', 'development']) {
  mockFetch({ loggedIn: true, role: 'admin', appPages: { 'app-1': appPage(1, { context: ctx }) } });
  const inner = globalThis.fetch;
  const patches: unknown[] = [];
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const path = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : input.url;
    const reply = (body: unknown, status = 200) => Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
    if (path === '/api/v1/scoring') {
      return reply({
        product: 'Rampart', version: 'test', customised: false,
        risk: { base: {}, bands: {}, factors: [{ name: 'PRODUCTION_ENV', when: 'x', points: 60, group: 'context' }] },
        sla: { matrix: {}, kevDueDate: true, maxDays: 365, startFrom: 'firstSeen', restartOnReactivation: true, pauseDuringRiskAcceptance: true },
        environments, application_types: ['repo'],
      });
    }
    if (path === '/api/v1/applications/app-1' && (init?.method ?? 'GET') === 'PATCH') {
      patches.push(JSON.parse(String(init?.body)));
      return reply({});
    }
    return inner(input, init);
  });
  return patches;
}

describe('the settings of an application: what it is and where it runs (D140)', () => {
  it('says what the application is, and lets a maintainer say where it runs', async () => {
    const patches = serve(context());
    renderApp('/applications/app-1?tab=settings');
    expect(await screen.findByText(/Branch main of github.com\/acme\/shop/)).toBeInTheDocument();

    const env = screen.getByRole('combobox', { name: 'Environment' });
    expect(env).toHaveValue('none'); // nobody said: not described yet
    expect(screen.getByRole('option', { name: 'Not described yet' })).toBeInTheDocument();
    expect(await screen.findByText(/\+60/)).toBeInTheDocument(); // what production is worth, from the policy in force

    await userEvent.selectOptions(env, 'production');
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(patches).toEqual([{ environment: 'production' }])); // only what changed
  });

  it('sends the empty string when the environment is taken back to not described', async () => {
    const patches = serve(context({ environment: 'staging' }));
    renderApp('/applications/app-1?tab=settings');
    const env = await screen.findByRole('combobox', { name: 'Environment' });
    expect(env).toHaveValue('staging');
    await userEvent.selectOptions(env, 'none');
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(patches).toEqual([{ environment: '' }]));
  });

  it('builds its choices from what the server accepts, so a value the server does not know is not offered', async () => {
    serve(context(), ['production', 'staging']);
    renderApp('/applications/app-1?tab=settings');
    const env = await screen.findByRole('combobox', { name: 'Environment' });
    // until the server has answered, the form offers the values the program knows; then it offers exactly what the server says
    await waitFor(() => expect(within(env).getAllByRole('option').map((o) => o.textContent)).toEqual(['Not described yet', 'Production', 'Staging']));
  });

  it('shows an application that a resource manages, and does not let it be changed here', async () => {
    const patches = serve(context({ managed_by: 'crd', environment: 'production' }));
    renderApp('/applications/app-1?tab=settings');
    const env = await screen.findByRole('combobox', { name: 'Environment' });
    expect(env).toBeDisabled();
    expect(env).toHaveValue('production');
    expect(screen.queryByRole('button', { name: 'Save changes' })).toBeNull();
    expect(patches).toEqual([]);
  });

  it('says nothing about what it is for an application that is repository-wide', async () => {
    serve(context({ type: '', repository: '', branch: '' }));
    renderApp('/applications/app-1?tab=settings');
    await screen.findByRole('combobox', { name: 'Environment' });
    expect(screen.queryByText(/Branch .* of /)).toBeNull();
  });
});
