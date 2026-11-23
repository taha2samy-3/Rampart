import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { appPage, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const context = (over: Record<string, unknown> = {}) => ({
  business_criticality: 'high',
  internet_facing: false,
  data_classification: [],
  compensating_controls: [],
  lifecycle: 'production',
  type: 'repo',
  repository: 'github.com/acme/shop',
  branch: 'main',
  environment: '',
  managed_by: 'crd',
  ...over,
});

/** The server of the page: the application and what the score knows. */
function serve(ctx: Record<string, unknown>, environments = ['production', 'staging', 'test', 'development']) {
  mockFetch({ loggedIn: true, role: 'admin', appPages: { 'app-1': appPage(1, { context: ctx }) } });
  const inner = globalThis.fetch;
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const path = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : input.url;
    const reply = (body: unknown, status = 200) =>
      Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }));
    if (path === '/api/v1/scoring') {
      return reply({
        product: 'Rampart',
        version: 'test',
        customised: false,
        risk: {
          base: {},
          bands: {},
          factors: [
            { name: 'PRODUCTION_ENV', when: 'x', points: 60, group: 'context' },
            { name: 'APP_HIGH', when: 'x', points: 50, group: 'context' },
            { name: 'INTERNET_FACING', when: 'x', points: 100, group: 'context' },
          ],
        },
        sla: {
          matrix: {},
          kevDueDate: true,
          maxDays: 365,
          startFrom: 'firstSeen',
          restartOnReactivation: true,
          pauseDuringRiskAcceptance: true,
        },
        environments,
        application_types: ['repo'],
      });
    }
    return inner(input, init);
  });
}

describe('the settings of an application: read-only dynamic risk context (D140)', () => {
  it('says what the application is, and shows read-only values without form inputs or save buttons', async () => {
    serve(context());
    renderApp('/applications/app-1?tab=settings');
    expect(await screen.findByText(/Branch main of github.com\/acme\/shop/)).toBeInTheDocument();

    const section = screen.getByTestId('app-settings-section');
    expect(section.querySelector('select')).toBeNull();
    expect(section.querySelector('input')).toBeNull();
    expect(section.querySelector('button[type="submit"]')).toBeNull();
    expect(within(section).getByText(/Editing from the UI is disabled/)).toBeInTheDocument();
  });

  it('dynamically displays live risk policy factor points for configured environment and criticality', async () => {
    serve(context({ environment: 'production', business_criticality: 'high', lifecycle: 'development' }));
    renderApp('/applications/app-1?tab=settings');

    const section = await screen.findByTestId('app-settings-section');
    // Production environment adds +60 points from PRODUCTION_ENV factor
    expect(await within(section).findByText(/\+60 points/)).toBeInTheDocument();
    // High criticality adds +50 points from APP_HIGH factor
    expect(within(section).getByText(/\+50 points/)).toBeInTheDocument();
    expect(within(section).getByText('Production')).toBeInTheDocument();
    expect(within(section).getByText('High')).toBeInTheDocument();
  });

  it('renders dynamic enterprise attributes when present', async () => {
    serve(context({ attributes: { has_vpn: true, network_tier: 'dmz' } }));
    renderApp('/applications/app-1?tab=settings');

    const section = await screen.findByTestId('app-settings-section');
    expect(within(section).getByText('has_vpn')).toBeInTheDocument();
    expect(within(section).getByText('true')).toBeInTheDocument();
    expect(within(section).getByText('network_tier')).toBeInTheDocument();
    expect(within(section).getByText('dmz')).toBeInTheDocument();
  });

  it('says nothing about what it is for an application that is repository-wide', async () => {
    serve(context({ type: '', repository: '', branch: '' }));
    renderApp('/applications/app-1?tab=settings');
    await screen.findByText(/What the score knows about this application/);
    expect(screen.queryByText(/Branch .* of /)).toBeNull();
  });
});
