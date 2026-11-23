import { screen } from '@testing-library/react';
import { axe } from 'vitest-axe';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { appPage, mockFetch, renderApp } from '@/test/helpers';
import type { ApplicationScanSourcesResponse } from '@/api/types';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const APP_ID = '01931f6a-0000-7000-8000-000000000001';

const sampleSources: ApplicationScanSourcesResponse = {
  total: 2,
  sources: [
    {
      id: 'src-1',
      name: 'checkout-ci',
      type: 'upload',
      scanner_family: 'semgrep',
      categories: ['sast', 'sca'],
      auth_type: 'multi',
      active: true,
      created_at: '2026-11-20T01:00:00Z',
      total_runs: 14,
      last_scan_at: '2026-11-22T10:00:00Z',
    },
    {
      id: 'src-2',
      name: 'dast-scheduled',
      type: 'apiPull',
      categories: ['dast'],
      auth_type: 'token',
      active: false,
      created_at: '2026-11-19T01:00:00Z',
      disabled_at: '2026-11-21T01:00:00Z',
      total_runs: 3,
      last_scan_at: '2026-11-20T12:00:00Z',
    },
  ],
};

function stubSources(body: unknown, status = 200) {
  mockFetch({
    loggedIn: true,
    appPages: {
      [APP_ID]: appPage(1, { id: APP_ID, name: 'Checkout Service', slug: 'checkout-service', branch: 'main' }),
    },
    inventory: { components: [] },
  });
  const inner = globalThis.fetch;
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes('/sources')) {
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { 'Content-Type': status === 200 ? 'application/json' : 'application/problem+json' },
        })
      );
    }
    return inner(input, init);
  });
}

describe('Application Sources & Pipelines Tab', () => {
  it('renders populated scan sources table with live API data and badges', async () => {
    stubSources(sampleSources);
    const { container } = renderApp(`/applications/${APP_ID}?tab=sources`);

    expect(await screen.findByRole('heading', { name: /Scan Sources & Pipelines/i })).toBeInTheDocument();

    // Source 1 checks
    expect(screen.getByText('checkout-ci')).toBeInTheDocument();
    expect(screen.getByText('(semgrep)')).toBeInTheDocument();
    expect(screen.getByText('Token + OIDC Federation')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('14')).toBeInTheDocument();
    expect(screen.getByText('sast')).toBeInTheDocument();
    expect(screen.getByText('sca')).toBeInTheDocument();

    // Source 2 checks
    expect(screen.getByText('dast-scheduled')).toBeInTheDocument();
    expect(screen.getByText('apiPull')).toBeInTheDocument();
    expect(screen.getByText('Disabled')).toBeInTheDocument();
    expect(screen.getAllByText('3').length).toBeGreaterThanOrEqual(1);

    // Accessibility check
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('renders honest zero-mock empty state with snippet tabs when no sources exist', async () => {
    stubSources({ sources: [], total: 0 });
    renderApp(`/applications/${APP_ID}?tab=sources`);

    expect(await screen.findByText(/No Scan Sources Bound Yet/i)).toBeInTheDocument();
    expect(screen.getByText(/Kubernetes CRD/i)).toBeInTheDocument();
    expect(screen.getByText(/Helm values.yaml/i)).toBeInTheDocument();
    expect(screen.getByText(/CI Pipeline \(cURL\)/i)).toBeInTheDocument();

    // Contains app slug in snippets
    expect(screen.getAllByText(/checkout-service-ci/i).length).toBeGreaterThanOrEqual(1);
  });

  it('renders problem message when sources fetch fails', async () => {
    stubSources({ title: 'Internal Server Error', status: 500 }, 500);
    renderApp(`/applications/${APP_ID}?tab=sources`);

    expect(await screen.findByText(/Failed to load scan sources/i)).toBeInTheDocument();
  });
});
