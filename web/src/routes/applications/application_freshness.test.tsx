import { screen } from '@testing-library/react';
import { axe } from 'vitest-axe';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { appPage, mockFetch, renderApp } from '@/test/helpers';
import type { ApplicationFreshness } from '@/api/types';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const APP_ID = '01931f6a-0000-7000-8000-000000000001';

const sampleFreshness: ApplicationFreshness = {
  sbom: {
    at: '2026-11-20T04:00:00Z',
    components: 42,
  },
  rescored_at: '2026-11-20T05:30:00Z',
  analyzers: [
    {
      name: 'built-in-matcher',
      kind: 'sbom',
      scope: 'cluster',
      state: 'completed',
      last_analysed_at: '2026-11-20T04:30:00Z',
      findings: 5,
      created: 5,
      closed: 0,
    },
    {
      name: 'sonatype-oss-index',
      kind: 'external',
      scope: 'cluster',
      state: 'running',
      in_progress_since: '2026-11-20T06:15:00Z',
      findings: 0,
      created: 0,
      closed: 0,
    },
    {
      name: 'custom-analyzer',
      kind: 'external',
      scope: 'tenant',
      state: 'failed',
      error: 'dial tcp 10.0.0.5:50051: connection refused',
      findings: 1,
      created: 1,
      closed: 0,
    },
  ],
  feeds: [
    {
      name: 'cisa_kev',
      display_name: 'CISA KEV',
      status: 'success',
      last_sync: '2026-11-20T05:30:00Z',
    },
    {
      name: 'first_epss',
      display_name: 'FIRST EPSS',
      status: 'success',
      last_sync: '2026-11-20T05:00:00Z',
    },
  ],
};

function stubFreshness(body: unknown, status = 200) {
  mockFetch({
    loggedIn: true,
    appPages: {
      [APP_ID]: appPage(1, { id: APP_ID, name: 'Fresh App', slug: 'fresh-app' }),
    },
    inventory: { components: [] },
  });
  const inner = globalThis.fetch;
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes('/freshness')) {
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

describe('Application Freshness & Analyzers Section', () => {
  it('renders truthful analyzer states: completed, running, and failed with errors', async () => {
    stubFreshness(sampleFreshness);
    const { container } = renderApp(`/applications/${APP_ID}?tab=sbom`);

    expect(await screen.findByRole('heading', { name: /Application Freshness & Analyzers/i })).toBeInTheDocument();
    expect(screen.getByText(/Newest SBOM ingested:/i)).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText(/Findings re-scored:/i)).toBeInTheDocument();

    // Completed analyzer
    expect(screen.getByText('built-in-matcher')).toBeInTheDocument();
    expect(screen.getByTestId('analyzer-state-completed')).toHaveTextContent('Completed');
    expect(screen.getByText('(+5 new, -0 closed)')).toBeInTheDocument();

    // Running analyzer
    expect(screen.getByText('sonatype-oss-index')).toBeInTheDocument();
    expect(screen.getByTestId('analyzer-state-running')).toHaveTextContent('Running');
    expect(screen.getByText(/In progress since/i)).toBeInTheDocument();

    // Failed analyzer
    expect(screen.getByText('custom-analyzer')).toBeInTheDocument();
    expect(screen.getByTestId('analyzer-state-failed')).toHaveTextContent('Failed');
    expect(screen.getByText(/connection refused/i)).toBeInTheDocument();

    // Global threat feeds
    expect(screen.getByText(/Platform Threat Intelligence Feeds \(2\) — shared platform-wide/i)).toBeInTheDocument();
    expect(screen.getByText('CISA KEV')).toBeInTheDocument();
    expect(screen.getByText('FIRST EPSS')).toBeInTheDocument();

    // Accessibility check
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('renders informative message when no SBOM has been uploaded', async () => {
    stubFreshness({
      feeds: sampleFreshness.feeds,
      analyzers: [],
    });
    renderApp(`/applications/${APP_ID}?tab=sbom`);

    expect(await screen.findByText(/No SBOM has been uploaded for this application yet/i)).toBeInTheDocument();
    expect(screen.getByText(/No analyzers active or recorded for this application/i)).toBeInTheDocument();
  });

  it('renders error message when freshness fetch fails', async () => {
    stubFreshness({ title: 'Internal Server Error', status: 500 }, 500);
    renderApp(`/applications/${APP_ID}?tab=sbom`);

    expect(await screen.findByText(/Could not load freshness details/i)).toBeInTheDocument();
  });
});
