import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { app, appPage, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const fw = (over: Record<string, unknown>) => ({ id: 'x', name: 'X', version: '1', origin: 'builtin', verdict: 'meets', controls: 10, clear: 10, open: 0, not_assessed: 0, open_findings: 0, accepted_findings: 0, window_days: 30, ...over });

async function open(appCompliance: unknown) {
  mockFetch({ loggedIn: true, apps: [app(1)], appPages: { 'app-1': appPage(1) }, appCompliance });
  renderApp('/applications/app-1');
  return (await screen.findByRole('heading', { name: 'Compliance', level: 2 })).closest('section')!;
}

describe('Application page: compliance', () => {
  it('says which frameworks the application meets today, and why not where it does not', async () => {
    const section = await open({
      application: 'app-1', evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: ['PCI DSS 4.0.1 requirement 6'],
      frameworks: [
        fw({ id: 'cwe-top25', name: 'CWE Top 25', version: '2024', verdict: 'meets', controls: 25, clear: 25 }),
        fw({ id: 'owasp-top10-2021', name: 'OWASP Top 10', version: '2021', verdict: 'gaps', controls: 10, clear: 7, open: 2, not_assessed: 1, open_findings: 5 }),
        fw({ id: 'acme-policy', name: 'ACME secure coding', version: '2026.1', origin: 'tenant', verdict: 'partial', controls: 4, clear: 1, not_assessed: 3, logo: '/api/v1/taxonomies/acme-policy/logo?v=1' }),
      ],
    });
    expect(await within(section).findByText('Meets all 25 controls.')).toBeInTheDocument();
    expect(within(section).getByText('2 of 10 controls are broken by 5 open findings.')).toBeInTheDocument();
    expect(within(section).getByText(/1 of 4 controls clear; 3 cannot be read yet/)).toBeInTheDocument();
    expect(within(section).getByText(/PCI DSS 4.0.1 requirement 6/)).toBeInTheDocument();
    // each row opens the Compliance page on that framework, for this application
    const link = within(section).getByRole('link', { name: /OWASP Top 10/ });
    expect(link.getAttribute('href')).toContain('framework=owasp-top10-2021');
    expect(link.getAttribute('href')).toContain('application=app-1');
    // the bar says its numbers to a screen reader, and the installed framework shows its own logo
    expect(within(section).getByRole('img', { name: '7 controls clear, 2 open, 1 not read' })).toBeInTheDocument();
    expect(section.querySelector('img[src="/api/v1/taxonomies/acme-policy/logo?v=1"]')).not.toBeNull();
  });

  it('says when no framework reads the application', async () => {
    const section = await open({ application: 'app-1', evaluated_at: '2026-11-17T00:00:00Z', frameworks: [], not_in_scope: [] });
    expect(await within(section).findByText('No framework reads this application yet.')).toBeInTheDocument();
  });

  it('reports a failed reading instead of an empty list', async () => {
    const section = await open('error');
    expect(await within(section).findByText('The compliance reading could not be loaded.', undefined, { timeout: 4000 })).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    const section = await open({ application: 'app-1', evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [], frameworks: [fw({ id: 'cwe-top25', name: 'CWE Top 25', version: '2024' })] });
    await within(section).findByText('Meets all 10 controls.');
    expect(await axe(section)).toHaveNoViolations();
  });
});
