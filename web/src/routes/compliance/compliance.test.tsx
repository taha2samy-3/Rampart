import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { app, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const bands = (c: number, h: number, m: number, l: number) => ({ critical: c, high: h, medium: m, low: l });
const ctl = (id: string, name: string, status: string, b: ReturnType<typeof bands>, evidence: string[] = []) => ({
  id, name, status, bands: b, open: b.critical + b.high + b.medium + b.low, query: 'cwe:89 state:open,under_investigation,affected', evidence,
});

describe('compliance', () => {
  it('says per control what is open, what is clear and what was never assessed, and links the findings', async () => {
    const calls = mockFetch({
      loggedIn: true, apps: [app(1)],
      taxonomyStatus: { 'owasp-top10-2021': { status: [
        ctl('A03:2021', 'Injection', 'open', bands(2, 1, 0, 0), ['semgrep']),
        ctl('A02:2021', 'Cryptographic Failures', 'clear', bands(0, 0, 0, 0), ['semgrep']),
        ctl('A09:2021', 'Security Logging and Monitoring Failures', 'not_assessed', bands(0, 0, 0, 0)),
      ] } },
    });
    renderApp('/compliance');
    const table = await screen.findByRole('table', { name: 'Controls' });
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(4);
    expect(within(rows[1]!).getByText('Open findings')).toBeInTheDocument();
    expect(within(rows[1]!).getByText(/3: 2 critical, 1 high/)).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Evidence from semgrep')).toBeInTheDocument();
    expect(within(rows[1]!).getByRole('link', { name: 'See the findings' }).getAttribute('href')).toContain('cwe%3A89');
    expect(within(rows[2]!).getByText('Assessed, none open')).toBeInTheDocument();
    expect(within(rows[3]!).getByText('Not assessed')).toBeInTheDocument();
    expect(screen.getByText(/It is evidence, not a certification/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Download CSV' })).toHaveAttribute('href', '/api/v1/taxonomies/owasp-top10-2021/status?format=csv');
    expect(await axe(table)).toHaveNoViolations();

    // Choosing an application asks for that application, and the export follows.
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Application' }), 'app-1');
    await waitFor(() => expect(calls.some((c) => c.url.includes('/status') && c.url.includes('application=app-1'))).toBe(true));
    expect(screen.getByRole('link', { name: 'Download CSV' }).getAttribute('href')).toContain('application=app-1');
  });

  it('shows the problem when a framework cannot be evaluated', async () => {
    mockFetch({ loggedIn: true, taxonomyStatus: 'error' });
    renderApp('/compliance');
    expect(await screen.findByText('The framework could not be evaluated.')).toBeInTheDocument();
  });
});
