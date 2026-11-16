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
    expect(within(rows[1]!).getByText('Not met')).toBeInTheDocument();
    expect(within(rows[1]!).getByText(/3: 2 critical, 1 high/)).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Evidence from semgrep')).toBeInTheDocument();
    expect(within(rows[1]!).getByRole('link', { name: 'See the findings' }).getAttribute('href')).toContain('cwe%3A89');
    expect(within(rows[2]!).getByText('Met')).toBeInTheDocument();
    expect(within(rows[3]!).getByText('Not assessed')).toBeInTheDocument();
    expect(screen.getByText(/It is evidence for an auditor, not a certification/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Download CSV' })).toHaveAttribute('href', '/api/v1/taxonomies/owasp-top10-2021/status?format=csv');
    expect(await axe(table)).toHaveNoViolations();

    // Choosing an application asks for that application, and the export follows.
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Application' }), 'app-1');
    await waitFor(() => expect(calls.some((c) => c.url.includes('/status') && c.url.includes('application=app-1'))).toBe(true));
    expect(screen.getByRole('link', { name: 'Download CSV' }).getAttribute('href')).toContain('application=app-1');
  });

  // D102: a framework the tenant installed is offered with its origin; one that does not validate is named with its
  // reason, not offered; each control says why it reads as it does; an approved exception is shown apart and linked;
  // a manual control is attested by a maintainer through a form that says what is recorded.
  it('reads a tenant framework: reasons, exceptions, a broken resource, and an attestation', async () => {
    const calls = mockFetch({
      loggedIn: true, role: 'maintainer', apps: [app(1)],
      taxonomies: [
        { id: 'acme', name: 'ACME secure coding', version: '2026.1', origin: 'tenant' },
        { id: 'acme-old', name: 'acme-old', version: '', origin: 'tenant', error: 'compliance framework: control "SC-9": unknown category "sasst"' },
      ],
      taxonomyHistory: ['2026-11-15', '2026-11-14'],
      taxonomyStatus: { acme: { status: [
        { ...ctl('SC-1', 'No critical injection', 'clear', bands(0, 0, 0, 0), ['semgrep']), accepted: 2, query_exact: true,
          reason: 'Nothing that bears on it is open, and a SAST or DAST scan ran in the last 30 days. 2 findings are risk-accepted: approved exceptions, not counted as open.' },
        { id: 'SC-3', name: 'A threat model is reviewed for each release', status: 'not_assessed', manual: true, open: 0, bands: bands(0, 0, 0, 0),
          reason: 'A person attests this control, and nobody has yet.' },
        { ...ctl('SC-5', 'No injection or secrets', 'open', bands(0, 1, 0, 0)), query_exact: false, reason: '1 open finding breaks it.' },
      ] } },
    });
    renderApp('/compliance');
    const table = await screen.findByRole('table', { name: 'Controls' });
    expect(screen.getByRole('combobox', { name: 'Framework' })).toHaveTextContent('ACME secure coding 2026.1 (your own)');
    expect(screen.getByText('Not applied')).toBeInTheDocument();
    expect(screen.getByText(/unknown category "sasst"/)).toBeInTheDocument();
    const [, sc1, sc3, sc5] = within(table).getAllByRole('row');
    expect(within(sc1!).getByText(/2 findings are risk-accepted/)).toBeInTheDocument();
    expect(within(sc1!).getByRole('link', { name: '2 accepted exceptions' }).getAttribute('href')).toContain('state%3Arisk_accepted');
    expect(within(sc5!).getByRole('link', { name: 'See part of the findings' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'As of' })).toBeInTheDocument();
    expect(await axe(table)).toHaveNoViolations();

    await userEvent.click(within(sc3!).getByRole('button', { name: 'Attest' }));
    const dialog = await screen.findByRole('dialog', { name: 'Attest SC-3' });
    expect(within(dialog).getByRole('button', { name: 'Record attestation' })).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText('What you checked'), 'Threat model of 4.2 reviewed');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Record attestation' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.url.includes('/taxonomies/acme/controls/SC-3/attestations'))).toBe(true));
    const sent = JSON.parse(calls.find((c) => c.method === 'POST')!.body!);
    expect(sent).toMatchObject({ status: 'passed', note: 'Threat model of 4.2 reviewed' });
    expect(sent.expires_at).toMatch(/^\d{4}-\d{2}-\d{2}T23:59:59/);
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Attest SC-3' })).toBeNull());
    expect(await axe(document.body)).toHaveNoViolations();
  });

  it('offers no attestation to a viewer', async () => {
    mockFetch({
      loggedIn: true, role: 'viewer', taxonomies: [{ id: 'acme', name: 'ACME', version: '1', origin: 'tenant' }],
      taxonomyStatus: { acme: { status: [{ id: 'SC-3', name: 'Threat model', status: 'not_assessed', manual: true, open: 0, bands: bands(0, 0, 0, 0) }] } },
    });
    renderApp('/compliance');
    await screen.findByRole('table', { name: 'Controls' });
    expect(screen.queryByRole('button', { name: 'Attest' })).toBeNull();
  });

  it('shows the problem when a framework cannot be evaluated', async () => {
    mockFetch({ loggedIn: true, taxonomyStatus: 'error' });
    renderApp('/compliance');
    expect(await screen.findByText('The framework could not be evaluated.')).toBeInTheDocument();
  });
});
