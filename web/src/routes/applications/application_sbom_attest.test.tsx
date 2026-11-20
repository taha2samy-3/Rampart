import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { appPage, finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const appSummary = appPage(1, {
  id: '01a1e562-93be-7b79-9762-615a097742e5',
  slug: 'rampart-demo-app',
  name: 'Rampart Demo App',
});

const appComponent = {
  name: 'log4j-core',
  version: '2.14.1',
  purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
  type: 'maven',
  track: 'main',
  license: 'Apache-2.0',
  direct: true,
  asset_id: 'a-1',
  asset_name: 'flare-reminders',
  application_name: 'Rampart Demo App',
  vulnerabilities: 2,
};

describe('Application Route: SBOM, Attest & CVE Sections', () => {
  it('renders SBOM section with download links and flags packages with CVEs', async () => {
    mockFetch({
      loggedIn: true,
      appPages: {
        '01a1e562-93be-7b79-9762-615a097742e5': appSummary,
      },
      inventory: { components: [appComponent] },
    });

    renderApp('/applications/01a1e562-93be-7b79-9762-615a097742e5');

    // Verify SBOM section
    const sbomSection = await screen.findByRole('region', { name: /Software Bill of Materials/i });
    expect(sbomSection).toBeInTheDocument();

    // The manifests are in a menu: open it, then check the links
    await userEvent.click(within(sbomSection).getByRole('button', { name: /Export manifests/i }));
    expect(await screen.findByRole('menuitem', { name: /CycloneDX SBOM/ })).toHaveAttribute(
      'href',
      expect.stringContaining('/sbom?format=cyclonedx')
    );
    expect(screen.getByRole('menuitem', { name: /SPDX SBOM/ })).toHaveAttribute(
      'href',
      expect.stringContaining('/sbom?format=spdx')
    );

    // Verify vulnerable package alert and table row
    expect(await within(sbomSection).findByText(/1 package in this application has active CVEs/i)).toBeInTheDocument();
    const table = within(sbomSection).getByRole('table', { name: 'Application packages table' });
    expect(within(table).getByText('log4j-core')).toBeInTheDocument();
    expect(within(table).getByRole('link', { name: /2 open CVEs/i })).toBeInTheDocument();

    // The per-package button re-scores; it does not claim to scan
    expect(within(table).getByRole('button', { name: /Re-evaluate log4j-core/i })).toBeInTheDocument();
    expect(within(table).queryByRole('button', { name: /^Scan /i })).toBeNull();
  });

  const fw = (over: Record<string, unknown>) => ({ id: 'x', name: 'X', version: '1', origin: 'builtin', verdict: 'partial', controls: 2, clear: 0, open: 0, at_risk: 0, not_assessed: 2, open_findings: 0, overdue_findings: 0, accepted_findings: 0, window_days: 30, ...over });
  const ctl = (id: string, name: string, manual: boolean, status = 'not_assessed') => ({ id, name, status, open: 0, bands: { critical: 0, high: 0, medium: 0, low: 0 }, manual });
  const ID = '01a1e562-93be-7b79-9762-615a097742e5';

  it('lists only the manual controls of the frameworks in scope, and attests the real control for this application', async () => {
    mockFetch({
      loggedIn: true, role: 'maintainer',
      appPages: { [ID]: appSummary },
      inventory: { components: [appComponent] },
      appCompliance: { application: ID, evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [], frameworks: [fw({ id: 'acme-policy', name: 'ACME secure coding' })] },
      taxonomyStatus: { 'acme-policy': { status: [ctl('TM-1', 'Threat model signed off', true), ctl('SC-1', 'No secrets in code', false)] } },
    });
    renderApp(`/applications/${ID}`);

    const section = await screen.findByRole('region', { name: /Manual controls/i });
    const table = await within(section).findByRole('table', { name: 'Manual controls table' });
    expect(within(table).getByText('Threat model signed off')).toBeInTheDocument();
    expect(within(table).queryByText('No secrets in code')).toBeNull(); // read from scans: not attested by hand
    expect(within(table).getByText('Not attested')).toBeInTheDocument();

    await userEvent.click(within(table).getByRole('button', { name: 'Attest' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Threat model signed off')).toBeInTheDocument(); // a control the framework has, not an invented id
    expect(await axe(section)).toHaveNoViolations();
  });

  it('names the owner of an attestation, and sends the owner the person typed', async () => {
    const withOwner = { ...ctl('TM-1', 'Threat model signed off', true, 'clear'), attestation: { id: 'a1', framework_id: 'acme-policy', control_id: 'TM-1', status: 'passed', note: 'x', attested_by: 'user:sara@acme.example', owner: 'team:appsec', attested_at: '2026-11-01T00:00:00Z', expires_at: '2027-11-01T00:00:00Z' } };
    mockFetch({
      loggedIn: true, role: 'maintainer',
      appPages: { [ID]: appSummary },
      inventory: { components: [appComponent] },
      appCompliance: { application: ID, evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [], frameworks: [fw({ id: 'acme-policy', name: 'ACME secure coding' })] },
      taxonomyStatus: { 'acme-policy': { status: [withOwner] } },
    });
    const inner = globalThis.fetch;
    const bodies: unknown[] = [];
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input instanceof URL ? input.pathname : input.url;
      if (path.endsWith('/attestations') && init?.method === 'POST') bodies.push(JSON.parse(String(init.body)));
      return inner(input, init);
    });
    renderApp(`/applications/${ID}`);
    const section = await screen.findByRole('region', { name: /Manual controls/i });
    expect(await within(section).findByText('appsec')).toBeInTheDocument(); // the owner, not the person who clicked
    await userEvent.click(within(section).getByRole('button', { name: 'Attest again' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Owner'), 'team:payments-security');
    await userEvent.type(within(dialog).getByLabelText('What you checked'), 'Reviewed with the team');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Record attestation' }));
    await vi.waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({ owner: 'team:payments-security', application_id: ID, status: 'passed' });
  });

  const withTicket = (ticket: Record<string, unknown>) => ({
    ...ctl('TM-1', 'Threat model signed off', true, 'clear'),
    attestation: { id: 'a1', framework_id: 'acme-policy', control_id: 'TM-1', status: 'passed', note: 'x', attested_by: 'user:sara@acme.example', attested_at: '2026-11-01T00:00:00Z', expires_at: '2026-12-01T00:00:00Z', ticket },
  });
  const openWith = async (role: 'admin' | 'maintainer', ticket: Record<string, unknown>) => {
    mockFetch({
      loggedIn: true, role,
      appPages: { [ID]: appSummary },
      inventory: { components: [appComponent] },
      appCompliance: { application: ID, evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [], frameworks: [fw({ id: 'acme-policy', name: 'ACME secure coding' })] },
      taxonomyStatus: { 'acme-policy': { status: [withTicket(ticket)] } },
    });
    const calls: string[] = [];
    const inner = globalThis.fetch;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input instanceof URL ? input.pathname : input.url;
      if (path.includes('/attestation-tickets/') && init?.method === 'POST') { calls.push(path); return Promise.resolve(new Response(null, { status: 202 })); }
      return inner(input, init);
    });
    renderApp(`/applications/${ID}`);
    return { section: await screen.findByRole('region', { name: /Manual controls/i }), calls };
  };

  it('links the renewal ticket that was opened', async () => {
    const { section } = await openWith('maintainer', { status: 'opened', ref: 'SEC-42', url: 'https://jira.example/browse/SEC-42' });
    expect(await within(section).findByRole('link', { name: 'SEC-42' })).toHaveAttribute('href', 'https://jira.example/browse/SEC-42');
  });

  it('shows a ticket that gave up, with why, and lets only an administrator try again', async () => {
    const admin = await openWith('admin', { status: 'failed', error: 'tracker HTTP 401: bad credentials' });
    expect(await within(admin.section).findByText('Could not be opened')).toBeInTheDocument();
    expect(within(admin.section).getByText(/bad credentials/)).toBeInTheDocument();
    await userEvent.click(within(admin.section).getByRole('button', { name: 'Try again' }));
    await vi.waitFor(() => expect(admin.calls).toEqual(['/api/v1/attestation-tickets/a1/retry']));
  });

  it('does not offer "Try again" to a maintainer', async () => {
    const { section } = await openWith('maintainer', { status: 'failed', error: 'x' });
    expect(await within(section).findByText('Could not be opened')).toBeInTheDocument();
    expect(within(section).queryByRole('button', { name: 'Try again' })).toBeNull();
  });

  it('says so when no framework has a manual control, and offers no invented attestation', async () => {
    mockFetch({
      loggedIn: true, role: 'maintainer',
      appPages: { [ID]: appSummary },
      inventory: { components: [appComponent] },
      appCompliance: { application: ID, evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [], frameworks: [fw({ id: 'acme-policy', name: 'ACME secure coding' })] },
      taxonomyStatus: { 'acme-policy': { status: [ctl('SC-1', 'No secrets in code', false)] } },
    });
    renderApp(`/applications/${ID}`);
    const section = await screen.findByRole('region', { name: /Manual controls/i });
    expect(await within(section).findByText('No manual controls')).toBeInTheDocument();
    expect(within(section).queryByRole('button', { name: /attest/i })).toBeNull();
  });

  it('shows no Attest button to someone who is not a maintainer', async () => {
    mockFetch({
      loggedIn: true, role: 'triager',
      appPages: { [ID]: appSummary },
      inventory: { components: [appComponent] },
      appCompliance: { application: ID, evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [], frameworks: [fw({ id: 'acme-policy', name: 'ACME secure coding' })] },
      taxonomyStatus: { 'acme-policy': { status: [ctl('TM-1', 'Threat model signed off', true)] } },
    });
    renderApp(`/applications/${ID}`);
    const section = await screen.findByRole('region', { name: /Manual controls/i });
    expect(await within(section).findByText('Threat model signed off')).toBeInTheDocument();
    expect(within(section).queryByRole('button', { name: /attest/i })).toBeNull();
  });

  it('verifies CVE changes table is present at the bottom', async () => {
    mockFetch({
      loggedIn: true,
      appPages: {
        '01a1e562-93be-7b79-9762-615a097742e5': appSummary,
      },
      inventory: { components: [appComponent] },
    });

    renderApp('/applications/01a1e562-93be-7b79-9762-615a097742e5');

    // Verify CVE changes section is rendered
    expect(await screen.findByRole('region', { name: 'What changed' })).toBeInTheDocument();
  });

  it('allows expanding package CVEs in the accordion to inspect details', async () => {
    const baseFinding = finding(1, 'critical');
    mockFetch({
      loggedIn: true,
      appPages: {
        '01a1e562-93be-7b79-9762-615a097742e5': appSummary,
      },
      inventory: { components: [appComponent] },
      findings: [
        {
          ...baseFinding,
          finding: {
            ...baseFinding.finding,
            id: 'f-log4shell',
            title: 'Log4Shell RCE in log4j-core',
            vulnerability_id: 'CVE-2021-44228',
            location: {
              file_path: 'src/a.go',
              start_line: 1,
              component_name: 'log4j-core',
              purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
              fixed_version: '2.17.1',
            } as never,
          },
        },
      ],
    });

    renderApp('/applications/01a1e562-93be-7b79-9762-615a097742e5');

    const sbomSection = await screen.findByRole('region', { name: /Software Bill of Materials/i });
    const table = await within(sbomSection).findByRole('table', { name: 'Application packages table' });

    // Find expand toggle button
    const expandBtn = within(table).getByRole('button', { name: /Expand CVEs for log4j-core/i });
    expect(expandBtn).toBeInTheDocument();

    await userEvent.click(expandBtn);

    // Verify expanded accordion content
    expect(await screen.findByText(/Vulnerabilities in/i)).toBeInTheDocument();
    expect(screen.getByText('CVE-2021-44228')).toBeInTheDocument();

    // Click Details button to open FindingDetailModal
    const detailsBtn = screen.getByRole('button', { name: /^Details$/i });
    await userEvent.click(detailsBtn);

    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getAllByText(/Log4Shell RCE in log4j-core/i).length).toBeGreaterThan(0);

    // Verify "Open in Findings Explorer →" link includes the query search parameter
    const explorerLink = within(dialog).getByRole('link', { name: /Open in Findings Explorer/i });
    expect(explorerLink).toBeInTheDocument();
    expect(explorerLink).toHaveAttribute('href', expect.stringContaining('q=cve%3ACVE-2021-44228'));
    expect(explorerLink).toHaveAttribute('href', expect.stringContaining('sel=f-log4shell'));
  });

  // What the databases know of a CVE is shown where the application lists it, with the same section as the Finding page.
  it('shows what the databases know of the CVE when it is opened from the application', async () => {
    const baseFinding = finding(1, 'critical');
    mockFetch({
      loggedIn: true,
      appPages: { '01a1e562-93be-7b79-9762-615a097742e5': appSummary },
      inventory: { components: [appComponent] },
      findings: [{
        ...baseFinding,
        finding: { ...baseFinding.finding, id: 'f-log4shell', title: 'Log4Shell RCE in log4j-core', vulnerability_id: 'CVE-2021-44228',
          location: { file_path: 'pom.xml', start_line: 1, component_name: 'log4j-core', installed_version: '2.14.1', fixed_version: '2.17.1' } as never },
      }],
      vuln: {
        record: {
          id: 'CVE-2021-44228', aliases: ['GHSA-jfh8-c2jp-5v3q'], cwes: [502, 917], cvss_score: 10, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
          epss_score: 0.94358, kev: true, kev_date_added: '2021-12-10', kev_due_date: '2021-12-24', kev_ransomware: true, exploit_maturity: 'weaponized',
          description: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.',
          published: '2021-12-10T10:15:00Z', modified: '2025-10-21T00:00:00Z', links: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
        },
        impact: { id: 'CVE-2021-44228', findings: 1, open: 1, applications: [{ id: '01a1e562-93be-7b79-9762-615a097742e5', slug: 'shop', name: 'Shop', findings: 1, open: 1, max_severity: 'critical', max_risk_score: 990, asset_ids: [] }] },
      },
    });
    renderApp('/applications/01a1e562-93be-7b79-9762-615a097742e5');
    const sbomSection = await screen.findByRole('region', { name: /Software Bill of Materials/i });
    await userEvent.click(within(await within(sbomSection).findByRole('table', { name: 'Application packages table' })).getByRole('button', { name: /Expand CVEs for log4j-core/i }));
    await userEvent.click(await screen.findByRole('button', { name: /^Details$/i }));

    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText('Known exploited')).toBeInTheDocument();
    expect(within(dialog).getByText(/Added to the CISA catalogue/)).toBeInTheDocument();
    expect(within(dialog).getByText(/used in ransomware campaigns/)).toBeInTheDocument();
    expect(within(dialog).getByText(/94\.4% in the next 30 days/)).toBeInTheDocument();
    expect(within(dialog).getByText('10.0')).toBeInTheDocument();
    expect(within(dialog).getByText('A working exploit is in circulation')).toBeInTheDocument();
    expect(within(dialog).getByText('CWE-502')).toBeInTheDocument();
    expect(within(dialog).getByText(/Apache Log4j2 JNDI features/)).toBeInTheDocument();
    expect(await within(dialog).findByText('Found in 1 application')).toBeInTheDocument();
    expect(within(dialog).getByRole('heading', { name: 'Where it is' })).toBeInTheDocument();
  });

  it('has no accessibility violations across the application page', async () => {
    mockFetch({
      loggedIn: true,
      appPages: {
        '01a1e562-93be-7b79-9762-615a097742e5': appSummary,
      },
      inventory: { components: [appComponent] },
    });

    const { container } = renderApp('/applications/01a1e562-93be-7b79-9762-615a097742e5');
    await screen.findByRole('region', { name: /Software Bill of Materials/i });
    expect(await axe(container)).toHaveNoViolations();
  });

  it('re-checks with analyzers for someone who may triage, and says what it did', async () => {
    mockFetch({ loggedIn: true, role: 'triager', appPages: { [ID]: appSummary }, inventory: { components: [appComponent] } });
    const inner = globalThis.fetch;
    const calls: string[] = [];
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input instanceof URL ? input.pathname : input.url;
      if (path.endsWith('/refresh-vulnerabilities') && init?.method === 'POST') {
        calls.push(path);
        return Promise.resolve(new Response(JSON.stringify({ status: 'started', queued: 2, message: 'Queued 2 analyses for application' }), { status: 202, headers: { 'content-type': 'application/json' } }));
      }
      return inner(input, init);
    });
    renderApp(`/applications/${ID}`);
    const section = await screen.findByRole('region', { name: /Software Bill of Materials/i });
    await userEvent.click(await within(section).findByRole('button', { name: /Check again/i }));
    expect(await within(section).findByRole('status')).toHaveTextContent('Queued 2 analyses for application');
    expect(calls).toEqual([`/api/v1/applications/${ID}/refresh-vulnerabilities`]);
  });

  it('offers neither button to a viewer', async () => {
    mockFetch({ loggedIn: true, role: 'viewer', appPages: { [ID]: appSummary }, inventory: { components: [appComponent] } });
    renderApp(`/applications/${ID}`);
    const section = await screen.findByRole('region', { name: /Software Bill of Materials/i });
    await within(section).findByRole('table', { name: 'Application packages table' });
    expect(within(section).queryByRole('button', { name: /Check again/i })).toBeNull();
  });
});
