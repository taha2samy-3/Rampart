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

    // Verify SBOM & VEX download links
    expect(within(sbomSection).getByRole('link', { name: 'CycloneDX SBOM' })).toHaveAttribute(
      'href',
      expect.stringContaining('/sbom?format=cyclonedx')
    );
    expect(within(sbomSection).getByRole('link', { name: 'SPDX SBOM' })).toHaveAttribute(
      'href',
      expect.stringContaining('/sbom?format=spdx')
    );

    // Verify vulnerable package alert and table row
    expect(await within(sbomSection).findByText(/1 package in this application has active CVEs/i)).toBeInTheDocument();
    const table = within(sbomSection).getByRole('table', { name: 'Application packages table' });
    expect(within(table).getByText('log4j-core')).toBeInTheDocument();
    expect(within(table).getByRole('link', { name: /2 open CVEs/i })).toBeInTheDocument();

    // Verify Scan Now button on package
    expect(within(table).getByRole('button', { name: /Scan log4j-core/i })).toBeInTheDocument();
  });

  it('renders Attest section and allows opening attestation modal', async () => {
    mockFetch({
      loggedIn: true,
      appPages: {
        '01a1e562-93be-7b79-9762-615a097742e5': appSummary,
      },
      inventory: { components: [appComponent] },
    });

    renderApp('/applications/01a1e562-93be-7b79-9762-615a097742e5');

    // Verify Attest section
    const attestSection = await screen.findByRole('region', { name: /Compliance Attestations/i });
    expect(attestSection).toBeInTheDocument();

    const recordBtn = within(attestSection).getByRole('button', { name: /^Attest$/i });
    expect(recordBtn).toBeInTheDocument();

    // Click Attest to open dialog
    await userEvent.click(recordBtn);
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByText(/Application Security Review/i)).toBeInTheDocument();
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
            } as any,
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
});
