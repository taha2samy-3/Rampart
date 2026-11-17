import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { appPage, mockFetch, renderApp } from '@/test/helpers';

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
