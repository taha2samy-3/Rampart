import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const gitleaksOcc = {
  id: 'occ-1',
  tenant_id: 't-1',
  finding_id: 'f-1',
  ingest_run_id: 'r-1',
  scan_source_id: 'src-1',
  asset_id: 'a-1',
  track: 'main',
  occurrence_key: 'key-1',
  scanner_family: 'gitleaks',
  scanner_name: 'Gitleaks',
  scanner_version: '8.18.0',
  tool_record_id: 'rule-aws-key:file.py:14',
  tool_severity: 'critical',
  normalized: {
    commit: '3a7b92f8c01d4e2a8b9c1d0e3f4a5b6c7d8e9f0a',
    author: 'Alice Developer',
    email: 'alice@example.com',
    entropy: 4.82,
    remediation_guidance: 'Revoke the AWS access key immediately using the AWS IAM console.',
    rule_docs: 'https://github.com/gitleaks/gitleaks',
  },
  raw: {
    RuleID: 'aws-access-key-id',
    Description: 'AWS Access Key Detected',
    Commit: '3a7b92f8c01d4e2a8b9c1d0e3f4a5b6c7d8e9f0a',
    Author: 'Alice Developer',
    Email: 'alice@example.com',
  },
  present: true,
  seen_count: 3,
  first_seen: '2026-11-01T00:00:00Z',
  last_seen: '2026-11-15T00:00:00Z',
};

describe('Scanner evidence', () => {
  it('renders scanner metadata, dynamic attributes, and raw JSON', async () => {
    mockFetch({
      loggedIn: true,
      findings: [finding(1)],
      occurrences: [gitleaksOcc],
    });

    renderApp('/findings?sel=f-1');

    const insp = await screen.findByRole('complementary', { name: 'Finding details' });
    const heading = await within(insp).findByRole('heading', { name: 'Scanner evidence' });
    const section = heading.closest('section')!;

    // Scanner metadata
    expect(within(section).getByText('Gitleaks')).toBeInTheDocument();
    expect(within(section).getByText('v8.18.0')).toBeInTheDocument();
    expect(within(section).getByText(/critical/i)).toBeInTheDocument();
    expect(within(section).getByText('rule-aws-key:file.py:14')).toBeInTheDocument();

    // Extracted dynamic attributes
    expect(within(section).getByText('Author')).toBeInTheDocument();
    expect(within(section).getByText('Alice Developer')).toBeInTheDocument();
    expect(within(section).getByText('3a7b92f8c01d4e2a8b9c1d0e3f4a5b6c7d8e9f0a')).toBeInTheDocument();
    expect(within(section).getByText('4.82')).toBeInTheDocument();
    expect(within(section).getByText(/Revoke the AWS access key immediately/)).toBeInTheDocument();

    // Safe link
    const link = within(section).getByRole('link', { name: /github.com\/gitleaks/ });
    expect(link).toHaveAttribute('href', 'https://github.com/gitleaks/gitleaks');

    // Raw scanner record
    expect(within(section).getByText('Raw scanner record (JSON)')).toBeInTheDocument();
    expect(within(section).getByRole('button', { name: 'Copy raw JSON' })).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    mockFetch({
      loggedIn: true,
      findings: [finding(1)],
      occurrences: [gitleaksOcc],
    });

    renderApp('/findings?sel=f-1');
    const insp = await screen.findByRole('complementary', { name: 'Finding details' });
    await within(insp).findByText('Gitleaks');
    expect(await axe(insp)).toHaveNoViolations();
  });
});
