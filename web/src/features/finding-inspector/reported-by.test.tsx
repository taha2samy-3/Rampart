import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import type { CorrelatedRef } from '@/api/types';
import { finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const trivy = { scanner: 'trivy', name: 'trivy', version: '0.58', first_seen: '2026-11-01T00:00:00Z', last_seen: '2026-11-11T00:00:00Z', reports: 9, present: true, tool_severity: 'critical', latest_run_id: 'r1', locations: 1 };

async function open(sources: Parameters<typeof mockFetch>[0]['sources']) {
  mockFetch({ loggedIn: true, findings: [finding(1)], sources });
  renderApp('/findings?sel=f-1');
  const insp = await screen.findByRole('complementary', { name: 'Finding details' });
  const heading = await within(insp).findByRole('heading', { name: 'Reported by' });
  return { insp, section: heading.closest('section')! };
}

describe('Reported by', () => {
  it('says which tool reported it, since when, and whether it still does', async () => {
    const { section } = await open({ reported_by: [trivy] });
    expect(await within(section).findByText('Trivy')).toBeInTheDocument();
    expect(within(section).getByText(/still reports it/)).toBeInTheDocument();
    expect(within(section).getByText(/First reported .*Nov.*, in 9 scans\./)).toBeInTheDocument();
    expect(within(section).getByText(/It rated it critical/)).toBeInTheDocument();
  });

  it('says so when a tool has stopped reporting it, and lists the same issue found by another tool', async () => {
    const { section } = await open({
      reported_by: [{ ...trivy, present: false }],
      also_reported_by: [{ id: 'f-9', scanner: 'grype', rule_id: 'GHSA-x', state: 'open' }],
    });
    expect(await within(section).findByText(/no longer reports it/)).toBeInTheDocument();
    expect(within(section).getByText('Grype')).toBeInTheDocument();
    expect(within(section).getByText(/also found this, as another finding \(open\)/)).toBeInTheDocument();
    expect(within(section).getByRole('link', { name: 'Open it' })).toHaveAttribute('href', expect.stringContaining('sel=f-9'));
  });

  it('shows a plain line when nothing reported it', async () => {
    const empty = await open({});
    expect(await within(empty.section).findByText('No scan has reported this finding.')).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    const { insp } = await open({ reported_by: [trivy], also_reported_by: [{ id: 'f-9', scanner: 'grype', rule_id: 'x', state: 'open' } satisfies CorrelatedRef] });
    await within(insp).findByText('Trivy');
    expect(await axe(insp)).toHaveNoViolations();
  });
});
