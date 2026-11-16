import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

function cve(i: number, id: string, appId: string, epss?: number, kev = false) {
  const row = finding(i, 'critical');
  Object.assign(row.finding, { vulnerability_id: id, application_id: appId, asset_id: `asset-${i}`, title: `Title of ${id}` });
  // 150 points of the EPSS factor are not a probability: the probability is on the breakdown.
  Object.assign(row.risk, { epss_score: epss, has_kev: kev, factors: [{ name: 'EPSS_HIGH', points: 150, reason: 'EPSS exploitation probability is >= 50%' }] });
  return row;
}

describe('Vulnerabilities', () => {
  it('groups the open findings by CVE, counts the applications, and shows the real EPSS and KEV', async () => {
    mockFetch({ loggedIn: true, findings: [cve(1, 'CVE-2021-44228', 'app-a', 0.97, true), cve(2, 'CVE-2021-44228', 'app-b', 0.97, true), cve(3, 'CVE-2020-1', 'app-a', undefined, false)] });
    renderApp('/vulnerabilities');
    const table = await screen.findByRole('table', { name: 'Vulnerabilities by CVE' });
    const log4j = within(table).getByText('CVE-2021-44228').closest('tr')!;
    expect(within(log4j).getByText('97.0%')).toBeInTheDocument(); // not 150.0%
    expect(within(log4j).getByText('CISA KEV')).toBeInTheDocument();
    const cells = within(log4j).getAllByRole('cell').map((c) => c.textContent);
    expect(cells).toContain('2'); // two applications
    const other = within(table).getByText('CVE-2020-1').closest('tr')!;
    expect(within(other).getByText('—')).toBeInTheDocument(); // no EPSS known
    expect(within(other).queryByText('CISA KEV')).toBeNull();
  });

  it('reports a failed load instead of "No vulnerabilities tracked"', async () => {
    mockFetch({ loggedIn: true, findings: 'error' });
    renderApp('/vulnerabilities');
    expect(await screen.findByText('Vulnerabilities could not be loaded.', undefined, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.queryByText('No vulnerabilities tracked')).toBeNull();
  });
});
