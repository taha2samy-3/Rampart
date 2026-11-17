import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { app, appPage, mockFetch, renderApp } from '@/test/helpers';
import { dayString } from './ChangesSection';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const row = (id: string, vuln: string, over: Record<string, unknown> = {}) => ({
  id, vulnerability_id: vuln, rule_id: vuln, title: `Title of ${vuln}`, category: 'sca', severity: 'high', risk_band: 'high', risk_score: 600, state: 'open',
  asset: 'github.com/acme/shop', first_seen: '2026-11-03T10:00:00Z', at: '2026-11-03T10:00:00Z', ...over,
});
const changes = {
  application: 'app-1', from: '2026-10-19', to: '2026-11-17', days: 30,
  summary: { new: 2, closed: 1, reopened: 1, open_at_start: 40, open_at_end: 41, previous: { from: '2026-09-19', to: '2026-10-18', new: 5, closed: 3 } },
  daily: [{ day: '2026-11-03', new: 2, closed: 0 }, { day: '2026-11-05', new: 0, closed: 1 }],
  new: [row('f1', 'CVE-2026-1111', { risk_band: 'critical', severity: 'critical' }), row('f2', 'CVE-2026-2222')],
  closed: [row('f3', 'CVE-2020-0002', { state: 'fixed', resolution: 'fixed', resolved_at: '2026-11-05T09:00:00Z' })],
  reopened: [row('f4', 'CVE-2020-0001', { at: '2026-11-10T09:00:00Z' })],
  open: [row('f1', 'CVE-2026-1111')],
  truncated: [],
};

async function open(sc: Parameters<typeof mockFetch>[0] = {}) {
  const calls = mockFetch({ loggedIn: true, apps: [app(1)], appPages: { 'app-1': appPage(1) }, appChanges: changes, ...sc });
  renderApp('/applications/app-1');
  const section = (await screen.findByRole('heading', { name: 'What changed', level: 2 })).closest('section')!;
  return { calls, section };
}
const changesCall = (calls: ReturnType<typeof mockFetch>) => calls.filter((c) => c.url.includes('/changes')).map((c) => new URL(c.url, 'http://x').searchParams);

// "Which CVEs appeared in this application, and which were closed, between two days": Snyk's new and resolved issues,
// Tenable's discovered and remediated, with the numbers of the period before to compare.
describe('Application page: what changed', () => {
  it('says what appeared and what was closed, compared with the period before, and lists the CVEs', async () => {
    const { section } = await open();
    expect(await within(section).findByText(/2 new \(5 before\), 1 closed \(3 before\), 1 came back\. Open went from 40 to 41\./)).toBeInTheDocument();
    const tabs = within(section).getAllByRole('tab').map((t) => t.textContent);
    expect(tabs).toEqual(['New (2)', 'Closed (1)', 'Came back (1)', 'Open at the end (41)']);
    const newList = within(section).getByRole('table', { name: /new$/ });
    expect(within(newList).getByRole('link', { name: 'CVE-2026-1111' })).toBeInTheDocument();
    expect(within(newList).getByText('Title of CVE-2026-2222')).toBeInTheDocument();

    await userEvent.click(within(section).getByRole('tab', { name: 'Closed (1)' }));
    const closed = await within(section).findByRole('table', { name: /closed$/ });
    expect(within(closed).getByText('CVE-2020-0002')).toBeInTheDocument();
    expect(within(closed).getByText('Fixed')).toBeInTheDocument(); // how it was closed
    expect(within(closed).getByRole('columnheader', { name: 'How' })).toBeInTheDocument();

    await userEvent.click(within(section).getByRole('tab', { name: 'Came back (1)' }));
    expect(await within(section).findByText('CVE-2020-0001')).toBeInTheDocument();
  });

  it('draws one chart that says its numbers, and asks for the last 30 days by default', async () => {
    const { calls, section } = await open();
    expect(await within(section).findByRole('img', { name: '2 new and 1 closed in 30 days' })).toBeInTheDocument();
    const q = changesCall(calls)[0]!;
    expect(q.get('to')).toBe(dayString(new Date()));
    expect(q.get('from')).toBe(dayString(new Date(), 29));
  });

  it('changes the period from the list, and takes two days of its own', async () => {
    const { calls, section } = await open();
    await within(section).findByText(/2 new \(5 before\)/);
    await userEvent.selectOptions(within(section).getByLabelText('Period'), '7');
    await waitFor(() => expect(changesCall(calls).some((q) => q.get('from') === dayString(new Date(), 6))).toBe(true));

    await userEvent.selectOptions(within(section).getByLabelText('Period'), 'custom');
    const from = within(section).getByLabelText('From');
    await userEvent.clear(from);
    await userEvent.type(from, '2026-10-01');
    await waitFor(() => expect(changesCall(calls).some((q) => q.get('from') === '2026-10-01')).toBe(true));
  });

  it('says so when a list is cut and when a list is empty', async () => {
    const { section } = await open({ appChanges: { ...changes, closed: [], truncated: ['new'] } });
    await within(section).findByText(/2 new \(5 before\)/);
    expect(within(section).getByText('The list shows the first 2; the number above is exact.')).toBeInTheDocument();
    await userEvent.click(within(section).getByRole('tab', { name: 'Closed (1)' }));
    expect(await within(section).findByText('None in this period.')).toBeInTheDocument();
  });

  it('reports a failed load, and leaves the rest of the page alone', async () => {
    const { section } = await open({ appChanges: 'error' });
    expect(await within(section).findByText('What changed could not be loaded.', undefined, { timeout: 4000 })).toBeInTheDocument();
    // the neighbours still render: the summary and the compliance section are not taken down by it
    expect(screen.getByRole('heading', { name: 'Compliance', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Where it stands', level: 2 })).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    const { section } = await open();
    await within(section).findByText(/2 new \(5 before\)/);
    expect(await axe(section)).toHaveNoViolations();
  });
});
