import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { app, appPage, mockFetch, overviewData, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const trend = Array.from({ length: 30 }, (_, i) => ({ day: `2026-10-${String(i + 1).padStart(2, '0')}`, value: 20 + (i % 7) }));

describe('overview', () => {
  it('opens with what changed and what is overdue, not with a row of numbers', async () => {
    mockFetch({ loggedIn: true, trend });
    const { container } = renderApp('/overview');
    expect(await screen.findByRole('heading', { name: 'What changed in the last day' })).toBeInTheDocument();
    expect(screen.getByText('12 new, 3 reopened, 7 fixed.')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Past their deadline' })).toBeInTheDocument();
    expect(screen.getByText('Hard-coded JWT signing secret')).toBeInTheDocument();
    expect(screen.getByText(/overdue by \d+ days/)).toBeInTheDocument();
    expect(screen.getByText('14 findings are past their deadline; the 1 longest overdue are listed.')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('says how the deadlines are going and what is open, in words', async () => {
    mockFetch({ loggedIn: true, trend });
    renderApp('/overview');
    expect(await screen.findByText('75% of findings were resolved within their deadline in the last 90 days.')).toBeInTheDocument();
    expect(screen.getByText('Open now: 2 critical, 5 high, 9 medium, 4 low.')).toBeInTheDocument();
  });

  it('draws the trend as an image with a text alternative and the numbers one click away', async () => {
    mockFetch({ loggedIn: true, trend });
    renderApp('/overview');
    const chart = await screen.findByRole('img', { name: /Open findings per day, from 20 on 2026-10-01 to \d+ on 2026-10-30/ });
    expect(chart).toBeInTheDocument();
    await userEvent.click(screen.getByText('Show the numbers'));
    expect(await screen.findAllByRole('row')).toHaveLength(31); // a header and a row per day
  });

  it('ranks the applications by risk and lists the ones not scanned lately', async () => {
    mockFetch({ loggedIn: true, trend });
    renderApp('/overview');
    const ranked = await screen.findByRole('heading', { name: 'Applications by risk' });
    const list = ranked.closest('section')!;
    const items = within(list).getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(within(items[0]!).getByRole('link', { name: 'Application 1' })).toHaveAttribute('href', '/applications/app-1');
    expect(within(items[0]!).getByText('2 critical, 5 high, 1 low')).toBeInTheDocument();
    const gaps = screen.getByRole('heading', { name: 'Not scanned lately' }).closest('section')!;
    expect(within(gaps).getByText('Never scanned')).toBeInTheDocument();
  });

  it('empty states say so plainly', async () => {
    mockFetch({
      loggedIn: true,
      overview: overviewData({ changes: { since: '2026-11-11T10:00:00Z', new: 0, reopened: 0, fixed: 0 }, open: { critical: 0, high: 0, medium: 0, low: 0 }, overdue: [], overdue_total: 0, sla: { within: 0, late: 0, breached: 0 }, top_apps: [], coverage_gaps: [] }),
    });
    renderApp('/overview');
    expect(await screen.findByText('Nothing is past its deadline.')).toBeInTheDocument();
    expect(screen.getByText('No application has an open finding.')).toBeInTheDocument();
    expect(screen.getByText('Every application was scanned in the last 14 days.')).toBeInTheDocument();
    expect(screen.getByText('No finding has had a deadline yet.')).toBeInTheDocument();
    expect(screen.queryByText('See the new findings')).toBeNull();
  });

  it('a 500 shows the problem with its request id and a retry', async () => {
    mockFetch({ loggedIn: true, overview: 'error' });
    const { container } = renderApp('/overview');
    expect(await screen.findByText('The overview could not be loaded', undefined, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.getByText('req_ov')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe('applications', () => {
  it('lists applications with what is open, the risk, the deadlines past and the last scan', async () => {
    mockFetch({ loggedIn: true, apps: [app(1), app(2, { name: 'Ghost', open: { critical: 0, high: 0, medium: 0, low: 0 }, risk_score: 0, exposure_count: 0, sla_breached: 0, last_scan: undefined })] });
    const { container } = renderApp('/applications');
    const grid = await screen.findByRole('grid', { name: 'Applications' });
    const rows = within(grid).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByText('Application 1')).toBeInTheDocument();
    expect(within(rows[0]!).getByText('2 critical, 5 high, 1 low')).toBeInTheDocument();
    expect(within(rows[0]!).getByText('870')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('None open')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Never scanned')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('a row opens the application page, which says where it stands', async () => {
    const recent = new Date(Date.now() - 3_600_000).toISOString();
    const old = new Date(Date.now() - 45 * 86_400_000).toISOString();
    const scan_coverage = [
      { category: 'sast', scanners: ['semgrep'], last_scan: recent, open: { critical: 1, high: 2 } },
      { category: 'sca', scanners: [], open: {} },
      { category: 'iac', scanners: ['checkov'], last_scan: old, open: {} },
    ];
    mockFetch({ loggedIn: true, apps: [app(1)], appPages: { 'app-1': appPage(1, { scan_coverage }) } });
    const { history, container } = renderApp('/applications');
    await userEvent.click(await screen.findByText('Application 1'));
    await waitFor(() => expect(history.location.pathname).toBe('/applications/app-1'));
    expect(await screen.findByRole('heading', { name: 'Application 1', level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/2 critical, 5 high, 1 low\./)).toBeInTheDocument();
    expect(screen.getByText('Highest risk score: 870. 7 critical or high.')).toBeInTheDocument();
    expect(screen.getByText('60% of findings were resolved within their deadline in the last 90 days.')).toBeInTheDocument();
    // D93: the deadlines and the time to fix are bars whose parts are named in words beside them
    expect(screen.getByText('resolved in time')).toBeInTheDocument();
    expect(screen.getByText('still open past the deadline')).toBeInTheDocument();
    expect(screen.getByText('6.5 days on average, 4 fixed')).toBeInTheDocument();
    // the trend: one panel per band and the arrivals against the fixes, with the numbers in words
    expect(await screen.findByText(/^Today: \d+ critical, \d+ high/)).toBeInTheDocument();
    expect(screen.getByText(/new and \d+ fixed in \d+ weeks/)).toBeInTheDocument();
    expect(screen.getByText('Over 180 days')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'SQL injection in order search' })).toBeInTheDocument();
    expect(within(screen.getByRole('table', { name: 'By asset and scanner' })).getByText('semgrep')).toBeInTheDocument();
    // D101: one row per kind of testing; the gap and the stale scan are said in words, not only shown
    expect(screen.getByText('2 of 3 kinds of testing have run. Not scanned: Dependencies (SCA). Older than 30 days: Infrastructure as code.')).toBeInTheDocument();
    // the radar: neutral, fixed axis order, the gap named on its spoke; its label is the same sentence
    expect(screen.getByRole('img', { name: '2 of 3 kinds of testing have run. Not scanned: Dependencies (SCA).' })).toBeInTheDocument();
    expect(screen.getByText('not scanned')).toBeInTheDocument();
    const cov = screen.getByRole('table', { name: 'Scan coverage' });
    const sca = within(cov).getByText('Dependencies (SCA)').closest('tr')!;
    expect(within(sca).getByText('Not scanned')).toBeInTheDocument();
    const sast = within(cov).getByText('Code (SAST)').closest('tr')!;
    expect(within(sast).getByText('1 critical, 2 high')).toBeInTheDocument();
    expect(within(sast).getByRole('img', { name: '1 critical, 2 high' })).toBeInTheDocument();
    expect(within(within(cov).getByText('Infrastructure as code').closest('tr')!).getByText(/, stale$/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('an application that does not exist says so, and leads back to the list', async () => {
    mockFetch({ loggedIn: true, appPages: {} });
    renderApp('/applications/nope');
    expect(await screen.findByText('The application could not be loaded')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'All applications' })).toHaveAttribute('href', '/applications');
  });

  it('no applications yet says how they come', async () => {
    mockFetch({ loggedIn: true, apps: [] });
    renderApp('/applications');
    expect(await screen.findByText('No applications yet')).toBeInTheDocument();
  });

  it('a 500 shows the problem with its request id', async () => {
    mockFetch({ loggedIn: true, apps: 'error' });
    renderApp('/applications');
    expect(await screen.findByText('Applications could not be loaded', undefined, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.getByText('req_apps')).toBeInTheDocument();
  });
});
