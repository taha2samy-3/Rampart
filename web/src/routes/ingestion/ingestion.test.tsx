import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp, run } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('ingest runs', () => {
  it('empty: says what a run is and shows the upload command', async () => {
    mockFetch({ loggedIn: true, runs: [] });
    const { container } = renderApp('/ingestion');
    expect(await screen.findByText('No ingest runs yet')).toBeInTheDocument();
    expect(screen.getByText('rampart upload --source default semgrep.sarif')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('lists runs with source, status and what they found, and selecting one docks its details', async () => {
    const failed = run(2, { status: 'failed', error: 'sha256_mismatch', scanners: ['trivy'], stats: { parsed: 0, created: 0, updated: 0, untouched: 0, reactivated: 0, closed: 0, record_errors: 0, weak_fingerprints: 0 } });
    mockFetch({ loggedIn: true, runs: [[run(1), failed]] });
    const { container } = renderApp('/ingestion');
    const grid = await screen.findByRole('grid', { name: 'Ingest runs' });
    const rows = within(grid).getAllByRole('row').filter((r) => r.hasAttribute('data-row-id'));
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByText('github.com/acme/shop @ main')).toBeInTheDocument();
    expect(within(rows[0]!).getByText('Completed')).toBeInTheDocument();
    expect(within(rows[0]!).getByText('4 new, 2 closed')).toBeInTheDocument();

    await userEvent.click(rows[1]!);
    const insp = screen.getByRole('complementary', { name: 'Run details' });
    // A failed run says what went wrong in plain words, and keeps the stable code for support.
    await waitFor(() => expect(within(insp).getByText(/does not match the SHA-256/)).toBeInTheDocument());
    expect(within(insp).getByText('sha256_mismatch')).toBeInTheDocument();
    expect(within(insp).getAllByText('Failed').length).toBeGreaterThan(0);
    expect(await axe(container)).toHaveNoViolations();
  });

  it('shows how far a run in progress has got', async () => {
    mockFetch({ loggedIn: true, runs: [[run(1, { status: 'merging' })]] });
    renderApp('/ingestion?sel=00000001-aaaa-bbbb-cccc-000000000000');
    const insp = await screen.findByRole('complementary', { name: 'Run details' });
    await waitFor(() => expect(within(insp).getByText('Merging findings into the inventory.')).toBeInTheDocument());
    const steps = within(insp).getAllByRole('listitem');
    expect(steps.find((li) => li.getAttribute('aria-current') === 'step')).toHaveTextContent('Merging');
  });

  it('lists the records it could not read, with where they are, and offers the raw report to a maintainer', async () => {
    const bad = run(1, {
      status: 'completed_with_errors', error: 'record_errors', has_report: true,
      stats: { parsed: 3, created: 1, updated: 0, untouched: 1, reactivated: 0, closed: 0, record_errors: 2, weak_fingerprints: 0 },
      record_error_list: [{ where: 'results 2', message: 'the record does not have the shape this tool writes' }, { where: 'results 9', message: 'the record does not have the shape this tool writes' }],
    });
    mockFetch({ loggedIn: true, role: 'admin', runs: [[bad]] });
    renderApp('/ingestion?sel=00000001-aaaa-bbbb-cccc-000000000000');
    const insp = await screen.findByRole('complementary', { name: 'Run details' });
    expect(await within(insp).findByText('results 2')).toBeInTheDocument();
    expect(within(insp).getByText('results 9')).toBeInTheDocument();
    expect(within(insp).getByText(/nothing was closed/)).toBeInTheDocument();
    const link = within(insp).getByRole('link', { name: 'Download the raw report' });
    expect(link).toHaveAttribute('href', '/api/v1/runs/00000001-aaaa-bbbb-cccc-000000000000/report');
    expect(await axe(insp)).toHaveNoViolations();
  });

  it('does not offer the raw report below the maintainer role', async () => {
    mockFetch({ loggedIn: true, role: 'triager', runs: [[run(1, { has_report: true })]] });
    renderApp('/ingestion?sel=00000001-aaaa-bbbb-cccc-000000000000');
    const insp = await screen.findByRole('complementary', { name: 'Run details' });
    await within(insp).findByRole('heading', { name: 'Where it came from' });
    expect(within(insp).queryByRole('link', { name: 'Download the raw report' })).toBeNull();
  });

  it('says when retention removed the raw report, and offers no download', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [[run(1, { report_purged_at: '2026-10-02T03:17:00Z' })]] });
    renderApp('/ingestion?sel=00000001-aaaa-bbbb-cccc-000000000000');
    const insp = await screen.findByRole('complementary', { name: 'Run details' });
    expect(await within(insp).findByText(/raw report was removed on/)).toBeInTheDocument();
    expect(within(insp).queryByRole('link', { name: 'Download the raw report' })).toBeNull();
  });

  it('a pull-request run says it changed no finding', async () => {
    mockFetch({ loggedIn: true, runs: [[run(1, { ephemeral: true, context: { repository: 'github.com/acme/shop', branch: 'pr/12', commit: 'f00dbabe' } })]] });
    renderApp('/ingestion?sel=00000001-aaaa-bbbb-cccc-000000000000');
    expect(await screen.findByText(/no finding was changed/)).toBeInTheDocument();
  });

  it('loads more runs on request, using the cursor from the server', async () => {
    const calls = mockFetch({ loggedIn: true, runs: [[run(1)], [run(2)]] });
    renderApp('/ingestion');
    await userEvent.click(await screen.findByRole('button', { name: 'Load more runs' }));
    await waitFor(() => expect(screen.getAllByRole('row').filter((r) => r.hasAttribute('data-row-id'))).toHaveLength(2));
    expect(calls.some((c) => c.url.includes('cursor=1'))).toBe(true);
    expect(await screen.findByText('That is every run.')).toBeInTheDocument();
  });

  it('a deep link to a run outside the loaded pages fetches it directly', async () => {
    const old = run(9, { scanners: ['grype'] });
    const calls = mockFetch({ loggedIn: true, runs: [[run(1)], [old]] });
    renderApp(`/ingestion?sel=${old.id}`);
    const insp = await screen.findByRole('complementary', { name: 'Run details' });
    await waitFor(() => expect(within(insp).getByRole('heading', { name: 'grype' })).toBeInTheDocument());
    expect(calls.some((c) => c.url === `/api/v1/runs/${old.id}`)).toBe(true);
  });

  it('a 500 shows the problem with its request id and a retry', async () => {
    mockFetch({ loggedIn: true, runs: 'error' });
    const { container } = renderApp('/ingestion');
    expect(await screen.findByText('Ingest runs could not be loaded', undefined, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.getByText('req_runs')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});
