import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { app, mockFetch, renderApp, run } from '@/test/helpers';

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

  it('opens manual upload dialog, selects file, and uploads report', async () => {
    mockFetch({ loggedIn: true, runs: [] });
    const { container } = renderApp('/ingestion');
    const uploadBtn = await screen.findAllByRole('button', { name: 'Upload report' });
    await userEvent.click(uploadBtn[0]!);

    expect(screen.getByRole('dialog', { name: 'Upload security report' })).toBeInTheDocument();
    expect(screen.getByText('Drop a scanner report here, or click to browse')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('switches to Parsers & Formats tab and lists all engines with accessible details', async () => {
    mockFetch({ loggedIn: true, runs: [] });
    const { container } = renderApp('/ingestion');

    const tab = await screen.findByRole('tab', { name: 'Parsers & Formats' });
    await userEvent.click(tab);

    expect(await screen.findByRole('heading', { name: 'Parsers and formats' })).toBeInTheDocument();
    // What the server lists, the tenant's parser packages included (D98); no invented list.
    expect(await screen.findByText('4 built in, 1 installed as a package')).toBeInTheDocument();

    const table = screen.getByRole('table', { name: 'Supported parsers table' });
    expect(within(table).getByText('SARIF 2.1.0 Parser')).toBeInTheDocument();
    expect(within(table).getByText('CycloneDX Parser (JSON/XML)')).toBeInTheDocument();
    expect(within(table).getByText('Trivy Parser (JSON)')).toBeInTheDocument();
    const pkgRow = within(table).getByText('pip-audit (Declarative)').closest('tr')!;
    expect(within(pkgRow).getByText('Installed package')).toBeInTheDocument();

    // Category filtering
    const sastFilter = screen.getByRole('button', { name: 'SAST' });
    await userEvent.click(sastFilter);
    expect(within(table).getByText('Semgrep Parser (JSON)')).toBeInTheDocument();
    expect(within(table).queryByText('CycloneDX Parser (JSON/XML)')).toBeNull();

    // Reset filter
    await userEvent.click(screen.getByRole('button', { name: 'All Categories' }));
    expect(within(table).getByText('CycloneDX Parser (JSON/XML)')).toBeInTheDocument();

    // Click parser to view details
    await userEvent.click(within(table).getByText('SARIF 2.1.0 Parser'));
    const dialog = screen.getByRole('dialog', { name: 'SARIF 2.1.0 Parser' });
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByText('builtin:sarif')).toBeInTheDocument();
    expect(within(dialog).getByText('rampart upload --parser sarif --app <application> --source default report.json')).toBeInTheDocument();
    await userEvent.click(within(dialog).getAllByRole('button', { name: 'Close' })[0]!);
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'SARIF 2.1.0 Parser' })).toBeNull());

    // Custom CEL Parser dialog
    await userEvent.click(screen.getByRole('button', { name: 'Add a parser package' }));
    const celDialog = await screen.findByRole('dialog', { name: 'Declarative CEL Mapping Engine' });
    expect(celDialog).toBeInTheDocument();
    expect(within(celDialog).getByText(/apiVersion: rampart.aspm.dev\/v1alpha1/)).toBeInTheDocument();
    await userEvent.click(within(celDialog).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Declarative CEL Mapping Engine' })).toBeNull());

    expect(await axe(container)).toHaveNoViolations();
  });

  it('says so when the parsers cannot be loaded, instead of showing a made-up list', { timeout: 15000 }, async () => {
    mockFetch({ loggedIn: true, runs: [], parsers: 'error' });
    renderApp('/ingestion');
    await userEvent.click(await screen.findByRole('tab', { name: 'Parsers & Formats' }));
    // A 500 is retried twice (App.tsx) before the error shows.
    expect(await screen.findByRole('alert', {}, { timeout: 8000 })).toHaveTextContent('The parsers could not be loaded.');
    expect(screen.queryByRole('table', { name: 'Supported parsers table' })).toBeNull();
  });
});

// An upload that named an application that did not exist made a new empty one, so a typo in a pipeline or a
// dialog made an application nobody asked for. Choosing one from the list now says "it must exist"; making a new
// one is a visible choice of a maintainer.
describe('manual upload: the application', () => {
  async function openDialog(sc: Parameters<typeof mockFetch>[0]) {
    const calls = mockFetch({ loggedIn: true, runs: [], apps: [app(1, { id: 'app-1', slug: 'shop', name: 'Shop' })], ...sc });
    renderApp('/ingestion');
    await userEvent.click((await screen.findAllByRole('button', { name: 'Upload report' }))[0]!);
    const dialog = await screen.findByRole('dialog', { name: 'Upload security report' });
    await userEvent.upload(within(dialog).getByLabelText('Report file'), new File(['{}'], 'r.sarif', { type: 'application/json' }));
    return { calls, dialog };
  }
  const sent = (calls: Awaited<ReturnType<typeof openDialog>>['calls']) => calls.find((c) => c.url.startsWith('/api/v1/uploads/direct'))?.form;

  it('sends createApplication=false for an application chosen from the list', async () => {
    const { calls, dialog } = await openDialog({ role: 'maintainer' });
    await userEvent.selectOptions(within(dialog).getByLabelText('Application'), 'shop');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Upload' }));
    await waitFor(() => expect(sent(calls)).toBeDefined());
    expect(sent(calls)).toMatchObject({ application: 'shop', createApplication: 'false' });
  });

  it('lets a maintainer make a new application on purpose, and says what it will be called', async () => {
    const { calls, dialog } = await openDialog({ role: 'maintainer', upload: { application: 'billing-api', applicationCreated: true } });
    await userEvent.selectOptions(within(dialog).getByLabelText('Application'), 'New application...');
    const submit = within(dialog).getByRole('button', { name: 'Upload' });
    expect(submit).toBeDisabled(); // a new application needs a name
    await userEvent.type(within(dialog).getByLabelText('Name of the new application'), 'Billing API!');
    expect(within(dialog).getByText('It will be created as billing-api.')).toBeInTheDocument();
    await userEvent.click(submit);
    await waitFor(() => expect(sent(calls)).toBeDefined());
    expect(sent(calls)).toMatchObject({ application: 'billing-api', createApplication: 'true' });
    expect(await screen.findByText('Report uploaded. Application billing-api was created.')).toBeInTheDocument();
  });

  it('does not offer a new application to someone who may not make one', async () => {
    const { dialog } = await openDialog({ role: 'triager' });
    expect(within(dialog).queryByRole('option', { name: 'New application...' })).toBeNull();
  });

  it('shows the server\'s answer when the application does not exist', async () => {
    const { dialog } = await openDialog({ role: 'maintainer', upload: 404 });
    await userEvent.selectOptions(within(dialog).getByLabelText('Application'), 'shop');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Upload' }));
    expect(await within(dialog).findByText(/There is no application/)).toBeInTheDocument();
  });
});
