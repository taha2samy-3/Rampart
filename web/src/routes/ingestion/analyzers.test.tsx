import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { analyzer, analyzerEvent, analyzerKey, matcher, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

async function openTab() {
  const view = renderApp('/ingestion');
  await userEvent.click(await screen.findByRole('tab', { name: 'Analyzers' }));
  return view;
}

const refused = analyzer({ name: 'broken', scope: 'tenant', namespace: 'acme', ready: false, error: 'spec.protocol: "http" is not supported', target: undefined });

describe('the Analyzers tab', () => {
  it('lists the services and the built-in matcher, each with its kind, where it runs and its status', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer(), matcher(), refused] });
    const { container } = await openTab();
    const table = await screen.findByRole('table', { name: 'Analyzers' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(3);

    const svc = rows.find((r) => within(r).queryByText('sonatype-oss-index'))!;
    expect(within(svc).getByText('Service')).toBeInTheDocument();
    expect(within(svc).getByText('sonatype-analyzer.rampart-system.svc:9090')).toBeInTheDocument();
    expect(within(svc).getByText('Ready')).toBeInTheDocument();
    expect(within(svc).getByText('Not tested yet')).toBeInTheDocument();

    const mat = rows.find((r) => within(r).queryByText('default'))!;
    expect(within(mat).getByText('Built-in matcher')).toBeInTheDocument();
    expect(within(mat).getByText('hybrid')).toBeInTheDocument();

    const bad = rows.find((r) => within(r).queryByText('broken'))!;
    expect(within(bad).getByText('Refused')).toBeInTheDocument();
    expect(within(bad).getByText(/This tenant, acme/)).toBeInTheDocument();

    expect(screen.getByText('3 analyzers: 2 services, 1 built-in. 0 failed the last test.')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('says when analyzers run, and that a failing one closes nothing', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer()] });
    await openTab();
    const note = await screen.findByRole('note');
    expect(note).toHaveTextContent('every uploaded SBOM');
    expect(note).toHaveTextContent('when you ask');
    expect(note).toHaveTextContent('on a schedule');
    expect(note).toHaveTextContent('fails closes no finding');
  });

  it('says which settings of the built-in matcher change what it matches, and which do not yet', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [matcher(), analyzer()] });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /default/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    expect(within(insp).getByText(/do not change what it matches yet/)).toBeInTheDocument();
    // a service has no such note
    await userEvent.click(screen.getByRole('button', { name: /sonatype-oss-index/ }));
    expect(within(insp).queryByText(/do not change what it matches yet/)).toBeNull();
  });

  it('filters by kind and finds an analyzer by a word', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer(), matcher()] });
    await openTab();
    const table = await screen.findByRole('table', { name: 'Analyzers' });
    await userEvent.type(screen.getByRole('searchbox', { name: 'Find an analyzer' }), 'sonatype');
    expect(within(table).getByText('sonatype-oss-index')).toBeInTheDocument();
    expect(within(table).queryByText('default')).toBeNull();
    await userEvent.clear(screen.getByRole('searchbox', { name: 'Find an analyzer' }));
    await userEvent.type(screen.getByRole('searchbox', { name: 'Find an analyzer' }), 'nothing-like-this');
    expect(await screen.findByText('No analyzer matches')).toBeInTheDocument();
  });

  it('is empty with a way forward when the server has none', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [] });
    const { container } = await openTab();
    expect(await screen.findByText('No analyzers yet')).toBeInTheDocument();
    expect(screen.getByText(/ClusterExternalAnalyzer, ExternalAnalyzer, ClusterSBOMAnalyzer or SBOMAnalyzer/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('says so when the analyzers cannot be loaded', { timeout: 15000 }, async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: 'error' });
    await openTab();
    expect(await screen.findByRole('alert', {}, { timeout: 8000 })).toHaveTextContent('The analyzers could not be loaded');
    expect(screen.queryByRole('table', { name: 'Analyzers' })).toBeNull();
  });

  it('shows how a service is set up and the reason a refused resource was refused', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer({ secure: true, timeout_seconds: 30 }), refused] });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    expect(within(insp).getByText('Encrypted with TLS')).toBeInTheDocument();
    expect(within(insp).getByText('30 seconds')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /broken/ }));
    expect(within(insp).getByText('Refused by the server')).toBeInTheDocument();
    expect(within(insp).getByText('spec.protocol: "http" is not supported')).toBeInTheDocument();
  });

  it('shows the matcher settings in words, not as a raw object', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [matcher()] });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /default/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    expect(within(insp).getByText('OSV, GitHub advisories')).toBeInTheDocument();
    expect(within(insp).getByText('0 3 * * *')).toBeInTheDocument();
    expect(within(insp).getByText('Skipped')).toBeInTheDocument();
    expect(within(insp).getByText('Direct and transitive')).toBeInTheDocument();
  });

  it('an administrator tests an analyzer; the result and the history show it, and the list remembers it', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer()] });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    expect(await within(insp).findByText(/Nothing is recorded yet/)).toBeInTheDocument();

    await userEvent.click(within(insp).getByRole('button', { name: 'Test' }));
    expect(await within(insp).findByText('0.1.0', { selector: 'span.font-mono' })).toBeInTheDocument();
    const post = calls.find((c) => c.method === 'POST' && c.url === '/api/v1/analyzers/test')!;
    expect(JSON.parse(post.body!)).toEqual({ kind: 'external', scope: 'cluster', namespace: '', name: 'sonatype-oss-index' });

    // The history lists the test that was just recorded, and the row now says what it found.
    await waitFor(() => expect(within(insp).queryByText(/Nothing is recorded yet/)).toBeNull());
    expect(within(insp).getByText('Test worked')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Analyzers' });
    await waitFor(() => expect(within(table).getByText('Test worked')).toBeInTheDocument());
  });

  it('a test that fails says why, in the result, the history and the row', async () => {
    mockFetch({
      loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer()],
      analyzerTest: { ok: false, outcome: 'failed', message: 'Could not reach sonatype-analyzer.rampart-system.svc:9090: no answer within 1m0s', latency_ms: 60000 },
    });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    await userEvent.click(within(insp).getByRole('button', { name: 'Test' }));
    expect((await within(insp).findAllByText(/no answer within 1m0s/)).length).toBeGreaterThanOrEqual(2);
    expect(within(insp).getByText('Test failed')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Analyzers' });
    await waitFor(() => expect(within(table).getByText('Test failed')).toBeInTheDocument());
    expect(screen.getByText(/1 failed the last test/)).toBeInTheDocument();
  });

  it('a person who is not an administrator can read the analyzers but not test them', async () => {
    mockFetch({ loggedIn: true, role: 'triager', runs: [], analyzers: [analyzer()] });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    expect(within(insp).getByRole('button', { name: 'Test' })).toBeDisabled();
    expect(within(insp).getByText('Only an administrator can test an analyzer.')).toBeInTheDocument();
  });

  it('when the test cannot run at all, the inspector says so and keeps the analyzer selected', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer()], analyzerTest: 500 });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    await userEvent.click(within(insp).getByRole('button', { name: 'Test' }));
    expect(await within(insp).findByRole('alert')).toHaveTextContent('The test could not be run');
    expect(within(insp).getByRole('button', { name: 'Test' })).toBeEnabled();
  });

  it('lists an earlier history, newest first, with who ran it', async () => {
    const a = analyzer();
    mockFetch({
      loggedIn: true, role: 'admin', runs: [], analyzers: [a],
      analyzerEvents: {
        [analyzerKey(a)]: [
          analyzerEvent(2, { outcome: 'failed', message: 'It answered but says it is not serving: warming up', actor: 'user:grace' }),
          analyzerEvent(1, { actor: 'user:ada', created_at: '2026-11-10T09:00:00Z' }),
        ],
      },
    });
    const { container } = await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    const items = await within(insp).findAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(within(items[0]!).getByText('Test failed')).toBeInTheDocument();
    expect(within(items[0]!).getByText(/by user:grace/)).toBeInTheDocument();
    expect(within(items[1]!).getByText('Test worked')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('an administrator asks one analyzer to analyse every SBOM, and is told how many were queued', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer()], analyzerAnalyze: 12 });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    await userEvent.click(within(insp).getByRole('button', { name: 'Analyze every SBOM' }));
    expect(await within(insp).findByText('12 analyses queued. They run in the background.')).toBeInTheDocument();
    const post = calls.find((c) => c.method === 'POST' && c.url === '/api/v1/analyzers/analyze')!;
    expect(JSON.parse(post.body!)).toEqual({ kind: 'external', scope: 'cluster', namespace: '', name: 'sonatype-oss-index' });
  });

  it('says so when nothing was queued, and when analysis is switched off on the server', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer()], analyzerAnalyze: 0 });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    await userEvent.click(within(insp).getByRole('button', { name: 'Analyze every SBOM' }));
    expect(await within(insp).findByText(/Nothing was queued/)).toBeInTheDocument();
  });

  it('shows the server refusing to queue when analysis is switched off', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer()], analyzerAnalyze: 409 });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    await userEvent.click(within(insp).getByRole('button', { name: 'Analyze every SBOM' }));
    const alert = await within(insp).findByRole('alert');
    expect(alert).toHaveTextContent('The analyses could not be queued');
    expect(alert).toHaveTextContent('analysis.enabled');
  });

  it('only an administrator can ask for it, and not for an analyzer that is off or refused', async () => {
    mockFetch({ loggedIn: true, role: 'triager', runs: [], analyzers: [analyzer(), analyzer({ name: 'off', enabled: false }), refused] });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    expect(within(insp).getByRole('button', { name: 'Analyze every SBOM' })).toBeDisabled();
  });

  it('is not offered for a switched-off analyzer even to an administrator', async () => {
    mockFetch({ loggedIn: true, role: 'admin', runs: [], analyzers: [analyzer({ name: 'off', enabled: false }), refused] });
    await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /off/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    expect(within(insp).getByRole('button', { name: 'Analyze every SBOM' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: /broken/ }));
    expect(within(insp).getByRole('button', { name: 'Analyze every SBOM' })).toBeDisabled();
  });

  it('lists an analysis the server ran in the history, as an analysis and not as a test', async () => {
    const a = analyzer();
    mockFetch({
      loggedIn: true, role: 'admin', runs: [], analyzers: [a],
      analyzerEvents: {
        [analyzerKey(a)]: [
          analyzerEvent(5, { event: 'analysis', outcome: 'failed', message: 'The analyzer failed on attempt 5 of 5: connection refused. It will not be retried; its findings are kept as they were', actor: undefined }),
          analyzerEvent(4, { event: 'analysis', message: 'Analysed 212 components: 7 findings, 2 new, 1 no longer reported', actor: undefined }),
        ],
      },
    });
    const { container } = await openTab();
    await userEvent.click(await screen.findByRole('button', { name: /sonatype-oss-index/ }));
    const insp = screen.getByRole('complementary', { name: 'Analyzer details' });
    const items = await within(insp).findAllByRole('listitem');
    expect(within(items[0]!).getByText('Analysis failed')).toBeInTheDocument();
    expect(within(items[0]!).getByText(/its findings are kept as they were/)).toBeInTheDocument();
    expect(within(items[1]!).getByText('Analysis finished')).toBeInTheDocument();
    expect(within(items[1]!).getByText(/Analysed 212 components/)).toBeInTheDocument();
    // the row says what the last thing was
    const table = screen.getByRole('table', { name: 'Analyzers' });
    expect(within(table).getByText('Analysis failed')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });
});
