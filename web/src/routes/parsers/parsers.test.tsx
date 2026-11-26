import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import type { ParserDescriptor } from '@/api/types';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const parser = (over: Partial<ParserDescriptor>): ParserDescriptor => ({
  id: 'cluster:sarif', name: 'sarif Parser', kind: 'parser', version: '2.1.0', support_level: 'cluster', description: 'Streaming SARIF 2.1.0 parser',
  category: 'sast', family: 'report', runtime: 'wasm', origin: 'cluster', module: 'sarif', status: 'ready', ...over,
});

const PARSERS: ParserDescriptor[] = [
  parser({ last_run: { id: 'run-1', status: 'completed', at: '2026-11-19T10:00:00Z' }, last_success: '2026-11-19T10:00:00Z' }),
  parser({ id: 'cluster:semgrep', name: 'semgrep Parser', module: 'semgrep', status: 'module_missing', unavailable: 'its WASM module is not installed on this server (parsers.delivery in the chart)' }),
  parser({ id: 'cluster:bandit', name: 'bandit Parser', runtime: 'lua', module: undefined, last_run: { id: 'run-2', status: 'failed', error: 'parse_error', at: '2026-11-18T09:00:00Z' }, last_success: '2026-11-10T09:00:00Z' }),
  parser({ id: 'cluster:broken', name: 'broken Parser', runtime: 'wasm', module: undefined, status: 'refused', error: 'spec.detect: no filename or content probe' }),
  parser({ id: 'cluster:sbom-cyclonedx', name: 'cyclonedx SBOM Parser', family: 'sbom', category: 'sca', module: 'sbom-cyclonedx', description: 'CycloneDX SBOM reader' }),
  parser({ id: 'cluster:sbom-spdx', name: 'spdx SBOM Parser', family: 'sbom', category: 'sca', module: 'sbom-spdx', status: 'module_missing', unavailable: 'its WASM module is not installed on this server (parsers.delivery in the chart)' }),
  parser({ id: 'cluster:sbom-openvex', name: 'openvex SBOM Parser', family: 'sbom', category: 'vex', module: 'sbom-openvex', description: 'OpenVEX 0.2 exploitability assertions reader' }),
];

describe('the Parsers page', () => {
  it('is in the sidebar on its own, and has three tabs: parsers, SBOM parsers and analyzers', async () => {
    mockFetch({ loggedIn: true, parsers: PARSERS, analyzers: [] });
    renderApp('/parsers');
    const nav = await screen.findByRole('navigation');
    expect(within(nav).getByRole('link', { name: 'Parsers' })).toHaveAttribute('href', '/parsers');
    expect(await screen.findByRole('heading', { level: 1, name: 'Parsers and analyzers' })).toBeInTheDocument();
    const tabs = screen.getAllByRole('tab').map((t) => t.textContent);
    expect(tabs).toEqual(['Parsers', 'SBOM parsers', 'Analyzers']);
  });

  it('Ingestion no longer holds the parsers or the analyzers', async () => {
    mockFetch({ loggedIn: true, runs: [] });
    renderApp('/ingestion');
    await screen.findByRole('heading', { level: 1, name: 'Ingest runs' });
    expect(screen.queryByRole('tab', { name: /Parsers/ })).toBeNull();
    expect(screen.queryByRole('tab', { name: 'Analyzers' })).toBeNull();
  });

  it('lists the report parsers only, each with its type, whether it is installed correctly and when it last worked', async () => {
    mockFetch({ loggedIn: true, parsers: PARSERS });
    const { container } = renderApp('/parsers');
    const table = await screen.findByRole('table', { name: 'Parsers' });
    const row = (name: string) => within(table).getByText(name).closest('tr')!;
    expect(within(table).queryByText('cyclonedx SBOM Parser')).toBeNull(); // an SBOM parser is on the other tab

    expect(within(row('sarif Parser')).getByText('WASM module')).toBeInTheDocument();
    expect(within(row('sarif Parser')).getByText('Ready')).toBeInTheDocument();
    expect(within(row('sarif Parser')).getByText('Completed')).toBeInTheDocument();
    expect(within(row('bandit Parser')).getByText('Lua script')).toBeInTheDocument();
    expect(within(row('bandit Parser')).getByText('Failed')).toBeInTheDocument(); // it last worked and failed
    expect(within(row('semgrep Parser')).getByText('Module missing')).toBeInTheDocument();
    expect(within(row('semgrep Parser')).getByText('Never used')).toBeInTheDocument();
    expect(within(row('broken Parser')).getByText('Refused')).toBeInTheDocument();
    expect(screen.getByText('4 installed: 2 ready, 2 with a problem.')).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('lists the SBOM parsers on their own tab, with the format each reads', async () => {
    mockFetch({ loggedIn: true, parsers: PARSERS });
    renderApp('/parsers');
    await userEvent.click(await screen.findByRole('tab', { name: 'SBOM parsers' }));
    const table = await screen.findByRole('table', { name: 'SBOM parsers' });
    expect(within(table).getByText('cyclonedx SBOM Parser')).toBeInTheDocument();
    expect(within(table).queryByText('sarif Parser')).toBeNull();
    const spdx = within(table).getByText('spdx SBOM Parser').closest('tr')!;
    expect(within(spdx).getByText('spdx')).toBeInTheDocument();
    expect(within(spdx).getByText('Module missing')).toBeInTheDocument();
    expect(within(table).getByText('openvex SBOM Parser')).toBeInTheDocument();
    expect(screen.getByText('3 installed: 2 ready, 1 with a problem.')).toBeInTheDocument();
  });

  it('the inspector says what is wrong, and when it last worked, with a link to the run', async () => {
    mockFetch({ loggedIn: true, parsers: PARSERS });
    renderApp('/parsers');
    await userEvent.click(await screen.findByRole('button', { name: /semgrep Parser/ }));
    const insp = screen.getByRole('complementary', { name: 'Parser details' });
    expect(within(insp).getByText('Module missing')).toBeInTheDocument();
    expect(within(insp).getByText(/its WASM module is not installed on this server/)).toBeInTheDocument();
    expect(within(insp).getByText(/Deliver the modules with parsers.delivery/)).toBeInTheDocument();
    expect(within(insp).getByText('semgrep', { selector: 'span.font-mono' })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /bandit Parser/ }));
    expect(within(insp).getByText('parse_error')).toBeInTheDocument();
    expect(within(insp).getByRole('link', { name: 'Open the run' })).toHaveAttribute('href', expect.stringContaining('sel=run-2'));
    expect(within(insp).getByText(/Last time it completed/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /broken Parser/ }));
    expect(within(insp).getByText('spec.detect: no filename or content probe')).toBeInTheDocument();
    expect(within(insp).getByText(/The server refused the resource/)).toBeInTheDocument();
  });

  it('finds a parser by a word, and says so when none matches', async () => {
    mockFetch({ loggedIn: true, parsers: PARSERS });
    renderApp('/parsers');
    const table = await screen.findByRole('table', { name: 'Parsers' });
    await userEvent.type(screen.getByRole('searchbox', { name: 'Find a parser' }), 'bandit');
    expect(within(table).getByText('bandit Parser')).toBeInTheDocument();
    expect(within(table).queryByText('sarif Parser')).toBeNull();
    await userEvent.clear(screen.getByRole('searchbox', { name: 'Find a parser' }));
    await userEvent.type(screen.getByRole('searchbox', { name: 'Find a parser' }), 'zzz');
    expect(await screen.findByText('No parser matches')).toBeInTheDocument();
  });

  it('filters report parsers by category sub-tabs', async () => {
    mockFetch({
      loggedIn: true,
      parsers: [
        ...PARSERS,
        parser({ id: 'cluster:gitleaks', name: 'gitleaks Parser', category: 'secrets' }),
      ],
    });
    renderApp('/parsers');
    const table = await screen.findByRole('table', { name: 'Parsers' });
    expect(within(table).getByText('sarif Parser')).toBeInTheDocument();
    expect(within(table).getByText('gitleaks Parser')).toBeInTheDocument();

    const secretsBtn = screen.getByRole('button', { name: /Secrets/ });
    await userEvent.click(secretsBtn);

    expect(within(table).getByText('gitleaks Parser')).toBeInTheDocument();
    expect(within(table).queryByText('sarif Parser')).toBeNull();

    const allBtn = screen.getByRole('button', { name: /All/ });
    await userEvent.click(allBtn);
    expect(within(table).getByText('sarif Parser')).toBeInTheDocument();
    expect(within(table).getByText('gitleaks Parser')).toBeInTheDocument();
  });

  it('is empty with a way forward when nothing is installed, and says so when the list cannot be loaded', async () => {
    mockFetch({ loggedIn: true, parsers: [] });
    renderApp('/parsers');
    expect(await screen.findByText('No parser is installed')).toBeInTheDocument();
    vi.unstubAllGlobals();
    mockFetch({ loggedIn: true, parsers: 'error' });
    renderApp('/parsers?tab=sbom');
    expect(await screen.findByRole('alert', {}, { timeout: 8000 })).toHaveTextContent('The parsers could not be loaded');
  }, 20000);

  it('the Analyzers tab shows the analyzers with a status icon beside each status', async () => {
    mockFetch({ loggedIn: true, analyzers: [{ kind: 'external', scope: 'cluster', name: 'sonatype', enabled: true, ready: true, target: 'a:1', updated_at: '2026-11-10T10:00:00Z' }] });
    renderApp('/parsers?tab=analyzers');
    const table = await screen.findByRole('table', { name: 'Analyzers' });
    expect(within(table).getByText('Ready')).toBeInTheDocument();
    expect(within(table).getByText('Not tested yet')).toBeInTheDocument();
  });
  // docs/50 step 3: a parser package's runtime, version, error and use are shown in the inspector of its mapping:
  // row, since /parsers already lists it; a package that failed to compile says why there.
  it('shows the package behind a mapping parser, with its compile error', async () => {
    mockFetch({
      loggedIn: true,
      parsers: [
        parser({ id: 'mapping:acme-dast', name: 'acme-dast', runtime: 'mapping', origin: 'tenant', module: undefined, status: 'refused', error: 'records: does not compile' }),
      ],
      packages: [
        { name: 'acme-dast', kind: 'parser', runtime: 'mapping', version: '0.2.0', egress: [], secrets: [], config: [], used_by: [], error: 'records: expression "$.alerts[*]" does not compile', updated_at: '2026-11-16T10:00:00Z' },
      ],
    });
    const { container } = renderApp('/parsers');
    await userEvent.click(await screen.findByRole('button', { name: /acme-dast/ }));
    const pkg = await screen.findByTestId('parser-package');
    expect(await within(pkg).findByText('0.2.0')).toBeInTheDocument();
    expect(within(pkg).getByText('mapping')).toBeInTheDocument();
    expect(within(pkg).getByText('Not used')).toBeInTheDocument();
    expect(within(pkg).getByText('records: expression "$.alerts[*]" does not compile')).toBeInTheDocument();
    expect(within(pkg).getByText(/Uploads that name acme-dast/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('shows no package section for a parser that is not a package', async () => {
    mockFetch({ loggedIn: true, parsers: PARSERS });
    renderApp('/parsers');
    await userEvent.click(await screen.findByRole('button', { name: /sarif Parser/ }));
    expect(screen.queryByTestId('parser-package')).toBeNull();
  });
});
