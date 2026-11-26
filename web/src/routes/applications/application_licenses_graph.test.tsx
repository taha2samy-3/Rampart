import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { appPage, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const APP_ID = '01a1e562-93be-7b79-9762-615a097742e5';

const appWithTags = appPage(1, {
  id: APP_ID,
  slug: 'rampart-demo-app',
  name: 'Rampart Demo App',
  version: '1.4.0',
  tags: ['production', 'backend', 'pci-dss'],
});

const componentsList = [
  {
    name: 'log4j-core',
    version: '2.14.1',
    purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
    type: 'maven',
    license: 'Apache-2.0',
    vulnerabilities: 1,
  },
  {
    name: 'react',
    version: '18.2.0',
    purl: 'pkg:npm/react@18.2.0',
    type: 'npm',
    license: 'MIT',
    vulnerabilities: 0,
  },
  {
    name: 'gpl-tool',
    version: '1.0.0',
    purl: 'pkg:generic/gpl-tool@1.0.0',
    type: 'generic',
    license: 'GPL-3.0',
    vulnerabilities: 0,
  },
];

const risk = (r: Partial<Record<'critical' | 'high' | 'medium' | 'low', number>> = {}) => ({ critical: 0, high: 0, medium: 0, low: 0, ...r });
const LOG4J = 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1';

// app -> log4j-core (critical), react ; react -> loose-envify
const mockGraph = {
  asset_id: APP_ID,
  format: 'CycloneDX',
  spec_version: '1.5',
  root: 'app',
  has_dependencies: true,
  total_components: 4,
  direct_components: 2,
  transitive_components: 1,
  unreachable_components: 0,
  nodes: [
    { id: 'app', name: 'Rampart Demo App', version: '1.4.0', root: true, depth: 0, vulnerabilities: risk() },
    { id: LOG4J, name: 'log4j-core', version: '2.14.1', purl: LOG4J, direct: true, depth: 1, licenses: ['Apache-2.0'], vulnerabilities: risk({ critical: 1, high: 1 }) },
    { id: 'pkg:npm/react@18.2.0', name: 'react', version: '18.2.0', purl: 'pkg:npm/react@18.2.0', direct: true, depth: 1, vulnerabilities: risk() },
    { id: 'pkg:npm/loose-envify@1.4.0', name: 'loose-envify', version: '1.4.0', purl: 'pkg:npm/loose-envify@1.4.0', depth: 2, vulnerabilities: risk({ low: 1 }) },
  ],
  edges: [
    { from: 'app', to: LOG4J },
    { from: 'app', to: 'pkg:npm/react@18.2.0' },
    { from: 'pkg:npm/react@18.2.0', to: 'pkg:npm/loose-envify@1.4.0' },
  ],
};

function stubGraph(body: unknown, status = 200) {
  mockFetch({ loggedIn: true, appPages: { [APP_ID]: appWithTags }, inventory: { components: componentsList } });
  const inner = globalThis.fetch;
  vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes('/sbom/graph')) {
      return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': status === 200 ? 'application/json' : 'application/problem+json' } }));
    }
    return inner(input, init);
  });
}

describe('Application Route: Tags, Licenses & Dependency Graph Tabs', () => {
  it('renders application version and tags in the header, as plain text', async () => {
    mockFetch({
      loggedIn: true,
      appPages: { [APP_ID]: appWithTags },
      inventory: { components: componentsList },
    });

    renderApp(`/applications/${APP_ID}`);

    expect(await screen.findByText('Rampart Demo App')).toBeInTheDocument();
    expect(screen.getByText('v1.4.0')).toBeInTheDocument();
    expect(screen.getByText('production, backend, pci-dss')).toBeInTheDocument();
  });

  it('navigates to Licenses tab and groups components by license and risk', async () => {
    mockFetch({
      loggedIn: true,
      appPages: { [APP_ID]: appWithTags },
      inventory: { components: componentsList },
    });

    renderApp(`/applications/${APP_ID}?tab=licenses`);

    // Should display summary metrics
    expect(await screen.findByText('Unique Licenses')).toBeInTheDocument();
    expect(screen.getAllByText('Apache-2.0').length).toBeGreaterThan(0);
    expect(screen.getAllByText('MIT').length).toBeGreaterThan(0);
    expect(screen.getAllByText('GPL-3.0').length).toBeGreaterThan(0);

    // Verify Copyleft and Permissive badges
    expect(screen.getByText('Copyleft')).toBeInTheDocument();
    expect(screen.getAllByText('Permissive')).toHaveLength(3);

    // Click View Packages for Apache-2.0
    const viewButtons = screen.getAllByRole('button', { name: /View Packages/i });
    expect(viewButtons.length).toBeGreaterThan(0);
    await userEvent.click(viewButtons[0]!);

    expect(screen.getAllByText('log4j-core').length).toBeGreaterThan(0);
  });

  it('draws the dependency tree, marks what has findings, and shows how a component is reached', async () => {
    stubGraph(mockGraph);
    renderApp(`/applications/${APP_ID}?tab=graph`);

    // a sentence, not tiles: the counts come from the edges
    expect(await screen.findByText(/4 components: 2 the application uses directly and 1 it reaches through them/)).toBeInTheDocument();
    expect(screen.getByText(/2 components have open findings\./)).toBeInTheDocument();

    const tree = screen.getByRole('tree', { name: 'Dependencies' });
    // the first levels are open: the root and its two dependencies
    const log4j = within(tree).getByRole('treeitem', { name: /log4j-core 2\.14\.1, 2 open findings, worst Critical/ });
    expect(within(tree).getByRole('treeitem', { name: 'react 18.2.0' })).toHaveAttribute('aria-expanded', 'false');
    expect(within(tree).queryByRole('treeitem', { name: /loose-envify/ })).not.toBeInTheDocument();

    // the keyboard opens a branch and selects: ArrowRight on react opens it
    within(tree).getByRole('treeitem', { name: 'react 18.2.0' }).focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(await within(tree).findByRole('treeitem', { name: /loose-envify 1\.4\.0, 1 open finding, worst Low/ })).toBeInTheDocument();

    await userEvent.click(log4j);
    const inspector = screen.getByRole('complementary', { name: 'Selected component' });
    expect(within(inspector).getByText('Used directly by the application.')).toBeInTheDocument();
    expect(within(inspector).getByText('Critical')).toBeInTheDocument();
    expect(within(inspector).getByText('How the application reaches it')).toBeInTheDocument();

    // the drawing, the toolbar and the inspector pass the accessibility checks, in both views
    expect(await axe(tree.closest('div[class*="grid"]') ?? tree)).toHaveNoViolations();
    await userEvent.click(screen.getByRole('button', { name: 'List' }));
    expect(await axe(screen.getByRole('tree', { name: 'Dependencies' }))).toHaveNoViolations();
  });

  it('finds a component by name and opens the way to it', async () => {
    stubGraph(mockGraph);
    renderApp(`/applications/${APP_ID}?tab=graph`);
    await screen.findByRole('tree', { name: 'Dependencies' });
    await userEvent.type(screen.getByRole('searchbox', { name: 'Find a component' }), 'loose');
    await userEvent.click(await screen.findByRole('button', { name: /loose-envify/ }));
    const tree = screen.getByRole('tree', { name: 'Dependencies' });
    expect(within(tree).getByRole('treeitem', { name: /loose-envify/ })).toHaveAttribute('aria-selected', 'true');
    expect(within(screen.getByRole('complementary', { name: 'Selected component' })).getByText('Reached through other components, 2 levels down.')).toBeInTheDocument();
  });

  it('shows only the paths that lead to findings, and the same tree as a list', async () => {
    stubGraph(mockGraph);
    renderApp(`/applications/${APP_ID}?tab=graph`);
    await screen.findByRole('tree', { name: 'Dependencies' });
    await userEvent.click(screen.getByRole('checkbox', { name: 'Only paths with open findings' }));
    const tree = screen.getByRole('tree', { name: 'Dependencies' });
    expect(within(tree).getByRole('treeitem', { name: /loose-envify/ })).toBeInTheDocument();
    expect(within(tree).getByRole('treeitem', { name: /log4j-core/ })).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'List' }));
    const list = screen.getByRole('tree', { name: 'Dependencies' });
    expect(within(list).getAllByRole('treeitem')).toHaveLength(4); // app, log4j-core, react, loose-envify
  });

  it('says so when the SBOM states no dependencies, instead of drawing a flat list', async () => {
    stubGraph({ ...mockGraph, has_dependencies: false, edges: [], root: '', direct_components: 0, transitive_components: 0 });
    renderApp(`/applications/${APP_ID}?tab=graph`);
    expect(await screen.findByText('This SBOM has no dependency graph')).toBeInTheDocument();
    expect(screen.getByText(/lists 4 components but not what depends on what/)).toBeInTheDocument();
    expect(screen.queryByRole('tree')).not.toBeInTheDocument();
  });

  it('tells where the root is not linked and which components are not reached', async () => {
    stubGraph({ ...mockGraph, inferred_root: true, unreachable_components: 2 });
    renderApp(`/applications/${APP_ID}?tab=graph`);
    expect(await screen.findByText(/does not say what the application itself depends on/)).toBeInTheDocument();
    expect(screen.getByText('2 components are not reached from the application and are not drawn.')).toBeInTheDocument();
  });

  it('asks for an SBOM when there is none, and offers a retry when the request fails', async () => {
    stubGraph({ type: 'https://rampart.aspm.dev/problems/not-found', title: 'SBOM not found', status: 404 }, 404);
    renderApp(`/applications/${APP_ID}?tab=graph`);
    expect(await screen.findByText('No SBOM for this application yet')).toBeInTheDocument();
    expect(screen.getByText(/rampart sbom upload bom\.json --parser cyclonedx/)).toBeInTheDocument();
  });

  it('shows a failure with a retry', async () => {
    stubGraph({ type: 'https://rampart.aspm.dev/problems/internal', title: 'Boom', status: 500 }, 500);
    renderApp(`/applications/${APP_ID}?tab=graph`);
    expect(await screen.findByText('The dependency graph did not load')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
});
