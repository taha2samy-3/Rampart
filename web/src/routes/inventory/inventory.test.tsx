import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const asset = { id: 'a-1', name: 'shop', kind: 'repository', application_name: 'Shop', critical_findings: 1, high_findings: 2, medium_findings: 0, low_findings: 0, total_findings: 3, component_count: 2 };
const lodash = { name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20?type=x', type: 'npm', license: 'MIT', vulnerabilities: 2, asset_id: 'a-1', asset_name: 'shop', application_name: 'Shop', track: 'main' };

// An SBOM that was uploaded and parsed never showed here: the page asked for endpoints that did not exist, and
// every failure was turned into an empty list, so it said "No matching components found" and nothing else.
describe('Inventory', () => {
  it('lists the assets and the packages of the SBOMs, with links that the findings filter understands', async () => {
    mockFetch({ loggedIn: true, inventory: { assets: [asset], components: [lodash, { ...lodash, asset_id: 'a-2', asset_name: 'api' }] } });
    renderApp('/inventory');
    const assets = await screen.findByRole('table', { name: 'Assets table' });
    expect(within(assets).getByRole('link', { name: 'shop' }).getAttribute('href')).toContain('asset%3Aa-1');

    await userEvent.click(screen.getByRole('tab', { name: /SBOM Packages/ }));
    const comps = await screen.findByRole('table', { name: 'Components table' });
    expect(within(comps).getAllByText('lodash')).toHaveLength(2); // the same package on two assets is two rows
    expect(within(comps).getAllByText('MIT').length).toBe(2);
    // which application and which branch a package comes from: the same package on two tracks is two rows
    expect(within(comps).getAllByText('Shop').length).toBe(2);
    expect(within(comps).getAllByText('main').length).toBe(2);
    expect(within(comps).getAllByRole('link', { name: '2 open' })[0]!.getAttribute('href')).toContain('purl%3A%22pkg%3Anpm%2Flodash%22'); // no version, no qualifiers
  });

  it('shows the same package on each track of an asset, and filters by track or application', async () => {
    mockFetch({ loggedIn: true, inventory: { components: [lodash, { ...lodash, track: 'staging' }, { ...lodash, name: 'express', purl: 'pkg:npm/express@4.0.0', application_name: 'Billing' }] } });
    renderApp('/inventory');
    await userEvent.click(await screen.findByRole('tab', { name: /SBOM Packages/ }));
    const comps = await screen.findByRole('table', { name: 'Components table' });
    expect(within(comps).getAllByText('lodash')).toHaveLength(2);
    expect(within(comps).getByText('staging')).toBeInTheDocument();
    await userEvent.type(screen.getByPlaceholderText('Filter inventory...'), 'billing');
    expect(within(comps).queryByText('lodash')).toBeNull();
    expect(within(comps).getByText('express')).toBeInTheDocument();
  });

  it('says when the list is cut', async () => {
    mockFetch({ loggedIn: true, inventory: { components: [lodash], total: 900, truncated: true } });
    renderApp('/inventory');
    await userEvent.click(await screen.findByRole('tab', { name: /SBOM Packages/ }));
    expect(await screen.findByText('Showing 1 of 900 packages. Narrow the filter to see the rest.')).toBeInTheDocument();
  });

  it('reports a failed load instead of saying there is nothing', async () => {
    mockFetch({ loggedIn: true, inventory: { error: true } });
    renderApp('/inventory');
    expect(await screen.findByText('The inventory could not be loaded.', undefined, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.queryByText('No matching assets found')).toBeNull();
  });

  it('does not render an unimplemented component scan button', async () => {
    mockFetch({ loggedIn: true, inventory: { components: [lodash] } });
    renderApp('/inventory');
    await userEvent.click(await screen.findByRole('tab', { name: /SBOM Packages/ }));
    const comps = await screen.findByRole('table', { name: 'Components table' });
    expect(within(comps).queryByRole('button', { name: /Re-evaluate risk scores/i })).toBeNull();
  });

  it('has no accessibility violations', async () => {
    mockFetch({ loggedIn: true, inventory: { assets: [asset], components: [lodash] } });
    const { container } = renderApp('/inventory');
    await screen.findByRole('table', { name: 'Assets table' });
    expect(await axe(container)).toHaveNoViolations();
  });
});
