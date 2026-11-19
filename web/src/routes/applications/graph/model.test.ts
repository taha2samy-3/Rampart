import { describe, expect, it } from 'vitest';
import {
  allExpandable,
  buildIndex,
  initialExpanded,
  layoutTree,
  pathFromRoot,
  revealed,
  searchNodes,
  visibleTree,
  worstBand,
  ROW_HEIGHT,
  type GraphNodeData,
  type GraphResponse,
  type Risk,
} from './model';

const none: Risk = { critical: 0, high: 0, medium: 0, low: 0 };
const node = (id: string, risk: Partial<Risk> = {}, extra: Partial<GraphNodeData> = {}): GraphNodeData => ({
  id, name: id, version: '1', depth: -1, vulnerabilities: { ...none, ...risk }, ...extra,
});

function graph(nodes: GraphNodeData[], edges: [string, string][], root = 'app'): GraphResponse {
  return {
    asset_id: 'a', format: 'CycloneDX', spec_version: '1.5', root, nodes, edges: edges.map(([from, to]) => ({ from, to })),
    has_dependencies: edges.length > 0, total_components: nodes.length, direct_components: 0, transitive_components: 0, unreachable_components: 0,
  };
}

// app -> a, b ; a -> c ; b -> c ; c -> d (c has two parents, d has a critical finding)
const diamond = () =>
  graph(
    [node('app'), node('a'), node('b'), node('c'), node('d', { critical: 1 })],
    [['app', 'a'], ['app', 'b'], ['a', 'c'], ['b', 'c'], ['c', 'd']],
  );

describe('buildIndex', () => {
  it('lists what has findings first, the most severe first, then by name', () => {
    const idx = buildIndex(
      graph([node('app'), node('zeta', { high: 1 }), node('alpha'), node('crit', { critical: 1 }), node('beta')], [['app', 'zeta'], ['app', 'alpha'], ['app', 'crit'], ['app', 'beta']]),
    );
    expect(idx.children.get('app')).toEqual(['crit', 'zeta', 'alpha', 'beta']);
  });

  it('counts the components with findings below each one, and ends on a cycle', () => {
    const g = graph([node('app'), node('a'), node('b', { low: 1 })], [['app', 'a'], ['a', 'b'], ['b', 'a']]);
    const idx = buildIndex(g);
    expect(idx.riskBelow.get('app')).toBe(1);
    expect(idx.riskBelow.get('a')).toBe(1);
  });

  it('ignores an edge that names a component the response does not have', () => {
    const idx = buildIndex(graph([node('app'), node('a')], [['app', 'a'], ['app', 'ghost']]));
    expect(idx.children.get('app')).toEqual(['a']);
  });
});

describe('worstBand', () => {
  it('is the most severe band with an open finding, and null with none', () => {
    expect(worstBand({ ...none, medium: 2, low: 1 })).toBe('medium');
    expect(worstBand({ ...none, critical: 1, low: 9 })).toBe('critical');
    expect(worstBand(none)).toBeNull();
  });
});

describe('pathFromRoot', () => {
  it('is the shortest path, both ends included', () => {
    const idx = buildIndex(diamond());
    expect(pathFromRoot(idx, 'd')).toHaveLength(4);
    expect(pathFromRoot(idx, 'd')![0]).toBe('app');
    expect(pathFromRoot(idx, 'd')![3]).toBe('d');
    expect(pathFromRoot(idx, 'app')).toEqual(['app']);
  });

  it('is null for a component the root does not reach', () => {
    const idx = buildIndex(graph([node('app'), node('a'), node('lost')], [['app', 'a']]));
    expect(pathFromRoot(idx, 'lost')).toBeNull();
    expect(pathFromRoot(idx, 'nothing')).toBeNull();
  });
});

describe('visibleTree', () => {
  it('shows only what is open', () => {
    const idx = buildIndex(diamond());
    const closed = visibleTree(idx, new Set(), false);
    expect(closed.items.map((i) => i.id)).toEqual(['app']);
    const first = visibleTree(idx, initialExpanded(idx, 2), false);
    // c sits under both a and b, so it is drawn twice (once opened, once as a pointer); its own dependency d is not shown yet
    expect(first.items.map((i) => i.id).sort()).toEqual(['a', 'app', 'b', 'c', 'c']);
    expect(first.items.some((i) => i.id === 'd')).toBe(false);
    expect(first.items.find((i) => i.id === 'a')!.expandable).toBe(true);
  });

  it('opens a shared component once and points to it the second time', () => {
    const idx = buildIndex(diamond());
    const tree = visibleTree(idx, allExpandable(idx), false);
    const cs = tree.items.filter((i) => i.id === 'c');
    expect(cs).toHaveLength(2);
    expect(cs.filter((i) => i.again)).toHaveLength(1);
    expect(tree.items.filter((i) => i.id === 'd')).toHaveLength(1); // its subtree is not repeated
    expect(cs.find((i) => i.again)!.expandable).toBe(false);
  });

  it('stops at a cycle instead of looping', () => {
    const idx = buildIndex(graph([node('app'), node('a'), node('b')], [['app', 'a'], ['a', 'b'], ['b', 'a']]));
    const tree = visibleTree(idx, allExpandable(idx), false);
    expect(tree.items.length).toBeLessThan(10);
    expect(tree.items.some((i) => i.again)).toBe(true);
  });

  it('with onlyRisk keeps the branches that lead to a finding, opened', () => {
    const idx = buildIndex(
      graph([node('app'), node('clean'), node('vuln'), node('deep', { high: 1 }), node('fine')], [['app', 'clean'], ['app', 'vuln'], ['vuln', 'deep'], ['clean', 'fine']]),
    );
    const tree = visibleTree(idx, new Set(), true);
    expect(tree.items.map((i) => i.id).sort()).toEqual(['app', 'deep', 'vuln']);
  });

  it('stops at its limit and says so', () => {
    const many = Array.from({ length: 50 }, (_, i) => node(`n${i}`));
    const idx = buildIndex(graph([node('app'), ...many], many.map((n) => ['app', n.id] as [string, string])));
    const tree = visibleTree(idx, allExpandable(idx), false, 20);
    expect(tree.items).toHaveLength(20);
    expect(tree.truncated).toBe(true);
  });

  it('is empty when there is no root', () => {
    const idx = buildIndex(graph([node('a')], [], ''));
    expect(visibleTree(idx, new Set(), false).root).toBeNull();
  });
});

describe('layoutTree', () => {
  it('puts a level in a column, a leaf on its own row, and a parent between its children', () => {
    const idx = buildIndex(diamond());
    const tree = visibleTree(idx, allExpandable(idx), false);
    const size = layoutTree(tree);
    const app = tree.root!;
    expect(app.x).toBe(0);
    const [a, b] = app.children;
    expect(a!.x).toBeGreaterThan(app.x);
    expect(app.y).toBe((a!.y + b!.y) / 2);
    const ys = tree.items.filter((i) => i.children.length === 0).map((i) => i.y);
    expect(new Set(ys).size).toBe(ys.length); // no two leaves on one row
    expect(size.height).toBe(ys.length * ROW_HEIGHT);
  });
});

describe('revealed and searchNodes', () => {
  it('opens what lies on the way to a component', () => {
    const idx = buildIndex(diamond());
    const open = revealed(idx, 'd', new Set(['app']));
    const tree = visibleTree(idx, open, false);
    expect(tree.items.some((i) => i.id === 'd')).toBe(true);
  });

  it('finds by name or by purl, case blind, up to a limit', () => {
    const g = graph([node('app'), node('Axios', {}, { purl: 'pkg:npm/axios@1' }), node('lodash', {}, { purl: 'pkg:npm/lodash@4' })], []);
    expect(searchNodes(g, 'AXI').map((n) => n.id)).toEqual(['Axios']);
    expect(searchNodes(g, 'pkg:npm').map((n) => n.id)).toEqual(['Axios', 'lodash']);
    expect(searchNodes(g, 'pkg:npm', 1)).toHaveLength(1);
    expect(searchNodes(g, '  ')).toEqual([]);
  });
});
