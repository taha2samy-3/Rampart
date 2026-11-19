import type { Band } from '@/lib/band';

/** One component as GET /api/v1/applications/{id}/sbom/graph sends it. */
export interface GraphNodeData {
  id: string;
  name: string;
  version?: string;
  purl?: string;
  scope?: string;
  licenses?: string[];
  root?: boolean;
  direct?: boolean;
  /** Length of the shortest path from the root; -1 when no path reaches it. */
  depth: number;
  vulnerabilities: Risk;
}

export interface Risk {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface GraphEdgeData {
  from: string;
  to: string;
  /** The document does not state this edge: it was added under a root that has no entry. */
  inferred?: boolean;
}

export interface GraphResponse {
  asset_id: string;
  format: string;
  spec_version: string;
  root: string;
  nodes: GraphNodeData[];
  edges: GraphEdgeData[];
  has_dependencies: boolean;
  inferred_root?: boolean;
  total_components: number;
  direct_components: number;
  transitive_components: number;
  unreachable_components: number;
  dangling_edges?: number;
}

const BAND_ORDER: Exclude<Band, 'info'>[] = ['critical', 'high', 'medium', 'low'];

export function riskTotal(r: Risk): number {
  return r.critical + r.high + r.medium + r.low;
}

/** The most severe band a component has open findings in, or null when it has none. */
export function worstBand(r: Risk): Exclude<Band, 'info'> | null {
  return BAND_ORDER.find((b) => r[b] > 0) ?? null;
}

export interface GraphIndex {
  root: string;
  byId: Map<string, GraphNodeData>;
  children: Map<string, string[]>;
  parents: Map<string, string[]>;
  /** How many components in the subtree of a component (itself included) have open findings. Cycle safe. */
  riskBelow: Map<string, number>;
}

const rank = (n: GraphNodeData) => {
  const w = worstBand(n.vulnerabilities);
  return w === null ? BAND_ORDER.length : BAND_ORDER.indexOf(w);
};

/** What a reader looks at first: components with findings, the most severe first, then by name. */
function byAttention(byId: Map<string, GraphNodeData>) {
  return (a: string, b: string) => {
    const na = byId.get(a)!;
    const nb = byId.get(b)!;
    return rank(na) - rank(nb) || riskTotal(nb.vulnerabilities) - riskTotal(na.vulnerabilities) || na.name.localeCompare(nb.name) || a.localeCompare(b);
  };
}

export function buildIndex(data: GraphResponse): GraphIndex {
  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const children = new Map<string, string[]>();
  const parents = new Map<string, string[]>();
  for (const e of data.edges) {
    if (!byId.has(e.from) || !byId.has(e.to)) continue;
    children.set(e.from, [...(children.get(e.from) ?? []), e.to]);
    parents.set(e.to, [...(parents.get(e.to) ?? []), e.from]);
  }
  const order = byAttention(byId);
  for (const list of children.values()) list.sort(order);
  for (const list of parents.values()) list.sort(order);

  // Subtree risk with a visited set per call: a component in a cycle counts once.
  const riskBelow = new Map<string, number>();
  for (const id of byId.keys()) {
    const seen = new Set<string>();
    const stack = [id];
    let n = 0;
    while (stack.length) {
      const cur = stack.pop()!;
      if (seen.has(cur)) continue;
      seen.add(cur);
      if (riskTotal(byId.get(cur)!.vulnerabilities) > 0) n++;
      for (const ch of children.get(cur) ?? []) stack.push(ch);
    }
    riskBelow.set(id, n);
  }
  return { root: data.root, byId, children, parents, riskBelow };
}

/** The shortest path from the root to a component, both ends included; null when none reaches it. */
export function pathFromRoot(index: GraphIndex, id: string): string[] | null {
  if (!index.root || !index.byId.has(id)) return null;
  const prev = new Map<string, string | null>([[index.root, null]]);
  const queue = [index.root];
  for (let i = 0; i < queue.length; i++) {
    const cur = queue[i]!;
    if (cur === id) break;
    for (const ch of index.children.get(cur) ?? []) {
      if (!prev.has(ch)) {
        prev.set(ch, cur);
        queue.push(ch);
      }
    }
  }
  if (!prev.has(id)) return null;
  const path: string[] = [];
  for (let cur: string | null | undefined = id; cur != null; cur = prev.get(cur)) path.unshift(cur);
  return path;
}

/** What is open when the view first appears: the root and the first levels below it. */
export function initialExpanded(index: GraphIndex, levels = 1): Set<string> {
  const open = new Set<string>();
  const walk = (id: string, depth: number) => {
    if (depth >= levels || open.has(id)) return;
    open.add(id);
    for (const ch of index.children.get(id) ?? []) walk(ch, depth + 1);
  };
  if (index.root) walk(index.root, 0);
  return open;
}

/** Everything that has children, for "expand all". */
export function allExpandable(index: GraphIndex): Set<string> {
  return new Set([...index.children.keys()]);
}

/** Opens the components on the way from the root to `id`, so it is on screen. */
export function revealed(index: GraphIndex, id: string, expanded: Set<string>): Set<string> {
  const path = pathFromRoot(index, id);
  if (!path) return expanded;
  const next = new Set(expanded);
  for (const step of path.slice(0, -1)) next.add(step);
  return next;
}

export function searchNodes(data: GraphResponse, query: string, limit = 8): GraphNodeData[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const out: GraphNodeData[] = [];
  for (const n of data.nodes) {
    if (n.name.toLowerCase().includes(q) || (n.purl ?? '').toLowerCase().includes(q)) {
      out.push(n);
      if (out.length === limit) break;
    }
  }
  return out;
}

/** One place a component is drawn. The same component under two parents is two of these. */
export interface TreeItem {
  key: string;
  id: string;
  depth: number;
  parentKey: string | null;
  children: TreeItem[];
  /** It has dependencies of its own. */
  expandable: boolean;
  expanded: boolean;
  /** Drawn before, further up: this one is a pointer to it and is not opened again (keeps a shared subtree from exploding). */
  again: boolean;
  x: number;
  y: number;
}

export interface VisibleTree {
  root: TreeItem | null;
  items: TreeItem[];
  truncated: boolean;
}

export const MAX_ITEMS = 1500;

/**
 * The tree as it is open: from the root, a component's dependencies are shown when it is expanded. A component is opened
 * at its first appearance only; where it appears again it is a pointer ("again"). With onlyRisk, a component is shown
 * only if it or something below it has open findings, and what is shown is opened.
 */
export function visibleTree(index: GraphIndex, expanded: Set<string>, onlyRisk: boolean, max = MAX_ITEMS): VisibleTree {
  if (!index.root || !index.byId.has(index.root)) return { root: null, items: [], truncated: false };
  const items: TreeItem[] = [];
  const opened = new Set<string>();
  let truncated = false;

  const make = (id: string, depth: number, parentKey: string | null, ancestors: Set<string>): TreeItem | null => {
    if (items.length >= max) {
      truncated = true;
      return null;
    }
    const kids = (index.children.get(id) ?? []).filter((c) => !onlyRisk || (index.riskBelow.get(c) ?? 0) > 0);
    const again = opened.has(id) || ancestors.has(id);
    const isOpen = !again && kids.length > 0 && (onlyRisk || expanded.has(id));
    const item: TreeItem = {
      key: `${parentKey ?? ''}/${id}`, id, depth, parentKey, children: [], expandable: kids.length > 0 && !again, expanded: isOpen, again, x: 0, y: 0,
    };
    items.push(item);
    opened.add(id);
    if (isOpen) {
      const next = new Set(ancestors).add(id);
      for (const ch of kids) {
        const child = make(ch, depth + 1, item.key, next);
        if (child) item.children.push(child);
      }
    }
    return item;
  };
  const root = make(index.root, 0, null, new Set());
  return { root, items, truncated };
}

export const COL_WIDTH = 264;
export const ROW_HEIGHT = 28;

/** Left to right, a level to a column; a leaf takes the next row and a parent sits at the middle of its first and last child. */
export function layoutTree(tree: VisibleTree): { width: number; height: number } {
  if (!tree.root) return { width: 0, height: 0 };
  let row = 0;
  let maxDepth = 0;
  const place = (item: TreeItem) => {
    maxDepth = Math.max(maxDepth, item.depth);
    item.x = item.depth * COL_WIDTH;
    if (item.children.length === 0) {
      item.y = row++ * ROW_HEIGHT;
      return;
    }
    item.children.forEach(place);
    item.y = (item.children[0]!.y + item.children[item.children.length - 1]!.y) / 2;
  };
  place(tree.root);
  return { width: (maxDepth + 1) * COL_WIDTH, height: Math.max(row, 1) * ROW_HEIGHT };
}
