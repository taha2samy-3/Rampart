package graph

import (
	"strings"
	"testing"

	"rampart/internal/domain"
)

func comp(ref, name, version string) domain.SBOMComponent {
	return domain.SBOMComponent{Ref: ref, Name: name, Version: version, Purl: "pkg:npm/" + name + "@" + version}
}

func edge(from, to string) domain.DependencyEdge {
	return domain.DependencyEdge{FromRef: from, ToRef: to}
}

func byID(v *View) map[string]Node {
	m := map[string]Node{}
	for _, n := range v.Nodes {
		m[n.ID] = n
	}
	return m
}

// root -> a, b; a -> c; b -> c; c -> d. c has two parents and is drawn once as a node.
func TestBuildViewDirectTransitiveAndDepth(t *testing.T) {
	comps := []domain.SBOMComponent{comp("root", "app", "1"), comp("a", "a", "1"), comp("b", "b", "1"), comp("c", "c", "1"), comp("d", "d", "1")}
	edges := []domain.DependencyEdge{edge("root", "a"), edge("root", "b"), edge("a", "c"), edge("b", "c"), edge("c", "d")}
	v := BuildView(comps, edges, "root", nil)
	if v.Root != "root" || !v.HasDependencies {
		t.Fatalf("root = %q, has dependencies = %v", v.Root, v.HasDependencies)
	}
	if v.Direct != 2 || v.Transitive != 2 || v.Unreachable != 0 {
		t.Errorf("direct %d, transitive %d, unreachable %d; want 2, 2, 0", v.Direct, v.Transitive, v.Unreachable)
	}
	n := byID(v)
	if n["root"].Depth != 0 || !n["root"].Root || n["root"].Direct {
		t.Errorf("the root is not a dependency of itself: %+v", n["root"])
	}
	if !n["a"].Direct || n["a"].Depth != 1 || n["c"].Direct || n["c"].Depth != 2 || n["d"].Depth != 3 {
		t.Errorf("depths: a %+v c %+v d %+v", n["a"], n["c"], n["d"])
	}
	if len(v.Edges) != 5 {
		t.Errorf("edges = %d, want 5", len(v.Edges))
	}
}

// A document with no dependencies is an inventory: no root is invented, nothing is called direct or transitive.
func TestBuildViewWithoutEdgesIsAnInventory(t *testing.T) {
	comps := []domain.SBOMComponent{comp("a", "a", "1"), comp("b", "b", "1")}
	v := BuildView(comps, nil, "", nil)
	if v.HasDependencies || v.Direct != 0 || v.Transitive != 0 || v.Unreachable != 0 || v.Root != "" {
		t.Errorf("an inventory must say nothing about the graph: %+v", v)
	}
	if len(v.Nodes) != 2 || v.Edges == nil {
		t.Errorf("nodes = %d, edges nil = %v; the nodes are kept and the edge list is an empty list, not null", len(v.Nodes), v.Edges == nil)
	}
	// a declared root alone does not make it a graph, and is still not counted as a dependency
	v = BuildView(comps, nil, "a", nil)
	if v.Root != "a" || v.Direct != 0 {
		t.Errorf("declared root with no edges: %+v", v)
	}
}

func TestBuildViewRootIsChosenTheSameWayEveryTime(t *testing.T) {
	comps := []domain.SBOMComponent{comp("x", "x", "1"), comp("y", "y", "1"), comp("z", "z", "1"), comp("w", "w", "1")}
	// two parentless components: x reaches 1, y reaches 2 (z, w)
	edges := []domain.DependencyEdge{edge("x", "w"), edge("y", "z"), edge("z", "w")}
	for i := 0; i < 20; i++ {
		if v := BuildView(comps, edges, "", nil); v.Root != "y" {
			t.Fatalf("run %d: root = %q, want y (it reaches the most)", i, v.Root)
		}
	}
	// the component x is not reached from y's root: it is reported, not hidden
	if v := BuildView(comps, edges, "", nil); v.Unreachable != 1 {
		t.Errorf("unreachable = %d, want 1", v.Unreachable)
	}
}

func TestBuildViewToleratesBadEdges(t *testing.T) {
	comps := []domain.SBOMComponent{comp("r", "r", "1"), comp("a", "a", "1"), comp("b", "b", "1")}
	edges := []domain.DependencyEdge{
		edge("r", "a"), edge("r", "a"), // duplicate
		edge("a", "a"),                 // self
		edge("a", "b"), edge("b", "a"), // cycle
		edge("a", "missing"), // names nothing
		{FromRef: "", ToRef: "a"},
		edge("pkg:npm/a@1", "b"), // by purl, the same edge as a -> b
	}
	v := BuildView(comps, edges, "r", nil)
	if len(v.Edges) != 3 { // r->a, a->b, b->a
		t.Errorf("edges = %+v", v.Edges)
	}
	if v.DanglingEdges != 2 {
		t.Errorf("dangling = %d, want 2", v.DanglingEdges)
	}
	if v.Direct != 1 || v.Transitive != 1 {
		t.Errorf("a cycle must end: direct %d, transitive %d", v.Direct, v.Transitive)
	}
}

func TestBuildViewCarriesRiskAndIsOrdered(t *testing.T) {
	comps := []domain.SBOMComponent{comp("b", "zlib", "1"), comp("a", "axios", "0.21.1"), comp("r", "app", "1")}
	risk := func(c domain.SBOMComponent) Risk {
		if c.Name == "axios" {
			return Risk{Critical: 1, High: 2}
		}
		return Risk{}
	}
	v := BuildView(comps, []domain.DependencyEdge{edge("r", "a"), edge("r", "b")}, "r", risk)
	if got := byID(v)["a"].Vulnerabilities; got.Critical != 1 || got.High != 2 || got.Total() != 3 {
		t.Errorf("risk = %+v", got)
	}
	names := []string{v.Nodes[0].Name, v.Nodes[1].Name, v.Nodes[2].Name}
	if strings.Join(names, ",") != "app,axios,zlib" {
		t.Errorf("nodes are sorted by name: %v", names)
	}
}

func TestRenderMermaidIsStableAndSafe(t *testing.T) {
	comps := []domain.SBOMComponent{
		{Ref: "r", Name: "app", Version: "1"},
		{Ref: "a", Name: "evil\"]\n  click N1 \"javascript:alert(1)", Version: "<1>"},
		{Ref: "b", Name: "b", Version: "2"},
	}
	edges := []domain.DependencyEdge{edge("r", "a"), edge("r", "b"), edge("b", "a")}
	first := NewDependencyGraph(comps, edges, "r").RenderMermaid()
	for i := 0; i < 20; i++ {
		if got := NewDependencyGraph(comps, edges, "r").RenderMermaid(); got != first {
			t.Fatalf("run %d: the output changed between calls", i)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(first), "\n")[1:] {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "N") {
			t.Errorf("a label produced a statement of its own: %q", line)
		}
	}
	if strings.Contains(first, "click") && strings.Contains(first, "\n  click") {
		t.Errorf("a name injected a click statement:\n%s", first)
	}
}

// A document that lists the dependencies of its components but none for its root (the case of many generators): the
// components nothing depends on are shown under the root, and the edges that say so are marked.
func TestBuildViewInfersTheTopWhenTheRootHasNoEntry(t *testing.T) {
	comps := []domain.SBOMComponent{comp("root", "app", "1"), comp("a", "a", "1"), comp("b", "b", "1"), comp("c", "c", "1"), comp("lonely", "lonely", "1")}
	edges := []domain.DependencyEdge{edge("a", "c"), edge("b", "c")} // nothing from root
	v := BuildView(comps, edges, "root", nil)
	if !v.InferredRoot || v.Root != "root" {
		t.Fatalf("root %q, inferred = %v", v.Root, v.InferredRoot)
	}
	n := byID(v)
	if !n["a"].Direct || !n["b"].Direct || !n["lonely"].Direct || n["c"].Direct || n["c"].Depth != 2 {
		t.Errorf("the components nothing depends on sit under the root: a %+v lonely %+v c %+v", n["a"], n["lonely"], n["c"])
	}
	if v.Direct != 3 || v.Transitive != 1 || v.Unreachable != 0 {
		t.Errorf("direct %d, transitive %d, unreachable %d; want 3, 1, 0", v.Direct, v.Transitive, v.Unreachable)
	}
	inferred := 0
	for _, e := range v.Edges {
		if e.Inferred {
			inferred++
			if e.From != "root" {
				t.Errorf("an inferred edge must leave the root: %+v", e)
			}
		}
	}
	if inferred != 3 {
		t.Errorf("inferred edges = %d, want 3; the two the document states are not marked", inferred)
	}

	// when the root does state dependencies, nothing is added: what is not reached is reported, not attached
	edges = append(edges, edge("root", "a"))
	v = BuildView(comps, edges, "root", nil)
	if v.InferredRoot || v.Unreachable != 2 { // b and lonely
		t.Errorf("a root with dependencies is taken as written: inferred %v, unreachable %d", v.InferredRoot, v.Unreachable)
	}
	// and an inventory, which states no dependency at all, is never turned into a flat graph
	if v := BuildView(comps, nil, "root", nil); v.InferredRoot || v.HasDependencies {
		t.Errorf("an inventory must stay an inventory: %+v", v)
	}
}
