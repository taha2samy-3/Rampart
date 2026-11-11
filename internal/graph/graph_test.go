package graph_test

import (
	"strings"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/graph"
)

func TestDependencyGraph(t *testing.T) {
	components := []domain.SBOMComponent{
		{
			Ref:     "pkg:npm/my-app@1.0.0",
			Purl:    "pkg:npm/my-app@1.0.0",
			Name:    "my-app",
			Version: "1.0.0",
		},
		{
			Ref:     "pkg:npm/express@4.18.2",
			Purl:    "pkg:npm/express@4.18.2",
			Name:    "express",
			Version: "4.18.2",
		},
		{
			Ref:     "pkg:npm/debug@4.3.4",
			Purl:    "pkg:npm/debug@4.3.4",
			Name:    "debug",
			Version: "4.3.4",
		},
		{
			Ref:     "pkg:npm/ms@2.1.3",
			Purl:    "pkg:npm/ms@2.1.3",
			Name:    "ms",
			Version: "2.1.3",
		},
	}

	edges := []domain.DependencyEdge{
		{FromRef: "pkg:npm/my-app@1.0.0", ToRef: "pkg:npm/express@4.18.2"},
		{FromRef: "pkg:npm/express@4.18.2", ToRef: "pkg:npm/debug@4.3.4"},
		{FromRef: "pkg:npm/debug@4.3.4", ToRef: "pkg:npm/ms@2.1.3"},
	}

	g := graph.NewDependencyGraph(components, edges, "pkg:npm/my-app@1.0.0")

	// 1. Mark direct vs transitive dependencies
	g.MarkDirectDependencies()

	var expressDirect, debugDirect, msDirect bool
	for _, c := range g.Components {
		switch c.Name {
		case "express":
			expressDirect = c.Direct
		case "debug":
			debugDirect = c.Direct
		case "ms":
			msDirect = c.Direct
		}
	}

	if !expressDirect {
		t.Errorf("expected express to be direct dependency of my-app")
	}
	if debugDirect {
		t.Errorf("expected debug to be transitive dependency (not direct)")
	}
	if msDirect {
		t.Errorf("expected ms to be transitive dependency (not direct)")
	}

	// 2. Trace path to deep vulnerable dependency "ms"
	path := g.FindShortestPath("pkg:npm/ms@2.1.3")
	if len(path) != 4 {
		t.Fatalf("expected path length 4 (my-app -> express -> debug -> ms), got %d: %v", len(path), path)
	}
	if path[0] != "pkg:npm/my-app@1.0.0" || path[3] != "pkg:npm/ms@2.1.3" {
		t.Errorf("unexpected path: %v", path)
	}

	// 3. Render Mermaid diagram
	mermaid := g.RenderMermaid()
	if !strings.Contains(mermaid, "flowchart TD") || !strings.Contains(mermaid, "-->") {
		t.Errorf("invalid mermaid diagram: %s", mermaid)
	}

	// 4. Render Text Tree
	tree := g.RenderTextTree()
	if !strings.Contains(tree, "my-app@1.0.0") || !strings.Contains(tree, "express@4.18.2") {
		t.Errorf("invalid text tree: %s", tree)
	}
}
