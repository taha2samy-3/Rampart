package graph

import (
	"fmt"
	"sort"
	"strings"

	"rampart/internal/domain"
)

// DependencyGraph models the software supply chain components and their relationships.
type DependencyGraph struct {
	RootRef    string
	Nodes      map[string]*domain.SBOMComponent
	Parents    map[string][]string // child -> parents
	Children   map[string][]string // parent -> children
	Components []*domain.SBOMComponent
	Edges      []domain.DependencyEdge
}

// NewDependencyGraph builds a directed graph from components and dependency edges.
func NewDependencyGraph(components []domain.SBOMComponent, edges []domain.DependencyEdge, rootRef string) *DependencyGraph {
	g := &DependencyGraph{
		RootRef:    rootRef,
		Nodes:      make(map[string]*domain.SBOMComponent),
		Parents:    make(map[string][]string),
		Children:   make(map[string][]string),
		Components: make([]*domain.SBOMComponent, len(components)),
		Edges:      edges,
	}

	for i := range components {
		c := components[i]
		g.Components[i] = &c

		if c.Ref != "" {
			g.Nodes[c.Ref] = g.Components[i]
		}
		if c.Purl != "" {
			g.Nodes[c.Purl] = g.Components[i]
		}
		if c.Name != "" && c.Version != "" {
			g.Nodes[c.Name+"@"+c.Version] = g.Components[i]
		}
	}

	for _, e := range edges {
		from := e.FromRef
		to := e.ToRef
		if from == "" || to == "" {
			continue
		}

		g.Children[from] = append(g.Children[from], to)
		g.Parents[to] = append(g.Parents[to], from)
	}

	// Auto-detect root if unspecified: find node with children but no parent
	if g.RootRef == "" {
		for from := range g.Children {
			if len(g.Parents[from]) == 0 {
				g.RootRef = from
				break
			}
		}
	}
	if g.RootRef == "" && len(components) > 0 {
		if components[0].Ref != "" {
			g.RootRef = components[0].Ref
		} else if components[0].Purl != "" {
			g.RootRef = components[0].Purl
		}
	}

	return g
}

// MarkDirectDependencies traverses the graph from the root and marks direct vs transitive components.
func (g *DependencyGraph) MarkDirectDependencies() {
	if g.RootRef == "" && len(g.Children) == 0 {
		// If no explicit edges exist, assume components marked directly are true
		return
	}

	// 1. Direct children of root
	directSet := make(map[string]bool)
	for _, child := range g.Children[g.RootRef] {
		directSet[child] = true
	}

	// 2. Mark components
	for _, c := range g.Components {
		isDirect := false
		if c.Ref != "" && directSet[c.Ref] {
			isDirect = true
		} else if c.Purl != "" && directSet[c.Purl] {
			isDirect = true
		} else if directSet[c.Name+"@"+c.Version] {
			isDirect = true
		}

		c.Direct = isDirect
	}
}

// FindShortestPath performs BFS to trace the exact dependency path from root to a target package.
// e.g. ["my-app@1.0.0", "express@4.18.2", "debug@4.3.4"]
func (g *DependencyGraph) FindShortestPath(targetRef string) []string {
	if g.RootRef == "" || targetRef == "" {
		return nil
	}

	queue := [][]string{{g.RootRef}}
	visited := make(map[string]bool)
	visited[g.RootRef] = true

	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		current := path[len(path)-1]

		if g.matchesRef(current, targetRef) {
			return path
		}

		for _, child := range g.Children[current] {
			if !visited[child] {
				visited[child] = true
				newPath := make([]string, len(path), len(path)+1)
				copy(newPath, path)
				newPath = append(newPath, child)
				queue = append(queue, newPath)
			}
		}
	}

	return nil
}

// RenderMermaid generates a visual Mermaid flowchart diagram (flowchart TD).
func (g *DependencyGraph) RenderMermaid() string {
	var sb strings.Builder
	sb.WriteString("flowchart TD\n")

	nodeIDs := make(map[string]string)
	counter := 1

	getNodeID := func(ref string) string {
		if id, ok := nodeIDs[ref]; ok {
			return id
		}
		id := fmt.Sprintf("N%d", counter)
		counter++
		nodeIDs[ref] = id

		label := ref
		if node, ok := g.Nodes[ref]; ok {
			label = fmt.Sprintf("%s@%s", node.Name, node.Version)
		}
		// Escape quotes for mermaid
		label = strings.ReplaceAll(label, `"`, `'`)
		fmt.Fprintf(&sb, "  %s[\"%s\"]\n", id, label)
		return id
	}

	// Render edges
	type edgeKey struct {
		from, to string
	}
	seenEdges := make(map[edgeKey]bool)

	for from, children := range g.Children {
		fromID := getNodeID(from)
		for _, to := range children {
			ek := edgeKey{from: from, to: to}
			if seenEdges[ek] {
				continue
			}
			seenEdges[ek] = true
			toID := getNodeID(to)
			fmt.Fprintf(&sb, "  %s --> %s\n", fromID, toID)
		}
	}

	return sb.String()
}

// RenderTextTree generates a hierarchical ASCII tree view of the dependency relationships.
func (g *DependencyGraph) RenderTextTree() string {
	if g.RootRef == "" {
		return "(empty dependency tree)"
	}

	var sb strings.Builder
	rootLabel := g.labelForRef(g.RootRef)
	sb.WriteString(rootLabel + "\n")

	visited := make(map[string]bool)
	g.renderSubTree(&sb, g.RootRef, "", visited)
	return sb.String()
}

func (g *DependencyGraph) renderSubTree(sb *strings.Builder, parentRef string, prefix string, visited map[string]bool) {
	children := g.Children[parentRef]
	sort.Strings(children)

	for i, child := range children {
		isLast := i == len(children)-1
		connector := "├── "
		childPrefix := prefix + "│   "
		if isLast {
			connector = "└── "
			childPrefix = prefix + "    "
		}

		childLabel := g.labelForRef(child)
		sb.WriteString(prefix + connector + childLabel + "\n")

		if !visited[child] {
			visited[child] = true
			g.renderSubTree(sb, child, childPrefix, visited)
		}
	}
}

func (g *DependencyGraph) labelForRef(ref string) string {
	if node, ok := g.Nodes[ref]; ok {
		return fmt.Sprintf("%s@%s", node.Name, node.Version)
	}
	return ref
}

func (g *DependencyGraph) matchesRef(a, b string) bool {
	if a == b {
		return true
	}
	nodeA, okA := g.Nodes[a]
	nodeB, okB := g.Nodes[b]
	if okA && okB && nodeA.Purl != "" && nodeA.Purl == nodeB.Purl {
		return true
	}
	return false
}
