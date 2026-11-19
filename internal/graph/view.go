package graph

import (
	"sort"

	"rampart/internal/domain"
)

// Risk is the number of open findings of one package, by severity band (info counts as low).
type Risk struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Total is the number of open findings.
func (r Risk) Total() int { return r.Critical + r.High + r.Medium + r.Low }

// Node is one component of an SBOM as a client draws it. ID is the one name an edge uses for it.
type Node struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Purl     string   `json:"purl,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
	// Root marks the component the application is. Direct marks what the root depends on itself; a component the root
	// reaches only through another is transitive. Depth is the length of the shortest path from the root (root 0,
	// direct 1), and -1 for a component no path from the root reaches.
	Root            bool `json:"root,omitempty"`
	Direct          bool `json:"direct,omitempty"`
	Depth           int  `json:"depth"`
	Vulnerabilities Risk `json:"vulnerabilities"`
}

// Edge is "From depends on To", by node id. Inferred marks an edge the document does not state: see BuildView.
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Inferred bool   `json:"inferred,omitempty"`
}

// View is what the graph API returns: every component, every dependency between them, and the numbers worked out from
// the edges. It is built from the stored components and edges only, so what is drawn is what the document said.
type View struct {
	Root  string `json:"root"`
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	// HasDependencies is false when the document states no dependency between its components (an inventory, not a graph).
	// Then nothing can be said about direct or transitive, and the counts below are zero.
	HasDependencies bool `json:"has_dependencies"`
	// InferredRoot is true when the document states dependencies but none from its root, as many generators write them: the
	// components nothing depends on are then shown under the root, with edges marked Inferred.
	InferredRoot bool `json:"inferred_root,omitempty"`
	Direct       int  `json:"direct_components"`
	Transitive   int  `json:"transitive_components"`
	// Unreachable counts components that no path from the root reaches.
	Unreachable int `json:"unreachable_components"`
	// DanglingEdges counts edges that name a component the document does not contain; they are left out of Edges.
	DanglingEdges int `json:"dangling_edges,omitempty"`
}

// BuildView builds the view of an SBOM. rootRef is the root the document declared; when it names none, the root is the
// component nothing depends on that reaches the most components, and ties go to the smaller id, so the answer is the same
// on every call. risk maps a component to its open findings and may be nil.
func BuildView(components []domain.SBOMComponent, edges []domain.DependencyEdge, rootRef string, risk func(domain.SBOMComponent) Risk) *View {
	v := &View{Nodes: make([]Node, 0, len(components)), Edges: []Edge{}}

	index := map[string]int{} // any name a component or an edge uses -> position in v.Nodes
	for _, c := range components {
		id := ComponentID(c)
		if id == "" {
			continue
		}
		if _, dup := index[id]; dup {
			continue
		}
		n := Node{ID: id, Name: c.Name, Version: c.Version, Purl: c.Purl, Scope: c.Scope, Licenses: c.Licenses, Depth: -1}
		if n.Name == "" {
			n.Name = firstNonEmpty(c.Purl, c.Ref)
		}
		if risk != nil {
			n.Vulnerabilities = risk(c)
		}
		pos := len(v.Nodes)
		v.Nodes = append(v.Nodes, n)
		for _, key := range []string{c.Ref, c.Purl, nameVersion(c)} {
			if key != "" {
				if _, taken := index[key]; !taken {
					index[key] = pos
				}
			}
		}
	}

	// Edges, by node id, once each.
	type pair struct{ from, to int }
	seen := map[pair]bool{}
	children := make([][]int, len(v.Nodes))
	parents := make([]int, len(v.Nodes))
	for _, e := range edges {
		from, okF := index[e.FromRef]
		to, okT := index[e.ToRef]
		if !okF || !okT {
			v.DanglingEdges++
			continue
		}
		if from == to || seen[pair{from, to}] {
			continue
		}
		seen[pair{from, to}] = true
		children[from] = append(children[from], to)
		parents[to]++
		v.Edges = append(v.Edges, Edge{From: v.Nodes[from].ID, To: v.Nodes[to].ID})
	}
	sort.Slice(v.Edges, func(i, j int) bool {
		if v.Edges[i].From != v.Edges[j].From {
			return v.Edges[i].From < v.Edges[j].From
		}
		return v.Edges[i].To < v.Edges[j].To
	})
	v.HasDependencies = len(v.Edges) > 0

	root := -1
	if rootRef != "" {
		if p, ok := index[rootRef]; ok {
			root = p
		}
	}
	if root < 0 && v.HasDependencies {
		root = pickRoot(v.Nodes, children, parents)
	}
	if root >= 0 {
		v.Root = v.Nodes[root].ID
		v.Nodes[root].Root = true
	}

	// A document that lists the dependencies of its components but not those of its root (a Maven or npm plugin writes it
	// so) still has a top: the components nothing depends on are what the application uses itself.
	if v.HasDependencies && root >= 0 && len(children[root]) == 0 {
		for i := range v.Nodes {
			if i == root || parents[i] != 0 {
				continue
			}
			children[root] = append(children[root], i)
			parents[i]++
			v.Edges = append(v.Edges, Edge{From: v.Nodes[root].ID, To: v.Nodes[i].ID, Inferred: true})
			v.InferredRoot = true
		}
		sort.Slice(v.Edges, func(i, j int) bool {
			if v.Edges[i].From != v.Edges[j].From {
				return v.Edges[i].From < v.Edges[j].From
			}
			return v.Edges[i].To < v.Edges[j].To
		})
	}

	if v.HasDependencies && root >= 0 {
		// Breadth first from the root: the depth of each component, which also guards against cycles.
		v.Nodes[root].Depth = 0
		queue := []int{root}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, ch := range children[cur] {
				if v.Nodes[ch].Depth >= 0 {
					continue
				}
				v.Nodes[ch].Depth = v.Nodes[cur].Depth + 1
				queue = append(queue, ch)
			}
		}
		for i := range v.Nodes {
			n := &v.Nodes[i]
			switch {
			case n.Root:
			case n.Depth == 1:
				n.Direct = true
				v.Direct++
			case n.Depth > 1:
				v.Transitive++
			default:
				v.Unreachable++
			}
		}
	}

	sort.SliceStable(v.Nodes, func(i, j int) bool {
		a, b := v.Nodes[i], v.Nodes[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.ID < b.ID
	})
	return v
}

// pickRoot chooses the root of a document that declared none: among the components nothing depends on, the one that
// reaches the most, the smaller id first on a tie.
func pickRoot(nodes []Node, children [][]int, parents []int) int {
	best, bestReach := -1, -1
	for i := range nodes {
		if parents[i] != 0 || len(children[i]) == 0 {
			continue
		}
		reach := reachable(i, children)
		if reach > bestReach || (reach == bestReach && nodes[i].ID < nodes[best].ID) {
			best, bestReach = i, reach
		}
	}
	return best
}

func reachable(from int, children [][]int) int {
	seen := map[int]bool{from: true}
	stack := []int{from}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, ch := range children[cur] {
			if !seen[ch] {
				seen[ch] = true
				stack = append(stack, ch)
			}
		}
	}
	return len(seen) - 1
}

// ComponentID is the name a component goes by in a View: its ref, else its purl, else name@version. The edges of a
// document use the ref (or the purl), so this is the one that finds a component from an edge.
func ComponentID(c domain.SBOMComponent) string {
	return firstNonEmpty(c.Ref, c.Purl, nameVersion(c))
}

func nameVersion(c domain.SBOMComponent) string {
	if c.Name == "" || c.Version == "" {
		return ""
	}
	return c.Name + "@" + c.Version
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
