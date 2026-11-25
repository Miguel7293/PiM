package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

type NodeKind string
type EdgeKind string

const (
	Component  NodeKind = "component"
	Dependency NodeKind = "dependency"
	Entrypoint NodeKind = "entrypoint"
	DependsOn  EdgeKind = "depends_on"
	Exposes    EdgeKind = "exposes"
)

type Node struct {
	ID    string            `json:"id"`
	Kind  NodeKind          `json:"kind"`
	Label string            `json:"label"`
	Attrs map[string]string `json:"attrs,omitempty"`
}
type Edge struct {
	From  string            `json:"from"`
	To    string            `json:"to"`
	Kind  EdgeKind          `json:"kind"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Graph's zero value is ready for use. Duplicate node IDs are rejected.
// Values are copied on insertion and retrieval to protect graph invariants.
type Graph struct {
	nodes map[string]Node
	edges []Edge
}
type StructureGraph struct{ Graph }

func cloneAttrs(attrs map[string]string) map[string]string {
	if attrs == nil {
		return nil
	}
	result := make(map[string]string, len(attrs))
	for k, v := range attrs {
		result[k] = v
	}
	return result
}
func (g *Graph) AddNode(n Node) error {
	if n.ID == "" {
		return fmt.Errorf("add node: empty ID")
	}
	if _, ok := g.nodes[n.ID]; ok {
		return fmt.Errorf("add node %q: duplicate ID", n.ID)
	}
	if g.nodes == nil {
		g.nodes = make(map[string]Node)
	}
	n.Attrs = cloneAttrs(n.Attrs)
	g.nodes[n.ID] = n
	return nil
}
func (g *Graph) AddEdge(e Edge) error {
	for _, id := range []string{e.From, e.To} {
		if _, ok := g.nodes[id]; !ok {
			return fmt.Errorf("add edge: node %q does not exist", id)
		}
	}
	e.Attrs = cloneAttrs(e.Attrs)
	g.edges = append(g.edges, e)
	return nil
}
func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.nodes[id]
	n.Attrs = cloneAttrs(n.Attrs)
	return n, ok
}
func (g *Graph) Nodes() []Node {
	result := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		n.Attrs = cloneAttrs(n.Attrs)
		result = append(result, n)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
func (g *Graph) Edges() []Edge {
	result := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		e.Attrs = cloneAttrs(e.Attrs)
		result = append(result, e)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		// Attributes break ties for parallel edges independently of insertion order.
		x, _ := json.Marshal(a.Attrs)
		y, _ := json.Marshal(b.Attrs)
		return string(x) < string(y)
	})
	return result
}

// MarshalJSON returns two-space-indented JSON with a trailing newline.
// Use it directly or WriteJSON for canonical bytes: json.Marshal compacts output.
func (g Graph) MarshalJSON() ([]byte, error) {
	data, err := json.MarshalIndent(struct {
		Nodes []Node `json:"nodes"`
		Edges []Edge `json:"edges"`
	}{g.Nodes(), g.Edges()}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal graph: %w", err)
	}
	return append(data, '\n'), nil
}
func (g Graph) WriteJSON(w io.Writer) error {
	data, err := g.MarshalJSON()
	if err != nil {
		return err
	}
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("write graph: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("write graph: %w", io.ErrShortWrite)
	}
	return nil
}
