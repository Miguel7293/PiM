package graph

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "regenerate graph golden JSON")

func fixtureGraph(t *testing.T, reverse bool) *StructureGraph {
	t.Helper()
	g := &StructureGraph{}
	nodes := []Node{
		{ID: "component:go:example/app", Kind: Component, Label: "example/app"},
		{ID: "dependency:go:example/lib@v1.2.3", Kind: Dependency, Label: "example/lib", Attrs: map[string]string{"version": "v1.2.3", "ecosystem": "go"}},
		{ID: "entrypoint:go:cmd/app", Kind: Entrypoint, Label: "cmd/app"},
	}
	edges := []Edge{
		{From: nodes[0].ID, To: nodes[1].ID, Kind: DependsOn},
		{From: nodes[0].ID, To: nodes[2].ID, Kind: Exposes},
	}
	if reverse {
		nodes[0], nodes[2] = nodes[2], nodes[0]
		edges[0], edges[1] = edges[1], edges[0]
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range edges {
		if err := g.AddEdge(e); err != nil {
			t.Fatal(err)
		}
	}
	return g
}
func TestCanonicalJSON(t *testing.T) {
	g := fixtureGraph(t, false)
	first, err := g.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	again, err := g.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := fixtureGraph(t, true).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var written bytes.Buffer
	if err := g.WriteJSON(&written); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) || !bytes.Equal(first, reversed) || !bytes.Equal(first, written.Bytes()) {
		t.Fatal("non-deterministic JSON")
	}
	if !json.Valid(first) || first[len(first)-1] != '\n' {
		t.Fatal("invalid canonical JSON")
	}
	if data, err := json.Marshal(g); err != nil || !json.Valid(data) {
		t.Fatalf("json.Marshal: %s %v", data, err)
	}
	path := filepath.Join("testdata", "structure.golden.json")
	if *update {
		if err := os.WriteFile(path, first, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, want) {
		t.Fatalf("golden mismatch; regenerate with go test ./internal/graph -update\ngot:\n%s", first)
	}
}
func TestValidationAndCopies(t *testing.T) {
	var g Graph
	if err := g.AddNode(Node{}); err == nil {
		t.Fatal("accepted empty ID")
	}
	n := Node{ID: "a", Attrs: map[string]string{"x": "original"}}
	if err := g.AddNode(n); err != nil {
		t.Fatal(err)
	}
	n.Attrs["x"] = "changed"
	if err := g.AddNode(n); err == nil {
		t.Fatal("accepted duplicate")
	}
	for _, e := range []Edge{{From: "missing", To: "a"}, {From: "a", To: "missing"}} {
		if err := g.AddEdge(e); err == nil {
			t.Fatal("accepted missing endpoint")
		}
	}
	e := Edge{From: "a", To: "a", Kind: DependsOn, Attrs: map[string]string{"x": "original"}}
	if err := g.AddEdge(e); err != nil {
		t.Fatal(err)
	}
	e.Attrs["x"] = "changed"
	got, ok := g.Node("a")
	if !ok || got.Attrs["x"] != "original" {
		t.Fatal(got)
	}
	got.Attrs["x"] = "changed"
	nodes := g.Nodes()
	nodes[0].Attrs["x"] = "changed"
	edges := g.Edges()
	if edges[0].Attrs["x"] != "original" {
		t.Fatal(edges)
	}
	edges[0].Attrs["x"] = "changed"
	if g.Nodes()[0].Attrs["x"] != "original" || g.Edges()[0].Attrs["x"] != "original" {
		t.Fatal("mutable graph leaked")
	}
	if _, ok := g.Node("missing"); ok {
		t.Fatal("missing node found")
	}
}

type brokenWriter struct{ err error }

func (w brokenWriter) Write(p []byte) (int, error) { return 0, w.err }
func TestEmptyAndWriterErrors(t *testing.T) {
	var g Graph
	data, err := g.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\n  \"nodes\": [],\n  \"edges\": []\n}\n" {
		t.Fatalf("empty: %s", data)
	}
	failure := errors.New("write failure")
	if err := g.WriteJSON(brokenWriter{failure}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := g.WriteJSON(brokenWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}
func TestParallelEdgesOrder(t *testing.T) {
	build := func(reverse bool) []byte {
		g := fixtureGraph(t, false)
		attrs := []string{"z", "a"}
		if reverse {
			attrs[0], attrs[1] = attrs[1], attrs[0]
		}
		for _, v := range attrs {
			if err := g.AddEdge(Edge{From: "component:go:example/app", To: "entrypoint:go:cmd/app", Kind: Exposes, Attrs: map[string]string{"x": v}}); err != nil {
				t.Fatal(err)
			}
		}
		data, err := g.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if !bytes.Equal(build(false), build(true)) {
		t.Fatal("parallel edges not deterministic")
	}
}
