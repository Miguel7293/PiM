package recon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Miguel7293/PiM-/internal/graph"
)

func requireNode(t *testing.T, g *graph.StructureGraph, id string, kind graph.NodeKind, attrs map[string]string) {
	t.Helper()
	n, ok := g.Node(id)
	if !ok || n.Kind != kind {
		t.Fatalf("missing/wrong node %q: %+v", id, n)
	}
	for k, want := range attrs {
		if n.Attrs[k] != want {
			t.Errorf("%s attr %s = %q, want %q", id, k, n.Attrs[k], want)
		}
	}
}
func TestScanGo(t *testing.T) {
	root := filepath.Join("testdata", "gorepo")
	g, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	requireNode(t, g, "component:go:example.com/demo", graph.Component, map[string]string{"ecosystem": "go", "ignored_replacements": "example.com/direct => ../local"})
	requireNode(t, g, "dependency:go:example.com/direct@v1.2.3", graph.Dependency, map[string]string{"version": "v1.2.3", "ecosystem": "go"})
	requireNode(t, g, "dependency:go:example.com/transitive@v0.4.0", graph.Dependency, map[string]string{"indirect": "true"})
	requireNode(t, g, "dependency:go:example.com/new@v1.1.0", graph.Dependency, map[string]string{"replaces": "example.com/old@v1.0.0"})
	requireNode(t, g, "entrypoint:go:cmd/demo", graph.Entrypoint, nil)
	if len(g.Nodes()) != 5 || len(g.Edges()) != 4 {
		t.Fatalf("unexpected graph: %+v %+v", g.Nodes(), g.Edges())
	}
	for _, e := range g.Edges() {
		n, _ := g.Node(e.To)
		want := graph.DependsOn
		if n.Kind == graph.Entrypoint {
			want = graph.Exposes
		}
		if e.From != "component:go:example.com/demo" || e.Kind != want {
			t.Fatal(e)
		}
	}
	file, err := Scan(context.Background(), filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := g.MarshalJSON()
	b, _ := file.MarshalJSON()
	if !bytes.Equal(a, b) {
		t.Fatal("file and directory differ")
	}
}
func TestScanNPM(t *testing.T) {
	g, err := Scan(context.Background(), filepath.Join("testdata", "npmrepo"))
	if err != nil {
		t.Fatal(err)
	}
	requireNode(t, g, "component:npm:demo", graph.Component, nil)
	requireNode(t, g, "dependency:npm:alpha@^1.2.3", graph.Dependency, map[string]string{"ecosystem": "npm", "version": "^1.2.3", "scope": "prod"})
	requireNode(t, g, "dependency:npm:beta@>=3 <4", graph.Dependency, map[string]string{"scope": "dev"})
	requireNode(t, g, "dependency:npm:shared@~2.0.0", graph.Dependency, map[string]string{"scope": "prod,dev"})
	requireNode(t, g, "entrypoint:npm:src/index.js", graph.Entrypoint, nil)
	requireNode(t, g, "entrypoint:npm:bin/demo.js", graph.Entrypoint, nil)
	if len(g.Nodes()) != 6 || len(g.Edges()) != 5 {
		t.Fatalf("unexpected graph size: %d %d", len(g.Nodes()), len(g.Edges()))
	}
	first, _ := g.MarshalJSON()
	for i := 0; i < 10; i++ {
		other, err := Scan(context.Background(), filepath.Join("testdata", "npmrepo"))
		if err != nil {
			t.Fatal(err)
		}
		data, _ := other.MarshalJSON()
		if !bytes.Equal(first, data) {
			t.Fatal("unstable scan")
		}
	}
}
func writeFixture(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestBothManifests(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "go.mod", "module example/app\ngo 1.23\n")
	writeFixture(t, root, "package.json", `{"name":"app","bin":"cli\\main.js"}`)
	writeFixture(t, root, "main.go", "package main\nfunc main() {}\n")
	writeFixture(t, root, "helpers_test.go", "package main\n")
	g, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	requireNode(t, g, "component:go:example/app", graph.Component, nil)
	requireNode(t, g, "component:npm:app", graph.Component, nil)
	requireNode(t, g, "entrypoint:go:.", graph.Entrypoint, nil)
	requireNode(t, g, "entrypoint:npm:cli/main.js", graph.Entrypoint, nil)
	if len(g.Nodes()) != 4 {
		t.Fatal(g.Nodes())
	}
	single, err := Scan(context.Background(), filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(single.Nodes()) != 2 {
		t.Fatal("single manifest scanned sibling")
	}
}
func TestScanErrors(t *testing.T) {
	root := t.TempDir()
	for _, target := range []string{filepath.Join(root, "missing"), root, filepath.Join("testdata", "broken", "package.json")} {
		g, err := Scan(context.Background(), target)
		if err == nil || g != nil || !strings.Contains(err.Error(), strconv.Quote(target)) || errors.Unwrap(err) == nil {
			t.Fatalf("%q: graph=%v err=%v", target, g, err)
		}
	}
	if _, err := Scan(context.Background(), root); !errors.Is(err, ErrNoManifest) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Scan(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := goEntrypoints(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	writeFixture(t, root, "go.mod", "module example/app\nrequire (\n")
	if _, err := Scan(context.Background(), root); err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Fatal(err)
	}
	writeFixture(t, root, "go.mod", "module example/app\n")
	writeFixture(t, root, "main.go", "this is not Go")
	if _, err := Scan(context.Background(), root); err == nil || !strings.Contains(err.Error(), "main.go") {
		t.Fatal(err)
	}
}
func TestMalformedManifests(t *testing.T) {
	for _, input := range []string{"", "module", "module a\nmodule b", "module a\nrequire a", "module a\nrequire (\na v1.0.0", "module a\n)", "module a\nreplace a =>", "module a\nunknown b", "module \"unterminated", "module a\nrequire a latest"} {
		if _, err := parseGo([]byte(input)); err == nil {
			t.Errorf("accepted go.mod %q", input)
		}
	}
	for _, input := range []string{`null`, `{}`, `{"name":1}`, `{"name":"a","dependencies":{"a":1}}`, `{"name":"a","bin":42}`, `{"name":"a","main":"../outside.js"}`, `{"name":"a","bin":{"a":false}}`, `{"name":"a","dependencies":{"a":""}}`} {
		if _, err := parseNPM([]byte(input)); err == nil {
			t.Errorf("accepted package.json %q", input)
		}
	}
}
func TestGoQuotedPathsAndReplacements(t *testing.T) {
	input := "module \"example/app\" // comment\nrequire (\n\"example/a\" v1.0.0 // indirect\nexample/b v2.0.0\n)\nreplace (\nexample/a => example/fork v3.0.0\nexample/a v1.0.0 => example/specific v4.0.0\nexample/b v1.0.0 => example/unused v5.0.0\n)\n"
	p, err := parseGo([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if p.name != "example/app" || len(p.deps) != 2 || p.deps[0].name != "example/specific" || p.deps[0].version != "v4.0.0" || p.deps[0].attrs["indirect"] != "true" || p.deps[1].name != "example/b" {
		t.Fatalf("%+v", p)
	}
}
