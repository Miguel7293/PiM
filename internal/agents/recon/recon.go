// Package recon performs static, local manifest analysis without executing code.
package recon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Miguel7293/PiM-/internal/graph"
)

var ErrNoManifest = errors.New("no recognized manifest (go.mod or package.json)")

type dependency struct {
	name, version string
	attrs         map[string]string
}
type project struct {
	name, ecosystem string
	attrs           map[string]string
	deps            []dependency
	entries         []string
}

// Scan accepts a repository root or a single manifest. It never resolves versions.
func Scan(ctx context.Context, target string) (*graph.StructureGraph, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("scan %q: %w", target, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("inspect target %q: %w", target, err)
	}
	files := []string{}
	if info.IsDir() {
		for _, name := range []string{"go.mod", "package.json"} {
			path := filepath.Join(target, name)
			if _, err := os.Stat(path); err == nil {
				files = append(files, path)
			} else if !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("inspect manifest %q: %w", path, err)
			}
		}
	} else if name := filepath.Base(target); name == "go.mod" || name == "package.json" {
		files = append(files, target)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("scan %q: %w", target, ErrNoManifest)
	}
	g := &graph.StructureGraph{}
	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("scan %q: %w", path, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read manifest %q: %w", path, err)
		}
		var p project
		if filepath.Base(path) == "go.mod" {
			p, err = parseGo(data)
			if err == nil {
				p.entries, err = goEntrypoints(ctx, filepath.Dir(path))
			}
		} else {
			p, err = parseNPM(data)
		}
		if err != nil {
			return nil, fmt.Errorf("scan manifest %q: %w", path, err)
		}
		if err = addProject(g, p); err != nil {
			return nil, fmt.Errorf("build graph for %q: %w", path, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("scan %q: %w", target, err)
	}
	return g, nil
}

// IDs are component:<ecosystem>:<name>, dependency:<ecosystem>:<name>@<version>,
// and entrypoint:<ecosystem>:<relative path with forward slashes>.
func addProject(g *graph.StructureGraph, p project) error {
	id := "component:" + p.ecosystem + ":" + p.name
	if p.attrs == nil {
		p.attrs = map[string]string{}
	}
	p.attrs["ecosystem"] = p.ecosystem
	if err := g.AddNode(graph.Node{ID: id, Kind: graph.Component, Label: p.name, Attrs: p.attrs}); err != nil {
		return err
	}
	for _, d := range p.deps {
		depID := "dependency:" + p.ecosystem + ":" + d.name + "@" + d.version
		if d.attrs == nil {
			d.attrs = map[string]string{}
		}
		d.attrs["ecosystem"] = p.ecosystem
		d.attrs["version"] = d.version
		edgeAttrs := map[string]string{}
		if scope := d.attrs["scope"]; scope != "" {
			edgeAttrs["scope"] = scope
		}
		if old, ok := g.Node(depID); ok {
			// Replacements can make multiple requirements share one dependency ID.
			if old.Attrs["scope"] != d.attrs["scope"] {
				return fmt.Errorf("conflicting dependency scopes for %q", depID)
			}
		} else if err := g.AddNode(graph.Node{ID: depID, Kind: graph.Dependency, Label: d.name, Attrs: d.attrs}); err != nil {
			return err
		}
		if err := g.AddEdge(graph.Edge{From: id, To: depID, Kind: graph.DependsOn, Attrs: edgeAttrs}); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, entry := range p.entries {
		entryID := "entrypoint:" + p.ecosystem + ":" + entry
		if seen[entryID] {
			continue
		}
		seen[entryID] = true
		if err := g.AddNode(graph.Node{ID: entryID, Kind: graph.Entrypoint, Label: entry, Attrs: map[string]string{"ecosystem": p.ecosystem}}); err != nil {
			return err
		}
		if err := g.AddEdge(graph.Edge{From: id, To: entryID, Kind: graph.Exposes}); err != nil {
			return err
		}
	}
	return nil
}
