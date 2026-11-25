package recon

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

func parseNPM(data []byte) (project, error) {
	p := project{ecosystem: "npm"}
	var m struct {
		Name            string            `json:"name"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		Main            string            `json:"main"`
		Bin             json.RawMessage   `json:"bin"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return p, fmt.Errorf("parse package.json: %w", err)
	}
	if strings.TrimSpace(m.Name) == "" {
		return p, fmt.Errorf("package.json: missing name")
	}
	p.name = m.Name
	for _, group := range []struct {
		deps  map[string]string
		scope string
	}{{m.Dependencies, "prod"}, {m.DevDependencies, "dev"}} {
		names := make([]string, 0, len(group.deps))
		for name := range group.deps {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			version := group.deps[name]
			if strings.TrimSpace(name) == "" || strings.TrimSpace(version) == "" {
				return p, fmt.Errorf("invalid dependency %q", name)
			}
			// npm permits the same declaration in both groups. Preserve both scopes.
			if group.scope == "dev" && m.Dependencies[name] == version {
				for i := range p.deps {
					if p.deps[i].name == name {
						p.deps[i].attrs["scope"] = "prod,dev"
					}
				}
				continue
			}
			p.deps = append(p.deps, dependency{name, version, map[string]string{"scope": group.scope}})
		}
	}
	addEntry := func(s string) error {
		s = strings.ReplaceAll(s, "\\", "/")
		s = path.Clean(s)
		if s == "." || s == ".." || strings.HasPrefix(s, "../") || path.IsAbs(s) || strings.Contains(s, ":") {
			return fmt.Errorf("entrypoint must be a relative file path: %q", s)
		}
		p.entries = append(p.entries, s)
		return nil
	}
	if m.Main != "" {
		if err := addEntry(m.Main); err != nil {
			return p, err
		}
	}
	if len(m.Bin) > 0 && string(m.Bin) != "null" {
		var single string
		if err := json.Unmarshal(m.Bin, &single); err == nil {
			if err := addEntry(single); err != nil {
				return p, err
			}
		} else {
			var bins map[string]string
			if err := json.Unmarshal(m.Bin, &bins); err != nil {
				return p, fmt.Errorf("parse bin: %w", err)
			}
			for _, entry := range bins {
				if err := addEntry(entry); err != nil {
					return p, err
				}
			}
		}
	}
	sort.Strings(p.entries)
	return p, nil
}
