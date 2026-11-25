package recon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// modTokens recognizes quoted paths and comments without interpreting URLs as comments.
func modTokens(line string) ([]string, string, error) {
	var tokens []string
	for line = strings.TrimSpace(line); line != ""; line = strings.TrimSpace(line) {
		if strings.HasPrefix(line, "//") {
			return tokens, strings.TrimSpace(line[2:]), nil
		}
		if line[0] == '"' || line[0] == '`' {
			quote := line[0]
			end := 1
			for ; end < len(line); end++ {
				if quote == '"' && line[end] == '\\' {
					end++
					continue
				}
				if line[end] == quote {
					break
				}
			}
			if end >= len(line) {
				return nil, "", fmt.Errorf("unterminated quoted string")
			}
			value, err := strconv.Unquote(line[:end+1])
			if err != nil {
				return nil, "", err
			}
			tokens = append(tokens, value)
			line = line[end+1:]
		} else {
			end := strings.IndexAny(line, " \t\r")
			if end < 0 {
				end = len(line)
			}
			tokens = append(tokens, line[:end])
			line = line[end:]
		}
	}
	return tokens, "", nil
}

func parseGo(data []byte) (project, error) {
	p := project{ecosystem: "go", attrs: map[string]string{}}
	type replacement struct{ name, version, to, toVersion string }
	var replacements []replacement
	var ignored []string
	block := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	line := 0
	seen := map[string]bool{}
	for scanner.Scan() {
		line++
		fields, comment, err := modTokens(scanner.Text())
		if err != nil {
			return p, fmt.Errorf("line %d: %w", line, err)
		}
		if len(fields) == 0 {
			continue
		}
		fail := func() (project, error) { return p, fmt.Errorf("invalid go.mod directive on line %d", line) }
		if fields[0] == ")" {
			if block == "" || len(fields) != 1 {
				return fail()
			}
			block = ""
			continue
		}
		directive := block
		if directive == "" {
			directive = fields[0]
			fields = fields[1:]
			if len(fields) == 1 && fields[0] == "(" {
				switch directive {
				case "require", "replace", "exclude", "retract", "tool":
					block = directive
					continue
				default:
					return fail()
				}
			}
		}
		switch directive {
		case "module":
			if len(fields) != 1 || fields[0] == "" || p.name != "" {
				return fail()
			}
			p.name = fields[0]
		case "require":
			if len(fields) != 2 || fields[0] == "" || !strings.HasPrefix(fields[1], "v") || seen[fields[0]] {
				return fail()
			}
			seen[fields[0]] = true
			attrs := map[string]string{}
			if words := strings.Fields(comment); len(words) > 0 && words[0] == "indirect" {
				attrs["indirect"] = "true"
			}
			p.deps = append(p.deps, dependency{fields[0], fields[1], attrs})
		case "replace":
			arrow := -1
			for i, s := range fields {
				if s == "=>" {
					if arrow >= 0 {
						return fail()
					}
					arrow = i
				}
			}
			if (arrow != 1 && arrow != 2) || len(fields)-arrow < 2 || len(fields)-arrow > 3 {
				return fail()
			}
			r := replacement{name: fields[0], to: fields[arrow+1]}
			if arrow == 2 {
				r.version = fields[1]
			}
			if len(fields)-arrow == 3 {
				r.toVersion = fields[arrow+2]
				if !strings.HasPrefix(r.toVersion, "v") {
					return fail()
				}
			}
			if r.toVersion == "" {
				ignored = append(ignored, strings.Join(fields, " "))
			} else {
				replacements = append(replacements, r)
			}
		case "go", "toolchain":
			if len(fields) != 1 {
				return fail()
			}
		case "exclude":
			if len(fields) != 2 {
				return fail()
			}
		case "retract", "tool", "godebug":
			if len(fields) == 0 {
				return fail()
			}
		default:
			return fail()
		}
	}
	if err := scanner.Err(); err != nil {
		return p, fmt.Errorf("read go.mod: %w", err)
	}
	if block != "" {
		return p, fmt.Errorf("unterminated %s block", block)
	}
	if p.name == "" {
		return p, fmt.Errorf("go.mod: missing module directive")
	}
	for i := range p.deps {
		d := &p.deps[i]
		var selected *replacement
		for j := range replacements {
			r := &replacements[j]
			if r.name == d.name && (r.version == "" || r.version == d.version) {
				if selected == nil || r.version != "" {
					selected = r
				}
			}
		}
		if selected != nil {
			d.attrs["replaces"] = d.name + "@" + d.version
			d.name = selected.to
			d.version = selected.toVersion
		}
	}
	// The graph is the scan report; unsupported local replacements remain visible here.
	if len(ignored) > 0 {
		sort.Strings(ignored)
		p.attrs["ignored_replacements"] = strings.Join(ignored, "; ")
	}
	return p, nil
}

func goEntrypoints(ctx context.Context, root string) ([]string, error) {
	entries := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (d.Name() == "vendor" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.PackageClauseOnly)
		if err != nil {
			return fmt.Errorf("parse Go package %q: %w", path, err)
		}
		if file.Name.Name == "main" {
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			entries[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find Go entrypoints: %w", err)
	}
	result := make([]string, 0, len(entries))
	for entry := range entries {
		result = append(result, entry)
	}
	sort.Strings(result)
	return result, nil
}
