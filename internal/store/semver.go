package store

import (
	"regexp"
	"strings"
)

var semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

type semanticVersion struct {
	core []string
	pre  []string
}

func numeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
func parseVersion(s string) (semanticVersion, bool) {
	m := semverPattern.FindStringSubmatch(s)
	if m == nil {
		return semanticVersion{}, false
	}
	v := semanticVersion{core: m[1:4]}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
		for _, p := range v.pre {
			if numeric(p) && len(p) > 1 && p[0] == '0' {
				return semanticVersion{}, false
			}
		}
	}
	return v, true
}
func compareNumber(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}
func compareVersion(a, b semanticVersion) int {
	for i := range a.core {
		if c := compareNumber(a.core[i], b.core[i]); c != 0 {
			return c
		}
	}
	if len(a.pre) == 0 && len(b.pre) > 0 {
		return 1
	}
	if len(b.pre) == 0 && len(a.pre) > 0 {
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		c := strings.Compare(x, y)
		if numeric(x) && numeric(y) {
			c = compareNumber(x, y)
		} else if numeric(x) {
			c = -1
		} else if numeric(y) {
			c = 1
		}
		if c != 0 {
			return c
		}
	}
	if len(a.pre) < len(b.pre) {
		return -1
	}
	if len(a.pre) > len(b.pre) {
		return 1
	}
	return 0
}
func normalizeVersion(ecosystem, version string) string {
	if ecosystem == "Go" {
		return strings.TrimPrefix(version, "v")
	}
	return version
}
func matches(a Affected, version string) bool {
	version = normalizeVersion(a.Package.Ecosystem, version)
	for _, v := range a.Versions {
		if normalizeVersion(a.Package.Ecosystem, v) == version {
			return true
		}
	}
	if a.Package.Ecosystem != "Go" && a.Package.Ecosystem != "npm" {
		return false
	}
	target, ok := parseVersion(version)
	if !ok {
		return false
	}
	for _, r := range a.Ranges {
		// Commit ancestry cannot be inferred from a package version.
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}
		active := false
		for _, event := range r.Events {
			if start, ok := event["introduced"]; ok {
				bound, valid := parseVersion(normalizeVersion(a.Package.Ecosystem, start))
				active = start == "0" || (valid && compareVersion(target, bound) >= 0)
			}
			for _, end := range []string{"fixed", "last_affected", "limit"} {
				if value, ok := event[end]; ok {
					bound, valid := parseVersion(normalizeVersion(a.Package.Ecosystem, value))
					if active && valid {
						c := compareVersion(target, bound)
						if c < 0 || (end == "last_affected" && c == 0) {
							return true
						}
					}
					active = false
				}
			}
		}
		if active {
			return true
		}
	}
	return false
}
