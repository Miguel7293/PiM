package store

import "testing"

func TestRangeLookup(t *testing.T) {
	s, err := Open(t.TempDir() + "/mirror.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, tc := range []struct {
		name, eco, kind, version string
		events                   []map[string]string
		versions                 []string
		want                     bool
	}{
		{"inside", "npm", "SEMVER", "1.5.0", []map[string]string{{"introduced": "1.0.0"}, {"fixed": "2.0.0"}}, nil, true},
		{"fixed", "npm", "SEMVER", "2.0.0", []map[string]string{{"introduced": "1.0.0"}, {"fixed": "2.0.0"}}, nil, false},
		{"before", "npm", "SEMVER", "0.9.0", []map[string]string{{"introduced": "1.0.0"}}, nil, false},
		{"last", "npm", "ECOSYSTEM", "2.0.0", []map[string]string{{"introduced": "0"}, {"last_affected": "2.0.0"}}, nil, true},
		{"after last", "npm", "SEMVER", "2.0.1", []map[string]string{{"introduced": "0"}, {"last_affected": "2.0.0"}}, nil, false},
		{"zero", "Go", "SEMVER", "v0.0.0", []map[string]string{{"introduced": "0"}}, nil, true},
		{"prefix", "Go", "ECOSYSTEM", "v1.2.3", []map[string]string{{"introduced": "1.2.0"}, {"fixed": "v1.3.0"}}, nil, true},
		{"prerelease", "npm", "SEMVER", "1.0.0-beta.10", []map[string]string{{"introduced": "1.0.0-beta.2"}, {"fixed": "1.0.0"}}, nil, true},
		{"pseudo", "Go", "SEMVER", "v0.0.0-20260101000000-abcdef123456", []map[string]string{{"introduced": "0"}, {"fixed": "0.0.0-20260201000000-abcdef123456"}}, nil, true},
		{"explicit", "Go", "GIT", "v1.2.3", nil, []string{"1.2.3"}, true},
		{"git ignored", "Go", "GIT", "1.0.0", []map[string]string{{"introduced": "0"}}, nil, false},
		{"reintroduced", "npm", "SEMVER", "3.0.0", []map[string]string{{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}}, nil, true},
		{"gap", "npm", "SEMVER", "1.5.0", []map[string]string{{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := Affected{Package: Package{tc.eco, "demo"}, Ranges: []Range{{Type: tc.kind, Events: tc.events}, {Type: "SEMVER", Events: []map[string]string{{"introduced": "99.0.0"}}}}, Versions: tc.versions}
			if err := replace(s, tc.eco, Vuln{ID: "test", Affected: []Affected{a, a}}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Lookup(a.Package, tc.version)
			if err != nil || (len(got) == 1) != tc.want || len(got) > 1 {
				t.Fatalf("lookup: %v %v", got, err)
			}
		})
	}
}
func TestSemver(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "2.0.0", "99999999999999999999999999.0.0"}
	for i := 1; i < len(ordered); i++ {
		a, _ := parseVersion(ordered[i-1])
		b, _ := parseVersion(ordered[i])
		if compareVersion(a, b) >= 0 || compareVersion(b, a) <= 0 {
			t.Fatal(ordered[i])
		}
	}
	for _, v := range []string{"1", "01.0.0", "1.0.0-01", "1.0.0-", "1.0.0+", "1.0.0-a..b"} {
		if _, ok := parseVersion(v); ok {
			t.Fatalf("accepted %q", v)
		}
	}
	a, _ := parseVersion("1.2.3+build")
	b, _ := parseVersion("1.2.3+other")
	if compareVersion(a, b) != 0 {
		t.Fatal("metadata affects ordering")
	}
}
