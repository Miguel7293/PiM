package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPersistenceAndKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "mirror.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pkg := Package{"npm", "../../@scope/demo"}
	want := []Vuln{{ID: "GHSA-test", Aliases: []string{"CVE-test"}, Affected: []Affected{{Package: pkg, Ranges: []Range{{Type: "SEMVER", Events: []map[string]string{{"introduced": "0"}, {"fixed": "2"}}}}, Versions: []string{"1"}}}}}
	if err = s.Put(pkg, "1", want); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	header, err := os.ReadFile(path)
	if err != nil || string(header[:16]) != "SQLite format 3\x00" {
		t.Fatalf("not SQLite: %v", err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Lookup(pkg, "1")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("lookup = %#v, %v", got, err)
	}
	for _, key := range []struct {
		pkg     Package
		version string
	}{{pkg, "2"}, {Package{"PyPI", pkg.Name}, "1"}, {Package{"npm", "other"}, "1"}} {
		if _, err = s.Lookup(key.pkg, key.version); !errors.Is(err, ErrNotFound) {
			t.Fatalf("miss = %v", err)
		}
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM affected_packages WHERE ecosystem='npm' AND ranges LIKE '%fixed%'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("affected = %d, %v", count, err)
	}
	if err = s.db.QueryRow(`SELECT count(*) FROM schema_version WHERE version=1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration = %d, %v", count, err)
	}
	if err = s.Put(pkg, "1", nil); err != nil {
		t.Fatal(err)
	}
	got, err = s.Lookup(pkg, "1")
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty = %v, %v", got, err)
	}
}

func TestDefaultPathAndValidation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PIM_DATA_DIR", dir)
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = os.Stat(filepath.Join(dir, "pim.db")); err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []Package{{}, {"npm", ""}, {"", "demo"}} {
		if err = s.Put(pkg, "1", nil); err == nil {
			t.Fatal("expected validation error")
		}
		if _, err = s.Lookup(pkg, "1"); err == nil {
			t.Fatal("expected validation error")
		}
	}
	pkg := Package{"npm", "demo"}
	if err = s.Put(pkg, "", nil); err == nil {
		t.Fatal("expected version error")
	}
	if err = s.Put(pkg, "1", []Vuln{{}}); err == nil {
		t.Fatal("expected ID error")
	}
}

func TestRollbackAndFutureSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pim.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pkg := Package{"Go", "example.org/demo"}
	if err = s.Put(pkg, "1", []Vuln{{ID: "old"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER reject_lookup BEFORE UPDATE ON lookups BEGIN SELECT RAISE(ABORT,'test failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if err = s.Put(pkg, "1", []Vuln{{ID: "new"}}); err == nil {
		t.Fatal("expected transaction failure")
	}
	got, err := s.Lookup(pkg, "1")
	if err != nil || len(got) != 1 || got[0].ID != "old" {
		t.Fatalf("old snapshot lost: %v %v", got, err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM vulns WHERE id='new'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial write: %d %v", count, err)
	}
	if _, err = s.db.Exec(`INSERT INTO schema_version VALUES(999)`); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path); err == nil {
		other.Close()
		t.Fatal("expected unsupported schema error")
	}
}
