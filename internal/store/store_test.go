package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func replace(s *SQLiteStore, eco string, vs ...Vuln) error {
	return s.ReplaceOSV(context.Background(), eco, func(emit func(Vuln) error) error {
		for _, v := range vs {
			if err := emit(v); err != nil {
				return err
			}
		}
		return nil
	})
}
func fixture(id, eco string) Vuln {
	return Vuln{ID: id, Affected: []Affected{{Package: Package{eco, "demo"}, Versions: []string{"1.0.0"}}}}
}
func TestSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "mirror.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Lookup(Package{"Go", "demo"}, "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	for _, eco := range []string{"Go", "npm"} {
		if err = replace(s, eco, fixture("shared", eco)); err != nil {
			t.Fatal(err)
		}
	}
	if err = replace(s, "Go", fixture("new", "Go"), Vuln{}); err == nil {
		t.Fatal("expected rollback")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, eco := range []string{"Go", "npm"} {
		got, err := s.Lookup(Package{eco, "demo"}, "1.0.0")
		if err != nil || len(got) != 1 || got[0].ID != "shared" {
			t.Fatalf("snapshot: %v %v", got, err)
		}
	}
	if err = replace(s, "Go"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(Package{"Go", "demo"}, "1.0.0")
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	got, err = s.Lookup(Package{"npm", "demo"}, "1.0.0")
	if err != nil || len(got) != 1 {
		t.Fatalf("other ecosystem lost: %v %v", got, err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT count(*) FROM mirror_runs`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("runs: %d %v", count, err)
	}
	if _, err = s.Lookup(Package{}, ""); err == nil {
		t.Fatal("invalid package accepted")
	}
	if err = replace(s, "PyPI"); err == nil {
		t.Fatal("unsupported ecosystem accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.ReplaceOSV(ctx, "Go", func(func(Vuln) error) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(migrations[0] + `CREATE TABLE schema_version(version INTEGER PRIMARY KEY); INSERT INTO schema_version VALUES(1); INSERT INTO vulns VALUES('OSV','old','{"id":"old"}');`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var id string
	if err = s.db.QueryRow(`SELECT id FROM vulns`).Scan(&id); err != nil || id != "old" {
		t.Fatalf("vuln lost: %s %v", id, err)
	}
	if _, err = s.db.Exec(`SELECT * FROM lookups`); err == nil {
		t.Fatal("lookups still exists")
	}
	if _, err = s.Lookup(Package{"Go", "demo"}, "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO schema_version VALUES(999)`); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path); err == nil {
		other.Close()
		t.Fatal("future schema accepted")
	}
}
func TestDefaultPath(t *testing.T) {
	t.Setenv("PIM_DATA_DIR", t.TempDir())
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}
