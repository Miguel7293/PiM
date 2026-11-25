// Package store provides an offline SQLite vulnerability mirror.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("package version is not mirrored")

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

func (p Package) Validate(version string) error {
	if strings.TrimSpace(p.Ecosystem) == "" || strings.TrimSpace(p.Name) == "" || strings.TrimSpace(version) == "" {
		return errors.New("ecosystem, package name and version are required")
	}
	return nil
}

// Vuln is a potential finding. Version matching can produce false positives;
// verification of exploitability is outside this package's scope.
type Vuln struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases,omitempty"`
	Summary  string     `json:"summary,omitempty"`
	Affected []Affected `json:"affected,omitempty"`
}

type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

type Range struct {
	Type   string              `json:"type"`
	Repo   string              `json:"repo,omitempty"`
	Events []map[string]string `json:"events"`
}

type Store interface {
	Lookup(Package, string) ([]Vuln, error)
	Put(Package, string, []Vuln) error
}

type SQLiteStore struct{ db *sql.DB }

// Open accepts a database file path. Empty uses PIM_DATA_DIR/pim.db (or ./pim.db
// when the environment variable is unset). Call Close when finished.
func Open(path string) (*SQLiteStore, error) {
	if path == "" {
		path = filepath.Join(os.Getenv("PIM_DATA_DIR"), "pim.db")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve mirror path: %w", err)
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return nil, fmt.Errorf("create mirror directory: %w", err)
	}
	db, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, fmt.Errorf("open mirror: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &SQLiteStore{db: db}
	if _, err = db.Exec("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;"); err == nil {
		err = s.migrate()
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize mirror: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// Lookup never contacts a source. Only explicitly mirrored tuples are available;
// ranges are retained as source evidence, not evaluated with guessed semantics.
func (s *SQLiteStore) Lookup(pkg Package, version string) ([]Vuln, error) {
	if err := pkg.Validate(version); err != nil {
		return nil, fmt.Errorf("lookup mirror: %w", err)
	}
	var data string
	err := s.db.QueryRow(`SELECT result FROM lookups WHERE ecosystem=? AND package=? AND version=?`, pkg.Ecosystem, pkg.Name, version).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("lookup mirror: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("lookup mirror: %w", err)
	}
	var result []Vuln
	if err = json.Unmarshal([]byte(data), &result); err != nil {
		return nil, fmt.Errorf("decode mirror: %w", err)
	}
	return result, nil
}

// Put atomically stores an OSV snapshot and its generic vulnerability records.
// Separate lookup snapshots preserve the exact response for each mirrored tuple.
func (s *SQLiteStore) Put(pkg Package, version string, vulns []Vuln) error {
	if err := pkg.Validate(version); err != nil {
		return fmt.Errorf("write mirror: %w", err)
	}
	for _, v := range vulns {
		if strings.TrimSpace(v.ID) == "" {
			return errors.New("write mirror: empty vulnerability ID")
		}
	}
	if vulns == nil {
		vulns = []Vuln{}
	}
	data, err := json.Marshal(vulns)
	if err != nil {
		return fmt.Errorf("encode mirror: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin mirror update: %w", err)
	}
	defer tx.Rollback()
	for _, v := range vulns {
		payload, _ := json.Marshal(v)
		if _, err = tx.Exec(`INSERT INTO vulns(source,id,payload) VALUES('OSV',?,?) ON CONFLICT(source,id) DO UPDATE SET payload=excluded.payload`, v.ID, string(payload)); err != nil {
			return fmt.Errorf("store vulnerability: %w", err)
		}
		if _, err = tx.Exec(`DELETE FROM affected_packages WHERE source='OSV' AND vuln_id=?`, v.ID); err != nil {
			return fmt.Errorf("replace affected packages: %w", err)
		}
		for _, a := range v.Affected {
			ranges, _ := json.Marshal(a.Ranges)
			versions, _ := json.Marshal(a.Versions)
			if _, err = tx.Exec(`INSERT INTO affected_packages(source,vuln_id,ecosystem,package,ranges,versions) VALUES('OSV',?,?,?,?,?)`, v.ID, a.Package.Ecosystem, a.Package.Name, string(ranges), string(versions)); err != nil {
				return fmt.Errorf("store affected package: %w", err)
			}
		}
	}
	if _, err = tx.Exec(`INSERT INTO lookups(ecosystem,package,version,result) VALUES(?,?,?,?) ON CONFLICT(ecosystem,package,version) DO UPDATE SET result=excluded.result`, pkg.Ecosystem, pkg.Name, version, string(data)); err != nil {
		return fmt.Errorf("store lookup: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit mirror update: %w", err)
	}
	return nil
}
