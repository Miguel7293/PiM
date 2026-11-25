// Package store provides an offline SQLite vulnerability mirror.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("ecosystem is not mirrored")

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

// Lookup evaluates only locally stored evidence and never contacts a source.
func (s *SQLiteStore) Lookup(pkg Package, version string) ([]Vuln, error) {
	if err := pkg.Validate(version); err != nil {
		return nil, fmt.Errorf("lookup mirror: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin lookup: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow(`SELECT 1 FROM mirror_runs WHERE source='OSV' AND ecosystem=? LIMIT 1`, pkg.Ecosystem).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("read mirror metadata: %w", err)
	}
	rows, err := tx.Query(`SELECT v.payload,a.ranges,a.versions FROM affected_packages a JOIN vulns v ON v.source=a.source AND v.id=a.vuln_id WHERE a.source='OSV' AND a.ecosystem=? AND a.package=? ORDER BY v.id`, pkg.Ecosystem, pkg.Name)
	if err != nil {
		return nil, fmt.Errorf("query affected packages: %w", err)
	}
	defer rows.Close()
	result := []Vuln{}
	seen := map[string]bool{}
	for rows.Next() {
		var payload, ranges, versions string
		if err := rows.Scan(&payload, &ranges, &versions); err != nil {
			return nil, fmt.Errorf("read affected package: %w", err)
		}
		a := Affected{Package: pkg}
		var v Vuln
		for _, item := range []struct {
			data string
			dst  any
		}{{payload, &v}, {ranges, &a.Ranges}, {versions, &a.Versions}} {
			if err := json.Unmarshal([]byte(item.data), item.dst); err != nil {
				return nil, fmt.Errorf("decode mirror: %w", err)
			}
		}
		if !seen[v.ID] && matches(a, version) {
			result = append(result, v)
			seen[v.ID] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read mirror: %w", err)
	}
	return result, nil
}

// ReplaceOSV consumes one record at a time in a single ecosystem transaction.
// The producer must return any decoding error so the previous snapshot survives.
func (s *SQLiteStore) ReplaceOSV(ctx context.Context, ecosystem string, produce func(func(Vuln) error) error) error {
	if ecosystem != "Go" && ecosystem != "npm" {
		return fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin mirror update: %w", err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM affected_packages WHERE source='OSV' AND ecosystem=?`, ecosystem); err != nil {
		return fmt.Errorf("clear ecosystem: %w", err)
	}
	count := 0
	seen := map[string]bool{}
	err = produce(func(v Vuln) error {
		if strings.TrimSpace(v.ID) == "" || seen[v.ID] {
			return fmt.Errorf("invalid or duplicate vulnerability ID %q", v.ID)
		}
		seen[v.ID] = true
		payload, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encode vulnerability: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO vulns(source,id,payload) VALUES('OSV',?,?) ON CONFLICT(source,id) DO UPDATE SET payload=excluded.payload`, v.ID, string(payload)); err != nil {
			return fmt.Errorf("store vulnerability: %w", err)
		}
		for _, a := range v.Affected {
			if a.Package.Ecosystem != ecosystem {
				continue
			}
			if strings.TrimSpace(a.Package.Name) == "" {
				return errors.New("empty affected package name")
			}
			ranges, _ := json.Marshal(a.Ranges)
			versions, _ := json.Marshal(a.Versions)
			if _, err = tx.ExecContext(ctx, `INSERT INTO affected_packages(source,vuln_id,ecosystem,package,ranges,versions) VALUES('OSV',?,?,?,?,?)`, v.ID, ecosystem, a.Package.Name, string(ranges), string(versions)); err != nil {
				return fmt.Errorf("store affected package: %w", err)
			}
		}
		count++
		return nil
	})
	if err != nil {
		return fmt.Errorf("replace OSV ecosystem: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mirror_runs(source,ecosystem,fetched_at,vuln_count) VALUES('OSV',?,?,?)`, ecosystem, time.Now().UTC().Format(time.RFC3339Nano), count); err != nil {
		return fmt.Errorf("record mirror run: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit mirror: %w", err)
	}
	return nil
}
