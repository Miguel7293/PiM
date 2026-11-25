package store

import "fmt"

var migrations = []string{`
CREATE TABLE vulns (
 source TEXT NOT NULL,
 id TEXT NOT NULL,
 payload TEXT NOT NULL,
 PRIMARY KEY(source,id)
);
CREATE TABLE affected_packages (
 source TEXT NOT NULL,
 vuln_id TEXT NOT NULL,
 ecosystem TEXT NOT NULL,
 package TEXT NOT NULL,
 ranges TEXT NOT NULL,
 versions TEXT NOT NULL,
 FOREIGN KEY(source,vuln_id) REFERENCES vulns(source,id)
);
CREATE INDEX affected_package_lookup ON affected_packages(ecosystem,package);
CREATE TABLE lookups (
 ecosystem TEXT NOT NULL,
 package TEXT NOT NULL,
 version TEXT NOT NULL,
 result TEXT NOT NULL,
 PRIMARY KEY(ecosystem,package,version)
);
`, `
DROP TABLE lookups;
CREATE TABLE mirror_runs (
 source TEXT NOT NULL,
 ecosystem TEXT NOT NULL,
 fetched_at TEXT NOT NULL,
 vuln_count INTEGER NOT NULL
);
CREATE INDEX mirror_runs_ecosystem ON mirror_runs(source,ecosystem);
`}

func (s *SQLiteStore) migrate() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}
	var version int
	if err = tx.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_version`).Scan(&version); err != nil {
		return err
	}
	if version < 0 || version > len(migrations) {
		return fmt.Errorf("unsupported schema version %d", version)
	}
	for i := version; i < len(migrations); i++ {
		if _, err = tx.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err = tx.Exec(`INSERT INTO schema_version(version) VALUES(?)`, i+1); err != nil {
			return err
		}
	}
	return tx.Commit()
}
