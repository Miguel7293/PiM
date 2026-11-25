# OSV bulk mirror

`store.Open(path)` opens an offline SQLite mirror. An empty path uses
`PIM_DATA_DIR/pim.db` (or `./pim.db`). Close the store after use.

Call `OSVBulk.Ingest(ctx, dst, "Go")` or `"npm"` explicitly when preparing or
updating the mirror. It downloads the complete ecosystem's `all.zip` from
`https://osv-vulnerabilities.storage.googleapis.com/{Ecosystem}/all.zip`.
It never sends client package names or versions. Scans must only call `Lookup`.
`BaseURL` and `HTTPClient` are configurable for local fixtures.

Downloads use a temporary file, removed on success or failure. Default limits
are 1 GiB downloaded, 16 MiB decompressed per entry, and 1,000,000 ZIP entries.
`MaxDownloadBytes`, `MaxEntryBytes`, and `MaxEntries` override these limits;
zero selects defaults and negative values are rejected. Entries are processed
one at a time, never extracted to filesystem paths. Invalid ZIP/JSON, checksums,
HTTP failures, exceeded limits, and canceled contexts preserve the old snapshot.

Replacement uses one transaction per ecosystem. Only that ecosystem's affected
package rows are replaced; other ecosystems and sources remain available.
Generic vulnerability records are retained, including records from earlier
snapshots. Matching uses the current affected-package rows. `mirror_runs`
records each successful source, ecosystem, UTC fetch time, and record count.
Migration 2 drops tuple-based `lookups` without deleting existing `vulns`.
Legacy tuple data does not establish complete ecosystem coverage.

`Lookup(pkg, version)` is entirely local. An ecosystem never bulk-ingested
returns `store.ErrNotFound`; an ingested ecosystem with no matches returns an
empty non-nil slice. Explicit versions match exactly (Go's leading `v` is
normalized). SEMVER and ECOSYSTEM ranges support introduced, exclusive fixed,
inclusive last_affected, and exclusive limit events, including introduced `0`,
multiple intervals, prereleases, and Go pseudo-versions. Build metadata does
not affect range ordering. GIT ranges are ignored because version strings do
not establish commit ancestry. PyPI/PEP 440 is outside this implementation.
Format reference: https://ossf.github.io/osv-schema/.

Version matching can produce false positives: findings do not establish that
a vulnerable dependency is used or exploitable. Verification is separate.
Tests generate synthetic ZIP fixtures and use local HTTP servers only.
