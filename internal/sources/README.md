# OSV mirror

`store.Open(path)` opens a SQLite file using the pure-Go modernc.org/sqlite
 driver. An empty path uses `PIM_DATA_DIR/pim.db`, or `./pim.db` when unset.
Close the store after use. Reopening the same file preserves results offline.

`OSVClient.Refresh(ctx, dst, pkg, version)` explicitly ingests all pages from
OSV into a transactional snapshot. `Fetch` retains IDs, CVE aliases, summaries,
affected packages, versions, and ranges. Prepare this mirror separately with an
approved catalog: ingestion sends the specified package and version to OSV.
Do not invoke ingestion with a client's discovered stack during an assessment.

`Lookup(store.Package{Ecosystem: "npm", Name: "example"}, "1.0.0")` reads only
SQLite. A miss returns `store.ErrNotFound`, without network fallback. An empty
list means that exact tuple was ingested with no known findings. Tuple strings
are matched exactly. Failed ingestion preserves the last successful snapshot.

Versioned migrations use `schema_version`. Generic `vulns` records are keyed by
source and ID; `affected_packages` retains ecosystem, package, ranges and
explicit versions. These tables leave room for other structured sources.
`lookups` keeps complete exact-tuple OSV snapshots, including empty responses.
Ranges are retained as evidence; this implementation does not infer matches for
versions that have not been ingested. Newer unsupported schemas are rejected.

Version-to-CVE matching can produce false positives. These records are potential
findings, not confirmation of exploitability. Verification is outside this scope.
Tests use synthetic fixtures and local HTTP servers, never the public API.
