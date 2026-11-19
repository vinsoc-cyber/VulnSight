# Open findings

What the whole-tree review found and has **not** fixed.

[review-dispositions.md](review-dispositions.md) is the author's account of
work already done, which is the weakest kind of evidence a document can
offer. This page is the opposite: the part of the review that is still
outstanding, written down so that "the review is finished" cannot quietly
come to mean "the review stopped".

Every entry was reproduced against the real code — by running the module, by
measuring the repo's own cached data, or by reading a value back out of the
process — not inferred from reading. Where confidence is below certain, the
entry says so.

**This page shrinks.** Everything it listed about the deployment surface,
the published API contract, the tools that could report success without
measuring, and the default sort has been fixed and locked by a revert
check. So has the rest of what it used to carry: `revert_checks.py` now
re-checks each anchor against the patched text instead of the original, so
a second edit to one file cannot silently no-op; the design audit opens
five surfaces it had never opened; `cache.py` splits migrations with
`sqlite3.complete_statement`; `fetch_nvd` stops between CWEs when shutdown
is requested; `audit_tests.py`'s "must not raise" escape reads the
docstring and the name rather than the whole function body; and MITRE's
Groupings are in the catalog.

One entry was removed as **wrong rather than fixed.** It claimed the export
popover was skipped because a closed `<details>` gives its children
zero-size rects. Measured, its three format buttons and its label are in
the ordinary results states whether the popover is open or shut — the
popover is positioned, not `display: none`. A state added for it measured
223 text nodes and 74 targets, identical to `12-results-light` element for
element, so it was removed again: a state that measures nothing new is
worse than no state, because the count implies coverage.

What remains is below.

## How the review was produced

Five reviews ran in parallel over the whole tree, one per area, each with a
file list and no shared context:

| Area | Files |
|---|---|
| HTTP layer | `app.py`, `security.py`, `openapi.py`, `jobs.py`, `http_retry.py`, `config.py` |
| Search pipeline | `search_service.py`, `cache.py`, `query_filters.py`, `records.py`, `cvss.py` |
| Source clients | `osv_client.py`, `nvd_client.py`, `ghsa_client.py`, `epss_client.py` |
| AI and taxonomy | `ai_classifier.py`, `cwe_categories.py`, `generate_cwe_catalog.py` |
| Tooling and deployment | `tools/*.py`, `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh`, `run.sh` |

`modules/cwe_catalog.py` is generated data and was not reviewed as code. The
frontend was reviewed directly as part of the design pass, including the
results surface, which `tools/design_audit.py` had never opened — see
[design](design.md).

Two areas independently reported the same NVD `affects` defect, which is the
one finding that had two witnesses.

## Still open

### A long OSV download cannot be interrupted

`shutdown()` raises a process-wide stop signal, and `fetch_nvd` polls it
between CWEs — which is what the earlier version of this entry asked for,
and it works. `osv_client` does not. Its bulk export read loop
(`osv_client.py:249`) streams an ecosystem's full archive — ~10 MB for
maven or go, ~220 MB for npm — in a `while True` with no cancellation
check, so `docker stop` during a first-use npm fetch still waits out the
stop timeout and turns SIGTERM into SIGKILL.

Bounded by the download rather than unbounded, and the job row is
reconciled on the next boot, so this is a slow-shutdown problem rather
than a correctness one. The fix is the same shape as the NVD one: check
`jobs.shutting_down()` between chunks.

### `"no such column"` is treated as a benign migration error

`cache._BENIGN_MIGRATION_ERRORS` lists it so that a re-run of a
`RENAME COLUMN` migration is self-healing — the old name is gone, which is
the expected outcome rather than a failure. But the match is a substring
over the whole error text, so a genuinely broken future migration that
references a column nobody created is stamped as applied and never runs
again.

Narrower than it was: statements are split with `sqlite3.complete_statement`
now rather than on `;`, so a migration carrying a semicolon in a string or
comment is no longer cut in half. What remains is that the benign-error list
cannot tell "this migration already ran" from "this migration is wrong".
Fixing it means pinning each tolerated error to the migration version that
may raise it, rather than to the whole chain.

### Migration stamping is transactional while the DDL is not

sqlite3 runs DDL in autocommit mode while the `INSERT INTO schema_version`
stamp is inside a transaction. A hard failure in migration *N* therefore
rolls back the stamps for 1..N-1 whose DDL has already committed, and every
subsequent boot re-runs the whole chain — including v4's full-table
`UPDATE advisories SET data = json_set(...)`. Self-healing, so it costs
startup time rather than data.

## Recorded decisions, not defects

These were found, judged, and deliberately left. They are here so that
"nobody noticed" is not a possible reading.

**`osv-native` is a fetch mode, not a record provenance.** `normalize_osv`
hard-codes `"source": "osv"` and `fetch_osv_native` only adds
`native=True`, so a row's `sources` says `["osv"]` while `per_source` names
`osv-native` separately. The entry stays in `_SOURCE_PRIORITY` because the
alternative is a silent fall to the default rank the day a record *is*
stamped that way — which is the defect
`test_every_valid_source_has_an_explicit_base_priority` exists for.

**`cache.get_advisory` has no production caller.** It stays as the
single-row reader the tests use and a revert check reintroduces the per-id
loop through, with a docstring saying plainly that it is not a path to wire
new code onto.

**The class filter narrows the rail and not the map.** Typing "idor" leaves
the rail showing "1 of 29" beside a map still showing twenty-nine. The map
is the overview and collapsing it to a single tile while typing would
destroy that, so the behaviour stands rather than being changed on a
preference.
