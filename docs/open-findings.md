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
check. What remains is below.

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

### A second edit to the same file can silently no-op

`tools/revert_checks.py` pre-checks every anchor against the file's
*original* text, then applies the replacements *cumulatively*. If edit 1
consumes or alters edit 2's anchor, `str.replace` returns the string
unchanged and no error is raised — so a half-applied revert is scored as a
pass.

`tools/checks/__init__.py` warns about exactly this consequence ("reverting
either alone leaves the behaviour correct and the check reports a false
pass") and nothing enforces it. Several current checks have two edits on one
file and none no-ops today, so this is latent rather than live. The fix is
to assert each `find` is present in the *patched* text immediately before
its replace, and report `ANCHOR MISSING` rather than continuing.

### The design audit never opens anything

It measures what is visible when the page loads. The results surface is now
populated before measuring, but four surfaces are still never opened: the
auth gate, the export popover, the CWE combobox listbox, and the mobile
filters slide-over. `shown()` does not walk ancestors, but zero-size rects
filter those elements out anyway, so they are skipped entirely — and the
auth gate has its own revert check, which means a focus-trap regression
would be caught by the browser tests and not by the audit.

### `cache.py` migrations split on a semicolon

`for stmt in sql.split(";")` splits a statement in half if a future
migration contains a semicolon inside a comment or a string literal. DDL
also runs in sqlite3's autocommit mode while the `INSERT INTO
schema_version` is transactional, so a hard failure in migration *N* rolls
back the stamps for 1..N-1 whose DDL already committed, and every
subsequent boot re-runs the whole list — including v4's full-table
`UPDATE advisories SET data = json_set(...)`.

Self-healing via `_BENIGN_MIGRATION_ERRORS`, so this is a slow-startup and
maintainability problem rather than a corruption one. Separately, treating
`"no such column"` as blanket-benign will stamp a genuinely broken future
migration as applied.

### `shutdown()` still blocks on a running job

Queued work is dropped at exit now, but a job already executing still holds
interpreter exit open, because `ThreadPoolExecutor`'s workers are
non-daemon and CPython joins them through `threading._register_atexit`. A
four-minute NVD sweep therefore delays shutdown until Docker's stop timeout
turns SIGTERM into SIGKILL. Bounded by the job rather than by the stop
timeout; fixing it properly needs the runner to check a cancellation flag
between CWEs.

### MITRE Categories are absent from the catalog

`NAMES` holds `Weakness` entries only — `'1035' in NAMES` is `False`. An
advisory tagged with a Category id renders as a bare "CWE-1035" and
`is_known_category("cwe:1035")` rejects it in the picker.

### `audit_tests.py`'s "must not raise" escape is a substring match

The `says_so` check looks for phrases like "must not raise" and "is safe"
anywhere in a function's source *or its name*. A test with no assertions
whose body happens to contain one of those phrases — in a variable, a
comment, an unrelated string — is silently cleared. It also walks nested
`def`s, so a test that *defines* a helper containing assertions but never
calls it counts as asserting.

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
