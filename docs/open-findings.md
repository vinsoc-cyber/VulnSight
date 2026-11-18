# Open findings

What the whole-tree review found and has **not** fixed.

[review-dispositions.md](review-dispositions.md) is the author's account of
work already done, which is the weakest kind of evidence a document can
offer. This page is the opposite: it is the part of the review that is still
outstanding, written down so that "the review is finished" cannot quietly
come to mean "the review stopped".

Every entry was reproduced against the real code — by running the module, by
measuring the repo's own cached data, or by reading a value back out of the
process — not inferred from reading. Where confidence is below certain, the
entry says so in its own words.

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

### The default order is not a triage order

The workspace lists results by publication date, so a LOW advisory at 1%
EPSS sits above a CRITICAL one that is being actively exploited. The
interface no longer *claims* otherwise — it says "newest first" on the
result line, and the direction control names the field it is sorting — but
the stated primary job is "decide what to look at next", and date order does
not serve it.

The fix is a risk-ordered sort (severity, KEV, EPSS) offered as the default,
which is a product decision rather than a defect: it changes what every
existing API caller gets back. Raised here rather than made unilaterally.

### `openapi.py` describes responses the handlers do not send

- `/api/v1/ai/test` declares its body optional; the handler returns **415**
  without one, and **400** for a non-object body. Neither status is in the
  spec. Verified with a live request.
- `/api/v1/ai/classify` omits **415**, which `_json_object` can return,
  while `/search` and `/jobs` both list it.
- `/search` and `/jobs` omit **403** (CSRF) and **413** (`MAX_CONTENT_LENGTH`),
  both reachable on those paths.

This is the one failure mode the file's own header says it exists to
prevent: "an invented schema is worse than none, because a client generator
will believe it". `tests/test_openapi.py` checks path and method parity and
validates the responses it actually elicits, so nothing catches a status the
tests never provoke.

### `components.schemas` is dead

`grep -c '\$ref' modules/openapi.py` is **0**. All six registered schemas are
inlined by object identity at their use sites, so the served document carries
each one twice (`_ERROR` six times) and a generator emits anonymous inline
models instead of `Error`, `Advisory`, `Job`, `SearchResponse`. `_VERDICT`
and `_CLASSIFY_RESPONSE` are never registered at all.

### The spec hardcodes limits it could import

`categories.maxItems: 100` duplicates `search_service.MAX_CATEGORY_INPUTS`,
which the file already imports and uses correctly for classify.
`affects.maxLength: 300` and `max_results.maximum: 500` duplicate literals in
`parse_search_query`. They agree today; raising `MAX_CATEGORY_INPUTS` leaves
the spec saying 100 and no test fails.

### Deployment

- **`chown -R vulnsight:vulnsight /app`** makes the whole application source
  writable by the runtime user, so any file-write primitive becomes
  persistent code execution that survives a restart. `/data` needs to be
  writable; `/app` does not.
- **Floating pins plus layer caching ship stale dependencies.**
  `requirements.txt` is `Flask>=3.1.2,<4`; the `pip install` layer is keyed
  on that file's content, which never changes, so a rebuild after a Flask
  security release installs nothing new — into an image holding a GitHub
  token and AI keys. Two builds from one commit are also not reproducible.
- **Credentials arrive as container environment variables**, so they appear
  in `docker inspect`, `/proc/1/environ` and `docker compose config` — the
  last being the first thing anyone pastes into a bug report. The app already
  writes its own token to a 0600 file, so the file-based pattern exists.
- **`run.sh` makes its one credential-protecting step non-fatal.**
  `chmod 600 .env 2>/dev/null || true` defeats the `set -e` above it and
  never verifies the result, so the server can start with a readable
  credentials file and say nothing.

### Tooling that can still report success without measuring

- **`audit_tests.py` advertises five detectors and implements three.**
  `self-fulfilling` and `reimplements` are produced by no code path, and
  `loop-only` is produced but undocumented. It also has no floor: an empty
  `tests/` glob prints "nothing flagged" and exits 0 under `--strict`.
- **`design_audit.py` exits 0 when playwright is missing**, so wired into CI
  without a browser it passes forever having measured nothing. It also
  discards the `page.goto` response, and Flask's 404 body is exactly one
  `h1` with no overflow and no JS errors — so if `/api/docs` stopped
  registering, the states added to cover it would audit the 404 and report
  clean.
- **`sync_module_map.py` reports "already accurate" when it parses zero
  rows**, the same false-negative shape that `sync_check_counts.py` had and
  that is now fixed there.
- **A second edit to the same file can silently no-op.** The revert harness
  pre-checks anchors against the original text but applies replacements
  cumulatively, so if edit 1 consumes edit 2's anchor, `str.replace` returns
  the string unchanged and a half-applied revert reports as a pass. Several
  current checks have two edits on one file; none no-ops today.

### Smaller, verified

- `write_atomic` does not preserve permissions: `mkstemp` creates at 0600 and
  `os.replace` carries that mode, so every file it touches is narrowed to
  0600. Verified: a 0644 file comes back 0600. It also never `fsync`s, so the
  crash-safety claim holds for Ctrl-C but not for power loss.
- `cache.py` migrations split on `";"`, so a semicolon inside a future
  comment or string literal splits a statement; and DDL runs in autocommit
  while the version stamp is transactional, so a failure in migration *N*
  re-runs 1..N-1 on the next boot. Self-healing, so this is slow-startup
  rather than corruption — but treating `"no such column"` as blanket-benign
  will stamp a genuinely broken future migration as applied.
- `cache.get_classifications` builds an unchunked `IN` clause while
  `get_advisories` ten lines above chunks at 500 with a comment explaining
  why. Bounded at 501 parameters today, so it cannot fire — latent, and an
  inconsistency inside one file.
- `run_search` compares `failed_sources` against *requested* sources rather
  than *attempted* ones, so if every source that actually ran failed but one
  was skipped with a warning, the response is 200 with `count: 0` instead of
  the 502 `docs/api.md` documents.
- An invalid `sort` or `direction` is silently coerced to the default while
  every other invalid field raises a 400.
- `min(published)` / `max(updated)` compare raw timestamp strings across
  sources that format differently. Correct to the second for UTC, wrong on
  sub-second ties and any non-UTC offset. `parse_timestamp` exists for this
  and is not used.
- `osv-native` is never a real `source` value: `normalize_osv` hard-codes
  `"source": "osv"`, so `_SOURCE_PRIORITY["osv-native"]` is unreachable and
  a row's `sources` says `["osv"]` while `per_source` names `osv-native`
  separately.
- `cache.get_advisory` has no production caller.
- `jobs.shutdown` now drops queued work at exit, but a job already executing
  still blocks interpreter exit, because executor threads are non-daemon and
  CPython joins them. Bounded by the job, not by the stop timeout.
- `aggregate_category_verdicts({})` returns a definitive "no" synthesized
  from zero verdicts. Not reachable through `/api/ai/classify` today — the
  view rejects an empty category list — but it is one caller away.
- `NAMES` holds MITRE `Weakness` entries only; `Categories` are absent, so an
  advisory tagged with a Category id renders as a bare "CWE-1035".
- `generate_cwe_catalog.py` validates that its output compiles, but nothing
  checks that the new catalog is not materially smaller than the one it
  replaces, nor that the ~150 ids hard-coded in `cwe_categories.py` survive
  it. A deprecated `EXTRA_ALIASES` entry silently drops its aliases.
- `_is_useful_prefilter_term`'s curated keywords still include some that fire
  on unrelated text: `"overflows"` matches "buffer overflows" into the
  integer class, `"forbidden"` matches "403 Forbidden", `"panic"` matches any
  Go panic.
