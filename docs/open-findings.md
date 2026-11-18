# Open findings

Defects that a whole-tree review found, verified, and did **not** fix.

[review-dispositions.md](review-dispositions.md) is the author's account of
work already done, which is the weakest kind of evidence a document can
offer. This page is the opposite: it is the part of the review that is still
outstanding, written down so that "the review is finished" cannot quietly
come to mean "the review stopped".

Every entry below was reproduced against the real code — by running the
module, by measuring the repo's own cached data, or by reading a value back
out of the process — not inferred from reading. Each says what it costs, so
the next person can rank them rather than re-derive them.

Nothing here is a guess. Where confidence is below certain, the entry says
so in its own words.

## How this page was produced

Five reviews ran in parallel over the whole tree, one per area, each with a
file list and no shared context:

| Area | Files |
|---|---|
| HTTP layer | `app.py`, `security.py`, `openapi.py`, `jobs.py`, `http_retry.py`, `config.py` |
| Search pipeline | `search_service.py`, `cache.py`, `query_filters.py`, `records.py`, `cvss.py` |
| Source clients | `osv_client.py`, `nvd_client.py`, `ghsa_client.py`, `epss_client.py` |
| AI and taxonomy | `ai_classifier.py`, `cwe_categories.py`, `generate_cwe_catalog.py` |
| Tooling and deployment | `tools/*.py`, `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh`, `run.sh` |

`modules/cwe_catalog.py` is generated data and was not reviewed as code.
The frontend (`static/`, `templates/`) was reviewed directly rather than by
a separate pass, as part of the design work.

Two areas independently reported the same NVD `affects` defect below, which
is the one finding here with two witnesses.

## Correctness

**An advisory can be in the cache twice, under two primary keys.**
`search_service._merge_group` picks its base with `min(records, key=source
priority)`, and `min` returns the *first* minimum — so when a group holds two
records of the same source the base is decided by the order the upstream API
paginated. Two GHSA advisories sharing a CVE (GitHub's own "Duplicate
Advisory" pairing) therefore merge to `advisory_id` GHSA-AAAA under
`direction=desc` and GHSA-BBBB under `asc`. `cache.upsert_advisories` then
holds two rows for one advisory, and a classify call on the second is a cache
miss that re-spends tokens. Same cause: an NVD-only group is keyed by its
CVE, so the same advisory keys differently depending on which sources ran.

**`affects` silently deletes every NVD-only row.** `nvd_client` names
packages `vendor:product` from the CPE criteria; `query_filters.matches_package`
requires exact equality against the package name. Reproduced against the real
CPE for CVE-2021-23337: the name is `lodash:lodash`, and
`matches_package(record, "lodash")` is `False`. So `affects=lodash` with
`sources=["ghsa","nvd"]` drops every NVD-only group — while `per_source`
reports a healthy NVD count, and no warning is emitted, although the same
function goes out of its way to warn about the `type` and `ecosystem` filters
it cannot honour. Found independently by two reviews.

**The per-source limit is applied on a different key than the requested
sort.** For `sort` in `cve_id`, `epss_percentage` or `epss_percentile`,
`run_search` asks GHSA for the top `max_results` by *published*, then
re-sorts locally. A 2021 CVE with EPSS 0.97 is never a candidate for an
EPSS-sorted search, and `stats.truncated` reads `false` because the merge
fitted. GHSA supports `cve_id` natively, so part of this is free to fix; the
EPSS sorts need a warning instead.

**`cvss_score` and `cvss_vector` can come from different sources.** The score
is the max across sources; the vector is first-wins in collection order. A
merged row can therefore ship `cvss_score: 9.8` beside a vector that
recomputes to 5.5, with no `cvss_vector_by_source` for an auditor to check
against.

**`cve_id` sort puts CVE-less rows first.** `_cve_sort_key` sorts them below
real CVEs ascending, as its docstring says — but `direction` defaults to
`desc`, which inverts it. An `osv-native` search, where most records have no
CVE, opens on a page of nothing but CVE-less rows.

**OSV renders a version range that drops vulnerable branches.**
`_introduced_range` folds every event in a range into one
`introduced`/`fixed` pair, keeping the last of each, so a range expressing
several vulnerable branches loses all but the final one. Measured against the
repo's own `osv_cache/Go.zip`: 928 of 15,341 affected entries (6.0%) carry
more than one `introduced`, and 906 render a `vulnerable_version_range` that
contradicts the `first_patched_version` beside it. `GO-2021-0068` renders
`>= 1.15.0-0, < 1.15.7` next to `first_patched_version: 1.14.14`; the truth
is `[0, 1.14.14) ∪ [1.15.0-0, 1.15.7)`. An operator on Go 1.13 reads that and
concludes they are unaffected. This is an under-report, which is the
expensive direction for a triage tool.

**A quota marker matches inside a rate-limit message.** `_QUOTA_MARKERS`
contains the bare word `quota` and is tested before `_RATE_MARKERS`, so
`"Rate limit reached; your quota resets in 20s"` parks the key for six hours
*and persists that to disk*. On a single-key install the rest of the batch
then fails as "AI quota exhausted", and the restart that would have cleared
it does not, because it was persisted.

**`find("{")` … `rfind("}")` spans two objects** when a model echoes the
schema before answering, so the whole retry budget is spent per advisory
before it lands as "unreadable reply".

## Availability

**NVD has no fetch deadline and no cap on upstream calls.** `ghsa_client` has
`FETCH_DEADLINE_SECONDS`; NVD has nothing, and sleeps `_request_delay()`
between every CWE without consulting the clock. Selecting all bug classes
resolves to 158 CWEs; without `NVD_API_KEY` that is 158 × 6.5s = **1027
seconds of mandatory sleep** before a single round trip, against a gunicorn
`--timeout 180` with `--workers 1 --threads 8`. The worker is killed and
takes all eight threads with it, aborting every other in-flight search. One
click on "select all" is a self-DoS.

**NVD fetches a full 2,000-row page and discards it.** The paging code binds
`vulns` from the `startIndex=0` page and then rebinds it from the tail page.
That doubles the request count against the tightest rate limit in the app
(4.6 req/30s against NVD's 5/30s), and `tail_index` is computed from the
first response's `totalResults`, so records published between the two calls
are missed — from a page that was thrown away anyway.

**EPSS enrichment has no deadline.** Each batch retries independently and
failures are swallowed per batch, so a FIRST outage costs the full budget
rather than failing fast: `sort=epss_percentage` with `max_results=500`
enriches up to 2,000 CVEs in 20 batches, ≈1240s inside one request.

**The OSV download lock wraps the warm-cache check.** `_DOWNLOAD_LOCK` is
process-wide and is taken *before* the "already cached and fresh?"
short-circuit, so a search for `go` blocks behind a 221 MB `npm` download for
a file it was never going to fetch.

**Jobs have no backpressure.** `submit()` never looks at how many jobs are
already queued, and the executor queue is unbounded in front of one worker.
Every POST still answers `202` with a poll URL that may not resolve for days,
and there is no cancellation.

**NVD paging dereferences shapes the API does not guarantee.** Reproduced:
`{"vulnerabilities": [None]}` raises `AttributeError` and
`{"totalResults": "many"}` raises `ValueError`, neither of which is an
`NvdError` — so they escape as a 500 and discard the GHSA and OSV results
already collected in the same request. The guard that was added for this
covers `normalize`, not the paging code that runs before it.

**An optional cache write can kill a successful search.**
`cache.upsert_advisories` is unguarded although the cache is documented as
optional, so a locked or full database discards minutes of completed fetching
as a 500.

## Tooling that can report success without measuring

**`audit_tests.py --strict` cannot currently fail**, and two of the five
detectors its docstring advertises — `self-fulfilling` and `reimplements` —
are not implemented by any code path. A run reports 33 findings, all
`loop-only`, which `--strict` excludes. It also has no floor: an empty
`tests/` glob prints "nothing flagged" and exits 0.

**`design_audit.py` exits 0 when playwright is missing**, so wired into CI
without a browser it passes forever having measured nothing. It also
discards the `page.goto` response, and Flask's 404 body is exactly one `h1`
with no overflow and no JS errors — so if `/api/docs` stopped registering,
the three states added specifically to cover that page would audit the 404
and report clean.

**`sync_module_map.py` reports "already accurate" when it parses zero rows**,
the same false-negative shape that `sync_check_counts.py` had and that is now
fixed there.

**A second edit to the same file can silently no-op.** The revert harness
pre-checks anchors against the original text but applies replacements
cumulatively, so if edit 1 consumes edit 2's anchor, `str.replace` returns
the string unchanged and a half-applied revert reports as a pass. Six of the
current checks have two edits on one file; none no-ops today.

## Deployment

**`chown -R vulnsight:vulnsight /app`** makes the whole application source
writable by the runtime user, so any file-write primitive becomes persistent
code execution that survives a restart. `/data` needs to be writable; `/app`
does not.

**Floating pins plus layer caching ship stale dependencies.**
`requirements.txt` is `Flask>=3.1.2,<4`; the `pip install` layer is keyed on
that file's content, which never changes, so a rebuild after a Flask security
release installs nothing new — into an image that holds a GitHub token and AI
keys. Two builds from one commit are also not reproducible.

**Credentials are delivered as container environment variables**, so they
appear in `docker inspect`, `/proc/1/environ` and `docker compose config` —
the last being the first thing anyone pastes into a bug report.

**`run.sh` makes its one credential-protecting step non-fatal.**
`chmod 600 .env 2>/dev/null || true` defeats the `set -e` above it and never
verifies the result, so the server can start with a readable credentials file
and say nothing.

## Smaller, verified

- `write_atomic` does not preserve permissions: `mkstemp` creates at 0600 and
  `os.replace` carries that mode, so every file it touches is narrowed to
  0600. Verified: a 0644 file comes back 0600. It also never `fsync`s, so the
  crash-safety claim holds for Ctrl-C but not for power loss.
- The AI cooldown file writes through a fixed `.tmp` path, so two workers
  interleave into one file, `os.replace` publishes invalid JSON, and every
  recorded cooldown is silently lost. `tools.write_atomic` already solves
  this and is not used here.
- The verdict fingerprint hashes `packages` and `cwes` in merge order, so the
  same advisory fingerprints differently depending on which sources answered,
  and cached verdicts are re-paid for no semantic change.
- `If-None-Match` is compared with `==`, so a legal multi-tag or `*`
  conditional re-serves the full body — on an endpoint whose own comment
  frames the 304 as a DoS control.
- `/api/v1/ai/test` declares its body optional; the handler returns 415
  without one. Neither 415 nor the 400 is in the spec.
- `openapi.py` registers six `components.schemas` and uses `$ref` zero times,
  so generators emit anonymous inline models.
- A non-retryable, non-key-exhausted AI error (a wrong `AI_MODEL`, HTTP 400)
  is still retried across every configured key with no backoff, so eight keys
  turn one impossible request into eight paid calls.
- `osv_client` caps the *compressed* stream but decompresses without a bound.
- `_is_transient_gh_error` matches markers as substrings, so a 404 whose body
  contains `1503` retries three times.
- An empty API-token file crashes startup with a bare `FileExistsError`
  pointing at "file exists" when the problem is "file is empty".
- `jobs.shutdown()` has no production caller and its docstring's premise is
  wrong: executor threads are non-daemon and CPython joins them at exit, so
  shutdown is neither graceful nor prompt.
