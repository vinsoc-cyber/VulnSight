# Review dispositions

Six reviews covered this codebase by dimension: the HTTP layer, the search
pipeline, the source clients, the AI classifier, the CWE taxonomy, and the
frontend. This records what happened to each finding, including the ones
deliberately left alone and why — so "it was reviewed" is checkable rather
than asserted.

**This page only covers findings that were acted on.** A later whole-tree
pass found defects that are verified and still open; they are listed in
[open findings](open-findings.md), including several this page's own
structure would otherwise have hidden. Read that page before concluding
anything from this one.

`fixed` means the behaviour changed and a test covers it. `kept` means the
finding was real and the behaviour is unchanged on purpose. `doc` means the
code was right and the documentation was wrong.

## Checking this table instead of believing it

A table like this is the author's own account of their own work, so none of
it should be taken on trust. Everything below is reproducible from a clean
checkout; the numbers are from the last run.

| What | Command | Result |
|---|---|---|
| Tests | `python -m unittest discover -s tests -p "test_*.py"` | 927 pass |
| Frontend | `node tests/test_frontend_security.js && node tests/test_frontend_finder.js` | pass |
| Lint | `ruff check .` | clean |
| Types | `pyright` | 0 errors |
| Coverage | `python -m coverage run -m unittest discover -s tests && python -m coverage report` | 91% (branch) |
| **Fixes are really locked** | `python tools/revert_checks.py` | **223/223 caught** |

The `caught` figure is read from `docs/revert-results.json`, which
`tools/revert_checks.py` writes when it runs the whole battery.
`tools/sync_check_counts.py` used to write `**N/N caught**` unconditionally
— the strongest evidence row in this document was generated to read as a
perfect score, by a tool that runs no checks. It now refuses to write the
figure at all when no run has published one.

The harness itself had the matching flaw: it only ever observed "red after
the revert", which is also what an already-failing module looks like, so
every check routed to a red module reported `caught`. It measures each
module unpatched first now and reports `BASELINE RED` instead.

The last row is the one that matters. A green suite says nothing about
*which* fixes it defends: the suite was green before these fixes too, because
it did not test the broken behaviour. `tools/revert_checks.py` re-introduces
each of 223 named bugs in the working tree, runs the test module that is
supposed to notice, and requires it to go **red**. A fix whose revert leaves
the suite green is not covered, whatever this table says — that check found
three such gaps on its first run, and they were closed rather than argued
away. Two were genuine (GHSA record degradation had no test through
`run_search`; the `Link`-header test had reimplemented the parser instead of
calling it). The third was the harness's own fault: the cooldown fix is
maxed in two places, so reverting either one alone leaves the behaviour
correct, and the harness could only revert one edit at a time. It now
reverts whole fixes.

Two numbers in this document were themselves wrong until measured. The
module map's line counts drifted on every row; `tools/sync_module_map.py`
derives them now and `tests/test_docs.py` fails if they drift again. The same
is true of the class tables in [bug classes](bug-classes.md).

## What is mechanically locked, and what cannot be

118 rows below say `fixed`. The revert checks lock most of them; this says
plainly which ones they do not, because a table that implies full coverage
is the same problem as a table that asserts a fix.

A revert check needs an edit that puts a **defect** back. Some fixes have no
such edit, and no amount of effort invents one:

- **Dead-code removals.** An unreachable severity branch, `_build_date_params`
  with no caller, a `resultsPerPage` assignment every call site overrode, a
  second advisory-id length limit that could never be reached, an unused
  `noqa`. Restoring them changes nothing observable. They are verified by
  the suite that still passes without them, not by a revert.
- **Pure refactors.** `g` shadowing the Flask global (the genexp has its own
  scope), `classify_batch` extracted from a 115-line view, the second
  key-rotation implementation deleted, hand-copied limits in `openapi.py`
  replaced by the constants they duplicated. The behaviour is identical by
  construction; only future drift is the defect, and drift cannot be
  reintroduced without inventing a wrong value.
- **Performance-only fixes.** `published_bounds` re-parsing per record,
  `isPicked()` querying the document per option, the picker re-scoring on
  every arrow key. Same output, less of it. Measured when they were made;
  a revert produces no failing assertion.
- **Fixes that need something we will not do in a test.** `gh` invoked by
  bare name: `gh_executable()` falls back to `"gh"` anyway and every test
  mocks `subprocess.run`, so no revert differs without executing a real
  binary.

That list was itself too generous. A revert check is not the only
mechanical guard available: what each of those fixes produced is a
**property of the tree**, and a property can be asserted directly. Dead code
is gone or it is not; a cache is consulted or it is not; a helper is
importable without Flask or it is not.
`tests/test_cleanup_stays_clean.py` holds those assertions, so no row above
rests on nothing. Writing it corrected two things on this page: the
`published_bounds` cache lives on a private helper (so that an unhashable
argument still raises `ValueError` rather than `TypeError` from
`lru_cache`), and `gh` is genuinely resolved to a path rather than left to
`PATH` at exec time.

What remains outside both mechanisms is narrow: the picker's per-keystroke
re-scoring, whose cost is only observable with instrumentation the page does
not expose.

The index at the end of this page lists every revert check by name with the
test module that catches it; `python tools/revert_checks.py` runs them and
must report all of them caught.

## HTTP layer, jobs, security

| Finding | Disposition |
|---|---|
| Bind guard read `HOST`, which gunicorn never reads — unauthenticated 200 on a 0.0.0.0 bind | fixed |
| Failed migrations recorded as applied, never retried | fixed |
| Job terminal transitions unguarded; a job could stay `running` forever | fixed |
| `fail_orphaned_jobs` ran only at startup; a second worker killed a live job | fixed |
| Retention pruning had one caller, so nothing ever pruned | fixed |
| Classify with no category billed a pass against `bac` | fixed |
| `error_status` persisted and never served | fixed |
| `api_ai_classify` was 115 lines of service logic in a view | fixed |
| Auth gated on a path prefix, rate limiter on the endpoint | fixed |
| 100 SQLite connections per classify request | fixed |
| Job poll parsed the stored request and discarded it | fixed |
| Token file written without `O_EXCL`; workers minted different tokens | fixed |
| `build_spec()` rebuilt per unauthenticated request | fixed |
| Documented guard order (CSRF → rate limit → auth) was the reverse of the code | doc |
| Module map line counts stale across the board | fixed, now test-enforced |
| Generated token printed to stderr, into `docker logs` | fixed |
| CSP nonce hook registered after the guards | fixed |
| `g` loop variable shadowing the Flask global | fixed |
| Two different advisory-id length limits | fixed (the unreachable one removed) |
| `RateLimiter` eviction was O(n) under the lock | fixed |
| Limiters are per worker; docs did not say so | doc |
| `COOLDOWN_PATH` used `BASE_DIR`, so Docker lost it | fixed |
| `export FOO=bar` in `.env` set a variable named `export FOO` | fixed |
| `docs/api.md` quoted an error string the server cannot emit | doc |
| Comment claimed "the one inline bootstrap script"; there are three | doc |
| `docker-compose` bind-mount ownership caveat | **kept** — a comment about a commented-out line; the container already fails loudly |
| `requirements.txt` uses ranges, not pins, with no lockfile | **kept** — changing the dependency policy is the maintainer's call, not a cleanup |
| `assert` used for type narrowing | **kept** — the branch has already returned; `ruff.toml` records the exemption |
| Unreachable batch-size check | fixed |
| `"category"` echoed in the classify response | **kept** — older clients read it; it is documented now |
| Index on `advisories(cve_id)` that no query uses | fixed |

## Search pipeline

| Finding | Disposition |
|---|---|
| Merge reported the last severity fetched, not the worst | fixed |
| `type` / `ecosystem` silently ignored for NVD | fixed (warns) |
| One malformed GHSA/NVD record 500'd the whole search | fixed |
| Partial NVD failure invisible | fixed |
| EPSS failure produced a fabricated ranking | fixed |
| Descriptive fields taken from an empty base record | fixed |
| `cvss_vector` never reached a row from NVD | fixed |
| Date filter kept a row whose displayed date failed the filter | **kept** — documented; "never subtract a row a source vouched for" is the deliberate rule |
| GHSA/NVD 502 vs OSV 200 for the same failure | fixed |
| `published_bounds` re-parsed per record | fixed |
| `_merge_group` deep-copied three times | **kept** — `source_records` is now opt-in, which removes most of the cost; the rest is a snapshot the merge relies on |
| `_SOURCE_PRIORITY` missing a valid source | fixed |
| `ghsa_id` filled with a CVE id | fixed |
| Severity and CVSS can come from different sources | **kept** — worst-of-each is right for triage; now documented, with per-source attribution |
| Unvalidated `max()` inputs | fixed |
| Sort keys were raw timestamp strings | **kept** — all four sources emit UTC; the filter path already parses properly |
| `stats.truncated` cannot express upstream capping | fixed (`failed_sources` added) |
| `source_records` doubled every response, read by nobody | fixed (opt-in) |
| Keyless records all collapsed onto `advisory_id == ""` | fixed |
| EPSS lookup case-sensitive | fixed |
| `VALID_SORTS` duplicated `_SORT_FIELD` | fixed |
| `per_source` shipped twice | **kept** — both are documented and a client may read either |
| Unreachable fallback / near-unreachable handler / two sort branches | **kept** — defensive, and the comments explain them |

## Source clients

| Finding | Disposition |
|---|---|
| Generated Python built from unvalidated XML attributes | fixed |
| Partial NVD failure returned a short result set silently | fixed |
| One malformed record killed the batch | fixed |
| `actions` ecosystem could never be fetched | fixed |
| No per-ecosystem load lock; concurrent searches each parsed the export | fixed |
| Bulk zip buffered twice in memory, no size cap | fixed |
| Adjacent NVD date windows overlapped by a day | fixed |
| First page fetched at max size and discarded | **kept** — the tail fetch is what makes "newest first" correct; the cost is one page |
| Tail-page trick rests on an ordering NVD does not guarantee | **kept** — documented in the code; changing it needs a real API guarantee |
| A failed refresh discarded a usable stale cache | fixed |
| Filter loop outside the per-record guard | fixed |
| Pagination stopped on the wrong `Link` header | fixed |
| GHSA had no retry and discarded partial results | fixed |
| No decompression budget | fixed (download cap) |
| NVD cost estimate understated in docs and UI | **kept** — the estimate is a hint shown before spending; the windows count is now in the code comment |
| `docs/data-sources.md` credited NVD with vectors it dropped | fixed |
| An empty abstraction level emitted invalid Python | fixed |
| Three clients, three retry policies | fixed |
| `_strip_to_path` trusted the `Link` header | fixed |
| `cache_status` had no `try` around `getsize`/`getmtime` | fixed |
| `_zip_path` did not validate `..` | fixed |
| `gh` invoked by bare name | fixed |
| NVD 403 reported only as rate limiting | fixed |
| `ElementTree` on downloaded XML | **kept** — `ruff.toml` records why: operator-run tool, output validated and compiled |
| Cross-client CWE format inconsistency | **kept** — all three normalise at the boundary now; the defensive `str()` is cheap |
| Unreachable severity branch | fixed |
| `_build_date_params` with no caller | fixed |
| `resultsPerPage` dead assignment | fixed |
| `purl` / `ranges` / `versions` never read | fixed |
| Unused `noqa` | fixed |

## AI classifier

| Finding | Disposition |
|---|---|
| Failing test was a time bomb | fixed |
| Advisory text injected into the prompt with no delimiter | fixed |
| One 429 failed the whole batch on a single key | fixed |
| `_persist_cooldown` overwrote instead of taking the max | fixed |
| Cost cap meters logical calls, not HTTP requests | **kept** — the cap is enforced before spending, as documented; retries are bounded and now shared |
| Raw provider error body logged | fixed (403 body to DEBUG; no token reaches a response) |
| `AIConfig.__repr__` printed every key | fixed |
| Cooldown read once; temp file had a fixed name | **kept** — shipped config is one worker; the file is now in `DATA_DIR` and takes the max |
| Fingerprinting cost on the search hot path | fixed (batched reads) |
| OpenAPI did not cover the AI endpoints | fixed |
| `__main__` block mid-file hid 30 tests | fixed |
| `AIConfig.token` is a side-effecting property | **kept** — it is the cooling-aware picker, and the side effect is the cursor it advances |
| Malformed AI env var crashes at import | **kept** — a malformed cost knob should fail loudly, not silently default |
| Fingerprint omitted `base_url` / max tokens / thinking | fixed |
| `aggregate_category_verdicts` returned three shapes | fixed |
| 401/403 parks a key for 24h with no escape | **kept** — deleting the file clears it; documented in operations |
| Unbounded prompt fields | fixed |
| `ping()` could spend a call on an exhausted key | fixed |
| Two key-rotation implementations | fixed |
| `AIError.status` effectively write-only | **kept** — it shapes `public_message`; removing a small public attribute risks a consumer for no gain |
| Stale docstring claim about an example check | fixed |
| Hand-copied limits in `openapi.py` | fixed |

## CWE taxonomy

| Finding | Disposition |
|---|---|
| CWE-913 filed under Broken Access Control | fixed |
| CWE-436 separated from its own child | fixed |
| Six classes could not find the bug their label names | fixed |
| Specific children parked in `extended` under vaguer parents | fixed |
| Credential-exposure cluster unreachable | fixed |
| `"acl"` and `"eval"` were substring traps | fixed |
| Bare `"bypass"` was 52% of BAC's prefilter passes | fixed |
| IDOR ranked below its own CWE | fixed |
| Catalog is generated and nothing checked it | fixed |
| Derived keywords included junk short forms | fixed |
| `CATEGORIES` is untyped with a parallel `KEYWORDS` dict | **kept** — a restructure with no behaviour change; the two re-linking tests already enforce it |
| Section banners do not match the entries above them | **kept** — the `group` field is authoritative and the doc tables are generated from it |
| Alias collisions resolve by accident of scoring | **kept** — every collision resolves to the intended weakness; now covered by a test |
| `CWE_RELEASED` / `cwe_aliases()` / `MAX_CATEGORY_CODE_LENGTH` unused | fixed |

## Frontend

| Finding | Disposition |
|---|---|
| Partial re-score cleared the stale banner | fixed |
| Concurrent toasts rendered on top of each other | fixed |
| Per-card retry dropped focus to `<body>` | fixed |
| `[hidden]` worked only via nine bespoke rules | fixed |
| `refreshPackages` interpolated without escaping | fixed |
| `renderSummary` wrote server numbers uncoerced | fixed |
| Auth gate claimed `aria-modal` and trapped nothing | fixed |
| Picker re-scored the catalog on every arrow key | fixed |
| `isPicked()` queried the document per option | fixed |
| Verdict state held in two places | fixed (documented single source) |
| `search` registered directly as a click handler | fixed |
| Print output unreadable in the dark theme | fixed |
| `safeAttr` threw on a non-string | fixed |
| Breakpoint written in three places | fixed (JS reads the CSS token) |
| Enter committed an option nothing highlighted | fixed |
| Empty `<li>` inside `role="listbox"` | fixed |
| Picked options `aria-disabled` but activatable | **kept** — `pickEntry` is idempotent; re-announcing is not a defect |
| `role="alert"` on every errored card | fixed |
| `#summary` re-announces in full on every render | **kept** — it is the status line; partial updates would announce less, not more clearly |
| apidocs nav has no `aria-current` | **kept** — a separate page with its own small scope |
| `historyLabel` read the DOM | fixed |
| No `storage` event listener | fixed |
| Theme choice was one-way | fixed |
| Export not blocked on stale verdicts | fixed (warns; the CSV self-describes) |
| `#export-btn` unfocusable until app.js ran | fixed |
| `trapPanelTab` forces a reflow per Tab | **kept** — ~45 nodes, once per keypress while a modal panel is open |
| No per-batch progress during a long AI pass | **kept** — a feature, not a defect |
| `.source-list` had no rule | fixed |
| `detail.scrollTop = 0` was a no-op | fixed |
| `focusWhenVisible` timer not cleared | **kept** — the `done` flag guards it |
| `esc` implemented twice | fixed |
| No tests for `esc` / `safeUrl` / XSS end to end | fixed |

<!-- begin generated check index -->

## The 223 checks, by area

Generated from `tools/checks/` by `tools/sync_check_counts.py`; a
test fails if it drifts. Each line is a bug that was really in this
codebase and the test module that now refuses to let it back in.

### First pass: security, merge, sources, taxonomy, docs (29)

| Reverting this | is caught by |
|---|---|
| the retry backoff clock is bound at import again | `tests/test_http_retry.py` |
| bind guard trusts HOST again | `tests/test_security.py` |
| merge promotes the last severity, not the worst | `tests/test_search_service.py` |
| one bad record sinks the GHSA batch again | `tests/test_search_service.py` |
| prompt fence removed | `tests/test_ai_classifier.py` |
| catalog generator stops validating Version | `tests/test_generate_cwe_catalog.py` |
| cooldown overwrites instead of taking the max | `tests/test_ai_classifier.py` |
| migrations stamped even when they fail | `tests/test_cache.py` |
| job reconciliation ignores the owner again | `tests/test_jobs.py` |
| cve_id sorts as text | `tests/test_search_service.py` |
| severity synonyms stop folding | `tests/test_search_service.py` |
| NVD windows overlap again | `tests/test_nvd_client.py` |
| GHSA pagination breaks on the wrong Link header | `tests/test_ghsa_client.py` |
| GHSA cursor trusted again | `tests/test_ghsa_client.py` |
| GHSA cursor checked by prefix again | `tests/test_ghsa_client.py` |
| OSV load lock removed | `tests/test_osv_client.py` |
| OSV cache path stops being validated | `tests/test_osv_client.py` |
| auth falls back to a path prefix | `tests/test_app.py` |
| classify defaults a missing category to bac | `tests/test_app.py` |
| taxonomy regressions (CWE-913 back in bac) | `tests/test_cwe_categories.py` |
| bare 'bypass' keyword returns | `tests/test_cwe_categories.py` |
| verdict fingerprint drops base_url | `tests/test_ai_classifier.py` |
| verdict shape stops being uniform | `tests/test_ai_classifier.py` |
| module map rewrite eats the newline before the closing fence | `tests/test_doc_sync_tools.py` |
| testing-doc counts stop being derived | `tests/test_doc_sync_tools.py` |
| the brand paints on top of the status pills | `tests/test_ui_e2e.py` |
| a disabled button keeps its warning colour again | `tests/test_ui_e2e.py` |
| app.js loses its scope wrapper | `tests/test_frontend_js.py` |
| module-map drift test stops deriving | `tests/test_docs.py` |

### HTTP layer, jobs, cache, config, AI classifier (43)

| Reverting this | is caught by |
|---|---|
| a partly failed score is reported as a confident no | `tests/test_ai_classifier.py` |
| a key is retried instead of rotated | `tests/test_ai_classifier.py` |
| the request body size cap is removed | `tests/test_app.py` |
| the AI rate limiter matches the path, so /api/v1 is unlimited | `tests/test_app.py` |
| the system prompt stops reaching the provider | `tests/test_ai_classifier.py` |
| the default provider's reply shape stops being parsed | `tests/test_ai_classifier.py` |
| a revoked key stops being parked | `tests/test_ai_classifier.py` |
| a transient rate limit is persisted across restarts again | `tests/test_ai_classifier.py` |
| the auth allowlist goes back to being unreachable | `tests/test_app.py` |
| the prune sentinel means 'at boot' instead of 'never' | `tests/test_jobs.py` |
| a job stays running when recording its terminal state raises | `tests/test_jobs.py` |
| a job that cannot be marked running is abandoned in queued | `tests/test_jobs.py` |
| finished jobs are pruned only at process start | `tests/test_jobs.py` |
| error_status is persisted but never served to the poller | `tests/test_jobs.py` |
| every job poll parses the stored request body it then discards | `tests/test_jobs.py` |
| one SQLite connection per advisory id in a classify request | `tests/test_cache.py` |
| an index on advisories(cve_id) that no query uses | `tests/test_cache.py` |
| two workers mint different API tokens into the same file | `tests/test_security.py` |
| the generated API token is printed into docker logs | `tests/test_security.py` |
| rate-limit eviction scans every key and drops the one being limited | `tests/test_security.py` |
| 'export FOO=bar' in .env sets a variable named 'export FOO' | `tests/test_config.py` |
| the AI key cooldown file is written outside VULNSIGHT_DATA_DIR | `tests/test_config.py` |
| AIConfig's repr prints every API key | `tests/test_ai_classifier.py` |
| only the description is capped, so a prompt field can be unbounded | `tests/test_ai_classifier.py` |
| the health check spends a paid call on a key known to be cooling | `tests/test_ai_classifier.py` |
| the raw provider error body is handed back to the caller | `tests/test_ai_classifier.py` |
| one transient 429 ends the whole batch on a single-key setup | `tests/test_ai_classifier.py` |
| a guard-blocked response carries an empty CSP nonce | `tests/test_app.py` |
| the rate limiter matches the path, so /api/v1 is unlimited | `tests/test_app.py` |
| the OpenAPI document is rebuilt for every unauthenticated request | `tests/test_openapi.py` |
| the AI endpoints are missing from the OpenAPI document | `tests/test_openapi.py` |
| an advisory can close its own evidence fence again | `tests/test_ai_classifier.py` |
| a reply that never answers is a confident no again | `tests/test_ai_classifier.py` |
| a duplicated API key is kept and can never be cooled | `tests/test_ai_classifier.py` |
| the rate-limit bucket trusts the leftmost X-Forwarded-For entry | `tests/test_security.py` |
| an advised Retry-After of zero cancels the backoff again | `tests/test_http_retry.py` |
| a bad later GHSA page discards the pages already fetched | `tests/test_ghsa_client.py` |
| the rce prefilter trap comes back | `tests/test_cwe_categories.py` |
| the revert harness stops checking a green baseline | `tests/test_cleanup_stays_clean.py` |
| the sandbox copies the operator's .env into /tmp again | `tests/test_cleanup_stays_clean.py` |
| the caught figure goes back to being asserted, not measured | `tests/test_cleanup_stays_clean.py` |
| the status pill state is unannounced at 480px again | `tests/test_frontend_js.py` |
| the unreachable-source dot differs only by colour again | `tests/test_frontend_js.py` |

### Search pipeline and source clients (30)

| Reverting this | is caught by |
|---|---|
| the NVD page size stops accounting for what is left to fetch | `tests/test_nvd_client.py` |
| a typo in a transient-error marker stops GHSA retrying | `tests/test_ghsa_client.py` |
| GHSA stops retrying a transient page at all | `tests/test_ghsa_client.py` |
| EPSS keys are not normalised on the way back | `tests/test_epss_client.py` |
| the advisory batch is sent in one oversized statement | `tests/test_cache.py` |
| an empty base record erases another source's description | `tests/test_search_service.py` |
| cvss_vector is dropped when the base record has none | `tests/test_search_service.py` |
| ghsa_id is filled with a CVE id | `tests/test_search_service.py` |
| records with no identifier all collapse onto one advisory_id | `tests/test_search_service.py` |
| a non-numeric CVSS score crashes the merge | `tests/test_search_service.py` |
| osv-native has no base priority and ties on fetch order | `tests/test_search_service.py` |
| every selected source failing answers 200, not 502 | `tests/test_search_service.py` |
| NVD silently drops the advisory-type filter | `tests/test_search_service.py` |
| NVD silently drops the ecosystem filter | `tests/test_search_service.py` |
| a partly failed NVD fetch is reported as a complete one | `tests/test_search_service.py` |
| EPSS failure fabricates a ranking | `tests/test_search_service.py` |
| the EPSS lookup is case-sensitive | `tests/test_search_service.py` |
| source_records ships in every response and is cached | `tests/test_search_service.py` |
| count: 0 cannot be told apart from an outage | `tests/test_search_service.py` |
| VALID_SORTS drifts from the sort-field map | `tests/test_search_service.py` |
| one malformed OSV record kills the whole export | `tests/test_osv_client.py` |
| the OSV bulk download is buffered whole with no size cap | `tests/test_osv_client.py` |
| a failed OSV refresh throws away a usable cached export | `tests/test_osv_client.py` |
| an OSV ecosystem whose name has a space can never be fetched | `tests/test_osv_client.py` |
| a cache file that vanishes mid-read crashes the healthcheck | `tests/test_osv_client.py` |
| normalised OSV packages carry purl/ranges/versions and a null range | `tests/test_osv_client.py` |
| one malformed NVD record sinks the whole batch | `tests/test_nvd_client.py` |
| NVD's CVSS vector is read and thrown away | `tests/test_nvd_client.py` |
| a failing later page discards the advisories already fetched | `tests/test_ghsa_client.py` |
| EPSS is queried with the publisher's casing | `tests/test_epss_client.py` |

### CWE taxonomy and the browser code (20)

| Reverting this | is caught by |
|---|---|
| the auth gate stops trapping focus and inerting the page | `tests/test_ui_e2e.py` |
| the global [hidden] rule is removed | `tests/test_frontend_js.py` |
| the opening screen stops offering the classes | `tests/test_ui_e2e.py` |
| the map stops following the rail | `tests/test_ui_e2e.py` |
| picking a class throws focus back to the rail | `tests/test_ui_e2e.py` |
| a hard-coded size hides inside clamp() | `tests/test_frontend_js.py` |
| the API page goes back to its own ad-hoc sizes | `tests/test_frontend_js.py` |
| the two stylesheets disagree about the scale | `tests/test_frontend_js.py` |
| CWE-436 separated from its own child again | `tests/test_cwe_categories.py` |
| 'acl' returns as a bare substring trap | `tests/test_cwe_categories.py` |
| junk short forms come back into the derived keywords | `tests/test_cwe_categories.py` |
| real short search terms are rejected as noise | `tests/test_cwe_categories.py` |
| the type scale goes back to hard-coded sizes | `tests/test_frontend_js.py` |
| a declared type token stops being used | `tests/test_frontend_js.py` |
| two spellings of the same pill radius come back | `tests/test_frontend_js.py` |
| safeAttr throws on a non-string again | `tests/test_frontend_js.py` |
| esc stops coercing its argument | `tests/test_frontend_js.py` |
| Enter commits an option nothing highlighted | `tests/test_ui_e2e.py` |
| an empty listbox row stops being presentational | `tests/test_ui_e2e.py` |
| toasts stop sharing one live region | `tests/test_ui_e2e.py` |

### Removals, extractions and caches (property-asserted) (19)

| Reverting this | is caught by |
|---|---|
| search tests write their fixtures into the real cache | `tests/test_cleanup_stays_clean.py` |
| the job tests let the worker reach the real GitHub API | `tests/test_cleanup_stays_clean.py` |
| a generator truncates the file it rewrites | `tests/test_cleanup_stays_clean.py` |
| the atomic write stops being atomic | `tests/test_cleanup_stays_clean.py` |
| a test's only assertion hides behind an if | `tests/test_cleanup_stays_clean.py` |
| a test compares a value with itself | `tests/test_cleanup_stays_clean.py` |
| the image stops declaring the bind it chose | `tests/test_deployment.py` |
| compose publishes the port on every interface | `tests/test_deployment.py` |
| the container goes back to running as root | `tests/test_deployment.py` |
| gunicorn is given more workers than the limiter allows | `tests/test_deployment.py` |
| curl is left in the shipped image | `tests/test_deployment.py` |
| the entrypoint forks instead of exec'ing | `tests/test_deployment.py` |
| an env var the code reads is documented nowhere | `tests/test_deployment.py` |
| a helper with no caller comes back | `tests/test_cleanup_stays_clean.py` |
| the second key-rotation implementation comes back | `tests/test_cleanup_stays_clean.py` |
| the published-window cache is removed | `tests/test_cleanup_stays_clean.py` |
| gh is invoked by bare name again | `tests/test_cleanup_stays_clean.py` |
| the picker goes back to asking the DOM per option | `tests/test_cleanup_stays_clean.py` |
| a generator binds the name g again | `tests/test_cleanup_stays_clean.py` |

### Availability, cost and correctness from the whole-tree review (25)

| Reverting this | is caught by |
|---|---|
| an NVD search can outlive the worker again | `tests/test_nvd_client.py` |
| NVD fetches a full page and throws it away again | `tests/test_nvd_client.py` |
| the NVD paging dereferences shapes the API does not promise | `tests/test_nvd_client.py` |
| a non-numeric totalResults raises again | `tests/test_nvd_client.py` |
| EPSS enrichment runs without a deadline again | `tests/test_epss_client.py` |
| a dead EPSS endpoint costs the whole batch budget | `tests/test_epss_client.py` |
| the OSV freshness check goes back behind the download lock | `tests/test_osv_client.py` |
| a zip member inflates without a bound again | `tests/test_osv_client.py` |
| jobs queue without backpressure again | `tests/test_jobs.py` |
| a successful search dies on an optional cache write | `tests/test_search_service.py` |
| a merged advisory gets two primary keys again | `tests/test_search_service.py` |
| the CVSS vector stops describing the score beside it | `tests/test_search_service.py` |
| records without a CVE sort to the top again | `tests/test_search_service.py` |
| affects silently deletes every NVD-only row again | `tests/test_query_filters.py` |
| OSV renders only the last vulnerable branch again | `tests/test_osv_client.py` |
| a throttle is misread as a spent key again | `tests/test_ai_classifier.py` |
| the verdict parser spans two JSON objects again | `tests/test_ai_classifier.py` |
| two workers share one cooldown temp path again | `tests/test_ai_classifier.py` |
| an impossible AI request is retried on every key again | `tests/test_ai_classifier.py` |
| source availability churns the verdict cache again | `tests/test_ai_classifier.py` |
| a GHSA rate limit is retried blindly again | `tests/test_ghsa_client.py` |
| short GHSA markers match inside identifiers again | `tests/test_ghsa_client.py` |
| a conditional request with a tag list re-serves the whole body | `tests/test_app.py` |
| a 304 drops the validators that make the next request conditional | `tests/test_app.py` |
| an empty token file crashes startup with the wrong reason | `tests/test_security.py` |

### Deployment, the published contract, and tools that could not fail (22)

| Reverting this | is caught by |
|---|---|
| the image makes its own source writable by the runtime user | `tests/test_deployment.py` |
| dependencies go back to floating ranges | `tests/test_deployment.py` |
| run.sh swallows the failure of its one credential check | `tests/test_deployment.py` |
| the credential check moves back behind the slow work | `tests/test_deployment.py` |
| the OpenAPI document stops using its own components | `tests/test_openapi.py` |
| the spec claims /ai/test takes no body again | `tests/test_openapi.py` |
| the spec restates a limit instead of importing it | `tests/test_openapi.py` |
| a 415 from the shared body helper goes back undocumented | `tests/test_openapi.py` |
| the test auditor stops detecting a self-fulfilling test | `tests/test_cleanup_stays_clean.py` |
| the test auditor stops detecting a recomputed expectation | `tests/test_cleanup_stays_clean.py` |
| the test auditor reports a clean sweep of nothing | `tests/test_cleanup_stays_clean.py` |
| write_atomic narrows every file it touches to 0600 | `tests/test_cleanup_stays_clean.py` |
| the module map reports accurate on a block it cannot parse | `tests/test_doc_sync_tools.py` |
| a missing browser makes the design audit report success | `tests/test_doc_sync_tools.py` |
| the design audit stops checking the page it asked for | `tests/test_doc_sync_tools.py` |
| an unsupported sort is silently coerced to the default | `tests/test_search_service.py` |
| timestamps are compared as raw strings again | `tests/test_search_service.py` |
| a total failure is measured against requested, not attempted, sources | `tests/test_search_service.py` |
| an empty verdict set is reported as a confident no | `tests/test_ai_classifier.py` |
| the catalog generator accepts a truncated catalog | `tests/test_generate_cwe_catalog.py` |
| the forbidden keyword trap comes back | `tests/test_cwe_categories.py` |
| the overflows keyword trap comes back | `tests/test_cwe_categories.py` |

### The redesign, and the review that read it back (19)

| Reverting this | is caught by |
|---|---|
| the search warnings are swallowed by the media query above them | `tests/test_frontend_js.py` |
| the KEV badge is painted in the HIGH severity colour | `tests/test_frontend_js.py` |
| the KEV badge shouts its label | `tests/test_frontend_js.py` |
| the withdrawn badge shouts its label | `tests/test_frontend_js.py` |
| the no-CWE badge shouts its label | `tests/test_frontend_js.py` |
| the result summary goes back to one string joined by middle dots | `tests/test_frontend_js.py` |
| the design audit never opens the surfaces that float above the page | `tests/test_frontend_js.py` |
| the audit fixture stops at the advisory, so no verdict is measured | `tests/test_frontend_js.py` |
| the taxonomy group headings go back to the monospace face | `tests/test_frontend_js.py` |
| the skip link goes back to the monospace face | `tests/test_frontend_js.py` |
| the API reference shouts its section headings again | `tests/test_frontend_js.py` |
| the AI's reasoning runs the full width of the card | `tests/test_frontend_js.py` |
| nothing measures how long a line of prose is | `tests/test_frontend_js.py` |
| the generator asks for the element CWE 5.0 renamed | `tests/test_generate_cwe_catalog.py` |
| a catalog with no Groupings at all is written anyway | `tests/test_generate_cwe_catalog.py` |
| the shipped catalog goes back to Views only | `tests/test_generate_cwe_catalog.py` |
| a state that measures the page twice is counted as coverage | `tests/test_frontend_js.py` |
| a revert that undoes one of three copies is scored as a full revert | `tests/test_cleanup_stays_clean.py` |
| a shutdown request can never be withdrawn by the inline search path | `tests/test_jobs.py` |

### Taking the chrome off the workspace: views, folds, ranks (8)

| Reverting this | is caught by |
|---|---|
| the command bar is painted before anything has been searched for | `tests/test_ui_e2e.py` |
| the view never switches, so the results arrive with no controls | `tests/test_ui_e2e.py` |
| a query refused for having no source switches the page to results | `tests/test_ui_e2e.py` |
| a folded section hides the setting along with the controls | `tests/test_ui_e2e.py` |
| ticking a source leaves the folded heading describing the old query | `tests/test_ui_e2e.py` |
| replaying a saved search leaves the headings on the query it replaced | `tests/test_ui_e2e.py` |
| the phone filter drawer is transparent and the page reads through it | `tests/test_ui_e2e.py` |
| a type step is declared with nothing on the page using it | `tests/test_frontend_js.py` |

### One taxonomy, not two: the map, the fold, the entry (8)

| Reverting this | is caught by |
|---|---|
| the rail prints the whole taxonomy a second time, at rest | `tests/test_ui_e2e.py` |
| the description block comes back under all twenty-nine labels | `tests/test_ui_e2e.py` |
| a class loses its description without gaining a title | `tests/test_ui_e2e.py` |
| the bug-class fold grows a value its own chips already say | `tests/test_ui_e2e.py` |
| the mono code comes back to every map entry | `tests/test_frontend_js.py` |
| the comparison bar comes back under every map entry | `tests/test_frontend_js.py` |
| a .map-* rule outlives the markup it styled | `tests/test_frontend_js.py` |
| the map entry hangs its label and its count from one edge | `tests/test_ui_e2e.py` |

<!-- end generated check index -->
