# Review dispositions

Six reviews covered this codebase by dimension: the HTTP layer, the search
pipeline, the source clients, the AI classifier, the CWE taxonomy, and the
frontend. This records what happened to each finding, including the ones
deliberately left alone and why — so "it was reviewed" is checkable rather
than asserted.

`fixed` means the behaviour changed and a test covers it. `kept` means the
finding was real and the behaviour is unchanged on purpose. `doc` means the
code was right and the documentation was wrong.

## Checking this table instead of believing it

A table like this is the author's own account of their own work, so none of
it should be taken on trust. Everything below is reproducible from a clean
checkout; the numbers are from the last run.

| What | Command | Result |
|---|---|---|
| Tests | `python -m unittest discover -s tests -p "test_*.py"` | 604 pass |
| Frontend | `node tests/test_frontend_security.js && node tests/test_frontend_finder.js` | pass |
| Lint | `ruff check .` | clean |
| Types | `pyright` | 0 errors |
| Coverage | `python -m coverage run -m unittest discover -s tests && python -m coverage report` | 91% (branch) |
| **Fixes are really locked** | `python tools/revert_checks.py` | **24/24 caught** |

The last row is the one that matters. A green suite says nothing about
*which* fixes it defends: the suite was green before these fixes too, because
it did not test the broken behaviour. `tools/revert_checks.py` re-introduces
each of 24 named bugs in the working tree, runs the test module that is
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
