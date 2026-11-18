# Testing

```bash
.venv/bin/python -m unittest discover -s tests        # 687 tests: 641 offline + 46 browser
.venv/bin/python -m unittest discover -s tests -v     # with names
.venv/bin/python tests/test_app.py                    # a single file
```

The offline suite needs **no network, no credentials and no browser**. GHSA, NVD,
OSV and the AI provider are all mocked.

## What is covered

| File | Tests | Covers |
|---|---|---|
| `test_search_service.py` | 84 | query parsing, merge/dedupe, sort, filters, per-source degradation |
| `test_ai_classifier.py` | 74 | prompt fence, verdict aggregation, key rotation, cooldowns, cost cap |
| `test_app.py` | 71 | routes, guards, `/api/v1` aliases, job endpoints, JSON errors, DOM contract |
| `test_cwe_categories.py` | 45 | taxonomy invariants, `cwe:<id>`, picker catalog, keyword precision |
| `test_security.py` | 42 | bind/exposure rules, CSRF origin check, rate limiter, proxy trust |
| `test_nvd_client.py` | 36 | date windowing, normalisation, rate-limit and 403 handling |
| `test_http_retry.py` | 27 | the one retry policy: backoff, `Retry-After`, deadlines, what retries |
| `test_osv_client.py` | 32 | zip parsing, CWE and keyword filters, load lock, cache-path validation |
| `test_ui_e2e.py` | 46 | the real UI in a browser — *optional*, see below |
| `test_cache.py` | 22 | SQLite lifecycle, migrations, the v4 id backfill |
| `test_doc_sync_tools.py` | 30 | the two doc generators: rewrite, `--check`, alignment, failure paths |
| `test_jobs.py` | 23 | job lifecycle, orphan recovery, owner liveness, error redaction, pruning |
| `test_ghsa_client.py` | 20 | `gh` invocation, cursor pagination, `Link` parsing |
| `test_generate_cwe_catalog.py` | 15 | generated Python compiles, and XML attributes cannot inject code |
| `test_docs.py` | 18 | doc/code agreement: quoted numbers, routes, env vars, links, counts |
| `test_deployment.py` | 16 | Dockerfile, compose, entrypoint and run.sh: the bind the image declares, the user it drops to, head parity |
| `test_cleanup_stays_clean.py` | 14 | the fixes no revert can reach: dead code gone, extractions callable, caches consulted |
| `test_records.py` | 13 | the shared per-record guard: one bad advisory costs one advisory |
| `test_cvss.py` | 12 | v3.0/3.1 base scores against spec vectors |
| `test_epss_client.py` | 13 | batching, malformed responses |
| `test_openapi.py` | 12 | spec/route agreement, and real responses against the schemas |
| `test_config.py` | 9 | `.env` parsing, `DATA_DIR`, numeric knobs |
| `test_query_filters.py` | 5 | shared published/affects/severity predicates |
| `test_frontend_js.py` | 8 | runs every `tests/*.js` under node |

## Frontend helper tests (node)

Pure helpers are lifted straight out of `static/app.js` and executed, so the
tested source is always the shipped source:

- `test_frontend_security.js` — CSV escaping, including formula-injection
  neutralisation.
- `test_frontend_finder.js` — CWE-finder ranking, history sanitisation,
  `stateSignature` dedupe, `relativeTime`, `publishedWindow`.

`test_frontend_js.py` discovers and runs them inside the Python suite, and skips
if `node` is unavailable. They earn their keep: the finder tests caught a null
timestamp rendering as *"20685d ago"*.

## Browser tests (optional)

`tests/test_ui_e2e.py` drives the real UI. It is the only part of the suite with
a third-party dependency and it **skips itself** unless both pieces are present:

```bash
pip install -r requirements-dev.txt
playwright install chromium          # or rely on a system Chrome
.venv/bin/python -m unittest discover -s tests    # the 26 e2e tests join in
```

Verified by hiding the import: `unittest discover` reports
`Ran 687 tests` / `OK (skipped=46)`, and every other test still runs.

It exists because `static/app.js` decides what the user *believes* — which
advisories are hidden, which verdict belongs to which advisory, and when real
budget is spent — and none of that is reachable from a Python unit test. Each
test corresponds to a defect that actually shipped:

| Group | Asserts |
|---|---|
| `TestCweFinder` | alias → CWE with its full official name, exact-id ranking, `Enter` adds without searching, popup closes on `Tab` |
| `TestClassFilter` | the filter hides rows **on screen**, a selected class is never hidden, community terms match, group headings track their contents |
| `TestAiSpendRequiresConsent` | `⌘↵` runs the free search, `Confirmed only` asks first and reverts on cancel, a failed pass restores the raw queue |
| `TestVerdictsFollowTheQuery` | changing the class flags verdicts stale and blocks the filter; the summary reports the visible count |
| `TestFailureStates` | a source-less search keeps the previous view; missing EPSS is not rendered as `0.00%` |
| `TestRecentSearches` | no duplicate entries, signature-keyed rows, restore reapplies filters |
| `TestAccessibility` | exactly one `<h1>`, labelled containers expose their label, the mobile panel takes and traps focus |

### Assert on what is rendered

These tests check `getComputedStyle(el).display`, never `el.hidden`. That is not
style preference. A `.cat { display: grid }` rule beat the UA stylesheet's
`[hidden] { display: none }`, so the class filter set `hidden` on every row and
**changed nothing on screen** — while a property-based assertion stayed green.
Delete `.taxonomy-item[hidden] { display: none }` from the stylesheet and two of
these tests fail, which is the point.

Also useful: each test declares expected console noise via
`self.tolerated_errors`; anything else fails the test, so a stray JS exception
cannot hide inside a passing run.

## Verifying a change

```bash
.venv/bin/python -m unittest discover -s tests   # everything
ruff check .                                     # lint (config in ruff.toml)
pyright                                          # types (config in pyrightconfig.json)
node tests/test_frontend_security.js             # JS helpers, lifted from app.js
node tests/test_frontend_finder.js
```

**Lint.** `ruff.toml` selects the bug-finding rules (pyflakes, bugbear, bandit,
naive-datetime, dead code) rather than ruff's default four, and every ignore in
it states why. The tree is clean under it, so a new finding is a real one.

One caution learned here: a narrowed `--select` makes `RUF100` lie. Under a
restricted rule set it reported a live `# noqa: E402` as unused, because the
rule it suppressed was not enabled in that run. Removing the `noqa` broke the
default `ruff check` immediately. Trust `ruff check .`, not a narrowed run.

**Types.** `pyrightconfig.json` runs pyright in standard mode over `app.py`,
`modules/`, `tools/` and `tests/`. Strict mode would mean annotating every
JSON-shaped dict that crosses an API boundary for little gain. Where a test
deliberately passes a type the signature forbids — that *is* the test — the
call site uses an explicit `cast(Any, ...)` with a comment, never a blanket
`# type: ignore`.

**Coverage.** `.coveragerc` measures `app.py`, `modules/` and `tools/` with
branch coverage:

```bash
.venv/bin/python -m coverage run -m unittest discover -s tests
.venv/bin/python -m coverage report
```

Pass coverage the *module* name `app`, not the path `app.py` — a path there is
accepted silently, measures nothing, and in this repo it also perturbed nine
unrelated tests into failing. `.coveragerc` has it right; the warning is for
anyone running coverage by hand.

## The frontend

`static/app.js` and `static/style.css` are served exactly as written -- no
bundler, no build step -- so for a long time nothing checked them beyond
`node --check`, which only parses. There are four checkers now, all dev-only
(`package.json` devDependencies; nothing here is served):

```bash
npm install          # once
npm run check        # eslint + stylelint + tsc + the node helper tests
```

**eslint** (`eslint.config.mjs`) selects bug-finding rules -- undeclared
names, unreachable code, shadowed bindings, `==` vs `===`, `eval` -- and not
a formatting opinion. Its first run found that `app.js` had no wrapper at
all: ~79 functions and every piece of state were true globals, indented four
spaces as a leftover from when the code lived inside a `<script>` tag in the
template. `let AI = {}` shares a name with the browser's own `AI` global.
The file is one IIFE in strict mode now, and
`TestNothingLeaksToTheWindow` asserts nothing reaches `window`.

**tsc** (`jsconfig.json`, `checkJs`) type-checks the JSDoc. It is not a
compile step: `noEmit` is on. Writing down the `window.BOOT` contract
immediately showed that two of the shapes the code assumed were not the
shapes the server sends.

**stylelint** (`.stylelintrc.json`) runs the standard config minus its
formatting opinions -- the compact one-line rules in `style.css` are
deliberate. What is left is substantive: it found `button` styled in two
blocks 700 lines apart.

### Measuring the design instead of looking at it

```bash
python tools/design_audit.py --out /tmp/shots
```

Starts the app, drives a real browser across seven viewport/theme states,
and measures text contrast against the painted background, tap-target sizes,
keyboard focus visibility, horizontal overflow and console errors. It exits
non-zero when something fails, and writes screenshots and `report.json`.

A screenshot proves a page rendered; it does not prove the page is any good,
and a reviewer eyeballing one gets contrast wrong almost every time. Three
cautions are baked into that script because each produced a false finding
before it was understood:

- `el.focus()` does not put Chrome into `:focus-visible` for a button, so
  probing focus that way reports a correctly-styled page as having no focus
  rings at all. Only pressing Tab is honest.
- a focus ring usually lives on a wrapper via `:focus-within`, so checking
  only `document.activeElement` reports every composed control as bare.
- `getComputedStyle` returns `rgb()` in 0-255 **and** `color(srgb r g b)` --
  which is what `color-mix()` resolves to -- in 0-1. Reading the second as
  the first reported 16:1 text as 1.17:1 and produced a page of
  contrast "failures" that did not exist.

Real findings it did produce: the wordmark painted underneath the status
pills below ~420px (and the logo did the same at 320px), `Retry failed` kept
its full amber while disabled, and `/favicon.ico` 404'd on every first load
because no icon was declared. All three are now covered by
`TestTopbarLayoutHolds` and the revert checks.

## Proving a fix is actually locked

A green suite says nothing about *which* fixes it defends. This suite was green
before the fixes in [review dispositions](review-dispositions.md) too — it did
not test the broken behaviour.

```bash
.venv/bin/python tools/revert_checks.py            # all checks
.venv/bin/python tools/revert_checks.py cooldown   # one, by label
```

For each of 105 named bugs it re-introduces the bug in the working tree, runs the
test module that should notice, and requires the suite to go **red**, then
restores the file. A revert that leaves the suite green means that fix is not
covered, whatever any summary claims. It writes to tracked files — it restores
them in a `finally` and verifies the tree is clean on exit, but do not run it on
a dirty tree you care about.

It earns its keep. Its first run found three uncovered fixes. Two were real
gaps: GHSA record degradation was never driven through `run_search`, and the
`Link`-header test had reimplemented the parser instead of calling it, so it
stayed green while the shipped parser was broken. The third was the harness's
own limitation — the cooldown fix takes a `max()` in two places, so reverting
either alone leaves the behaviour correct. It reverts whole fixes now, not
single edits.

If you fix a bug: write the failing assertion first, then fix it, then add a
`CHECKS` entry so the next person cannot quietly unfix it.
