# Design

The design plan this interface is built to, the reasoning behind each choice,
and the measurements that check it. Written so the next person can disagree
with a decision on its merits rather than guess at the intent.

Numbers quoted here are produced by `python tools/design_audit.py`, which
drives a real browser across fourteen viewport/theme states. `tests/test_docs.py`
fails if this page drifts from the stylesheet.

## The subject

VulnSight is a **triage console**, not a dashboard and not a search engine.

An application-security or red-team engineer arrives with one question —
*"which of these thousands of advisories are actually this bug class?"* — and
narrows a corpus of tens of thousands of records down to the handful worth
reading. Then they spend **real, metered money** (AI classification calls)
confirming the shortlist.

- **Audience.** AppSec and offensive-security engineers. Technically expert,
  impatient, usually with a terminal open beside the browser. They know what
  CWE-639 means; they do not need it explained.
- **Primary job.** Decide what to look at next — and never be surprised by
  what a click cost.
- **What failure looks like.** A confident-looking list that quietly omitted
  a source, or an AI pass that spent the budget without saying so.

Everything below follows from that. The interface is a reading surface for
dense, coded data, where the two things that must never be ambiguous are
**severity** and **what an action will spend**.

## Colour

Six named values carry the system. The rest of the sheet is neutral.

| Token | Light | Dark | Job |
|---|---|---|---|
| `--bg` | `#f7f8f9` | `#15181d` | the ground |
| `--ink` | `#14181d` | `#e9ebef` | body text |
| `--accent` | `#334e68` | `#8fb3d9` | structure: focus, selection, the one filled control |
| `--sev-critical` | `#c8102e` | `#ff5a74` | severity fill |
| `--sev-high` | `#d2600f` | `#ff9348` | severity fill |
| `--ok` | `#1a6b4a` | `#4fc08d` | reserved: "AI confirmed this match" |

`--sev-medium` and `--sev-low` complete the severity family.

**The rule that holds it together: severity owns chroma.** Four hues are
spoken for by the thing the user is triaging on. The structure accent is a
desaturated steel deliberately far from all four, so the single filled
button on the page reads as *the action* and never competes with an orange
badge for the same glance. Source, ecosystem and package badges get an
outline and no fill — they were louder than the CWE that is the actual
subject of the search.

`--ok` and `--bad` carry two things and only two: the AI verdict, and
whether GitHub and the AI endpoint are reachable. That second use is why
`--sev-low` is a steel blue rather than the green it once shared — a low
severity and a working connection must not look like the same fact.

Neither status is hue alone. A reachable source is a filled dot, an
unreachable one is a ring, because red and green are the commonest pair to
confuse and between 461 and 480px the word beside the dot is clipped out of
view. The same rule is why the pill's state is clipped rather than
`display: none`: clipping keeps it in the accessibility tree, and the
narrower breakpoint had been removing it outright.

Two families that look similar are not interchangeable: `--warn` / `--bad`
are **text** colours that must clear 4.5:1 on the badge fill, while
`--sev-*` are **fills** that sit behind ink. The stylesheet says so at the
point of definition.

## Type

No webfonts. The CSP is `default-src 'self'` with no `font-src`, so a CDN
face is blocked outright — correct for a tool that holds the operator's
GitHub and AI credentials. Personality therefore has to come from the scale
and from how the two system stacks are used, not from a typeface purchase.

- `--sans` — `system-ui` stack. All prose, labels and controls.
- `--mono` — `ui-monospace` stack. **Only** for codes the reader may copy or
  compare down a column: CWE and CVE ids, CVSS vectors, EPSS figures,
  ecosystem codes. Never as texture on a label.

That second rule is deliberate and was re-tested during this pass. Using a
monospace face for small data labels is one of the commonest tells of a
generated page, and the temptation here ("security tool, terminal heritage")
is strong. The stylesheet had already drawn the line in the right place:
mono means *this is a code*, and nothing else.

### The scale

Six steps. Every rule in the sheet uses a token; there are no hard-coded
sizes, and `tests/test_frontend_js.py` fails if one appears.

| Token | Size | Job | Ratio to previous |
|---|---|---|---|
| `--text-xs` | 11px | metadata, badges, counts | — |
| `--text-sm` | 12.5px | secondary text, small controls | 1.14 |
| `--text-base` | 14px | body, inputs, buttons | 1.12 |
| `--text-lg` | 17px | card and panel titles | 1.21 |
| `--text-xl` | 22px | section and dialog headings | 1.29 |
| `--text-display` | `clamp(28px, 3.4vw, 40px)` | the page heading, once | ~1.36 |

Ratios widen as they climb, so a step up is legible as a change of **rank**
rather than merely a change of size. The scale is also enforced to keep
steps at least 1.10× apart.

This replaced a genuine defect rather than a matter of taste. The sheet used
to declare nine tokens, reference three of them, and then set **14
hard-coded sizes — ten of which landed inside a 6px band**. A declared scale
that nothing uses is worse than no scale: it reads as intentional while the
page is ad hoc, and the result was one undifferentiated field of small grey
text. The landing page now renders six sizes where it rendered ten.

Line length stays under 80 characters; the workspace copy is capped at
`520px`.

### Corners

Four radii and two shapes, each with a job: `--radius-xs` 4px (tight
controls), `--radius-sm` 6px (cards, badges), `--radius` 9px (panels),
`--radius-pill` 999px (chips, status pills). Plus `0` and `50%`, which are
not steps on a scale — they are "no corner" and "a circle".

Previously five tokens were declared, two referenced, and the rest written
raw, including both `99px` and `999px` for the same pill: two answers to one
question.

## The opening screen

The workspace used to open on a centred card: a headline, a paragraph,
three numbered steps and a tip telling you to go and tick a class in the
rail. Below it, nothing — at 1440×900 roughly 60% of the reading surface
was empty, and the card's whole job was to point at a control somewhere
else.

It opens on the taxonomy now. All 29 bug classes, under their families,
each with its code and the size of its CWE set, and picking one is a click
rather than a hunt. The hero is the most characteristic thing in this
subject's world — the set of weakness classes — rendered as the real thing
rather than described.

```
 Search by how the bug
 works, not by the title.          ← the claim, at display size
 Pick a class to start — or type a CWE id…

 Access control & auth ─────────────────────────────────────────
 ┌──────────────────┬──────────────────┬──────────────────┐
 ┃BAC Broken Access │CSRF Cross-Site   │CORS CORS / Origin│   ┃ = the spine,
 ┃    Control       │     Request…     │     Validation   │       filled when
 ┃    17 CWEs       │     2 CWEs       │     3 CWEs       │       picked
 └──────────────────┴──────────────────┴──────────────────┘
 Injection ─────────────────────────────────────────────────────
 ┌──────────────────┬──────────────────┬──────────────────┐
 │SQLI SQL Injection│XSS  Cross-Site…  │SSTI Server-Side… │
```

Two structural devices, both carrying information rather than decorating:
the hairline that runs out from each family name, so a family reads as a
band across the grid instead of a label floating above it; and a left spine
on each tile that fills with the accent when the class is picked. No card
shadows — these are 29 equal things, and elevation would imply a hierarchy
that does not exist.

The map and the rail's checkbox list are two views of the same checkboxes,
so they cannot disagree; a browser test asserts exactly that, because if
they ever drift the page shows one selection and searches another. Clicking
a picked class removes it, so the map is a toggle rather than a one-way
door. Focus stays on the tile you clicked: the shared `pickEntry()` hands
focus to the rail's search box, which is right when you arrived by typing
and wrong when you arrived by clicking.

## Layout

A fixed command surface on the left, a reading surface on the right. The
rail is where you *build* a query; the workspace is where you *read* the
answer. Nothing that changes the query lives in the workspace, and nothing
that reports results lives in the rail.

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │ VS  VulnSight     ●GH Connected ○AI Not configured [Test AI] 1059 cached │  topbar, sticky
 ├──────────────────────┬─────────────────────────────────────────────────┤
 │ Build a search       │  Advisory queue                 Severity   CVSS │  display heading
 │  ┌────┬────┬────┐    │  Merged records from GHSA,     ┌────┬────┐      │  + severity key,
 │  │  4 │ 29 │944 │    │  NVD and OSV, ranked for       │Crit│High│      │    right-aligned
 │  └────┴────┴────┘    │  triage.                       └────┴────┘      │
 │                      │ ─────────────────────────────────────────────── │
 │ Bug class   CWE 4.20 │  Select a bug class.   [Refine AI][Retry][Exp↓] │  toolbar: the
 │ ┌──────────────────┐ │                                                 │    money actions
 │ │ 639 · IDOR …     │ │  ┌───────────────────────────────────────────┐  │
 │ └──────────────────┘ │  │  Search by how the bug works,             │  │  hero: the claim,
 │ [Broken Access ✕]    │  │  not by the title.                        │  │    not a stat
 │ ┌──────────────────┐ │  │                                           │  │
 │ │ ☑ Broken Access  │ │  │  ① Search   ② Refine   ③ Isolate          │  │  a real sequence,
 │ │ ☐ CSRF           │ │  └───────────────────────────────────────────┘  │    so numbered
 │ └──────────────────┘ │                                                 │
 │ Sources / Scope …    │                                                 │
 │ ┌──────────────────┐ │                                                 │
 │ │ Run intelligent  │ │                                                 │  the only filled
 │ │       scan       │ │                                                 │    control
 │ └──────────────────┘ │                                                 │
 └──────────────────────┴─────────────────────────────────────────────────┘
```

Below `900px` the rail becomes a modal slide-over reached from a **Filters**
button, and the workspace takes the full width. The breakpoint is declared
once, as `--breakpoint-panel`, and read by `app.js` from CSS so the two
cannot drift.

```
 ┌───────────────────────────┐
 │ VS   ●GH ●AI [Test] ◐  ☰  │   below 460px the wordmark and the two
 ├───────────────────────────┤   status indicators are clipped out of
 │ Advisory queue            │   view (not removed — still announced),
 │ Merged records from …     │   because at 320px they were competing
 │ ┌─────────┬─────────┐     │   with the controls you came for
 │ │Critical │ High    │     │
 │ └─────────┴─────────┘     │
 │ [Refine with AI        ]  │   actions stack full-width; a disabled
 │ [Retry failed          ]  │   one is grey, never accent-coloured
 │ [Export               ↓]  │
 └───────────────────────────┘
```

**Alignment.** Everything is left-aligned and ragged-right. The one
exception is the severity key, which is right-aligned under its `CVSS`
label so the four bands line up with the numbers they describe. No centred
text anywhere: this is a scanning surface, and a centred left edge destroys
scanning.

## The second page

`/api/docs` is the other rendered page, and it was outside every earlier
audit — those only ever loaded `/`. Reviewing it found that the design
system covered one of the product's two pages: `static/apidocs.css` carried
seven hard-coded font sizes and no scale tokens at all, on the page an
integrator reads before writing a client.

The sheet is standalone on purpose — `style.css` is 1,700 lines of app UI
and this page needs a few dozen rules — and it already restated the palette
as the small subset it uses. It now restates the type scale the same way,
and `tests/test_frontend_js.py` checks **both** sheets: no hard-coded sizes
in either, and the steps they declare must be equal, or "one scale" is a
claim rather than a fact.

It also had no `rel="icon"`, so every first load of `/api/docs` logged a
404 for `/favicon.ico` — in the console of a tool whose job is to surface
problems. Both templates now declare the same head, and a test fails if they
diverge again.

**One deliberate exception to the tell list.** This page uses tracked-out
small-caps for three things: table column heads (`FIELD` / `TYPE` /
`NOTES`), the `REQUIRED` badge, and section labels (`REQUEST BODY`,
`RESPONSES`). The brief lists ALL-CAPS eyebrows as a tell, and on the app
page there is exactly one such rule (severity badges, where the label is a
code). Here they are kept: in an API reference they are column headers and
status badges in a dense table, not decoration above a heading, and the
convention is what a reader of any API reference already scans for. Noted
rather than silently kept, so the next reviewer can disagree.

## Principles

1. **Severity is the only chroma that means anything.** Chrome stays
   neutral. If something is coloured, it is because the colour is data.
2. **No size without a job.** Two things set at different sizes must differ
   in rank. Six steps, and a test that keeps them apart.
3. **Mono means "this is a code you can copy."** Never texture, never a
   label.
4. **The control that spends money is the only filled one** — and a disabled
   action is grey, never a muted version of its accent, because a
   half-bright warning colour still reads as actionable.
5. **Say what the user gets, not what the system does.** Source descriptions
   answer "what do I get if I tick this?" — *"GitHub, filtered by CWE at the
   source"*, not *"GHSA · CWE filter"*.

## Reviewed against the brief

A design is not finished because its author likes it. This is the check
against the known tells of a generated page, done by measuring the sheet.

| Tell | Status |
|---|---|
| Cream `#F4F1EA` + serif display + terracotta accent | absent |
| Near-black + a single acid-green or vermilion accent | partly — the ground is near-black, but the accent is a desaturated steel chosen to stay out of the severity hues, and severity owns the chroma |
| Broadsheet: hairline rules, zero radius, dense columns | absent |
| SaaS-card kit: one radius on everything, identical soft shadows | absent — four radii that encode rank, no `rgba(0,0,0,.1)` shadow anywhere |
| Tracked-out ALL-CAPS eyebrow above every heading | one uppercase rule, on severity badges, where the label is a code |
| Meta strings joined with middle dots (`A · B · C`) | **was present** — five decorative joins, now written as phrases. The remaining dots join genuinely parallel facets (`GHSA+NVD · max 100 · oldest first`) |
| `WORD — fragment` with a spaced em dash | used sparingly, in prose, not as a label pattern |
| Tinted near-black (`#0B0B0B`, `#111`) standing in for black | absent |
| Monospace for small data labels | avoided on purpose — see **Type** |
| `→` appended to link and button text | one `→`, and it is `package → first-patched-version`, carrying meaning |

### What changed because of this review

- The type scale, as described above. The plan that went into this pass said
  "keep the type, fix the copy"; measuring the sheet showed the type *was*
  the problem.
- Two things were deliberately **not** changed. The palette is already a
  documented, measured system; re-picking it would have been motion rather
  than design. And promoting mono to the structural voice was rejected as a
  listed tell, after the stylesheet turned out to have made the better call
  already.

## What is measured, and where

`python tools/design_audit.py --out shots/` drives Chromium across fourteen
states and fails on any of:

| | Viewport | Themes |
|---|---|---|
| `/` empty | 1440×900, 390×844, 320×844, 820×1180, 1920×1080 | light and dark |
| `/` with results | 1440×900, 390×844, 320×844 | light and dark |
| `/api/docs` | 1440×900, 390×844 | light and dark |

The figure here is checked against `design_audit.STATES`, so it cannot
drift the way "seven" did when the API page was added.

**The populated states are the point of the second row.** For as long as
this tool has existed it opened the page and measured whatever was visible,
which is the empty landing screen — so the results surface, where the
operator spends the entire session, had never been measured at any width in
either theme. It is also where almost all of the interface lives: the
severity badge, the EPSS meter, the per-card meta row, the source badges
and the warnings. The audit now stubs a search at the network boundary and
waits for the first card.

The first run against it failed, and what it found was not cosmetic:

- Every advisory-id and CVE link had a **17px** hit area, under the 24px
  floor, on the surface a phone user spends the whole session in — and
  those links are the way out of this page. The history **Clear** button
  was 18px. Half of the interactive elements at 390px were under-size.
- An empty CWE list still rendered `· CWEs:` and an empty `<code>`, which
  paints as a stray 6px box after the count.
- Severity was encoded **twice**: the card's left spine, and a saturated
  filled badge at the opposite corner. The spine is the half that reads
  down a column — the eye follows one edge instead of re-entering every
  card — so the badge was repeating it, louder, and pulling the glance off
  the title on every row. The word stays, because colour alone is not a
  signal; it now sits on a 16% tint of its own band instead of a fill.
- Search warnings were emitted as error toasts, so a persistent statement
  about the result set floated over the bottom-right of the list and
  covered the title of whichever advisory was there. A warning about the
  results, hiding the results. They render with the summary they qualify.

Two copy defects came out of the same pass. The workspace said results were
"ranked for triage" when the default order is publication date — which is
why a LOW advisory at 1% EPSS sits above a CRITICAL one being actively
exploited. And the direction control offered "Newest first / Oldest first"
whatever the sort field, so ordering by CVE id offered an age for something
that has none, and ordering by EPSS called the highest probability
"newest". The direction words follow the field now, and the active order is
stated on the result line, which is where someone reading the list looks.


- **Contrast** below the WCAG AA threshold for that element's own size and
  weight, measured against the actually-painted background rather than the
  element's own (usually transparent) `background-color`.
- **Tap targets** under 24px, measured on the real hit area — the wrapping
  `<label>` where there is one, not the 16px checkbox inside it.
- **Keyboard focus** with no visible indicator, found by pressing Tab and
  checking the element *and its ancestors*, because a composed control shows
  its ring on a `:focus-within` wrapper.
- **Horizontal overflow** at any width.
- **Console or page errors.**

Three cautions are encoded in that script because each produced a false
finding before it was understood:

1. `el.focus()` does not put Chrome into `:focus-visible` for a button, so
   probing focus that way reports a correctly-styled page as having no focus
   rings at all.
2. A focus ring usually lives on a wrapper, so checking only
   `document.activeElement` reports every composed control as bare.
3. `getComputedStyle` returns `rgb()` in 0–255 **and** `color(srgb r g b)` —
   which is what `color-mix()` resolves to — in 0–1. Reading the second as
   the first turns 16:1 text into 1.17:1 and invents a page of failures.

See [testing](testing.md) for the frontend linters and the type-scale drift
tests, and [architecture](architecture.md) for where the files live.
