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
| `--text-figure` | `clamp(30px, 4.2vw, 52px)` | the funnel figures, once | ~1.30 |

Ratios widen as they climb, so a step up is legible as a change of **rank**
rather than merely a change of size. The scale is also enforced to keep
steps at least 1.10× apart.

`--text-figure` is the seventh step and has exactly one user: the funnel.
It exists because the funnel is the page's single loud element, and at
`--text-display` the masthead and the figures would be two things claiming
the same rank. If anything else ever takes this step, the funnel has
stopped being the loud thing and the step should go.

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

## What was wrong with the page as a whole

Not any one region. The page is a competent dark admin console, and that
is the problem: nothing about it could only be this product. Three
structural facts produce that:

**Everything is in a box, and the boxes nest.** A bordered rail inside the
shell, bordered sections inside the rail, bordered controls inside the
sections; a bordered workspace, bordered cards, bordered badges inside the
cards. Five levels of container on a page whose content is already
hierarchical. Each border is defensible alone; together they are why the
page reads as chrome rather than evidence.

**Structure is carried by borders rather than by space and type.** Because
every group is drawn, none of them need to be *placed*, so the whole page
sits at one rhythm. There is no silence anywhere.

**The masthead says nothing.** "Advisory queue" at 40px over a paragraph,
with the severity key floated opposite. It is a title, not a statement of
where you are in a funnel of 944 CWEs → 29 classes → your selection → the
handful AI confirms. That funnel is the product, and the page never shows
it.


Unchanged, and that is a decision rather than an omission. The palette is
measured, documented and accessible, and severity owns the chroma. Re-picking
it would be motion, not design — and the one axis the brief leaves free is
where this page is generic, which is structure, not hue.

| Token | Light | Dark | Job |
|---|---|---|---|
| `--bg` | `#f7f8f9` | `#15181d` | the ground |
| `--ink` | `#14181d` | `#e9ebef` | body text |
| `--accent` | `#334e68` | `#8fb3d9` | focus, selection, the one filled control |
| `--sev-critical` | `#c8102e` | `#ff5a74` | severity edge |
| `--sev-high` | `#d2600f` | `#ff9348` | severity edge |
| `--ok` | `#1a6b4a` | `#4fc08d` | AI confirmed, and source reachable |

What changes is how much of it is *drawn*: `--line` stops being the
default way to group things.

## Critique, before building

Working the brief from scratch for "a security dashboard" lands on: dark
ground, left rail, cards, a coloured severity pill, a stat row at the top.
That is close to what this page already is, which is the evidence that it
was never designed — it was defaulted into.

So, against each free axis:

- **The funnel as the hero.** A row of big numbers is the brief's named
  default hero treatment, and I am proposing big numbers. The difference
  has to be real or this fails its own test: these are not vanity stats
  (users, uptime, "99.9%"), they are the four stages of the query the user
  is building, in order, and the fourth changes when they search. If they
  were decorative I would be reproducing the tell exactly. **Revised:** the
  figures are *derived from the live query*, the fourth is empty until a
  search runs, and there is no card, border or gradient behind them — the
  moment they get a box they become the stat row and must go.

- **Removing borders.** The risk is landing on the broadsheet tell —
  hairlines, zero radius, dense columns. **Revised:** radii stay on the
  things that remain boxes (inputs, modals, badges), entry density goes
  *down* not up, and the one vertical rule is a column separator, not a
  grid. Airy, not newspaper.

- **The severity edge.** Already present as a 3px card border-left; making
  it the entry's only container is a change of role, not a new device. It
  reads down a column, which is what a triage queue is scanned as.

- **Not changing the palette.** Tempting to prove effort by re-picking it.
  The doc already argues this and the argument is right: the palette is
  the one part that was designed rather than defaulted.

- **`--text-figure`.** A seventh step on a scale the docs defend as six.
  Justified only if the funnel is genuinely the page's one loud thing — and
  if it is, 40px display type next to 40px figures would be two things
  claiming the same rank. It earns the step by being the only user of it.

## Every region, judged

The sections above are the plan. This is the critique: each region of the
page in turn, against the brief's list of generated-page tells and against
the five principles. It exists because the earlier passes judged the
regions that were being changed, which is the easy half — a page is
generic in the regions nobody looked at.

Two of these were found only because this sweep happened. The results
surface had never been opened by `tools/design_audit.py`, and the AI
verdict panel had never been rendered outside a browser test that asserts
on text.

| Region | Verdict |
|---|---|
| Topbar wordmark | **Keep.** A two-letter monogram and a name. The subtitle says what the product does in five words rather than a tagline. |
| Status pills | **Changed.** Mono was set on the whole pill, putting a monospace face on "Connected" and "cached" — the sheet's own rule is that mono means a code. Mono is now on `GH`/`AI` and the count only. State words were shouted caps and `AUTHED` was `gh auth status` vocabulary. |
| Status dots | **Changed.** Filled vs ring, not red vs green alone. Below 480px the word beside the dot is clipped, so hue was carrying the state by itself. |
| `Test AI` | **Keep.** The one accent-filled control in the topbar, and it spends nothing — it is the "will this work before I pay" button, which is the brief's second job. |
| Cache count | **Keep.** A number that changes under the reader's eye, so the digits are mono and do not shift width. |
| Theme toggle | **Keep.** An icon button with an `aria-label`; no text competing at 320px. |
| Rail heading + reach line | **Changed.** "4 / 29 / 944" in three bordered boxes was the brief's named default hero treatment, holding three numbers nobody acts on. One sentence of prose now. |
| Recent searches | **Keep.** Real state, not a canned preset list: each row is a query that was actually run, with its hit count and how long ago. |
| Bug-class finder | **Keep.** A combobox over 944 CWEs that accepts an id, a name or a community alias. The hint under it states all three, which is the only place that can be said for a one-line input. |
| Selected chips | **Keep.** Each carries a remove control; the count line states what the selection will cost ("1 AI pass per advisory") before anything is spent. |
| Class list | **Keep.** Checkboxes with a description each. The descriptions are what the AI prompt uses as the class definition, so they are load-bearing text rather than help copy. |
| Sources | **Keep.** Each option says what you get, not what it is: "GitHub, filtered by CWE at the source". |
| Scope / Query | **Changed.** The direction control said "Newest first" whatever the sort field, so ordering by CVE id offered an age for something that has none. |
| Run buttons | **Keep.** One filled control — the one that spends money — and a quiet secondary beside it. A disabled action is grey, never a dimmed accent, because a half-bright warning colour still reads as actionable. |
| Workspace heading | **Changed.** It claimed results were "ranked for triage" when the order is publication date. |
| Severity key | **Changed.** Four bordered cards in a page already built of them. A legend has no business carrying the weight of the thing it explains. |
| Signals line | **Keep.** `GHSA NVD OSV EPSS AI` names the per-card marks, in the order they appear on a card. |
| Result summary | **Changed.** An empty CWE list still rendered `· CWEs:` and an empty `<code>`, which paints as a stray box. The active order is now stated here. |
| Search warnings | **Changed.** Emitted as error toasts, so a persistent statement about the result set floated over the list and covered a card title. |
| Toolbar actions | **Keep.** "Refine with AI" is the filled one; it is the control that spends. |
| Export | **Keep.** A `<details>` popover, three formats, no modal for a three-item menu. |
| Card | **Keep.** A bordered rounded rectangle is the right primitive *here*: a card holds genuinely mixed content — a title, badges, a package range, a meta row and sometimes a verdict — unlike the twenty-nine equal taxonomy entries, which were boxes around nothing. |
| Severity on a card | **Changed.** Encoded twice: a left spine *and* a saturated filled badge at the far corner. The spine is the half that reads down a column. |
| `KEV / EXPLOITED` | **Keep.** The one filled badge on the surface, on the single most decision-relevant fact: this is being exploited now. Boldness spent once. |
| Source badges | **Keep.** Outline, no fill. They were louder than the CWE that is the subject of the search. |
| CWE badge | **Keep.** The id in mono, the name in sans behind a hairline. The id is the code; the name is prose. |
| Package range | **Keep.** `lodash → 4.17.21` — the arrow carries meaning (vulnerable → fixed), which is the brief's own exception to the "→ appended to link text" tell. |
| Meta row | **Changed.** The advisory and CVE links had a 17px hit area. The labels before each value stay: two identifiers sit side by side and the row is the only place to disambiguate them. |
| EPSS meter | **Keep.** A quantity as a length, beside the figure. The same device as the class-field measure, which is why it reads as one system. |
| AI verdict panel | **Keep.** Green left rule for a confirmed match, the class it matched, a confidence figure, and the model's reason in full. `--ok` green appears here and on the status dots and nowhere else. |
| Empty / onboarding hero | **Keep.** The claim at display size, and the taxonomy immediately under it. |
| Class field | **Changed.** Twenty-nine identical boxes said these are twenty-nine equal things. The CWE count is a length now, and the track doubles as the entry's baseline. |
| Auth gate | **Keep.** A modal that traps focus and inerts the page behind it, with one input and one action. It appears because the bind guard decided a token is required, and it says so. |
| Toasts | **Partly kept.** Transient completion messages stay as toasts; only the persistent warnings moved. A toast that disappears is a different thing from a statement about the result set. |
| Mobile slide-over | **Keep.** Below 900px the rail becomes a panel reached from one button. The breakpoint is declared once as `--breakpoint-panel` and read from CSS by `app.js`, so the two cannot drift. |

### Tells, re-checked across the whole page

| Tell | Status |
|---|---|
| Cream `#F4F1EA` + serif display + terracotta accent | absent |
| Near-black + one acid accent | partly — the ground is near-black, the accent is a desaturated steel chosen to stay out of the four severity hues, and severity owns the chroma |
| Broadsheet: hairline rules, zero radius, dense columns | absent. The class field lost its borders but gained space and a measure, not rules |
| SaaS-card kit: one radius on everything, identical soft shadows | **was present, and the earlier self-review graded its way out of it by counting radii.** Four radii on one component at four sizes is still one component. The class field and the severity key are no longer cards; the result card stays, because it holds mixed content |
| ALL-CAPS eyebrow above every heading | one CSS rule, on severity badges, where the label is a code. The status words were shouted in the markup instead, which the CSS-only claim did not cover; they are sentence case now |
| Meta strings joined with middle dots | the remaining dots join genuinely parallel facets (`6 advisories · newest first · CWEs: 639`) |
| `WORD — fragment` with a spaced em dash | used in prose, not as a label pattern |
| Tinted near-black standing in for black | absent |
| Monospace for small data labels | **was present on the status pills.** Mono is now codes, ids, vectors and counts only |
| `→` appended to link and button text | one `→`, in `package → first-patched-version`, carrying meaning |

### What this sweep did not change, and why

The **default sort** is publication date, so a LOW advisory at 1% EPSS sits
above a CRITICAL one being actively exploited. The interface no longer
claims otherwise, but a risk-ordered default would serve the stated job
better. It changes what every existing API caller gets back, so it is a
product decision and sits in [open findings](open-findings.md).

The **class filter narrows the rail and not the map**. Typing "idor" leaves
the rail showing "1 of 29" beside a map still showing twenty-nine. Both
readings are defensible — the map is the overview, and collapsing it to one
tile while typing would destroy that — so the behaviour stands rather than
being changed on a preference.

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
