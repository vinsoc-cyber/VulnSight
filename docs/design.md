# Design

The design plan this interface is built to, the reasoning behind each choice,
and the measurements that check it. Written so the next person can disagree
with a decision on its merits rather than guess at the intent.

Numbers quoted here are produced by `python tools/design_audit.py`, which
drives a real browser across nineteen viewport/theme states. `tests/test_docs.py`
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

`--text-display` has exactly one user: the line that tells you how to
start, on the browse view. That line leaves the page as soon as a search
returns, so nothing on the results view competes with an advisory title.

A seventh step, `--text-figure` at up to 52px, used to carry the funnel
figures. The funnel is gone (see **Two views, one page** below) and a step
with no user is a decision nobody made, so the step went with it.

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
each with the size of its CWE set, and picking one is a click rather than
a hunt. The hero is the most characteristic thing in this subject's world
— the set of weakness classes — rendered as the real thing rather than
described.

```
 Search by how the bug
 works, not by the title.          ← the claim, at display size
 Pick a class to start, or search by CWE id…

 Access control & auth ─────────────────────────────────────────
 ┃ Broken Access      Cross-Site Request   CORS / Origin      ┃ = the spine,
 ┃ Control (BAC…)     Forgery (CSRF)       Validation Failure     filled when
 ┃ 17 CWEs            2 CWEs               3 CWEs                 picked
 Injection ─────────────────────────────────────────────────────
   SQL Injection      Cross-Site           Server-Side Template
                      Scripting (XSS)      Injection / Code…
   3 CWEs             5 CWEs               6 CWEs
```

An entry says two things: which bug it is, and how wide a net the class
casts. It said four. A mono code sat in a left gutter — `BAC`, `CSRF`,
`SSTI` — spelling the name beside it a second time in the API's internal
spelling, which is something to look up in `/api/docs` rather than to read
29 times on the way to picking one. And a 2px track under each entry drew,
as a length, the count printed directly above it.

**Reversed, later.** The track was argued for on this page as 29 classes
made comparable at a glance, and the argument does not survive asking who
makes that comparison. Nobody picks a bug class by the size of its CWE
set; you pick the bug you are hunting and then read what it covers. What
the track did do was end at a different x under every entry — labels wrap
to one line or two and the track sat below whatever they did — and 29
ragged underlines is most of the reason four tidy columns read as a
jumble. The label and the count are pushed to the two edges of the entry
instead, so every label in a row starts on one line and every count ends
on another.

Two structural devices, both carrying information rather than decorating:
the hairline that runs out from each family name, so a family reads as a
band across the grid instead of a label floating above it; and a left spine
on each tile that fills with the accent when the class is picked. No card
shadows — these are 29 equal things, and elevation would imply a hierarchy
that does not exist.

The map and the rail's checkbox list are two views of the same checkboxes,
so they cannot disagree; a browser test asserts exactly that, because if
they ever drift the page shows one selection and searches another. They
are not, however, two views that belong on screen at once — see
[One taxonomy, not two](#one-taxonomy-not-two). Clicking
a picked class removes it, so the map is a toggle rather than a one-way
door. Focus stays on the tile you clicked: the shared `pickEntry()` hands
focus to the rail's search box, which is right when you arrived by typing
and wrong when you arrived by clicking.

## Layout

A fixed command surface on the left, a reading surface on the right. The
rail is where you *build* a query; the workspace is where you *read* the
answer. Nothing that changes the query lives in the workspace, and nothing
that reports results lives in the rail.

### Two views, one page

The workspace carries `data-view`, and it has two values. Everything that
is dead in one of them is absent rather than greyed.

```
 data-view="browse"                       data-view="results"
 ┌────────────────────────────┐           ┌────────────────────────────┐
 │ Search by how the bug      │  display  │ 6 advisories, most urgent  │  the live count,
 │ works, not by the title.   │   step    │ CWEs 639   6 AI-scored     │    at body size
 │ Pick a class to start …    │           │        [Refine][Retry][Exp]│  commands arrive
 │                            │           │ ────────────────────────── │    with the data
 │ Access control & auth      │           │ ▌Improper access control…  │
 │  BAC  Broken Access  17    │  the      │   Exploited (KEV)          │
 │  CSRF Cross-Site Req  2    │  class    │   lodash → 4.17.21         │
 │  ───────────────────────   │  map is   │   ● Confirmed match   94%  │
 │ Injection                  │  the      │   GHSA+NVD npm CWE-639 …   │
 │  SQLI SQL Injection   3    │  hero     │ ▌Prototype pollution in …  │
 └────────────────────────────┘           └────────────────────────────┘
```

What used to sit above both: `Advisory queue` at display size, a
paragraph, four figures at 52px and a severity key — roughly **290px of
chrome that never changed and never left**. It gave the page two display
headings fighting for the top, and a legend for badges that were not on
screen yet. Three of the four figures were constants; the rail states both
in one line, and the two live ones are in the summary.

The command bar goes with it. Every control on it — Refine with AI, Retry
failed, Confirmed only, Export — is dead until a result exists, and four
greyed controls above the fold read as a broken page rather than an early
one. It is `display: none` and not `visibility: hidden`, because the bar
is sticky and 64px tall: hidden-but-present would push the class map down
the screen by the height of controls nobody can use.

The switch is one-way and fires when the search *starts*, after the
validation bail-outs. A spinner, an empty result set and an error all
belong to the results view, because each is an answer to a question that
was asked; a rejected query never ran, so the page is still browsing.

```
 ┌──────────────────────┬─────────────────────────────────────────────────┐
 │ Build a search       │  (workspace: one of the two views above)        │
 │ 29 classes over 956  │                                                 │
 │ CWEs, four sources   │                                                 │
 │                      │                                                 │
 │ Bug class   CWE 5.0  │                                                 │
 │ ┌──────────────────┐ │                                                 │
 │ │ 639 · IDOR …     │ │                                                 │
 │ └──────────────────┘ │                                                 │
 │ [Broken Access ✕]    │                                                 │
 │ ┌──────────────────┐ │                                                 │
 │ │ ☑ Broken Access  │ │                                                 │
 │ │ ☐ CSRF           │ │                                                 │
 │ └──────────────────┘ │                                                 │
 │ Sources      GHSA ⌄  │  ← folded, value kept on the heading            │
 │ Scope                │  ← open: ecosystem is changed between searches  │
 │ Options  100 rows ⌄  │  ← folded                                       │
 │ ┌──────────────────┐ │                                                 │
 │ │ Run intelligent  │ │                                                 │  the only filled
 │ │       scan       │ │                                                 │    control
 │ └──────────────────┘ │                                                 │
 └──────────────────────┴─────────────────────────────────────────────────┘
```

**The rail folds two of its seven sections.** It held all seven open at
once — about 1400px of scroll behind a 320px column, so opening the page
put you in the middle of a checkbox list with no visible beginning.
Sources and Options are the two a search rarely needs, and each keeps its
current value on the heading while shut, so folding hides the controls and
never the setting: with Sources shut and no value there, a query could run
against OSV's ~220MB npm export with nothing in the rail saying so. Scope
stays open, because ecosystem is the filter people change between searches.

Below `900px` the rail becomes a modal slide-over reached from a **Filters**
button, and the workspace takes the full width. The breakpoint is declared
once, as `--breakpoint-panel`, and read by `app.js` from CSS so the two
cannot drift.

```
 ┌───────────────────────────┐
 │ VS   ●GH ●AI [Test] ◐  ☰  │   below 460px the wordmark and the two
 ├───────────────────────────┤   status indicators are clipped out of
 │ [Refine with AI        ]  │   view (not removed — still announced),
 │ [Retry failed          ]  │   because at 320px they were competing
 │ [Export               ↓]  │   with the controls you came for
 ├───────────────────────────┤
 │ ▌Improper access control… │   actions stack full-width; a disabled
 │   Exploited (KEV)         │   one is grey, never accent-coloured
 │   lodash → 4.17.21        │
 └───────────────────────────┘
```

**Alignment.** Everything is left-aligned and ragged-right. No centred
text anywhere: this is a scanning surface, and a centred left edge destroys
scanning. The one right-aligned thing is a folded section's value, which
sits against the rail's right edge so the chevrons line up down the column.

### One taxonomy, not two

The pass above quietened the chrome, and the page was still reported as
busy to look at. Measuring the landing screen said why: it was printing
the taxonomy twice.

| On the landing screen | Before | After |
|---|---:|---:|
| Painted elements | 444 | 202 |
| Of those, carrying text | 200 | 105 |
| …at 13px or smaller | 188 | 94 |
| Bug-class names on screen | 59 | 30 |
| Family headings, for 7 families | 14 | 7 |
| Characters of text in the 320px rail | 5542 | 408 |
| Characters of text in the workspace | 1415 | 1296 |

Every class was on screen twice at rest: once as the workspace map, and
again as a rail list with a description under every label. A second copy
of the taxonomy is not a second way in — it is the same way in, printed
twice, in two visual languages, and the reader has to work out that they
are the same 29 things before either is useful. 94% of the page's text
sat in the two smallest steps of the scale, with nothing between 13px and
the 28px of the heading.

So the map is the taxonomy, and the rail list is the control that edits
it. It folds, like Sources and Options, and ships shut. The rule those
two established — a fold may hide controls and never state — is why it
needs no value on its heading: what is ticked is named directly above it,
as Query-target chips, and a value there would be the same selection
printed a third time. Two browser tests hold the pair of claims: that a
class name is painted once per place it means something, and that the one
fold without a value has its setting on screen anyway.

The description under each label went with it — up to five lines at 11px,
29 times, the largest block of small grey text the page had. It is on the
row's `title`, on the map entry beside it, and in
[Bug classes](bug-classes.md), which has the width for a sentence.

```
 before                              after
 ┌─────────────────────────┐         ┌─────────────────────────┐
 │ Bug classes 29 available│         │ Bug classes 29 available ⌄
 │ [Filter these 29 classes]         │ ☑ Include extended CWEs │
 │ ┌─────────────────────┐ │         │                         │
 │ │ Access control & auth│ │        │ Sources          GHSA ⌄ │
 │ │ ☑ Broken Access Cont…│ │        │                         │
 │ │   Authorization and  │ │  ~1900 │ Scope                   │
 │ │   access-control fla…│ │   px   │ [maven ▾] [Any ▾]       │
 │ │   object-level (BOLA │ │   of   │                         │
 │ │   /IDOR), function-l…│ │  list  │ Options  100 results, ⌄ │
 │ │ ☐ Cross-Site Request…│ │        │                         │
 │ │   A state-changing r…│ │        └─────────────────────────┘
 │ │   …27 more           │ │
 │ └─────────────────────┘ │          the same 29 classes are in
 └─────────────────────────┘          the workspace, with the room
                                      to show them
```

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

  **Reversed, later.** The test above was the wrong test. The figures never
  acquired a box, so by its own terms the funnel passed — and it still had
  to go, because only one of the four ever moved. "Derived from the live
  query" was true of `944` and `29` in the sense that the template read
  them from the catalog, not in the sense that a reader would ever see them
  change. Two constants and a selection counter at 52px, kept because a
  rule written in advance said boxes were the danger. The rule was about
  the wrong property.

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

  **Reversed, later.** "Two things claiming the same rank" was the right
  worry and the wrong conclusion: the answer was to have one of them, not
  to give the second its own step. The masthead and the funnel both went,
  `--text-display` now has a single user, and the scale is back to six.

## Every region, after the rebuild

Each region of the page in turn. The table below is the state *after* the
restructure described above, not before it: an earlier version of this
table was written during the corrective pass and said "keep" for regions
the rebuild then changed, which made it a record of intentions rather than
of the page.

**Redesigned** means the region's visual structure changed in the rebuild.
**Reworked** means it was corrected earlier in the review — a defect, a
contrast failure, a piece of copy. **Kept** means it survives review
unchanged, with the reason recorded, because "we changed everything" is
not a better answer than "this part was already right".

| Region | |
|---|---|
| Rail column | **Redesigned.** A panel with its own fill and border became a column with one vertical rule. A rail in a different colour from the workspace is two surfaces; this is one page. |
| Rail sections | **Redesigned.** Six stacked bordered blocks gave the rail one flat rhythm in which nothing outranked anything. Space and headings carry it now. |
| Class list rows | **Redesigned.** Twenty-nine filled rows made the checked state fight the fill it sat on. Unfilled, a selection is simply the one that is coloured. |
| Source rows | **Redesigned.** Same change; the dashed "advanced" box became a dashed rule. |
| Masthead | **Removed.** It became a masthead with the funnel beneath it, and then went entirely: title, paragraph, figures and key were ~290px of chrome that never changed and never left, above a page whose own hero sat below them. Two display headings were fighting for the top. |
| The funnel | **Removed.** Added as 944 CWEs → 29 classes → selected → found at `--text-figure`, then taken out: three of the four figures were constants, and 52px is a lot of page to spend on a number that cannot change. The rail states the catalog size in one line; the two live figures are in the result summary. |
| Severity key | **Removed.** Four bordered cards → four marks → gone. It was a legend, in 11px mono, for badges that are not on screen until a search returns — and when they are, each one carries its band as a word. |
| Workspace views | **New.** `data-view` is `browse` or `results`; the command bar exists only in the second. Four permanently-greyed controls above the fold read as a broken page rather than an early one. |
| Rail folding | **New.** Sources and Options fold, each keeping its current value on the heading. Seven sections open at once was ~1400px of scroll behind a 320px column, so the page opened mid-list with no visible beginning. |
| Result card | **Redesigned.** Became an entry: the severity edge runs the full height and is the only container. A triage queue is scanned down a column, and a box makes the eye re-enter at every row. |
| Entry badges | **Redesigned twice.** Once the entry lost its border, ~30 outline badges across six entries were the loudest texture on the surface; they became codes separated by hairlines. That left three rows of 11px grey between the title and the verdict — provenance, packages, ids — all at one rank, which is what made a column of entries unscannable. They are ranked now: a flag row that renders only when something exceptional applies, the package and its fix at `--text-sm` in full ink, and everything true of every row in the set demoted into one quiet receipts line below the verdict. |
| `Exploited (KEV)` | **Kept, and now alone.** The one filled badge on an entry, on the one fact most likely to change what the reader does next. |
| Severity badge | **Reworked.** Was a saturated fill duplicating the spine; now the word on a 16% tint of its own band, with text tokens that clear AA as ink rather than behind it. |
| AI verdict panel | **Redesigned.** A bordered box nested inside a borderless entry was the one place the rebuild contradicted itself. Same device as the entry: a coloured edge and space. |
| Onboarding panel | **Redesigned.** Removed. A border around the whole opening screen is a border around the page. |
| Class map entry | **Redesigned twice.** Twenty-nine equal boxes said these are twenty-nine equal things, so the box went and the CWE count became a length. Reversed: nobody picks a bug class by the size of its CWE set, so the comparison the track enabled is one no operator makes — and 29 tracks ending at 29 different x positions, under labels that wrap to one line or two, is most of why four tidy columns read as a jumble. The mono code went with it: `BAC` beside "Broken Access Control" is the API's spelling of the name already there. An entry is a name and a count, pushed to the two edges so a row's labels start on one line and its counts end on another. |
| Rail class list | **Folded.** It was the second printing of the taxonomy the workspace map already shows — 29 names and 7 family headings rendered twice over, with a five-line description under every label. It is the control that edits the map now, shut by default, and the one fold with no value on its heading: what is ticked is named directly above it as Query-target chips. |
| Status pills | **Reworked.** Mono was set on the whole pill, putting a monospace face on "Connected" and "cached"; the state words were shouted caps, and `AUTHED` was `gh auth status` vocabulary. |
| Status dots | **Reworked.** Filled vs ring, not red vs green alone — below 480px the word beside the dot is clipped, so hue was carrying the state by itself. |
| Result summary | **Reworked.** An empty CWE list rendered a stray `<code>` box; the active order is stated here now. |
| Search warnings | **Reworked.** Were error toasts, so a persistent statement about the results floated over the list and covered a card title. |
| Sort / direction | **Reworked.** "Newest first" was offered for every sort field, including ones with no age; and `risk` is the UI default now, because a queue ordered by publication date is not a triage queue. |
| Meta row links | **Reworked.** A 17px hit area on the two links that are the way out of this page. |
| Wordmark | **Kept.** A monogram and a name, with a subtitle that says what the product does in five words rather than a tagline. |
| `Test AI` | **Kept.** The one accent-filled control in the topbar, and it spends nothing — the "will this work before I pay" button. |
| Cache count | **Kept.** A number that changes under the reader's eye, so the digits are mono and do not shift width. |
| Theme toggle | **Kept.** An icon button with a label; no text competing at 320px. |
| Recent searches | **Kept.** Real state — queries that were actually run, with hit counts — not a canned preset list. |
| Bug-class finder | **Kept.** A combobox over 944 CWEs taking an id, a name or a community alias, and the hint says all three. |
| Selected chips | **Kept.** Each removable, and the count line states what the selection will cost before anything is spent. |
| Scope controls | **Kept.** Inputs and selects keep their edges: a field is a thing you type into and needs to look like one. |
| Run buttons | **Kept.** One filled control — the one that spends money — and a disabled action is grey, never a dimmed accent. |
| Toolbar actions | **Kept.** "Refine with AI" is the filled one; it is the control that spends. |
| Package range | **Kept.** `lodash → 4.17.21`: the arrow carries meaning, which is the brief's own exception to the appended-arrow tell. |
| EPSS meter | **Kept.** A quantity as a length beside the figure, and now the only one on the page: a percentile is a position in a distribution, which is what a length is for, where a CWE-set size was only ever a number that happened to be drawable. |
| Export popover | **Kept.** A `<details>` popover genuinely needs an edge: it floats over content. |
| Auth gate | **Kept.** A modal that traps focus and inerts the page, with one input and one action. |
| Toasts | **Kept.** Transient messages stay transient; only the persistent warnings moved into the flow. |
| Mobile slide-over | **Reworked.** Below 900px the rail becomes a panel from one button, at a breakpoint declared once and read from CSS by `app.js` — but the rule that made it a panel set position, z-index and a shadow and never a background, so it inherited the base rail's deliberate `background: none` and the drawer was transparent on every phone. `--rail-bg` had been declared in all four theme blocks and referenced nowhere; nothing looks at a colour token with no users, which is how it survived two design passes. |

Of 36 regions: 11 redesigned, 1 new, 7 reworked earlier in the review, and 17 kept.
The kept ones are mostly controls and overlays — the places where a border is doing real
work, and where the brief's advice to remove one accessory means leaving
the remaining ones alone.

### Tells, re-checked across the whole page

| Tell | Status |
|---|---|
| Cream `#F4F1EA` + serif display + terracotta accent | absent |
| Near-black + one acid accent | partly — the ground is near-black, the accent is a desaturated steel chosen to stay out of the four severity hues, and severity owns the chroma |
| Broadsheet: hairline rules, zero radius, dense columns | absent. The class field lost its borders but gained space and a measure, not rules |
| SaaS-card kit: one radius on everything, identical soft shadows | **was present, and the earlier self-review graded its way out of it by counting radii.** Four radii on one component at four sizes is still one component. The class field and the severity key are no longer cards; the result card stays, because it holds mixed content |
| ALL-CAPS eyebrow above every heading | one CSS rule, on severity badges, where the label is a band name. Capitals typed into markup escape that rule twice over: the status words did, and so did every qualifier on an advisory card -- `NO CWE · AI`, `WITHDRAWN 2024-09-20`, `KEV / EXPLOITED`, and a score reading `42% · CACHED · PARTIAL`. All sentence case now, and a test reads the rendered labels rather than the stylesheet |
| Meta strings joined with middle dots | **was present, and this row previously said otherwise while quoting the string that proved it.** The result summary was seven facts in one run of text -- count, order, two warnings, provenance, the CWE list and the cache state -- separated only by dots, so a warning read as a label and nothing could be skipped to. It is a sentence plus separate elements now. Five uses remain, all list separators inside one dense row rather than a meta string: three build a saved search's facets, two a CWE's aliases |
| `WORD — fragment` with a spaced em dash | used in prose, not as a label pattern |
| Tinted near-black standing in for black | absent |
| Monospace for small data labels | **was present in seven more places than this row claimed.** Fixing the status pills did not fix the taxonomy group headings ("Memory & concurrency"), the Clear and Retry buttons, the Filters button, the skip link or either half of a recent-search row. The sheet's own type note already forbade all of it; nothing checked. Twenty uses remain, each named in `tests/test_frontend_js.py::TestMonoMeansThisIsACode`, and adding one is now a decision about whether the thing is a code |
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

`python tools/design_audit.py --out shots/` drives Chromium across nineteen
states and fails on any of:

| | Viewport | Themes |
|---|---|---|
| `/` empty | 1440×900, 390×844, 320×844, 820×1180, 1920×1080 | light and dark |
| `/` with results | 1440×900, 390×844, 320×844 | light and dark |
| `/api/docs` | 1440×900, 390×844 | light and dark |
| Surfaces that float above the page | filter drawer 390×844, CWE finder 1440×900, toast 1440×900, recent searches 1440×900, auth gate 1440×900 | one each |

The figure here is checked against `design_audit.STATES`, so it cannot
drift the way "seven" did when the API page was added.

**The last row is the one that had never been looked at.** Fourteen states
all measured the page at rest. Five surfaces float above it, two of them on
translucent grounds, so what they composite onto is a property of the stack
rather than of any rule in the sheet — and none of it had been measured.
The filter drawer is the worst case: below 1180px it is the only way to
reach the controls, and its rules live solely inside a media query, so no
desktop state could have touched them either. The auth gate is what a
token-protected deployment shows an operator first.

Opening them needed care, and the first attempt was wrong in a way worth
recording. The recent-searches state waited for `.history-drop`, a button
that is present whether or not the panel is open — so it measured the
ordinary results page a second time, reported a clean pass, and the state
count went up without the coverage going up. Each opener now waits for a
selector the surface itself adds, and a failure to open is a reported
problem rather than a silent fallback to the page underneath. The auth gate
runs against its own server started with a token, because the UI raises it
on what the *server* said; flipping a flag in the page would have measured
a lookalike and skipped the focus trap, which is most of what there is to
measure about a modal. It reports two focus stops, which is the trap
holding.

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
