# Design

The design plan this interface is built to, the reasoning behind each choice,
and the measurements that check it. Written so the next person can disagree
with a decision on its merits rather than guess at the intent.

Numbers quoted here are produced by `python tools/design_audit.py`, which
drives a real browser across seven viewport/theme states. `tests/test_docs.py`
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

`--ok` green is reserved for a confirmed AI match and used nowhere else,
which is why `--sev-low` is a steel blue rather than the green it once
shared.

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

## Layout

A fixed command surface on the left, a reading surface on the right. The
rail is where you *build* a query; the workspace is where you *read* the
answer. Nothing that changes the query lives in the workspace, and nothing
that reports results lives in the rail.

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │ VS  VulnSight        ●GH AUTHED ●AI READY [Test AI] (1059)  ◐          │  topbar, sticky
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

`python tools/design_audit.py --out shots/` drives Chromium across seven
states (desktop/mobile/narrow/tablet/wide × light/dark) and fails on any of:

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
