"""Checks for the redesign pass and the review that followed it.

Covers the defects an independent read of the rebuilt interface turned up
-- a block of rules swallowed by the media query above it, a badge wearing
a colour that means something else, labels shouted in capitals, a summary
that was one undifferentiated run of text -- plus the two measuring tools
that could report a clean pass over surfaces they had never opened, and
the stop signal that only half the system could withdraw.

See tools/checks/__init__.py for the shape of an entry.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    # --- rules that apply at some widths and not others ------------------
    (
        "the search warnings are swallowed by the media query above them",
        # Exactly the original bug: the block ends up inside
        # `@media (max-width: 1180px)`, so on every desktop the warnings
        # render as a bare <ul> with the browser's default disc.
        [("static/style.css",
          ".summary-order { color: var(--faint); }\n\n.search-warnings {",
          "@media (max-width: 1180px) {\n.summary-order { color: var(--faint); }\n\n"
          ".search-warnings {")],
        "test_frontend_js",
    ),

    # --- colour that means the wrong thing --------------------------------
    (
        "the KEV badge is painted in the HIGH severity colour",
        [("static/style.css",
          "  color: var(--kev-ink);\n  background: var(--kev);",
          "  color: var(--sev-ink);\n  background: var(--sev-high);")],
        "test_frontend_js",
    ),

    # --- shouted labels ---------------------------------------------------
    (
        "the KEV badge shouts its label",
        [("static/app.js",
          ">Exploited (KEV)</span>", ">KEV / EXPLOITED</span>")],
        "test_frontend_js",
    ),
    (
        "the withdrawn badge shouts its label",
        [("static/app.js",
          '>Withdrawn ${esc(String(a.withdrawn_at).slice(0,10))}</span>',
          '>WITHDRAWN ${esc(String(a.withdrawn_at).slice(0,10))}</span>')],
        "test_frontend_js",
    ),
    (
        "the no-CWE badge shouts its label",
        [("static/app.js", ">No CWE tag</span>", ">NO CWE · AI</span>")],
        "test_frontend_js",
    ),

    # --- the summary ------------------------------------------------------
    (
        "the result summary goes back to one string joined by middle dots",
        [("static/app.js",
          '`<p class="summary-facts">${unscoredNote}${capped}${psText}'
          '${cweText}${cachedText}</p>`',
          "` · ${unscoredNote} · ${capped} · ${psText} · ${cweText}"
          " · ${cachedText}`")],
        "test_frontend_js",
    ),

    # --- tools that could pass without measuring --------------------------
    (
        "the design audit never opens the surfaces that float above the page",
        [("tools/design_audit.py",
          '    ("15-filter-drawer", "", 390, 844, "dark", False, "drawer"),',
          '    # removed')],
        "test_frontend_js",
    ),
    (
        "the audit fixture stops at the advisory, so no verdict is measured",
        [("tools/design_audit.py",
          '        "ai": _sample_verdict(index),', "")],
        "test_frontend_js",
    ),

    # --- mono as texture on a label ---------------------------------------
    (
        "the taxonomy group headings go back to the monospace face",
        [("static/style.css",
          "  font: var(--weight-bold) var(--text-xs) var(--sans);\n"
          "  letter-spacing: .04em;\n}",
          "  font: 650 var(--text-xs) var(--mono);\n"
          "  letter-spacing: .08em;\n}")],
        "test_frontend_js",
    ),
    (
        "the skip link goes back to the monospace face",
        [("static/style.css",
          "  font: var(--weight-bold) var(--text-sm) var(--sans);",
          "  font: 700 var(--text-sm) var(--mono);")],
        "test_frontend_js",
    ),

    # --- the API reference, held to the same rules ------------------------
    (
        "the API reference shouts its section headings again",
        [("static/apidocs.css",
          "section h3 { margin: 24px 0 8px; font-size: var(--text-sm); font-weight: 650;\n"
          "             color: var(--muted); }",
          "section h3 { margin: 24px 0 8px; font-size: var(--text-sm); "
          "text-transform: uppercase;\n             color: var(--muted); }")],
        "test_frontend_js",
    ),

    # --- line length ------------------------------------------------------
    (
        "the AI's reasoning runs the full width of the card",
        [("static/style.css", ".desc {\n  max-width: 72ch;", ".desc {")],
        "test_frontend_js",
    ),
    (
        "nothing measures how long a line of prose is",
        [("tools/design_audit.py",
          'for row in data.get("prose", []) if row["chars"] > 85',
          'for row in data.get("prose", []) if row["chars"] > 100000')],
        "test_frontend_js",
    ),

    # --- the catalog's missing third of its entries -----------------------
    (
        "the generator asks for the element CWE 5.0 renamed",
        [("tools/generate_cwe_catalog.py",
          '    for path in ("c:Groupings/c:Grouping", "c:Categories/c:Category",\n'
          '                 "c:Views/c:View"):',
          '    for path in ("c:Categories/c:Category", "c:Views/c:View"):')],
        "test_generate_cwe_catalog",
    ),
    (
        "a catalog with no Groupings at all is written anyway",
        [("tools/generate_cwe_catalog.py",
          "    if len(weaknesses) >= 100 and found_non_weakness < 100:",
          "    if False:")],
        "test_generate_cwe_catalog",
    ),
    (
        "the shipped catalog goes back to Views only",
        [("modules/cwe_catalog.py", "'1035': ", "'99991035': ")],
        "test_generate_cwe_catalog",
    ),

    (
        "a state that measures the page twice is counted as coverage",
        [("tools/design_audit.py",
          "    base_by_shape = {state[1:6]: state[0] for state in states\n"
          "                     if len(state) == 6}",
          "    base_by_shape = {}")],
        "test_frontend_js",
    ),

    (
        "a revert that undoes one of three copies is scored as a full revert",
        [("tools/revert_checks.py",
          "        patched[path] = patched[path].replace(find, replace)",
          "        patched[path] = patched[path].replace(find, replace, 1)")],
        "test_cleanup_stays_clean",
    ),

    # --- the stop signal --------------------------------------------------
    (
        "a shutdown request can never be withdrawn by the inline search path",
        [("modules/jobs.py",
          "def resume() -> None:", "def _unused_resume() -> None:"),
         ("modules/jobs.py", "            resume()", "            pass")],
        "test_jobs",
    ),
]
