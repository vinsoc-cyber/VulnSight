"""Checks for the pass that took the chrome off the workspace.

The complaint behind this pass was that the page was hard to use and busy
to look at. Three things carried most of it: ~290px of masthead that never
changed and never left, four permanently-dead controls above the fold, and
a rail with seven sections open at once. The entries below put each defect
back -- not the absence of the fix, the bug itself -- and name the test
module that has to notice.

See tools/checks/__init__.py for the shape of an entry.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    # --- the two views ----------------------------------------------------
    (
        "the command bar is painted before anything has been searched for",
        # The page ships in the browse view and the rule is what keeps the
        # bar off it, so dropping the rule puts four dead controls back
        # above the fold exactly as they were.
        [("static/style.css",
          '.workspace[data-view="browse"] .result-command { display: none; }',
          '.workspace[data-view="browse"] .result-command { display: flex; }')],
        "test_ui_e2e",
    ),
    (
        "the view never switches, so the results arrive with no controls",
        [("static/app.js", "      setView('results');", "      ")],
        "test_ui_e2e",
    ),
    (
        "a query refused for having no source switches the page to results",
        # Hoisted above the two validation bail-outs: the bar then arrives
        # for a search that never ran, and stays for the session.
        [("static/app.js",
          "      if (!state.categories.length) { toast('Select a bug class or a CWE', 'err'); return false; }",
          "      setView('results');\n"
          "      if (!state.categories.length) { toast('Select a bug class or a CWE', 'err'); return false; }"),
         ("static/app.js", "      setView('results');\n      setResultsBusy(true);",
          "      setResultsBusy(true);")],
        "test_ui_e2e",
    ),

    # --- the folded rail sections ----------------------------------------
    (
        "a folded section hides the setting along with the controls",
        # The rail then states nothing about which sources a search will
        # use, which is the whole risk of folding them away.
        [("static/app.js", "    function renderFoldValues() {",
          "    function renderFoldValues() {\n      if (true) return;")],
        "test_ui_e2e",
    ),
    (
        "ticking a source leaves the folded heading describing the old query",
        [("static/app.js",
          "      updateNvdHint();\n      renderFoldValues();\n    }));",
          "      updateNvdHint();\n    }));")],
        "test_ui_e2e",
    ),
    (
        "replaying a saved search leaves the headings on the query it replaced",
        # applyState() writes .value and .checked directly, which fires no
        # change event, so without this call the rail describes the
        # previous query while running the restored one.
        [("static/app.js",
          "      renderSelection();\n      // Writing .value and .checked fires no change event",
          "      renderSelection();\n      if (true) return;\n"
          "      // Writing .value and .checked fires no change event")],
        "test_ui_e2e",
    ),

    # --- a token with no users ---------------------------------------------
    (
        "the phone filter drawer is transparent and the page reads through it",
        # The slide-over rule set position, z-index and a shadow and never a
        # background, so it inherited the base rail's deliberate
        # `background: none` -- correct for a desktop column sharing the
        # page's surface, and a see-through panel on every phone.
        [("static/style.css",
          "    background: var(--rail-bg);\n    box-shadow: var(--shadow);",
          "    box-shadow: var(--shadow);")],
        "test_ui_e2e",
    ),

    # --- the scale that outlived its user ---------------------------------
    (
        "a type step is declared with nothing on the page using it",
        [("static/style.css",
          "  --text-display: clamp(28px, 3.4vw, 40px);",
          "  --text-display: clamp(28px, 3.4vw, 40px);\n"
          "  --text-figure:  clamp(30px, 4.2vw, 52px);")],
        "test_frontend_js",
    ),
]

# Deliberately not a check here: "the audit measures a rail whose folded
# sections it never opened". There is no tests/test_design_audit.py -- the
# tool is the measuring instrument, not a thing the suite drives -- so no
# test module could go red and the battery would score it NOT CAUGHT. It is
# guarded in the tool instead: _open_overlay waits on a control *inside* a
# fold rather than on the heading, which is visible either way, so an
# expansion that stops working fails the audit at that state instead of
# quietly dropping every control in it from the counts.

