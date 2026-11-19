"""Checks for the pass that stopped the page saying everything twice.

The previous pass quietened the chrome and the complaint survived it: the
workspace was still busy to look at. Measuring the landing page said why.
All twenty-nine bug classes were painted twice -- once as the workspace
map, once as a rail list with a description under every label -- along with
fourteen family headings for seven families; 444 elements were painted, 200
of them carrying text and 188 of those at 13px or under; and 5542 of the
page's characters sat inside a 320px rail against 1415 in the workspace,
which has five times the width.

So the taxonomy is in one place, the rail list is the control that edits it
and ships shut, and a map entry says the two things an entry is for. The
entries below put each defect back -- the bug, not the absence of the fix --
and name the test module that has to notice.

See tools/checks/__init__.py for the shape of an entry.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    # --- one taxonomy, not two --------------------------------------------
    (
        "the rail prints the whole taxonomy a second time, at rest",
        # Shipping the fold open is the state this pass found: both copies
        # on screen at once, 29 names rendered twice over.
        [("templates/index.html",
          '<details class="field control-fold class-fold">',
          '<details class="field control-fold class-fold" open>')],
        "test_ui_e2e",
    ),
    (
        "the description block comes back under all twenty-nine labels",
        [("templates/index.html",
          "              <span class=\"cat-copy\">\n"
          "                <span class=\"c-label\">{{ c.label }}</span>\n"
          "              </span>",
          "              <span class=\"cat-copy\">\n"
          "                <span class=\"c-label\">{{ c.label }}</span>\n"
          "                <span class=\"c-desc\">{{ c.description }}</span>\n"
          "              </span>")],
        "test_ui_e2e",
    ),
    (
        "a class loses its description without gaining a title",
        # The half-done version of the fix: the five-line block goes and
        # nothing replaces it, so the description is reachable nowhere on
        # the page at all.
        [("templates/index.html", '\n                   title="{{ c.description }}">', ">")],
        "test_ui_e2e",
    ),
    (
        "the bug-class fold grows a value its own chips already say",
        [("templates/index.html",
          "              Bug classes <span class=\"hint\" id=\"class-count\">"
          "{{ categories|length }} available</span>\n"
          "            </span>",
          "              Bug classes <span class=\"hint\" id=\"class-count\">"
          "{{ categories|length }} available</span>\n"
          "            </span>\n"
          "            <span class=\"fold-value\" id=\"classes-value\">1 selected</span>")],
        "test_ui_e2e",
    ),

    # --- two facts per entry, not four ------------------------------------
    (
        "the mono code comes back to every map entry",
        [("static/app.js",
          '                <span class="map-label">${esc(c.label)}</span>',
          '                <span class="map-code">'
          '${esc(c.code || c.key.toUpperCase())}</span>\n'
          '                <span class="map-label">${esc(c.label)}</span>')],
        "test_frontend_js",
    ),
    (
        "the comparison bar comes back under every map entry",
        [("static/app.js",
          "                <span class=\"map-count\">${n} CWE${n === 1 ? '' : 's'}</span>",
          "                <span class=\"map-count\">${n} CWE${n === 1 ? '' : 's'}</span>\n"
          "                <span class=\"map-track\" aria-hidden=\"true\"><i></i></span>")],
        "test_frontend_js",
    ),
    (
        "a .map-* rule outlives the markup it styled",
        # Dead CSS is invisible by construction: the rule paints nothing,
        # so nothing looks wrong, and the next reader takes the selector
        # for a part that exists.
        [("static/style.css",
          ".map-count { color: var(--faint); font-size: var(--text-xs); }",
          ".map-count { color: var(--faint); font-size: var(--text-xs); }\n"
          ".map-code { color: var(--accent); }")],
        "test_frontend_js",
    ),

    # --- the rhythm the tracks used to break ------------------------------
    (
        "the map entry hangs its label and its count from one edge",
        [("static/style.css",
          "  align-content: space-between;",
          "  align-content: start;")],
        "test_ui_e2e",
    ),
]
