"""Revert checks for the CWE taxonomy and the browser code.

The taxonomy entries matter because a wrong class quietly changes what a
search returns -- nothing errors, the answer is just incomplete. The
frontend entries matter because `static/app.js` decides what the user
believes, and almost none of it is reachable from a Python unit test.

See tools/checks/__init__.py for the shape of an entry.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    (
        "the API page goes back to its own ad-hoc sizes",
        [("static/apidocs.css",
          "  font: var(--text-base)/1.6 ui-sans-serif",
          "  font: 15px/1.6 ui-sans-serif")],
        "test_frontend_js",
    ),
    (
        "the two stylesheets disagree about the scale",
        [("static/apidocs.css",
          "  --text-base: 14px;",
          "  --text-base: 15px;")],
        "test_frontend_js",
    ),
    # -- CWE taxonomy ------------------------------------------------------
    (
        "CWE-436 separated from its own child again",
        [("modules/cwe_categories.py",
          '        "extended": ["117", "436"],',
          '        "extended": ["117"],')],
        "test_cwe_categories",
    ),
    (
        "'acl' returns as a bare substring trap",
        [("modules/cwe_categories.py",
          '        "permission bypass", "acl bypass",',
          '        "permission bypass", "acl",')],
        "test_cwe_categories",
    ),
    (
        "junk short forms come back into the derived keywords",
        [("modules/cwe_categories.py",
          '_SUBSTRING_DECOYS = ("php", "soc", "alist", "css", "api", "url", "uri", "ssl")',
          '_SUBSTRING_DECOYS = ()')],
        "test_cwe_categories",
    ),
    (
        # The first attempt at this revert wrote `frozenset(set()) or
        # frozenset({...})`, which is falsy on the left and so evaluated to
        # the real set: the check reported a false gap because the edit
        # changed nothing. Remove the terms outright.
        "real short search terms are rejected as noise",
        [("modules/cwe_categories.py",
          '    "xss", "csrf", "ssrf", "xxe", "rce", "idor", "bola", "bfla", "sqli",\n'
          '    "ssti", "lfi", "rfi", "xpath", "ldap", "dos", "prng", "toctou", "uaf",\n'
          '    "smtp", "crlf", "http", "json", "yaml", "xml", "jwt", "cors", "redos",\n',
          "")],
        "test_cwe_categories",
    ),

    # -- static/app.js -----------------------------------------------------
    (
        "the type scale goes back to hard-coded sizes",
        [("static/style.css",
          "  font-size: var(--text-lg);\n  font-weight: 750;",
          "  font-size: 16px;\n  font-weight: 750;")],
        "test_frontend_js",
    ),
    (
        "a declared type token stops being used",
        [("static/style.css",
          "  --text-xl:      22px;     /* section and dialog headings */",
          "  --text-xl:      22px;     /* section and dialog headings */\n"
          "  --text-unused:  18px;     /* nothing references this */")],
        "test_frontend_js",
    ),
    (
        "two spellings of the same pill radius come back",
        [("static/style.css",
          "  border-radius: var(--radius-pill);\n"
          "  font: 650 var(--text-xs)/1 var(--mono);",
          "  border-radius: 99px;\n"
          "  font: 650 var(--text-xs)/1 var(--mono);")],
        "test_frontend_js",
    ),
    (
        "safeAttr throws on a non-string again",
        [("static/app.js",
          "    const safeAttr = esc;",
          "    const safeAttr = s => s.replace(/[&<>\"']/g, c => "
          "({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));")],
        "test_frontend_js",
    ),
    (
        "esc stops coercing its argument",
        [("static/app.js",
          "      return String(s || '').replace(/[&<>\"']/g,",
          "      return (s || '').replace(/[&<>\"']/g,")],
        "test_frontend_js",
    ),
    (
        "Enter commits an option nothing highlighted",
        [("static/app.js",
          "      if (comboMatches.length && comboActive < 0) comboActive = 0;",
          "")],
        "test_ui_e2e",
    ),
    (
        "an empty listbox row stops being presentational",
        [("static/app.js",
          '        list.innerHTML = `<li class="combo-empty" role="presentation">`',
          '        list.innerHTML = `<li class="combo-empty">`')],
        "test_ui_e2e",
    ),
    (
        "toasts stop sharing one live region",
        [("static/app.js",
          "        region.setAttribute('role', 'region');\n"
          "        region.setAttribute('aria-label', 'Notifications');",
          "")],
        "test_ui_e2e",
    ),
]
