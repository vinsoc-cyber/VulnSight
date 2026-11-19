"""Run the Node-based frontend tests as part of the normal pytest suite.

The `tests/*.js` files exercise pure helpers lifted straight out of
`static/app.js` (CSV escaping, history sanitisation, …). They used to be
runnable only by hand, so regressions in them went unnoticed.
"""

import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(os.path.dirname(TESTS_DIR), "static")
NODE = shutil.which("node") or ""


@unittest.skipUnless(NODE, "node is not installed")
class TestFrontendJavaScript(unittest.TestCase):
    def test_every_js_test_file_passes(self):
        scripts = sorted(
            name for name in os.listdir(TESTS_DIR)
            if name.startswith("test_") and name.endswith(".js")
        )
        self.assertTrue(scripts, "expected at least one tests/test_*.js file")
        for script in scripts:
            with self.subTest(script=script):
                proc = subprocess.run(
                    [NODE, os.path.join(TESTS_DIR, script)],
                    capture_output=True, text=True, timeout=120,
                )
                self.assertEqual(
                    proc.returncode, 0,
                    msg=f"{script} failed:\n{proc.stdout}\n{proc.stderr}",
                )

    STYLESHEETS = ("style.css", "apidocs.css")

    def _stylesheet(self, name="style.css"):
        with open(os.path.join(STATIC_DIR, name), encoding="utf-8") as fh:
            return fh.read()

    def test_the_shipped_javascript_parses(self):
        """`node --check` is the one syntax check this file has: nothing
        compiles it, and the helper tests read it as text, so a broken
        brace reaches the browser and the suite stays green."""
        for name in ("app.js",):
            with self.subTest(file=name):
                proc = subprocess.run(
                    [NODE, "--check", os.path.join(STATIC_DIR, name)],
                    capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(proc.returncode, 0,
                                 msg=f"{name} does not parse:\n{proc.stderr}")

    def test_app_js_keeps_everything_in_one_scope(self):
        """The file had no wrapper: ~79 functions and all of its state were
        true globals, indented four spaces as a leftover from living inside
        a <script> tag. `let AI = {}` collided with the browser's own `AI`.
        TestNothingLeaksToTheWindow in tests/test_ui_e2e.py proves nothing
        leaks in a real page; this one fails fast, without a browser."""
        with open(os.path.join(STATIC_DIR, "app.js"), encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("(function () {", source, "app.js lost its scope wrapper")
        self.assertIn("'use strict';", source)
        self.assertTrue(source.rstrip().endswith("})();"),
                        "the scope wrapper is not closed at the end of the file")

    def test_no_stylesheet_sets_a_size_by_hand(self):
        """Both sheets, not just the app's. apidocs.css carried seven
        hard-coded sizes and zero tokens, so the design system covered one
        of the product's two pages -- and the second one was exactly the
        page an integrator reads before writing a client."""
        for name in self.STYLESHEETS:
            with self.subTest(sheet=name):
                css = self._stylesheet(name)
                # Every px inside a font-size, including the ones wrapped
                # in clamp()/calc(): `font-size: clamp(22px, 2.4vw, 30px)`
                # is three hard-coded sizes, and the first version of this
                # test only looked for a px immediately after the colon.
                sizes = {px for decl in re.findall(r"font-size:\s*([^;}]+)[;}]", css)
                         for px in re.findall(r"([\d.]+)px", decl)}
                sizes |= set(re.findall(r"font:[^;]*?\b([\d.]+)px(?=[/ ])", css))
                self.assertEqual(sizes, set(),
                                 f"{name} sets sizes outside the scale: {sorted(sizes)}")

    def test_the_global_hidden_rule_is_present(self):
        """Every [hidden] in this app is hidden by one declaration. The UA
        stylesheet's own `[hidden] { display: none }` loses to any rule with
        a class selector, and several components set display: .combo-list is
        flex, .auth-gate is flex, .cat is grid. Without this rule the CWE
        popup stays painted with hidden=true on it, and the auth scrim
        covers the whole app permanently.

        No test referenced it, and the browser assertions that would have
        noticed were reading el.hidden -- the attribute, which is true
        either way. They read computed display now; this is the cheap
        guard that fails in milliseconds instead of minutes."""
        css = self._stylesheet()
        self.assertRegex(
            css, r"\[hidden\]\s*\{[^}]*display:\s*none\s*!important",
            "the global [hidden] rule is gone; components that set display "
            "will stay painted when hidden")

    def test_both_stylesheets_agree_on_the_scale(self):
        """Restating the tokens is fine -- apidocs.css is standalone on
        purpose -- but the values have to match, or "one scale" is a claim
        rather than a fact."""
        def steps(css):
            return dict(re.findall(
                r"--text-(xs|sm|base|lg|xl):\s*([\d.]+px)", css))
        app, api = (steps(self._stylesheet(n)) for n in self.STYLESHEETS)
        self.assertTrue(api, "apidocs.css declares no scale")
        for step, value in api.items():
            self.assertEqual(value, app.get(step),
                             f"--text-{step} differs between the two sheets")

    def test_the_stylesheet_sets_no_size_or_radius_by_hand(self):
        """The sheet declared nine type tokens, referenced three, and then
        set 14 hard-coded font sizes -- ten of which landed inside a 6px
        band. A scale that nothing uses is worse than no scale: it reads as
        intentional while the page is ad hoc. Same story for radius, which
        had five tokens, two references, and both `99px` and `999px` for
        the same pill. Tokens or nothing."""
        css = self._stylesheet()
        sizes = set(re.findall(r"font-size:\s*([\d.]+px)", css))
        sizes |= set(re.findall(r"font:[^;]*?\b([\d.]+px)(?=[/ ])", css))
        self.assertEqual(sizes, set(),
                         f"hard-coded font sizes outside the scale: {sorted(sizes)}")

        # `[^;}]+[;}]`: the last declaration in a block may carry no
        # semicolon -- legal CSS that this stylelint config allows -- and the
        # `;`-only form missed exactly that position, which is where a stray
        # `border-radius: 999px` would sit.
        radii = {v.strip() for v in
                 re.findall(r"border-radius:\s*([^;}]+)[;}]", css)}
        # 0 and 50% are not steps on a scale: one is "no corner", the other
        # is "a circle", and neither has a smaller or larger sibling.
        radii -= {"0", "50%"}
        raw = {r for r in radii if not r.startswith("var(")}
        self.assertEqual(raw, set(), f"hard-coded radii: {sorted(raw)}")

    def test_every_declared_type_token_is_used(self):
        """The other half of the same defect: six of the nine declared type
        tokens were dead. A token nobody references is a decision nobody
        made."""
        css = self._stylesheet()
        declared = set(re.findall(r"--text-([\w-]+):", css))
        used = set(re.findall(r"var\(--text-([\w-]+)\)", css))
        self.assertEqual(declared - used, set(),
                         f"declared type tokens nobody uses: "
                         f"{sorted(declared - used)}")

    def test_the_type_scale_has_distinct_steps(self):
        """Ten sizes inside a 6px band is not a hierarchy. Each step must be
        far enough from the last to read as a different rank."""
        css = self._stylesheet()
        steps = [float(px) for px in
                 re.findall(r"--text-(?:xs|sm|base|lg|xl):\s*([\d.]+)px", css)]
        self.assertGreaterEqual(len(steps), 5, "the scale lost steps")
        steps.sort()
        for smaller, larger in zip(steps, steps[1:]):
            self.assertGreaterEqual(
                larger / smaller, 1.10,
                f"{smaller}px and {larger}px are too close to read as ranks")


class TestTheStatusPillStaysReadable(unittest.TestCase):
    """The two pills in the topbar say whether GitHub and the AI endpoint are
    reachable. Nothing else on the page answers that, and the answer decides
    whether a search returns anything and whether a classify run can spend
    money -- so it has to survive a narrow viewport, a screen reader and a
    reader who cannot separate red from green.

    All three had been broken in the same small block of CSS."""

    def _sheet(self):
        with open(os.path.join(STATIC_DIR, "style.css"), encoding="utf-8") as fh:
            return fh.read()

    def test_the_state_word_is_never_removed_from_the_accessibility_tree(self):
        """`.pill-value { display: none }` at 480px took the word out of the
        a11y tree as well as off the screen, so between 461 and 480px the
        pill announced "GH" and showed a bare coloured dot."""
        css = self._sheet()
        for match in re.finditer(r"\.pill-value\s*\{([^}]*)\}", css):
            with self.subTest(rule=match.group(0)[:40]):
                self.assertNotRegex(
                    match.group(1), r"display:\s*none",
                    "clip .pill-value instead; display:none unannounces it")

    def test_an_unreachable_source_differs_by_shape_and_not_only_by_colour(self):
        """Both dots were filled circles separated by hue alone."""
        css = self._sheet()
        ok = re.search(r"\.dot\.ok\s*\{([^}]*)\}", css)
        bad = re.search(r"\.dot\.bad\s*\{([^}]*)\}", css)
        self.assertIsNotNone(ok, "no .dot.ok rule")
        self.assertIsNotNone(bad, "no .dot.bad rule")
        assert ok is not None and bad is not None
        # `border: 0` is not a ring, and `\d` matched it: the revert check
        # for this rule reported NOT CAUGHT until the width was required.
        self.assertRegex(bad.group(1), r"border:\s*[1-9]\d*px",
                         "the unreachable dot is a ring, not a second colour")
        self.assertRegex(bad.group(1), r"background:\s*none",
                         "a ring with a fill is still just a coloured dot")
        self.assertNotRegex(ok.group(1), r"border:\s*[1-9]\d*px",
                            "the reachable dot is filled, so the two differ")

    def test_mono_is_not_used_as_texture_on_the_pill(self):
        """`--mono` means "this is a code". The pill set it on the whole
        wrapper, which put a monospace face on "Connected" and "cached" --
        the one use of mono the stylesheet's own header forbids."""
        css = self._sheet()
        pill = re.search(r"\n\.pill\s*\{([^}]*)\}", css)
        self.assertIsNotNone(pill, "no .pill rule")
        assert pill is not None
        self.assertNotIn("var(--mono)", pill.group(1))
        for selector in (".pill-key", ".cache-count"):
            with self.subTest(selector=selector):
                rule = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css)
                self.assertIsNotNone(rule, f"no {selector} rule")
                assert rule is not None
                self.assertIn("var(--mono)", rule.group(1))

    def test_the_sheet_keeps_exactly_one_uppercase_rule(self):
        """docs/design.md claims one, on severity badges, where the label is
        a code -- and the claim was about CSS, so it stayed true while the
        status words were typed in capitals in the template instead."""
        rules = re.findall(r"text-transform:\s*uppercase", self._sheet())
        self.assertEqual(len(rules), 1, "design.md documents exactly one")

    def test_the_api_page_is_held_to_the_same_rule(self):
        """It was not. This test read style.css only, so while the main page
        was taken down to one uppercase rule the API reference kept three --
        an all-caps eyebrow over every section ("REQUEST BODY"), shouted
        column headers ("FIELD TYPE NOTES") and a REQUIRED flag. It is a
        second stylesheet, which is exactly why nothing noticed: the page an
        integrator reads was the one surface the redesign never reached."""
        with open(os.path.join(STATIC_DIR, "apidocs.css"), encoding="utf-8") as fh:
            rules = re.findall(r"text-transform:\s*uppercase", fh.read())
        self.assertEqual(
            rules, [],
            "the API page shouts its labels; the main page stopped doing "
            "that and these two are one interface")

    def test_the_status_words_are_sentence_case_and_say_what_a_user_sees(self):
        """They read AUTHED / OFFLINE / READY / OFF: shouted, and the first
        of them is `gh auth status` vocabulary rather than anything a user
        of this page would say."""
        template = os.path.join(os.path.dirname(STATIC_DIR), "templates",
                                "index.html")
        with open(template, encoding="utf-8") as fh:
            markup = fh.read()
        values = re.findall(
            r'class="pill-value">\{\{(.+?)\}\}</span>', markup)
        self.assertEqual(len(values), 2, "expected the GH and AI pills")
        for expression in values:
            for word in re.findall(r"'([^']+)'", expression):
                with self.subTest(word=word):
                    self.assertRegex(
                        word, r"^[A-Z][a-z]+(?: [a-z]+)*$",
                        "status words are sentence case, not shouted")
                    self.assertNotIn("auth", word.lower(),
                                     "say what the user sees, not what gh calls it")


class TestNoBaseRuleIsTrappedInAMediaQuery(unittest.TestCase):
    """A rule that exists *only* inside `@media` styles the page at some
    widths and not others.

    `.search-warnings`, `.search-warnings li` and `.summary-order` spent a
    while inside `@media (max-width: 1180px)`, because the edit that moved
    them anchored on `.result-command {` and matched the copy *inside* that
    block rather than the base rule. Above 1180px -- every desktop -- the
    search warnings rendered as a bare <ul> with the browser's default
    disc: a raw list bullet on a page with no other bullets, on the one
    surface the operator looks at all session. No test noticed, because
    every other test asks the stylesheet whether a rule exists, and it did.

    So this asks a different question: which selectors have no base rule at
    all? The answer is a short, deliberate list -- the mobile filter
    drawer, the coarse-pointer hit expanders, the keyframe steps and the
    dark-mode block. Anything else appearing here means a base rule was
    swallowed by the media query above it."""

    # Selectors that are *meant* to exist only inside a media query, each
    # with the query that owns them. Adding to this list is a design
    # decision: it declares that the page is deliberately unstyled in that
    # respect at every other width.
    MEDIA_ONLY = {
        # The filter rail becomes a drawer below 1180px; none of this
        # chrome exists on a desktop, where the rail is always open.
        ".filters-open",
        ".filters-open .control-rail",
        ".filters-open .filter-scrim",
        ".filter-icon",
        ".filter-icon::after",
        # The toolbar is a flex row on a desktop, where the primary
        # action needs no span; below 480px it becomes a two-column grid
        # and the primary takes the full measure.
        ".toolbar-actions > button.ai",
        # Dropped from the narrow topbar for room.
        ".cache-pill",
        ".system-status > .pill:not(.pill-action)",
        # WCAG 2.5.5 hit expanders, scoped to (pointer: coarse) so the
        # desktop keeps its compact chrome.
        "button.pill",
        ".combo-clear::after",
        ".chip-x::after",
        ".verdict-retry::after",
        # @keyframes steps and the dark-mode token block.
        "from",
        "to",
        ':root:not([data-theme="light"])',
    }

    def test_every_other_selector_has_a_rule_at_every_width(self):
        with open(os.path.join(STATIC_DIR, "style.css"), encoding="utf-8") as fh:
            css = fh.read()
        # Comments hold braces and selector text -- including, in this very
        # stylesheet, the sentence explaining this bug. Strip them first or
        # the parse below reads the explanation as code.
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)

        base: set[str] = set()
        nested: set[str] = set()
        depth = 0
        buf = ""
        for char in css:
            if char == "{":
                selector = buf.strip()
                if not selector.startswith("@"):
                    for part in selector.split(","):
                        part = part.strip()
                        if part:
                            (base if depth == 0 else nested).add(part)
                depth += 1
                buf = ""
            elif char == "}":
                depth = max(0, depth - 1)
                buf = ""
            elif char == ";":
                buf = ""
            else:
                buf += char

        self.assertEqual(depth, 0, "unbalanced braces in style.css")
        self.assertGreater(len(base), 250, "the parse found almost no rules")

        trapped = sorted(nested - base - self.MEDIA_ONLY)
        self.assertEqual(
            trapped, [],
            "these selectors are styled at some widths and not others; "
            "move the base rule out of the media query, or add it to "
            f"MEDIA_ONLY and say why: {trapped}")

        # The allowlist is an assertion too: a selector that no longer
        # needs the exemption should lose it, or it stops meaning anything.
        stale = sorted(self.MEDIA_ONLY - nested)
        self.assertEqual(stale, [],
                         f"MEDIA_ONLY lists selectors that are gone: {stale}")

    def test_the_search_warnings_are_styled_on_a_desktop(self):
        """The specific regression, named, so the failure says what broke."""
        with open(os.path.join(STATIC_DIR, "style.css"), encoding="utf-8") as fh:
            css = re.sub(r"/\*.*?\*/", "", fh.read(), flags=re.S)
        for selector in (".search-warnings", ".search-warnings li",
                         ".summary-order"):
            with self.subTest(selector=selector):
                index = css.find(selector + " ")
                self.assertNotEqual(index, -1, f"no {selector} rule at all")
                depth = css.count("{", 0, index) - css.count("}", 0, index)
                self.assertEqual(
                    depth, 0,
                    f"{selector} is nested {depth} level(s) deep, so the "
                    "warnings are unstyled outside that query")


class TestTheCardSaysThingsInWords(unittest.TestCase):
    """Every qualifier on an advisory card was shouted in capitals --
    `NO CWE · AI`, `WITHDRAWN 2024-09-20`, `KEV / EXPLOITED`, and a score
    that read `42% · CACHED · PARTIAL`.

    The stylesheet is already disciplined about this: it carries exactly
    one `text-transform: uppercase`, on the severity badge, where the word
    is a band name. These were literal capitals typed into the template
    strings, so that rule never saw them and no test did either -- the same
    loophole that let the status pills ship reading AUTHED / OFFLINE."""

    def _js(self):
        with open(os.path.join(STATIC_DIR, "app.js"), encoding="utf-8") as fh:
            return fh.read()

    # Acronyms are not shouting: GHSA and CWE have no lowercase form.
    ACRONYMS = {"GHSA", "NVD", "OSV", "EPSS", "AI", "CWE", "CVE", "KEV",
                "CVSS", "API", "CSV", "JSON", "ID", "URL"}

    def _words(self, text):
        return [w for w in re.findall(r"\b[A-Z][A-Z0-9]+\b", text)
                if w not in self.ACRONYMS]

    def test_the_badge_labels_are_not_shouted(self):
        js = self._js()
        for cls in ("badge--native", "badge--withdrawn", "badge--kev"):
            with self.subTest(badge=cls):
                rule = re.search(
                    re.escape(cls) + r'"[^>]*>(.*?)</span>', js, re.S)
                self.assertIsNotNone(rule, f"no {cls} badge is rendered")
                assert rule is not None
                label = re.sub(r"\$\{[^{}]*\}", "", rule.group(1))
                self.assertEqual(
                    self._words(label), [],
                    f"{cls} shouts: {label.strip()!r}")

    def test_the_score_qualifiers_are_words_beside_the_figure(self):
        """They were glued to the percentage with middle dots and set in
        the monospace face this sheet reserves for codes, so "cached" read
        as part of the number."""
        js = self._js()
        self.assertNotIn("' · CACHED'", js)
        self.assertNotIn("' · PARTIAL'", js)
        self.assertIn("verdict-note", js,
                      "the qualifiers are their own elements now")

    def test_kev_is_not_painted_in_a_severity_colour(self):
        """`--sev-high` filled the KEV badge, so on a CRITICAL row the
        loudest thing on the card was orange -- the hue the ramp reserves
        for the band below. "Being exploited" is not a fifth severity."""
        with open(os.path.join(STATIC_DIR, "style.css"), encoding="utf-8") as fh:
            css = re.sub(r"/\*.*?\*/", "", fh.read(), flags=re.S)
        rule = re.search(r"\.badge--kev\s*\{([^}]*)\}", css)
        self.assertIsNotNone(rule, "no .badge--kev rule")
        assert rule is not None
        self.assertNotRegex(
            rule.group(1), r"var\(--sev-",
            "KEV is wearing a severity colour; it is a different axis")

    def test_the_summary_is_not_one_string_joined_by_middle_dots(self):
        """Seven facts -- count, order, two warnings, provenance, the CWE
        list and the cache state -- arrived as a single run of text with
        " · " between them, so there was no way to skip to the one that
        mattered, and a warning looked like a label."""
        js = self._js()
        summary = re.search(r"function renderSummary\b.*?\n    \}", js, re.S)
        self.assertIsNotNone(summary, "renderSummary is gone")
        assert summary is not None
        self.assertNotIn(" · ", summary.group(0),
                         "the facts are separate elements, not a dot chain")
        self.assertIn("summary-facts", summary.group(0))


class TestTheAuditLooksAtTheSurfacesPeopleUse(unittest.TestCase):
    """tools/design_audit.py measured fourteen states, every one of them
    the page at rest. Four surfaces that float above it -- the filter
    drawer, the CWE list, a toast and the auth gate -- plus the recent
    searches panel were never opened, so nothing had ever checked what
    they composite onto. The drawer is the worst of those: below 1180px it
    is the only way to reach the controls, and its rules live solely
    inside a media query, so no state could reach them."""

    def _audit(self):
        root = os.path.dirname(STATIC_DIR)
        sys.path.insert(0, root)
        import importlib
        return importlib.import_module("tools.design_audit")

    def test_every_floating_surface_has_a_state(self):
        audit = self._audit()
        covered = {s[6] for s in audit.STATES if len(s) > 6}
        self.assertEqual(
            covered, set(audit.OVERLAYS),
            "an opener exists that no state uses, or the reverse")
        for wanted in ("drawer", "combo", "toast", "gate", "history"):
            with self.subTest(surface=wanted):
                self.assertIn(wanted, covered)

    def test_a_state_that_measures_nothing_new_is_reported(self):
        """The first recent-searches state waited on a button that is
        always present, so it measured the results page element for
        element -- 223 text nodes, 74 targets -- and reported a clean pass
        for a surface nobody had opened. Waiting for a *visible* selector
        is not enough, because the selector was visible.

        Exercised rather than grepped for: an earlier version of this test
        asserted the string "base_by_shape" appeared in the source, which
        a revert to `base_by_shape = {}` satisfied while making the guard
        inert -- the revert check correctly reported NOT CAUGHT."""
        audit = self._audit()
        states = [
            ("base", "", 1440, 900, "light", False),
            ("overlay", "", 1440, 900, "light", False, "combo"),
        ]
        same = {"text": [0] * 7, "targets": [0] * 3}

        identical = audit.duplicate_states(
            {"base": same, "overlay": dict(same)}, states)
        self.assertEqual(len(identical), 1,
                         "a state measuring the page twice was not reported")
        self.assertIn("overlay", identical[0])
        self.assertIn("base", identical[0])

    def test_a_state_that_adds_elements_is_accepted(self):
        audit = self._audit()
        states = [
            ("base", "", 1440, 900, "light", False),
            ("overlay", "", 1440, 900, "light", False, "combo"),
        ]
        report = {"base": {"text": [0] * 7, "targets": [0] * 3},
                  "overlay": {"text": [0] * 9, "targets": [0] * 4}}
        self.assertEqual(audit.duplicate_states(report, states), [])

    def test_a_state_with_no_comparable_base_is_left_alone(self):
        """The drawer runs at 390px and the combo at 1440: comparing an
        overlay against a base of a different shape would report every
        state as suspicious and the check would be turned off."""
        audit = self._audit()
        states = [
            ("base", "", 1440, 900, "light", False),
            ("overlay", "", 390, 844, "dark", False, "drawer"),
        ]
        same = {"text": [0] * 7, "targets": [0] * 3}
        self.assertEqual(
            audit.duplicate_states({"base": same, "overlay": dict(same)},
                                   states), [])

    def test_a_populated_card_carries_a_verdict(self):
        """The fixture stopped at the advisory, so the verdict block --
        half the height of a scored card -- was never measured."""
        audit = self._audit()
        self.assertIn("ai", audit._sample_advisory(0),
                      "no AI verdict on the sample advisory")
        classes = {bool(audit._sample_verdict(i)["is_match"]) for i in range(4)}
        self.assertEqual(classes, {True, False},
                         "the sample verdicts are all one class")


class TestTheMapEntrySaysTwoThings(unittest.TestCase):
    """A class-map entry carries a name and a CWE count. Nothing else.

    It carried four. A mono code in a left gutter -- BAC, CSRF, SSTI --
    spelt the name beside it a second time in the API's internal spelling,
    and a 2px track encoded, as a length, the count printed directly above
    it. Both were argued for in this repo, and both are reversed: the
    comparison the bar enabled is one nobody makes, because you pick the
    bug you are hunting rather than the class with the widest CWE set, and
    29 tracks ending at 29 different x positions under labels that wrap to
    one line or two is most of why four tidy columns read as a jumble.

    The arguments are still in the sheet, marked reversed. This is what
    stops the parts coming back by accident: they are named here, so
    adding one is a decision rather than a diff."""

    STRUCTURE = ["map-group", "map-group-name", "map-grid", "map-class"]
    ENTRY = ["map-label", "map-count"]

    @staticmethod
    def _read(name):
        with open(os.path.join(STATIC_DIR, name), encoding="utf-8") as fh:
            return fh.read()

    def test_the_renderer_emits_exactly_these_parts(self):
        js = self._read("app.js")
        block = js[js.index("function renderClassMap"):
                   js.index("function renderSelection")]
        found = re.findall(r'class="(map-[a-z-]+)', block)
        self.assertEqual(
            found, self.STRUCTURE + self.ENTRY,
            "renderClassMap emits a part this test does not know about, or "
            "has stopped emitting one it does")

    def test_the_sheet_has_no_rule_for_a_part_that_is_gone(self):
        css = re.sub(r"/\*.*?\*/", "", self._read("style.css"), flags=re.S)
        styled = set(re.findall(r"\.(map-[a-z-]+)", css))
        emitted = set(self.STRUCTURE + self.ENTRY)
        self.assertEqual(
            sorted(styled - emitted), [],
            "a .map-* rule outlived the markup it styled")
        # One direction only: .map-group is the grid item the container's
        # own gap spaces, so it carries no rule and needs none. A part that
        # paints text is a different matter -- an unstyled one would fall
        # back to the browser's 16px serif in the middle of the picker.
        self.assertEqual(
            sorted(set(self.ENTRY) - styled), [],
            "an entry part is rendered with no rule at all")

    def test_the_removed_parts_are_gone_from_every_file(self):
        template = os.path.join(os.path.dirname(STATIC_DIR),
                                "templates", "index.html")
        with open(template, encoding="utf-8") as fh:
            files = {"index.html": fh.read()}
        files["app.js"] = self._read("app.js")
        files["style.css"] = self._read("style.css")
        for name, text in files.items():
            stripped = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
            stripped = re.sub(r"<!--.*?-->", "", stripped, flags=re.S)
            for part in ("map-code", "map-track"):
                with self.subTest(file=name, part=part):
                    self.assertNotIn(part, stripped)


class TestMonoMeansThisIsACode(unittest.TestCase):
    """The type note at the top of style.css says the monospace face is
    "used for CWE/CVE ids, CVSS vectors and EPSS figures because those are
    codes where column alignment genuinely matters, never as texture on a
    label".

    The sheet then broke its own rule in seven places: the taxonomy group
    headings ("Memory & concurrency"), the Clear button, the skip link
    ("Skip to advisory results"), the Retry button, the Filters button and
    both halves of a recent-search row ("4 hours ago"). A written rule
    that nothing checks is a comment, so this is the check: every use is
    named, and adding one is a decision about whether the thing is a code.
    """

    # Each entry is a claim that what this selector renders is an id, a
    # figure, or a mark -- never prose and never a verb.
    MONO = {
        ".logo": "the VS wordmark",
        ".badge": "advisory, CVE and CWE ids",
        ".meta": "the id / date / CVSS / EPSS row",
        ".code": "inline code", "code": "inline code",
        "kbd": "keyboard keys, where mono is the convention",
        ".source-code": "GHSA / NVD / OSV",
        ".chip-code": "the class code on a chip",
        ".combo-code": "a CWE id in the finder",
        ".combo-in": "the code of the class that already covers it",
        ".combo-note": "a CWE count, or the abstraction level",
        ".combo-option.picked::after": "a tick glyph",
        ".pill-key": "GH / AI",
        ".cache-count": "a count",
        ".section-note": "the CWE catalog release, e.g. CWE 5.0",
        ".history-count": "a hit count",
        ".history-matches": "a confirmed-match count",
        ".verdict-score": "a confidence percentage",
    }

    def test_every_monospace_rule_is_one_of_these(self):
        with open(os.path.join(STATIC_DIR, "style.css"), encoding="utf-8") as fh:
            css = re.sub(r"/\*.*?\*/", "", fh.read(), flags=re.S)

        stack: list[str] = []
        buf = ""
        used: set[str] = set()
        for char in css:
            if char == "{":
                stack.append(buf.strip())
                buf = ""
            elif char == "}":
                if stack:
                    stack.pop()
                buf = ""
            elif char == ";":
                if "var(--mono)" in buf and stack:
                    used.add(stack[-1])
                buf = ""
            else:
                buf += char

        self.assertTrue(used, "the parse found no monospace rules at all")
        unlisted = sorted(used - set(self.MONO))
        self.assertEqual(
            unlisted, [],
            "these set the monospace face without saying why; if what they "
            "render is an id or a figure add them to MONO with the reason, "
            f"and if it is a label use --sans: {unlisted}")

    def test_the_list_does_not_outlive_the_rules(self):
        """An allowlist nobody prunes stops being an assertion."""
        with open(os.path.join(STATIC_DIR, "style.css"), encoding="utf-8") as fh:
            css = re.sub(r"/\*.*?\*/", "", fh.read(), flags=re.S)
        stale = sorted(sel for sel in self.MONO
                       if sel not in ("code", ".code") and sel not in css)
        self.assertEqual(stale, [], f"MONO lists selectors that are gone: {stale}")


class TestProseHasAMeasure(unittest.TestCase):
    """The AI's reasoning is the one block on this page that has to be read
    closely rather than scanned -- it is what an operator weighs before
    deciding an advisory matters. It ran the full width of the card: 150
    characters a line at 1440px and 186 at 1920, against the 45-80 a reader
    can track without losing the return sweep. The API reference's endpoint
    prose ran 145.

    The cap is in `ch`, which is the width of a zero -- far wider than the
    average glyph in a proportional face -- so the stylesheet alone cannot
    tell you what you got. `tools/design_audit.py` measures the rendered
    line from each element's own font at every state and fails over 85;
    this only guards the caps and the gate from being removed."""

    def test_every_prose_block_declares_a_measure(self):
        checked = 0
        for sheet, selectors in (("style.css", (".desc",)),
                                 ("apidocs.css", (".desc", ".lede"))):
            with open(os.path.join(STATIC_DIR, sheet), encoding="utf-8") as fh:
                css = re.sub(r"/\*.*?\*/", "", fh.read(), flags=re.S)
            for selector in selectors:
                with self.subTest(sheet=sheet, selector=selector):
                    rule = re.search(
                        r"(?:^|\n)" + re.escape(selector) + r"\s*\{([^}]*)\}",
                        css)
                    self.assertIsNotNone(rule, f"{sheet}: no {selector} rule")
                    assert rule is not None
                    self.assertRegex(
                        rule.group(1), r"max-width:\s*\d+ch",
                        f"{sheet} {selector} has no measure, so it runs as "
                        "wide as its container")
                    checked += 1
        self.assertEqual(checked, 3,
                         "a prose block stopped being checked at all")

    def test_the_audit_still_fails_on_an_unreadable_line(self):
        """A gate whose threshold is raised out of reach measures nothing,
        which is the failure mode this whole family of tools exists for."""
        root = os.path.dirname(STATIC_DIR)
        with open(os.path.join(root, "tools", "design_audit.py"),
                  encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn('data.get("prose", [])', source,
                      "the audit no longer measures line length")
        threshold = re.search(r'row\["chars"\]\s*>\s*(\d+)', source)
        self.assertIsNotNone(threshold, "no line-length threshold")
        assert threshold is not None
        self.assertLessEqual(
            int(threshold.group(1)), 90,
            "the line-length gate is set past anything a reader can track")


if __name__ == "__main__":
    unittest.main()
