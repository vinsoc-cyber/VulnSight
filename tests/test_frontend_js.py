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


if __name__ == "__main__":
    unittest.main()
