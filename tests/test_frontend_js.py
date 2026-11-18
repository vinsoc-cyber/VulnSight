"""Run the Node-based frontend tests as part of the normal pytest suite.

The `tests/*.js` files exercise pure helpers lifted straight out of
`static/app.js` (CSV escaping, history sanitisation, …). They used to be
runnable only by hand, so regressions in them went unnoticed.
"""

import os
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


if __name__ == "__main__":
    unittest.main()
