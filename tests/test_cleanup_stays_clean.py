"""Fixes that no revert check can defend, locked a different way.

A revert check needs an edit that puts a *defect* back. Some fixes have no
such edit: deleting dead code, extracting a function, or adding a cache all
leave behaviour identical by construction, so reverting them produces no
failing assertion anywhere.

`docs/review-dispositions.md` used to simply say those rows could not be
mechanically locked. That is true of *revert* checks and false of testing in
general: what each of those fixes produced is a **property** of the tree, and
a property can be asserted directly. Dead code is gone or it is not. A cache
is consulted or it is not. A helper is importable without Flask or it is not.

These are deliberately shallow, structural assertions. They are not a
substitute for behavioural tests -- the rest of the suite does that work --
they exist so that no row in the disposition table rests on nothing.
"""

import ast
import hashlib
import inspect
import os
import re
import subprocess
import pathlib
import sys
import tempfile
import unittest
from typing import Any, cast

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import ai_classifier, ghsa_client, openapi, query_filters
from tools import write_atomic
from modules.config import MAX_AI_BATCH, MAX_AI_CALLS_PER_REQUEST

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _source(relative):
    with open(os.path.join(ROOT, relative), encoding="utf-8") as handle:
        return handle.read()


class TestDeadCodeStaysDeleted(unittest.TestCase):
    """Removals. Re-adding them changes no behaviour, so only the absence
    itself can be asserted -- which is exactly what was fixed."""

    def test_build_date_params_has_no_caller_and_no_body(self):
        """A helper with no caller, kept in step with the real date logic by
        hand. The two had already drifted when it was deleted."""
        self.assertNotIn("_build_date_params", _source("modules/nvd_client.py"))

    def test_results_per_page_is_not_assigned_and_then_overridden(self):
        """Every call site passed its own resultsPerPage, so the default
        assignment was read by nothing and said something untrue about the
        page size."""
        src = _source("modules/nvd_client.py")
        assigns = re.findall(r'^\s*(?:params\[)?["\']?resultsPerPage["\']?\]?\s*=',
                             src, re.M)
        self.assertLessEqual(
            len(assigns), 1,
            "resultsPerPage is assigned more than once; one of them is dead")

    def test_there_is_one_key_rotation_implementation(self):
        """Two existed: a `rotate_token` method and the cooling-aware picker
        in `AIConfig.token`. They disagreed about what "next key" meant."""
        src = _source("modules/ai_classifier.py")
        self.assertNotIn("def rotate_token", src)
        self.assertNotIn("_call_messages_retrying", src)
        self.assertFalse(hasattr(ai_classifier.AIConfig, "rotate_token"))

    def test_there_is_one_advisory_id_length_limit(self):
        """Two different maxima guarded the same field; the second could
        never be reached, so it documented a limit that did not apply."""
        src = _source("modules/search_service.py")
        limits = set(re.findall(r"MAX_ADVISORY_ID\w*", src))
        self.assertLessEqual(len(limits), 1, f"competing id limits: {limits}")

    def test_the_tree_has_no_unused_noqa(self):
        """RUF100 catches these, but only on a full `ruff check .` -- a
        narrowed --select reports a live noqa as unused, which is how a real
        E402 suppression got deleted here once."""
        # NOT `--select RUF100`. Under a narrowed rule set RUF100 reports
        # a *live* noqa as unused, because the rule it suppresses is not
        # enabled in that run -- which is how a real E402 suppression got
        # deleted here once. Only the project's full config is truthful.
        proc = subprocess.run(["ruff", "check", ".", "--output-format", "concise"],
                              cwd=ROOT, capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0,
                         f"ruff is not clean:\n{proc.stdout}\n{proc.stderr}")
        self.assertNotIn("RUF100", proc.stdout)


class TestExtractionsStayExtracted(unittest.TestCase):
    """Refactors. The behaviour is identical by construction; what changed
    is where the logic can be called from, which is assertable."""

    def test_classify_batch_is_callable_without_a_request(self):
        """115 lines of service logic lived in a Flask view, so nothing
        could classify a batch -- or test one -- without a request context."""
        self.assertTrue(callable(ai_classifier.classify_batch))
        params = inspect.signature(ai_classifier.classify_batch).parameters
        self.assertNotIn("request", params)

    def test_the_openapi_limits_are_the_constants_not_copies(self):
        """The document hand-copied the batch and call-cap numbers. They
        were already one revision behind the code when this was found."""
        spec = openapi.build_spec("/")
        text = str(spec)
        self.assertIn(str(MAX_AI_BATCH), text)
        self.assertIn(str(MAX_AI_CALLS_PER_REQUEST), text)
        # And the module reads them rather than restating them.
        src = _source("modules/openapi.py")
        self.assertIn("MAX_AI_BATCH", src)
        self.assertIn("MAX_AI_CALLS_PER_REQUEST", src)

    def test_no_generator_binds_the_name_g(self):
        """`g` is the Flask request global, imported and used in the same
        function. The genexp had its own scope so it worked, which is worse:
        it read as a bug and behaved correctly."""
        tree = ast.parse(_source("app.py"))
        # If app.py ever had no comprehensions and no for-loops, "none of
        # them binds `g`" would be true and meaningless.
        self.assertGreater(
            sum(1 for n in ast.walk(tree)
                if isinstance(n, (ast.comprehension, ast.For))), 5,
            "nothing to check; the walk found no loops")
        for node in ast.walk(tree):
            if isinstance(node, (ast.comprehension,)):
                target = node.target
                names = ([target.id] if isinstance(target, ast.Name)
                         else [e.id for e in getattr(target, "elts", [])
                               if isinstance(e, ast.Name)])
                self.assertNotIn("g", names,
                                 "a comprehension binds `g`, shadowing Flask's")
            if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
                self.assertNotEqual(node.target.id, "g",
                                    "a for-loop binds `g`, shadowing Flask's")

    def test_gh_is_resolved_to_a_path_not_invoked_by_bare_name(self):
        """A bare `gh` is resolved against PATH at exec time, so whatever is
        first on an operator's PATH runs with their GitHub credentials."""
        self.assertTrue(hasattr(ghsa_client, "gh_executable"))
        src = _source("modules/ghsa_client.py")
        # No argv list may start with a literal "gh".
        self.assertNotIn('["gh"', src)
        self.assertNotIn("['gh'", src)
        self.assertIn("gh_executable()", src)


class TestThePerformanceFixesAreStillInPlace(unittest.TestCase):
    """Same output, less of it. A revert changes no assertion -- but the
    mechanism that makes it fast is a property, and it either exists or it
    does not."""

    def test_published_bounds_parses_a_window_once(self):
        """It re-parsed the same window string per record. At 5,000 records
        that is 5,000 identical date parses on the hot path."""
        cached = getattr(query_filters, "_published_bounds_cached", None)
        self.assertIsNotNone(cached, "the memoised helper is gone")
        assert cached is not None
        self.assertTrue(hasattr(cached, "cache_info"),
                        "_published_bounds_cached is no longer memoised")

        window = "2026-01-01..2026-02-01"
        cached.cache_clear()
        first = query_filters.published_bounds(window)
        for _ in range(50):
            query_filters.published_bounds(window)
        info = cached.cache_info()
        self.assertEqual(info.misses, 1, "the window is being re-parsed")
        self.assertEqual(info.hits, 50, "the cache is not being hit")
        self.assertEqual(first, query_filters.published_bounds(window))

    def test_the_cache_does_not_swallow_the_type_contract(self):
        """Why the cache is on the private helper: lru_cache raises
        TypeError on an unhashable argument, and every rejection from this
        function is contracted to be a ValueError."""
        # The wrong type is the point of the test, so it is cast rather
        # than smuggled past the signature with a blanket ignore.
        with self.assertRaises(ValueError):
            query_filters.published_bounds(cast(Any, ["not", "a", "string"]))

    def test_the_picker_is_told_what_is_checked_rather_than_asking_the_dom(self):
        """isPicked() ran a document query per option, so opening a 944-row
        catalog meant 944 DOM queries before a single keystroke."""
        src = _source("static/app.js")
        self.assertIn("function isPicked(entry, checked)", src)
        self.assertIn("function checkedClassKeys(", src)

    def test_the_osv_export_is_parsed_once_per_ecosystem(self):
        """Eight concurrent searches each parsed the whole export, which is
        where the out-of-memory kills came from."""
        src = _source("modules/osv_client.py")
        self.assertIn("_load_lock", src)


class TestNoTestCanSilentlyStopChecking(unittest.TestCase):
    """A green suite is worth what its tests can still fail.

    `tools/audit_tests.py` sweeps every test method for the shapes a test
    takes once it has stopped checking: no assertion at all, assertions
    reachable only inside an `if` (so an empty result is a pass), and
    comparisons of a value with itself. Running it here means the sweep is
    part of the suite rather than something somebody remembers to do.

    Its first run over this repo flagged 15 of 687 methods. Eleven were
    legitimate -- `self.fail()` inside a guard, determinism tests that
    compare two calls, "must not raise" smoke tests -- and the detector was
    taught about each. Five were real: four would have passed with an empty
    loop, and one browser test would have passed if the wordmark were
    hidden at every width.
    """

    def test_no_test_method_is_flagged_as_unable_to_fail(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "audit_tests.py"),
             "--strict"],
            cwd=ROOT, capture_output=True, text=True, timeout=180)
        self.assertEqual(proc.returncode, 0,
                         f"tests that cannot fail:\n{proc.stdout}")


class TestTheRevertHarnessCannotTouchTheCheckout(unittest.TestCase):
    """It edits source files on purpose. It must do that to a copy.

    The first version edited the checkout and restored in a `finally`,
    which is correct in isolation and wrong the moment anything else reads
    the repo. During one long run somebody ran `docker compose up --build`
    and got an image with a deliberately-broken `app.js` baked in, from a
    compose file that was mid-revert and publishing on every interface. A
    warning in a docstring is not a guard; this is.
    """

    def test_running_a_destructive_check_leaves_the_tree_byte_identical(self):
        watched = ["static/app.js", "docker-compose.yml",
                   "modules/search_service.py"]
        before = {f: hashlib.sha256(_source(f).encode()).hexdigest() for f in watched}

        # Checks that rewrite exactly those three files.
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "revert_checks.py"),
             "compose publishes", "opening screen stops", "one bad record"],
            cwd=ROOT, capture_output=True, text=True, timeout=900)
        self.assertIn("reverts caught", proc.stdout, proc.stdout + proc.stderr)

        after = {f: hashlib.sha256(_source(f).encode()).hexdigest() for f in watched}
        self.assertEqual(before, after,
                         "the harness modified the working tree")

    def test_it_says_where_it_is_running(self):
        """If it ever stops printing a sandbox path, it is back in the
        checkout and the test above is the only thing standing in the way."""
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "revert_checks.py"),
             "cve_id sorts"],
            cwd=ROOT, capture_output=True, text=True, timeout=900)
        self.assertRegex(proc.stdout, r"running in /")
        self.assertNotIn(ROOT + "\n", proc.stdout)

    def test_in_place_is_opt_in_and_says_so(self):
        source = _source("tools/revert_checks.py")
        self.assertIn("--in-place", source)
        self.assertIn("editing the checkout", source)
        # The default path must build a sandbox.
        self.assertIn("tree = sandbox(REPO)", source)


class TestTheGeneratorsCannotTruncateWhatTheyRewrite(unittest.TestCase):
    """Five tools rewrite a file in place, and `Path.write_text` truncates
    first and writes second. An interruption between the two -- a full
    disk, a Ctrl-C, an OOM kill -- leaves a half-written file. For
    `modules/cwe_catalog.py` that is a module the running server imports,
    so the next start fails on a SyntaxError in generated code nobody
    edited. The codebase already knew the careful pattern; it was used for
    the AI cooldown file and nowhere else."""

    def test_a_failed_write_leaves_the_original_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "catalog.py"
            target.write_text("ORIGINAL\n", encoding="utf-8")

            class Boom(Exception):
                pass

            real_fdopen = os.fdopen

            def failing_fdopen(fd, *args, **kwargs):
                handle = real_fdopen(fd, *args, **kwargs)

                class Failing:
                    """Writes half of what it is given, then fails -- the
                    shape of a full disk. Not a TextIOBase subclass: the
                    three methods write_atomic uses are the whole contract
                    here, and inheriting the rest only invites a signature
                    mismatch."""

                    def write(self, s):            # half of it lands
                        handle.write(s[: len(s) // 2])
                        raise Boom("disk full")

                    def __enter__(self):
                        return self

                    def __exit__(self, *exc):
                        handle.close()
                        return False

                return Failing()

            os.fdopen = failing_fdopen
            try:
                with self.assertRaises(Boom):
                    write_atomic(target, "NEW CONTENT THAT NEVER ARRIVES\n")
            finally:
                os.fdopen = real_fdopen

            self.assertEqual(target.read_text(encoding="utf-8"), "ORIGINAL\n",
                             "a failed write damaged the original")
            leftovers = [p.name for p in pathlib.Path(directory).iterdir()
                         if p.name != "catalog.py"]
            self.assertEqual(leftovers, [], "a temp file was orphaned")

    def test_a_normal_write_replaces_the_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "x.txt"
            target.write_text("old", encoding="utf-8")
            write_atomic(target, "new")
            self.assertEqual(target.read_text(encoding="utf-8"), "new")

    def test_every_generator_uses_it(self):
        """A generator that goes back to write_text is one truncation away
        from leaving a doc, or an imported module, half-written."""
        generators = ("tools/sync_module_map.py", "tools/sync_bug_classes_doc.py",
                      "tools/sync_testing_doc.py", "tools/sync_check_counts.py",
                      "tools/generate_cwe_catalog.py")
        for name in generators:
            with self.subTest(tool=name):
                source = _source(name)
                self.assertIn("write_atomic", source)
                self.assertNotIn(".write_text(", source,
                                 f"{name} writes a file without the rename")


class TestEveryFixedRowHasAGuard(unittest.TestCase):
    """The disposition table is the author's account of their own work. This
    is the part that is not: every `fixed` row is either locked by a revert
    check or named in the list of kinds that cannot be, and that list has to
    stay honest about which kinds those are."""

    def test_the_doc_names_a_guard_for_every_kind_it_excludes(self):
        from tools.checks import GROUPS

        doc = _source("docs/review-dispositions.md")
        self.assertIn("What is mechanically locked, and what cannot be", doc)
        # Each excluded kind must point at where it *is* covered instead.
        for kind in ("Dead-code removals", "Pure refactors",
                     "Performance-only fixes"):
            self.assertIn(kind, doc, f"{kind} is no longer explained")
        self.assertIn("tests/test_cleanup_stays_clean.py", doc,
                      "the doc must say where the unrevertable fixes are locked")

        total = sum(len(c) for c in GROUPS.values())
        self.assertGreater(total, 80, "revert checks disappeared")


if __name__ == "__main__":
    unittest.main()
