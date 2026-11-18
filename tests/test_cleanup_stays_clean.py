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
import subprocess
import pathlib
import re
import shutil
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
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
        # Exactly one mention, not "at most one": the earlier form matched
        # nothing at all (the real line is a kwarg, `resultsPerPage=...`,
        # not an assignment statement) and so passed at zero -- the same
        # defect this test exists to catch, in the test itself.
        # Two mentions now, both in the request builder: the page itself,
        # and the one-row probe that replaced a full page which was fetched
        # and then discarded. What this test is really guarding is that
        # there is no *default assignment* read by nothing.
        self.assertEqual(
            src.count("resultsPerPage"), 2,
            "resultsPerPage should only appear where a request is built")
        self.assertNotRegex(
            src, r"^\s*resultsPerPage\s*[:=]",
            "a default resultsPerPage assignment is back, and every call "
            "site overrides it")

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
        # The surviving limit lives in app.py, where the request is
        # validated. The earlier form looked for a MAX_ADVISORY_ID constant
        # in search_service that has never existed, so it asserted "at most
        # one of nothing" and could not fail.
        caps = [line for line in _source("app.py").splitlines()
                if "len(gid)" in line and "128" in line]
        self.assertEqual(len(caps), 1,
                         f"expected exactly one advisory-id length cap, got {caps}")
        self.assertNotIn("128", _source("modules/search_service.py"),
                         "a second id-length limit came back")

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
        # At the path, not anywhere in the blob: assertIn("100", str(spec))
        # and assertIn("500", str(spec)) were both satisfied by the
        # unrelated max_results schema ('maximum': 500, 'default': 100), so
        # the document could publish maxItems: 7 and stay green.
        body = (spec["paths"]["/api/v1/ai/classify"]["post"]["requestBody"]
                ["content"]["application/json"]["schema"])
        self.assertEqual(body["properties"]["advisory_ids"]["maxItems"],
                         MAX_AI_BATCH)
        self.assertIn(f"{MAX_AI_CALLS_PER_REQUEST} per request", str(spec))
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


class TestTheSharedFixturesMatchTheRealShapes(unittest.TestCase):
    """A fixture that has drifted from the record it stands in for tests a
    shape the product never produces.

    Four test files each hand-built "a normalized advisory" for the AI
    classifier, and the four copies had already diverged: one omitted
    `advisory_id`, which is the first key the cache-id fallback reads, so
    that branch was exercised nowhere. They now share `samples.advisory`,
    and this is what stops the single copy drifting in turn.
    """

    def test_the_advisory_fixture_only_uses_real_normalized_fields(self):
        from modules import ghsa_client
        from samples import SAMPLE, advisory
        real = set(ghsa_client.normalize(SAMPLE))
        invented = sorted(set(advisory()) - real)
        self.assertEqual(
            invented, [],
            f"samples.advisory() carries fields normalize() never emits: "
            f"{invented}")

    def test_the_advisory_fixture_carries_every_field_the_classifier_reads(self):
        """_build_user_prompt and the verdict cache id between them read
        eight keys. A fixture missing one silently tests the empty branch."""
        from samples import advisory
        source = inspect.getsource(ai_classifier)
        read = set(re.findall(r'adv\.get\(["\'](\w+)["\']', source))
        self.assertTrue(read, "the extraction found no adv.get() calls")
        missing = sorted(read - set(advisory()) - {"osv_id"})
        self.assertEqual(
            missing, [],
            f"ai_classifier reads these and the fixture omits them: {missing}")


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

        # Checks that rewrite exactly those three files, chosen so that the
        # modules they route to are cheap. This used to name "opening screen
        # stops", which routes to test_ui_e2e -- so proving the harness does
        # not touch the checkout cost a full Chromium run, 16 times over,
        # inside every battery. "app.js loses its scope wrapper" rewrites the
        # same file and is caught by test_frontend_js in milliseconds.
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "revert_checks.py"),
             "compose publishes", "loses its scope wrapper", "one bad record"],
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


class TestWriteAtomicKeepsThePermissionsItFound(unittest.TestCase):
    """`mkstemp` creates at 0600 and `os.replace` carries the temp file's
    mode, not the target's -- so every file this touched was silently
    narrowed to 0600. Git tracks only the +x bit, so the change was
    invisible in review, and anything reading those files as a different
    UID (a CI runner, a bind-mounted docs server, a build container) got
    EACCES on a file nobody knowingly changed."""

    def test_a_group_readable_file_stays_group_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "generated.py"
            target.write_text("old\n", encoding="utf-8")
            os.chmod(target, 0o644)
            write_atomic(target, "new\n")
            self.assertEqual(oct(os.stat(target).st_mode)[-3:], "644")
            self.assertEqual(target.read_text(encoding="utf-8"), "new\n")

    def test_a_private_file_stays_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "secret"
            target.write_text("x", encoding="utf-8")
            os.chmod(target, 0o600)
            write_atomic(target, "y\n")
            self.assertEqual(oct(os.stat(target).st_mode)[-3:], "600")

    def test_an_executable_keeps_its_bit(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "script.sh"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            os.chmod(target, 0o755)
            write_atomic(target, "#!/bin/sh\necho hi\n")
            self.assertEqual(oct(os.stat(target).st_mode)[-3:], "755")

    def test_a_new_file_is_not_born_private(self):
        """0600 on a file that did not exist is the same defect, just
        without a previous mode to compare against."""
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "fresh.py"
            write_atomic(target, "x\n")
            mode = os.stat(target).st_mode & 0o777
            self.assertTrue(mode & 0o044, f"created as {oct(mode)}, unreadable "
                                          f"to anyone but the owner")

    def test_a_failed_write_leaves_the_original_and_no_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "f.py"
            target.write_text("original\n", encoding="utf-8")
            with mock.patch("os.replace", side_effect=OSError("boom")), \
                 self.assertRaises(OSError):
                write_atomic(target, "replacement\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "original\n")
            leftovers = [n for n in os.listdir(tmp) if n.endswith(".tmp")]
            self.assertEqual(leftovers, [], "a temp file was left behind")


class TestTheTestAuditorsDetectorsCanFire(unittest.TestCase):
    """`audit_tests.py` advertised five detectors and implemented three:
    `self-fulfilling` and `reimplements` were produced by no code path at
    all, so `--strict` could not fail on them however bad a test was.

    Reporting clean is worth something only if the detector is capable of
    reporting otherwise. These feed it known-bad and known-good functions.
    """

    def _flags(self, source):
        import ast

        from tools import audit_tests

        source = textwrap.dedent(source)
        tree = ast.parse(source)
        imported = audit_tests._imported_names(tree)
        helpers = {node.name for node in tree.body
                   if isinstance(node, ast.FunctionDef)}
        fn = next(node for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef)
                  and node.name.startswith("test_"))
        return audit_tests.audit_function(source, fn, imported, helpers)

    SELF_FULFILLING = (
        "import unittest\n"
        "class T(unittest.TestCase):\n"
        "    def test_nothing(self):\n"
        "        rows = [{'a': 1}, {'a': 2}]\n"
        "        total = sum(r['a'] for r in rows)\n"
        "        self.assertEqual(total, 3)\n"
    )
    CALLS_THE_PRODUCT = (
        "import unittest\n"
        "from modules import cwe_categories\n"
        "class T(unittest.TestCase):\n"
        "    def test_real(self):\n"
        "        self.assertTrue(cwe_categories.resolve_cwes(['bac'], True))\n"
    )
    PASSES_A_CALLBACK = (
        "import unittest\n"
        "from modules import search_service\n"
        "class T(unittest.TestCase):\n"
        "    def test_sorts(self):\n"
        "        ids = ['CVE-2025-9', 'CVE-2026-1']\n"
        "        self.assertEqual(sorted(ids, key=search_service._cve_sort_key),\n"
        "                         ['CVE-2025-9', 'CVE-2026-1'])\n"
    )
    RECOMPUTES = (
        "import unittest\n"
        "from modules import nvd_client\n"
        "class T(unittest.TestCase):\n"
        "    def test_page_size(self):\n"
        "        sent = nvd_client.page_size_for(200)\n"
        "        self.assertEqual(min(max(sent, 10), 2000),\n"
        "                         min(max(200, 10), 2000))\n"
    )
    LITERAL_EXPECTATION = (
        "import unittest\n"
        "from modules import nvd_client\n"
        "class T(unittest.TestCase):\n"
        "    def test_page_size(self):\n"
        "        self.assertEqual(nvd_client._page_size(200), 200)\n"
    )

    def test_a_test_that_never_touches_the_product_is_flagged(self):
        self.assertIn("self-fulfilling", self._flags(self.SELF_FULFILLING))

    def test_a_test_that_calls_the_product_is_not_flagged(self):
        self.assertNotIn("self-fulfilling", self._flags(self.CALLS_THE_PRODUCT))

    def test_a_product_function_passed_as_a_callback_is_not_flagged(self):
        """`key=search_service._cve_sort_key` reaches the product without
        being called in the test. The first implementation asked only "does
        it call an imported name" and flagged 45 honest tests, which is how
        a gate gets switched off."""
        self.assertNotIn("self-fulfilling", self._flags(self.PASSES_A_CALLBACK))

    def test_a_test_that_recomputes_its_expectation_is_flagged(self):
        """The NVD page-size test did exactly this: it evaluated
        `min(max(results_per_page, 10), 2000)` while the module used
        `remaining`, so replacing the whole expression with
        `params.results_per_page` left it green."""
        self.assertIn("reimplements", self._flags(self.RECOMPUTES))

    def test_a_literal_expectation_is_not_flagged_as_reimplementing(self):
        self.assertNotIn("reimplements", self._flags(self.LITERAL_EXPECTATION))

    def test_the_auditor_refuses_to_sweep_an_empty_directory(self):
        """An empty glob printed "0 test methods / nothing flagged" and
        returned 0 under --strict, so a misconfigured path reported a clean
        sweep of nothing -- the exact shape this tool exists to find."""
        from tools import audit_tests

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(audit_tests, "TESTS", pathlib.Path(tmp)):
                self.assertNotEqual(audit_tests.main(["--strict"]), 0)


class TestTheHarnessCannotReportAnUnmeasuredPass(unittest.TestCase):
    """`129/129 reverts caught` is the strongest claim this repo makes, and
    two separate mechanisms let it be printed without anything being
    measured.

    The harness only ever observed "red after the revert", which is also
    what an already-failing module looks like -- so every check routed to a
    red module reported `caught`. A revert whose replacement breaks an
    import does the same thing: every test errors, the suite is red, the
    harness calls it a pass. And `sync_check_counts.py` wrote
    `**N/N caught**` unconditionally, so the document's evidence row was
    generated to read as a perfect score by a tool that runs no checks."""

    def _toy_tree(self):
        """run_checks writes to the tree it is given, so it gets a scratch
        one. Pointing it at ROOT would have this test doing the single thing
        the harness exists not to do."""
        tmp = tempfile.mkdtemp(prefix="revert-harness-test-")
        self.addCleanup(shutil.rmtree, tmp, True)
        tree = pathlib.Path(tmp)
        (tree / "subject.py").write_text("VALUE = 1\n", encoding="utf-8")
        return tree

    def test_a_module_that_is_already_red_is_not_counted_as_caught(self):
        from tools import revert_checks

        tree = self._toy_tree()
        with mock.patch.object(revert_checks, "suite_is_green",
                               lambda module, t: False):
            results, unrestored = revert_checks.run_checks(
                [("a label", [("subject.py", "VALUE = 1", "VALUE = 2")],
                  "test_subject")], tree)
        self.assertEqual([status for _, status, _ in results], ["BASELINE RED"],
                         "a red module must not launder into 'caught'")
        self.assertEqual(unrestored, [])
        self.assertEqual((tree / "subject.py").read_text(encoding="utf-8"),
                         "VALUE = 1\n", "the revert was applied anyway")

    def test_the_baseline_is_measured_once_per_module_not_once_per_check(self):
        from tools import revert_checks

        tree = self._toy_tree()
        seen = []

        def green(module, _tree):
            seen.append(module)
            return len(seen) == 1       # green on the baseline, red after

        checks = [(f"check {n}",
                   [("subject.py", "VALUE = 1", f"VALUE = {n + 2}")],
                   "test_subject")
                  for n in range(3)]
        with mock.patch.object(revert_checks, "suite_is_green", green):
            results, _ = revert_checks.run_checks(checks, tree)
        self.assertEqual([s for _, s, _ in results], ["caught"] * 3)
        self.assertEqual(seen.count("test_subject"), 4,
                         "expected 1 baseline run plus 3 patched runs")

    def test_the_sandbox_copy_leaves_the_operators_credentials_behind(self):
        """copytree preserved the 0600 mode, so this was never a
        world-readable leak -- but it put live GitHub and AI credentials in
        /tmp on every run, cleaned up only by a `finally` a SIGKILL skips,
        and ran the deliberately-broken suite with the real keys in
        os.environ because modules/config.py calls load_dotenv at import."""
        from tools.revert_checks import _ignore

        names = [".env", ".env.local", ".env.production", ".vulnsight_api_token",
                 ".ai_key_cooldown.json", "advisories.db", "advisories.db-wal",
                 "app.py", "modules"]
        skipped = _ignore(".", names)
        for secret in (".env", ".env.local", ".env.production",
                       ".vulnsight_api_token", ".ai_key_cooldown.json"):
            with self.subTest(name=secret):
                self.assertIn(secret, skipped, f"{secret} is copied to /tmp")
        # And the exclusions that were already right stay right.
        self.assertIn("advisories.db", skipped)
        self.assertEqual({"app.py", "modules"}, set(names) - skipped)

    def test_the_caught_figure_is_a_measurement_and_not_a_literal(self):
        """sync_check_counts.py must refuse to write a figure when no run
        has published one, rather than invent a perfect score."""
        import json as _json

        from tools import sync_check_counts

        # Asserted as behaviour, not by grepping for the old line: that
        # string now appears in the comment explaining why it is gone.
        body = inspect.getsource(sync_check_counts.main)
        self.assertIn("read_results()", body,
                      "fix_caught no longer consults the recorded run")

        with tempfile.TemporaryDirectory() as tmp:
            missing = pathlib.Path(tmp) / "nope.json"
            with mock.patch.object(sync_check_counts, "RESULTS_PATH", missing):
                self.assertIsNone(sync_check_counts.read_results())
            partial = pathlib.Path(tmp) / "r.json"
            partial.write_text(_json.dumps({"checked": 3, "caught": 2}),
                               encoding="utf-8")
            with mock.patch.object(sync_check_counts, "RESULTS_PATH", partial):
                recorded = sync_check_counts.read_results()
            self.assertIsNotNone(recorded)
            assert recorded is not None
            self.assertEqual(recorded["caught"], 2)

    # The "did the last run actually measure everything?" gate deliberately
    # does NOT live here. Fifteen checks route to this module, so the harness
    # runs it -- and an assertion that the recorded run had no gaps would be
    # red on exactly the run that closes them, which makes this module red,
    # which produces the gap. It lives in tests/test_records.py, which no
    # check targets, so it cannot be its own fixed point.


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


class TestTheSuiteLeavesNothingBehind(unittest.TestCase):
    """`tests/test_app.py` and `docs/testing.md` both promise the suite
    needs no network and no credentials. It needed both.

    Measured before the fix: two job tests reached the real GitHub
    Advisory API with the operator's `gh` credentials, because the
    `with mock.patch(...)` around the submit call had already exited by the
    time the worker thread ran the search. Four search classes wrote their
    fixtures into the repo's own advisories.db -- `GHSA-a`, `CVE-2026-*`,
    and the genuine CVE-2021-44228 row overwritten with
    `summary: "Log4Shell", description: "d"` inside a 1,059-row cache the
    app serves from. And the classifier tests wrote fixture-token hashes
    into the real `.ai_key_cooldown.json`, which in Docker is the mounted
    volume holding live key cooldowns.

    None of that is visible from a green suite, which is why it survived
    this long. These tests make the residue itself the assertion.
    """

    REPO_STATE = ("advisories.db", ".ai_key_cooldown.json",
                  ".vulnsight_api_token")

    def _snapshot(self):
        state = {}
        for name in self.REPO_STATE:
            path = os.path.join(ROOT, name)
            if os.path.exists(path):
                with open(path, "rb") as handle:
                    state[name] = hashlib.sha256(handle.read()).hexdigest()
        return state

    def _run_subset(self, pattern):
        return subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", pattern],
            cwd=ROOT, capture_output=True, text=True, timeout=900)

    def test_running_the_search_and_app_tests_touches_no_repo_state(self):
        before = self._snapshot()
        proc = self._run_subset("test_search_service.py")
        self.assertIn("OK", proc.stderr, proc.stderr[-2000:])
        proc = self._run_subset("test_app.py")
        self.assertIn("OK", proc.stderr, proc.stderr[-2000:])
        self.assertEqual(self._snapshot(), before,
                         "a test wrote into the repo's own state files")

    def test_the_classifier_tests_write_no_cooldown_file(self):
        marker = os.path.join(ROOT, ".ai_key_cooldown.json")
        existed = os.path.exists(marker)
        proc = self._run_subset("test_ai_classifier.py")
        self.assertIn("OK", proc.stderr, proc.stderr[-2000:])
        self.assertEqual(
            os.path.exists(marker), existed,
            "the classifier tests wrote the real AI key-cooldown file; in "
            "Docker that is the operator's live key state")

    def test_the_job_tests_do_not_shell_out_to_gh(self):
        """A job is run by a worker thread after the request returns, so a
        patch scoped to the submit call is already gone by the time the
        search happens."""
        source = _source("tests/test_app.py")
        marker = 'mock.patch(target, return_value=value)'
        self.assertIn(marker, source,
                      "TestJobEndpoints no longer patches gh for the whole "
                      "test; the worker thread will reach GitHub")
        self.assertIn("modules.ghsa_client.fetch_advisories", source)
        self.assertIn("modules.ghsa_client.gh_auth_ok", source)


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
