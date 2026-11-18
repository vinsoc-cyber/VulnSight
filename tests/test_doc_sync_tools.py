"""The two generators that keep docs/ in step with the code.

Both were written to stop a doc drifting and then never run by anything, so
they sat at 0% coverage: a doc guard that is itself unverified is a guard
that can silently stop guarding. `tests/test_docs.py` runs their --check
mode against the shipped docs; these tests drive the rewrite paths, the
failure paths, and the formatting the tools are supposed to own.
"""

import contextlib
import io
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.cwe_categories import CATEGORIES, resolve_cwes
from tools import sync_bug_classes_doc, sync_module_map, sync_testing_doc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _run(tool, argv):
    """Call a tool's main(), returning (exit code, stdout)."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), \
            contextlib.redirect_stderr(buffer):
        code = tool.main(argv)
    return code, buffer.getvalue()


class TestModuleMapSync(unittest.TestCase):
    """sync_module_map rewrites the line counts in the architecture map."""

    MAP = (
        "# Architecture\n\n"
        "## Module map\n\n"
        "```\n"
        "app.py          1   Flask routes\n"
        "modules/\n"
        "  cvss.py       2   CVSS base score\n"
        "  records.py    3   per-record guard\n"
        "```\n\n"
        "## Next section\n"
    )

    @contextlib.contextmanager
    def _doc(self, text=None):
        """A throwaway architecture.md; ROOT still points at the real repo,
        so the counts the tool derives are the real files' counts."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "architecture.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.MAP if text is None else text)
            with mock.patch.object(sync_module_map, "ARCH",
                                   sync_module_map.pathlib.Path(path)):
                yield path

    def _real(self, name):
        path = sync_module_map.resolve(name)
        assert path is not None, name
        return sync_module_map.line_count(path)

    def test_wrong_counts_are_replaced_with_the_real_ones(self):
        with self._doc() as path:
            code, out = _run(sync_module_map, [])
            self.assertEqual(code, 0, out)
            body = _read(path)
        for name in ("app.py", "cvss.py", "records.py"):
            self.assertRegex(body, rf"{re.escape(name)}\s+{self._real(name)}\s")

    def test_check_reports_drift_and_changes_nothing(self):
        with self._doc() as path:
            before = _read(path)
            code, out = _run(sync_module_map, ["--check"])
            self.assertEqual(code, 1)
            self.assertIn("app.py", out)
            self.assertEqual(_read(path), before,
                             "--check wrote to the file")

    def test_an_accurate_map_is_left_alone(self):
        accurate = self.MAP
        for name in ("app.py", "cvss.py", "records.py"):
            accurate = re.sub(rf"({re.escape(name)}\s+)\d+",
                              rf"\g<1>{self._real(name)}", accurate)
        with self._doc(accurate) as path:
            # Written by hand above, so the columns are ragged; the tool
            # normalises them once and is a no-op from then on.
            _run(sync_module_map, [])
            first = _read(path)
            code, out = _run(sync_module_map, [])
            self.assertEqual(code, 0)
            self.assertIn("already accurate", out)
            self.assertEqual(_read(path), first)

    def test_the_counts_line_up_in_one_column(self):
        """The previous version patched the digits in place and kept whatever
        spacing it found, so a hand-typed row stayed crooked forever and the
        tool still called the map accurate."""
        crooked = self.MAP.replace("  cvss.py       2 ", "  cvss.py   2 ")
        with self._doc(crooked) as path:
            _run(sync_module_map, [])
            body = _read(path)
        ends = {len(m.group(0))
                for m in re.finditer(r"^\s*[\w./]+\.\w+\s+\d+", body, re.M)}
        self.assertEqual(len(ends), 1, f"counts end at columns {sorted(ends)}")

    def test_the_description_survives_the_rewrite(self):
        with self._doc() as path:
            _run(sync_module_map, [])
            body = _read(path)
        for description in ("Flask routes", "CVSS base score", "per-record guard"):
            self.assertIn(description, body)

    def test_text_outside_the_fence_is_untouched(self):
        with self._doc() as path:
            _run(sync_module_map, [])
            body = _read(path)
        self.assertTrue(body.startswith("# Architecture\n\n## Module map\n"))
        self.assertTrue(body.endswith("```\n\n## Next section\n"))

    def test_the_closing_fence_stays_on_its_own_line(self):
        """The row pattern trimmed trailing whitespace with `\\s*$`. The map
        body is the fenced block *without* its closing ```, so it ends in a
        newline -- which `\\s*` consumed while `$` matched at end-of-string.
        The rewrite dropped it, the fence was glued to the last row, and the
        block then parsed one row short while the tool reported the map
        accurate. `test_text_outside_the_fence_is_untouched` could not see
        this: the document still *ends* with the right characters."""
        with self._doc() as path:
            _run(sync_module_map, [])
            body = _read(path)
        self.assertIn("\n```\n", body, "the closing fence lost its own line")
        fenced = re.search(r"## Module map\n+```\n(.*?)```", body, re.S)
        self.assertIsNotNone(fenced)
        assert fenced is not None
        self.assertTrue(fenced.group(1).endswith("\n"),
                        "the map body must end with a newline")
        self.assertEqual(len(fenced.group(1).strip().splitlines()), 4,
                         "a row went missing from the rewritten block")

    def test_rewriting_twice_does_not_corrupt_the_block(self):
        with self._doc() as path:
            _run(sync_module_map, [])
            once = _read(path)
            _run(sync_module_map, [])
            self.assertEqual(_read(path), once)

    def test_a_row_naming_a_file_that_does_not_exist_is_reported(self):
        gone = self.MAP.replace("  cvss.py       2 ", "  deleted_module.py  2 ")
        with self._doc(gone) as path:
            code, out = _run(sync_module_map, [])
            self.assertIn("deleted_module.py: listed but not on disk", out)
            self.assertNotEqual(code, 0, "a stale row must not exit clean")
            # The row is left as-is rather than deleted: removing a line from
            # a hand-maintained doc is the author's call, not the tool's.
            self.assertIn("deleted_module.py", _read(path))

    def test_a_doc_with_no_module_map_is_an_error_not_a_crash(self):
        with self._doc("# Architecture\n\nNo map here.\n"):
            code, out = _run(sync_module_map, [])
        self.assertEqual(code, 2)
        self.assertIn("no fenced module map", out)

    def test_resolve_searches_every_shipped_directory(self):
        for name, expected in (("app.py", "app.py"),
                               ("cvss.py", "modules/cvss.py"),
                               ("app.js", "static/app.js"),
                               ("index.html", "templates/index.html"),
                               ("sync_module_map.py", "tools/sync_module_map.py")):
            with self.subTest(name=name):
                path = sync_module_map.resolve(name)
                self.assertIsNotNone(path, name)
                assert path is not None
                self.assertEqual(path.relative_to(ROOT).as_posix(), expected)

    def test_resolve_returns_none_for_something_that_is_not_there(self):
        self.assertIsNone(sync_module_map.resolve("no_such_file.py"))


class TestTestingDocSync(unittest.TestCase):
    """sync_testing_doc rewrites the per-file test counts in docs/testing.md.

    The counts and the suite total were hand-typed; the header claimed 543
    against a real 591 and the browser count was five short.
    """

    DOC = (
        "# Testing\n\n"
        "```bash\n"
        ".venv/bin/python -m unittest discover -s tests        "
        "# 1 tests: 1 offline + 0 browser\n"
        "```\n\n"
        "## What is covered\n\n"
        "| File | Tests | Covers |\n|---|---|---|\n"
        "{rows}\n"
        "## Next\n"
    )

    @contextlib.contextmanager
    def _doc(self, rows=None):
        """A throwaway testing.md; TESTS still points at the real tests/, so
        the counts the tool derives are the suite's real counts."""
        if rows is None:
            rows = "".join(
                f"| `{name}` | 1 | prose that must survive |\n"
                for name in sorted(sync_testing_doc.counts()))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "testing.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.DOC.format(rows=rows))
            with mock.patch.object(sync_testing_doc, "DOC",
                                   sync_testing_doc.pathlib.Path(path)):
                yield path

    def test_the_regex_count_matches_what_the_loader_collects(self):
        """The tool defines a test as `def test_` at method indentation. If
        that ever stops matching unittest's own collection, every number it
        writes is wrong -- so check it against the loader, not against itself."""
        loader = unittest.defaultTestLoader
        for name, claimed in sync_testing_doc.counts().items():
            with self.subTest(file=name):
                suite = loader.discover(
                    str(sync_testing_doc.TESTS), pattern=name,
                    top_level_dir=str(sync_testing_doc.TESTS))
                self.assertEqual(suite.countTestCases(), claimed)

    def test_wrong_counts_are_replaced_with_the_real_ones(self):
        real = sync_testing_doc.counts()
        with self._doc() as path:
            code, out = _run(sync_testing_doc, [])
            self.assertEqual(code, 0, out)
            body = _read(path)
        for name, expected in real.items():
            self.assertIn(f"| `{name}` | {expected} |", body)

    def test_the_header_total_is_split_into_offline_and_browser(self):
        real = sync_testing_doc.counts()
        total = sum(real.values())
        browser = real[sync_testing_doc.E2E]
        with self._doc() as path:
            _run(sync_testing_doc, [])
            body = _read(path)
        self.assertIn(
            f"# {total} tests: {total - browser} offline + {browser} browser", body)

    def test_the_covers_prose_is_never_touched(self):
        with self._doc() as path:
            _run(sync_testing_doc, [])
            body = _read(path)
        self.assertEqual(body.count("prose that must survive"),
                         len(sync_testing_doc.counts()))

    def test_check_reports_drift_and_changes_nothing(self):
        with self._doc() as path:
            before = _read(path)
            code, out = _run(sync_testing_doc, ["--check"])
            self.assertEqual(code, 1)
            self.assertIn("table says 1", out)
            self.assertEqual(_read(path), before, "--check wrote to the file")

    def test_an_accurate_doc_is_a_no_op(self):
        with self._doc() as path:
            _run(sync_testing_doc, [])
            first = _read(path)
            code, out = _run(sync_testing_doc, [])
            self.assertEqual(code, 0)
            self.assertIn("already accurate", out)
            self.assertEqual(_read(path), first)

    def test_a_test_file_missing_from_the_table_is_reported_not_invented(self):
        """A new file needs a description the generator cannot write, so it
        says so and exits non-zero rather than inserting a blank row."""
        names = sorted(sync_testing_doc.counts())
        rows = "".join(f"| `{n}` | 1 | prose that must survive |\n"
                       for n in names[1:])
        with self._doc(rows) as path:
            code, out = _run(sync_testing_doc, [])
            body = _read(path)
        self.assertIn(f"{names[0]}:", out)
        self.assertIn("missing from the table", out)
        self.assertNotEqual(code, 0)
        self.assertNotIn(f"| `{names[0]}` |", body)

    def test_a_doc_with_no_table_is_an_error_not_a_crash(self):
        with self._doc(rows=""):
            code, out = _run(sync_testing_doc, [])
        self.assertEqual(code, 2)
        self.assertIn("no per-file test table", out)


class TestBugClassesDocSync(unittest.TestCase):
    """sync_bug_classes_doc rebuilds the class tables from CATEGORIES."""

    @contextlib.contextmanager
    def _doc(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bug-classes.md")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
            with mock.patch.object(sync_bug_classes_doc, "DOC",
                                   sync_bug_classes_doc.pathlib.Path(path)):
                yield path

    def _stale(self, heading=None):
        heading = heading or f"## The {len(CATEGORIES)} shipped classes"
        return (f"# Bug classes\n\nIntro line.\n\n{heading}\n\n"
                "`~` marks the extended set.\n\n"
                "| Key | Code | Class | Core | Extended |\n|---|---|---|---|---|\n"
                "| `stale` | `99` | Stale row | 1 | 2 |\n\n"
                "## Something else\n\nTail text.\n")

    def test_every_class_appears_exactly_once(self):
        rendered = sync_bug_classes_doc.render_tables()
        for key in CATEGORIES:
            self.assertEqual(rendered.count(f"| `{key}` |"), 1, key)

    def test_the_reachable_cwe_count_is_derived_not_typed(self):
        rendered = sync_bug_classes_doc.render_tables()
        expected = len(resolve_cwes(list(CATEGORIES)))
        self.assertIn(f"{expected} distinct CWEs are reachable", rendered)

    def test_a_class_with_no_extended_set_renders_a_dash(self):
        row = sync_bug_classes_doc._row(
            "x", {"code": "1", "label": "L", "core": ["79"], "extended": []})
        self.assertTrue(row.rstrip().endswith("| — |"), row)

    def test_every_group_gets_its_own_heading_and_header_row(self):
        rendered = sync_bug_classes_doc.render_tables()
        groups = {spec["group"] for spec in CATEGORIES.values()}
        for group in groups:
            self.assertIn(f"#### {group}\n", rendered)
        self.assertEqual(rendered.count("| Key | Code | Class |"), len(groups))

    def test_a_stale_table_is_rebuilt(self):
        with self._doc(self._stale()) as path:
            code, out = _run(sync_bug_classes_doc, [])
            self.assertEqual(code, 0, out)
            body = _read(path)
        self.assertNotIn("| `stale` |", body)
        for key in CATEGORIES:
            self.assertIn(f"| `{key}` |", body)

    def test_the_surrounding_document_is_preserved(self):
        with self._doc(self._stale()) as path:
            _run(sync_bug_classes_doc, [])
            body = _read(path)
        self.assertTrue(body.startswith("# Bug classes\n\nIntro line.\n\n"))
        self.assertTrue(body.endswith("## Something else\n\nTail text.\n"))

    def test_check_reports_drift_and_changes_nothing(self):
        with self._doc(self._stale()) as path:
            before = _read(path)
            code, out = _run(sync_bug_classes_doc, ["--check"])
            self.assertEqual(code, 1)
            self.assertIn("out of date", out)
            self.assertEqual(_read(path), before,
                             "--check wrote to the file")

    def test_rewriting_twice_changes_nothing_the_second_time(self):
        with self._doc(self._stale()) as path:
            _run(sync_bug_classes_doc, [])
            first = _read(path)
            code, out = _run(sync_bug_classes_doc, [])
            self.assertEqual(code, 0)
            self.assertIn("already accurate", out)
            self.assertEqual(_read(path), first)

    def test_a_wrong_class_count_in_the_heading_is_still_found(self):
        """The heading states the class count, so adding a class moves the
        heading the tool is looking for. It falls back to the pattern and
        fixes the number rather than refusing to run."""
        with self._doc(self._stale("## The 9999 shipped classes")) as path:
            code, out = _run(sync_bug_classes_doc, [])
            self.assertEqual(code, 0, out)
            body = _read(path)
        self.assertIn(f"## The {len(CATEGORIES)} shipped classes", body)
        self.assertNotIn("9999", body)

    def test_a_doc_with_no_class_section_is_an_error_not_a_crash(self):
        with self._doc("# Bug classes\n\nNothing here.\n"):
            code, out = _run(sync_bug_classes_doc, [])
        self.assertEqual(code, 2)
        self.assertIn("no class-table section", out)


class TestAToolCannotReportCleanOnNothing(unittest.TestCase):
    """Three tools could print success having measured nothing, which is
    worse than failing: it is indistinguishable from a real pass.

    `sync_module_map` reported "already accurate" when ROW_RE parsed zero
    rows -- somebody converting the fenced block to a markdown table, or
    reindenting it, would have silently stopped every line count being
    derived. `sync_testing_doc` already guarded the equivalent case, which
    is how the asymmetry was found.
    """

    def test_sync_module_map_refuses_a_block_it_cannot_parse(self):
        import re as _re

        original = sync_module_map.ROW_RE
        try:
            sync_module_map.ROW_RE = _re.compile(r"ZZZ_NEVER_MATCHES")
            with contextlib.redirect_stderr(io.StringIO()):
                rc = sync_module_map.main(["--check"])
        finally:
            sync_module_map.ROW_RE = original
        self.assertEqual(rc, 2, "a map that parses to nothing reported clean")

    def test_sync_module_map_is_happy_with_the_real_block(self):
        """The floor must not fire on the document as it stands."""
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = sync_module_map.main(["--check"])
        self.assertIn(rc, (0, 1), "the floor fired on a healthy map")

    def test_the_design_audit_does_not_report_success_without_a_browser(self):
        """Wired into CI without playwright it returned 0 -- passing
        forever having measured nothing, which is the exact failure it
        exists to catch in other people's work."""
        source = _read(os.path.join(ROOT, "tools", "design_audit.py"))
        self.assertNotRegex(
            source,
            r"playwright is not installed[\s\S]{0,200}?return 0\b",
            "a missing browser still exits 0")
        self.assertRegex(source, r"return 77")

    def test_the_design_audit_checks_the_page_it_asked_for(self):
        """Flask's 404 body is exactly one <h1> with no overflow and no JS
        errors, so it satisfies every structural check. If /api/docs ever
        stopped registering, the states added to cover it would have
        audited the 404 and reported clean."""
        source = _read(os.path.join(ROOT, "tools", "design_audit.py"))
        self.assertRegex(source, r"response\s*=\s*page\.goto")
        self.assertRegex(source, r"response\.status\s*>=\s*400")


if __name__ == "__main__":
    unittest.main()
