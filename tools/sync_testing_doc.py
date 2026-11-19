#!/usr/bin/env python3
"""Rewrite the per-file test counts in docs/testing.md.

The table says how many tests each file holds and the header states the suite
total, split into offline and browser. All of it was hand-typed and all of it
had drifted -- the header claimed 543 against a real 591, and the e2e count
was five short.

    python tools/sync_testing_doc.py          # rewrite
    python tools/sync_testing_doc.py --check  # report drift, change nothing

The "Covers" column is prose and is never touched; only the numbers are
derived. A test file missing from the table is reported rather than invented,
because a new file needs a description a generator cannot write.
"""

from __future__ import annotations

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools import write_atomic

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "testing.md"
TESTS = ROOT / "tests"
E2E = "test_ui_e2e.py"

# A test method is a `def test_` at class-method indentation. Verified against
# the loader: this count and `unittest discover` agree exactly.
TEST_DEF_RE = re.compile(r"^    def test_", re.M)
ROW_RE = re.compile(r"^\| `(test_\w+\.py)` \| (\d+) \|(.*)$", re.M)
TOTAL_RE = re.compile(r"^(\.venv/bin/python -m unittest discover -s tests\s+# )"
                      r"(\d+) tests: (\d+) offline \+ (\d+) browser$", re.M)

# The same three figures turn up in prose, in this doc and in the others, and
# `tests/test_docs.py::test_no_doc_quotes_a_suite_size_that_has_drifted`
# checks every one of them. Rewriting only the header left "`Ran 735 tests`"
# four lines below it stale and the suite red -- a generator that owns a
# number has to own every copy of it, or it has merely moved the hand-editing
# somewhere less visible.
PROSE_RES = {
    "offline": re.compile(r"(\d+)(?= offline tests?\b)"),
    "browser": re.compile(r"(\d+)(?= browser tests?\b)"),
    "browser_alt": re.compile(r"(\d+)(?= e2e tests?\b)"),
    "total": re.compile(r"(?<=`Ran )(\d+)(?= tests`)"),
    # docs/review-dispositions.md quotes the suite as evidence in a table:
    # "| Tests | ... | 883 pass |". Nothing owned that cell, so it was
    # hand-typed, and it was the one figure on the page whose whole job is
    # to be checkable. tests/test_docs.py asserts it against the real
    # count, which is how it was found seventeen tests stale.
    "pass": re.compile(r"(\d+)(?= pass \|)"),
}


def counts() -> dict[str, int]:
    return {
        path.name: len(TEST_DEF_RE.findall(path.read_text(encoding="utf-8")))
        for path in sorted(TESTS.glob("test_*.py"))
    }


def main(argv: list[str]) -> int:
    actual = counts()
    if not actual:
        print("no test files found", file=sys.stderr)
        return 2

    text = DOC.read_text(encoding="utf-8")
    listed = {m.group(1) for m in ROW_RE.finditer(text)}
    if not listed:
        print("docs/testing.md has no per-file test table", file=sys.stderr)
        return 2

    drift: list[str] = [
        f"{name}: {actual[name]} tests, missing from the table"
        for name in sorted(set(actual) - listed)
    ]
    drift += [f"{name}: in the table but not in tests/"
              for name in sorted(listed - set(actual))]

    def fix_row(match: re.Match[str]) -> str:
        name, claimed, rest = match.groups()
        if name not in actual:
            return match.group(0)
        if int(claimed) != actual[name]:
            drift.append(f"{name}: table says {claimed}, file has {actual[name]}")
        return f"| `{name}` | {actual[name]} |{rest}"

    text = ROW_RE.sub(fix_row, text)

    total = sum(actual.values())
    browser = actual.get(E2E, 0)

    def fix_total(match: re.Match[str]) -> str:
        prefix, claimed, offline, claimed_browser = match.groups()
        if (int(claimed), int(offline), int(claimed_browser)) != (
                total, total - browser, browser):
            drift.append(
                f"header says {claimed} tests ({offline} + {claimed_browser}); "
                f"the suite has {total} ({total - browser} + {browser})")
        return f"{prefix}{total} tests: {total - browser} offline + {browser} browser"

    text, substitutions = TOTAL_RE.subn(fix_total, text)
    if not substitutions:
        drift.append("header: no 'N tests: N offline + N browser' line to update")

    figures = {"offline": total - browser, "browser": browser,
               "browser_alt": browser, "total": total, "pass": total}
    pending: dict[pathlib.Path, str] = {DOC: text}
    for path in [*sorted(ROOT.glob("*.md")), *sorted((ROOT / "docs").glob("*.md"))]:
        body = pending.get(path) or path.read_text(encoding="utf-8")
        for kind, pattern in PROSE_RES.items():
            want = str(figures[kind])

            def fix(match: re.Match[str], want=want, kind=kind, path=path) -> str:
                if match.group(1) != want:
                    drift.append(f"{path.name}: says {match.group(1)} "
                                 f"where the {kind} count is {want}")
                return want

            body = pattern.sub(fix, body)
        pending[path] = body

    if not drift:
        print("docs/testing.md counts are already accurate")
        return 0
    for line in drift:
        print(line)
    if "--check" in argv:
        return 1

    unwritable = [line for line in drift
                  if "missing from the table" in line or "not in tests/" in line]
    written = 0
    for path, body in pending.items():
        if body != path.read_text(encoding="utf-8"):
            write_atomic(path, body)
            written += 1
    print(f"\nrewrote {len(drift) - len(unwritable)} count(s) across "
          f"{written} file(s)")
    return 2 if unwritable else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
