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

    if not drift:
        print("docs/testing.md counts are already accurate")
        return 0
    for line in drift:
        print(line)
    if "--check" in argv:
        return 1

    unwritable = [line for line in drift
                  if "missing from the table" in line or "not in tests/" in line]
    write_atomic(DOC, text)
    print(f"\nrewrote {len(drift) - len(unwritable)} count(s) in {DOC.name}")
    return 2 if unwritable else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
