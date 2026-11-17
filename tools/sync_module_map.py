#!/usr/bin/env python3
"""Rewrite the line counts in the docs/architecture.md module map.

`tests/test_docs.py::test_the_module_map_line_counts_are_real` fails whenever
the map disagrees with the files, which is the point -- but correcting it by
hand after every edit is busywork. Run this instead:

    python tools/sync_module_map.py          # rewrite the map
    python tools/sync_module_map.py --check  # report drift, change nothing
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARCH = ROOT / "docs" / "architecture.md"
CANDIDATE_DIRS = ("", "modules/", "static/", "templates/")


def resolve(name: str) -> pathlib.Path | None:
    for prefix in CANDIDATE_DIRS:
        path = ROOT / f"{prefix}{name}"
        if path.is_file():
            return path
    return None


def main(argv: list[str]) -> int:
    check_only = "--check" in argv
    text = ARCH.read_text(encoding="utf-8")
    block = re.search(r"(## Module map\n+```\n)(.*?)(```)", text, re.S)
    if block is None:
        print("docs/architecture.md has no fenced module map", file=sys.stderr)
        return 2

    drift: list[str] = []

    def fix(line_match: re.Match[str]) -> str:
        indent, name, gap, claimed = line_match.groups()
        path = resolve(name)
        if path is None:
            drift.append(f"{name}: listed but not on disk")
            return line_match.group(0)
        actual = len(path.read_text(encoding="utf-8").splitlines())
        if int(claimed) != actual:
            drift.append(f"{name}: map says {claimed}, file is {actual}")
        # Keep the column aligned: the number is right-aligned in its field.
        width = len(gap) + len(claimed)
        return f"{indent}{name}{str(actual).rjust(width)}"

    body = re.sub(r"^(\s*)([\w./]+\.\w+)(\s+)(\d+)", fix, block.group(2), flags=re.M)

    if not drift:
        print("module map is already accurate")
        return 0
    for line in drift:
        print(line)
    if check_only:
        return 1
    ARCH.write_text(text[:block.start(2)] + body + text[block.end(2):], encoding="utf-8")
    print(f"\nrewrote {len(drift)} row(s) in docs/architecture.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
