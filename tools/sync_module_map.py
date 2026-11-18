#!/usr/bin/env python3
"""Rewrite the line counts in the docs/architecture.md module map.

`tests/test_docs.py::test_the_module_map_line_counts_are_real` fails whenever
the map disagrees with the files, which is the point -- but correcting it by
hand after every edit is busywork. Run this instead:

    python tools/sync_module_map.py          # rewrite the map
    python tools/sync_module_map.py --check  # report drift, change nothing

The whole row is re-rendered, not just the digits: an earlier version patched
the number in place and kept whatever spacing it found, so a hand-typed row
stayed misaligned forever and the tool reported the map "accurate". Alignment
is now derived from the longest row, so the format is the tool's to own.
"""

from __future__ import annotations

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools import write_atomic

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARCH = ROOT / "docs" / "architecture.md"
CANDIDATE_DIRS = ("", "modules/", "static/", "templates/", "tools/")

# indent, name, gap, claimed count, gap, description.
#
# The trailing trim is [^\S\n]* -- horizontal whitespace only -- not \s*.
# The map body is the fenced block *without* its closing ```, so it ends with
# a newline; \s* happily consumed that newline and matched $ at end-of-string,
# the rewrite dropped it, and the closing fence ended up glued to the last
# row. The block then parsed one row short and the tool called the map
# accurate while it was corrupt.
ROW_RE = re.compile(r"^(\s*)([\w./]+\.\w+)(\s+)(\d+)(\s+)(\S.*?)[^\S\n]*$", re.M)

# Space between the count and the description, in every row.
DESC_GAP = 3


def resolve(name: str) -> pathlib.Path | None:
    for prefix in CANDIDATE_DIRS:
        path = ROOT / f"{prefix}{name}"
        if path.is_file():
            return path
    return None


def line_count(path: pathlib.Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def render(body: str) -> tuple[str, list[str]]:
    """Return the re-rendered map body and the drift it corrected."""
    drift: list[str] = []
    rows: list[tuple[re.Match[str], int | None]] = []
    for match in ROW_RE.finditer(body):
        name, claimed = match.group(2), match.group(4)
        path = resolve(name)
        if path is None:
            drift.append(f"{name}: listed but not on disk")
            rows.append((match, None))
            continue
        actual = line_count(path)
        if int(claimed) != actual:
            drift.append(f"{name}: map says {claimed}, file is {actual}")
        rows.append((match, actual))

    # One column for the whole block: the count ends where the longest
    # "indent + name + two spaces + count" needs it to.
    target = max(
        (len(m.group(1)) + len(m.group(2)) + 2 + len(str(actual)))
        for m, actual in rows if actual is not None
    ) if any(a is not None for _, a in rows) else 0

    out, cursor = [], 0
    for match, actual in rows:
        if actual is None:
            continue
        indent, name, description = match.group(1), match.group(2), match.group(6)
        pad = " " * (target - len(indent) - len(name) - len(str(actual)))
        rendered = f"{indent}{name}{pad}{actual}{' ' * DESC_GAP}{description}"
        if rendered != match.group(0):
            drift.append(f"{name}: row reformatted")
        out.append(body[cursor:match.start()])
        out.append(rendered)
        cursor = match.end()
    out.append(body[cursor:])
    return "".join(out), drift


def main(argv: list[str]) -> int:
    check_only = "--check" in argv
    text = ARCH.read_text(encoding="utf-8")
    block = re.search(r"(## Module map\n+```\n)(.*?)(```)", text, re.S)
    if block is None:
        print("docs/architecture.md has no fenced module map", file=sys.stderr)
        return 2

    body, drift = render(block.group(2))
    # Deduplicate: a reformat and a count change on one row are one problem.
    seen, unique = set(), []
    for line in drift:
        if line.split(":")[0] not in seen or "not on disk" in line:
            seen.add(line.split(":")[0])
            unique.append(line)

    # A floor, before "accurate" can be printed. If ROW_RE stops matching --
    # somebody converts the fenced block to a markdown table, or reindents
    # it -- `rows` is empty, nothing drifts, and both modes printed "already
    # accurate" and exited 0 on a document that had stopped carrying any
    # derived figure at all. sync_testing_doc guards the equivalent case.
    # Not a fixed threshold -- a small map is legitimate. The failure this
    # guards is "the block still has content and none of it parses", which
    # is what a reformat or a reindent produces: `rows` is empty, nothing
    # drifts, and both modes printed "already accurate" on a document that
    # had stopped carrying any derived figure at all.
    parsed = len(ROW_RE.findall(block.group(2)))
    content_lines = [line for line in block.group(2).splitlines() if line.strip()]
    if content_lines and not parsed:
        print(f"the module map has {len(content_lines)} line(s) and none of "
              f"them parse as rows; its shape has changed and nothing is "
              f"being derived", file=sys.stderr)
        return 2

    if not unique:
        print("module map is already accurate")
        return 0
    for line in unique:
        print(line)
    if check_only:
        return 1

    missing = [line for line in unique if "not on disk" in line]
    write_atomic(ARCH, text[:block.start(2)] + body + text[block.end(2):])
    print(f"\nrewrote {len(unique) - len(missing)} row(s) in docs/architecture.md")
    return 2 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
