#!/usr/bin/env python3
"""Rewrite the class tables in docs/bug-classes.md from CATEGORIES.

The tables list every class's core and extended CWE sets, and the line below
them states how many distinct CWEs the classes reach. All of it is derived
from modules/cwe_categories.py, and all of it had to be hand-edited in step
with the data -- so it drifted the moment the taxonomy was corrected.

    python tools/sync_bug_classes_doc.py          # rewrite
    python tools/sync_bug_classes_doc.py --check  # report drift, change nothing
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import write_atomic  # noqa: E402

from modules.cwe_categories import CATEGORIES, resolve_cwes  # noqa: E402

DOC = ROOT / "docs" / "bug-classes.md"
HEADER = "| Key | Code | Class | Core | Extended |\n|---|---|---|---|---|\n"


def _groups() -> list[tuple[str, list[tuple[str, dict]]]]:
    """Classes by group, each group in first-appearance order."""
    ordered: dict[str, list[tuple[str, dict]]] = {}
    for key, spec in CATEGORIES.items():
        ordered.setdefault(spec["group"], []).append((key, spec))
    return list(ordered.items())


def _row(key: str, spec: dict) -> str:
    core = ", ".join(spec["core"])
    extended = ", ".join(spec["extended"]) or "—"
    return f"| `{key}` | `{spec['code']}` | {spec['label']} | {core} | {extended} |\n"


def render_tables() -> str:
    out = []
    for group, members in _groups():
        out.append(f"#### {group}\n\n")
        out.append(HEADER)
        out.extend(_row(key, spec) for key, spec in members)
        out.append("\n")
    reachable = len(resolve_cwes(list(CATEGORIES)))
    out.append(
        f"{reachable} distinct CWEs are reachable through these classes; "
        "the other ~800 are\nreachable individually — see "
        "[CWE catalog](cwe-catalog.md).\n"
    )
    return "".join(out)


def main(argv: list[str]) -> int:
    text = DOC.read_text(encoding="utf-8")
    heading = f"## The {len(CATEGORIES)} shipped classes"
    start = text.find(heading)
    if start < 0:
        # The heading itself carries the class count, so a changed count moves
        # it. Fall back to the old wording so this script can still fix it.
        match = re.search(r"^## The \d+ shipped classes", text, re.M)
        if match is None:
            print("docs/bug-classes.md has no class-table section", file=sys.stderr)
            return 2
        start, heading = match.start(), match.group(0)

    intro_end = text.index("\n", text.index("\n", start) + 1) + 1
    end = text.index("\n## ", intro_end)

    rebuilt = (
        f"## The {len(CATEGORIES)} shipped classes\n\n"
        "`~` marks the extended set.\n\n"
        + render_tables()
    )
    new_text = text[:start] + rebuilt + text[end:]

    if new_text == text:
        print("docs/bug-classes.md is already accurate")
        return 0
    if "--check" in argv:
        print("docs/bug-classes.md class tables are out of date")
        return 1
    write_atomic(DOC, new_text)
    print(f"rewrote the class tables in {DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
