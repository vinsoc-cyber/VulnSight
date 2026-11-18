#!/usr/bin/env python3
"""Prove each behavioural fix is actually locked by a test.

A test suite that is green tells you nothing about which fixes it defends.
This reverts each fix in the working tree, runs the test module that is
supposed to catch it, and confirms the suite goes RED -- then restores the
file. A fix whose revert leaves the suite green is not covered, whatever a
summary claims.

This is mutation testing aimed at a specific list of known-real bugs rather
than at random operators: every entry below is a bug that was actually in
this codebase, with the exact edit that reintroduces it.

    python3 tools/revert_checks.py              # all checks
    python3 tools/revert_checks.py cooldown     # only matching labels

Exit status is 0 only when every revert is caught.

Writes to tracked files. It restores from an in-memory copy in a `finally`,
and verifies the tree is clean on the way out, but do not run it on a dirty
tree you care about.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

PY = ".venv/bin/python"

# The checks themselves live in tools/checks/, one module per area, so that
# two people adding checks at once do not collide in a single long list.
# See tools/checks/__init__.py for the shape of an entry and the rule that
# a fix guarded in two places must be reverted in one entry.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools.checks import all_checks  # noqa: E402  (needs the path above)

CHECKS = all_checks()


def suite_is_green(module: str) -> bool:
    proc = subprocess.run(
        [PY, "-m", "unittest", "discover", "-s", "tests", "-p", module + ".py"],
        capture_output=True, text=True, timeout=900,
    )
    return "\nOK" in proc.stderr


def main(argv: list[str]) -> int:
    wanted = [a.lower() for a in argv[1:]]
    checks = [c for c in CHECKS
              if not wanted or any(w in c[0].lower() for w in wanted)]
    if not checks:
        print(f"no check matches {argv[1:]}", file=sys.stderr)
        return 2

    results: list[tuple[str, str, str]] = []
    unrestored: list[str] = []
    for label, edits, module in checks:
        originals = {path: pathlib.Path(path).read_text(encoding="utf-8")
                     for path, _, _ in edits}
        missing = [find for path, find, _ in edits
                   if find not in originals[path]]
        if missing:
            results.append((label, "ANCHOR MISSING", module))
            continue

        try:
            patched = dict(originals)
            for path, find, replace in edits:
                patched[path] = patched[path].replace(find, replace, 1)
            for path, text in patched.items():
                pathlib.Path(path).write_text(text, encoding="utf-8")
            green = suite_is_green(module)
        finally:
            for path, text in originals.items():
                pathlib.Path(path).write_text(text, encoding="utf-8")
                if pathlib.Path(path).read_text(encoding="utf-8") != text:
                    unrestored.append(f"{path} (after: {label})")
        results.append((label, "NOT CAUGHT" if green else "caught", module))

    width = max(len(r[0]) for r in results)
    caught = sum(1 for _, status, _ in results if status == "caught")
    for label, status, module in results:
        tail = "" if status == "caught" else f"   <-- {module}"
        print(f"  {label:<{width}}  {status}{tail}")
    print(f"\n{caught}/{len(results)} reverts caught by the suite")

    if unrestored:
        print("\nWARNING: restore failed, these files are NOT as they were:",
              file=sys.stderr)
        print("\n".join(f"  {line}" for line in unrestored), file=sys.stderr)
        return 2

    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
