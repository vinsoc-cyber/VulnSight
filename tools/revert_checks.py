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

It runs in a disposable copy of the tree, never in your checkout.

That is not a nicety. The first version edited tracked files in place and
restored them in a `finally`, which is correct in isolation and wrong the
moment anyone else is using the repo: during a long run of this harness
somebody ran `docker compose up --build`, and the image they got had a
deliberately-broken `app.js` baked into it and a compose file that
published on every interface. A warning in a docstring is not a guard. The
checkout is now read-only to this tool, and `--in-place` is the only way
back to the old behaviour.

    python3 tools/revert_checks.py              # all checks
    python3 tools/revert_checks.py cooldown     # only matching labels
    python3 tools/revert_checks.py --in-place   # edit the checkout (unsafe)

Exit status is 0 only when every revert is caught.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
PY = str(REPO / ".venv" / "bin" / "python")

# Copied into the sandbox; everything else is build output, caches, or
# large downloads that no check reads.
SKIP = {".git", ".venv", "node_modules", "__pycache__", "osv_cache",
        ".coverage", "htmlcov", ".ruff_cache", ".pytest_cache"}

# The checks themselves live in tools/checks/, one module per area, so that
# two people adding checks at once do not collide in a single long list.
# See tools/checks/__init__.py for the shape of an entry and the rule that
# a fix guarded in two places must be reverted in one entry.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools.checks import all_checks  # noqa: E402  (needs the path above)

CHECKS = all_checks()


def _ignore(_dir: str, names: list[str]) -> set[str]:
    return {n for n in names if n in SKIP or n.endswith((".db", ".db-wal", ".db-shm"))}


def sandbox(root: pathlib.Path) -> pathlib.Path:
    """A throwaway copy of the tree, including uncommitted work.

    Not `git worktree`: the checks have to run against what is on disk
    right now, which is usually not what is committed.
    """
    dest = pathlib.Path(tempfile.mkdtemp(prefix="revert-checks-")) / root.name
    shutil.copytree(root, dest, ignore=_ignore, symlinks=True)
    return dest


def suite_is_green(module: str, cwd: pathlib.Path) -> bool:
    proc = subprocess.run(
        [PY, "-m", "unittest", "discover", "-s", "tests", "-p", module + ".py"],
        capture_output=True, text=True, timeout=900, cwd=cwd,
    )
    return "\nOK" in proc.stderr


def run_checks(checks, tree: pathlib.Path):
    """Apply each revert in *tree*, run its module, restore, record."""
    results: list[tuple[str, str, str]] = []
    unrestored: list[str] = []

    for label, edits, module in checks:
        originals = {path: (tree / path).read_text(encoding="utf-8")
                     for path, _, _ in edits}
        if any(find not in originals[path] for path, find, _ in edits):
            results.append((label, "ANCHOR MISSING", module))
            continue

        try:
            patched = dict(originals)
            for path, find, replace in edits:
                patched[path] = patched[path].replace(find, replace, 1)
            for path, text in patched.items():
                (tree / path).write_text(text, encoding="utf-8")
            green = suite_is_green(module, tree)
        finally:
            for path, text in originals.items():
                (tree / path).write_text(text, encoding="utf-8")
                if (tree / path).read_text(encoding="utf-8") != text:
                    unrestored.append(f"{path} (after: {label})")
        results.append((label, "NOT CAUGHT" if green else "caught", module))

    return results, unrestored


def main(argv: list[str]) -> int:
    in_place = "--in-place" in argv
    wanted = [a.lower() for a in argv[1:] if not a.startswith("--")]
    checks = [c for c in CHECKS
              if not wanted or any(w in c[0].lower() for w in wanted)]
    if not checks:
        print(f"no check matches {wanted}", file=sys.stderr)
        return 2

    if in_place:
        print("!! --in-place: editing the checkout. Anything else reading this "
              "tree -- a build, an editor, a running server -- will see "
              "deliberately broken files while this runs.", file=sys.stderr)
        tree, throwaway = REPO, None
    else:
        tree = sandbox(REPO)
        throwaway = tree.parent
        print(f"running in {tree}")

    try:
        results, unrestored = run_checks(checks, tree)
    finally:
        if throwaway is not None:
            shutil.rmtree(throwaway, ignore_errors=True)

    width = max(len(r[0]) for r in results)
    caught = sum(1 for _, status, _ in results if status == "caught")
    for label, status, module in results:
        tail = "" if status == "caught" else f"   <-- {module}"
        print(f"  {label:<{width}}  {status}{tail}")
    print(f"\n{caught}/{len(results)} reverts caught by the suite")

    # Only reachable with --in-place; in a sandbox the tree is deleted.
    if unrestored:
        print("\nWARNING: restore failed, these files are NOT as they were:",
              file=sys.stderr)
        print("\n".join(f"  {line}" for line in unrestored), file=sys.stderr)
        return 2

    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
