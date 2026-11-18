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

A whole run publishes what it measured to docs/revert-results.json, which
`tools/sync_check_counts.py` quotes and `tests/test_docs.py` checks. That
makes adding or removing a check a two-pass operation: the first run is
against a tree whose recorded figure is stale, so the modules that assert
on it are legitimately red and their own checks come back BASELINE RED.
Run it again after committing the new results and they measure normally.
Two runs is the honest cost of a document that quotes a measurement rather
than asserting one.
"""
from __future__ import annotations

import fnmatch
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
# The interpreter already running this harness, not one resolved inside the
# tree under test. `REPO/.venv/bin/python` is correct in a real checkout and
# absent in a sandbox copy, because `.venv` is deliberately not copied -- so
# a nested run (which tests/test_cleanup_stays_clean.py performs, to prove
# the harness never edits the checkout) died with FileNotFoundError before
# reaching its first check. That made test_cleanup_stays_clean permanently
# red inside a sandbox, and under the old scoring every one of the 15 checks
# routed to it reported `caught` without being measured. They were counted
# in the "129/129" this tool used to print.
PY = sys.executable

# Copied into the sandbox; everything else is build output, caches, or
# large downloads that no check reads.
SKIP = {".git", ".venv", "node_modules", "__pycache__", "osv_cache",
        ".coverage", "htmlcov", ".ruff_cache", ".pytest_cache",
        # Secrets. copytree preserved the 0600 mode, so this was never a
        # world-readable leak, but it put the operator's live GitHub and AI
        # credentials in /tmp on every run -- and the cleanup is a `finally`
        # that a SIGKILL skips. It also meant the sandboxed suite ran with
        # the real keys in os.environ (modules/config.py calls load_dotenv at
        # import) while the code under test was deliberately broken, so a
        # check that reverts a redaction could print a live key.
        ".env", ".vulnsight_api_token", ".ai_key_cooldown.json"}
SKIP_GLOBS = ("*.db*", ".env.*")
# ...except the tracked, secret-free templates. `.env.*` on its own also
# matched `.env.example`, which three test modules read -- so the sandbox
# suite went red before any revert was applied, and every check routed to
# those modules would have been scored `caught` by a harness that could not
# tell "red because of the revert" from "red already".
SKIP_EXCEPTIONS = {".env.example", ".env.sample", ".env.template"}

# The checks themselves live in tools/checks/, one module per area, so that
# two people adding checks at once do not collide in a single long list.
# See tools/checks/__init__.py for the shape of an entry and the rule that
# a fix guarded in two places must be reverted in one entry.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools.checks import all_checks  # noqa: E402  (needs the path above)

CHECKS = all_checks()

# What the last whole-battery run actually measured.
RESULTS_PATH = REPO / "docs" / "revert-results.json"


def _ignore(_dir: str, names: list[str]) -> set[str]:
    return {n for n in names
            if n not in SKIP_EXCEPTIONS
            and (n in SKIP
                 or any(fnmatch.fnmatch(n, pattern) for pattern in SKIP_GLOBS))}


def apply_edits(
    originals: dict[str, str],
    edits: list[tuple[str, str, str]],
) -> tuple[dict[str, str], tuple[str, str] | None]:
    """Apply one check's edits, or name the first anchor that is not there.

    Two things this gets right that the inline version did not.

    Each anchor is re-checked against the text *as it now stands*. The
    caller's pre-check reads the original file while the replacements apply
    cumulatively, so when edit 1 consumed or altered edit 2's anchor,
    `str.replace` returned the string unchanged and nothing said so -- a
    half-applied revert scored as a pass. `tools/checks/__init__.py` warns
    about exactly that consequence and nothing enforced it.

    And every occurrence is replaced, not the first. A fix applied in three
    places is not reverted by undoing one of them: the behaviour stays
    correct and the check reports NOT CAUGHT for a guard that is sound.
    Two live checks have that shape -- `if sort_field == "cve_id":` occurs
    three times in search_service.py, and `"maxItems":
    MAX_CATEGORY_INPUTS,` twice in openapi.py.
    """
    patched = dict(originals)
    for path, find, replace in edits:
        if find not in patched[path]:
            return patched, (path, find)
        patched[path] = patched[path].replace(find, replace)
    return patched, None


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
    """Apply each revert in *tree*, run its module, restore, record.

    Each module is run once *unpatched* first. Without that the harness
    could only observe "red after the revert", which is also what an
    already-failing module looks like -- so every check routed to a red
    module reported `caught`, and the tool printed "N/N reverts caught by
    the suite", which is the one claim it exists to make. A revert whose
    replacement text breaks an import does the same thing: every test in the
    module errors, the suite is red, and the harness calls it a pass.
    """
    results: list[tuple[str, str, str]] = []
    unrestored: list[str] = []
    baseline: dict[str, bool] = {}

    for label, edits, module in checks:
        if module not in baseline:
            baseline[module] = suite_is_green(module, tree)
        if not baseline[module]:
            results.append((label, "BASELINE RED", module))
            continue
        originals = {path: (tree / path).read_text(encoding="utf-8")
                     for path, _, _ in edits}
        if any(find not in originals[path] for path, find, _ in edits):
            results.append((label, "ANCHOR MISSING", module))
            continue

        try:
            # Each anchor is re-checked against the text as it now stands,
            # not against the original.
            #
            # The pre-check above reads `originals` while the replacements
            # below apply cumulatively, so if edit 1 consumed or altered
            # edit 2's anchor, `str.replace` returned the string unchanged
            # and nothing said so -- a half-applied revert scored as a
            # pass. tools/checks/__init__.py warns about exactly that
            # consequence ("reverting either alone leaves the behaviour
            # correct and the check reports a false pass") and nothing
            # enforced it. Several checks have two edits on one file.
            patched, stale = apply_edits(originals, edits)
            if stale is not None:
                results.append((label, "ANCHOR MISSING", module))
                continue
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

    results_are_partial = len(checks) != len(CHECKS)
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

    # Published so docs/review-dispositions.md can quote a measurement
    # instead of an assertion. sync_check_counts.py used to write
    # "**N/N caught**" unconditionally -- the document's strongest evidence
    # row was generated to read as a perfect score whether or not anything
    # had ever been run. A partial run (a label filter) is not evidence
    # about the whole battery, so it does not publish.
    if not wanted and not results_are_partial:
        RESULTS_PATH.write_text(json.dumps({
            "checked": len(results),
            "caught": caught,
            "baseline_red": sum(1 for _, s, _ in results if s == "BASELINE RED"),
            "anchor_missing": sum(1 for _, s, _ in results if s == "ANCHOR MISSING"),
            "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {RESULTS_PATH.relative_to(REPO)}")

    # Only reachable with --in-place; in a sandbox the tree is deleted.
    if unrestored:
        print("\nWARNING: restore failed, these files are NOT as they were:",
              file=sys.stderr)
        print("\n".join(f"  {line}" for line in unrestored), file=sys.stderr)
        return 2

    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
