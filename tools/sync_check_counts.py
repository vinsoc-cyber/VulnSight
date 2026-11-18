#!/usr/bin/env python3
"""Rewrite the revert-check figures in the docs, and the index of them.

`docs/review-dispositions.md` offers "N/N caught" as its evidence and
`docs/testing.md` says the harness guards "N named bugs". Both were typed by
hand, so adding a check left the strongest claim in those documents as the
least trustworthy number in them.

It also writes an index of every check, grouped, into the dispositions page.
A disposition table is the author's account of their own work; an index of
executable checks beside it is something a reader can run.

    python tools/sync_check_counts.py          # rewrite
    python tools/sync_check_counts.py --check  # report drift, change nothing
"""

from __future__ import annotations

import pathlib
import json
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import write_atomic  # noqa: E402

from tools.checks import GROUPS  # noqa: E402  (needs the path above)

DISPOSITIONS = ROOT / "docs" / "review-dispositions.md"
TESTING = ROOT / "docs" / "testing.md"
TESTS = ROOT / "tests"
# What the last whole-battery revert run measured. Written by
# tools/revert_checks.py; this tool quotes it and refuses to invent it.
RESULTS_PATH = ROOT / "docs" / "revert-results.json"

BEGIN = "<!-- begin generated check index -->"
END = "<!-- end generated check index -->"

# Group key -> the heading it appears under in the index.
TITLES = {
    "core": "First pass: security, merge, sources, taxonomy, docs",
    "runtime": "HTTP layer, jobs, cache, config, AI classifier",
    "search": "Search pipeline and source clients",
    "frontend": "CWE taxonomy and the browser code",
    "cleanup": "Removals, extractions and caches (property-asserted)",
}


def read_results() -> dict | None:
    """What `tools/revert_checks.py` recorded on its last whole-battery run.

    None when there is no such record, which is not the same as zero: the
    caller must refuse to write a figure rather than invent one.
    """
    try:
        data = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not all(isinstance(data.get(k), int) for k in ("checked", "caught")):
        return None
    return data


def suite_size() -> int:
    return sum(
        len(re.findall(r"^    def test_", path.read_text(encoding="utf-8"), re.M))
        for path in sorted(TESTS.glob("test_*.py"))
    )


def render_index(total: int) -> str:
    lines = [
        BEGIN,
        "",
        f"## The {total} checks, by area",
        "",
        "Generated from `tools/checks/` by `tools/sync_check_counts.py`; a",
        "test fails if it drifts. Each line is a bug that was really in this",
        "codebase and the test module that now refuses to let it back in.",
        "",
    ]
    for key, checks in GROUPS.items():
        lines.append(f"### {TITLES.get(key, key)} ({len(checks)})")
        lines.append("")
        lines.append("| Reverting this | is caught by |")
        lines.append("|---|---|")
        for label, _edits, module in checks:
            lines.append(f"| {label} | `tests/{module}.py` |")
        lines.append("")
    lines.append(END)
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    total = sum(len(c) for c in GROUPS.values())
    tests = suite_size()
    drift: list[str] = []

    def rewrite(text: str, name: str) -> str:
        """Replace the derived figures in one document.

        Named rather than nested in the loop: closing over the loop variable
        is the shape of a late-binding bug even where it happens to work.
        """
        def fix_named(match: re.Match[str]) -> str:
            if int(match.group(1)) != total:
                drift.append(f"{name}: says {match.group(1)} named bugs, "
                             f"there are {total}")
            return f"{total} named bugs"

        def fix_caught(match: re.Match[str]) -> str:
            """Write what the last whole-battery run measured.

            This used to return f"**{total}/{total} caught**" whatever the
            document said and whatever had happened -- so the strongest
            evidence row in docs/review-dispositions.md was generated to
            read as a perfect score, by a tool that has never run a single
            check. Three checks could start failing and `--check` would stay
            green on a figure the generator itself had invented.
            """
            measured = read_results()
            if measured is None:
                drift.append(
                    f"{name}: no measurement to quote. Run "
                    "`python tools/revert_checks.py` (whole battery, no "
                    "label filter) and commit docs/revert-results.json.")
                return match.group(0)
            if measured["checked"] != total:
                drift.append(
                    f"{name}: the recorded run covered {measured['checked']} "
                    f"check(s), there are now {total}. Re-run the battery.")
                return match.group(0)
            caught = measured["caught"]
            if (int(match.group(1)), int(match.group(2))) != (caught, total):
                drift.append(f"{name}: claims {match.group(1)}/"
                             f"{match.group(2)} caught, the run measured "
                             f"{caught}/{total}")
            return f"**{caught}/{total} caught**"

        def fix_pass(match: re.Match[str]) -> str:
            if int(match.group(1)) != tests:
                drift.append(f"{name}: states {match.group(1)} passing tests, "
                             f"the suite has {tests}")
            return f"| {tests} pass |"

        # subn, not sub: an anchor that has been reworded or deleted used to
        # match nothing, leave `drift` empty, and make --check report success
        # on a document that no longer carries any derived figure at all.
        for pattern, repl, what in (
            (r"(\d+) named bugs", fix_named, "'N named bugs'"),
            (r"\*\*(\d+)/(\d+) caught\*\*", fix_caught, "'**N/N caught**'"),
            (r"\| (\d+) pass \|", fix_pass, "'| N pass |'"),
        ):
            text, hits = re.subn(pattern, repl, text)
            if not hits and name == DISPOSITIONS.name:
                drift.append(f"{name}: no {what} figure left to update")
        return text

    for path in (DISPOSITIONS, TESTING):
        original = path.read_text(encoding="utf-8")
        text = rewrite(original, path.name)

        if path is DISPOSITIONS:
            index = render_index(total)
            if BEGIN in text and END in text:
                current = text[text.index(BEGIN):text.index(END) + len(END)]
                if current != index:
                    drift.append(f"{path.name}: the check index is out of date")
                text = text.replace(current, index, 1)
            else:
                drift.append(f"{path.name}: adding the check index")
                text = text.rstrip("\n") + "\n\n" + index + "\n"

        if text != original and "--check" not in argv:
            write_atomic(path, text)

    if not drift:
        print("the revert-check figures in the docs are already accurate")
        return 0
    for line in drift:
        print(line)
    if "--check" in argv:
        return 1
    print(f"\nrewrote {len(drift)} figure(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
