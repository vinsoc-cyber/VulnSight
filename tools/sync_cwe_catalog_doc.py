#!/usr/bin/env python3
"""Rewrite the derived figures in docs/cwe-catalog.md.

That page states the catalog's version, how many weaknesses it holds, how
many the picker offers, how many carry aliases and how large the generated
module is. All of it was hand-typed, and all of it went stale the moment
`tools/generate_cwe_catalog.py` was run: a regeneration from CWE 4.20 to
5.0 left the page describing a catalog that was no longer shipped, down to
a sentence claiming the generator "excludes Views and Categories" after it
had started including them.

    python tools/sync_cwe_catalog_doc.py          # rewrite
    python tools/sync_cwe_catalog_doc.py --check  # report drift, change nothing

It covers docs/cwe-catalog.md, README.md and docs/usage.md, because the
picker count and the CWE release are quoted on all three.

Prose is never touched; only the numbers are derived. A figure the page
stops stating is reported rather than silently dropped, because a document
that quietly stops carrying its evidence is the failure this whole family
of tools exists to prevent.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import write_atomic  # noqa: E402

CATALOG = ROOT / "modules" / "cwe_catalog.py"

# The same two figures -- how many weaknesses the picker offers, and which
# CWE release they come from -- are quoted on three pages. One generator
# owns them wherever they appear, because the version that went stale here
# went stale identically in the README and in the usage guide, and fixing
# three copies by hand is how they drifted apart in the first place.
DOCS = (
    ROOT / "docs" / "cwe-catalog.md",
    ROOT / "README.md",
    ROOT / "docs" / "usage.md",
)


def figures() -> dict[str, str]:
    """Every derived figure on the page, read from the shipped catalog."""
    from modules.cwe_catalog import (
        ALIASES,
        CWE_RELEASED,
        CWE_VERSION,
        DEPRECATED,
        NAMES,
        NON_WEAKNESS,
    )
    from modules.cwe_categories import CATEGORIES, picker_catalog

    weaknesses = set(NAMES) - set(NON_WEAKNESS)
    rows = picker_catalog()["rows"]
    return {
        "version": CWE_VERSION,
        "released": CWE_RELEASED,
        "weaknesses": str(len(weaknesses)),
        "deprecated": str(len(DEPRECATED)),
        "picker": str(len(rows)),
        "aliased": str(len(ALIASES)),
        "kib": str(round(CATALOG.stat().st_size / 1024)),
        "classes": str(len(CATEGORIES)),
        "buckets": str(len(NON_WEAKNESS)),
    }


# Each pattern captures the figure and nothing else, so the prose around it
# is preserved exactly.
PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("version", r"(?<=CWE \*\*)[\d.]+(?=\*\* \(released)", "{version}"),
    ("released", r"(?<=\*\* \(released )[\d-]+(?=\))", "{released}"),
    ("weaknesses", r"(?<=\| Weaknesses \| \*\*)\d+(?=\*\*)", "{weaknesses}"),
    ("deprecated", r"(?<=\*\* total; )\d+(?= deprecated)", "{deprecated}"),
    ("buckets", r"(?<=\| Groupings and Views \| \*\*)\d+(?=\*\*)", "{buckets}"),
    ("picker", r"(?<=\| Offered in the picker \| \*\*)\d+(?=\*\*)", "{picker}"),
    ("aliased", r"(?<=\| With community aliases \| )\d+(?= \|)", "{aliased}"),
    ("kib", r"(?<=\| File size \| ~)\d+(?= KiB)", "{kib}"),
    ("rows", r"(?<=across )\d+(?= rows plus )", "{picker}"),
    ("classes", r"(?<=rows plus )\d+(?= classes)", "{classes}"),
    ("json_version", r'(?<="version": ")[\d.]+(?=")', "{version}"),
    # README.md and docs/usage.md: "**944 weaknesses of CWE 4.20**".
    ("offered_prose", r"(?<=\*\*)\d+(?= weaknesses of CWE )", "{picker}"),
    ("version_prose", r"(?<= weaknesses of CWE )[\d.]+(?=\*\*)", "{version}"),
    # README.md: "Where the 944 CWEs come from".
    ("offered_link", r"(?<=Where the )\d+(?= CWEs come from)", "{picker}"),
)


def main(argv: list[str]) -> int:
    values = figures()
    drift: list[str] = []
    pending: dict[pathlib.Path, str] = {}
    seen: set[str] = set()

    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        for name, pattern, template in PATTERNS:
            want = template.format(**values)

            def replace(match: re.Match[str], name=name, want=want,
                        doc=doc) -> str:
                if match.group(0) != want:
                    drift.append(f"{doc.name}: {name} says "
                                 f"{match.group(0)}, it is {want}")
                return want

            text, hits = re.subn(pattern, replace, text)
            if hits:
                seen.add(name)
        pending[doc] = text

    # Every figure has to be carried by at least one page. A figure that
    # has vanished everywhere is a document that quietly stopped stating
    # its evidence, which is the failure this family of tools exists for.
    for name, _pattern, _template in PATTERNS:
        if name not in seen:
            drift.append(f"{name}: no page states this figure any more")

    if not drift:
        print("the CWE catalog figures in the docs are already accurate")
        return 0
    for line in drift:
        print(line)
    missing = [line for line in drift if "no page states" in line]
    if "--check" in argv:
        return 1
    written = 0
    for doc, text in pending.items():
        if text != doc.read_text(encoding="utf-8"):
            write_atomic(doc, text)
            written += 1
    print(f"\nrewrote {len(drift) - len(missing)} figure(s) across "
          f"{written} file(s)")
    return 2 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
