#!/usr/bin/env python3
"""Regenerate modules/cwe_catalog.py from the official MITRE CWE XML catalog.

The catalog powers the CWE picker in the UI: the user types either an ID
("639") or a bug name ("IDOR", "SQL injection") and gets the matching CWEs.
That search runs client-side, so the whole ID -> name table ships to the
browser and must stay compact.

Usage:
    python tools/generate_cwe_catalog.py                 # download latest
    python tools/generate_cwe_catalog.py path/to.xml     # use a local copy

Source: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
"""

from __future__ import annotations

import io
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import write_atomic

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUT_PATH = Path(__file__).resolve().parent.parent / "modules" / "cwe_catalog.py"

# Abstraction levels worth offering in the picker, ordered from most to least
# specific. Advisories are tagged with Base/Variant CWEs most of the time;
# Class/Pillar entries are the vague umbrellas (CWE-284 and friends).
ABSTRACTIONS = ("Variant", "Base", "Compound", "Class", "Pillar")

# Version and Date are the only XML attributes that reach the generated file
# outside a repr() -- they are also interpolated into its module docstring,
# where a value containing a triple quote would close the docstring and the
# rest would be executed on import. repr() cannot help there, so these two are
# validated instead: anything that is not an ordinary version or date string
# is a tampered or corrupt catalog, and refusing is the only safe answer.
_SAFE_ATTRIBUTE = re.compile(r"[\w.\- :]{1,40}\Z")


def _checked_attribute(value: str, name: str) -> str:
    if not _SAFE_ATTRIBUTE.match(value or ""):
        raise SystemExit(
            f"refusing to generate: catalog {name} is not a plain "
            f"version/date string: {value!r}"
        )
    return value

# Community names that never appear in MITRE's own text but are what people
# actually type. Everything else comes from the catalog's Alternate_Terms.
EXTRA_ALIASES: dict[str, tuple[str, ...]] = {
    "22": ("path traversal", "directory traversal", "LFI", "zip slip"),
    "78": ("RCE", "shell injection"),
    "79": ("XSS",),
    "89": ("SQLi",),
    "94": ("RCE", "code execution"),
    "352": ("CSRF", "XSRF"),
    "434": ("file upload", "webshell"),
    "502": ("insecure deserialization", "unmarshal", "object injection"),
    "601": ("open redirect",),
    "611": ("XXE",),
    "862": ("BFLA", "missing authorization"),
    # BOLA and IDOR belong to CWE-639, which MITRE already tags with both in
    # its own Alternate_Terms; adding them here scored 863 as an exact alias
    # hit alongside 639, so searching "IDOR" surfaced the wrong weakness at
    # the same rank as the right one. 863 keeps only the generic term.
    "863": ("AuthZ",),
    "918": ("SSRF",),
    "1321": ("prototype pollution",),
    "1336": ("SSTI", "template injection"),
}


def load_xml(source: str | None) -> ET.Element:
    if source:
        return ET.parse(source).getroot()
    print(f"downloading {CWE_ZIP_URL} ...", file=sys.stderr)
    # A fixed https URL, not user input.
    with urllib.request.urlopen(CWE_ZIP_URL, timeout=120) as response:
        payload = response.read()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".xml"))
        return ET.fromstring(archive.read(name))


def split_terms(text: str) -> list[str]:
    """"Insecure Direct Object Reference / IDOR" -> both halves, separately."""
    return [part.strip() for part in text.split("/") if part.strip()]


def collect(root: ET.Element) -> tuple[dict, dict, list[str], list[str], str, str]:
    namespace = {"c": root.tag.split("}")[0].strip("{")}
    names: dict[str, str] = {}
    aliases: dict[str, list[str]] = {}
    deprecated: list[str] = []
    # Categories and Views. They carry a name so an advisory tagged with
    # one renders a label, and they are not weaknesses, so they have no
    # abstraction level and are never offered as a search target.
    non_weakness: list[str] = []

    weaknesses = root.findall("c:Weaknesses/c:Weakness", namespace)
    for weakness in weaknesses:
        cwe_id = weakness.get("ID") or ""
        name = (weakness.get("Name") or "").strip()
        if not cwe_id or not name:
            continue
        status = (weakness.get("Status") or "").strip()
        is_deprecated = status == "Deprecated" or name.upper().startswith("DEPRECATED")
        # Deprecated IDs stay in the name table so old advisory tags still
        # render a label, but they are hidden from the picker.
        names[cwe_id] = name
        if is_deprecated:
            deprecated.append(cwe_id)
            continue

        terms: list[str] = []
        for term in weakness.findall("c:Alternate_Terms/c:Alternate_Term/c:Term", namespace):
            terms.extend(split_terms(term.text or ""))
        terms.extend(EXTRA_ALIASES.get(cwe_id, ()))

        seen: set[str] = set()
        unique: list[str] = []
        for term in terms:
            # An alias already contained in the name adds nothing to search.
            if term.lower() in seen or term.lower() in name.lower():
                continue
            seen.add(term.lower())
            unique.append(term)
        if unique:
            aliases[cwe_id] = unique

    # Categories and Views, for their labels only.
    #
    # MITRE ships three kinds of entry and this read one of them, so an
    # advisory tagged with a Category id -- CWE-1035, "OWASP Top Ten 2017
    # Category A9" -- rendered as a bare "CWE-1035" in the UI and in every
    # CSV export, which looks like a missing label rather than the kind of
    # id it is.
    #
    # They are NOT search targets: a Category is a bucket, not a weakness,
    # and picker_catalog() builds its rows from ABSTRACTION, which only
    # Weakness entries have. So adding them here gives them a name without
    # offering them as something to search for.
    # CWE 5.0 renamed <Categories><Category> to <Groupings><Grouping>.
    # Both spellings are read, because the generator has to keep working
    # against an older XML a user may already have on disk -- and because
    # the failure mode of guessing one was silent: `findall` on a path that
    # no longer exists returns `[]`, which is indistinguishable from "this
    # release has none". The 5.0 regeneration therefore dropped all 431
    # Groupings, kept the 62 Views, and reported success. `_require_any`
    # below turns that silence into an error.
    found_non_weakness = 0
    for path in ("c:Groupings/c:Grouping", "c:Categories/c:Category",
                 "c:Views/c:View"):
        for entry in root.findall(path, namespace):
            found_non_weakness += 1
            entry_id = entry.get("ID") or ""
            name = (entry.get("Name") or "").strip()
            if not entry_id or not name or entry_id in names:
                continue
            status = (entry.get("Status") or "").strip()
            names[entry_id] = name
            non_weakness.append(entry_id)
            if status == "Deprecated" or name.upper().startswith("DEPRECATED"):
                deprecated.append(entry_id)

    unknown_aliases = sorted(set(EXTRA_ALIASES) - set(names))
    if unknown_aliases:
        raise SystemExit(f"EXTRA_ALIASES references unknown CWEs: {unknown_aliases}")

    # Every real CWE release carries hundreds of these, so zero means the
    # element was renamed again rather than emptied. Scoped to a catalog
    # big enough to be a real one: the unit fixtures are a handful of
    # <Weakness> elements with no Groupings at all, and that is legitimate.
    if len(weaknesses) >= 100 and found_non_weakness < 100:
        raise SystemExit(
            f"only {found_non_weakness} Grouping/Category/View entries were "
            f"found; the catalog has always had hundreds. The element was "
            f"most likely renamed again -- check the top-level children of "
            f"<Weakness_Catalog>: "
            f"{[child.tag.split('}')[-1] for child in root]}")

    return (
        names,
        aliases,
        deprecated,
        non_weakness,
        _checked_attribute(root.get("Version") or "?", "Version"),
        _checked_attribute(root.get("Date") or "?", "Date"),
    )


def render(root: ET.Element) -> str:
    namespace = {"c": root.tag.split("}")[0].strip("{")}
    names, aliases, deprecated, non_weakness, version, date = collect(root)

    abstraction_by_id = {
        (weakness.get("ID") or ""): (weakness.get("Abstraction") or "")
        for weakness in root.findall("c:Weaknesses/c:Weakness", namespace)
    }
    by_abstraction: dict[str, list[str]] = {}
    for cwe_id in names:
        if cwe_id in deprecated:
            continue
        level = abstraction_by_id.get(cwe_id, "")
        if level in ABSTRACTIONS:
            by_abstraction.setdefault(level, []).append(cwe_id)

    def key(cwe_id: str) -> int:
        return int(cwe_id)

    lines = [
        '"""Full MITRE CWE weakness catalog — GENERATED FILE, DO NOT EDIT BY HAND.',
        "",
        f"Source: CWE {version} ({date}) from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "Regenerate with: python tools/generate_cwe_catalog.py",
        "",
        "``NAMES`` maps every CWE ID to its official name: Weaknesses, and",
        "also Categories and Views, so an advisory tagged with one of those",
        "renders a label instead of a bare id. Deprecated ids are kept for",
        "the same reason. Only Weaknesses are offered in the picker.",
        "",
        "``ALIASES`` adds the community terms people actually search for",
        "(IDOR, SSRF, XXE, ...).",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        f"CWE_VERSION = {version!r}",
        f"CWE_RELEASED = {date!r}",
        "",
        "NAMES: dict[str, str] = {",
    ]
    lines.extend(f"    {cwe_id!r}: {names[cwe_id]!r},"
                 for cwe_id in sorted(names, key=key))
    lines.append("}")
    lines.append("")
    lines.append("ALIASES: dict[str, tuple[str, ...]] = {")
    lines.extend(f"    {cwe_id!r}: {tuple(aliases[cwe_id])!r},"
                 for cwe_id in sorted(aliases, key=key))
    lines.append("}")
    lines.append("")
    lines.append("# Abstraction level, shown in the picker so an umbrella CWE is obvious.")
    lines.append("ABSTRACTION: dict[str, tuple[str, ...]] = {")
    for level in ABSTRACTIONS:
        ids = tuple(sorted(by_abstraction.get(level, []), key=key))
        # repr() of a tuple, not a hand-built "(a, b,)": an abstraction level
        # with no members used to emit "(,)", which is a SyntaxError, and
        # main() wrote the file before anything checked it -- so a filtered or
        # future catalog would brick `import app` on the next start.
        lines.append(f"    {level!r}: {ids!r},")
    lines.append("}")
    lines.append("")
    lines.append("# Categories and Views: named so a tag renders a label, and")
    lines.append("# deliberately absent from ABSTRACTION so the picker never offers")
    lines.append("# them -- a bucket is not a weakness you can search for.")
    lines.append("NON_WEAKNESS: frozenset[str] = frozenset({")
    lines.extend(f"    {cwe_id!r}," for cwe_id in sorted(non_weakness, key=key))
    lines.append("})")
    lines.append("")
    lines.append("DEPRECATED: frozenset[str] = frozenset({")
    lines.extend(f"    {cwe_id!r}," for cwe_id in sorted(deprecated, key=key))
    lines.append("})")
    lines.append("")
    return "\n".join(lines)


# The smallest catalog worth writing. MITRE ships ~940 weaknesses and the
# curated classes reference ~150 ids; a filtered, truncated or partially
# downloaded XML would otherwise be compiled, written, and only noticed on
# the next CI run -- after the file the server imports had been replaced.
MIN_WEAKNESSES = 800


def _check_catalog(names: dict, aliases: dict, deprecated: list[str]) -> None:
    """Refuse a catalog that is materially smaller or missing the ids the
    curated classes depend on.

    compile() proves the output is valid Python, which is not the same as
    proving it is a usable catalog. A deprecated EXTRA_ALIASES entry drops
    its aliases silently -- searching "XXE" or "SSRF" simply stops working
    -- and nothing checked the ~150 ids that modules/cwe_categories.py
    hard-codes.
    """
    if len(names) < MIN_WEAKNESSES:
        raise SystemExit(
            f"refusing to write: only {len(names)} weaknesses parsed, "
            f"expected at least {MIN_WEAKNESSES}. Is the XML truncated?")

    sys.path.insert(0, str(OUT_PATH.parent.parent))
    try:
        from modules.cwe_categories import CATEGORIES
    except Exception as exc:                       # pragma: no cover
        print(f"note: could not cross-check the curated classes ({exc})",
              file=sys.stderr)
        return

    curated = {cwe_id for spec in CATEGORIES.values()
               for cwe_id in (*spec["core"], *spec["extended"])}
    missing = sorted(curated - set(names), key=lambda value: int(value))
    if missing:
        raise SystemExit(
            f"refusing to write: {len(missing)} CWE(s) the curated classes "
            f"use are absent from this catalog: {missing[:10]}")

    # A curated id that still exists but has been RETIRED upstream is the
    # case that got through: CWE 5.0 deprecated 613 and split it into
    # 1462-1467, and "is it in names?" said yes. Warned rather than
    # refused -- the catalog is correct, it is the curated class that now
    # needs a decision, and refusing to write would leave the operator
    # with no catalog at all.
    retired = sorted((cwe_id for cwe_id in curated if cwe_id in deprecated),
                     key=lambda value: int(value))
    if retired:
        print(f"warning: {len(retired)} curated CWE(s) are deprecated in this "
              f"catalog and should be repointed at their successors: "
              f"{retired}", file=sys.stderr)

    lost = sorted(cwe_id for cwe_id in EXTRA_ALIASES if cwe_id not in aliases)
    if lost:
        print(f"warning: EXTRA_ALIASES for {lost} did not survive -- those "
              f"ids are deprecated in this catalog, so their community "
              f"terms will no longer match.", file=sys.stderr)


def main() -> None:
    root = load_xml(sys.argv[1] if len(sys.argv) > 1 else None)
    names, aliases, _deprecated, _non_weakness, _version, _date = collect(root)
    _check_catalog(names, aliases, _deprecated)
    text = render(root)
    # This file writes Python that modules/cwe_categories.py imports, which
    # every client imports in turn -- so anything that lands here runs inside
    # the server at startup. Never write a module that does not compile, and
    # never write one built from values that were not repr()'d above.
    try:
        compile(text, str(OUT_PATH), "exec")
    except SyntaxError as exc:
        raise SystemExit(
            f"refusing to write {OUT_PATH}: generated module does not compile "
            f"({exc.msg} at line {exc.lineno})"
        ) from exc
    write_atomic(OUT_PATH, text)
    print(f"wrote {OUT_PATH} ({len(text) / 1024:.1f} KiB)")


if __name__ == "__main__":
    main()
