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


def collect(root: ET.Element) -> tuple[dict, dict, list[str], str, str]:
    namespace = {"c": root.tag.split("}")[0].strip("{")}
    names: dict[str, str] = {}
    aliases: dict[str, list[str]] = {}
    deprecated: list[str] = []

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

    unknown_aliases = sorted(set(EXTRA_ALIASES) - set(names))
    if unknown_aliases:
        raise SystemExit(f"EXTRA_ALIASES references unknown CWEs: {unknown_aliases}")

    return (
        names,
        aliases,
        deprecated,
        _checked_attribute(root.get("Version") or "?", "Version"),
        _checked_attribute(root.get("Date") or "?", "Date"),
    )


def render(root: ET.Element) -> str:
    namespace = {"c": root.tag.split("}")[0].strip("{")}
    names, aliases, deprecated, version, date = collect(root)

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
        "``NAMES`` maps every CWE ID (including deprecated ones, so historical",
        "advisory tags still render) to its official name. ``ALIASES`` adds the",
        "community terms people actually search for (IDOR, SSRF, XXE, ...).",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        f"CWE_VERSION = {version!r}",
        f"CWE_RELEASED = {date!r}",
        "",
        "NAMES: dict[str, str] = {",
    ]
    for cwe_id in sorted(names, key=key):
        lines.append(f"    {cwe_id!r}: {names[cwe_id]!r},")
    lines.append("}")
    lines.append("")
    lines.append("ALIASES: dict[str, tuple[str, ...]] = {")
    for cwe_id in sorted(aliases, key=key):
        lines.append(f"    {cwe_id!r}: {tuple(aliases[cwe_id])!r},")
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
    lines.append("DEPRECATED: frozenset[str] = frozenset({")
    for cwe_id in sorted(deprecated, key=key):
        lines.append(f"    {cwe_id!r},")
    lines.append("})")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    root = load_xml(sys.argv[1] if len(sys.argv) > 1 else None)
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
    OUT_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {OUT_PATH} ({len(text) / 1024:.1f} KiB)")


if __name__ == "__main__":
    main()
