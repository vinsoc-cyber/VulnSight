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

# (label, [(file, find, replace-with), ...], test module)
#
# A check may carry several edits. Some fixes are deliberately defended in
# two places -- the cooldown below is maxed both where it is computed and
# where it is written -- and reverting one at a time proves nothing, because
# the other half still holds. For those, revert the whole fix at once.
Edit = tuple[str, str, str]
CHECKS: list[tuple[str, list[Edit], str]] = [
    (
        "bind guard trusts HOST again",
        [("modules/security.py",
          "    if _declared_bind is not None:\n        return _declared_bind",
          "    if _declared_bind is not None:\n        return _declared_bind\n"
          '    return os.environ.get("HOST", "127.0.0.1")')],
        "test_security",
    ),
    (
        "merge promotes the last severity, not the worst",
        [("modules/search_service.py",
          "        source: canonical_severity(max(\n"
          '            (record.get("severity") or "unknown" for record in group),\n'
          "            key=_severity_rank,\n"
          "        ))\n        for source, group in source_records.items()",
          '        record.get("source", "?"): canonical_severity(record.get("severity"))\n'
          "        for record in records")],
        "test_search_service",
    ),
    (
        "one bad record sinks the GHSA batch again",
        [("modules/search_service.py",
          "            g, skipped = records_mod.normalize_all(",
          "            g, skipped = (lambda rs, fn, **kw: ([fn(r) for r in rs], 0))(")],
        "test_search_service",
    ),
    (
        "prompt fence removed",
        [("modules/ai_classifier.py",
          '    text = text.replace(_FENCE_OPEN, "").replace(_FENCE_CLOSE, "")',
          "    pass")],
        "test_ai_classifier",
    ),
    (
        "catalog generator stops validating Version",
        [("tools/generate_cwe_catalog.py",
          '    if not _SAFE_ATTRIBUTE.match(value or ""):',
          "    if False:")],
        "test_generate_cwe_catalog",
    ),
    (
        # Both halves at once. mark_skip_token passes the already-maxed
        # deadline AND _persist_cooldown maxes again; either one alone keeps
        # the behaviour correct, so a single-edit revert reports a false pass.
        "cooldown overwrites instead of taking the max",
        [("modules/ai_classifier.py",
          "                        self._persist_cooldown(value, deadline - now)",
          "                        self._persist_cooldown(value, seconds)"),
         ("modules/ai_classifier.py",
          "            state[fingerprint] = max(state.get(fingerprint, 0.0),\n"
          "                                     time.time() + seconds)",
          "            state[fingerprint] = time.time() + seconds")],
        "test_ai_classifier",
    ),
    (
        "migrations stamped even when they fail",
        [("modules/cache.py",
          "                    if not _is_benign_migration_error(str(exc)):\n                        raise",
          "                    pass")],
        "test_cache",
    ),
    (
        "job reconciliation ignores the owner again",
        [("modules/cache.py",
          '            if not _owner_is_alive(row["owner"], row["created_at"], now)',
          "            if True")],
        "test_jobs",
    ),
    (
        "cve_id sorts as text",
        [("modules/search_service.py",
          '        if sort_field == "cve_id":',
          "        if False:")],
        "test_search_service",
    ),
    (
        "severity synonyms stop folding",
        [("modules/search_service.py",
          "    mapped = _SEVERITY_SYNONYMS.get(text)\n    if mapped:\n        return mapped",
          "    pass")],
        "test_search_service",
    ),
    (
        "NVD windows overlap again",
        [("modules/nvd_client.py",
          "        cursor_end = cursor_start - timedelta(days=1)",
          "        cursor_end = cursor_start - timedelta(milliseconds=1)")],
        "test_nvd_client",
    ),
    (
        "GHSA pagination breaks on the wrong Link header",
        [("modules/ghsa_client.py",
          "        m = _LINK_NEXT_RE.search(line)\n        if m:\n            next_url = m.group(1)\n            break",
          "        m = _LINK_NEXT_RE.search(line)\n        if m:\n            next_url = m.group(1)\n        break")],
        "test_ghsa_client",
    ),
    (
        "GHSA cursor trusted again",
        [("modules/ghsa_client.py",
          '    if not path.startswith("/advisories"):',
          "    if False:")],
        "test_ghsa_client",
    ),
    (
        "OSV load lock removed",
        [("modules/osv_client.py",
          "    with _load_lock(ghsa_ecosystem):",
          "    if True:")],
        "test_osv_client",
    ),
    (
        "OSV cache path stops being validated",
        [("modules/osv_client.py",
          '    safe = re.sub(r"[^A-Za-z0-9._-]", "_", osv_eco).strip(".")',
          '    safe = osv_eco.replace("/", "_").replace(" ", "_")')],
        "test_osv_client",
    ),
    (
        "auth falls back to a path prefix",
        [("app.py",
          "        if request.endpoint in _UNAUTHENTICATED_ENDPOINTS:\n            return None",
          '        if not request.path.startswith("/api/"):\n            return None')],
        "test_app",
    ),
    (
        "classify defaults a missing category to bac",
        [("app.py",
          "                if not isinstance(single, str) or not single.strip():",
          "                if False:")],
        "test_app",
    ),
    (
        "taxonomy regressions (CWE-913 back in bac)",
        [("modules/cwe_categories.py",
          '            "276",  # Incorrect Default Permissions',
          '            "913",')],
        "test_cwe_categories",
    ),
    (
        "bare 'bypass' keyword returns",
        [("modules/cwe_categories.py",
          '        "authorization bypass", "authorisation bypass", "access control bypass",',
          '        "bypass",')],
        "test_cwe_categories",
    ),
    (
        "verdict fingerprint drops base_url",
        [("modules/ai_classifier.py", '        "base_url": cfg.base_url,', "")],
        "test_ai_classifier",
    ),
    (
        "verdict shape stops being uniform",
        [("modules/ai_classifier.py",
          '    aggregate.setdefault("matched_category", None)',
          "    pass")],
        "test_ai_classifier",
    ),
    (
        "module map rewrite eats the newline before the closing fence",
        [("tools/sync_module_map.py",
          r'(\S.*?)[^\S\n]*$", re.M)',
          r'(\S.*?)\s*$", re.M)')],
        "test_doc_sync_tools",
    ),
    (
        "testing-doc counts stop being derived",
        [("tools/sync_testing_doc.py",
          "        if int(claimed) != actual[name]:",
          "        if False:")],
        "test_doc_sync_tools",
    ),
    (
        "module-map drift test stops deriving",
        [("docs/architecture.md", "app.py                ", "app.py                1 ")],
        "test_docs",
    ),
]


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
