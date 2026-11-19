"""Checks for the second hardening pass over docs/open-findings.md.

The first pass (tools/checks/hardening.py) closed the availability,
correctness and cost findings. This one covers what was left: the
deployment surface, the published API contract, the tools that could report
success without measuring, and the smaller verified defects.

See tools/checks/__init__.py for the shape of an entry.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    # --- deployment ------------------------------------------------------
    (
        "the image makes its own source writable by the runtime user",
        [("Dockerfile",
          "    && chown -R vulnsight:vulnsight /data",
          "    && chown -R vulnsight:vulnsight /app /data")],
        "test_deployment",
    ),
    (
        "dependencies go back to floating ranges",
        [("requirements.txt", "Flask==3.1.3", "Flask>=3.1.2,<4")],
        "test_deployment",
    ),
    (
        "run.sh swallows the failure of its one credential check",
        [("run.sh",
          "  if ! chmod 600 .env 2>/dev/null; then",
          "  chmod 600 .env 2>/dev/null || true\n  if false; then")],
        "test_deployment",
    ),
    (
        "the credential check moves back behind the slow work",
        # The whole guard has to move below the install, which is where it
        # was. Swapping two neighbouring lines leaves it in front and the
        # check correctly reports NOT CAUGHT.
        [("run.sh",
          "# Before anything slow. A readable credentials file is a reason to stop,",
          "# MOVED-BELOW-INSTALL\npip install -q -r requirements.txt\n"
          "# Before anything slow. A readable credentials file is a reason to stop,")],
        "test_deployment",
    ),

    # --- the published contract ------------------------------------------
    (
        "the OpenAPI document stops using its own components",
        [("modules/openapi.py",
          '    return {"$ref": f"#/components/schemas/{name}"} if name else schema',
          "    return schema")],
        "test_openapi",
    ),
    (
        "the spec claims /ai/test takes no body again",
        [("modules/openapi.py",
          '                    "requestBody": _json_body({"type": "object"}),',
          '                    "requestBody": _json_body({"type": "object"}, required=False),')],
        "test_openapi",
    ),
    (
        # Two edits, because one is not the defect. Replacing the import
        # with the literal 100 changes nothing while the constant is 100 --
        # the failure is that raising the constant then leaves the
        # published contract saying the old number, so the revert has to do
        # both halves to reproduce it.
        "the spec restates a limit instead of importing it",
        [("modules/openapi.py",
          '            "maxItems": MAX_CATEGORY_INPUTS,',
          '            "maxItems": 100,'),
         ("modules/search_service.py",
          "MAX_CATEGORY_INPUTS = 100",
          "MAX_CATEGORY_INPUTS = 150")],
        "test_openapi",
    ),
    (
        "a 415 from the shared body helper goes back undocumented",
        [("modules/openapi.py",
          '                        # Same `_json_object` helper as /search and /jobs,\n'
          '                        # which both list it.\n'
          '                        "415": _ERROR_RESPONSE,\n',
          "")],
        "test_openapi",
    ),

    # --- tooling that must not pass without measuring --------------------
    (
        "the test auditor stops detecting a self-fulfilling test",
        [("tools/audit_tests.py",
          "            and not _references_anything_outside(fn, imported, helpers)):",
          "            and False):")],
        "test_cleanup_stays_clean",
    ),
    (
        "the test auditor stops detecting a recomputed expectation",
        [("tools/audit_tests.py",
          "        if _is_computed(node.args[0]) and _is_computed(node.args[1]):",
          "        if False:")],
        "test_cleanup_stays_clean",
    ),
    (
        "the test auditor reports a clean sweep of nothing",
        # Both floors. Removing the file-count one alone still leaves the
        # method-count one, which returns 2 on an empty directory -- so a
        # single-edit revert reported NOT CAUGHT, correctly.
        [("tools/audit_tests.py",
          "    if len(files) < 5:",
          "    if False:"),
         ("tools/audit_tests.py",
          "    if counted < 50:",
          "    if False:")],
        "test_cleanup_stays_clean",
    ),
    (
        "write_atomic narrows every file it touches to 0600",
        [("tools/__init__.py",
          "        if path.exists():\n            shutil.copymode(path, tmp)",
          "        if False:\n            shutil.copymode(path, tmp)")],
        "test_cleanup_stays_clean",
    ),
    (
        "the module map reports accurate on a block it cannot parse",
        [("tools/sync_module_map.py",
          "    if content_lines and not parsed:",
          "    if False:")],
        "test_doc_sync_tools",
    ),
    (
        "a missing browser makes the design audit report success",
        [("tools/design_audit.py",
          '        print("SKIPPED: nothing was measured", file=sys.stderr)\n        return 77',
          "        return 0")],
        "test_doc_sync_tools",
    ),
    (
        "the design audit stops checking the page it asked for",
        [("tools/design_audit.py",
          "            if response is not None and response.status >= 400:",
          "            if False:")],
        "test_doc_sync_tools",
    ),

    # --- correctness ------------------------------------------------------
    (
        "an unsupported sort is silently coerced to the default",
        [("modules/search_service.py",
          "    if sort not in VALID_SORTS:\n        raise SearchError(\n"
          '            f"Unsupported sort: {sort}. One of: {\', \'.join(VALID_SORTS)}.", 400)',
          '    if sort not in VALID_SORTS:\n        sort = "published"')],
        "test_search_service",
    ),
    (
        "timestamps are compared as raw strings again",
        [("modules/search_service.py",
          '    merged["updated_at"] = _latest(updated)',
          '    merged["updated_at"] = max(updated) if updated else None')],
        "test_search_service",
    ),
    (
        "a total failure is measured against requested, not attempted, sources",
        [("modules/search_service.py",
          "    if (failed_sources and attempted_sources\n"
          "            and set(failed_sources) >= set(attempted_sources)):",
          "    if failed_sources and set(failed_sources) >= set(q.sources):")],
        "test_search_service",
    ),
    (
        "an empty verdict set is reported as a confident no",
        [("modules/ai_classifier.py",
          "    if not category_verdicts:",
          "    if False:")],
        "test_ai_classifier",
    ),
    (
        "the catalog generator accepts a truncated catalog",
        [("tools/generate_cwe_catalog.py",
          "    if len(names) < MIN_WEAKNESSES:",
          "    if False:")],
        "test_generate_cwe_catalog",
    ),
    (
        "the forbidden keyword trap comes back",
        [("modules/cwe_categories.py",
          '        "unauthenticated", "unauthorized", "unauthorised",',
          '        "unauthenticated", "unauthorized", "unauthorised", "forbidden",')],
        "test_cwe_categories",
    ),
    (
        "the overflows keyword trap comes back",
        [("modules/cwe_categories.py",
          '                    "integer overflows"],',
          '                    "overflows"],')],
        "test_cwe_categories",
    ),
]
