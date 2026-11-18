"""Checks carried over from the first pass of the review.

Each entry is a bug that was really in this codebase, with the exact edit
that puts it back. See tools/revert_checks.py for how they are run and
tools/checks/__init__.py for the shape of an entry.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    (
        "the retry backoff clock is bound at import again",
        [("modules/http_retry.py",
          "    sleep: Callable[[float], None] | None = None,\n) -> T:",
          "    sleep: Callable[[float], None] = time.sleep,\n) -> T:"),
         ("modules/http_retry.py",
          "    if sleep is None:\n        sleep = time.sleep\n\n",
          "")],
        "test_http_retry",
    ),
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
          '    if parts.path != "/advisories":',
          "    if False:")],
        "test_ghsa_client",
    ),
    (
        # The guard was a prefix match for most of its life, which let
        # "/advisories/../user" through -- the API server resolves that to
        # /user and returns the operator's account.
        "GHSA cursor checked by prefix again",
        [("modules/ghsa_client.py",
          '    if parts.path != "/advisories":',
          '    if not parts.path.startswith("/advisories"):')],
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
        # The whole fix at once. The ellipsis stops the overflow at any
        # width; the 460px block gives the brand column its intrinsic width
        # and clips the name and the two status indicators out of the way.
        # Each of those on its own leaves the layout correct, so reverting
        # any subset reports a false pass -- a first attempt at this check
        # removed two of the three and found no overlap, because the pills
        # were still clipped and so the brand still had room.
        "the brand paints on top of the status pills",
        [("static/style.css",
          "  /* The brand column can shrink to nothing; without this the text simply\n"
          "     painted over the status pills instead of shrinking with its box. */\n"
          "  overflow: hidden;\n"
          "  text-overflow: ellipsis;\n"
          "  white-space: nowrap;\n",
          ""),
         ("static/style.css",
          '@media (max-width: 460px) {\n'
          '  /* The brand column was minmax(0, 1fr), so at 320px it collapsed to 21px\n'
          '     while the 32px logo carried on painting over the status pills. `auto`\n'
          '     gives the mark its intrinsic width and makes the status group -- which\n'
          '     has somewhere to give -- absorb the shortfall instead. */\n'
          '  .topbar { grid-template-columns: auto minmax(0, 1fr) auto; }\n'
          '\n'
          '  /* Clipped, not display:none, in all three cases below: each stays in the\n'
          '     accessibility tree, so the home link is still announced as\n'
          '     "VulnSight home" and GH/AI readiness is still reachable -- they just\n'
          '     stop competing for 320px of width with the controls you came for. */\n'
          '  .brand-copy,\n'
          '  .system-status > .pill:not(.pill-action) {\n'
          '    position: absolute;\n'
          '    width: 1px;\n'
          '    height: 1px;\n'
          '    overflow: hidden;\n'
          '    clip: rect(0, 0, 0, 0);\n'
          '    white-space: nowrap;\n'
          '  }\n'
          '}\n\n',
          "")],
        "test_ui_e2e",
    ),
    (
        "a disabled button keeps its warning colour again",
        [("static/style.css",
          "button.warn-btn:disabled {\n"
          "  color: var(--faint);\n"
          "  background: var(--panel-2);\n"
          "  border-color: var(--line-strong);\n"
          "}",
          "button.warn-btn:disabled { background: var(--panel-2); }")],
        "test_ui_e2e",
    ),
    (
        "app.js loses its scope wrapper",
        [("static/app.js", "(function () {\n  'use strict';\n", "")],
        "test_frontend_js",
    ),
    (
        "module-map drift test stops deriving",
        [("docs/architecture.md", "app.py                ", "app.py                1 ")],
        "test_docs",
    ),
]
