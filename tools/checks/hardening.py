"""Checks for the defects found by the whole-tree review.

These were all listed in docs/open-findings.md as verified-and-unfixed
before being fixed. Each entry puts one of them back.

See tools/checks/__init__.py for the shape of an entry and the rule that a
fix guarded in two places must be reverted in one entry.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    # --- availability ----------------------------------------------------
    (
        "an NVD search can outlive the worker again",
        [("modules/nvd_client.py",
          "        if time.monotonic() >= deadline:",
          "        if False:")],
        "test_nvd_client",
    ),
    (
        "NVD fetches a full page and throws it away again",
        [("modules/nvd_client.py",
          '        probe = _fetch_page(dict(query, resultsPerPage="1"))',
          "        probe = _fetch_page(query)")],
        "test_nvd_client",
    ),
    (
        "the NVD paging dereferences shapes the API does not promise",
        [("modules/nvd_client.py",
          "    if not isinstance(items, list):\n        return []\n"
          "    return [item for item in items if isinstance(item, dict)]",
          "    return items")],
        "test_nvd_client",
    ),
    (
        "a non-numeric totalResults raises again",
        [("modules/nvd_client.py",
          "    try:\n        return max(0, int(body.get(\"totalResults\") or 0))\n"
          "    except (TypeError, ValueError):",
          "    if True:\n        return max(0, int(body.get(\"totalResults\") or 0))\n"
          "    try:")],
        "test_nvd_client",
    ),
    (
        "EPSS enrichment runs without a deadline again",
        [("modules/epss_client.py",
          "        if time.monotonic() >= deadline:",
          "        if False:")],
        "test_epss_client",
    ),
    (
        "a dead EPSS endpoint costs the whole batch budget",
        [("modules/epss_client.py",
          "        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:",
          "        if False:")],
        "test_epss_client",
    ),
    (
        "the OSV freshness check goes back behind the download lock",
        [("modules/osv_client.py",
          "    if _is_fresh(path, force, max_age):\n        return path\n\n    with _DOWNLOAD_LOCK:",
          "    if False:\n        return path\n\n    with _DOWNLOAD_LOCK:")],
        "test_osv_client",
    ),
    (
        "a zip member inflates without a bound again",
        [("modules/osv_client.py",
          "                    if info.file_size > MAX_MEMBER_BYTES:",
          "                    if False:")],
        "test_osv_client",
    ),
    (
        "jobs queue without backpressure again",
        [("modules/jobs.py",
          "    if depth >= MAX_UNFINISHED_JOBS:",
          "    if False:")],
        "test_jobs",
    ),
    (
        "a successful search dies on an optional cache write",
        [("modules/search_service.py",
          "    try:\n        cache.upsert_advisories(results)\n    except Exception:",
          "    cache.upsert_advisories(results)\n    if False:")],
        "test_search_service",
    ),

    # --- correctness -----------------------------------------------------
    (
        "a merged advisory gets two primary keys again",
        [("modules/search_service.py",
          "    base = min(records,\n"
          "               key=lambda item: (_SOURCE_PRIORITY.get(item.get(\"source\") or \"\", 99),\n"
          "                                 str(item.get(\"advisory_id\") or \"\"),\n"
          "                                 str(item.get(\"cve_id\") or \"\")))",
          "    base = min(records,\n"
          "               key=lambda item: _SOURCE_PRIORITY.get(item.get(\"source\") or \"\", 99))")],
        "test_search_service",
    ),
    (
        "the CVSS vector stops describing the score beside it",
        [("modules/search_service.py",
          '    merged["cvss_vector"] = _vector_for_score(records, merged.get("cvss_score"))',
          '    merged["cvss_vector"] = next(\n'
          '        (record.get("cvss_vector") for record in records if record.get("cvss_vector")),\n'
          "        None,\n    )")],
        "test_search_service",
    ),
    (
        "records without a CVE sort to the top again",
        [("modules/search_service.py",
          '    with_cve, without = [], []\n    for record in records:\n'
          '        (with_cve if _CVE_ID_RE.match(str(record.get("cve_id") or "").strip())\n'
          "         else without).append(record)\n    return with_cve + without",
          "    return records")],
        "test_search_service",
    ),
    (
        "affects silently deletes every NVD-only row again",
        [("modules/query_filters.py",
          '        if ":" in name and wanted in name.split(":", 1):\n            return True',
          "        if False:\n            return True")],
        "test_query_filters",
    ),
    (
        "OSV renders only the last vulnerable branch again",
        [("modules/osv_client.py",
          "    parts: list[str] = []\n    for rng in ranges or []:\n"
          "        for introduced, fixed in _intervals(rng.get(\"events\") or []):",
          "    parts: list[str] = []\n    for rng in ranges or []:\n"
          "        for introduced, fixed in _intervals(rng.get(\"events\") or [])[-1:]:")],
        "test_osv_client",
    ),

    # --- cost and credentials -------------------------------------------
    (
        "a throttle is misread as a spent key again",
        [("modules/ai_classifier.py",
          "        if any(marker in text for marker in _RATE_MARKERS):\n"
          "            return True, True, min(advised if advised is not None else 30, _MAX_RATE_PAUSE)\n"
          "        if any(marker in text for marker in _QUOTA_MARKERS):",
          "        if any(marker in text for marker in _QUOTA_MARKERS):")],
        "test_ai_classifier",
    ),
    (
        "the verdict parser spans two JSON objects again",
        [("modules/ai_classifier.py",
          "    candidate = _last_json_object(text)",
          '    candidate = (text[text.find("{"):text.rfind("}") + 1]\n'
          '                 if "{" in text and "}" in text else None)')],
        "test_ai_classifier",
    ),
    (
        "two workers share one cooldown temp path again",
        [("modules/ai_classifier.py",
          '    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".cooldown-", suffix=".tmp")',
          '    tmp = COOLDOWN_PATH + ".tmp"\n'
          "    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)")],
        "test_ai_classifier",
    ),
    (
        "an impossible AI request is retried on every key again",
        [("modules/ai_classifier.py",
          "            if not e.retryable and not e.key_exhausted:\n                raise\n",
          "")],
        "test_ai_classifier",
    ),
    (
        "source availability churns the verdict cache again",
        [("modules/ai_classifier.py",
          '        "user": _build_user_prompt(_stable_order(adv), category),',
          '        "user": _build_user_prompt(adv, category),')],
        "test_ai_classifier",
    ),
    (
        "a GHSA rate limit is retried blindly again",
        # Both halves in one entry: dropping the permanent check alone does
        # not restore the bug, because "rate limit" also has to be back in
        # the transient list for the retry to happen.
        [("modules/ghsa_client.py",
          "    if any(phrase in text for phrase in _PERMANENT_GH_PHRASES):\n        return False",
          "    if False:\n        return False"),
         ("modules/ghsa_client.py",
          '    "temporary failure", "tls handshake",',
          '    "temporary failure", "tls handshake", "rate limit",')],
        "test_ghsa_client",
    ),
    (
        "short GHSA markers match inside identifiers again",
        [("modules/ghsa_client.py",
          "    return bool(_TRANSIENT_TOKEN_RE.search(text))",
          "    return any(tok in text for tok in _TRANSIENT_GH_TOKENS)")],
        "test_ghsa_client",
    ),

    # --- HTTP layer ------------------------------------------------------
    (
        "a conditional request with a tag list re-serves the whole body",
        [("app.py",
          "def _etag_matches(header: str | None, etag: str) -> bool:",
          "def _etag_matches(header: str | None, etag: str) -> bool:\n"
          "    return header == etag\n\n"
          "def _unused_etag_matches(header: str | None, etag: str) -> bool:")],
        "test_app",
    ),
    (
        "a 304 drops the validators that make the next request conditional",
        [("app.py",
          '    response.headers["ETag"] = etag\n'
          '    response.headers["Cache-Control"] = cache_control\n'
          "    return response",
          "    return response")],
        "test_app",
    ),

    # --- startup ---------------------------------------------------------
    (
        "an empty token file crashes startup with the wrong reason",
        [("modules/security.py",
          "        raise SystemExit(\n"
          '            f"{path} exists but is empty, so there is no API token to use. "\n'
          '            f"Delete it and start again; a new token will be generated."\n'
          "        ) from None",
          "        raise")],
        "test_security",
    ),
]
