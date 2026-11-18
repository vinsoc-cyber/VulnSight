"""Checks for the search pipeline and the four source clients.

Each entry is a bug that was really in this codebase, taken from the
"Search pipeline" and "Source clients" sections of
docs/review-dispositions.md, with the exact edit that puts it back. See
tools/revert_checks.py for how they are run and tools/checks/__init__.py for
the shape of an entry.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

CHECKS: list[tuple[str, list[Edit], str]] = [
    (
        "a typo in a transient-error marker stops GHSA retrying",
        [("modules/ghsa_client.py",
          '    "timed out", "502", "503", "504", "bad gateway", "service unavailable",',
          '    "timed out", "5O2", "503", "504", "bad gatway", "service unavailable",')],
        "test_ghsa_client",
    ),
    (
        "GHSA stops retrying a transient page at all",
        [("modules/ghsa_client.py",
          "def _is_transient_gh_error(exc: BaseException) -> bool:\n"
          "    if not isinstance(exc, GhCliError):\n"
          "        return False",
          "def _is_transient_gh_error(exc: BaseException) -> bool:\n"
          "    return False\n"
          "    if not isinstance(exc, GhCliError):\n"
          "        return False")],
        "test_ghsa_client",
    ),
    (
        "EPSS keys are not normalised on the way back",
        [("modules/epss_client.py",
          "            results[cve.upper()] = {",
          "            results[cve] = {")],
        "test_epss_client",
    ),
    (
        "the advisory batch is sent in one oversized statement",
        [("modules/cache.py",
          "        for start in range(0, len(ids), 500):\n"
          "            chunk = ids[start:start + 500]",
          "        for start in range(0, len(ids), 100000):\n"
          "            chunk = ids[start:start + 100000]")],
        "test_cache",
    ),
    # ---------------------------------------------------------------- merge
    (
        "an empty base record erases another source's description",
        [("modules/search_service.py",
          '    for key in ("summary", "description", "html_url"):\n'
          "        if not merged.get(key):\n"
          "            merged[key] = next(\n"
          "                (record.get(key) for record in records if record.get(key)),\n"
          "                merged.get(key),\n"
          "            )\n"
          "    return merged",
          "    return merged")],
        "test_search_service",
    ),
    (
        "cvss_vector is dropped when the base record has none",
        [("modules/search_service.py",
          '    merged["cvss_vector"] = next(\n'
          '        (record.get("cvss_vector") for record in records if record.get("cvss_vector")),\n'
          "        None,\n"
          "    )\n",
          "")],
        "test_search_service",
    ),
    (
        "ghsa_id is filled with a CVE id",
        [("modules/search_service.py",
          '        merged["ghsa_id"] = None',
          '        merged["ghsa_id"] = cve_ids[0] if cve_ids else None')],
        "test_search_service",
    ),
    (
        "records with no identifier all collapse onto one advisory_id",
        [("modules/search_service.py",
          '        merged["advisory_id"] = f"anon-{fingerprint}"',
          '        merged["advisory_id"] = ""')],
        "test_search_service",
    ),
    (
        "a non-numeric CVSS score crashes the merge",
        [("modules/search_service.py",
          "        scores = [\n"
          '            record["cvss_score"] for record in group\n'
          '            if isinstance(record.get("cvss_score"), (int, float))\n'
          "        ]",
          "        scores = [\n"
          '            record["cvss_score"] for record in group\n'
          '            if record.get("cvss_score") is not None\n'
          "        ]")],
        "test_search_service",
    ),
    (
        "osv-native has no base priority and ties on fetch order",
        [("modules/search_service.py",
          '                    enumerate(("ghsa", "osv", "osv-native", "nvd"))}',
          '                    enumerate(("ghsa", "osv", "nvd"))}')],
        "test_search_service",
    ),
    # ------------------------------------------------------------- run_search
    (
        "every selected source failing answers 200, not 502",
        [("modules/search_service.py",
          "    if failed_sources and set(failed_sources) >= set(q.sources):",
          "    if False:")],
        "test_search_service",
    ),
    (
        "NVD silently drops the advisory-type filter",
        [("modules/search_service.py",
          '        if q.adv_type and q.adv_type != "reviewed":\n'
          "            warnings.append(\n"
          "                f\"NVD does not support the '{q.adv_type}' advisory-type \"\n"
          '                "filter; its rows are unfiltered by type."\n'
          "            )",
          "        if False:\n            pass")],
        "test_search_service",
    ),
    (
        "NVD silently drops the ecosystem filter",
        [("modules/search_service.py",
          '        if q.ecosystem and q.ecosystem != "any":\n'
          "            warnings.append(\n"
          '                f"NVD is not indexed by ecosystem; its rows are not limited "\n'
          "                f\"to '{q.ecosystem}'.\"\n"
          "            )",
          "        if False:\n            pass")],
        "test_search_service",
    ),
    (
        "a partly failed NVD fetch is reported as a complete one",
        [("modules/search_service.py",
          '            failed = nvd_report.get("failed_cwes", 0)\n'
          "            if failed:\n"
          "                warnings.append(\n"
          "                    f\"NVD: {failed} of {nvd_report.get('total_cwes', failed)} \"\n"
          '                    "CWE queries failed; its results are incomplete."\n'
          "                )",
          "            pass")],
        "test_search_service",
    ),
    (
        "EPSS failure fabricates a ranking",
        [("modules/search_service.py",
          "        if results and not enriched:\n"
          "            warnings.append(\n"
          '                "EPSS scores are unavailable, so these results are in merge "\n'
          '                "order, not EPSS order."\n'
          "            )",
          "        if False:\n            pass")],
        "test_search_service",
    ),
    (
        "the EPSS lookup is case-sensitive",
        [("modules/search_service.py",
          '            score = epss_scores.get(str(rec.get("cve_id") or "").upper())',
          '            score = epss_scores.get(rec.get("cve_id"))')],
        "test_search_service",
    ),
    (
        "source_records ships in every response and is cached",
        [("modules/search_service.py",
          "    if not q.include_source_records:",
          "    if False:")],
        "test_search_service",
    ),
    (
        "count: 0 cannot be told apart from an outage",
        [("modules/search_service.py",
          '            "failed_sources": sorted(set(failed_sources)),\n',
          "")],
        "test_search_service",
    ),
    (
        "VALID_SORTS drifts from the sort-field map",
        [("modules/search_service.py",
          "VALID_SORTS = tuple(_SORT_FIELD)",
          'VALID_SORTS = ("published", "updated", "cve_id")')],
        "test_search_service",
    ),
    # ------------------------------------------------------------ OSV client
    (
        "one malformed OSV record kills the whole export",
        [("modules/osv_client.py",
          "                    records.append(normalize_osv(rec))\n"
          "                except Exception:",
          "                    records.append(normalize_osv(rec))\n"
          "                except (ValueError, UnicodeDecodeError):")],
        "test_osv_client",
    ),
    (
        "the OSV bulk download is buffered whole with no size cap",
        [("modules/osv_client.py",
          "            written = 0\n"
          "            with urllib.request.urlopen(req, timeout=timeout) as resp, \\\n"
          '                    open(tmp, "wb") as handle:\n'
          "                while True:\n"
          "                    chunk = resp.read(1 << 20)\n"
          "                    if not chunk:\n"
          "                        break\n"
          "                    written += len(chunk)\n"
          "                    if written > MAX_BULK_BYTES:\n"
          "                        raise OsvError(\n"
          '                            f"OSV bulk for {osv_eco} exceeded "\n'
          '                            f"{MAX_BULK_BYTES // (1 << 20)} MB; refusing it")\n'
          "                    handle.write(chunk)",
          "            with urllib.request.urlopen(req, timeout=timeout) as resp:\n"
          "                data = resp.read()\n"
          '            with open(tmp, "wb") as handle:\n'
          "                handle.write(data)")],
        "test_osv_client",
    ),
    (
        "a failed OSV refresh throws away a usable cached export",
        [("modules/osv_client.py",
          "            if not force and os.path.exists(path) and os.path.getsize(path) > 0:\n"
          "                age_hours = (time.time() - os.path.getmtime(path)) / 3600\n"
          "                logger.warning(\n"
          '                    "OSV refresh for %s failed (%s); using the cached copy, "\n'
          '                    "which is %.1f hours old", osv_eco, e, age_hours)\n'
          "                return path",
          "            pass")],
        "test_osv_client",
    ),
    (
        "an OSV ecosystem whose name has a space can never be fetched",
        [("modules/osv_client.py",
          '        url = f"{OSV_BASE}/{urllib.parse.quote(osv_eco)}/all.zip"',
          '        url = f"{OSV_BASE}/{osv_eco}/all.zip"')],
        "test_osv_client",
    ),
    (
        "a cache file that vanishes mid-read crashes the healthcheck",
        [("modules/osv_client.py",
          "        try:\n"
          "            size = os.path.getsize(p)\n"
          "            mtime = os.path.getmtime(p)\n"
          "        except OSError:\n"
          "            # Deleted between the check and the read, or never there.\n"
          "            # These caches are documented as safe to delete at any time,\n"
          "            # and this renders on every healthcheck.\n"
          "            continue",
          "        if not os.path.exists(p):\n"
          "            continue\n"
          "        size = os.path.getsize(p)\n"
          "        mtime = os.path.getmtime(p)")],
        "test_osv_client",
    ),
    (
        "normalised OSV packages carry purl/ranges/versions and a null range",
        [("modules/osv_client.py",
          '            "vulnerable_version_range": _introduced_range(ranges),',
          '            "purl": pkg.get("purl"),\n'
          '            "ranges": ranges,\n'
          '            "versions": aff.get("versions") or [],\n'
          '            "vulnerable_version_range": None,')],
        "test_osv_client",
    ),
    # ------------------------------------------------------------ NVD client
    (
        "one malformed NVD record sinks the whole batch",
        [("modules/nvd_client.py",
          "    normalized, skipped = records.normalize_all(\n"
          '        raw_all, normalize, source="NVD",\n'
          '        identify=lambda v: records.identify((v or {}).get("cve") or {}, "id"),\n'
          "    )",
          "    normalized, skipped = ([normalize(v) for v in raw_all], 0)")],
        "test_nvd_client",
    ),
    (
        "NVD's CVSS vector is read and thrown away",
        [("modules/nvd_client.py",
          '        "cvss_vector": cvss_vector,\n',
          "")],
        "test_nvd_client",
    ),
    # ----------------------------------------------------------- GHSA client
    (
        "a failing later page discards the advisories already fetched",
        [("modules/ghsa_client.py",
          "        except GhCliError:\n"
          "            if not results:\n"
          "                raise          # nothing collected: the source really did fail\n"
          '            logger.warning("GHSA: keeping %d advisory(ies) from the pages that "\n'
          '                           "succeeded; a later page kept failing", len(results))\n'
          "            break",
          "        except GhCliError:\n            raise")],
        "test_ghsa_client",
    ),
    # ----------------------------------------------------------- EPSS client
    (
        "EPSS is queried with the publisher's casing",
        [("modules/epss_client.py",
          "    cve_ids = [c.upper() for c in cve_ids]",
          "    cve_ids = list(cve_ids)")],
        "test_epss_client",
    ),
]
