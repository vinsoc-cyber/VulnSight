"""NIST National Vulnerability Database (NVD) API v2 client.

Fetches CVEs from the NVD REST API filtered by CWE, severity, date range,
and keyword. The NVD API only accepts ONE cweId per request, so we iterate
over the requested CWEs, deduplicate, and normalize to the shared advisory
shape used by ghsa_client / osv_client.

Docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits:
  - Without API key: 5 requests per 30-second window  (~6s between calls)
  - With API key:   50 requests per 30-second window  (~0.6s between calls)

Set NVD_API_KEY in .env for faster queries (free, get one at
https://nvd.nist.gov/developers/request-an-api-key).
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import http_retry, records

from .cwe_categories import normalize_cwe_id
from .query_filters import published_bounds

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "vulnsight/1.0 (+nvd)"
NVD_EARLIEST = datetime(1988, 1, 1, tzinfo=timezone.utc)


class NvdError(RuntimeError):
    """Raised on NVD API failures."""


_SEVERITY_MAP = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}


def _api_key() -> str | None:
    return os.environ.get("NVD_API_KEY", "").strip() or None


def _request_delay() -> float:
    return 0.7 if _api_key() else 6.5


@dataclass
class NvdSearchParams:
    cwes: list[str] = field(default_factory=list)
    keyword: str | None = None
    severity: str | None = None
    published_range: str | None = None
    max_results: int = 200
    results_per_page: int = 200


def _format_nvd_date(value: datetime, *, end: bool = False) -> str:
    suffix = "23:59:59.999Z" if end else "00:00:00.000Z"
    return f"{value:%Y-%m-%d}T{suffix}"


def _build_date_windows(
    published: str | None, now: datetime | None = None
) -> list[dict[str, str]]:
    """Split a published filter into newest-first NVD-compatible windows.

    NVD rejects ranges over 120 days.  Splitting preserves the user's requested
    range instead of silently replacing an old start date with "120 days ago".
    """
    if not published:
        return []
    lower, upper = published_bounds(published)
    now = now or datetime.now(tz=timezone.utc)
    # NVD has no useful records before its historical lower bound. Clamping also
    # prevents datetime underflow for syntactically valid dates near year 1.
    start = max(lower or NVD_EARLIEST, NVD_EARLIEST)
    end = min(upper or now, now)
    if start > end:
        return []

    windows: list[dict[str, str]] = []
    cursor_end = end
    while cursor_end >= start:
        # Date formatting expands to whole days, so 119 days between endpoints
        # yields at most 120 consecutive calendar days (NVD's hard limit).
        cursor_start = max(start, cursor_end - timedelta(days=119))
        windows.append({
            "pubStartDate": _format_nvd_date(cursor_start),
            "pubEndDate": _format_nvd_date(cursor_end, end=True),
        })
        if cursor_start <= start:
            break
        # A full day back, not a millisecond: the dates are truncated to
        # midnight/23:59:59.999 below, so a millisecond stayed inside the
        # same day and both windows fetched it.
        cursor_end = cursor_start - timedelta(days=1)
    return windows


def _fetch_page(params: dict[str, str], timeout: int = 60) -> dict:
    """Make a single NVD API GET request and return parsed JSON.

    Transient failures are retried with backoff. NVD is the most
    failure-prone source here -- one request per CWE per date window, rate
    limited hard without an API key -- and it was the only client with no
    retry at all, so a single 503 dropped that CWE from the results entirely.
    """
    qs = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}"
                  for k, v in params.items())
    url = f"{NVD_BASE}?{qs}"

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    key = _api_key()
    if key:
        headers["apiKey"] = key

    req = urllib.request.Request(url, headers=headers)

    def _once() -> bytes:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    try:
        data = http_retry.with_retries(_once, what="NVD request", attempts=3)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            # NVD returns 403 both for throttling and for a rejected key, and
            # reporting only the former sent operators to the wrong fix.
            detail = ""
            try:
                detail = (e.read() or b"")[:200].decode("utf-8", "replace").strip()
            except Exception:
                logger.debug("NVD 403 body could not be read", exc_info=True)
            logger.warning("NVD 403: %s", detail or "(no body)")
            raise NvdError(
                "NVD refused the request (HTTP 403): rate limited, or "
                "NVD_API_KEY is invalid. Try again in 30s, or check the key."
            ) from e
        raise NvdError(f"NVD API HTTP {e.code}: {e.reason}") from e
    except Exception as e:
        raise NvdError(f"NVD API request failed: {e}") from e

    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise NvdError(f"Could not parse NVD response: {e}") from e


def _fetch_cves_for_cwe(cwe: str, params: NvdSearchParams) -> list[dict]:
    """Fetch all CVEs matching a single CWE, paginating as needed."""
    base_q: dict[str, str] = {
        "cweId": f"CWE-{normalize_cwe_id(cwe)}",
        "noRejected": "",
    }
    if params.severity and params.severity != "any":
        # NVD wants the uppercase form, which is what _SEVERITY_MAP's keys
        # are. The inverse lookup that used to sit here could never fire --
        # an upper-cased severity is never one of that map's lowercase values
        # -- so it was dead code that made the passthrough look conditional.
        base_q["cvssV3Severity"] = params.severity.upper()

    if params.keyword:
        base_q["keywordSearch"] = params.keyword

    results: list[dict] = []
    delay = _request_delay()
    windows = _build_date_windows(params.published_range) or [{}]

    for window_index, window in enumerate(windows):
        if len(results) >= params.max_results:
            break
        if window_index:
            time.sleep(delay)

        remaining = params.max_results - len(results)
        # NVD recommends its optimized 2,000-row page size. Fetching a full page
        # avoids a second tail request for most 120-day windows, then we trim
        # locally to the caller's much smaller result budget.
        page_size = min(max(params.results_per_page, remaining), 2000)
        query = dict(base_q, **window, startIndex="0", resultsPerPage=str(page_size))
        body = _fetch_page(query)
        vulns = body.get("vulnerabilities") or []
        total = int(body.get("totalResults") or len(vulns))

        # NVD returns publish-date ascending. Fetch the tail page so a bounded
        # "newest first" search does not return the oldest CVEs in the range.
        if total > page_size:
            time.sleep(delay)
            tail_index = max(0, total - page_size)
            body = _fetch_page(dict(query, startIndex=str(tail_index)))
            vulns = body.get("vulnerabilities") or []

        vulns.sort(
            key=lambda item: ((item.get("cve") or {}).get("published") or ""),
            reverse=True,
        )
        results.extend(vulns[:remaining])

    results.sort(
        key=lambda item: ((item.get("cve") or {}).get("published") or ""),
        reverse=True,
    )
    return results[: params.max_results]


def fetch_nvd(params: NvdSearchParams, report: dict | None = None) -> list[dict]:
    """Fetch CVEs for all requested CWEs, deduplicate, and normalize.

    *report*, if given, is filled with ``failed_cwes``/``total_cwes`` so the
    caller can tell the user the result set is incomplete. Passed in rather
    than returned so existing callers are unaffected, and held per call rather
    than on the module so concurrent searches cannot overwrite each other.
    """
    if not params.cwes:
        return []
    if report is not None:
        report["failed_cwes"] = 0
        report["total_cwes"] = len(params.cwes)

    seen_ids: set[str] = set()
    raw_all: list[dict] = []
    delay = _request_delay()
    errors: list[NvdError] = []
    successful_queries = 0

    for i, cwe in enumerate(params.cwes):
        if i > 0:
            time.sleep(delay)

        per_cwe = NvdSearchParams(
            cwes=[cwe],
            keyword=params.keyword,
            severity=params.severity,
            published_range=params.published_range,
            max_results=params.max_results,
            results_per_page=2000,
        )
        try:
            batch = _fetch_cves_for_cwe(cwe, per_cwe)
        except NvdError as e:
            logger.warning("NVD fetch for CWE-%s failed: %s", cwe, e)
            errors.append(e)
            continue
        successful_queries += 1

        for vuln in batch:
            cve_id = (vuln.get("cve") or {}).get("id", "")
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                raw_all.append(vuln)

    if errors and not successful_queries:
        raise NvdError(f"all NVD CWE queries failed; last error: {errors[-1]}")

    # Partial failure is the common case here -- one request per CWE per date
    # window, rate limited hard without a key -- and it used to be invisible:
    # 17 of 18 CWEs could fail and the caller saw a plausible "NVD: 12" with
    # no warning, reading it as "NVD has 12 of these".
    if report is not None:
        report["failed_cwes"] = len(errors)
    if errors:
        logger.warning("NVD: %d of %d CWE queries failed",
                       len(errors), len(params.cwes))

    # Per record: normalize dereferences weaknesses[].description[],
    # cpeMatch[].criteria.split() and float(baseScore), none of which the NVD
    # schema guarantees. A null criteria or a baseScore of "N/A" used to raise
    # out of here as an AttributeError/ValueError -- not an NvdError, so it
    # bypassed the per-source degradation in run_search and 500'd the entire
    # search, including the sources that had already succeeded.
    normalized, skipped = records.normalize_all(
        raw_all, normalize, source="NVD",
        identify=lambda v: records.identify((v or {}).get("cve") or {}, "id"),
    )
    if skipped:
        logger.warning("NVD: %d record(s) could not be normalized", skipped)
    normalized.sort(key=lambda item: item.get("published_at") or "", reverse=True)
    return normalized[: params.max_results]


# ---------------------------------------------------------------------------
# Normalization: NVD CVE -> shared advisory dict
# ---------------------------------------------------------------------------

def _extract_cwes(cve: dict) -> list[str]:
    cwes: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = d.get("value", "")
            if val.startswith("CWE-") and val not in ("CWE-noinfo", "CWE-Other"):
                bare = normalize_cwe_id(val)
                if bare not in cwes:
                    cwes.append(bare)
    return cwes


def _extract_cvss(cve: dict) -> tuple[float | None, str, str | None]:
    metrics = cve.get("metrics") or {}
    # Prefer the newest CVSS version available: v4.0 > v3.1 > v3.0 > v2.
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for entry in metrics.get(key) or []:
            cvss_data = entry.get("cvssData") or {}
            score = cvss_data.get("baseScore")
            sev = (cvss_data.get("baseSeverity") or "").upper()
            if score is not None:
                # The vector was read and thrown away, which is why
                # docs/data-sources.md credited NVD with "CVSS v3/v4 vectors"
                # that never reached a row: cvss_vector was OSV-only, so a
                # GHSA+NVD merge showed cvss_vector null with nothing to look
                # up even when NVD had supplied one.
                return (float(score), _SEVERITY_MAP.get(sev, "unknown"),
                        cvss_data.get("vectorString") or None)
    for entry in metrics.get("cvssMetricV2") or []:
        cvss_data = entry.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        sev = (entry.get("baseSeverity") or "").upper()
        if score is not None:
            return (float(score), _SEVERITY_MAP.get(sev, "unknown"),
                    cvss_data.get("vectorString") or None)
    return None, "unknown", None


def _extract_packages(cve: dict) -> list[dict]:
    packages: list[dict] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3] if len(parts) > 3 else ""
                    product = parts[4] if len(parts) > 4 else ""
                    version_end = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                    packages.append({
                        "ecosystem": "nvd",
                        "name": f"{vendor}:{product}" if vendor else product,
                        "vulnerable_version_range": f"< {version_end}" if version_end else None,
                        "first_patched_version": version_end,
                    })
    return packages


def _extract_description(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    descs = cve.get("descriptions") or []
    return descs[0].get("value", "") if descs else ""


def normalize(vuln: dict) -> dict:
    cve = vuln.get("cve") or {}
    cve_id = cve.get("id", "")
    desc = _extract_description(cve)
    cwes = _extract_cwes(cve)
    cvss_score, severity, cvss_vector = _extract_cvss(cve)
    packages = _extract_packages(cve)
    refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]

    kev_date = cve.get("cisaExploitAdd")
    aliases = [cve_id] if cve_id else []

    return {
        "advisory_id": cve_id,
        "ghsa_id": None,
        "cve_id": cve_id,
        "summary": (desc[:120] + "…") if len(desc) > 120 else desc,
        "description": desc,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwes": cwes,
        "packages": packages,
        "ecosystems": sorted({p["ecosystem"] for p in packages if p.get("ecosystem")}),
        "html_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
        "references": refs,
        "published_at": cve.get("published", ""),
        "updated_at": cve.get("lastModified", ""),
        "type": "nvd",
        "source": "nvd",
        "aliases": aliases,
        "nvd_status": cve.get("vulnStatus", ""),
        "kev": bool(kev_date),
    }
