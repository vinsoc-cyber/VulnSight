"""FIRST EPSS (Exploit Prediction Scoring System) client.

Fetches EPSS scores from the FIRST API to augment vulnerability results with
exploit-likelihood data.  No authentication required.

Endpoint: https://api.first.org/data/v1/epss
Docs:     https://www.first.org/epss/api

Rate limits:
  - Max 100 CVEs per request (batch query)
  - No published per-minute cap, but be courteous

Uses stdlib ``urllib`` only (consistent with the rest of the codebase).
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

from . import http_retry

logger = logging.getLogger(__name__)

EPSS_BASE = "https://api.first.org/data/v1/epss"
USER_AGENT = "vulnsight/1.0 (+epss)"
BATCH_SIZE = 100  # API-imposed maximum CVEs per request


# Enrichment is optional, so its whole budget sits well under the worker
# timeout: a slow or dead FIRST must cost some scores, never the search.
FETCH_DEADLINE_SECONDS = 45.0
# A dead endpoint looks identical to a slow one batch by batch. Three in a
# row is an outage, not bad luck.
MAX_CONSECUTIVE_FAILURES = 3


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores for a list of CVE IDs.

    Returns ``{cve_id: {"epss": float, "percentile": float}}`` for every CVE
    the API returned data for.  CVEs without EPSS data are silently omitted.

    On network or parsing errors the function logs a warning and returns an
    empty dict -- callers should never crash because EPSS enrichment failed.
    """
    if not cve_ids:
        return {}

    # Deduplicate while preserving a deterministic order for testing, and
    # drop blanks: a record with no CVE id reaches here as "" (merge keeps
    # whatever the source gave), and `?cve=,,` is a paid round trip that
    # can only come back empty.
    # Normalised BEFORE dedup. _fetch_batch upper-cases on the way out, but
    # dict.fromkeys ran first, so ["CVE-2024-1", "cve-2024-1"] survived as
    # two entries and went out twice in the same ?cve= list -- a 100-id
    # batch carrying fewer than 100 distinct CVEs.
    unique: list[str] = list(dict.fromkeys(
        c.strip().upper() for c in cve_ids if c and c.strip()))
    if not unique:
        return {}

    results: dict[str, dict] = {}
    # A deadline and a consecutive-failure brake. Each batch retried
    # independently (attempts=2, timeout=30) and failures were swallowed per
    # batch, so a FIRST outage cost the FULL budget rather than failing
    # fast: sort=epss_percentage with max_results=500 enriches up to 2,000
    # CVEs in 20 batches, which is ~1240s inside one request against a 180s
    # worker timeout. Enrichment is an optimisation; it must never be the
    # reason a search dies.
    deadline = time.monotonic() + FETCH_DEADLINE_SECONDS
    consecutive_failures = 0
    for index, batch in enumerate(_batches(unique, BATCH_SIZE)):
        if time.monotonic() >= deadline:
            logger.warning("EPSS: %.0fs budget spent; %d of %d CVEs scored",
                           FETCH_DEADLINE_SECONDS, len(results), len(unique))
            break
        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            logger.warning("EPSS: %d batches failed in a row; giving up with "
                           "%d of %d CVEs scored", consecutive_failures,
                           len(results), len(unique))
            break
        try:
            results.update(_fetch_batch(batch))
            consecutive_failures = 0
        except Exception:
            consecutive_failures += 1
            logger.warning("EPSS batch %d failed for %d CVEs", index,
                           len(batch), exc_info=True)

    return results


def _batches(items: list[str], size: int):
    """Yield successive chunks of *size* from *items*."""
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _fetch_batch(cve_ids: list[str], timeout: int = 30) -> dict[str, dict]:
    """Query the FIRST EPSS API for up to 100 CVEs and return parsed scores."""
    # Upper-cased on the way out and on the way back: _merge_group preserves
    # whatever casing the publisher used, and FIRST keys its response
    # case-sensitively, so a lower-cased alias silently returned no score --
    # indistinguishable in the UI from an advisory that genuinely has none.
    cve_ids = [c.upper() for c in cve_ids]
    params = urllib.parse.urlencode({"cve": ",".join(cve_ids)})
    url = f"{EPSS_BASE}?{params}"

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)

    def _once() -> bytes:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    try:
        # Retried like every other upstream. This client used to swallow
        # everything and return {} on the first failure, which is how an EPSS
        # outage became a silently unranked result set.
        data = http_retry.with_retries(_once, what="EPSS request", attempts=2)
    except urllib.error.HTTPError as exc:
        logger.warning("EPSS API HTTP %d: %s", exc.code, exc.reason)
        return {}
    except Exception as exc:
        logger.warning("EPSS API request failed: %s", exc)
        return {}

    try:
        body = json.loads(data)
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse EPSS response: %s", exc)
        return {}

    results: dict[str, dict] = {}
    for entry in body.get("data") or []:
        cve = entry.get("cve")
        if not cve:
            continue
        try:
            # .upper() here is the "way back" half the comment above
            # promises and this did not do: the key was whatever FIRST
            # echoed. search_service looks the score up with .upper(), so a
            # lower-cased echo returned a dict the caller could not read and
            # the advisory showed no EPSS at all -- indistinguishable from
            # one that genuinely has none, which is the exact failure the
            # "way out" half was added to prevent.
            results[cve.upper()] = {
                "epss": float(entry["epss"]),
                "percentile": float(entry["percentile"]),
            }
        except (KeyError, TypeError, ValueError):
            continue

    return results
