"""OSV.dev source (bulk-download + local CWE filter).

Why bulk and not the API: the OSV REST API is *package-centric* — you can only
query by package/commit/purl/id. It has NO CWE filter and no "list everything in
an ecosystem" browse (POST /v1/query with {"cwe":...} returns "Invalid query").
So to browse by bug class / CWE the way this tool does, we download OSV's
per-ecosystem bulk export (a small zip, ~10 MB) and filter locally.

Bulk export layout:
  https://osv-vulnerabilities.storage.googleapis.com/{Ecosystem}/all.zip
  -> a zip of one JSON file per vulnerability (OSV schema).

We normalise each record to the SAME shape as ghsa_client.normalize() so the
cache, AI layer, and UI treat GHSA and OSV records identically.

OSV records for maven/npm/pip/Go/crates are largely mirrored from GHSA (their id
is GHSA-...), so merging dedupes heavily; the genuine additions are source-native
records (GO-..., RUSTSEC-..., PYSEC-..., etc.).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import zipfile

from . import http_retry
from .config import DATA_DIR
from .cvss import base_score, is_v4_vector, severity_from_score
from .cwe_categories import category_keywords, normalize_cwe_id
from .query_filters import matches_common_filters

logger = logging.getLogger(__name__)

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
CACHE_DIR = os.path.join(DATA_DIR, "osv_cache")
DEFAULT_MAX_AGE = 24 * 3600  # re-download the bulk zip at most once a day
USER_AGENT = "vulnsight/1.0 (+osv bulk)"

# GHSA ecosystem name  ->  OSV ecosystem name (OSV uses different casing/labels).
ECOSYSTEM_MAP: dict[str, str] = {
    "maven": "Maven",
    "go": "Go",
    "npm": "npm",
    "pip": "PyPI",
    "composer": "Packagist",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "rust": "crates.io",
    "pub": "Pub",
    "swift": "SwiftURL",
    "erlang": "Hex",
    "actions": "GitHub Actions",
}

# In-process cache of parsed+normalized records, keyed by GHSA ecosystem name.
# Each entry is (loaded_at_timestamp, records).  TTL-based eviction prevents
# unbounded growth over the lifetime of a long-running process.
_MEM: dict[str, tuple[float, list[dict]]] = {}
_MEM_TTL = 3600   # seconds – evict cached records older than 1 hour
_MEM_MAX = 5      # max ecosystems kept in memory at once
# npm, the largest export, is ~220 MB. 512 MB leaves headroom while keeping
# the damage from a runaway or hostile response bounded -- the cap is what
# stops a response that never ends from filling the disk.
MAX_BULK_BYTES = 512 << 20
_DOWNLOAD_LOCK = threading.Lock()
# _MEM is read and mutated from every request thread. It used to be touched
# unguarded, which gave two real races: a check-then-get that could read an
# entry another thread had just evicted, and an eviction where two threads
# picked the same victim — the second `del` raising KeyError, or `min()` raising
# "dictionary changed size during iteration". Neither is an OsvError, so
# neither was caught, and both surfaced as a 500 for the whole search.
_MEM_LOCK = threading.Lock()

# One load lock per ecosystem, held across download *and* parse. The memo read
# was already guarded and the download was serialised, but the parse -- the
# expensive part -- ran completely unlocked: on a cold cache N concurrent
# requests for the same ecosystem each inflated and normalised the entire
# archive, the last writer won, and the rest was garbage. npm's export is
# 226,880 members and ~372 MB uncompressed, against a shipped config of
# --workers 1 --threads 8, so eight simultaneous npm searches is a realistic
# way to run the container out of memory.
_LOAD_LOCKS: dict[str, threading.Lock] = {}
_LOAD_LOCKS_GUARD = threading.Lock()


def _load_lock(ecosystem: str) -> threading.Lock:
    with _LOAD_LOCKS_GUARD:
        return _LOAD_LOCKS.setdefault(ecosystem, threading.Lock())


class OsvError(RuntimeError):
    pass


def supported_ecosystem(ghsa_ecosystem: str) -> bool:
    return ghsa_ecosystem in ECOSYSTEM_MAP


# ---------------------------------------------------------------------------
# Download + cache the bulk zip
# ---------------------------------------------------------------------------

def _introduced_range(ranges: list) -> str | None:
    """A readable ">= x, < y" from OSV's event list, or None.

    `vulnerable_version_range` sat hard-coded None next to a raw copy of
    `ranges` that nothing read. This is the part of it a reader wants.
    """
    for rng in ranges or []:
        introduced = fixed = None
        for event in rng.get("events") or []:
            introduced = event.get("introduced") or introduced
            fixed = event.get("fixed") or fixed
        # OSV writes introduced "0" for "since the beginning", which is not
        # a bound worth rendering.
        if introduced == "0":
            introduced = None
        if introduced and fixed:
            return f">= {introduced}, < {fixed}"
        if introduced:
            return f">= {introduced}"
        if fixed:
            return f"< {fixed}"
    return None


def _zip_path(osv_eco: str) -> str:
    """Cache path for an ecosystem's bulk zip.

    download_ecosystem is a public entry point taking an arbitrary string.
    Every caller routes through ECOSYSTEM_MAP today, so this is hardening
    rather than a live hole -- but "replace / and space" left ".." intact,
    and the result is joined onto CACHE_DIR.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", osv_eco).strip(".")
    if not safe:
        raise OsvError(f"unusable OSV ecosystem name: {osv_eco!r}")
    path = os.path.join(CACHE_DIR, f"{safe}.zip")
    if os.path.dirname(os.path.abspath(path)) != os.path.abspath(CACHE_DIR):
        raise OsvError(f"refusing a cache path outside {CACHE_DIR}: {osv_eco!r}")
    return path


def download_ecosystem(osv_eco: str, force: bool = False,
                       max_age: int = DEFAULT_MAX_AGE, timeout: int = 120) -> str:
    """Ensure the ecosystem's all.zip is cached locally; return its path."""
    with _DOWNLOAD_LOCK:
        os.makedirs(CACHE_DIR, exist_ok=True)
        path = _zip_path(osv_eco)
        if (not force and os.path.exists(path)
                and (time.time() - os.path.getmtime(path)) < max_age
                and os.path.getsize(path) > 0):
            return path

        # quote(): several OSV ecosystem names contain a space ("GitHub
        # Actions", "Rocky Linux"). Interpolated raw, http.client rejects the
        # path outright -- so the `actions` ecosystem, which the UI offers in
        # its dropdown, could never be fetched at all. The broad handler below
        # then reported it as a generic "OSV fetch failed".
        url = f"{OSV_BASE}/{urllib.parse.quote(osv_eco)}/all.zip"
        req = urllib.request.Request(url, headers={"user-agent": USER_AGENT})

        tmp = path + ".tmp"

        def _once() -> None:
            # Streamed to disk in chunks, not read() into memory. npm's export
            # is ~220 MB, and buffering it whole and then copying it into a
            # BytesIO for the zip probe cost ~440 MB peak for a file that is
            # only ever used from disk afterwards. The running cap also stops
            # a hostile or broken upstream streaming until the process dies,
            # which no Content-Length check would have caught.
            written = 0
            with urllib.request.urlopen(req, timeout=timeout) as resp, \
                    open(tmp, "wb") as handle:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_BULK_BYTES:
                        raise OsvError(
                            f"OSV bulk for {osv_eco} exceeded "
                            f"{MAX_BULK_BYTES // (1 << 20)} MB; refusing it")
                    handle.write(chunk)

        try:
            http_retry.with_retries(
                _once, what=f"OSV bulk {osv_eco}", attempts=2)
        except Exception as e:  # surface a clean message to the UI
            _unlink_quietly(tmp)
            # A stale export beats no export. The freshness check above only
            # short-circuits on success, so once the zip was a day old a
            # transient download failure dropped OSV from the search entirely
            # -- while a perfectly usable copy sat on disk.
            if not force and os.path.exists(path) and os.path.getsize(path) > 0:
                age_hours = (time.time() - os.path.getmtime(path)) / 3600
                logger.warning(
                    "OSV refresh for %s failed (%s); using the cached copy, "
                    "which is %.1f hours old", osv_eco, e, age_hours)
                return path
            raise OsvError(f"could not download OSV bulk for {osv_eco}: {e}") from e

        # Validate the temp file, then publish it atomically: a half-written
        # or non-zip download must never replace a cache that still works.
        if not zipfile.is_zipfile(tmp):
            _unlink_quietly(tmp)
            raise OsvError(f"OSV bulk response for {osv_eco} is not a valid zip archive")
        try:
            os.replace(tmp, path)
        except OSError as e:
            _unlink_quietly(tmp)
            raise OsvError(f"could not cache OSV bulk for {osv_eco}: {e}") from e
        return path


def _unlink_quietly(path: str) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)


_QUAL_MAP = {"LOW": "low", "MODERATE": "medium", "MEDIUM": "medium",
             "HIGH": "high", "CRITICAL": "critical"}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_GHSA_RE = re.compile(r"^GHSA-", re.I)


# ---------------------------------------------------------------------------
# Normalise one OSV record -> the shared advisory shape
# ---------------------------------------------------------------------------

def normalize_osv(rec: dict) -> dict:
    osv_id = rec.get("id", "")
    aliases = rec.get("aliases") or []
    ghsa_id = osv_id if _GHSA_RE.match(osv_id) else next(
        (a for a in aliases if _GHSA_RE.match(a)), osv_id)
    cve_id = next((a for a in aliases if _CVE_RE.match(a)), None)
    if not cve_id and _CVE_RE.match(osv_id):
        cve_id = osv_id

    cwes = list((rec.get("database_specific") or {}).get("cwe_ids") or [])

    # Score from the v3 vector, which is computed exactly per the spec. v4 used
    # to be tried first, which meant the 922 records carrying both got the
    # made-up v4 number in place of the correct v3 one. v4 is no longer scored
    # at all (see cvss.is_v4_vector); the vector is still carried so an operator
    # can look it up, and severity for a v4-only record comes from the
    # publisher's own qualitative rating.
    ds_sev = (rec.get("database_specific") or {}).get("severity")
    cvss_score = None
    cvss_vector = None
    for s in rec.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = base_score(s.get("score", ""))
            if score is not None:
                cvss_score, cvss_vector = score, s.get("score", "")
                break
    if cvss_vector is None:
        # No usable v3. Surface whatever vector there is, unscored.
        cvss_vector = next(
            (s.get("score", "") for s in rec.get("severity") or []
             if is_v4_vector(s.get("score", ""))),
            None,
        )
    if ds_sev and str(ds_sev).upper() in _QUAL_MAP:
        severity = _QUAL_MAP[str(ds_sev).upper()]
    else:
        severity = severity_from_score(cvss_score)

    packages = []
    ecos = set()
    for aff in rec.get("affected") or []:
        pkg = (aff or {}).get("package") or {}
        name = pkg.get("name")
        if not name:
            continue
        ranges = aff.get("ranges") or []
        fixed_versions = [
            ev["fixed"]
            for rng in ranges
            for ev in rng.get("events") or []
            if ev.get("fixed")
        ]
        eco = pkg.get("ecosystem")
        if eco:
            ecos.add(eco)
        packages.append({
            "ecosystem": eco,
            "name": name,
            # purl, ranges and versions are not kept: nothing reads
            # them -- not the UI, not app.py, not search_service -- and they
            # were ~8% of the cached payload by bytes and 13% of the memory
            # retained for the Go export, persisted verbatim into SQLite.
            # The one thing a reader wants out of `ranges` is the introduced
            # version, which fills the field that sat hard-coded None beside
            # the raw copy.
            "vulnerable_version_range": _introduced_range(ranges),
            "first_patched_version": fixed_versions[0] if fixed_versions else None,
            "fixed_versions": fixed_versions,
        })

    return {
        "advisory_id": ghsa_id,
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": rec.get("summary") or (rec.get("details") or "")[:120],
        "description": rec.get("details") or "",
        "severity": severity,
        "cvss_score": cvss_score,
        # The vector the score came from, or the v4 vector when there is no
        # score. A v4-only advisory now shows its vector rather than a number
        # nothing computed honestly.
        "cvss_vector": cvss_vector,
        "cwes": cwes,
        "packages": packages,
        "ecosystems": sorted(ecos),
        "html_url": f"https://osv.dev/vulnerability/{osv_id}",
        "references": [r.get("url") for r in (rec.get("references") or []) if r.get("url")],
        "published_at": rec.get("published"),
        "updated_at": rec.get("modified"),
        "withdrawn_at": rec.get("withdrawn"),
        "type": "osv",
        "source": "osv",
        "osv_id": osv_id,
        "aliases": aliases,
    }


# ---------------------------------------------------------------------------
# Load + filter
# ---------------------------------------------------------------------------

def _load_records(ghsa_ecosystem: str, force: bool = False) -> list[dict]:
    """Return all normalized OSV records for an ecosystem (memoised).

    Cached entries are evicted after *_MEM_TTL* seconds, and the total number
    of cached ecosystems is capped at *_MEM_MAX* (oldest-first eviction).
    """
    osv_eco = ECOSYSTEM_MAP.get(ghsa_ecosystem)
    if not osv_eco:
        raise OsvError(f"ecosystem '{ghsa_ecosystem}' not supported by OSV bulk mode")

    # Fast path: return cached records if within TTL. One lookup under the lock,
    # so the entry cannot be evicted between the membership test and the read.
    if not force:
        with _MEM_LOCK:
            entry = _MEM.get(ghsa_ecosystem)
        if entry is not None and (time.time() - entry[0]) < _MEM_TTL:
            return entry[1]

    with _load_lock(ghsa_ecosystem):
        # Re-check under the lock: while we waited, the thread that held it
        # may have finished the very load we were about to repeat.
        if not force:
            with _MEM_LOCK:
                entry = _MEM.get(ghsa_ecosystem)
            if entry is not None and (time.time() - entry[0]) < _MEM_TTL:
                return entry[1]
        return _load_records_locked(ghsa_ecosystem, osv_eco, force)


def _load_records_locked(ghsa_ecosystem: str, osv_eco: str, force: bool) -> list[dict]:
    """Download and parse one ecosystem. Caller holds that ecosystem's lock."""
    path = download_ecosystem(osv_eco, force=force)
    records: list[dict] = []
    skipped = 0
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    rec = json.loads(zf.read(name))
                    records.append(normalize_osv(rec))
                except Exception:
                    # normalize_osv used to sit outside this block, and the
                    # outer handler catches only archive errors, so one record
                    # of the wrong shape — a JSON array where an object was
                    # expected raises AttributeError — escaped as a 500 for the
                    # entire search, not just for OSV. An export with 226,880
                    # records should not be all-or-nothing on any one of them.
                    skipped += 1
                    logger.debug("skipping unusable OSV record %s in %s", name, path)
    except (OSError, zipfile.BadZipFile) as e:
        raise OsvError(f"invalid OSV bulk archive for {osv_eco}: {e}") from e

    if skipped:
        # At INFO, not debug: silent data loss is the failure mode this whole
        # tool exists to avoid.
        logger.info("Skipped %d unusable record(s) of %d in %s",
                    skipped, skipped + len(records), os.path.basename(path))

    with _MEM_LOCK:
        _MEM[ghsa_ecosystem] = (time.time(), records)
        # Cap the number of ecosystems held in memory. Inside the lock, so two
        # threads cannot choose the same victim.
        while len(_MEM) > _MEM_MAX:
            oldest = min(_MEM, key=lambda k: _MEM[k][0])
            del _MEM[oldest]

    return records


def fetch_osv(ecosystem: str, cwes: list[str], affects: str | None = None,
              severity: str | None = None, max_results: int = 200,
              force_refresh: bool = False,
              published: str | None = None) -> list[dict]:
    """Filter the ecosystem's OSV records by CWE set (+ optional package/severity).

    Records with none of the target CWEs are dropped. Sorted newest-first.
    """
    if ecosystem in (None, "", "any"):
        raise OsvError("OSV bulk mode needs a specific ecosystem (not 'any')")
    # str(): a non-string here raised out as an AttributeError, which is
    # not an OsvError, so it escaped per-source degradation and 500'd the
    # entire search instead of dropping OSV.
    want = {normalize_cwe_id(str(c)) for c in cwes}
    records = _load_records(ecosystem, force=force_refresh)

    out = []
    for r in records:
        rec_cwes = {normalize_cwe_id(str(c)) for c in r.get("cwes") or []}
        if not (rec_cwes & want):
            continue
        if not matches_common_filters(
            r, published=published, affects=affects, severity=severity
        ):
            continue
        out.append(r)

    out.sort(key=lambda r: (r.get("published_at") or ""), reverse=True)
    return out[:max_results]


def fetch_osv_native(
    ecosystem: str,
    categories: list[str],
    max_results: int = 100,
    force_refresh: bool = False,
    affects: str | None = None,
    severity: str | None = None,
    published: str | None = None,
) -> list[dict]:
    """Return source-native OSV records (GO-/RUSTSEC-/PYSEC-…) that CWE filtering
    can never reach, narrowed by bug-class keywords so the AI has a sane pool.

    These carry no CWE tag, so the caller is expected to run the AI classifier on
    them to decide which are genuinely BAC / injection / etc.
    """
    if ecosystem in (None, "", "any"):
        raise OsvError("OSV native mode needs a specific ecosystem (not 'any')")
    kws = category_keywords(categories)
    records = _load_records(ecosystem, force=force_refresh)

    out = []
    for r in records:
        if str(r.get("ghsa_id", "")).startswith("GHSA"):
            continue  # GHSA-sourced -> already covered by the CWE path
        if r.get("cwes"):
            continue  # CWE-tagged -> already reachable via the CWE filter
        if kws:
            text = (r.get("summary", "") + " " + r.get("description", "")).lower()
            if not any(k in text for k in kws):
                continue
        if not matches_common_filters(
            r, published=published, affects=affects, severity=severity
        ):
            continue
        out.append(dict(r, native=True))

    out.sort(key=lambda r: (r.get("published_at") or ""), reverse=True)
    return out[:max_results]


def cache_status() -> list[dict]:
    """For the UI: which ecosystems are downloaded and how old."""
    status = []
    for ghsa_eco, osv_eco in ECOSYSTEM_MAP.items():
        p = _zip_path(osv_eco)
        try:
            size = os.path.getsize(p)
            mtime = os.path.getmtime(p)
        except OSError:
            # Deleted between the check and the read, or never there.
            # These caches are documented as safe to delete at any time,
            # and this renders on every healthcheck.
            continue
        status.append({
            "ecosystem": ghsa_eco,
            "size_mb": round(size / 1e6, 1),
            "age_hours": round((time.time() - mtime) / 3600, 1),
        })
    return status
