"""Search orchestration: parse request → fetch sources → merge/dedupe → sort → enrich."""

from __future__ import annotations

import copy
import json
import logging
import re
from dataclasses import dataclass, field

from . import ai_classifier
from . import cache
from . import epss_client
from . import ghsa_client as ghsa
from . import nvd_client
from . import osv_client
from . import records as records_mod
from .cwe_categories import (
    ECOSYSTEMS,
    SEVERITIES,
    canonical_category,
    cwe_label,
    is_known_category,
    normalize_cwe_id,
    resolve_cwes,
)
from .query_filters import matches_common_filters, valid_published_filter

logger = logging.getLogger(__name__)

VALID_SORTS = ("published", "updated", "cve_id", "epss_percentage", "epss_percentile")
VALID_DIRECTIONS = ("asc", "desc")
VALID_SOURCES = ("ghsa", "nvd", "osv", "osv-native")
VALID_TYPES = ("reviewed", "unreviewed", "malware")
_SORT_FIELD = {
    "published": "published_at",
    "updated": "updated_at",
    "cve_id": "cve_id",
    "epss_percentage": "epss_percentage",
    "epss_percentile": "epss_percentile",
}
MAX_CATEGORY_INPUTS = 100


_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d+)$", re.I)


def _cve_sort_key(value: object) -> tuple[int, int, str]:
    """(year, sequence, raw) so CVE-2026-100 sorts above CVE-2026-9.

    Anything that is not a CVE id sorts below every real one in ascending
    order, which keeps records without a CVE out of the way rather than
    interleaved.
    """
    text = value if isinstance(value, str) else ""
    match = _CVE_ID_RE.match(text.strip())
    if not match:
        return (-1, -1, text)
    return (int(match.group(1)), int(match.group(2)), text)


class SearchError(RuntimeError):
    """Search failure that maps to an HTTP response.

    Return ``public_message`` to clients; do not stringify the exception.
    """

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status
        self.public_message = message


@dataclass
class SearchQuery:
    categories: list[str]
    include_extended: bool
    ecosystem: str
    affects: str | None
    severity: str
    published: str | None
    adv_type: str
    sort: str
    direction: str
    max_results: int
    sources: list[str]
    refresh_osv: bool
    cwes: list[str]
    #: Keep the per-source snapshots in the response. Off by default: they are
    #: ~35% of the payload (measured over 500 cached rows: 2.91 MB -> 1.89 MB)
    #: and nothing reads them -- not the UI, not app.py. They stay available
    #: for anyone auditing how a row was merged.
    include_source_records: bool


@dataclass
class SearchOutcome:
    results: list[dict]
    warnings: list[str]
    per_source: dict[str, int]
    #: Row counts at each pipeline stage. ``per_source`` is measured before the
    #: merge and ``len(results)`` after truncation, so the two never agreed and
    #: a script could not tell a de-duplicated row from a dropped one. These
    #: name each stage instead of leaving the caller to infer it.
    stats: dict = field(default_factory=dict)


def parse_str_list(
    val,
    *,
    field_name: str = "values",
    max_items: int = 100,
    max_item_length: int = 300,
) -> list[str]:
    """Accept a bounded JSON string list or comma-separated string."""
    if val is None or val == "":
        return []
    if isinstance(val, list):
        if len(val) > max_items:
            raise SearchError(
                f"Too many {field_name}; maximum is {max_items}.", 400
            )
        raw_values = val
    elif isinstance(val, str):
        if len(val) > max_items * (max_item_length + 1):
            raise SearchError(f"{field_name} is too long.", 400)
        raw_values = val.split(",")
    else:
        raise SearchError(f"{field_name} must be a list or comma-separated string.", 400)

    out: list[str] = []
    for item in raw_values:
        if not isinstance(item, str):
            raise SearchError(f"{field_name} entries must be strings.", 400)
        text = item.strip()
        if not text:
            continue
        if len(text) > max_item_length:
            raise SearchError(
                f"{field_name} entries may not exceed {max_item_length} characters.",
                400,
            )
        out.append(text)
        if len(out) > max_items:
            raise SearchError(
                f"Too many {field_name}; maximum is {max_items}.", 400
            )
    return out


def parse_bool(value, default: bool = False) -> bool:
    """Parse JSON booleans without treating the string "false" as truthy."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "1", "yes"):
            return True
        if normalized in ("false", "0", "no"):
            return False
    raise SearchError(f"Invalid boolean value: {value!r}", 400)


def parse_text(value, default: str, field_name: str) -> str:
    if value is None or value == "":
        return default
    if not isinstance(value, str):
        raise SearchError(f"{field_name} must be a string.", 400)
    return value.strip() or default


def parse_search_query(body: dict) -> SearchQuery:
    """Validate a raw /api/search JSON body into a SearchQuery."""
    category_inputs = parse_str_list(
        body.get("categories"),
        field_name="categories",
        max_items=MAX_CATEGORY_INPUTS,
        max_item_length=64,
    )
    if not category_inputs:
        raise SearchError("Select at least one bug class or CWE.", 400)
    categories = list(dict.fromkeys(canonical_category(c) for c in category_inputs))
    include_extended = parse_bool(body.get("include_extended"), True)
    ecosystem = parse_text(body.get("ecosystem"), "any", "ecosystem")
    affects = parse_text(body.get("affects"), "", "affects") or None
    severity = parse_text(body.get("severity"), "any", "severity")
    published = parse_text(body.get("published"), "", "published") or None
    adv_type = parse_text(body.get("type"), "reviewed", "type")
    sort = parse_text(body.get("sort"), "published", "sort")
    if sort not in VALID_SORTS:
        sort = "published"
    direction = parse_text(body.get("direction"), "desc", "direction")
    if direction not in VALID_DIRECTIONS:
        direction = "desc"
    try:
        max_results = max(1, min(500, int(body.get("max_results", 100))))
    except (TypeError, ValueError):
        max_results = 100

    # A category is either a curated bug class ("bac") or a single CWE picked
    # from the full MITRE catalog ("cwe:1321").
    unknown_categories = [
        category for category in categories if not is_known_category(category)
    ]
    if unknown_categories:
        raise SearchError(f"Unsupported categories: {', '.join(unknown_categories)}", 400)

    cwes = resolve_cwes(categories, include_extended)
    if not cwes:
        raise SearchError("No CWEs resolved from the selected categories.", 400)

    if ecosystem not in ("any", *ECOSYSTEMS):
        raise SearchError(f"Unsupported ecosystem: {ecosystem}", 400)
    if severity not in ("any", *SEVERITIES):
        raise SearchError(f"Unsupported severity: {severity}", 400)
    if adv_type not in VALID_TYPES:
        raise SearchError(f"Unsupported advisory type: {adv_type}", 400)
    if not valid_published_filter(published):
        raise SearchError(f"Invalid published filter: {published}", 400)
    if affects and len(affects) > 300:
        raise SearchError("affects is too long (maximum 300 characters).", 400)

    sources = parse_str_list(
        body.get("sources"),
        field_name="sources",
        max_items=len(VALID_SOURCES),
        max_item_length=32,
    ) or ["ghsa"]
    sources = list(dict.fromkeys(sources))
    invalid_sources = [source for source in sources if source not in VALID_SOURCES]
    if invalid_sources:
        raise SearchError(f"Unsupported data source(s): {', '.join(invalid_sources)}", 400)
    refresh_osv = parse_bool(body.get("refresh_osv"), False)
    include_source_records = parse_bool(body.get("include_source_records"), False)

    return SearchQuery(
        categories=categories,
        include_extended=include_extended,
        ecosystem=ecosystem,
        affects=affects,
        severity=severity,
        published=published,
        adv_type=adv_type,
        sort=sort,
        direction=direction,
        max_results=max_results,
        sources=sources,
        refresh_osv=refresh_osv,
        include_source_records=include_source_records,
        cwes=cwes,
    )


_SOURCE_PRIORITY = {"ghsa": 0, "osv": 1, "nvd": 2}
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _record_identifier_values(record: dict) -> list[str]:
    values = [record.get("advisory_id"), record.get("cve_id"), record.get("ghsa_id"), record.get("osv_id")]
    values.extend(record.get("aliases") or [])
    return [str(value).strip() for value in values if str(value or "").strip()]


def _record_identifiers(record: dict) -> set[str]:
    return {value.upper() for value in _record_identifier_values(record)}


def _unique_dicts(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for item in items:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        if key not in seen:
            seen.add(key)
            out.append(copy.deepcopy(item))
    return out


def _merge_group(records: list[dict]) -> dict:
    base = min(records, key=lambda item: _SOURCE_PRIORITY.get(item.get("source"), 99))
    merged = copy.deepcopy(base)
    sources = sorted({record.get("source", "?") for record in records})
    merged["sources"] = sources

    source_records: dict[str, list[dict]] = {}
    for record in records:
        source = record.get("source", "?")
        snapshot = {
            key: copy.deepcopy(value)
            for key, value in record.items()
            if key not in ("source_records", "cwe_labels", "ai")
        }
        source_records.setdefault(source, []).append(snapshot)
    merged["source_records"] = source_records

    # Dedupe case-insensitively but publish the identifier as its source wrote
    # it: GHSA ids are lowercase base32, and an upper-cased alias no longer
    # resolves against the GitHub API or a permalink.
    identifier_values: list[str] = []
    seen_identifiers: set[str] = set()
    for record in records:
        for identifier in _record_identifier_values(record):
            if identifier.upper() not in seen_identifiers:
                seen_identifiers.add(identifier.upper())
                identifier_values.append(identifier)
    merged["aliases"] = sorted(identifier_values, key=str.upper)
    ghsa_ids = sorted(
        (identifier for identifier in identifier_values if identifier.upper().startswith("GHSA-")),
        key=str.upper,
    )
    cve_ids = sorted(
        (identifier for identifier in identifier_values if identifier.upper().startswith("CVE-")),
        key=str.upper,
    )
    if ghsa_ids:
        base_id = str(base.get("ghsa_id") or "")
        merged["ghsa_id"] = base_id if base_id.upper().startswith("GHSA-") else ghsa_ids[0]
    elif cve_ids:
        merged["ghsa_id"] = cve_ids[0]
    # advisory_id: prefer the base record's advisory_id; fall back to best
    # GHSA or CVE identifier so the merged record always has a stable key.
    if not merged.get("advisory_id"):
        merged["advisory_id"] = merged.get("ghsa_id") or (cve_ids[0] if cve_ids else "")
    if cve_ids:
        base_cve = str(base.get("cve_id") or "")
        merged["cve_id"] = base_cve if base_cve.upper().startswith("CVE-") else cve_ids[0]

    cwes: dict[str, str] = {}
    for record in records:
        for cwe in record.get("cwes") or []:
            normalized = normalize_cwe_id(str(cwe))
            if normalized:
                cwes.setdefault(normalized, normalized)
    merged["cwes"] = list(cwes.values())

    merged["references"] = list(dict.fromkeys(
        reference
        for record in records
        for reference in (record.get("references") or [])
        if reference
    ))
    merged["packages"] = _unique_dicts([
        package
        for record in records
        for package in (record.get("packages") or [])
        if isinstance(package, dict)
    ])
    merged["ecosystems"] = sorted({
        ecosystem
        for record in records
        for ecosystem in (record.get("ecosystems") or [])
        if ecosystem
    })

    # Derive these from source_records, not from `records` keyed by source
    # name. One source can contribute several advisories to a group -- two
    # GHSA records sharing a CVE is the case merge_advisories exists for -- and
    # a comprehension keyed by source silently kept only the last of them, so
    # the max() below ran over one value per source instead of all of them.
    # A medium+low GHSA pair therefore merged to "low", and reversing the page
    # order merged the same advisory to "medium".
    severity_by_source = {
        source: max(
            (record.get("severity") or "unknown" for record in group),
            key=lambda value: _SEVERITY_RANK.get(value, 0),
        )
        for source, group in source_records.items()
    }
    cvss_by_source = {}
    for source, group in source_records.items():
        scores = [
            record["cvss_score"] for record in group
            if isinstance(record.get("cvss_score"), (int, float))
        ]
        if scores:
            cvss_by_source[source] = max(scores)
    merged["severity_by_source"] = severity_by_source
    merged["cvss_by_source"] = cvss_by_source
    merged["severity"] = max(
        severity_by_source.values(), key=lambda value: _SEVERITY_RANK.get(value, 0)
    )
    if cvss_by_source:
        merged["cvss_score"] = max(cvss_by_source.values())

    published = [record.get("published_at") for record in records if record.get("published_at")]
    updated = [record.get("updated_at") for record in records if record.get("updated_at")]
    withdrawn = [record.get("withdrawn_at") for record in records if record.get("withdrawn_at")]
    # Keep the base advisory's own publication date.  min() across sources
    # backdates a 2025 GHSA advisory to its 2019 CVE, which then sorts and
    # displays under a year in which that advisory did not yet exist.  Every
    # source's own date stays available under source_records.
    merged["published_at"] = base.get("published_at") or (min(published) if published else None)
    merged["updated_at"] = max(updated) if updated else None
    merged["withdrawn_at"] = max(withdrawn) if withdrawn else None
    merged["kev"] = any(bool(record.get("kev")) for record in records)
    merged["native"] = any(bool(record.get("native")) for record in records)
    for key in ("nvd_status", "osv_id"):
        value = next((record.get(key) for record in records if record.get(key)), None)
        if value is not None:
            merged[key] = value
    # cvss_vector is set unconditionally, not through the loop above: only OSV
    # produces it, and GHSA always wins as the base record, so a merged
    # GHSA+OSV row inherited a base that has no such key and silently dropped
    # the vector. That is the one field a v4-only advisory has instead of a
    # score, so losing it left `cvss_score: null` with nothing to look up.
    merged["cvss_vector"] = next(
        (record.get("cvss_vector") for record in records if record.get("cvss_vector")),
        None,
    )
    return merged


def merge_advisories(collected: list[dict]) -> list[dict]:
    """Dedupe by the full alias graph and preserve source-specific metadata.

    Bridging on a shared *CVE* looks unsafe in theory — a CVE names a
    vulnerability, and GitHub mints one GHSA per affected package, so four
    advisories can carry one CVE.  Measured against the cached exports
    (242,566 records: npm + Go + Maven) it is safe in practice, and a guard
    against it is actively harmful:

    - Where GitHub does split a CVE across packages, the records cross-declare
      each other in ``aliases`` (all four advisories behind CVE-2020-29242 list
      the other three), so they merge on advisory identifiers regardless.
    - CVE-only bridges between two records that each carry their own advisory
      id occur 8 times in that corpus, and all 8 are GitHub "Duplicate
      Advisory" pairs that must merge — including one package rename
      (fuxa-server / @frangoteam/fuxa) whose package sets are disjoint.

    A guard that skipped those bridges scored 0 correct splits against 8
    regressions, so the alias graph is deliberately left transitive.  Revisit
    only with counter-evidence from a corpus that contains a genuine
    per-package split with no reciprocal alias.
    """
    if not collected:
        return []

    parents = list(range(len(collected)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    owner: dict[str, int] = {}
    for index, record in enumerate(collected):
        for identifier in _record_identifiers(record):
            if identifier in owner:
                union(index, owner[identifier])
            else:
                owner[identifier] = index

    groups: dict[int, list[dict]] = {}
    order: list[int] = []
    for index, record in enumerate(collected):
        root = find(index)
        if root not in groups:
            groups[root] = []
            order.append(root)
        groups[root].append(record)
    return [_merge_group(groups[root]) for root in order]


def _group_matches_filters(
    record: dict,
    *,
    published: str | None = None,
    affects: str | None = None,
    severity: str | None = None,
) -> bool:
    """Keep a merged record when any single source's record matches the query.

    _merge_group deliberately widens severity to the maximum across sources, so
    filtering the merged value would drop an advisory the moment a second source
    disagreed: a GHSA record tagged `high` survived a `severity=high` search on
    its own and vanished as soon as NVD called the same CVE `critical`.  Adding
    a source must never subtract results.
    """
    candidates = [
        source_record
        for source_group in (record.get("source_records") or {}).values()
        for source_record in source_group
    ] or [record]
    return any(
        matches_common_filters(
            candidate, published=published, affects=affects, severity=severity
        )
        for candidate in candidates
    )


def run_search(q: SearchQuery) -> SearchOutcome:
    """Fetch from each requested source, then merge, sort, cache and enrich."""
    warnings: list[str] = []
    per_source: dict[str, int] = {}
    collected: list[dict] = []
    # 'osv' and 'osv-native' read the same bulk export. Honour the refresh
    # request once so selecting both does not download and re-parse ~10 MB twice.
    osv_refresh_pending = q.refresh_osv

    # --- GHSA (server-side CWE filter) ---
    if "ghsa" in q.sources:
        ghsa_sort = q.sort if q.sort in ("published", "updated") else "published"
        params = ghsa.SearchParams(
            ecosystem=q.ecosystem, cwes=q.cwes, affects=q.affects, severity=q.severity,
            type=q.adv_type, published=q.published, sort=ghsa_sort, direction=q.direction,
            max_results=q.max_results, per_page=100,
        )
        try:
            raw = ghsa.fetch_advisories(params)
            # Per record: ghsa.normalize dereferences identifiers[].value,
            # cwes[].cwe_id and severity.lower(), none of which the API
            # guarantees. One advisory with "identifiers": [None] used to
            # raise AttributeError -- not a GhCliError, so it bypassed the
            # degradation below and 500'd the whole search, discarding the
            # results already fetched from the other three sources.
            g, skipped = records_mod.normalize_all(
                raw, ghsa.normalize, source="GHSA",
                identify=lambda a: records_mod.identify(a, "ghsa_id"),
            )
            collected += g
            per_source["ghsa"] = len(g)
            if skipped:
                warnings.append(
                    f"GHSA: skipped {skipped} advisory record(s) that could not be read."
                )
        except ghsa.GhCliError as e:
            logger.warning("GHSA fetch failed: %s", e)
            if q.sources == ["ghsa"]:
                raise SearchError("GHSA fetch failed.", 502) from e
            warnings.append("GHSA fetch failed.")

    # --- OSV (local CWE filter over the bulk export) ---
    if "osv" in q.sources:
        if not osv_client.supported_ecosystem(q.ecosystem):
            warnings.append(
                f"OSV bulk mode needs a specific supported ecosystem; "
                f"'{q.ecosystem}' skipped. Supported: {', '.join(osv_client.ECOSYSTEM_MAP)}."
            )
        else:
            refresh, osv_refresh_pending = osv_refresh_pending, False
            try:
                o = osv_client.fetch_osv(q.ecosystem, q.cwes, affects=q.affects,
                                         severity=q.severity, max_results=q.max_results,
                                         force_refresh=refresh,
                                         published=q.published)
                collected += o
                per_source["osv"] = len(o)
            except osv_client.OsvError as e:
                logger.warning("OSV fetch failed: %s", e)
                warnings.append("OSV fetch failed.")

    # --- NVD (server-side CWE filter via NIST API v2) ---
    if "nvd" in q.sources:
        nvd_params = nvd_client.NvdSearchParams(
            cwes=q.cwes,
            keyword=q.affects,
            severity=q.severity,
            published_range=q.published,
            max_results=q.max_results,
        )
        # The UI offers "Advisory type" and "Ecosystem" as global scope
        # controls, and docs/usage.md lists them with the rest -- but only
        # GHSA is given either one, and the post-merge re-filter re-checks
        # neither. A `type: malware` search therefore returned Log4Shell from
        # NVD with nothing on screen saying the filter had been ignored.
        # Honouring them for NVD is not possible as the records stand (its
        # `type` holds the source name and every package is stamped
        # ecosystem "nvd"), so say so rather than quietly widening the query.
        if q.adv_type and q.adv_type != "reviewed":
            warnings.append(
                f"NVD does not support the '{q.adv_type}' advisory-type "
                "filter; its rows are unfiltered by type."
            )
        if q.ecosystem and q.ecosystem != "any":
            warnings.append(
                f"NVD is not indexed by ecosystem; its rows are not limited "
                f"to '{q.ecosystem}'."
            )
        nvd_report: dict = {}
        try:
            n = nvd_client.fetch_nvd(nvd_params, report=nvd_report)
            collected += n
            per_source["nvd"] = len(n)
            failed = nvd_report.get("failed_cwes", 0)
            if failed:
                warnings.append(
                    f"NVD: {failed} of {nvd_report.get('total_cwes', failed)} "
                    "CWE queries failed; its results are incomplete."
                )
        except nvd_client.NvdError as e:
            logger.warning("NVD fetch failed: %s", e)
            if q.sources == ["nvd"]:
                raise SearchError("NVD fetch failed.", 502) from e
            warnings.append("NVD fetch failed.")

    # --- OSV native (no CWE) — needs the AI pass to be useful ---
    if "osv-native" in q.sources:
        if not osv_client.supported_ecosystem(q.ecosystem):
            warnings.append(
                f"OSV native mode needs a specific supported ecosystem; "
                f"'{q.ecosystem}' skipped."
            )
        else:
            refresh, osv_refresh_pending = osv_refresh_pending, False
            try:
                on = osv_client.fetch_osv_native(q.ecosystem, q.categories,
                                                 max_results=q.max_results,
                                                 force_refresh=refresh,
                                                 affects=q.affects,
                                                 severity=q.severity,
                                                 published=q.published)
                collected += on
                per_source["osv-native"] = len(on)
                if on:
                    warnings.append(
                        f"{len(on)} OSV native records have no CWE — click "
                        f"'Refine with AI' to classify them."
                    )
            except osv_client.OsvError as e:
                logger.warning("OSV native fetch failed: %s", e)
                warnings.append("OSV native fetch failed.")

    fetched_total = len(collected)
    results = merge_advisories(collected)
    merged_total = len(results)
    results = [
        record for record in results
        if _group_matches_filters(
            record,
            published=q.published,
            affects=q.affects,
            severity=q.severity,
        )
    ]
    filtered_total = len(results)

    # Sort by the requested field. Numeric EPSS fields cannot fall back to ""
    # — mixed float/str keys raise TypeError on Python 3.
    sort_field = _SORT_FIELD[q.sort]
    numeric = sort_field in ("epss_percentage", "epss_percentile")

    def _sort_key(record: dict):
        value = record.get(sort_field)
        if numeric:
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0.0
        if sort_field == "cve_id":
            # A CVE id is a year and a sequence number, not a word. Sorted as
            # text, "newest CVE first" silently meant "highest ASCII first" --
            # CVE-2026-9 outranked CVE-2026-100, and the sequence is not
            # zero-padded, so this is wrong for most real result sets.
            return _cve_sort_key(value)
        return value or ""

    def _enrich_epss(records: list[dict]) -> int:
        """Attach EPSS scores. Returns how many records got one."""
        cve_ids = [r["cve_id"] for r in records if r.get("cve_id")]
        if not cve_ids:
            return 0
        epss_scores = epss_client.fetch_epss(cve_ids)
        enriched = 0
        for rec in records:
            score = epss_scores.get(rec.get("cve_id", ""))
            if score:
                rec["epss_percentage"] = score["epss"]
                rec["epss_percentile"] = score["percentile"]
                enriched += 1
        return enriched

    # Sorting by EPSS needs every candidate scored first; every other sort mode
    # can truncate first, which keeps EPSS to one batched request instead of one
    # per 100 merged records (up to 4x max_results before truncation).
    if numeric:
        enriched = _enrich_epss(results)
        results.sort(key=_sort_key, reverse=(q.direction != "asc"))
        results = results[:q.max_results]
        # fetch_epss swallows every failure and returns {}, and _sort_key maps
        # a missing score to 0.0 -- so an EPSS outage silently handed the user
        # merge order presented as an exploit-probability ranking.
        # docs/data-sources.md promises a missing score is never rendered as a
        # measured zero; the ordering has to keep the same promise.
        if results and not enriched:
            warnings.append(
                "EPSS scores are unavailable, so these results are in merge "
                "order, not EPSS order."
            )
    else:
        results.sort(key=_sort_key, reverse=(q.direction != "asc"))
        results = results[:q.max_results]
        _enrich_epss(results)

    # Strip before caching and before the response. source_records is built
    # for the merge and for _group_matches_filters, both of which have already
    # run by here. Persisting it doubled advisories.db for data no reader ever
    # asked for, and shipping it doubled the JSON the browser has to parse.
    if not q.include_source_records:
        for rec in results:
            rec.pop("source_records", None)

    cache.upsert_advisories(results)

    # Attach CWE labels for the UI.
    for rec in results:
        rec["cwe_labels"] = [{"id": c, "label": cwe_label(c)} for c in rec.get("cwes", [])]

    # Attach cached AI only when every requested category has a fresh verdict.
    # Partial cache hits are completed by /api/ai/classify, never presented as a
    # finished multi-category decision.
    cfg = ai_classifier.load_config()
    ai_categories = [category for category in q.categories if is_known_category(category)]
    if cfg.configured and ai_categories:
        cached_by_category: dict[str, dict[str, dict]] = {}
        for category in ai_categories:
            fingerprints = {
                rec["advisory_id"]: ai_classifier.classification_fingerprint(
                    cfg, rec, category
                )
                for rec in results
            }
            cached_by_category[category] = cache.get_classifications(
                list(fingerprints),
                category,
                expected_fingerprints=fingerprints,
            )
        for rec in results:
            aid = rec["advisory_id"]
            category_verdicts = {
                category: cached_by_category[category][aid]
                for category in ai_categories
                if aid in cached_by_category[category]
            }
            if len(category_verdicts) == len(ai_categories):
                rec["ai"] = ai_classifier.aggregate_category_verdicts(
                    category_verdicts
                )

    return SearchOutcome(
        results=results,
        warnings=warnings,
        per_source=per_source,
        stats={
            "fetched_per_source": dict(per_source),
            "fetched_total": fetched_total,
            "after_merge": merged_total,
            "after_filter": filtered_total,
            "returned": len(results),
            # Whether rows were dropped purely to honour max_results, which is
            # the signal a paging client needs and could not previously derive:
            # a smaller `returned` might equally have meant de-duplication.
            "truncated": filtered_total > len(results),
        },
    )
