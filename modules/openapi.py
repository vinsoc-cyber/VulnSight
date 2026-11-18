"""The OpenAPI description of the HTTP API.

Written by hand, checked by machine. Flask carries no type information about
request or response bodies, so anything claiming to *derive* this document would
be deriving paths and inventing schemas — and an invented schema in an API
description is worse than none, because a client generator will believe it.

What is enforced instead (tests/test_openapi.py):

- every route in ``url_map`` under /api/v1 appears here, and vice versa, so a
  new endpoint cannot ship undescribed;
- the methods match;
- a real response from the app validates against the documented response schema.

That last one is the point: the document is checked against what the server
actually sends, not against what it was believed to send when it was written.
"""

from __future__ import annotations

import functools

from .config import MAX_AI_BATCH, MAX_AI_CALLS_PER_REQUEST
from .cwe_categories import CATEGORIES, ECOSYSTEMS, SEVERITIES
from .search_service import (DEFAULT_MAX_RESULTS, MAX_AFFECTS_LENGTH,
                              MAX_CATEGORY_INPUTS, MAX_RESULTS_CAP)

API_VERSION = "1.0.0"

_TOKEN_SCHEME = "vulnsightToken"

def _ref_to(name: str) -> dict:
    """A $ref usable inside a schema literal, before the registry exists.

    The nested uses -- Advisory inside SearchResponse.results, SearchStats
    inside .stats, Verdict inside ClassifyResponse.verdicts -- are written
    at module level, so `_ref`'s identity lookup cannot reach them. Naming
    the target here keeps those three out of the "registered but never
    referenced" state, which is the same decoration in a different place.
    `test_every_ref_resolves` fails if a name here is not published.
    """
    return {"$ref": f"#/components/schemas/{name}"}


_ERROR = {
    "type": "object",
    "required": ["error"],
    "properties": {
        "error": {
            "type": "string",
            "description": "Operator-facing message. Never an exception string.",
        }
    },
}

_SEARCH_REQUEST = {
    "type": "object",
    "required": ["categories"],
    "properties": {
        "categories": {
            "type": "array",
            "minItems": 1,
            # Imported, not retyped. This file already imports
            # MAX_CATEGORY_INPUTS and uses it correctly for classify;
            # hardcoding it here meant raising the limit left the spec
            # saying 100 with no test failing.
            "maxItems": MAX_CATEGORY_INPUTS,
            "items": {"type": "string", "maxLength": 64},
            "description": (
                "Curated bug-class keys and/or `cwe:<id>` for any single MITRE "
                "weakness. Both forms are filtered on and AI-scored."
            ),
        },
        "include_extended": {
            "type": "boolean",
            "default": True,
            "description": "Add each class's wider CWE set to its high-precision core.",
        },
        "ecosystem": {"type": "string", "enum": ["any", *ECOSYSTEMS], "default": "any"},
        "affects": {
            "type": "string",
            "maxLength": MAX_AFFECTS_LENGTH,
            "nullable": True,
            "description": (
                "Case-insensitive package name. Matches either half of an "
                "NVD `vendor:product` name, and the whole name otherwise."
            ),
        },
        "severity": {"type": "string", "enum": ["any", *SEVERITIES], "default": "any"},
        "published": {
            "type": "string",
            "description": (
                "`YYYY-MM-DD`, a comparator (`>=`, `>`, `<=`, `<`) plus a date, "
                "or a `from..to` range. Bounds are UTC."
            ),
        },
        "type": {
            "type": "string",
            "enum": ["reviewed", "unreviewed", "malware"],
            "default": "reviewed",
        },
        "sort": {
            "type": "string",
            "enum": ["published", "updated", "cve_id",
                     "epss_percentage", "epss_percentile"],
            "default": "published",
            "description": "An unrecognised value falls back to `published` silently.",
        },
        "direction": {"type": "string", "enum": ["asc", "desc"], "default": "desc"},
        "max_results": {
            "type": "integer", "minimum": 1,
            "maximum": MAX_RESULTS_CAP, "default": DEFAULT_MAX_RESULTS,
            "description": "Clamped, not rejected, when out of range.",
        },
        "sources": {
            "type": "array",
            "items": {"type": "string",
                      "enum": ["ghsa", "nvd", "osv", "osv-native"]},
            "default": ["ghsa"],
        },
        "refresh_osv": {
            "type": "boolean",
            "default": False,
            "description": "Re-download the OSV bulk export before searching.",
        },
        "include_source_records": {
            "type": "boolean",
            "default": False,
            "description": ("Return each contributing source's untouched "
                            "snapshot under `source_records`. Off by default: "
                            "it is roughly 35% of the payload and is only "
                            "useful for auditing how a row was merged."),
        },
    },
}

_STATS = {
    "type": "object",
    "required": ["fetched_per_source", "fetched_total", "after_merge",
                 "after_filter", "returned", "truncated"],
    "properties": {
        "fetched_per_source": {
            "type": "object", "additionalProperties": {"type": "integer"},
            "description": "Rows from each source, counted before the merge.",
        },
        "fetched_total": {"type": "integer"},
        "after_merge": {"type": "integer",
                        "description": "After alias de-duplication."},
        "after_filter": {"type": "integer",
                         "description": "After local published/affects/severity."},
        "returned": {"type": "integer", "description": "Equals `count`."},
        "truncated": {
            "type": "boolean",
            "description": (
                "The *local* pipeline dropped rows for `max_results`. It does "
                "NOT mean the source is exhausted: each source truncates on its "
                "own first, so a single-source search usually reports false."
            ),
        },
        "failed_sources": {
            "type": "array", "items": {"type": "string"},
            "description": (
                "Requested sources that failed outright. Empty on a clean "
                "run. If every selected source fails the request is a 502 "
                "instead, so a non-empty list here always means a partial "
                "result -- which `count` alone cannot distinguish from "
                "'nothing matched'."
            ),
        },
    },
}

_ADVISORY = {
    "type": "object",
    "properties": {
        "advisory_id": {"type": "string"},
        "ghsa_id": {"type": "string", "nullable": True},
        "cve_id": {"type": "string", "nullable": True},
        "aliases": {"type": "array", "items": {"type": "string"}},
        "sources": {"type": "array", "items": {"type": "string"}},
        "source_records": {
            "type": "object",
            "description": ("Each contributing source's untouched snapshot. "
                            "Present only when the request set "
                            "`include_source_records`."),
        },
        "severity": {"type": "string",
                     "enum": ["unknown", "low", "medium", "high", "critical"]},
        "severity_by_source": {"type": "object",
                               "additionalProperties": {"type": "string"}},
        "cvss_score": {
            "type": "number", "nullable": True,
            "description": (
                "Null for an advisory whose only vector is CVSS v4.0: v4 is "
                "not scored here, and a wrong number is worse than none. Use "
                "cvss_vector to score it yourself."
            ),
        },
        "cvss_vector": {
            "type": "string", "nullable": True,
            "description": "The vector cvss_score came from, or the v4 vector when unscored.",
        },
        "cvss_by_source": {"type": "object",
                           "additionalProperties": {"type": "number"}},
        "cwes": {"type": "array", "items": {"type": "string"}},
        "cwe_labels": {"type": "array", "items": {"type": "object"}},
        "packages": {"type": "array", "items": {"type": "object"}},
        "ecosystems": {"type": "array", "items": {"type": "string"}},
        "published_at": {"type": "string", "nullable": True},
        "updated_at": {"type": "string", "nullable": True},
        "withdrawn_at": {"type": "string", "nullable": True},
        "kev": {"type": "boolean"},
        "epss_percentage": {"type": "number", "nullable": True},
        "epss_percentile": {"type": "number", "nullable": True},
        "html_url": {"type": "string", "nullable": True},
        "summary": {"type": "string", "nullable": True},
        "description": {"type": "string", "nullable": True},
        "ai": {
            "type": "object",
            "nullable": True,
            "description": (
                "Present only when a fresh cached verdict exists for EVERY "
                "requested category. A partial hit is never shown as a decision."
            ),
        },
    },
}

_SEARCH_RESPONSE = {
    "type": "object",
    "required": ["count", "query", "stats", "warnings", "results"],
    "properties": {
        "count": {"type": "integer"},
        "query": {
            "type": "object",
            "description": "The query as the server resolved it, echoed back.",
        },
        "stats": _ref_to("SearchStats"),
        "warnings": {
            "type": "array", "items": {"type": "string"},
            "description": (
                "A source that failed while others succeeded. An all-sources "
                "failure still returns 200 with count 0, so check this."
            ),
        },
        "results": {"type": "array", "items": _ref_to("Advisory")},
    },
}

_JOB = {
    "type": "object",
    "required": ["job_id", "kind", "status", "created_at"],
    "properties": {
        "job_id": {"type": "string", "pattern": "^[0-9a-f]{24}$"},
        "kind": {"type": "string", "enum": ["search"]},
        "status": {"type": "string",
                   "enum": ["queued", "running", "done", "failed"]},
        "created_at": {"type": "number"},
        "started_at": {"type": "number", "nullable": True},
        "finished_at": {"type": "number", "nullable": True},
        "result": {"allOf": [_SEARCH_RESPONSE],
                   "description": "Present only when status is `done`."},
        "error": {"type": "string",
                  "description": "Present only when status is `failed`."},
        "error_status": {
            "type": "integer",
            "description": ("The HTTP status this failure maps to; present "
                            "only when status is `failed`. 4xx means the "
                            "request was wrong, 5xx that an upstream was."),
        },
    },
}


_VERDICT = {
    "type": "object",
    "description": (
        "One advisory's answer, collapsed across every requested category. "
        "Every branch returns the same keys; `error` is present only when "
        "the pass failed outright."
    ),
    "properties": {
        "is_match": {
            "type": "boolean", "nullable": True,
            "description": ("True if any category matched. null means the "
                            "pass could not decide, which is not the same "
                            "as false."),
        },
        "matched_category": {"type": "string", "nullable": True},
        "confidence": {"type": "number", "nullable": True},
        "vuln_type": {"type": "string", "nullable": True},
        "reason": {"type": "string", "nullable": True},
        "scored_categories": {
            "type": "array", "items": {"type": "string"},
            "description": ("Which categories this verdict actually answers "
                            "for. A verdict that does not cover the current "
                            "query is stale, not applicable."),
        },
        "has_errors": {"type": "boolean"},
        "errors": {"type": "object", "additionalProperties": {"type": "string"}},
        "cached": {"type": "boolean"},
        "error": {"type": "string"},
        "by_category": {"type": "object"},
    },
    "required": ["is_match", "scored_categories", "has_errors", "cached"],
}

_CLASSIFY_RESPONSE = {
    "type": "object",
    "properties": {
        "category": {"type": "string",
                     "description": "The first requested category."},
        "categories": {"type": "array", "items": {"type": "string"}},
        "verdicts": {"type": "object", "additionalProperties": _ref_to("Verdict"),
                     "description": "Keyed by advisory_id."},
        "by_category": {
            "type": "object",
            "description": "Raw per-category verdicts, before aggregation.",
        },
        "missing": {
            "type": "array", "items": {"type": "string"},
            "description": "Requested ids that are not in the cache.",
        },
    },
    "required": ["categories", "verdicts", "by_category", "missing"],
}


# Every schema that `components.schemas` publishes, keyed by the object so a
# use site can be turned into a $ref by identity.
#
# `components.schemas` registered six schemas and the document contained
# zero `$ref`: every use site inlined the same object, so the served JSON
# carried each schema twice (_ERROR six times, through _ERROR_RESPONSE) and
# a generator emitted anonymous inline models instead of Error, Advisory,
# Job and SearchResponse. The registry was decoration.
_COMPONENT_NAMES: dict[int, str] = {}


def _component(name: str, schema: dict) -> dict:
    """Register *schema* under *name* and return it unchanged."""
    _COMPONENT_NAMES[id(schema)] = name
    return schema


def _ref(schema: dict) -> dict:
    """A $ref to *schema* when it is registered, else the schema itself.

    By identity, not by value: two schemas can be structurally equal and
    mean different things, and the use sites already pass the very objects
    the registry holds.
    """
    name = _COMPONENT_NAMES.get(id(schema))
    return {"$ref": f"#/components/schemas/{name}"} if name else schema


def _json_body(schema: dict, *, required: bool = True) -> dict:
    return {
        "required": required,
        "content": {"application/json": {"schema": _ref(schema)}},
    }


def _json_response(description: str, schema: dict) -> dict:
    return {
        "description": description,
        "content": {"application/json": {"schema": _ref(schema)}},
    }


# Registered here, after every schema exists and before the first use site
# below turns one into a $ref. The same tuple feeds components.schemas in
# build_spec, so a schema cannot be published under a name it is not
# referenced by, or referenced by a name it is not published under.
_COMPONENTS: tuple[tuple[str, dict], ...] = (
    ("Error", _ERROR),
    ("SearchRequest", _SEARCH_REQUEST),
    ("SearchResponse", _SEARCH_RESPONSE),
    ("SearchStats", _STATS),
    ("Advisory", _ADVISORY),
    ("Job", _JOB),
    ("Verdict", _VERDICT),
    ("ClassifyResponse", _CLASSIFY_RESPONSE),
)
for _name, _schema in _COMPONENTS:
    _component(_name, _schema)

_ERROR_RESPONSE = _json_response("Error", _ERROR)


@functools.lru_cache(maxsize=4)
def build_spec(server_url: str = "/") -> dict:
    """The full OpenAPI 3.1 document.

    Cached: it is a pure function of module-level constants, and the ETag
    already tells clients it cannot change within an API_VERSION. Callers
    must treat the result as read-only -- Flask's jsonify only serialises it.
    """
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "VulnSight",
            "version": API_VERSION,
            "summary": "Search vulnerability advisories by bug class, not keyword.",
            "description": (
                "Filters GHSA, NVD and OSV on the CWE set that characterises a "
                "bug class, merges them through their alias graph, and can run "
                "an LLM pass that judges whether each advisory's root cause "
                "really is that class.\n\n"
                f"Ships {len(CATEGORIES)} curated bug classes; any single CWE "
                "also works as an ad-hoc class via `cwe:<id>`.\n\n"
                "Every path is also served without the `/v1` prefix. Those "
                "aliases are permanent, but new clients should use `/v1`."
            ),
        },
        "servers": [{"url": server_url}],
        "components": {
            "securitySchemes": {
                _TOKEN_SCHEME: {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-VulnSight-Token",
                    "description": (
                        "Required on every mutating call, and on job polling, "
                        "when VULNSIGHT_API_TOKEN is set. "
                        "`Authorization: Bearer <token>` is accepted too."
                    ),
                }
            },
            # _VERDICT and _CLASSIFY_RESPONSE were used by the paths and
            # never registered here, so they were the only two shapes a
            # client could not name at all.
            "schemas": dict(_COMPONENTS),
        },
        "paths": {
            "/api/v1/meta": {
                "get": {
                    "operationId": "getMeta",
                    "summary": "Curated taxonomy, ecosystems, and service status",
                    "responses": {"200": _json_response(
                        "Reference data", {"type": "object"})},
                }
            },
            "/api/v1/cwes": {
                "get": {
                    "operationId": "getCweCatalog",
                    "summary": "The full MITRE CWE catalog, column-oriented",
                    "description": (
                        "Served with a version ETag and a one-day cache. Send "
                        "`If-None-Match` to get a 304 instead of ~66 KB."
                    ),
                    "responses": {
                        "200": _json_response("Catalog", {
                            "type": "object",
                            "required": ["version", "released", "columns", "rows"],
                            "properties": {
                                "version": {"type": "string",
                                            "description": "MITRE CWE release, e.g. 4.20."},
                                "released": {"type": "string",
                                             "description": "That release's date."},
                                "columns": {"type": "array",
                                            "items": {"type": "string"}},
                                "rows": {
                                    "type": "array",
                                    "items": {"type": "array"},
                                    "description": ("Column-oriented to keep the "
                                                    "payload small; `columns` names "
                                                    "the positions."),
                                },
                            },
                        }),
                        "304": {"description": "Catalog unchanged"},
                    },
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "operationId": "getOpenApiSpec",
                    "summary": "This document",
                    "responses": {
                        "200": _json_response("OpenAPI 3.1 document",
                                              {"type": "object"}),
                        "304": {"description": "Specification unchanged"},
                    },
                }
            },
            "/api/v1/osv/status": {
                "get": {
                    "operationId": "getOsvStatus",
                    "summary": "Which OSV bulk exports are cached, and how stale",
                    "responses": {"200": _json_response(
                        "Cache status", {"type": "object"})},
                }
            },
            "/api/v1/search": {
                "post": {
                    "operationId": "search",
                    "summary": "Search advisories by bug class (synchronous)",
                    "description": (
                        "Runs on the request thread. Use POST /api/v1/jobs "
                        "instead when `sources` includes `nvd`: without an NVD "
                        "API key that path sleeps ~6.5 s per CWE, which is "
                        "minutes for a class with extended CWEs enabled."
                    ),
                    "security": [{_TOKEN_SCHEME: []}],
                    "requestBody": _json_body(_SEARCH_REQUEST),
                    "responses": {
                        "200": _json_response("Search results", _SEARCH_RESPONSE),
                        "400": _ERROR_RESPONSE,
                        "401": _ERROR_RESPONSE,
                        "415": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                        "502": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/jobs": {
                "post": {
                    "operationId": "submitSearchJob",
                    "summary": "Queue a search and poll for it",
                    "description": (
                        "Takes exactly the body /api/v1/search takes. The query "
                        "is validated before the job is created, so a malformed "
                        "request fails now rather than a minute later. Spends "
                        "the same rate-limit bucket as a synchronous search."
                    ),
                    "security": [{_TOKEN_SCHEME: []}],
                    "requestBody": _json_body(_SEARCH_REQUEST),
                    "responses": {
                        "202": _json_response("Job accepted", {
                            "type": "object",
                            "required": ["job_id", "kind", "status", "poll"],
                            "properties": {
                                "job_id": {"type": "string"},
                                "kind": {"type": "string"},
                                "status": {"type": "string", "enum": ["queued"]},
                                "poll": {"type": "string"},
                            },
                        }),
                        "400": _ERROR_RESPONSE,
                        "401": _ERROR_RESPONSE,
                        "415": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/jobs/{job_id}": {
                "get": {
                    "operationId": "getJob",
                    "summary": "Poll a queued search",
                    "description": (
                        "The only GET that requires the token when one is set: "
                        "a job result is the output of your query, not public "
                        "reference data. `result` appears only on `done` and "
                        "`error` only on `failed` — there are no partial results."
                    ),
                    "security": [{_TOKEN_SCHEME: []}],
                    "parameters": [{
                        "name": "job_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "pattern": "^[0-9a-f]{24}$"},
                    }],
                    "responses": {
                        "200": _json_response("Job state", _JOB),
                        "401": _ERROR_RESPONSE,
                        "404": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/ai/classify": {
                "post": {
                    "operationId": "classify",
                    "summary": "Run the LLM pass over cached advisories",
                    "description": (
                        "Costs `len(categories) × len(advisory_ids)` model "
                        "calls, capped at "
                        f"{MAX_AI_CALLS_PER_REQUEST} per request. Advisories must "
                        "already be in the cache — run a search first; unknown "
                        "ids come back under `missing` rather than failing."
                    ),
                    "security": [{_TOKEN_SCHEME: []}],
                    "requestBody": _json_body({
                        "type": "object",
                        "required": ["categories", "advisory_ids"],
                        "properties": {
                            "categories": {
                                "type": "array",
                                "maxItems": MAX_CATEGORY_INPUTS,
                                "items": {"type": "string", "maxLength": 64},
                            },
                            "category": {
                                "type": "string",
                                "description": ("Singular alias for a "
                                                "one-element `categories`."),
                            },
                            "advisory_ids": {
                                "type": "array", "maxItems": MAX_AI_BATCH,
                                "items": {"type": "string", "maxLength": 128},
                            },
                            "ghsa_ids": {
                                "type": "array", "maxItems": MAX_AI_BATCH,
                                "items": {"type": "string", "maxLength": 128},
                                "description": "Accepted alias for advisory_ids.",
                            },
                            "force": {
                                "type": "boolean", "default": False,
                                "description":
                                    "Ignore cached verdicts and re-spend.",
                            },
                        },
                    }),
                    "responses": {
                        "200": _json_response("Verdicts", _CLASSIFY_RESPONSE),
                        "400": _ERROR_RESPONSE,
                        "401": _ERROR_RESPONSE,
                        # Same `_json_object` helper as /search and /jobs,
                        # which both list it.
                        "415": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/ai/test": {
                "post": {
                    "operationId": "pingAiProvider",
                    "summary": "One trivial prompt, to check the provider answers",
                    "security": [{_TOKEN_SCHEME: []}],
                    # Required, because the handler requires it. The spec
                    # said optional and `_json_object` returns 415 without a
                    # JSON content-type and 400 for a non-object body --
                    # neither of which was listed. A client generated from
                    # this document called pingAiProvider() with no
                    # arguments and got an undocumented 415, which is the
                    # one failure this file's header says it exists to
                    # prevent: "an invented schema is worse than none,
                    # because a client generator will believe it."
                    "requestBody": _json_body({"type": "object"}),
                    "responses": {
                        "200": _json_response("Provider reply", {"type": "object"}),
                        "400": _ERROR_RESPONSE,
                        "401": _ERROR_RESPONSE,
                        "415": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                    },
                }
            },
        },
    }
