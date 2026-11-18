"""Checks for the runtime surfaces: HTTP layer, jobs, security, classifier.

One entry per `fixed` row of docs/review-dispositions.md's "HTTP layer, jobs,
security" and "AI classifier" tables, minus the rows already defended from
tools/checks/core.py. Each edit puts the *original* bug back, not a mutation
of the fix; where a fix is guarded in two places both halves are in the same
entry, because reverting either one alone leaves the behaviour correct and the
harness would report a false pass.
"""

from __future__ import annotations

Edit = tuple[str, str, str]

# The AI endpoints as the spec describes them, lifted verbatim from
# modules/openapi.py: deleting both is what the document looked like when
# the richest and most expensive endpoints in the API were undescribed.
_AI_PATHS = """            "/api/v1/ai/classify": {
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
                        "429": _ERROR_RESPONSE,
                    },
                }
            },
            "/api/v1/ai/test": {
                "post": {
                    "operationId": "pingAiProvider",
                    "summary": "One trivial prompt, to check the provider answers",
                    "security": [{_TOKEN_SCHEME: []}],
                    "requestBody": _json_body({"type": "object"}, required=False),
                    "responses": {
                        "200": _json_response("Provider reply", {"type": "object"}),
                        "401": _ERROR_RESPONSE,
                        "429": _ERROR_RESPONSE,
                    },
                }
            },
"""


CHECKS: list[tuple[str, list[Edit], str]] = [
    (
        "a partly failed score is reported as a confident no",
        [("modules/ai_classifier.py",
          '        aggregate["is_match"] = None\n'
          "        if not successes:",
          '        aggregate["is_match"] = False\n'
          "        if not successes:")],
        "test_ai_classifier",
    ),
    (
        "a key is retried instead of rotated",
        [("modules/ai_classifier.py",
          "    max_attempts = max(retries + 1, nkeys)",
          "    max_attempts = retries + 1")],
        "test_ai_classifier",
    ),
    (
        "the request body size cap is removed",
        [("app.py",
          '    app.config["MAX_CONTENT_LENGTH"] = max(1024, _max_request_bytes)',
          '    app.config["MAX_CONTENT_LENGTH"] = None')],
        "test_app",
    ),
    (
        "the AI rate limiter matches the path, so /api/v1 is unlimited",
        [("app.py",
          '        elif request.endpoint in ("api_ai_classify", "api_ai_test"):',
          '        elif request.path in ("/api/ai/classify", "/api/ai/test"):')],
        "test_app",
    ),
    (
        "the system prompt stops reaching the provider",
        [("modules/ai_classifier.py",
          '            "system": system,',
          '            "system": "",')],
        "test_ai_classifier",
    ),
    (
        "the default provider's reply shape stops being parsed",
        [("modules/ai_classifier.py",
          'c.get("type") == "text"',
          'c.get("type") == "nope"')],
        "test_ai_classifier",
    ),
    (
        "a revoked key stops being parked",
        [("modules/ai_classifier.py",
          "        return False, True, 24 * 3600",
          "        return False, False, 0")],
        "test_ai_classifier",
    ),
    (
        "a transient rate limit is persisted across restarts again",
        [("modules/ai_classifier.py",
          "            cfg.mark_skip_token(auth, skip_for, persist=not retryable)",
          "            cfg.mark_skip_token(auth, skip_for, persist=True)")],
        "test_ai_classifier",
    ),
    (
        "the auth allowlist goes back to being unreachable",
        [("app.py",
          "        if request.endpoint in _UNAUTHENTICATED_ENDPOINTS:\n"
          "            return None\n"
          "        expected = app.config.get",
          '        if request.method not in ("POST", "PUT", "PATCH", "DELETE") \\\n'
          '                and request.endpoint != "api_jobs_get":\n'
          "            return None\n"
          "        if request.endpoint in _UNAUTHENTICATED_ENDPOINTS:\n"
          "            return None\n"
          "        expected = app.config.get")],
        "test_app",
    ),
    (
        "the prune sentinel means 'at boot' instead of 'never'",
        [("modules/jobs.py",
          '_last_prune = float("-inf")',
          "_last_prune = 0.0")],
        "test_jobs",
    ),
    # -- jobs ---------------------------------------------------------------
    (
        "a job stays running when recording its terminal state raises",
        [("modules/jobs.py",
          "    try:\n"
          "        cache.finish_job(job_id, path=path, **outcome)\n"
          "    except Exception:\n"
          '        logger.exception("Could not record terminal state for job %s", job_id)',
          "    cache.finish_job(job_id, path=path, **outcome)")],
        "test_jobs",
    ),
    (
        "a job that cannot be marked running is abandoned in queued",
        [("modules/jobs.py",
          '        logger.exception("Could not mark job %s running", job_id)\n'
          '        _finish(job_id, path, error="Job could not be started. See server logs.",\n'
          "                error_status=503)\n"
          "        return",
          '        logger.exception("Could not mark job %s running", job_id)\n'
          "        return")],
        "test_jobs",
    ),
    (
        "finished jobs are pruned only at process start",
        [("modules/jobs.py",
          "    cache.create_job(job_id, kind, request, path=path)\n    _prune(path)\n",
          "    cache.create_job(job_id, kind, request, path=path)\n")],
        "test_jobs",
    ),
    (
        "error_status is persisted but never served to the poller",
        [("modules/jobs.py",
          '        if job.get("error_status"):\n'
          '            view["error_status"] = job["error_status"]',
          "        pass")],
        "test_jobs",
    ),
    (
        "every job poll parses the stored request body it then discards",
        [("modules/cache.py",
          '        "request": None,',
          '        "request": json.loads(row["request"]) if row["request"] else None,')],
        "test_jobs",
    ),
    # -- cache --------------------------------------------------------------
    (
        "one SQLite connection per advisory id in a classify request",
        [("modules/cache.py",
          "    ids = list(dict.fromkeys(advisory_ids))\n"
          "    if not ids:\n"
          "        return {}\n"
          "    found: dict[str, dict] = {}\n"
          "    with _db(path) as conn:\n"
          "        # Chunked so a large batch cannot trip SQLITE_LIMIT_VARIABLE_NUMBER.\n"
          "        # That limit was 999 until SQLite 3.32 (2020) and is 32766 on\n"
          "        # anything current -- the old comment said 999 flatly, which is the\n"
          "        # number people then write tests against, and a 1,500-id test\n"
          '        # \"proving\" the chunking passed with the chunking removed. The\n'
          "        # chunk stays at 500 because the floor is what has to be safe: a\n"
          "        # build may still be compiled with the old limit.\n"
          "        for start in range(0, len(ids), 500):\n"
          "            chunk = ids[start:start + 500]\n"
          '            placeholders = ",".join("?" * len(chunk))\n'
          "            rows = conn.execute(\n"
          "                # Only placeholders are interpolated; every value is bound.\n"
          '                f"SELECT advisory_id, data FROM advisories "\n'
          '                f"WHERE advisory_id IN ({placeholders})",\n'
          "                chunk,\n"
          "            ).fetchall()\n"
          "            for row in rows:\n"
          "                try:\n"
          '                    found[row["advisory_id"]] = json.loads(row["data"])\n'
          "                except (TypeError, ValueError):\n"
          "                    continue          # one unreadable row must not sink the batch\n"
          "    return found",
          "    found: dict[str, dict] = {}\n"
          "    for advisory_id in advisory_ids:\n"
          "        record = get_advisory(advisory_id, path=path)\n"
          "        if record is not None:\n"
          "            found[advisory_id] = record\n"
          "    return found")],
        "test_cache",
    ),
    (
        "an index on advisories(cve_id) that no query uses",
        [("modules/cache.py",
          "    data        TEXT NOT NULL,          -- normalized record as JSON\n"
          "    fetched_at  REAL NOT NULL\n"
          ");",
          "    data        TEXT NOT NULL,          -- normalized record as JSON\n"
          "    fetched_at  REAL NOT NULL\n"
          ");\n"
          "CREATE INDEX IF NOT EXISTS idx_advisories_cve ON advisories(cve_id);")],
        "test_cache",
    ),
    # -- security -----------------------------------------------------------
    (
        "two workers mint different API tokens into the same file",
        [("modules/security.py",
          "        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)",
          "        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)")],
        "test_security",
    ),
    (
        "the generated API token is printed into docker logs",
        [("modules/security.py",
          "    if sys.stderr.isatty():\n"
          '        banner += f"\\n!! Enter this token in the UI: {token}"\n'
          "    else:\n"
          '        banner += "\\n!! Read it from that file; it is not logged."',
          '    banner += f"\\n!! Enter this token in the UI: {token}"')],
        "test_security",
    ),
    (
        "rate-limit eviction scans every key and drops the one being limited",
        [("modules/security.py",
          "            if bucket is None:\n"
          "                if len(self._hits) >= self.max_keys:\n"
          "                    # Least recently touched, in O(1).\n"
          "                    self._hits.popitem(last=False)\n"
          "                bucket = deque()\n"
          "                self._hits[key] = bucket\n"
          "            else:\n"
          "                self._hits.move_to_end(key)",
          "            if bucket is None:\n"
          "                if len(self._hits) >= self.max_keys:\n"
          "                    # O(n) over every key, under the lock.\n"
          "                    oldest = min(\n"
          "                        self._hits,\n"
          "                        key=lambda k: self._hits[k][-1] if self._hits[k] else 0.0,\n"
          "                    )\n"
          "                    del self._hits[oldest]\n"
          "                bucket = deque()\n"
          "                self._hits[key] = bucket")],
        "test_security",
    ),
    # -- configuration ------------------------------------------------------
    (
        "'export FOO=bar' in .env sets a variable named 'export FOO'",
        [("modules/config.py",
          '            if key.startswith("export "):\n'
          '                key = key[len("export "):].strip()',
          "            pass")],
        "test_config",
    ),
    (
        "the AI key cooldown file is written outside VULNSIGHT_DATA_DIR",
        [("modules/ai_classifier.py",
          'COOLDOWN_PATH = os.path.join(config.DATA_DIR, ".ai_key_cooldown.json")',
          'COOLDOWN_PATH = os.path.join(config.BASE_DIR, ".ai_key_cooldown.json")')],
        "test_config",
    ),
    # -- AI classifier ------------------------------------------------------
    (
        # Both halves at once: the dataclass field hides the credentials from
        # the generated repr and __repr__ replaces it with fingerprints, so
        # reverting either one alone still prints no key -- a false pass.
        "AIConfig's repr prints every API key",
        [("modules/ai_classifier.py",
          "    tokens: list[str] = field(repr=False)",
          "    tokens: list[str]"),
         ("modules/ai_classifier.py",
          "    def __repr__(self) -> str:\n"
          '        keys = ", ".join(self._token_fingerprint(tok)[:8] for tok in self.tokens)\n'
          '        return (f"AIConfig(provider={self.provider!r}, base_url={self.base_url!r}, "\n'
          '                f"model={self.model!r}, keys={len(self.tokens)}[{keys}])")\n\n',
          "")],
        "test_ai_classifier",
    ),
    (
        # Only `description` was capped; the other fields were pasted in whole,
        # so one advisory could inflate the prompt without bound. The limits
        # are left in place for description so the truncation marker still
        # works -- this reverts exactly which fields are bounded.
        "only the description is capped, so a prompt field can be unbounded",
        [("modules/ai_classifier.py",
          '_FIELD_LIMITS = {"summary": 400, "description": 2500, '
          '"packages": 600, "cwes": 300}',
          '_FIELD_LIMITS = {"summary": 10 ** 9, "description": 2500, '
          '"packages": 10 ** 9, "cwes": 10 ** 9}')],
        "test_ai_classifier",
    ),
    (
        "the health check spends a paid call on a key known to be cooling",
        [("modules/ai_classifier.py",
          "    waiting = cfg.seconds_until_any_live()\n"
          "    if cfg.tokens and not cfg.live_indices():\n"
          '        return {"ok": False, "keys": len(cfg.tokens),\n'
          '                "error": f"All API keys are cooling down; the first frees up "\n'
          '                         f"in about {int(waiting)}s."}',
          "    pass")],
        "test_ai_classifier",
    ),
    (
        "the raw provider error body is handed back to the caller",
        [("modules/ai_classifier.py",
          "        if e.code == 429 and exhausted and not retryable:\n"
          '            public = "AI quota exhausted. Try again later."\n'
          "        else:\n"
          '            public = f"AI provider returned HTTP {e.code}"',
          '        public = f"AI HTTP {e.code}: {detail}"')],
        "test_ai_classifier",
    ),
    (
        "one transient 429 ends the whole batch on a single-key setup",
        [("modules/ai_classifier.py",
          "            wait = cfg.seconds_until_any_live()\n"
          "            if (last is not None and last.retryable\n"
          "                    and attempt < max_attempts - 1\n"
          "                    and 0 < wait <= _MAX_RATE_PAUSE):\n"
          '                logger.info("All API keys cooling; waiting %.0fs", wait)\n'
          "                time.sleep(wait)\n"
          "                live = cfg.live_indices()",
          "            pass")],
        "test_ai_classifier",
    ),
    # -- HTTP layer ---------------------------------------------------------
    (
        # Both halves at once: dropping the decorator alone would stop the
        # nonce being generated at all (which every page test would notice for
        # the wrong reason). Registering it again after the guards is what
        # reproduces the real defect -- the hook still runs, just too late for
        # any response a guard short-circuits.
        "a guard-blocked response carries an empty CSP nonce",
        [("app.py",
          "    @app.before_request\n    def create_csp_nonce():",
          "    def create_csp_nonce():"),
         ("app.py",
          "    @app.after_request\n    def add_security_headers(response):",
          "    app.before_request(create_csp_nonce)\n\n"
          "    @app.after_request\n    def add_security_headers(response):")],
        "test_app",
    ),
    (
        "the rate limiter matches the path, so /api/v1 is unlimited",
        [("app.py",
          '        if request.endpoint in ("api_search", "api_jobs_create"):\n'
          '            limiter = app.config.get("SEARCH_LIMITER")\n'
          '        elif request.endpoint in ("api_ai_classify", "api_ai_test"):\n'
          '            limiter = app.config.get("AI_LIMITER")',
          '        if request.path in ("/api/search", "/api/jobs"):\n'
          '            limiter = app.config.get("SEARCH_LIMITER")\n'
          '        elif request.path in ("/api/ai/classify", "/api/ai/test"):\n'
          '            limiter = app.config.get("AI_LIMITER")')],
        "test_app",
    ),
    (
        "the OpenAPI document is rebuilt for every unauthenticated request",
        [("app.py",
          "        etag = f'W/\"openapi-{openapi.API_VERSION}\"'\n"
          '        if request.headers.get("If-None-Match") == etag:\n'
          '            return "", 304\n'
          "        response = jsonify(openapi.build_spec())",
          "        response = jsonify(openapi.build_spec())\n"
          "        etag = f'W/\"openapi-{openapi.API_VERSION}\"'")],
        "test_openapi",
    ),
    (
        "the AI endpoints are missing from the OpenAPI document",
        [("modules/openapi.py", _AI_PATHS, "")],
        "test_openapi",
    ),
]
