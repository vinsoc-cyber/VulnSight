"""The OpenAPI document is hand-written, so these tests are what keep it true.

The document's whole value is that a client generator will believe it. A
description that has drifted from the server is worse than no description, so
the checks here are deliberately the two that catch drift: the path set must
match ``url_map`` in both directions, and a real response from the app must
validate against the schema the document claims for it.

The validator is a small local one rather than `jsonschema`, because the project
runs on Flask and the standard library and a documentation test is not a good
reason to break that. It covers the subset the spec actually uses.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import re
import tempfile
import unittest
from unittest import mock

from modules import ai_classifier, cache, openapi
from samples import SAMPLE


def validate(value, schema, path="$") -> list[str]:
    """Return a list of human-readable violations; empty means valid."""
    errors: list[str] = []

    if "allOf" in schema:
        for sub in schema["allOf"]:
            errors += validate(value, sub, path)
        return errors

    expected = schema.get("type")
    if value is None:
        if schema.get("nullable") or expected is None:
            return errors
        return [f"{path}: null but type is {expected}"]

    checkers = {
        "object": dict, "array": list, "string": str,
        "boolean": bool, "number": (int, float), "integer": int,
    }
    if expected in checkers:
        # bool is a subclass of int in Python; the spec means them separately.
        if expected in ("number", "integer") and isinstance(value, bool):
            return [f"{path}: bool where {expected} expected"]
        if not isinstance(value, checkers[expected]):
            return [f"{path}: {type(value).__name__} where {expected} expected"]

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum']}")

    if expected == "object":
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required key {key!r}")
        for key, sub in (schema.get("properties") or {}).items():
            if key in value:
                errors += validate(value[key], sub, f"{path}.{key}")
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict):
            declared = set(schema.get("properties") or {})
            for key, item in value.items():
                if key not in declared:
                    errors += validate(item, extra, f"{path}.{key}")

    if expected == "array" and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            errors += validate(item, schema["items"], f"{path}[{index}]")

    return errors

# EPSS enrichment runs inside run_search, and nothing was mocking it, so the
# "offline" suite made 2 live DNS lookups to api.first.org per run. It passed
# only because epss_client swallows every failure — which also meant these
# tests would pass identically if EPSS enrichment were entirely broken.
# Individual tests that patch fetch_epss themselves still win: an inner
# mock.patch takes precedence over this one.
_epss_patch = None


def setUpModule():
    global _epss_patch
    _epss_patch = mock.patch("modules.epss_client.fetch_epss", return_value={})
    _epss_patch.start()


def tearDownModule():
    if _epss_patch is not None:
        _epss_patch.stop()


class _AppCase(unittest.TestCase):
    """Shared fixture. Holds no tests, so subclasses do not re-run each other's."""

    def setUp(self):
        self.spec = openapi.build_spec()
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        self._env = mock.patch.dict(os.environ, {
            "VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "off",
            "HOST": "127.0.0.1",
            "VULNSIGHT_BIND": "127.0.0.1",
        }, clear=False)
        self._env.start()
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        from modules import jobs
        jobs.shutdown(wait=True)
        # Disposing of the pool must not leave the process-wide stop
        # signal raised for every later test in the run.
        jobs.resume()
        self._env.stop()
        cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def _live_v1_routes(self) -> dict[str, set[str]]:
        """Flask spells parameters `<job_id>`; OpenAPI spells them `{job_id}`."""
        out: dict[str, set[str]] = {}
        for rule in self.app.url_map.iter_rules():
            path = re.sub(r"<(?:[^:<>]+:)?([^<>]+)>", r"{\1}", str(rule))
            if not path.startswith("/api/v1/"):
                continue
            methods = {m for m in (rule.methods or ())
                       if m in ("GET", "POST", "PUT", "PATCH", "DELETE")}
            out.setdefault(path, set()).update(methods)
        return out


class TestSpecMatchesTheRoutes(_AppCase):
    def test_every_route_is_described(self):
        live = set(self._live_v1_routes())
        described = set(self.spec["paths"])
        self.assertTrue(live, "no /api/v1 routes found — the check would be vacuous")
        self.assertEqual(live - described, set(), "routes with no OpenAPI entry")

    def test_nothing_is_described_that_does_not_exist(self):
        live = set(self._live_v1_routes())
        described = set(self.spec["paths"])
        self.assertEqual(described - live, set(), "OpenAPI describes missing routes")

    def test_documented_methods_match_the_routes(self):
        for path, methods in self._live_v1_routes().items():
            with self.subTest(path=path):
                described = {m.upper() for m in self.spec["paths"][path]}
                self.assertEqual(described, methods)

    def test_spec_is_served_with_an_etag(self):
        r = self.client.get("/api/v1/openapi.json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["openapi"], "3.1.0")
        etag = r.headers["ETag"]
        again = self.client.get("/api/v1/openapi.json",
                                headers={"If-None-Match": etag})
        self.assertEqual(again.status_code, 304)


class TestSpecMatchesRealResponses(_AppCase):
    """The check that matters: validate what the server sends, not what we assumed."""

    def test_a_real_search_response_validates(self):
        schema = self.spec["components"]["schemas"]["SearchResponse"]
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            body = self.client.post(
                "/api/v1/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
            ).get_json()
        self.assertEqual(validate(body, schema), [])

    def test_a_real_cwe_catalog_response_validates(self):
        """It was documented as an unconstrained object too, and the release
        date it now carries was generated but read by nothing."""
        schema = (self.spec["paths"]["/api/v1/cwes"]["get"]
                  ["responses"]["200"]["content"]["application/json"]["schema"])
        body = self.client.get("/api/v1/cwes").get_json()
        self.assertEqual(validate(body, schema), [], list(body)[:6])
        self.assertTrue(body["released"], "the catalog must state its release date")

    def test_a_real_classify_response_validates(self):
        """The module's headline claim is that the document is checked
        against what the server actually sends. That was vacuous for the
        richest response in the API, which was documented as an
        unconstrained {"type": "object"} and posted to by no test."""
        schema = (self.spec["paths"]["/api/v1/ai/classify"]["post"]
                  ["responses"]["200"]["content"]["application/json"]["schema"])
        verdict = {"is_match": True, "confidence": 0.9,
                   "vuln_type": "BOLA/IDOR", "reason": "r"}
        with mock.patch("modules.cache.get_advisories",
                        return_value={"GHSA-aaaa": {
                            "advisory_id": "GHSA-aaaa", "cve_id": "CVE-1",
                            "summary": "s", "description": "d",
                            "cwes": ["639"], "packages": []}}), \
             mock.patch("modules.ai_classifier.load_config") as load_config, \
             mock.patch("modules.ai_classifier.classify_one", return_value=verdict), \
             mock.patch("modules.cache.save_classification"), \
             mock.patch("modules.cache.get_classifications", return_value={}):
            load_config.return_value = ai_classifier.AIConfig(
                provider="glm", base_url="https://x", tokens=["k"], model="m")
            body = self.client.post(
                "/api/v1/ai/classify",
                json={"categories": ["bac"],
                      "advisory_ids": ["GHSA-aaaa", "GHSA-missing"]},
            ).get_json()
        self.assertEqual(validate(body, schema), [], body)
        self.assertEqual(body["missing"], ["GHSA-missing"])

    def test_a_classify_response_with_an_error_verdict_validates(self):
        """The error branch used to return a different shape, so a schema
        for this response could not have been written at all."""
        schema = (self.spec["paths"]["/api/v1/ai/classify"]["post"]
                  ["responses"]["200"]["content"]["application/json"]["schema"])
        with mock.patch("modules.cache.get_advisories",
                        return_value={"GHSA-aaaa": {
                            "advisory_id": "GHSA-aaaa", "cve_id": "CVE-1",
                            "summary": "s", "description": "d",
                            "cwes": ["639"], "packages": []}}), \
             mock.patch("modules.ai_classifier.load_config") as load_config, \
             mock.patch("modules.ai_classifier.classify_one",
                        side_effect=ai_classifier.AIError("boom")), \
             mock.patch("modules.cache.save_classification"), \
             mock.patch("modules.cache.get_classifications", return_value={}):
            load_config.return_value = ai_classifier.AIConfig(
                provider="glm", base_url="https://x", tokens=["k"], model="m")
            body = self.client.post(
                "/api/v1/ai/classify",
                json={"categories": ["bac"], "advisory_ids": ["GHSA-aaaa"]},
            ).get_json()
        self.assertEqual(validate(body, schema), [], body)

    def test_an_empty_search_response_validates(self):
        schema = self.spec["components"]["schemas"]["SearchResponse"]
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[]):
            body = self.client.post(
                "/api/v1/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
            ).get_json()
        self.assertEqual(body["count"], 0)
        self.assertEqual(validate(body, schema), [])

    def test_a_real_job_response_validates_in_every_state(self):
        import time
        schema = self.spec["components"]["schemas"]["Job"]
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            job_id = self.client.post(
                "/api/v1/jobs",
                json={"categories": ["bac"], "ecosystem": "maven"},
            ).get_json()["job_id"]
            seen = set()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                body = self.client.get(f"/api/v1/jobs/{job_id}").get_json()
                self.assertEqual(validate(body, schema), [], body)
                seen.add(body["status"])
                if body["status"] in ("done", "failed"):
                    break
                time.sleep(0.01)
        self.assertIn("done", seen)

    def test_an_error_response_validates(self):
        schema = self.spec["components"]["schemas"]["Error"]
        body = self.client.post("/api/v1/search", json={"categories": []}).get_json()
        self.assertEqual(validate(body, schema), [])

    def test_the_validator_actually_rejects_bad_data(self):
        """Guards against the whole suite passing because validate() returns []."""
        schema = self.spec["components"]["schemas"]["SearchResponse"]
        self.assertNotEqual(validate({}, schema), [])
        self.assertNotEqual(validate({"count": "twelve"}, schema), [])
        stats = self.spec["components"]["schemas"]["SearchStats"]
        self.assertNotEqual(validate({"truncated": "yes"}, stats), [])


class TestEveryStatusTheHandlersSendIsDocumented(_AppCase):
    """The spec listed responses the handlers do not send, and omitted ones
    they do.

    `/api/v1/ai/test` declared its body optional while `_json_object`
    returns **415** without a JSON content-type and **400** for a non-object
    body; neither was listed, so a client generated from this document
    called pingAiProvider() with no arguments and got an undocumented 415.
    `/api/v1/ai/classify` omitted 415 from the same helper while `/search`
    and `/jobs` both listed it.

    The existing tests check path and method parity and validate the
    responses they happen to elicit, so a status nothing provokes was
    invisible. These provoke them."""

    def _documented(self, path, method="post"):
        return set(self.spec["paths"][path][method]["responses"])

    def _assert_documented(self, path, status, **kwargs):
        response = self.client.post(path, **kwargs)
        self.assertEqual(response.status_code, status)
        self.assertIn(str(status), self._documented(path),
                      f"{path} returns {status} and the spec does not say so")

    def test_a_request_with_no_json_content_type_is_a_documented_415(self):
        for path in ("/api/v1/search", "/api/v1/ai/classify", "/api/v1/ai/test",
                     "/api/v1/jobs"):
            with self.subTest(path=path):
                self._assert_documented(path, 415, data="not json")

    def test_a_non_object_json_body_is_a_documented_400(self):
        for path in ("/api/v1/search", "/api/v1/ai/classify", "/api/v1/ai/test",
                     "/api/v1/jobs"):
            with self.subTest(path=path):
                self._assert_documented(path, 400, data="[1, 2, 3]",
                                        content_type="application/json")

    def test_ai_test_does_not_claim_its_body_is_optional(self):
        """It is the handler that decides, and the handler requires one."""
        body = self.spec["paths"]["/api/v1/ai/test"]["post"]["requestBody"]
        self.assertTrue(body["required"])


class TestTheComponentsAreActuallyReferenced(_AppCase):
    """`components.schemas` registered six schemas and the document
    contained zero `$ref`: every use site inlined the same object, so the
    served JSON carried each schema twice (Error six times) and a generator
    emitted anonymous inline models instead of Error, Advisory, Job and
    SearchResponse. Two more shapes, Verdict and ClassifyResponse, were
    used by the paths and never registered at all."""

    def test_the_document_uses_refs(self):
        text = json.dumps(self.spec)
        self.assertGreater(text.count('"$ref"'), 10,
                           "components.schemas is decoration again")

    def test_every_ref_resolves(self):
        text = json.dumps(self.spec)
        names = set(self.spec["components"]["schemas"])
        dangling = sorted({ref for ref in
                           re.findall(r"#/components/schemas/(\w+)", text)
                           if ref not in names})
        self.assertEqual(dangling, [], f"unresolvable $ref: {dangling}")

    def test_every_registered_schema_is_referenced_somewhere(self):
        """A schema nobody points at is the same decoration in a new place."""
        text = json.dumps(self.spec)
        referenced = set(re.findall(r"#/components/schemas/(\w+)", text))
        unused = sorted(set(self.spec["components"]["schemas"]) - referenced)
        self.assertEqual(unused, [], f"registered but never referenced: {unused}")

    def test_the_shapes_a_client_needs_to_name_are_all_published(self):
        for name in ("Error", "Advisory", "Job", "SearchRequest",
                     "SearchResponse", "Verdict", "ClassifyResponse"):
            with self.subTest(schema=name):
                self.assertIn(name, self.spec["components"]["schemas"])


class TestTheSpecDoesNotRestateLimits(_AppCase):
    """100, 300 and 500 were typed into the schema while the module that
    enforces them held the same numbers, so raising one left the published
    contract saying the old value and no test failed."""

    def test_the_published_limits_are_the_enforced_ones(self):
        from modules import search_service

        properties = self.spec["components"]["schemas"]["SearchRequest"]["properties"]
        self.assertEqual(properties["categories"]["maxItems"],
                         search_service.MAX_CATEGORY_INPUTS)
        self.assertEqual(properties["affects"]["maxLength"],
                         search_service.MAX_AFFECTS_LENGTH)
        self.assertEqual(properties["max_results"]["maximum"],
                         search_service.MAX_RESULTS_CAP)
        self.assertEqual(properties["max_results"]["default"],
                         search_service.DEFAULT_MAX_RESULTS)

    def test_the_enforced_limit_is_the_one_a_request_actually_hits(self):
        """Reading the constant proves the spec and the module agree; this
        proves the module agrees with itself."""
        from modules import search_service

        over = "x" * (search_service.MAX_AFFECTS_LENGTH + 1)
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query(
                {"categories": ["bac"], "affects": over})
        query = search_service.parse_search_query(
            {"categories": ["bac"], "max_results": 10_000})
        self.assertEqual(query.max_results, search_service.MAX_RESULTS_CAP)


if __name__ == "__main__":
    unittest.main(verbosity=2)
