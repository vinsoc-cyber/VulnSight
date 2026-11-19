"""End-to-end Flask endpoint tests (offline: gh CLI, OSV and AI all mocked;
cache pointed at a temp SQLite DB before the app module is imported)."""

import re
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import contextlib
import tempfile
import time
import unittest
from unittest import mock

from modules import ai_classifier
from modules import cache
from modules import ghsa_client as ghsa
from modules import nvd_client
from modules import osv_client
from samples import (
    NVD_VULN, OSV_GHSA, SAMPLE, SORT_A, SORT_B, SORT_C, http_error,
    make_sortable_raw, redirect_cooldown,
)

import app as app_module

# EPSS enrichment runs inside run_search, and nothing was mocking it, so the
# "offline" suite made 26 live DNS lookups to api.first.org per run. It passed
# only because epss_client swallows every failure — which also meant these
# tests would pass identically if EPSS enrichment were entirely broken.
# Individual tests that patch fetch_epss themselves still win: an inner
# mock.patch takes precedence over this one.
_epss_patch = None
_undo_cooldown = None


def setUpModule():
    global _epss_patch, _undo_cooldown
    # test_ai_classify_flow and friends drive the classifier with fixture
    # tokens, and mark_skip_token defaults to persist=True -- so without
    # this the suite writes their hashes into the repo's real
    # .ai_key_cooldown.json. See samples.redirect_cooldown.
    _undo_cooldown = redirect_cooldown()
    _epss_patch = mock.patch("modules.epss_client.fetch_epss", return_value={})
    _epss_patch.start()


def tearDownModule():
    if _undo_cooldown is not None:
        _undo_cooldown()
    if _epss_patch is not None:
        _epss_patch.stop()


class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        # Point the cache at a temp db BEFORE calling the app factory
        # (create_app() runs cache.init_db()).
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        # Isolate these tests from a developer .env that enables auth/limits.
        self._sec_env = mock.patch.dict(os.environ, {
            "VULNSIGHT_API_TOKEN": "",
            "VULNSIGHT_RATE_LIMIT": "off",
            "VULNSIGHT_PUBLIC_HOST": "",
            "HOST": "127.0.0.1",
            "VULNSIGHT_BIND": "127.0.0.1",
        }, clear=False)
        self._sec_env.start()
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        self._sec_env.stop()
        cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    # ------------------------------------------------------------------ meta

    def test_meta(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/api/meta")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("bac", data["categories"])
        self.assertIn("maven", data["ecosystems"])

    # ---------------------------------------------------------------- search

    def test_search_mocked(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post("/api/search", json={"categories": ["bac"], "ecosystem": "maven"})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["results"][0]["ghsa_id"], "GHSA-h3m5-97jq-qjrf")
        self.assertTrue(data["results"][0]["cwe_labels"])
        # persisted to cache
        self.assertEqual(cache.count_advisories(cache.DB_PATH), 1)

    def test_search_merge_dedupe_ghsa_osv(self):
        # Same CVE from both sources should collapse into ONE row tagged both.
        ghsa_rec = dict(SAMPLE, ghsa_id="GHSA-dupe", cve_id="CVE-2026-777")
        osv_rec = dict(OSV_GHSA, id="GHSA-dupe", aliases=["CVE-2026-777"])
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[ghsa_rec]), \
             mock.patch("modules.osv_client.fetch_osv",
                        return_value=[osv_client.normalize_osv(osv_rec)]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "ecosystem": "go",
                                       "sources": ["ghsa", "osv"]})
        data = r.get_json()
        self.assertEqual(data["count"], 1)                       # deduped
        self.assertEqual(sorted(data["results"][0]["sources"]), ["ghsa", "osv"])
        self.assertEqual(data["results"][0]["source"], "ghsa")   # GHSA base kept
        self.assertEqual(data["query"]["per_source"], {"ghsa": 1, "osv": 1})

    def test_search_osv_only_native_record(self):
        with mock.patch("modules.osv_client.fetch_osv",
                        return_value=[osv_client.normalize_osv(OSV_GHSA)]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "ecosystem": "go",
                                       "sources": ["osv"]})
        data = r.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["results"][0]["sources"], ["osv"])

    def test_search_osv_any_ecosystem_warns(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "ecosystem": "any",
                                       "sources": ["ghsa", "osv"]})
        data = r.get_json()
        self.assertTrue(any("OSV" in w for w in data["warnings"]))

    def test_search_no_category_returns_400(self):
        r = self.client.post("/api/search", json={})
        self.assertEqual(r.status_code, 400)
        self.assertIn("bug class", r.get_json()["error"].lower())

    def test_search_ghsa_error_502(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", side_effect=ghsa.GhCliError("nope")):
            r = self.client.post("/api/search", json={"categories": ["bac"]})
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.get_json()["error"], "GHSA fetch failed.")
        self.assertNotIn("nope", r.get_data(as_text=True))

    def test_mutating_apis_require_json_content_type(self):
        r = self.client.post(
            "/api/search", data='{"categories":["bac"]}', content_type="text/plain"
        )
        self.assertEqual(r.status_code, 415)
        r = self.client.post(
            "/api/ai/classify", data='{"advisory_ids":["X"]}', content_type="text/plain"
        )
        self.assertEqual(r.status_code, 415)
        with mock.patch("modules.ai_classifier.ping") as ping:
            r = self.client.post(
                "/api/ai/test", data="{}", content_type="text/plain"
            )
        self.assertEqual(r.status_code, 415)
        ping.assert_not_called()

    def test_ai_health_check_accepts_json_and_sets_security_headers(self):
        with mock.patch(
            "modules.ai_classifier.ping", return_value={"ok": True}
        ) as ping:
            r = self.client.post("/api/ai/test", json={})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])
        ping.assert_called_once_with()
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])

    def test_search_sort_updated_end_to_end(self):
        # Regression: body.sort="updated" used to be ignored (always published_at).
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=make_sortable_raw()):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "sort": "updated"})
        self.assertEqual(r.status_code, 200)
        ids = [x["ghsa_id"] for x in r.get_json()["results"]]
        # updated desc is now A, B, C -- distinct from every other
        # (field, direction) pair in the fixture. It used to be the exact
        # reverse of published, which made `published desc` and
        # `updated asc` the same order and hid a direction-flipped mix-up.
        self.assertEqual(ids, [SORT_A, SORT_B, SORT_C])

    # ------------------------------------------------------------ ai/classify

    def test_ai_classify_not_configured(self):
        with mock.patch("modules.ai_classifier.load_config",
                        return_value=ai_classifier.AIConfig("anthropic", "", [], "")):
            r = self.client.post("/api/ai/classify", json={"category": "bac", "advisory_ids": ["X"]})
        self.assertEqual(r.status_code, 400)

    def test_ai_classify_flow(self):
        # Seed cache with an advisory, then classify with mocked AI.
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("modules.ai_classifier._call_messages",
                        return_value='{"is_match": true, "confidence": 0.9, "vuln_type": "IDOR", "reason": "r"}'):
            r = self.client.post("/api/ai/classify",
                                 json={"category": "bac", "advisory_ids": [SAMPLE["ghsa_id"]]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["verdicts"][SAMPLE["ghsa_id"]]["is_match"])
        self.assertEqual(data["missing"], [])  # everything was in the cache

    def test_ai_classifies_every_selected_category(self):
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch(
                 "modules.ai_classifier._call_messages",
                 return_value=(
                     '{"is_match": true, "confidence": 0.9, '
                     '"vuln_type": "match", "reason": "r"}'
                 ),
             ) as call:
            r = self.client.post(
                "/api/ai/classify",
                json={
                    "categories": ["xss", "sqli"],
                    "advisory_ids": [SAMPLE["ghsa_id"]],
                },
            )
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["categories"], ["xss", "sqli"])
        self.assertEqual(set(data["by_category"]), {"xss", "sqli"})
        self.assertEqual(call.call_count, 2)
        self.assertEqual(
            data["verdicts"][SAMPLE["ghsa_id"]]["scored_categories"],
            ["sqli", "xss"],
        )

    def test_ai_batch_is_bounded(self):
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg):
            r = self.client.post(
                "/api/ai/classify",
                json={
                    "category": "bac",
                    "advisory_ids": [f"GHSA-{index}" for index in range(101)],
                },
            )
        self.assertEqual(r.status_code, 400)
        self.assertIn("maximum is", r.get_json()["error"])

    def test_ai_classify_rejects_nested_and_oversized_list_values(self):
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg):
            for body in (
                {"categories": [{"name": "bac"}], "advisory_ids": ["X"]},
                {"categories": ["bac"], "advisory_ids": [{"id": "X"}]},
                {"categories": ["bac"], "advisory_ids": ["X" * 201]},
            ):
                with self.subTest(body=body):
                    r = self.client.post("/api/ai/classify", json=body)
                    self.assertEqual(r.status_code, 400)

    def test_ai_health_check_is_post_only(self):
        self.assertEqual(self.client.get("/api/ai/test").status_code, 405)

    def test_ai_classify_reports_missing_ids(self):
        # Regression: ids absent from the cache used to be dropped silently;
        # now they must come back in "missing" (and the call still succeeds).
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("modules.ai_classifier._call_messages",
                        return_value='{"is_match": true, "confidence": 0.9, "vuln_type": "IDOR", "reason": "r"}'):
            r = self.client.post(
                "/api/ai/classify",
                json={"category": "bac",
                      "advisory_ids": [SAMPLE["ghsa_id"], "GHSA-not-in-cache"]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(
            set(data.keys()),
            {"category", "categories", "verdicts", "by_category", "missing"},
        )
        self.assertEqual(data["missing"], ["GHSA-not-in-cache"])
        self.assertIn(SAMPLE["ghsa_id"], data["verdicts"])
        self.assertNotIn("GHSA-not-in-cache", data["verdicts"])

    # -------------------------------------------------------------- NVD source

    def test_search_nvd_source(self):
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        with mock.patch("modules.nvd_client.fetch_nvd",
                        return_value=[nvd_normalized]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "sources": ["nvd"]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["results"][0]["cve_id"], "CVE-2021-44228")
        self.assertEqual(data["results"][0]["source"], "nvd")
        self.assertEqual(data["query"]["per_source"], {"nvd": 1})

    def test_search_nvd_and_ghsa_dedupe(self):
        ghsa_raw = dict(SAMPLE, cve_id="CVE-2021-44228")
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=[ghsa_raw]), \
             mock.patch("modules.nvd_client.fetch_nvd",
                        return_value=[nvd_normalized]):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"],
                                       "sources": ["ghsa", "nvd"]})
        data = r.get_json()
        self.assertEqual(data["count"], 1)
        self.assertIn("ghsa", data["results"][0]["sources"])
        self.assertIn("nvd", data["results"][0]["sources"])
        self.assertEqual(data["results"][0]["source"], "ghsa")

    def test_search_nvd_error_502_when_only_source(self):
        with mock.patch("modules.nvd_client.fetch_nvd",
                        side_effect=nvd_client.NvdError("rate limited")):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"], "sources": ["nvd"]})
        self.assertEqual(r.status_code, 502)

    def test_search_nvd_error_warning_with_other_sources(self):
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=[SAMPLE]), \
             mock.patch("modules.nvd_client.fetch_nvd",
                        side_effect=nvd_client.NvdError("rate limited")):
            r = self.client.post("/api/search",
                                 json={"categories": ["bac"],
                                       "sources": ["ghsa", "nvd"]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(any("NVD fetch failed" in w for w in data["warnings"]))
        self.assertEqual(data["query"]["per_source"].get("ghsa"), 1)

    def test_index_has_nvd_checkbox(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        self.assertIn(b'value="nvd"', r.data)

    # ----------------------------------------------------------------- pages

    def test_index_renders(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"VulnSight", r.data)
        self.assertIn(b"window.BOOT", r.data)  # server data is injected via BOOT

    def test_index_boot_and_static_assets(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        self.assertIn(b"window.BOOT", r.data)
        self.assertIn(b"app.js", r.data)
        self.assertIn(b"style.css", r.data)

    def test_index_keeps_frontend_dom_contract(self):
        """The visual shell may change, but app.js hooks must remain stable."""
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            html = self.client.get("/").get_data(as_text=True)

        required_ids = [
            "refresh_osv", "include_extended", "ecosystem",
            "severity", "affects_pick", "published", "max_results", "sort",
            "direction", "type", "auto-btn", "search-btn",
            "cwe-search", "cwe-clear", "cwe-options", "selected-chips",
            "selection-count", "selection-live",
            "history-section", "history-list", "history-clear", "stale-banner",
            "class-search", "class-count", "taxonomy-list", "taxonomy-empty",
            "summary", "ai-btn", "retry-btn", "only_match", "export-btn",
            "results", "ai-test-pill", "filters-toggle", "filters-close",
            "filter-scrim",
            "auth-gate", "auth-token", "auth-save",
        ]
        for element_id in required_ids:
            self.assertEqual(html.count(f'id="{element_id}"'), 1, element_id)

        for name in ("category", "source"):
            self.assertIn(f'name="{name}"', html)
        # The CWE catalog is fetched from /api/cwes, never inlined in the page.
        self.assertNotIn("cwe_catalog", html)
        # Screen-reader landmarks: one h1, and no aria-label stranded on a bare
        # <div> (role=generic drops the label).
        self.assertEqual(html.count("<h1"), 1)
        # Derived, not a hand-listed set of classes: the list named three,
        # one of which has since been deleted, and a new labelled <div> would
        # never have been added to it. Every bare <div> carrying an
        # aria-label needs a role, because role=generic drops the label.
        for tag in re.findall(r"<div\b[^>]*>", html):
            if "aria-label" not in tag:
                continue
            with self.subTest(tag=tag[:70]):
                self.assertRegex(
                    tag, r'role="[a-z]+"',
                    "a <div> with an aria-label and no role is announced "
                    "as role=generic, which drops the label")
        self.assertLess(len(html), 60000, "index page should stay lean")
        for export_format in ("csv", "json", "csv-matches"):
            self.assertIn(f'data-fmt="{export_format}"', html)
        # app.js reads window.BOOT at load, so the data has to be defined
        # above the tag. Match the tag itself: a bare "app.js" also matches any
        # comment that happens to name the file, which made this pass or fail
        # on prose rather than on script order.
        self.assertIn('<script src="/static/app.js">', html)
        self.assertLess(html.index("window.BOOT"),
                        html.index('<script src="/static/app.js">'))
        self.assertIn('id="ai-test-pill" type="button"', html)
        self.assertIn('value="epss_percentage"', html)
        self.assertIn('value="epss_percentile"', html)
        self.assertIn('id="theme-toggle"', html)
        self.assertIn("AUTH_REQUIRED: false", html)

    def test_static_assets_served(self):
        css = self.client.get("/static/style.css")
        js = self.client.get("/static/app.js")
        self.assertEqual(css.status_code, 200)
        self.assertIn("text/css", css.headers.get("Content-Type", ""))
        self.assertEqual(js.status_code, 200)
        self.assertIn("function csvCell", js.get_data(as_text=True))
        self.assertIn("epss_percentage", js.get_data(as_text=True))

    def test_osv_status_endpoint(self):
        r = self.client.get("/api/osv/status")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("supported", data)
        self.assertIn("cached", data)

    def test_cwe_catalog_endpoint(self):
        r = self.client.get("/api/cwes")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["columns"], ["id", "label", "aliases", "level"])
        self.assertGreater(len(data["rows"]), 900)
        by_id = {row[0]: row for row in data["rows"]}
        # Full name and code for every entry — that is the point of the picker.
        self.assertEqual(by_id["639"][1], "Authorization Bypass Through User-Controlled Key")
        self.assertIn("IDOR", by_id["639"][2].split("|"))
        self.assertEqual(by_id["639"][3], "Base")

    def test_cwe_catalog_is_cacheable(self):
        """The browser must reuse the catalog instead of refetching 60+ KB."""
        first = self.client.get("/api/cwes")
        etag = first.headers["ETag"]
        self.assertIn("max-age=", first.headers["Cache-Control"])
        again = self.client.get("/api/cwes", headers={"If-None-Match": etag})
        self.assertEqual(again.status_code, 304)
        self.assertEqual(again.get_data(), b"")

    def test_classify_accepts_single_cwe_pseudo_category(self):
        # get_advisories, plural: classify_batch has used the batched
        # reader since it stopped opening one connection per id, and
        # cache.get_advisory (singular) has had no production caller
        # since. Patching it stubbed nothing -- these passed only because
        # the per-test database happened to be empty, which was also the
        # only brake on the fan-out test below.
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
                mock.patch("modules.cache.get_advisories", return_value={}):
            r = self.client.post(
                "/api/ai/classify",
                json={"categories": ["cwe:1321", "bac"], "advisory_ids": ["GHSA-x"]},
            )
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["categories"], ["cwe:1321", "bac"])
        self.assertEqual(body["missing"], ["GHSA-x"])

    def test_classify_rejects_over_budget_fan_out(self):
        """categories × advisories is the real cost; cap the product, not each."""
        from modules.cwe_categories import picker_catalog

        real_cwes = [f"cwe:{row[0]}" for row in picker_catalog()["rows"][:30]]
        advisory_ids = [f"GHSA-x-{i}" for i in range(30)]
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg):
            r = self.client.post(
                "/api/ai/classify",
                json={"categories": real_cwes, "advisory_ids": advisory_ids},
            )
        self.assertEqual(r.status_code, 400)
        error = r.get_json()["error"]
        self.assertIn("900", error)
        self.assertIn(str(app_module.MAX_AI_CALLS_PER_REQUEST), error)

    def test_classify_allows_fan_out_within_budget(self):
        from modules.cwe_categories import picker_catalog

        real_cwes = [f"cwe:{row[0]}" for row in picker_catalog()["rows"][:10]]
        cfg = ai_classifier.AIConfig("anthropic", "https://x", ["tok"], "PRO")
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
                mock.patch("modules.cache.get_advisories", return_value={}):
            r = self.client.post(
                "/api/ai/classify",
                json={"categories": real_cwes,
                      "advisory_ids": [f"GHSA-x-{i}" for i in range(20)]},
            )
        self.assertEqual(r.status_code, 200)

    def test_index_exposes_the_ai_call_budget_to_the_client(self):
        """The UI sizes its batches from this, so it must be in BOOT."""
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            html = self.client.get("/").get_data(as_text=True)
        self.assertIn(
            f"AI_CALL_BUDGET: {app_module.MAX_AI_CALLS_PER_REQUEST}", html
        )

    def test_classify_rejects_malformed_cwe_pseudo_category(self):
        r = self.client.post(
            "/api/ai/classify",
            json={"categories": ["cwe:0"], "advisory_ids": ["GHSA-x"]},
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("Unsupported categories", r.get_json()["error"])

    def test_csrf_blocks_foreign_origin(self):
        r = self.client.post(
            "/api/search",
            json={"categories": ["bac"]},
            headers={"Origin": "http://evil.example"},
        )
        self.assertEqual(r.status_code, 403)
        self.assertIn("Cross-origin", r.get_json()["error"])

    def test_csrf_allows_localhost_origin(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"Origin": "http://127.0.0.1:5000"},
            )
        self.assertEqual(r.status_code, 200)

    def test_csrf_blocks_prefix_lookalike_origins(self):
        for origin in (
            "http://localhost.evil.com",
            "http://localhostevil.com",
            "http://127.0.0.1.attacker.com",
            "http://127.0.0.1.example",
            "http://127.0.0.1:5000.evil.com",
        ):
            with self.subTest(origin=origin):
                r = self.client.post(
                    "/api/search",
                    json={"categories": ["bac"]},
                    headers={"Origin": origin},
                )
                self.assertEqual(r.status_code, 403, origin)

    def test_csrf_blocks_cross_site_fetch_metadata(self):
        r = self.client.post(
            "/api/search",
            json={"categories": ["bac"]},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(r.status_code, 403)

    def test_csrf_blocks_evil_referer_without_origin(self):
        r = self.client.post(
            "/api/search",
            json={"categories": ["bac"]},
            headers={"Referer": "http://evil.example/page"},
        )
        self.assertEqual(r.status_code, 403)

    def test_search_ghsa_error_does_not_leak_cli_stderr(self):
        with mock.patch(
            "modules.ghsa_client.fetch_advisories",
            side_effect=ghsa.GhCliError("token ghp_LEAKED"),
        ):
            r = self.client.post("/api/search", json={"categories": ["bac"]})
        self.assertEqual(r.status_code, 502)
        body = r.get_data(as_text=True)
        self.assertNotIn("ghp_LEAKED", body)
        self.assertEqual(r.get_json()["error"], "GHSA fetch failed.")

    def test_ai_test_hides_provider_error_body(self):
        cfg = ai_classifier.AIConfig("glm", "https://x", ["tok"], "m")
        err = http_error(
            401,
            url="https://x/chat/completions",
            reason="Unauthorized",
            headers=None,
            body=b'{"error":"invalid api_key sk-secret-abc"}',
        )
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("urllib.request.urlopen", side_effect=err):
            r = self.client.post("/api/ai/test", json={})
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertFalse(r.get_json()["ok"])
        self.assertEqual(r.get_json()["error"], "AI provider returned HTTP 401")
        self.assertNotIn("sk-secret-abc", body)
        self.assertNotIn("invalid api_key", body)

    def test_ai_classify_hides_provider_error_body(self):
        cache.upsert_advisories([ghsa.normalize(SAMPLE)], cache.DB_PATH)
        cfg = ai_classifier.AIConfig("glm", "https://x", ["tok"], "m")
        err = http_error(
            403,
            url="https://x/chat/completions",
            reason="Forbidden",
            headers=None,
            body=b'{"error":"token ghp_LEAKED rejected"}',
        )
        with mock.patch("modules.ai_classifier.load_config", return_value=cfg), \
             mock.patch("urllib.request.urlopen", side_effect=err):
            r = self.client.post(
                "/api/ai/classify",
                json={"category": "bac", "advisory_ids": [SAMPLE["ghsa_id"]]},
            )
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        data = r.get_json()
        self.assertEqual(
            data["by_category"]["bac"][SAMPLE["ghsa_id"]]["error"],
            "AI provider returned HTTP 403",
        )
        self.assertIn("AI provider returned HTTP 403", data["verdicts"][SAMPLE["ghsa_id"]]["error"])
        self.assertNotIn("ghp_LEAKED", body)

    def test_index_csp_nonce_matches_header(self):
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            r = self.client.get("/")
        html = r.get_data(as_text=True)
        csp = r.headers["Content-Security-Policy"]
        marker = 'script nonce="'
        nonce = html.split(marker, 1)[1].split('"', 1)[0]
        self.assertGreaterEqual(len(nonce), 20)
        self.assertIn(f"'nonce-{nonce}'", csp)


    def test_a_guard_blocked_response_still_carries_a_real_csp_nonce(self):
        """before_request hooks run in registration order, so with the nonce
        hook registered after the guards every response short-circuited by
        CSRF, auth or the rate limiter carried `script-src 'self' 'nonce-'`:
        a malformed source expression."""
        r = self.client.post(
            "/api/search",
            json={"categories": ["bac"]},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("'nonce-'", r.headers["Content-Security-Policy"])


class TestApiVersioning(unittest.TestCase):
    """Every API route answers on both /api/... and /api/v1/...."""

    def setUp(self):
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
        self._env.stop()
        cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def test_every_api_route_has_a_v1_twin(self):
        """Fails when a new /api/ route ships without its versioned alias."""
        # /api/docs is an HTML reference page, not versioned API surface: it
        # renders whatever the current spec says, so there is nothing to pin.
        not_api_surface = {"/api/docs"}
        rules = [
            str(rule) for rule in self.app.url_map.iter_rules()
            if str(rule).startswith("/api/") and str(rule) not in not_api_surface
        ]
        legacy = {r for r in rules if not r.startswith("/api/v1/")}
        versioned = {
            "/api" + r[len("/api/v1"):] for r in rules if r.startswith("/api/v1/")
        }
        self.assertTrue(legacy, "no /api routes found — the check would be vacuous")
        self.assertEqual(
            legacy - versioned, set(),
            "these /api routes have no /api/v1 alias",
        )

    def test_v1_and_legacy_return_the_same_payload(self):
        for legacy, versioned in (
            ("/api/meta", "/api/v1/meta"),
            ("/api/cwes", "/api/v1/cwes"),
            ("/api/osv/status", "/api/v1/osv/status"),
        ):
            with self.subTest(path=versioned):
                with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=True):
                    a = self.client.get(legacy)
                    b = self.client.get(versioned)
                self.assertEqual(a.status_code, 200)
                self.assertEqual(b.status_code, 200)
                self.assertEqual(a.get_json(), b.get_json())

    def test_v1_search_is_rate_limited_like_the_legacy_path(self):
        """The limiter matches on endpoint; a path match left /api/v1 unlimited."""
        self._env.stop()
        self._env = mock.patch.dict(os.environ, {
            "VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "on",
            "VULNSIGHT_SEARCH_RATE": "1", "VULNSIGHT_RATE_WINDOW": "60",
            "HOST": "127.0.0.1",
            "VULNSIGHT_BIND": "127.0.0.1",
        }, clear=False)
        self._env.start()
        from app import create_app
        client = create_app().test_client()
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = client.post("/api/v1/search",
                                json={"categories": ["bac"], "ecosystem": "maven"})
            second = client.post("/api/v1/search",
                                 json={"categories": ["bac"], "ecosystem": "maven"})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    def test_search_reports_row_counts_per_pipeline_stage(self):
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post("/api/v1/search",
                                 json={"categories": ["bac"], "ecosystem": "maven"})
        stats = r.get_json()["stats"]
        self.assertEqual(stats["fetched_per_source"], {"ghsa": 1})
        self.assertEqual(
            [stats["fetched_total"], stats["after_merge"],
             stats["after_filter"], stats["returned"]],
            [1, 1, 1, 1],
        )
        self.assertFalse(stats["truncated"])

    def test_truncated_flag_distinguishes_paging_from_dedupe(self):
        """`count` alone could not tell a dropped row from a de-duplicated one."""
        raw = [dict(SAMPLE, ghsa_id=f"GHSA-{n}", cve_id=f"CVE-2026-{n}")
               for n in range(5)]
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=raw):
            r = self.client.post("/api/v1/search", json={
                "categories": ["bac"], "ecosystem": "maven", "max_results": 2,
            })
        stats = r.get_json()["stats"]
        self.assertEqual(stats["after_filter"], 5)
        self.assertEqual(stats["returned"], 2)
        self.assertTrue(stats["truncated"])


class TestTheRequestGuardsNobodyExercised(unittest.TestCase):
    """Three guards the docs promise and no test reached. Each was
    confirmed by mutation: the suite stayed green with the guard removed.
    """

    def _make(self, env=None):
        merged = {"VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "off",
                  "HOST": "127.0.0.1", "VULNSIGHT_BIND": "127.0.0.1"}
        merged.update(env or {})
        patcher = mock.patch.dict(os.environ, merged, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        original = cache.DB_PATH
        cache.DB_PATH = tmp.name

        def restore():
            cache.DB_PATH = original
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(tmp.name + suffix)
                except OSError:
                    pass

        self.addCleanup(restore)
        from app import create_app
        app = create_app()
        app.config["TESTING"] = True
        return app.test_client()

    def test_an_oversized_body_is_refused(self):
        """docs/automation.md promises MAX_REQUEST_BYTES. Setting
        MAX_CONTENT_LENGTH to None left every test green -- the cap could
        have been removed and shipped."""
        client = self._make({"MAX_REQUEST_BYTES": "2048"})
        huge = {"categories": ["bac"], "pad": "x" * 8192}
        self.assertEqual(client.post("/api/v1/search", json=huge).status_code, 413)

    def test_a_body_inside_the_cap_is_accepted(self):
        client = self._make({"MAX_REQUEST_BYTES": "65536"})
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[]):
            r = client.post("/api/v1/search", json={"categories": ["bac"]})
        self.assertNotEqual(r.status_code, 413)

    def test_the_versioned_ai_endpoint_is_rate_limited_too(self):
        """Only the legacy path was tested, so mutating just the AI branch
        of _rate_limit to path-matching left the suite green."""
        client = self._make({"VULNSIGHT_RATE_LIMIT": "on",
                             "VULNSIGHT_AI_RATE": "1",
                             "VULNSIGHT_RATE_WINDOW": "60"})
        body = {"categories": ["bac"], "advisory_ids": ["GHSA-x"]}
        with mock.patch("modules.cache.get_advisories", return_value={}):
            first = client.post("/api/v1/ai/classify", json=body)
            second = client.post("/api/v1/ai/classify", json=body)
        self.assertNotEqual(first.status_code, 429)
        self.assertEqual(second.status_code, 429)

    def test_a_non_object_json_body_is_a_400(self):
        client = self._make()
        r = client.post("/api/v1/search", data="[1, 2, 3]",
                        content_type="application/json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())


class TestJobEndpoints(unittest.TestCase):
    """The async path: submit, poll, and the guards around both."""

    def _make(self, env=None):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        merged = {
            "VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "off",
            "HOST": "127.0.0.1",
            "VULNSIGHT_BIND": "127.0.0.1",
        }
        merged.update(env or {})
        self._env = mock.patch.dict(os.environ, merged, clear=False)
        self._env.start()

        # For the whole test, not just the POST. A job is run by a worker
        # thread *after* the request returns, so a `with mock.patch(...)`
        # around the submit call has already exited by the time the search
        # happens -- and the worker then called the real `gh api`, reaching
        # GitHub with the operator's credentials. This file's header and
        # docs/testing.md both promise the suite needs no network and no
        # credentials; two tests here were quietly breaking that.
        for target, value in (("modules.ghsa_client.fetch_advisories", [SAMPLE]),
                              ("modules.ghsa_client.gh_auth_ok", True)):
            patcher = mock.patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        from modules import jobs
        jobs.shutdown(wait=True)
        jobs.resume()
        if hasattr(self, "_env"):
            self._env.stop()
        if hasattr(self, "_orig_db"):
            cache.DB_PATH = self._orig_db
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def _poll(self, job_id, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self.client.get(f"/api/v1/jobs/{job_id}")
            body = r.get_json()
            if body["status"] in ("done", "failed"):
                return body
            time.sleep(0.01)
        raise AssertionError("job never finished")

    def test_submit_returns_202_with_a_pollable_location(self):
        self._make()
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post("/api/v1/jobs",
                                 json={"categories": ["bac"], "ecosystem": "maven"})
            self.assertEqual(r.status_code, 202)
            body = r.get_json()
            self.assertEqual(body["status"], "queued")
            self.assertEqual(body["kind"], "search")
            self.assertEqual(r.headers["Location"], f"/api/v1/jobs/{body['job_id']}")
            done = self._poll(body["job_id"])
        self.assertEqual(done["status"], "done")
        self.assertEqual(done["result"]["count"], 1)

    def test_job_result_matches_the_synchronous_response(self):
        """Moving a slow query to /jobs must not mean parsing a second shape."""
        self._make()
        query = {"categories": ["bac"], "ecosystem": "maven"}
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            sync = self.client.post("/api/v1/search", json=query).get_json()
            job_id = self.client.post("/api/v1/jobs", json=query).get_json()["job_id"]
            async_result = self._poll(job_id)["result"]
        self.assertEqual(sync.keys(), async_result.keys())
        self.assertEqual(sync["query"], async_result["query"])
        self.assertEqual(sync["stats"], async_result["stats"])
        self.assertEqual(sync["results"], async_result["results"])

    def test_a_bad_query_is_rejected_now_not_a_minute_later(self):
        self._make()
        r = self.client.post("/api/v1/jobs", json={"categories": []})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("job_id", r.get_json())

    def test_a_failing_search_becomes_a_failed_job_with_its_status(self):
        self._make()
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        side_effect=ghsa.GhCliError("nope")):
            job_id = self.client.post(
                "/api/v1/jobs",
                json={"categories": ["bac"], "sources": ["ghsa"]},
            ).get_json()["job_id"]
            done = self._poll(job_id)
        self.assertEqual(done["status"], "failed")
        self.assertEqual(done["error"], "GHSA fetch failed.")
        self.assertNotIn("nope", done["error"])
        self.assertNotIn("result", done)

    def test_unknown_and_malformed_job_ids_are_404(self):
        self._make()
        for job_id in ("0" * 24, "not-a-job", "a" * 23, "A" * 24, "1;DROP TABLE jobs"):
            with self.subTest(job_id=job_id):
                r = self.client.get(f"/api/v1/jobs/{job_id}")
                self.assertEqual(r.status_code, 404)
                self.assertEqual(r.get_json(), {"error": "No such job."})

    def test_traversal_in_a_job_id_never_reaches_the_handler(self):
        """Werkzeug normalises the path, so it matches no route at all."""
        self._make()
        r = self.client.get("/api/v1/jobs/%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json(), {"error": "No such endpoint."})

    def test_api_errors_are_json_even_when_no_route_matches(self):
        """A script doing r.json() on a wrong path used to get a parse error."""
        self._make()
        missing = self.client.get("/api/v1/nope")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.get_json(), {"error": "No such endpoint."})

        wrong_method = self.client.get("/api/v1/search")
        self.assertEqual(wrong_method.status_code, 405)
        self.assertIn("error", wrong_method.get_json())

        # The UI still gets HTML, because a browser is not a script.
        html = self.client.get("/definitely-not-a-page")
        self.assertEqual(html.status_code, 404)
        self.assertIsNone(html.get_json(silent=True))

    def test_polling_requires_the_token_unlike_other_gets(self):
        """A job result is the operator's query output, not public reference data."""
        self._make({"VULNSIGHT_API_TOKEN": "secret"})
        headers = {"X-VulnSight-Token": "secret"}
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            job_id = self.client.post(
                "/api/v1/jobs", json={"categories": ["bac"], "ecosystem": "maven"},
                headers=headers,
            ).get_json()["job_id"]
        self.assertEqual(self.client.get(f"/api/v1/jobs/{job_id}").status_code, 401)
        self.assertEqual(self.client.get("/api/v1/cwes").status_code, 200)
        authed = self.client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        self.assertEqual(authed.status_code, 200)

    def test_submitting_a_job_spends_the_search_rate_limit(self):
        """Otherwise /jobs is a free way around the limit it exists to work with."""
        self._make({"VULNSIGHT_RATE_LIMIT": "on", "VULNSIGHT_SEARCH_RATE": "1",
                    "VULNSIGHT_RATE_WINDOW": "60"})
        query = {"categories": ["bac"], "ecosystem": "maven"}
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = self.client.post("/api/v1/jobs", json=query)
            second = self.client.post("/api/v1/jobs", json=query)
            third = self.client.post("/api/v1/search", json=query)
        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(third.status_code, 429)  # shared bucket, not two budgets

    def test_legacy_job_paths_work_too(self):
        self._make()
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post("/api/jobs",
                                 json={"categories": ["bac"], "ecosystem": "maven"})
            self.assertEqual(r.status_code, 202)
            job_id = r.get_json()["job_id"]
            self._poll(job_id)
        self.assertEqual(self.client.get(f"/api/jobs/{job_id}").status_code, 200)


class TestAppAuthAndLimits(unittest.TestCase):
    def _make(self, env):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        merged = {
            "VULNSIGHT_API_TOKEN": "",
            "VULNSIGHT_RATE_LIMIT": "on",
            "VULNSIGHT_PUBLIC_HOST": "",
            "VULNSIGHT_SEARCH_RATE": "30",
            "VULNSIGHT_AI_RATE": "20",
            "VULNSIGHT_RATE_WINDOW": "60",
            "HOST": "127.0.0.1",
            "VULNSIGHT_BIND": "127.0.0.1",
        }
        merged.update(env)
        self._env = mock.patch.dict(os.environ, merged, clear=False)
        self._env.start()
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        if hasattr(self, "_env"):
            self._env.stop()
        if hasattr(self, "_orig_db"):
            cache.DB_PATH = self._orig_db
        if hasattr(self, "tmp"):
            for ext in ["", "-wal", "-shm"]:
                try:
                    os.unlink(self.tmp.name + ext)
                except OSError:
                    pass

    def test_a_route_added_later_is_guarded_until_it_is_listed(self):
        """The allowlist used to be unreachable. A method check above it --
        "anything that is not a write, except job polling, is public" --
        returned first, and since every allowlisted endpoint is GET-only,
        the list never decided anything. Emptying it changed no test.

        What that cost: a GET route added later was public by default. The
        comment above the list claimed the opposite."""
        self._make({"VULNSIGHT_API_TOKEN": "s3cret"})

        @self.app.route("/api/v1/secrets")
        def api_secrets():
            return {"ok": True}

        client = self.app.test_client()
        self.assertEqual(client.get("/api/v1/secrets").status_code, 401,
                         "a new GET route is public by default again")
        self.assertEqual(
            client.get("/api/v1/secrets",
                       headers={"X-VulnSight-Token": "s3cret"}).status_code, 200)

    def test_the_allowlist_is_what_keeps_public_data_public(self):
        """The other half: the listed endpoints must stay reachable."""
        self._make({"VULNSIGHT_API_TOKEN": "s3cret"})
        client = self.app.test_client()
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=True):
            for path in ("/", "/api/v1/cwes", "/api/v1/meta",
                         "/api/v1/openapi.json", "/api/v1/osv/status"):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 200)

    def test_token_required_on_post_not_get(self):
        self._make({"VULNSIGHT_API_TOKEN": "test-secret-token"})
        self.assertEqual(
            self.client.post("/api/search", json={"categories": ["bac"]}).status_code,
            401,
        )
        # Both "/" and "/api/meta" report gh auth status, and unmocked that
        # shells out to the real `gh auth status`. It is cached, so only the
        # first caller paid -- which is why this went unnoticed.
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=False):
            self.assertEqual(self.client.get("/api/meta").status_code, 200)
            html = self.client.get("/").get_data(as_text=True)
        self.assertIn("AUTH_REQUIRED: true", html)
        self.assertNotIn("test-secret-token", html)
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            ok = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-VulnSight-Token": "test-secret-token"},
            )
            bearer = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"Authorization": "Bearer test-secret-token"},
            )
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(bearer.status_code, 200)
        self.assertEqual(
            self.client.post(
                "/api/search",
                json={"categories": ["bac"]},
                headers={"X-VulnSight-Token": "wrong"},
            ).status_code,
            401,
        )

    def test_csrf_allows_configured_public_host(self):
        self._make({"VULNSIGHT_PUBLIC_HOST": "vulnsight.example"})
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            r = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"Origin": "https://vulnsight.example"},
            )
        self.assertEqual(r.status_code, 200)

    def test_search_rate_limit(self):
        self._make({"VULNSIGHT_SEARCH_RATE": "1", "VULNSIGHT_RATE_WINDOW": "60"})
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"}
            )
            second = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"}
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.headers.get("Retry-After"), "60")

    def test_unauthenticated_posts_do_not_consume_the_rate_limit(self):
        """Auth runs before rate limiting, so a rejected caller spends nothing.

        With the hooks the other way round an unauthenticated flood drained the
        shared bucket and the operator's own next request — with the right
        token — came back 429. Every request here is 401; none reaches the
        limiter, and the authenticated request that follows still succeeds.
        """
        self._make({
            "VULNSIGHT_API_TOKEN": "secret",
            "VULNSIGHT_SEARCH_RATE": "2",
            "VULNSIGHT_RATE_WINDOW": "60",
        })
        rejected = [
            self.client.post("/api/search", json={"categories": ["bac"]}).status_code
            for _ in range(6)
        ]
        self.assertEqual(rejected, [401] * 6)
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            operator = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-VulnSight-Token": "secret"},
            )
        self.assertEqual(operator.status_code, 200)

    def test_rate_limit_key_ignores_forwarded_for_by_default(self):
        """X-Forwarded-For is client-controlled; trusting it mints free buckets."""
        self._make({"VULNSIGHT_SEARCH_RATE": "1", "VULNSIGHT_RATE_WINDOW": "60"})
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "1.1.1.1"},
            )
            second = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "2.2.2.2"},
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    def test_rate_limit_key_honours_forwarded_for_when_proxy_trusted(self):
        self._make({
            "VULNSIGHT_SEARCH_RATE": "1",
            "VULNSIGHT_RATE_WINDOW": "60",
            "VULNSIGHT_TRUST_PROXY": "1",
        })
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            first = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "1.1.1.1"},
            )
            other_client = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "2.2.2.2"},
            )
            same_client = self.client.post(
                "/api/search", json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-Forwarded-For": "1.1.1.1"},
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(other_client.status_code, 200)  # separate bucket
        self.assertEqual(same_client.status_code, 429)   # same bucket, exhausted

    def test_classify_without_a_category_is_rejected_not_billed(self):
        """parse_text defaulted a missing category to "bac", so a request with
        no category at all ran a paid pass against Broken Access Control and
        returned verdicts the caller never asked for. /api/v1/search rejects
        the same omission and openapi.py declares categories required."""
        self._make({"GLM_TOKEN": "live-key", "VULNSIGHT_RATE_LIMIT": "off"})
        with mock.patch("modules.ai_classifier.classify_many") as spend:
            response = self.client.post("/api/v1/ai/classify",
                                        json={"advisory_ids": ["GHSA-aaaa"]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("bug class", (response.get_json() or {}).get("error", ""))
        spend.assert_not_called()

    def test_a_route_outside_api_is_not_unauthenticated_by_default(self):
        """Auth matched on `request.path.startswith("/api/")` while the rate
        limiter matched on the endpoint and carried a comment explaining why
        the path was wrong. Two guards, two notions of "protected": the next
        POST /export or /admin/reindex would have been open, and no test
        would have noticed."""
        self._make({"GLM_TOKEN": "live-key", "VULNSIGHT_API_TOKEN": "s3cret",
                    "VULNSIGHT_RATE_LIMIT": "off"})

        @self.app.route("/admin/reindex", methods=["POST"])
        def _admin_reindex():
            from flask import jsonify
            return jsonify({"ok": True})

        client = self.app.test_client()
        self.assertEqual(client.post("/admin/reindex").status_code, 401)
        self.assertEqual(
            client.post("/admin/reindex",
                        headers={"X-VulnSight-Token": "s3cret"}).status_code,
            200)

    def test_public_reference_data_stays_readable_without_a_token(self):
        self._make({"GLM_TOKEN": "live-key", "VULNSIGHT_API_TOKEN": "s3cret",
                    "VULNSIGHT_RATE_LIMIT": "off"})
        client = self.app.test_client()
        # "/" renders the shell, which asks gh whether it is authenticated.
        # Unmocked that shells out to the real `gh auth status` with the
        # operator's credentials, in a suite whose header promises it needs
        # neither network nor credentials.
        with mock.patch("modules.ghsa_client.gh_auth_ok", return_value=True):
            for path in ("/", "/api/v1/cwes", "/api/v1/meta",
                         "/api/v1/openapi.json", "/api/v1/osv/status"):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 200)

    def test_a_mutating_api_call_still_needs_the_token(self):
        self._make({"GLM_TOKEN": "live-key", "VULNSIGHT_API_TOKEN": "s3cret",
                    "VULNSIGHT_RATE_LIMIT": "off"})
        client = self.app.test_client()
        self.assertEqual(
            client.post("/api/v1/search", json={"categories": ["bac"]}).status_code,
            401)

    def test_non_loopback_autogens_token(self):
        data_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, data_dir, ignore_errors=True)
        self._make({
            "HOST": "0.0.0.0",
            "VULNSIGHT_BIND": "0.0.0.0",
            "GLM_TOKEN": "live-key",
            "VULNSIGHT_API_TOKEN": "",
            "VULNSIGHT_DATA_DIR": data_dir,
            "VULNSIGHT_RATE_LIMIT": "off",
        })
        token = self.app.config["VULNSIGHT_TOKEN"]
        self.assertTrue(token)
        path = os.path.join(data_dir, ".vulnsight_api_token")
        with open(path, encoding="utf-8") as fh:
            saved = fh.read().strip()
        self.assertEqual(saved, token)
        self.assertEqual(self.client.post("/api/search", json={"categories": ["bac"]}).status_code, 401)
        with mock.patch("modules.ghsa_client.fetch_advisories", return_value=[SAMPLE]):
            ok = self.client.post(
                "/api/search",
                json={"categories": ["bac"], "ecosystem": "maven"},
                headers={"X-VulnSight-Token": token},
            )
        self.assertEqual(ok.status_code, 200)

    def test_ai_rate_limit(self):
        self._make({"VULNSIGHT_AI_RATE": "1", "VULNSIGHT_RATE_WINDOW": "60"})
        with mock.patch("modules.ai_classifier.ping", return_value={"ok": True}):
            first = self.client.post("/api/ai/test", json={})
            second = self.client.post("/api/ai/test", json={})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)


class TestConditionalRequestsFollowTheSpec(unittest.TestCase):
    """`If-None-Match == etag` rejected both legal forms a caller may send:
    a comma-separated tag list and `*`.

    That matters more than a style nit here. app.py's own comment frames
    the 304 on /openapi.json as a DoS control -- the endpoint is
    unauthenticated and exempt from the rate limiter precisely because the
    304 is meant to be the cheap path -- so a caller sending a tag list
    walked past it and re-serialised the whole document every time."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig_db = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        self._env = mock.patch.dict(os.environ, {
            "VULNSIGHT_API_TOKEN": "", "VULNSIGHT_RATE_LIMIT": "off",
            "VULNSIGHT_BIND": "127.0.0.1"}, clear=False)
        self._env.start()
        from app import create_app
        self.client = create_app().test_client()

    def tearDown(self):
        self._env.stop()
        cache.DB_PATH = self._orig_db
        for ext in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.unlink(self.tmp.name + ext)

    def _etag(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return response.headers["ETag"]

    def test_a_tag_list_containing_the_match_is_a_304(self):
        for path in ("/api/v1/openapi.json", "/api/v1/cwes"):
            etag = self._etag(path)
            for header in (etag, f'{etag}, W/"other"', f'W/"other", {etag}', "*"):
                with self.subTest(path=path, header=header):
                    response = self.client.get(
                        path, headers={"If-None-Match": header})
                    self.assertEqual(response.status_code, 304, header)

    def test_a_tag_list_without_the_match_still_serves_the_body(self):
        for path in ("/api/v1/openapi.json", "/api/v1/cwes"):
            with self.subTest(path=path):
                response = self.client.get(
                    path, headers={"If-None-Match": 'W/"a", W/"b"'})
                self.assertEqual(response.status_code, 200)

    def test_the_304_still_carries_its_validators(self):
        """RFC 9110 S15.4.5: a 304 SHOULD send what a 200 would have sent
        for caching. Dropping them makes the next request unconditional, so
        the 304 saves one round trip and then stops saving anything."""
        for path in ("/api/v1/openapi.json", "/api/v1/cwes"):
            etag = self._etag(path)
            with self.subTest(path=path):
                response = self.client.get(
                    path, headers={"If-None-Match": etag})
                self.assertEqual(response.status_code, 304)
                self.assertEqual(response.headers.get("ETag"), etag)
                self.assertTrue(response.headers.get("Cache-Control"),
                                "the 304 dropped Cache-Control")


if __name__ == "__main__":
    unittest.main(verbosity=2)
