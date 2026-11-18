"""Tests for search_service: query parsing, merge/dedupe, and run_search
orchestration (sort-field fix, source error policy). All fetchers are mocked
and the cache is pointed at a temp SQLite DB."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest
from unittest import mock

from modules import ghsa_client as ghsa
from modules import nvd_client
from modules import search_service
from samples import NVD_VULN, SAMPLE, SORT_A, SORT_B, SORT_C, TempCacheDB, make_sortable_raw

# EPSS enrichment runs inside run_search, and nothing was mocking it, so the
# "offline" suite made 12 live DNS lookups to api.first.org per run. It passed
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


class TestParseStrList(unittest.TestCase):
    def test_comma_string(self):
        self.assertEqual(search_service.parse_str_list("a, b,,c"), ["a", "b", "c"])

    def test_list_entries_must_be_strings(self):
        with self.assertRaises(search_service.SearchError):
            search_service.parse_str_list(["x", 1])

    def test_none_and_empty(self):
        self.assertEqual(search_service.parse_str_list(None), [])
        self.assertEqual(search_service.parse_str_list(""), [])


class TestParseSearchQuery(unittest.TestCase):
    def test_empty_categories_raises(self):
        with self.assertRaises(search_service.SearchError) as cm:
            search_service.parse_search_query({})
        self.assertEqual(cm.exception.status, 400)
        message = str(cm.exception).lower()
        self.assertIn("bug class", message)
        self.assertIn("cwe", message)
        self.assertEqual(cm.exception.public_message, str(cm.exception))
        self.assertNotIn("Traceback", cm.exception.public_message)

    def test_defaults(self):
        q = search_service.parse_search_query({"categories": ["bac"]})
        self.assertEqual(q.categories, ["bac"])
        self.assertEqual(q.sort, "published")
        self.assertEqual(q.direction, "desc")
        self.assertEqual(q.max_results, 100)
        self.assertEqual(q.sources, ["ghsa"])
        self.assertEqual(q.ecosystem, "any")
        self.assertEqual(q.severity, "any")
        self.assertEqual(q.adv_type, "reviewed")
        self.assertTrue(q.include_extended)
        self.assertIn("639", q.cwes)  # resolved from bac

    def test_bogus_sort_and_direction_fall_back(self):
        q = search_service.parse_search_query({"categories": ["bac"], "sort": "bogus", "direction": "sideways"})
        self.assertEqual(q.sort, "published")
        self.assertEqual(q.direction, "desc")

    def test_max_results_clamped(self):
        cases = [(0, 1), (9999, 500), ("abc", 100), ("250", 250), (-5, 1)]
        for raw, want in cases:
            with self.subTest(max_results=raw):
                q = search_service.parse_search_query({"categories": ["bac"], "max_results": raw})
                self.assertEqual(q.max_results, want)

    def test_single_cwe_pseudo_category_resolves_alone(self):
        """A CWE picked from the catalog is a valid query with no bug class."""
        q = search_service.parse_search_query({"categories": ["cwe:1321"]})
        self.assertEqual(q.cwes, ["1321"])
        self.assertEqual(q.categories, ["cwe:1321"])

    def test_cwe_pseudo_categories_merge_without_duplicates(self):
        q = search_service.parse_search_query(
            {"categories": ["xss", "cwe:79", "cwe:639"]})
        self.assertEqual(q.cwes.count("79"), 1)   # already in xss core, not duped
        self.assertIn("639", q.cwes)              # genuinely new -> appended
        self.assertNotIn("89", q.cwes)            # sqli not requested

    def test_cwe_pseudo_categories_keep_selection_order(self):
        q = search_service.parse_search_query(
            {"categories": ["sqli", "cwe:79", "cwe:639"], "include_extended": False}
        )
        # The class's own core set, then each pseudo-category in the order it
        # was selected. Taken from CATEGORIES rather than copied, so a
        # taxonomy correction does not fail a test about ordering.
        from modules.cwe_categories import CATEGORIES
        self.assertEqual(q.cwes, [*CATEGORIES["sqli"]["core"], "79", "639"])

    def test_empty_selection_is_rejected(self):
        with self.assertRaises(search_service.SearchError) as cm:
            search_service.parse_search_query({"categories": []})
        self.assertEqual(cm.exception.status, 400)

    def test_unknown_category_is_400(self):
        for body in (
            {"categories": ["nope"]},
            {"categories": ["nope"], "sources": ["ghsa"]},
            {"categories": ["bac", "nope"]},
        ):
            with self.subTest(body=body), self.assertRaises(search_service.SearchError) as cm:
                search_service.parse_search_query(body)
            self.assertEqual(cm.exception.status, 400)

    def test_malformed_cwe_keys_are_rejected(self):
        malformed = (
            "cwe:",                 # no id
            "cwe:0",                # CWE ids are positive
            "cwe:012",              # no leading zeros; '12' is canonical
            "cwe:12345678",         # beyond MAX_CWE_ID_DIGITS
            "cwe:79a",              # not numeric
            "cwe-79",               # wrong separator
            "CWE:79 ; DROP TABLE",  # junk
        )
        for category in malformed:
            with self.subTest(category=category), \
                    self.assertRaises(search_service.SearchError) as cm:
                search_service.parse_search_query({"categories": [category]})
            self.assertEqual(cm.exception.status, 400)

    def test_cwe_keys_are_case_insensitive(self):
        q = search_service.parse_search_query({"categories": ["CWE:639"]})
        self.assertEqual(q.cwes, ["639"])

    def test_equivalent_cwe_key_spellings_collapse_to_one_category(self):
        """Two spellings would otherwise mean two AI passes and two cache keys."""
        q = search_service.parse_search_query(
            {"categories": ["CWE:639", "cwe:639", "bac"]})
        self.assertEqual(q.categories, ["cwe:639", "bac"])
        self.assertEqual(q.cwes.count("639"), 1)

    def test_string_list_fields_are_bounded_and_strictly_typed(self):
        invalid_bodies = (
            {"categories": [{"name": "bac"}]},
            {"categories": ["b" * 65]},
            {"categories": ["bac"], "sources": ["ghsa", "nvd", "osv", "osv-native", "ghsa"]},
            {"categories": ["bac"], "sources": [{"name": "ghsa"}]},
        )
        for body in invalid_bodies:
            with self.subTest(body=body), self.assertRaises(search_service.SearchError):
                search_service.parse_search_query(body)

    def test_sources_are_deduplicated(self):
        q = search_service.parse_search_query({"categories": ["bac"], "sources": ["ghsa", "ghsa"]})
        self.assertEqual(q.sources, ["ghsa"])

    def test_string_false_is_not_truthy(self):
        q = search_service.parse_search_query({"categories": ["bac"], "include_extended": "false"})
        self.assertFalse(q.include_extended)

    def test_invalid_source_and_date_rejected(self):
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "sources": ["made-up"]})
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "published": "last Tuesday"})
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "published": "2026-02-30"})
        with self.assertRaises(search_service.SearchError):
            search_service.parse_search_query({"categories": ["bac"], "ecosystem": {"unexpected": True}})


class TestMergeAdvisories(unittest.TestCase):
    def test_same_cve_prefers_ghsa_base_even_if_later(self):
        osv_rec = {"advisory_id": "GHSA-osvv", "cve_id": "CVE-2026-1",
                   "ghsa_id": "GHSA-osvv", "source": "osv", "summary": "from osv"}
        ghsa_rec = {"advisory_id": "GHSA-real", "cve_id": "CVE-2026-1",
                    "ghsa_id": "GHSA-real", "source": "ghsa", "summary": "from ghsa"}
        out = search_service.merge_advisories([osv_rec, ghsa_rec])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["summary"], "from ghsa")  # GHSA base won
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])  # union, sorted

    def test_ghsa_first_keeps_ghsa_base(self):
        ghsa_rec = {"advisory_id": "CVE-2026-2", "cve_id": "CVE-2026-2",
                    "source": "ghsa", "summary": "from ghsa"}
        osv_rec = {"advisory_id": "CVE-2026-2", "cve_id": "CVE-2026-2",
                   "source": "osv", "summary": "from osv"}
        out = search_service.merge_advisories([ghsa_rec, osv_rec])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["summary"], "from ghsa")
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])

    def test_keyless_record_kept_and_order_preserved(self):
        rec_x = {"advisory_id": "CVE-2026-3", "cve_id": "CVE-2026-3",
                 "source": "ghsa", "summary": "x"}
        keyless = {"summary": "no ids at all"}
        rec_y = {"advisory_id": "CVE-2026-4", "cve_id": "CVE-2026-4",
                 "source": "osv", "summary": "y"}
        dup_x = {"advisory_id": "CVE-2026-3", "cve_id": "CVE-2026-3",
                 "source": "osv", "summary": "x-osv"}
        out = search_service.merge_advisories([rec_x, keyless, rec_y, dup_x])
        self.assertEqual([r["summary"] for r in out], ["x", "no ids at all", "y"])
        self.assertEqual(out[0]["sources"], ["ghsa", "osv"])
        self.assertEqual(out[1]["sources"], ["?"])  # fallback source tag

    def test_merge_preserves_complementary_metadata(self):
        nvd = {
            "advisory_id": "CVE-2026-55", "ghsa_id": None,
            "cve_id": "CVE-2026-55", "source": "nvd",
            "severity": "critical", "cvss_score": 9.8, "cwes": ["89"],
            "references": ["https://nvd.example"], "packages": [], "ecosystems": [],
            "kev": True, "nvd_status": "Analyzed",
        }
        ghsa = {
            "advisory_id": "GHSA-bridge", "ghsa_id": "GHSA-bridge",
            "cve_id": "CVE-2026-55", "source": "ghsa",
            "severity": "high", "cvss_score": 8.1, "cwes": ["CWE-89"],
            "references": ["https://ghsa.example"], "packages": [], "ecosystems": [],
        }
        merged = search_service.merge_advisories([nvd, ghsa])[0]
        self.assertEqual(merged["source"], "ghsa")
        self.assertTrue(merged["kev"])
        self.assertEqual(merged["nvd_status"], "Analyzed")
        self.assertEqual(merged["severity"], "critical")
        self.assertEqual(merged["cvss_by_source"], {"nvd": 9.8, "ghsa": 8.1})
        self.assertEqual(set(merged["references"]), {"https://nvd.example", "https://ghsa.example"})
        self.assertEqual(set(merged["source_records"]), {"ghsa", "nvd"})

    def test_alias_graph_bridge_merges_all_records(self):
        records = [
            {"advisory_id": "GHSA-one", "ghsa_id": "GHSA-one",
             "aliases": ["CVE-2026-77"], "source": "ghsa"},
            {"advisory_id": "GO-2026-1", "osv_id": "GO-2026-1",
             "ghsa_id": "GO-2026-1",
             "aliases": ["CVE-2026-77", "RUSTSEC-2026-1"], "source": "osv"},
            {"advisory_id": "RUSTSEC-2026-1", "osv_id": "RUSTSEC-2026-1",
             "ghsa_id": "RUSTSEC-2026-1", "source": "osv"},
        ]
        merged = search_service.merge_advisories(records)
        self.assertEqual(len(merged), 1)
        self.assertIn("RUSTSEC-2026-1", merged[0]["aliases"])

    def test_cve_bridges_a_source_with_no_advisory_id(self):
        """The bridge that matters: an NVD record's only identifier IS the CVE."""
        ghsa_rec = {"advisory_id": "GHSA-real", "ghsa_id": "GHSA-real",
                    "cve_id": "CVE-2026-9", "source": "ghsa"}
        nvd_rec = {"advisory_id": "CVE-2026-9", "ghsa_id": None,
                   "cve_id": "CVE-2026-9", "source": "nvd"}
        merged = search_service.merge_advisories([ghsa_rec, nvd_rec])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["sources"], ["ghsa", "nvd"])

    def test_shared_cve_merges_github_duplicate_advisories(self):
        """A "Duplicate Advisory" stub shares only the CVE with the real one.

        All 8 CVE-only bridges in the cached npm + Go + Maven exports are this
        shape, which is why merge_advisories keeps the alias graph transitive.
        """
        real = {"advisory_id": "GHSA-5vjc-qx43-r747",
                "ghsa_id": "GHSA-5vjc-qx43-r747", "cve_id": "CVE-2022-27200",
                "aliases": ["CVE-2022-27200"], "source": "ghsa",
                "summary": "Stored Cross-site Scripting in folder-auth plugin"}
        duplicate = {"advisory_id": "GHSA-chr6-386q-4m3v",
                     "ghsa_id": "GHSA-chr6-386q-4m3v", "cve_id": "CVE-2022-27200",
                     "aliases": ["CVE-2022-27200"], "source": "ghsa",
                     "summary": "Duplicate Advisory: Stored Cross-site Scripting"}
        merged = search_service.merge_advisories([real, duplicate])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["advisory_id"], "GHSA-5vjc-qx43-r747")

    def test_same_source_records_promote_the_worst_severity(self):
        """severity_by_source used to be keyed by source name, so when one
        source contributed several records to a group only the last survived
        and max() ran over a single value. A medium+low GHSA pair merged to
        "low", and reversing the page order merged it to "medium" -- the same
        advisory triaged two different ways depending on fetch order.
        """
        worse = {"advisory_id": "GHSA-aaaa", "cve_id": "CVE-2026-1",
                 "aliases": ["CVE-2026-1"], "source": "ghsa",
                 "severity": "medium", "cvss_score": 5.3}
        milder = {"advisory_id": "GHSA-bbbb", "cve_id": "CVE-2026-1",
                  "aliases": ["CVE-2026-1"], "source": "ghsa",
                  "severity": "low", "cvss_score": 3.3}
        for order in ([worse, milder], [milder, worse]):
            merged = search_service.merge_advisories(order)
            self.assertEqual(len(merged), 1)
            row = merged[0]
            self.assertEqual(row["severity"], "medium")
            self.assertEqual(row["cvss_score"], 5.3)
            self.assertEqual(row["severity_by_source"], {"ghsa": "medium"})
            self.assertEqual(row["cvss_by_source"], {"ghsa": 5.3})
            # Both records stay visible under source_records either way.
            self.assertEqual(len(row["source_records"]["ghsa"]), 2)

    def test_a_non_numeric_cvss_score_does_not_crash_the_merge(self):
        """max() over mixed str/float raises TypeError, which is not a
        SearchError, so it escaped run_search and 500'd the whole request."""
        good = {"advisory_id": "GHSA-aaaa", "cve_id": "CVE-2026-2",
                "aliases": ["CVE-2026-2"], "source": "ghsa",
                "severity": "high", "cvss_score": 7.5}
        bad = {"advisory_id": "OSV-1", "cve_id": "CVE-2026-2",
               "aliases": ["CVE-2026-2"], "source": "osv",
               "severity": "high", "cvss_score": "N/A"}
        row = search_service.merge_advisories([good, bad])[0]
        self.assertEqual(row["cvss_score"], 7.5)
        self.assertNotIn("osv", row["cvss_by_source"])

    def test_cvss_vector_survives_the_merge(self):
        """Only OSV produces it, and GHSA always wins as the base record.

        A v4-only advisory has the vector *instead of* a score, so dropping it
        left cvss_score null with nothing to look up.
        """
        osv = {"advisory_id": "GHSA-x", "ghsa_id": "GHSA-x", "cve_id": "CVE-1",
               "source": "osv", "cvss_score": None,
               "cvss_vector": "CVSS:4.0/AV:N/AC:L/VC:H/VI:H/VA:H"}
        ghsa = {"advisory_id": "GHSA-x", "ghsa_id": "GHSA-x", "cve_id": "CVE-1",
                "source": "ghsa", "cvss_score": 7.5}
        merged = search_service.merge_advisories([osv, ghsa])[0]
        self.assertEqual(merged["source"], "ghsa")   # base is still GHSA
        self.assertEqual(merged["cvss_vector"], "CVSS:4.0/AV:N/AC:L/VC:H/VI:H/VA:H")

    def test_cvss_vector_is_always_present_even_when_no_source_has_one(self):
        """The key exists on every merged record, so a client can rely on it."""
        ghsa = {"advisory_id": "GHSA-y", "ghsa_id": "GHSA-y", "source": "ghsa",
                "cvss_score": 7.5}
        merged = search_service.merge_advisories([ghsa])[0]
        self.assertIn("cvss_vector", merged)
        self.assertIsNone(merged["cvss_vector"])

    def test_aliases_keep_the_publisher_casing(self):
        """GHSA ids are lowercase base32; an upper-cased alias no longer resolves."""
        record = {"advisory_id": "GHSA-h3m5-97jq-qjrf",
                  "ghsa_id": "GHSA-h3m5-97jq-qjrf",
                  "cve_id": "CVE-2021-44228", "source": "ghsa"}
        merged = search_service.merge_advisories([record])[0]
        self.assertIn("GHSA-h3m5-97jq-qjrf", merged["aliases"])
        self.assertNotIn("GHSA-H3M5-97JQ-QJRF", merged["aliases"])

    def test_published_at_keeps_the_base_advisory_date(self):
        """min() across sources backdated a 2026 advisory to its 2021 CVE."""
        ghsa_rec = {"advisory_id": "GHSA-real", "ghsa_id": "GHSA-real",
                    "cve_id": "CVE-2026-9", "source": "ghsa",
                    "published_at": "2026-06-25T00:00:00Z"}
        nvd_rec = {"advisory_id": "CVE-2026-9", "ghsa_id": None,
                   "cve_id": "CVE-2026-9", "source": "nvd",
                   "published_at": "2021-12-10T00:00:00Z"}
        merged = search_service.merge_advisories([ghsa_rec, nvd_rec])[0]
        self.assertEqual(merged["published_at"], "2026-06-25T00:00:00Z")

    def test_group_matches_filters_uses_each_source_record(self):
        """severity is widened to max(); filtering that value drops real matches."""
        ghsa_rec = {"advisory_id": "GHSA-real", "ghsa_id": "GHSA-real",
                    "cve_id": "CVE-2026-9", "source": "ghsa", "severity": "high"}
        nvd_rec = {"advisory_id": "CVE-2026-9", "ghsa_id": None,
                   "cve_id": "CVE-2026-9", "source": "nvd", "severity": "critical"}
        merged = search_service.merge_advisories([ghsa_rec, nvd_rec])[0]
        self.assertEqual(merged["severity"], "critical")  # still the worst case
        self.assertTrue(search_service._group_matches_filters(merged, severity="high"))
        self.assertTrue(search_service._group_matches_filters(merged, severity="critical"))
        self.assertFalse(search_service._group_matches_filters(merged, severity="low"))


class TestRunSearch(TempCacheDB, unittest.TestCase):
    def _run(self, body):
        body.setdefault("categories", ["bac"])
        q = search_service.parse_search_query(body)
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=make_sortable_raw()):
            return search_service.run_search(q)

    def test_sort_published_default(self):
        out = self._run({})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_A, SORT_C, SORT_B])
        self.assertEqual(out.per_source, {"ghsa": 3})

    def test_sort_updated_fixed(self):
        # Regression: the old code always sorted by published_at.
        out = self._run({"sort": "updated"})
        # updated desc is A, B, C in the corrected fixture; it used to
        # be the exact reverse of published, which made two orderings
        # identical and hid a direction-flipped field mix-up.
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_A, SORT_B, SORT_C])

    def test_sort_updated_ascending(self):
        out = self._run({"sort": "updated", "direction": "asc"})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_C, SORT_B, SORT_A])

    def test_sort_cve_id(self):
        out = self._run({"sort": "cve_id"})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_B, SORT_A, SORT_C])
        out = self._run({"sort": "cve_id", "direction": "asc"})
        self.assertEqual([r["ghsa_id"] for r in out.results],
                         [SORT_C, SORT_A, SORT_B])

    def test_sort_epss_handles_missing_scores(self):
        """Records without EPSS used to crash sort (float vs '')."""
        body = {"categories": ["bac"], "sort": "epss_percentage"}
        q = search_service.parse_search_query(body)
        scores = {
            "CVE-2026-0002": {"epss": 0.9, "percentile": 0.99},
            "CVE-2026-0001": {"epss": 0.1, "percentile": 0.4},
        }
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=make_sortable_raw()), \
             mock.patch("modules.epss_client.fetch_epss", return_value=scores):
            out = search_service.run_search(q)
        ids = [r["ghsa_id"] for r in out.results]
        self.assertEqual(ids, [SORT_A, SORT_C, SORT_B])

    def test_common_filters_are_enforced_after_normalization(self):
        q = search_service.parse_search_query({"categories": ["bac"], "published": ">=2099-01-01"})
        with mock.patch(
            "modules.ghsa_client.fetch_advisories", return_value=make_sortable_raw()
        ):
            out = search_service.run_search(q)
        self.assertEqual(out.results, [])

    def test_ghsa_only_failure_is_502(self):
        q = search_service.parse_search_query({"categories": ["bac"]})  # sources == ["ghsa"]
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        side_effect=ghsa.GhCliError("nope")):
            with self.assertRaises(search_service.SearchError) as cm:
                search_service.run_search(q)
        self.assertEqual(cm.exception.status, 502)
        self.assertEqual(str(cm.exception), "GHSA fetch failed.")
        self.assertNotIn("nope", str(cm.exception))

    def test_ghsa_failure_with_other_sources_is_warning(self):
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["ghsa", "osv"], "ecosystem": "go"})
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        side_effect=ghsa.GhCliError("nope")), \
             mock.patch("modules.osv_client.fetch_osv", return_value=[]):
            out = search_service.run_search(q)
        self.assertTrue(any("GHSA fetch failed" in w for w in out.warnings))
        self.assertFalse(any("nope" in w for w in out.warnings))
        self.assertNotIn("ghsa", out.per_source)
        self.assertEqual(out.per_source.get("osv"), 0)
        self.assertEqual(out.results, [])


class TestRunSearchNvd(TempCacheDB, unittest.TestCase):
    """NVD source integration in run_search."""

    def test_nvd_source_included(self):
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["nvd"]})
        with mock.patch("modules.nvd_client.fetch_nvd",
                        return_value=[nvd_normalized]):
            out = search_service.run_search(q)
        self.assertEqual(out.per_source, {"nvd": 1})
        self.assertEqual(out.results[0]["cve_id"], "CVE-2021-44228")
        self.assertEqual(out.results[0]["source"], "nvd")

    def test_nvd_only_failure_is_502(self):
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["nvd"]})
        with mock.patch("modules.nvd_client.fetch_nvd",
                        side_effect=nvd_client.NvdError("rate limited")):
            with self.assertRaises(search_service.SearchError) as cm:
                search_service.run_search(q)
        self.assertEqual(cm.exception.status, 502)

    def test_nvd_failure_with_ghsa_is_warning(self):
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["ghsa", "nvd"]})
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=make_sortable_raw()), \
             mock.patch("modules.nvd_client.fetch_nvd",
                        side_effect=nvd_client.NvdError("rate limited")):
            out = search_service.run_search(q)
        self.assertTrue(any("NVD fetch failed" in w for w in out.warnings))
        self.assertEqual(out.per_source.get("ghsa"), 3)
        self.assertNotIn("nvd", out.per_source)

    def test_nvd_ghsa_dedupe_by_cve(self):
        """Same CVE from GHSA and NVD should merge into one record."""
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        ghsa_raw_rec = dict(SAMPLE, cve_id="CVE-2021-44228")
        q = search_service.parse_search_query(
            {"categories": ["bac"], "sources": ["ghsa", "nvd"]})
        with mock.patch("modules.ghsa_client.fetch_advisories",
                        return_value=[ghsa_raw_rec]), \
             mock.patch("modules.nvd_client.fetch_nvd",
                        return_value=[nvd_normalized]):
            out = search_service.run_search(q)
        cves = [r["cve_id"] for r in out.results]
        self.assertEqual(cves.count("CVE-2021-44228"), 1)
        self.assertIn("ghsa", out.results[0]["sources"])
        self.assertIn("nvd", out.results[0]["sources"])

    def test_adding_nvd_does_not_drop_a_filtered_ghsa_match(self):
        """Adding a source must never subtract results.

        GHSA calls CVE-2021-44228 `high` and published it 2026-06-25; NVD calls
        it `critical` and published 2021-12-10.  Merging widens severity to the
        max and used to widen published_at to the min, so both filters dropped
        the record the moment NVD was switched on.
        """
        nvd_normalized = nvd_client.normalize(NVD_VULN)
        ghsa_raw_rec = dict(SAMPLE, cve_id="CVE-2021-44228")
        for filters in ({"severity": "high"}, {"published": ">=2026-01-01"}):
            with self.subTest(**filters):
                ghsa_only = search_service.parse_search_query(
                    {"categories": ["bac"], "sources": ["ghsa"], **filters})
                both = search_service.parse_search_query(
                    {"categories": ["bac"], "sources": ["ghsa", "nvd"], **filters})
                with mock.patch("modules.ghsa_client.fetch_advisories",
                                return_value=[ghsa_raw_rec]), \
                     mock.patch("modules.nvd_client.fetch_nvd",
                                return_value=[nvd_normalized]):
                    alone = search_service.run_search(ghsa_only)
                    merged = search_service.run_search(both)
                self.assertEqual(len(alone.results), 1)
                self.assertEqual(len(merged.results), 1)
                self.assertEqual(merged.results[0]["sources"], ["ghsa", "nvd"])



class TestTheMergeKeepsWhatTheSourcesActuallyHave(unittest.TestCase):
    """Fields outside the merge whitelist came from the base record even when
    the base's copy was empty, so text that one source had and the base did
    not was unreachable outside source_records."""

    def test_an_empty_base_does_not_erase_another_sources_text(self):
        ghsa = {"source": "ghsa", "advisory_id": "GHSA-x", "cve_id": "CVE-1",
                "aliases": ["CVE-1"], "summary": "", "description": "",
                "html_url": "", "severity": "high"}
        nvd = {"source": "nvd", "advisory_id": "CVE-1", "cve_id": "CVE-1",
               "aliases": ["CVE-1"], "summary": "Real summary",
               "description": "The real description",
               "html_url": "https://nvd.example/CVE-1", "severity": "high"}
        merged = search_service.merge_advisories([ghsa, nvd])[0]
        self.assertEqual(merged["description"], "The real description")
        self.assertEqual(merged["summary"], "Real summary")
        self.assertEqual(merged["html_url"], "https://nvd.example/CVE-1")

    def test_a_non_empty_base_still_wins(self):
        ghsa = {"source": "ghsa", "advisory_id": "GHSA-x", "cve_id": "CVE-1",
                "aliases": ["CVE-1"], "summary": "GHSA summary",
                "description": "GHSA description", "severity": "high"}
        nvd = {"source": "nvd", "advisory_id": "CVE-1", "cve_id": "CVE-1",
               "aliases": ["CVE-1"], "summary": "NVD summary",
               "description": "NVD description", "severity": "high"}
        merged = search_service.merge_advisories([ghsa, nvd])[0]
        self.assertEqual(merged["summary"], "GHSA summary")

    def test_ghsa_id_holds_a_ghsa_id_or_nothing(self):
        """It was filled with a CVE id when no GHSA id existed, which put a
        CVE under a column named ghsa_id in the CSV and the API shape."""
        nvd_only = {"source": "nvd", "advisory_id": "CVE-9", "cve_id": "CVE-9",
                    "aliases": ["CVE-9"], "summary": "s", "description": "d",
                    "severity": "low"}
        merged = search_service.merge_advisories([nvd_only])[0]
        self.assertIsNone(merged["ghsa_id"])
        self.assertEqual(merged["advisory_id"], "CVE-9")

    def test_records_with_no_identifier_stay_distinct(self):
        """They all collapsed onto advisory_id == "", so two such rows shared
        one AI verdict and one overwrote the other."""
        rows = search_service.merge_advisories([
            {"source": "osv", "summary": "first", "description": "d"},
            {"source": "osv", "summary": "second", "description": "e"},
        ])
        ids = [r["advisory_id"] for r in rows]
        self.assertEqual(len(set(ids)), 2, ids)
        self.assertTrue(all(i.startswith("anon-") for i in ids), ids)

    def test_an_anonymous_id_is_stable_across_runs(self):
        """A cached verdict has to still match on the next search."""
        record = {"source": "osv", "summary": "first", "description": "d"}
        first = search_service.merge_advisories([dict(record)])[0]["advisory_id"]
        second = search_service.merge_advisories([dict(record)])[0]["advisory_id"]
        self.assertEqual(first, second)

    def test_every_valid_source_has_an_explicit_base_priority(self):
        """osv-native fell to the default and tied with a record whose source
        was missing or misspelt, leaving fetch order to break the tie."""
        self.assertEqual(set(search_service._SOURCE_PRIORITY),
                         set(search_service.VALID_SOURCES))

    def test_valid_sorts_is_derived_from_the_sort_field_map(self):
        self.assertEqual(set(search_service.VALID_SORTS),
                         set(search_service._SORT_FIELD))


class TestEverySourceFailingIsA502(TempCacheDB, unittest.TestCase):
    """GHSA and NVD answered 502 when they were the only source; OSV answered
    200 + a warning for the same failure. A script could rely on neither."""

    def _run(self, body, ghsa_fails=False, osv_fails=False, nvd_fails=False,
             ghsa_rows=None):
        def ghsa_fetch(params):
            if ghsa_fails:
                raise search_service.ghsa.GhCliError("gh exploded")
            return list(ghsa_rows or [])

        def osv_fetch(*a, **kw):
            if osv_fails:
                raise search_service.osv_client.OsvError("osv exploded")
            return []

        def nvd_fetch(params, report=None):
            if nvd_fails:
                raise search_service.nvd_client.NvdError("nvd exploded")
            return []

        with mock.patch.object(search_service.ghsa, "fetch_advisories", ghsa_fetch), \
             mock.patch.object(search_service.ghsa, "normalize", side_effect=lambda a: a), \
             mock.patch.object(search_service.osv_client, "fetch_osv", osv_fetch), \
             mock.patch.object(search_service.osv_client, "supported_ecosystem",
                               return_value=True), \
             mock.patch.object(search_service.nvd_client, "fetch_nvd", nvd_fetch), \
             mock.patch.object(search_service.epss_client, "fetch_epss", return_value={}):
            return search_service.run_search(search_service.parse_search_query(body))

    def test_osv_alone_failing_is_now_a_502_like_the_others(self):
        with self.assertRaises(search_service.SearchError) as caught:
            self._run({"categories": ["bac"], "sources": ["osv"],
                       "ecosystem": "maven"}, osv_fails=True)
        self.assertEqual(caught.exception.status, 502)

    def test_all_of_several_sources_failing_is_a_502(self):
        with self.assertRaises(search_service.SearchError) as caught:
            self._run({"categories": ["bac"], "sources": ["ghsa", "nvd"]},
                      ghsa_fails=True, nvd_fails=True)
        self.assertEqual(caught.exception.status, 502)

    def test_a_partial_failure_is_still_a_200_with_the_names(self):
        rows = [{"source": "ghsa", "advisory_id": "GHSA-a", "cve_id": "CVE-1",
                 "aliases": ["CVE-1"], "severity": "high", "summary": "s",
                 "description": "d", "cwes": ["639"], "packages": [],
                 "published_at": "2026-01-01T00:00:00Z", "type": "reviewed"}]
        out = self._run({"categories": ["bac"], "sources": ["ghsa", "nvd"]},
                        nvd_fails=True, ghsa_rows=rows)
        self.assertEqual(len(out.results), 1)
        self.assertEqual(out.stats["failed_sources"], ["nvd"])

    def test_a_clean_run_reports_no_failed_sources(self):
        rows = [{"source": "ghsa", "advisory_id": "GHSA-a", "cve_id": "CVE-1",
                 "aliases": ["CVE-1"], "severity": "high", "summary": "s",
                 "description": "d", "cwes": ["639"], "packages": [],
                 "published_at": "2026-01-01T00:00:00Z", "type": "reviewed"}]
        out = self._run({"categories": ["bac"], "sources": ["ghsa"]},
                        ghsa_rows=rows)
        self.assertEqual(out.stats["failed_sources"], [])


class TestOneBadGhsaRecordDoesNotSinkTheSearch(TempCacheDB, unittest.TestCase):
    """ghsa.normalize dereferences identifiers[].value, cwes[].cwe_id and
    severity.lower(), none of which the API guarantees. Normalizing a page
    with a list comprehension made any one of them fatal: the resulting
    AttributeError is not a GhCliError, so it bypassed the per-source
    degradation and 500'd the whole search, discarding what the other
    sources had already returned."""

    GOOD = {"ghsa_id": "GHSA-good", "identifiers": [{"type": "CVE", "value": "CVE-2026-1"}],
            "severity": "HIGH", "cwes": [{"cwe_id": "CWE-639"}],
            "summary": "s", "description": "d", "vulnerabilities": [],
            "published_at": "2026-01-01T00:00:00Z", "type": "reviewed"}

    def _run(self, raw):
        with mock.patch.object(search_service.ghsa, "fetch_advisories",
                               return_value=raw), \
             mock.patch.object(search_service.cache, "upsert_advisories"), \
             mock.patch.object(search_service.epss_client, "fetch_epss",
                               return_value={}):
            return search_service.run_search(search_service.parse_search_query(
                {"categories": ["bac"], "sources": ["ghsa"]}))

    def test_a_null_identifier_does_not_kill_the_page(self):
        out = self._run([dict(self.GOOD), {**self.GOOD, "ghsa_id": "GHSA-bad",
                                           "identifiers": [None]}])
        self.assertEqual(len(out.results), 1)
        self.assertTrue(any("skipped 1" in w for w in out.warnings), out.warnings)

    def test_a_string_where_a_cwe_object_belongs_does_not_kill_the_page(self):
        out = self._run([dict(self.GOOD), {**self.GOOD, "ghsa_id": "GHSA-bad",
                                           "cwes": ["CWE-79"]}])
        self.assertEqual(len(out.results), 1)

    def test_a_numeric_severity_does_not_kill_the_page(self):
        out = self._run([dict(self.GOOD), {**self.GOOD, "ghsa_id": "GHSA-bad",
                                           "severity": 7}])
        self.assertEqual(len(out.results), 1)

    def test_the_user_is_told_how_many_were_dropped(self):
        bad = [{**self.GOOD, "ghsa_id": f"GHSA-bad{i}", "identifiers": [None]}
               for i in range(3)]
        out = self._run([dict(self.GOOD), *bad])
        self.assertEqual(len(out.results), 1)
        self.assertTrue(any("skipped 3" in w for w in out.warnings), out.warnings)

    def test_a_clean_page_warns_about_nothing(self):
        out = self._run([dict(self.GOOD)])
        self.assertEqual(len(out.results), 1)
        self.assertEqual([w for w in out.warnings if "skipped" in w], [])


class TestSeverityVocabulary(unittest.TestCase):
    """An unrecognised severity word ranked 0 -- below "low".

    So merging a MODERATE advisory (GraphQL's vocabulary, which reaches the
    merge unnormalised from some paths) with a genuinely low one reported
    "low". A silent downgrade is the worst direction for a triage tool to
    fail in, and static/app.js whitelists the word for the badge class, so an
    un-folded one also rendered as `unknown`.
    """

    def _merge(self, first, second):
        return search_service.merge_advisories([
            {"source": "ghsa", "advisory_id": "G", "cve_id": "C",
             "aliases": ["C"], "severity": first,
             "summary": "s", "description": "d"},
            {"source": "osv", "advisory_id": "O", "cve_id": "C",
             "aliases": ["C"], "severity": second,
             "summary": "s", "description": "d"},
        ])[0]

    def test_known_synonyms_are_folded(self):
        for raw, expected in (("MODERATE", "medium"), ("moderate", "medium"),
                              ("Important", "high"), ("severe", "high"),
                              ("informational", "low"), ("none", "unknown")):
            with self.subTest(raw=raw):
                self.assertEqual(search_service.canonical_severity(raw), expected)

    def test_a_synonym_is_not_downgraded_below_low(self):
        self.assertEqual(self._merge("MODERATE", "low")["severity"], "medium")
        self.assertEqual(self._merge("Important", "medium")["severity"], "high")

    def test_the_stored_word_is_canonical_not_raw(self):
        """The badge class is whitelisted from this value."""
        merged = self._merge("MODERATE", "low")
        self.assertEqual(merged["severity"], "medium")
        self.assertEqual(merged["severity_by_source"]["ghsa"], "medium")

    def test_an_unknown_word_is_unknown_not_a_silent_low(self):
        self.assertEqual(search_service.canonical_severity("wat"), "unknown")
        self.assertEqual(self._merge("wat", "low")["severity"], "low")

    def test_the_four_real_words_are_untouched(self):
        for word in ("unknown", "low", "medium", "high", "critical"):
            with self.subTest(word=word):
                self.assertEqual(search_service.canonical_severity(word), word)

    def test_severity_and_cvss_are_independently_worst_case(self):
        """A row can read HIGH / 5.8 when one source states a severity with
        no score and another a score with a lower severity. That is wanted
        for triage; severity_by_source and cvss_by_source carry the
        attribution."""
        merged = search_service.merge_advisories([
            {"source": "ghsa", "advisory_id": "G", "cve_id": "C",
             "aliases": ["C"], "severity": "high",
             "summary": "s", "description": "d"},
            {"source": "osv", "advisory_id": "O", "cve_id": "C",
             "aliases": ["C"], "severity": "medium", "cvss_score": 5.8,
             "summary": "s", "description": "d"},
        ])[0]
        self.assertEqual(merged["severity"], "high")
        self.assertEqual(merged["cvss_score"], 5.8)
        self.assertEqual(merged["severity_by_source"],
                         {"ghsa": "high", "osv": "medium"})
        self.assertEqual(merged["cvss_by_source"], {"osv": 5.8})


class TestEpssIsCaseInsensitive(TempCacheDB, unittest.TestCase):
    """_merge_group preserves the publisher's casing and FIRST keys its
    response case-sensitively, so a lower-cased CVE alias silently returned
    no score -- which the UI renders as "no data", not as an error."""

    def test_a_lowercased_cve_still_gets_its_score(self):
        records = [{"source": "ghsa", "advisory_id": "GHSA-a",
                    "cve_id": "cve-2026-1", "aliases": ["cve-2026-1"],
                    "severity": "high", "summary": "s", "description": "d",
                    "cwes": ["639"], "packages": [],
                    "published_at": "2026-01-01T00:00:00Z", "type": "reviewed"}]
        captured = {}

        def fake_epss(ids):
            captured["ids"] = list(ids)
            return {"CVE-2026-1": {"epss": 0.42, "percentile": 0.9}}

        with mock.patch.object(search_service.ghsa, "fetch_advisories",
                               return_value=records), \
             mock.patch.object(search_service.ghsa, "normalize",
                               side_effect=lambda a: a), \
             mock.patch.object(search_service.cache, "upsert_advisories"), \
             mock.patch.object(search_service.epss_client, "fetch_epss", fake_epss):
            out = search_service.run_search(search_service.parse_search_query(
                {"categories": ["bac"], "sources": ["ghsa"]}))
        self.assertEqual(out.results[0].get("epss_percentage"), 0.42)


class TestCveIdsSortAsNumbers(TempCacheDB, unittest.TestCase):
    """A CVE id is a year and a sequence, not a word.

    Sorted as text, "newest CVE first" silently meant "highest ASCII first":
    CVE-2026-9 outranked CVE-2026-100. The sequence is not zero-padded, so
    this is wrong for most real result sets, and static/app.js sorted the
    same way client-side.
    """

    def test_the_sequence_is_compared_numerically(self):
        ids = ["CVE-2026-10", "CVE-2026-9", "CVE-2026-100", "CVE-2026-2"]
        ordered = sorted(ids, key=search_service._cve_sort_key, reverse=True)
        self.assertEqual(
            ordered, ["CVE-2026-100", "CVE-2026-10", "CVE-2026-9", "CVE-2026-2"])

    def test_the_year_outranks_the_sequence(self):
        ids = ["CVE-2025-99999", "CVE-2026-1"]
        self.assertEqual(
            sorted(ids, key=search_service._cve_sort_key, reverse=True),
            ["CVE-2026-1", "CVE-2025-99999"])

    def test_rows_without_a_cve_sort_last_rather_than_interleaved(self):
        ids = ["CVE-2026-5", None, "not-a-cve", "CVE-2026-1"]
        ordered = sorted(ids, key=search_service._cve_sort_key, reverse=True)
        self.assertEqual(ordered[:2], ["CVE-2026-5", "CVE-2026-1"])

    def test_a_search_sorted_by_cve_id_uses_it(self):
        records = [
            {"source": "ghsa", "advisory_id": f"GHSA-{i}", "cve_id": cve,
             "aliases": [cve], "severity": "high", "summary": "s",
             "description": "d", "cwes": ["639"], "packages": [],
             "published_at": "2026-01-01T00:00:00Z", "type": "reviewed"}
            for i, cve in enumerate(["CVE-2026-9", "CVE-2026-100", "CVE-2026-10"])
        ]
        with mock.patch.object(search_service.ghsa, "fetch_advisories",
                               return_value=records), \
             mock.patch.object(search_service.ghsa, "normalize",
                               side_effect=lambda a: a), \
             mock.patch.object(search_service.epss_client, "fetch_epss",
                               return_value={}):
            out = search_service.run_search(search_service.parse_search_query(
                {"categories": ["bac"], "sources": ["ghsa"], "sort": "cve_id"}))
        self.assertEqual([r["cve_id"] for r in out.results],
                         ["CVE-2026-100", "CVE-2026-10", "CVE-2026-9"])


class TestSourceRecordsAreOptIn(TempCacheDB, unittest.TestCase):
    """source_records is ~35% of the payload and nothing reads it.

    Measured over 500 cached rows: 2.91 MB with, 1.89 MB without. It was
    also persisted into advisories.db, doubling the cache for data no reader
    ever asked for.
    """

    RECORDS = [
        {"source": "ghsa", "advisory_id": "GHSA-a", "cve_id": "CVE-2026-1",
         "aliases": ["CVE-2026-1"], "severity": "medium", "cvss_score": 5.3,
         "summary": "s", "description": "d", "cwes": ["639"], "packages": [],
         "published_at": "2026-01-01T00:00:00Z", "type": "reviewed"},
        {"source": "ghsa", "advisory_id": "GHSA-b", "cve_id": "CVE-2026-1",
         "aliases": ["CVE-2026-1"], "severity": "low", "cvss_score": 3.3,
         "summary": "s", "description": "d", "cwes": ["639"], "packages": [],
         "published_at": "2026-01-01T00:00:00Z", "type": "reviewed"},
    ]

    def _search(self, body):
        with mock.patch.object(search_service.ghsa, "fetch_advisories",
                               return_value=list(self.RECORDS)), \
             mock.patch.object(search_service.ghsa, "normalize",
                               side_effect=lambda a: a), \
             mock.patch.object(search_service.cache, "upsert_advisories"), \
             mock.patch.object(search_service.epss_client, "fetch_epss",
                               return_value={}):
            return search_service.run_search(search_service.parse_search_query(body))

    def test_it_is_absent_by_default(self):
        out = self._search({"categories": ["bac"], "sources": ["ghsa"]})
        self.assertNotIn("source_records", out.results[0])

    def test_it_is_returned_on_request(self):
        out = self._search({"categories": ["bac"], "sources": ["ghsa"],
                            "include_source_records": True})
        self.assertIn("source_records", out.results[0])
        self.assertEqual(len(out.results[0]["source_records"]["ghsa"]), 2)

    def test_dropping_it_does_not_change_the_merge(self):
        """It is built for the merge and the re-filter, both of which have
        already run by the time it is stripped."""
        without = self._search({"categories": ["bac"], "sources": ["ghsa"]})
        with_it = self._search({"categories": ["bac"], "sources": ["ghsa"],
                                "include_source_records": True})
        self.assertEqual(without.results[0]["severity"], "medium")
        self.assertEqual(without.results[0]["severity"],
                         with_it.results[0]["severity"])
        self.assertEqual(without.results[0]["cvss_score"],
                         with_it.results[0]["cvss_score"])

    def test_it_is_not_persisted_unless_requested(self):
        captured = {}
        with mock.patch.object(search_service.ghsa, "fetch_advisories",
                               return_value=list(self.RECORDS)), \
             mock.patch.object(search_service.ghsa, "normalize",
                               side_effect=lambda a: a), \
             mock.patch.object(search_service.cache, "upsert_advisories",
                               side_effect=lambda rows, **kw: captured.setdefault("rows", rows)), \
             mock.patch.object(search_service.epss_client, "fetch_epss",
                               return_value={}):
            search_service.run_search(search_service.parse_search_query(
                {"categories": ["bac"], "sources": ["ghsa"]}))
        self.assertNotIn("source_records", captured["rows"][0])


class TestTheUserIsToldWhatWasNotHonoured(TempCacheDB, unittest.TestCase):
    """Silent data loss is the failure mode this whole tool exists to avoid.

    A result set that is quietly incomplete, or quietly unfiltered, still
    looks like an answer -- which is worse than an error.
    """

    NVD_RECORD = {
        "source": "nvd", "advisory_id": "CVE-2021-44228",
        "cve_id": "CVE-2021-44228", "aliases": ["CVE-2021-44228"],
        "severity": "critical", "cvss_score": 10.0, "summary": "Log4Shell",
        "description": "d", "cwes": ["917"],
        "packages": [{"ecosystem": "nvd", "name": "log4j"}],
        "published_at": "2021-12-10T00:00:00Z", "type": "nvd",
    }

    def _run(self, body, nvd_records=None, nvd_report=None, epss=None):
        def fake_fetch_nvd(params, report=None):
            if report is not None and nvd_report:
                report.update(nvd_report)
            return list(nvd_records or [])

        with mock.patch.object(search_service.ghsa, "fetch_advisories", return_value=[]), \
             mock.patch.object(search_service.nvd_client, "fetch_nvd", fake_fetch_nvd), \
             mock.patch.object(search_service.epss_client, "fetch_epss",
                               return_value=epss if epss is not None else {}):
            return search_service.run_search(search_service.parse_search_query(body))

    def test_an_advisory_type_filter_nvd_ignores_is_declared(self):
        """A `type: malware` search returned Log4Shell with nothing saying the
        filter had been dropped. The UI offers it as a global scope control."""
        out = self._run({"categories": ["ssti"], "sources": ["ghsa", "nvd"],
                         "type": "malware"}, nvd_records=[self.NVD_RECORD])
        self.assertEqual([r["cve_id"] for r in out.results], ["CVE-2021-44228"])
        self.assertTrue(any("advisory-type" in w for w in out.warnings),
                        f"no warning about the ignored type filter: {out.warnings}")

    def test_an_ecosystem_filter_nvd_ignores_is_declared(self):
        out = self._run({"categories": ["ssti"], "sources": ["ghsa", "nvd"],
                         "ecosystem": "maven"}, nvd_records=[self.NVD_RECORD])
        self.assertTrue(any("ecosystem" in w for w in out.warnings), out.warnings)

    def test_the_default_type_does_not_warn(self):
        out = self._run({"categories": ["ssti"], "sources": ["ghsa", "nvd"]},
                        nvd_records=[self.NVD_RECORD])
        self.assertEqual([w for w in out.warnings if "advisory-type" in w], [])

    def test_a_partly_failed_nvd_fetch_says_the_results_are_incomplete(self):
        """17 of 18 CWEs could fail and the user saw a plausible "NVD: 12",
        reading it as "NVD has 12 of these"."""
        out = self._run({"categories": ["bac"], "sources": ["ghsa", "nvd"]},
                        nvd_records=[self.NVD_RECORD],
                        nvd_report={"failed_cwes": 17, "total_cwes": 18})
        self.assertTrue(any("17 of 18" in w and "incomplete" in w
                            for w in out.warnings), out.warnings)

    def test_a_fully_successful_nvd_fetch_does_not_warn(self):
        out = self._run({"categories": ["bac"], "sources": ["ghsa", "nvd"]},
                        nvd_records=[self.NVD_RECORD],
                        nvd_report={"failed_cwes": 0, "total_cwes": 18})
        self.assertEqual([w for w in out.warnings if "incomplete" in w], [])

    def test_sorting_by_epss_with_no_epss_data_says_so(self):
        """fetch_epss swallows everything and returns {}, and the sort key
        maps a missing score to 0.0 -- so merge order was presented as an
        exploit-probability ranking."""
        records = [dict(self.NVD_RECORD, advisory_id=f"CVE-2026-{i}",
                        cve_id=f"CVE-2026-{i}", aliases=[f"CVE-2026-{i}"])
                   for i in range(3)]
        out = self._run({"categories": ["bac"], "sources": ["nvd"],
                         "sort": "epss_percentage"}, nvd_records=records, epss={})
        self.assertEqual(len(out.results), 3)
        self.assertTrue(any("merge order" in w for w in out.warnings), out.warnings)

    def test_a_working_epss_sort_does_not_warn(self):
        records = [dict(self.NVD_RECORD, advisory_id=f"CVE-2026-{i}",
                        cve_id=f"CVE-2026-{i}", aliases=[f"CVE-2026-{i}"])
                   for i in range(2)]
        scores = {f"CVE-2026-{i}": {"epss": 0.1 * (i + 1), "percentile": 0.5}
                  for i in range(2)}
        out = self._run({"categories": ["bac"], "sources": ["nvd"],
                         "sort": "epss_percentage"},
                        nvd_records=records, epss=scores)
        self.assertEqual([w for w in out.warnings if "merge order" in w], [])


class TestAnAdvisoryCannotGetTwoPrimaryKeys(unittest.TestCase):
    """`min` returns the first minimum, so when a group held two records of
    one source the base was decided by upstream pagination order. GitHub's
    own "Duplicate Advisory" pairs share a CVE, so the same advisory merged
    to GHSA-AAAA under direction=desc and GHSA-BBBB under asc -- and
    cache.upsert_advisories then held two rows for it, making a classify
    call on the second a cache miss that re-spends tokens."""

    def _group(self):
        return [
            {"source": "ghsa", "advisory_id": "GHSA-bbbb", "cve_id": "CVE-2026-1",
             "published_at": "2026-02-01T00:00:00Z", "summary": "b"},
            {"source": "ghsa", "advisory_id": "GHSA-aaaa", "cve_id": "CVE-2026-1",
             "published_at": "2026-01-01T00:00:00Z", "summary": "a"},
        ]

    def test_the_base_is_the_same_whichever_order_the_api_paginated(self):
        forward = search_service._merge_group(self._group())
        backward = search_service._merge_group(list(reversed(self._group())))
        for field in ("advisory_id", "published_at", "summary"):
            with self.subTest(field=field):
                self.assertEqual(forward[field], backward[field],
                                 f"{field} depends on fetch order")

    def test_the_winner_is_decided_by_identifier_not_by_position(self):
        merged = search_service._merge_group(self._group())
        self.assertEqual(merged["advisory_id"], "GHSA-aaaa")


class TestTheVectorDescribesTheScoreBesideIt(unittest.TestCase):
    """cvss_score is the worst across sources and cvss_vector was first-wins,
    so a row could ship 9.8 next to a vector that recomputes to 5.5 -- and
    unlike severity there is no cvss_vector_by_source to audit against."""

    def test_the_vector_comes_from_the_source_that_supplied_the_score(self):
        merged = search_service._merge_group([
            {"source": "osv", "advisory_id": "A", "cvss_score": 5.5,
             "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            {"source": "nvd", "advisory_id": "A", "cvss_score": 9.8,
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ])
        self.assertEqual(merged["cvss_score"], 9.8)
        self.assertEqual(merged["cvss_vector"],
                         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_a_vector_with_no_matching_score_is_still_kept(self):
        """A v4-only advisory has a vector and no score; losing it leaves
        cvss_score null with nothing to look up."""
        merged = search_service._merge_group([
            {"source": "osv", "advisory_id": "A", "cvss_vector": "CVSS:4.0/AV:N"},
        ])
        self.assertEqual(merged["cvss_vector"], "CVSS:4.0/AV:N")


class TestRecordsWithoutACveStayOutOfTheWay(unittest.TestCase):
    """_cve_sort_key sorts them below every real CVE ascending, exactly as
    documented -- and `direction` defaults to desc, which reverses the whole
    key and put them at the top. An osv-native search, where most records
    have no CVE, opened on a page of nothing else."""

    def test_they_are_last_in_both_directions(self):
        rows = [{"cve_id": "CVE-2026-2"}, {"cve_id": None},
                {"cve_id": "CVE-2026-1"}, {"cve_id": "GO-2021-0001"}]
        out = search_service._cve_last(rows)
        self.assertEqual([r["cve_id"] for r in out[:2]],
                         ["CVE-2026-2", "CVE-2026-1"])
        self.assertEqual({r["cve_id"] for r in out[2:]}, {None, "GO-2021-0001"})

    def test_their_relative_order_is_preserved(self):
        rows = [{"cve_id": "GO-1"}, {"cve_id": "CVE-2026-1"}, {"cve_id": "GO-2"}]
        self.assertEqual([r["cve_id"] for r in search_service._cve_last(rows)],
                         ["CVE-2026-1", "GO-1", "GO-2"])


class TestAFailedCacheWriteDoesNotDiscardTheSearch(unittest.TestCase):
    """modules/cache.py's own docstring says the cache is optional. The
    write was unguarded, so a locked database threw away minutes of
    rate-limited fetching as a 500 at the very last step."""

    def test_the_results_survive_a_database_that_refuses_to_write(self):
        import sqlite3

        def boom(*a, **k):
            raise sqlite3.OperationalError("database is locked")

        with mock.patch.object(search_service.cache, "upsert_advisories", boom), \
             mock.patch.object(search_service.ghsa, "fetch_advisories",
                               return_value=[SAMPLE]), \
             mock.patch.object(search_service.cache, "get_classifications",
                               return_value={}):
            outcome = search_service.run_search(
                search_service.parse_search_query(
                    {"categories": ["bac"], "sources": ["ghsa"]}))
        self.assertTrue(outcome.results, "a cache failure emptied the search")


if __name__ == "__main__":
    unittest.main(verbosity=2)
