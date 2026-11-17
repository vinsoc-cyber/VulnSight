"""Tests for nvd_client: normalisation, date params, fetch logic.

All HTTP calls are mocked; nothing touches the network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import unittest
from datetime import datetime, timezone
from unittest import mock

from modules import nvd_client, records
from samples import NVD_VULN


class TestNormalize(unittest.TestCase):
    def test_basic_fields(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertIsNone(n["ghsa_id"])
        self.assertEqual(n["advisory_id"], "CVE-2021-44228")
        self.assertEqual(n["cve_id"], "CVE-2021-44228")
        self.assertEqual(n["source"], "nvd")
        self.assertEqual(n["severity"], "critical")
        self.assertEqual(n["cvss_score"], 10.0)
        self.assertTrue(n["kev"])
        self.assertEqual(n["nvd_status"], "Analyzed")

    def test_cwes_extracted(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertIn("917", n["cwes"])
        self.assertIn("20", n["cwes"])
        self.assertNotIn("noinfo", n["cwes"])

    def test_packages_from_cpe(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertTrue(len(n["packages"]) >= 1)
        pkg = n["packages"][0]
        self.assertEqual(pkg["name"], "apache:log4j")
        self.assertEqual(pkg["first_patched_version"], "2.15.0")

    def test_non_vulnerable_cpe_skipped(self):
        n = nvd_client.normalize(NVD_VULN)
        names = [p["name"] for p in n["packages"]]
        self.assertEqual(len(names), 1)

    def test_description_english_preferred(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertIn("Log4j2", n["description"])
        self.assertNotIn("espanol", n["description"])

    def test_references(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertEqual(len(n["references"]), 2)
        self.assertIn("logging.apache.org", n["references"][0])

    def test_html_url(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertEqual(n["html_url"], "https://nvd.nist.gov/vuln/detail/CVE-2021-44228")

    def test_summary_truncated(self):
        n = nvd_client.normalize(NVD_VULN)
        self.assertTrue(len(n["summary"]) <= 125)


class TestDateParams(unittest.TestCase):
    # These asserted against _build_date_params, a "compatibility helper" that
    # nothing but these tests called. Point them at the function that actually
    # ships so the coverage is real.
    def test_empty(self):
        self.assertEqual(nvd_client._build_date_windows(None), [])
        self.assertEqual(nvd_client._build_date_windows(""), [])

    def test_recent_date(self):
        windows = nvd_client._build_date_windows(">=2026-06-01")
        self.assertTrue(windows)
        self.assertIn("pubStartDate", windows[0])
        self.assertIn("pubEndDate", windows[0])

    def test_old_date_is_split_without_losing_requested_start(self):
        now = datetime(2026, 8, 17, tzinfo=timezone.utc)
        windows = nvd_client._build_date_windows(">=2020-01-01", now=now)
        self.assertGreater(len(windows), 1)
        self.assertTrue(windows[0]["pubEndDate"].startswith("2026-08-17"))
        self.assertTrue(windows[-1]["pubStartDate"].startswith("2020-01-01"))
        for window in windows:
            start = datetime.fromisoformat(window["pubStartDate"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(window["pubEndDate"].replace("Z", "+00:00"))
            self.assertLessEqual((end - start).total_seconds(), 120 * 86400)

    def test_year_one_is_clamped_without_datetime_underflow(self):
        now = datetime(2026, 8, 17, tzinfo=timezone.utc)
        windows = nvd_client._build_date_windows(">=0001-01-01", now=now)
        self.assertGreater(len(windows), 1)
        self.assertTrue(windows[-1]["pubStartDate"].startswith("1988-01-01"))


class TestFetchNvd(unittest.TestCase):
    def _mock_urlopen(self, responses):
        """Create a mock for urllib.request.urlopen that returns responses in order."""
        call_count = {"i": 0}

        def _urlopen(req, timeout=None):
            i = call_count["i"]
            call_count["i"] += 1
            data = json.dumps(responses[i % len(responses)]).encode()
            resp = mock.MagicMock()
            resp.read.return_value = data
            resp.__enter__ = mock.Mock(return_value=resp)
            resp.__exit__ = mock.Mock(return_value=False)
            return resp

        return _urlopen

    @mock.patch.dict(os.environ, {"NVD_API_KEY": "test-key"})
    @mock.patch("modules.nvd_client.time.sleep")
    def test_fetch_deduplicates(self, mock_sleep):
        response = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [NVD_VULN],
        }
        with mock.patch("modules.nvd_client.urllib.request.urlopen",
                        side_effect=self._mock_urlopen([response])):
            results = nvd_client.fetch_nvd(nvd_client.NvdSearchParams(
                cwes=["917", "20"], max_results=10))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2021-44228")

    @mock.patch.dict(os.environ, {"NVD_API_KEY": "test-key"})
    @mock.patch("modules.nvd_client.time.sleep")
    def test_empty_cwes_returns_empty(self, mock_sleep):
        results = nvd_client.fetch_nvd(nvd_client.NvdSearchParams(cwes=[]))
        self.assertEqual(results, [])

    @mock.patch("modules.nvd_client._fetch_cves_for_cwe")
    @mock.patch("modules.nvd_client.time.sleep")
    def test_all_cwe_failures_are_not_silently_empty(self, mock_sleep, mock_fetch):
        mock_fetch.side_effect = nvd_client.NvdError("rate limited")
        with self.assertRaises(nvd_client.NvdError):
            nvd_client.fetch_nvd(nvd_client.NvdSearchParams(cwes=["79", "89"]))

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_request_delay_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NVD_API_KEY", None)
            delay = nvd_client._request_delay()
        self.assertGreaterEqual(delay, 6.0)

    @mock.patch.dict(os.environ, {"NVD_API_KEY": "test-key"})
    def test_request_delay_with_key(self):
        delay = nvd_client._request_delay()
        self.assertLessEqual(delay, 1.0)


class TestNormalizeCVSSFallback(unittest.TestCase):
    def test_v2_fallback(self):
        vuln = {
            "cve": {
                "id": "CVE-2015-0001",
                "descriptions": [{"lang": "en", "value": "old vuln"}],
                "metrics": {
                    "cvssMetricV2": [{
                        "cvssData": {"baseScore": 7.5},
                        "baseSeverity": "HIGH",
                    }],
                },
                "weaknesses": [],
                "references": [],
            },
        }
        n = nvd_client.normalize(vuln)
        self.assertEqual(n["cvss_score"], 7.5)
        self.assertEqual(n["severity"], "high")

    def test_no_metrics(self):
        vuln = {
            "cve": {
                "id": "CVE-2000-0001",
                "descriptions": [{"lang": "en", "value": "ancient"}],
                "metrics": {},
                "weaknesses": [],
                "references": [],
            },
        }
        n = nvd_client.normalize(vuln)
        self.assertIsNone(n["cvss_score"])
        self.assertEqual(n["severity"], "unknown")

    def test_v40_preferred_over_v31(self):
        """When both v4.0 and v3.1 metrics exist, v4.0 is preferred."""
        vuln = {
            "cve": {
                "id": "CVE-2026-99999",
                "descriptions": [{"lang": "en", "value": "v4 vuln"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        },
                    }],
                    "cvssMetricV40": [{
                        "cvssData": {
                            "version": "4.0",
                            "baseScore": 8.7,
                            "baseSeverity": "HIGH",
                        },
                    }],
                },
                "weaknesses": [],
                "references": [],
            },
        }
        n = nvd_client.normalize(vuln)
        self.assertEqual(n["cvss_score"], 8.7)
        self.assertEqual(n["severity"], "high")

    def test_v40_only(self):
        """A CVE with only v4.0 metrics still extracts correctly."""
        vuln = {
            "cve": {
                "id": "CVE-2026-88888",
                "descriptions": [{"lang": "en", "value": "v4 only"}],
                "metrics": {
                    "cvssMetricV40": [{
                        "cvssData": {
                            "version": "4.0",
                            "baseScore": 9.3,
                            "baseSeverity": "CRITICAL",
                        },
                    }],
                },
                "weaknesses": [],
                "references": [],
            },
        }
        n = nvd_client.normalize(vuln)
        self.assertEqual(n["cvss_score"], 9.3)
        self.assertEqual(n["severity"], "critical")


class TestDateWindowsDoNotOverlap(unittest.TestCase):
    """Adjacent windows shared a day, and the duplicates ate the budget.

    _format_nvd_date truncates to the date and expands to
    00:00:00.000/23:59:59.999, so `cursor_start - 1ms` still landed inside
    the previous day. _fetch_cves_for_cwe counts rows against max_results
    before the later de-duplication, so a 100-result query spanning several
    windows silently returned fewer than 100 unique CVEs.
    """

    def _windows(self, published, now=None):
        now = now or datetime(2026, 8, 17, 14, 32, 11, tzinfo=timezone.utc)
        return nvd_client._build_date_windows(published, now=now)

    def test_adjacent_windows_do_not_share_a_day(self):
        windows = self._windows(">=2026-01-01")
        self.assertGreater(len(windows), 1, "need several windows to test this")
        for earlier, later in zip(windows[1:], windows[:-1]):
            with self.subTest(start=later["pubStartDate"]):
                self.assertLess(earlier["pubEndDate"][:10],
                                later["pubStartDate"][:10])

    def test_the_requested_start_is_still_covered(self):
        windows = self._windows(">=2026-01-01")
        self.assertEqual(windows[-1]["pubStartDate"][:10], "2026-01-01")

    def test_the_range_has_no_gap(self):
        """One day back must not skip a day either."""
        windows = self._windows(">=2024-01-01")
        for earlier, later in zip(windows[1:], windows[:-1]):
            end = datetime.strptime(earlier["pubEndDate"][:10], "%Y-%m-%d")
            start = datetime.strptime(later["pubStartDate"][:10], "%Y-%m-%d")
            self.assertEqual((start - end).days, 1,
                             f"gap between {earlier['pubEndDate']} and "
                             f"{later['pubStartDate']}")


class TestTheQuerySentToNvd(unittest.TestCase):
    """Driven through _fetch_cves_for_cwe, because the query is built inline."""

    def _capture(self, **params):
        seen = []

        def fake_page(query, timeout=60):
            seen.append(dict(query))
            return {"vulnerabilities": [], "totalResults": 0}

        with mock.patch.object(nvd_client, "_fetch_page", fake_page), \
             mock.patch.object(nvd_client.time, "sleep", lambda s: None):
            nvd_client._fetch_cves_for_cwe(
                "79", nvd_client.NvdSearchParams(cwes=["79"], **params))
        self.assertTrue(seen, "no request was built")
        return seen

    def test_severity_is_sent_in_the_form_nvd_wants(self):
        """The inverse-map lookup that used to sit here could never fire: an
        upper-cased severity is never one of _SEVERITY_MAP's lowercase
        values. It was dead code that made the passthrough look
        conditional."""
        self.assertEqual(self._capture(severity="critical")[0]["cvssV3Severity"],
                         "CRITICAL")

    def test_no_severity_means_no_severity_filter(self):
        for value in ("any", "", None):
            with self.subTest(severity=value):
                query = self._capture(severity=value)[0]
                self.assertNotIn("cvssV3Severity", query)

    def test_the_page_size_that_ships_is_the_computed_one(self):
        """base_q carried a resultsPerPage that every call site overrode, so
        the assignment never reached a request."""
        params = nvd_client.NvdSearchParams(cwes=["79"], max_results=10)
        expected = min(max(params.results_per_page, 10), 2000)
        query = self._capture(max_results=10)[0]
        self.assertEqual(query["resultsPerPage"], str(expected))

    def test_the_cwe_is_sent_normalised(self):
        self.assertEqual(self._capture()[0]["cweId"], "CWE-79")


class TestOneBadRecordDoesNotSinkTheBatch(unittest.TestCase):
    """normalize() dereferences fields the NVD schema does not guarantee.

    Normalizing a page with a list comprehension made any one of them fatal
    for the whole search: the AttributeError/ValueError is not an NvdError, so
    it bypassed the per-source degradation in run_search and surfaced as a 500
    that discarded the sources which had already succeeded.
    """

    def _vuln(self, cve_id, **overrides):
        cve = {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": f"description of {cve_id}"}],
            "published": "2026-01-01T00:00:00.000",
            "lastModified": "2026-01-01T00:00:00.000",
            "metrics": {}, "weaknesses": [], "configurations": [], "references": [],
        }
        cve.update(overrides)
        return {"cve": cve}

    def test_malformed_records_are_skipped_and_counted(self):
        batch = [
            self._vuln("CVE-2026-1"),
            # Shapes NVD does not forbid, each of which used to raise:
            self._vuln("CVE-2026-2", descriptions=[{"lang": "en", "value": None}]),
            self._vuln("CVE-2026-3", weaknesses=["CWE-79"]),
            self._vuln("CVE-2026-4", configurations=[
                {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": None}]}]}]),
            self._vuln("CVE-2026-5"),
        ]
        kept, skipped = records.normalize_all(
            batch, nvd_client.normalize, source="NVD")
        self.assertEqual(skipped, 3)
        self.assertEqual([r["cve_id"] for r in kept], ["CVE-2026-1", "CVE-2026-5"])

    def test_a_clean_batch_reports_no_skips(self):
        batch = [self._vuln("CVE-2026-1"), self._vuln("CVE-2026-2")]
        kept, skipped = records.normalize_all(
            batch, nvd_client.normalize, source="NVD")
        self.assertEqual(skipped, 0)
        self.assertEqual(len(kept), 2)

    def test_identify_never_raises_on_a_malformed_record(self):
        for item in (None, "a string", 42, [], {}, {"id": None}):
            self.assertEqual(records.identify(item, "id"), "")
        self.assertEqual(records.identify({"id": "CVE-1"}, "id"), "CVE-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
