"""Tests for epss_client: parsing, batching, empty input, error handling.

All HTTP calls are mocked; nothing touches the network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import io
import unittest
from typing import Any, cast
from unittest import mock

from modules import epss_client
from samples import http_error


def _mock_urlopen(response_body: dict):
    """Return a context-manager mock for ``urllib.request.urlopen``."""
    data = json.dumps(response_body).encode()
    resp = mock.MagicMock()
    resp.read.return_value = data
    resp.__enter__ = mock.Mock(return_value=resp)
    resp.__exit__ = mock.Mock(return_value=False)
    return resp


class TestTheResponseIsNormalisedOnTheWayBack(unittest.TestCase):
    """`_fetch_batch` upper-cases the ids it sends, and the comment above
    that line says "and on the way back" -- but the result was keyed by
    whatever FIRST echoed. search_service looks a score up with .upper(),
    so a lower-cased echo returned a dict the caller could not read and the
    advisory rendered with no EPSS: indistinguishable from one that has
    none, which is the exact failure the "way out" half exists to prevent.

    Every existing test mocked an upper-case echo, so the claim was
    trivially satisfied."""

    def _fetch(self, echoed):
        body = json.dumps({"data": [
            {"cve": echoed, "epss": "0.5", "percentile": "0.9"}]}).encode()
        with mock.patch.object(
                epss_client.urllib.request, "urlopen",
                return_value=mock.MagicMock(
                    __enter__=lambda s: io.BytesIO(body),
                    __exit__=lambda *a: False)):
            return epss_client.fetch_epss(["CVE-2024-1234"])

    def test_a_lower_cased_echo_is_still_found(self):
        out = self._fetch("cve-2024-1234")
        self.assertIn("CVE-2024-1234", out)
        self.assertAlmostEqual(out["CVE-2024-1234"]["epss"], 0.5)

    def test_a_mixed_case_echo_is_still_found(self):
        self.assertIn("CVE-2024-1234", self._fetch("Cve-2024-1234"))

    def test_an_upper_case_echo_still_works(self):
        self.assertIn("CVE-2024-1234", self._fetch("CVE-2024-1234"))


class TestParseResponse(unittest.TestCase):
    """Verify that a well-formed API response is correctly parsed."""

    RESPONSE = {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "total": 2,
        "offset": 0,
        "limit": 100,
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.03456", "percentile": "0.87654", "date": "2026-08-18"},
            {"cve": "CVE-2024-5678", "epss": "0.92100", "percentile": "0.99800", "date": "2026-08-18"},
        ],
    }

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_basic_parsing(self, mock_open):
        mock_open.return_value = _mock_urlopen(self.RESPONSE)
        result = epss_client.fetch_epss(["CVE-2024-1234", "CVE-2024-5678"])

        self.assertEqual(len(result), 2)
        self.assertAlmostEqual(result["CVE-2024-1234"]["epss"], 0.03456)
        self.assertAlmostEqual(result["CVE-2024-1234"]["percentile"], 0.87654)
        self.assertAlmostEqual(result["CVE-2024-5678"]["epss"], 0.92100)
        self.assertAlmostEqual(result["CVE-2024-5678"]["percentile"], 0.99800)

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_missing_fields_skipped(self, mock_open):
        """Entries without cve/epss/percentile are silently dropped."""
        response = {
            "data": [
                {"cve": "CVE-2024-1111", "epss": "0.5", "percentile": "0.9"},
                {"epss": "0.3", "percentile": "0.7"},  # no cve key
                {"cve": "CVE-2024-2222"},  # no epss/percentile
            ],
        }
        mock_open.return_value = _mock_urlopen(response)
        result = epss_client.fetch_epss(["CVE-2024-1111", "CVE-2024-2222"])

        self.assertEqual(len(result), 1)
        self.assertIn("CVE-2024-1111", result)

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_empty_data_array(self, mock_open):
        mock_open.return_value = _mock_urlopen({"data": []})
        result = epss_client.fetch_epss(["CVE-2024-0000"])
        self.assertEqual(result, {})

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_duplicates_are_deduplicated(self, mock_open):
        """Duplicate CVE IDs in input only produce one API query per CVE."""
        response = {
            "data": [
                {"cve": "CVE-2024-1234", "epss": "0.5", "percentile": "0.8"},
            ],
        }
        mock_open.return_value = _mock_urlopen(response)
        result = epss_client.fetch_epss(["CVE-2024-1234", "CVE-2024-1234", "CVE-2024-1234"])

        self.assertEqual(len(result), 1)
        # Only one HTTP call despite three duplicate input CVEs.
        mock_open.assert_called_once()


class TestBatching(unittest.TestCase):
    """Verify that >100 CVEs are split into multiple requests."""

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_splits_into_batches(self, mock_open):
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(250)]

        def side_effect(req, timeout=None):
            # Parse the requested CVEs from the URL to return matching data.
            url = req.full_url if hasattr(req, "full_url") else req.get_full_url()
            qs = url.split("?", 1)[1] if "?" in url else ""
            from urllib.parse import parse_qs
            params = parse_qs(qs)
            requested = params.get("cve", [""])[0].split(",")
            data = [
                {"cve": cve, "epss": "0.01", "percentile": "0.50"}
                for cve in requested if cve
            ]
            return _mock_urlopen({"data": data})

        mock_open.side_effect = side_effect
        result = epss_client.fetch_epss(cve_ids)

        # Should have made 3 calls: 100 + 100 + 50.
        self.assertEqual(mock_open.call_count, 3)
        self.assertEqual(len(result), 250)

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_exactly_100_is_one_batch(self, mock_open):
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(100)]

        def side_effect(req, timeout=None):
            data = [{"cve": c, "epss": "0.1", "percentile": "0.5"} for c in cve_ids]
            return _mock_urlopen({"data": data})

        mock_open.side_effect = side_effect
        result = epss_client.fetch_epss(cve_ids)

        self.assertEqual(mock_open.call_count, 1)
        self.assertEqual(len(result), 100)


class TestEmptyInput(unittest.TestCase):
    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_empty_list_returns_empty_dict(self, mock_open):
        result = epss_client.fetch_epss([])
        self.assertEqual(result, {})
        mock_open.assert_not_called()

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_none_itself_is_treated_as_empty(self, mock_open):
        """This was a verbatim copy of the test above -- same body, same
        empty list -- under a name promising None. fetch_epss(None) was
        never exercised."""
        self.assertEqual(epss_client.fetch_epss(cast(Any, None)), {})
        mock_open.assert_not_called()

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_only_blank_ids_makes_no_request(self, mock_open):
        self.assertEqual(epss_client.fetch_epss(["", "   "]), {})
        mock_open.assert_not_called()


class TestErrorHandling(unittest.TestCase):
    """Network and parse failures must return an empty dict, never crash."""

    def setUp(self):
        # The retry policy's backoff is real time: 4.9 of this module's 5.3
        # seconds were spent asleep. Nothing here is testing the clock.
        sleep = mock.patch.object(epss_client.http_retry.time, "sleep")
        sleep.start()
        self.addCleanup(sleep.stop)

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_a_transient_failure_is_retried_before_giving_up(self, mock_open):
        """`== {}` is produced both by "retried twice then gave up" and by
        "swallowed on the first failure" -- and swallowing on the first
        failure is the bug _fetch_batch was wrapped in with_retries to fix.
        Only the call count tells them apart."""
        mock_open.side_effect = OSError("Connection refused")
        self.assertEqual(epss_client.fetch_epss(["CVE-2024-1234"]), {})
        self.assertEqual(mock_open.call_count, 2,
                         "EPSS gave up without retrying")

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_a_recovered_failure_returns_the_score(self, mock_open):
        """The other half: a retry that succeeds must not be discarded."""
        body = json.dumps({"data": [
            {"cve": "CVE-2024-1234", "epss": "0.5", "percentile": "0.9"}]}).encode()
        mock_open.side_effect = [
            OSError("Connection refused"),
            mock.MagicMock(__enter__=lambda s: io.BytesIO(body),
                           __exit__=lambda *a: False),
        ]
        out = epss_client.fetch_epss(["CVE-2024-1234"])
        self.assertIn("CVE-2024-1234", out)
        self.assertEqual(mock_open.call_count, 2)

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_network_error_returns_empty(self, mock_open):
        mock_open.side_effect = OSError("Connection refused")
        result = epss_client.fetch_epss(["CVE-2024-1234"])
        self.assertEqual(result, {})

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_http_error_returns_empty(self, mock_open):
        mock_open.side_effect = http_error(
            500,
            url="https://api.first.org/data/v1/epss",
            reason="Internal Server Error",
            headers=None,
            fp=None,
        )
        result = epss_client.fetch_epss(["CVE-2024-9999"])
        self.assertEqual(result, {})

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_invalid_json_returns_empty(self, mock_open):
        resp = mock.MagicMock()
        resp.read.return_value = b"not json at all"
        resp.__enter__ = mock.Mock(return_value=resp)
        resp.__exit__ = mock.Mock(return_value=False)
        mock_open.return_value = resp
        result = epss_client.fetch_epss(["CVE-2024-1234"])
        self.assertEqual(result, {})

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_partial_batch_failure(self, mock_open):
        """If the second batch fails, results from the first are still returned."""
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(150)]
        call_count = {"i": 0}

        def side_effect(req, timeout=None):
            call_count["i"] += 1
            if call_count["i"] == 1:
                data = [
                    {"cve": f"CVE-2024-{i:04d}", "epss": "0.05", "percentile": "0.60"}
                    for i in range(100)
                ]
                return _mock_urlopen({"data": data})
            raise OSError("Connection reset")

        mock_open.side_effect = side_effect
        result = epss_client.fetch_epss(cve_ids)

        # First batch of 100 succeeded.
        self.assertEqual(len(result), 100)


class TestTheQuerySentToFirst(unittest.TestCase):
    """FIRST keys its response case-sensitively, and the merge preserves
    whatever casing the publisher used, so a lower-cased alias asked for a CVE
    the API does not know and came back with nothing -- indistinguishable in
    the UI from an advisory that genuinely has no score."""

    @mock.patch("modules.epss_client.urllib.request.urlopen")
    def test_a_lowercased_cve_is_upper_cased_on_the_way_out(self, mock_open):
        seen = {}

        def capture(req, timeout=None):
            seen["url"] = req.full_url
            return _mock_urlopen({"data": [
                {"cve": "CVE-2024-1234", "epss": "0.5", "percentile": "0.9"},
            ]})

        mock_open.side_effect = capture
        result = epss_client.fetch_epss(["cve-2024-1234"])
        self.assertIn("CVE-2024-1234", seen["url"])
        self.assertNotIn("cve-2024-1234", seen["url"])
        self.assertIn("CVE-2024-1234", result)


class TestEnrichmentCannotCostTheSearch(unittest.TestCase):
    """Each batch retried independently (attempts=2, timeout=30) and
    failures were swallowed per batch, so a FIRST outage cost the FULL
    budget rather than failing fast: sort=epss_percentage with
    max_results=500 enriches up to 2,000 CVEs in 20 batches, which is
    ~1240s inside one request against a 180s worker timeout. Enrichment is
    an optimisation; it must never be why a search dies."""

    def _run(self, n_cves, per_batch_seconds, fail=False):
        now = {"t": 0.0}
        calls = {"n": 0}

        def fake_batch(batch, timeout=30):
            calls["n"] += 1
            now["t"] += per_batch_seconds
            if fail:
                raise RuntimeError("FIRST is down")
            return {}

        with mock.patch.object(epss_client, "_fetch_batch", fake_batch), \
             mock.patch.object(epss_client.time, "monotonic", lambda: now["t"]):
            epss_client.fetch_epss([f"CVE-2026-{i}" for i in range(n_cves)])
        return calls["n"], now["t"]

    def test_a_slow_endpoint_stops_at_the_deadline(self):
        calls, elapsed = self._run(2000, per_batch_seconds=62.0)
        self.assertLess(elapsed, epss_client.FETCH_DEADLINE_SECONDS + 70,
                        f"enrichment ran for {elapsed:.0f}s")
        self.assertLess(calls, 20, "every batch was attempted anyway")

    def test_a_dead_endpoint_gives_up_rather_than_retrying_every_batch(self):
        calls, _ = self._run(2000, per_batch_seconds=0.1, fail=True)
        self.assertLessEqual(
            calls, epss_client.MAX_CONSECUTIVE_FAILURES,
            f"{calls} batches were attempted against a dead endpoint")

    def test_a_healthy_endpoint_still_scores_everything(self):
        calls, _ = self._run(500, per_batch_seconds=0.01)
        self.assertEqual(calls, 5, "a working endpoint was cut short")


class TestTheBatchCarriesDistinctCves(unittest.TestCase):
    """_fetch_batch upper-cases on the way out, but dedup ran first, so
    ["CVE-2024-1", "cve-2024-1"] survived as two entries and went out twice
    in the same ?cve= list."""

    def test_case_variants_are_one_entry(self):
        seen = []

        def fake_batch(batch, timeout=30):
            seen.extend(batch)
            return {}

        with mock.patch.object(epss_client, "_fetch_batch", fake_batch):
            epss_client.fetch_epss(["CVE-2024-1", "cve-2024-1", "Cve-2024-1",
                                    "CVE-2024-2"])
        self.assertEqual(seen, ["CVE-2024-1", "CVE-2024-2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
