"""One retry policy, shared by every upstream.

Before this module there were four answers to the same question: a full
implementation in ai_classifier, none in ghsa_client, none in nvd_client, and
a swallow-everything in epss_client. A GitHub 502 on page 3 of 5 therefore
discarded 200 already-fetched advisories and reported the whole source dead,
while the same class of failure against the AI provider was retried three
times with backoff.
"""

import io
import os
import sys
import time
import unittest
import urllib.error
from email.message import Message
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import http_retry  # noqa: E402


def _http_error(code, retry_after=None):
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError("u", code, "err", headers, io.BytesIO(b"{}"))


class TestRetryAfterParsing(unittest.TestCase):
    def test_delta_seconds_form(self):
        self.assertEqual(http_retry.parse_retry_after("30"), 30.0)

    def test_http_date_form(self):
        value = http_retry.parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT")
        self.assertIsNotNone(value)
        assert value is not None
        self.assertGreater(value, 0)

    def test_a_past_date_is_not_negative(self):
        self.assertEqual(
            http_retry.parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), 0.0)

    def test_garbage_and_empty_are_none(self):
        for value in (None, "", "   ", "soon", "NaN-ish"):
            self.assertIsNone(http_retry.parse_retry_after(value), repr(value))


class TestWhatCountsAsRetryable(unittest.TestCase):
    def test_gateway_and_throttle_statuses_retry(self):
        for code in (408, 429, 500, 502, 503, 504, 529):
            self.assertTrue(http_retry.is_retryable(_http_error(code)), code)

    def test_client_errors_do_not_retry(self):
        """Retrying a bad request only spends quota to fail identically."""
        for code in (400, 401, 403, 404, 422):
            self.assertFalse(http_retry.is_retryable(_http_error(code)), code)

    def test_network_level_failures_retry(self):
        self.assertTrue(http_retry.is_retryable(urllib.error.URLError("reset")))
        self.assertTrue(http_retry.is_retryable(TimeoutError()))

    def test_retry_after_is_honoured_for_429_only(self):
        """A 503 with a generous Retry-After would otherwise stall a request
        far longer than plain backoff, and is usually gone next attempt."""
        self.assertEqual(http_retry.retry_after_of(_http_error(429, "12")), 12.0)
        self.assertIsNone(http_retry.retry_after_of(_http_error(503, "600")))


class TestWithRetries(unittest.TestCase):
    def setUp(self):
        self.slept: list[float] = []

    def _sleep(self, seconds):
        self.slept.append(seconds)

    def test_a_transient_failure_is_retried_then_succeeds(self):
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise _http_error(503)
            return "ok"

        result = http_retry.with_retries(
            flaky, what="t", attempts=3, sleep=self._sleep)
        self.assertEqual(result, "ok")
        self.assertEqual(calls["n"], 3)
        self.assertEqual(len(self.slept), 2)

    def test_a_permanent_failure_is_not_retried(self):
        calls = {"n": 0}

        def bad():
            calls["n"] += 1
            raise _http_error(400)

        with self.assertRaises(urllib.error.HTTPError):
            http_retry.with_retries(bad, what="t", attempts=3, sleep=self._sleep)
        self.assertEqual(calls["n"], 1)
        self.assertEqual(self.slept, [])

    def test_the_last_failure_is_raised_when_the_budget_runs_out(self):
        def always():
            raise _http_error(502)

        with self.assertRaises(urllib.error.HTTPError) as caught:
            http_retry.with_retries(always, what="t", attempts=2, sleep=self._sleep)
        self.assertEqual(caught.exception.code, 502)

    def test_retry_after_drives_the_wait_on_429(self):
        calls = {"n": 0}

        def throttled():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(429, "7")
            return "ok"

        http_retry.with_retries(throttled, what="t", attempts=2, sleep=self._sleep)
        self.assertEqual(self.slept, [7.0])

    def test_no_single_wait_exceeds_the_ceiling(self):
        """An upstream answering "Retry-After: 3600" must not hold a request
        open for an hour."""
        calls = {"n": 0}

        def throttled():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(429, "3600")
            return "ok"

        http_retry.with_retries(throttled, what="t", attempts=2, sleep=self._sleep)
        self.assertLessEqual(self.slept[0], http_retry.MAX_BACKOFF)

    def test_a_passed_deadline_stops_further_attempts(self):
        calls = {"n": 0}

        def always():
            calls["n"] += 1
            raise _http_error(503)

        with self.assertRaises(urllib.error.HTTPError):
            http_retry.with_retries(
                always, what="t", attempts=5,
                deadline=time.monotonic() - 1, sleep=self._sleep)
        self.assertEqual(calls["n"], 1, "must not keep trying past the deadline")

    def test_a_retry_that_would_overrun_the_deadline_is_not_slept(self):
        def always():
            raise _http_error(503)

        with self.assertRaises(urllib.error.HTTPError):
            http_retry.with_retries(
                always, what="t", attempts=5,
                deadline=time.monotonic() + 0.01, sleep=self._sleep)
        self.assertEqual(self.slept, [])

    def test_a_custom_predicate_overrides_the_status_rule(self):
        """The GHSA client talks to GitHub through the `gh` CLI, so it never
        sees an HTTPError -- only a subprocess result."""
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("gh api timed out after 60s")
            return "ok"

        result = http_retry.with_retries(
            flaky, what="t", attempts=2, sleep=self._sleep,
            retryable=lambda exc: "timed out" in str(exc))
        self.assertEqual(result, "ok")
        self.assertEqual(calls["n"], 2)

    def test_backoff_grows_and_is_jittered(self):
        delays = [http_retry.backoff_delay(i) for i in range(4)]
        self.assertTrue(all(b > a for a, b in zip(delays, delays[1:])))
        # Jitter: the same attempt must not always produce the same number,
        # or a fan-out of one request per CWE retries in lockstep.
        self.assertGreater(
            len({round(http_retry.backoff_delay(0), 4) for _ in range(20)}), 1)


class TestClientsShareThePolicy(unittest.TestCase):
    def test_ai_classifier_does_not_keep_a_second_copy(self):
        from modules import ai_classifier
        self.assertEqual(set(ai_classifier.RETRYABLE_STATUS),
                         set(http_retry.RETRYABLE_STATUS))
        self.assertEqual(ai_classifier._parse_retry_after("45"),
                         http_retry.parse_retry_after("45"))

    def test_every_network_client_imports_the_shared_policy(self):
        import importlib
        for name in ("ghsa_client", "nvd_client", "osv_client", "epss_client",
                     "ai_classifier"):
            module = importlib.import_module(f"modules.{name}")
            self.assertTrue(hasattr(module, "http_retry"),
                            f"modules.{name} does not use the shared retry policy")


class TestNvdRetries(unittest.TestCase):
    def test_a_transient_nvd_failure_is_retried(self):
        from modules import nvd_client
        calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(503)
            return mock.MagicMock(
                __enter__=lambda s: io.BytesIO(b'{"vulnerabilities": []}'),
                __exit__=lambda *a: None)

        with mock.patch.object(nvd_client.urllib.request, "urlopen", fake_urlopen), \
             mock.patch.object(http_retry.time, "sleep", lambda s: None):
            body = nvd_client._fetch_page({"cweId": "CWE-79"})
        self.assertEqual(body, {"vulnerabilities": []})
        self.assertEqual(calls["n"], 2)

    def test_a_403_names_both_of_its_causes(self):
        """NVD returns 403 for throttling and for a rejected key; reporting
        only the former sent operators to the wrong fix."""
        from modules import nvd_client

        def fake_urlopen(req, timeout=None):
            raise _http_error(403)

        with mock.patch.object(nvd_client.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(nvd_client.NvdError) as caught:
                nvd_client._fetch_page({"cweId": "CWE-79"})
        message = str(caught.exception).lower()
        self.assertIn("rate limited", message)
        self.assertIn("nvd_api_key", message)


if __name__ == "__main__":
    unittest.main(verbosity=2)
