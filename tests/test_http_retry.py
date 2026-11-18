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
import pathlib
import sys
import time
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import http_retry
from samples import http_error


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

    def test_a_date_with_no_timezone_is_read_as_utc(self):
        """RFC 9110 requires GMT, and real servers still omit it. Treating a
        naive datetime as UTC keeps the wait finite; subtracting it from an
        aware `now` would raise TypeError and lose the header entirely."""
        value = http_retry.parse_retry_after("Wed, 21 Oct 2099 07:28:00")
        self.assertIsNotNone(value)
        assert value is not None
        self.assertGreater(value, 0)

    def test_a_date_parser_returning_none_is_not_a_crash(self):
        """parsedate_to_datetime raises on bad input in 3.12 but returned
        None in older versions, and this runs against whatever is installed."""
        with mock.patch("email.utils.parsedate_to_datetime", return_value=None):
            self.assertIsNone(
                http_retry.parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT"))


class TestWhatCountsAsRetryable(unittest.TestCase):
    def test_gateway_and_throttle_statuses_retry(self):
        for code in (408, 429, 500, 502, 503, 504, 529):
            self.assertTrue(http_retry.is_retryable(http_error(code)), code)

    def test_client_errors_do_not_retry(self):
        """Retrying a bad request only spends quota to fail identically."""
        for code in (400, 401, 403, 404, 422):
            self.assertFalse(http_retry.is_retryable(http_error(code)), code)

    def test_network_level_failures_retry(self):
        self.assertTrue(http_retry.is_retryable(urllib.error.URLError("reset")))
        self.assertTrue(http_retry.is_retryable(TimeoutError()))

    def test_retry_after_is_honoured_for_429_only(self):
        """A 503 with a generous Retry-After would otherwise stall a request
        far longer than plain backoff, and is usually gone next attempt."""
        self.assertEqual(http_retry.retry_after_of(http_error(429, retry_after="12")), 12.0)
        self.assertIsNone(http_retry.retry_after_of(http_error(503, retry_after="600")))

    def test_a_429_carrying_no_headers_at_all_is_none_not_a_crash(self):
        """urllib builds the HTTPError, but a mocked or wrapped opener can
        hand back one with hdrs=None, and this runs on the failure path."""
        error = http_error(429, headers=None)
        self.assertIsNone(http_retry.retry_after_of(error))

    def test_a_header_lookup_that_raises_is_none_not_a_crash(self):
        error = http_error(429, retry_after="12")
        broken = mock.Mock()
        broken.get.side_effect = RuntimeError("header store is gone")
        with mock.patch.object(type(error), "headers",
                               mock.PropertyMock(return_value=broken)):
            self.assertIsNone(http_retry.retry_after_of(error))

    def test_a_non_http_exception_has_no_advice(self):
        self.assertIsNone(http_retry.retry_after_of(OSError("connection reset")))


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
                raise http_error(503)
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
            raise http_error(400)

        with self.assertRaises(urllib.error.HTTPError):
            http_retry.with_retries(bad, what="t", attempts=3, sleep=self._sleep)
        self.assertEqual(calls["n"], 1)
        self.assertEqual(self.slept, [])

    def test_the_last_failure_is_raised_when_the_budget_runs_out(self):
        def always():
            raise http_error(502)

        with self.assertRaises(urllib.error.HTTPError) as caught:
            http_retry.with_retries(always, what="t", attempts=2, sleep=self._sleep)
        self.assertEqual(caught.exception.code, 502)

    def test_retry_after_drives_the_wait_on_429(self):
        calls = {"n": 0}

        def throttled():
            calls["n"] += 1
            if calls["n"] == 1:
                raise http_error(429, retry_after="7")
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
                raise http_error(429, retry_after="3600")
            return "ok"

        http_retry.with_retries(throttled, what="t", attempts=2, sleep=self._sleep)
        self.assertLessEqual(self.slept[0], http_retry.MAX_BACKOFF)

    def test_a_passed_deadline_stops_further_attempts(self):
        calls = {"n": 0}

        def always():
            calls["n"] += 1
            raise http_error(503)

        with self.assertRaises(urllib.error.HTTPError):
            http_retry.with_retries(
                always, what="t", attempts=5,
                deadline=time.monotonic() - 1, sleep=self._sleep)
        self.assertEqual(calls["n"], 1, "must not keep trying past the deadline")

    def test_a_retry_that_would_overrun_the_deadline_is_not_slept(self):
        def always():
            raise http_error(503)

        with self.assertRaises(urllib.error.HTTPError):
            http_retry.with_retries(
                always, what="t", attempts=5,
                deadline=time.monotonic() + 0.01, sleep=self._sleep)
        self.assertEqual(self.slept, [])

    def test_a_deadline_that_passes_during_a_sleep_stops_the_loop(self):
        """The other deadline test never reaches the top-of-loop guard: it
        refuses the sleep first. Here the first retry is affordable and the
        budget is gone by the time it wakes, which is the path that breaks
        out of the loop and re-raises the exception it was holding."""
        calls = {"n": 0}

        def always():
            calls["n"] += 1
            raise http_error(503)

        # Call 1 is the "can I afford this sleep?" check; call 2 is the
        # top-of-loop guard on the second attempt, by which time time is up.
        clock = iter([0.0, 1000.0])
        with mock.patch.object(http_retry.time, "monotonic",
                               side_effect=lambda: next(clock)), \
                self.assertLogs(http_retry.logger, "WARNING") as logs, \
                self.assertRaises(urllib.error.HTTPError):
            http_retry.with_retries(always, what="t", attempts=5,
                                    base_delay=0.1, deadline=100.0,
                                    sleep=self._sleep)
        self.assertEqual(calls["n"], 1)
        self.assertEqual(len(self.slept), 1, "the affordable retry must sleep")
        self.assertTrue(any("out of time after 1 attempt(s)" in line
                            for line in logs.output), logs.output)

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


class TestTheBackoffClockCanBeMocked(unittest.TestCase):
    """`sleep` used to be bound as a default argument, `sleep=time.sleep`,
    which Python evaluates once at import. Patching `time.sleep` afterwards
    therefore did nothing, and every caller that thought it had mocked the
    clock waited the real backoff: one test module spent 4.9 of its 5.3
    seconds asleep while appearing to be instant. The whole offline suite
    dropped from ~17s to 8.5s when this was resolved at call time instead.
    """

    def test_patching_time_sleep_is_honoured(self):
        slept = []
        with mock.patch.object(http_retry.time, "sleep", slept.append):
            with self.assertRaises(urllib.error.HTTPError):
                http_retry.with_retries(
                    lambda: (_ for _ in ()).throw(http_error(503)),
                    what="t", attempts=3, base_delay=30)
        self.assertEqual(len(slept), 2, "the retries did not sleep at all")
        self.assertTrue(all(s > 0 for s in slept))

    def test_an_explicit_sleep_still_wins(self):
        mine = []
        with mock.patch.object(http_retry.time, "sleep",
                               lambda s: self.fail("used the module clock")):
            with self.assertRaises(urllib.error.HTTPError):
                http_retry.with_retries(
                    lambda: (_ for _ in ()).throw(http_error(503)),
                    what="t", attempts=2, base_delay=1, sleep=mine.append)
        self.assertEqual(len(mine), 1)


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
            # Imported *and* called: binding the name proves nothing about
            # whether the module routes its requests through the policy.
            # __file__ is Optional on a module object; a namespace package
            # has none, and these are all real modules.
            module_file = module.__file__
            self.assertIsNotNone(module_file, f"{name} has no source file")
            assert module_file is not None
            source = pathlib.Path(module_file).read_text(encoding="utf-8")
            self.assertIn("with_retries(", source,
                          f"{name} imports the shared policy but never calls it")
            self.assertTrue(hasattr(module, "http_retry"),
                            f"modules.{name} does not use the shared retry policy")


class TestNvdRetries(unittest.TestCase):
    def test_a_transient_nvd_failure_is_retried(self):
        from modules import nvd_client
        calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise http_error(503)
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
            raise http_error(403)

        with mock.patch.object(nvd_client.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(nvd_client.NvdError) as caught:
                nvd_client._fetch_page({"cweId": "CWE-79"})
        message = str(caught.exception).lower()
        self.assertIn("rate limited", message)
        self.assertIn("nvd_api_key", message)


class TestAnAdvisedWaitIsAFloorNotAReplacement(unittest.TestCase):
    """`Retry-After: 0` is legal and proxies send it; a past HTTP-date and an
    unparseable value both land on 0.0 too. Because 0.0 is not None it used to
    replace the backoff outright, so the whole attempt budget went out
    back-to-back with no delay -- against a host that had just said it was
    overloaded, and with none of the jitter this module exists to add."""

    def _slept(self, retry_after):
        waits = []
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise http_error(429, retry_after=retry_after)
            return "ok"

        out = http_retry.with_retries(flaky, what="t", attempts=3,
                                      sleep=waits.append)
        self.assertEqual(out, "ok")
        return waits

    def test_a_zero_retry_after_does_not_cancel_the_backoff(self):
        waits = self._slept("0")
        self.assertTrue(waits, "no sleep happened at all")
        for wait in waits:
            self.assertGreater(wait, 0.0, f"slept {wait} after Retry-After: 0")

    def test_an_unparseable_retry_after_does_not_cancel_it_either(self):
        for value in ("nan", "-5", "Thu, 01 Jan 1970 00:00:00 GMT"):
            with self.subTest(retry_after=value):
                for wait in self._slept(value):
                    self.assertGreater(wait, 0.0)

    def test_a_longer_advised_wait_still_wins(self):
        """The server knows better than the formula when it asks for more."""
        for wait in self._slept("30"):
            self.assertGreaterEqual(wait, 30.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
