"""Tests for ghsa_client: query building, normalisation, pagination, header parsing.

All subprocess calls to the `gh` CLI are mocked; nothing touches the network.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import unittest
from unittest import mock

from modules import ghsa_client as ghsa
from samples import SAMPLE


class TestATransientPageIsRetried(unittest.TestCase):
    """The module's headline promise -- "a page that fails transiently is
    retried" -- had no test and no revert check. `_is_transient_gh_error`,
    `_TRANSIENT_GH_MARKERS` and `FETCH_DEADLINE_SECONDS` appeared in no
    test file at all, so a typo in one marker would silently restore the
    bug where one flaky page loses 200 advisories.

    The existing failure test uses stderr="boom", which is deliberately
    *not* transient, so it exercised the opposite branch.
    """

    def test_the_markers_that_decide_a_retry(self):
        for text in ("502 Bad Gateway", "connection reset by peer",
                     "TLS handshake timeout", "API rate limit exceeded",
                     "temporary failure in name resolution", "unexpected EOF"):
            with self.subTest(stderr=text):
                self.assertTrue(
                    ghsa._is_transient_gh_error(ghsa.GhCliError(text)),
                    f"{text!r} should be worth another attempt")

    def test_a_permanent_failure_is_not_retried(self):
        for text in ("Not Found", "Bad credentials", "Validation Failed",
                     "could not resolve to a Repository"):
            with self.subTest(stderr=text):
                self.assertFalse(
                    ghsa._is_transient_gh_error(ghsa.GhCliError(text)))

    def test_only_a_gh_error_counts(self):
        """is_retryable's default reads HTTP status; this one only ever
        sees a subprocess result, so anything else must fall through."""
        self.assertFalse(ghsa._is_transient_gh_error(OSError("502")))
        self.assertFalse(ghsa._is_transient_gh_error(ValueError("timed out")))

    def test_a_flaky_first_page_is_retried_and_the_fetch_succeeds(self):
        """End to end: the predicate is wired into the fetch, not merely
        defined. Without the retry this returns nothing."""
        good = json.dumps([dict(SAMPLE)])
        calls = {"n": 0}

        def flaky(cmd, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return mock.Mock(returncode=1, stdout="", stderr="502 Bad Gateway")
            return mock.Mock(returncode=0, stdout="HTTP/2.0 200\r\n\r\n" + good,
                             stderr="")

        with mock.patch.object(ghsa.subprocess, "run", side_effect=flaky), \
                mock.patch.object(ghsa.http_retry.time, "sleep"):
            out = ghsa.fetch_advisories(ghsa.SearchParams(max_results=10))
        self.assertEqual(calls["n"], 2, "the transient page was not retried")
        self.assertEqual(len(out), 1)

    def test_a_permanent_first_page_is_not_retried(self):
        calls = {"n": 0}

        def always_bad(cmd, *args, **kwargs):
            calls["n"] += 1
            return mock.Mock(returncode=1, stdout="", stderr="Bad credentials")

        with mock.patch.object(ghsa.subprocess, "run", side_effect=always_bad), \
                mock.patch.object(ghsa.http_retry.time, "sleep"), \
                self.assertRaises(ghsa.GhCliError):
            ghsa.fetch_advisories(ghsa.SearchParams(max_results=10))
        self.assertEqual(calls["n"], 1, "a permanent failure was retried")

    def test_the_whole_fetch_has_a_deadline(self):
        """50 pages times a 60s per-call timeout is a 50-minute worst case
        inside a request the shipped gunicorn allows 180s."""
        self.assertLessEqual(ghsa.FETCH_DEADLINE_SECONDS, 180)
        self.assertGreater(ghsa.FETCH_DEADLINE_SECONDS, 0)


class TestSearchParams(unittest.TestCase):
    def test_query_build(self):
        p = ghsa.SearchParams(ecosystem="maven", cwes=["CWE-639", "862"],
                              severity="high", affects="a:b")
        q = p.to_query()
        self.assertEqual(q["ecosystem"], "maven")
        self.assertEqual(q["cwes"], "639,862")   # CWE- prefix stripped
        self.assertEqual(q["severity"], "high")
        self.assertEqual(q["affects"], "a:b")

    def test_any_omitted(self):
        p = ghsa.SearchParams(ecosystem="any", severity="any")
        q = p.to_query()
        self.assertNotIn("ecosystem", q)
        self.assertNotIn("severity", q)

    def test_per_page_capped(self):
        self.assertEqual(ghsa.SearchParams(per_page=500).to_query()["per_page"], "100")


class TestNormalize(unittest.TestCase):
    def test_normalize(self):
        n = ghsa.normalize(SAMPLE)
        self.assertEqual(n["ghsa_id"], "GHSA-h3m5-97jq-qjrf")
        self.assertEqual(n["cwes"], ["CWE-639"])
        self.assertEqual(n["severity"], "high")
        self.assertEqual(n["cvss_score"], 7.5)
        self.assertEqual(len(n["packages"]), 1)  # malformed skipped
        self.assertEqual(n["packages"][0]["name"], "org.openremote:manager")
        self.assertEqual(n["ecosystems"], ["maven"])
        self.assertEqual(n["references"], ["https://example.com/a"])  # non-str dropped


class TestPagination(unittest.TestCase):
    def _fake_run(self, pages):
        """Return a fake subprocess.run that yields pages sequentially."""
        calls = {"i": 0}

        def _run(cmd, capture_output, text, timeout):
            i = calls["i"]
            calls["i"] += 1
            body, next_url = pages[i]
            headers = "HTTP/2 200\ncontent-type: application/json"
            if next_url:
                headers += f'\nLink: <{next_url}>; rel="next"'
            out = headers + "\n\n" + json.dumps(body)
            return mock.Mock(returncode=0, stdout=out, stderr="")

        return _run, calls

    def test_follows_cursor_and_caps(self):
        pages = [
            ([{"ghsa_id": "A"}], "https://api.github.com/advisories?after=x"),
            ([{"ghsa_id": "B"}], "https://api.github.com/advisories?after=y"),
            ([{"ghsa_id": "C"}], None),
        ]
        fake, calls = self._fake_run(pages)
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=fake):
            res = ghsa.fetch_advisories(ghsa.SearchParams(per_page=1, max_results=2))
        self.assertEqual([r["ghsa_id"] for r in res], ["A", "B"])  # capped at 2
        self.assertEqual(calls["i"], 2)  # stopped early, didn't fetch page C

    def test_stops_when_no_next(self):
        pages = [([{"ghsa_id": "A"}], None)]
        fake, _ = self._fake_run(pages)
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=fake):
            res = ghsa.fetch_advisories(ghsa.SearchParams(max_results=100))
        self.assertEqual(len(res), 1)

    def test_api_error_raises(self):
        def _run(cmd, capture_output, text, timeout):
            body = {"message": "Bad creds", "documentation_url": "x"}
            return mock.Mock(returncode=0, stdout="HTTP/2 401\n\n" + json.dumps(body), stderr="")
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=_run):
            with self.assertRaises(ghsa.GhCliError):
                ghsa.fetch_advisories(ghsa.SearchParams())

    def test_nonzero_exit_raises(self):
        def _run(cmd, capture_output, text, timeout):
            return mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=_run):
            with self.assertRaises(ghsa.GhCliError):
                ghsa.fetch_advisories(ghsa.SearchParams())


class TestRunGhApiHeaderSplit(unittest.TestCase):
    def test_crlf_header_body_separator(self):
        """Regression: gh may emit \r\n line endings; the header/body split and
        the Link-header cursor must still be parsed."""
        body = [{"ghsa_id": "A"}]
        stdout = (
            "HTTP/2 200\r\n"
            "Content-Type: application/json\r\n"
            'Link: <https://api.github.com/advisories?after=zz>; rel="next"\r\n'
            "\r\n"
            + json.dumps(body)
        )

        def _run(cmd, capture_output, text, timeout):
            return mock.Mock(returncode=0, stdout=stdout, stderr="")

        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=_run):
            data, next_url = ghsa._run_gh_api("/advisories?per_page=1")
        self.assertEqual(data, body)
        self.assertEqual(next_url, "https://api.github.com/advisories?after=zz")


class TestAuthStatusIsCached(unittest.TestCase):
    """`gh auth status` forks a process and calls GitHub — 639 ms, measured.

    It runs while rendering GET / and GET /api/meta, neither of which is
    authenticated or rate limited, and the Docker healthcheck hits /api/meta
    every 30 seconds.
    """

    def setUp(self):
        ghsa.reset_auth_cache()

    def tearDown(self):
        ghsa.reset_auth_cache()

    def test_repeated_calls_fork_once(self):
        with mock.patch.object(ghsa, "_gh_auth_uncached", return_value=True) as probe:
            results = [ghsa.gh_auth_ok() for _ in range(20)]
        self.assertEqual(results, [True] * 20)
        self.assertEqual(probe.call_count, 1)

    def test_a_negative_result_is_cached_too(self):
        with mock.patch.object(ghsa, "_gh_auth_uncached", return_value=False) as probe:
            self.assertFalse(ghsa.gh_auth_ok())
            self.assertFalse(ghsa.gh_auth_ok())
        self.assertEqual(probe.call_count, 1)

    def test_force_and_reset_both_bypass_the_cache(self):
        with mock.patch.object(ghsa, "_gh_auth_uncached", return_value=True) as probe:
            ghsa.gh_auth_ok()
            ghsa.gh_auth_ok(force=True)
            ghsa.reset_auth_cache()
            ghsa.gh_auth_ok()
        self.assertEqual(probe.call_count, 3)

    def test_the_cache_expires(self):
        with mock.patch.object(ghsa, "_gh_auth_uncached", return_value=True) as probe, \
             mock.patch.object(ghsa, "AUTH_CACHE_SECONDS", 0):
            ghsa.gh_auth_ok()
            ghsa.gh_auth_ok()
        self.assertEqual(probe.call_count, 2)



class TestPaginationCursorHandling(unittest.TestCase):
    """HTTP permits repeated Link headers."""

    def _gh_response(self, headers, body="[]"):
        """Drive the real _run_gh_api with a canned `gh api -i` stdout."""
        # Two CRLFs: _run_gh_api splits on the blank line between headers
        # and body (re.split(r"\r?\n\r?\n")). With one, the JSON ended up
        # inside the header blob, `data` came back empty, and the `body`
        # argument did nothing -- the three callers discarded it with `_,`.
        completed = mock.Mock(returncode=0,
                              stdout=headers + "\r\n\r\n" + body, stderr="")
        with mock.patch.object(ghsa.subprocess, "run", return_value=completed):
            return ghsa._run_gh_api("/advisories?per_page=100")

    def test_a_prev_link_before_next_does_not_stop_pagination(self):
        """The loop broke on the first header starting with "link:" whether
        or not it held rel="next", so a response that sent rel="prev" first
        stopped at page 1 -- 100 results for a max_results=500 query, with no
        error.

        Driven through _run_gh_api, not a copy of its loop: the earlier
        version of this test reimplemented the parsing and so stayed green
        when the shipped parser was broken.
        """
        _, next_url = self._gh_response(
            'HTTP/2.0 200\r\n'
            'link: <https://api.github.com/advisories?page=1>; rel="prev"\r\n'
            'link: <https://api.github.com/advisories?page=3>; rel="next"'
        )
        self.assertIsNotNone(next_url)
        assert next_url is not None
        self.assertIn("page=3", next_url)

    def test_a_single_next_link_is_found(self):
        _, next_url = self._gh_response(
            'HTTP/2.0 200\r\n'
            'link: <https://api.github.com/advisories?page=2>; rel="next"'
        )
        assert next_url is not None
        self.assertIn("page=2", next_url)

    def test_no_next_link_ends_pagination(self):
        _, next_url = self._gh_response(
            'HTTP/2.0 200\r\n'
            'link: <https://api.github.com/advisories?page=1>; rel="prev"'
        )
        self.assertIsNone(next_url)

    def test_a_cursor_outside_advisories_is_refused(self):
        """The cursor comes from a response header and becomes an argv
        element, so a value like "--input=/etc/passwd" would be read by gh's
        flag parser rather than as a path."""
        for hostile in ("https://api.github.com/user",
                        "https://evil.test/--input=/etc/passwd",
                        "https://api.github.com/"):
            with self.subTest(url=hostile):
                with self.assertRaises(ghsa.GhCliError):
                    ghsa._strip_to_path(hostile)

    def test_a_legitimate_cursor_is_accepted(self):
        path = ghsa._strip_to_path(
            "https://api.github.com/advisories?per_page=100&after=abc")
        self.assertTrue(path.startswith("/advisories?"))
        self.assertIn("after=abc", path)


class TestAFailingLaterPageKeepsWhatSucceeded(unittest.TestCase):
    """Losing 200 advisories because page 3 of 5 failed made a flaky page look
    like a dead source. Whatever has already been collected is returned."""

    def _first_page_then_failure(self, next_url):
        calls = {"i": 0}

        def _run(cmd, capture_output, text, timeout):
            calls["i"] += 1
            if calls["i"] == 1:
                headers = ("HTTP/2 200\ncontent-type: application/json"
                           f'\nLink: <{next_url}>; rel="next"')
                return mock.Mock(
                    returncode=0,
                    stdout=headers + "\n\n" + json.dumps([{"ghsa_id": "A"}]),
                    stderr="")
            return mock.Mock(returncode=1, stdout="", stderr="boom")

        return _run, calls

    def test_the_pages_that_succeeded_are_still_returned(self):
        run, calls = self._first_page_then_failure(
            "https://api.github.com/advisories?after=x")
        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=run):
            res = ghsa.fetch_advisories(
                ghsa.SearchParams(per_page=1, max_results=10))
        self.assertEqual([r["ghsa_id"] for r in res], ["A"])
        self.assertEqual(calls["i"], 2, "the second page was never attempted")

    def test_a_first_page_that_fails_is_still_an_error(self):
        """Nothing collected means the source really did fail; degrading to an
        empty list there would report "no advisories" for an outage."""
        def _run(cmd, capture_output, text, timeout):
            return mock.Mock(returncode=1, stdout="", stderr="boom")

        with mock.patch("modules.ghsa_client.subprocess.run", side_effect=_run):
            with self.assertRaises(ghsa.GhCliError):
                ghsa.fetch_advisories(ghsa.SearchParams(max_results=10))


if __name__ == "__main__":
    unittest.main(verbosity=2)
