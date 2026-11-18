"""Tests for osv_client: normalisation and local filtering of OSV bulk records.

The bulk-zip loader (_load_records) is mocked everywhere; nothing downloads.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import io
import json
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

from modules import cwe_categories as cwe
from modules import osv_client
from samples import OSV_GHSA, OSV_NATIVE, make_osv_zip


class TestNormalizeOsv(unittest.TestCase):
    def test_normalize_ghsa_sourced(self):
        n = osv_client.normalize_osv(OSV_GHSA)
        self.assertEqual(n["advisory_id"], "GHSA-xr65-5cpm-g36x")
        self.assertEqual(n["ghsa_id"], "GHSA-xr65-5cpm-g36x")
        self.assertEqual(n["cve_id"], "CVE-2026-11122")
        self.assertEqual(n["cwes"], ["CWE-863"])
        self.assertEqual(n["severity"], "critical")
        self.assertEqual(n["source"], "osv")
        self.assertEqual(n["packages"][0]["first_patched_version"], "0.9.5")
        self.assertTrue(n["html_url"].endswith("GHSA-xr65-5cpm-g36x"))

    def test_normalize_native(self):
        n = osv_client.normalize_osv(OSV_NATIVE)
        self.assertEqual(n["advisory_id"], "GO-2023-1737")  # no GHSA alias -> keeps OSV id
        self.assertEqual(n["ghsa_id"], "GO-2023-1737")  # no GHSA alias -> keeps OSV id
        self.assertEqual(n["cve_id"], "CVE-2023-29401")
        self.assertEqual(n["cwes"], [])
        self.assertEqual(n["severity"], "low")  # derived from CVSS vector

    def test_supported(self):
        self.assertTrue(osv_client.supported_ecosystem("maven"))
        self.assertTrue(osv_client.supported_ecosystem("go"))
        self.assertFalse(osv_client.supported_ecosystem("any"))


class TestFetchOsv(unittest.TestCase):
    def test_invalid_download_does_not_replace_cached_zip(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory), \
             mock.patch("modules.osv_client.urllib.request.urlopen") as urlopen:
            path = osv_client._zip_path("Go")
            good = make_osv_zip([OSV_NATIVE])
            with open(path, "wb") as handle:
                handle.write(good)
            # A real response is a stream: read(n) returns b"" at EOF. A
            # MagicMock whose read() always returns the same bytes never ends,
            # which is not how any HTTP response behaves.
            response = mock.MagicMock()
            body = io.BytesIO(b"not-a-zip")
            response.read.side_effect = body.read
            response.__enter__.return_value = response
            response.__exit__.return_value = False
            urlopen.return_value = response
            with self.assertRaises(osv_client.OsvError):
                osv_client.download_ecosystem("Go", force=True)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), good)

    def test_an_endless_response_is_cut_off_at_the_cap(self):
        """The cap is what stops a response that never ends from filling the
        disk. Writing this test is how the streaming loop was found to run
        away against a mock whose read() never returns b"" -- it wrote 119 MB
        before it was killed."""
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory), \
             mock.patch.object(osv_client, "MAX_BULK_BYTES", 1 << 20), \
             mock.patch("modules.osv_client.urllib.request.urlopen") as urlopen:
            response = mock.MagicMock()
            response.read.return_value = b"x" * 65536      # never ends
            response.__enter__.return_value = response
            response.__exit__.return_value = False
            urlopen.return_value = response
            with self.assertRaises(osv_client.OsvError) as caught:
                osv_client.download_ecosystem("Go", force=True)
            self.assertIn("exceeded", str(caught.exception))
            # The partial file must not be left behind.
            self.assertFalse(
                os.path.exists(osv_client._zip_path("Go") + ".tmp"))

    def test_a_failed_download_leaves_no_partial_file(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory), \
             mock.patch("modules.osv_client.urllib.request.urlopen",
                        side_effect=OSError("connection reset")):
            with self.assertRaises(osv_client.OsvError):
                osv_client.download_ecosystem("Go", force=True)
            self.assertFalse(
                os.path.exists(osv_client._zip_path("Go") + ".tmp"))

    def test_zip_records_and_cwe_filter(self):
        # Build an in-memory bulk zip (samples.make_osv_zip replaces the removed
        # osv_client.bytes_to_records), unzip+normalize it ourselves, and drive
        # fetch_osv via a patched loader.
        data = make_osv_zip([OSV_GHSA, OSV_NATIVE])
        recs = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.endswith(".json"):
                    recs.append(osv_client.normalize_osv(json.loads(zf.read(name))))
        self.assertEqual(len(recs), 2)
        with mock.patch("modules.osv_client._load_records", return_value=recs):
            # BAC includes CWE-863 -> only the GHSA-sourced record matches.
            out = osv_client.fetch_osv("go", cwe.category_cwes("bac"), max_results=50)
        self.assertEqual([r["ghsa_id"] for r in out], ["GHSA-xr65-5cpm-g36x"])

    def test_fetch_osv_requires_ecosystem(self):
        with self.assertRaises(osv_client.OsvError):
            osv_client.fetch_osv("any", ["863"])

    def _two_severities(self):
        crit = osv_client.normalize_osv(OSV_GHSA)  # critical, CWE-863, rancher/fleet
        low = osv_client.normalize_osv(dict(
            OSV_GHSA,
            id="GHSA-low1-low1-low1",
            aliases=["CVE-2026-99999"],
            database_specific={"cwe_ids": ["CWE-863"], "severity": "LOW"},
            affected=[{"package": {"ecosystem": "Go", "name": "github.com/other/pkg"},
                       "ranges": []}],
        ))
        return [crit, low]

    def test_fetch_osv_severity_filter(self):
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            out = osv_client.fetch_osv("go", ["863"], severity="critical")
        self.assertEqual([r["ghsa_id"] for r in out], ["GHSA-xr65-5cpm-g36x"])
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            out_any = osv_client.fetch_osv("go", ["863"], severity="any")
        self.assertEqual({r["ghsa_id"] for r in out_any},
                         {"GHSA-xr65-5cpm-g36x", "GHSA-low1-low1-low1"})

    def test_fetch_osv_published_filter(self):
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            recent = osv_client.fetch_osv(
                "go", ["863"], published=">=2026-01-01"
            )
        self.assertTrue(recent)
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            future = osv_client.fetch_osv(
                "go", ["863"], published=">=2099-01-01"
            )
        self.assertEqual(future, [])

    def test_fetch_osv_affects_filter_case_insensitive_exact(self):
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            out = osv_client.fetch_osv(
                "go", ["863"], affects="GITHUB.COM/RANCHER/FLEET"
            )
        self.assertEqual([r["ghsa_id"] for r in out], ["GHSA-xr65-5cpm-g36x"])
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            partial = osv_client.fetch_osv("go", ["863"], affects="RANCHER/Fleet")
        self.assertEqual(partial, [])
        with mock.patch("modules.osv_client._load_records", return_value=self._two_severities()):
            out2 = osv_client.fetch_osv("go", ["863"], affects="no-such-package")
        self.assertEqual(out2, [])


class TestFetchOsvNative(unittest.TestCase):
    def test_fetch_osv_native(self):
        # A native record with no CWE but a BAC keyword should be surfaced;
        # the GHSA-sourced one should be excluded (it's covered by CWE path).
        native_bac = dict(OSV_NATIVE, id="GO-2024-001",
                          summary="auth bypass: missing authorization on admin route",
                          aliases=[], database_specific={})
        native_other = dict(OSV_NATIVE, id="GO-2024-002",
                            summary="denial of service via large input", aliases=[],
                            database_specific={})
        recs = [osv_client.normalize_osv(r)
                for r in (OSV_GHSA, native_bac, native_other)]
        with mock.patch("modules.osv_client._load_records", return_value=recs):
            out = osv_client.fetch_osv_native("go", ["bac"], max_results=50)
        ids = [r["ghsa_id"] for r in out]
        self.assertIn("GO-2024-001", ids)       # keyword-matched native
        self.assertNotIn("GO-2024-002", ids)    # no keyword match
        self.assertNotIn("GHSA-xr65-5cpm-g36x", ids)  # GHSA-sourced excluded
        self.assertTrue(out[0]["native"])

    def test_native_respects_common_filters(self):
        native = dict(
            OSV_NATIVE,
            id="GO-2026-100",
            summary="authorization bypass",
            aliases=[],
            database_specific={"severity": "HIGH"},
        )
        records = [osv_client.normalize_osv(native)]
        package = records[0]["packages"][0]["name"]
        with mock.patch("modules.osv_client._load_records", return_value=records):
            out = osv_client.fetch_osv_native(
                "go",
                ["bac"],
                affects=package.upper(),
                severity="high",
                published=">=2023-01-01",
            )
        self.assertEqual([record["ghsa_id"] for record in out], ["GO-2026-100"])


class TestOneBadRecordDoesNotKillTheSearch(unittest.TestCase):
    """normalize_osv used to sit outside the per-record try, and the outer
    handler catches only archive errors — so one wrong-shaped record raised
    AttributeError out of OSV entirely and 500'd the whole search."""

    def _archive(self, entries, directory):
        path = os.path.join(directory, "Go.zip")
        with zipfile.ZipFile(path, "w") as zf:
            for name, payload in entries.items():
                zf.writestr(name, payload if isinstance(payload, str)
                            else json.dumps(payload))
        return path

    def _load(self, entries):
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._archive(entries, tmp)
            osv_client._MEM.clear()
            try:
                with mock.patch.object(osv_client, "download_ecosystem",
                                       return_value=archive):
                    return osv_client._load_records("go")
            finally:
                osv_client._MEM.clear()

    def test_a_json_array_where_an_object_belongs_is_skipped(self):
        records = self._load({
            "good1.json": {"id": "GO-2026-1", "affected": []},
            "bad.json": ["not", "a", "dict"],
            "good2.json": {"id": "GO-2026-2", "affected": []},
        })
        self.assertEqual(sorted(r["advisory_id"] for r in records),
                         ["GO-2026-1", "GO-2026-2"])

    def test_unparsable_json_is_still_skipped(self):
        records = self._load({
            "good.json": {"id": "GO-1", "affected": []},
            "broken.json": "{not json",
        })
        self.assertEqual([r["advisory_id"] for r in records], ["GO-1"])

    def test_skipped_records_are_reported_not_swallowed(self):
        with self.assertLogs("modules.osv_client", level="INFO") as logs:
            self._load({
                "good.json": {"id": "GO-1", "affected": []},
                "bad.json": ["nope"],
            })
        self.assertTrue(any("Skipped 1 unusable" in line for line in logs.output),
                        logs.output)



class TestNormalisedPackagesCarryOnlyWhatIsRead(unittest.TestCase):
    """purl, ranges and versions were written into every package and read
    nowhere -- not by the UI, not by app.py, not by search_service -- while
    being ~49% of the package payload and persisted verbatim into SQLite.
    The one thing a reader wants out of `ranges` is the version window, which
    sat hard-coded None right beside the raw copy."""

    def _normalise(self, ranges=None, versions=None):
        record = {
            "id": "GHSA-x", "summary": "s", "details": "d",
            "affected": [{
                "package": {"ecosystem": "Go", "name": "example.com/p",
                            "purl": "pkg:golang/example.com/p"},
                "ranges": ranges if ranges is not None else [],
                "versions": versions if versions is not None else [],
            }],
        }
        return osv_client.normalize_osv(record)["packages"][0]

    def test_the_unread_fields_are_gone(self):
        pkg = self._normalise(
            ranges=[{"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}],
            versions=["1.0.0", "1.1.0"])
        for dropped in ("purl", "ranges", "versions"):
            self.assertNotIn(dropped, pkg, dropped)

    def test_what_is_read_is_still_there(self):
        pkg = self._normalise(
            ranges=[{"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}])
        self.assertEqual(pkg["ecosystem"], "Go")
        self.assertEqual(pkg["name"], "example.com/p")
        self.assertEqual(pkg["first_patched_version"], "1.2.3")
        self.assertEqual(pkg["fixed_versions"], ["1.2.3"])

    def test_the_version_range_is_populated_not_hard_coded_none(self):
        pkg = self._normalise(
            ranges=[{"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}])
        self.assertEqual(pkg["vulnerable_version_range"], ">= 1.0.0, < 1.2.3")

    def test_range_shapes(self):
        for ranges, expected in (
            ([{"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}],
             ">= 1.0.0, < 1.2.3"),
            # OSV writes "0" for "since the beginning"; not a bound worth showing.
            ([{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}], "< 2.0.0"),
            ([{"events": [{"introduced": "1.5"}]}], ">= 1.5"),
            ([{"events": [{"introduced": "0"}]}], None),
            ([], None),
        ):
            with self.subTest(ranges=ranges):
                self.assertEqual(osv_client._introduced_range(ranges), expected)


class TestCachePathCannotEscapeTheCacheDir(unittest.TestCase):
    """download_ecosystem is a public entry point taking an arbitrary string.
    Every caller routes through ECOSYSTEM_MAP today, so this is hardening --
    but "replace / and space" left ".." intact and the result is joined onto
    CACHE_DIR."""

    def test_traversal_attempts_stay_inside_the_cache_dir(self):
        for hostile in ("../../etc/passwd", "../outside", "a/../../b"):
            with self.subTest(name=hostile):
                path = osv_client._zip_path(hostile)
                self.assertEqual(
                    os.path.dirname(os.path.abspath(path)),
                    os.path.abspath(osv_client.CACHE_DIR))

    def test_a_name_that_reduces_to_nothing_is_refused(self):
        for hostile in ("..", "", "...", "."):
            with self.subTest(name=hostile):
                with self.assertRaises(osv_client.OsvError):
                    osv_client._zip_path(hostile)

    def test_a_real_ecosystem_name_still_works(self):
        self.assertTrue(
            osv_client._zip_path("GitHub Actions").endswith("GitHub_Actions.zip"))
        self.assertTrue(osv_client._zip_path("Go").endswith("Go.zip"))


class TestConcurrentLoadsParseOnce(unittest.TestCase):
    """The memo read was guarded and the download serialised, but the parse
    -- the expensive part -- ran unlocked.

    On a cold cache N concurrent requests for the same ecosystem each
    inflated and normalised the whole archive, the last writer won, and the
    rest was garbage. npm's export is 226,880 members and ~372 MB
    uncompressed, against a shipped config of --workers 1 --threads 8.
    """

    def setUp(self):
        osv_client._MEM.clear()

    def tearDown(self):
        osv_client._MEM.clear()

    def test_eight_concurrent_cold_loads_parse_once(self):
        parses = []
        barrier = threading.Barrier(8)

        def fake_load(ghsa_ecosystem, osv_eco, force):
            parses.append(ghsa_ecosystem)
            time.sleep(0.05)
            records = [{"advisory_id": "OSV-1"}]
            with osv_client._MEM_LOCK:
                osv_client._MEM[ghsa_ecosystem] = (time.time(), records)
            return records

        def worker():
            barrier.wait()
            osv_client._load_records("maven")

        with mock.patch.object(osv_client, "_load_records_locked", fake_load):
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(len(parses), 1, f"archive parsed {len(parses)} times")

    def test_different_ecosystems_do_not_block_each_other(self):
        order = []

        def fake_load(ghsa_ecosystem, osv_eco, force):
            order.append(("start", ghsa_ecosystem))
            time.sleep(0.05)
            with osv_client._MEM_LOCK:
                osv_client._MEM[ghsa_ecosystem] = (time.time(), [])
            order.append(("end", ghsa_ecosystem))
            return []

        with mock.patch.object(osv_client, "_load_records_locked", fake_load):
            threads = [threading.Thread(target=osv_client._load_records, args=(eco,))
                       for eco in ("maven", "npm", "go")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        starts = [e for e in order[:3] if e[0] == "start"]
        self.assertEqual(len(starts), 3, "ecosystems serialised against each other")

    def test_a_warm_memo_skips_the_loader_entirely(self):
        with osv_client._MEM_LOCK:
            osv_client._MEM["maven"] = (time.time(), [{"advisory_id": "cached"}])
        with mock.patch.object(osv_client, "_load_records_locked") as loader:
            records = osv_client._load_records("maven")
        loader.assert_not_called()
        self.assertEqual(records[0]["advisory_id"], "cached")


def _no_sleep_retries(call, **kwargs):
    """http_retry.with_retries with the backoff sleep stubbed out.

    `sleep` is a default argument bound at import, so patching
    http_retry.time.sleep does not reach it.
    """
    kwargs.setdefault("sleep", lambda _seconds: None)
    return _REAL_WITH_RETRIES(call, **kwargs)


_REAL_WITH_RETRIES = osv_client.http_retry.with_retries


class TestAFailedRefreshKeepsAUsableCache(unittest.TestCase):
    """The freshness check only short-circuits on success, so once the zip was
    a day old a transient download failure dropped OSV from the search
    entirely -- while a perfectly usable copy sat on disk."""

    def _stale_cache(self, directory):
        path = osv_client._zip_path("Go")
        with open(path, "wb") as handle:
            handle.write(make_osv_zip([OSV_NATIVE]))
        os.utime(path, (0, 0))          # far older than DEFAULT_MAX_AGE
        return path

    def test_a_stale_cache_is_used_when_the_refresh_fails(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory), \
             mock.patch.object(osv_client.http_retry, "with_retries",
                               _no_sleep_retries), \
             mock.patch("modules.osv_client.urllib.request.urlopen",
                        side_effect=OSError("connection reset")):
            path = self._stale_cache(directory)
            with self.assertLogs("modules.osv_client", level="WARNING") as logs:
                self.assertEqual(osv_client.download_ecosystem("Go"), path)
            with open(path, "rb") as handle:
                self.assertTrue(handle.read())
        self.assertTrue(any("using the cached copy" in line for line in logs.output),
                        logs.output)

    def test_an_explicit_refresh_still_reports_the_failure(self):
        """force=True is the user asking for fresh data; handing back the old
        copy silently would be the same silence in a different place."""
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory), \
             mock.patch.object(osv_client.http_retry, "with_retries",
                               _no_sleep_retries), \
             mock.patch("modules.osv_client.urllib.request.urlopen",
                        side_effect=OSError("connection reset")):
            self._stale_cache(directory)
            with self.assertRaises(osv_client.OsvError):
                osv_client.download_ecosystem("Go", force=True)

    def test_no_cache_at_all_still_reports_the_failure(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory), \
             mock.patch.object(osv_client.http_retry, "with_retries",
                               _no_sleep_retries), \
             mock.patch("modules.osv_client.urllib.request.urlopen",
                        side_effect=OSError("connection reset")):
            with self.assertRaises(osv_client.OsvError):
                osv_client.download_ecosystem("Go")


class TestAnEcosystemNameWithASpaceIsFetchable(unittest.TestCase):
    """Several OSV ecosystem names contain a space ("GitHub Actions").

    Interpolated raw, http.client rejects the request path outright -- so the
    `actions` ecosystem the UI offers in its dropdown could never be fetched
    at all, and the broad handler reported it as a generic "OSV fetch failed".
    """

    def test_the_url_percent_encodes_the_name(self):
        seen = {}
        payload = make_osv_zip([OSV_NATIVE])

        def capture(req, timeout=None):
            seen["url"] = req.full_url
            response = mock.MagicMock()
            body = io.BytesIO(payload)
            response.read.side_effect = body.read
            response.__enter__.return_value = response
            response.__exit__.return_value = False
            return response

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory), \
             mock.patch("modules.osv_client.urllib.request.urlopen",
                        side_effect=capture):
            osv_client.download_ecosystem(
                osv_client.ECOSYSTEM_MAP["actions"], force=True)
        self.assertIn("GitHub%20Actions", seen["url"])
        self.assertNotIn(" ", seen["url"])


class TestCacheStatusSurvivesAVanishingFile(unittest.TestCase):
    """These caches are documented as safe to delete at any time, and this
    renders on every healthcheck: a file removed between the existence check
    and the read must not take /api/meta down."""

    def test_a_file_removed_mid_read_is_skipped(self):
        def vanishing(path):
            raise OSError(2, "No such file or directory", path)

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory):
            with open(osv_client._zip_path("Go"), "wb") as handle:
                handle.write(b"x" * 10)
            with mock.patch("modules.osv_client.os.path.getsize", vanishing):
                self.assertEqual(osv_client.cache_status(), [])

    def test_a_present_cache_is_still_reported(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(osv_client, "CACHE_DIR", directory):
            with open(osv_client._zip_path("Go"), "wb") as handle:
                handle.write(b"x" * 10)
            status = osv_client.cache_status()
        self.assertEqual([entry["ecosystem"] for entry in status], ["go"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
