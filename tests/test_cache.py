"""Tests for cache: SQLite persistence, upserts, classification storage and
the connection-lifecycle fix (no leaked WAL/SHM sidecar files)."""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import tempfile
import unittest
from unittest import mock

from modules import cache
from modules import ghsa_client as ghsa
from samples import SAMPLE


class TestAdvisoryIdBackfill(unittest.TestCase):
    """v3 renamed the column but left the stored JSON without an advisory_id.

    A record read back without one gives the AI batch nothing to key its verdict
    by, so verdicts were dropped — or worse, attributed to whichever advisory
    finished last.
    """

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.path = self.tmp.name

    def tearDown(self):
        # The -wal/-shm sidecars too: `with sqlite3.connect(...)` commits but
        # does not close, so SQLite leaves them behind. Every other class in
        # this file already removed them; this one leaked four per run.
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(self.path + suffix)
            except OSError:
                pass

    def _rows_missing_id(self):
        with sqlite3.connect(self.path) as conn:
            return [
                r[0] for r in conn.execute(
                    "SELECT advisory_id FROM advisories "
                    "WHERE COALESCE(json_extract(data, '$.advisory_id'), '') = ''"
                )
            ]

    def test_migration_backfills_ids_written_before_v3(self):
        cache.init_db(self.path)
        # Simulate a pre-v3 row: the column is set, the JSON is not.
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO advisories (advisory_id, cve_id, severity, data, fetched_at)"
                " VALUES (?,?,?,?,?)",
                ("GHSA-old-row", "CVE-2026-1", "high",
                 json.dumps({"ghsa_id": "GHSA-old-row", "summary": "s"}), 0),
            )
            conn.execute("DELETE FROM schema_version WHERE version >= 4")
        self.assertEqual(self._rows_missing_id(), ["GHSA-old-row"])

        cache.init_db(self.path)          # re-run migrations
        self.assertEqual(self._rows_missing_id(), [])
        record = cache.get_advisory("GHSA-old-row", self.path)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["advisory_id"], "GHSA-old-row")
        self.assertEqual(record["summary"], "s")   # nothing else was disturbed

    def test_migration_is_idempotent_and_leaves_good_rows_alone(self):
        cache.init_db(self.path)
        cache.upsert_advisories(
            [{"advisory_id": "GHSA-good", "cve_id": "CVE-2026-2",
              "severity": "low", "summary": "keep"}], self.path)
        for _ in range(3):
            cache.init_db(self.path)
        self.assertEqual(self._rows_missing_id(), [])
        kept = cache.get_advisory("GHSA-good", self.path)
        assert kept is not None
        self.assertEqual(kept["summary"], "keep")


class TestCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = self.tmp.name
        cache.init_db(self.db)

    def tearDown(self):
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.db + ext)
            except OSError:
                pass

    def test_upsert_and_get(self):
        n = ghsa.normalize(SAMPLE)
        cache.upsert_advisories([n], self.db)
        self.assertEqual(cache.count_advisories(self.db), 1)
        got = cache.get_advisory(n["advisory_id"], self.db)
        assert got is not None, "the advisory just upserted must read back"
        self.assertEqual(got["cve_id"], "CVE-2026-57168")
        # upsert again -> still 1
        cache.upsert_advisories([n], self.db)
        self.assertEqual(cache.count_advisories(self.db), 1)

    def test_classification_roundtrip(self):
        gid = "GHSA-xxxx"
        verdict = {"is_match": True, "confidence": 0.9, "vuln_type": "BOLA", "reason": "r"}
        cache.save_classification(gid, "bac", verdict, "PRO", self.db)
        got = cache.get_classifications([gid], "bac", self.db)
        self.assertTrue(got[gid]["is_match"])
        self.assertEqual(got[gid]["confidence"], 0.9)
        self.assertTrue(got[gid]["cached"])
        # different category -> not returned
        self.assertEqual(cache.get_classifications([gid], "sqli", self.db), {})

    def test_classification_fingerprint_invalidates_stale_verdict(self):
        gid = "GHSA-fingerprint"
        verdict = {"is_match": True, "confidence": 0.9, "vuln_type": "BOLA", "reason": "r"}
        cache.save_classification(
            gid, "bac", verdict, "PRO", self.db, fingerprint="fingerprint-v1"
        )
        fresh = cache.get_classifications(
            [gid], "bac", self.db,
            expected_fingerprints={gid: "fingerprint-v1"},
        )
        stale = cache.get_classifications(
            [gid], "bac", self.db,
            expected_fingerprints={gid: "fingerprint-v2"},
        )
        self.assertIn(gid, fresh)
        self.assertEqual(stale, {})

    def test_upsert_skips_bad_records_and_empty_list(self):
        cache.upsert_advisories([], self.db)  # early return, no error
        self.assertEqual(cache.count_advisories(self.db), 0)
        # A record without advisory_id must be silently skipped.
        cache.upsert_advisories(
            [{"cve_id": "CVE-2026-1", "severity": "high"},
             {"advisory_id": "GHSA-okok", "ghsa_id": "GHSA-okok", "cve_id": "CVE-2026-2", "severity": "low"}],
            self.db,
        )
        self.assertEqual(cache.count_advisories(self.db), 1)
        self.assertIsNotNone(cache.get_advisory("GHSA-okok", self.db))

    def test_get_classifications_empty_ids(self):
        self.assertEqual(cache.get_classifications([], "bac", self.db), {})

    def test_init_db_migrates_legacy_classification_table(self):
        legacy = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        legacy.close()
        try:
            connection = sqlite3.connect(legacy.name)
            connection.execute(
                """CREATE TABLE ai_classification (
                    ghsa_id TEXT NOT NULL, category TEXT NOT NULL,
                    is_match INTEGER NOT NULL, confidence REAL NOT NULL,
                    vuln_type TEXT, reason TEXT, model TEXT, created_at REAL NOT NULL,
                    PRIMARY KEY (ghsa_id, category)
                )"""
            )
            connection.commit()
            connection.close()
            cache.init_db(legacy.name)
            connection = sqlite3.connect(legacy.name)
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(ai_classification)")
            }
            connection.close()
            self.assertIn("fingerprint", columns)
        finally:
            for ext in ("", "-wal", "-shm"):
                try:
                    os.unlink(legacy.name + ext)
                except OSError:
                    pass

    def test_no_wal_shm_leftover_after_operations(self):
        """Regression: every cache function must really close its connection.
        With WAL mode, SQLite deletes the -wal/-shm sidecars when the last
        connection closes; leaked connections leave them behind."""
        rec = {"advisory_id": "GHSA-wal-test", "ghsa_id": "GHSA-wal-test", "cve_id": "CVE-2026-3", "severity": "low"}
        cache.upsert_advisories([rec], self.db)
        cache.get_advisory("GHSA-wal-test", self.db)
        cache.count_advisories(self.db)
        cache.save_classification(
            "GHSA-wal-test", "bac",
            {"is_match": True, "confidence": 1.0, "vuln_type": "t", "reason": "r"},
            "PRO", self.db)
        cache.get_classifications(["GHSA-wal-test"], "bac", self.db)
        for ext in ["-wal", "-shm"]:
            self.assertFalse(os.path.exists(self.db + ext),
                             msg=f"leaked SQLite sidecar file: {self.db + ext}")



class TestBatchedAdvisoryReads(unittest.TestCase):
    """The classify endpoint looped over get_advisory, which opens a
    connection and issues PRAGMA journal_mode=WAL per id -- 100 connects for
    one request, before a single model call."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = self.tmp.name
        cache.init_db(self.db)
        self.records = [
            {"advisory_id": f"GHSA-{i:05d}", "cve_id": f"CVE-2026-{i}",
             "severity": "high", "summary": "s", "description": "d"}
            for i in range(120)
        ]
        cache.upsert_advisories(self.records, path=self.db)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.db + suffix):
                os.unlink(self.db + suffix)

    def test_it_returns_the_same_rows_as_reading_one_at_a_time(self):
        ids = [r["advisory_id"] for r in self.records]
        one_by_one = {i: cache.get_advisory(i, path=self.db) for i in ids}
        self.assertEqual(cache.get_advisories(ids, path=self.db),
                         {k: v for k, v in one_by_one.items() if v})

    def test_a_whole_batch_costs_one_connection_not_one_per_id(self):
        """The loop opened a connection and issued PRAGMA journal_mode=WAL
        per id -- 100 connects for one classify request, before a single
        model call."""
        ids = [r["advisory_id"] for r in self.records]
        with mock.patch.object(cache, "_connect", wraps=cache._connect) as connect:
            found = cache.get_advisories(ids, path=self.db)
        self.assertEqual(len(found), len(ids))
        self.assertEqual(connect.call_count, 1)

    def test_unknown_ids_are_simply_absent(self):
        found = cache.get_advisories(
            ["GHSA-00001", "GHSA-does-not-exist"], path=self.db)
        self.assertEqual(set(found), {"GHSA-00001"})

    def test_an_empty_request_does_not_touch_the_database(self):
        self.assertEqual(cache.get_advisories([], path=self.db), {})

    def test_duplicate_ids_are_collapsed(self):
        found = cache.get_advisories(["GHSA-00001"] * 5, path=self.db)
        self.assertEqual(list(found), ["GHSA-00001"])

    def test_a_batch_larger_than_the_sqlite_parameter_limit_works(self):
        """SQLite's default limit is 999 bound parameters."""
        ids = [f"GHSA-{i:05d}" for i in range(120)] + [f"missing-{i}" for i in range(1500)]
        found = cache.get_advisories(ids, path=self.db)
        self.assertEqual(len(found), 120)

    def test_one_unreadable_row_does_not_sink_the_batch(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE advisories SET data='{not json' "
                         "WHERE advisory_id='GHSA-00002'")
        found = cache.get_advisories(
            ["GHSA-00001", "GHSA-00002", "GHSA-00003"], path=self.db)
        self.assertEqual(set(found), {"GHSA-00001", "GHSA-00003"})


class TestMigrationsFailLoudly(unittest.TestCase):
    """A migration that fails must not be recorded as applied.

    Every OperationalError was swallowed and the version stamped anyway, so a
    migration that failed for a real reason -- v4's json_set() on a SQLite
    build without JSON1, say -- was marked done and never retried. The defect
    it exists to repair then persisted forever, silently.
    """

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = self.tmp.name

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.db + suffix):
                os.unlink(self.db + suffix)

    def _versions(self):
        with sqlite3.connect(self.db) as conn:
            return [r[0] for r in conn.execute("SELECT version FROM schema_version")]

    def test_a_clean_run_records_every_migration(self):
        cache.init_db(self.db)
        self.assertEqual(sorted(self._versions()),
                         [v for v, _ in cache._MIGRATIONS])

    def test_no_index_is_created_for_a_column_no_query_uses(self):
        """Every read of advisories is `WHERE advisory_id = ?` (the primary
        key) or COUNT(*). An index on cve_id served none of them and cost a
        write on every upsert."""
        cache.init_db(self.db)
        indexed = set()
        with sqlite3.connect(self.db) as conn:
            for row in conn.execute("PRAGMA index_list('advisories')").fetchall():
                for info in conn.execute(f"PRAGMA index_info('{row[1]}')"):
                    indexed.add(info[2])
        self.assertNotIn("cve_id", indexed)

    def test_rerunning_is_idempotent(self):
        cache.init_db(self.db)
        before = sorted(self._versions())
        cache.init_db(self.db)
        self.assertEqual(sorted(self._versions()), before)

    def test_a_real_failure_is_raised_and_the_version_is_not_stamped(self):
        broken = [*cache._MIGRATIONS,
                  (99, "UPDATE advisories SET data = no_such_function(data)")]
        with mock.patch.object(cache, "_MIGRATIONS", broken):
            with self.assertRaises(sqlite3.OperationalError):
                cache.init_db(self.db)
        self.assertNotIn(99, self._versions())

    def test_a_failed_migration_is_retried_on_the_next_start(self):
        """The whole point: the version must stay un-stamped so a fixed
        environment re-runs it."""
        broken = [*cache._MIGRATIONS,
                  (99, "UPDATE advisories SET data = no_such_function(data)")]
        with mock.patch.object(cache, "_MIGRATIONS", broken):
            with self.assertRaises(sqlite3.OperationalError):
                cache.init_db(self.db)
        repaired = [*cache._MIGRATIONS,
                    (99, "ALTER TABLE advisories ADD COLUMN repaired INTEGER")]
        with mock.patch.object(cache, "_MIGRATIONS", repaired):
            cache.init_db(self.db)
        self.assertIn(99, self._versions())

    def test_benign_rerun_errors_are_still_tolerated(self):
        for message in ("duplicate column name: fingerprint",
                        "table jobs already exists",
                        "no such column: ghsa_id"):
            self.assertTrue(cache._is_benign_migration_error(message), message)
        self.assertFalse(
            cache._is_benign_migration_error("no such function: json_set"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
