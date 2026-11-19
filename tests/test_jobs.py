"""Tests for the background job store and runner.

The pool is real here — these submit work and wait for it — because the thing
worth testing is that a job actually leaves the request thread, lands in SQLite,
and comes back with the right terminal state.
"""

import contextlib
import os
import pathlib
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3
import tempfile
import unittest
from typing import Any, cast
from unittest import mock

from modules import cache, jobs


def _wait_for(job_id, path, statuses=("done", "failed"), timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = cache.get_job(job_id, path=path)
        if job and job["status"] in statuses:
            return job
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {statuses}")


def _job(job_id, path):
    """cache.get_job() is Optional; every call routed through here expects
    a row that exists, so a missing one is a test failure, not a None."""
    row = cache.get_job(job_id, path=path)
    assert row is not None, f"no job row for {job_id}"
    return row


class TestJobLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        cache.init_db(cache.DB_PATH)

    def tearDown(self):
        jobs.shutdown(wait=True)
        jobs.resume()
        cache.DB_PATH = self._orig
        for ext in ["", "-wal", "-shm"]:
            try:
                os.unlink(self.tmp.name + ext)
            except OSError:
                pass

    def test_successful_job_stores_its_result(self):
        job_id = jobs.submit("search", {"n": 2}, lambda req: {"doubled": req["n"] * 2})
        job = _wait_for(job_id, self.tmp.name)
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["result"], {"doubled": 4})
        self.assertIsNone(job["error"])
        self.assertIsNotNone(job["started_at"])
        self.assertIsNotNone(job["finished_at"])

    def test_job_failure_carries_the_public_message_and_status(self):
        def runner(_req):
            raise jobs.JobFailure("GHSA fetch failed.", 502)

        job_id = jobs.submit("search", {}, runner)
        job = _wait_for(job_id, self.tmp.name)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["error"], "GHSA fetch failed.")
        self.assertEqual(job["error_status"], 502)
        self.assertIsNone(job["result"])

    def test_unexpected_exception_is_not_leaked_to_the_caller(self):
        """A job result is a response body; exception text does not belong in one."""
        def runner(_req):
            raise RuntimeError("connection to 10.0.0.5 failed: password=hunter2")

        job_id = jobs.submit("search", {}, runner)
        job = _wait_for(job_id, self.tmp.name)
        self.assertEqual(job["status"], "failed")
        self.assertNotIn("hunter2", job["error"])
        self.assertNotIn("10.0.0.5", job["error"])
        self.assertEqual(job["error_status"], 500)

    def test_public_view_hides_internals_and_unfinished_results(self):
        job_id = jobs.submit("search", {"secret": "in-request"}, lambda _r: {"ok": 1})
        job = _wait_for(job_id, self.tmp.name)
        view = jobs.public_view(job)
        self.assertEqual(view["result"], {"ok": 1})
        self.assertNotIn("request", view)   # the echo belongs in the result, not here
        self.assertNotIn("error", view)

        queued = {**job, "status": "running", "result": {"partial": True}}
        running_view = jobs.public_view(queued)
        self.assertNotIn("result", running_view)  # no partial results

    def test_a_failed_job_tells_the_poller_which_status_to_expect(self):
        """error_status was persisted, covered by a test named for it, and
        then dropped here -- so it never reached a client. app.py promises "a
        polled result is identical to a synchronous one", but the synchronous
        path answers a gh failure with 502 while this one answered 200 +
        {"status": "failed"} with no way to tell 400 (your query is wrong, do
        not retry) from 502/503 (upstream, back off)."""
        def runner(_req):
            raise jobs.JobFailure("GHSA fetch failed.", 502)

        job_id = jobs.submit("search", {}, runner)
        view = jobs.public_view(_wait_for(job_id, self.tmp.name))
        self.assertEqual(view["status"], "failed")
        self.assertEqual(view["error"], "GHSA fetch failed.")
        self.assertEqual(view["error_status"], 502)

    def test_polling_never_parses_the_stored_request(self):
        """Each row holds the whole submitted body, and public_view discards
        it, so parsing it made every poll a multi-megabyte json.loads for a
        field no response has ever carried. The raw text stays in the row."""
        cache.create_job("d" * 24, "search", {"categories": ["bac"]},
                         path=self.tmp.name)
        self.assertIsNone(_job("d" * 24, self.tmp.name)["request"])

    def _set_owner(self, job_id, owner):
        import sqlite3
        with sqlite3.connect(self.tmp.name) as conn:
            conn.execute("UPDATE jobs SET owner=? WHERE job_id=?", (owner, job_id))

    def test_orphaned_jobs_are_failed_on_startup(self):
        """A restart leaves rows mid-flight that nothing is executing any more.

        "Orphaned" means the process that accepted the job is gone, so the
        rows have to carry a dead owner -- creating them in this live process
        is the case startup() must now leave alone.
        """
        cache.create_job("a" * 24, "search", {}, path=self.tmp.name)
        cache.mark_job_running("a" * 24, path=self.tmp.name)
        cache.create_job("b" * 24, "search", {}, path=self.tmp.name)  # still queued
        # PID 2**22-1 is above the default pid_max, so it cannot be running.
        for job_id in ("a" * 24, "b" * 24):
            self._set_owner(job_id, "4194303-deadbeef")

        failed = jobs.startup(path=self.tmp.name)
        self.assertEqual(failed, 2)
        for job_id in ("a" * 24, "b" * 24):
            job = _job(job_id, self.tmp.name)
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["error_status"], 503)
            self.assertIn("restart", job["error"].lower())

    def test_a_second_worker_does_not_kill_a_live_workers_job(self):
        """jobs rows are shared process-wide; the worker pool is not. The
        unqualified UPDATE meant a second gunicorn worker booting 200ms after
        the first marked the first's in-flight job "failed -- server
        restarted". The poller resubmitted, then the original worker's own
        finish_job flipped the same row to "done": one job, two terminal
        states, on every respawn."""
        cache.create_job("c" * 24, "search", {}, path=self.tmp.name)
        cache.mark_job_running("c" * 24, path=self.tmp.name)
        # Owned by a process that is very much alive: this one.
        failed = jobs.startup(path=self.tmp.name)
        self.assertEqual(failed, 0)
        self.assertEqual(
            _job("c" * 24, self.tmp.name)["status"], "running")

    def test_a_job_with_no_owner_is_still_reconciled(self):
        """Rows written before the owner column existed."""
        cache.create_job("d" * 24, "search", {}, path=self.tmp.name)
        self._set_owner("d" * 24, None)
        self.assertEqual(jobs.startup(path=self.tmp.name), 1)

    def test_a_very_old_job_is_reconciled_even_if_its_pid_looks_alive(self):
        """Backstop for a recycled PID: in a container the next boot starts
        from low PIDs, so a dead worker's id can be worn by a live process."""
        cache.create_job("e" * 24, "search", {}, path=self.tmp.name)
        cache.mark_job_running("e" * 24, path=self.tmp.name)
        import sqlite3
        with sqlite3.connect(self.tmp.name) as conn:
            conn.execute("UPDATE jobs SET created_at=? WHERE job_id=?",
                         (time.time() - cache.STALE_JOB_SECONDS - 60, "e" * 24))
        self.assertEqual(jobs.startup(path=self.tmp.name), 1)

    def test_startup_leaves_finished_jobs_alone(self):
        job_id = jobs.submit("search", {}, lambda _r: {"ok": 1})
        _wait_for(job_id, self.tmp.name)
        jobs.startup(path=self.tmp.name)
        self.assertEqual(_job(job_id, self.tmp.name)["status"], "done")

    def test_prune_drops_finished_jobs_only(self):
        done = jobs.submit("search", {}, lambda _r: {"ok": 1})
        _wait_for(done, self.tmp.name)
        cache.create_job("c" * 24, "search", {}, path=self.tmp.name)  # unfinished

        removed = cache.prune_jobs(-1, path=self.tmp.name)  # everything is "old"
        self.assertEqual(removed, 1)
        self.assertIsNone(cache.get_job(done, path=self.tmp.name))
        self.assertIsNotNone(cache.get_job("c" * 24, path=self.tmp.name))

    def test_malformed_job_id_is_not_found_without_a_query(self):
        for bad in ("", "nothex", "../../etc/passwd", "a" * 23, "A" * 24, 42):
            with self.subTest(job_id=bad):
                # The int in that list is the wrong type on purpose: an id that
                # is not a str must be rejected like any other malformed one.
                # `is None` alone is what a valid-but-absent id returns
                # too. The point of the guard is that a malformed id never
                # reaches the database at all.
                with mock.patch.object(cache, "get_job") as queried:
                    self.assertIsNone(jobs.get(cast(Any, bad), path=self.tmp.name))
                queried.assert_not_called()

    def test_job_ids_are_unguessable(self):
        ids = {jobs.new_job_id() for _ in range(200)}
        self.assertEqual(len(ids), 200)
        self.assertTrue(all(len(i) == jobs.JOB_ID_BYTES * 2 for i in ids))



class TestAJobAlwaysReachesATerminalState(unittest.TestCase):
    """A job stuck in `queued` or `running` is a poller that waits forever.

    fail_orphaned_jobs only runs at process start, so nothing rescues a
    stranded row on a live server.
    """

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = self.tmp.name
        cache.init_db(self.db)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.db + suffix):
                os.unlink(self.db + suffix)

    def _run_sync(self, job_id, request, runner):
        jobs._run(job_id, request, runner, self.db)
        return _job(job_id, self.db)

    def test_a_job_that_cannot_be_marked_running_is_failed_not_abandoned(self):
        """This branch used to log and return, leaving the row in `queued`
        with the runner never executed and nothing telling the caller."""
        job_id = jobs.new_job_id()
        cache.create_job(job_id, "search", {}, path=self.db)
        ran = []
        with mock.patch.object(cache, "mark_job_running",
                               side_effect=sqlite3.OperationalError("database is locked")):
            row = self._run_sync(job_id, {}, lambda req: ran.append(1))
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error_status"], 503)
        self.assertEqual(ran, [], "the runner must not have executed")

    def test_a_failure_to_record_success_does_not_raise_out_of_the_worker(self):
        job_id = jobs.new_job_id()
        cache.create_job(job_id, "search", {}, path=self.db)
        with mock.patch.object(cache, "finish_job",
                               side_effect=sqlite3.OperationalError("disk I/O error")):
            # Must not raise out of the worker; the Future holds nobody.
            jobs._run(job_id, {}, lambda req: {"ok": True}, self.db)
        self.assertEqual(_job(job_id, self.db)["status"], "running")

    def test_a_normal_job_still_completes(self):
        job_id = jobs.new_job_id()
        cache.create_job(job_id, "search", {}, path=self.db)
        row = self._run_sync(job_id, {"q": 1}, lambda req: {"count": 7})
        self.assertEqual(row["status"], "done")
        self.assertEqual(row["result"]["count"], 7)

    def test_a_job_failure_keeps_its_status(self):
        job_id = jobs.new_job_id()
        cache.create_job(job_id, "search", {}, path=self.db)

        def runner(req):
            raise jobs.JobFailure("GHSA fetch failed.", status=502)

        row = self._run_sync(job_id, {}, runner)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error_status"], 502)


class TestFinishedJobsArePruned(unittest.TestCase):
    """docs/api.md, docs/automation.md and docs/configuration.md all promise
    retention-based pruning. It ran only in startup(), so the shipped
    deployment -- one gunicorn worker in a long-lived container -- never
    pruned at all, and every row stores a full search payload."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = self.tmp.name
        cache.init_db(self.db)
        jobs._last_prune = float("-inf")

    def tearDown(self):
        # Shut the pool down first: without this the worker thread outlived
        # the class, still holding the database file tearDown then unlinked,
        # and it was alive during the next class's global clock patch --
        # where a stray time.monotonic() raises StopIteration off a
        # side_effect list.
        jobs.shutdown(wait=True)
        jobs.resume()
        jobs._last_prune = float("-inf")
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.db + suffix):
                os.unlink(self.db + suffix)

    def test_submitting_prunes_old_finished_jobs(self):
        stale = jobs.new_job_id()
        cache.create_job(stale, "search", {}, path=self.db)
        cache.finish_job(stale, result={"count": 0}, path=self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE jobs SET created_at = ?, finished_at = ?",
                         (time.time() - 90000, time.time() - 90000))

        with mock.patch.dict(os.environ, {"VULNSIGHT_JOB_RETENTION": "3600"}):
            jobs.submit("search", {}, lambda req: {"count": 1}, path=self.db)
        # No sleep: _prune runs synchronously inside submit(), before the
        # work reaches the pool, so the row is already gone when submit
        # returns. The 0.3s wait was pure latency pretending to be a
        # synchronisation point.
        self.assertIsNone(cache.get_job(stale, path=self.db))

    def test_pruning_is_rate_limited_not_run_on_every_submission(self):
        calls = []
        with mock.patch.object(cache, "prune_jobs", side_effect=lambda *a, **k: calls.append(1)):
            for _ in range(5):
                jobs._prune(self.db)
        self.assertEqual(len(calls), 1)

    def test_a_freshly_booted_host_still_prunes(self):
        """`_last_prune` is compared against time.monotonic(), whose zero is
        the host's boot rather than the epoch. It was initialised to 0.0,
        which therefore meant "pruned at boot" -- so a worker starting on a
        machine that had been up less than an hour skipped pruning for its
        whole first hour, and these very tests failed on a rebooted laptop
        while passing everywhere else."""
        # Read the source, not the attribute: setUp has already assigned
        # this module global, so asserting on it here would pass whatever
        # the module initialises it to.
        source = pathlib.Path(jobs.__file__).read_text(encoding="utf-8")
        self.assertIn(
            '_last_prune = float("-inf")', source,
            "the module's sentinel must mean 'never pruned', not 'at boot'")
        self.assertNotIn("_last_prune = 0.0", source)

        calls = []
        with mock.patch.object(jobs.time, "monotonic", return_value=5.0), \
                mock.patch.object(cache, "prune_jobs",
                                  side_effect=lambda *a, **k: calls.append(1)):
            jobs._last_prune = float("-inf")
            jobs._prune(self.db)          # 5 seconds after boot
        self.assertEqual(calls, [1],
                         "a worker five seconds into a boot must still prune")

    def test_the_interval_still_holds_once_something_has_been_pruned(self):
        """The other half: having pruned, it must not prune again for an
        hour, or every submission pays for a scan of the jobs table."""
        calls = []
        with mock.patch.object(jobs.time, "monotonic", side_effect=[10.0, 20.0]), \
                mock.patch.object(cache, "prune_jobs",
                                  side_effect=lambda *a, **k: calls.append(1)):
            jobs._last_prune = float("-inf")
            jobs._prune(self.db)          # prunes, records monotonic 10
            jobs._prune(self.db)          # 10s later: far inside the interval
        self.assertEqual(calls, [1])

    def test_a_pruning_failure_never_fails_the_submission(self):
        with mock.patch.object(cache, "prune_jobs",
                               side_effect=sqlite3.OperationalError("locked")):
            jobs._prune(self.db, force=True)   # must not raise


class TestTheQueueHasABottom(unittest.TestCase):
    """ThreadPoolExecutor's work queue is unbounded and the pool is one
    worker by design, and `submit` never looked at the depth. The search
    limiter allows 30 submissions a minute and an NVD search takes minutes
    each, so a loop or a careless script left thousands of rows queued --
    every POST still answering 202 with a poll URL that would not resolve
    for days. There is no cancellation, so the only way out was a restart,
    which then failed all of them at once."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self._orig = cache.DB_PATH
        cache.DB_PATH = self.tmp.name
        cache.init_db(cache.DB_PATH)

    def tearDown(self):
        jobs.shutdown(wait=True)
        jobs.resume()
        cache.DB_PATH = self._orig
        for ext in ("", "-wal", "-shm"):
            with contextlib.suppress(OSError):
                os.unlink(self.tmp.name + ext)

    def test_a_submission_past_the_depth_is_refused_with_503(self):
        for n in range(jobs.MAX_UNFINISHED_JOBS):
            cache.create_job(f"job{n}", "search", {}, path=cache.DB_PATH)
        with self.assertRaises(jobs.JobFailure) as caught:
            jobs.submit("search", {}, lambda req: None, path=cache.DB_PATH)
        self.assertEqual(caught.exception.status, 503)
        self.assertIn("queued", caught.exception.public_message)

    def test_the_refusal_does_not_create_a_row_nobody_will_ever_poll(self):
        for n in range(jobs.MAX_UNFINISHED_JOBS):
            cache.create_job(f"job{n}", "search", {}, path=cache.DB_PATH)
        before = cache.count_unfinished_jobs(cache.DB_PATH)
        with contextlib.suppress(jobs.JobFailure):
            jobs.submit("search", {}, lambda req: None, path=cache.DB_PATH)
        self.assertEqual(cache.count_unfinished_jobs(cache.DB_PATH), before)

    def test_a_normal_submission_below_the_depth_still_works(self):
        job_id = jobs.submit("search", {}, lambda req: {"ok": True},
                             path=cache.DB_PATH)
        self.assertTrue(job_id)

    def test_finished_jobs_do_not_count_against_the_depth(self):
        """Otherwise the queue fills permanently after enough searches."""
        for n in range(jobs.MAX_UNFINISHED_JOBS + 10):
            cache.create_job(f"done{n}", "search", {}, path=cache.DB_PATH)
            cache.finish_job(f"done{n}", result={"ok": True}, path=cache.DB_PATH)
        self.assertEqual(cache.count_unfinished_jobs(cache.DB_PATH), 0)
        self.assertTrue(jobs.submit("search", {}, lambda req: None,
                                    path=cache.DB_PATH))


class TestTheStopSignalIsNotAOneWayLatch(unittest.TestCase):
    """`shutdown()` raises a process-wide stop signal that long fetch loops
    poll between upstream calls, so `docker stop` does not have to mean
    SIGKILL. Nothing withdrew it.

    That was read asymmetrically by the two halves of the system. Queued
    work came back on its own -- `_pool()` builds a fresh pool, so a job
    submitted after a shutdown ran normally -- while `/api/search`, which
    runs the pipeline inline and never touches the pool, polled the same
    flag and stopped at its first CWE. A process that survived a shutdown
    request would therefore keep accepting searches and answer every one
    of them with an empty result set marked `timed_out`, indefinitely.

    In the suite it showed up as five NVD tests that passed alone and
    failed in a full run, because three tearDowns call `shutdown()` to
    dispose of the pool and the signal outlived them."""

    def tearDown(self):
        jobs.resume()

    def test_a_fetch_loop_stops_when_shutdown_is_requested(self):
        """The signal has to work, or the rest of this is moot."""
        jobs.resume()
        self.assertFalse(jobs.shutting_down())
        jobs.shutdown(wait=True)
        self.assertTrue(jobs.shutting_down())

    def test_resume_withdraws_it(self):
        jobs.shutdown(wait=True)
        jobs.resume()
        self.assertFalse(jobs.shutting_down())

    def test_the_inline_search_path_recovers_as_the_pool_does(self):
        """The asymmetry itself: submitting a job used to revive one half
        of the system and leave the other half stopped."""
        from modules import nvd_client

        jobs.shutdown(wait=True)
        self.assertTrue(nvd_client._shutting_down(),
                        "precondition: the fetch loop sees the signal")

        # Whatever brings the queue back must bring the inline path back
        # too -- they read one flag, so they cannot disagree about it.
        jobs.resume()
        self.assertFalse(
            nvd_client._shutting_down(),
            "the inline pipeline is still stopped while the pool is live")

    def test_disposing_of_the_pool_in_a_teardown_leaves_the_process_usable(self):
        """What the three tearDowns actually do, asserted end to end: a
        later NVD fetch must return its records rather than nothing."""
        from modules import nvd_client

        jobs.shutdown(wait=True)   # as test_app / test_jobs / test_openapi do
        jobs.resume()

        fetched: list[str] = []

        def fake_fetch(cwe, params):
            fetched.append(cwe)
            return []

        report: dict = {}
        with mock.patch.object(nvd_client, "_fetch_cves_for_cwe", fake_fetch), \
             mock.patch.object(nvd_client, "_request_delay", lambda: 0.0):
            nvd_client.fetch_nvd(
                nvd_client.NvdSearchParams(cwes=["79", "89"]), report=report)

        self.assertEqual(fetched, ["79", "89"],
                         "the fetch loop stopped although nothing is stopping")
        self.assertFalse(report.get("timed_out"),
                         "the search reported a shutdown that is over")


if __name__ == "__main__":
    unittest.main(verbosity=2)
