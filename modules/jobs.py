"""Background jobs, so a long search is not an HTTP round trip.

A search that includes NVD sleeps ~6.5 s per CWE to stay inside the unauthenticated
rate limit. With extended CWEs enabled a single query resolves to well over a
hundred of them, which is minutes of wall clock before any HTTP client's default
timeout — the request is not slow, it is un-completable. Submitting it as a job
lets a script poll a cheap endpoint instead of holding a socket open and hoping.

State lives in SQLite (see cache.py, migration v5) rather than in memory. That is
not for durability of the *work* — the work dies with the process — but for
durability of the *fact*: a job orphaned by a restart is still visible, and is
reported failed rather than leaving a poller waiting on something that will never
finish.

Known limits, both documented in docs/automation.md rather than discovered:

- **Execution is pinned to the process that accepted the job.** The pool is
  in-process. Job rows are shared, so polling works from any worker, but with
  gunicorn ``--workers`` above 1 the work itself only runs where it was
  submitted. The shipped Dockerfile uses one worker.
- **There is no cancellation.** Python cannot interrupt a thread blocked in
  ``time.sleep``, and the fetch loop has no cancellation points, so a running job
  runs to completion or until the process exits.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import cache
from .security import env_int

logger = logging.getLogger(__name__)

JOB_ID_BYTES = 12
_JOB_ID_RE = re.compile(rf"[0-9a-f]{{{JOB_ID_BYTES * 2}}}")
#: Finished jobs are dropped after this long. Long enough that a cron run which
#: polls slowly still finds its result; short enough that the table stays small.
DEFAULT_RETENTION_SECONDS = 24 * 3600

_POOL: ThreadPoolExecutor | None = None
_POOL_LOCK = threading.Lock()


def _pool() -> ThreadPoolExecutor:
    """One shared pool, created on first use.

    Defaults to a single worker on purpose: the sources are rate-limited per
    *account*, not per request, so running searches concurrently would spend the
    same NVD and GitHub budget faster without finishing any job sooner.
    """
    global _POOL
    with _POOL_LOCK:
        if _POOL is None:
            workers = max(1, min(8, env_int("VULNSIGHT_JOB_WORKERS", 1)))
            _POOL = ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="vulnsight-job"
            )
            logger.info("Job pool started with %d worker(s)", workers)
        return _POOL


def new_job_id() -> str:
    return secrets.token_hex(JOB_ID_BYTES)


def startup(path: str | None = None) -> int:
    """Reconcile jobs left behind by a previous process. Returns how many."""
    orphaned = cache.fail_orphaned_jobs(
        "Server restarted while this job was in flight; resubmit it.", path=path
    )
    if orphaned:
        logger.warning("Failed %d job(s) orphaned by a restart", orphaned)
    _prune(path, force=True)
    return orphaned


# Pruning ran only here, at process start. docs/api.md, docs/automation.md and
# docs/configuration.md all state that finished jobs are removed after
# VULNSIGHT_JOB_RETENTION -- but the shipped deployment is one gunicorn worker
# in a container that runs for weeks, so in practice nothing ever pruned. Each
# row stores the full search payload, including every advisory's
# source_records, so a nightly cron doing one max_results=500 sweep grew
# advisories.db without bound. The table already carries idx_jobs_created for
# a query that was never issued on a live process.
_PRUNE_INTERVAL_SECONDS = 3600.0
_last_prune = 0.0
_prune_lock = threading.Lock()


def _prune(path: str | None, *, force: bool = False) -> None:
    """Prune finished jobs, at most once an hour unless *force*."""
    global _last_prune
    now = time.monotonic()
    with _prune_lock:
        if not force and (now - _last_prune) < _PRUNE_INTERVAL_SECONDS:
            return
        _last_prune = now
    try:
        cache.prune_jobs(
            env_int("VULNSIGHT_JOB_RETENTION", DEFAULT_RETENTION_SECONDS), path=path
        )
    except Exception:
        # Housekeeping must never be the reason a submission fails.
        logger.exception("Could not prune finished jobs")


def submit(kind: str, request: dict, runner, path: str | None = None) -> str:
    """Persist a job, queue *runner*, and return the id to poll.

    *runner* takes the request dict and returns the JSON-serialisable payload
    that becomes the job's result. Raising ``JobFailure`` reports an
    operator-facing message with a chosen HTTP status; any other exception is
    logged in full and reported generically, because a job result is a response
    body and exception text is not safe to put in one.
    """
    job_id = new_job_id()
    cache.create_job(job_id, kind, request, path=path)
    _prune(path)
    _pool().submit(_run, job_id, request, runner, path)
    return job_id


class JobFailure(Exception):
    """A failure with a message that is safe to hand back to the caller."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.public_message = message
        self.status = status


def _finish(job_id: str, path: str | None, **outcome) -> None:
    """Record a terminal state, and never let that recording be what fails.

    finish_job was called bare in all three branches. If it raised -- SQLite
    "database is locked" past the busy timeout, a full disk, a non-serialisable
    field creeping into a normalized record -- the exception was captured by a
    Future nobody holds, the row stayed `running`, and because
    fail_orphaned_jobs only runs at process start, a poller on a live server
    waited for it forever.
    """
    try:
        cache.finish_job(job_id, path=path, **outcome)
    except Exception:
        logger.exception("Could not record terminal state for job %s", job_id)


def _run(job_id: str, request: dict, runner, path: str | None) -> None:
    try:
        cache.mark_job_running(job_id, path=path)
    except Exception:
        # This branch used to return without recording anything, so the job
        # sat in `queued` forever: the runner never executed and nothing ever
        # told the caller. Failing to start is itself a terminal state.
        logger.exception("Could not mark job %s running", job_id)
        _finish(job_id, path, error="Job could not be started. See server logs.",
                error_status=503)
        return
    try:
        result = runner(request)
    except JobFailure as e:
        _finish(job_id, path, error=e.public_message, error_status=e.status)
    except Exception:
        # Full detail to the log, a generic message to the caller: the same
        # split the HTTP handlers make, for the same reason.
        logger.exception("Job %s failed", job_id)
        _finish(job_id, path, error="Job failed. See server logs.", error_status=500)
    else:
        _finish(job_id, path, result=result)


def get(job_id: str, path: str | None = None) -> dict | None:
    """Look up a job. Malformed ids are "not found", never a database round trip."""
    if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
        return None
    return cache.get_job(job_id, path=path)


def public_view(job: dict) -> dict:
    """The job as a client should see it: no internals, no partial results."""
    view = {
        "job_id": job["job_id"],
        "kind": job["kind"],
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
    }
    if job["status"] == "done":
        view["result"] = job["result"]
    elif job["status"] == "failed":
        view["error"] = job["error"]
    return view


def shutdown(wait: bool = False) -> None:
    """Release the pool. Used by tests; the process exit handles the real case."""
    global _POOL
    with _POOL_LOCK:
        pool, _POOL = _POOL, None
    if pool is not None:
        pool.shutdown(wait=wait)
