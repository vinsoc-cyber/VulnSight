"""Tiny SQLite cache for advisories and AI classifications.

Two tables:
  advisories        - normalized advisory record (raw JSON), keyed by advisory_id
  ai_classification - AI verdict per (advisory_id, category), so re-running a
                      search does not re-spend AI tokens on the same advisory.

The cache is optional: the app works without it, it just re-fetches. Keeping
it makes the UI snappy and the AI pass cheap on repeat searches.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager

from .config import DATA_DIR

DB_PATH = os.path.join(DATA_DIR, "advisories.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT PRIMARY KEY,
    cve_id      TEXT,
    severity    TEXT,
    data        TEXT NOT NULL,          -- normalized record as JSON
    fetched_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_classification (
    advisory_id TEXT NOT NULL,
    category    TEXT NOT NULL,
    is_match    INTEGER NOT NULL,       -- 0/1
    confidence  REAL NOT NULL,          -- 0..1
    vuln_type   TEXT,
    reason      TEXT,
    model       TEXT,
    fingerprint TEXT,
    created_at  REAL NOT NULL,
    PRIMARY KEY (advisory_id, category)
);
"""
# No index on advisories(cve_id): nothing filters, joins or orders by it. Every
# read of this table is either `WHERE advisory_id = ?` (served by the primary
# key) or `COUNT(*)`. The index only cost a write on every upsert. The column
# stays -- docs/operations.md shows operators querying it by hand.

# ---------------------------------------------------------------------------
# Schema migrations — append-only list of (version, sql) tuples.
# Each sql string may contain multiple semicolon-separated statements.
# ---------------------------------------------------------------------------
_MIGRATIONS = [
    # v1: base schema (advisories + ai_classification + indexes)
    (1, _SCHEMA),
    # v2: add fingerprint column to ai_classification
    (2, "ALTER TABLE ai_classification ADD COLUMN fingerprint TEXT"),
    # v3: rename ghsa_id -> advisory_id (source-neutral primary key)
    (3, "ALTER TABLE advisories RENAME COLUMN ghsa_id TO advisory_id;"
        "ALTER TABLE ai_classification RENAME COLUMN ghsa_id TO advisory_id"),
    # v4: v3 renamed the *column* but left the stored JSON alone, so rows written
    # before it carry no advisory_id inside `data`. Anything that reads a cached
    # record back — the AI batch in particular — then has no id to key the result
    # by. Backfill from the primary key, which is authoritative. Idempotent.
    (4, "UPDATE advisories"
        "   SET data = json_set(data, '$.advisory_id', advisory_id)"
        " WHERE json_valid(data)"
        "   AND COALESCE(json_extract(data, '$.advisory_id'), '') = ''"),
    # v5: background jobs. A search that spans NVD spends minutes in rate-limit
    # sleeps, which is longer than any default HTTP client timeout, so it has to
    # be submittable and pollable rather than held open on a socket. Stored
    # rather than kept in memory so a job orphaned by a restart is still
    # observable — and can be reported failed instead of hanging in `running`.
    (5, """CREATE TABLE IF NOT EXISTS jobs (
               job_id      TEXT PRIMARY KEY,
               kind        TEXT NOT NULL,
               status      TEXT NOT NULL,      -- queued|running|done|failed
               request     TEXT NOT NULL,      -- the submitted body, as JSON
               result      TEXT,               -- payload as JSON when done
               error       TEXT,               -- operator-facing message
               error_status INTEGER,           -- HTTP status the error maps to
               created_at  REAL NOT NULL,
               started_at  REAL,
               finished_at REAL
           );
           CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at)"""),
    # v6: owner. jobs rows are shared process-wide; the worker pool is not.
    # startup() issued an unqualified UPDATE over every queued/running row, so
    # a second gunicorn worker booting ~200ms after the first marked the
    # first's live job "failed -- server restarted", the poller resubmitted,
    # and then the original worker's own finish_job flipped the same row to
    # "done": one job reporting two terminal states. Same on every respawn.
    (6, "ALTER TABLE jobs ADD COLUMN owner TEXT"),
]


def _connect(path: str | None = None) -> sqlite3.Connection:
    # Resolve the module global at CALL time (not def time) so tests / callers
    # can repoint cache.DB_PATH and have every function honour it.
    conn = sqlite3.connect(path or DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


@contextmanager
def _db(path: str | None = None):
    """Connection scope: commit on success, rollback on error, always close.

    sqlite3.Connection's own context manager only manages the transaction —
    it never closes the connection — so this wrapper owns the full lifecycle.
    """
    conn = _connect(path)
    try:
        with conn:          # transaction scope (commit/rollback)
            yield conn
    finally:
        conn.close()


# Re-running a migration is expected (the version table can be behind while
# the objects already exist), and SQLite reports those as OperationalError
# just like a genuine failure. These are the messages that mean "already
# done"; everything else is a real problem and must not be swallowed.
_BENIGN_MIGRATION_ERRORS = (
    "duplicate column name",        # ALTER TABLE ADD COLUMN, re-run
    "already exists",               # CREATE TABLE/INDEX without IF NOT EXISTS
    "no such column",               # RENAME COLUMN, re-run (old name is gone)
)


def _is_benign_migration_error(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _BENIGN_MIGRATION_ERRORS)


def init_db(path: str | None = None) -> None:
    """Create / migrate the database to the latest schema version."""
    db_path = path or DB_PATH
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with _db(db_path) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version ("
            "    version INTEGER NOT NULL"
            ")"
        )
        row = conn.execute(
            "SELECT MAX(version) AS v FROM schema_version"
        ).fetchone()
        current = row["v"] if row["v"] is not None else 0

        for version, sql in _MIGRATIONS:
            if version <= current:
                continue
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if not stmt:
                    continue
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError as exc:
                    # Only the re-run cases are benign, and they are named.
                    # Catching every OperationalError and stamping the version
                    # anyway meant a migration that failed for a *real* reason
                    # was recorded as applied and never retried: on a SQLite
                    # build without JSON1, v4's json_set() raises "no such
                    # function", so the advisory_id backfill silently never
                    # happened and the defect it exists to repair persisted
                    # forever. app.py is still patching around that downstream.
                    if not _is_benign_migration_error(str(exc)):
                        raise
            # Stamped only after every statement in the migration survived.
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (version,),
            )


# ---------------------------------------------------------------------------
# Advisories
# ---------------------------------------------------------------------------

def upsert_advisories(records: list[dict], path: str | None = None) -> None:
    if not records:
        return
    now = time.time()
    with _db(path) as conn:
        conn.executemany(
            """INSERT INTO advisories (advisory_id, cve_id, severity, data, fetched_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT(advisory_id) DO UPDATE SET
                 cve_id=excluded.cve_id,
                 severity=excluded.severity,
                 data=excluded.data,
                 fetched_at=excluded.fetched_at""",
            [
                (
                    r.get("advisory_id"),
                    r.get("cve_id"),
                    r.get("severity"),
                    json.dumps(r, ensure_ascii=False),
                    now,
                )
                for r in records
                if r.get("advisory_id")
            ],
        )


def get_advisory(advisory_id: str, path: str | None = None) -> dict | None:
    with _db(path) as conn:
        row = conn.execute(
            "SELECT data FROM advisories WHERE advisory_id=?", (advisory_id,)
        ).fetchone()
    return json.loads(row["data"]) if row else None


def get_advisories(advisory_ids, path: str | None = None) -> dict[str, dict]:
    """Read many advisories in one round trip.

    The caller used to loop over get_advisory, which opens a connection and
    issues `PRAGMA journal_mode=WAL` per id -- 100 connects, 100 pragmas and
    100 single-row queries for one classify request, before a single model
    call. The IN-clause is built from a placeholder count and every value is
    bound, so no identifier reaches the SQL text.
    """
    ids = list(dict.fromkeys(advisory_ids))
    if not ids:
        return {}
    found: dict[str, dict] = {}
    with _db(path) as conn:
        # SQLite's default parameter limit is 999; chunk so a large batch
        # cannot trip it.
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            placeholders = ",".join("?" * len(chunk))
            rows = conn.execute(
                # Only placeholders are interpolated; every value is bound.
                f"SELECT advisory_id, data FROM advisories "
                f"WHERE advisory_id IN ({placeholders})",
                chunk,
            ).fetchall()
            for row in rows:
                try:
                    found[row["advisory_id"]] = json.loads(row["data"])
                except (TypeError, ValueError):
                    continue          # one unreadable row must not sink the batch
    return found


def count_advisories(path: str | None = None) -> int:
    with _db(path) as conn:
        return conn.execute("SELECT COUNT(*) AS c FROM advisories").fetchone()["c"]


# ---------------------------------------------------------------------------
# AI classifications
# ---------------------------------------------------------------------------

def save_classification(
    advisory_id: str,
    category: str,
    verdict: dict,
    model: str,
    path: str | None = None,
    *,
    fingerprint: str | None = None,
) -> None:
    with _db(path) as conn:
        conn.execute(
            """INSERT INTO ai_classification
               (advisory_id, category, is_match, confidence, vuln_type, reason, model,
                fingerprint, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(advisory_id, category) DO UPDATE SET
                 is_match=excluded.is_match,
                 confidence=excluded.confidence,
                 vuln_type=excluded.vuln_type,
                 reason=excluded.reason,
                 model=excluded.model,
                 fingerprint=excluded.fingerprint,
                 created_at=excluded.created_at""",
            (
                advisory_id,
                category,
                1 if verdict.get("is_match") else 0,
                float(verdict.get("confidence", 0.0)),
                verdict.get("vuln_type"),
                verdict.get("reason"),
                model,
                fingerprint,
                time.time(),
            ),
        )


def _job_row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "job_id": row["job_id"],
        "kind": row["kind"],
        "status": row["status"],
        # Not parsed. public_view discards it and nothing else reads it, so
        # for a max_results=500 search this was a multi-megabyte json.loads
        # on every poll for a field no response has ever contained. The raw
        # text is still in the row for anyone who needs it.
        "request": None,
        "result": json.loads(row["result"]) if row["result"] else None,
        "error": row["error"],
        "error_status": row["error_status"],
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
    }


# Identifies this process for its lifetime. Jobs execute in the worker that
# accepted them, so a job is orphaned exactly when its owner is gone.
PROCESS_ID = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"

# A job whose owner still looks alive but which has been in flight far longer
# than any search can take is reconciled anyway. This is the backstop for a
# recycled PID -- in a container the next boot starts from low PIDs, so a dead
# worker's id can be worn by a live process.
STALE_JOB_SECONDS = 3 * 3600


def _owner_is_alive(owner: str | None, created_at: float, now: float) -> bool:
    """Is the process that accepted this job still running?

    Unqualified reconciliation was the bug: startup() failed *every*
    queued/running row, so a second gunicorn worker booting 200ms after the
    first marked the first's live job "failed -- server restarted". The
    poller resubmitted, then the original worker's own finish_job flipped the
    same row to "done" -- one job, two terminal states, on every respawn.

    Unsure counts as alive, because wrongly failing a running job is worse
    than leaving a dead one for the staleness backstop to catch.
    """
    if now - (created_at or 0) > STALE_JOB_SECONDS:
        return False
    if not owner:
        return False                      # written before v6: nobody owns it
    if owner == PROCESS_ID:
        return True                       # our own, from before this call
    pid_text = owner.split("-", 1)[0]
    if not pid_text.isdigit():
        return False
    try:
        os.kill(int(pid_text), 0)         # signal 0: liveness probe only
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                       # exists, owned by someone else
    except OSError:
        return True
    return True


def create_job(job_id: str, kind: str, request: dict, path: str | None = None) -> None:
    with _db(path) as conn:
        conn.execute(
            """INSERT INTO jobs (job_id, kind, status, request, created_at, owner)
               VALUES (?,?,'queued',?,?,?)""",
            (job_id, kind, json.dumps(request, ensure_ascii=False), time.time(),
             PROCESS_ID),
        )


def mark_job_running(job_id: str, path: str | None = None) -> None:
    with _db(path) as conn:
        conn.execute(
            "UPDATE jobs SET status='running', started_at=? WHERE job_id=?",
            (time.time(), job_id),
        )


def finish_job(
    job_id: str,
    *,
    result: dict | None = None,
    error: str | None = None,
    error_status: int | None = None,
    path: str | None = None,
) -> None:
    status = "failed" if error is not None else "done"
    with _db(path) as conn:
        conn.execute(
            """UPDATE jobs
                  SET status=?, result=?, error=?, error_status=?, finished_at=?
                WHERE job_id=?""",
            (
                status,
                json.dumps(result, ensure_ascii=False) if result is not None else None,
                error,
                error_status,
                time.time(),
                job_id,
            ),
        )


def get_job(job_id: str, path: str | None = None) -> dict | None:
    with _db(path) as conn:
        row = conn.execute(
            "SELECT * FROM jobs WHERE job_id=?", (job_id,)
        ).fetchone()
    return _job_row_to_dict(row) if row else None


def fail_orphaned_jobs(message: str, path: str | None = None) -> int:
    """Fail jobs left mid-flight by a dead process.

    Nothing is executing them any more — the worker pool lives in the process
    that died — so leaving them `queued`/`running` would strand every poller
    forever on a job that can never finish.
    """
    now = time.time()
    with _db(path) as conn:
        rows = conn.execute(
            "SELECT job_id, owner, created_at FROM jobs "
            "WHERE status IN ('queued','running')"
        ).fetchall()
        orphans = [
            row["job_id"] for row in rows
            if not _owner_is_alive(row["owner"], row["created_at"], now)
        ]
        if not orphans:
            return 0
        placeholders = ",".join("?" * len(orphans))
        cursor = conn.execute(
            f"""UPDATE jobs
                   SET status='failed', error=?, error_status=503, finished_at=?
                 WHERE job_id IN ({placeholders})""",
            (message, now, *orphans),
        )
        return cursor.rowcount or 0


def prune_jobs(max_age_seconds: float, path: str | None = None) -> int:
    """Drop finished jobs older than *max_age_seconds*; unfinished ones stay."""
    with _db(path) as conn:
        cursor = conn.execute(
            "DELETE FROM jobs WHERE finished_at IS NOT NULL AND finished_at < ?",
            (time.time() - max_age_seconds,),
        )
        return cursor.rowcount or 0


def get_classifications(
    advisory_ids: list[str],
    category: str,
    path: str | None = None,
    *,
    expected_fingerprints: dict[str, str] | None = None,
) -> dict[str, dict]:
    if not advisory_ids:
        return {}
    placeholders = ",".join("?" * len(advisory_ids))
    with _db(path) as conn:
        rows = conn.execute(
            f"""SELECT * FROM ai_classification
                WHERE category=? AND advisory_id IN ({placeholders})""",
            [category, *advisory_ids],
        ).fetchall()
    out: dict[str, dict] = {}
    for r in rows:
        if expected_fingerprints is not None:
            expected = expected_fingerprints.get(r["advisory_id"])
            if not expected or r["fingerprint"] != expected:
                continue
        out[r["advisory_id"]] = {
            "is_match": bool(r["is_match"]),
            "confidence": r["confidence"],
            "vuln_type": r["vuln_type"],
            "reason": r["reason"],
            "model": r["model"],
            "cached": True,
        }
    return out
