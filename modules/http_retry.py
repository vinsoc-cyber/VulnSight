"""One retry policy for every upstream this tool talks to.

Four clients, four different answers to the same question:

    ai_classifier   a full implementation -- a retryable-status set, both
                    Retry-After forms, exponential backoff with jitter
    ghsa_client     no retry at all; one flaky page discarded the pages
                    already fetched and reported the whole source failed
    nvd_client      no retry, and every 403 reported as "rate limited" even
                    though NVD also returns 403 for an invalid key
    epss_client     swallowed everything and returned {}

So a GitHub 502 on page 3 of 5 lost 200 advisories, while the same class of
failure against the AI provider was retried three times with backoff. This
module is that policy, stated once. The AI-specific parts -- key rotation,
quota parsing, cooldown persistence -- stay in ai_classifier, because they
are about credentials rather than about HTTP.

Jitter matters here beyond politeness: a search fans out one request per CWE,
so a synchronised retry storm is exactly what a rate-limited upstream would
see without it.
"""

from __future__ import annotations

import logging
import random
import time
import urllib.error
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# 429 and the gateway family. 408/409/425 are retryable per RFC 9110; 520/522/
# 524 are Cloudflare; 529 is Anthropic's overloaded_error. A 4xx that is not
# in here means "your request is wrong" and retrying it only wastes quota.
RETRYABLE_STATUS = frozenset(
    {408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529}
)

DEFAULT_ATTEMPTS = 3
DEFAULT_BASE_DELAY = 1.5
# No upstream gets to hold a request open for longer than this on one wait,
# however generous its Retry-After is. The caller is a browser or a cron job.
MAX_BACKOFF = 60.0


def parse_retry_after(value: str | None) -> float | None:
    """Seconds from a Retry-After header, in either of its two forms.

    The server states exactly how long to wait; guessing short wastes a
    request, guessing long stalls one that would already have succeeded.
    """
    if not value:
        return None
    text = str(value).strip()
    try:
        return max(0.0, float(text))              # delta-seconds form
    except ValueError:
        pass
    try:                                           # HTTP-date form
        from email.utils import parsedate_to_datetime

        when = parsedate_to_datetime(text)
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError):
        return None


def backoff_delay(attempt: int, base: float = DEFAULT_BASE_DELAY) -> float:
    """Exponential backoff with jitter, for *attempt* counted from zero."""
    return min(MAX_BACKOFF, base * (2 ** min(attempt, 4))) + random.uniform(0, 0.6)


def status_of(exc: BaseException) -> int | None:
    """The HTTP status behind an exception, if it has one."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code
    return None


def is_retryable(exc: BaseException) -> bool:
    """True for a failure worth trying again.

    URLError without an HTTPError is a DNS/connection/timeout failure, which
    is transient by definition.
    """
    status = status_of(exc)
    if status is not None:
        return status in RETRYABLE_STATUS
    return isinstance(exc, (urllib.error.URLError, TimeoutError, OSError))


def retry_after_of(exc: BaseException) -> float | None:
    """Retry-After from an HTTPError's headers, honoured for 429 only.

    Deliberately not for the other retryable statuses: a 503 carrying a
    generous Retry-After would otherwise stall a request far longer than
    plain backoff, and the 503 is usually gone by the next attempt.
    """
    if not isinstance(exc, urllib.error.HTTPError) or exc.code != 429:
        return None
    headers = getattr(exc, "headers", None)
    if headers is None:
        return None
    try:
        return parse_retry_after(headers.get("Retry-After"))
    except Exception:
        return None


def with_retries(
    call: Callable[[], T],
    *,
    what: str,
    attempts: int = DEFAULT_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    deadline: float | None = None,
    retryable: Callable[[BaseException], bool] = is_retryable,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Run *call*, retrying transient failures.

    *deadline* is a time.monotonic() instant: once passed, no further attempt
    is started. Pagination needs it, because a per-attempt timeout multiplied
    by pages and retries is otherwise unbounded -- the GHSA client's 50-page
    guard times its 60s timeout is a 50-minute worst case inside one request.

    *retryable* decides which failures are worth another attempt. The default
    reads HTTP status; the GHSA client passes its own, because it talks to
    GitHub through the `gh` CLI and only ever sees a subprocess result.

    Re-raises the last exception when the budget runs out, so the caller's own
    error handling is unchanged.
    """
    last: BaseException | None = None
    for attempt in range(max(1, attempts)):
        if deadline is not None and attempt and time.monotonic() >= deadline:
            logger.warning("%s: out of time after %d attempt(s)", what, attempt)
            break
        try:
            return call()
        except Exception as exc:                      # re-raised below
            last = exc
            if not retryable(exc) or attempt == attempts - 1:
                raise
            advised = retry_after_of(exc)
            delay = advised if advised is not None else backoff_delay(attempt, base_delay)
            delay = min(delay, MAX_BACKOFF)
            if deadline is not None and time.monotonic() + delay >= deadline:
                logger.warning("%s: retry would exceed the deadline", what)
                raise
            logger.info("%s: attempt %d/%d failed (%s); retrying in %.1fs",
                        what, attempt + 1, attempts, exc, delay)
            sleep(delay)
    assert last is not None
    raise last
