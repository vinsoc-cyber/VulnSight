"""Turning upstream records into the shared advisory shape, one at a time.

GHSA, NVD and OSV all answer with records whose shape their APIs do not
guarantee: a null where an object was promised, a bare string in a list of
objects, a score of ``"N/A"``. Normalizing a whole page with a list
comprehension makes every one of those fatal for the *entire* search, because
the resulting ``AttributeError``/``TypeError`` is not the module's own error
type and so slips past the per-source degradation handling in
``search_service.run_search`` and out through ``app.py`` as a 500.

OSV learned this first (one bad member of a 226,880-record export must not be
all-or-nothing). This module is that lesson in one place, so the three clients
degrade the same way instead of three different ways.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def normalize_all(
    items: Iterable[T],
    normalize: Callable[[T], dict],
    *,
    source: str,
    identify: Callable[[T], str] | None = None,
) -> tuple[list[dict], int]:
    """Normalize *items*, skipping any single record that cannot be read.

    Returns ``(records, skipped)``. A skipped record is logged at DEBUG with
    whatever identifier *identify* can recover; the caller is expected to
    surface the count, because silently returning a short list is the failure
    mode this whole tool exists to avoid.
    """
    records: list[dict] = []
    skipped = 0
    for item in items:
        try:
            records.append(normalize(item))
        except Exception:
            skipped += 1
            name = ""
            if identify is not None:
                try:
                    name = identify(item)
                except Exception:
                    name = ""
            logger.debug("skipping unusable %s record %s", source, name or "<unidentified>")
    if skipped:
        logger.warning(
            "Skipped %d unusable %s record(s) of %d", skipped, source, skipped + len(records)
        )
    return records, skipped


def identify(item: Any, *keys: str) -> str:
    """Best-effort id for a log line; never raises on a malformed record."""
    if isinstance(item, dict):
        for key in keys:
            value = item.get(key)
            if isinstance(value, str) and value:
                return value
    return ""
