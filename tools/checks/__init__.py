"""Revert checks, grouped by the part of the system they defend.

One entry is::

    (label, [(file, find, replace), ...], test_module)

`label` names the bug in the words of the defect, not the fix. The edits are
applied together and must put the *original bug* back -- a fix that is
guarded in two places needs both halves in one entry, or reverting either
alone leaves the behaviour correct and the check reports a false pass.
`test_module` is the tests/ file (without .py) that should go red.

Adding a group: create a module here exporting `CHECKS` and list it below.
Separate modules keep concurrent work from colliding in one long list.
"""

from __future__ import annotations

from . import cleanup
from . import core
from . import frontend
from . import hardening
from . import hardening2
from . import runtime
from . import search

Edit = tuple[str, str, str]
Check = tuple[str, list[Edit], str]

GROUPS: dict[str, list[Check]] = {
    "core": core.CHECKS,
    "runtime": runtime.CHECKS,
    "search": search.CHECKS,
    "frontend": frontend.CHECKS,
    "cleanup": cleanup.CHECKS,
    "hardening": hardening.CHECKS,
    "hardening2": hardening2.CHECKS,
}


def all_checks() -> list[Check]:
    """Every check, in group order, with duplicate labels rejected."""
    out: list[Check] = []
    seen: set[str] = set()
    for name, checks in GROUPS.items():
        for check in checks:
            label = check[0]
            if label in seen:
                raise ValueError(f"duplicate check label in {name}: {label!r}")
            seen.add(label)
            out.append(check)
    return out
