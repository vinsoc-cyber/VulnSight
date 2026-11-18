"""Maintenance tools, importable so the tests can drive them.

Each is a standalone script with a `main(argv)` that returns an exit code --
`tests/test_docs.py` runs the --check mode of the doc generators against the
shipped docs, so a doc that has drifted fails the suite rather than waiting
for someone to remember to run the script.
"""

from __future__ import annotations

import contextlib
import os
import pathlib
import tempfile


def write_atomic(path: pathlib.Path, text: str) -> None:
    """Replace *path*'s contents, or leave them exactly as they were.

    Every generator here rewrites a file in place. `Path.write_text`
    truncates first and writes second, so an interruption between the two
    -- a full disk, a Ctrl-C, an OOM kill -- leaves a half-written file.
    For `modules/cwe_catalog.py` that file is one the running server
    imports, and the next start fails on a SyntaxError in generated code
    nobody edited.

    Write beside the target and rename: on POSIX the rename is atomic, so a
    reader sees either the old file or the new one and never a partial one.
    The temp file goes in the same directory because rename is only atomic
    within a filesystem.
    """
    path = pathlib.Path(path)
    handle, tmp = tempfile.mkstemp(dir=str(path.parent),
                                   prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
