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
import shutil
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

    Two details the first version got wrong:

    *Permissions.* `mkstemp` creates at 0600 and `os.replace` carries the
    temp file's mode, not the target's -- so every file this touched was
    silently narrowed to 0600. Verified: a 0644 file came back 0600. Git
    tracks only the +x bit, so the change was invisible in review, and
    anything reading those files as a different UID -- a CI runner, a
    bind-mounted docs server, a build container -- got EACCES on a file
    nobody knowingly changed.

    *Durability.* Neither the data nor the directory entry was flushed, so
    the docstring's crash-safety claim held for Ctrl-C and an OOM kill but
    not for power loss: a rename without an fsync can surface as a
    zero-length file.
    """
    path = pathlib.Path(path)
    handle, tmp = tempfile.mkstemp(dir=str(path.parent),
                                   prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        # The target's mode if it exists, else the umask default, rather
        # than mkstemp's private 0600.
        if path.exists():
            shutil.copymode(path, tmp)
        else:
            os.chmod(tmp, 0o666 & ~_umask())
        os.replace(tmp, path)
        # The rename itself is only durable once the directory entry is.
        with contextlib.suppress(OSError):
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _umask() -> int:
    """The process umask, read without leaving it changed."""
    current = os.umask(0o022)
    os.umask(current)
    return current
