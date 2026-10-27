"""Writing a file so that nobody ever reads half of it."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path


def replace_text(path: Path, text: str) -> None:
    """Put ``text`` in the file ``path`` in one step, as UTF-8.

    The text goes to a temporary file in the same folder, which then takes the place
    of ``path``. Another process reads the old file or the new one, never a part of
    one. A write that fails or is interrupted leaves the old file as it was. Raises
    OSError when the file can't be written.
    """
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        # newline="\n": the same bytes on Windows as everywhere else.
        with open(tmp, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(tmp, path)
    finally:
        # Gone already when the write worked. Left behind when it failed.
        with contextlib.suppress(OSError):
            tmp.unlink()


def write_text(path: Path, text: str) -> None:
    """Put ``text`` in ``path``, through a symbolic link and in place for a device.

    A regular file is replaced by :func:`replace_text`, so a reader sees the old file
    or the new one. A path that resolves to something which is not a regular file — a
    device such as ``/dev/stdout`` or ``NUL``, a pipe, a socket — is written in place:
    it has no directory entry to swap, and a rename onto it either fails or replaces
    the device itself. A symbolic link is followed, so the file it names is updated
    and the link stays a link. Raises OSError when the file can't be written.
    """
    # realpath: a link is written through, as the baseline file already was.
    target = Path(os.path.realpath(path))
    if target.exists() and not target.is_file():
        # newline="\n": the same bytes on Windows as everywhere else.
        with open(target, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        return
    replace_text(target, text)
