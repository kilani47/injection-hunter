"""
core/store.py: a tiny persistent, file-backed dict for this lab's progress
state.

The Seiyaku Arc is a single-operator local lab, not a multi-tenant
service, so "who solved what" isn't tied to a browser's session cookie at
all: it's one global save file the whole app shares. That's what actually
fixes "restarting docker resets my progress", a cookie-based session was
never guaranteed to survive that in the first place (a non-permanent
Flask session cookie is a browser-session cookie by default, gone the
moment the browser itself closes, restarting docker or not); a file on
disk, bind-mounted from the host rather than kept in a Docker volume, is.

Deliberately dict-like (get/__getitem__/__setitem__, the same surface
core/unlock.py's own docstring says it only ever assumes) so unlock.py's
functions work against this with zero changes: swapping what gets passed
in at the call site in app.py is the entire fix.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


class ProgressStore(dict):
    """A dict subclass that persists itself to a JSON file on every write.

    Loads whatever's already on disk at construction time; every
    `__setitem__` afterward immediately rewrites the whole file, atomically
    (write to a temp file in the same directory, then `os.replace`), so a
    crash mid-write, or a read happening at the same moment, never sees a
    half-written file. This lab's actual traffic is a single local
    operator clicking one button at a time, so this simple
    write-the-whole-thing-every-time approach is more than enough; there's
    no real concurrent-writer scenario here to guard against beyond basic
    corruption-safety.
    """

    def __init__(self, path: str):
        super().__init__()
        self._path = path
        self._load()

    def _load(self) -> None:
        if not os.path.isfile(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable save file: start clean rather than
            # crash the whole app over a progress file. Nothing here is
            # security-sensitive; losing a malformed save is an acceptable
            # failure mode for a CTF lab's own progress tracker.
            return
        if isinstance(data, dict):
            self.update(data)

    def _save(self) -> None:
        directory = os.path.dirname(self._path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".progress-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(dict(self), fh)
            # mkstemp creates the file mode 0600 (owner-only); this app
            # commonly runs as root inside its container against a host
            # bind mount (see docker-compose.yml), so a 0600 file would be
            # unreadable/unremovable from the host without sudo. Nothing
            # in this save file is sensitive, so make it plainly readable
            # and writable by anyone, matching the honest "this file is
            # meant to be looked at and hand-edited if needed" bind-mount
            # setup, not something to lock down.
            os.chmod(tmp_path, 0o666)
            os.replace(tmp_path, self._path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, value)
        self._save()
