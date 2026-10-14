"""The environment for programs DA Privacy Kit runs (lsblk, gsettings, systemctl, the browser).
When it runs from an AppImage, the AppImage runtime adds variables describing its own mount;
they mean nothing to those programs, and another AppImage started by one of them would misread
them, so they are left out. Variables the app changed for itself only (GI_TYPELIB_PATH, for its
bundled typelibs) are given to them as they were."""

from __future__ import annotations

import os
from contextlib import contextmanager

APPIMAGE_VARS = ("APPIMAGE", "APPDIR", "ARGV0", "OWD", "APPIMAGE_EXTRACT_AND_RUN")
# variables changed for this process only, with their values before (None: they weren't set)
ORIGINAL: dict[str, str | None] = {}


def set_for_self(name: str, value: str) -> None:
    """Set an environment variable for this process only: host_env() gives children the value
    it had before."""
    ORIGINAL.setdefault(name, os.environ.get(name))
    os.environ[name] = value


def host_env(environ=None, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in (os.environ if environ is None else environ).items() if k not in APPIMAGE_VARS}
    for name, value in ORIGINAL.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    env.update(extra)
    return env


@contextmanager
def as_host():
    """os.environ as host_env() while a library starts a program itself (webbrowser)."""
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(host_env(saved))
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def appdir() -> str | None:
    """The AppImage's mount point, when running from one."""
    d = os.environ.get("APPDIR")
    return os.path.realpath(d) if d and os.path.isdir(d) else None
