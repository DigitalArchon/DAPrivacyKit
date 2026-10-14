"""How a unit, a timer or a file manager's right-click entry starts this same program: the
AppImage file (not the temporary folder it is mounted on while it runs), the command the user ran, an
installed command, or this Python with -m (from a source tree), and how to write that command
into a systemd unit or a desktop file."""

from __future__ import annotations

import os
import shlex
import sys


def scan_command(environ=os.environ, argv0: str | None = None) -> list[str]:
    """How a timer should start this same program: the AppImage file (not the temporary
    folder it is mounted on while it runs), the command the user ran, an installed command, or
    this Python with -m (run from a source tree, `python -m daprivacyscanner`)."""
    import shutil

    appimage = environ.get("APPIMAGE")
    if appimage and os.path.isfile(appimage):
        return [appimage]
    argv0 = os.path.abspath(sys.argv[0] if argv0 is None else argv0)
    if os.path.isfile(argv0) and os.access(argv0, os.X_OK) and not argv0.endswith(".py"):
        return [argv0]
    found = shutil.which("daprivacyscanner")
    return [found] if found else [sys.executable, "-m", "daprivacyscanner"]


def systemd_exec(argv: list[str]) -> str:
    """An ExecStart= command line: each word quoted when it needs it, % and $ doubled (systemd
    expands both, even inside quotes)."""
    def word(w: str) -> str:
        w = w.replace("%", "%%").replace("$", "$$")
        if w and not any(c in w for c in ' \t"\'\\;$'):
            return w
        return '"' + w.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return " ".join(word(w) for w in argv)


def desktop_exec(argv: list[str]) -> str:
    """An Exec= command of a desktop file or Dolphin service menu (Desktop Entry spec): words with
    reserved characters in double quotes, with ", `, $ and \\ escaped by a backslash, a literal %
    doubled, and then every backslash doubled again (string values are unescaped before the quoting
    rules apply). Field codes (%F) are appended by the caller."""
    def word(w: str) -> str:
        w = w.replace("%", "%%")
        if w and not any(c in w for c in ' \t\n"\'\\><~|&;$*?#()`=[]{}'):
            return w
        return '"' + "".join("\\" + c if c in '"`$\\' else c for c in w) + '"'
    return " ".join(word(w) for w in argv).replace("\\", "\\\\")


def shell_words(argv: list[str]) -> str:
    """A command line for a shell script or a Nemo action (parsed like a shell)."""
    return " ".join(shlex.quote(w) for w in argv)
