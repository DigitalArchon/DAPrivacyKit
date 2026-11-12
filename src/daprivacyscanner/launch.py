"""How a unit, a timer or a file manager's right-click entry starts this same program: the
AppImage file (not the temporary folder it is mounted on while it runs), the command the user ran, an
installed command, or this Python with -m (from a source tree), and how to write that command
into a systemd unit or a desktop file."""

from __future__ import annotations

import os
import shlex
import stat as _stat
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


def _own_group(gid: int, uid: int) -> bool:
    """`gid` is the account's own group (a private group: its primary one, which no other account is in), so its
    members being able to write a folder is the account alone writing it."""
    import grp
    import pwd
    try:
        me = pwd.getpwuid(uid)
        g = grp.getgrgid(gid)
    except KeyError:
        return False
    if gid != me.pw_gid or any(m != me.pw_name for m in g.gr_mem):
        return False
    try:
        return not any(p.pw_gid == gid and p.pw_uid != uid for p in pwd.getpwall())
    except OSError:
        return False


def _status(path: str, follow: bool) -> os.stat_result:
    return os.stat(path) if follow else os.lstat(path)


def unsafe_place(path: str, uid: int | None = None) -> str:
    """Why a program at `path` isn't safe for a unit, a timer or a menu entry to run later ("" when it is): it, or a
    folder it is in, belongs to another account or can be written by others (a folder anyone can write to, as /tmp,
    whatever its sticky bit: once the file is gone, another account can make one of that name). Such entries run the
    path as it is when they start, so whoever can put a file there would have it run as this account. Checked both
    along the path as given (each link's owner) and along the real path."""
    uid = os.getuid() if uid is None else uid
    given = os.path.abspath(path)
    real = os.path.realpath(given)

    def chain(p: str) -> list[str]:
        out = [p]
        while p != "/":
            p = os.path.dirname(p)
            out.append(p)
        return out
    for p, follow in [(x, False) for x in chain(given)] + [(x, True) for x in chain(real)]:
        try:
            st = _status(p, follow)
        except OSError:
            return f"{p} can't be looked at, so it can't be told whether another account could replace {given}."
        what = "it" if p in (given, real) else f"the folder {p}"
        if st.st_uid not in (uid, 0):
            return f"{given} is run from a place another account controls: {what} belongs to another account."
        if _stat.S_ISLNK(st.st_mode):
            continue                                    # a link's own mode means nothing; its folder is checked
        if st.st_mode & 0o002:
            return f"{given} is run from a place every account can write to: {what} can be changed by anyone."
        if st.st_mode & 0o020 and not _own_group(st.st_gid, uid):
            return (f"{given} is run from a place other accounts can write to: {what} can be changed by the members "
                    "of its group.")
    return ""


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
