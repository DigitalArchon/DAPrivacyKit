"""Process names, as /proc/PID/comm gives them.

The kernel keeps at most 15 bytes of a name (TASK_COMM_LEN less its terminator) and cuts it there, in the middle of a
character for many names that aren't ASCII ("Évolution-donné" ends in half an "é"), and any account's process can set
its own to arbitrary bytes (prctl PR_SET_NAME, or writing its comm). Read as strict UTF-8 such a name raised
UnicodeDecodeError, a ValueError that `except OSError` let through, so one process anywhere on the machine stopped every
check that lists processes. So names are read as bytes and decoded leniently: what isn't UTF-8 becomes U+FFFD, which
matches no name a check looks for and prints and serialises everywhere."""

from __future__ import annotations

from pathlib import Path

# what the kernel keeps of a name (TASK_COMM_LEN is 16, with its terminating NUL)
COMM_MAX = 15


def decode(raw: bytes) -> str:
    """A name's bytes as text: UTF-8 where it is, U+FFFD for each byte that isn't; the newline the kernel adds, and
    white space around it, removed."""
    return raw.decode("utf-8", "replace").strip()


def comm(proc: str | Path) -> str:
    """The name of the process whose /proc folder is `proc` (its comm). Raises OSError as reading it does (the process
    has ended, or another account's is hidden): callers skip it as before."""
    with open(Path(proc) / "comm", "rb") as f:
        return decode(f.read(256))
