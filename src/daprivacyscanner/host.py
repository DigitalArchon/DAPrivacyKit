"""The machine being scanned, as checks see it: where system files are, whose home it is, the
environment, and how commands are run. Checks never touch the filesystem or subprocess
directly, so tests can point them at a fixture home, a fake /etc tree and captured command
output instead of the developer's real system."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Sequence

if TYPE_CHECKING:
    from .privileged import Privileged

DEFAULT_TIMEOUT = 15.0
NOT_FOUND = 127                 # the program isn't installed (as a shell says it)
CANT_RUN = 126                  # it is there but couldn't be started: not executable, a wrong format, its input unopenable
TIMED_OUT = 124


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def missing(self) -> bool:
        """The program isn't installed. Only that: one that is there but couldn't be started is `cant_run`, a failure
        like any other (never "not installed", which checks take for "not on this machine")."""
        return self.returncode == NOT_FOUND

    @property
    def cant_run(self) -> bool:
        """The program is there but couldn't be started (permission denied, a wrong format, its input unopenable)."""
        return self.returncode == CANT_RUN


class CommandRunner:
    """Runs a program without a shell, with C locale output so parsers see one format."""

    def run(self, argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT, stdin: Path | None = None,
            env: Mapping[str, str] | None = None) -> CommandResult:
        """`stdin`: a file the program reads as its standard input (default: none). `env`: variables added to its
        environment (mat2's TMPDIR)."""
        raise NotImplementedError

    def which(self, name: str) -> bool:
        raise NotImplementedError


_RUNNING: set[subprocess.Popen] = set()       # the commands SystemRunner is running now, for end_commands
_RUNNING_LOCK = threading.Lock()


def end_commands(programs: set[str]) -> int:
    """Ends the commands running now whose program is one of `programs` (by name: a file chooser, zenity or kdialog,
    left open when the app quits, which waited up to an hour otherwise). How many were told to end."""
    with _RUNNING_LOCK:
        procs = [p for p in _RUNNING if os.path.basename(str(p.args[0])) in programs]
    for p in procs:
        try:
            p.terminate()
        except OSError:
            pass
    return len(procs)


class SystemRunner(CommandRunner):
    def __init__(self, environ: Mapping[str, str] | None = None):
        from .hostenv import host_env
        env = host_env(environ, LC_ALL="C", LANG="C")
        self._env = env

    def run(self, argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT, stdin: Path | None = None,
            env: Mapping[str, str] | None = None) -> CommandResult:
        argv = tuple(argv)
        if not self.which(argv[0]):
            return CommandResult(argv, NOT_FOUND, "", f"{argv[0]}: not found")
        # every other failure is said as such: any OSError used to read as "not installed" (a program that may not be
        # run, a wrong format, an input that couldn't be opened), and checks took that for "not on this machine"
        try:
            source = open(stdin, "rb") if stdin is not None else open(os.devnull, "rb")
        except OSError as e:
            return CommandResult(argv, CANT_RUN, "", f"{argv[0]}: its input couldn't be opened ({e.strerror or e})")
        try:
            with source, subprocess.Popen(argv, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                          errors="replace", env={**self._env, **env} if env else self._env) as p:
                with _RUNNING_LOCK:
                    _RUNNING.add(p)
                try:
                    out, err = p.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    p.kill()
                    try:                        # a child it started, still holding the pipes, mustn't hold the scan
                        p.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    return CommandResult(argv, TIMED_OUT, "", f"timed out after {timeout:g} s")
                except BaseException:
                    p.kill()
                    raise
                finally:
                    with _RUNNING_LOCK:
                        _RUNNING.discard(p)
        except FileNotFoundError as e:          # gone since `which` looked, or a script whose interpreter isn't there
            return CommandResult(argv, NOT_FOUND, "", f"{argv[0]}: not found ({e.strerror or e})")
        except OSError as e:
            return CommandResult(argv, CANT_RUN, "", f"{argv[0]} couldn't be started ({e.strerror or e})")
        return CommandResult(argv, p.returncode, out, err)

    def which(self, name: str) -> bool:
        return shutil.which(name, path=self._env.get("PATH")) is not None


class FakeRunner(CommandRunner):
    """Replays captured output. `outputs` maps an argv (tuple, or a string split on spaces) to
    its stdout, or to a CommandResult. Commands not listed behave as not installed, unless
    their program is in `installed` (then they fail with exit status 1)."""

    def __init__(self, outputs: Mapping[Sequence[str] | str, str | CommandResult] | None = None,
                 installed: Sequence[str] = (), handlers: Mapping[str, object] | None = None):
        self.outputs: dict[tuple[str, ...], CommandResult] = {}
        for argv, out in (outputs or {}).items():
            key = tuple(argv.split(" ")) if isinstance(argv, str) else tuple(argv)
            self.outputs[key] = out if isinstance(out, CommandResult) else CommandResult(key, 0, out)
        # program -> callable(argv) returning a CommandResult (or None to fall through): stateful fakes
        self.handlers = dict(handlers or {})
        self.installed = set(installed) | {k[0] for k in self.outputs} | set(self.handlers)
        self.calls: list[tuple[str, ...]] = []
        self.envs: list[dict[str, str]] = []           # what each call added to the environment, in step with calls

    def run(self, argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT, stdin: Path | None = None,
            env: Mapping[str, str] | None = None) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        self.envs.append(dict(env or {}))
        if argv[0] in self.handlers:
            result = self.handlers[argv[0]](argv)
            if result is not None:
                return result
        if argv in self.outputs:
            return self.outputs[argv]
        if argv[0] in self.installed:
            return CommandResult(argv, 1, "", "no captured output for this command")
        return CommandResult(argv, NOT_FOUND, "", f"{argv[0]}: not found")

    def which(self, name: str) -> bool:
        return name in self.installed or name in self.handlers


def unescape_mount(field: str) -> str:
    """A path from /proc/mounts, /proc/swaps or mountinfo: the kernel writes space, tab, newline and backslash in it as
    \\ooo. Only the space was undone, so a folder mounted at a path with one of the others (or a RAM disk in a home
    folder whose path has a space, where nothing was undone) wasn't recognised as mounted, and a whole folder's
    deletion went on into a filesystem mounted there."""
    return _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), field)


_OCTAL = re.compile(r"\\([0-7]{3})")


class Unreadable(Exception):
    """A file exists but this process may not read it (typically needs root)."""


class FormatChanged(Exception):
    """A file exists and was read, but isn't in the form a check expects (a database without the table it reads, a
    JSON file that doesn't parse): damaged, or its program now keeps it differently. The runner reports the check as
    couldn't check, never as a pass."""

    def __init__(self, path, what: str):
        super().__init__(f"{path}: {what}")
        self.path = path
        self.what = what


@dataclass
class Host:
    home: Path
    environ: Mapping[str, str]
    runner: CommandRunner
    root: Path = Path("/")              # prefix for absolute system paths: /etc, /proc, /sys, /run
    uid: int = field(default_factory=os.getuid)
    # the privileged helper, when the user granted administrator access for this scan
    privileged: "Privileged | None" = None

    @classmethod
    def local(cls) -> "Host":
        env = dict(os.environ)
        return cls(home=Path(env.get("HOME") or os.path.expanduser("~")), environ=env, runner=SystemRunner(env))

    def sys_path(self, path: str | os.PathLike) -> Path:
        """A system path (/etc/..., /proc/...) on the host being scanned."""
        p = Path(path)
        if not p.is_absolute():
            raise ValueError(f"system paths are absolute: {path}")
        return self.root / p.relative_to("/")

    def read_sys(self, path: str | os.PathLike) -> str | None:
        """A system file's text (`path` as on the scanned host, e.g. "/etc/crypttab"), or None
        if it doesn't exist. A file only root can read is read through the privileged helper
        when it is running and the file is on its list; otherwise this raises Unreadable."""
        try:
            return self.read_file(self.sys_path(path))
        except Unreadable:
            if self.privileged is None or not self.privileged.can_read(str(path)):
                raise
            from .privileged import HelperError

            try:
                return self.privileged.read_file(str(path))
            except HelperError:
                raise Unreadable(str(self.sys_path(path))) from None

    @staticmethod
    def read_file(p: Path) -> str | None:
        """Like read_sys, for a path already resolved (sys_path, or the path resolver)."""
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
            return None
        except PermissionError as e:
            raise Unreadable(str(p)) from e

    @staticmethod
    def read_head(p: Path, n: int = 4096) -> bytes | None:
        """The first `n` bytes of a file (magic numbers, PNG chunks, key headers), or None if it
        doesn't exist. Raises Unreadable."""
        try:
            with open(p, "rb") as f:
                return f.read(n)
        except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
            return None
        except PermissionError as e:
            raise Unreadable(str(p)) from e

    def display(self, path: Path) -> str:
        """How a path is shown in evidence: as on the scanned host, with ~ for home."""
        if path == self.home:
            return "~"
        if path.is_relative_to(self.home):
            return "~/" + str(path.relative_to(self.home))
        if self.root != Path("/") and path.is_relative_to(self.root):
            return str(Path("/") / path.relative_to(self.root))
        return str(path)

    def run(self, *argv: str, timeout: float = DEFAULT_TIMEOUT, stdin: Path | None = None,
            env: Mapping[str, str] | None = None) -> CommandResult:
        extra = {**({"stdin": stdin} if stdin is not None else {}), **({"env": env} if env else {})}
        return self.runner.run(argv, timeout=timeout, **extra)

    def run_flatpak(self, *args: str, timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        """flatpak, run as a user who has no Flatpak installation of their own, makes one: an empty repository in
        ~/.local/share/flatpak and a cache in ~/.cache/flatpak (seen on Fedora 44 with an empty home folder). A scan
        never writes (rule 4), and there is nothing of the user's to list then: flatpak gets data and cache folders of
        its own for the call, in the runtime folder where there is one, removed at once."""
        data = Path(self.environ.get("XDG_DATA_HOME") or self.home / ".local" / "share")
        if (data / "flatpak").is_dir():
            return self.run("flatpak", *args, timeout=timeout)
        import tempfile
        runtime = self.environ.get("XDG_RUNTIME_DIR") or ""
        tmp = tempfile.mkdtemp(prefix="daprivacyscanner-flatpak.", dir=runtime if os.path.isdir(runtime) else None)
        try:
            return self.run("flatpak", *args, timeout=timeout,
                            env={"XDG_DATA_HOME": f"{tmp}/data", "XDG_CACHE_HOME": f"{tmp}/cache"})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
