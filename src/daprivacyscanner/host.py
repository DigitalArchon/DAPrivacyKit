"""The machine being scanned, as checks see it: where system files are, whose home it is, the
environment, and how commands are run. Checks never touch the filesystem or subprocess
directly, so tests can point them at a fixture home, a fake /etc tree and captured command
output instead of the developer's real system."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Sequence

if TYPE_CHECKING:
    from .privileged import Privileged

DEFAULT_TIMEOUT = 15.0
NOT_FOUND = 127
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
        """The program isn't installed."""
        return self.returncode == NOT_FOUND


class CommandRunner:
    """Runs a program without a shell, with C locale output so parsers see one format."""

    def run(self, argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT, stdin: Path | None = None,
            env: Mapping[str, str] | None = None) -> CommandResult:
        """`stdin`: a file the program reads as its standard input (default: none). `env`: variables added to its
        environment (mat2's TMPDIR)."""
        raise NotImplementedError

    def which(self, name: str) -> bool:
        raise NotImplementedError


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
        try:
            with open(stdin, "rb") if stdin is not None else open(os.devnull, "rb") as source:
                p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout,
                                   stdin=source, env={**self._env, **env} if env else self._env)
        except subprocess.TimeoutExpired:
            return CommandResult(argv, TIMED_OUT, "", f"timed out after {timeout:g} s")
        except OSError as e:
            return CommandResult(argv, NOT_FOUND, "", str(e))
        return CommandResult(argv, p.returncode, p.stdout, p.stderr)

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
