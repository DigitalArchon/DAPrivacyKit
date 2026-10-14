"""The app's side of the privileged helper (helper.py): starts it through pkexec when the user
asks for a scan with administrator access, and sends it named requests. If the user declines,
the scan goes on without it and system checks report partial detection (docs/TECHNICAL.md, design rule 3)."""

from __future__ import annotations

import atexit
import json
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

from . import helper

# A root-owned install (packaging/install-helper.sh), with its own polkit action. Otherwise the
# copy beside this module is run with the system Python, which is only as trustworthy as the
# directory it is in: whoever can write there can change what runs as root once you authorize
# it. Fine for development; an installed app should use the root-owned copy.
INSTALLED_HELPER = Path("/usr/libexec/daprivacyscanner/daprivacyscanner-helper")
SYSTEM_PYTHON = "/usr/bin/python3"
AUTH_TIMEOUT = 300.0
CALL_TIMEOUT = 60.0
CHANGE_TIMEOUT = 120.0      # restarting a service can take a while


class HelperUnavailable(Exception):
    """The helper couldn't be started (no pkexec, no polkit agent, it failed)."""


class HelperDeclined(HelperUnavailable):
    """The user cancelled or failed the authorization prompt."""


class HelperError(Exception):
    """The helper refused or failed one request."""


class Privileged:
    """What checks and fixes may ask of root. The named methods are read-only detection;
    call() sends one of the helper's change actions (see helper.py)."""

    def call(self, action: str, args: dict, timeout: float | None = None):
        raise NotImplementedError

    def alive(self) -> bool:
        return True

    def luks_dump(self, device: str) -> dict:
        raise NotImplementedError

    def clevis_list(self, device: str) -> list[dict]:
        raise NotImplementedError

    def read_file(self, path: str) -> str | None:
        raise NotImplementedError

    def empty_password_accounts(self) -> list[str]:
        raise NotImplementedError

    def sshd_settings(self) -> dict[str, list[str]]:
        raise NotImplementedError

    def firewall_summary(self) -> dict:
        raise NotImplementedError

    def ufw_status(self) -> str:
        raise NotImplementedError

    def observe_traffic(self, seconds: int) -> dict:
        raise NotImplementedError

    @staticmethod
    def can_read(path: str) -> bool:
        return helper.readable(path)

    def close(self) -> None:
        pass


def installed_helper() -> Path | None:
    """The root-owned helper, if it is installed safely: owned by root and writable by no one
    else, in directories that are too."""
    p = INSTALLED_HELPER
    try:
        for q in [p, *p.parents]:
            st = q.lstat()
            if st.st_uid != 0 or st.st_mode & 0o022 or (q == p and not os.access(q, os.X_OK)):
                return None
    except OSError:
        return None
    return p


STALE_HELPER = ("The installed administrator helper is from another version of DA Privacy Kit. Install this "
                "version's from the app, or with `daprivacyscanner --install-helper`.")


def installed_helper_protocol() -> int | None:
    """The protocol of the installed helper (a copy of helper.py), read from its source, or None
    when it isn't installed or can't be read."""
    p = installed_helper()
    if p is None:
        return None
    try:
        m = re.search(r"^PROTOCOL = (\d+)", p.read_text(errors="replace"), re.M)
    except OSError:
        return None
    return int(m.group(1)) if m else None


def installed_helper_stale() -> bool:
    """The installed helper speaks another protocol than this app (it was installed from an
    older or newer version), so it would be refused."""
    return installed_helper() is not None and installed_helper_protocol() != helper.PROTOCOL


_TMP: Path | None = None            # without a runtime folder: a private folder of this process's own, removed at exit


def _private_folder() -> Path:
    """Where the helper's copy goes: $XDG_RUNTIME_DIR/daprivacyscanner (the user's own folder, in memory); without
    a runtime folder, a folder under a random name of this process's own, removed when it exits. Never a fixed
    name in /tmp, which another account could have made first (and which was then left in its way)."""
    global _TMP
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.path.isdir(runtime):
        base = Path(runtime) / "daprivacyscanner"
        base.mkdir(mode=0o700, exist_ok=True)
        os.chmod(base, 0o700)
        return base
    if _TMP is None or not _TMP.is_dir():
        _TMP = Path(tempfile.mkdtemp(prefix="daprivacyscanner-"))
        atexit.register(shutil.rmtree, _TMP, ignore_errors=True)
    return _TMP


def _readable_by_root(src: Path) -> Path:
    """helper.py where root can read it. An AppImage's files are on a FUSE mount that only this
    user can open (root included), so it is copied into a private folder of this user's
    (_private_folder, 0700) first. The trust is the same as running it from a source tree this
    user can write to; the installed, root-owned helper is what removes it."""
    from .hostenv import appdir
    d = appdir()
    if d is None or not str(src).startswith(d + "/"):
        return src
    base = _private_folder()
    dest = base / "helper.py"
    tmp = base / f".helper.py.{os.getpid()}"
    tmp.write_bytes(src.read_bytes())
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
    return dest


def fallback_command() -> list[str]:
    """This version's helper, run by the system Python: used until the helper is installed, and
    to install or update it."""
    return ["pkexec", SYSTEM_PYTHON, "-I", str(_readable_by_root(Path(helper.__file__).resolve()))]


def helper_command() -> list[str]:
    installed = installed_helper()
    if installed is not None:
        return ["pkexec", str(installed)]
    return fallback_command()


def install_helper(uninstall: bool = False) -> dict:
    """Installs this version's helper root-owned, with its polkit action (or removes both),
    through a helper started from this version's own copy: an installed one may be older."""
    h = PkexecHelper.start(argv=fallback_command())
    try:
        return h.call("uninstall_self" if uninstall else "install_self", {})
    finally:
        h.close()


class PkexecHelper(Privileged):
    def __init__(self, proc: subprocess.Popen, argv: list[str]):
        self.proc = proc
        self.argv = argv
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._next = 0
        threading.Thread(target=self._read, daemon=True).start()

    @classmethod
    def start(cls, timeout: float = AUTH_TIMEOUT, argv: list[str] | None = None) -> "PkexecHelper":
        """Asks for authorization (polkit shows its dialog) and starts the helper (`argv`, or
        helper_command()). Blocks until the user answers."""
        if not shutil.which("pkexec"):
            raise HelperUnavailable("pkexec (polkit) is not installed.")
        try:
            argv = argv or helper_command()
        except OSError as e:                    # the copy root reads couldn't be made: said, never an error nothing catches
            raise HelperUnavailable(f"The administrator helper couldn't be put where root can read it ({e.strerror or e}).") from None
        if argv[1] == SYSTEM_PYTHON and not os.path.exists(SYSTEM_PYTHON):
            raise HelperUnavailable(f"{SYSTEM_PYTHON} is not installed.")
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
        h = cls(proc, argv)
        try:
            hello = h._call("hello", {}, timeout)
        except HelperError:
            h.close()
            raise _why_not_started(proc) from None
        if hello.get("uid") != 0:
            h.close()
            raise HelperUnavailable("The helper did not start as root.")
        if hello.get("version") != helper.PROTOCOL:
            h.close()
            raise HelperUnavailable(STALE_HELPER if argv[1] != SYSTEM_PYTHON else
                                    "The helper answered with another protocol version.")
        return h

    def _read(self):
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _call(self, action: str, args: dict, timeout: float = CALL_TIMEOUT):
        with self._lock:
            self._next += 1
            rid = self._next
            try:
                self.proc.stdin.write(json.dumps({"id": rid, "action": action, "args": args}) + "\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                raise HelperError("the helper has exited") from None
            while True:     # skipping late replies to requests that timed out
                try:
                    line = self._lines.get(timeout=timeout)
                except queue.Empty:
                    raise HelperError(f"no answer from the helper within {timeout:g} s") from None
                if line is None:
                    raise HelperError("the helper has exited")
                reply = json.loads(line)
                if not isinstance(reply.get("id"), int) or reply["id"] >= rid:
                    break
            if reply.get("id") != rid:
                raise HelperError("unexpected reply from the helper")
            if not reply.get("ok"):
                raise HelperError(reply.get("error") or "the helper refused")
            return reply.get("result")

    def call(self, action: str, args: dict, timeout: float | None = None):
        return self._call(action, args, timeout or CHANGE_TIMEOUT)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def luks_dump(self, device: str) -> dict:
        return self._call("luks_dump", {"device": device})

    def clevis_list(self, device: str) -> list[dict]:
        return self._call("clevis_list", {"device": device})

    def read_file(self, path: str) -> str | None:
        r = self._call("read_file", {"path": path})
        return None if r.get("missing") else r["text"]

    def empty_password_accounts(self) -> list[str]:
        return self._call("empty_password_accounts", {})

    def sshd_settings(self) -> dict[str, list[str]]:
        return self._call("sshd_settings", {})

    def firewall_summary(self) -> dict:
        return self._call("firewall_summary", {})

    def ufw_status(self) -> str:
        return self._call("ufw_status", {})["text"]

    def observe_traffic(self, seconds: int) -> dict:
        return self._call("observe_traffic", {"seconds": seconds}, seconds + 60)

    def close(self) -> None:
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()     # end of input: the helper exits
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _why_not_started(proc: subprocess.Popen) -> HelperUnavailable:
    try:
        code = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        return HelperUnavailable("The helper did not answer.")
    err = (proc.stderr.read() if proc.stderr else "").strip()
    if "authentication agent" in err.lower():
        return HelperUnavailable("No polkit authentication agent is running in this session.")
    if code in (126, 127):
        return HelperDeclined("Administrator access was declined.")
    return HelperUnavailable(f"The helper failed to start (exit {code}): {err[:200]}")


class FakePrivileged(Privileged):
    """For tests: `luks` maps a device to captured `cryptsetup luksDump` output (parsed by the
    helper's own parser), `clevis` to `clevis luks list` output, `files` a path to its text.
    call() runs the real helper's change actions in this process, against helper.ROOT (which
    the test must point at a fixture tree) and helper.RUN (a fake command runner)."""

    def __init__(self, luks: dict[str, str] | None = None, clevis: dict[str, str] | None = None,
                 files: dict[str, str] | None = None, empty_passwords: list[str] | None = None,
                 sshd: dict[str, list[str]] | None = None, firewall: dict | None = None, ufw: str | None = None,
                 traffic: dict | None = None):
        self.luks, self.clevis, self.files = luks or {}, clevis or {}, files or {}
        self.empty_passwords, self.sshd, self.firewall = empty_passwords or [], sshd, firewall
        self.ufw, self.traffic = ufw, traffic
        self.calls: list[tuple[str, str]] = []

    def call(self, action: str, args: dict, timeout: float | None = None):
        if not helper.ROOT:
            raise AssertionError("tests must point helper.ROOT at a fixture tree before calling the helper")
        self.calls.append((action, json.dumps(args, sort_keys=True)))
        reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
        if not reply["ok"]:
            raise HelperError(reply["error"])
        return reply["result"]

    def empty_password_accounts(self) -> list[str]:
        self.calls.append(("empty_password_accounts", ""))
        return list(self.empty_passwords)

    def sshd_settings(self) -> dict[str, list[str]]:
        self.calls.append(("sshd_settings", ""))
        if self.sshd is None:
            raise HelperError("sshd is not installed")
        return self.sshd

    def firewall_summary(self) -> dict:
        self.calls.append(("firewall_summary", ""))
        return self.firewall or {}

    def observe_traffic(self, seconds: int) -> dict:
        self.calls.append(("observe_traffic", str(seconds)))
        return self.traffic or {"queries": [], "connections": [], "monitor": True}

    def ufw_status(self) -> str:
        self.calls.append(("ufw_status", ""))
        if self.ufw is None:
            raise HelperError("ufw is not installed")
        return self.ufw

    def luks_dump(self, device: str) -> dict:
        self.calls.append(("luks_dump", device))
        if device not in self.luks:
            raise HelperError("cryptsetup failed: Device is not a valid LUKS device.")
        return helper.parse_luks_dump(self.luks[device])

    def clevis_list(self, device: str) -> list[dict]:
        self.calls.append(("clevis_list", device))
        if device not in self.clevis:
            raise HelperError("clevis is not installed")
        return helper.parse_clevis_list(self.clevis[device])

    def read_file(self, path: str) -> str | None:
        self.calls.append(("read_file", path))
        if not self.can_read(path):
            raise HelperError("that file is not on the helper's list")
        return self.files.get(path)
