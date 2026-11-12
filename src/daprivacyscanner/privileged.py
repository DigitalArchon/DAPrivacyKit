"""The app's side of the privileged helper (helper.py): starts it through pkexec when the user
asks for a scan with administrator access, and sends it named requests. If the user declines,
the scan goes on without it and system checks report partial detection (docs/TECHNICAL.md, design rule 3).

A session is always the installed, root-owned helper (packaging/install-helper.sh, or the app's own install).
Until it is installed, or while the installed one is from another version, administrator access isn't available
and the app offers to install it: this version's helper.py is then run once, only to install itself, by
`pkexec /usr/bin/python3 -I -c LOADER <file> <sha256>`, where the loader reads the file once, checks its hash
against the one the app gave (on the command line pkexec authorised) and runs exactly those bytes, so a file a
process of the user's swapped while the prompt stood is refused, never run as root."""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

from . import helper

INSTALLED_HELPER = Path("/usr/libexec/daprivacyscanner/daprivacyscanner-helper")
SYSTEM_PYTHON = "/usr/bin/python3"
AUTH_TIMEOUT = 300.0
CALL_TIMEOUT = 60.0
CHANGE_TIMEOUT = 120.0      # restarting a service can take a while
KEEPALIVE_TIMEOUT = 10.0
STDERR_KEPT = 4096          # of what the helper (or pkexec) wrote to stderr, the last this many bytes
# what pkexec runs to install or update the helper: the file read once, its hash checked against the one given, those
# bytes run (helper.own_source then installs them, never the file read again)
LOADER = ("import hashlib,sys;p,h=sys.argv[1:3];f=open(p,'rb');d=f.read(1<<23);f.close();"
          "hashlib.sha256(d).hexdigest()==h or sys.exit('The helper was changed after the app checked it: not run.');"
          "sys.argv=[p,'--install-only'];"
          "exec(compile(d,p,'exec'),{'__name__':'__main__','__file__':p,'__daprivacyscanner_source__':d})")


class HelperUnavailable(Exception):
    """The helper couldn't be started (no pkexec, no polkit agent, it failed)."""


class HelperDeclined(HelperUnavailable):
    """The user cancelled or failed the authorization prompt."""


class HelperNotInstalled(HelperUnavailable):
    """The helper isn't installed root-owned, or the installed one is from another version: administrator access
    needs it installed first (install_helper), which the app offers."""


class HelperError(Exception):
    """The helper refused or failed one request. `data`: what the answer carried beside the error, such as the
    "change_id" of a change that failed part way (journalled, so it can be put back) and what it "ran"; "declined"
    when the password asked for again (helper.CONSENT) wasn't given, "stopped" when the request was cancelled, and
    "timed_out" (with the "change_id" the app gave a change) when no answer came: whether it was made, list_changes
    says."""

    def __init__(self, message: str = "", data: dict | None = None):
        super().__init__(message)
        self.data = dict(data or {})


class ConsentDeclined(HelperError):
    """The helper asked for the password again (something that can't be undone, or reaches beyond the user's account)
    and it wasn't given: nothing was done."""


class Privileged:
    """What checks and fixes may ask of root. The named methods are read-only detection;
    call() sends one of the helper's change actions (see helper.py)."""

    def call(self, action: str, args: dict, timeout: float | None = None) -> Any:
        raise NotImplementedError

    def alive(self) -> bool:
        return True

    def busy(self) -> bool:
        """Whether a request is in hand now (it is never closed under one for being idle)."""
        return False

    def keepalive(self) -> None:
        """Tells the helper it is still wanted (long work holds the access), so it doesn't end for being idle."""

    def cancel(self, actions: set[str] | frozenset[str]) -> bool:
        """Stops the request in hand if it is one of `actions` (the user stopped what it is for). Whether one was."""
        return False

    def list_changes(self) -> list[dict]:
        changes: list[dict] = self.call("list_changes", {})["changes"]
        return changes

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
NOT_INSTALLED = ("The administrator helper isn't installed. Install it once, from the app (the note at the top of the "
                 "window) or with `daprivacyscanner --install-helper`: until it is, nothing runs as administrator.")


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


def _readable_by_root(src: Path, data: bytes | None = None) -> Path:
    """helper.py where root can read it. An AppImage's files are on a FUSE mount that only this
    user can open (root included), so it is copied into a private folder of this user's
    (_private_folder, 0700) first (`data`: what was read of it, written as it is). Whoever runs as this user could
    change the copy (or a source tree's file) later: the loader runs it only if its hash is the one the app gave."""
    from .hostenv import appdir
    d = appdir()
    if d is None or not str(src).startswith(d + "/"):
        return src
    base = _private_folder()
    dest = base / "helper.py"
    tmp = base / f".helper.py.{os.getpid()}"
    tmp.write_bytes(src.read_bytes() if data is None else data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
    return dest


def fallback_command() -> list[str]:
    """This version's helper, to install or update (or remove) itself and for nothing else: `pkexec /usr/bin/python3
    -I -c LOADER <file> <sha256>`. The hash is of the bytes read here, from the app's own package."""
    src = Path(helper.__file__).resolve()
    data = src.read_bytes()
    return ["pkexec", SYSTEM_PYTHON, "-I", "-c", LOADER, str(_readable_by_root(src, data)),
            hashlib.sha256(data).hexdigest()]


def helper_command() -> list[str]:
    """A session's helper: the installed one, of this version. HelperNotInstalled otherwise (the app offers to install
    it): a session never runs the fallback, whose file the user's own processes can reach."""
    installed = installed_helper()
    if installed is None:
        raise HelperNotInstalled(NOT_INSTALLED)
    if installed_helper_protocol() != helper.PROTOCOL:
        raise HelperNotInstalled(STALE_HELPER)
    return ["pkexec", str(installed)]


def install_helper(uninstall: bool = False) -> dict:
    """Installs this version's helper root-owned, with its polkit actions (or removes both),
    through a helper started from this version's own copy (an installed one may be older), which does nothing else."""
    try:
        argv = fallback_command()
    except OSError as e:
        raise HelperUnavailable(f"The administrator helper couldn't be put where root can read it ({e.strerror or e}).") from None
    h = PkexecHelper.start(argv=argv, mode="install")
    try:
        done: dict = h.call("uninstall_self" if uninstall else "install_self", {})
        return done
    finally:
        h.close()


def call_timeout(action: str, args: dict, timeout: float | None) -> float:
    """How long a request may take: a change's time, and the password prompt's for one that asks again."""
    base = timeout or CHANGE_TIMEOUT
    if action == "observe_traffic" and timeout is None:
        base = (args.get("seconds") or 0) + 60
    return base + (AUTH_TIMEOUT if action in helper.CONSENT_ACTIONS else 0)


class PkexecHelper(Privileged):
    """The helper, through pkexec, spoken to over a socket pair: its stdin and stdout are one end, this process holds the
    other. A pipe's end can be opened again through /proc/<this process>/fd by any process of the same user (and
    requests written into it with an id this side skips as late), a socket's can't (ENXIO)."""

    def __init__(self, proc: subprocess.Popen, argv: list[str], sock: socket.socket | None = None):
        self.proc = proc
        self.argv = argv
        self.sock = sock
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()          # one request at a time
        self._wlock = threading.Lock()         # one line written at a time (a cancel goes beside a request in hand)
        self._next = 0
        self._inflight: tuple[int, str] | None = None
        self._eof = False
        self.stderr_tail = b""
        threading.Thread(target=self._read, daemon=True, name="helper-read").start()
        self._drainer = None
        if proc.stderr is not None:
            self._drainer = threading.Thread(target=self._drain, daemon=True, name="helper-stderr")
            self._drainer.start()

    @classmethod
    def start(cls, timeout: float = AUTH_TIMEOUT, argv: list[str] | None = None, mode: str = "session") -> "PkexecHelper":
        """Asks for authorization (polkit shows its dialog) and starts the helper (`argv`, or
        helper_command()). Blocks until the user answers. `mode`: what the helper must say it is ("install" for the
        loader's copy)."""
        if not shutil.which("pkexec"):
            raise HelperUnavailable("pkexec (polkit) is not installed.")
        if argv is None:
            argv = helper_command()
        if argv[1] == SYSTEM_PYTHON and not os.path.exists(SYSTEM_PYTHON):
            raise HelperUnavailable(f"{SYSTEM_PYTHON} is not installed.")
        mine, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            proc = subprocess.Popen(argv, stdin=theirs.fileno(), stdout=theirs.fileno(), stderr=subprocess.PIPE,
                                    close_fds=True)
        except OSError as e:
            mine.close()
            raise HelperUnavailable(f"pkexec couldn't be started ({e.strerror or e}).") from None
        finally:
            theirs.close()
        h = cls(proc, argv, mine)
        try:
            hello = h._call("hello", {}, timeout)
        except HelperError:
            h.close()
            raise _why_not_started(h) from None
        if hello.get("uid") != 0:
            h.close()
            raise HelperUnavailable("The helper did not start as root.")
        if hello.get("version") != helper.PROTOCOL:
            h.close()
            raise HelperUnavailable(STALE_HELPER if mode == "session" else "The helper answered with another protocol version.")
        if hello.get("mode") != mode:
            h.close()
            raise HelperUnavailable("The helper didn't start the way it was asked to.")
        return h

    def _read(self) -> None:
        try:
            if self.sock is None:                   # a helper given pipes (tests)
                for line in self.proc.stdout or ():
                    self._lines.put(line.decode("utf-8", "replace") if isinstance(line, bytes) else line)
            else:
                buf = b""
                while True:
                    chunk = self.sock.recv(1 << 16)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._lines.put(line.decode("utf-8", "replace"))
        except (OSError, ValueError):
            pass
        self._eof = True
        self._lines.put(None)

    def _drain(self) -> None:
        """What the helper and pkexec write to stderr, read so a full pipe never blocks them; the last part kept, for
        why it didn't start."""
        err = self.proc.stderr
        if err is None:                             # only started when there is one
            return
        try:
            while True:
                chunk = err.read1(4096) if hasattr(err, "read1") else err.read(4096)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode()
                self.stderr_tail = (self.stderr_tail + chunk)[-STDERR_KEPT:]
        except (OSError, ValueError):
            return

    def _write(self, obj: dict) -> None:
        data = (json.dumps(obj) + "\n").encode()
        with self._wlock:
            if self.sock is not None:
                self.sock.sendall(data)
            else:                                   # a helper given pipes (tests)
                stdin = self.proc.stdin
                if stdin is None:
                    raise BrokenPipeError("the helper was given no input")
                stdin.write(data if "b" in getattr(stdin, "mode", "") else data.decode())
                stdin.flush()

    def _call(self, action: str, args: dict, timeout: float = CALL_TIMEOUT, wait: bool = True) -> Any:
        if not self._lock.acquire(blocking=wait):
            return None
        try:
            return self._exchange(action, args, timeout)
        finally:
            self._lock.release()

    def _exchange(self, action: str, args: dict, timeout: float) -> Any:
        self._next += 1
        rid = self._next
        unknown = {"change_id": args["change_id"]} if isinstance(args.get("change_id"), str) else {}
        try:
            self._write({"id": rid, "action": action, "args": args})
        except (BrokenPipeError, ValueError, OSError):
            raise HelperError("the helper has exited") from None
        self._inflight = (rid, action)
        try:
            while True:     # skipping late replies to requests that timed out
                try:
                    line = self._lines.get(timeout=timeout)
                except queue.Empty:
                    raise HelperError(f"no answer from the helper within {timeout:g} s",
                                      {**unknown, "timed_out": True} if unknown else {"timed_out": True}) from None
                if line is None:
                    raise HelperError("the helper has exited", {**unknown, "timed_out": True} if unknown else {})
                try:
                    reply = json.loads(line)
                except ValueError:
                    reply = None
                if not isinstance(reply, dict):
                    raise HelperError("unexpected reply from the helper")
                if not isinstance(reply.get("id"), int) or reply["id"] >= rid:
                    break
        finally:
            self._inflight = None
        if reply.get("id") != rid:
            raise HelperError("unexpected reply from the helper")
        if not reply.get("ok"):
            data = {k: reply[k] for k in ("change_id", "ran", "declined", "stopped") if k in reply}
            raise (ConsentDeclined if reply.get("declined") else HelperError)(reply.get("error") or "the helper refused",
                                                                             data)
        return reply.get("result")

    def call(self, action: str, args: dict, timeout: float | None = None) -> Any:
        # a change carries an id of the app's, so that if no answer comes, what became of it can be asked (list_changes)
        if action in helper.JOURNALLED and "change_id" not in args:
            args = {**args, "change_id": uuid.uuid4().hex}
        return self._call(action, args, call_timeout(action, args, timeout))

    def alive(self) -> bool:
        return self.proc.poll() is None and not self._eof

    def busy(self) -> bool:
        return self._lock.locked()

    def keepalive(self) -> None:
        """Only when no request is in hand: one that is keeps the helper from being idle anyway."""
        try:
            self._call("keepalive", {}, KEEPALIVE_TIMEOUT, wait=False)
        except HelperError:
            pass

    def cancel(self, actions: set[str] | frozenset[str]) -> bool:
        inflight = self._inflight
        if inflight is None or inflight[1] not in actions:
            return False
        try:
            self._write({"id": None, "action": "cancel", "args": {"id": inflight[0]}})
        except (OSError, ValueError):
            return False
        return True

    def luks_dump(self, device: str) -> dict:
        dump: dict = self._call("luks_dump", {"device": device})
        return dump

    def clevis_list(self, device: str) -> list[dict]:
        bindings: list[dict] = self._call("clevis_list", {"device": device})
        return bindings

    def read_file(self, path: str) -> str | None:
        r = self._call("read_file", {"path": path})
        return None if r.get("missing") else r["text"]

    def empty_password_accounts(self) -> list[str]:
        accounts: list[str] = self._call("empty_password_accounts", {})
        return accounts

    def sshd_settings(self) -> dict[str, list[str]]:
        settings: dict[str, list[str]] = self._call("sshd_settings", {})
        return settings

    def firewall_summary(self) -> dict:
        summary: dict = self._call("firewall_summary", {})
        return summary

    def ufw_status(self) -> str:
        text: str = self._call("ufw_status", {})["text"]
        return text

    def observe_traffic(self, seconds: int) -> dict:
        seen: dict = self._call("observe_traffic", {"seconds": seconds},
                                call_timeout("observe_traffic", {"seconds": seconds}, None))
        return seen

    def close(self) -> None:
        """The end of input: the helper finishes the request in hand, if any, and exits."""
        try:
            if self.sock is not None:
                self.sock.shutdown(socket.SHUT_WR)
            elif self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        if self.sock is not None and self.proc.poll() is not None:
            try:
                self.sock.close()
            except OSError:
                pass


def _why_not_started(h: PkexecHelper) -> HelperUnavailable:
    proc = h.proc
    try:
        code = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()                 # pkexec's child is root by now: this process may not signal it
        except (PermissionError, ProcessLookupError, OSError):
            pass
        return HelperUnavailable("The helper did not answer.")
    if h._drainer is not None:          # what it wrote, read to its end by its own thread
        h._drainer.join(timeout=2)
    err = h.stderr_tail.decode("utf-8", "replace").strip()
    if "authentication agent" in err.lower():
        return HelperUnavailable("No polkit authentication agent is running in this session.")
    if code in (126, 127):
        return HelperDeclined("Administrator access was declined.")
    return HelperUnavailable(f"The helper failed to start (exit {code}): {err[-200:]}")


class FakePrivileged(Privileged):
    """For tests: `luks` maps a device to captured `cryptsetup luksDump` output (parsed by the
    helper's own parser), `clevis` to `clevis luks list` output, `files` a path to its text.
    call() runs the real helper's change actions in this process, against helper.ROOT (which
    the test must point at a fixture tree) and helper.RUN (a fake command runner). `consent`: what the user answers
    when the helper asks for the password again (helper.CONSENT)."""

    def __init__(self, luks: dict[str, str] | None = None, clevis: dict[str, str] | None = None,
                 files: dict[str, str] | None = None, empty_passwords: list[str] | None = None,
                 sshd: dict[str, list[str]] | None = None, firewall: dict | None = None, ufw: str | None = None,
                 traffic: dict | None = None, consent: bool = True):
        self.luks, self.clevis, self.files = luks or {}, clevis or {}, files or {}
        self.empty_passwords, self.sshd, self.firewall = empty_passwords or [], sshd, firewall
        self.ufw, self.traffic, self.consent = ufw, traffic, consent
        self.calls: list[tuple[str, str]] = []
        self.asked: list[str] = []

    def call(self, action: str, args: dict, timeout: float | None = None) -> Any:
        if not helper.ROOT:
            raise AssertionError("tests must point helper.ROOT at a fixture tree before calling the helper")
        self.calls.append((action, json.dumps(args, sort_keys=True)))
        saved = helper.ASK

        def ask(what: str) -> bool:
            self.asked.append(what)
            return self.consent
        helper.ASK = ask
        try:
            reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
        finally:
            helper.ASK = saved
        if not reply["ok"]:
            raise (ConsentDeclined if reply.get("declined") else HelperError)(
                reply["error"], {k: reply[k] for k in ("change_id", "ran", "declined", "stopped") if k in reply})
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
