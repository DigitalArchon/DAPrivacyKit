"""The root helper's hardening (the review of 2026-11-12): how the app talks to it (a socket pair, bounded lines,
an idle end, keep-alives, cancel), what it inherits (umask, limits), whose its state is, what it asks the password
for again, what it may turn on or off, its journal (an intent record first, the app's change ids, list_changes),
and how the install-only fallback runs only the bytes the app checked. Nothing here runs as root."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time

import pytest

from daprivacyscanner import helper, privileged
from daprivacyscanner.privileged import ConsentDeclined, FakePrivileged, HelperError, PkexecHelper
from daprivacyscanner.server import AdminSession

from fakes import FakeSystem

ME = (os.geteuid(), os.getegid())
HELPER = helper.__file__


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / "root"
    r.mkdir()
    monkeypatch.setattr(helper, "ROOT", str(r))
    system = FakeSystem()
    monkeypatch.setattr(helper, "RUN", system)
    monkeypatch.setattr(helper, "CALLER", (*ME, "/home/alice"))
    (r / "home/alice/.cache").mkdir(parents=True)
    system.mounts(monkeypatch, r)
    return r


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        e = helper.Refused(reply["error"], reply)
        raise e
    return reply["result"]


# ------------------------------------------------------------------ 1. the socket pair, and the session's ends

def test_a_socket_end_cant_be_opened_again_through_proc_as_a_pipes_could():
    """Any process of the same user could open the app's pipe ends through /proc/<app>/fd/N and write requests into
    the helper's session (with an id the app skipped as late). A socket's end can't be opened that way."""
    r, w = os.pipe()
    fd = os.open(f"/proc/self/fd/{w}", os.O_WRONLY)              # a pipe: opened again, and written to
    os.close(fd)
    os.close(r)
    os.close(w)
    mine, theirs = socket.socketpair()
    with pytest.raises(OSError) as e:
        os.open(f"/proc/self/fd/{mine.fileno()}", os.O_WRONLY)
    assert e.value.errno == errno.ENXIO
    mine.close()
    theirs.close()


def test_the_app_starts_the_helper_on_a_socket_pair(tmp_path, monkeypatch):
    """pkexec passes the socket on as the helper's stdin and stdout (its fds 0 and 1)."""
    seen = []

    class Proc:
        stderr = None

        def __init__(self, argv, stdin, stdout, stderr, close_fds):
            seen.append((stdin, stdout))
            st = os.fstat(stdin)
            assert stat.S_ISSOCK(st.st_mode) and stdin == stdout
            self.sock = socket.socket(fileno=os.dup(stdin))
            threading.Thread(target=self.answer, daemon=True).start()

        def answer(self):
            line = self.sock.makefile("rb").readline()
            req = json.loads(line)
            self.sock.sendall((json.dumps({"id": req["id"], "ok": True, "result": {
                "version": helper.PROTOCOL, "uid": 0, "mode": "session"}}) + "\n").encode())

        def poll(self):
            return None

        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(privileged.shutil, "which", lambda name: "/usr/bin/pkexec")
    monkeypatch.setattr(privileged.subprocess, "Popen", Proc)
    h = PkexecHelper.start(argv=["pkexec", "/usr/libexec/daprivacyscanner/daprivacyscanner-helper"])
    assert seen and h.sock is not None and h.alive()


def serve_in_thread(monkeypatch, **settings):
    """The helper's session loop in this process, on a socket pair: returns (the app's end, the thread)."""
    for k, v in settings.items():
        monkeypatch.setattr(helper, k, v)
    mine, theirs = socket.socketpair()
    t = threading.Thread(target=helper.serve, args=(theirs.fileno(), theirs.fileno()), daemon=True)
    t.start()
    return mine, theirs, t


def ask(sock, obj, wait=5.0):
    sock.sendall((json.dumps(obj) + "\n").encode() if isinstance(obj, dict) else obj)
    sock.settimeout(wait)
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None
        buf += chunk
    return json.loads(buf.split(b"\n", 1)[0])


def test_a_request_line_has_a_limit(monkeypatch):
    mine, theirs, t = serve_in_thread(monkeypatch, MAX_REQUEST=1000)
    try:
        reply = ask(mine, b'{"id": 1, "action": "hello", "args": {"x": "' + b"a" * 5000 + b'"}}\n')
        assert reply == {"id": None, "ok": False, "error": "request too long"}
        assert ask(mine, {"id": 2, "action": "hello"})["result"]["version"] == helper.PROTOCOL   # and it goes on
    finally:
        mine.close()
        t.join(5)
        theirs.close()


def test_the_helper_ends_by_itself_when_unused_and_keepalive_keeps_it(monkeypatch):
    mine, theirs, t = serve_in_thread(monkeypatch, HELPER_IDLE=0.4)
    try:
        for i in range(4):                                       # 0.8 s in all, with a request every 0.2 s
            time.sleep(0.2)
            assert ask(mine, {"id": i + 1, "action": "keepalive"})["result"] == {"alive": True}
        t.join(2)
        assert not t.is_alive()                                  # then idle: it ended (the process exits)
    finally:
        mine.close()
        theirs.close()


def test_the_helper_has_an_absolute_lifetime(monkeypatch):
    mine, theirs, t = serve_in_thread(monkeypatch, HELPER_LIFETIME=0.3, HELPER_IDLE=10)
    try:
        ask(mine, {"id": 1, "action": "keepalive"})
        time.sleep(0.4)
        t.join(2)
        assert not t.is_alive()
    finally:
        mine.close()
        theirs.close()


def test_a_long_request_is_cancelled_by_the_app(monkeypatch):
    """The traffic watch runs for up to 5 minutes: Stop (the online tests' "stop now") ends it at once."""
    class Mon:
        def stop(self):
            return ""
    monkeypatch.setattr(helper, "MONITOR", lambda: Mon())
    monkeypatch.setattr(helper, "SLEEP", lambda s: time.sleep(0.05))
    monkeypatch.setattr(helper, "RUN", lambda argv: (0, "", ""))
    monkeypatch.setattr(helper, "ASK", lambda what: True)           # the password given, for every account's lookups
    mine, theirs, t = serve_in_thread(monkeypatch)
    try:
        mine.sendall((json.dumps({"id": 7, "action": "observe_traffic", "args": {"seconds": 300}}) + "\n").encode())
        time.sleep(0.2)
        started = time.monotonic()
        reply = ask(mine, {"id": None, "action": "cancel", "args": {"id": 7}})
        assert reply == {"id": 7, "ok": False, "error": "Stopped.", "stopped": True}
        assert time.monotonic() - started < 2
        assert ask(mine, {"id": 8, "action": "hello"})["id"] == 8       # a cancel is never answered itself
    finally:
        mine.close()
        t.join(5)
        theirs.close()


def test_the_app_sends_a_cancel_only_for_the_request_it_names():
    class Sock:
        def __init__(self):
            self.sent = []

        def sendall(self, data):
            self.sent.append(json.loads(data))

    class Proc:
        stdout = stderr = None

        def poll(self):
            return None
    h = PkexecHelper.__new__(PkexecHelper)
    h.sock, h.proc, h._wlock, h._inflight = Sock(), Proc(), threading.Lock(), (5, "trim_scan")
    assert not h.cancel({"observe_traffic"}) and h.sock.sent == []
    assert h.cancel({"trim_scan"}) and h.sock.sent == [{"id": None, "action": "cancel", "args": {"id": 5}}]


# ------------------------------------------------------------------ 14. what the app makes of the helper's answers

def fake_helper(script):
    """A PkexecHelper over a socket pair whose other end `script(sock)` plays the helper."""
    mine, theirs = socket.socketpair()
    threading.Thread(target=script, args=(theirs,), daemon=True).start()

    class Proc:
        stderr = None

        def poll(self):
            return None

        def wait(self, timeout=None):
            return 0
    return PkexecHelper(Proc(), ["x"], mine)


def test_a_reply_that_isnt_json_is_a_helper_error_not_a_crash():
    def script(sock):
        sock.makefile("rb").readline()
        sock.sendall(b"Traceback (most recent call last):\n")
    with pytest.raises(HelperError, match="unexpected reply"):
        fake_helper(script).call("read_file", {"path": "/etc/crypttab"})


def test_no_answer_to_a_change_gives_its_id_to_ask_about_later():
    """A change answered after the app's timeout was lost with its change id: now the app gives the id, and the error
    carries it, so list_changes can say whether it was made."""
    got = []

    def script(sock):
        got.append(json.loads(sock.makefile("rb").readline()))
    h = fake_helper(script)
    with pytest.raises(HelperError) as e:
        h.call("write_dropin", {"name": "sleep", "settings": {"AllowHibernation": "no"}}, timeout=0.3)
    assert e.value.data["timed_out"] and e.value.data["change_id"] == got[0]["args"]["change_id"]
    assert helper._CHANGE_ID.match(e.value.data["change_id"])


def test_a_declined_password_is_its_own_error():
    def script(sock):
        req = json.loads(sock.makefile("rb").readline())
        sock.sendall((json.dumps({"id": req["id"], "ok": False, "error": "This wasn't done", "declined": True}) + "\n")
                     .encode())
    with pytest.raises(ConsentDeclined) as e:
        fake_helper(script).call("clear_crash_dumps", {})
    assert e.value.data == {"declined": True}


def test_asking_again_gets_the_prompts_time_on_top():
    assert privileged.call_timeout("clear_syslog", {}, None) == privileged.CHANGE_TIMEOUT + privileged.AUTH_TIMEOUT
    assert privileged.call_timeout("observe_traffic", {"seconds": 60}, None) == 120 + privileged.AUTH_TIMEOUT
    assert privileged.call_timeout("revert", {}, None) == privileged.CHANGE_TIMEOUT + privileged.AUTH_TIMEOUT
    assert privileged.call_timeout("write_dropin", {}, None) == privileged.CHANGE_TIMEOUT


def test_a_helper_that_wont_end_isnt_killed_with_an_error(monkeypatch):
    """pkexec's child is root: kill() raised PermissionError out of _why_not_started."""
    class Proc:
        stderr = None

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("pkexec", timeout)

        def kill(self):
            raise PermissionError(1, "Operation not permitted")
    h = PkexecHelper.__new__(PkexecHelper)
    h.proc, h._drainer, h.stderr_tail = Proc(), None, b""
    assert "did not answer" in str(privileged._why_not_started(h))


def test_stderr_is_drained_while_the_helper_runs(tmp_path, monkeypatch):
    """A full stderr pipe would have stopped pkexec or the helper: it is read as it comes, the last part kept."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "pkexec").write_text("#!/bin/sh\nhead -c 300000 /dev/zero | tr '\\0' x >&2\necho 'the last words' >&2\n"
                                   "exit 1\n")
    (bindir / "pkexec").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setattr(privileged, "SYSTEM_PYTHON", sys.executable)
    with pytest.raises(privileged.HelperUnavailable, match="the last words"):
        PkexecHelper.start(timeout=20, argv=["pkexec", "x"])


# ------------------------------------------------------------------ 5. the fallback runs only what the app checked

def loader(path, digest, tmp_path):
    return subprocess.run([sys.executable, "-I", "-c", privileged.LOADER, str(path), digest],
                          input='{"id": 1, "action": "hello"}\n{"id": 2, "action": "read_file", "args": {"path": '
                                '"/etc/crypttab"}}\n', capture_output=True, text=True, timeout=30, cwd=tmp_path)


def test_the_loader_runs_the_helper_only_if_its_hash_is_the_apps(tmp_path):
    copy = tmp_path / "helper.py"
    data = open(HELPER, "rb").read()
    copy.write_bytes(data)
    p = loader(copy, hashlib.sha256(data).hexdigest(), tmp_path)
    replies = [json.loads(line) for line in p.stdout.splitlines()]
    assert replies[0]["result"] == {"version": helper.PROTOCOL, "uid": os.geteuid(), "mode": "install"}
    assert replies[1] == {"id": 2, "ok": False, "error": "this copy of the helper only installs or removes itself"}
    copy.write_bytes(data + b"\nimport os; os.system('touch PWNED')\n")       # changed after the app checked it
    p = loader(copy, hashlib.sha256(data).hexdigest(), tmp_path)
    assert p.returncode != 0 and p.stdout == "" and "changed after the app checked it" in p.stderr
    assert not (tmp_path / "PWNED").exists()


def test_the_loaded_helper_installs_the_bytes_it_checked_not_the_file_read_again(tmp_path, monkeypatch):
    data = open(HELPER, "rb").read()
    g = {"__name__": "loaded", "__file__": str(tmp_path / "helper.py"), "__daprivacyscanner_source__": data}
    (tmp_path / "helper.py").write_text("print('swapped')\n")
    exec(compile(data, str(tmp_path / "helper.py"), "exec"), g)  # noqa: S102 - the helper's bytes run as its loader runs them
    assert g["own_source"]() == data


def test_install_and_remove_go_through_the_fallback_and_nothing_else(monkeypatch):
    started = []

    class H:
        def call(self, action, args):
            return {"action": action}

        def close(self):
            pass

    def start(argv=None, mode="session", **kw):
        started.append((argv[:4], mode))
        return H()
    monkeypatch.setattr(privileged.PkexecHelper, "start", staticmethod(start))
    assert privileged.install_helper()["action"] == "install_self"
    assert privileged.install_helper(uninstall=True)["action"] == "uninstall_self"
    assert started == [(["pkexec", privileged.SYSTEM_PYTHON, "-I", "-c"], "install")] * 2


def test_in_a_session_installing_or_removing_asks_again(root, monkeypatch):
    asked = []
    monkeypatch.setattr(helper, "ASK", lambda what: asked.append(what) or False)
    with pytest.raises(helper.Refused) as e:
        call("uninstall_self")
    assert e.value.data["declined"] and "remove its administrator helper" in asked[0]
    assert "your password wasn't given" in str(e.value)
    monkeypatch.setattr(helper, "MODE", "install")                # the install-only copy: its own start asked
    asked.clear()
    call("install_self")
    assert asked == [] and (root / helper.INSTALLED.lstrip("/")).exists()


# ------------------------------------------------------------------ 4. what asks for the password again

@pytest.mark.parametrize("action, args", [("clear_crash_dumps", {}), ("clear_syslog", {}), ("clear_journal_files", {}),
                                          ("vacuum_journal", {"time": "2weeks"}), ("clear_opensnitch_log", {}),
                                          ("snapper_cleanup", {}), ("observe_traffic", {"seconds": 5}),
                                          ("names_orphans", {})])
def test_what_cant_be_undone_or_reaches_others_data_asks_again(root, monkeypatch, action, args):
    asked = []
    monkeypatch.setattr(helper, "ASK", lambda what: asked.append(what) or False)
    monkeypatch.setattr(helper, "MONITOR", lambda: (_ for _ in ()).throw(AssertionError("ran")))
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    assert not reply["ok"] and reply["declined"] and asked == [helper.CONSENT[action]]
    assert helper.CONSENT[action] in reply["error"]


def test_reads_and_reversible_changes_dont_ask_again(root, monkeypatch):
    monkeypatch.setattr(helper, "ASK", lambda what: pytest.fail(f"asked: {what}"))
    assert call("hello")["version"] == helper.PROTOCOL
    r = call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})
    assert call("revert", change_id=r["change_id"])["ok"]


def test_the_fake_says_what_was_asked_and_what_the_user_answered(root):
    with pytest.raises(ConsentDeclined):
        FakePrivileged(consent=False).call("clear_crash_dumps", {})
    p = FakePrivileged()
    assert p.call("clear_crash_dumps", {}) == {"deleted": 0} and p.asked == [helper.CONSENT["clear_crash_dumps"]]


def test_turning_remote_access_back_on_in_a_revert_asks_again(root, monkeypatch):
    helper.RUN.units = {"ssh.service": ["enabled", "active"]}
    r = call("set_service", unit="ssh.service", enable=False, start=False)
    asked = []
    monkeypatch.setattr(helper, "ASK", lambda what: asked.append(what) or False)
    with pytest.raises(helper.Refused) as e:
        call("revert", change_id=r["change_id"])
    assert e.value.data["declined"] and "ssh.service back on" in asked[0]
    assert helper.RUN.units["ssh.service"] == ["disabled", "inactive"]              # left off
    monkeypatch.setattr(helper, "ASK", lambda what: True)
    assert call("revert", change_id=r["change_id"])["ok"] and helper.RUN.units["ssh.service"] == ["enabled", "active"]


def test_pkcheck_asks_about_the_apps_own_process(monkeypatch):
    seen = []

    def run(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, run.code, "", "")
    pid = os.getppid()
    monkeypatch.setattr(helper, "SUBJECT", (pid, helper._proc_start(pid), 1000))
    monkeypatch.setattr(helper.subprocess, "run", run)
    run.code = 0
    assert helper._pkcheck("delete the logs")
    assert seen[0] == ["pkcheck", "--action-id", helper.SENSITIVE_ACTION, "--process",
                       f"{pid},{helper._proc_start(pid)},1000", "--allow-user-interaction", "--detail", "what",
                       "delete the logs"]
    run.code = 3                                               # dismissed
    assert not helper._pkcheck("delete the logs")
    run.code = 2                                               # no agent to ask with
    with pytest.raises(helper.Refused, match="no polkit agent"):
        helper._pkcheck("delete the logs")
    monkeypatch.setattr(helper, "SUBJECT", (pid, 1, 1000))      # another process now has that pid
    with pytest.raises(helper.Refused, match="has ended"):
        helper._pkcheck("delete the logs")


def test_the_sensitive_action_is_in_both_policies():
    from pathlib import Path
    packaged = (Path(__file__).resolve().parents[1] / "packaging/au.com.digitalarchon.daprivacyscanner.policy").read_text()
    assert packaged == helper.POLICY
    assert f'<action id="{helper.SENSITIVE_ACTION}">' in packaged and "$(what)" in packaged
    block = packaged.split(f'<action id="{helper.SENSITIVE_ACTION}">')[1].split("</action>")[0]
    assert block.count("auth_admin<") == 3 and "keep" not in block


# ------------------------------------------------------------------ 3. each unit only the way the app turns it

@pytest.mark.parametrize("args", [
    {"unit": "ssh.service", "enable": True, "start": True},
    {"unit": "sshd.service", "enable": None, "start": True},
    {"unit": "xrdp.service", "enable": True, "start": None},
    {"unit": "teamviewerd.service", "enable": True, "start": True},
    {"unit": "anydesk.service", "enable": None, "start": True},
    {"unit": "rustdesk.service", "enable": True, "start": True},
    {"unit": "firewalld.service", "enable": False, "start": False},
    {"units": ["firewalld.service"], "enable": False, "start": False, "mask": True},
    {"unit": "opensnitchd.service", "enable": False, "start": False},
    {"unit": "opensnitch.service", "enable": None, "start": False},
    {"units": ["ssh.service"], "enable": False, "start": False, "mask": True},
])
def test_a_unit_is_turned_only_the_way_the_app_turns_it(root, args):
    helper.RUN.units = {u: ["disabled", "inactive"] for u in helper.SERVICES}
    with pytest.raises(helper.Refused, match="doesn't turn"):
        call("set_service", **args)
    assert not any(c[1] in ("enable", "disable", "start", "stop", "mask") for c in helper.RUN.calls if c[0] == "systemctl")


def test_every_way_the_guides_turn_units_is_allowed(root):
    """What checks/guides ask for (service_off; the firewall, OpenSnitch, fstrim.timer and tmp.mount on) still works."""
    helper.RUN.units = {"avahi-daemon.socket": ["enabled", "active"], "avahi-daemon.service": ["enabled", "active"],
                        "firewalld.service": ["disabled", "inactive"], "tmp.mount": ["disabled", "inactive"],
                        "fstrim.timer": ["disabled", "inactive"], "rsyslog.service": ["enabled", "active"]}
    call("set_service", units=["avahi-daemon.socket", "avahi-daemon.service"], enable=False, start=False, mask=True)
    call("set_service", unit="firewalld.service", enable=True, start=True)
    call("set_service", unit="tmp.mount", enable=True, start=None)
    call("set_service", unit="fstrim.timer", enable=True, start=True)
    call("set_service", unit="rsyslog.service", enable=False, start=False)


def test_a_forced_revert_puts_back_the_rest_once_a_units_package_is_gone(root):
    """revert refused even when forced once a unit wasn't installed any more."""
    helper.RUN.units = {"ufw.service": ["disabled", "inactive"]}
    r = call("ufw_enable", allow=["22/tcp"])
    del helper.RUN.units["ufw.service"]                         # ufw's unit removed with its package
    out = call("revert", change_id=r["change_id"])
    assert out["conflict"] and "isn't installed any more" in out["message"]
    out = call("revert", change_id=r["change_id"], force=True)
    assert out["ok"] and helper.RUN.ufw_rules == [] and not helper.RUN.ufw_active
    assert "ufw.service isn't installed any more" in out["message"]


# ------------------------------------------------------------------ 9. the journal: intent first, the app's ids

def test_the_intent_record_is_on_the_disk_before_the_file_is_written(root, monkeypatch):
    real_write = helper._write
    seen = []

    def write(path, data, mode=0o644):
        if path.startswith("/etc/"):
            [entry] = list((root / "var/lib/daprivacyscanner/changes").iterdir())
            seen.append(json.loads(entry.read_text())["state"])
        return real_write(path, data, mode)
    monkeypatch.setattr(helper, "_write", write)
    r = call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})
    assert seen == ["intent"] and helper._load_change(r["change_id"])["state"] == "applied"


def test_a_write_that_fails_part_way_leaves_a_record_not_a_change(root, monkeypatch):
    """A full disk, or an inherited limit on file sizes: the drop-in isn't written, nothing is left changed, and
    list_changes says what became of it."""
    real_write = helper._write

    def write(path, data, mode=0o644):
        if path.startswith("/etc/") and data is not None:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(path, data, mode)
    monkeypatch.setattr(helper, "_write", write)
    reply = helper.handle(json.dumps({"id": 1, "action": "write_dropin", "args": {
        "name": "sleep", "settings": {"AllowHibernation": "no"}, "change_id": "a" * 32}}))
    assert not reply["ok"] and "change_id" not in reply                  # nothing left to put back
    assert not (root / "etc/systemd/sleep.conf.d/60-daprivacyscanner.conf").exists()
    assert not (root / "var/lib/daprivacyscanner").exists()
    [c] = call("list_changes")["changes"]
    assert c["change_id"] == "a" * 32 and c["state"] == "failed" and c["action"] == "write_dropin"


def test_the_apps_change_id_names_the_entry_and_list_changes_follows_it(root, monkeypatch):
    cid = "0123456789abcdef" * 2
    r = call("write_dropin", name="sleep", settings={"AllowHibernation": "no"}, change_id=cid)
    assert r["change_id"] == cid
    [c] = call("list_changes")["changes"]
    assert c["change_id"] == cid and c["state"] == "applied" and "60-daprivacyscanner.conf" in c["text"]
    for bad in ("x" * 32, "ABC", 7):
        with pytest.raises(helper.Refused, match="bad change id"):
            call("write_dropin", name="sleep-delay", settings={"HibernateDelaySec": "2h"}, change_id=bad)
    with pytest.raises(helper.Refused, match="used already"):
        call("write_dropin", name="sleep-delay", settings={"HibernateDelaySec": "2h"}, change_id=cid)
    call("revert", change_id=cid)
    assert [(c["change_id"], c["state"]) for c in call("list_changes")["changes"]] == [(cid, "reverted")]
    with pytest.raises(helper.Refused, match="used already"):                   # even once put back
        call("write_dropin", name="sleep", settings={"AllowHibernation": "no"}, change_id=cid)
    monkeypatch.setattr(helper, "CALLER", (ME[0] + 1, ME[1], "/home/bob"))      # another account's: not theirs
    assert call("list_changes")["changes"] == []


def test_another_accounts_change_isnt_reverted(root, monkeypatch):
    r = call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})
    monkeypatch.setattr(helper, "CALLER", (ME[0] + 1, ME[1], "/home/bob"))
    with pytest.raises(helper.Refused, match="another account"):
        call("revert", change_id=r["change_id"])


def test_a_service_change_is_recorded_before_systemctl_runs(root, monkeypatch):
    helper.RUN.units = {"apport.service": ["enabled", "active"]}
    states = []
    real = helper.RUN

    def run(argv):
        if argv[:2] == ["systemctl", "disable"]:
            [entry] = list((root / "var/lib/daprivacyscanner/changes").iterdir())
            states.append(json.loads(entry.read_text()))
        return real(argv)
    monkeypatch.setattr(helper, "RUN", run)
    r = call("set_service", unit="apport.service", enable=False, start=False)
    assert states[0]["state"] == "intent" and states[0]["services"][0]["after"] == ["disabled", "inactive"]
    assert helper._load_change(r["change_id"])["state"] == "applied"


def test_a_change_that_changes_nothing_leaves_no_record(root):
    helper.RUN.units = {"apport.service": ["disabled", "inactive"]}
    assert call("set_service", unit="apport.service", enable=False, start=False) == {"changed": False}
    assert not (root / "var/lib/daprivacyscanner").exists()


# ------------------------------------------------------------------ 2. what the helper inherits, whose its state is

def test_the_helper_sets_its_own_umask_working_folder_and_limits(tmp_path, monkeypatch):
    import resource
    monkeypatch.setattr(helper, "_no_dumps", lambda: None)
    saved_umask, cwd = os.umask(0), os.getcwd()
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    try:
        if hard == resource.RLIM_INFINITY:
            resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, hard))
        os.chdir(tmp_path)
        helper._harden()
        assert os.umask(0o022) == 0o022 and os.getcwd() == "/"
        if hard == resource.RLIM_INFINITY:
            assert resource.getrlimit(resource.RLIMIT_FSIZE)[0] == resource.RLIM_INFINITY
    finally:
        os.umask(saved_umask)
        os.chdir(cwd)
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))


def test_every_folder_a_change_makes_gets_its_mode_whatever_the_umask(root):
    saved = os.umask(0)
    try:
        call("write_dropin", name="resolved-dot", settings={"DNSOverTLS": "yes"})
    finally:
        os.umask(saved)
    for d in ("etc", "etc/systemd", "etc/systemd/resolved.conf.d"):
        assert stat.S_IMODE((root / d).stat().st_mode) == 0o755, d
    assert stat.S_IMODE((root / "var/lib/daprivacyscanner").stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "var/lib/daprivacyscanner/changes").stat().st_mode) == 0o700


def test_the_helpers_own_folders_get_their_modes_back(root):
    """An older helper started under umask 000 left /var/lib/daprivacyscanner writable by every account."""
    (root / "var/lib/daprivacyscanner/changes").mkdir(parents=True)
    os.chmod(root / "var/lib/daprivacyscanner", 0o777)
    os.chmod(root / "var/lib/daprivacyscanner/changes", 0o777)
    call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})
    assert stat.S_IMODE((root / "var/lib/daprivacyscanner").stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "var/lib/daprivacyscanner/changes").stat().st_mode) == 0o700


def test_a_journal_entry_anyone_could_have_written_is_never_put_back(root):
    """In a folder writable by every account, another account could plant an entry whose "before" is content of
    theirs and have `revert {force: true}` write it anywhere as root."""
    target = root / "etc/systemd/sleep.conf.d/60-daprivacyscanner.conf"
    r = call("write_dropin", name="sleep", settings={"AllowHibernation": "no"})
    entry = root / f"var/lib/daprivacyscanner/changes/{r['change_id']}.json"
    data = json.loads(entry.read_text())
    data["files"][0]["before"] = "UExBTlRFRA=="                          # "PLANTED"
    entry.write_text(json.dumps(data))
    os.chmod(entry, 0o666)                                              # writable by others: not the helper's own
    with pytest.raises(helper.Refused, match="isn't the helper's own"):
        call("revert", change_id=r["change_id"], force=True)
    os.chmod(entry, 0o600)
    os.link(entry, root / "elsewhere.json")                             # two names: not its own either
    with pytest.raises(helper.Refused, match="isn't the helper's own"):
        call("revert", change_id=r["change_id"], force=True)
    assert "AllowHibernation=no" in target.read_text()


def test_a_planted_swap_list_turns_nothing_on(root, monkeypatch):
    (root / "run/daprivacyscanner").mkdir(parents=True)
    os.chmod(root / "run/daprivacyscanner", 0o777)
    planted = root / "run/daprivacyscanner/swap.json"
    planted.write_text(json.dumps({"devices": [{"name": "/home/mallory/swap", "priority": 1}]}))
    os.chmod(planted, 0o666)
    (root / "proc").mkdir(exist_ok=True)
    (root / "proc/swaps").write_text("Filename Type Size Used Priority\n")
    calls = []
    monkeypatch.setattr(helper, "RUN", lambda argv: calls.append(argv) or (0, "", ""))
    assert call("swap_on")["on"] == [] and calls == []
    # the helper's own list, but naming a file another account could write: not turned on either
    (root / "run/daprivacyscanner").mkdir(mode=0o755, exist_ok=True)       # (swap_on removed the planted list)
    planted.write_text(json.dumps({"devices": [{"name": "/home/mallory/swap", "priority": 1}]}))
    os.chmod(planted, 0o644)
    (root / "home/mallory").mkdir(parents=True)
    (root / "home/mallory/swap").write_bytes(b"")
    os.chmod(root / "home/mallory/swap", 0o666)
    assert call("swap_on")["on"] == [] and calls == []


# ------------------------------------------------------------------ 10. a folder made for the user

def test_a_folder_is_made_under_its_own_name_then_given_away_by_its_descriptor(root, monkeypatch):
    seen = []
    real = helper._renameat2

    def rename(olddir, old, newdir, new, flags):
        seen.append((old, new, flags))
        st = os.stat(old, dir_fd=olddir)
        assert (st.st_uid, stat.S_IMODE(st.st_mode)) == (ME[0], 0o700)       # given away before it has its name
        return real(olddir, old, newdir, new, flags)
    monkeypatch.setattr(helper, "_renameat2", rename)
    fd, created = helper._folder_fd("/home/alice", (".cache", "thumbnails"), *ME)
    os.close(fd)
    assert created and seen[0][0].startswith(".daprivacyscanner-") and seen[0][1:] == ("thumbnails",
                                                                                     helper.RENAME_NOREPLACE)
    assert sorted(os.listdir(root / "home/alice/.cache")) == ["thumbnails"]


def test_a_folder_made_meanwhile_is_taken_as_it_is_never_replaced(root, monkeypatch):
    def rename(olddir, old, newdir, new, flags):
        os.mkdir(new, 0o700, dir_fd=newdir)                              # made by the user at that moment
        (root / "home/alice/.cache/thumbnails/theirs.txt").write_text("x")
        raise OSError(errno.EEXIST, "File exists")
    monkeypatch.setattr(helper, "_renameat2", rename)
    fd, created = helper._folder_fd("/home/alice", (".cache", "thumbnails"), *ME)
    os.close(fd)
    assert not created and (root / "home/alice/.cache/thumbnails/theirs.txt").exists()
    assert sorted(os.listdir(root / "home/alice/.cache")) == ["thumbnails"]          # the random one removed


# ------------------------------------------------------------------ 8. names looked up in the folder, not by path

def test_a_live_name_is_looked_up_in_the_folder_never_through_a_link(root):
    home = root / "home/alice"
    (home / "Documents").mkdir()
    (home / "Documents/kept.txt").write_text("x")
    (root / "secret").mkdir()
    (root / "secret/id_ed25519").write_text("k")
    s = {"home": "/home/alice", "own_only": True}
    assert helper._live(s, "Documents", {b"kept.txt", b"gone.txt"}) == {b"kept.txt"}
    os.rename(home / "Documents", home / "Old")
    os.symlink(root / "secret", home / "Documents")                       # swapped for a link after the walk
    assert helper._live(s, "Documents", {b"id_ed25519", b"kept.txt"}) == set()


# ------------------------------------------------------------------ 11. parser bounds

def test_a_group_descriptor_size_ext4_couldnt_have_is_refused():
    sb = bytearray(1024)
    sb[0x38:0x3A] = (0xEF53).to_bytes(2, "little")
    sb[0x28:0x2C], sb[0x58:0x5A], sb[0x20:0x24] = (8192).to_bytes(4, "little"), (256).to_bytes(2, "little"), \
        (32768).to_bytes(4, "little")
    sb[0x60:0x64] = (0x80).to_bytes(4, "little")                         # 64-bit: the size is the superblock's word
    for size, ok in ((64, True), (1024, True), (0xFFFF, False), (48, False), (2048, False)):
        sb[0xFE:0x100] = size.to_bytes(2, "little")
        fs = helper.parse_ext4_superblock(bytes(sb))
        assert (fs["inodes"] is not None) == ok, size


def test_the_inode_tables_are_never_looked_for_past_the_device(tmp_path):
    dev = tmp_path / "dev"
    dev.write_bytes(bytes(1 << 20))
    fd = os.open(dev, os.O_RDONLY)
    try:
        g = {"groups": 1 << 20, "desc": 64, "gdt": 1, "per_group": 8192, "size": 256}
        assert helper._ext4_inode_tables(fd, g, 4096, 1 << 20) == []
    finally:
        os.close(fd)


def test_a_journal_whose_extents_name_the_same_blocks_again_isnt_read(tmp_path, monkeypatch):
    """Overlap was checked for the logical order only: the same blocks could be read up to ~512 GiB."""
    dev = tmp_path / "dev"
    dev.write_bytes(bytes(1 << 20))
    monkeypatch.setattr(helper, "parse_ext4_superblock", lambda sb: {"block_size": 4096, "journal": "inode",
                                                                     "journal_map": b""})
    for extents, why in (([(0, 10, 100), (10, 10, 100)], "the same blocks"),
                         ([(0, 10, 300)], "past the device's end")):
        monkeypatch.setattr(helper, "ext4_extents", lambda node, read, e=extents: e)
        fd = os.open(dev, os.O_RDONLY)
        try:
            assert helper._ext4_journal(fd, 4096)[0] == "unknown", why
        finally:
            os.close(fd)


def test_a_deleted_folder_is_looked_for_in_a_bounded_number_of_copies(monkeypatch):
    reads = []
    table = bytes(8) + (100).to_bytes(4, "little")                         # group 0's inode table: block 100
    monkeypatch.setattr(helper, "_aligned_read", lambda fd, off, length: ((table + bytes(length))[:length], 0))
    monkeypatch.setattr(helper, "_journal_block", lambda fd, j, lblk: reads.append(lblk) or bytes(4096))
    j = {"inodes": {"per_group": 8192, "size": 256, "desc": 64, "gdt": 1, "groups": 1}, "bsize": 4096,
         "icopies": {100: list(range(100000))}}
    helper._ext4_inode_gens(0, j, 12)
    assert len(reads) == helper.NAMES_INODE_COPIES


# ------------------------------------------------------------------ 12. every account's lookups stay in memory

def test_the_traffic_monitor_writes_into_a_memory_file(monkeypatch):
    class Popen:
        def __init__(self, argv, stdout, **kw):
            self.out = stdout

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(helper.subprocess, "Popen", Popen)
    m = helper._Monitor()
    assert os.readlink(f"/proc/self/fd/{m.out.fileno()}").startswith("/memfd:daprivacyscanner-lookups")
    m.out.write(b'{"question": [{"name": "example.org."}]}\n')
    assert m.stop().startswith('{"question"')


# ------------------------------------------------------------------ 1. the app's session timer

class P:
    def __init__(self):
        self.closed = self.pings = 0
        self.inflight = False

    def alive(self):
        return not self.closed

    def busy(self):
        return self.inflight

    def keepalive(self):
        self.pings += 1

    def close(self):
        self.closed += 1


def until(cond, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_access_ends_when_idle_even_while_nothing_asks():
    """_expire ran only inside active() and get(): with the page idle, the access never ended."""
    p = P()
    a = AdminSession(lambda: p, idle=0.2, tick=0.05)
    a.get(True)
    assert until(lambda: p.closed) and a.helper is None


def test_held_access_sends_keepalives_and_a_request_in_hand_is_never_closed():
    p = P()
    a = AdminSession(lambda: p, idle=0.1, tick=0.03, keepalive=0.05)
    a.get(True)
    with a.hold():
        assert until(lambda: p.pings >= 2) and not p.closed
    p.inflight = True                                    # a request in hand, without a hold (an fstrim, minutes long)
    time.sleep(0.3)
    assert not p.closed
    p.inflight = False
    assert until(lambda: p.closed)


def test_a_scans_drop_leaves_access_something_asked_for_meanwhile():
    """A scan that found nothing to fix as root closed the helper under the TRIM test, between its with_root and its
    hold."""
    p = P()
    a = AdminSession(lambda: p, idle=60)
    a.get(False) or a.get(True)
    mark = a.claimed()
    a.get(True)                                          # the TRIM test asks (and is about to hold it)
    assert not a.drop_unless_claimed(mark) and not p.closed
    mark = a.claimed()
    with a.hold():
        assert not a.drop_unless_claimed(mark)
    p.inflight = True
    assert not a.drop_unless_claimed(mark)
    p.inflight = False
    assert a.drop_unless_claimed(mark) and p.closed


def test_applying_a_fix_uses_the_access_there_is_now(cat, tmp_path):
    """A stored plan carried the Host of its dry run: the rescan after applying used a helper that had ended, or none
    though access had been given since."""
    from fastapi.testclient import TestClient

    from conftest import make_host
    from daprivacyscanner.server import create_app
    host = make_host(tmp_path)
    helpers = []

    def start():
        helpers.append(P())
        return helpers[-1]
    c = TestClient(create_app("t", cat, make_host=lambda: host, start_helper=start))
    H = {"X-Token": "t"}
    c.post("/api/scan", headers=H, json={})
    fixable = [cid for cid, r in c.get("/api/state", headers=H).json()["report"]["results"].items()
               if r.get("fixable") and not r.get("fix_root") and r["status"] in ("fail", "warn")]
    plan = None
    for cid in fixable:
        r = c.post(f"/api/fix/{cid}/plan", headers=H, json={}).json()
        if r.get("plan") and not r["plan"].get("needs_root"):
            plan = r["plan"]
            break
    if plan is None:
        pytest.skip("no fixable check without root on this fixture")
    c.app.state.admin.get(True)                           # access given after the dry run
    c.post("/api/fix/apply", headers=H, json={"plan_id": plan["id"], "confirm_irreversible": True})
    assert host.privileged is helpers[-1]
