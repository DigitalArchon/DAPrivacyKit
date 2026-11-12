"""Try an app: what a file is, the programs in an unpacked archive, the sandbox's command for each kind of trial,
the watch on the throwaway home with its decoys, the network summed up from packets, and the tool's API with a
stand-in for the program. Real sandboxes were run on real machines (Mint 22.3, CachyOS); here nothing is started."""

from __future__ import annotations

import ipaddress
import json
import os
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner.host import CommandResult, FakeRunner, Host
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import activity as A
from daprivacyscanner.tools import bait, homewatch, menu, pcap, sandbox, trial

H = {"X-Token": "t0ken"}
ELF = b"\x7fELF\x02\x01\x01\x00"


@pytest.fixture
def host(tmp_path):
    root = tmp_path / "root"
    home = root / "home/alice"
    for d in ("home/alice/Downloads", "run/user/1000", "tmp/.X11-unix", "usr/share/applications", "usr/bin", "etc"):
        (root / d).mkdir(parents=True)
    (root / "tmp/.X11-unix/X0").write_text("")
    (root / "usr/bin/foo").write_text("")
    (root / "usr/share/applications/foo.desktop").write_text("[Desktop Entry]\nType=Application\nName=Foo\nExec=foo %U\n")
    (root / "usr/share/applications/org.x.App.desktop").write_text(
        "[Desktop Entry]\nType=Application\nName=App\nExec=flatpak run --branch=stable --command=app org.x.App @@u %u @@\n"
        "X-Flatpak=org.x.App\n")
    ok = lambda argv: CommandResult(argv, 0, "")                                         # noqa: E731
    ip = lambda argv: CommandResult(argv, 0, "[]" if "-j" in argv else "")             # noqa: E731 (no networks listed)
    return Host(home=home, environ={"HOME": str(home), "XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0",
                                    "XDG_DATA_DIRS": "/usr/share", "LANG": "en_GB.UTF-8"},
                runner=FakeRunner(handlers={"bwrap": ok, "pasta": ok, "ip": ip, "mount": ok, "flatpak": ok}), root=root, uid=1000)


# ------------------------------------------------------------------ what a file is

@pytest.mark.parametrize("name, head, kind, refused", [
    ("Tool.AppImage", ELF + b"AI\x02" + b"\0" * 50, "appimage", False),
    ("Old.AppImage", ELF + b"AI\x01" + b"\0" * 50, "appimage", True),            # type 1: it can only mount itself
    ("tool", ELF + b"\0" * 60, "program", False),
    ("run.sh", b"#!/bin/sh\necho hi\n", "script", False),
    ("main.py", b"print('hi')\n", "script", False),
    ("pkg.deb", b"!<arch>\ndebian-binary   1700000000  0     0     100644  4         `\n2.0\n", "deb", False),
    ("a.tar.gz", b"\x1f\x8b\x08" + b"\0" * 20, "archive", False),
    ("a.zip", b"PK\x03\x04" + b"\0" * 20, "archive", False),
    ("letter.docx", b"PK\x03\x04" + b"\0" * 20, "unknown", True),
    ("setup.exe", b"MZ" + b"\0" * 70, "unknown", True),
    ("notes.txt", b"just text\n", "unknown", True),
])
def test_what_a_file_is_goes_by_its_content(tmp_path, name, head, kind, refused):
    f = tmp_path / name
    f.write_bytes(head)
    s = trial.classify(f)
    assert s.kind == kind and bool(s.problem) == refused


def test_a_name_is_made_safe_for_the_sandbox():
    assert trial.safe_name("My App (v2).AppImage") == "My_App__v2_.AppImage"
    assert trial.safe_name("..hidden") == "hidden" and trial.safe_name("--help") == "help" and trial.safe_name("ééé") == "___"


def test_the_programs_in_an_unpacked_package(tmp_path):
    tree = tmp_path / "app"
    for d in ("usr/bin", "usr/share/applications", "usr/share/foo", "opt/Foo/resources", "usr/lib/foo"):
        (tree / d).mkdir(parents=True)
    (tree / "opt/Foo/foo").write_bytes(ELF + b"\0" * 8 + b"\x02\x00" + b"\0" * 40)
    os.chmod(tree / "opt/Foo/foo", 0o755)
    os.symlink("/opt/Foo/foo", tree / "usr/bin/foo")                          # as packages do: an absolute link
    (tree / "usr/bin/foo-helper").write_text("#!/bin/sh\n")
    (tree / "usr/share/foo/data.bin").write_bytes(ELF + b"\0" * 60)           # not in a place programs are looked for
    (tree / "opt/Foo/resources/inner").write_text("#!/bin/sh\n")
    (tree / "usr/share/applications/foo.desktop").write_text("[Desktop Entry]\nName=Foo Editor\nExec=/opt/Foo/foo %U\n")
    os.symlink("/etc/passwd", tree / "usr/bin/leaves-the-tree")
    got = trial.candidates(tree, deb=True)
    assert got[0] == {"rel": "opt/Foo/foo", "what": "a Linux program", "label": "Foo Editor", "real": "opt/Foo/foo"}  # the menu entry's first
    assert [c["rel"] for c in got] == ["opt/Foo/foo", "usr/bin/foo-helper"]


def test_the_programs_in_an_unpacked_archive(tmp_path):
    tree = tmp_path / "app"
    (tree / "myapp/bin").mkdir(parents=True)
    (tree / "myapp/node_modules/x").mkdir(parents=True)
    (tree / "myapp/bin/run.sh").write_text("#!/bin/sh\n")
    (tree / "myapp/main.py").write_text("print(1)\n")
    (tree / "myapp/README.md").write_text("read me\n")
    (tree / "myapp/node_modules/x/cli.sh").write_text("#!/bin/sh\n")
    assert [c["rel"] for c in trial.candidates(tree, deb=False)] == ["myapp/main.py", "myapp/bin/run.sh"]


CANDIDATES_CHILD = """
import json, resource, sys
resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
from pathlib import Path
from daprivacyscanner.tools import trial
print(json.dumps(trial.candidates(Path(sys.argv[1]), deb=True)))
"""


def test_an_unpacked_tree_is_read_without_following_links_out_of_it(tmp_path):
    """The review of 2026-11-04: the programs in a package are looked for by the app, outside any sandbox, and every
    menu entry was read through links: one linked to /dev/zero was read until memory ran out, one that was a pipe kept
    Try an app waiting for good, and a folder linked to the computer's (usr/bin -> /usr/bin) had the computer's own
    programs listed as the package's. Run in a child with a memory cap and a time limit, so the old way fails here
    without harm."""
    computer = tmp_path / "computer"
    (computer / "bin").mkdir(parents=True)
    (computer / "bin/sneaky").write_text("#!/bin/sh\n")
    (computer / "outside.desktop").write_text("[Desktop Entry]\nName=Outside\nExec=prog\n")
    tree = tmp_path / "app"
    apps = tree / "usr/share/applications"
    for d in ("usr/share/applications", "usr/share/inner", "usr/games", "opt/Inner"):
        (tree / d).mkdir(parents=True)
    os.symlink(str(computer / "bin"), tree / "usr/bin")                            # the computer's own programs
    os.symlink(str(computer / "outside.desktop"), apps / "a-outside.desktop")      # a menu entry of the computer's
    os.symlink("../../../../computer/outside.desktop", apps / "b-up.desktop")
    os.mkfifo(apps / "c-pipe.desktop")
    os.symlink("/dev/zero", apps / "d-zero.desktop")
    (tree / "usr/games/prog").write_text("#!/bin/sh\n")
    # a link inside the tree is followed inside it, as the sandbox will
    (tree / "usr/share/inner/inner.desktop").write_text("[Desktop Entry]\nName=Inner\nExec=/opt/Inner/inner\n")
    os.symlink("../inner/inner.desktop", apps / "e-inner.desktop")
    (tree / "opt/Inner/inner").write_text("#!/bin/sh\n")
    r = subprocess.run([sys.executable, "-c", CANDIDATES_CHILD, str(tree)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr[-400:]
    got = [(c["rel"], c["label"]) for c in json.loads(r.stdout)]
    assert got == [("opt/Inner/inner", "Inner"), ("usr/games/prog", "")], got
    assert trial.in_tree(str(tree), "usr/bin/sneaky") is None and trial.in_tree(str(tree), "usr/../usr/games/prog") == "usr/games/prog"


def test_a_program_linked_in_a_package_runs_where_it_really_is(tmp_path):
    """The review of 2026-11-04: Google Chrome's and Brave's packages have /usr/bin/x -> /opt/…/x. The program listed
    is the link, and choosing it opened it here, where the link led to the computer's own /opt: it couldn't be started
    (or, with the app installed, the computer's file was read). It is now read where it is in the tree, without
    following a link, and run from there; the page gets the list as before."""
    t = a_trial(tmp_path, kind="deb")
    (t.app / "usr/bin").mkdir(parents=True)
    (t.app / "opt/Foo").mkdir(parents=True)
    (t.app / "opt/Foo/foo").write_bytes(ELF + b"\0" * 8 + b"\x02\x00" + b"\0" * 40)
    os.chmod(t.app / "opt/Foo/foo", 0o755)
    os.symlink("/opt/Foo/foo", t.app / "usr/bin/foo")
    (t.app / "bin").mkdir()
    (t.app / "bin/elsewhere").write_text("#!/bin/sh\n")                       # not in what the sandbox gives the package
    t.candidates = trial.candidates(t.app, deb=True)
    assert [c["rel"] for c in t.candidates] == ["usr/bin/foo"] and not os.path.exists("/opt/Foo/foo")
    trial.choose(t, "usr/bin/foo")
    assert t.argv == ["/opt/Foo/foo"] and "real" not in t.view()["candidates"][0]
    # an archive's absolute link names a file of the computer's, which isn't what runs: the tree's is
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/bin/sh\n")
    a = trial.Trial("0a1b2c3d4e5e", tmp_path / "t2", "memory", "archive", "x.tar", "an archive")
    (a.app / str(outside.parent).lstrip("/")).mkdir(parents=True)
    (a.app / str(outside).lstrip("/")).write_text("echo it has no #! line\n")
    os.symlink(str(outside), a.app / "run.sh")
    a.candidates = trial.candidates(a.app, deb=False)
    trial.choose(a, "run.sh")
    assert a.argv == ["/bin/sh", "/app/" + str(outside).lstrip("/")]


def test_arguments_are_given_once_however_often_the_start_is_tried(tmp_path):
    """The review of 2026-11-04: a start that failed after the arguments were added (pasta not usable, no Xephyr) left
    them in the command, and each start tried again added them again; a Box kept from the trial had them all."""
    t = a_trial(tmp_path, kind="appimage", argv=["/app/Tool.AppImage"])
    trial.choose(t, "", "--profile work")
    trial.choose(t, "", "--profile work")
    assert t.argv == ["/app/Tool.AppImage", "--profile", "work"]
    trial.choose(t, "", "")
    assert t.argv == ["/app/Tool.AppImage"], "arguments taken out again are gone"


# ------------------------------------------------------------------ the sandbox's command

def parts(host, tmp_path, **kw):
    etc = sandbox.identity_files(tmp_path / "etc", kw.pop("resolv", None))
    return trial.Parts(sandbox.Display("x11", [("/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0")], {"DISPLAY": ":0"}), etc, **kw)


def a_trial(tmp_path, kind="program", **kw):
    folder = tmp_path / "trial"
    for sub in ("home", "app", "private"):
        (folder / sub).mkdir(parents=True, exist_ok=True)
    return trial.Trial("0a1b2c3d4e5f", folder, "memory", kind, "tool", "a Linux program", **kw)


def pairs(argv, flag):
    return [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == flag]


def test_a_program_gets_a_throwaway_home_and_nothing_of_the_users(host, tmp_path):
    t = a_trial(tmp_path, argv=["/app/tool"], env={"APPIMAGE_EXTRACT_AND_RUN": "1"})
    a = trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))
    assert a[0] == "bwrap" and "--die-with-parent" in a and "--unshare-all" in a and "--share-net" not in a
    assert "--new-session" in a and a[a.index("--cap-drop") + 1] == "ALL" and "--clearenv" in a
    assert (str(t.home), "/home/user") in pairs(a, "--bind") and (str(t.app), "/app") in pairs(a, "--ro-bind")
    assert not any(str(host.home) in x for x in a), "nothing of the real home is in the sandbox"
    assert ("/opt", "/opt") not in pairs(a, "--ro-bind") and not any(x.startswith("/dev/dri") for x in a)
    env = dict(pairs(a, "--setenv"))
    assert env["HOME"] == "/home/user" and env["USER"] == "user" and env["APPIMAGE_EXTRACT_AND_RUN"] == "1"
    assert env["LANG"] == "en_GB.UTF-8" and env["LIBGL_ALWAYS_SOFTWARE"] == "1" and "DBUS_SESSION_BUS_ADDRESS" not in env
    assert a[a.index("--") + 1:] == ["/app/tool"]                           # no python3 on this fixture: the program itself


def test_the_observed_network_is_pastas_fenced_and_captured(host, tmp_path):
    t = a_trial(tmp_path, argv=["/app/tool"])
    p = parts(host, tmp_path, resolv="nameserver 169.254.0.1\n", pasta="pasta", pcap=tmp_path / "packets")
    a = trial.ENGINES["bubblewrap"].command(host, t, p)
    assert a[0] == "pasta" and a[a.index("--pcap") + 1] == str(tmp_path / "packets") and "--no-map-gw" in a
    assert "--no-icmp" in a[:a.index("--")], "no pings sent on from the computer: the capture's sums don't see them"
    fence = a[a.index("--") + 3]
    assert "prohibit to 192.168.0.0/16" in fence and "1080" not in fence, "the local network is refused, no proxy let through"
    assert "--share-net" in a, "inside pasta's namespace it shares that network, not the computer's"
    assert (str(p.etc["resolv.conf"]), "/etc/resolv.conf") in pairs(a, "--ro-bind") or host.sys_path("/etc/resolv.conf").exists() is False


def test_a_packages_usr_is_laid_over_the_computers_and_its_opt_put_in_place(host, tmp_path):
    t = a_trial(tmp_path, kind="deb", argv=["/usr/bin/foo"])
    (t.app / "usr/bin").mkdir(parents=True)
    (t.app / "opt/Foo").mkdir(parents=True)
    a = trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))
    assert a[:11] == ["bwrap", "--die-with-parent", "--unshare-user", "--uid", "0", "--gid", "0", "--cap-add", "ALL", "--dev-bind", "/"]
    stage = a[a.index("/bin/sh"):]
    assert stage[2] == trial.OVERLAY and stage[4:6] == ["mount", str(t.app / "usr")] and stage[6] == "bwrap"
    inner = stage[6:]
    assert (str(t.app / "opt"), "/opt") in pairs(inner, "--ro-bind") and (str(t.app), "/app") not in pairs(inner, "--ro-bind")
    assert inner[inner.index("--") + 1:] == ["/usr/bin/foo"]


def test_an_installed_app_in_opt_gets_the_computers_opt_read_only(host, tmp_path):
    t = a_trial(tmp_path, kind="installed", argv=["/opt/Foo/foo"], host_opt=True)
    a = trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))
    assert ("/opt", "/opt") in pairs(a, "--ro-bind")


def test_the_graphics_card_and_sound_only_when_given(host, tmp_path):
    (host.root / "run/user/1000/pulse").mkdir()
    (host.root / "run/user/1000/pulse/native").write_text("")
    t = a_trial(tmp_path, argv=["/app/tool"])
    a = trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path, devices=("/dev/dri/renderD128",), sound=True))
    env = dict(pairs(a, "--setenv"))
    assert ("/dev/dri/renderD128", "/dev/dri/renderD128") in pairs(a, "--dev-bind") and "LIBGL_ALWAYS_SOFTWARE" not in env
    assert env["PULSE_SERVER"] == "unix:/run/user/1000/pulse/native"
    assert "PULSE_SERVER" not in dict(pairs(trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path)), "--setenv"))


def test_a_flatpak_runs_with_its_own_permissions_dropped(host, tmp_path):
    t = a_trial(tmp_path, kind="flatpak", argv=["--branch=stable", "org.x.App"], flatpak="org.x.App")
    t.options = {"network": "off", "gpu": False, "sound": False}
    a = trial.ENGINES["flatpak"].command(host, t, parts(host, tmp_path))
    assert a[:6] == ["flatpak", "run", "--sandbox", "--session-bus", "--own-name=org.x.App", "--die-with-parent"]
    assert a[6:8] == ["--nofilesystem=host", "--nofilesystem=home"] and f"--filesystem={t.home}" in a, "the home by its path"
    assert "--unshare=network" in a and "--share=network" not in a and "--device=dri" not in a and a[-2:] == ["--branch=stable", "org.x.App"]
    t.options = {"network": "on", "gpu": True, "sound": True}
    b = trial.ENGINES["flatpak"].command(host, t, parts(host, tmp_path))
    assert "--share=network" in b and "--device=dri" in b and "--socket=pulseaudio" in b


def test_the_wrapper_is_the_sandboxs_pid_1_where_there_is_python3(host, tmp_path):
    """bubblewrap's own process out of the program's sight (its environment and command line name the user and the
    computer: the tools review of 2026-10-17)."""
    t = a_trial(tmp_path, argv=["/app/tool"])
    (host.root / "usr/bin").mkdir(parents=True, exist_ok=True)
    (host.root / "usr/bin/python3").write_text("")
    a = trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))
    end = a.index("--")
    assert "--as-pid-1" in a[:end] and a[end + 1:end + 4] == [sandbox.PYTHON, "-I", "-c"] and a[end + 4] == trial.STAY


def test_a_programs_sandbox_holds_a_logouts_sigterm_and_a_flatpaks_doesnt(host, tmp_path):
    """bubblewrap's sandbox, with STAY in it to pass SIGTERM on, is started under TETHER's hold, so a logout's SIGTERM,
    sent to every process at once, doesn't end bubblewrap or pasta before the program; Flatpak's own sandbox has
    nothing of the app's inside to pass it on, and is started as before."""
    (host.root / "usr/bin/python3").write_text("")
    spawned = []
    spawn = lambda argv, **kw: spawned.append(argv) or SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    t = a_trial(tmp_path, argv=["/app/tool"])
    trial.start(host, t, {"real_display": True}, spawn)
    trial.stop(host, t)
    assert spawned[-1][3] == trial.TETHER and spawned[-1][4:6] == [str(os.getpid()), "--hold"] and trial.STAY in spawned[-1]
    f = a_trial(tmp_path / "f", kind="flatpak", argv=["org.x.App"], flatpak="org.x.App")
    trial.start(host, f, {"network": "on", "real_display": True}, spawn)
    trial.stop(host, f)
    assert spawned[-1][3] == trial.TETHER and "--hold" not in spawned[-1] and "flatpak" in spawned[-1]
    assert trial.tethered(host, ["/usr/bin/Xephyr"]) == [sandbox.PYTHON, "-I", "-c", trial.TETHER, str(os.getpid()),
                                                         "/usr/bin/Xephyr"], "Xephyr ends with the SIGTERM _finish sends"
    compile(trial.TETHER, "tether", "exec")


def test_the_wrapper_is_python_and_names_the_helpers_it_doesnt_wait_for():
    compile(trial.STAY, "stay", "exec")
    assert "dbus-daemon" in trial.STAY and all(len(n) <= 15 for n in trial.HELPERS)
    assert "<wait for everything it starts>" in trial.shown(["python3", "-c", trial.STAY, "/app/x"])


# ------------------------------------------------------------------ the watch and the decoys

def test_decoys_are_made_up_and_private(tmp_path):
    made = bait.plant(tmp_path)
    assert made[".ssh/id_ed25519"] == "an SSH private key" and made[".ssh"] == "the folder ~/.ssh"
    assert ".config" not in made and ".local" not in made, "folders every program uses aren't decoys"
    key = (tmp_path / ".ssh/id_ed25519").read_bytes()
    assert key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----") and (tmp_path / ".ssh/id_ed25519").stat().st_mode & 0o777 == 0o600
    cookies = next(tmp_path.glob(".mozilla/firefox/*/cookies.sqlite"))
    assert cookies.read_bytes().startswith(b"SQLite format 3\0")
    other = tmp_path.parent / "second"
    other.mkdir()
    bait.plant(other)
    assert (other / ".ssh/id_ed25519").read_bytes() != key, "new for each trial"


def wait_for(cond, seconds=3.0):
    end = time.time() + seconds
    while time.time() < end and not cond():
        time.sleep(0.05)
    return cond()


def test_the_watch_sees_what_is_written_and_which_decoys_are_looked_at(tmp_path):
    made = bait.plant(tmp_path)
    w = homewatch.HomeWatch(tmp_path, made)
    w.start()
    try:
        time.sleep(0.2)
        assert w.counts() == {"files": 0, "written": 0, "decoys": 0, "overflow": 0}, "its own look through isn't the program's"
        (tmp_path / ".config/Foo/deep").mkdir(parents=True)
        # inotify watches a new folder only once the watch has seen it made: what happens in it before then is found
        # by looking, as created, never as moved. Wait for that here, or a loaded machine fails the test (it did)
        assert wait_for(lambda: any(r[0].endswith("/.config/Foo/deep") for r in w.records()))
        time.sleep(0.2)
        (tmp_path / ".config/Foo/a.conf").write_text("x")
        (tmp_path / ".config/Foo/deep/b").write_text("y")
        (tmp_path / ".ssh/id_ed25519").read_bytes()
        os.listdir(tmp_path / ".gnupg")
        with open(tmp_path / ".bash_history", "a") as f:
            f.write("z\n")
        os.rename(tmp_path / ".config/Foo/a.conf", tmp_path / ".config/Foo/c.conf")
        assert wait_for(lambda: w.counts()["decoys"] == 3 and w.counts()["files"] >= 4)
    finally:
        w.stop()
    seen = {d["path"]: d for d in w.decoys()}
    assert seen["~/.ssh/id_ed25519"]["opened"] == 1 and seen["~/.ssh/id_ed25519"]["what"] == "an SSH private key"
    assert seen["~/.bash_history"]["changed"] >= 1 and seen["~/.gnupg"]["listed"] == 1 and "~/.ssh" not in seen
    files = {r[0][len(str(tmp_path)) + 1:]: r[1] for r in w.records() if not r[1] & A.DIR}
    assert files[".config/Foo/c.conf"] & A.MOVED and files[".config/Foo/a.conf"] & A.DELETED and ".config/Foo/deep/b" in files
    assert ".ssh/id_ed25519" not in files, "a decoy that was only read isn't something the program wrote"
    assert ".bash_history" in files
    assert homewatch.left(tmp_path, made) == {"files": 2, "bytes": 2, "folders": 2}
    s = A.summarise(w.records(), A.Where(str(tmp_path), 1000), 5, names=True)
    assert {p["folder"] for p in s["places"]} >= {"~/.config/Foo", "~/.config/Foo/deep"}


# ------------------------------------------------------------------ the network, from packets

def eth(payload):
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + payload


def ip4(src, dst, proto, body):
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0, ipaddress.ip_address(src).packed,
                       ipaddress.ip_address(dst).packed) + body


def tcp(sp, dp, flags, data=b""):
    return struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 0x50, flags, 0, 0, 0) + data


def udp(sp, dp, data):
    return struct.pack(">HHHH", sp, dp, 8 + len(data), 0) + data


def qname(n):
    return b"".join(bytes([len(part)]) + part.encode() for part in n.split(".")) + b"\0"


def client_hello(host):
    name = host.encode()
    ext = struct.pack(">HH", 0, len(name) + 5) + struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\0" * 32 + b"\0" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\0" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def test_hosts_are_named_by_what_the_program_asked_or_said():
    me = "192.168.1.50"
    q = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + qname("example.org") + struct.pack(">HH", 1, 1)
    ans = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + qname("example.org") + struct.pack(">HH", 1, 1) + b"\xc0\x0c" \
        + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    q2 = struct.pack(">HHHHHH", 2, 0x0100, 1, 0, 0, 0) + qname("never-used.example") + struct.pack(">HH", 1, 1)
    packets = [eth(ip4(me, "169.254.0.1", 17, udp(4000, 53, q))), eth(ip4("169.254.0.1", me, 17, udp(53, 4000, ans))),
               eth(ip4(me, "169.254.0.1", 17, udp(4001, 53, q2))),
               eth(ip4(me, "93.184.216.34", 6, tcp(5000, 443, 0x02))), eth(ip4(me, "93.184.216.34", 6, tcp(5000, 443, 0x18, b"x" * 100))),
               eth(ip4("93.184.216.34", me, 6, tcp(443, 5000, 0x18, b"y" * 900))),
               eth(ip4(me, "203.0.113.9", 6, tcp(5001, 443, 0x02))), eth(ip4(me, "203.0.113.9", 6, tcp(5001, 443, 0x18, client_hello("tracker.example.net")))),
               eth(ip4(me, "198.51.100.7", 17, udp(6000, 123, b"n" * 48))), b"\x00" * 9]
    stream = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    stream += b"".join(struct.pack("<IIII", 0, 0, len(p), len(p)) + p for p in packets)
    f = pcap.Flows()
    for i in range(0, len(stream), 37):                                      # as it comes from a pipe: in pieces
        f.feed(stream[i:i + 37])
    r = f.result()
    hosts = {h["host"]: h for h in r["hosts"]}
    assert hosts["example.org"] == {"host": "example.org", "named_by": "dns", "addresses": ["93.184.216.34"],
                                    "more_addresses": False, "ports": ["443"], "more_ports": False, "connections": 1,
                                    "sent": 100, "received": 900}
    # a name it gave when connecting, never looked up for that address: only its word
    assert hosts["tracker.example.net"]["named_by"] == "program" and hosts["198.51.100.7"]["ports"] == ["123/udp"]
    assert r["looked_up"] == ["never-used.example"] and r["packets"] == 10
    assert "xxxx" not in repr(r), "no payload is kept"


def test_a_stream_that_isnt_a_capture_is_dropped():
    f = pcap.Flows()
    f.feed(b"not a pcap stream at all, just bytes" * 10)
    assert f.result()["hosts"] == [] and f.result()["broken"] == 1 and not f.buf


# ------------------------------------------------------------------ the tool

def test_a_file_is_copied_in_and_the_original_left_alone(host):
    src = host.home / "Downloads/My Tool.AppImage"
    src.write_bytes(ELF + b"AI\x02" + b"\0" * 100)
    src.chmod(0o644)
    t = trial.prepare_file(host, src, "memory")
    try:
        assert t.kind == "appimage" and t.argv == ["/app/My_Tool.AppImage"] and t.env == {"APPIMAGE_EXTRACT_AND_RUN": "1"}
        assert (t.app / "My_Tool.AppImage").stat().st_mode & 0o777 == 0o700 and src.stat().st_mode & 0o111 == 0
        assert str(t.folder).startswith(str(host.root / "run/user/1000/daprivacyscanner-trial/"))
        assert t.folder.stat().st_mode & 0o777 == 0o700
    finally:
        trial.discard(host, t)
    assert not t.folder.exists() and src.exists()
    # a link to the file (Downloads/latest -> the real one): the contents are copied, the link's target left as it is
    link = host.home / "Downloads/latest.AppImage"
    link.symlink_to(src)
    t = trial.prepare_file(host, link, "memory")
    try:
        copy = t.app / "latest.AppImage"
        assert not copy.is_symlink() and copy.read_bytes() == src.read_bytes() and copy.stat().st_mode & 0o777 == 0o700
        assert src.stat().st_mode & 0o777 == 0o644, "the user's own file isn't touched through the link"
    finally:
        trial.discard(host, t)


def test_what_cant_be_tried_is_refused_with_why(host):
    old = host.home / "Downloads/Old.AppImage"
    old.write_bytes(ELF + b"AI\x01" + b"\0" * 100)
    with pytest.raises(trial.TrialError, match="type 1"):
        trial.prepare_file(host, old, "memory")
    assert trial.leftovers(host) == []
    snap = menu.App("s.desktop", "Snappy", ["/snap/bin/snappy"], "snap", snap="snappy")
    with pytest.raises(trial.TrialError, match="Snap"):
        trial.prepare_app(host, snap, "memory")
    home_app = menu.App("h.desktop", "Mine", [str(host.home / "bin/mine")], "native")
    with pytest.raises(trial.TrialError, match="system's folders"):
        trial.prepare_app(host, home_app, "memory")


def test_folders_left_by_a_run_that_was_killed_are_cleared(host):
    base = host.root / "run/user/1000/daprivacyscanner-trial"
    (base / "0a1b2c3d4e5f/home").mkdir(parents=True)
    (base / "0a1b2c3d4e5f/home/x").write_text("left")
    (base / "not-a-trial").mkdir()
    assert trial.leftovers(host) == [str(base / "0a1b2c3d4e5f")]
    trial.clear_leftovers(host)
    assert not (base / "0a1b2c3d4e5f").exists() and (base / "not-a-trial").exists()


def test_a_trial_on_the_disk_goes_with_its_read_only_folders(tmp_path):
    """The review of 2026-11-04: a trial on the disk whose home held a read-only folder (Go's module cache, a tarball's,
    or the program's own chmod) wasn't removed by Discard or by the clean-up at each start, which only delete there:
    shutil.rmtree can't delete what is in a read-only folder. Its folders are made writable first, as in memory, never
    through a link."""
    folder = tmp_path / "cache" / trial.FOLDER / "0a1b2c3d4e5f"
    mod = folder / "home/go/pkg/mod/example.com/m@v1.0.0"
    mod.mkdir(parents=True)
    (folder / "app").mkdir()
    (mod / "go.mod").write_text("module example.com/m\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "kept").write_text("x")
    os.symlink(str(elsewhere), folder / "home/go/link")
    for p, mode in ((mod / "go.mod", 0o444), (mod, 0o555), (folder / "home/go", 0o500), (folder / "home", 0o500),
                    (elsewhere, 0o555)):
        os.chmod(p, mode)
    try:
        trial._remove(folder, in_memory=False)
        assert not folder.exists() and not folder.parent.exists()
        assert (elsewhere / "kept").exists() and stat.S_IMODE(elsewhere.stat().st_mode) == 0o555, "a link's folder is left as it is"
    finally:
        for p in [elsewhere, *([folder, *folder.rglob("*")] if folder.exists() else [])]:     # pytest's own clean-up
            if p.is_dir() and not p.is_symlink():
                os.chmod(p, 0o700)


def test_a_trial_through_the_api(cat, host):
    src = host.home / "Downloads/tool.sh"
    src.write_text("#!/bin/sh\necho hi\n")
    spawned = []

    def spawn(argv, **kw):
        spawned.append((argv, kw))
        return SimpleNamespace(pid=os.getpid() + 100000, stdout=None)
    with TestClient(create_app("t0ken", cat, make_host=lambda: host, spawn_app=spawn)) as c:
        d = c.get("/api/tools/trial", headers=H).json()
        assert d["status"]["available"] and d["trial"] is None and [p["id"] for p in d["status"]["places"]] == ["memory", "disk"]
        assert {a["id"] for a in d["apps"]} == {"foo.desktop", "org.x.App.desktop"}
        assert c.post("/api/tools/trial/start", headers=H, json={}).status_code == 400
        assert c.post("/api/tools/trial/prepare", headers=H, json={"path": "relative.sh"}).status_code == 400
        t = c.post("/api/tools/trial/prepare", headers=H, json={"path": str(src), "where": "memory"}).json()["trial"]
        assert t["state"] == "ready" and t["kind"] == "script" and t["command"] == "/app/tool.sh"
        assert c.post("/api/tools/trial/prepare", headers=H, json={"path": str(src)}).status_code == 409      # one at a time
        r = c.post("/api/tools/trial/start", headers=H, json={"network": "on"})
        assert r.status_code == 400 and "never shares this computer's network" in r.json()["error"]
        r = c.post("/api/tools/trial/start", headers=H, json={"network": "off", "gpu": True, "args": "--verbose 'two words'"})
        assert r.status_code == 400 and "tick that it may use this display" in r.json()["error"]      # no Xephyr here
        t = c.post("/api/tools/trial/start", headers=H, json={"network": "off", "gpu": True, "args": "--verbose 'two words'",
                                                             "real_display": True}).json()["trial"]
        assert t["state"] == "running" and t["how"]["network"] == "off" and t["how"]["decoys"] == 34 and t["how"]["display"] == "x11"
        argv, kw = spawned[0]
        assert argv[argv.index("--") + 1:] == ["/app/tool.sh", "--verbose", "two words"] and kw["start_new_session"] is True
        assert kw["env"] == sandbox.SPAWN_ENV and kw["cwd"] == "/"      # nothing of the app's environment (bubblewrap's)
        folder = host.root / "run/user/1000/daprivacyscanner-trial" / t["id"]
        (folder / "home/.config").mkdir(exist_ok=True)
        (folder / "home/.config/made").write_text("x")                            # as the program would
        (folder / "home/.ssh/id_ed25519").read_bytes()
        deadline = time.time() + 3
        while time.time() < deadline:
            live = c.get("/api/tools/trial/status", headers=H).json()["trial"]["live"]
            if live["decoys"] and live["written"]:
                break
            time.sleep(0.05)
        assert live["decoys_seen"][0]["what"] == "an SSH private key" and live["hosts"] is None
        t = c.post("/api/tools/trial/stop", headers=H).json()["trial"]
        r = t["result"]
        assert t["state"] == "ended" and t["stopped"] and r["network"] == "off" and r["hosts"] is None
        assert [d["path"] for d in r["decoys"]] == ["~/.ssh/id_ed25519"] and r["decoys_planted"] == 34
        assert r["left"]["files"] == 1 and r["summary"]["places"][0]["files"] == [{"name": "~/.config/made", "did": "created, written"}]
        assert c.get("/api/tools", headers=H).json()["trial"] == "ended"
        assert c.post("/api/tools/trial/discard", headers=H).json() == {"trial": None} and not folder.exists()


def test_an_installed_app_and_a_flatpak_through_the_api(cat, host):
    spawned = []
    spawn = lambda argv, **kw: spawned.append((argv, kw)) or SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    with TestClient(create_app("t0ken", cat, make_host=lambda: host, spawn_app=spawn)) as c:
        t = c.post("/api/tools/trial/prepare", headers=H, json={"app": "foo.desktop"}).json()["trial"]
        assert t["kind"] == "installed" and t["command"] == "/usr/bin/foo"
        c.post("/api/tools/trial/start", headers=H, json={"decoys": False, "real_display": True})
        assert c.post("/api/tools/trial/stop", headers=H).json()["trial"]["result"]["decoys_planted"] == 0
        c.post("/api/tools/trial/discard", headers=H)
        t = c.post("/api/tools/trial/prepare", headers=H, json={"app": "org.x.App.desktop"}).json()["trial"]
        assert t["kind"] == "flatpak" and t["command"] == "--branch=stable --command=app org.x.App"
        r = c.post("/api/tools/trial/start", headers=H, json={"network": "observed"})
        assert r.status_code == 400 and "can't be observed" in r.json()["error"]
        r = c.post("/api/tools/trial/start", headers=H, json={"network": "on"})
        assert r.status_code == 400 and "a Flatpak app is given this display" in r.json()["error"]
        t = c.post("/api/tools/trial/start", headers=H, json={"network": "on", "real_display": True}).json()["trial"]
        argv, kw = spawned[-1]
        assert t["how"]["engine"] == "flatpak" and "--share=network" in argv and "--sandbox" in argv
        home = host.root / "run/user/1000/daprivacyscanner-trial" / t["id"] / "home"
        assert kw["env"]["HOME"] == str(home), "its data goes to the throwaway home, not ~/.var/app"
        c.post("/api/tools/trial/discard", headers=H)
        assert c.get("/api/tools/trial", headers=H).json()["trial"] is None


def test_a_flatpak_isnt_started_while_it_is_open_already(host, tmp_path):
    """The review of 2026-11-04: a Flatpak trial owns its app's name on the bus (--own-name), so with the app open as
    usual, the trial's copy handed its start to that one, outside the sandbox, and ended at once. Refused, as View
    offline… refuses it, and so when flatpak ps can't answer."""
    t = a_trial(tmp_path, kind="flatpak", argv=["org.x.App"], flatpak="org.x.App")
    spawned = []
    spawn = lambda argv, **kw: spawned.append(argv) or SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(argv, 0, "4242 org.x.App\n" if "ps" in argv else "")
    with pytest.raises(trial.TrialError, match="tool is open already.*Close tool first"):
        trial.start(host, t, {"network": "on"}, spawn)
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(argv, 1 if "ps" in argv else 0, "")
    with pytest.raises(trial.TrialError, match="couldn't be told"):
        trial.start(host, t, {"network": "on"}, spawn)
    assert not spawned and t.state == "ready" and not list(t.home.iterdir()), "nothing planted, nothing started"
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(argv, 0, "4243 org.x.Other\n" if "ps" in argv else "")
    trial.start(host, t, {"network": "on", "real_display": True}, spawn)
    assert len(spawned) == 1 and t.state == "running", "another app open is no reason"
    trial.stop(host, t)


def test_a_trial_in_memory_is_ended_before_it_fills_the_runtime_folder(host, tmp_path, monkeypatch):
    """A trial in memory is in the runtime folder, the session's own tmpfs (1.2 GB on the Mint PC), and nothing held it
    to a size while it ran: a browser's cache or a program writing all it can filled it, and the session's programs
    couldn't write their runtime files until it was discarded. Its room is looked at while it runs, whether the panel
    asks or not, and the trial is ended, its result kept, once less than ROOM_KEPT is left; a start with less is
    refused, and the status says how much is kept free."""
    monkeypatch.setattr(trial, "ROOM_EVERY", 0.05)
    left = {"now": 900 << 20}
    monkeypatch.setattr(trial, "room", lambda folder: left["now"])
    spawn = lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    t = a_trial(tmp_path, argv=["/app/tool"])
    trial.start(host, t, {"real_display": True}, spawn)
    try:
        time.sleep(0.3)
        assert t.state == "running", "with room left it runs on"
        left["now"] = trial.ROOM_KEPT - (1 << 20)                            # it wrote nearly all there was
        wait_for(lambda: t.result is not None)
        assert t.state == "ended" and t.short_of_room == trial.ROOM_KEPT - (1 << 20)
        assert t.result["ended"] == trial.ROOM_WORDS and t.result["short_of_room"] == t.short_of_room
        assert t.result["summary"] is not None and not t.result["failed"], "what it did is kept, as when ended here"
        assert t.room is None
    finally:
        trial.stop(host, t)
    # with too little room already, it isn't started at all
    t2 = a_trial(tmp_path / "2", argv=["/app/tool"])
    with pytest.raises(trial.TrialError, match="too little room left in memory.*prepare it on the disk"):
        trial.start(host, t2, {}, lambda argv, **kw: pytest.fail("started"))
    # on the disk, the session's room isn't at stake: not watched
    t3 = a_trial(tmp_path / "3", argv=["/app/tool"])
    t3.where = "disk"
    trial.start(host, t3, {"real_display": True}, spawn)
    assert t3.room is None and t3.state == "running"
    trial.stop(host, t3)
    assert trial.status(host)["room_kept"] == trial.ROOM_KEPT


def test_the_overlays_lower_folder_is_escaped_for_mount(tmp_path):
    """overlayfs reads ":" "," and "\\" in lowerdir as separators unless escaped: a trial under a folder with one of
    them in its path would have failed to start. Run as the sandbox runs it, with a stand-in for mount."""
    import shlex
    import subprocess
    fake, got = tmp_path / "mount", tmp_path / "args"
    fake.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shlex.quote(str(got)) + "\n")
    fake.chmod(0o755)
    r = subprocess.run(["/bin/sh", "-c", trial.OVERLAY, "sh", str(fake), "/x/a:b,c\\d", "/bin/true"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert got.read_text().splitlines() == ["-t", "overlay", "overlay", "-o", "lowerdir=/x/a\\:b\\,c\\\\d:/usr", "/usr"]


# ------------------------------------------------------------------ bind sources from an unpacked tree

def test_a_bind_source_is_a_real_folder_at_every_part(tmp_path):
    """sandbox.bind_source: what bubblewrap (and the kernel, for an overlay) resolve on the computer is never reached
    through a link in a tree the app didn't write itself (the review of 2026-11-12)."""
    (tmp_path / "base/a/b").mkdir(parents=True)
    (tmp_path / "base/a/f").write_text("x")
    (tmp_path / "elsewhere").mkdir()
    os.symlink(str(tmp_path / "elsewhere"), tmp_path / "base/link")
    os.symlink("a", tmp_path / "base/rel")
    base = tmp_path / "base"
    assert sandbox.bind_source(base, "a/b") == str(base / "a/b")
    assert sandbox.bind_source(base, "a/f", kind="file") == str(base / "a/f")
    assert sandbox.bind_source(base, "missing") is None and sandbox.bind_source(base) == str(base)
    for rel, kind in (("link", "dir"), ("rel/b", "dir"), ("a/f", "dir"), ("a/b", "file"), ("a/../a", "dir")):
        with pytest.raises(sandbox.SandboxError):
            sandbox.bind_source(base, rel, kind=kind)
    with pytest.raises(sandbox.SandboxError):
        sandbox.bind_source(tmp_path / "base/link", "")             # the base itself is never a link


@pytest.mark.parametrize("part, target", [("opt", "abs"), ("opt", "rel"), ("usr", "abs"), ("usr", "rel")])
@pytest.mark.parametrize("native", [False, True])
def test_a_packages_usr_or_opt_that_links_out_of_it_is_refused(host, tmp_path, monkeypatch, part, target, native):
    """A .deb's top-level ./opt or ./usr linked out of the package (to /, to the home): bubblewrap bound what the link
    led to on the computer at /opt, or the kernel laid it over /usr. Neither command is built now, in either way of
    laying the package over /usr (bubblewrap's own overlay, or the first bubblewrap's mount)."""
    monkeypatch.setattr(trial, "native_overlay", lambda h: native)
    outside = tmp_path / "outside"
    outside.mkdir()
    t = a_trial(tmp_path, kind="deb", argv=["/usr/bin/foo"])
    other = "usr" if part == "opt" else "opt"
    (t.app / other / "bin").mkdir(parents=True)
    os.symlink(str(outside) if target == "abs" else os.path.relpath(outside, t.app), t.app / part)
    with pytest.raises(trial.TrialError, match="link to somewhere outside the package"):
        trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))
    if part == "usr":
        with pytest.raises(trial.TrialError):
            trial.package_part(t, "usr")


def test_a_real_package_keeps_its_links_inside_and_runs(host, tmp_path, monkeypatch):
    """Links inside a package resolve inside the sandbox and are left as they are; a top-level folder linked to another
    folder of the package is bound where it really is."""
    monkeypatch.setattr(trial, "native_overlay", lambda h: True)
    t = a_trial(tmp_path, kind="deb", argv=["/usr/bin/foo"])
    for d in ("usr/bin", "usr/share/foo"):
        (t.app / d).mkdir(parents=True)
    os.symlink("/opt/Foo/foo", t.app / "usr/bin/foo")
    os.symlink("usr/share/foo", t.app / "opt")
    a = trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))
    assert (str(t.app / "usr/share/foo"), "/opt") in pairs(a, "--ro-bind")
    assert a[a.index("--overlay-src") + 3] == str(t.app / "usr")


def test_a_boxs_exchange_or_home_that_became_a_link_isnt_bound(host, tmp_path):
    t = a_trial(tmp_path, argv=["/app/tool"])
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(str(elsewhere), tmp_path / "Exchange")
    t.binds = [(str(tmp_path / "Exchange"), "/home/user/Exchange")]
    with pytest.raises(trial.TrialError, match="isn't a plain folder"):
        trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))
    t.binds = []
    (t.folder / "home").rmdir()
    os.symlink(str(elsewhere), t.folder / "home")
    with pytest.raises(trial.TrialError, match="isn't a plain folder"):
        trial.ENGINES["bubblewrap"].command(host, t, parts(host, tmp_path))


def test_a_package_linked_out_of_itself_is_refused_once_unpacked(host, tmp_path):
    """prepare_file says it before a program is chosen: the stand-in unpacker leaves ./opt linked out of the package,
    as the real one did for a crafted .deb (tarfile's "tar" filter doesn't look at where links lead)."""
    src = host.home / "Downloads/pkg.deb"
    src.write_bytes(b"!<arch>\ndebian-binary   1700000000  0     0     100644  4         `\n2.0\n")
    outside = tmp_path / "outside"
    outside.mkdir()

    def unpacked(argv, **kw):
        dest = Path(argv[argv.index("/out") - 1])
        (dest / "usr/bin").mkdir(parents=True)
        (dest / "usr/bin/foo").write_text("#!/bin/sh\n")
        os.symlink(str(outside), dest / "opt")
        return SimpleNamespace(returncode=0, stderr=b"")
    (host.root / "usr/bin/bwrap").write_text("")
    with pytest.raises(trial.TrialError, match="opt folder is a link"):
        trial.prepare_file(host, src, "memory", run=unpacked)
    assert not list((host.root / "run/user/1000").glob("daprivacyscanner-trial/*")), "nothing of it is left"


# ------------------------------------------------------------------ what it may take of the computer

def _systemd(host, ok=True):
    (host.root / "run/user/1000/systemd").mkdir(parents=True, exist_ok=True)
    (host.root / "proc").mkdir(parents=True, exist_ok=True)
    (host.root / "proc/meminfo").write_text("MemTotal:       16384000 kB\nMemFree: 100 kB\n")
    host.runner.handlers["systemd-run"] = lambda argv: CommandResult(argv, 0 if ok else 1, "",
                                                                     "" if ok else "Failed to set MemoryMax")
    trial._CAPPED.clear()


def test_a_trial_runs_in_a_group_with_a_limit_on_memory_and_processes(host, tmp_path):
    """Nothing held what a trial took of the computer: a program asking for memory until there is none had the
    kernel kill something else, and one starting processes without end filled the user's own limit (the review of
    2026-11-12). The cap is the outermost part of the command, so TETHER still ends with the app and Stop still
    reaches the group."""
    _systemd(host)
    (host.root / "usr/bin/python3").write_text("")
    spawned = []
    spawn = lambda argv, **kw: spawned.append(argv) or SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    t = a_trial(tmp_path, argv=["/app/tool"])
    how = trial.start(host, t, {"real_display": True}, spawn)
    trial.stop(host, t)
    cmd = spawned[-1]
    assert cmd[:5] == ["systemd-run", "--user", "--scope", "--collect", "--quiet"]
    assert f"--description={trial.DESCRIPTION}" in cmd and "tool" not in " ".join(cmd[:8]), "the journal gets no name"
    assert f"-pMemoryMax={int(16384000 * 1024 * trial.MEMORY_SHARE)}" in cmd and f"-pTasksMax={trial.TASKS_MAX}" in cmd
    after = cmd[cmd.index("--", 5) + 1:]
    assert after[:3] == [sandbox.PYTHON, "-I", "-c"] and after[3] == trial.TETHER, "the tether is inside the group"
    assert how["capped"] == {"memory": trial.memory_cap(host), "tasks": trial.TASKS_MAX} and not how["capped_why"]
    assert trial.status(host)["capped"]["tasks"] == trial.TASKS_MAX
    assert trial.cap_env(host) == {"XDG_RUNTIME_DIR": "/run/user/1000"}, "all systemd-run needs to reach the user's bus"
    # killed for the limit, as the live test on Mint 22.3 saw (exit 137 with the cap at 200 MB): said as the limit,
    # not only as a signal
    assert "limit on the memory" in trial.ended_words(137, False, "SIGKILL", how["capped"])
    assert "limit on the memory" not in trial.ended_words(137, False, "SIGKILL", None)


def test_without_a_working_scope_the_trial_runs_uncapped_and_says_so(host, tmp_path):
    """A user manager without the memory or pids controller refuses the properties: the trial still runs (a start
    that failed would leave the user with no trial at all), and the panel says nothing limits it."""
    _systemd(host, ok=False)
    spawned = []
    spawn = lambda argv, **kw: spawned.append(argv) or SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    t = a_trial(tmp_path, argv=["/app/tool"])
    how = trial.start(host, t, {"real_display": True}, spawn)
    trial.stop(host, t)
    assert spawned[-1][0] != "systemd-run" and how["capped"] is None
    assert "MemoryMax" in how["capped_why"] and "MemoryMax" in trial.status(host)["capped_why"]
    trial._CAPPED.clear()


def test_a_flatpak_trial_is_not_capped_by_the_app(host, tmp_path):
    """flatpak run moves the app into a group of Flatpak's own, which a group of the app's doesn't hold."""
    _systemd(host)
    spawn = lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    f = a_trial(tmp_path / "f", kind="flatpak", argv=["org.x.App"], flatpak="org.x.App")
    how = trial.start(host, f, {"network": "on", "real_display": True}, spawn)
    trial.stop(host, f)
    assert how["capped"] is None and "Flatpak" in how["capped_why"]


# ------------------------------------------------------------------ what a Flatpak trial's portals leave

def test_an_autostart_entry_or_permission_a_flatpak_trial_left_is_in_the_result(host, tmp_path):
    """A Flatpak app keeps the portals (it needs the filtered bus to start at all): through them it can ask the
    desktop to start it at every login, which the desktop writes outside the sandbox (the review of 2026-11-12,
    suspected and confirmed from the portal's own behaviour). The result names what appeared while it ran."""
    auto = host.home / ".config/autostart"
    auto.mkdir(parents=True)
    (auto / "already.desktop").write_text("[Desktop Entry]\n")
    dbs = host.home / ".local/share/flatpak/db"
    dbs.mkdir(parents=True)
    (dbs / "background").write_bytes(b"old")
    spawn = lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    f = a_trial(tmp_path / "f", kind="flatpak", argv=["org.x.App"], flatpak="org.x.App")
    trial.start(host, f, {"network": "on", "real_display": True}, spawn)
    (auto / "org.x.App.desktop").write_text("[Desktop Entry]\nExec=flatpak run org.x.App\n")
    (dbs / "background").write_bytes(b"new and longer")
    trial.stop(host, f)
    assert f.result["portal"] == {"autostart": ["org.x.App.desktop"], "permissions": ["background"]}
    notes = " ".join(trial.prepare_app(host, menu.App(id="org.x.App.desktop", name="App", kind="flatpak",
                                                      argv=["flatpak", "run", "org.x.App"], flatpak="org.x.App"),
                                       "memory").notes)
    assert "autostart entry" in notes and "opening a web address in your usual browser" in notes


def test_a_trial_without_flatpak_has_nothing_of_the_portals_in_its_result(host, tmp_path):
    spawn = lambda argv, **kw: SimpleNamespace(pid=1 << 22, stdout=None)     # noqa: E731
    t = a_trial(tmp_path, argv=["/app/tool"])
    trial.start(host, t, {"real_display": True}, spawn)
    trial.stop(host, t)
    assert t.result["portal"] is None, "a trial in bubblewrap has no session bus, so no portals"


# ------------------------------------------------------------------ the sandbox's own /etc

def _etc_tree(host):
    """A computer's /etc with the leaks the review of 2026-11-12 found, and what apps need."""
    etc = host.root / "etc"
    for name in ("passwd", "group", "passwd-", "group-", "shadow", "hostname", "hosts", "machine-id", "environment",
                 "nsswitch.conf", "ld.so.cache", "mime.types", "os-release", "timezone", "resolv.conf", "locale.conf",
                 "pacman.conf", "inputrc", "magic", "shells", "lsb-release", "debian_version", "ca-certificates.conf"):
        (etc / name).write_text(f"{name}\n")
    for name in ("profile.d", "apt", "dbus-1", "at-spi2", "xml", "fonts", "gtk-3.0", "gtk-4.0", "xdg", "ssl",
                 "sddm.conf.d", "systemd/system", "NetworkManager/system-connections", "libreoffice"):
        (etc / name).mkdir(parents=True, exist_ok=True)
    (etc / "systemd/system/home-alice-Ephemeral.mount").write_text("[Mount]\n")
    zone = host.root / "usr/share/zoneinfo/Europe/Berlin"
    zone.parent.mkdir(parents=True, exist_ok=True)
    zone.write_text("")
    (etc / "localtime").symlink_to("/usr/share/zoneinfo/Europe/Berlin")


def test_the_sandboxs_etc_holds_only_what_programs_read(host, tmp_path):
    """An allowlist, as the browser's /etc is (sandbox.app_etc): the list of what to cover over the computer's own
    /etc missed passwd- and group- (the account's and the user's name, 0644 here), /etc/environment and profile.d
    (a proxy's password, a token), the mirrors, the display manager's automatic login and the app's own mount units,
    whose names hold the home's path (the review of 2026-11-12)."""
    _etc_tree(host)
    t = a_trial(tmp_path, argv=["/app/tool"])
    p = parts(host, tmp_path)
    a = trial.ENGINES["bubblewrap"].command(host, t, p)
    assert ("/etc", "/etc") not in pairs(a, "--ro-bind"), "never the computer's whole /etc"
    assert "/etc" in [a[i + 1] for i, x in enumerate(a) if x == "--tmpfs"]
    assert ["--remount-ro", "/etc"] == [a[a.index("--remount-ro")], a[a.index("--remount-ro") + 1]]
    inside = {dst for src, dst in pairs(a, "--ro-bind") + pairs(a, "--symlink")}
    for name in ("nsswitch.conf", "ld.so.cache", "mime.types", "os-release", "dbus-1", "at-spi2", "xml", "fonts",
                 "gtk-3.0", "gtk-4.0", "xdg", "ssl", "inputrc", "magic", "shells", "lsb-release", "libreoffice"):
        assert f"/etc/{name}" in inside, name
    for name in ("passwd-", "group-", "shadow", "environment", "profile.d", "apt", "locale.conf", "pacman.conf",
                 "sddm.conf.d", "systemd", "systemd/system", "NetworkManager"):
        assert f"/etc/{name}" not in inside, name
    own = {dst: src for src, dst in pairs(a, "--ro-bind")}
    for name in ("passwd", "group", "hostname", "hosts", "machine-id"):
        assert own[f"/etc/{name}"] == str(p.etc[name]), name
    links = {dst: src for src, dst in pairs(a, "--symlink")}
    assert links["/etc/localtime"] == "/usr/share/zoneinfo/Europe/Berlin", "the user's own times"
    assert "/etc/resolv.conf" not in inside, "no network, no resolver: not the computer's servers or search domain"


def test_the_sandboxs_etc_names_pastas_resolver_when_the_network_is_observed(host, tmp_path):
    _etc_tree(host)
    t = a_trial(tmp_path, argv=["/app/tool"])
    p = parts(host, tmp_path, resolv=sandbox.FORWARD_RESOLV, pasta="pasta", pcap=tmp_path / "packets")
    a = trial.ENGINES["bubblewrap"].command(host, t, p)
    assert (str(p.etc["resolv.conf"]), "/etc/resolv.conf") in pairs(a, "--ro-bind")
    assert p.etc["resolv.conf"].read_text() == sandbox.FORWARD_RESOLV
