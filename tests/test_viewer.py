"""View offline… (tools/viewer.py): a download opened in the desktop's own viewer with no network, from a
copy the browser can't reach. Nothing here runs bubblewrap or a viewer."""

from __future__ import annotations

import os

import pytest

from daprivacyscanner.host import CommandResult
from daprivacyscanner.tools import viewer as V

from test_browser_sandbox import H, Proc, app_for, bwrap_ok, check, env_of, host, installed, old, pairs, wayland  # noqa: F401
from daprivacyscanner.tools import transfer as T

PDF = b"%PDF-1.7\n1 0 obj << /URI (https://example.com/track) >> endobj\n%%EOF\n"


def desktop(host, app_id, exec_, extra=""):
    d = host.root / "usr/share/applications"
    d.mkdir(parents=True, exist_ok=True)
    (d / app_id).write_text(f"[Desktop Entry]\nName=Document Viewer\nExec={exec_}\n{extra}[Desktop Action new]\nExec=other\n")


def set_up(host, default="xreader.desktop", exec_="xreader %U", extra=""):
    installed(host, "tor")
    T.prepare(host, "tor-browser")
    d = T.downloads_dir(host, "tor-browser")
    (d / "report.pdf").write_bytes(PDF)
    old(d / "report.pdf")
    (host.root / "usr/bin").mkdir(parents=True, exist_ok=True)
    (host.root / "usr/bin/xreader").write_text("")
    desktop(host, default, exec_, extra)
    asked = []
    host.runner.handlers["xdg-mime"] = lambda argv: asked.append(argv) or CommandResult(tuple(argv), 0, default + "\n")
    wayland(host)
    bwrap_ok(host)
    return asked


def test_the_plan_names_the_viewer_and_its_command(host):
    asked = set_up(host)
    v = V.plan(host, "tor-browser", "report.pdf")
    assert asked == [("xdg-mime", "query", "default", "application/pdf")]
    assert v.app == "Document Viewer" and v.argv == ["/usr/bin/xreader", "/home/user/report.pdf"] and not v.flatpak


def unseal(argv: list[str]) -> list[str]:
    """bubblewrap's command with its options written out again (sandbox.sealed passes them through a descriptor,
    read here while the spawn is under way)."""
    i = argv.index("--args")
    fd = int(argv[i + 1])
    data = os.pread(fd, 1 << 20, 0)
    return [*argv[:i], *(a.decode() for a in data.split(b"\0")[:-1]), *argv[i + 2:]]


def test_it_opens_a_copy_with_no_network(host):
    set_up(host)
    calls = []

    def spawn(argv, **kw):
        assert argv[1] == "--args" and int(argv[2]) in kw["pass_fds"] and kw["env"] == V.sandbox.SPAWN_ENV
        calls.append((unseal(argv), kw))
        p = Proc()
        p.pid = 4_194_400                       # above any pid_max: a viewer that has ended
        return p
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    got = V.view(host, "tor-browser", "report.pdf", private, spawn, check(host, "report.pdf"))
    [(argv, kw)] = calls
    assert argv[0] == "bwrap" and "--unshare-all" in argv and "--share-net" not in argv      # no python3 in the fixture
    if V.seccomp.supported():                           # its system-call filter: strict, a memory file passed to it
        fd = int(argv[argv.index("--seccomp") + 1])
        assert fd in kw["pass_fds"] and got["nesting"] is None
    copies = [src for src, dst in pairs(argv, "--ro-bind") if dst == "/home/user/report.pdf"]
    assert len(copies) == 1
    copy = copies[0]
    assert "/TempBrowser/.view-" in copy and "tor-browser" not in copy.split("/TempBrowser/")[1]   # out of its reach
    assert open(copy, "rb").read() == PDF and oct(os.stat(copy).st_mode & 0o777) == "0o400"
    assert argv[argv.index("--") + 1:] == ["/usr/bin/xreader", "/home/user/report.pdf"]
    assert ("/run/user/" + str(os.getuid()) + "/wayland-0", "/run/user/1000/wayland-0") in pairs(argv, "--ro-bind")
    e = env_of(argv)
    assert e["HOME"] == "/home/user" and "DBUS_SESSION_BUS_ADDRESS" not in e and "PULSE_SERVER" not in e
    assert e["__GLX_VENDOR_LIBRARY_NAME"] == "mesa" and e["LIBGL_ALWAYS_SOFTWARE"] == "1"     # no GPU in its sandbox
    assert got["app"] == "Document Viewer" and got["whole"].startswith("bwrap --unshare-all")
    # the next view removes copies nobody holds any more
    V.view(host, "tor-browser", "report.pdf", private, spawn, check(host, "report.pdf"))
    assert not os.path.exists(copy) and len(list((host.home / "TempBrowser").glob(".view-*"))) == 1


def test_a_flatpak_viewer_loses_its_network(host):
    """In Flatpak's own sandbox with what it declares dropped (--sandbox), and only the display, the filtered session
    bus with its own name, and the copy's folder, read-only, put back: no GVFS, no sound (the 2026-10-17 review)."""
    set_up(host, "org.gnome.Papers.desktop",
           "/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=papers --file-forwarding "
           "--filesystem=home org.gnome.Papers @@u %U @@", "X-Flatpak=org.gnome.Papers\n")
    asked = []
    host.runner.handlers["flatpak"] = lambda argv: asked.append(argv) or CommandResult(tuple(argv), 0, "")
    calls = []
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    got = V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: calls.append(argv) or Proc(),
                 check(host, "report.pdf"))
    [argv] = calls
    assert ("flatpak", "ps", "--columns=pid,application") in asked          # not already open (it would be handed it)
    app = argv.index("org.gnome.Papers")
    opts = argv[2:app]
    assert argv[:2] == ["flatpak", "run"] and opts[:len(V.FLATPAK_RUN)] == list(V.FLATPAK_RUN)
    assert {"--sandbox", "--unshare=network", "--no-talk-name=org.gtk.vfs.*", "--nosocket=pulseaudio"} <= set(opts)
    assert "--own-name=org.gnome.Papers" in opts and "--socket=wayland" in opts and "--socket=x11" not in opts
    [folder] = [o for o in opts if o.startswith("--filesystem=")]
    assert folder.startswith(f"--filesystem={host.home}/TempBrowser/.view-") and folder.endswith(":ro")
    assert "--branch=stable" in opts and "--arch=x86_64" in opts                # the launcher's own: only these
    assert not any(a in argv for a in ("--filesystem=home", "--file-forwarding", "@@u", "@@"))
    copy = argv[-1]
    assert copy == folder[len("--filesystem="):-len(":ro")] + "/report.pdf" and open(copy, "rb").read() == PDF
    assert got["flatpak"] == "org.gnome.Papers"
    assert "usual browser" in got["notes"][0] and "in memory" in got["notes"][0] and "screen reader" in got["notes"][0]
    # what it would remember goes to its own /tmp, in memory, as well
    assert "--command=env" in argv[:app] and not any(a == "--command=papers" for a in argv)
    assert argv[app + 1:app + 1 + len(V.FLATPAK_MEMORY)] == list(V.FLATPAK_MEMORY)
    assert argv[app + 1 + len(V.FLATPAK_MEMORY)] == "papers"


def test_a_flatpak_viewer_s_own_command_comes_from_its_metadata(host):
    """A launcher without --command: the app's command from `flatpak info --show-metadata`; none, not started."""
    set_up(host, "org.gnome.Papers.desktop", "/usr/bin/flatpak run org.gnome.Papers %U", "X-Flatpak=org.gnome.Papers\n")
    meta = "[Application]\nname=org.gnome.Papers\nruntime=org.gnome.Platform/x86_64/50\ncommand=papers\n\n[Context]\nshared=ipc;\n"
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(tuple(argv), 0, meta)
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    calls = []
    V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: calls.append(argv) or Proc(),
           check(host, "report.pdf"))
    [argv] = calls
    app = argv.index("org.gnome.Papers")
    assert "--command=env" in argv[:app] and argv[app + 1 + len(V.FLATPAK_MEMORY)] == "papers"
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(tuple(argv), 0, "[Context]\nshared=ipc;\n")
    with pytest.raises(V.ViewError, match="can't be told"):
        V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: Proc(), check(host, "report.pdf"))


@pytest.mark.parametrize("exec_, extra, says", [
    ("/snap/bin/okular %U", "", "Snap"),
    ("/home/alice/.local/bin/viewer %f", "", "isn't in the system's folders"),
    ("", "", "no command"),
])
def test_viewers_it_wont_start(host, exec_, extra, says):
    set_up(host, exec_=exec_, extra=extra)
    with pytest.raises(V.ViewError, match=says):
        V.plan(host, "tor-browser", "report.pdf")


def test_never_a_program_or_an_archive(host):
    set_up(host)
    d = T.downloads_dir(host, "tor-browser")
    (d / "invoice.pdf").write_bytes(b"\x7fELF" + bytes(64))
    old(d / "invoice.pdf")
    with pytest.raises(V.ViewError, match="isn't a document or picture"):
        V.plan(host, "tor-browser", "invoice.pdf")
    with pytest.raises(V.ViewError, match="isn't one of the browser's downloads"):
        V.plan(host, "tor-browser", "../../.bashrc")
    with pytest.raises(V.ViewError, match="isn't a finished download"):
        V.plan(host, "tor-browser", "nope.pdf")


def test_a_viewer_that_fails_says_why(host, monkeypatch):
    set_up(host)
    monkeypatch.setattr(V, "WATCH", 0.05)
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)

    def spawn(argv, **kw):
        os.write(kw["stderr"], b"bwrap: execvp /usr/bin/xreader: No such file or directory\n")
        return Proc(rc=1)
    # the app's words; what the sandbox wrote only quoted (the review of 2026-11-12)
    with pytest.raises(V.ViewError, match="couldn't open it: its sandbox couldn't be set up \\(its start log says "
                                          "“bwrap: execvp /usr/bin/xreader: No such file or directory”\\)"):
        V.view(host, "tor-browser", "report.pdf", private, spawn, check(host, "report.pdf"))


def test_a_download_changed_after_it_was_listed_is_not_opened(host):
    set_up(host)
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    shown = check(host, "report.pdf")
    d = T.downloads_dir(host, "tor-browser")
    (d / "report.pdf").write_bytes(b"%PDF-1.7\n/JavaScript (app.alert(1))\n%%EOF\n")
    old(d / "report.pdf")
    calls = []
    with pytest.raises(T.Changed):
        V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: calls.append(argv) or Proc(), shown)
    assert calls == [] and not list((host.home / "TempBrowser").glob(".view-*"))


def test_no_viewer_leaves_no_copy(host):
    set_up(host, exec_="/snap/bin/okular %U")
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    with pytest.raises(V.ViewError, match="Snap"):
        V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: Proc(), check(host, "report.pdf"))
    assert not list((host.home / "TempBrowser").glob(".view-*/*"))


def test_through_the_api(cat, host):
    set_up(host)
    c = app_for(cat, host)
    listed = c.get("/api/tools/browser", headers=H).json()["browsers"][0]["downloads"]
    assert listed[0]["name"] == "report.pdf" and listed[0]["viewable"] and listed[0]["what"] == "a PDF"
    r = c.post("/api/tools/browser/view", headers=H, json={"browser": "tor", "name": "report.pdf", "open": False}).json()
    assert r["viewer"]["command"] == "/usr/bin/xreader /home/user/report.pdf"
    r = c.post("/api/tools/browser/view", headers=H, json={"browser": "tor", "name": "nope.pdf", "open": False})
    assert r.status_code == 400


def test_a_view_leaves_the_browser_s_own_files_alone(host):
    """The browser's sandbox sees its X authority file and /etc files read-only, by inode: a view writes its
    own in a folder of its own, never over the browser's (a new cookie or boot id under a running browser)."""
    set_up(host)
    private = host.home / "TempBrowser/.tor-browser-app"
    (private / "etc").mkdir(parents=True)
    (private / "etc/boot_id").write_text("the browser's\n")
    (private / "Xauthority").write_bytes(b"the browser's")
    calls = []
    V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: calls.append(argv) or Proc(), check(host, "report.pdf"))
    assert (private / "etc/boot_id").read_text() == "the browser's\n" and (private / "Xauthority").read_bytes() == b"the browser's"
    own = private / "view"
    assert (own / "etc/boot_id").exists() and not (own / "view.log").exists()     # the log is a memory file


def test_on_wayland_the_viewer_gets_a_socket_marked_as_a_sandbox_s(host, monkeypatch):
    """As the browser's: the compositor keeps screen recording and the clipboard in the background from it."""
    set_up(host)
    monkeypatch.setattr(V, "_socket", lambda h, path: "/run/compositor-0")
    made = {}

    def sandbox_socket(compositor, path, app_id):
        r, w = os.pipe()
        made.update(compositor=compositor, path=path, app_id=app_id, read=r, write=w)
        return w
    monkeypatch.setattr(V.wayland, "sandbox_socket", sandbox_socket)
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    calls = []
    V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: calls.append((unseal(argv), kw)) or Proc(),
           check(host, "report.pdf"))
    [(argv, kw)] = calls
    w = made["write"]
    assert made["compositor"] == "/run/compositor-0" and made["path"].parent == private / "view"
    assert (str(made["path"]), "/run/user/1000/wayland-0") in pairs(argv, "--ro-bind")
    assert argv[argv.index("--sync-fd") + 1] == str(w) and kw["pass_fds"][0] == w
    assert len(kw["pass_fds"]) == 2 + V.seccomp.supported()                     # and --args, and the filter
    with pytest.raises(OSError):
        os.fstat(w)                                                     # the app's copy is closed
    os.close(made["read"])


def test_a_copy_a_viewer_has_mapped_is_held(host):
    """A viewer that maps the file and closes it still uses it: the next view doesn't overwrite it."""
    f = host.home / "copy.pdf"
    f.write_bytes(PDF)
    st = os.stat(f)
    proc = host.root / "proc/4242"
    (proc / "fd").mkdir(parents=True)
    (proc / "maps").write_text(f"7f00-7f01 r--s 00000000 {os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x} "
                               f"{st.st_ino}                    /home/user/copy.pdf\n"
                               "7f02-7f03 r-xp 00000000 00:00 0 \n")
    assert (st.st_dev, st.st_ino) in V._held(host)


def test_the_viewers_etc_holds_only_what_programs_read(host, tmp_path):
    """As a trial's (sandbox.app_etc): the list of what to cover over the computer's own /etc missed passwd-,
    /etc/environment, the mirrors and more (the review of 2026-11-12). A viewer opens a file a website gave the
    browser."""
    set_up(host)
    etc = host.root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    for name in ("passwd", "group", "passwd-", "group-", "environment", "nsswitch.conf", "hostname", "hosts",
                 "machine-id", "resolv.conf", "mime.types"):
        (etc / name).write_text(name)
    for name in ("profile.d", "apt", "dbus-1", "fonts", "NetworkManager"):
        (etc / name).mkdir(parents=True, exist_ok=True)
    own = tmp_path / "own"
    own.mkdir()
    copy = tmp_path / "stage"
    copy.mkdir()
    (copy / "report.pdf").write_bytes(PDF)
    v = V.Viewer("Document Viewer", "xreader.desktop", ["/usr/bin/xreader", "/home/user/report.pdf"])
    a = V.argv(host, v, copy / "report.pdf", "report.pdf", own, V.sandbox.Display("x11", [], {}))
    inside = {dst for src, dst in pairs(a, "--ro-bind") + pairs(a, "--symlink")}
    assert ("/etc", "/etc") not in pairs(a, "--ro-bind") and "/etc/dbus-1" in inside and "/etc/fonts" in inside
    for name in ("passwd-", "group-", "environment", "profile.d", "apt", "NetworkManager", "resolv.conf"):
        assert f"/etc/{name}" not in inside, name
    own_files = {dst: src for src, dst in pairs(a, "--ro-bind")}
    assert own_files["/etc/passwd"].endswith("/etc/passwd") and own_files["/etc/passwd"] != "/etc/passwd"


def test_a_copy_replaced_by_a_link_isnt_given_to_the_viewer(host, tmp_path):
    """The copy is bound by itself, never through a link in its place (sandbox.bind_source), as trials' and Boxes'
    folders are (the review of 2026-11-12)."""
    set_up(host)
    own = tmp_path / "own"
    own.mkdir()
    stage = tmp_path / "stage"
    stage.mkdir()
    (tmp_path / "elsewhere.pdf").write_bytes(PDF)
    os.symlink(str(tmp_path / "elsewhere.pdf"), stage / "report.pdf")
    v = V.Viewer("Document Viewer", "xreader.desktop", ["/usr/bin/xreader", "/home/user/report.pdf"])
    disp = V.sandbox.Display("x11", [], {})
    with pytest.raises(V.ViewError, match="isn't a plain file"):
        V.argv(host, v, stage / "report.pdf", "report.pdf", own, disp)
    os.unlink(stage / "report.pdf")
    (stage / "report.pdf").write_bytes(PDF)
    a = V.argv(host, v, stage / "report.pdf", "report.pdf", own, disp)
    assert (str(stage / "report.pdf"), "/home/user/report.pdf") in pairs(a, "--ro-bind")


def test_on_x11_the_viewer_gets_a_display_of_its_own_or_this_one_only_when_ticked(host, monkeypatch):
    """The review of 2026-11-12: a viewer a hostile file took over, given the X server's socket, could read and type
    into every other window. Xephyr first, its focus keeper sizing the viewer's window to it, the viewer's sandbox
    given Xephyr's socket alone; without Xephyr only when the user ticked that it may."""
    set_up(host)
    del host.environ["WAYLAND_DISPLAY"]
    (host.root / "tmp/.X11-unix").mkdir(parents=True, exist_ok=True)
    (host.root / "tmp/.X11-unix/X0").write_text("")
    (host.root / "proc/net").mkdir(parents=True, exist_ok=True)
    (host.root / "proc/net/unix").write_text("")
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    with pytest.raises(V.ViewError, match="tick that it may use this display"):
        V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: pytest.fail("started"),
               check(host, "report.pdf"))
    calls = []
    V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: calls.append(unseal(argv)) or Proc(),
           check(host, "report.pdf"), real_display=True)
    [argv] = calls
    assert ("/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0") in pairs(argv, "--ro-bind")           # this display, as ticked
    host.runner.handlers["Xephyr"] = lambda argv: CommandResult(tuple(argv), 0)
    calls.clear()

    class Server(Proc):
        pid = 4_194_401

        def poll(self):
            return None

    def spawn(argv, **kw):
        if "Xephyr" in argv:
            calls.append(argv)
            sock = V.wayland.socket.socket(V.wayland.socket.AF_UNIX)
            V.wayland._bind(sock, private / "view/x11/X1")              # a long path, through its folder
            return Server()
        calls.append(unseal(argv))
        return Proc()
    got = V.view(host, "tor-browser", "report.pdf", private, spawn, check(host, "report.pdf"))
    xephyr, viewer = calls
    assert "Xephyr" in xephyr and ("--seccomp" in xephyr) is V.seccomp.supported()      # Xephyr's own: strict
    assert ("/tmp/.X11-unix/X0", "/tmp/.X11-unix/X0") in pairs(xephyr, "--ro-bind")
    ro = pairs(viewer, "--ro-bind")
    assert (str(private / "view/x11/X1"), "/tmp/.X11-unix/X99") in ro and not any(s.endswith("X11-unix/X0") for s, _ in ro)
    assert got["app"] == "Document Viewer"
