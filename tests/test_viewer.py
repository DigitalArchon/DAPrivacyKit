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


def test_it_opens_a_copy_with_no_network(host):
    set_up(host)
    calls = []

    def spawn(argv, **kw):
        calls.append((argv, kw))
        return Proc()
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    got = V.view(host, "tor-browser", "report.pdf", private, spawn, check(host, "report.pdf"))
    [(argv, kw)] = calls
    assert argv[0] == "bwrap" and "--unshare-all" in argv and "--share-net" not in argv      # no python3 in the fixture
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
    set_up(host, "org.gnome.Papers.desktop",
           "/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=papers --file-forwarding org.gnome.Papers @@u %U @@",
           "X-Flatpak=org.gnome.Papers\n")
    host.runner.handlers["flatpak"] = lambda argv: CommandResult(tuple(argv), 0, "[Context]\nshared=network;ipc;\n"
        "filesystems=xdg-run/gvfsd;xdg-download:ro;home;!xdg-config/kdeglobals;\n")
    calls = []
    private = host.home / "TempBrowser/.tor-browser-app"
    private.mkdir(parents=True, exist_ok=True)
    got = V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: calls.append(argv) or Proc(),
                 check(host, "report.pdf"))
    [argv] = calls
    assert argv[:3] == ["/usr/bin/flatpak", "run", "--unshare=network"] and argv[-3] == "@@u"
    assert "--nofilesystem=home" in argv and "--nofilesystem=xdg-download" in argv and "--nofilesystem=xdg-run/gvfsd" in argv
    assert not any(a.startswith("--nofilesystem=!") for a in argv)
    assert "/TempBrowser/.view-" in argv[-2] and got["flatpak"] == "org.gnome.Papers"
    assert "usual browser" in got["notes"][0] and "kept in memory" in got["notes"][0]
    # what it would remember goes to its own /tmp, in memory, not ~/.var/app (Evince wrote the file's name there)
    app = argv.index("org.gnome.Papers")
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
    with pytest.raises(V.ViewError, match="couldn't open it: bwrap: execvp"):
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
    assert (own / "view.log").exists() and (own / "etc/boot_id").exists()


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
    V.view(host, "tor-browser", "report.pdf", private, lambda argv, **kw: calls.append((argv, kw)) or Proc(),
           check(host, "report.pdf"))
    [(argv, kw)] = calls
    w = made["write"]
    assert made["compositor"] == "/run/compositor-0" and made["path"].parent == private / "view"
    assert (str(made["path"]), "/run/user/1000/wayland-0") in pairs(argv, "--ro-bind")
    assert argv[argv.index("--sync-fd") + 1] == str(w) and kw["pass_fds"] == (w,)
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
