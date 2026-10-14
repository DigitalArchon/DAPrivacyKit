"""Smoke test for an extracted AppImage, run by the AppImage's own Python inside a distro
container with a virtual display (see packaging/test-appimage.sh).

    smoke.py <AppDir> <out-dir> <name> fallback   WebKitGTK absent: a terminal scan; the app refuses to open
                                                  without its window and says why; with --browser it opens in
                                                  the browser, says what that exposes, and scans through the API
    smoke.py <AppDir> <out-dir> <name> full       WebKitGTK present: the app window, and a screenshot
                                                  of the page rendered by the host's WebKitGTK"""

import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

APPDIR, OUT, NAME, MODE = sys.argv[1:5]
ENV = {**os.environ, "XDG_CONFIG_HOME": "/tmp/smoke/config", "XDG_DATA_HOME": "/tmp/smoke/data",
       "XDG_STATE_HOME": "/tmp/smoke/state", "XDG_CACHE_HOME": "/tmp/smoke/cache"}
PORT = 8790


def check(ok: bool, what: str) -> None:
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    if not ok:
        raise SystemExit(1)


def start(*args: str) -> tuple[subprocess.Popen, str, str, str]:
    """Run the app; once it prints its one-time link, open it as a browser would: the page that comes back
    carries the session token in its body (data-token), which every API call then sends as X-Token."""
    proc = subprocess.Popen([f"{APPDIR}/AppRun", "--port", str(PORT), *args], env=ENV, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = []
    for line in proc.stdout:
        log.append(line)
        print(f"  | {line.rstrip()}")
        if line.startswith("http://"):
            page = urllib.request.urlopen(line.strip(), timeout=10).read().decode()
            m = re.search(r'<body data-token="([^"]+)">', page)
            check(m is not None, f"{NAME}: the one-time link gives the page its session token")
            return proc, html.unescape(m.group(1)), page, "".join(log)
    raise SystemExit("the app exited before printing its link")


def api(token: str, method: str, path: str, body: dict | None = None):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method,
                                 headers={"X-Token": token, "Content-Type": "application/json"},
                                 data=json.dumps(body).encode() if body is not None else None)
    data = urllib.request.urlopen(req, timeout=120).read()
    return json.loads(data) if data[:1] in (b"{", b"[") else data.decode()


def errors_of(report: dict) -> list[str]:
    return [f"{cid}: {r.get('error')}" for cid, r in report["results"].items() if r["status"] == "error"]


if MODE == "fallback":
    # a terminal scan: the catalogue, every check and the report, with no window at all
    r = subprocess.run([f"{APPDIR}/AppRun", "--scan", "--json"], env=ENV, capture_output=True, text=True, timeout=300)
    report = json.loads(r.stdout)["report"] if r.stdout.startswith("{") else None
    check(r.returncode in (0, 1) and report is not None and len(report["results"]) > 80,
          f"{NAME}: a terminal scan runs every check" + ("" if report else f"\n  | {r.stderr[-800:]}"))
    errs = errors_of(report)
    check(not errs, f"{NAME}: no check fails with an error" + "".join(f"\n  | {e}" for e in errs))
    # without its window it stops and says why: never the browser unasked
    r = subprocess.run([f"{APPDIR}/AppRun", "--port", str(PORT)], env=ENV, capture_output=True, text=True, timeout=60)
    check(r.returncode == 2 and "WebKitGTK" in r.stderr and "--browser" in r.stderr and "http://" not in r.stdout,
          f"{NAME}: without WebKitGTK it says why and doesn't open the browser by itself")
    # webbrowser honours $BROWSER: "echo" stands in for opening a browser
    proc, token, _, log = start("--browser")
    check("running in your web browser" in log and "extension" in log,
          f"{NAME}: with --browser it opens in the browser and says what that exposes")
    st = api(token, "GET", "/api/state")
    check(len(st["catalogue"]) > 80 and not st["helper_installed"], f"{NAME}: the page's state loads")
    rep = api(token, "POST", "/api/scan", {})
    check(not errors_of(rep), f"{NAME}: a scan through the server")
    text = api(token, "GET", "/api/export")
    check(text.startswith("DA Privacy Kit: everything it keeps"), f"{NAME}: Export everything")
    api(token, "POST", "/api/quit")
    proc.wait(10)
    check(proc.returncode is not None, f"{NAME}: Quit ends the process")
    sys.exit(0)

# --- full: the app window first
win = subprocess.Popen([f"{APPDIR}/AppRun"], env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(8)
alive = win.poll() is None
win.terminate()
log = win.communicate(timeout=10)[0]
ok = alive and "Traceback" not in log and "WebKitGTK" not in log
check(ok, f"{NAME}: the app window starts and stays up" + ("" if ok else "\n" + "\n".join(f"  | {x}" for x in log.splitlines()[-15:])))

# the page itself, rendered by the host's WebKitGTK through the bundled PyGObject, after a scan
proc, token, page, _ = start("--browser", "--no-open")
api(token, "POST", "/api/scan", {})
sys.path.insert(0, f"{APPDIR}/usr/python/lib/python3.12/site-packages")
from daprivacyscanner.app import _bundled_girepository  # noqa: E402

_bundled_girepository()
import gi  # noqa: E402

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import GLib, Gtk, WebKit2  # noqa: E402

shot = f"{OUT}/{NAME}.png"
window = Gtk.OffscreenWindow()
view = WebKit2.WebView()
view.set_size_request(1400, 900)
window.add(view)
window.show_all()


def snap() -> bool:
    view.get_snapshot(WebKit2.SnapshotRegion.VISIBLE, WebKit2.SnapshotOptions.NONE, None,
                      lambda v, r: (v.get_snapshot_finish(r).write_to_png(shot), Gtk.main_quit()))
    return False


# the page the one-time link gave, at the app's address: it takes its token from its body, as at a real launch
view.connect("load-changed", lambda v, e: e == WebKit2.LoadEvent.FINISHED and GLib.timeout_add(3000, snap))
view.load_html(page, f"http://127.0.0.1:{PORT}/")
GLib.timeout_add(40000, Gtk.main_quit)
Gtk.main()
check(os.path.exists(shot), f"{NAME}: the page renders ({shot})")
api(token, "POST", "/api/quit")
proc.wait(10)
