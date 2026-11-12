"""The page in a real WebKitGTK (pywebview's window, as the app shows it), against a canned API: what jsdom can't see.

Run by tests/test_webkit_smoke.py on a private Xvfb display it starts and stops (never the user's display): DISPLAY
must name it. It checks, with real keyboard and mouse events (xdotool, XTEST, on that display alone):

  - Tab and Shift+Tab go round inside a dialog, the page behind out of reach;
  - a press on Remove metadata's Stop while its progress is drawn again every 400 ms, released after two drawings,
    still clicks it (the panel used to be drawn anew, and the click was lost);
  - the page breaks none of its Content-Security-Policy (a securitypolicyviolation listener, loaded before the page's
    script from the page's own origin, counts them);

and saves a screenshot of the page in each theme, and of a dialog, into --out. Prints one line of JSON: the results.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WEB = ROOT / "src" / "daprivacyscanner" / "web"
TITLE = "DA Privacy Kit smoke test"
TOKEN = "smoke-token"

PROBE = """// loaded before the page's own script: every breach of the page's Content-Security-Policy, counted
window.__violations = [];
document.addEventListener("securitypolicyviolation", (e) => {
  window.__violations.push({ directive: e.violatedDirective, blocked: e.blockedURI, source: e.sourceFile, line: e.lineNumber,
                             sample: e.sample || "" });
});
"""


def pywebviews(v: dict) -> bool:
    """A breach by pywebview's own injected script, not the page's: it adds <style> elements (customize.js, to make text
    unselectable; api.js's _loadCss), which the page's CSP refuses; the page itself never makes one. Attributed to the
    document, not to /static/app.js."""
    return v["directive"].startswith("style-src") and v["blocked"] == "inline" and not v["source"].endswith("/static/app.js")


def fixture() -> dict:
    sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "src")]
    from test_web import fixture_state
    with tempfile.TemporaryDirectory() as d:
        state = fixture_state(Path(d))["state"]
    state["welcome"] = {**state.get("welcome", {}), "show": False}
    state["in_browser"] = False
    return state


class Canned:
    """The API's answers the page asks for here, and what it sent."""

    def __init__(self, state: dict):
        self.state = state
        self.posted: list[str] = []
        self.polls = 0
        self.stopped = False

    def job(self) -> dict:
        self.polls += 1
        state = "stopped" if self.stopped and self.polls % 3 == 0 else "running"
        return {"kind": "read", "state": state, "phase": "Reading what the files carry", "done": min(self.polls, 999),
                "total": 1000, "current": f"photo-{self.polls}.jpg", "paths": ["/home/user/Pictures"], "hidden": False,
                "selection": None, "result": None, "error": "", "stopping": self.stopped}

    def answer(self, method: str, path: str):
        if method == "GET" and path == "/api/state":
            return self.state
        if method == "GET" and path == "/api/online/status":
            return {"job": None, "admin_active": False}
        if method == "GET" and path == "/api/tools":
            return {"tools": [], "groups": [], "features": [], "can_pick": False, "downloads": [],
                    "downloads_dir": "~/Downloads", "verify": {"gpgv": True, "sqv": False, "install": None},
                    "metadata": {"mat2": {"installed": True, "install": ""}, "exiftool": {"installed": True, "install": ""},
                                 "sandbox": {"available": True, "why": ""}}, "admin_active": False}
        if method == "GET" and path == "/api/tools/metadata/job":
            return {"job": self.job()}
        if method == "POST" and path == "/api/tools/metadata/stop":
            self.stopped = True
            return {"job": self.job()}
        return None


def serve(canned: Canned) -> ThreadingHTTPServer:
    from daprivacyscanner.server import SECURITY_HEADERS

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):          # quiet
            pass

        def send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Admin-Active", "0")
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def handle_any(self, method: str):
            path = self.path.split("?")[0]
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                canned.posted.append(path)
            if path == "/":
                page = (WEB / "index.html").read_text(encoding="utf-8")
                page = page.replace("<body>", f'<body data-token="{TOKEN}">', 1)
                page = page.replace('<script src="/static/app.js">', '<script src="/static/smoke-probe.js"></script>\n'
                                    '<script src="/static/app.js">', 1)
                return self.send(200, page.encode(), "text/html; charset=utf-8")
            if path == "/static/smoke-probe.js":
                return self.send(200, PROBE.encode(), "text/javascript")
            if path.startswith("/static/"):
                f = (WEB / path.removeprefix("/static/")).resolve()
                if f.parent != WEB or not f.is_file():
                    return self.send(404, b"", "text/plain")
                ctype = {".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml",
                         ".jpg": "image/jpeg"}.get(f.suffix, "application/octet-stream")
                return self.send(200, f.read_bytes(), ctype)
            data = canned.answer(method, path)
            if data is None:
                return self.send(404, json.dumps({"detail": f"no canned answer for {method} {path}"}).encode(),
                                 "application/json")
            return self.send(200, json.dumps(data).encode(), "application/json")

        def do_GET(self):
            self.handle_any("GET")

        def do_POST(self):
            self.handle_any("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def xdo(*args: str) -> str:
    return subprocess.run(["xdotool", *args], capture_output=True, text=True, timeout=20,
                          env={**os.environ}).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    out = Path(ap.parse_args().out)
    out.mkdir(parents=True, exist_ok=True)
    if not os.environ.get("DISPLAY", "").startswith(":9"):
        print(json.dumps({"error": "DISPLAY must be a private Xvfb display (:9x)"}))
        return 2
    os.environ.pop("WAYLAND_DISPLAY", None)
    os.environ["GDK_BACKEND"] = "x11"

    canned = Canned(fixture())
    srv = serve(canned)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"

    import gi
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk, GLib

    import webview

    res: dict = {"checks": {}, "notes": [], "shots": []}
    window = webview.create_window(TITLE, url, width=1360, height=880)

    def js(code: str):
        # run as it is: evaluate_js wraps it in an eval(), which the page's CSP refuses (as the app's own CloseGuard)
        return window.run_js(code)

    def shot(name: str):
        """The whole private display, saved as PNG (in the GTK thread, as GDK wants)."""
        done = threading.Event()
        path = out / f"{name}.png"

        def grab():
            try:
                root = Gdk.get_default_root_window()
                pb = Gdk.pixbuf_get_from_window(root, 0, 0, root.get_width(), root.get_height())
                pb.savev(str(path), "png", [], [])
                res["shots"].append(str(path))
            except Exception as e:  # noqa: BLE001 - a missing screenshot is a note, not a failure of the page
                res["notes"].append(f"screenshot {name}: {e}")
            done.set()
            return False

        GLib.idle_add(grab)
        done.wait(10)

    def wait_for(code: str, seconds: float = 20) -> bool:
        # as a string: run_js gives back what JavaScriptCore converts, and a string is the one sure to come back as it is
        end, last = time.monotonic() + seconds, None
        while time.monotonic() < end:
            try:
                last = js(f"String(!!({code}))")
                if last == "true":
                    return True
            except Exception as e:  # noqa: BLE001 - not loaded yet
                last = repr(e)
            time.sleep(0.2)
        res["notes"].append(f"waited for {code}: {last}")
        return False

    def check(name: str, ok: bool, detail=None):
        res["checks"][name] = {"ok": bool(ok), "detail": detail}

    def run():
        try:
            window.events.loaded.wait(40)
            if not wait_for("typeof S !== 'undefined' && !!S.state && !!document.querySelector('#checks-list .citem')"):
                check("loaded", False, js("document.body ? document.body.innerText.slice(0, 300) : ''"))
                return
            check("loaded", True)
            wid = xdo("search", "--sync", "--name", TITLE).split("\n")[0]
            xdo("windowfocus", "--sync", wid)
            geo = dict(line.split("=", 1) for line in xdo("getwindowgeometry", "--shell", wid).splitlines() if "=" in line)
            wx, wy = int(geo.get("X", 0)), int(geo.get("Y", 0))
            wait_for("document.querySelector('#scan-info').textContent.startsWith('Scanned')")
            time.sleep(1.0)                                    # painted
            shot("page-dark")

            # --- Tab goes round inside a dialog, with real key events
            js("modal({ title: 'Smoke test', body: [h('input', { type: 'text', id: 'smoke-field' })], "
               "buttons: [{ label: 'No' }, { label: 'Yes', kind: 'primary' }] }); true")
            time.sleep(0.3)
            seen = []
            where = "(() => { const a = document.activeElement; return a.id || a.textContent || a.tagName; })()"
            for _ in range(4):
                xdo("key", "--clearmodifiers", "Tab")
                time.sleep(0.15)
                seen.append(js(where))
            xdo("key", "--clearmodifiers", "shift+Tab")
            time.sleep(0.15)
            back = js(where)
            inside = js("!!document.activeElement.closest('.modal')")
            check("tab_cycle", seen == ["smoke-field", "No", "Yes", "smoke-field"] and back == "Yes" and inside,
                  {"tab": seen, "shift_tab": back})
            shot("dialog-dark")
            xdo("key", "Escape")
            time.sleep(0.3)
            check("escape_closes", js("document.querySelectorAll('.modal').length") == 0)

            # --- a press on Stop held across two drawings of the progress still clicks it
            js("openMetadata(null, []); true")
            if not wait_for("[...document.querySelectorAll('.modal .meta-slot button')].some(b => b.textContent === 'Stop')"):
                check("stop_click", False, "the progress never showed")
                return
            rect = js("(() => { const b = [...document.querySelectorAll('.modal .meta-slot button')]"
                      ".find(x => x.textContent === 'Stop'); const r = b.getBoundingClientRect(); "
                      "return { x: r.left + r.width / 2, y: r.top + r.height / 2, dpr: window.devicePixelRatio }; })()")
            x, y = wx + int(rect["x"] * rect["dpr"]), wy + int(rect["y"] * rect["dpr"])
            before = canned.polls
            xdo("mousemove", "--sync", str(x), str(y))
            xdo("mousedown", "1")
            time.sleep(1.0)                                    # two or three drawings of the progress meanwhile
            shot("progress-pressed-dark")
            during = canned.polls - before
            xdo("mouseup", "1")
            time.sleep(0.6)
            label = js("[...document.querySelectorAll('.modal .meta-slot button')].map(b => b.textContent).join('|')")
            check("stop_click", "/api/tools/metadata/stop" in canned.posted and during >= 2,
                  {"drawn_while_pressed": during, "posted": canned.posted, "buttons": label})
            shot("progress-dark")
            js("while (document.querySelector('.modal')) document.querySelector('.modal .buttons button:last-child').click(); true")

            # --- the light theme
            js("toggleTheme(); true")
            time.sleep(0.4)
            shot("page-light")
            js("openReads(); true")
            time.sleep(0.4)
            shot("dialog-light")
            js("while (document.querySelector('.modal')) document.querySelector('.modal .buttons button:last-child').click(); "
               "toggleTheme(); true")

            violations = js("JSON.stringify(window.__violations)")
            violations = json.loads(violations) if isinstance(violations, str) else []
            theirs = [v for v in violations if pywebviews(v)]
            if theirs:
                res["notes"].append(f"pywebview's own <style> refused by the page's CSP {len(theirs)} times (its text "
                                    "selection rule never applies)")
            check("csp", [v for v in violations if not pywebviews(v)] == [], violations)
        except Exception as e:  # noqa: BLE001 - said in the result
            res["error"] = f"{type(e).__name__}: {e}"
        finally:
            window.destroy()

    webview.start(run, gui="gtk", private_mode=True)
    srv.shutdown()
    print(json.dumps(res), flush=True)
    return 0


if __name__ == "__main__":
    if shutil.which("xdotool") is None:
        print(json.dumps({"error": "xdotool isn't installed"}))
        sys.exit(2)
    code = main()
    sys.stderr.flush()
    os._exit(code)          # WebKit's and GLib's threads would keep the process (the app ends the same way, app.exit_now)
