"""Local HTTP server for the GUI, bound to 127.0.0.1.

Access: the page is opened once with a launch token in the URL (?t=...), which the server
exchanges for the session token, handed to the page in its body (data-token) and then forgotten,
so the token in the launch command line and the browser's history is worthless a second later. The
page keeps the session token in its session storage, which belongs to this origin alone (host and
port: a cookie would go to every other local server on 127.0.0.1 the user visits in --browser mode,
whatever its port, since cookies ignore ports), and sends it with every API call in the X-Token
header, which a cross-site page can't add without a CORS preflight the server doesn't answer.
Requests whose Host header isn't this server's address are refused (DNS rebinding)."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import html
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.responses import JSONResponse as _JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, about, online, report as report_mod
from .catalogue import CATEGORY_TITLE, CONTEXT_KEYS, CONTEXT_LABEL, Catalogue, Scope
from .checks import load_all
from .fix import FixPlan, apply_plan, revert_entry
from .guide import Guide
from .history import Accepted, Baseline, LastReport, forget_scans, hidden
from .host import Host
from .paths import PathResolver
from .privileged import (HelperDeclined, HelperError, HelperUnavailable, PkexecHelper, Privileged, installed_helper,
                         installed_helper_stale)
from .privileged import install_helper as install_helper_root
from .runner import Runner
from .undo import UndoLog

PLAN_TTL = 15 * 60
ADMIN_IDLE = 5 * 60              # administrator access ends after this long unused
OUTBOX_EVERY = 2.0               # seconds between looks into the browsers' TempOutboxes
KEEPS_EVERY = 2.0                # seconds between looks at a watched app (What does this app keep?)


class JSONResponse(_JSONResponse):
    """JSON with everything beyond ASCII escaped. A file name that isn't UTF-8 (allowed on Linux: an old archive,
    a Windows drive) reaches Python as a lone surrogate (U+DCFF for the byte 0xff), which UTF-8 can't encode:
    escaped, it goes to the page (shown as a replacement character) and comes back as the same surrogate, so the
    path still names the file."""

    def render(self, content) -> bytes:
        import json
        return json.dumps(content, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


WEB_DIR = Path(__file__).resolve().parent / "web"


def default_open_url(url: str) -> None:
    """xdg-open, detached, with the host's environment (not the AppImage's)."""
    from .hostenv import host_env
    subprocess.Popen(["xdg-open", url], env=host_env(None), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)


class AdminSession:
    """Administrator access, once granted: the helper keeps running so one polkit prompt covers
    a scan and the fixes that follow. It ends when the user drops it, quits, after ADMIN_IDLE
    seconds unused, or right after a scan that found nothing a root fix could act on."""

    def __init__(self, start: Callable[[], Privileged], idle: float = ADMIN_IDLE):
        self.start, self.idle = start, idle
        self.helper: Privileged | None = None
        self.last_used = 0.0
        self.holds = 0                   # long work using it (the TRIM test): no idle end, no drop after a scan
        self.lock = threading.Lock()
        self.changed = threading.Condition(self.lock)
        # a request is asking for access (the prompt is up): the lock isn't held meanwhile, so active() and drop(),
        # called from the page's polling, answer at once instead of holding the server up for as long as the
        # prompt stands (it did: up to five minutes, with the event loop stuck behind it)
        self.starting = False
        self.failure: Exception | None = None       # why the attempt failed, for the requests that waited on it

    def active(self) -> bool:
        with self.lock:
            self._expire()
            return self.helper is not None

    def _expire(self) -> None:
        if self.helper is not None and (not self.helper.alive() or (
                not self.holds and time.monotonic() - self.last_used > self.idle)):
            self.helper.close()
            self.helper = None

    def get(self, prompt: bool) -> Privileged | None:
        """The running helper; with `prompt`, asks for administrator access if there is none
        (blocks until the user answers; raises HelperUnavailable / HelperDeclined). One prompt serves
        every request that asks while it is up: the others wait for its answer, and share a refusal."""
        with self.lock:
            self._expire()
            if self.helper is not None or not prompt:
                return self._use()
            if self.starting:
                self.changed.wait_for(lambda: not self.starting)
                self._expire()
                if self.helper is None:
                    raise self.failure or HelperUnavailable("Administrator access wasn't granted.")
                return self._use()
            self.starting, self.failure = True, None
        try:
            helper = self.start()               # the prompt: with the lock released, so nothing waits on it
        except BaseException as e:
            with self.lock:
                self.failure = e if isinstance(e, Exception) else HelperUnavailable("Administrator access wasn't granted.")
                self.starting = False
                self.changed.notify_all()
            raise
        with self.lock:
            self.starting = False
            if self.helper is None:
                self.helper = helper
            else:                               # can't happen (starting keeps the others waiting), but never two
                helper.close()
            self.changed.notify_all()
            return self._use()

    def _use(self) -> Privileged | None:
        if self.helper is not None:
            self.last_used = time.monotonic()
        return self.helper

    def drop(self) -> None:
        with self.lock:
            if self.helper is not None:
                self.helper.close()
                self.helper = None

    def held(self) -> bool:
        with self.lock:
            return self.holds > 0

    @contextlib.contextmanager
    def hold(self):
        """While long work uses the access: it doesn't end when idle, and a scan doesn't drop it.
        The user's Drop still ends it (the work then stops)."""
        with self.lock:
            self.holds += 1
        try:
            yield
        finally:
            with self.lock:
                self.holds -= 1
                self.last_used = time.monotonic()


def needs_root_to_fix(catalogue: Catalogue, result: dict) -> bool:
    """A fixable result whose fix (or any step of its guide) goes through the helper."""
    if not result.get("fixable"):
        return False
    spec = catalogue.checks.get(result["id"])
    impl = load_all().get(result["id"])
    return bool(spec and (spec.scope is Scope.SYSTEM or result.get("fix_root")
                          or (impl is not None and impl.fix_needs_root)))


def create_app(token: str, catalogue: Catalogue, make_host: Callable[[], Host] = Host.local,
               on_quit: Callable[[], None] | None = None,
               start_helper: Callable[[], Privileged] = PkexecHelper.start,
               make_net: Callable[[], "online.Net"] = online.RealNet,
               launch_token: str | None = None, allowed_hosts: set[str] | None = None, dev: bool = False,
               install_helper: Callable[[bool], dict] = install_helper_root,
               pick: Callable[[str, bool, str], list[str] | None] | None = None,
               open_tool: dict | None = None, spawn_browser: Callable = subprocess.Popen,
               open_url: Callable[[str], None] | None = None, watch_outbox: bool = False,
               spawn_app: Callable = subprocess.Popen) -> FastAPI:
    """`token` is the session token (the X-Token header of every API call; the page gets it when the
    launch token is exchanged). `launch_token`, if given, is accepted once on GET /?t=... `allowed_hosts`: the Host
    header values served (None: any, for tests). `on_quit` ends the process (POST /api/quit): in
    the browser, closing the tab doesn't. `start_helper` asks for administrator access (polkit)
    and returns the privileged helper. `make_net` gives the network to the online tests and to the
    browser download the user starts in the Tools panel; a scan never calls it (rule 10). `dev` shows detection hints, unverified notes and timings.
    `install_helper` installs this version's helper root-owned (or removes it), asking for access.
    `pick` is the app window's file dialog (in the browser, zenity or kdialog are used when installed).
    `open_tool` ({"tool", "paths"}, from --tool) opens the page on a tool, once. `spawn_browser`
    starts the browser from the RAM disk (subprocess.Popen; a fake in tests). `open_url` opens one of
    about.LINKS in the user's default browser (xdg-open, detached; a fake in tests). `watch_outbox` starts
    the watcher that empties the browsers' TempOutboxes into their To upload while the app runs, and removes trial
    folders an ended copy of the app left (both off in tests, which call them themselves). `spawn_app` starts an app for "What does this app keep?" and "Try an app"
    (subprocess.Popen; a fake in tests)."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, default_response_class=JSONResponse)
    app.state.report = None
    app.state.restored = False             # whether the saved last report was looked for
    app.state.online_job = None
    app.state.trim_job = None
    app.state.meta_job = None              # Remove metadata: reading or cleaning files and folders
    app.state.browser_job = None           # Tor or Mullvad Browser into the RAM disk: download, verify, unpack
    app.state.names_job = None             # the names of the user's deleted files: handed to the page once
    app.state.clean_job = None             # cleaning the folders they are in (ext4)
    app.state.trim_cleaned = False         # leftovers of an unfinished TRIM test were looked for
    app.state.erase_facts = {}             # Retire a drive: what each drive said about erasing, this session only
    app.state.keeps_job = None             # What does this app keep?: the watch, then its result (memory only)
    app.state.trial = None                 # Try an app: the one trial, its sandbox and its report (memory only)
    app.state.trial_cleaned = False        # trial folders left by a run of the app that was killed were looked for
    scan_lock = asyncio.Lock()
    plans: dict[str, tuple[FixPlan, Host]] = {}
    easy_ids: set[str] = set()             # plans built by Easy fixes: the only ones it applies
    admin = app.state.admin = AdminSession(start_helper)
    launch = {"token": launch_token}
    pending_tool = {"value": open_tool}

    @app.middleware("http")
    async def check_host(request: Request, call_next):
        if allowed_hosts is not None and request.headers.get("host", "").lower() not in allowed_hosts:
            return PlainTextResponse("This server only answers its own address.", status_code=421)
        try:
            response = await call_next(request)
        except Exception as e:  # noqa: BLE001 - see below
            # an error nothing caught: the page gets its kind; stderr (the journal, or ~/.xsession-errors, for an app
            # started from the menu) only its kind and the route, never a traceback, whose values and messages can
            # hold a file's path or name
            print(f"{request.method} {request.url.path}: {type(e).__name__}", file=sys.stderr)
            response = JSONResponse({"error": f"The app hit an error it didn't expect ({type(e).__name__})."},
                                    status_code=500)
        # what the API answers (downloads' names, a photo's metadata, deleted files' names) is never cached: in
        # --browser mode the user's browser kept a JSON answer in its disk cache otherwise (tested with Firefox)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def host_now() -> Host:
        """A host for this request, with administrator access if it is active (never prompts)."""
        host = make_host()
        host.privileged = admin.get(prompt=False)
        return host

    async def with_root(host: Host) -> str | None:
        """Gives the host administrator access, asking for it if needed. Returns why not, or None."""
        try:
            host.privileged = await asyncio.to_thread(admin.get, True)
        except HelperDeclined:
            return "Administrator access was declined, so nothing was changed."
        except HelperUnavailable as e:
            return f"Administrator access isn't available: {e} Nothing was changed."
        return None

    def keep(plan: FixPlan, host: Host) -> None:
        now = time.time()
        for pid in [k for k, (p, _) in plans.items() if now - p.created > PLAN_TTL]:
            del plans[pid]
        plans[plan.id] = (plan, host)

    def paths_of(host: Host) -> PathResolver:
        return PathResolver(host.home, host.environ)

    def undo_log(host: Host) -> UndoLog:
        return UndoLog.for_user(paths_of(host))

    def busy() -> JSONResponse:
        return JSONResponse({"error": "A scan or fix is already running."}, status_code=409)

    def persist(host: Host) -> None:
        """Keeps the report as it is now for the next start (after a scan, a fix, a revert or the
        online tests)."""
        if app.state.report is not None:
            LastReport(paths_of(host)).save(app.state.report)

    def recheck_undone(host: Host) -> list:
        """Fixes the user applied that have been undone since (UndoLog.undone), against the report as
        it is now: after a scan, a fix, a revert, accepting a finding or forgetting history."""
        report = app.state.report
        if report is None:
            return []
        report["undone"] = undo_log(host).undone(report["results"], Accepted(paths_of(host)).all(), host)
        return report["undone"]

    def restore(host: Host) -> None:
        """The saved last report, once, when there is no report yet."""
        if app.state.report is None and not app.state.restored:
            app.state.restored = True
            app.state.report = LastReport(paths_of(host)).load(set(catalogue.checks))

    def refresh(host: Host, check_id: str, also: tuple[str, ...] = ()) -> dict:
        """After a fix or revert: the context again, this check (and `also`), and every check whose
        severity depends on a context key that changed (a fix can change the context, e.g. autologin).
        Works the same on a report restored from the last run. The report is updated in place.
        Returns {"result": this check, "rechecked": {id: result}, "context": the new context}."""
        old = app.state.report
        rep = Runner(catalogue, host).rescan([check_id, *also], old["context"] if old else None)
        d = rep.to_dict()
        for key in rep.kept_context:                  # known before, not readable now: keep what was shown
            d["context"]["values"][key] = old["context"]["values"][key]
        if old is not None:
            old["results"].update(d["results"])
            old["modifiers"].update(d["modifiers"])
            old["context"] = d["context"]
        return {"result": d["results"].get(check_id), "rechecked": d["results"], "context": d["context"]}

    async def body_of(request: Request) -> dict:
        try:
            body = await request.json()
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}

    def auth(request: Request) -> None:
        # compare_digest refuses text beyond ASCII (a TypeError, which would be a 500): such a header is just wrong
        t = request.headers.get("x-token")
        if t is not None and t.isascii() and hmac.compare_digest(t, token):
            return
        raise HTTPException(403, "bad token")

    @app.get("/")
    async def index(request: Request):
        t = request.query_params.get("t")
        if t is not None:
            # the launch token: one exchange for the session token, handed to the page in its body (it keeps it in
            # its session storage, this origin's own), then it is forgotten
            if launch["token"] is not None and t.isascii() and hmac.compare_digest(t, launch["token"]):
                launch["token"] = None
                page = (WEB_DIR / "index.html").read_text(encoding="utf-8")
                page = page.replace("<body>", f'<body data-token="{html.escape(token)}">', 1)
                return HTMLResponse(page, headers={"Cache-Control": "no-store"})
            return PlainTextResponse("This link has already been used. Start DA Privacy Kit again for a new one. "
                                     "If you opened it only once, something else on this computer may have used it "
                                     "first: quit the app.", status_code=403)
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/api/state", dependencies=[Depends(auth)])
    async def state():
        host = make_host()
        await asyncio.to_thread(restore, host)
        await asyncio.to_thread(undo_log(host).expire_backups)     # backups kept only for a while (known_hosts')
        if not app.state.trim_cleaned and not trim_running():
            from .tools import trimtest
            app.state.trim_cleaned = True
            await asyncio.to_thread(trimtest.leftovers, host)      # a test the app didn't finish (closed, crashed)
        return {
            "version": __version__,
            "app": about.age(),                      # its version and build date, and whether this copy is getting old
            "catalogue": [s.to_dict() for s in catalogue],
            "categories": CATEGORY_TITLE,
            "context_keys": list(CONTEXT_KEYS),
            "labels": CONTEXT_LABEL,                 # every context key and finding name, in words
            "implemented": sorted(load_all()),
            "report": app.state.report,
            "can_quit": on_quit is not None,
            "in_browser": on_quit is not None,      # only --browser passes on_quit: the page then says what that exposes
            "admin_active": admin.active(),
            "admin_idle_minutes": ADMIN_IDLE // 60,
            "helper_installed": installed_helper() is not None,
            "helper_stale": installed_helper_stale(),
            "dev": dev,
            "reads": about.READS, "never": about.NEVER,
            "accepted": Accepted(paths_of(host)).all(),
            "last_scan": (Baseline(paths_of(host)).load() or {}).get("taken"),
            "open_tool": pending_tool.pop("value", None),
            "presentation": await asyncio.to_thread(presentation_on, host),
            "welcome": {"show": about.welcome_shown(paths_of(host).config_home), "links": about.LINKS},
        }

    @app.post("/api/welcome", dependencies=[Depends(auth)])
    async def welcome(request: Request):
        """Body {"hide": bool}: don't show the welcome warning at start-up again (or do)."""
        body = await body_of(request)
        host = make_host()
        await asyncio.to_thread(about.hide_welcome, paths_of(host).config_home, body.get("hide") is True)
        return {"show": about.welcome_shown(paths_of(host).config_home)}

    @app.post("/api/open", dependencies=[Depends(auth)])
    async def open_link(request: Request):
        """Body {"link": name}: opens one of about.LINKS in the default browser. In the app's window a
        link would replace the app's own page; only these addresses, never one the page sends."""
        body = await body_of(request)
        url = about.LINKS.get(body.get("link")) if isinstance(body.get("link"), str) else None
        if url is None:
            return JSONResponse({"error": "Unknown link."}, status_code=400)
        try:
            await asyncio.to_thread(open_url or default_open_url, url)
        except OSError as e:
            return JSONResponse({"error": f"It couldn't be opened ({e.strerror or e}): the address is {url}"},
                                status_code=400)
        return {"ok": True, "url": url}

    def presentation_on(host: Host) -> dict:
        from .tools import presentation
        st = presentation.status(host) if presentation.is_on(host) else {"on": False, "since": None, "lapsed": []}
        return {"on": st["on"], "since": st["since"], "lapsed": st["lapsed"]}

    @app.post("/api/helper/install", dependencies=[Depends(auth)])
    async def helper_install(request: Request):
        """Body {"uninstall": bool}. Installs this version's helper root-owned with its polkit
        action, through a helper started from this version's own copy (an installed one may be
        older); asks for the password. Access granted before is dropped, so the next root work
        starts the installed helper."""
        body = await body_of(request)
        if scan_lock.locked():
            return busy()
        if trim_running() or keeps_running():
            return JSONResponse({"error": "A tool (the TRIM test, Deleted file names, or What does this app keep?) is "
                                          "using administrator access: installing the helper would stop it."},
                                status_code=409)
        async with scan_lock:
            await asyncio.to_thread(admin.drop)
            try:
                r = await asyncio.to_thread(install_helper, bool(body.get("uninstall")))
            except (HelperUnavailable, HelperError) as e:
                return JSONResponse({"error": str(e), "declined": isinstance(e, HelperDeclined)}, status_code=403)
        return {"ok": True, **r, "helper_installed": installed_helper() is not None,
                "helper_stale": installed_helper_stale()}

    @app.post("/api/admin/drop", dependencies=[Depends(auth)])
    async def drop_admin():
        await asyncio.to_thread(admin.drop)
        return {"admin_active": False}

    @app.post("/api/scan", dependencies=[Depends(auth)])
    async def scan(request: Request):
        """Body {"admin": true} asks for administrator access first, unless it is already granted
        (a scan uses access that is active either way). Declining it doesn't stop the scan: it runs
        without, and system checks report that they couldn't check. Access granted for a scan is
        dropped again at once when nothing it found needs it to fix."""
        try:
            body = await request.json()
        except ValueError:
            body = {}
        want_admin = isinstance(body, dict) and bool(body.get("admin"))
        if scan_lock.locked():
            return JSONResponse({"error": "A scan is already running."}, status_code=409)
        async with scan_lock:
            host = make_host()
            granted = {"requested": want_admin, "granted": False, "message": "", "dropped": False}
            if want_admin:
                try:
                    host.privileged = await asyncio.to_thread(admin.get, True)
                    granted["granted"] = True
                except HelperUnavailable as e:
                    granted["message"] = str(e)
            else:
                host.privileged = await asyncio.to_thread(admin.get, False)
            report = await asyncio.to_thread(Runner(catalogue, host).scan)
            new = {**report.to_dict(), "admin": granted}
            new["changes"] = await asyncio.to_thread(Baseline(paths_of(host)).record, new)
            old = app.state.report
            if old is not None:                       # a new scan keeps the online tests' results
                for cid in list(old["results"]):
                    if cid in catalogue.checks and catalogue[cid].scope.value == "online":
                        new["results"][cid] = old["results"][cid]
                        new["modifiers"][cid] = old["modifiers"].get(cid, [])
                if old.get("online"):
                    new["online"] = old["online"]
            app.state.report = new
            await asyncio.to_thread(recheck_undone, host)
            await asyncio.to_thread(persist, host)
            if host.privileged is not None and not admin.held() and not any(needs_root_to_fix(catalogue, dict(r, id=cid))
                                                       for cid, r in new["results"].items()):
                await asyncio.to_thread(admin.drop)   # nothing to fix as root: don't keep root around
                granted["dropped"] = True
        return {**app.state.report, "admin_active": admin.active()}

    # ------------------------------------------------------------ accepted findings and export

    @app.post("/api/accept", dependencies=[Depends(auth)])
    async def accept(request: Request):
        """Body {"check_id", "accept": bool, "note"}: mark a finding as a risk the user accepts
        (or unmark it). An accepted finding is hidden and not counted until its severity rises
        above the one it has now (history.resurfaced)."""
        body = await body_of(request)
        cid = str(body.get("check_id", ""))
        if cid not in catalogue.checks:
            return JSONResponse({"error": f"No check {cid}"}, status_code=404)
        result = ((app.state.report or {}).get("results") or {}).get(cid) or {}
        host = make_host()
        data = await asyncio.to_thread(Accepted(paths_of(host)).set, cid, bool(body.get("accept")),
                                       str(body.get("note") or ""), result.get("effective_severity"),
                                       result.get("severity_reason", ""))
        undone = await asyncio.to_thread(recheck_undone, host)
        await asyncio.to_thread(persist, host)
        return {"accepted": data, "undone": undone}

    @app.get("/api/report", dependencies=[Depends(auth)])
    async def export_report(request: Request):
        """The last report as text or JSON (?format=text|json), redacted with ?redact=1."""
        if app.state.report is None:
            return JSONResponse({"error": "Scan first."}, status_code=400)
        fmt = request.query_params.get("format", "text")
        redact = request.query_params.get("redact") in ("1", "true", "yes")
        host = make_host()
        text = await asyncio.to_thread(report_mod.export, app.state.report, catalogue, fmt, host, redact,
                                       Accepted(paths_of(host)).all())
        return PlainTextResponse(text, media_type="application/json" if fmt == "json" else "text/plain; charset=utf-8")

    @app.get("/api/export", dependencies=[Depends(auth)])
    async def export_everything(request: Request):
        """Everything the app keeps, for the user's backups: the last report (if there is one),
        accepted findings and every change in History with how to undo it by hand
        (?format=text|json, ?redact=1)."""
        fmt = request.query_params.get("format", "text")
        redact = request.query_params.get("redact") in ("1", "true", "yes")
        host = make_host()
        text = await asyncio.to_thread(lambda: report_mod.export_all(
            app.state.report, catalogue, undo_log(host).entries(), Accepted(paths_of(host)).all(), fmt, host, redact))
        return PlainTextResponse(text, media_type="application/json" if fmt == "json" else "text/plain; charset=utf-8")

    def online_settings(host: Host) -> tuple[dict, str]:
        try:
            return online.load_settings(paths_of(host).config_home), ""
        except online.SettingsError as e:
            return dict(online.DEFAULTS), str(e)

    @app.get("/api/online", dependencies=[Depends(auth)])
    async def online_tests():
        """The online tests and exactly who each contacts with the settings in use. Contacts nobody."""
        from .checks.online import online_checks

        from .network import carrying_vpn_links

        host = make_host()
        settings, error = online_settings(host)
        impl = online_checks()
        vpn = bool(carrying_vpn_links(host))
        tests = []
        for s in catalogue:
            if s.scope.value != "online":
                continue
            on, reason = online.DEFAULTS_WHY.get(s.id, (False, ""))
            if s.id in online.VPN_TESTS and vpn:
                reason += " A VPN is connected now, so it is worth running."
            tests.append({"id": s.id, "title": s.title, "why": s.why, "contacts": list(s.contacts),
                          "hosts": impl[s.id](s).hosts(settings) if s.id in impl else [],
                          "default": on, "default_why": reason, "with_admin": online.WITH_ADMIN.get(s.id, ""),
                          "group": online.contact_group(s.id, settings)})
        return {"tests": tests, "observe_seconds": settings["observe_seconds"], "settings_error": error,
                "admin_active": admin.active(), "vpn_active": vpn,
                "proxy_vars": online.proxy_vars(host.environ),     # set, and not used by the tests: the page says so
                "settings_path": str(online.settings_path(paths_of(host).config_home))}

    # ------------------------------------------------------------ online tests: a background job
    # They take a while (the traffic test watches for a minute), so they run as a job the page
    # polls, and the rest of the app stays usable: they don't hold the scan lock. Results are
    # merged into the report as each test finishes.

    def job_view(job: dict | None) -> dict | None:
        if job is None:
            return None
        return {**{k: v for k, v in job.items() if k not in ("cancel", "abort")}, "stopping": job["cancel"],
                "now": time.time()}

    def mark_online(job: dict) -> None:
        if app.state.report is not None and job["results"]:
            app.state.report["online"] = {"ran": job["finished"], "ids": sorted(job["results"]),
                                          "privileged": job.get("privileged", False)}

    def merge_online(job: dict, cid: str, result: dict, states: list, extra: dict) -> None:
        """On the event loop: one finished online test into the job and the current report.
        After "stop now", results still arriving (the cancelled test's) are dropped."""
        if job["abort"]:
            return
        job["results"][cid] = result
        job["done"] = len(job["results"])
        rep = app.state.report
        if rep is None:
            return
        rep["results"][cid] = result
        rep["modifiers"][cid] = states
        for target, notes in extra.items():
            res = rep["results"].get(target)
            if res is not None:
                titles = {n["title"] for n in res["notes"]}
                res["notes"] += [n for n in notes if n["title"] not in titles]

    async def run_online_job(job: dict, settings: dict, want_admin: bool) -> None:
        loop = asyncio.get_running_loop()
        try:
            host = await asyncio.to_thread(host_now)
            if want_admin and host.privileged is None:
                job["state"] = "asking"
                problem = await with_root(host)
                job["admin_message"] = (problem or "").replace(" Nothing was changed.", "")
            job["privileged"] = host.privileged is not None
            job["state"], job["started"] = "running", time.time()

            def progress(cid: str, done: int, total: int) -> None:
                job["current"] = {"id": cid, "title": catalogue[cid].title, "started": time.time()}

            def on_result(cid, result, states, extra) -> None:
                d = result.to_dict()
                notes = {k: [n.to_dict() for n in v] for k, v in extra.items()}
                loop.call_soon_threadsafe(merge_online, job, cid, d, states, notes)

            runner = Runner(catalogue, host, net=make_net(), online=settings)
            await asyncio.to_thread(runner.scan_online, job["ids"], progress, lambda: job["cancel"], on_result)
            await asyncio.sleep(0)                         # let the last merge run first
            if not job["abort"]:
                job["state"] = "stopped" if job["cancel"] and job["done"] < job["total"] else "done"
        except Exception as e:  # noqa: BLE001 - report it on the page rather than spin forever
            if not job["abort"]:
                job["state"], job["error"] = "failed", f"{type(e).__name__}: {e}"
        finally:
            job["winding_down"] = False
            if not job["abort"]:                           # "stop now" already ended it
                job["current"], job["finished"] = None, time.time()
                mark_online(job)
                await asyncio.to_thread(persist, host)

    @app.post("/api/online/run", dependencies=[Depends(auth)])
    async def online_run(request: Request):
        """Starts the chosen online tests as a background job and returns at once; the page
        follows it with /api/online/status. Body: {"ids": [...], "observe_seconds": n, "admin":
        bool}. Only ever started by the user, after the page has shown who each test contacts.
        With "admin", asks for administrator access first if it isn't active; declining it
        doesn't stop the tests, they run without."""
        body = await body_of(request)
        ids = [s.id for s in catalogue if s.scope.value == "online" and s.id in (body.get("ids") or [])]
        if not ids:
            return JSONResponse({"error": "Choose at least one online test."}, status_code=400)
        if app.state.report is None:
            return JSONResponse({"error": "Scan first: the online tests build on the scan's results."}, status_code=400)
        job = app.state.online_job
        if job is not None and job["state"] in ("starting", "asking", "running"):
            return JSONResponse({"error": "Online tests are already running."}, status_code=409)
        if job is not None and job.get("winding_down"):
            return JSONResponse({"error": "The test you stopped is still finishing; try again in a few seconds."},
                                status_code=409)
        settings, error = online_settings(make_host())
        if error:
            return JSONResponse({"error": error}, status_code=400)
        secs = body.get("observe_seconds")
        if isinstance(secs, int) and not isinstance(secs, bool) and 5 <= secs <= 300:
            settings["observe_seconds"] = secs
        job = app.state.online_job = {
            "id": uuid.uuid4().hex, "state": "starting", "ids": ids, "total": len(ids), "done": 0,
            "titles": {i: catalogue[i].title for i in ids}, "current": None, "created": time.time(),
            "started": None, "finished": None, "observe_seconds": settings["observe_seconds"], "results": {},
            "admin_message": "", "error": "", "privileged": False, "cancel": False, "abort": False,
            "winding_down": True, "cancelled": None}
        app.state.online_task = asyncio.create_task(run_online_job(job, settings, bool(body.get("admin"))))
        return {"job": job_view(job)}

    @app.get("/api/online/status", dependencies=[Depends(auth)])
    async def online_status():
        return {"job": job_view(app.state.online_job), "admin_active": admin.active()}

    @app.post("/api/online/stop", dependencies=[Depends(auth)])
    async def online_stop(request: Request):
        """Body {"now": false}: stop after the test that is running now (it finishes and its
        result is kept). {"now": true}: stop at once; the running test's result is discarded and
        only earlier results are kept. The cancelled test ends in the background within seconds
        (online tests check for this), and no new run starts until it has."""
        body = await body_of(request)
        job = app.state.online_job
        if job is not None and job["state"] in ("starting", "asking", "running"):
            job["cancel"] = True
            if body.get("now"):
                job["abort"] = True
                job["cancelled"] = job["current"]["title"] if job["current"] else None
                job["state"], job["current"], job["finished"] = "stopped", None, time.time()
                mark_online(job)
        return {"job": job_view(job)}

    # ------------------------------------------------------------ fixes

    @app.post("/api/fix/{check_id}/plan", dependencies=[Depends(auth)])
    async def plan_fix(check_id: str, request: Request):
        """The dry run: exactly what the fix would do now, or for a guided fix, the guide with
        each option's dry run. Changes nothing. Body (optional): {"params": {...}}, the guide's
        inputs as the user set them; the guide checks them itself."""
        body = await body_of(request)
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        if check_id not in catalogue.checks:
            return JSONResponse({"error": f"No check {check_id}"}, status_code=404)
        if scan_lock.locked():
            return busy()
        online = catalogue[check_id].scope is Scope.ONLINE
        async with scan_lock:
            host = await asyncio.to_thread(host_now)
            # an online test's guide is built from the result the user saw: the test isn't run again
            stored = app.state.report["results"].get(check_id) if online and app.state.report is not None else None
            result, plan = await asyncio.to_thread(Runner(catalogue, host).plan_fix, check_id, params, stored)
            if plan is None and result.needs_admin and host.privileged is None:
                # administrator access ended since the scan found it: the check can only be read again with it
                why = await with_root(host)
                if why is not None:
                    return JSONResponse({"error": f"This needs administrator access to read again. {why}"},
                                        status_code=400)
                result, plan = await asyncio.to_thread(Runner(catalogue, host).plan_fix, check_id, params, stored)
        if app.state.report is not None and not online:         # an online result stays as its test left it
            app.state.report["results"][check_id] = result.to_dict()
        if plan is None and online and stored is None:
            return JSONResponse({"error": "Run this online test first: its guide is built from what the test found.",
                                 "result": result.to_dict()}, status_code=400)
        if plan is None:
            return JSONResponse({"error": "This check can't be fixed here now.", "result": result.to_dict()},
                                status_code=400)
        if isinstance(plan, Guide):
            for p in plan.plans:
                keep(p, host)
            return {"guide": plan.to_dict(), "dry_run": plan.dry_run(), "result": result.to_dict()}
        keep(plan, host)
        return {"plan": plan.to_dict(), "dry_run": plan.dry_run(), "result": result.to_dict()}

    @app.post("/api/fix/apply", dependencies=[Depends(auth)])
    async def apply_fix(request: Request):
        """Applies a plan exactly as shown. Body: {"plan_id", "confirm_irreversible"}."""
        body = await body_of(request)
        stored = plans.pop(str(body.get("plan_id")), None)
        if stored is None or time.time() - stored[0].created > PLAN_TTL:
            return JSONResponse({"error": "That plan has expired; open the fix again."}, status_code=400)
        plan, host = stored
        if scan_lock.locked():
            plans[plan.id] = stored
            return busy()
        async with scan_lock:
            if plan.needs_root:
                problem = await with_root(host)
                if problem:
                    plans[plan.id] = stored
                    return JSONResponse({"error": problem, "declined": True}, status_code=403)
            log = undo_log(host)
            res = await asyncio.to_thread(apply_plan, plan, host, log, bool(body.get("confirm_irreversible")))
            again = await asyncio.to_thread(refresh, host, plan.check_id)
            if res.ok and res.entry_id:               # what the check said right after: undone later if it comes back
                await asyncio.to_thread(log.set_outcome, res.entry_id, again.get("result"))
            undone = await asyncio.to_thread(recheck_undone, host)
            await asyncio.to_thread(persist, host)
            # the History entry as made: what each step did, exactly (a failed attempt's too, when it got as far
            # as changing something), for the page to show right away
            entry = await asyncio.to_thread(lambda: UndoLog.summary(log.get(res.entry_id), host)) if res.entry_id else None
        if not res.ok:
            return JSONResponse({"error": res.error, "rolled_back": res.rolled_back, "entry": entry, "undone": undone,
                                 **again}, status_code=400)
        return {"ok": True, "entry_id": res.entry_id, "applied": res.applied, "entry": entry, "undone": undone, **again}

    # ------------------------------------------------------------ Easy fixes
    # The catalogue's `easy` fixes of the checks that fail or warn now, applied together after one dry
    # run and one confirmation: each plan applied on its own, as its own entry in History.

    def easy_view(result, plans: list[FixPlan], covered_by: str | None = None) -> dict:
        spec = catalogue[result.id]
        return {"check_id": result.id, "title": spec.title, "cost": spec.easy.cost, "kind": spec.kind,
                "covered_by": covered_by,
                "severity": result.effective_severity, "status": result.status.value,
                "needs_root": any(p.needs_root for p in plans),
                "blockers": [b for p in plans for b in p.blockers],
                "irreversible": any(p.irreversible for p in plans),
                "plans": [{**p.to_dict(), "dry_run": p.dry_run()} for p in plans]}

    @app.post("/api/easy/plan", dependencies=[Depends(auth)])
    async def easy_plan():
        """The dry run of every Easy fix that applies now (findings the user accepted left out).
        Changes nothing."""
        if scan_lock.locked():
            return busy()
        async with scan_lock:
            host = await asyncio.to_thread(host_now)
            items = await asyncio.to_thread(Runner(catalogue, host).plan_easy)
        accepted = await asyncio.to_thread(Accepted(paths_of(host)).all)
        visible = []
        for result, item_plans in items:
            d = result.to_dict()
            if app.state.report is not None:
                app.state.report["results"][result.id] = d
            if not hidden(accepted, result.id, d):
                visible.append((result, item_plans))
        # a change two checks offer is applied once; the second check stays listed, saying which fix covers it, so
        # the dialog lists what the count counts
        covered = Runner.merge_shared_easy(visible, lambda cid: catalogue[cid].title)
        out = []
        for result, item_plans in visible:
            for p in item_plans:
                keep(p, host)
                easy_ids.add(p.id)
            out.append(easy_view(result, item_plans, covered.get(result.id)))
        easy_ids.intersection_update(plans)        # forget the ones that have expired
        return {"items": out, "admin_active": admin.active()}

    @app.post("/api/easy/apply", dependencies=[Depends(auth)])
    async def easy_apply(request: Request):
        """Body {"plan_ids": [...], "confirm_irreversible"}: applies each plan exactly as shown, one
        after another, each as its own fix in History. Administrator access is asked for once, if
        any needs it; declined, those are skipped and the others applied. A plan that fails is
        rolled back and the rest go on."""
        body = await body_of(request)
        ids = body.get("plan_ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids) or len(set(ids)) != len(ids):
            return JSONResponse({"error": "Choose the fixes to apply."}, status_code=400)
        if not set(ids) <= easy_ids:              # another fix's plan: applied on its own, after its own dry run
            return JSONResponse({"error": "Only the Easy fixes' own plans are applied together."}, status_code=400)
        stored = [plans.get(i) for i in ids]
        if any(x is None or time.time() - x[0].created > PLAN_TTL for x in stored):
            return JSONResponse({"error": "These plans have expired; open Easy fixes again."}, status_code=400)
        if scan_lock.locked():
            return busy()
        for i in ids:
            plans.pop(i, None)
            easy_ids.discard(i)
        order = list(catalogue.checks)
        todo = sorted((p for p, _ in stored), key=lambda p: order.index(p.check_id))
        host = stored[0][1]
        async with scan_lock:
            declined = await with_root(host) if any(p.needs_root for p in todo) else None
            log, out = undo_log(host), []
            for plan in todo:
                if plan.needs_root and declined:
                    out.append({"check_id": plan.check_id, "title": plan.title, "ok": False, "error": declined,
                                "declined": True})
                    continue
                res = await asyncio.to_thread(apply_plan, plan, host, log, bool(body.get("confirm_irreversible")))
                out.append({"check_id": plan.check_id, "title": plan.title, "ok": res.ok, "error": res.error,
                            "entry_id": res.entry_id, "rolled_back": res.rolled_back})
            checked = list(dict.fromkeys(p.check_id for p in todo))
            again = await asyncio.to_thread(refresh, host, checked[0], tuple(checked[1:]))
            for r in out:                             # what the check said right after: undone later if it comes back
                if r.get("entry_id") and r["ok"]:
                    await asyncio.to_thread(log.set_outcome, r["entry_id"], again["rechecked"].get(r["check_id"]))
            for r in out:                             # each History entry as made: what every step did, exactly
                r["entry"] = await asyncio.to_thread(lambda: UndoLog.summary(log.get(r["entry_id"]), host)) \
                    if r.get("entry_id") else None
            undone = await asyncio.to_thread(recheck_undone, host)
            await asyncio.to_thread(persist, host)
        return {"ok": all(r["ok"] for r in out), "results": out, "rechecked": again["rechecked"],
                "context": again["context"], "undone": undone, "admin_active": admin.active()}

    # ------------------------------------------------------------ history

    @app.get("/api/undo", dependencies=[Depends(auth)])
    async def undo_entries():
        host = host_now()
        log = undo_log(host)
        await asyncio.to_thread(log.expire_backups)
        entries = await asyncio.to_thread(lambda: [UndoLog.summary(e, host) for e in reversed(log.entries())])
        return {"entries": entries}

    @app.post("/api/undo/{entry_id}/drop-backup", dependencies=[Depends(auth)])
    async def drop_backup(entry_id: str):
        """Deletes an entry's backups that were kept only for a while (known_hosts' plain copy) now, rather than
        when they expire: the step can then no longer be reverted."""
        host = host_now()
        log = undo_log(host)
        if log.get(entry_id) is None:
            return JSONResponse({"error": "No such fix in the history."}, status_code=404)
        gone = await asyncio.to_thread(log.drop_backups, entry_id)
        return {"dropped": gone, "entry": UndoLog.summary(log.get(entry_id), host)}

    @app.post("/api/undo/{entry_id}/revert", dependencies=[Depends(auth)])
    async def revert(entry_id: str, request: Request):
        body = await body_of(request)
        if scan_lock.locked():
            return busy()
        async with scan_lock:
            host = await asyncio.to_thread(host_now)
            log = undo_log(host)
            entry = log.get(entry_id)
            if entry is None:
                return JSONResponse({"error": "No such fix in the history."}, status_code=404)
            if UndoLog.needs_root(entry):
                problem = await with_root(host)
                if problem:
                    return JSONResponse({"error": problem.replace("changed", "reverted"), "declined": True},
                                        status_code=403)
            results = await asyncio.to_thread(revert_entry, entry, host, log, bool(body.get("force")))
            again = await asyncio.to_thread(refresh, host, entry["check_id"])
            undone = await asyncio.to_thread(recheck_undone, host)
            await asyncio.to_thread(persist, host)
        return {"ok": all(r.ok for r in results), "conflict": any(r.conflict for r in results),
                "messages": [r.message for r in results], "entry": UndoLog.summary(log.get(entry_id), host),
                "undone": undone, **again}

    @app.post("/api/undo/forget", dependencies=[Depends(auth)])
    async def forget(request: Request):
        """Body {"everything": bool}. Without it: reverted and failed entries, and applied ones
        older than 90 days, go (with their file backups). Changes made stay as they are. With
        everything, the saved last scan goes too (the page keeps showing it until a new one)."""
        body = await body_of(request)
        host = make_host()
        log = undo_log(host)
        everything = bool(body.get("everything"))
        gone = await asyncio.to_thread(log.forget, everything)
        if everything:
            await asyncio.to_thread(forget_scans, paths_of(host))
        undone = await asyncio.to_thread(recheck_undone, host)
        return {"forgotten": gone, "entries": [UndoLog.summary(e) for e in reversed(log.entries())], "undone": undone}

    # ------------------------------------------------------------ tools (docs/TECHNICAL.md, Tools)
    # Started by the user on files they chose; nothing is kept and nothing leaves the machine.

    def tool_paths(host: Host, raw) -> list[Path]:
        from .tools.pick import checked
        items = raw if isinstance(raw, list) else [raw]
        if not items or len(items) > 50:
            raise ValueError("Choose between 1 and 50 files.")
        return [checked(x, host.home) for x in items]

    def bad_path(e: Exception) -> JSONResponse:
        return JSONResponse({"error": str(e)}, status_code=400)

    @app.get("/api/tools", dependencies=[Depends(auth)])
    async def tools_list():
        from .tools import GROUPS, TOOLS, metadata, ramdisk
        from .tools.pick import dialog, downloads, recent_downloads
        from .checks.guides import install
        from types import SimpleNamespace
        host = make_host()

        def gather():
            st = ramdisk.status(host)
            return {
                "tools": TOOLS, "groups": [{"id": g, "title": t} for g, t in GROUPS],
                # the browser's own RAM disk, for its tile's status
                "browser_disk": ramdisk.status(host, ramdisk.BROWSER).open,
                "features": [s.id for s in catalogue if s.tier.value == "feature"],
                "can_pick": pick is not None or dialog(host) is not None,
                "downloads": recent_downloads(host), "downloads_dir": host.display(downloads(host)),
                "verify": {"gpgv": host.runner.which("gpgv"), "sqv": host.runner.which("sqv"),
                           "install": install(SimpleNamespace(host=host), debian="gpgv", fedora="gnupg2",
                                              arch="gnupg", suse="gpg2")},
                "metadata": metadata.status(host),
                "ramdisk": {**st.to_dict(host.home), "max_mb": ramdisk.max_mb(host), "default_mb": ramdisk.DEFAULT_MB},
                "admin_active": admin.active(),
                # for their tiles: a trial there is, an app being watched
                "trial": app.state.trial.state if app.state.trial is not None else None,
                "keeps": app.state.keeps_job["state"] if app.state.keeps_job is not None else None,
            }
        return await asyncio.to_thread(gather)

    @app.post("/api/tools/pick", dependencies=[Depends(auth)])
    async def tools_pick(request: Request):
        """Body {"multiple": bool} or {"folder": true}: the file (or folder) dialog; {"paths": [...]}
        ([] when cancelled), or {"unavailable": true} when there is none (the page then asks for a path)."""
        from .tools.pick import dialog, downloads
        body = await body_of(request)
        host = make_host()
        chooser = pick or dialog(host)
        if chooser is None:
            return {"unavailable": True, "paths": []}
        kind = "folder" if body.get("folder") else "open"
        paths = await asyncio.to_thread(chooser, kind, bool(body.get("multiple")) and kind == "open",
                                        str(downloads(host)))
        return {"paths": list(paths or [])}

    @app.post("/api/tools/verify", dependencies=[Depends(auth)])
    async def tools_verify(request: Request):
        """Body {"path", "key_files": [...], "expected": "", "use_keyring": true}: Verify a download."""
        from .tools import verify as V
        from .tools.keys import DataError
        body = await body_of(request)
        host = make_host()
        try:
            path = tool_paths(host, body.get("path"))[0]
            keys = tool_paths(host, body["key_files"]) if body.get("key_files") else []
        except ValueError as e:
            return bad_path(e)
        expected = str(body.get("expected") or "")[:300]
        try:
            v = await asyncio.to_thread(V.verify, host, path, keys, expected, body.get("use_keyring") is not False)
        except DataError as e:
            return JSONResponse({"error": f"The app's list of signing keys couldn't be read: {e}"}, status_code=500)
        except OSError as e:
            return JSONResponse({"error": f"{path.name} couldn't be read: {e.strerror or e}"}, status_code=400)
        return {"verdict": v.to_dict(host.home)}

    @app.post("/api/tools/metadata/show", dependencies=[Depends(auth)])
    async def tools_metadata_show(request: Request):
        """Body {"paths"}: everything each file carries (at most 50 files: the page asks for one at a time
        when the user opens it in a long list)."""
        from .tools import metadata
        body = await body_of(request)
        host = make_host()
        try:
            paths = tool_paths(host, body.get("paths"))
        except ValueError as e:
            return bad_path(e)
        files = await asyncio.to_thread(lambda: [metadata.show(host, p).to_dict() for p in paths])
        return {"files": files}

    # Remove metadata on files and folders: a background job (a folder can hold thousands of files), followed
    # by the page; one at a time. Its result stays for as long as the app runs, never saved.

    def meta_running() -> bool:
        job = app.state.meta_job
        return job is not None and job["state"] == "running"

    def meta_view(job: dict | None) -> dict | None:
        return None if job is None else {k: v for k, v in job.items() if k != "cancel"}

    def meta_roots(host: Host, body: dict) -> list[Path]:
        from .tools.pick import checked
        items = body.get("paths")
        items = items if isinstance(items, list) else [items]
        if not items or len(items) > 50:
            raise ValueError("Choose between 1 and 50 files or folders.")
        return [checked(x, host.home, folders=True) for x in items]

    async def run_meta_job(job: dict, roots: list[Path], hidden: bool, only: set[str] | None, light: bool) -> None:
        from .tools import metadata
        host = make_host()

        def progress(done, path):
            job["done"], job["current"] = done, path.name

        def stopping():
            return job["cancel"]

        def work():
            sel = metadata.collect(roots, hidden)
            if only is not None:
                sel.files = [c for c in sel.files if str(c.path) in only]
            job["selection"], job["total"] = sel.to_dict(host), len(sel.files)
            if job["kind"] == "read":
                job["phase"] = "Reading what each file carries"
                return {"files": metadata.read_many(host, sel, progress, stopping)}
            job["phase"] = "Making clean copies"
            try:
                return metadata.clean_many(host, sel.files, light, progress, stopping).to_dict(host)
            except metadata.Stopped as e:
                if e.run is not None:
                    job["result"] = e.run.to_dict(host)
                raise
        try:
            job["result"] = await asyncio.to_thread(work)
            job["state"] = "done"
        except metadata.Stopped:
            job["state"] = "stopped"
        except OSError as e:
            job["state"], job["error"] = "failed", f"{e.strerror or e}" + (f": {e.filename}" if e.filename else "")
        except Exception as e:  # noqa: BLE001 - shown on the page rather than spin forever
            job["state"], job["error"] = "failed", f"{type(e).__name__}: {e}"
        finally:
            job["phase"], job["current"] = None, ""

    async def start_meta_job(request: Request, kind: str):
        body = await body_of(request)
        if meta_running():
            return JSONResponse({"error": "Remove metadata is already busy: wait for it, or stop it."}, status_code=409)
        host = make_host()
        try:
            roots = meta_roots(host, body)
        except ValueError as e:
            return bad_path(e)
        only = None
        if kind == "clean" and body.get("files") is not None:
            files = body.get("files")
            if not isinstance(files, list) or not files:
                return JSONResponse({"error": "Tick at least one file to clean."}, status_code=400)
            only = {f for f in files if isinstance(f, str)}
        job = app.state.meta_job = {"id": uuid.uuid4().hex, "kind": kind, "state": "running", "phase": "Finding the files",
                                    "done": 0, "total": 0, "current": "", "selection": None, "result": None,
                                    "error": "", "cancel": False, "lightweight": bool(body.get("lightweight")),
                                    "paths": [str(r) for r in roots], "hidden": body.get("hidden") is True}
        app.state.meta_task = asyncio.create_task(run_meta_job(job, roots, body.get("hidden") is True, only,
                                                               bool(body.get("lightweight"))))
        return {"job": meta_view(job)}

    @app.post("/api/tools/metadata/read", dependencies=[Depends(auth)])
    async def tools_metadata_read(request: Request):
        """Body {"paths": files and folders, "hidden": bool}: reads what every file carries (a folder's
        subfolders included) and returns at once; the page follows it with GET /api/tools/metadata/job."""
        return await start_meta_job(request, "read")

    @app.post("/api/tools/metadata/clean", dependencies=[Depends(auth)])
    async def tools_metadata_clean(request: Request):
        """Body {"paths", "hidden", "files": the ones ticked (all when absent), "lightweight"}: a cleaned
        copy beside each file chosen on its own, and a new "NAME (cleaned)" folder beside each folder;
        the originals aren't changed. Returns at once, like read."""
        return await start_meta_job(request, "clean")

    @app.get("/api/tools/metadata/job", dependencies=[Depends(auth)])
    async def tools_metadata_job():
        return {"job": meta_view(app.state.meta_job)}

    @app.post("/api/tools/metadata/stop", dependencies=[Depends(auth)])
    async def tools_metadata_stop():
        """Stops after the batch it is on: what was cleaned by then stays, and is listed."""
        job = app.state.meta_job
        if job is not None and job["state"] == "running":
            job["cancel"] = True
        return {"job": meta_view(job)}

    @app.post("/api/tools/metadata/open", dependencies=[Depends(auth)])
    async def tools_metadata_open(request: Request):
        """Body {"folder"}: opens in the file manager a folder the last clean-up wrote into (a cleaned
        folder, or the folder of a file cleaned beside itself); no other."""
        body = await body_of(request)
        job = app.state.meta_job
        res = (job or {}).get("result") or {}
        allowed = {f["output_path"] for f in res.get("folders", []) if f.get("output_path")}
        allowed |= {str(Path(r["path"]).parent) for r in res.get("results", []) if r.get("ok") and not r.get("root")}
        folder = body.get("folder")
        if not isinstance(folder, str) or folder not in allowed or not Path(folder).is_dir():
            return JSONResponse({"error": "That isn't a folder the clean-up wrote into."}, status_code=400)
        host = make_host()
        r = await asyncio.to_thread(host.run, "xdg-open", folder)
        return {"ok": r.ok}

    def ramdisk_view(host: Host, name: str | None = None) -> dict:
        from .tools import ramdisk
        st = ramdisk.status(host, name or ramdisk.NAME)
        return {**st.to_dict(host.home), "max_mb": ramdisk.max_mb(host), "default_mb": ramdisk.DEFAULT_MB,
                "commands": ramdisk.commands(host, name or ramdisk.NAME)}

    def disk_of(body: dict) -> str:
        """Which RAM disk a request is about: the browser's (~/TempBrowser) or the RAM disk tool's."""
        from .tools import ramdisk
        return ramdisk.BROWSER if body.get("disk") == "browser" else ramdisk.NAME

    @app.get("/api/tools/ramdisk", dependencies=[Depends(auth)])
    async def tools_ramdisk():
        host = make_host()
        return {"ramdisk": await asyncio.to_thread(ramdisk_view, host), "admin_active": admin.active()}

    @app.post("/api/tools/ramdisk/open", dependencies=[Depends(auth)])
    async def tools_ramdisk_open(request: Request):
        """Body {"size_mb", "noexec", "disk"}: the helper mounts ~/RAMDisk, or ~/TempBrowser for
        "disk": "browser" (it checks them again)."""
        from .tools import ramdisk
        body = await body_of(request)
        name = disk_of(body)
        size, noexec = body.get("size_mb"), body.get("noexec", True)
        host = make_host()
        if not isinstance(size, int) or isinstance(size, bool) or not 50 <= size <= ramdisk.max_mb(host):
            return JSONResponse({"error": f"Choose a size from 50 to {ramdisk.max_mb(host)} MB."}, status_code=400)
        if scan_lock.locked():
            return busy()
        async with scan_lock:
            problem = await with_root(host)
            if problem:
                return JSONResponse({"error": problem.replace("changed", "opened"), "declined": True}, status_code=403)
            try:
                await asyncio.to_thread(host.privileged.call, "ramdisk_open",
                                        {"size_mb": size, "noexec": bool(noexec), "name": name})
            except HelperError as e:
                return JSONResponse({"error": f"It couldn't be opened: {e}"}, status_code=400)
            if name == ramdisk.BROWSER:                 # this copy opened it: this copy closes it when it quits
                from .tools import owner
                await asyncio.to_thread(owner.claim, host, name, ramdisk.folder(host, name))
        return {"ramdisk": await asyncio.to_thread(ramdisk_view, host, name), "admin_active": admin.active()}

    @app.post("/api/tools/ramdisk/tidy", dependencies=[Depends(auth)])
    async def tools_ramdisk_tidy(request: Request):
        """Body {"disk"}: the empty, read-only folder an open left when a restart ended the mount, put back as it was
        (ramdisk.put_back, as the user: no administrator access). Closing one that isn't open stays refused."""
        from .tools import ramdisk
        name = disk_of(await body_of(request))
        host = make_host()
        st = await asyncio.to_thread(ramdisk.status, host, name)
        if st.open or not st.leftover:
            return JSONResponse({"error": f"~/{name} isn't a folder a RAM disk left behind."}, status_code=409)
        try:
            done = await asyncio.to_thread(ramdisk.put_back, host, name)
        except OSError as e:
            return JSONResponse({"error": f"It couldn't be put back: {e.strerror or e}."}, status_code=409)
        return {"ramdisk": await asyncio.to_thread(ramdisk_view, host, name), "done": done}

    @app.post("/api/tools/ramdisk/close", dependencies=[Depends(auth)])
    async def tools_ramdisk_close(request: Request):
        """Body {"disk"} as for opening. Refused while a program uses it ("Close X first");
        otherwise every file in it is overwritten with zeros and deleted (as the user), then the
        helper unmounts it."""
        from .tools import ramdisk
        name = disk_of(await body_of(request))
        host = make_host()
        st = await asyncio.to_thread(ramdisk.status, host, name)
        if not st.open:
            # nothing to close: a folder of that name that isn't the RAM disk is the user's own, and is left alone
            return JSONResponse({"error": f"~/{name} isn't open, so there is nothing to close."}, status_code=409)
        if scan_lock.locked():
            return busy()
        async with scan_lock:
            wiped = None
            if st.open:
                from .tools.browser import disk_users
                users = await asyncio.to_thread(disk_users, host, st.path)
                if users:
                    return JSONResponse({"error": f"Close {', '.join(users)} first: "
                                         f"{'it is' if len(users) == 1 else 'they are'} using files in ~/{name}.",
                                         "users": users}, status_code=409)
                from .tools.browser import wipe_disk
                w = await asyncio.to_thread(wipe_disk if name == ramdisk.BROWSER else ramdisk.wipe, st.path)
                wiped = {"files": w.files, "bytes": w.bytes, "failed": w.failed[:20]}
            problem = await with_root(host)
            if problem:
                return JSONResponse({"error": problem.replace("changed", "closed") + (
                    " Its files have been overwritten and deleted already." if wiped else ""), "declined": True,
                    "wiped": wiped}, status_code=403)
            try:
                await asyncio.to_thread(host.privileged.call, "ramdisk_close", {"name": name})
            except HelperError as e:
                return JSONResponse({"error": f"It couldn't be closed: {e}", "wiped": wiped}, status_code=400)
            from .tools import owner
            owner.release(host, name)
        return {"ramdisk": await asyncio.to_thread(ramdisk_view, host, name), "wiped": wiped,
                "admin_active": admin.active()}

    # Tor Browser or Mullvad Browser in the RAM disk. Downloading reaches the network (make_net), only
    # when the user starts it, after the page has named the hosts; verifying and unpacking follow in the
    # same background job, which the page follows. Starting the browser is quick.

    def browser_view(job: dict | None) -> dict | None:
        if job is None:
            return None
        return {**{k: v for k, v in job.items() if k not in ("cancel", "archive")}, "stopping": job["cancel"],
                "now": time.time()}

    def browser_busy() -> bool:
        j = app.state.browser_job
        return j is not None and j["state"] == "running"

    async def run_browser_job(job: dict, b, archive: Path | None, held: int | None = None) -> None:
        from .tools import browser as B, owner
        host = make_host()
        state, error, unchecked = "failed", "", ""
        try:
            if archive is None:
                archive = await asyncio.to_thread(B.download, host, make_net(), b, job, lambda: job["cancel"])
            else:                                       # the user's own archive: a copy of it, only the latest version
                archive = await asyncio.to_thread(B.copy_in, host, archive, job)
                job.update(phase=f"Asking {B.index_host(b)} which version is the latest", done=0, total=0)
                try:
                    job["latest"] = await asyncio.to_thread(B.check_latest, make_net(), b, archive.name)
                except B.Unreachable as e:              # blocked here? decided once the signature is verified
                    unchecked = str(e)
            job.update(phase=f"Checking {archive.name}'s signature", done=0, total=0)
            job["verdict"] = await asyncio.to_thread(B.verified, host, archive)
            if unchecked:
                job["warning"] = await asyncio.to_thread(B.accept_unchecked, archive, b, unchecked,
                                                         job["verdict"]["signed"])
            if job["cancel"]:
                raise B.Stopped("Stopped before unpacking: nothing was unpacked.")
            target = await asyncio.to_thread(B.unpack, host, archive, b, job)
            security = await asyncio.to_thread(B.preset_security, host, b, target)
            vpn_preset = await asyncio.to_thread(B.preset_vpn, host, b, target, archive) if job["vpn"] else None
            job["release"] = await asyncio.to_thread(B.record_release, host, b, archive, job["source"], security,
                                                     bool(unchecked), job["verdict"]["signed"], vpn_preset)
            job["outbox"] = await asyncio.to_thread(B.default_outbox, host, b)
            job["version"] = job["version"] or job["release"]["version"]
            state = "done"
        except B.Stopped as e:
            state, error = "stopped", str(e)
        except B.BrowserError as e:
            error = str(e)
        except OSError as e:
            error = f"It couldn't be written to the RAM disk: {e.strerror or e}"
        except Exception as e:  # noqa: BLE001 - shown on the page rather than spin forever
            error = f"{type(e).__name__}: {e}"
        finally:
            # what was downloaded gives its memory back, whatever happened; a file of the user's stays
            await asyncio.to_thread(B.tidy, host, archive) if archive is not None else None
            owner.let_go(held)
            job.update(state=state, error=error, finished=time.time(), phase=None)

    def adopt_browser_disk(host: Host) -> None:
        """~/TempBrowser open with no copy of the app running that owns it (the one that opened it ended): the copy
        showing the browser panel takes it over, and closes it when it quits (owner.py)."""
        from .tools import owner, ramdisk
        if ramdisk.mounted(host, ramdisk.BROWSER):
            try:
                owner.claim(host, ramdisk.BROWSER, ramdisk.folder(host, ramdisk.BROWSER))
            except OSError:
                pass

    @app.get("/api/tools/browser", dependencies=[Depends(auth)])
    async def tools_browser():
        from .tools import browser as B
        from .tools.pick import dialog
        host = make_host()
        chooser = "window" if pick is not None else getattr(dialog(host), "__name__", None)
        await asyncio.to_thread(adopt_browser_disk, host)
        return {**await asyncio.to_thread(B.status, host), "job": browser_view(app.state.browser_job),
                "can_pick": chooser is not None, "picker": chooser, "admin_active": admin.active()}

    @app.post("/api/tools/browser/get", dependencies=[Depends(auth)])
    async def tools_browser_get(request: Request):
        """Body {"browser": "tor" | "mullvad"} to download it (the page has named the hosts), or
        {"archive": path} for one the user downloaded (its .asc beside it); "vpn" (default true): Mullvad
        Browser set up for Mullvad VPN (browser.preset_vpn). Returns at once; the page follows the job with
        GET /api/tools/browser."""
        from .tools import browser as B
        body = await body_of(request)
        host = make_host()
        if browser_busy():
            return JSONResponse({"error": "A browser is already being set up."}, status_code=409)
        archive = None
        try:
            if body.get("archive"):
                archive = tool_paths(host, body["archive"])[0]
                b = B.which(archive)
                plat = B.platform_name()
                if plat is None or plat not in archive.name:
                    return JSONResponse({"error": f"{archive.name} isn't made for this processor."}, status_code=400)
            else:
                b = B.BROWSERS[body.get("browser")]
        except (KeyError, TypeError):
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        except ValueError as e:
            return bad_path(e)
        problem = await asyncio.to_thread(B.ready, host)
        if problem:
            return JSONResponse({"error": problem}, status_code=409)
        from .tools import owner
        held = await asyncio.to_thread(owner.hold, host, f"browser-{b.id}")
        if held is None:
            return JSONResponse({"error": f"{b.name} is being set up or started in another window of this app."},
                                status_code=409)
        job = app.state.browser_job = {"id": uuid.uuid4().hex, "state": "running", "browser": b.id, "name": b.name,
                                       "source": "file" if archive else "download", "hosts": [B.index_host(b)] if archive else list(b.hosts),
                                       "phase": "Starting", "done": 0, "total": 0, "version": "", "verdict": None,
                                       "error": "", "cancel": False, "created": time.time(), "finished": None,
                                       "vpn": b.id == "mullvad" and body.get("vpn", True) is not False}
        app.state.browser_task = asyncio.create_task(run_browser_job(job, b, archive, held))
        return {"job": browser_view(job)}

    @app.post("/api/tools/browser/stop", dependencies=[Depends(auth)])
    async def tools_browser_stop():
        job = app.state.browser_job
        if job is not None and job["state"] == "running":
            job["cancel"] = True
        return {"job": browser_view(job)}

    @app.post("/api/tools/browser/dismiss", dependencies=[Depends(auth)])
    async def tools_browser_dismiss():
        if not browser_busy():
            app.state.browser_job = None
        return {"job": None if not browser_busy() else browser_view(app.state.browser_job)}

    def browser_of(body: dict):
        from .tools import browser as B
        return B.BROWSERS.get(body.get("browser")) if isinstance(body.get("browser"), str) else None

    @app.post("/api/tools/browser/start", dependencies=[Depends(auth)])
    async def tools_browser_start(request: Request):
        """Body {"browser", "sandbox": true, "sound": false, "nested": false, "gpu": false, "expect": {...}}: starts
        it from the RAM disk, its caches and settings in there too, in the sandbox unless asked not to; on X11 in a
        display of its own (Xephyr) when asked; with the graphics card when asked. `expect`: what the panel showed of the sandbox (B.EXPECTED):
        a start that would fall short of it is refused (409), so what the page showed is what the user gets."""
        from .tools import browser as B
        from .tools import sandbox as S
        body = await body_of(request)
        host = make_host()
        b = browser_of(body)
        if b is None:
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        expect = body.get("expect") if isinstance(body.get("expect"), dict) else None
        expect = {k: expect[k] for k in B.EXPECTED if k in expect} if expect else None
        try:
            how = await asyncio.to_thread(B.start, host, b, spawn_browser, body.get("sandbox") is not False,
                                          body.get("sound") is True, make_net, body.get("nested") is True, expect,
                                          body.get("gpu") is True)
        except (B.BrowserError, S.SandboxError) as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        except OSError as e:
            return JSONResponse({"error": f"{b.name} couldn't be started: {e.strerror or e}"}, status_code=400)
        return {**await asyncio.to_thread(B.status, host), "started": how}

    @app.post("/api/tools/browser/swap", dependencies=[Depends(auth)])
    async def tools_browser_swap(request: Request):
        """Body {"off": true | false}: the helper turns off every swap that reaches a disk, for the
        browser's session, or back on what it turned off. Not a fix: nothing in History; a reboot
        turns it back on anyway."""
        from .tools import browser as B
        body = await body_of(request)
        if not isinstance(body.get("off"), bool):
            return JSONResponse({"error": "Say whether to turn swap off or on."}, status_code=400)
        host = make_host()
        if scan_lock.locked():
            return busy()
        async with scan_lock:
            problem = await with_root(host)
            if problem:
                return JSONResponse({"error": problem.replace("changed", "turned off" if body["off"] else "turned on"),
                                     "declined": True}, status_code=403)
            try:
                r = await asyncio.to_thread(host.privileged.call, "swap_off" if body["off"] else "swap_on", {})
            except HelperError as e:
                return JSONResponse({"error": f"Swap couldn't be turned {'off' if body['off'] else 'on'}: {e}"},
                                    status_code=400)
        return {**await asyncio.to_thread(B.status, host), "swap": r, "admin_active": admin.active()}

    @app.post("/api/tools/browser/bridges", dependencies=[Depends(auth)])
    async def tools_browser_bridges(request: Request):
        """Body {"browser": "tor", "mode": "none" | "obfs4" | "snowflake" | "meek" | "custom", "lines": text}:
        how Tor Browser's tor connects from its next start in the sandbox (Tor Browser's own Connect page
        is off there). Kept in the RAM disk only."""
        from .tools import browser as B
        body = await body_of(request)
        host = make_host()
        b = browser_of(body)
        if b is None or not b.tor:
            return JSONResponse({"error": "Bridges are for Tor Browser."}, status_code=400)
        problem = await asyncio.to_thread(B.ready, host)
        if problem or not B.installed(host, b):
            return JSONResponse({"error": problem or f"{b.name} isn't in the RAM disk."}, status_code=409)
        lines = body.get("lines", "")
        try:
            await asyncio.to_thread(B.set_bridges, host, b, str(body.get("mode")), lines if isinstance(lines, str) else "")
        except B.BrowserError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return await asyncio.to_thread(B.status, host)

    @app.post("/api/tools/browser/upload", dependencies=[Depends(auth)])
    async def tools_browser_upload(request: Request):
        """Body {"browser", "paths": [...], "clean": bool}: copies the files into its "To upload"
        folder, cleaned of metadata first when asked. The originals are never changed."""
        from .tools import browser as B, transfer
        body = await body_of(request)
        host = make_host()
        b = browser_of(body)
        if b is None:
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        problem = await asyncio.to_thread(B.ready, host)
        if problem or not B.installed(host, b):
            return JSONResponse({"error": problem or f"{b.name} isn't in the RAM disk."}, status_code=409)
        try:
            paths = tool_paths(host, body.get("paths"))
        except ValueError as e:
            return bad_path(e)
        added, errors = [], []
        for p in paths:
            try:
                added.append(await asyncio.to_thread(transfer.add, host, b.folder, p, body.get("clean") is True))
            except (transfer.TransferError, OSError) as e:
                errors.append(str(e) if isinstance(e, transfer.TransferError) else f"{p.name}: {e.strerror or e}")
        return {**await asyncio.to_thread(B.status, host), "added": added, "errors": errors}

    @app.post("/api/tools/browser/view", dependencies=[Depends(auth)])
    async def tools_browser_view(request: Request):
        """Body {"browser", "name", "open": bool, "check"}: which viewer would open a finished download, and
        how (open false); or open it there, with no network (open true, only when the copy made out of the
        browser's reach is what the page showed, `check`): tools/viewer.py."""
        from .tools import browser as B, sandbox as S, transfer, viewer
        body = await body_of(request)
        host = make_host()
        b = browser_of(body)
        if b is None:
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        problem = await asyncio.to_thread(B.ready, host)
        if problem or not B.installed(host, b):
            return JSONResponse({"error": problem or f"{b.name} isn't in the RAM disk."}, status_code=409)
        try:
            if body.get("open") is True:
                private = await asyncio.to_thread(B._dir, host, B.private_dir(host, b).name)
                got = await asyncio.to_thread(viewer.view, host, b.folder, body.get("name"), private, spawn_browser,
                                              body.get("check"))
            else:
                got = (await asyncio.to_thread(viewer.plan, host, b.folder, body.get("name"))).to_dict()
        except transfer.Changed as e:
            return JSONResponse({"error": str(e), "changed": True}, status_code=409)
        except (viewer.ViewError, B.BrowserError, transfer.TransferError, S.SandboxError) as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        except OSError as e:
            return JSONResponse({"error": f"It couldn't be opened: {e.strerror or e}"}, status_code=400)
        sb = await asyncio.to_thread(B.session_display, host)
        return {"viewer": got, "display": sb}

    @app.post("/api/tools/browser/outbox", dependencies=[Depends(auth)])
    async def tools_browser_outbox(request: Request):
        """Body {"browser", "on": bool}: makes the browser's TempOutbox (~/TempBrowser/Outbox for NAME), or
        removes it (refused while it holds files)."""
        from .tools import browser as B, transfer
        body = await body_of(request)
        host = make_host()
        b = browser_of(body)
        if b is None:
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        problem = await asyncio.to_thread(B.ready, host)
        if problem or not B.installed(host, b):
            return JSONResponse({"error": problem or f"{b.name} isn't in the RAM disk."}, status_code=409)
        try:
            if body.get("on") is True:
                await asyncio.to_thread(transfer.make_outbox, host, b.name)
            else:
                await asyncio.to_thread(transfer.remove_outbox, host, b.name)
        except (transfer.TransferError, OSError) as e:
            return JSONResponse({"error": str(e) if isinstance(e, transfer.TransferError) else
                                 f"It couldn't be changed: {e.strerror or e}"}, status_code=400)
        return await asyncio.to_thread(B.status, host)

    @app.post("/api/tools/browser/upload/remove", dependencies=[Depends(auth)])
    async def tools_browser_upload_remove(request: Request):
        from .tools import browser as B, transfer
        body = await body_of(request)
        host = make_host()
        b = browser_of(body)
        if b is None:
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        try:
            await asyncio.to_thread(transfer.remove_upload, host, b.folder, body.get("name"))
        except (transfer.TransferError, OSError) as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return await asyncio.to_thread(B.status, host)

    @app.post("/api/tools/browser/save", dependencies=[Depends(auth)])
    async def tools_browser_save(request: Request):
        """Body {"browser", "name", "check", "folder"}: copies a finished download out of the RAM disk into
        the folder the user chose (a new file, never over one, never executable), from a copy judged
        again out of the browser's reach: only when it is what the page showed (`check`, from the list)."""
        from .tools import browser as B, transfer
        body = await body_of(request)
        host = make_host()
        b = browser_of(body)
        if b is None:
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        folder = body.get("folder")
        if not isinstance(folder, str) or not folder.strip() or "\0" in folder:
            return JSONResponse({"error": "Choose a folder to save it in."}, status_code=400)
        folder = folder.strip()
        if folder == "~" or folder.startswith("~/"):
            folder = str(host.home) + folder[1:]
        elif folder.startswith("~"):               # ~name: another account's home, which this doesn't resolve
            return JSONResponse({"error": "Give the whole path of the folder, starting with / or ~/."}, status_code=400)
        dest = Path(folder)
        if not dest.is_absolute() or not dest.is_dir():
            return JSONResponse({"error": f"{folder} isn't a folder."}, status_code=400)
        try:
            saved = await asyncio.to_thread(transfer.save, host, b.folder, body.get("name"), dest, body.get("check"))
        except transfer.Changed as e:
            return JSONResponse({"error": str(e), "changed": True}, status_code=409)
        except (transfer.TransferError, OSError) as e:
            return JSONResponse({"error": str(e) if isinstance(e, transfer.TransferError) else
                                 f"It couldn't be saved: {e.strerror or e}"}, status_code=400)
        return {**await asyncio.to_thread(B.status, host), "saved": str(saved)}

    # the TRIM test: a background job (it reads the whole disk two or three times), followed by the page

    def trim_running() -> bool:
        jobs = (app.state.trim_job, app.state.names_job, app.state.clean_job)
        return any(j is not None and j["state"] in ("asking", "running") for j in jobs)

    # the TRIM test and Deleted file names don't start while an app is watched, nor the watch while they run: the
    # helper does one call at a time, and a disk read for minutes held the watch's polling (and its End) behind it
    def watching() -> JSONResponse:
        return JSONResponse({"error": "An app is being watched (What does this app keep?): end the watch first. Both "
                                      "need the administrator helper, which does one thing at a time."},
                            status_code=409)

    def trim_view(job: dict | None) -> dict | None:
        if job is None:
            return None
        return {**{k: v for k, v in job.items() if k != "cancel"}, "stopping": job["cancel"], "now": time.time()}

    async def run_trim_job(job: dict, mount: str) -> None:
        from .tools import trimtest
        host = make_host()
        try:
            problem = await with_root(host)
            if problem:
                job["state"], job["error"] = "failed", problem.replace("Nothing was changed.", "The test didn't start.")
                return
            job["state"], job["started"] = "running", time.time()
            with admin.hold():
                job["result"] = await asyncio.to_thread(trimtest.run, host, mount, lambda: admin.get(prompt=False), job)
            job["state"] = "done"
        except trimtest.Stopped as e:
            job["state"], job["error"] = "stopped", str(e)
        except ValueError as e:
            job["state"], job["error"] = "failed", str(e)
        except HelperError as e:
            job["state"], job["error"] = "failed", f"The helper refused: {e}"
        except OSError as e:
            job["state"], job["error"] = "failed", f"The test files couldn't be written or removed: {e.strerror or e}"
        except Exception as e:  # noqa: BLE001 - shown on the page rather than spin forever
            job["state"], job["error"] = "failed", f"{type(e).__name__}: {e}"
        finally:
            job["finished"], job["phase"], job["scan"] = time.time(), None, None

    @app.get("/api/tools/trim", dependencies=[Depends(auth)])
    async def tools_trim():
        from .tools import trimtest
        host = make_host()

        def gather():
            stuck = [] if trim_running() else trimtest.leftovers(host)
            return {"targets": [t.to_dict(host) for t in trimtest.targets(host)], "leftovers": stuck,
                    "test_bytes": trimtest.TEST_BYTES}
        return {**await asyncio.to_thread(gather), "job": trim_view(app.state.trim_job), "admin_active": admin.active()}

    @app.post("/api/tools/trim/start", dependencies=[Depends(auth)])
    async def tools_trim_start(request: Request):
        """Body {"mount"}: starts the TRIM test on that filesystem (asking for administrator access)
        and returns at once; the page follows it with GET /api/tools/trim."""
        body = await body_of(request)
        if trim_running():
            return JSONResponse({"error": "The TRIM test is already running."}, status_code=409)
        if keeps_running():
            return watching()
        mount = body.get("mount")
        if not isinstance(mount, str):
            return JSONResponse({"error": "Choose a filesystem to test."}, status_code=400)
        job = app.state.trim_job = {"id": uuid.uuid4().hex, "state": "asking", "mount": mount, "phase": "Starting",
                                    "scan": None, "done": 0, "total": 0, "phase_started": time.time(), "steps": [],
                                    "created": time.time(), "started": None, "finished": None, "result": None,
                                    "error": "", "cancel": False}
        app.state.trim_task = asyncio.create_task(run_trim_job(job, mount))
        return {"job": trim_view(job)}

    @app.post("/api/tools/trim/stop", dependencies=[Depends(auth)])
    async def tools_trim_stop():
        """Stops the test within seconds; its files are removed."""
        job = app.state.trim_job
        if job is not None and job["state"] in ("asking", "running"):
            job["cancel"] = True
        return {"job": trim_view(job)}

    @app.post("/api/tools/trim/dismiss", dependencies=[Depends(auth)])
    async def tools_trim_dismiss():
        """Forgets a finished test's result (it is never kept beyond this session anyway)."""
        if not trim_running():
            app.state.trim_job = None
        return {"job": trim_view(app.state.trim_job)}

    # Deleted file names: the list (a background job: on btrfs it reads the whole disk), handed to the
    # page once and never kept here; then, on ext4, cleaning the folders the user picks (another job),
    # whose result is handed over once too. The helper holds the names for the checks after a clean-up
    # until the page closes the tool (forget), or administrator access ends.

    def trim_passed(mount: str) -> bool | None:
        """Whether the TRIM test passed on this filesystem in this session (None: not run, or no answer)."""
        job = app.state.trim_job
        if job is None or job.get("mount") != mount or job["state"] != "done" or not job.get("result"):
            return None
        return job["result"]["verdict"] == "pass"

    def handed(job: dict | None, attr: str) -> dict:
        """The job's view; a finished one is handed over with this answer and forgotten here."""
        view = trim_view(job)
        if job is not None and job["state"] not in ("asking", "running"):
            setattr(app.state, attr, None)
        return {"job": view}

    async def run_names_job(job: dict, mount: str, trim_first: bool) -> None:
        from .tools import names
        host = make_host()
        try:
            problem = await with_root(host)
            if problem:
                job["state"], job["error"] = "failed", problem.replace("Nothing was changed.", "Nothing was read.")
                return
            job["state"] = "running"
            with admin.hold():
                if trim_first:
                    job.update(phase=f"Trimming {mount}", phase_started=time.time())
                    h = admin.get(prompt=False)
                    if h is None:
                        raise names.Stopped("Administrator access ended, so it stopped.")
                    job["trimmed"] = (await asyncio.to_thread(h.call, "names_fstrim", {"mount": mount}, 900)).get("trimmed")
                job["result"] = await asyncio.to_thread(names.scan, host, mount, lambda: admin.get(prompt=False), job,
                                                        trim_passed(mount))
            job["state"] = "done"
        except names.Stopped as e:
            job["state"], job["error"] = "stopped", str(e)
        except ValueError as e:
            job["state"], job["error"] = "failed", str(e)
        except HelperError as e:
            job["state"], job["error"] = "failed", f"The helper refused: {e}"
        except Exception as e:  # noqa: BLE001
            job["state"], job["error"] = "failed", f"{type(e).__name__}: {e}"
        finally:
            job["phase"] = None

    @app.get("/api/tools/names", dependencies=[Depends(auth)])
    async def tools_names():
        """The filesystems whose names can be listed."""
        from .tools import names
        host = make_host()
        targets = await asyncio.to_thread(names.targets, host)
        for t in targets:
            t["trim_passed"] = trim_passed(t["mount"])
        return {"targets": targets, "admin_active": admin.active(), "busy": trim_running()}

    @app.post("/api/tools/names/start", dependencies=[Depends(auth)])
    async def tools_names_start(request: Request):
        """Body {"mount", "trim_first"}: lists the names on that filesystem (the helper checks it may),
        trimming it first when asked (btrfs: Trim now and check again)."""
        body = await body_of(request)
        mount = body.get("mount")
        if not isinstance(mount, str):
            return JSONResponse({"error": "Which disk?"}, status_code=400)
        if trim_running():
            return JSONResponse({"error": "The TRIM test or another listing is still running."}, status_code=409)
        if keeps_running():
            return watching()
        job = app.state.names_job = {"state": "asking", "phase": "Starting", "done": 0, "total": 0, "unit": "",
                                     "phase_started": time.time(), "result": None, "error": "", "cancel": False,
                                     "mount": mount, "trimmed": None}
        app.state.names_task = asyncio.create_task(run_names_job(job, mount, body.get("trim_first") is True))
        return {"job": trim_view(job)}

    @app.get("/api/tools/names/job", dependencies=[Depends(auth)])
    async def tools_names_job():
        """The listing; once it is done, its names are handed over with this answer and forgotten here."""
        return handed(app.state.names_job, "names_job")

    @app.post("/api/tools/names/forget", dependencies=[Depends(auth)])
    async def tools_names_forget():
        """The page closed the tool (or gave up on it): stop, and have the helper forget the names."""
        for attr in ("names_job", "clean_job"):
            job = getattr(app.state, attr)
            if job is not None:
                job["cancel"] = True
                if job["state"] not in ("asking", "running"):
                    setattr(app.state, attr, None)
        h = admin.get(prompt=False) if admin.active() else None
        if h is not None and not trim_running():
            try:
                await asyncio.to_thread(h.call, "names_end", {})
            except Exception:  # noqa: BLE001 - it forgets them when access ends anyway
                pass
        return {"job": None}

    @app.post("/api/tools/names/plan", dependencies=[Depends(auth)])
    async def tools_names_plan(request: Request):
        """Body {"mount", "folders": [path under the listing's top], "rebuild": [those to rebuild
        rather than fill]}: what cleaning them would do now (the dry run). Changes nothing."""
        from .tools import rebuild
        body = await body_of(request)
        mount, rels, again = body.get("mount"), body.get("folders"), body.get("rebuild") or []
        if not isinstance(mount, str) or not isinstance(rels, list) or not all(isinstance(x, str) for x in rels) \
                or not 0 < len(rels) <= 500 or not isinstance(again, list) or not all(isinstance(x, str) for x in again):
            return JSONResponse({"error": "Choose the folders to clean."}, status_code=400)
        try:
            return {"plan": await asyncio.to_thread(rebuild.plan, make_host(), mount, rels, again),
                    "admin_active": admin.active()}
        except rebuild.Refused as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    async def run_clean_job(job: dict, mount: str, rels: list[str], again: list[str]) -> None:
        from .tools import names, rebuild
        host = make_host()
        try:
            problem = await with_root(host)
            if problem:
                job["state"], job["error"] = "failed", problem
                return
            job["state"] = "running"
            with admin.hold():
                job["result"] = await asyncio.to_thread(rebuild.run, host, mount, rels, lambda: admin.get(prompt=False),
                                                        job, again)
            job["state"] = "done"
        except names.Stopped as e:
            job["state"], job["error"] = "stopped", str(e)
        except rebuild.Refused as e:
            job["state"], job["error"] = "failed", str(e)
        except HelperError as e:
            job["state"], job["error"] = "failed", (
                "The listing has been forgotten (administrator access ended): list the names again first."
                if "not looking for names" in str(e) else f"The helper refused: {e}")
        except Exception as e:  # noqa: BLE001
            job["state"], job["error"] = "failed", f"{type(e).__name__}: {e}"
        finally:
            job["phase"] = None

    @app.post("/api/tools/names/clean", dependencies=[Depends(auth)])
    async def tools_names_clean(request: Request):
        """Body {"mount", "folders", "not_synced"}: cleans those folders as the plan says (each is
        checked again first), trims, and checks; returns at once, the page follows GET
        /api/tools/names/clean. `not_synced`: the user said none of them is synced by a service the
        app doesn't recognise. `rebuild`: those to rebuild rather than fill, as in the plan."""
        body = await body_of(request)
        mount, rels, again = body.get("mount"), body.get("folders"), body.get("rebuild") or []
        if not isinstance(mount, str) or not isinstance(rels, list) or not all(isinstance(x, str) for x in rels) \
                or not 0 < len(rels) <= 500 or not isinstance(again, list) or not all(isinstance(x, str) for x in again):
            return JSONResponse({"error": "Choose the folders to clean."}, status_code=400)
        if body.get("not_synced") is not True:
            return JSONResponse({"error": "Say first that none of these folders is synced by an online service."},
                                status_code=400)
        if trim_running():
            return JSONResponse({"error": "The TRIM test or another listing is still running."}, status_code=409)
        if keeps_running():
            return watching()
        job = app.state.clean_job = {"state": "asking", "phase": "Starting", "steps": [], "result": None, "error": "",
                                     "cancel": False, "mount": mount, "started": time.time()}
        app.state.clean_task = asyncio.create_task(run_clean_job(job, mount, rels, again))
        return {"job": trim_view(job)}

    @app.get("/api/tools/names/clean", dependencies=[Depends(auth)])
    async def tools_names_clean_job():
        return handed(app.state.clean_job, "clean_job")

    @app.post("/api/tools/names/check", dependencies=[Depends(auth)])
    async def tools_names_check(request: Request):
        """Body {"mount", "folders"}: reads folders cleaned before (and the journal) again for their
        names. Only while the helper still holds the listing; never asks for access."""
        from .tools import names, rebuild
        body = await body_of(request)
        mount, rels = body.get("mount"), body.get("folders")
        if not isinstance(mount, str) or not isinstance(rels, list) or not all(isinstance(x, str) for x in rels) \
                or not 0 < len(rels) <= 500:
            return JSONResponse({"error": "Which folders?"}, status_code=400)
        if trim_running():
            return JSONResponse({"error": "The TRIM test or another listing is still running."}, status_code=409)
        try:
            with admin.hold():
                return {"result": await asyncio.to_thread(rebuild.recheck, make_host(), mount, rels,
                                                          lambda: admin.get(prompt=False))}
        except (names.Stopped, rebuild.Refused) as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        except HelperError as e:
            return JSONResponse({"error": "The listing has been forgotten (administrator access ended): list the names "
                                          "again." if "not looking for names" in str(e) else f"The helper refused: {e}"},
                                status_code=409)

    async def of_listing(call) -> dict | JSONResponse:
        """Something done with the listing the helper still holds: never asks for access."""
        from .tools import names
        if trim_running():
            return JSONResponse({"error": "The TRIM test or another listing is still running."}, status_code=409)
        try:
            with admin.hold():
                return await asyncio.to_thread(call, lambda: admin.get(prompt=False) if admin.active() else None)
        except names.Stopped as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        except HelperError as e:
            forgotten = "not looking for names" in str(e) or "haven't been listed" in str(e)
            return JSONResponse({"error": "The listing has been forgotten (administrator access ended): list the names "
                                          "again first." if forgotten else f"The helper refused: {e}"}, status_code=409)

    @app.post("/api/tools/names/journal/clear", dependencies=[Depends(auth)])
    async def tools_names_journal_clear():
        """ext4: has the kernel write the listed filesystem's journal out and zero it (every folder's names in
        it at once). Only while the helper holds a listing; nothing of it is kept, and nothing can be undone."""
        from .tools import names
        return await of_listing(names.clear_journal)

    @app.post("/api/tools/names/journal/others", dependencies=[Depends(auth)])
    async def tools_names_journal_others():
        """ext4: the names in the journal's records of folders that are no listed folder's (gone, another
        account's, the system's). Only when the user asks, as administrator; shown once, never kept."""
        from .tools import names
        return await of_listing(names.orphans)

    @app.get("/api/tools/inuse", dependencies=[Depends(auth)])
    async def tools_inuse():
        """Who is using the camera, a microphone or the screen now; the page asks again every few
        seconds while the view is open. Reads only, keeps nothing."""
        from .tools import inuse
        return (await asyncio.to_thread(inuse.snapshot, make_host())).to_dict()

    # What does this app keep?: one app from the menu, started in a group of its own and watched by the helper for
    # as long as the user leaves it on. The result is held here, in memory, until it is dismissed or the app quits:
    # never in History, a report or an export.

    keeps_starting = asyncio.Lock()

    def keeps_running() -> bool:
        job = app.state.keeps_job
        return job is not None and job["state"] in ("asking", "running", "ending")

    def keeps_view(job: dict | None) -> dict | None:
        if job is None:
            return None
        return {**{k: v for k, v in job.items() if k != "cancel"}, "stopping": job["cancel"], "now": time.time()}

    async def run_keeps_job(job: dict, entry) -> None:
        from .tools import appwatch
        host = make_host()
        had_admin = admin.active()
        token, began = job["id"][:12], None
        units = appwatch.units(entry, token)
        try:
            problem = await with_root(host)
            if problem:
                job["state"], job["error"] = "failed", problem.replace("Nothing was changed.", "Nothing was started.")
                return
            if job["cancel"]:                           # ended while the authorization was being asked for
                job["state"], job["error"] = "failed", f"Ended before {entry.name} was started. Nothing was started."
                return
            with admin.hold():
                try:
                    # when it began and what GVFS's metadata held then (keyed hashes): kept here, never in the job
                    before = await asyncio.to_thread(appwatch.snapshot, host)
                    began = await asyncio.to_thread(host.privileged.call, "watch_begin", {"units": units})
                    job.update(watched=began["watched"], not_watched=began["skipped"])
                    await asyncio.to_thread(appwatch.start, host, entry, token, spawn_app)
                    job["state"], job["started"] = "running", time.time()
                    seen = False
                    while not job["cancel"]:
                        await asyncio.sleep(KEEPS_EVERY)
                        h = admin.get(prompt=False)
                        if h is None:
                            began = None
                            raise appwatch.WatchError("Administrator access ended, so the watch ended with it. "
                                                      "Nothing of what it saw is left.")
                        job["counts"] = await asyncio.to_thread(h.call, "watch_poll", {})
                        if "watched" in job["counts"]:          # a disk mounted or unmounted meanwhile
                            job["watched"] = job["counts"].pop("watched")
                            job["not_watched"] = job["counts"].pop("skipped", [])
                        job["alive"] = await asyncio.to_thread(appwatch.alive, host, units)
                        seen = seen or job["alive"] > 0
                        job["closed"] = seen and not job["alive"]                 # the app has ended: time to end
                        job["absent"] = not seen and time.time() - job["started"] > 20
                        # running, but not a file of its own or the user's opened: a wrapper that handed over to a
                        # copy already open (LibreOffice's oosplash stays, tested), which isn't watched
                        job["quiet"] = (seen and job["alive"] > 0 and not (job["counts"] or {}).get("files")
                                        and time.time() - job["started"] > appwatch.QUIET_AFTER)
                    job["state"] = "ending"
                    h = admin.get(prompt=False)         # the helper running now (the one polled), not the one given at the start
                    if h is None:
                        began = None
                        raise appwatch.WatchError("Administrator access ended, so the watch ended with it. "
                                                  "Nothing of what it saw is left.")
                    raw = await asyncio.to_thread(h.call, "watch_end", {}, 180)
                    watched, began = began, None
                finally:
                    if began is not None:               # it failed on the way: the watch doesn't stay on
                        h = admin.get(prompt=False)
                        try:
                            if h is not None:
                                await asyncio.to_thread(h.call, "watch_end", {}, 30)
                        except Exception:  # noqa: BLE001 - it ends with the helper anyway
                            pass
            job["result"] = await asyncio.to_thread(appwatch.report, host, entry, raw, watched, before)
            job["state"] = "done"
        except appwatch.WatchError as e:
            job["state"], job["error"] = "failed", str(e)
        except HelperError as e:
            job["state"], job["error"] = "failed", f"The helper refused: {e}"
        except OSError as e:
            job["state"], job["error"] = "failed", f"{entry.name} couldn't be started: {e.strerror or type(e).__name__}"
        except Exception as e:  # noqa: BLE001 - shown on the page rather than spin forever
            job["state"], job["error"] = "failed", f"{type(e).__name__}"
        finally:
            job["finished"] = time.time()
            # administrator access was for the watch: given up as soon as it ends, unless something else has it
            if not had_admin and not admin.held():
                await asyncio.to_thread(admin.drop)

    @app.get("/api/tools/keeps", dependencies=[Depends(auth)])
    async def tools_keeps():
        """The apps that can be watched, why it can't be done here (if so), and the watch or its result."""
        from .tools import appwatch, menu
        host = make_host()

        def gather():
            return {"unavailable": appwatch.available(host),
                    "apps": [a.to_dict() for a in menu.apps(host) if not a.terminal]}
        return {**await asyncio.to_thread(gather), "warning": appwatch.WARNING, "limits": appwatch.LIMITS,
                "job": keeps_view(app.state.keeps_job), "admin_active": admin.active()}

    @app.post("/api/tools/keeps/start", dependencies=[Depends(auth)])
    async def tools_keeps_start(request: Request):
        """Body {"app"}: a menu entry's id. Asks for administrator access, starts the watch, then the app."""
        from .tools import appwatch, menu
        body = await body_of(request)
        host = make_host()
        # checked and claimed with no await between: two starts at once both passed the check before either had
        # made its job, and the first went on watching, administrator access held, out of the page's reach
        if keeps_running() or keeps_starting.locked():
            return JSONResponse({"error": "An app is already being watched: end that first."}, status_code=409)
        if trim_running():
            return JSONResponse({"error": "The TRIM test or Deleted file names is running: let it finish first. Both "
                                          "need the administrator helper, which does one thing at a time."},
                                status_code=409)
        async with keeps_starting:
            why = await asyncio.to_thread(appwatch.available, host)
            if why:
                return JSONResponse({"error": why}, status_code=400)
            entry = await asyncio.to_thread(menu.app, host, body.get("app"))
            if entry is None or entry.terminal:
                return JSONResponse({"error": "Choose an app from the list."}, status_code=400)
            if await asyncio.to_thread(appwatch.running, host, entry):
                return JSONResponse({"error": f"Close {entry.name} first: started while it runs, it would only hand "
                                              "over to the copy that is open, which isn't watched."}, status_code=409)
            job = app.state.keeps_job = {"id": uuid.uuid4().hex, "state": "asking", "app": entry.name,
                                         "started": None, "finished": None, "counts": None, "alive": None,
                                         "closed": False, "absent": False, "quiet": False, "watched": [],
                                         "not_watched": [], "result": None, "error": "", "cancel": False}
            app.state.keeps_task = asyncio.create_task(run_keeps_job(job, entry))
        return {"job": keeps_view(job)}

    @app.post("/api/tools/keeps/stop", dependencies=[Depends(auth)])
    async def tools_keeps_stop():
        """Ends the watch (the app goes on running: it is the user's); the result follows."""
        job = app.state.keeps_job
        if job is not None and job["state"] in ("asking", "running"):
            job["cancel"] = True
        return {"job": keeps_view(job)}

    @app.post("/api/tools/keeps/dismiss", dependencies=[Depends(auth)])
    async def tools_keeps_dismiss():
        """Forgets a finished watch's result."""
        if not keeps_running():
            app.state.keeps_job = None
        return {"job": keeps_view(app.state.keeps_job)}

    # Try an app: one trial at a time: a file or an installed app, prepared (copied in, unpacked in a sandbox), run
    # in a sandbox with a throwaway home, watched, summed up, discarded. Nothing of it outlives the app.
    trial_lock = asyncio.Lock()

    def trial_view() -> dict | None:
        t = app.state.trial
        return t.view() if t is not None else None

    def trial_error(e: Exception) -> JSONResponse:
        return JSONResponse({"error": str(e), "trial": trial_view()}, status_code=400)

    @app.get("/api/tools/trial", dependencies=[Depends(auth)])
    async def tools_trial():
        """What a trial can have here, the apps that can be tried with a throwaway home, and the trial there is."""
        from .tools import menu, trial
        from .tools.pick import dialog
        host = make_host()

        def gather():
            if not app.state.trial_cleaned and app.state.trial is None:
                app.state.trial_cleaned = True
                trial.clear_leftovers(host)
            if app.state.trial is not None:
                trial.poll(host, app.state.trial)
            return {"status": trial.status(host),
                    "apps": [a.to_dict() for a in menu.apps(host) if not a.terminal and a.kind != "snap"]}
        return {**await asyncio.to_thread(gather), "trial": trial_view(),
                "can_pick": pick is not None or dialog(host) is not None}

    @app.post("/api/tools/trial/prepare", dependencies=[Depends(auth)])
    async def tools_trial_prepare(request: Request):
        """Body {"path"} (a file the user chose) or {"app"} (a menu entry), and {"where": memory|disk}: makes the
        trial's folder and copies or unpacks the file into it. Nothing is run."""
        from .tools import menu, trial
        from .tools.pick import PathRefused
        body = await body_of(request)
        host = make_host()
        where = body.get("where") if body.get("where") in ("memory", "disk") else "memory"
        async with trial_lock:
            if app.state.trial is not None:
                return JSONResponse({"error": "Discard the trial there is first.", "trial": trial_view()}, status_code=409)
            try:
                if body.get("app"):
                    entry = await asyncio.to_thread(menu.app, host, body.get("app"))
                    if entry is None:
                        return JSONResponse({"error": "Choose an app from the list."}, status_code=400)
                    app.state.trial = await asyncio.to_thread(trial.prepare_app, host, entry, where)
                else:
                    path = tool_paths(host, body.get("path"))[0]
                    app.state.trial = await asyncio.to_thread(trial.prepare_file, host, path, where)
            except (PathRefused, ValueError) as e:
                return trial_error(e)
            except subprocess.TimeoutExpired:
                return trial_error(ValueError("Unpacking it took too long."))
            except OSError as e:
                return trial_error(ValueError(f"It couldn't be copied into the trial's folder: {e.strerror or type(e).__name__}"))
            trial.CURRENT = app.state.trial             # what a Box can be made from (the guide of app.boxes)
        return {"trial": trial_view()}

    @app.post("/api/tools/trial/start", dependencies=[Depends(auth)])
    async def tools_trial_start(request: Request):
        """Body {"program", "args", "network", "gpu", "sound", "nested", "decoys"}: starts the prepared trial."""
        from .tools import sandbox, trial
        body = await body_of(request)
        host = make_host()
        async with trial_lock:
            t = app.state.trial
            if t is None:
                return JSONResponse({"error": "Choose what to try first."}, status_code=400)
            try:
                if t.state == "ready":
                    await asyncio.to_thread(trial.choose, t, body.get("program") or "", str(body.get("args") or ""))
                await asyncio.to_thread(trial.start, host, t, body, spawn_app)
            except (ValueError, sandbox.SandboxError) as e:
                return trial_error(e)
            except OSError as e:
                return trial_error(ValueError(f"It couldn't be started: {e.strerror or type(e).__name__}"))
        return {"trial": trial_view()}

    @app.get("/api/tools/trial/status", dependencies=[Depends(auth)])
    async def tools_trial_status():
        """The trial as it is now (the page asks while it runs): counts, decoys looked at, hosts so far."""
        from .tools import trial
        t = app.state.trial
        if t is not None:
            await asyncio.to_thread(trial.poll, make_host(), t)
        return {"trial": trial_view()}

    @app.post("/api/tools/trial/stop", dependencies=[Depends(auth)])
    async def tools_trial_stop():
        """Ends the trial's program and sums up what it did."""
        from .tools import trial
        async with trial_lock:
            if app.state.trial is not None:
                await asyncio.to_thread(trial.stop, make_host(), app.state.trial)
        return {"trial": trial_view()}

    def discard_trial() -> None:
        from .tools import trial
        t, app.state.trial = app.state.trial, None
        trial.CURRENT = None
        if t is not None:
            trial.discard(make_host(), t)

    app.state.discard_trial = discard_trial

    @app.post("/api/tools/trial/discard", dependencies=[Depends(auth)])
    async def tools_trial_discard():
        """Ends it if it runs and removes its folder (overwritten first when it is in memory)."""
        async with trial_lock:
            await asyncio.to_thread(discard_trial)
        return {"trial": None}

    # Boxes (the catalogue's app.boxes): set up through the guide, reverted from History. Here: the list with each
    # Box's runs in numbers, and starting one as its menu entry does (the launcher's own process, which doesn't
    # depend on this window).

    def box_of(host: Host, body: dict):
        from .tools import box
        b = box.read(host, body.get("box")) if isinstance(body.get("box"), str) else None
        if b is None:
            raise ValueError("There is no such Box.")
        return b

    @app.get("/api/tools/boxes", dependencies=[Depends(auth)])
    async def tools_boxes():
        from .tools import box, integration
        host = make_host()

        def gather():
            command = integration.program(host.environ)
            return [{**box.view(host, b, command, paths_of(host).data_home), "running": box.running(host, b.slug)}
                    for b in box.every(host)]
        return {"boxes": await asyncio.to_thread(gather)}

    @app.post("/api/tools/boxes/start", dependencies=[Depends(auth)])
    async def tools_boxes_start(request: Request):
        """Body {"box"}: starts it as its menu entry does."""
        from .tools import box, integration
        from .hostenv import host_env
        host = make_host()
        try:
            b = box_of(host, await body_of(request))
            why = box.problem(host, b)
            if why:
                raise ValueError(f"{b.name}'s Box can't start: {why}.")
            if box.running(host, b.slug):
                raise ValueError(f"{b.name} is already running in its Box.")
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        command = integration.program(host.environ) + ["--box", b.slug]
        try:
            await asyncio.to_thread(spawn_app, command, cwd=str(host.home), env=host_env(host.environ),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    start_new_session=True)
        except OSError as e:
            return JSONResponse({"error": f"It couldn't be started: {e.strerror or type(e).__name__}"}, status_code=400)
        return {"ok": True}

    @app.post("/api/tools/boxes/clear", dependencies=[Depends(auth)])
    async def tools_boxes_clear(request: Request):
        """Body {"box"}: forgets its runs."""
        from .tools import box
        host = make_host()
        try:
            b = box_of(host, await body_of(request))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        await asyncio.to_thread(box.clear_runs, host, b.slug)
        return {"ok": True}

    @app.post("/api/tools/boxes/show", dependencies=[Depends(auth)])
    async def tools_boxes_show(request: Request):
        """Body {"box"}: opens its Exchange folder in the file manager."""
        from .tools import box
        host = make_host()
        try:
            b = box_of(host, await body_of(request))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        target = box.folder(host, b.slug) / "Exchange"
        if not target.is_dir() or target.is_symlink():
            return JSONResponse({"error": "Its Exchange folder isn't there."}, status_code=400)
        r = await asyncio.to_thread(host.run, "xdg-open", str(target))
        return {"ok": r.ok}

    # Before you hand over a drive: the plan lists every file; deleting needs its id and a confirmation.
    # A tool, not a fix: nothing goes in History.
    handover_plans: dict[str, tuple[float, object]] = {}

    @app.get("/api/tools/handover", dependencies=[Depends(auth)])
    async def tools_handover():
        from .tools import handover
        return {"drives": [d.to_dict() for d in await asyncio.to_thread(handover.drives, make_host())]}

    @app.post("/api/tools/handover/plan", dependencies=[Depends(auth)])
    async def tools_handover_plan(request: Request):
        """Body {"mount"}: what cleaning that drive would delete now, every file listed. Changes nothing."""
        from .tools import handover
        body = await body_of(request)
        mount = body.get("mount")
        if not isinstance(mount, str):
            return JSONResponse({"error": "Choose a drive."}, status_code=400)
        try:
            p = await asyncio.to_thread(handover.plan, make_host(), mount)
        except handover.Refused as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        now = time.time()
        for k in [k for k, (t, _) in handover_plans.items() if now - t > PLAN_TTL]:
            del handover_plans[k]
        pid = uuid.uuid4().hex
        handover_plans[pid] = (now, p)
        return {"plan_id": pid, **p.to_dict()}

    @app.post("/api/tools/handover/clean", dependencies=[Depends(auth)])
    async def tools_handover_clean(request: Request):
        """Body {"plan_id", "confirm": true}: deletes exactly what that plan listed (each file checked again)."""
        from .tools import handover
        body = await body_of(request)
        stored = handover_plans.pop(str(body.get("plan_id")), None)
        if stored is None or time.time() - stored[0] > PLAN_TTL:
            return JSONResponse({"error": "That list has expired: look at the drive again."}, status_code=400)
        if body.get("confirm") is not True:
            handover_plans[str(body.get("plan_id"))] = stored
            return JSONResponse({"error": "Confirm first that these files are deleted for good."}, status_code=400)
        try:
            done = await asyncio.to_thread(handover.clean, make_host(), stored[1])
        except handover.Refused as e:
            handover_plans[str(body.get("plan_id"))] = stored          # "Close X first": the same list can be tried again
            return JSONResponse({"error": str(e)}, status_code=409)
        return done.to_dict()

    # Retire a drive: commands only, shown once the user types the drive's name; the app erases nothing.

    @app.get("/api/tools/retire", dependencies=[Depends(auth)])
    async def tools_retire():
        from .tools import retire
        drives = await asyncio.to_thread(retire.disks, make_host())
        return {"drives": [d.to_dict() for d in drives], "facts": app.state.erase_facts, "admin_active": admin.active()}

    @app.post("/api/tools/retire/facts", dependencies=[Depends(auth)])
    async def tools_retire_facts(request: Request):
        """Body {"disk"}: what the drive says about erasing itself (identify data, through the helper)."""
        from .tools import retire
        body = await body_of(request)
        host = make_host()
        try:
            d = await asyncio.to_thread(retire.find, host, str(body.get("disk", "")))
        except retire.Refused as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        problem = await with_root(host)
        if problem:
            return JSONResponse({"error": problem.replace(" Nothing was changed.", " Nothing was read."), "declined": True},
                                status_code=403)
        try:
            facts = await asyncio.to_thread(host.privileged.call, "erase_facts", {"disk": d.name})
        except HelperError as e:
            return JSONResponse({"error": f"The helper refused: {e}"}, status_code=400)
        app.state.erase_facts[d.name] = facts
        return {"facts": facts, "admin_active": admin.active()}

    @app.post("/api/tools/retire/guide", dependencies=[Depends(auth)])
    async def tools_retire_guide(request: Request):
        """Body {"disk", "typed", "kind", "from_start"}: the steps for that drive, once `typed` is its name."""
        from .tools import retire
        body = await body_of(request)
        name = str(body.get("disk", ""))
        try:
            g = await asyncio.to_thread(retire.guide, make_host(), name, str(body.get("typed", "")),
                                        body.get("kind") if isinstance(body.get("kind"), str) else None,
                                        body.get("from_start") is True, app.state.erase_facts.get(name))
        except retire.Refused as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return {"guide": g.to_dict()}

    @app.get("/api/tools/travel", dependencies=[Depends(auth)])
    async def tools_travel():
        """Before you travel: the checklist (the page shows each check's result from the last scan)."""
        from .tools import travel
        return await asyncio.to_thread(travel.status, make_host())

    # Presentation mode: notification banners and clipboard history off together, back together.
    # Not a fix (nothing in History); its own state file holds what to put back while it is on.

    @app.get("/api/tools/presentation", dependencies=[Depends(auth)])
    async def tools_presentation():
        """On: what it changed and how to undo each by hand; off: what turning it on would change."""
        from .tools import presentation
        return await asyncio.to_thread(presentation.status, make_host())

    @app.post("/api/tools/presentation/on", dependencies=[Depends(auth)])
    async def tools_presentation_on():
        from .fix import FixError
        from .tools import presentation
        try:
            return await asyncio.to_thread(presentation.turn_on, make_host())
        except presentation.AlreadyOn as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        except FixError as e:
            return JSONResponse({"error": f"It couldn't be turned on, and nothing was left changed: {e}"},
                                status_code=400)

    @app.post("/api/tools/presentation/renew", dependencies=[Depends(auth)])
    async def tools_presentation_renew():
        """What ended by itself while it stayed on (KDE's Do Not Disturb, after the app stopped), again."""
        from .fix import FixError
        from .tools import presentation
        try:
            return await asyncio.to_thread(presentation.renew, make_host())
        except FixError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    @app.post("/api/tools/presentation/off", dependencies=[Depends(auth)])
    async def tools_presentation_off():
        from .tools import presentation
        return await asyncio.to_thread(presentation.turn_off, make_host())

    @app.post("/api/tools/ramdisk/show", dependencies=[Depends(auth)])
    async def tools_ramdisk_show():
        """Opens ~/RAMDisk in the file manager."""
        from .tools import ramdisk
        host = make_host()
        r = await asyncio.to_thread(host.run, "xdg-open", str(ramdisk.folder(host)))
        return {"ok": r.ok}

    @app.post("/api/tools/browser/show", dependencies=[Depends(auth)])
    async def tools_browser_show(request: Request):
        """Body {"browser", "which": "uploads" | "downloads"}: opens that folder of the browser's in
        the file manager (checked first: a folder of the user's, not a link the browser left)."""
        from .tools import browser as B, transfer
        body = await body_of(request)
        host = make_host()
        b = browser_of(body)
        which = body.get("which")
        if b is None or which not in ("uploads", "downloads", "outbox", "permanent") or not B.installed(host, b):
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser, once it is in ~/TempBrowser."},
                                status_code=400)
        try:
            await asyncio.to_thread(transfer.prepare, host, b.folder)
            if which == "outbox":
                folder = await asyncio.to_thread(transfer.make_outbox, host, b.name)
        except transfer.TransferError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        if which == "permanent":
            from .tools.metadata import CLEANED, outbox_dir
            folder = outbox_dir(host.home) / CLEANED
            if not folder.is_dir() or folder.is_symlink():
                folder = outbox_dir(host.home)
            if not folder.is_dir() or folder.is_symlink():
                return JSONResponse({"error": "~/Outbox isn't there."}, status_code=409)
        elif which in ("uploads", "downloads"):
            folder = (transfer.uploads_dir if which == "uploads" else transfer.downloads_dir)(host, b.folder)
        r = await asyncio.to_thread(host.run, "xdg-open", str(folder))
        return {"ok": r.ok}

    def close_browser_disk(prompt: bool = True) -> str:
        """The browser's RAM disk is for while the app runs: quitting closes it (unless the browser
        still uses it), asking for administrator access if it has to. `prompt` False (the app told to end by a
        signal: logging out, shutting down) never asks: its files are overwritten and deleted all the same, and it
        stays mounted, empty, until it is closed or the computer restarts, rather than a password prompt coming up in
        the middle of a logout. What happened is said on a terminal only: it names programs ("Tor Browser still uses
        it"), and off a terminal stderr is a log on the disk (~/.xsession-errors, the journal)."""
        from .tools import browser
        try:
            msg = browser.close_disk(make_host(), lambda: admin.get(prompt=prompt))
        except Exception as e:  # noqa: BLE001 - quitting goes on; the page shows it open next time
            msg = f"~/TempBrowser couldn't be closed: {type(e).__name__}"   # no message: it can name a path
        if msg and sys.stderr.isatty():
            print(msg, file=sys.stderr)
        return msg

    app.state.close_browser_disk = close_browser_disk

    if watch_outbox:
        from .tools import transfer as _transfer

        def watch() -> None:
            from .tools import browser
            host = make_host()
            while True:
                time.sleep(OUTBOX_EVERY)
                try:
                    browser.run_outboxes(host)
                except Exception as e:  # noqa: BLE001 - one bad file mustn't stop the watcher
                    # its kind only: the message of an error with a file names it (a path), and stderr can be a
                    # log on the disk (the journal, ~/.xsession-errors)
                    print(f"The TempOutbox couldn't be emptied: {type(e).__name__}", file=sys.stderr)
        _transfer.WATCHED["on"] = True
        threading.Thread(target=watch, name="tempoutbox", daemon=True).start()

        def clear_trials() -> None:
            """Trial folders a copy of the app that has ended left behind go at the start (a running copy's are
            locked: trial.leftovers)."""
            from .tools import trial
            app.state.trial_cleaned = True
            try:
                trial.clear_leftovers(make_host())
            except OSError as e:
                print(f"Trial folders left from before couldn't be removed: {type(e).__name__}", file=sys.stderr)
        threading.Thread(target=clear_trials, name="trial-leftovers", daemon=True).start()

    if on_quit is not None:
        @app.post("/api/quit", dependencies=[Depends(auth)])
        async def quit_app():
            from .tools import presentation
            await asyncio.to_thread(close_browser_disk)
            await asyncio.to_thread(discard_trial)                          # a trial is for while the app runs
            await asyncio.to_thread(admin.drop)
            await asyncio.to_thread(presentation.turn_off, make_host())     # it was for while the app runs
            asyncio.get_running_loop().call_later(0.3, on_quit)  # let this reply reach the page first
            return {"ok": True}

    return app
