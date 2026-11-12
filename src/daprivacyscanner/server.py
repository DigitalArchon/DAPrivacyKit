"""Local HTTP server for the GUI, bound to 127.0.0.1.

Access: the page is opened once with a launch token in the URL (?t=...), which the server
exchanges for the session token, handed to the page in its body (data-token) and then forgotten,
so the token in the browser's history is worthless a second later (in --browser mode the link reaches the
browser through a launcher file only this account can read, never a command line: app.py). The
page keeps the session token in its session storage, which belongs to this origin alone (host and
port: a cookie would go to every other local server on 127.0.0.1 the user visits in --browser mode,
whatever its port, since cookies ignore ports), and sends it with every API call in the X-Token
header, which a cross-site page can't add without a CORS preflight the server doesn't answer.
Every connection whose program isn't this account's is refused (`same_user`, peer.py: any account can connect to
127.0.0.1), and so are requests whose Host header isn't this server's address (DNS rebinding). Every answer but the
page's shell (/ and /static) needs the token, checked for every route at once (`guard`), and every answer says it
is for this origin alone (Cross-Origin-Resource-Policy) with the page's Content-Security-Policy, so a website can't
load the app's files to tell it is running, nor frame it."""

from __future__ import annotations

import asyncio
import contextlib
import copy
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
from .jobs import Job, Jobs, Quitting, in_thread
from .jobs import view as job_view
from .paths import PathResolver
from .privileged import (HelperDeclined, HelperError, HelperNotInstalled, HelperUnavailable, PkexecHelper, Privileged,
                         installed_helper, installed_helper_stale)
from .privileged import install_helper as install_helper_root
from .runner import Runner
from .undo import UndoLog

PLAN_TTL = 15 * 60
ADMIN_IDLE = 5 * 60              # administrator access ends after this long unused
OUTBOX_EVERY = 2.0               # seconds between looks into the browsers' TempOutboxes
KEEPS_EVERY = 2.0                # seconds between looks at a watched app (What does this app keep?)
KEEPS_MISSES = 3                 # polls in a row the watch may leave unanswered (busy under a heavy load) before it ends
KEEPS_LEFT = 180.0               # seconds a watch goes on once its app has closed, or its panel was closed, then it ends
QUIT_WAIT = 10.0                 # seconds quitting waits for the jobs it told to stop
CHANGES_WAIT = 120.0             # and for a fix, a revert or a set-up under way (never cut short half-way)
SHORT_WORKERS = 16               # threads for requests' short work (asyncio.to_thread); long work has its own

# the page's own policy (index.html has it as a <meta> too), as a header on every answer, with what a <meta> can't say:
# no other site may frame it
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    # a website can't load the app's page, script or icon as its own resource (to tell it runs, and which version)
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}
OTHER_ACCOUNT = "This server answers only programs of the account that started DA Privacy Kit."


class JSONResponse(_JSONResponse):
    """JSON with everything beyond ASCII escaped. A file name that isn't UTF-8 (allowed on Linux: an old archive,
    a Windows drive) reaches Python as a lone surrogate (U+DCFF for the byte 0xff), which UTF-8 can't encode:
    escaped, it goes to the page (shown as a replacement character) and comes back as the same surrogate, so the
    path still names the file."""

    def render(self, content) -> bytes:
        import json
        return json.dumps(content, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


class TextResponse(PlainTextResponse):
    """A report as text. A file name that isn't UTF-8 is in it as the bytes it has on the disk: as a lone surrogate
    (above) it can't be encoded, and Export… as Text failed with an error. The page shows it as a replacement
    character, as it does a name in JSON."""

    def render(self, content) -> bytes:
        return content.encode(self.charset, "surrogateescape")


WEB_DIR = Path(__file__).resolve().parent / "web"


def default_open_url(url: str) -> None:
    """xdg-open, detached, with the host's environment (not the AppImage's)."""
    from .hostenv import host_env
    subprocess.Popen(["xdg-open", url], env=host_env(None), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)


def _busy(helper) -> bool:
    """Whether the helper has a request in hand (one that can't say is taken as idle)."""
    return bool(getattr(helper, "busy", lambda: False)())


KEEPALIVE_EVERY = 60.0           # seconds between the helper's keep-alives while long work holds the access
# the helper's requests a tool's Stop (or closing its panel) cancels while one is in hand
TRIM_REQUESTS = frozenset({"trim_scan", "trim_fstrim"})
NAMES_REQUESTS = frozenset({"names_step", "names_result", "names_orphans", "names_check", "names_folder",
                            "names_fstrim"})
ADMIN_TICK = 5.0                 # seconds between the session timer's looks


class AdminSession:
    """Administrator access, once granted: the helper keeps running so one polkit prompt covers
    a scan and the fixes that follow. It ends when the user drops it, quits, after ADMIN_IDLE
    seconds unused (a timer of its own looks every ADMIN_TICK: the access ended only when the page asked before,
    and stayed while it was idle), or right after a scan that found nothing a root fix could act on. While work
    holds it (hold()), the timer keeps the helper from ending itself for being idle (it ends after HELPER_IDLE without
    a request), and never closes it under a request in hand."""

    def __init__(self, start: Callable[[], Privileged], idle: float = ADMIN_IDLE, tick: float = ADMIN_TICK,
                 keepalive: float = KEEPALIVE_EVERY):
        self.start, self.idle, self.tick, self.keepalive_every = start, idle, tick, keepalive
        self.helper: Privileged | None = None
        self.last_used = 0.0
        self.last_ping = 0.0
        self.holds = 0                   # long work using it (the TRIM test): no idle end, no drop after a scan
        self.claims = 0                  # each request that asked for access (get with prompt): a scan's drop checks it
        self.lock = threading.Lock()
        self.changed = threading.Condition(self.lock)
        # a request is asking for access (the prompt is up): the lock isn't held meanwhile, so active() and drop(),
        # called from the page's polling, answer at once instead of holding the server up for as long as the
        # prompt stands (it did: up to five minutes, with the event loop stuck behind it)
        self.starting = False
        self.failure: Exception | None = None       # why the attempt failed, for the requests that waited on it
        self._timer: threading.Thread | None = None
        self._wake = threading.Event()

    def active(self) -> bool:
        with self.lock:
            self._expire()
            return self.helper is not None

    def _expire(self) -> None:
        if self.helper is not None and (not self.helper.alive() or (
                not self.holds and not _busy(self.helper) and time.monotonic() - self.last_used > self.idle)):
            # closed in a thread of its own: close() waits up to 5 s for a helper still answering a request, and this
            # runs on the event loop (active(), from the page's polling), which was held up for as long
            helper, self.helper = self.helper, None
            threading.Thread(target=helper.close, name="helper-close", daemon=True).start()

    def _start_timer(self) -> None:
        """Under the lock: the timer, while there is a helper."""
        if self._timer is None or not self._timer.is_alive():
            self._wake.clear()
            self._timer = threading.Thread(target=self._run_timer, name="admin-timer", daemon=True)
            self._timer.start()

    def _run_timer(self) -> None:
        while True:
            if self._wake.wait(self.tick):              # a tick, then a look (drop() wakes it at once)
                self._wake.clear()
            with self.lock:
                self._expire()
                helper, held = self.helper, self.holds > 0
                if helper is None:
                    self._timer = None
                    return
                ping = held and time.monotonic() - self.last_ping >= self.keepalive_every
                if ping:
                    self.last_ping = time.monotonic()
            if ping:
                getattr(helper, "keepalive", lambda: None)()   # outside the lock: it waits for the helper's answer

    def get(self, prompt: bool) -> Privileged | None:
        """The running helper; with `prompt`, asks for administrator access if there is none
        (blocks until the user answers; raises HelperUnavailable / HelperDeclined). One prompt serves
        every request that asks while it is up: the others wait for its answer, and share a refusal."""
        with self.lock:
            self._expire()
            if prompt:
                self.claims += 1                # someone is about to use it: a scan finishing now leaves it
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
            self._start_timer()
        return self.helper

    def drop(self) -> None:
        with self.lock:
            helper, self.helper = self.helper, None
        self._wake.set()
        if helper is not None:
            helper.close()          # with the lock released: active(), on the event loop, waited for it otherwise

    def claimed(self) -> int:
        """How many requests have asked for access so far (drop_unless_claimed's mark)."""
        with self.lock:
            return self.claims

    def drop_unless_claimed(self, mark: int) -> bool:
        """The access dropped, as drop() does, unless something has asked for it since `mark` (claimed()), work holds
        it, or a request is in hand: a scan that found nothing to fix as root closed the helper under the TRIM test,
        which had asked for it and was about to hold it. Whether it was dropped."""
        with self.lock:
            helper = self.helper
            if helper is None or self.claims != mark or self.holds or _busy(helper):
                return False
            self.helper = None
        self._wake.set()
        helper.close()
        return True

    def cancel(self, actions) -> bool:
        """Stops the helper's request in hand if it is one of `actions` (the user stopped it, or closed its panel)."""
        with self.lock:
            helper = self.helper
        return bool(getattr(helper, "cancel", lambda a: False)(actions)) if helper is not None else False

    def held(self) -> bool:
        with self.lock:
            return self.holds > 0

    @contextlib.contextmanager
    def hold(self):
        """While long work uses the access: it doesn't end when idle, and a scan doesn't drop it; the helper gets a
        keep-alive every KEEPALIVE_EVERY seconds. The user's Drop still ends it (the work then stops)."""
        with self.lock:
            self.holds += 1
            self.last_ping = time.monotonic()
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
               spawn_app: Callable = subprocess.Popen, close_window: Callable[[], None] | None = None,
               same_user: Callable[[tuple | None, tuple | None], bool] | None = None,
               on_launched: Callable[[], None] | None = None) -> FastAPI:
    """`token` is the session token (the X-Token header of every API call; the page gets it when the
    launch token is exchanged). `launch_token`, if given, is accepted once on GET /?t=..., and `on_launched` called
    then (app.py removes the launcher file that carried it). `allowed_hosts`: the Host
    header values served (None: any, for tests). `same_user(client, server)`: whether the program on the other end of
    a connection is this account's (peer.same_user; None: not asked, for tests, whose client isn't a socket); every
    connection that isn't is refused, the page's shell included. `on_quit` ends the process (POST /api/quit): in
    the browser, closing the tab doesn't. `close_window` closes the app's window, which quits it (POST /api/quit in
    the window: the page's Quit anyway, once it has asked, app.CloseGuard). `start_helper` asks for administrator
    access (polkit) and returns the privileged helper. `make_net` gives the network to the online tests and to the
    browser download the user starts in the Tools panel; a scan never calls it (rule 10). `dev` shows detection hints, unverified notes and timings.
    `install_helper` installs this version's helper root-owned (or removes it), asking for access.
    `pick` is the app window's file dialog (in the browser, zenity or kdialog are used when installed).
    `open_tool` ({"tool", "paths"}, from --tool) opens the page on a tool, once. `spawn_browser`
    starts the browser from the RAM disk (subprocess.Popen; a fake in tests). `open_url` opens one of
    about.LINKS in the user's default browser (xdg-open, detached; a fake in tests). `watch_outbox` starts
    the watcher that empties the browsers' TempOutboxes into their To upload while the app runs, and removes trial
    folders an ended copy of the app left (both off in tests, which call them themselves). `spawn_app` starts an app for "What does this app keep?" and "Try an app"
    (subprocess.Popen; a fake in tests).

    Quitting goes through `app.state.shutdown()` (POST /api/quit in --browser mode, app.main as the window closes or
    a signal ends the session): every job told to stop, then what quitting closes."""
    @contextlib.asynccontextmanager
    async def lifespan(_app):
        # the short work requests hand to a thread (reads, a scan, a plan): a pool of its own size, not the default's
        # few threads on a small machine (os.cpu_count() + 4); what blocks for long has a thread of its own (in_thread)
        from concurrent.futures import ThreadPoolExecutor
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(SHORT_WORKERS, thread_name_prefix="api"))
        yield

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, default_response_class=JSONResponse,
                  lifespan=lifespan)
    app.state.report = None
    app.state.restored = False             # whether the saved last report was looked for
    # the jobs the page follows, one of each kind (jobs.KINDS), as app.state.<kind>_job: the online tests; the TRIM
    # test; the names of the user's deleted files, handed to the page once, and cleaning the folders they are in
    # (ext4); Remove metadata, reading or cleaning files and folders; Tor or Mullvad Browser into the RAM disk
    # (download, verify, unpack); What does this app keep?, the watch, then its result (memory only)
    jobs = app.state.jobs = Jobs(app.state)
    app.state.names_listed = None          # (mount, the folders the last listing showed): what may be cleaned
    app.state.trim_cleaned = False         # leftovers of an unfinished TRIM test were looked for
    app.state.erase_facts = {}             # Retire a drive: what each drive said about erasing, this session only
    app.state.trial = None                 # Try an app: the one trial, its sandbox and its report (memory only)
    app.state.trial_cleaned = False        # trial folders left by a run of the app that was killed were looked for
    app.state.left_open = None             # why the last quit left ~/TempBrowser open, for the panel (memory only)
    scan_lock = asyncio.Lock()
    plans: dict[str, tuple[FixPlan, Host]] = {}
    easy_ids: set[str] = set()             # plans built by Easy fixes: the only ones it applies
    admin = app.state.admin = AdminSession(start_helper)
    launch = {"token": launch_token}
    pending_tool = {"value": open_tool}
    # changes under way (a fix, a revert, a set-up): quitting waits for them, never cutting one short half-way
    in_flight = threading.Condition()
    changes = {"n": 0}

    @contextlib.contextmanager
    def changing():
        with in_flight:
            changes["n"] += 1
        try:
            yield
        finally:
            with in_flight:
                changes["n"] -= 1
                in_flight.notify_all()

    def token_ok(request: Request) -> bool:
        # compare_digest refuses text beyond ASCII (a TypeError, which would be a 500): such a header is just wrong
        t = request.headers.get("x-token")
        return t is not None and t.isascii() and hmac.compare_digest(t, token)

    def shell_route(request: Request) -> bool:
        """The page's shell, served without the token: the page itself (where the launch token is exchanged) and its
        script, style and icon. Everything else needs it, whatever the route says (a forgotten Depends(auth) left one
        open otherwise)."""
        path = request.url.path
        return request.method in ("GET", "HEAD") and (path == "/" or path.startswith("/static/"))

    def secured(response):
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if same_user is not None and not same_user(request.scope.get("client"), request.scope.get("server")):
            return secured(PlainTextResponse(OTHER_ACCOUNT, status_code=403))
        if allowed_hosts is not None and request.headers.get("host", "").lower() not in allowed_hosts:
            return secured(PlainTextResponse("This server only answers its own address.", status_code=421))
        if not shell_route(request) and not token_ok(request):
            return secured(JSONResponse({"detail": "bad token"}, status_code=403))
        if jobs.quitting and request.method == "POST" and path != "/api/quit":
            return secured(quitting())
        try:
            response = await call_next(request)
        except Exception as e:  # noqa: BLE001 - see below
            # an error nothing caught: the page gets its kind; stderr (the journal, or ~/.xsession-errors, for an app
            # started from the menu) only its kind and the route, never a traceback, whose values and messages can
            # hold a file's path or name
            print(f"{request.method} {request.url.path}: {type(e).__name__}", file=sys.stderr)
            response = JSONResponse({"error": f"The app hit an error it didn't expect ({type(e).__name__})."},
                                    status_code=500)
        if path.startswith("/api/"):
            # what the API answers (downloads' names, a photo's metadata, deleted files' names) is never cached: in
            # --browser mode the user's browser kept a JSON answer in its disk cache otherwise (tested with Firefox)
            response.headers["Cache-Control"] = "no-store"
            # whether administrator access is held now, with every answer: the page's badge follows it, also when
            # it ended by itself (idle, the helper gone), which the page never learnt of before
            response.headers["X-Admin-Active"] = "1" if admin.active() else "0"
        return secured(response)

    def host_now() -> Host:
        """A host for this request, with administrator access if it is active (never prompts)."""
        host = make_host()
        host.privileged = admin.get(prompt=False)
        return host

    async def with_root(host: Host) -> str | None:
        """Gives the host administrator access, asking for it if needed (the prompt on a thread of its own: it can
        stand for minutes). Returns why not, or None. Without the helper installed (or with one from another version)
        nothing can ask: the answer says to install it, and the page offers that."""
        try:
            host.privileged = await in_thread(admin.get, True, name="admin-prompt")
        except HelperDeclined:
            return "Administrator access was declined, so nothing was changed."
        except HelperNotInstalled as e:
            return f"{e} Nothing was changed."
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

    def reconcile(host: Host, log: UndoLog) -> int:
        """History brought into line with the administrator helper's record of this user's changes, when the host has
        administrator access (UndoLog.reconcile): a step whose answer never came settled, and a change no entry knows
        of taken up. Quietly nothing with an older helper, or when it can't be asked."""
        if host.privileged is None:
            return 0
        try:
            return log.reconcile(host.privileged)
        except OSError:
            return 0

    def busy() -> JSONResponse:
        return JSONResponse({"error": "A scan or fix is already running."}, status_code=409)

    def quitting() -> JSONResponse:
        return JSONResponse({"error": "DA Privacy Kit is quitting."}, status_code=503)

    # The report is changed only on the event loop, and work on a thread gets a copy of it: a thread saving or
    # exporting it while the loop merged an online test's result into it could stop with "dictionary changed size
    # during iteration".

    def report_copy() -> dict | None:
        return copy.deepcopy(app.state.report)

    async def persist(host: Host) -> None:
        """Keeps the report as it is now for the next start (after a scan, a fix, a revert or the
        online tests)."""
        snap = report_copy()
        if snap is not None:
            await asyncio.to_thread(LastReport(paths_of(host)).save, snap)

    async def recheck_undone(host: Host) -> list:
        """Fixes the user applied that have been undone since (UndoLog.undone), against the report as
        it is now: after a scan, a fix, a revert, accepting a finding or forgetting history."""
        report = app.state.report
        if report is None:
            return []
        results = copy.deepcopy(report["results"])
        undone = await asyncio.to_thread(
            lambda: undo_log(host).undone(results, Accepted(paths_of(host)).all(), host))
        report["undone"] = undone
        return undone

    async def restore(host: Host) -> None:
        """The saved last report, once, when there is no report yet."""
        if app.state.report is None and not app.state.restored:
            app.state.restored = True
            loaded = await asyncio.to_thread(LastReport(paths_of(host)).load, set(catalogue.checks))
            if app.state.report is None:
                app.state.report = loaded

    async def refresh(host: Host, check_id: str, also: tuple[str, ...] = ()) -> dict:
        """After a fix or revert: the context again, this check (and `also`), and every check whose
        severity depends on a context key that changed (a fix can change the context, e.g. autologin).
        Works the same on a report restored from the last run. The report is updated in place, on the loop.
        Returns {"result": this check, "rechecked": {id: result}, "context": the new context}."""
        old = app.state.report
        context = copy.deepcopy(old["context"]) if old else None

        def rescan():
            rep = Runner(catalogue, host).rescan([check_id, *also], context)
            return rep, rep.to_dict()
        rep, d = await asyncio.to_thread(rescan)
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
        if not token_ok(request):                 # the guard has refused it already; kept on each route all the same
            raise HTTPException(403, "bad token")

    @app.get("/")
    async def index(request: Request):
        t = request.query_params.get("t")
        if t is not None:
            # the launch token: one exchange for the session token, handed to the page in its body (it keeps it in
            # its session storage, this origin's own), then it is forgotten
            if launch["token"] is not None and t.isascii() and hmac.compare_digest(t, launch["token"]):
                launch["token"] = None
                if on_launched is not None:             # the launcher file that carried it has done its work
                    try:
                        on_launched()
                    except OSError:
                        pass
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
        await restore(host)
        await asyncio.to_thread(undo_log(host).expire_backups)     # backups kept only for a while (known_hosts')
        if not app.state.trim_cleaned and not trim_running():
            from .tools import trimtest
            app.state.trim_cleaned = True
            await asyncio.to_thread(trimtest.leftovers, host)      # a test the app didn't finish (closed, crashed)

        def gather() -> dict:                      # files read, the helper's checked: off the event loop
            acc = Accepted(paths_of(host))
            return {"helper_installed": installed_helper() is not None, "helper_stale": installed_helper_stale(),
                    "accepted": acc.all(), "accepted_damaged": acc.damaged(host.display),   # said, never an empty list alone
                    "last_scan": (Baseline(paths_of(host)).load() or {}).get("taken"),
                    "presentation": presentation_on(host),
                    "welcome": {"show": about.welcome_shown(paths_of(host).config_home), "links": about.LINKS}}
        read = await asyncio.to_thread(gather)
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
            "dev": dev,
            "reads": about.READS, "never": about.NEVER,
            "open_tool": pending_tool.pop("value", None),
            **read,
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
        if online_admin():
            return JSONResponse({"error": "The online tests are using administrator access: installing the helper "
                                          "would stop them. Try again once they have finished."}, status_code=409)
        async with scan_lock:
            await asyncio.to_thread(admin.drop)
            try:
                with changing():
                    r = await in_thread(install_helper, bool(body.get("uninstall")), name="helper-install")
            except (HelperUnavailable, HelperError) as e:
                return JSONResponse({"error": str(e), "declined": isinstance(e, HelperDeclined)}, status_code=403)
        there = await asyncio.to_thread(lambda: (installed_helper() is not None, installed_helper_stale()))
        return {"ok": True, **r, "helper_installed": there[0], "helper_stale": there[1]}

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
                    host.privileged = await in_thread(admin.get, True, name="admin-prompt")
                    granted["granted"] = True
                except HelperUnavailable as e:
                    granted["message"] = str(e)
                    granted["install_helper"] = isinstance(e, HelperNotInstalled)
            else:
                host.privileged = await asyncio.to_thread(admin.get, False)
            mark = admin.claimed()                    # anything asking for the access after this keeps it
            with admin.hold() if host.privileged is not None else contextlib.nullcontext():
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
            await recheck_undone(host)
            await persist(host)
            if host.privileged is not None and not any(needs_root_to_fix(catalogue, dict(r, id=cid))
                                                       for cid, r in new["results"].items()):
                # nothing to fix as root: don't keep root around, unless something asked for it meanwhile (a tool
                # between its with_root and its hold) or holds it
                granted["dropped"] = await asyncio.to_thread(admin.drop_unless_claimed, mark)
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
        try:
            data = await asyncio.to_thread(Accepted(paths_of(host)).set, cid, bool(body.get("accept")),
                                           str(body.get("note") or ""), result.get("effective_severity"),
                                           result.get("severity_reason", ""))
        except OSError as e:                    # there but unreadable (its permissions): never written over
            return JSONResponse({"error": f"The list of findings you accepted couldn't be changed: {e.strerror or e}."},
                                status_code=400)
        undone = await recheck_undone(host)
        await persist(host)
        return {"accepted": data, "undone": undone}

    async def export_text(host: Host, what: str, fmt: str, redact: bool) -> str:
        report = report_copy()                  # a copy, taken on the loop: the thread reads it while the loop goes on

        def build() -> str:
            if what == "everything":
                return report_mod.export_all(report, catalogue, undo_log(host).entries(),
                                             Accepted(paths_of(host)).all(), fmt, host, redact)
            return report_mod.export(report, catalogue, fmt, host, redact, Accepted(paths_of(host)).all())
        return await asyncio.to_thread(build)

    @app.get("/api/report", dependencies=[Depends(auth)])
    async def export_report(request: Request):
        """The last report as text or JSON (?format=text|json), redacted with ?redact=1."""
        if app.state.report is None:
            return JSONResponse({"error": "Scan first."}, status_code=400)
        fmt = request.query_params.get("format", "text")
        redact = request.query_params.get("redact") in ("1", "true", "yes")
        text = await export_text(make_host(), "report", fmt, redact)
        return TextResponse(text, media_type="application/json" if fmt == "json" else "text/plain; charset=utf-8")

    @app.get("/api/export", dependencies=[Depends(auth)])
    async def export_everything(request: Request):
        """Everything the app keeps, for the user's backups: the last report (if there is one),
        accepted findings and every change in History with how to undo it by hand
        (?format=text|json, ?redact=1)."""
        fmt = request.query_params.get("format", "text")
        redact = request.query_params.get("redact") in ("1", "true", "yes")
        text = await export_text(make_host(), "everything", fmt, redact)
        return TextResponse(text, media_type="application/json" if fmt == "json" else "text/plain; charset=utf-8")

    @app.post("/api/export/save", dependencies=[Depends(auth)])
    async def export_save(request: Request):
        """Body {"what": "report"|"everything", "format": "text"|"json", "redact", "folder"?}: what GET /api/report or
        /api/export answers, saved by the app into a folder the user chooses (the file chooser in folder mode, or
        "folder": a path the page asked for when there is none, {"unavailable": true}), as a file of its own readable by
        the user alone (report.save). A download the window's WebKitGTK writes itself has the umask's mode: 0664 on
        Mint and Ubuntu, readable by every account. {"saved": the path as shown, "private": whether only the user can
        read it}, or {"cancelled": true}."""
        from .tools.pick import PathRefused, checked, dialog, downloads, resolved
        body = await body_of(request)
        what, fmt = body.get("what"), body.get("format", "text")
        if what not in ("report", "everything") or fmt not in ("text", "json"):
            return JSONResponse({"error": "Export what, and as text or JSON?"}, status_code=400)
        if what == "report" and app.state.report is None:
            return JSONResponse({"error": "Scan first."}, status_code=400)
        host = make_host()
        folder = body.get("folder")
        if folder is None:
            chooser = pick or dialog(host)
            if chooser is None:
                return {"unavailable": True}
            chosen = await in_thread(chooser, "folder", False, str(downloads(host)), name="file-chooser")
            if not chosen:
                return {"cancelled": True}
            folder = chosen[0]
        try:
            dest = checked(folder, host.home, folders=True)
            real = resolved(dest, host.home)
            if not real.is_dir():
                raise PathRefused(f"{host.display(dest)} isn't a folder.")
        except PathRefused as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        text = await export_text(host, what, fmt, bool(body.get("redact")))
        try:
            name, mode = await asyncio.to_thread(report_mod.save, real, report_mod.file_name(what, fmt), text)
        except OSError as e:
            return JSONResponse({"error": f"It couldn't be saved in {host.display(dest)}: {e.strerror or e}."},
                                status_code=400)
        return {"saved": host.display(dest / name), "private": not mode & 0o077}

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
        settings, error = await asyncio.to_thread(online_settings, host)
        impl = online_checks()
        vpn = bool(await asyncio.to_thread(carrying_vpn_links, host))
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

    def online_admin() -> bool:
        """Online tests running with administrator access, or still taking it up."""
        job = app.state.online_job
        return job is not None and (job["state"] in ("starting", "asking")
                                    or job["state"] == "running" and job["privileged"])

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
                res["notes"] = res["notes"] + [n for n in notes if n["title"] not in titles]

    async def run_online_job(job: dict, settings: dict, want_admin: bool) -> None:
        loop = asyncio.get_running_loop()
        host = make_host()
        try:
            host = await asyncio.to_thread(host_now)
            if want_admin and host.privileged is None:
                job["state"] = "asking"
                problem = await with_root(host)
                job["admin_message"] = (problem or "").replace(" Nothing was changed.", "")
            if job["cancel"]:                              # told to stop while access was asked for (quitting)
                job["state"] = "stopped"
                return
            job["privileged"] = host.privileged is not None
            job["state"], job["started"] = "running", time.time()

            def progress(cid: str, done: int, total: int) -> None:
                job["current"] = {"id": cid, "title": catalogue[cid].title, "started": time.time()}

            def on_result(cid, result, states, extra) -> None:
                d = result.to_dict()
                notes = {k: [n.to_dict() for n in v] for k, v in extra.items()}
                try:
                    loop.call_soon_threadsafe(merge_online, job, cid, d, states, notes)
                except RuntimeError:                       # the loop has closed: the app has quit
                    pass

            runner = Runner(catalogue, host, net=make_net(), online=settings)
            # administrator access is held while the tests use it: the traffic watch's requests go to the helper given
            # here, never through get(), so the idle end, a scan finding nothing to fix as root or a watch of an app
            # ending closed it in the middle of the watch, and the watch was lost
            with admin.hold() if host.privileged is not None else contextlib.nullcontext():
                await in_thread(runner.scan_online, job["ids"], progress, lambda: job["cancel"], on_result,
                                name="online-tests")
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
                await persist(host)

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
        settings, error = await asyncio.to_thread(online_settings, make_host())
        if error:
            return JSONResponse({"error": error}, status_code=400)
        secs = body.get("observe_seconds")
        if isinstance(secs, int) and not isinstance(secs, bool) and 5 <= secs <= 300:
            settings["observe_seconds"] = secs
        job = Job("online", "starting", ids=ids, total=len(ids), done=0, titles={i: catalogue[i].title for i in ids},
                  current=None, created=time.time(), started=None, finished=None,
                  observe_seconds=settings["observe_seconds"], results={}, admin_message="", error="",
                  privileged=False, abort=False, winding_down=True, cancelled=None)
        try:
            jobs.start(job, lambda j: run_online_job(j, settings, bool(body.get("admin"))))
        except Quitting:
            return quitting()
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
                admin.cancel({"observe_traffic"})        # the traffic watch, up to minutes long, ends now too
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
            stored = copy.deepcopy(app.state.report["results"].get(check_id)) \
                if online and app.state.report is not None else None
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
            # the access as it is now, never the one the plan was made with: that helper may have ended since (the
            # rescan below used a dead one), or access been given since
            host.privileged = admin.get(prompt=False)
            if plan.needs_root:
                problem = await with_root(host)
                if problem:
                    plans[plan.id] = stored
                    return JSONResponse({"error": problem, "declined": True}, status_code=403)
            log = undo_log(host)
            with changing(), (admin.hold() if host.privileged is not None else contextlib.nullcontext()):
                await asyncio.to_thread(reconcile, host, log)
                res = await asyncio.to_thread(apply_plan, plan, host, log, bool(body.get("confirm_irreversible")))
                if res.blocked:
                    # a program the plan needs closed was started since it was shown: nothing was changed, and the
                    # same plan can be applied once it is closed
                    plans[plan.id] = stored
                    return JSONResponse({"error": res.error, "blocked": True}, status_code=409)
                # with the checks the plan deals with too (br.start_script's makes br.shader_cache's fix possible), as a
                # revert and the Easy fixes do
                again = await refresh(host, plan.check_id, tuple(plan.also))
                if res.ok and res.entry_id:           # what the check said right after: undone later if it comes back
                    await asyncio.to_thread(log.set_outcome, res.entry_id, again.get("result"))
            undone = await recheck_undone(host)
            await persist(host)
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
            host.privileged = admin.get(prompt=False)       # the access as it is now, not as it was at the dry run
            declined = await with_root(host) if any(p.needs_root for p in todo) else None
            log, out = undo_log(host), []
            with changing(), (admin.hold() if host.privileged is not None else contextlib.nullcontext()):
                await asyncio.to_thread(reconcile, host, log)
                for plan in todo:
                    if plan.needs_root and declined:
                        out.append({"check_id": plan.check_id, "title": plan.title, "ok": False, "error": declined,
                                    "declined": True})
                        continue
                    if jobs.quitting:                 # the rest isn't started: each plan is its own, whole
                        out.append({"check_id": plan.check_id, "title": plan.title, "ok": False,
                                    "error": "Not applied: DA Privacy Kit is quitting."})
                        continue
                    res = await asyncio.to_thread(apply_plan, plan, host, log, bool(body.get("confirm_irreversible")))
                    out.append({"check_id": plan.check_id, "title": plan.title, "ok": res.ok, "error": res.error,
                                "entry_id": res.entry_id, "rolled_back": res.rolled_back})
                # with the checks a plan also deals with (a change two checks share, applied once as the first one's)
                checked = list(dict.fromkeys(cid for p in todo for cid in (p.check_id, *p.also)))
                again = await refresh(host, checked[0], tuple(checked[1:]))
                for r in out:                         # what the check said right after: undone later if it comes back
                    if r.get("entry_id") and r["ok"]:
                        await asyncio.to_thread(log.set_outcome, r["entry_id"], again["rechecked"].get(r["check_id"]))
            for r in out:                             # each History entry as made: what every step did, exactly
                r["entry"] = await asyncio.to_thread(lambda: UndoLog.summary(log.get(r["entry_id"]), host)) \
                    if r.get("entry_id") else None
            undone = await recheck_undone(host)
            await persist(host)
        return {"ok": all(r["ok"] for r in out), "results": out, "rechecked": again["rechecked"],
                "context": again["context"], "undone": undone, "admin_active": admin.active()}

    # ------------------------------------------------------------ history

    @app.get("/api/undo", dependencies=[Depends(auth)])
    async def undo_entries():
        host = host_now()
        log = undo_log(host)
        await asyncio.to_thread(log.expire_backups)
        # with administrator access, and nothing else using the helper now (a fix, a scan, long work): what the helper
        # recorded and History doesn't know, or didn't hear back about, is settled first
        if host.privileged is not None and not scan_lock.locked() and not admin.held():
            await asyncio.to_thread(reconcile, host, log)
        entries = await asyncio.to_thread(lambda: [UndoLog.summary(e, host) for e in reversed(log.entries())])
        # a log that couldn't be read is said, never shown as an empty History
        return {"entries": entries, "damaged": await asyncio.to_thread(log.damaged, host)}

    @app.post("/api/undo/{entry_id}/drop-backup", dependencies=[Depends(auth)])
    async def drop_backup(entry_id: str):
        """Deletes an entry's backups that were kept only for a while (known_hosts' plain copy) now, rather than
        when they expire: the step can then no longer be reverted."""
        host = host_now()
        log = undo_log(host)
        if await asyncio.to_thread(log.get, entry_id) is None:
            return JSONResponse({"error": "No such fix in the history."}, status_code=404)
        gone = await asyncio.to_thread(log.drop_backups, entry_id)
        return {"dropped": gone, "entry": await asyncio.to_thread(lambda: UndoLog.summary(log.get(entry_id), host))}

    def later_first(log: UndoLog, entry: dict) -> list[dict]:
        """The entries to revert, in order, to revert this one after every later entry that changed the same settings
        or files (and those that changed theirs again): newest first, this one last."""
        order = {e["id"]: i for i, e in enumerate(log.entries())}
        chain, todo = {entry["id"]: entry}, [entry]
        while todo:
            for b in log.blocking(todo.pop()):
                if b["id"] not in chain and (e := log.get(b["id"])) is not None:
                    chain[b["id"]] = e
                    todo.append(e)
        return sorted(chain.values(), key=lambda e: -order.get(e["id"], -1))

    @app.post("/api/undo/{entry_id}/revert", dependencies=[Depends(auth)])
    async def revert(entry_id: str, request: Request):
        """Body {"force", "later_first"}. Reverting is refused while a later entry that changed the same settings or
        files stands (its answer's `blocked_by`); with `later_first` those are reverted first, newest first, then this
        one, stopping at the first that doesn't go back fully. A step changed since is a conflict, and the answer's
        `force_does` says what reverting it anyway (`force`) would do."""
        body = await body_of(request)
        if scan_lock.locked():
            return busy()
        async with scan_lock:
            host = await asyncio.to_thread(host_now)
            log = undo_log(host)
            entry = await asyncio.to_thread(log.get, entry_id)
            if entry is None:
                return JSONResponse({"error": "No such fix in the history."}, status_code=404)
            chain = await asyncio.to_thread(later_first, log, entry) if body.get("later_first") else [entry]
            if any(UndoLog.needs_root(e) for e in chain):
                problem = await with_root(host)
                if problem:
                    return JSONResponse({"error": problem.replace("changed", "reverted"), "declined": True},
                                        status_code=403)
            with changing(), (admin.hold() if host.privileged is not None else contextlib.nullcontext()):
                await asyncio.to_thread(reconcile, host, log)
                results = []
                for e in chain:
                    fresh = log.get(e["id"])
                    if fresh is None:
                        continue
                    done = await asyncio.to_thread(revert_entry, fresh, host, log,
                                                   bool(body.get("force")) and fresh["id"] == entry_id)
                    results += done
                    if not all(r.ok for r in done):
                        break                       # a later one that didn't go back stops the rest: said
                checks = tuple(dict.fromkeys(c for e in chain for c in (e["check_id"], *(e.get("also") or ())) if c))
                again = await refresh(host, checks[0], checks[1:]) if checks else {}
            undone = await recheck_undone(host)
            await persist(host)
            summary = await asyncio.to_thread(lambda: UndoLog.summary(log.get(entry_id), host))
            reverted = [e["id"] for e in chain if (x := log.get(e["id"])) and x["state"] == "reverted"]
        return {"ok": all(r.ok for r in results), "conflict": any(r.conflict for r in results),
                "messages": [r.message for r in results],
                "force_does": list(dict.fromkeys(r.force_does for r in results if r.conflict and r.force_does)),
                "blocked_by": [b for r in results for b in r.blocked_by],
                "reverted": reverted, "entry": summary, "undone": undone, **again}

    @app.post("/api/undo/forget", dependencies=[Depends(auth)])
    async def forget(request: Request):
        """Body {"everything": bool}. Without it: reverted entries, failed ones with nothing left to revert,
        and applied ones older than 90 days, go (with their file backups). Changes made stay as they are. With
        everything, the saved last scan goes too (the page keeps showing it until a new one). Not while a fix is
        applied or reverted here (its backups are being written); one applied by another copy of the app is kept
        (UndoLog.forget)."""
        body = await body_of(request)
        if scan_lock.locked():
            return busy()
        async with scan_lock:
            host = make_host()
            log = undo_log(host)
            everything = bool(body.get("everything"))
            with changing():
                gone = await asyncio.to_thread(log.forget, everything)
                if everything:
                    await asyncio.to_thread(forget_scans, paths_of(host))
        undone = await recheck_undone(host)
        # with the host, as GET /api/undo: History draws the entries left from this answer, Wi-Fi connections by name
        entries = await asyncio.to_thread(lambda: [UndoLog.summary(e, host) for e in reversed(log.entries())])
        return {"forgotten": gone, "entries": entries, "undone": undone,
                "damaged": await asyncio.to_thread(log.damaged, host)}

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
                # with what opening and closing it run as root, which its card shows before either
                "ramdisk": {**st.to_dict(host.home), "max_mb": ramdisk.max_mb(host), "default_mb": ramdisk.DEFAULT_MB,
                            "commands": ramdisk.commands(host)},
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
        paths = await in_thread(chooser, kind, bool(body.get("multiple")) and kind == "open", str(downloads(host)),
                                name="file-chooser")
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
        return jobs.running("meta")

    meta_view = job_view

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
            job["result"] = await in_thread(work, name="metadata")
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
        job = Job("meta", "running", kind=kind, phase="Finding the files", done=0, total=0, current="", selection=None,
                  result=None, error="", lightweight=bool(body.get("lightweight")), paths=[str(r) for r in roots],
                  hidden=body.get("hidden") is True)
        try:
            jobs.start(job, lambda j: run_meta_job(j, roots, body.get("hidden") is True, only,
                                                   bool(body.get("lightweight"))))
        except Quitting:
            return quitting()
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
                with changing():
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
        from .tools import browser as B, owner
        if name == ramdisk.BROWSER and browser_busy():   # a close wiped the download or unpacking under the job
            return JSONResponse({"error": f"{app.state.browser_job['name']} is being set up in ~/{name}: wait until "
                                 "that has finished, or stop it, then close."}, status_code=409)
        held, why = (await asyncio.to_thread(B.hold_all, host)) if name == ramdisk.BROWSER else ([], "")
        if why:
            return JSONResponse({"error": why}, status_code=409)
        try:
            async with scan_lock:
                wiped = None
                inside = await asyncio.to_thread(ramdisk.mounts_inside, host, st.path)
                if inside:                              # a vault, a share, a drive: never overwritten or deleted
                    one = len(inside) == 1
                    return JSONResponse({"error": f"Unmount {', '.join(inside)} first: "
                                         f"{'another filesystem is' if one else 'other filesystems are'} mounted there, "
                                         f"inside ~/{name}. {'Its' if one else 'Their'} files aren't the RAM disk's to "
                                         f"overwrite, and ~/{name} can't be unmounted around {'it' if one else 'them'}.",
                                         "mounted": inside}, status_code=409)
                with changing():                        # the overwrite isn't cut short by quitting
                    if name == ramdisk.BROWSER:         # its TempOutboxes stopped meanwhile: their mat2 isn't a user
                        users, w = await in_thread(B.users_or_wipe, host, st.path, name="ramdisk-wipe")
                    else:
                        users = await asyncio.to_thread(B.disk_users, host, st.path)
                        w = None if users else await in_thread(ramdisk.wipe, st.path, name="ramdisk-wipe")
                if users:
                    return JSONResponse({"error": f"Close {', '.join(users)} first: "
                                         f"{'it is' if len(users) == 1 else 'they are'} using files in ~/{name}.",
                                         "users": users}, status_code=409)
                wiped = {"files": w.files, "bytes": w.bytes, "failed": w.failed[:20]}
                problem = await with_root(host)
                if problem:
                    return JSONResponse({"error": problem.replace("changed", "closed") + (
                        " Its files have been overwritten and deleted already." if wiped else ""), "declined": True,
                        "wiped": wiped}, status_code=403)
                try:
                    with changing():
                        await asyncio.to_thread(host.privileged.call, "ramdisk_close", {"name": name})
                except HelperError as e:
                    return JSONResponse({"error": f"It couldn't be closed: {e}", "wiped": wiped}, status_code=400)
                owner.release(host, name)
                if name == ramdisk.BROWSER:             # why a quit left it open, if it did: no longer so
                    await asyncio.to_thread(B.forget_left_open, host)
                    app.state.left_open = None
        finally:
            for fd in held:
                owner.let_go(fd)
        return {"ramdisk": await asyncio.to_thread(ramdisk_view, host, name), "wiped": wiped,
                "admin_active": admin.active()}

    # Tor Browser or Mullvad Browser in the RAM disk. Downloading reaches the network (make_net), only
    # when the user starts it, after the page has named the hosts; verifying and unpacking follow in the
    # same background job, which the page follows. Starting the browser is quick.

    browser_view = job_view

    def browser_busy() -> bool:
        return jobs.running("browser")

    async def run_browser_job(job: dict, b, archive: Path | None, held: int | None = None) -> None:
        from .tools import browser as B, kept, owner
        host = make_host()
        state, error, unchecked = "failed", "", ""
        try:
            if archive is None:
                archive = await in_thread(B.download, host, make_net(), b, job, lambda: job["cancel"])
            else:   # the user's own archive, or the kept copy: a copy of it in the RAM disk, only the latest version
                archive = await in_thread(B.copy_in, host, archive, job)
                job.update(phase=f"Asking {B.index_host(b)} which version is the latest", done=0, total=0)
                try:
                    job["latest"] = await in_thread(B.check_latest, make_net(), b, archive.name, job["source"] == "kept")
                except B.Unreachable as e:              # blocked here? decided once the signature is verified
                    unchecked = str(e)
                except B.Outdated as e:                 # the page offers the download of the new one
                    job["newer"] = e.latest
                    raise
            job.update(phase=f"Checking {archive.name}'s signature", done=0, total=0)
            job["verdict"] = await in_thread(B.verified, host, archive)
            if unchecked:
                job["warning"] = await asyncio.to_thread(B.accept_unchecked, archive, b, unchecked,
                                                         job["verdict"]["signed"])
            if job["cancel"]:
                raise B.Stopped("Stopped before unpacking: nothing was unpacked.")
            target = await in_thread(B.unpack, host, archive, b, job)
            security = await asyncio.to_thread(B.preset_security, host, b, target)
            vpn_preset = await asyncio.to_thread(B.preset_vpn, host, b, target, archive) if job["vpn"] else None
            job["release"] = await asyncio.to_thread(B.record_release, host, b, archive, job["source"], security,
                                                     bool(unchecked), job["verdict"]["signed"], vpn_preset)
            job["outbox"] = await asyncio.to_thread(B.default_outbox, host, b)
            job["version"] = job["version"] or job["release"]["version"]
            if job.get("keep"):                         # ticked: from the verified file, verified again where it is kept
                job.update(phase="Keeping the download for next time")
                try:
                    k = await in_thread(kept.keep, host, b, archive, B.verified)
                    job["kept"] = {"version": k["version"], "folder": host.display(kept.folder(host))}
                except (kept.KeepError, B.BrowserError, OSError) as e:
                    why = (e.strerror or e) if isinstance(e, OSError) else e
                    job["keep_error"] = f"The download wasn't kept: {why}"
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

    def left_open_note(host: Host) -> dict | None:
        """Why the last quit left ~/TempBrowser open (browser.close_disk's note in the runtime folder): taken by the
        copy that owns the disk now, as its panel is shown, and kept in its memory until dismissed or the disk is
        closed."""
        from .tools import browser as B, owner, ramdisk
        if not ramdisk.mounted(host, ramdisk.BROWSER):
            B.forget_left_open(host)
            app.state.left_open = None
        elif owner.owns(host, ramdisk.BROWSER, ramdisk.folder(host, ramdisk.BROWSER)):
            app.state.left_open = B.take_left_open(host) or app.state.left_open
        return app.state.left_open

    @app.get("/api/tools/browser", dependencies=[Depends(auth)])
    async def tools_browser():
        from .tools import browser as B
        from .tools.pick import dialog
        host = make_host()
        chooser = "window" if pick is not None else getattr(dialog(host), "__name__", None)
        await asyncio.to_thread(adopt_browser_disk, host)
        await asyncio.to_thread(B.tidy_leftovers, host)  # what a killed copy's set-up left: memory, until the next
        return {**await asyncio.to_thread(B.status, host), "job": browser_view(app.state.browser_job),
                "can_pick": chooser is not None, "picker": chooser, "admin_active": admin.active(),
                "left_open": await asyncio.to_thread(left_open_note, host)}

    @app.post("/api/tools/browser/get", dependencies=[Depends(auth)])
    async def tools_browser_get(request: Request):
        """Body {"browser": "tor" | "mullvad"} to download it (the page has named the hosts; "keep": true keeps the
        download for next time, tools/kept.py), {"archive": path} for one the user downloaded (its .asc beside it), or
        {"kept": "tor" | "mullvad"} for the kept copy, which goes the picked archive's way; "vpn" (default true):
        Mullvad Browser set up for Mullvad VPN (browser.preset_vpn). Returns at once; the page follows the job with
        GET /api/tools/browser."""
        from .tools import browser as B, kept
        body = await body_of(request)
        host = make_host()
        if browser_busy():
            return JSONResponse({"error": "A browser is already being set up."}, status_code=409)
        archive, source = None, "download"
        try:
            if body.get("archive"):
                archive, source = tool_paths(host, body["archive"])[0], "file"
                b = B.which(archive)
                plat = B.platform_name()
                if plat is None or plat not in archive.name:
                    return JSONResponse({"error": f"{archive.name} isn't made for this processor."}, status_code=400)
            elif body.get("kept"):
                b = B.BROWSERS[body.get("kept")]
                k = await asyncio.to_thread(kept.kept, host, b)
                if k is None:
                    return JSONResponse({"error": f"No download of {b.name} is kept."}, status_code=409)
                archive, source = k["archive"], "kept"
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
        job = Job("browser", "running", browser=b.id, name=b.name, source=source,
                  hosts=[B.index_host(b)] if archive else list(b.hosts), phase="Starting", done=0, total=0, version="",
                  verdict=None, error="", created=time.time(), finished=None,
                  vpn=b.id == "mullvad" and body.get("vpn", True) is not False,
                  keep=source == "download" and body.get("keep") is True)
        try:
            jobs.start(job, lambda j: run_browser_job(j, b, archive, held))
        except Quitting:
            owner.let_go(held)
            return quitting()
        return {"job": browser_view(job)}

    @app.post("/api/tools/browser/stop", dependencies=[Depends(auth)])
    async def tools_browser_stop():
        job = app.state.browser_job
        if job is not None and job["state"] == "running":
            job["cancel"] = True
        return {"job": browser_view(job)}

    @app.post("/api/tools/browser/dismiss", dependencies=[Depends(auth)])
    async def tools_browser_dismiss(request: Request):
        """The finished set-up job's result, put away; with {"browser"}, why that browser last stopped with an error
        (kept until dismissed or started again: browser.launch_problem); with {"left_open": true}, why the last quit
        left ~/TempBrowser open (left_open_note)."""
        from .tools import browser as B
        body = await body_of(request)
        if body.get("left_open") is True:
            app.state.left_open = None
            return {"ok": True}
        b = browser_of(body)
        if b is not None:
            B.forget_problem(b)
            return {"ok": True}
        if not browser_busy():
            app.state.browser_job = None
        return {"job": None if not browser_busy() else browser_view(app.state.browser_job)}

    def browser_of(body: dict):
        from .tools import browser as B
        return B.BROWSERS.get(body.get("browser")) if isinstance(body.get("browser"), str) else None

    @app.post("/api/tools/browser/kept/delete", dependencies=[Depends(auth)])
    async def tools_browser_kept_delete(request: Request):
        """Body {"browser"}: its kept download deleted from the app's cache folder (tools/kept.py). Not while it is
        being set up from it, here or in another copy of the app."""
        from .tools import browser as B, kept, owner
        host = make_host()
        b = browser_of(await body_of(request))
        if b is None:
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        key = f"browser-{b.id}"
        held = None if owner.held_here(key) else await asyncio.to_thread(owner.hold, host, key)
        if held is None:
            return JSONResponse({"error": f"{b.name} is being set up: delete it once that has finished."},
                                status_code=409)
        try:
            there = await asyncio.to_thread(kept.delete, host, b)
        except OSError as e:
            return JSONResponse({"error": f"It couldn't be deleted: {e.strerror or e}"}, status_code=400)
        finally:
            owner.let_go(held)
        return {**await asyncio.to_thread(B.status, host), "deleted": there}

    @app.post("/api/tools/browser/remove", dependencies=[Depends(auth)])
    async def tools_browser_remove(request: Request):
        """Body {"browser"}: a copy whose set-up was interrupted (unpacked, never recorded, so it doesn't start)
        overwritten and deleted on its own, without closing ~/TempBrowser and the other browser with it."""
        from .tools import browser as B
        host = make_host()
        b = browser_of(await body_of(request))
        if b is None:
            return JSONResponse({"error": "Choose Tor Browser or Mullvad Browser."}, status_code=400)
        if browser_busy() and app.state.browser_job.get("browser") == b.id:
            return JSONResponse({"error": f"{b.name} is being set up: wait until that has finished."}, status_code=409)
        try:
            files = await asyncio.to_thread(B.remove_copy, host, b)
        except B.BrowserError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        except OSError as e:
            return JSONResponse({"error": f"It couldn't be removed: {e.strerror or e}"}, status_code=400)
        return {**await asyncio.to_thread(B.status, host), "removed": files}

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
        if jobs.quitting:
            return quitting()
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
                with changing():
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
        return jobs.running("trim", "names", "clean")

    # the TRIM test and Deleted file names don't start while an app is watched, nor the watch while they run: the
    # helper does one call at a time, and a disk read for minutes held the watch's polling (and its End) behind it
    def watching() -> JSONResponse:
        return JSONResponse({"error": "An app is being watched (What does this app keep?): end the watch first. Both "
                                      "need the administrator helper, which does one thing at a time."},
                            status_code=409)

    trim_view = job_view

    async def run_trim_job(job: dict, mount: str) -> None:
        from .tools import trimtest
        host = make_host()
        try:
            problem = await with_root(host)
            if problem:
                job["state"], job["error"] = "failed", problem.replace("Nothing was changed.", "The test didn't start.")
                return
            if job["cancel"]:                          # stopped while access was asked for (quitting)
                raise trimtest.Stopped("Stopped before it started: nothing was written.")
            job["state"], job["started"] = "running", time.time()
            with admin.hold():
                job["result"] = await in_thread(trimtest.run, host, mount, lambda: admin.get(prompt=False), job,
                                                name="trim-test")
            job["state"] = "done"
        except trimtest.Stopped as e:
            job["state"], job["error"] = "stopped", str(e)
        except ValueError as e:
            job["state"], job["error"] = "failed", str(e)
        except HelperError as e:
            job["state"], job["error"] = ("stopped", "Stopped.") if e.data.get("stopped") or job["cancel"] else (
                "failed", f"The helper refused: {e}")
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
        job = Job("trim", "asking", mount=mount, phase="Starting", scan=None, done=0, total=0, phase_started=time.time(),
                  steps=[], created=time.time(), started=None, finished=None, result=None, error="")
        try:
            jobs.start(job, lambda j: run_trim_job(j, mount))
        except Quitting:
            return quitting()
        return {"job": trim_view(job)}

    @app.post("/api/tools/trim/stop", dependencies=[Depends(auth)])
    async def tools_trim_stop():
        """Stops the test within seconds; its files are removed."""
        job = app.state.trim_job
        if job is not None and job["state"] in ("asking", "running"):
            job["cancel"] = True
            admin.cancel(TRIM_REQUESTS)
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
                    job["trimmed"] = (await in_thread(h.call, "names_fstrim", {"mount": mount}, 900,
                                                      name="names-trim")).get("trimmed")
                if job["cancel"]:
                    raise names.Stopped("Stopped: nothing was listed.")
                job["result"] = await in_thread(names.scan, host, mount, lambda: admin.get(prompt=False), job,
                                                trim_passed(mount), name="names")
            # the folders it showed (their paths, never the names): a clean-up or check may name only these
            app.state.names_listed = (mount, frozenset(f["rel"] for f in job["result"]["folders"]))
            job["state"] = "done"
        except names.Stopped as e:
            job["state"], job["error"] = "stopped", str(e)
        except ValueError as e:
            job["state"], job["error"] = "failed", str(e)
        except HelperError as e:
            job["state"], job["error"] = ("stopped", "Stopped.") if e.data.get("stopped") or job["cancel"] else (
                "failed", f"The helper refused: {e}")
        except Exception as e:  # noqa: BLE001
            job["state"], job["error"] = "failed", f"{type(e).__name__}: {e}"
        finally:
            job["phase"] = None

    @app.get("/api/tools/names", dependencies=[Depends(auth)])
    async def tools_names():
        """The filesystems whose names can be listed."""
        from .tools import names, rebuild
        host = make_host()
        targets = await asyncio.to_thread(names.targets, host)
        for t in targets:
            t["trim_passed"] = trim_passed(t["mount"])
        return {"targets": targets, "admin_active": admin.active(), "busy": trim_running(),
                "interrupted": await asyncio.to_thread(rebuild.interrupted, host)}

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
        job = Job("names", "asking", phase="Starting", done=0, total=0, unit="", phase_started=time.time(), result=None,
                  error="", mount=mount, trimmed=None)
        try:
            jobs.start(job, lambda j: run_names_job(j, mount, body.get("trim_first") is True))
        except Quitting:
            return quitting()
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
        app.state.names_listed = None
        admin.cancel(NAMES_REQUESTS)
        h = admin.get(prompt=False) if admin.active() else None
        if h is not None and not trim_running():
            try:
                await asyncio.to_thread(h.call, "names_end", {})
            except Exception:  # noqa: BLE001 - it forgets them when access ends anyway
                pass
        return {"job": None}

    def not_listed(mount: str, rels: list[str]) -> JSONResponse | None:
        """Folders the last listing didn't show (the page names them; a clean-up must never reach further)."""
        listed = app.state.names_listed
        if listed is None or listed[0] != mount or not set(rels) <= listed[1]:
            return JSONResponse({"error": "Those folders weren't in the list of deleted names: list the names again."},
                                status_code=409)
        return None

    @app.get("/api/tools/names/interrupted", dependencies=[Depends(auth)])
    async def tools_names_interrupted():
        """A clean-up of a folder that a crash, a logout or a power cut interrupted (rebuild.Note), if any."""
        from .tools import rebuild
        return {"interrupted": await asyncio.to_thread(rebuild.interrupted, make_host())}

    @app.post("/api/tools/names/recover", dependencies=[Depends(auth)])
    async def tools_names_recover():
        """Finishes or undoes it (as the user: the folders are theirs), then forgets the note."""
        from .tools import rebuild
        if app.state.clean_job is not None and app.state.clean_job["state"] in ("asking", "running"):
            return JSONResponse({"error": "A clean-up is running."}, status_code=409)
        try:
            return await asyncio.to_thread(rebuild.recover, make_host())
        except OSError as e:
            return JSONResponse({"error": f"It couldn't be finished: {e.strerror or e}."}, status_code=409)

    @app.post("/api/tools/names/plan", dependencies=[Depends(auth)])
    async def tools_names_plan(request: Request):
        """Body {"mount", "folders": [path under the listing's top], "rebuild": [those to rebuild
        rather than fill]}: what cleaning them would do now (the dry run). Changes nothing. Only folders the last
        listing showed."""
        from .tools import rebuild
        body = await body_of(request)
        mount, rels, again = body.get("mount"), body.get("folders"), body.get("rebuild") or []
        if not isinstance(mount, str) or not isinstance(rels, list) or not all(isinstance(x, str) for x in rels) \
                or not 0 < len(rels) <= 500 or not isinstance(again, list) or not all(isinstance(x, str) for x in again):
            return JSONResponse({"error": "Choose the folders to clean."}, status_code=400)
        refused = not_listed(mount, rels)
        if refused:
            return refused
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
            if job["cancel"]:
                raise names.Stopped("Stopped before it started: nothing was changed.")
            with admin.hold():
                job["result"] = await in_thread(rebuild.run, host, mount, rels, lambda: admin.get(prompt=False), job,
                                                again, name="names-clean")
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
        refused = not_listed(mount, rels)
        if refused:
            return refused
        job = Job("clean", "asking", phase="Starting", steps=[], result=None, error="", mount=mount, started=time.time())
        try:
            jobs.start(job, lambda j: run_clean_job(j, mount, rels, again))
        except Quitting:
            return quitting()
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
        refused = not_listed(mount, rels)
        if refused:
            return refused
        try:
            with admin.hold():
                return {"result": await in_thread(rebuild.recheck, make_host(), mount, rels,
                                                  lambda: admin.get(prompt=False), name="names-check")}
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
                return await in_thread(call, lambda: admin.get(prompt=False) if admin.active() else None,
                                       name="names-listing")
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
        return jobs.running("keeps")

    keeps_view = job_view

    async def run_keeps_job(job: dict, entry) -> None:
        from .tools import appwatch
        host = make_host()
        had_admin = admin.active()
        token, began = job["id"][:12], None
        units = appwatch.units(entry, token)
        mark = None
        try:
            problem = await with_root(host)
            mark = admin.claimed()                  # anything asking for the access after this keeps it when this ends
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
                    seen, missed, closed_at = False, 0, None
                    while not job["cancel"]:
                        await asyncio.sleep(KEEPS_EVERY)
                        h = admin.get(prompt=False)
                        if h is None:
                            began = None
                            raise appwatch.WatchError("Administrator access ended, so the watch ended with it. "
                                                      "Nothing of what it saw is left.")
                        try:
                            job["counts"] = await asyncio.to_thread(h.call, "watch_poll", {})
                            missed = 0
                        except HelperError as e:
                            # a watch busy with a burst of events answers late: asked again at the next look (its late
                            # answer is passed over), and only given up after KEEPS_MISSES in a row
                            missed += 1
                            if "didn't answer" not in str(e):
                                raise
                            if missed >= KEEPS_MISSES:
                                raise appwatch.WatchError("The watch stopped answering (it may have been overloaded), so "
                                                          "it was ended. Nothing of what it saw is kept.") from None
                            continue
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
                        # it ends itself, as End does (its result kept for the panel), KEEPS_LEFT after the app stopped
                        # running (it closed, or it was never seen: it handed over to a copy that was open; one started
                        # again meanwhile goes on being watched) or after its panel was closed: administrator access
                        # was held until End was pressed, the app and the panel long gone
                        closed_at = (closed_at or time.time()) if job["closed"] or job["absent"] else None
                        away = max(job["away"], job["started"]) if job["away"] is not None else None
                        since = [s for s in (closed_at, away) if s is not None]
                        job["ends_at"] = min(since) + KEEPS_LEFT if since else None
                        if job["ends_at"] is not None and time.time() >= job["ends_at"]:
                            job["ended_itself"] = "closed" if closed_at is not None and closed_at == min(since) else "away"
                            break
                    job["state"] = "ending"
                    h = admin.get(prompt=False)         # the helper running now (the one polled), not the one given at the start
                    if h is None:
                        began = None
                        raise appwatch.WatchError("Administrator access ended, so the watch ended with it. "
                                                  "Nothing of what it saw is left.")
                    raw = await in_thread(h.call, "watch_end", {}, 180, name="watch-end")
                    watched, began = began, None
                finally:
                    if began is not None:               # it failed on the way: the watch doesn't stay on
                        h = admin.get(prompt=False)
                        try:
                            if h is not None:
                                await asyncio.to_thread(h.call, "watch_end", {}, 30)
                        except Exception:  # noqa: BLE001 - it ends with the helper anyway
                            pass
            job["result"] = await in_thread(appwatch.report, host, entry, raw, watched, before, name="watch-report")
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
            # administrator access was for the watch: given up as soon as it ends, unless something else has it (holds
            # it, or has asked for it since)
            if not had_admin and mark is not None:
                await asyncio.to_thread(admin.drop_unless_claimed, mark)

    @app.get("/api/tools/keeps", dependencies=[Depends(auth)])
    async def tools_keeps(request: Request):
        """The apps that can be watched, why it can't be done here (if so), and the watch or its result. `?panel=open`:
        the panel is open again, so the watch no longer ends itself for its having been closed."""
        from .tools import appwatch, menu
        host = make_host()
        job = app.state.keeps_job
        if job is not None and request.query_params.get("panel") == "open":
            job["away"] = None

        def gather():
            return {"unavailable": appwatch.available(host),
                    "apps": [a.to_dict() for a in menu.apps(host) if not a.terminal]}
        return {**await asyncio.to_thread(gather), "warning": appwatch.WARNING, "limits": appwatch.LIMITS,
                "ends_after": KEEPS_LEFT, "job": keeps_view(app.state.keeps_job), "admin_active": admin.active()}

    @app.post("/api/tools/keeps/away", dependencies=[Depends(auth)])
    async def tools_keeps_away():
        """The panel was closed while the watch runs: it ends itself KEEPS_LEFT later, unless the panel is opened again
        (GET with ?panel=open). Its own requests in flight then can't take this back: only an opening does."""
        job = app.state.keeps_job
        if job is not None and job["state"] in ("asking", "running") and job["away"] is None:
            job["away"] = time.time()
        return {"job": keeps_view(job)}

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
            job = Job("keeps", "asking", app=entry.name, started=None, finished=None, counts=None, alive=None,
                      closed=False, absent=False, quiet=False, watched=[], not_watched=[], result=None, error="",
                      away=None, ends_at=None, ended_itself="")
            try:
                jobs.start(job, lambda j: run_keeps_job(j, entry))
            except Quitting:
                return quitting()
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
                    app.state.trial = await in_thread(trial.prepare_app, host, entry, where, name="trial-prepare")
                else:
                    path = tool_paths(host, body.get("path"))[0]
                    app.state.trial = await in_thread(trial.prepare_file, host, path, where, name="trial-prepare")
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
            if jobs.quitting:
                return quitting()
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
            await in_thread(discard_trial, name="trial-discard")      # overwriting gigabytes in memory takes a while
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
        body = await body_of(request)

        def look():
            b = box_of(host, body)
            why = box.problem(host, b)
            if why:
                raise ValueError(f"{b.name}'s Box can't start: {why}.")
            if box.running(host, b.slug):
                raise ValueError(f"{b.name} is already running in its Box.")
            return b
        try:
            b = await asyncio.to_thread(look)
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
            with changing():
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
        now = {d.name: retire.identity(d) for d in drives}
        for name, f in list(app.state.erase_facts.items()):        # its drive gone, or another one under its name
            if f.get("drive") != now.get(name):
                del app.state.erase_facts[name]
        return {"drives": [d.to_dict() for d in drives], "facts": app.state.erase_facts, "admin_active": admin.active()}

    @app.post("/api/tools/retire/facts", dependencies=[Depends(auth)])
    async def tools_retire_facts(request: Request):
        """Body {"disk"}: what the drive says about erasing itself (identify data, through the helper)."""
        from .tools import retire
        body = await body_of(request)
        host = make_host()
        try:
            d = await asyncio.to_thread(retire.find, host, str(body.get("disk", "")))
            retire.same_drive(d, body.get("drive") if isinstance(body.get("drive"), list) else None)
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
        app.state.erase_facts[d.name] = facts = {**facts, "drive": retire.identity(d)}     # this drive's, not the name's
        return {"facts": facts, "admin_active": admin.active()}

    @app.post("/api/tools/retire/guide", dependencies=[Depends(auth)])
    async def tools_retire_guide(request: Request):
        """Body {"disk", "typed", "kind", "from_start", "drive"}: the steps for that drive, once `typed` is its name.
        `drive`: the identity the listing gave it (retire.identity); another drive under that name now is refused."""
        from .tools import retire
        body = await body_of(request)
        name = str(body.get("disk", ""))
        try:
            g = await asyncio.to_thread(retire.guide, make_host(), name, str(body.get("typed", "")),
                                        body.get("kind") if isinstance(body.get("kind"), str) else None,
                                        body.get("from_start") is True, app.state.erase_facts.get(name),
                                        body.get("drive") if isinstance(body.get("drive"), list) else None)
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
            with changing():
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
            with changing():
                return await asyncio.to_thread(presentation.renew, make_host())
        except FixError as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    @app.post("/api/tools/presentation/off", dependencies=[Depends(auth)])
    async def tools_presentation_off():
        from .tools import presentation
        with changing():
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

    def close_browser_disk() -> str:
        """The browser's RAM disk is for while the app runs: quitting closes it (unless the browser
        still uses it), asking for administrator access if it has to, also when the session ends (the owner's
        decision of 2026-10-17: unmounted properly rather than left mounted and empty), its files overwritten while
        the prompt waits (browser.close_disk). What happened is said on a terminal only: it names programs ("Tor
        Browser still uses it"), and off a terminal stderr is a log on the disk (~/.xsession-errors, the journal)."""
        from .tools import browser
        try:
            msg = browser.close_disk(make_host(), lambda: admin.get(prompt=True))
        except Exception as e:  # noqa: BLE001 - quitting goes on; the page shows it open next time
            msg = f"~/TempBrowser couldn't be closed: {type(e).__name__}"   # no message: it can name a path
        if msg and sys.stderr.isatty():
            print(msg, file=sys.stderr)
        return msg

    app.state.close_browser_disk = close_browser_disk

    def left_open_at_quit() -> list[str]:
        """What would keep ~/TempBrowser open if the app quit now, though quitting would close it (a viewer View
        offline… opened, another program using a file in it: browser.left_open_by). The page asks before it quits
        then, from its Quit and, in the window, as the window is closed (app.CloseGuard)."""
        from .tools import browser
        try:
            return browser.left_open_by(make_host())
        except Exception:  # noqa: BLE001 - can't tell: quitting goes on as before (the next start's panel says why)
            return []

    app.state.left_open_at_quit = left_open_at_quit

    @app.get("/api/quit", dependencies=[Depends(auth)])
    async def quit_check():
        """{"left_open": [programs]}: what would keep ~/TempBrowser open if the app quit now (left_open_at_quit)."""
        return {"left_open": await asyncio.to_thread(left_open_at_quit)}

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
            locked: trial.leftovers), and so does the empty folder a logout or a restart left where ~/TempBrowser was
            (systemd unmounts it when the session ends, helper.dropin_setting; the folder is put back as the user)."""
            from .tools import ramdisk, trial
            app.state.trial_cleaned = True
            host = make_host()
            try:
                trial.clear_leftovers(host)
            except OSError as e:
                print(f"Trial folders left from before couldn't be removed: {type(e).__name__}", file=sys.stderr)
            try:
                if ramdisk.status(host, ramdisk.BROWSER).leftover:
                    ramdisk.put_back(host, ramdisk.BROWSER)
            except OSError as e:
                print(f"The browser's RAM disk's folder couldn't be put back: {type(e).__name__}", file=sys.stderr)
        threading.Thread(target=clear_trials, name="trial-leftovers", daemon=True).start()

    quit_done = threading.Lock()
    quit_state: dict = {}

    def shutdown(wait: float | None = None, changes_wait: float | None = None) -> dict:
        """Quitting, however it comes (the page's Quit in --browser mode, the window closed, a logout's SIGTERM or
        SIGHUP, Ctrl+C), once: nothing new starts (jobs.quitting), every job is told to stop as its Stop does (the
        online tests, a download, mat2 over a folder, the TRIM test, a listing, a watch) and a file chooser left open
        is closed; then up to QUIT_WAIT seconds for the jobs to end, and CHANGES_WAIT for a fix, a revert or a set-up
        under way (never cut short half-way); then what is for while the app runs: ~/TempBrowser closed (asking for
        the password if it must, its files overwritten meanwhile), a trial discarded, administrator access dropped,
        Presentation mode turned off. Off the event loop, which the jobs' work needs. Before, nothing was stopped:
        Python waited for the jobs' threads at exit, an invisible process going on after the window closed. app.main
        ends the process (os._exit) once this has returned, whatever is left."""
        from .tools import presentation
        from .tools.pick import end_dialogs
        with quit_done:
            if quit_state:
                return quit_state
            told = jobs.cancel_all()
            end_dialogs()
            left = jobs.wait(QUIT_WAIT if wait is None else wait) if told else []
            with in_flight:
                settled = in_flight.wait_for(lambda: changes["n"] == 0, CHANGES_WAIT if changes_wait is None
                                             else changes_wait)
            closed = close_browser_disk()
            for what, step in (("The trial", discard_trial), ("Administrator access", admin.drop),
                               ("Presentation mode", lambda: presentation.turn_off(make_host()))):
                try:
                    step()
                except Exception as e:  # noqa: BLE001 - quitting goes on; its kind only (a message can name a path)
                    print(f"{what} couldn't be ended at quit: {type(e).__name__}", file=sys.stderr)
            quit_state.update(told=told, left=left, settled=settled, browser_disk=closed)
            return quit_state

    app.state.shutdown = shutdown

    if on_quit is not None:
        @app.post("/api/quit", dependencies=[Depends(auth)])
        async def quit_app():
            await in_thread(shutdown, name="quit")
            asyncio.get_running_loop().call_later(0.3, on_quit)  # let this reply reach the page first
            return {"ok": True}
    elif close_window is not None:
        @app.post("/api/quit", dependencies=[Depends(auth)])
        async def quit_window():
            """The window's Quit anyway, once the page has asked: the window closes, and the app quits as when it is
            closed (app.main closes what it must then)."""
            asyncio.get_running_loop().call_later(0.3, close_window)   # let this reply reach the page first
            return {"ok": True}

    return app
