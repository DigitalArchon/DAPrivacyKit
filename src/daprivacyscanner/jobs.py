"""The server's background work, and what quitting must stop.

A job is long work the page follows by polling (the online tests, the TRIM test, Deleted file names and their
clean-up, Remove metadata, setting up a browser, What does this app keep?, downloading an update): one of each kind at
a time, a dict of what
the page reads, with a `cancel` flag the work looks at as it goes. The registry (`Jobs`) starts them, tells whether
one is running, and at quit tells every one to stop and waits a while for them.

What blocks for long (a job's work, a file chooser left open for an hour, the password prompt) runs on a thread of its
own that doesn't keep the process alive (`in_thread`): asyncio.to_thread's pool is the event loop's default executor,
a few threads on a small machine, whose threads Python waits for at exit. Shared, the page's short requests waited
behind them, and after the window closed an invisible process went on running the online tests, a 600 MB download, mat2
over a folder or a dialog, until each ended by itself."""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from typing import Any, Awaitable, Callable

RUNNING = frozenset({"starting", "asking", "running", "ending"})     # every kind's states while it works
HIDDEN = frozenset({"cancel", "abort", "archive"})                    # the work's own, never sent to the page
KINDS = ("online", "trim", "names", "clean", "meta", "browser", "keeps", "update")


def running(job: dict | None) -> bool:
    return job is not None and job.get("state") in RUNNING


def view(job: dict | None) -> dict | None:
    """What the page gets of a job: everything but the work's own flags, with whether it was told to stop and the
    server's clock (for its timers)."""
    if job is None:
        return None
    return {**{k: v for k, v in job.items() if k not in HIDDEN}, "stopping": bool(job.get("cancel")), "now": time.time()}


class Job(dict):
    """A job: the dict the page reads (`view`), and the work's own `cancel`. `ended` is set once its work has
    finished, however it finished."""

    def __init__(self, kind: str, state: str = "running", /, **fields: Any):
        """`kind`: which of KINDS (a field of the page's may have that name too: Remove metadata's "read" or
        "clean")."""
        super().__init__({"id": uuid.uuid4().hex, "state": state, "cancel": False, **fields})
        self.kind = kind
        self.task: asyncio.Task | None = None
        self.ended = threading.Event()

    @property
    def running(self) -> bool:
        return running(self)


class Quitting(Exception):
    """The app is quitting: nothing new starts."""


class Jobs:
    """Every kind's job, kept in `state` as <kind>_job (where the routes, and tests, find it)."""

    def __init__(self, state):
        self.state = state
        self.quitting = False
        for kind in KINDS:
            setattr(state, f"{kind}_job", None)

    def get(self, kind: str) -> dict | None:
        return getattr(self.state, f"{kind}_job", None)

    def put(self, kind: str, job: dict | None) -> None:
        setattr(self.state, f"{kind}_job", job)

    def running(self, *kinds: str) -> bool:
        return any(running(self.get(k)) for k in kinds or KINDS)

    def start(self, job: Job, work: Callable[[Job], Awaitable[None]]) -> Job:
        """`work(job)` as a task on the running loop, the job kept as its kind's. Raises Quitting once quitting."""
        if self.quitting:
            raise Quitting()
        self.put(job.kind, job)

        async def run() -> None:
            try:
                await work(job)
            finally:
                job.ended.set()
        job.task = asyncio.get_running_loop().create_task(run(), name=f"job-{job.kind}")
        setattr(self.state, f"{job.kind}_task", job.task)
        return job

    def cancel_all(self) -> list[str]:
        """Quitting: no job starts from now on, and every one running is told to stop (as its Stop does). The kinds
        told."""
        self.quitting = True
        told = []
        for kind in KINDS:
            job = self.get(kind)
            if job is not None and running(job):
                job["cancel"] = True
                told.append(kind)
        return told

    def wait(self, timeout: float) -> list[str]:
        """Waits up to `timeout` seconds in all for the jobs running to end (from any thread but the event loop's,
        which their work needs). The kinds still running then."""
        deadline = time.monotonic() + timeout
        for kind in KINDS:
            job = self.get(kind)
            if isinstance(job, Job) and running(job):
                job.ended.wait(max(0.0, deadline - time.monotonic()))
        return [k for k in KINDS if running(self.get(k))]


async def in_thread(fn: Callable, *args, name: str = "work", **kwargs):
    """`fn(*args, **kwargs)` on a daemon thread of its own, awaited: for what can block for long (a job's work, a file
    chooser, the password prompt), which the loop's default executor would hold a thread of, and Python wait for at
    exit."""
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def deliver(ok: bool, value) -> None:
        if not fut.done():
            (fut.set_result if ok else fut.set_exception)(value)

    def work() -> None:
        try:
            value, ok = fn(*args, **kwargs), True
        except BaseException as e:  # noqa: BLE001 - handed to the awaiting coroutine
            value, ok = e, False
        try:
            loop.call_soon_threadsafe(deliver, ok, value)
        except RuntimeError:                    # the loop has closed (quitting): nobody waits for it any more
            pass
    threading.Thread(target=work, name=name, daemon=True).start()
    return await fut
