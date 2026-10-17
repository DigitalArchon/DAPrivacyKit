"""A Box (docs/TECHNICAL.md, Tools: Try an app; the catalogue's app.boxes, a set-up that lasts): an app kept in
a sandbox of its own for good, with a home of its own. Where a trial is thrown away, a Box stays: the app's
data lives in ~/Boxes/<name>/home and nowhere else, and the app never sees the real home.

    ~/Boxes/<name>/box.json    what it runs and what it gets (written by the guide, read here, checked again)
    ~/Boxes/<name>/home        its home folder: all it can write to, besides Exchange
    ~/Boxes/<name>/Exchange    the one folder shared with it, at ~/Exchange inside: files go in and out through it
    ~/Boxes/<name>/app         the program, for one kept from a trial of a downloaded file (read-only to it)
    ~/Boxes/<name>/runs.json   each run in numbers (below)

It is started from the menu (a launcher of the app's own, `daprivacyscanner --box <name>`) or from the Tools
panel, in the same sandbox as a trial (tools/trial.py's engines), without decoys: it is the app's real home now.
The sandbox's own files (its /etc, the X authority copy, the marked Wayland socket, the packets' pipe) are in
the runtime folder, never in the Box.

Each run is watched as a trial is, only while it runs (no monitor is ever left on), and what is kept of it is
numbers: when, how long, how many files it wrote, how many hosts it contacted and how many of those it had
never contacted before. The hosts are kept as salted hashes (as the scan's baseline keeps what starts at login),
never by name: a list of the sites a boxed browser visits would be a history. The salt is in the same file, so
anyone who can read it can test a guess (was this site contacted?): the panel and the guide say so (the owner's
decision of 2026-10-17), and the Box's home holds the app's own records anyway. The last RUNS_KEPT runs are kept;
the panel can clear them. The Tools panel starts a Box as the menu does (the launcher's command, on its own), so
a Box never depends on the app's window being open.

Set up through the guide and reverted from History like any set-up: reverting removes the launcher, the settings
and a program copied from a trial, and leaves the home and Exchange when they hold anything, saying so."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..host import Host
from ..launch import desktop_exec
from . import trial

BOXES = "Boxes"
RUNS_KEPT = 30
HOSTS_KEPT = 5000
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
KINDS = ("appimage", "program", "script", "archive", "deb", "installed", "flatpak")
NETWORKS = ("off", "observed", "on")
MARK = "Written by DA Privacy Kit. Revert it in the app's History to remove it."
FAILED_AT_ONCE = 10                     # seconds: a run that fails sooner is said in a dialog (`--box`), with its output


@dataclass
class Box:
    slug: str
    name: str
    kind: str
    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)
    flatpak: str | None = None
    host_opt: bool = False
    network: str = "off"
    gpu: bool = True
    sound: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def slug_of(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40].strip("-")
    return s or "app"


def clean_name(name: str) -> str:
    """A Box's name as it goes into box.json and the menu entry: one line of printable text (a file's name,
    which a trial's comes from, can hold a newline, and a newline in Name= would end that line of the entry)."""
    return " ".join(re.sub(r"[\x00-\x1f\x7f]", " ", name).split())[:120] or "app"


def root(host: Host) -> Path:
    return host.home / BOXES


def folder(host: Host, slug: str) -> Path:
    if not SLUG.fullmatch(slug or ""):
        raise trial.TrialError("That isn't a Box's name.")
    return root(host) / slug


def config_text(box: Box) -> str:
    return json.dumps({"note": MARK, **box.to_dict()}, indent=1, sort_keys=True) + "\n"


def parse(text: str, slug: str) -> Box | None:
    """A Box from its box.json, or None when the file isn't what the guide writes: it is a file in the user's
    home, so nothing in it is trusted to be well-formed."""
    try:
        d = json.loads(text)
    except ValueError:
        return None
    if not isinstance(d, dict) or d.get("slug") != slug or d.get("kind") not in KINDS or d.get("network") not in NETWORKS:
        return None
    argv, env = d.get("argv"), d.get("env", {})
    if (not isinstance(argv, list) or not argv or len(argv) > 60 or not all(isinstance(a, str) and 0 < len(a) < 4000 for a in argv)
            or not isinstance(env, dict) or len(env) > 30
            or not all(isinstance(k, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) and isinstance(v, str) for k, v in env.items())
            or not isinstance(d.get("name"), str) or not 0 < len(d["name"]) <= 120 or clean_name(d["name"]) != d["name"]):
        return None
    flat = d.get("flatpak")
    if d["kind"] == "flatpak" and not (isinstance(flat, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", flat)):
        return None
    if d["kind"] != "flatpak" and d["network"] == "on" or d["kind"] == "flatpak" and d["network"] == "observed":
        return None
    return Box(slug, d["name"], d["kind"], argv, env, flat if d["kind"] == "flatpak" else None, d.get("host_opt") is True,
               d["network"], d.get("gpu") is True, d.get("sound") is True)


def read(host: Host, slug: str) -> Box | None:
    try:
        path = folder(host, slug) / "box.json"
        if path.is_symlink() or path.stat().st_size > 200000:
            return None
        return parse(path.read_text(errors="replace"), slug)
    except (OSError, trial.TrialError):
        return None


def every(host: Host) -> list[Box]:
    try:
        names = sorted(n for n in os.listdir(root(host)) if SLUG.fullmatch(n))
    except OSError:
        return []
    return [b for b in (read(host, n) for n in names) if b is not None]


def launcher_path(data_home: Path, slug: str) -> Path:
    return Path(data_home) / "applications" / f"daprivacyscanner-box-{slug}.desktop"


def launcher_text(box: Box, command: list[str]) -> str:
    """The menu entry that starts the Box with this copy of the app."""
    return (f"[Desktop Entry]\n# {MARK}\nType=Application\nName={box.name} (in its Box)\n"
            "Comment=Runs in a sandbox with a home folder of its own (DA Privacy Kit)\n"
            f"Exec={desktop_exec(command + ['--box', box.slug])}\nIcon=security-high\nTerminal=false\n"
            "Categories=Utility;\n")


def problem(host: Host, box: Box) -> str | None:
    """Why the Box can't start as it is, or None."""
    f = folder(host, box.slug)
    if not (f / "home").is_dir() or (f / "home").is_symlink():
        return "its home folder is missing"
    if (f / "Exchange").is_symlink():                   # it is bound into the sandbox, writable: a folder, never a link
        return "its Exchange folder is a link, which the sandbox won't be given"
    if box.kind in ("appimage", "program", "script", "archive", "deb") and not (f / "app").is_dir():
        return "its program is missing from the Box"
    if box.kind == "installed" and not host.sys_path(box.argv[0]).exists():
        return f"its program ({box.argv[0]}) is no longer installed"
    if box.kind == "flatpak":                           # flatpak run would only fail, out of sight, as the Box starts
        if not host.runner.which("flatpak"):
            return "Flatpak isn't installed any more"
        branch = next((a.split("=", 1)[1] for a in box.argv if a.startswith("--branch=")), None)
        if not host.run_flatpak("info", "--show-ref", box.flatpak or "", *([branch] if branch else [])).ok:
            return f"its Flatpak app ({box.flatpak}) is no longer installed"
    return None


_SAME: dict[tuple, bool] = {}          # what same_program found, by both folders' listings (sizes and times)


def _listing(top: Path) -> dict[str, tuple]:
    out: dict[str, tuple] = {}
    for dirpath, dirs, files in os.walk(top):                 # links aren't followed: listed as links
        for n in dirs + files:
            p = os.path.join(dirpath, n)
            st = os.lstat(p)
            rel = os.path.relpath(p, top)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("folder",)
            else:
                out[rel] = ("file", st.st_size, st.st_mtime_ns)
    return out


def same_program(a: Path, b: Path) -> bool:
    """Whether the folders `a` and `b` hold the same program: the same names, links and contents (a trial's copy
    against the one already kept in a Box). Contents are compared only where everything else agrees."""
    import filecmp
    try:
        la, lb = _listing(a), _listing(b)
    except OSError:
        return False
    key = (str(a), str(b), tuple(sorted(la.items())), tuple(sorted(lb.items())))
    if key in _SAME:
        return _SAME[key]
    shape = lambda listing: {k: v[:2] for k, v in listing.items()}     # noqa: E731 - names, kinds, sizes, links
    same = shape(la) == shape(lb)
    try:
        same = same and all(filecmp.cmp(a / rel, b / rel, shallow=False) for rel, v in la.items() if v[0] == "file")
    except OSError:
        same = False
    _SAME.clear() if len(_SAME) > 32 else None
    _SAME[key] = same
    return same


def as_trial(host: Host, box: Box) -> trial.Trial:
    """The Box as something tools/trial.py can start: its own home, its own program, the Exchange folder shared,
    and the sandbox's own files in the runtime folder."""
    why = problem(host, box)
    if why:
        raise trial.TrialError(f"{box.name}'s Box can't start: {why}.")
    f = folder(host, box.slug)
    runtime = Path(host.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{host.uid}")
    runtime = runtime if str(runtime).startswith(str(host.home)) else host.sys_path(str(runtime))
    private = runtime / f"daprivacyscanner-box-{box.slug}"
    private.mkdir(mode=0o700, exist_ok=True)
    if private.is_symlink() or private.stat().st_uid != os.getuid():
        raise trial.TrialError("The Box's runtime folder isn't a folder of yours.")
    os.chmod(private, 0o700)
    exchange = f / "Exchange"
    exchange.mkdir(mode=0o700, exist_ok=True)
    return trial.Trial(os.urandom(6).hex(), f, "disk", box.kind, box.name, "a Box", argv=list(box.argv), flatpak=box.flatpak,
                       host_opt=box.host_opt, env=dict(box.env), private_at=private,
                       binds=[(str(exchange), f"{trial.sandbox.HOME_IN}/Exchange")])


def options(box: Box) -> dict:
    return {"network": box.network, "gpu": box.gpu, "sound": box.sound, "nested": False, "decoys": False}


# ------------------------------------------------------------------ what is kept of each run

def _runs_file(host: Host, slug: str) -> Path:
    return folder(host, slug) / "runs.json"


def runs(host: Host, slug: str) -> dict:
    try:
        d = json.loads(_runs_file(host, slug).read_text())
    except (OSError, ValueError, trial.TrialError):
        d = None
    if not isinstance(d, dict) or not isinstance(d.get("runs"), list) or not isinstance(d.get("hosts"), list):
        return {"salt": os.urandom(16).hex(), "hosts": [], "runs": []}
    return d


def record_run(host: Host, box: Box, t: trial.Trial) -> dict:
    """Adds the run that just ended to the Box's runs, in numbers; returns what was added. Hosts are kept as
    salted hashes only, to count the new ones next time."""
    d = runs(host, box.slug)
    r = t.result or {}
    names = [h["host"] for h in ((r.get("hosts") or {}).get("hosts") or [])]
    try:
        salt = bytes.fromhex(d.get("salt") or "")
    except ValueError:
        salt = b""
    if len(salt) != 16:
        salt = os.urandom(16)
        d = {"salt": salt.hex(), "hosts": [], "runs": d["runs"]}
    seen = set(d["hosts"])
    hashes = [hmac.new(salt, n.encode(), hashlib.sha256).hexdigest()[:16] for n in names]
    totals = (r.get("summary") or {}).get("totals") or {}
    run = {"when": round(t.started or time.time()), "seconds": r.get("seconds", 0),
           "written": totals.get("written", 0) + totals.get("created", 0), "deleted": totals.get("deleted", 0),
           "network": box.network, "hosts": len(names) if box.network == "observed" else None,
           "new_hosts": sum(1 for h in hashes if h not in seen) if box.network == "observed" else None,
           "sent": sum(h["sent"] for h in ((r.get("hosts") or {}).get("hosts") or [])) if box.network == "observed" else None,
           "failed": bool(r.get("failed")), "signal": r.get("signal")}
    d["runs"] = (d["runs"] + [run])[-RUNS_KEPT:]
    d["hosts"] = (d["hosts"] + [h for h in dict.fromkeys(hashes) if h not in seen])[-HOSTS_KEPT:]
    path = _runs_file(host, box.slug)
    tmp = path.with_suffix(".tmp")
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), "w") as fh:
        json.dump(d, fh)
    os.replace(tmp, path)
    return run


def clear_runs(host: Host, slug: str) -> None:
    try:
        _runs_file(host, slug).unlink()
    except (OSError, trial.TrialError):
        pass


def view(host: Host, box: Box, command: list[str], data_home: Path) -> dict:
    f = folder(host, box.slug)
    launcher = launcher_path(data_home, box.slug)
    try:
        current = launcher.read_text(errors="replace") == launcher_text(box, command)
    except OSError:
        current = False
    return {**box.to_dict(), "folder": host.display(f), "exchange": host.display(f / "Exchange"), "problem": problem(host, box),
            "launcher": current, "runs": runs(host, box.slug)["runs"][::-1]}


def _lock_path(host: Host, slug: str) -> Path:
    runtime = Path(host.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{host.uid}")
    runtime = runtime if str(runtime).startswith(str(host.home)) else host.sys_path(str(runtime))
    return runtime / f"daprivacyscanner-box-{slug}" / "lock"


def _try_lock(path: Path) -> int | None:
    """The lock file's descriptor, locked, or None when another process holds it (the Box runs). The lock is
    the kernel's (flock), held for as long as that process lives: a number of a process that has ended, used
    again by another, can't stand for it, and two launchers at once can't both pass."""
    import fcntl
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        return None if path.exists() else -1
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def running(host: Host, slug: str) -> bool:
    """Whether the Box runs now: its launcher's process holds the lock in the runtime folder."""
    path = _lock_path(host, slug)
    if not path.parent.is_dir():
        return False
    fd = _try_lock(path)
    if fd is None:
        return True
    if fd >= 0:
        os.close(fd)
    return False


def run_to_end(host: Host, box: Box, spawn=None, wait: float = 1.0) -> trial.Trial:
    """Starts the Box and stays until its program has ended (the launcher's own run: `--box`), then records the
    run. One run of a Box at a time."""
    import subprocess
    t = as_trial(host, box)
    fd = _try_lock(t.private / "lock")                  # held until this returns: the run is one process's
    if fd is None:
        raise trial.TrialError(f"{box.name} is already running in its Box.")
    try:
        trial.start(host, t, options(box), spawn or subprocess.Popen)
        told_to_end = None
        try:
            while t.state == "running":
                time.sleep(wait)
                trial.poll(host, t)
                if not hasattr(t.proc, "poll"):
                    trial.stop(host, t)                 # a test's stand-in: it never ends by itself
        except (SystemExit, KeyboardInterrupt) as e:   # the launcher told to end (logout, shutdown: box_cli's signals)
            told_to_end = e
            trial.stop(host, t)                         # the app with it, and the run recorded as it ended
        try:
            record_run(host, box, t)
        except OSError:                                 # the Box was removed while it ran: nothing to add to
            pass
        if told_to_end is not None:
            raise told_to_end
    finally:
        import shutil
        shutil.rmtree(t.private, ignore_errors=True)    # the sandbox's own files for this run: nothing to keep
        try:                                            # the folder bubblewrap made in the home to mount Exchange on:
            (t.home / "Exchange").rmdir()               # empty once the run ends (what the app saved there went to
        except OSError:                                 # the real Exchange); anything in it stays
            pass
        if fd >= 0:
            os.close(fd)                                # the lock goes with it (a launcher started meanwhile
    return t                                            # opened the same file and was refused)
