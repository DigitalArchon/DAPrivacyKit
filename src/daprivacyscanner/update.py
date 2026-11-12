"""Check for updates… (the owner's decisions of 2026-11-12): the one way the app looks for a newer version of itself,
and only when the user clicks it, after the page has named the hosts it contacts (design rule 10). It never runs by
itself: no timer, no check at start-up.

1. `latest`: GitHub's API is asked for the latest release (api.github.com, through online.Net: https only, no proxy,
   a generic User-Agent, nothing about this computer). Its tag must be v<version> (PEP 440, `version`), and the
   release must hold DAPrivacyKit-<version>-x86_64.AppImage and its .asc, by exact name, at the addresses GitHub's
   download page gives them; anything else is refused.
2. `download`: both files go into a hidden folder of the app's beside the running AppImage ($APPIMAGE), on the same
   filesystem so the replacement is one rename, through online.Net.download (github.com, which redirects to its file
   servers, ASSET_HOSTS: only those are followed), capped at the size the release gives; Stop ends it.
3. `verify`: Verify a download with the app's own release key alone (the `digitalarchon` project of
   signing-keys.yaml: its pinned primary and the subkeys it binds): anything but *verified* by it is
   refused and deleted. Then the version the file itself says it is: the verified file is run once with --version
   (`read_version`), under the host's environment and a timeout. A file's name says nothing (an older release,
   signed and genuine, renamed as the latest, passes the signature check), and its contents can't be read without
   running it (a zstd squashfs, which Python's standard library can't read before 3.14). That version must be the
   release's and newer than this copy's: a downgrade or the same version is refused.
4. `replace`, once the user has confirmed: the running file is kept beside it under a hidden name (`keep_path`, a
   hard link where the filesystem has them) and the new one renamed into its place, with its mode: the path stays
   the same, since timers, the Outbox's unit, the right-click entries and Boxes start the AppImage by that path.
   Refused where another account could change the file or its folder (launch.unsafe_place), or where it isn't the
   user's to change. What the new copy should remove is recorded ($XDG_STATE_HOME/daprivacyscanner/update.json),
   and the new copy removes the old one once it has started (`finish_pending`), that file and nothing else.
5. `restart` starts the new copy; the page then quits this one the usual way.

Not an AppImage (a source tree, a package someone made), or a development build: `situation` says how to update it
instead, and nothing is contacted."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import __version__, about, launch
from .host import Host

REPO = "DigitalArchon/DAPrivacyKit"
API_HOST = "api.github.com"
LATEST = f"https://{API_HOST}/repos/{REPO}/releases/latest"
DOWNLOAD_HOST = "github.com"
# GitHub hands a release's files over by redirecting github.com/<repo>/releases/download/... to its file servers:
# release-assets.githubusercontent.com (seen on 2026-11-12 for this project's releases), objects.githubusercontent.com
# before 2025. A redirect anywhere else stops the download (online.ConfinedRedirects).
ASSET_HOSTS = ("release-assets.githubusercontent.com", "objects.githubusercontent.com")
CHECK_HOSTS = (API_HOST,)
DOWNLOAD_HOSTS = (DOWNLOAD_HOST, *ASSET_HOSTS)
PROJECT = "digitalarchon"                    # signing-keys.yaml: the app's own release key
MAX_APPIMAGE = 256 * 2**20                   # 0.1.0b8's is 41 MB
MAX_SIGNATURE = 64 * 1024                    # a detached signature by two keys is under 1 KB
ROOM = 32 * 2**20                            # free room left beside the AppImage once both are there
VERSION_TIMEOUT = 60.0                       # seconds the new copy has to say its version (FUSE mount, Python's start)
RESTART_WATCH = 3.0                          # seconds a restarted copy is watched: one that stops at once is said
STAGE_PREFIX = ".DAPrivacyKit-update-"       # the hidden folder beside the AppImage, with a random part
_STAGE = re.compile(r"^\.DAPrivacyKit-update-[0-9a-f]{16}$")
_STAGED_FILE = re.compile(r"^DAPrivacyKit-[0-9A-Za-z.!+]+-x86_64\.AppImage(\.asc)?(\.part)?$")
RECORD = "update.json"


class UpdateError(Exception):
    """Why it stopped, in plain words, for the page."""


class Stopped(UpdateError):
    pass


# ------------------------------------------------------------------ versions (PEP 440)

_PEP440 = re.compile(r"^(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)(?:(?P<pre>a|b|rc)(?P<pre_n>\d+))?"
                     r"(?:\.post(?P<post>\d+))?(?:\.dev(?P<dev>\d+))?(?:\+(?P<local>[a-z0-9]+(?:\.[a-z0-9]+)*))?$")
_PRE = {"a": 0, "b": 1, "rc": 2}


@dataclass(frozen=True)
class Version:
    """A version in PEP 440's normal form (0.1.0b8, 1.0.post1, 2.0.dev3, 0.1.0b8+dev.abc): compared as PEP 440 orders
    them, a.dev < a.a1 < a.b1 < a.rc1 < a < a.post1, trailing zeros of the release ignored (1.0 == 1.0.0). `local` is
    what follows a +: a build of its own, never a release."""
    text: str
    key: tuple
    local: str = ""

    def __lt__(self, other: "Version") -> bool:
        return self.key < other.key

    def __le__(self, other: "Version") -> bool:
        return self.key <= other.key

    def __gt__(self, other: "Version") -> bool:
        return self.key > other.key

    def __ge__(self, other: "Version") -> bool:
        return self.key >= other.key

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)


def version(text: str) -> Version | None:
    m = _PEP440.match(text or "")
    if not m:
        return None
    release = tuple(int(x) for x in m["release"].split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    pre, post, dev = m["pre"], m["post"], m["dev"]
    pre_key = (-1, 0) if pre is None and post is None and dev is not None else (3, 0) if pre is None \
        else (_PRE[pre], int(m["pre_n"]))
    key = (int(m["epoch"] or 0), release, pre_key, -1 if post is None else int(post),
           math.inf if dev is None else int(dev), m["local"] or "")
    return Version(text, key, m["local"] or "")


def asset_name(v: str) -> str:
    return f"DAPrivacyKit-{v}-x86_64.AppImage"


# ------------------------------------------------------------------ the latest release

@dataclass(frozen=True)
class Release:
    version: str
    tag: str
    published: str                  # YYYY-MM-DD, as GitHub gives it
    name: str                       # the AppImage's file name
    url: str
    size: int
    sha256: str                     # GitHub's own digest of the file, "" when it gives none: a check against damage
    sig_url: str
    sig_size: int

    @property
    def page(self) -> str:
        return f"https://github.com/{REPO}/releases/tag/{self.tag}"

    def to_dict(self) -> dict:
        return {"version": self.version, "tag": self.tag, "published": self.published, "name": self.name,
                "size": self.size, "page": self.page}


def _failed(r) -> str:
    if r.status:
        return f"it answered {r.status}"
    return re.sub(r"^\[Errno -?\d+\]\s*", "", str(r.error or "")).strip().rstrip(".") or "no answer"


def latest(net) -> Release:
    """The latest release, as GitHub's API gives it, with its AppImage and signature found by their exact names.
    Raises UpdateError when it can't be told, or the release isn't one the app can take."""
    r = net.http_get(LATEST, timeout=20)
    if r.status in (403, 429):
        raise UpdateError("GitHub didn't answer the question now: it answers 60 an hour from one address, and more "
                          "may have been asked from yours. Try again in an hour.")
    if r.status == 404:
        raise UpdateError("GitHub says the project has no release yet.")
    if not r.ok:
        raise UpdateError(f"{API_HOST} couldn't be asked ({_failed(r)}). Nothing was downloaded.")
    try:
        data = json.loads(r.text())
        tag, assets = data["tag_name"], data["assets"]
        if not isinstance(tag, str) or not isinstance(assets, list):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        raise UpdateError("GitHub's answer couldn't be read. Nothing was downloaded.") from None
    v = version(tag[1:]) if tag.startswith("v") else None
    if v is None or v.local:
        raise UpdateError(f"The latest release's tag ({tag[:40]}) isn't v<version>, as the project's are. Nothing was "
                          "downloaded.")
    if data.get("draft") is not False or data.get("prerelease") is not False:
        raise UpdateError("GitHub's latest release is marked as a draft or a pre-release. Nothing was downloaded.")
    by_name: dict[str, dict] = {}
    for a in assets:
        if isinstance(a, dict) and isinstance(a.get("name"), str):
            by_name.setdefault(a["name"], a)
    name = asset_name(v.text)

    def asset(n: str, cap: int) -> tuple[str, int, str]:
        a = by_name.get(n)
        if a is None:
            raise UpdateError(f"The latest release ({tag}) has no {n}, so it can't be checked and put in place here. "
                              "Nothing was downloaded.")
        size, url = a.get("size"), a.get("browser_download_url")
        want = f"https://{DOWNLOAD_HOST}/{REPO}/releases/download/{tag}/{n}"
        if a.get("state") != "uploaded" or not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= cap:
            raise UpdateError(f"{n} on the latest release isn't a file of the size the app expects. Nothing was "
                              "downloaded.")
        if url != want:
            raise UpdateError(f"GitHub names {n} at an address the app doesn't expect. Nothing was downloaded.")
        digest = a.get("digest")
        digest = digest[7:].lower() if isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest) else ""
        return url, size, digest

    url, size, digest = asset(name, MAX_APPIMAGE)
    sig_url, sig_size, _ = asset(name + ".asc", MAX_SIGNATURE)
    published = data.get("published_at")
    published = published[:10] if isinstance(published, str) and re.match(r"\d{4}-\d\d-\d\d", published) else ""
    return Release(v.text, tag, published, name, url, size, digest, sig_url, sig_size)


def compare(latest_version: str, current: str = __version__) -> str:
    """"newer" (the release is newer than this copy), "same" or "older"."""
    a, b = version(latest_version), version(current)
    if a is None or b is None:
        return "older"
    return "newer" if a > b else "same" if a == b else "older"


# ------------------------------------------------------------------ this copy

def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def dev_build(environ, current: str = __version__) -> bool:
    """A development build, which no release replaces: built by packaging/build-appimage.sh dev (about.dev_build: its
    _built.py records the version with +dev.<commit>, and so does its file name, DAPrivacyKit-<version>+dev.<commit>),
    or any version with a local part (+...)."""
    v = version(current)
    name = os.path.basename(environ.get("APPIMAGE") or "")
    return v is None or bool(v.local) or "+dev." in name or about.dev_build()


def replace_problem(host: Host, path: Path) -> str:
    """Why the AppImage at `path` can't be replaced by this copy ("" when it can): it isn't a plain file of the user's,
    another account could change it or a folder it is in (launch.unsafe_place: whoever could would have their program
    run by every timer and right-click entry that starts it), or the user can't write its folder."""
    try:
        st = os.lstat(path)
    except OSError as e:
        return f"{path} can't be looked at ({e.strerror or e}), so it can't be replaced."
    if not stat.S_ISREG(st.st_mode):
        return f"{path} isn't a plain file, so it isn't replaced."
    unsafe = launch.unsafe_place(str(path), host.uid)
    if unsafe:
        return (f"{unsafe} So the app doesn't put a new copy there: move the AppImage into a folder of your own (such as "
                "~/Applications), start it from there and check again.")
    if st.st_uid != host.uid:
        return (f"{path} belongs to another account (an administrator put it there?), so it isn't yours to replace: "
                "update it the way it was installed.")
    if not os.access(path.parent, os.W_OK | os.X_OK):
        return (f"You can't change the folder it is in ({path.parent}), so it can't be replaced there. Download the "
                "new one from the releases page, or move this one into a folder of your own and check again.")
    return ""


def started_from(environ=os.environ) -> tuple | None:
    """The identity of the AppImage file this copy was started from, read as the app starts (the runtime opened it a
    moment before): another window of the app may replace it later, and this copy is then no longer the file there."""
    appimage = environ.get("APPIMAGE")
    try:
        return _identity(os.stat(appimage)) if appimage else None
    except OSError:
        return None


def situation(host: Host, current: str = __version__, repo: Path | None = None, started: tuple | None = None) -> dict:
    """What this copy is and how it updates, before anything is contacted: "appimage" (this dialog downloads and
    replaces it; `problem` when it can't be replaced where it is), "dev" (a development build), "source" (a source
    tree: git), or "package" (installed some other way: its package manager). `started`: started_from(), when known:
    a file there that isn't it any more was put there since (another window updated it)."""
    appimage = host.environ.get("APPIMAGE") or ""
    out: dict = {"version": current, "path": None, "problem": "", "how": [], "commands": [],
           "hosts": {"check": list(CHECK_HOSTS), "download": list(DOWNLOAD_HOSTS)},
           "releases": about.LINKS["releases"]}
    if appimage and os.path.isfile(appimage):
        path = Path(os.path.realpath(appimage))
        out["path"] = str(path)
        if dev_build(host.environ, current):
            out.update(mode="dev", how=[
                "This is a development build (built with packaging/build-appimage.sh dev, or carrying a local "
                "version), which no release replaces: build a new one from the source, or download a release from "
                "the releases page."])
            return out
        out.update(mode="appimage", problem=replace_problem(host, path))
        rec = load_pending(host)
        by = rec["to"] if rec is not None and rec["path"] == str(path) else ""     # the version another window put there
        try:
            moved = started is not None and _identity(os.stat(path)) != started
        except OSError:
            moved = False
        if not out["problem"] and (moved or by and by != current):
            out["problem"] = (f"{path} has been replaced since this window started"
                              + (f", by version {by}" if by and by != current else "")
                              + " (another window of the app updated it?). Quit this window and start the app again.")
        return out
    repo = _repo() if repo is None else repo
    if (repo / "pyproject.toml").is_file() and (repo / "src" / "daprivacyscanner").is_dir():
        if (repo / ".git").exists():
            out.update(mode="source", how=[f"It runs from a source tree, {repo}: update it with git there."],
                       commands=[f"git -C {shlex.quote(str(repo))} pull --ff-only"])
        else:
            out.update(mode="source", how=[f"It runs from a copy of the source, {repo}, that isn't a git clone: "
                                           "download the new source, or use the AppImage from the releases page."])
        return out
    out.update(mode="package", how=["It was installed as a package (by pip, or a package someone made), not as the "
                                    "AppImage: update it the way it was installed, with that package manager."])
    return out


# ------------------------------------------------------------------ downloading and checking it

@dataclass
class Staged:
    """A downloaded release beside the AppImage, in a hidden folder of the app's own."""
    folder: Path
    release: Release
    target: Path                              # the AppImage it would replace (its real path)
    target_id: tuple                          # (device, inode, size, mtime) of that file when the download began
    sha256: str = ""                          # of the verified file: set once verified
    inside: str = ""                          # the version the file says it is
    verdict: dict = field(default_factory=dict)

    @property
    def file(self) -> Path:
        return self.folder / self.release.name

    @property
    def signature(self) -> Path:
        return self.folder / (self.release.name + ".asc")


def _identity(st: os.stat_result) -> tuple:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _sha256(path: Path) -> str:
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def download(host: Host, net, rel: Release, job: dict, stop: Callable[[], bool]) -> Staged:
    """The release's AppImage and signature, into a new hidden folder beside the running AppImage (0700). On any
    failure, or Stop, nothing of it is left."""
    target = Path(os.path.realpath(host.environ.get("APPIMAGE") or ""))
    problem = replace_problem(host, target) if host.environ.get("APPIMAGE") else "This copy isn't an AppImage."
    if problem:
        raise UpdateError(problem)
    st = os.stat(target)
    free = shutil.disk_usage(target.parent).free
    if rel.size + rel.sig_size + ROOM > free:
        raise UpdateError(f"There isn't room for it beside this copy, in {target.parent} ({free // 2**20} MB free, "
                          f"{(rel.size + ROOM) // 2**20} MB needed). Nothing was downloaded.")
    folder = target.parent / f"{STAGE_PREFIX}{secrets.token_hex(8)}"
    os.mkdir(folder, 0o700)
    staged = Staged(folder, rel, target, _identity(st))

    def progress(done: int, total: int | None) -> None:
        job.update(done=done, total=total or 0)
    try:
        for url, path, size, what in ((rel.sig_url, staged.signature, rel.sig_size, "signature"),
                                      (rel.url, staged.file, rel.size, "AppImage")):
            job.update(phase=f"Downloading the {what} from {DOWNLOAD_HOST}", done=0, total=size)
            part = path.with_name(path.name + ".part")
            r = net.download(url, part, progress=progress, stop=stop, limit=size, timeout=60.0, hosts=ASSET_HOSTS)
            if stop():
                raise Stopped("Stopped: nothing was kept, and nothing was replaced.")
            if not r.ok:
                raise UpdateError(f"The {what} couldn't be downloaded ({_failed(r)}). Nothing was replaced.")
            got = part.stat().st_size
            if got != size:
                raise UpdateError(f"The {what} arrived with {got} bytes, not the {size} GitHub said. Nothing was "
                                  "replaced.")
            os.replace(part, path)
        if rel.sha256:
            job.update(phase="Comparing it with GitHub's own checksum", done=0, total=0)
            if _sha256(staged.file) != rel.sha256:
                raise UpdateError("It was damaged on the way: its SHA-256 isn't the one GitHub gives for it. It was "
                                  "deleted, and nothing was replaced.")
    except BaseException:
        discard(staged)
        raise
    return staged


def read_version(host: Host, path: Path) -> str:
    """The version the AppImage at `path` says it is: it is run once with --version (app.py prints "DA Privacy Kit
    <version>" and ends before anything else), as the user, under the host's environment, for at most
    VERSION_TIMEOUT seconds. Only ever on a file whose signature has been verified as the app's own release key's.
    AppImageLauncher, where it is installed, runs every AppImage started through binfmt_misc and first asks whether to
    integrate it: APPIMAGELAUNCHER_DISABLE has it run the file as it is, with no question (VERIFY on a machine with
    AppImageLauncher)."""
    os.chmod(path, 0o700)
    env = {"APPIMAGELAUNCHER_DISABLE": "1"}
    if host.environ.get("APPIMAGE_EXTRACT_AND_RUN") == "1":
        env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    r = host.run(str(path), "--version", timeout=VERSION_TIMEOUT, env=env)
    lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    m = re.fullmatch(r"DA Privacy Kit (\S{1,64})", lines[-1]) if r.ok and lines else None
    if m is None or version(m.group(1)) is None:
        why = f"exit status {r.returncode}" if not r.ok else "it printed no version"
        raise UpdateError(f"Its version couldn't be read from the file itself ({why}): an older release, which has "
                          "no --version, can look like this. It was deleted, and nothing was replaced.")
    return m.group(1)


def verify(host: Host, staged: Staged, current: str = __version__, projects=None, job: dict | None = None) -> dict:
    """Verify a download on the staged file with the app's own release key alone, then the version it says it is.
    Raises UpdateError unless it is verified, its version is the release's, and that is newer than this copy's."""
    from .tools import keys as K
    from .tools import verify as V
    ours = [p for p in (K.load() if projects is None else projects) if p.id == PROJECT]
    if not ours:
        raise UpdateError("The app's own release key isn't in its list of keys, so nothing can be verified.")
    if job is not None:
        job.update(phase=f"Checking its signature with {ours[0].name}'s release key", done=0, total=0)
    before = _sha256(staged.file)                    # the same bytes are verified, run and put in place (below)
    v = V.verify(host, staged.file, [], "", use_keyring=False, projects=ours)
    good = [s for s in v.signatures if s.good and s.project is not None and s.project.id == PROJECT
            and s.over == staged.file and not s.inside]
    if v.level != "verified" or not good:
        install = next((s.install for s in v.signatures if s.install), "")
        raise UpdateError(f"The download isn't verified ({v.title}" + (f": {v.text}" if v.text else "") + "). It was "
                          "deleted, and nothing was replaced." + (f" To check signatures, install gpgv: {install}"
                                                                  if install else ""))
    s = good[0]
    if s.signed_at and s.signed_at > time.time() + 86400:
        raise UpdateError("Its signature is dated in the future, which a release's never is (or this computer's clock "
                          "is wrong). It was deleted, and nothing was replaced.")
    if job is not None:
        job.update(phase="Reading the version inside it")
    inside = read_version(host, staged.file)
    if inside != staged.release.version:
        raise UpdateError(f"The file says it is version {inside}, not {staged.release.version} as the release does. "
                          "It was deleted, and nothing was replaced.")
    if compare(inside, current) != "newer":
        raise UpdateError(f"The file is version {inside}, which isn't newer than this copy ({current}). It was "
                          "deleted, and nothing was replaced.")
    if _sha256(staged.file) != before:
        raise UpdateError("The download changed while it was checked. It was deleted, and nothing was replaced.")
    staged.sha256, staged.inside = before, inside
    staged.verdict = {"title": v.title, "text": v.text, "signer": ours[0].name, "key_name": s.key_name,
                      "fingerprint": s.fingerprint, "fingerprint_grouped": K.group(s.fingerprint)
                      if re.fullmatch(r"[0-9A-F]{40}", s.fingerprint) else s.fingerprint,
                      "signed_at": s.signed_at, "notes": list(v.notes), "version": inside, "sha256": staged.sha256}
    return staged.verdict


def discard(staged: Staged | None) -> None:
    """The staged files and their folder, removed: only the names the app gave them (`_STAGED_FILE`), and the folder
    only once it is empty."""
    if staged is None:
        return
    _remove_stage(staged.folder)


def _remove_stage(folder: Path) -> bool:
    try:
        st = os.lstat(folder)
    except FileNotFoundError:
        return True
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or not _STAGE.match(folder.name):
        return False
    try:
        names = os.listdir(folder)
    except OSError:
        return False
    for n in names:
        p = folder / n
        try:
            if _STAGED_FILE.match(n) and stat.S_ISREG(os.lstat(p).st_mode):
                os.unlink(p)
        except OSError:
            pass
    try:
        os.rmdir(folder)
        return True
    except OSError:
        return False


def tidy(host: Host, keep: Path | None = None) -> int:
    """Staging folders a copy of the app left beside the AppImage (it ended while downloading, or before the user
    confirmed): removed as discard does, but the one in `keep`. The caller holds the update lock (owner.hold), so no
    other copy has one in hand. How many were removed."""
    appimage = host.environ.get("APPIMAGE")
    if not appimage:
        return 0
    parent = Path(os.path.realpath(appimage)).parent
    n = 0
    try:
        names = os.listdir(parent)
    except OSError:
        return 0
    for name in names:
        if _STAGE.match(name) and (keep is None or parent / name != keep):
            n += _remove_stage(parent / name)
    return n


# ------------------------------------------------------------------ putting it in place

def keep_path(target: Path, current: str = __version__) -> Path:
    """Where the running copy is kept until the new one has started: hidden, beside it, named by its version."""
    return target.with_name(f".{target.name}.{current}.old")


def _q(p) -> str:
    return shlex.quote(str(p))


def plan(staged: Staged, current: str = __version__) -> dict:
    """The confirm step: what replacing does, with the exact paths, the commands that would do the same by hand, and
    how to go back."""
    st = os.stat(staged.target)
    mode = (stat.S_IMODE(st.st_mode) & 0o777) | 0o100
    keep = keep_path(staged.target, current)
    return {"version": staged.inside, "from": current, "path": str(staged.target), "keep": str(keep),
            "staged": str(staged.file), "signature": str(staged.signature), "mode": f"{mode:04o}",
            "folder": str(staged.folder), "verdict": staged.verdict, "release": staged.release.to_dict(),
            "commands": [f"chmod {mode:04o} {_q(staged.file)}", f"ln {_q(staged.target)} {_q(keep)}",
                         f"mv -f {_q(staged.file)} {_q(staged.target)}"],
            "check": [f"gpg --verify {_q(staged.signature)} {_q(staged.file)}", f"{_q(staged.file)} --version"],
            "back": [f"mv -f {_q(keep)} {_q(staged.target)}"]}


def _record_path(host: Host) -> Path:
    from .paths import PathResolver
    return PathResolver(host.home, host.environ).state_home / "daprivacyscanner" / RECORD


def load_pending(host: Host) -> dict | None:
    try:
        data = json.loads(_record_path(host).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ok = isinstance(data, dict) and all(isinstance(data.get(k), str) for k in ("path", "keep", "from", "to")) \
        and isinstance(data.get("keep_id"), list) and isinstance(data.get("new_id"), list)
    return data if ok else None


def _drop_pending(host: Host) -> None:
    try:
        _record_path(host).unlink()
    except OSError:
        pass


def _sync_folder(folder: Path) -> None:
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def replace(host: Host, staged: Staged, current: str = __version__) -> dict:
    """The verified file in place of the running AppImage, once the user has confirmed: the running file kept beside it
    (keep_path), the new one renamed into its place with its mode. Refused when either has changed since it was
    checked. What the new copy is to remove when it starts is recorded."""
    from .history import write_json
    target = staged.target
    problem = replace_problem(host, target)
    if problem:
        raise UpdateError(problem)
    st = os.stat(target)
    if _identity(st) != staged.target_id:
        raise UpdateError(f"{target} has changed since the download began (another window of the app may have updated "
                          "it). Nothing was replaced: close this dialog and check again.")
    try:
        fst = os.lstat(staged.file)
    except OSError:
        raise UpdateError("The download is gone. Nothing was replaced: check again.") from None
    if not stat.S_ISREG(fst.st_mode) or fst.st_uid != host.uid or not staged.sha256 \
            or _sha256(staged.file) != staged.sha256:
        raise UpdateError("The download has changed since it was verified. Nothing was replaced: check again.")
    keep = keep_path(target, current)
    if os.path.lexists(keep):
        raise UpdateError(f"{keep} is there already (an earlier update's old copy?). Nothing was replaced: put it "
                          "back, or delete it, and try again.")
    mode = (stat.S_IMODE(st.st_mode) & 0o777) | 0o100
    os.chmod(staged.file, mode)
    try:
        os.link(target, keep, follow_symlinks=False)
        linked = True
    except FileExistsError:
        raise UpdateError(f"{keep} is there already. Nothing was replaced.") from None
    except OSError as e:
        if e.errno not in (errno.EPERM, errno.EXDEV, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EMLINK, errno.ENOSYS):
            raise
        linked = False                                   # no hard links here (a FAT or exFAT drive): two renames
    if linked:
        try:
            os.replace(staged.file, target)              # one rename: the path holds the old copy, then the new one
        except OSError:
            os.unlink(keep)                              # nothing changed: the second name of the old copy goes
            raise
    else:
        os.rename(target, keep)
        try:
            os.rename(staged.file, target)
        except OSError:
            os.rename(keep, target)
            raise
    _sync_folder(target.parent)
    kst, nst = os.lstat(keep), os.lstat(target)
    record = {"path": str(target), "keep": str(keep), "from": current, "to": staged.inside,
              "keep_id": list(_identity(kst)), "new_id": list(_identity(nst)), "when": int(time.time())}
    out = {"path": str(target), "keep": str(keep), "from": current, "to": staged.inside, "mode": f"{mode:04o}",
           "back": [f"mv -f {_q(keep)} {_q(target)}"], "note": ""}
    try:
        write_json(_record_path(host), record)
    except OSError as e:
        out["note"] = (f"The app couldn't note down that the new copy is to remove the old one ({e.strerror or e}): "
                       f"once the new one works, delete {keep} yourself.")
    discard(staged)
    return out


def finish_pending(host: Host, current: str = __version__) -> dict | None:
    """At the new copy's start (its page loaded): the old copy an update kept beside it is removed, that file alone
    (the recorded name, a plain file of the user's, the same device, inode, size and time: an inode number is used
    again for the next file made), and the record with it. Nothing when this isn't
    the copy the update put in place: the old one running again (Later), or another AppImage. What was done, or None."""
    rec = load_pending(host)
    appimage = host.environ.get("APPIMAGE")
    if rec is None or not appimage:
        return None
    path, keep = Path(rec["path"]), Path(rec["keep"])
    if os.path.realpath(appimage) != str(path):
        return None
    try:
        kst = os.lstat(keep)
    except FileNotFoundError:
        _drop_pending(host)                              # put back by hand, or removed: nothing left to do
        return None
    except OSError:
        return None
    if current != rec["to"]:
        return None                                      # the old copy, still or again: its kept file stays
    ours = (keep.parent == path.parent and keep.name.startswith(".") and keep.name.endswith(".old")
            and stat.S_ISREG(kst.st_mode) and kst.st_uid == host.uid and list(_identity(kst)) == rec["keep_id"])
    out = {"from": rec["from"], "to": rec["to"], "kept": str(keep), "removed": False}
    if ours:
        try:
            os.unlink(keep)
            out["removed"] = True
        except OSError:
            return out                                   # tried again at the next start
    _drop_pending(host)
    return out


def restart(host: Host, spawn: Callable = subprocess.Popen, browser: bool = False) -> None:
    """Starts the copy the update put in place (the same path), as the user started this one; the page then quits this
    one. Refused when the file there isn't the one the update put there; one that stops within RESTART_WATCH seconds
    is said, and this copy goes on."""
    from .hostenv import host_env
    rec = load_pending(host)
    appimage = host.environ.get("APPIMAGE")
    if rec is None or not appimage or os.path.realpath(appimage) != rec["path"]:
        raise UpdateError("No update is waiting to be started.")
    try:
        st = os.stat(rec["path"])
    except OSError as e:
        raise UpdateError(f"{rec['path']} can't be found ({e.strerror or e}).") from None
    if list(_identity(st)) != rec["new_id"]:
        raise UpdateError(f"{rec['path']} isn't the file the update put there any more, so it isn't started.")
    env = host_env(host.environ)
    if host.environ.get("APPIMAGE_EXTRACT_AND_RUN") == "1":
        env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    p = spawn([rec["path"]] + (["--browser"] if browser else []), env=env, cwd=str(host.home),
              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + RESTART_WATCH
    while time.monotonic() < deadline:
        code = p.poll()
        if code is not None:
            raise UpdateError(f"The new copy stopped at once (exit status {code}), so this one stays open. The old "
                              f"copy is kept as {rec['keep']}; to put it back: mv -f {_q(rec['keep'])} {_q(rec['path'])}")
        time.sleep(0.1)
