"""The undo log: every applied fix, with what each step changed, so it can be reverted from
the UI. Kept in $XDG_STATE_HOME/daprivacyscanner (0700), written atomically and on the disk before it counts (fsync), each
change made under the state folder's lock (the window, scheduled scans and other copies of the app write it too).

A fix is recorded before it is applied (write-ahead, fix.apply_plan): its entry is "applying" while its steps run, each
step's record added as it completes, then "applied" or "failed". One whose process is gone while it still says
"applying" was interrupted (killed, out of memory, a power cut): History shows it so, revertible for the steps it
records."""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from .fix import ACTION_KINDS, IRREVERSIBLE_KINDS, ROOT_KINDS, fsync_dir, make_writable
from .history import locked
from .host import Host
from .paths import PathResolver

UNREADABLE = "undo.json.unreadable-"      # a log that couldn't be read, kept aside under this name and the time
APPLYING, INTERRUPTED = "applying", "interrupted"


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _started(pid: int) -> str:
    """When the process started (clock ticks since boot, /proc/PID/stat's 22nd field): with the boot id, what tells
    the process that wrote an entry from a later one given the same number. "" when it isn't running."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    fields = text[text.rfind(")") + 2:].split()
    return fields[19] if len(fields) > 19 else ""


def owner_now() -> dict:
    """This process, as an "applying" entry names the one applying it."""
    pid = os.getpid()
    return {"pid": pid, "started": _started(pid), "boot": _boot_id()}


def _alive(owner: dict | None) -> bool:
    if not isinstance(owner, dict) or not isinstance(owner.get("pid"), int):
        return False
    if owner.get("boot") and owner["boot"] != _boot_id():
        return False                                    # the computer was restarted since
    started = _started(owner["pid"])
    return bool(started) and started == owner.get("started")


class UndoLog:
    def __init__(self, directory: Path):
        self.dir = directory
        self.file = directory / "undo.json"
        # what the file keeps beside its entries ("forgotten": the helper's change ids of entries forgotten), carried
        # over by every save made under the lock after a load
        self._kept: dict = {}

    @classmethod
    def for_user(cls, paths: PathResolver) -> "UndoLog":
        return cls(paths.state_home / "daprivacyscanner")

    def backup_dir(self, entry_id: str) -> Path:
        return self.dir / "backups" / entry_id

    def entries(self) -> list[dict]:
        """The entries as saved; none from a log that can't be read (`damaged` says so)."""
        try:
            return self._parse(self.file.read_text(encoding="utf-8"))[0]
        except FileNotFoundError:
            return []
        except (OSError, ValueError, RecursionError):
            return []

    @staticmethod
    def _parse(text: str) -> tuple[list[dict], dict]:
        data = json.loads(text)
        if not isinstance(data, dict) or not isinstance(data.get("entries", []), list):
            raise ValueError("not an undo log")
        entries = data.get("entries", [])
        if not all(isinstance(e, dict) and isinstance(e.get("id"), str) and isinstance(e.get("records"), list)
                   for e in entries):
            raise ValueError("not an undo log")
        return entries, {k: v for k, v in data.items() if k not in ("version", "entries")}

    def get(self, entry_id: str) -> dict | None:
        return next((e for e in self.entries() if e["id"] == entry_id), None)

    def _load(self) -> list[dict]:
        """The entries, for a change made under the lock. A log that can't be read (not JSON, not an undo log, not text,
        or an error reading it) is kept aside, renamed and never written over (it may be the only record of changes
        still in place), and the log starts again: before, the next fix saved itself over it, alone, and History was
        empty without a word."""
        try:
            entries, self._kept = self._parse(self.file.read_text(encoding="utf-8"))
            return entries
        except FileNotFoundError:
            self._kept = {}
            return []
        except (OSError, ValueError, RecursionError):
            stamp, n = time.strftime("%Y%m%d-%H%M%S"), 0
            aside = self.dir / f"{UNREADABLE}{stamp}"
            while os.path.lexists(aside):
                n += 1
                aside = self.dir / f"{UNREADABLE}{stamp}-{n}"
            os.rename(self.file, aside)
            self._kept = {}
            return []

    def _save(self, entries: list[dict]) -> None:
        """The log written whole, through a temporary file of this write's own, on the disk before it is renamed into
        place and the folder after (fsync): an empty undo.json after a power cut would lose every revert."""
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)
        fd, tmp = tempfile.mkstemp(prefix=".undo.json.", suffix=".tmp", dir=self.dir)
        try:
            with open(fd, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "entries": entries, **self._kept}, f, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.file)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        fsync_dir(self.dir)

    def damaged(self, host: Host | None = None) -> str:
        """What History says when its log couldn't be read: the log itself, or the copies kept aside; "" otherwise."""
        shown = host.display if host is not None else str
        try:
            self._parse(self.file.read_text(encoding="utf-8"))
            unreadable = False
        except FileNotFoundError:
            unreadable = False
        except (OSError, ValueError, RecursionError):
            unreadable = True
        kept = sorted(self.dir.glob(f"{UNREADABLE}*")) if self.dir.is_dir() else []
        said = []
        if unreadable:
            said.append(f"History's file, {shown(self.file)}, can't be read, so the fixes in it aren't listed here. It "
                        "is kept as it is: the next fix starts a new one beside it.")
        if kept:
            said.append(f"History's file couldn't be read, so it was kept aside ({', '.join(shown(k) for k in kept)}): "
                        "only what was applied since is listed here.")
        if said:
            said.append("The changes in it stay as they are; they can't be reverted from here. Forget everything "
                        "deletes it.")
        return " ".join(said)

    def add(self, entry_id: str, check_id: str, title: str, records: list[dict], state: str = "applied",
            extra: dict | None = None) -> dict:
        """`extra`: how the plan was offered (`via`, FixPlan.via) and, for a failed attempt, its `error` and
        the step it failed at (`failed_step`)."""
        entry = {"id": entry_id, "check_id": check_id, "title": title, "applied": time.time(), "state": state,
                 "records": records, **{k: v for k, v in (extra or {}).items() if v not in (None, "", {})}}
        with locked(self.dir):
            self._save(self._load() + [entry])
        return entry

    # ------------------------------------------------------------ write-ahead (fix.apply_plan)

    def begin(self, entry_id: str, check_id: str, title: str, extra: dict | None = None) -> dict:
        """The entry of a plan about to be applied, written before its first step: "applying", by this process."""
        return self.add(entry_id, check_id, title, [], state=APPLYING, extra={**(extra or {}), "owner": owner_now()})

    def _change(self, entry_id: str, fn) -> None:
        with locked(self.dir):
            entries = self._load()
            for e in entries:
                if e["id"] == entry_id:
                    fn(e)
            self._save(entries)

    def progress(self, entry_id: str, records: list[dict]) -> None:
        """The steps done so far (and the one under way), as they are now."""
        self._change(entry_id, lambda e: e.__setitem__("records", [dict(r) for r in records]))

    def finish(self, entry_id: str, state: str, records: list[dict], extra: dict | None = None) -> None:
        """The plan done: applied, or failed (with its `error` and `failed_step`)."""
        def done(e):
            e.update({"state": state, "records": [dict(r) for r in records],
                      **{k: v for k, v in (extra or {}).items() if v not in (None, "", {})}})
            e.pop("owner", None)
        self._change(entry_id, done)

    def discard(self, entry_id: str) -> None:
        """An attempt that changed nothing: no entry is left."""
        with locked(self.dir):
            entries = self._load()
            self._save([e for e in entries if e["id"] != entry_id])

    @staticmethod
    def applying(entry: dict) -> bool:
        """Being applied now, by a process that is still running (this window or another copy of the app)."""
        return entry.get("state") == APPLYING and _alive(entry.get("owner"))

    @staticmethod
    def state_of(entry: dict) -> str:
        """The entry's state as History shows it: "interrupted" for one still "applying" whose process is gone."""
        if entry.get("state") == APPLYING and not _alive(entry.get("owner")):
            return INTERRUPTED
        return entry.get("state", "applied")

    # ------------------------------------------------------------ later changes of the same things

    @staticmethod
    def resources(record: dict) -> set[str]:
        """What a step changed that is still in place (fix's Action.resources): none once it is reverted, or for a step
        with nothing to put back."""
        if not UndoLog.can_undo(record) or record.get("reverted"):
            return set()
        kind = ACTION_KINDS.get(record["kind"])
        try:
            return set(kind.resources(record)) if kind else set()
        except (KeyError, TypeError):
            return set()

    def blocking(self, entry: dict) -> list[dict]:
        """The entries applied after this one that changed one of the same settings or files and are still in place,
        newest first ({"id", "title", "applied", "what": the steps of theirs}): this one can be reverted only after
        them."""
        entries = self.entries()
        at = next((i for i, e in enumerate(entries) if e["id"] == entry["id"]), None)
        if at is None:
            return []
        mine = set().union(*(self.resources(r) for r in entry["records"])) if entry["records"] else set()
        out = []
        for later in reversed(entries[at + 1:]):
            if not mine or later.get("state") == "reverted":
                continue
            what = [UndoLog.describe(r) for r in later["records"] if self.resources(r) & mine]
            if what:
                out.append({"id": later["id"], "title": later["title"], "applied": later["applied"], "what": what})
        return out

    # ------------------------------------------------------------ the helper's own record of its changes

    def reconcile(self, privileged) -> int:
        """History brought into line with the administrator helper's record of this user's changes (fix.helper_changes;
        nothing from a helper that can't list them): a root step whose answer never came settled (made, never made, or
        reverted), and a change the helper made that no entry knows of (the app stopped before it could record it, or
        History's file was lost) taken up as an entry of its own, revertible from History. Never one whose entry was
        forgotten, nor a step of a plan still being applied. Returns how many records changed or were added."""
        from .fix import RootChange, helper_changes
        changes = helper_changes(privileged)
        if changes is None:
            return 0
        n = 0
        with locked(self.dir):
            entries = self._load()
            known = {r.get("change_id") for e in entries for r in e["records"]} | set(self._kept.get("forgotten") or [])
            for e in entries:
                if self.applying(e):
                    continue
                touched = False
                for r in e["records"]:
                    if r["kind"] in ROOT_KINDS and r.get("outcome") == "unknown" and r.get("change_id"):
                        if RootChange.settle(r, changes.get(r["change_id"])):
                            touched = True
                if touched:
                    n += 1
                    self._restate(e)
            for cid, c in sorted(changes.items(), key=lambda kv: kv[1].get("time") or 0):
                if cid in known or c["state"] not in ("applied", "intent"):
                    continue
                text = str(c.get("text") or c.get("action") or "a change made as administrator")[:300]
                rec = {"kind": "root", "change_id": cid, "text": text, "ran": [], "files": [], "lines": [], "dirs": [],
                       "recovered": True, **({"outcome": "unknown"} if c["state"] == "intent" else {})}
                entries.append({"id": cid, "check_id": "", "title": f"Recovered: {text}",
                                "applied": c.get("time") if isinstance(c.get("time"), (int, float)) else time.time(),
                                "state": "applied", "recovered": True, "records": [rec]})
                n += 1
            if n:
                self._save(entries)
        return n

    @staticmethod
    def _restate(entry: dict) -> None:
        """An entry's state once a step of it is settled: an interrupted or failed one stays as it is."""
        if entry.get("state") not in ("applied", "partly reverted"):
            return
        reversible = [r for r in entry["records"] if UndoLog.can_undo(r)]
        if reversible and all(r.get("reverted") for r in reversible):
            entry["state"] = "reverted"
            entry.setdefault("reverted", time.time())

    def update(self, entry: dict) -> None:
        reversible = [r for r in entry["records"] if UndoLog.can_undo(r)]
        put_back = lambda e: sum(bool(r.get("reverted")) for r in e["records"])  # noqa: E731
        with locked(self.dir):
            entries = self._load()
            if put_back(entry) > put_back(next((e for e in entries if e["id"] == entry["id"]), {"records": []})):
                entry["last_reverted"] = time.time()   # a revert put some of it back (all, or part): undone() goes by it
            if reversible and all(r.get("reverted") for r in reversible):
                entry["state"] = "reverted"
                entry["reverted"] = time.time()
                entry.pop("owner", None)
            elif any(r.get("reverted") for r in reversible):
                entry["state"] = "partly reverted"
                entry.pop("owner", None)
            self._save([entry if e["id"] == entry["id"] else e for e in entries])

    def set_outcome(self, entry_id: str, result: dict | None) -> None:
        """The check's result just after the fix was applied (the rescan): a later scan that finds
        the problem back, when this one had it resolved, means the fix was undone."""
        if not result:
            return
        with locked(self.dir):
            entries = self._load()
            for e in entries:
                if e["id"] == entry_id:
                    e["outcome"] = {"status": result.get("status"), "severity": result.get("effective_severity", 0),
                                    "at": time.time()}
            self._save(entries)

    def undone(self, results: dict, accepted: dict | None = None, host: Host | None = None) -> list[dict]:
        """Fixes the user applied whose problem is back: the check was resolved just after the fix (it
        passed: one that couldn't be checked then wasn't seen resolved), and is a finding again now. Not
        those reverted from History, even in part, nor any whose check had one of its fixes reverted since
        (the user brought the problem back), and not a finding the user has since accepted. Each names the
        steps whose settings no longer hold what the fix set (read now, when `host` is given). The latest
        fix per check. The log notes when each was first found undone, and forgets it once the problem is
        gone again."""
        from .fix import ACTION_KINDS
        from .history import ACTIVE, hidden
        accepted = accepted or {}
        # findings only: caches and histories (hygiene) grow back after a clean-up as a matter of course
        active = lambda r: bool(r) and r.get("status") in ACTIVE and r.get("effective_severity", 0) > 0 \
            and r.get("kind", "finding") == "finding"  # noqa: E731
        # nor fixes that only deleted files or ran commands: nothing of theirs can be changed back,
        # and what they removed comes back with use (thumbnails of pictures deleted since)
        nothing_to_undo = lambda e: bool(e["records"]) and all(  # noqa: E731
            rec["kind"] in IRREVERSIBLE_KINDS for rec in e["records"])
        # read without the lock, since reading what was changed back runs programs (gsettings): only the marks found
        # are saved, into the log as it is by then (another copy of the app may have added a fix meanwhile)
        entries, out, seen = self.entries(), [], set()
        marks: dict[str, float | None] = {}
        # when each check last had one of its fixes reverted from History, even in part
        reverted_at: dict[str, float] = {}
        for e in entries:
            t = e.get("last_reverted") or e.get("reverted")
            if t:
                reverted_at[e["check_id"]] = max(t, reverted_at.get(e["check_id"], t))
        for e in reversed(entries):
            o = e.get("outcome")
            if e["state"] != "applied" or not o or e["check_id"] in seen or nothing_to_undo(e):
                if "undone_since" in e:                         # reverted, or a later fix of the same check
                    marks[e["id"]] = None
                continue
            r = results.get(e["check_id"])
            if r is None:                                   # not scanned this time: say nothing either way
                continue
            seen.add(e["check_id"])
            # an outcome of unknown or error resolved nothing (the rescan after an online test's guide can't run it)
            was_fixed = o.get("status") in ("pass", "not_applicable") or (o.get("status") in ACTIVE
                                                                         and not o.get("severity"))
            # a fix of this check reverted since this one's outcome (step 1 of a guide whose step 2 this is): the
            # problem is back because the user put it back
            reverted_since = e["check_id"] in reverted_at and reverted_at[e["check_id"]] >= o.get("at", 0)
            if not (was_fixed and active(r)) or reverted_since or hidden(accepted, e["check_id"], r):
                if "undone_since" in e:
                    marks[e["id"]] = None
                continue
            if "undone_since" not in e:
                e["undone_since"] = marks[e["id"]] = time.time()
            steps = []
            if host is not None:
                for rec in e["records"]:
                    kind = ACTION_KINDS.get(rec["kind"])
                    if kind is None or rec.get("reverted") or rec["kind"] in IRREVERSIBLE_KINDS:
                        continue
                    try:
                        what = kind.changed_back(rec, host)
                    except Exception:  # noqa: BLE001 - a step that can't be read says nothing
                        what = None
                    if what:
                        steps.append(what)
            out.append({"entry_id": e["id"], "check_id": e["check_id"], "title": e["title"], "applied": e["applied"],
                        "undone_since": e["undone_since"], "severity": r.get("effective_severity", 0),
                        "changed_back": steps})
        if marks:
            with locked(self.dir):
                entries = self._load()
                for e in entries:
                    if e["id"] in marks and marks[e["id"]] is None:
                        e.pop("undone_since", None)
                    elif e["id"] in marks:
                        e.setdefault("undone_since", marks[e["id"]])
                self._save(entries)
        return sorted(out, key=lambda u: -u["severity"])

    def expire_backups(self, now: float | None = None) -> int:
        """Deletes the backups that were kept only for a while (`backup_expires`: known_hosts' plain copy, the very
        list its fix hides), once that time has passed: also a reverted step's, which has nothing more to put back.
        Returns how many went."""
        now = time.time() if now is None else now
        return self._drop(lambda e, r: r["backup_expires"] <= now)

    def drop_backups(self, entry_id: str) -> int:
        """Deletes an entry's backups that would expire anyway, now (History's "Delete it now")."""
        return self._drop(lambda e, r: e["id"] == entry_id)

    def _drop(self, which) -> int:
        due = lambda e, r: r.get("backup") and r.get("backup_expires") and which(e, r)  # noqa: E731
        if not any(due(e, r) for e in self.entries() for r in e["records"]):
            return 0                                # nothing due: no lock taken, nothing written (every page load asks)
        gone = 0
        with locked(self.dir):
            entries = self._load()
            for e in entries:
                for r in e["records"]:
                    if due(e, r):
                        for k in ("backup", "after_backup"):        # the copy of what the fix wrote goes with it
                            try:
                                if r.get(k):
                                    Path(r[k]).unlink()
                            except FileNotFoundError:
                                pass
                        r["backup"], r["backup_dropped"] = None, time.time()
                        r.pop("after_backup", None)
                        gone += 1
            if gone:
                self._save(entries)
        return gone

    @staticmethod
    def can_undo(record: dict) -> bool:
        """Whether reverting can still put this step back: not a deletion, not one whose backup has gone, and not a root
        step the helper's record says was never made."""
        if record["kind"] in ROOT_KINDS and not record.get("change_id"):
            return False
        return record["kind"] not in IRREVERSIBLE_KINDS and not record.get("backup_dropped")

    @staticmethod
    def needs_root(entry: dict) -> bool:
        return any(r["kind"] in ROOT_KINDS and r.get("change_id") and not r.get("reverted") for r in entry["records"])

    @staticmethod
    def describe(record: dict, host: Host | None = None) -> str:
        kind = ACTION_KINDS.get(record["kind"])
        return kind.describe_record(record, host) if kind else record.get("text", record["kind"])

    @staticmethod
    def via_text(entry: dict) -> str:
        """Where the change came from, in words: the guide's step and option, an Easy fix, or the fix
        from its row; "" for an entry from before this was kept."""
        if entry.get("recovered"):
            return ("Found in the administrator helper's own record of its changes: History had no entry for it (the app "
                    "stopped before it could write one, or History's file was lost)")
        via = entry.get("via") or {}
        if not via:
            return ""
        if via.get("guide"):
            step = f"step {via['step']}" + (f" ({via['step_title']})" if via.get("step_title") else "")
            text = f"From the guide “{via['guide']}”, {step}"
            if via.get("option") and via.get("options", 1) > 1:
                text += f", the option “{via['option']}”"
            return text + (", applied as an Easy fix" if via.get("easy") else "")
        return "Applied as an Easy fix" if via.get("easy") else "Applied with its Fix… button"

    @staticmethod
    def summary(entry: dict, host: Host | None = None) -> dict:
        """The entry as History shows it. With `host`, names kept out of the log (Wi-Fi
        connections) are looked up for display. A failed attempt (state "failed") carries its `error` and
        `failed_step`: its steps were put back, and one that couldn't be can be reverted from here. One interrupted
        (state "interrupted": the app stopped part way) can be reverted for the steps it records; one still being
        applied (state "applying") can't be, yet."""
        reversible = [r for r in entry["records"] if UndoLog.can_undo(r)]
        state = UndoLog.state_of(entry)
        return {"id": entry["id"], "check_id": entry["check_id"], "title": entry["title"], "applied": entry["applied"],
                "state": state, "reverted_at": entry.get("reverted"), "undone_since": entry.get("undone_since"),
                "can_revert": state != APPLYING and any(not r.get("reverted") for r in reversible),
                "needs_root": UndoLog.needs_root(entry), "via": dict(entry.get("via") or {}),
                "via_text": UndoLog.via_text(entry), "error": entry.get("error", ""),
                "failed_step": entry.get("failed_step", ""),
                "steps": [UndoLog.step(r, host) for r in entry["records"]]}

    @staticmethod
    def step(record: dict, host: Host | None = None) -> dict:
        """One step as History shows it: what it changed, the commands it ran (as root, for a root change),
        the lines it wrote into a file, the files the helper wrote, and how to undo it by hand; once
        reverted, what putting it back ran. `unknown`: whether it was made isn't known (under way when the app
        stopped, or a root step whose answer never came)."""
        kind = ACTION_KINDS.get(record["kind"])
        reversible = UndoLog.can_undo(record)
        try:
            ran = list(record["ran"]) if record.get("ran") else kind.ran(record) if kind else []   # as run, else rebuilt
            undo = kind.undo_hint(record) if kind and record["kind"] not in IRREVERSIBLE_KINDS \
                and not record.get("reverted") else ""
        except (KeyError, TypeError, ValueError):            # an entry written by an older version
            ran, undo = [], ""
        return {"text": UndoLog.describe(record, host), "reversible": reversible, "reverted": bool(record.get("reverted")),
                "as_root": record["kind"] in ROOT_KINDS or record["kind"] == "root-clear", "commands": ran,
                "lines": list(record.get("lines") or []), "files": list(record.get("files") or []), "undo": undo,
                "dirs": list(record.get("dirs") or []),
                "revert_ran": list(record.get("revert_ran") or []),
                "unknown": record["kind"] == "pending" or record.get("outcome") == "unknown",
                # a backup kept only for a while (known_hosts' plain copy): until when, or when it went
                "backup_until": record.get("backup_expires") if record.get("backup") and not record.get("reverted") else None,
                "backup_dropped": record.get("backup_dropped")}

    def forget(self, everything: bool = False, older_than_days: int = 90) -> int:
        """Drops entries (and their file backups): reverted ones, failed or interrupted ones with nothing left to
        revert (a step that couldn't be put back stays, for History says to revert it from there), and applied ones
        older than `older_than_days`; with `everything`, all of them. Never one being applied now (in this window or
        another copy of the app), nor its backups. Returns how many went. Changes made by forgotten entries stay as
        they are; they just can't be reverted from here any more, and their root changes' ids are kept (only the ids)
        so the helper's record of them isn't taken up again as changes History doesn't know (reconcile)."""
        import shutil
        cutoff = time.time() - older_than_days * 86400
        keep, gone, forgotten = [], 0, []
        with locked(self.dir):
            for e in self._load():
                left = any(UndoLog.can_undo(r) and not r.get("reverted") for r in e["records"])
                state = self.state_of(e)
                drop = state != APPLYING and (everything or state == "reverted"
                                              or (state in ("failed", INTERRUPTED) and not left) or e["applied"] < cutoff)
                if drop:
                    make_writable(self.backup_dir(e["id"]))      # a Box's program kept there, read-only folders and all
                    shutil.rmtree(self.backup_dir(e["id"]), ignore_errors=True)
                    forgotten += [r["change_id"] for r in e["records"]
                                  if r["kind"] in ROOT_KINDS and r.get("change_id") and not r.get("reverted")]
                    gone += 1
                else:
                    keep.append(e)
            if everything:
                # the backups no entry left names (a step that failed after taking its copy, before that was cleared
                # up: a plain copy of known_hosts among them), never those of an entry kept (one being applied now
                # writes into its own), and a log kept aside as unreadable
                named = {e["id"] for e in keep}
                try:
                    stray = [p for p in (self.dir / "backups").iterdir() if p.name not in named]
                except OSError:
                    stray = []
                for p in stray:
                    if p.is_dir() and not p.is_symlink():
                        make_writable(p)
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        p.unlink(missing_ok=True)
                try:
                    (self.dir / "backups").rmdir()           # once nothing is left in it
                except OSError:
                    pass
                for f in self.dir.glob(f"{UNREADABLE}*"):
                    f.unlink(missing_ok=True)
            if forgotten:
                self._kept["forgotten"] = sorted(set(self._kept.get("forgotten") or []) | set(forgotten))
            if gone or forgotten:
                self._save(keep)
        return gone
