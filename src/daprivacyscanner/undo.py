"""The undo log: every applied fix, with what each step changed, so it can be reverted from
the UI. Kept in $XDG_STATE_HOME/daprivacyscanner (0700), written atomically."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .fix import ACTION_KINDS, IRREVERSIBLE_KINDS, ROOT_KINDS
from .host import Host
from .paths import PathResolver


class UndoLog:
    def __init__(self, directory: Path):
        self.dir = directory
        self.file = directory / "undo.json"

    @classmethod
    def for_user(cls, paths: PathResolver) -> "UndoLog":
        return cls(paths.state_home / "daprivacyscanner")

    def backup_dir(self, entry_id: str) -> Path:
        return self.dir / "backups" / entry_id

    def entries(self) -> list[dict]:
        try:
            data = json.loads(self.file.read_text())
        except (FileNotFoundError, ValueError):
            return []
        return data.get("entries", []) if isinstance(data, dict) else []

    def get(self, entry_id: str) -> dict | None:
        return next((e for e in self.entries() if e["id"] == entry_id), None)

    def _save(self, entries: list[dict]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)
        tmp = self.file.with_suffix(".tmp")
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump({"version": 1, "entries": entries}, f, indent=1)
        os.replace(tmp, self.file)

    def add(self, entry_id: str, check_id: str, title: str, records: list[dict], state: str = "applied",
            extra: dict | None = None) -> dict:
        """`extra`: how the plan was offered (`via`, FixPlan.via) and, for a failed attempt, its `error` and
        the step it failed at (`failed_step`)."""
        entry = {"id": entry_id, "check_id": check_id, "title": title, "applied": time.time(), "state": state,
                 "records": records, **{k: v for k, v in (extra or {}).items() if v not in (None, "", {})}}
        self._save(self.entries() + [entry])
        return entry

    def update(self, entry: dict) -> None:
        reversible = [r for r in entry["records"] if UndoLog.can_undo(r)]
        if reversible and all(r.get("reverted") for r in reversible):
            entry["state"] = "reverted"
            entry["reverted"] = time.time()
        elif any(r.get("reverted") for r in reversible):
            entry["state"] = "partly reverted"
        self._save([entry if e["id"] == entry["id"] else e for e in self.entries()])

    def set_outcome(self, entry_id: str, result: dict | None) -> None:
        """The check's result just after the fix was applied (the rescan): a later scan that finds
        the problem back, when this one had it resolved, means the fix was undone."""
        if not result:
            return
        entries = self.entries()
        for e in entries:
            if e["id"] == entry_id:
                e["outcome"] = {"status": result.get("status"), "severity": result.get("effective_severity", 0),
                                "at": time.time()}
        self._save(entries)

    def undone(self, results: dict, accepted: dict | None = None, host: Host | None = None) -> list[dict]:
        """Fixes the user applied whose problem is back: the check was resolved just after the fix,
        and is a finding again now. Not those reverted from History, and not a finding the user has
        since accepted. Each names the steps whose settings no longer hold what the fix set (read
        now, when `host` is given). The latest fix per check. The log notes when each was first
        found undone, and forgets it once the problem is gone again."""
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
        entries, out, seen, dirty = self.entries(), [], set(), False
        for e in reversed(entries):
            o = e.get("outcome")
            if e["state"] not in ("applied", "partly reverted") or not o or e["check_id"] in seen or nothing_to_undo(e):
                if e.pop("undone_since", None) is not None:      # reverted, or a later fix of the same check
                    dirty = True
                continue
            r = results.get(e["check_id"])
            if r is None:                                   # not scanned this time: say nothing either way
                continue
            seen.add(e["check_id"])
            was_fixed = o.get("status") not in ACTIVE or not o.get("severity")
            if not (was_fixed and active(r)) or hidden(accepted, e["check_id"], r):
                if e.pop("undone_since", None) is not None:
                    dirty = True
                continue
            if "undone_since" not in e:
                e["undone_since"] = time.time()
                dirty = True
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
        if dirty:
            self._save(entries)
        return sorted(out, key=lambda u: -u["severity"])

    def expire_backups(self, now: float | None = None) -> int:
        """Deletes the backups that were kept only for a while (`backup_expires`: known_hosts' plain copy, the very
        list its fix hides), once that time has passed. Returns how many went."""
        now = time.time() if now is None else now
        return self._drop(lambda e, r: r["backup_expires"] <= now)

    def drop_backups(self, entry_id: str) -> int:
        """Deletes an entry's backups that would expire anyway, now (History's "Delete it now")."""
        return self._drop(lambda e, r: e["id"] == entry_id)

    def _drop(self, which) -> int:
        entries, gone = self.entries(), 0
        for e in entries:
            for r in e["records"]:
                if r.get("backup") and r.get("backup_expires") and not r.get("reverted") and which(e, r):
                    try:
                        Path(r["backup"]).unlink()
                    except FileNotFoundError:
                        pass
                    r["backup"], r["backup_dropped"] = None, time.time()
                    gone += 1
        if gone:
            self._save(entries)
        return gone

    @staticmethod
    def can_undo(record: dict) -> bool:
        """Whether reverting can still put this step back: not a deletion, and not one whose backup has gone."""
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
        `failed_step`: its steps were put back, and one that couldn't be can be reverted from here."""
        reversible = [r for r in entry["records"] if UndoLog.can_undo(r)]
        return {"id": entry["id"], "check_id": entry["check_id"], "title": entry["title"], "applied": entry["applied"],
                "state": entry["state"], "reverted_at": entry.get("reverted"), "undone_since": entry.get("undone_since"),
                "can_revert": any(not r.get("reverted") for r in reversible),
                "needs_root": UndoLog.needs_root(entry), "via": dict(entry.get("via") or {}),
                "via_text": UndoLog.via_text(entry), "error": entry.get("error", ""),
                "failed_step": entry.get("failed_step", ""),
                "steps": [UndoLog.step(r, host) for r in entry["records"]]}

    @staticmethod
    def step(record: dict, host: Host | None = None) -> dict:
        """One step as History shows it: what it changed, the commands it ran (as root, for a root change),
        the lines it wrote into a file, the files the helper wrote, and how to undo it by hand; once
        reverted, what putting it back ran."""
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
                # a backup kept only for a while (known_hosts' plain copy): until when, or when it went
                "backup_until": record.get("backup_expires") if record.get("backup") and not record.get("reverted") else None,
                "backup_dropped": record.get("backup_dropped")}

    def forget(self, everything: bool = False, older_than_days: int = 90) -> int:
        """Drops entries (and their file backups): reverted and failed ones, and applied ones
        older than `older_than_days`; with `everything`, all of them. Returns how many went.
        Changes made by forgotten entries stay as they are; they just can't be reverted from
        here any more."""
        import shutil
        cutoff = time.time() - older_than_days * 86400
        keep, gone = [], 0
        for e in self.entries():
            drop = everything or e["state"] in ("reverted", "failed") or e["applied"] < cutoff
            if drop:
                shutil.rmtree(self.backup_dir(e["id"]), ignore_errors=True)
                gone += 1
            else:
                keep.append(e)
        if gone:
            self._save(keep)
        return gone
