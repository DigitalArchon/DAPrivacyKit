"""What the app remembers between scans, in $XDG_STATE_HOME/daprivacyscanner (0700):

- the baseline: each check's status and severity from the last scan (never evidence), so a new
  scan can say what is new, what was resolved and what changed; for an inventory (what starts at
  login), a salted hash of each entry's name, never the name, so the next scan can say which
  entries are new. A hash can't be turned back into a name, but a guessed name can be tested
  against it, as with hashed known_hosts;
- accepted findings: checks the user has marked as a risk they accept, with their note, so the
  report converges on what is still to be done;
- the last report itself, so the app opens on it instead of a blank page. It holds the
  evidence (counts, settings, paths: never secrets or file contents, as evidence never does),
  readable by the user only (0600), less what the app says it doesn't keep between runs
  (`strip_for_saving`): an inventory's entries (what starts at login, which the baseline keeps only as
  hashes, so the saved report mustn't hold the names beside them), and the public addresses and
  lookup names the online tests saw. Each stripped result carries a note saying so, and the report
  lists what was left out in `not_kept`. History can forget it.

All are JSON files written atomically."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .paths import PathResolver

ACTIVE = ("fail", "warn")
UNCHECKED = ("unknown", "error")            # couldn't be checked: neither a problem nor resolved


def state_dir(paths: PathResolver) -> Path:
    return paths.state_home / "daprivacyscanner"


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, ValueError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_suffix(".tmp")
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


# ------------------------------------------------------------------ baseline

def item_hash(salt: str, item: str) -> str:
    import hashlib
    import hmac
    return hmac.new(bytes.fromhex(salt), item.encode(), hashlib.sha256).hexdigest()[:16]


def snapshot(report: dict, salt: str | None = None, previous: dict | None = None) -> dict:
    """What is kept of a report: per check, its status, severity and kind, and for an inventory the
    hashes of its entries (with `salt`). No evidence. A check that couldn't be checked this time (a scan
    without administrator access, an online test not run) keeps what it was when last checked, a problem
    or a risk, as `last` (from `previous`): it isn't resolved, and it isn't new when it is found again."""
    salt = salt or os.urandom(16).hex()
    before = (previous or {}).get("results") or {}
    results = {}
    for cid, r in report.get("results", {}).items():
        results[cid] = {"status": r["status"], "severity": r["effective_severity"], "kind": r.get("kind", "finding")}
        if "items" in r or r.get("kind") == "info" and r["status"] in ("pass", "warn", "fail"):
            results[cid]["items"] = sorted(item_hash(salt, i) for i in r.get("items") or [])
        if r["status"] in UNCHECKED and cid in before:
            was = _when_checked(before[cid], (previous or {}).get("taken"))
            if _active(was):
                results[cid]["last"] = {k: was[k] for k in ("status", "severity", "taken") if k in was}
    return {"taken": report.get("started", time.time()), "salt": salt, "results": results}


def _active(r: dict) -> bool:
    return r.get("status") in ACTIVE and r.get("severity", 0) > 0


def _when_checked(r: dict, taken: float | None) -> dict:
    """A baseline's entry as of the last scan that could check it: itself (as of `taken`), or what it carried
    over the scans that couldn't."""
    if r.get("status") in UNCHECKED:
        return r.get("last") or r
    return {**r, "taken": taken}


def diff(previous: dict | None, current: dict) -> dict | None:
    """Findings and hygiene items new since `previous`, resolved since, and those whose severity
    changed; those that were a problem when last checked and couldn't be checked this time (`unchecked`,
    each with what it was and when: never resolved, which only a scan that checked them can say); and an
    inventory's entries that are new (`new_items`, by check, named as in the current report: the previous
    scan's names were never kept). None without a previous scan."""
    if not previous or "results" not in previous:
        return None
    now = snapshot(current)["results"]
    before = {cid: _when_checked(r, previous.get("taken")) for cid, r in previous["results"].items()}
    checked = {cid: r for cid, r in now.items() if r["status"] not in UNCHECKED}

    new = sorted(cid for cid, r in now.items() if _active(r) and not (cid in before and _active(before[cid])))
    resolved = sorted(cid for cid, r in before.items() if _active(r) and cid in checked and not _active(checked[cid]))
    unchecked = [{"id": cid, "status": r["status"], "severity": r["severity"], "checked": r.get("taken")}
                 for cid, r in sorted(before.items()) if _active(r) and cid in now and cid not in checked]
    changed = [{"id": cid, "from": before[cid]["severity"], "to": r["severity"], "was": before[cid]["status"],
                "now": r["status"]}
               for cid, r in sorted(now.items()) if _active(r) and cid in before and _active(before[cid])
               and before[cid]["severity"] != r["severity"]]
    new_items = {}
    salt = previous.get("salt")
    for cid, r in current.get("results", {}).items():
        known = previous["results"].get(cid, {}).get("items")
        if salt and known is not None and r.get("items"):
            fresh = [i for i in r["items"] if item_hash(salt, i) not in set(known)]
            if fresh:
                new_items[cid] = fresh
    return {"previous": previous.get("taken"), "new": new, "resolved": resolved, "unchecked": unchecked,
            "changed": changed, "new_items": new_items}


class Baseline:
    def __init__(self, paths: PathResolver):
        self.file = state_dir(paths) / "last-scan.json"

    def load(self) -> dict | None:
        data = _load(self.file)
        return data or None

    def record(self, report: dict) -> dict | None:
        """Compares the report with the last one and stores it as the new baseline. Returns the
        differences (None on the first scan)."""
        previous = self.load()
        changes = diff(previous, report)
        _save(self.file, snapshot(report, (previous or {}).get("salt"), previous))
        return changes


# evidence that says where this computer has been: the online tests' addresses and lookup names, and saved Wi-Fi
# networks named by their checks (a café's, an airport's), shown on the page, never saved; label -> what it is
NOT_KEPT_LABELS = {"Public IPv4 address websites see": "addresses", "Public IPv6 address websites see": "addresses",
                   "Websites see you as": "addresses", "Looks like telemetry": "addresses", "Answered with": "addresses",
                   "Hidden network": "network names", "Open network that reconnects by itself": "network names"}
NOT_KEPT_VALUE = "not kept between runs: scan or run the test again to see it"


def strip_for_saving(report: dict) -> dict:
    """The report as the last report keeps it: without an inventory's entries (`items`, and the evidence that
    names them), and without the online tests' addresses and lookup names or saved Wi-Fi networks' names
    (NOT_KEPT_LABELS, their values replaced). Each result stripped gets a note saying so; `not_kept` lists what was left out, for the page."""
    out = json.loads(json.dumps({k: v for k, v in report.items() if k != "restored"}))
    not_kept: list[str] = []
    for cid, r in out.get("results", {}).items():
        stripped = False
        items = set(r.pop("items", None) or [])
        if items:
            r["evidence"] = [e for e in r.get("evidence", []) if e.get("label") not in items]
            stripped = True
            not_kept.append(f"the entries of {cid}")
        for e in r.get("evidence", []):
            if e.get("label") in NOT_KEPT_LABELS and e.get("value") not in (None, "", NOT_KEPT_VALUE):
                e["value"] = NOT_KEPT_VALUE
                stripped = True
                what = (f"the addresses {cid} saw" if NOT_KEPT_LABELS[e["label"]] == "addresses"
                        else f"the network names {cid} listed")
                if what not in not_kept:
                    not_kept.append(what)
        if stripped:
            r.setdefault("notes", []).append({"kind": "limitation", "title": "Not kept between runs",
                                              "text": "What this listed (names and addresses) is shown while the app "
                                                      "runs and never saved: scan again to see it."})
    changes = out.get("changes")
    if isinstance(changes, dict) and changes.get("new_items"):
        changes["new_items"] = {}
    if not_kept:
        out["not_kept"] = not_kept
    return out


class LastReport:
    """The whole last report, for the next start, less what isn't kept between runs (`strip_for_saving`).
    `load` drops results of checks that are no longer in the catalogue (`known`) and marks the report as
    restored."""

    def __init__(self, paths: PathResolver):
        self.file = state_dir(paths) / "last-report.json"

    def save(self, report: dict) -> None:
        _save(self.file, strip_for_saving(report))

    def load(self, known: set[str] | None = None) -> dict | None:
        data = _load(self.file)
        if not isinstance(data.get("results"), dict) or not isinstance(data.get("context"), dict):
            return None
        if known is not None:
            data["results"] = {k: v for k, v in data["results"].items() if k in known}
            data["modifiers"] = {k: v for k, v in (data.get("modifiers") or {}).items() if k in known}
        return {**data, "restored": True}


def forget_scans(paths: PathResolver) -> int:
    """Deletes the saved report and the baseline. Returns how many files went."""
    gone = 0
    for f in (LastReport(paths).file, Baseline(paths).file):
        try:
            f.unlink()
            gone += 1
        except FileNotFoundError:
            pass
    return gone


# ------------------------------------------------------------------ accepted findings
# An accepted finding is hidden: not listed (except under Accepted), not counted, not notified
# about. It is shown again by itself when its severity rises above what it was when accepted
# (the machine changed, or the app rates it higher now), with a note saying why, until the user
# accepts it again at the new severity or un-accepts it. The page applies the same rule.

class Accepted:
    def __init__(self, paths: PathResolver):
        self.file = state_dir(paths) / "accepted.json"

    def all(self) -> dict[str, dict]:
        return {k: v for k, v in _load(self.file).items() if isinstance(v, dict)}

    def set(self, check_id: str, accept: bool, note: str = "", severity: int | None = None,
            reason: str = "") -> dict[str, dict]:
        """Accepts (or un-accepts) a finding at its severity now, and what decided that severity."""
        data = self.all()
        if accept:
            data[check_id] = {"note": note.strip()[:300], "when": time.time(), "severity": severity,
                              "severity_reason": reason}
        else:
            data.pop(check_id, None)
        _save(self.file, data)
        return data


def resurfaced(record: dict | None, severity: int) -> bool:
    """An accepted finding whose severity rose above the one it was accepted at."""
    return bool(record) and isinstance(record.get("severity"), int) and severity > record["severity"]


def hidden(accepted: dict, check_id: str, result: dict) -> bool:
    """A finding the user accepted that stays hidden (its severity hasn't risen since)."""
    return check_id in accepted and not resurfaced(accepted[check_id], result.get("effective_severity", 0))


def why_resurfaced(record: dict, result: dict) -> str:
    """Why an accepted finding is shown again, in words."""
    when = time.strftime("%d %b %Y", time.localtime(record.get("when", 0)))
    then, now = record.get("severity_reason") or "", result.get("severity_reason") or ""
    text = (f"Shown again automatically: its severity rose from {record['severity']} to "
            f"{result['effective_severity']} since you accepted it on {when}")
    if then != now:
        return text + f" (then: {then or 'its base severity'}; now: {now or 'its base severity'})."
    return text + " (the app rates it higher now than when you accepted it)."
