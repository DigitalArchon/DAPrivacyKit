"""Exporting a report: as text or JSON, optionally redacted (hostname, account names, your
name, saved network names wherever they appear, addresses, paths under your home) so it can be shared when asking for help.
`export_all` adds everything else the app keeps (accepted findings, and every change in History with
what it was before and how to undo it by hand), for the user to keep as a backup."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from typing import Any, Iterable

from .catalogue import Catalogue
from .host import Host
from .model import STATUS_WORD

# evidence labels whose values name networks, accounts or devices: replaced whole when redacting
NAMED_LABELS = re.compile(r"^(Hidden network|Accounts|Empty password|Open network that reconnects by itself|Name|"
                          r"VPN interfaces|Interfaces with a public IPv6 address|Hostname|Contains your name|"
                          r"Paired devices|Passwordless rule)$")
MAC = re.compile(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
# a disk's or volume's UUID (luks-<UUID> device names, NetworkManager connections): one identifies the machine
UUID = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
# where drives are mounted: what follows is the drive's label ("Taxes 2024"), or the folder named for it
MOUNT_ROOTS = r"(?:/run/media/[^/\s]+|/media/[^/\s]+|/mnt)/"
_WHOLE_MOUNT = re.compile(rf"({MOUNT_ROOTS})[^/,;:()]+(/[^,;:()]*)?")    # a text that is a mount point: spaces and all
# in a sentence: a label with spaces ("My Passport", "Taxes 2024") runs on while the next word doesn't start lower-case
_MOUNT = re.compile(rf"({MOUNT_ROOTS})[^/\s,;:()]+(?: (?![a-z])[^/\s,;:()]+)*")
# a Firefox-family profile's folder: a random prefix of the install's and the profile's name
FF_PROFILE = re.compile(r"( profile )[a-z0-9]{8}\.[^\s,;:)]+")
# names a key file, keyring or wallet has when nobody chose one: left readable
DEFAULT_NAMES = frozenset({"login.keyring", "default.keyring", "Default_keyring.keyring", "user.keystore", "kdewallet.kwl",
                           "kdewallet.salt", "kdewallet", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk",
                           "id_ed25519_sk"})
# candidates only: each match is replaced only if it parses as an address (so a time like 14:26:05
# or a version like 1.2.3 stays as it is)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])")


def replace_addresses(text: str, v4: str, v6: str) -> str:
    """IP addresses in `text` replaced by `v4` / `v6`, except loopback and unspecified ones
    (127.0.0.1, 0.0.0.0, ::1, ::), which say nothing about the machine."""
    def sub(m: re.Match, cls, repl: str) -> str:
        try:
            a = cls(m.group(0))
        except ValueError:
            return m.group(0)
        return m.group(0) if a.is_loopback or a.is_unspecified else repl
    text = _IPV4.sub(lambda m: sub(m, ipaddress.IPv4Address, v4), text)
    return _IPV6.sub(lambda m: sub(m, ipaddress.IPv6Address, v6), text)


def _word(name: str) -> re.Pattern:
    """`name` as a whole word, any case: "user" matches in "user's", not in "users"."""
    return re.compile(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", re.I)


def saved_network_names(host: Host) -> list[str]:
    """Names of NetworkManager's saved connections (usually Wi-Fi network names): some checks
    show them as evidence labels, and they say where the machine has been."""
    r = host.run("nmcli", "-g", "NAME", "connection", "show")
    if not r.ok:
        return []
    return [n.replace("\\:", ":") for n in r.stdout.splitlines() if n.strip() and n != "lo"]


class Redactor:
    def __init__(self, host: Host, chosen: Iterable[str] = ()):
        """`chosen`: names the user gave things (key files, wallets: evidence marked `named`), replaced wherever
        they appear; `report` adds a report's own."""
        from .checks._util import user_names
        self.login, self.words = user_names(host)
        self.hostname = (host.read_sys("/proc/sys/kernel/hostname") or "").strip()
        self.home = str(host.home)
        self._base = [self.hostname, self.login, *self.words, *saved_network_names(host)]
        self._set_names(chosen)

    def _set_names(self, chosen: Iterable[str]) -> None:
        # longest first, so "alice-laptop" goes before "alice"
        names = [n for n in dict.fromkeys([*self._base, *(c for c in chosen if c not in DEFAULT_NAMES)]) if len(n) >= 3]
        self.names = [_word(n) for n in sorted(names, key=len, reverse=True)]

    def add_names(self, report: dict | None) -> None:
        """The names evidence in `report` marks as the user's (`named`), redacted from then on, everywhere."""
        found = [e["label"] for r in ((report or {}).get("results") or {}).values() for e in r.get("evidence") or []
                 if e.get("named") and isinstance(e.get("label"), str)]
        if found:
            self._set_names(found)

    def text(self, s: str) -> str:
        if not isinstance(s, str) or not s:
            return s
        s = s.replace(self.home, "~")
        for n in self.names:
            s = n.sub("[redacted]", s)
        s = MAC.sub("[mac]", s)
        s = UUID.sub("[uuid]", s)
        s = replace_addresses(s, "[ipv4]", "[ipv6]")
        s = re.sub(r"~/(?!\.)[^\s,;:)]+", "~/[redacted]", s)      # a path to a document, not to a dot-folder
        whole = _WHOLE_MOUNT.fullmatch(s.strip())
        s = f"{whole.group(1)}[drive]{whole.group(2) or ''}" if whole else _MOUNT.sub(r"\1[drive]", s)
        s = FF_PROFILE.sub(r"\1[profile]", s)
        return s

    def evidence(self, e: dict) -> dict:
        out = dict(e)
        if NAMED_LABELS.match(str(e.get("label", ""))):
            out["value"] = "[redacted]" if e.get("value") not in (None, "", True, False) else e.get("value")
        elif isinstance(out.get("value"), str):
            out["value"] = self.text(out["value"])
        out["label"] = self.text(str(out["label"]))
        return out

    def result(self, r: dict) -> dict:
        out = dict(r)
        out["summary"] = self.text(r.get("summary", ""))
        out["evidence"] = [self.evidence(e) for e in r.get("evidence", [])]
        out["notes"] = [{**n, "text": self.text(n["text"]), "title": self.text(n["title"])} for n in r.get("notes", [])]
        out["error"] = self.text(r.get("error", ""))
        if "items" in r:
            out["items"] = [self.text(i) for i in r["items"]]
        return out

    def report(self, report: dict) -> dict:
        self.add_names(report)
        out = json.loads(json.dumps(report))
        out["results"] = {k: self.result(v) for k, v in report.get("results", {}).items()}
        ctx = out.get("context", {})
        for key, c in ctx.get("values", {}).items():
            c["evidence"] = [self.evidence(e) for e in c.get("evidence", [])]
            c["note"] = self.text(c.get("note", ""))
            c["notes"] = [{**n, "text": self.text(n["text"])} for n in c.get("notes", [])]
        # what a fix changed back can name files under home and saved networks
        out["undone"] = [{**u, "title": self.text(u.get("title", "")),
                          "changed_back": [self.text(t) for t in u.get("changed_back") or []]}
                         for u in report.get("undone") or []]
        if isinstance(out.get("changes"), dict) and out["changes"].get("new_items"):
            out["changes"]["new_items"] = {k: [self.text(i) for i in v] for k, v in out["changes"]["new_items"].items()}
        out["redacted"] = True
        return out


def export(report: dict, catalogue: Catalogue, fmt: str = "text", host: Host | None = None, redact: bool = False,
           accepted: dict | None = None) -> str:
    """`accepted`: the accepted findings, whose notes the user wrote for themselves: redacted with the rest, since a
    note can name anything ("work laptop at Acme")."""
    accepted = accepted or {}
    if redact:
        if host is None:
            raise ValueError("redaction needs the host")
        red = Redactor(host)
        report = red.report(report)
        accepted = _deep(accepted, red.text)
    if fmt == "json":
        from .history import hidden
        return json.dumps({"format": "daprivacyscanner-report", "version": 1, "report": report, "accepted": accepted,
                           "hidden": sorted(c for c, r in report.get("results", {}).items()
                                            if r.get("is_finding") and hidden(accepted, c, r))}, indent=1)
    return render_text(report, catalogue, accepted or {})


def render_text(report: dict, catalogue: Catalogue, accepted: dict) -> str:
    from .history import hidden, resurfaced, why_resurfaced
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(report.get("started", time.time())))
    from . import about
    app = about.age()
    lines = [f"DA Privacy Kit report, {when}" + (" (redacted)" if report.get("redacted") else ""),
             f"Version {app['version']}" + (f", built {app['built']}" if app["built"] else ""),
             "Nothing in this report was sent anywhere by the app.", ""]
    if app["text"]:
        lines[3:3] = [app["text"]]
    lines += undone_text(report, catalogue)
    for cid, items in ((report.get("changes") or {}).get("new_items") or {}).items():
        spec = catalogue.checks.get(cid)
        lines.append(f"New since the last scan in \"{spec.title if spec else cid}\":")
        lines += [f"    + {i}" for i in items] + [""]
    ctx = report.get("context", {}).get("values", {})
    lines.append("Context: " + ", ".join(f"{k}={_v(c.get('value'))}" for k, c in ctx.items()))
    lines.append(f"Desktop: {report.get('context', {}).get('desktop', {}).get('label', '?')}")
    lines.append("")
    results = report.get("results", {})
    undone_ids = {u["check_id"] for u in report.get("undone") or []}
    # a problem when last checked that this scan couldn't check (history.diff's `unchecked`)
    was = {u["id"]: u for u in (report.get("changes") or {}).get("unchecked") or []}
    # what couldn't be checked comes straight after the findings: a problem there wouldn't show
    # as a finding, and the severity says what is at stake
    groups = [("Findings", lambda r: r.get("is_finding") and not hidden(accepted, r["id"], r)),
              ("Couldn't be checked: a problem here wouldn't show as a finding",
               lambda r: r["status"] in ("unknown", "error")),
              ("Accepted risks (hidden in the app)", lambda r: r.get("is_finding") and hidden(accepted, r["id"], r)),
              ("Hygiene", lambda r: r.get("is_hygiene")),
              ("Information", lambda r: r.get("kind") == "info" and r["status"] in ("fail", "warn")),
              ("Passed", lambda r: r["status"] == "pass")]
    # set-ups that last (tier feature) are listed apart, as the app's Tools panel lists them
    feature = lambda cid: cid in catalogue.checks and catalogue[cid].tier.value == "feature"  # noqa: E731
    groups = [(t, lambda r, k=k: k(r) and not feature(r["id"])) for t, k in groups]
    groups.append(("Set-ups in the Tools panel", lambda r: feature(r["id"]) and r["status"] in ("pass", "warn", "fail")))
    for title, keep in groups:
        rows = [dict(r, id=cid) for cid, r in results.items() if keep(dict(r, id=cid))]
        if not rows:
            continue
        rows.sort(key=lambda r: (-r["effective_severity"], r["status"] == "warn"))    # problems before risks
        lines.append(f"== {title} ({len(rows)})")
        if any(r.get("needs_admin") for r in rows):
            lines.append("   (those marked [admin] are checked by a scan with administrator access: --admin)")
        for r in rows:
            spec = catalogue.checks.get(r["id"])
            if feature(r["id"]):
                sev = "[set up] " if r["status"] == "pass" else "[not set up] "
            elif r["status"] in ("fail", "warn"):
                sev = f"[{r['effective_severity']}] {STATUS_WORD[r['status']]}: "
            elif r["status"] in ("unknown", "error"):
                sev = (f"[would be {r['effective_severity']}] " if r["effective_severity"] else "") + \
                    ("[admin] " if r.get("needs_admin") else "[failed to run] " if r["status"] == "error" else "")
            else:
                sev = ""
            lines.append(f"{sev}{spec.title + ' (' + r['id'] + ')' if spec else r['id']}")
            if r.get("summary"):
                lines.append(f"    {r['summary']}")
            if r["id"] in was and r["status"] in ("unknown", "error"):
                u = was[r["id"]]
                lines.append(f"    {STATUS_WORD.get(u['status'], 'Problem')}, severity {u['severity']}, when it was last "
                             "checked" + (time.strftime(" (%Y-%m-%d)", time.localtime(u["checked"])) if u.get("checked") else "")
                             + ". This scan couldn't check it, so it isn't resolved.")
            if r.get("error"):
                lines.append(f"    error: {r['error']}")
            if spec and spec.remedy and r.get("is_finding") and not hidden(accepted, r["id"], r):
                lines.append(f"    What to do: {spec.remedy}")
                if r.get("no_fix"):
                    lines.append(f"    The app can't do this for you here: {r['no_fix']}")
            if r["id"] in undone_ids:
                lines.append("    !! You fixed this, and it has been undone since: see the top of this report.")
            record = accepted.get(r["id"])
            if record and r.get("is_finding") and resurfaced(record, r["effective_severity"]):
                lines.append(f"    {why_resurfaced(record, r)}")
            if record and record.get("note"):
                lines.append(f"    accepted: {record['note']}")
            for e in r.get("evidence", []):
                lines.append(f"    - {e['label']}" + (f": {e['value']}" if e.get("value") not in (None, "") else ""))
        lines.append("")
    return "\n".join(lines)


def undone_text(report: dict, catalogue: Catalogue) -> list[str]:
    """The loudest part of a report: fixes the user applied that have been undone since."""
    undone = report.get("undone") or []
    if not undone:
        return []
    day = lambda t: time.strftime("%d %b %Y", time.localtime(t))  # noqa: E731
    n = len(undone)
    lines = ["!" * 78, f"!! {n} FIX{'ES' if n > 1 else ''} UNDONE: {'problems' if n > 1 else 'a problem'} you fixed "
             f"{'are' if n > 1 else 'is'} back", "!" * 78]
    for u in undone:
        spec = catalogue.checks.get(u["check_id"])
        lines.append(f"[{u['severity']}] {spec.title if spec else u['check_id']}")
        lines.append(f"    Fixed on {day(u['applied'])} ({u['title']}); found undone on {day(u['undone_since'])}.")
        for step in u.get("changed_back") or []:
            lines.append(f"    - changed back: {step}")
    lines += ["Something changed these back: an update, another program, a sync, or someone using this computer. "
              "Fix them again, and if it keeps happening, find what does it. If you changed one back on purpose, "
              "accept the finding.", ""]
    return lines


def _v(v: Any) -> str:
    return "unknown" if v is None else "yes" if v is True else "no" if v is False else str(v)


def _deep(obj, fn):
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_deep(v, fn) for v in obj]
    if isinstance(obj, dict):
        return {k: _deep(v, fn) for k, v in obj.items()}
    return obj


NOT_INCLUDED = ("The copies of files taken before they were changed (in ~/.local/state/daprivacyscanner/backups): they "
                "can hold exactly what a fix removed, such as server names in known_hosts.",
                "What the administrator helper kept of system files it changed (/var/lib/daprivacyscanner/changes, "
                "root only).",
                "Anything deleted: deletions are never recorded, only how many files and from where.")


def changes_of(entries: list[dict], catalogue: Catalogue, host: Host | None) -> list[dict]:
    """The undo log as exported: each entry and its steps, what each one changed (before and
    after) and how to undo it by hand. `host` names the Wi-Fi connections the log keeps by UUID."""
    from .fix import ACTION_KINDS
    from .undo import UndoLog
    out = []
    for e in entries:
        steps = []
        for r in e["records"]:
            kind = ACTION_KINDS.get(r["kind"])
            undoable = UndoLog.can_undo(r)
            shown = UndoLog.step(r)                 # the same as History shows: commands, lines, files, folders
            steps.append({"text": UndoLog.describe(r, host), "reversible": undoable, "reverted": bool(r.get("reverted")),
                          "undo_by_hand": kind.undo_hint(r) if kind and undoable and not r.get("reverted") else "",
                          "ran": shown["commands"], "as_root": shown["as_root"], "lines": shown["lines"],
                          "files": shown["files"], "dirs": shown["dirs"], "revert_ran": shown["revert_ran"],
                          "record": {k: v for k, v in r.items() if k != "text"}})
        spec = catalogue.checks.get(e["check_id"])
        at = lambda t: time.strftime("%Y-%m-%d %H:%M", time.localtime(t))  # noqa: E731
        out.append({"id": e["id"], "check_id": e["check_id"], "check": spec.title if spec else e["check_id"],
                    "title": e["title"], "applied": e["applied"], "applied_at": at(e["applied"]), "state": e["state"],
                    "reverted_at": at(e["reverted"]) if e.get("reverted") else "", "via": UndoLog.via_text(e),
                    "error": e.get("error", ""), "failed_step": e.get("failed_step", ""), "steps": steps})
    return out


def export_all(report: dict | None, catalogue: Catalogue, entries: list[dict], accepted: dict, fmt: str = "text",
               host: Host | None = None, redact: bool = False) -> str:
    """Everything the app keeps, in one file: the last report, accepted findings, and every change
    in History. Redacted, Wi-Fi connections stay as UUIDs and the rest goes through the Redactor."""
    if redact and host is None:
        raise ValueError("redaction needs the host")
    changes = changes_of(entries, catalogue, None if redact else host)
    if redact:
        red = Redactor(host)
        red.add_names(report)
        changes = _deep(changes, red.text)
        accepted = _deep(accepted, red.text)
        report = red.report(report) if report else None
    if fmt == "json":
        return json.dumps({"format": "daprivacyscanner-export", "version": 1, "exported": time.time(),
                           "redacted": redact, "report": report, "accepted": accepted, "changes": changes,
                           "not_included": list(NOT_INCLUDED)}, indent=1)
    when = time.strftime("%Y-%m-%d %H:%M")
    lines = [f"DA Privacy Kit: everything it keeps, exported {when}" + (" (redacted)" if redact else ""),
             "Keep it with your backups. Nothing in it was sent anywhere by the app.", "",
             f"== Changes made by DA Privacy Kit ({len(changes)})"]
    if not changes:
        lines.append("None.")
    for c in changes:
        lines.append(f"{c['applied_at']}  {c['title']}  [{c['state']}]"
                     + (f"  (reverted {c['reverted_at']})" if c["reverted_at"] else ""))
        lines.append(f"    for {c['check_id']}: {c['check']}")
        if c["via"]:
            lines.append(f"    {c['via']}")
        if c["state"] == "failed":
            lines.append(f"    FAILED: {c['error']}" + (f" (at: {c['failed_step']})" if c["failed_step"] else ""))
            lines.append("    The steps that had run were put back, as listed under each.")
        for st in c["steps"]:
            tag = "reverted" if st["reverted"] else "can be undone" if st["reversible"] else "permanent"
            root = ", as root" if st["as_root"] else ""
            lines.append(f"    - ({tag}) {st['text']}")
            lines += [f"        ran{root}: {x}" for x in st["ran"]]
            lines += [f"        wrote{root}: {x}" for x in st["files"]]
            lines += [f"        made folder: {x}" for x in st["dirs"]]
            lines += [f"        line: {x}" for x in st["lines"]]
            if st["undo_by_hand"]:
                lines.append(f"        undo by hand: {st['undo_by_hand']}")
            lines += [f"        putting it back ran{root}: {x}" for x in st["revert_ran"]]
    lines.append("")
    lines.append(f"== Accepted findings ({len(accepted)})")
    for cid, rec in sorted(accepted.items()):
        lines.append(f"{cid}: accepted at severity {rec.get('severity', '?')}" + (f": {rec['note']}" if rec.get("note") else ""))
    if not accepted:
        lines.append("None.")
    lines += ["", "== Not included"] + [f"- {x}" for x in NOT_INCLUDED] + [""]
    lines.append(render_text(report, catalogue, accepted) if report else "== No scan is saved: run one to include its report.")
    return "\n".join(lines)
