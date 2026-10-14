#!/usr/bin/env python3
"""For the maintainer: are the apps the checks read (apps.yaml) still the versions the checks were made for?

Run by hand, never from the test suite, which stays offline:

  .venv/bin/python packaging/check-app-versions.py              every app against its latest release (Repology)
  .venv/bin/python packaging/check-app-versions.py --only firefox,vlc
  .venv/bin/python packaging/check-app-versions.py --brief review.md
        also writes a review brief for the apps with a new major version: what each check relies on, where its code
        is, what to read upstream, and what to answer; hand it to Claude Code ("review the apps in review.md")
  .venv/bin/python packaging/check-app-versions.py --installed  this computer's versions instead of upstream's
  .venv/bin/python packaging/check-app-versions.py --mark firefox 160 [--tested]
        once an app is reviewed: records the version in apps.yaml (checked, basis, checked_on), keeping the file's
        layout and comments

Exits 1 when an app has a new major version (beyond its tolerance), 0 otherwise. Repology's "newest" is the
newest stable release any repository ships, which is sometimes a beta packaged early (a .9x KDE version in Fedora
rawhide): the table says how many repositories have it. Apps without a `repology` name are listed apart: look at
their release notes by hand."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daprivacyscanner import appversions  # noqa: E402
from daprivacyscanner.appversions import App, parse_version  # noqa: E402

APPS_FILE = ROOT / "apps.yaml"
REPOLOGY = "https://repology.org/api/v1/project/"
HEADERS = {"User-Agent": "DAPrivacyKit-maintenance/1 (https://github.com/DigitalArchon/DAPrivacyKit)"}
PAUSE = 1.1          # Repology asks for at most one request a second
TIMEOUT = 30


@dataclass
class Row:
    app: App
    latest: str = ""             # the newest version found
    repos: int = 0               # how many repositories ship it
    error: str = ""

    @property
    def version(self) -> tuple[int, ...] | None:
        return parse_version(self.latest) if self.latest else None

    @property
    def state(self) -> str:
        if self.error:
            return "error"
        if not self.app.up("repology") and not self.latest:
            return "untracked"
        v = self.version
        if v is None:
            return "unknown"
        if self.app.ahead(v):
            return "new major"
        if self.app.major(v) > self.app.major(self.app.checked):
            return "new major (tolerated)"
        if v > self.app.checked:
            return "newer"
        return "older" if v < self.app.checked else "same"


def repology_newest(name: str) -> tuple[str, int]:
    """(the newest version Repology knows, how many repositories ship it)."""
    req = urllib.request.Request(REPOLOGY + urllib.parse.quote(name, safe=":"), headers=HEADERS)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        packages = json.load(r)
    newest: dict[str, set[str]] = {}
    for p in packages:
        if p.get("status") == "newest" and parse_version(str(p.get("version", ""))):
            newest.setdefault(p["version"], set()).add(p.get("repo", ""))
    if not newest:
        return "", 0
    best = max(newest, key=lambda v: (parse_version(v), len(newest[v])))
    return best, len(newest[best])


def upstream(apps: list[App]) -> list[Row]:
    rows = []
    for i, app in enumerate(apps):
        row = Row(app)
        name = app.up("repology")
        if name:
            if i:
                time.sleep(PAUSE)
            try:
                row.latest, row.repos = repology_newest(name)
            except (urllib.error.URLError, OSError, ValueError) as e:
                row.error = str(getattr(e, "reason", e))[:80]
        rows.append(row)
        print(f"\r{i + 1}/{len(apps)} {app.id:<24}", end="", file=sys.stderr, flush=True)
    print("\r" + " " * 40 + "\r", end="", file=sys.stderr)
    return rows


def installed_here(apps: list[App]) -> list[Row]:
    from daprivacyscanner.host import Host
    have = appversions.installed(Host.local(), appversions.Apps({a.id: a for a in apps}))
    return [Row(a, have[a.id].text if a.id in have else "", 1 if a.id in have else 0) for a in apps if a.id in have]


ORDER = ["new major", "error", "new major (tolerated)", "newer", "unknown", "untracked", "same", "older"]


def table(rows: list[Row], where: str) -> str:
    out = [f"{'app':<16} {'made for':<32} {where:<28} state"]
    for r in sorted(rows, key=lambda r: (ORDER.index(r.state), r.app.id)):
        made = f"{r.app.checked_text} ({r.app.basis}, {r.app.on.isoformat()})"
        latest = r.latest + (f" ({r.repos} repos)" if r.repos > 1 and where == "latest" else "") if r.latest else "-"
        extra = f": {r.error}" if r.error else ""
        if r.state == "new major" and r.app.tolerance:
            extra = f" (tolerance {r.app.tolerance})"
        out.append(f"{r.app.id:<16} {made:<32} {latest:<28} {r.state}{extra}")
    return "\n".join(out)


def check_titles() -> dict[str, tuple[str, str]]:
    """{check id: (title, the files its detection, fix and guide are in)}."""
    from daprivacyscanner.catalogue import load as load_catalogue
    from daprivacyscanner.checks import load_all
    from daprivacyscanner.checks.fixes import FIXES
    from daprivacyscanner.checks.guides import GUIDES
    cat = load_catalogue(ROOT / "privacy-checks.yaml")
    reg = load_all()

    def where(obj) -> str:
        mod = getattr(obj, "__module__", "") or ""
        return "src/" + mod.replace(".", "/") + ".py" if mod else ""

    out = {}
    for spec in cat:
        files = [where(reg[spec.id])] if spec.id in reg else []
        for table_ in (FIXES, GUIDES):
            entry = table_.get(spec.id)
            fn = getattr(entry, "plan", None) or getattr(entry, "build", None)
            if fn is not None and where(fn) not in files:
                files.append(where(fn))
        out[spec.id] = (spec.title, ", ".join(f for f in files if f))
    return out


def brief(rows: list[Row]) -> str:
    """A review brief for the apps with a new major version, to work through with Claude Code."""
    todo = [r for r in rows if r.state == "new major"]
    titles = check_titles()
    lines = [f"# App review: {dt.date.today().isoformat()}", "",
             "Each app below has a major release newer than the version DA Privacy Kit's checks were made for "
             "(apps.yaml). For each one:", "",
             "1. Read its release notes from the version it was made for up to the latest, and the upstream changes "
             "to what the checks rely on (below): files and folders moved or renamed, settings keys renamed or "
             "dropped, database tables or columns changed, file formats changed, commands whose output changed.",
             "2. Read the checks' code (the files named) and say, check by check, whether it still finds what it "
             "looks for and whether its fix still changes something the app reads.",
             "3. Where something changed: update privacy-checks.yaml first, then the code and tests (old and new "
             "versions both handled where users still have the old one), and apps.yaml's relies_on.",
             "4. Where it can be tried on a test machine, do: install the new version, run the checks, apply and "
             "revert the fix.",
             "5. Then record it: `packaging/check-app-versions.py --mark <id> <version>` (`--tested` when it was "
             "tried on a real system).", ""]
    if not todo:
        lines.append("Nothing to review: no app has a new major version.")
    for r in todo:
        a = r.app
        lines += [f"## {a.name} ({a.id}): {a.checked_text} -> {r.latest}", "",
                  f"- Made for: {a.checked_text}, {appversions.BASIS[a.basis]} ({a.on.isoformat()})",
                  f"- Latest: {r.latest} (Repology: {a.up('repology')}, {r.repos} repositories)"]
        if a.up("notes"):
            lines.append(f"- Release notes: {a.up('notes')}")
        if a.up("source"):
            lines.append(f"- Source: {a.up('source')}")
        lines += [f"- Installed from: packages {', '.join(a.packages) or '-'}; Flatpak {', '.join(a.flatpak) or '-'}; "
                  f"Snap {', '.join(a.snap) or '-'}"]
        if a.data:
            lines.append(f"- Where it keeps its data (apps.yaml `data`): {a.data_text()}")
        lines += [f"- The checks rely on: {a.relies_on}"]
        if a.verify:
            lines.append(f"- Still to confirm: {a.verify}")
        lines += ["", "Checks:", ""]
        for cid in a.checks:
            title, files = titles.get(cid, ("(not in the catalogue)", ""))
            lines.append(f"- {cid}: {title}" + (f" ({files})" if files else ""))
        lines.append("")
    untracked = [r.app for r in rows if r.state == "untracked"]
    if untracked:
        lines += ["## Not tracked on Repology", "", "Look at these by hand:", ""]
        lines += [f"- {a.name} ({a.id}): made for {a.checked_text}; {a.up('notes') or 'no release notes link'}"
                  for a in untracked]
        lines.append("")
    return "\n".join(lines)


def mark(text: str, app_id: str, version: str, tested: bool, when: dt.date) -> str:
    """apps.yaml with one app's checked, basis and checked_on replaced, everything else as it was."""
    if parse_version(version) is None:
        raise SystemExit(f"{version!r} isn't a version")
    m = re.search(rf"^  - id: {re.escape(app_id)}\n(?:(?!  - id: ).*\n?)*", text, re.M)
    if not m:
        raise SystemExit(f"no app {app_id!r} in apps.yaml")
    block = m.group(0)
    new = re.sub(r'^    checked: .*$', f'    checked: "{version}"', block, count=1, flags=re.M)
    new = re.sub(r"^    basis: .*$", f"    basis: {'tested' if tested else 'current'}", new, count=1, flags=re.M)
    new = re.sub(r"^    checked_on: .*$", f"    checked_on: {when.isoformat()}", new, count=1, flags=re.M)
    out = text[:m.start()] + new + text[m.end():]
    appversions.parse(__import__("yaml").safe_load(out))          # still valid
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", help="comma-separated app ids")
    ap.add_argument("--brief", metavar="FILE", help="write a review brief for the apps with a new major version")
    ap.add_argument("--installed", action="store_true", help="this computer's versions instead of the latest upstream")
    ap.add_argument("--mark", nargs=2, metavar=("APP", "VERSION"), help="record a reviewed version in apps.yaml")
    ap.add_argument("--tested", action="store_true", help="with --mark: tried on a real system at that version")
    args = ap.parse_args(argv)
    if args.mark:
        APPS_FILE.write_text(mark(APPS_FILE.read_text(encoding="utf-8"), args.mark[0], args.mark[1], args.tested,
                                  dt.date.today()), encoding="utf-8")
        print(f"apps.yaml: {args.mark[0]} made for {args.mark[1]} ({'tested' if args.tested else 'current'})")
        return 0
    apps = list(appversions.load(APPS_FILE))
    if args.only:
        wanted = set(args.only.split(","))
        unknown = wanted - {a.id for a in apps}
        if unknown:
            raise SystemExit(f"not in apps.yaml: {', '.join(sorted(unknown))}")
        apps = [a for a in apps if a.id in wanted]
    rows = installed_here(apps) if args.installed else upstream(apps)
    print(table(rows, "installed here" if args.installed else "latest"))
    if args.brief:
        Path(args.brief).write_text(brief(rows), encoding="utf-8")
        print(f"\nReview brief: {args.brief}")
    return 1 if any(r.state == "new major" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
