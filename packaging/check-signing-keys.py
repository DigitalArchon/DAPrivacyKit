#!/usr/bin/env python3
"""Before a release: check that every fingerprint in signing-keys.yaml is still published on its
project's own page, and how old each confirmation is.

Run by hand (`.venv/bin/python packaging/check-signing-keys.py`), never from the test suite, which
stays offline. It fetches each `source` page once and looks for each pinned fingerprint in it (spaces
and case ignored). A page that turns scripts away is listed apart, to open in a browser; a project
whose `note` says how it was confirmed otherwise (Linux Mint, Arch, Qubes OS) shows that note. The
checksums a project publishes for files it doesn't sign are looked for on their pages too. Each bundled key's
and subkey's expiry is shown, warned about within EXPIRY_WARN_DAYS. For the browser in memory, the current Tor
Browser and Mullvad Browser releases' signatures (RELEASE_PROBES: the projects' own download indexes, then the
.asc they name, a few hundred bytes) must name a subkey the app carries: Tor Browser's signing subkey is
replaced every year or two, and the app refuses to unpack anything else. Exit status 1 if a fingerprint has
gone from a page that could be read (the project may have changed keys), a primary key or every subkey of a
project has expired (an old subkey kept beside current ones is only listed), or a release is signed by a subkey
the app doesn't carry. Pages are read gzipped or not (Proton's come gzipped unasked). The keys themselves are checked against their pins every time the
app loads them (tools/keys.py)."""

from __future__ import annotations

import datetime as dt
import gzip
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from daprivacyscanner.tools import keys  # noqa: E402

TIMEOUT = 20
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
           "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en"}
STALE_DAYS = 365
EXPIRY_WARN_DAYS = 120
# project id -> the download indexes of releases its key signs (tools/browser.py's)
RELEASE_PROBES = {"torbrowser": ("https://aus1.torproject.org/torbrowser/update_3/release/download-linux-x86_64.json",
                                 "https://cdn.mullvad.net/browser/update_responses/update_1/release/download-linux-x86_64.json")}


def fetch(url: str) -> tuple[str | None, str]:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = r.read(4_000_000)
            if data[:2] == b"\x1f\x8b":         # gzip, asked for or not (Proton's pages)
                data = gzip.decompress(data)
            return data.decode("utf-8", errors="replace"), str(r.status)
    except urllib.error.HTTPError as e:
        return None, str(e.code)
    except (urllib.error.URLError, OSError, EOFError) as e:
        return None, f"no answer ({str(getattr(e, 'reason', e))[:60]})"


def main() -> int:
    today = dt.date.today()
    missing = 0
    for p in keys.load():
        text, code = fetch(p.source)
        page = re.sub(r"[\s ]", "", text).upper() if text else ""
        age = (today - p.checked).days
        print(f"{p.name}: {p.source} ({code}), confirmed {p.checked.isoformat()} ({age} days ago"
              + (", over a year: confirm it again" if age > STALE_DAYS else "") + ")")
        for fpr, name in p.keys:
            if not text or "Just a moment" in (text or "")[:5000]:
                state = "page turned the script away: check it in a browser"
            elif fpr in page or fpr[-16:] in page:
                state = "on the page"
            else:
                state = "NOT ON THE PAGE"
                missing += 1
            print(f"    {keys.group(fpr)}  {name}: {state}")
        if p.unsigned:
            print("    publishes no signature: look again for one")
        for name, digest, url in p.checksums:
            ptext = text if url == p.source else fetch(url)[0]
            if ptext is None or "Just a moment" in ptext[:5000]:
                state = f"{url} turned the script away: check it in a browser"
            elif digest in ptext.lower():
                state = "on its page"
            else:
                state = f"NOT ON {url} (a new release? update it)"
                missing += 1
            print(f"    {name} sha256 {digest[:16]}…: {state}")
        if p.note:
            print(f"    note: {p.note}")
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        expiries = keys.key_expiries(p.key) if p.key else {}       # none for an unsigned project
        primaries = {f for f, _ in p.keys}
        subkeys = {f: e for f, e in expiries.items() if f not in primaries}
        # a project keeps its old subkeys in its key, expired, for the releases they signed (Tails does):
        # only a primary key that has run out, or every subkey, is something a re-export could mend
        all_gone = bool(subkeys) and all(e is not None and e < now for e in subkeys.values())
        for fpr, expires in expiries.items():
            if expires is None:
                continue
            days = int((expires - now) // 86400)
            when = dt.datetime.fromtimestamp(expires, dt.timezone.utc).date().isoformat()
            if days < 0 and (fpr in primaries or all_gone):
                print(f"    key {keys.group(fpr)} EXPIRED on {when}: re-export it from {p.key_from}")
                missing += 1
            elif days < 0:
                print(f"    subkey {keys.group(fpr)} expired on {when} (an old one: others are current)")
            elif days < EXPIRY_WARN_DAYS:
                print(f"    key {keys.group(fpr)} expires on {when} ({days} days): re-export it from {p.key_from} once "
                      "the project extends it")
        for index in RELEASE_PROBES.get(p.id, ()):
            text, code = fetch(index)
            try:
                sig_url = json.loads(text or "")["sig"]
                sig, code = fetch(sig_url)
                issuers = keys.signature_issuers(sig or "")
            except (ValueError, KeyError, TypeError, keys.PacketError):
                print(f"    {index}: couldn't be read ({code})")
                continue
            ours = {f for f, _ in p.keys} | set(p.subkeys)
            known = [i for i in issuers if i in ours or any(f.endswith(i) for f in ours)]
            if known:
                print(f"    {sig_url.rsplit('/', 1)[-1]}: signed by {keys.group(known[0])}, a key the app carries")
            else:
                print(f"    {sig_url.rsplit('/', 1)[-1]}: signed by {', '.join(issuers) or 'nothing readable'}, NOT A KEY "
                      f"THE APP CARRIES: re-export the key from {p.key_from}, or the browser in memory refuses it")
                missing += 1
    print("\nA fingerprint on the page is what matters; re-export a key from its `key_from` when its subkeys "
          "change (the app refuses a key that doesn't match its pin).")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
