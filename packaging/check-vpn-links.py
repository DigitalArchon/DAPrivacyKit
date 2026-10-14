#!/usr/bin/env python3
"""Before a release: check the links in vpn-providers.yaml and browsers.yaml, and how old each claim is.

Run by hand (`.venv/bin/python packaging/check-vpn-links.py`), never from the test suite, which
stays offline. It fetches every source and leak-test page once, prints the claims oldest first
with each link's HTTP status, and exits 1 if a link is dead (a site that turns scripts away
is listed apart, to open in a browser). A live link isn't proof the claim
still holds: read the source before updating its `verified` date."""

from __future__ import annotations

import datetime as dt
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from daprivacyscanner import browsers, vpn  # noqa: E402

TIMEOUT = 15


HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
           "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en"}


def status(url: str) -> tuple[str, str]:
    """(ok | blocked | dead, what happened). Sites that turn scripts away (403, 429, a dropped connection)
    are "blocked": open those in a browser. Only a missing page or host is "dead"."""
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return "ok", str(r.status)
    except urllib.error.HTTPError as e:
        return ("dead" if e.code in (404, 410) else "blocked"), str(e.code)
    except urllib.error.URLError as e:
        reason = str(getattr(e, "reason", e))
        return ("dead" if "Name or service not known" in reason else "blocked"), f"no answer ({reason[:60]})"
    except OSError as e:
        return "blocked", f"no answer ({str(e)[:60]})"


def main() -> int:
    data = vpn.load()
    today = dt.date.today()
    rows: dict[str, list[tuple[dt.date, str]]] = {}      # url -> [(verified, what)]
    for p in data:
        for f in p.all_facts():
            rows.setdefault(f.source, []).append((f.verified, f"{p.name}: {f.topic}"))
        if p.leak_test:
            rows.setdefault(p.leak_test, []).append((p.leak_test_verified, f"{p.name}: leak test page"))
        if p.browser_proxy:
            rows.setdefault(p.browser_proxy.source, []).append(
                (p.browser_proxy.verified, f"{p.name}: the proxy Mullvad Browser is set up with ({p.browser_proxy.hostname})"))
    for b in browsers.load():
        for f in b.facts:
            rows.setdefault(f.source, []).append((f.verified, f"{b.name} (browser): {f.topic}"))
    counts = {"ok": 0, "blocked": 0, "dead": 0}
    checked = {url: status(url) for url in rows}
    for url, claims in sorted(rows.items(), key=lambda kv: min(d for d, _ in kv[1])):
        state, code = checked[url]
        counts[state] += 1
        oldest = min(d for d, _ in claims)
        print(f"{state.upper() if state != 'ok' else 'ok':7} {code:>4}  {(today - oldest).days:>4} days  {url}")
        for d, what in sorted(set(claims)):
            print(f"{'':16}{d.isoformat()}  {what}")
    stale = [p.name for p in data if vpn.stale(p, today)]
    if stale:
        print(f"\nOlder than {vpn.STALE_DAYS} days (the app says so to users): {', '.join(stale)}")
    print(f"\n{len(rows)} links: {counts['ok']} fine, {counts['blocked']} turned the script away (open them in a "
          f"browser), {counts['dead']} dead.")
    return 1 if counts["dead"] else 0


if __name__ == "__main__":
    sys.exit(main())
