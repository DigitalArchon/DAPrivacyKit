"""A baseline for a linter that came in after the code: what it found then is counted per file and error code
(packaging/ci/*-baseline.txt), and a run fails only on more than that. Line numbers move with every edit and
aren't kept; a count that drops is reported, so the baseline can shrink (--write) and nothing grows back.

    ruff check --output-format json ... | python packaging/ci/ratchet.py ruff BASELINE [--write]
    mypy ... | python packaging/ci/ratchet.py mypy BASELINE [--write]

Each line of a baseline is `path code count`. The burn-down is that file going empty."""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

MYPY = re.compile(r"^(?P<path>[^:\n]+):(?P<line>\d+):(?:\d+:)? error: (?P<msg>.*?)\s+\[(?P<code>[a-z0-9-]+)\]$")


def findings(tool: str, text: str) -> list[tuple[str, str, str]]:
    """(path, code, what) for each finding, paths relative to the working directory."""
    out = []
    if tool == "ruff":
        for e in json.loads(text or "[]"):
            path = os.path.relpath(e["filename"])
            out.append((path, e["code"] or "syntax", f"{path}:{e['location']['row']}: {e['code']} {e['message']}"))
    else:
        for line in text.splitlines():
            m = MYPY.match(line.strip())
            if m:
                path = os.path.relpath(m["path"])
                out.append((path, m["code"], f"{path}:{m['line']}: [{m['code']}] {m['msg']}"))
            elif ": error:" in line:          # an error without a code (a syntax error, a bad config): never baselined
                out.append((line.split(":", 1)[0], "error", line.strip()))
    return out


def read(baseline: Path) -> Counter:
    counts: Counter = Counter()
    if baseline.is_file():
        for line in baseline.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                path, code, n = line.rsplit(None, 2)
                counts[(path, code)] = int(n)
    return counts


def write(baseline: Path, tool: str, counts: Counter) -> None:
    head = (f"# {tool}: what it found when packaging/check.sh came in (2026-11-12), per file and error code, to burn\n"
            f"# down. packaging/ci/ratchet.py fails a run on more than this; packaging/check.sh --rebaseline rewrites it.\n")
    baseline.write_text(head + "".join(f"{p} {c} {n}\n" for (p, c), n in sorted(counts.items())), encoding="utf-8")


def main() -> int:
    tool, baseline = sys.argv[1], Path(sys.argv[2])
    found = findings(tool, sys.stdin.read())
    counts = Counter((p, c) for p, c, _ in found)
    if "--write" in sys.argv[3:]:
        write(baseline, tool, Counter({k: n for k, n in counts.items() if k[1] != "error"}))
        print(f"{tool}: {sum(counts.values())} finding(s) written to {baseline}")
        return 0
    allowed = read(baseline)
    over = {k for k, n in counts.items() if n > allowed.get(k, 0)}
    for path, code, what in found:
        if (path, code) in over:
            print(what)
    for (path, code) in sorted(over):
        if allowed.get((path, code)):
            print(f"  ({path}: {counts[(path, code)]} {code}, the baseline allows {allowed[(path, code)]}: one of the "
                  f"above is new)")
    shrunk = sorted(k for k, n in allowed.items() if counts.get(k, 0) < n)
    if shrunk:
        print(f"{tool}: {len(shrunk)} baseline entr{'y' if len(shrunk) == 1 else 'ies'} have fewer findings now "
              f"(packaging/check.sh --rebaseline shrinks {baseline})")
    known = sum(min(n, allowed.get(k, 0)) for k, n in counts.items())
    print(f"{tool}: {'FAILED, ' if over else ''}{sum(n for k, n in counts.items() if k in over)} new, "
          f"{known} known (baseline {sum(allowed.values())})")
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
