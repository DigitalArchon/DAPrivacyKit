"""A check ruff doesn't have: a program started through subprocess without a timeout. A tool that hangs (a gpgv
waiting on a pipe, a dbus call nobody answers, a mount on a dead network share) then hangs the scan, a fix or the
helper with it.

Flags subprocess.run, call, check_call and check_output, and Popen's communicate(), called without `timeout=` (a
call that passes **kwargs is taken to pass it on). A call that must wait for as long as the program runs (a viewer,
the browser) says so on its line: `# timeout: none (why)`.

    python packaging/ci/check_timeouts.py [--baseline FILE] [--write-baseline FILE] PATH...

The baseline (packaging/ci/timeouts-baseline.txt) lists the calls found when the check was introduced, as
`path::function` (line numbers move), to be burnt down: a call that isn't in it fails the check, and an entry no
longer found is reported so the list can shrink."""

from __future__ import annotations

import argparse
import ast
import sys
from collections import Counter
from pathlib import Path

FUNCS = {"run", "call", "check_call", "check_output"}


class Finder(ast.NodeVisitor):
    def __init__(self, path: str, lines: list[str]):
        self.path, self.lines = path, lines
        self.stack: list[str] = []
        self.names: set[str] = set()              # names bound by `from subprocess import run, ...`
        self.found: list[tuple[int, str, str]] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "subprocess":
            self.names |= {a.asname or a.name for a in node.names if a.name in FUNCS}

    def _scoped(self, node) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scoped

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        what = None
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "subprocess" \
                and f.attr in FUNCS:
            what = f"subprocess.{f.attr}"
        elif isinstance(f, ast.Name) and f.id in self.names:
            what = f.id
        elif isinstance(f, ast.Attribute) and f.attr == "communicate":
            what = "communicate"
        if what and not any(k.arg == "timeout" or k.arg is None for k in node.keywords):
            line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
            if "# timeout: none" not in line:
                self.found.append((node.lineno, what, ".".join(self.stack) or "<module>"))
        self.generic_visit(node)


def scan(paths: list[str]) -> list[tuple[str, int, str, str]]:
    out = []
    for root in paths:
        files = [Path(root)] if Path(root).is_file() else sorted(Path(root).rglob("*.py"))
        for p in files:
            text = p.read_text(encoding="utf-8")
            finder = Finder(str(p), text.splitlines())
            finder.visit(ast.parse(text, str(p)))
            out += [(str(p), line, what, where) for line, what, where in finder.found]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--baseline")
    ap.add_argument("--write-baseline")
    a = ap.parse_args()
    found = scan(a.paths)
    keys = Counter(f"{path}::{where}" for path, _, _, where in found)
    if a.write_baseline:
        Path(a.write_baseline).write_text(
            "# packaging/ci/check_timeouts.py: calls without a timeout when the check came in, to burn down.\n"
            + "".join(f"{k} {n}\n" for k, n in sorted(keys.items())), encoding="utf-8")
        return 0
    allowed: Counter = Counter()
    if a.baseline:
        for line in Path(a.baseline).read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                k, _, n = line.rpartition(" ")
                allowed[k] = int(n)
    new = [f for f in found if keys[f"{f[0]}::{f[3]}"] > allowed.get(f"{f[0]}::{f[3]}", 0)]
    for path, line, what, where in new:
        print(f"{path}:{line}: {what}() without a timeout (in {where}); pass timeout=, or say why not: "
              "# timeout: none (why)")
    gone = sorted(k for k in allowed if keys.get(k, 0) < allowed[k])
    for k in gone:
        print(f"note: {k} has fewer calls without a timeout than the baseline says: shrink "
              f"{a.baseline} (--write-baseline)")
    if found and not new:
        print(f"{len(found)} known call(s) without a timeout, in the baseline ({sum(allowed.values())} listed)")
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
