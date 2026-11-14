"""The app and the helper are undumpable (PR_SET_DUMPABLE 0, the DA apps' one security standard, 2026-11-14), beside
the core size limit of 1 and coredump_filter 0 they had: no other program of the account reads their memory,
environment or open files through /proc or attaches to them. GTK and GLib in the app's own process are told not to
use portals, which refuse an undumpable process; what the app starts gets the environment as it was, and is
dumpable again from its exec. In a process of its own: these change the process for good."""

from __future__ import annotations

import json
import subprocess
import sys

CHILD = ("import ctypes, json, os, resource; print(json.dumps({'dumpable': ctypes.CDLL(None).prctl(3, 0, 0, 0, 0), "
         "'core': resource.getrlimit(resource.RLIMIT_CORE), 'filter': open('/proc/self/coredump_filter').read().strip(), "
         "'portal': os.environ.get('GTK_USE_PORTAL')}))")


def _run(code: str, env_portal: str | None = None) -> dict:
    import os
    env = {k: v for k, v in os.environ.items() if k != "GTK_USE_PORTAL"}
    if env_portal is not None:
        env["GTK_USE_PORTAL"] = env_portal
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


APP = ("import ctypes, json, os, subprocess, sys; from daprivacyscanner.app import no_core_dumps; no_core_dumps(); "
       "from daprivacyscanner.hostenv import host_env; "
       f"child = json.loads(subprocess.run([sys.executable, '-c', {CHILD!r}], capture_output=True, text=True, "
       "env=host_env()).stdout); "
       "print(json.dumps({'dumpable': ctypes.CDLL(None).prctl(3, 0, 0, 0, 0), "
       "'portal': os.environ.get('GTK_USE_PORTAL'), 'child': child}))")


def test_the_app_is_undumpable_and_what_it_starts_gets_the_environment_as_it_was():
    for given in (None, "1"):                       # unset, or set by a desktop that wants GTK's portals
        r = _run(APP, given)
        assert r["dumpable"] == 0 and r["portal"] == "0"
        child = r["child"]
        assert child["dumpable"] == 1 and child["portal"] == given      # its own, again, from its exec
        assert child["core"] == [1, 1] and child["filter"] == "00000000"    # these are inherited


def test_the_helper_is_undumpable():
    r = _run("import ctypes, json; from daprivacyscanner import helper; helper._no_dumps(); "
             "import resource; print(json.dumps({'dumpable': ctypes.CDLL(None).prctl(3, 0, 0, 0, 0), "
             "'core': resource.getrlimit(resource.RLIMIT_CORE)}))")
    assert r == {"dumpable": 0, "core": [1, 1]}
