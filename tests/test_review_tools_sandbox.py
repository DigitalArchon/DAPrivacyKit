"""What the tools review of 2026-10-17 found in the browser's sandbox and network (sandbox.py, torgate.py), kept
fixed. Nothing here starts bubblewrap or pasta."""

from __future__ import annotations

import re
from pathlib import Path

from daprivacyscanner.host import FakeRunner, Host
from daprivacyscanner.tools import sandbox as S

DOCS = Path(__file__).resolve().parents[1] / "docs"


def test_the_docs_give_the_core_limit_the_start_sets():
    """B8: the start sets a core size limit of 1, at which the kernel skips the dump (at 0 systemd-coredump kept one
    and journalled the command line); the design notes said 0."""
    assert S.NO_CORE == 1 and "resource.RLIMIT_CORE, (1, 1)" in S.KEYRING
    text = (DOCS / "TECHNICAL.md").read_text()
    assert "Sets `RLIMIT_CORE` to (1, 1)" in text and "Sets `RLIMIT_CORE` to (0, 0)." not in text
    source = Path(S.__file__).read_text()
    assert not re.search(r"a core size limit of 0\.", source)


def test_only_the_language_goes_in_not_the_regional_formats(tmp_path):
    """B6: the regional formats (ro_RO on one machine, hu_HU on another, under an English LANG) said the country
    while the clock inside is UTC. The language goes in; the formats, and LC_ALL that would carry them, don't."""
    env = {"LANG": "en_US.UTF-8", "LANGUAGE": "en_US", "LC_CTYPE": "en_US.UTF-8", "LC_MESSAGES": "en_US.UTF-8",
           "LC_TIME": "ro_RO.UTF-8", "LC_NUMERIC": "ro_RO.UTF-8", "LC_MONETARY": "ro_RO.UTF-8", "LC_PAPER": "ro_RO.UTF-8",
           "LC_MEASUREMENT": "ro_RO.UTF-8", "LC_ALL": "hu_HU.UTF-8", "TZ": "Europe/Bucharest"}
    host = Host(home=tmp_path, environ=env, runner=FakeRunner(), root=tmp_path, uid=1000)
    argv = S._env(host, S.Display("x11", [], {"DISPLAY": ":99"}), False)
    got = {argv[i + 1]: argv[i + 2] for i, a in enumerate(argv) if a == "--setenv"}
    assert {k: got[k] for k in ("LANG", "LANGUAGE", "LC_CTYPE", "LC_MESSAGES")} == {
        "LANG": "en_US.UTF-8", "LANGUAGE": "en_US", "LC_CTYPE": "en_US.UTF-8", "LC_MESSAGES": "en_US.UTF-8"}
    assert not any(k in got for k in ("LC_TIME", "LC_NUMERIC", "LC_MONETARY", "LC_PAPER", "LC_MEASUREMENT", "LC_ALL"))
    assert got["TZ"] == "UTC" and "ro_RO" not in " ".join(argv) and "hu_HU" not in " ".join(argv)
