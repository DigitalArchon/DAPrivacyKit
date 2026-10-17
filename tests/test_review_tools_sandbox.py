"""What the tools review of 2026-10-17 found in the browser's sandbox and network (sandbox.py, torgate.py), kept
fixed. Nothing here starts bubblewrap or pasta."""

from __future__ import annotations

import re
from pathlib import Path

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
