"""The Outbox, one file at a time (the review of 2026-11-12): a file that can't be cleaned goes to Not cleaned and
the rest go on; the working copy goes where there is room; a file still arriving waits as the TempOutbox's do."""

from __future__ import annotations

import os
import time

import pytest

from daprivacyscanner.tools import metadata as M

from conftest import make_host
from test_metadata_tools import fake_mat2


def outbox_host(tmp_path, files):
    host = make_host(tmp_path, home_files={f"Outbox/{n}": t for n, t in files.items()},
                     env={"XDG_RUNTIME_DIR": str(tmp_path / "run")})
    (tmp_path / "run").mkdir()
    host.runner.handlers["mat2"] = fake_mat2()
    old = time.time() - 60
    for n in files:
        os.utime(host.home / "Outbox" / n, (old, old))
    return host, host.home / "Outbox"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads files whatever their mode")
def test_one_file_that_cant_be_cleaned_never_stops_the_rest(tmp_path, monkeypatch):
    """shutil.copy2 into the runtime folder was uncaught: a video larger than that tmpfs, or a file moved away mid-run,
    ended the run with nothing said, and every file after it waited, failing the same way at each trigger."""
    host, box = outbox_host(tmp_path, {"a.jpg": "a", "b.jpg": "b", "c.jpg": "c", "d.jpg": "d"})
    os.chmod(box / "a.jpg", 0)                                          # can't be read
    real = M.clean

    def clean(h, p, **kw):
        if p.name == "b.jpg":
            raise RuntimeError("mat2 went wrong")
        if p.name == "c.jpg":
            raise OSError(28, "No space left on device", str(p))
        return real(h, p, **kw)
    monkeypatch.setattr(M, "clean", clean)
    run = M.run_outbox(host)
    assert run.cleaned == ["d.jpg"] and dict(run.not_cleaned) == {
        "a.jpg": "It can't be read (Permission denied).", "b.jpg": "It couldn't be cleaned (RuntimeError).",
        "c.jpg": "It couldn't be cleaned (No space left on device)."}
    assert sorted(p.name for p in (box / "Not cleaned").iterdir()) == ["a.jpg", "b.jpg", "c.jpg"]
    assert (box / "Cleaned/d.jpg").read_text() == "clean:d" and (box / "Originals/d.jpg").read_text() == "d"
    assert not any(str(tmp_path) in why for _, why in run.not_cleaned)            # no path: the unit's output is kept
    assert not list((tmp_path / "run").iterdir()) and not list(box.glob(".daprivacyscanner-*"))


def test_a_file_moved_away_meanwhile_is_passed_over(tmp_path, monkeypatch):
    host, box = outbox_host(tmp_path, {"a.jpg": "a", "b.jpg": "b"})
    real = M.clean

    def clean(h, p, **kw):
        if p.name == "a.jpg":
            os.rename(box / "a.jpg", tmp_path / "a.jpg")
            raise OSError(2, "No such file or directory")
        return real(h, p, **kw)
    monkeypatch.setattr(M, "clean", clean)
    run = M.run_outbox(host)
    assert run.cleaned == ["b.jpg"] and [n for n, _ in run.not_cleaned] == []
    assert (tmp_path / "a.jpg").read_text() == "a"


def test_the_working_copy_goes_where_there_is_room(tmp_path, monkeypatch):
    """The runtime folder is memory, often a tenth of it: a large file is cleaned in a hidden folder inside the
    Outbox (the disk the original is on), and where neither has room it goes to Not cleaned, saying why."""
    host, box = outbox_host(tmp_path, {"film.jpg": "x" * 1000})
    run_dir = str(tmp_path / "run")
    monkeypatch.setattr(M, "_room", lambda where: 10 if where == run_dir else 1 << 40)
    seen = []
    real = M.clean
    monkeypatch.setattr(M, "clean", lambda h, p, **kw: seen.append(p.parent) or real(h, p, **kw))
    assert M.run_outbox(host).cleaned == ["film.jpg"]
    assert seen[0].parent == box and seen[0].name.startswith(".daprivacyscanner-outbox-") and not seen[0].exists()
    (box / "big.jpg").write_text("y" * 1000)
    os.utime(box / "big.jpg", (1, 1))
    monkeypatch.setattr(M, "_room", lambda where: 10)
    run = M.run_outbox(host)
    assert not run.cleaned and run.not_cleaned[0][0] == "big.jpg" and "isn't room" in run.not_cleaned[0][1]
    assert (box / "Not cleaned/big.jpg").exists()


def test_a_file_still_arriving_waits_as_the_tempoutboxs_do(tmp_path, monkeypatch):
    """"Settled" was only an mtime two seconds old: a copy that stalled was cleaned half-written and the original
    moved into Originals. Now: open for writing by no program of the user's, unchanged while it is copied and
    cleaned, and, in the unit's run, unchanged since the last look."""
    from daprivacyscanner.tools import transfer
    host, box = outbox_host(tmp_path, {"held.jpg": "half", "grows.jpg": "part", "done.jpg": "all"})
    held = os.stat(box / "held.jpg")
    monkeypatch.setattr(transfer, "open_for_writing", lambda h, wanted: {(held.st_dev, held.st_ino)} & wanted)
    real = M.clean

    def clean(h, p, **kw):
        if p.name == "grows.jpg":                       # more of it arrives while its copy is cleaned
            with open(box / "grows.jpg", "a") as f:
                f.write(" and more")
        return real(h, p, **kw)
    monkeypatch.setattr(M, "clean", clean)
    run = M.run_outbox(host)
    assert run.cleaned == ["done.jpg"] and sorted(run.skipped) == ["grows.jpg", "held.jpg"] and not run.not_cleaned
    assert (box / "held.jpg").exists() and (box / "grows.jpg").read_text() == "part and more"
    assert not (box / "Cleaned/grows.jpg").exists() and not (box / "Originals/held.jpg").exists()
    # the unit's run looks twice: a file seen for the first time is left for the next pass
    old = time.time() - 60
    os.utime(box / "grows.jpg", (old, old))
    looks = M.OutboxLooks()
    monkeypatch.setattr(transfer, "open_for_writing", lambda h, wanted: set())
    monkeypatch.setattr(M, "clean", real)
    first = M.run_outbox(host, looks=looks)
    assert not first.cleaned and sorted(first.skipped) == ["grows.jpg", "held.jpg"]
    assert sorted(M.run_outbox(host, looks=looks).cleaned) == ["grows.jpg", "held.jpg"]


def test_an_outbox_that_fails_says_so(monkeypatch):
    import sys

    from daprivacyscanner import app
    told = []

    def broken(host):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(M, "run_outbox_settled", broken)
    monkeypatch.setattr(M, "notify_outbox_failed", lambda host: told.append(True))
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False, raising=False)
    assert app.outbox_cli() == 1 and told == [True]
