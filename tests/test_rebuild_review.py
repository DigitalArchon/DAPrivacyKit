"""Deleted file names, clearing them from a folder (the review of 2026-11-12): the folder keeps every file while it is
rebuilt (hard links; only subfolders move, last); what programs do meanwhile is followed; programs are looked for
again just before each folder; a note kept only while a folder is done lets the panel finish one a crash interrupted;
fscrypt folders aren't rebuilt; only folders the listing showed can be cleaned."""

from __future__ import annotations

import json
import os

import pytest

from daprivacyscanner.tools import names as N
from daprivacyscanner.tools import rebuild as R

from test_deleted_names import Helper, big, fake_proc
from test_trimtest import home_folders, host_for, make_storage, root  # noqa: F401 - the fixture


def tree(folder):
    return sorted((p.relative_to(folder).as_posix(), p.is_symlink(), p.is_dir()) for p in folder.rglob("*"))


def documents(tmp_path):
    top = tmp_path / "home"
    docs = top / "Documents"
    (docs / "sub").mkdir(parents=True)
    (docs / "sub/s.txt").write_text("s")
    for n in ("a.txt", "b.txt", "c.txt"):
        (docs / n).write_text(n)
    os.symlink("a.txt", docs / "link")
    return top, docs


def test_the_folder_keeps_every_file_while_it_is_rebuilt(tmp_path, monkeypatch):
    """Emptied at its live path before the swap, ~/Documents read as partly or wholly empty to anything path-based
    (a backup, a sync client's scan, an app starting) for as long as the moves took."""
    top, docs = documents(tmp_path)
    files = {"a.txt", "b.txt", "c.txt", "link"}
    seen = []
    real_link, real_move = R.LINK, R.MOVE

    def link(src, name, dst):
        seen.append(set(os.listdir(docs)))
        return real_link(src, name, dst)

    def move(src, name, dst):
        seen.append(set(os.listdir(docs)))
        return real_move(src, name, dst)
    monkeypatch.setattr(R, "LINK", link)
    monkeypatch.setattr(R, "MOVE", move)
    before = tree(docs)
    r = R.rebuild(top, "Documents")
    assert all(files <= s for s in seen) and r["moved"] == 5
    assert tree(docs) == before and os.listdir(top) == ["Documents"]
    assert all(os.stat(docs / n).st_nlink == 1 for n in ("a.txt", "b.txt", "c.txt"))     # no second name left
    assert os.readlink(docs / "link") == "a.txt"                                        # a link linked as itself


def test_what_programs_do_meanwhile_is_followed(tmp_path, monkeypatch):
    """Between carrying the entries over and the swap: a file saved again (a new copy renamed over the old), one
    deleted, one renamed, one created. The rebuilt folder shows each as the program left it."""
    top, docs = documents(tmp_path)
    real = R._finish

    def meanwhile(old, new, st):
        (docs / ".a.tmp").write_text("a, saved again")
        os.replace(docs / ".a.tmp", docs / "a.txt")
        os.unlink(docs / "b.txt")
        os.rename(docs / "c.txt", docs / "c-renamed.txt")
        (docs / "new.txt").write_text("made meanwhile")
        return real(old, new, st)
    monkeypatch.setattr(R, "_finish", meanwhile)
    R.rebuild(top, "Documents")
    assert sorted(os.listdir(docs)) == ["a.txt", "c-renamed.txt", "link", "new.txt", "sub"]
    assert (docs / "a.txt").read_text() == "a, saved again" and (docs / "new.txt").read_text() == "made meanwhile"
    assert (docs / "c-renamed.txt").read_text() == "c.txt" and os.listdir(top) == ["Documents"]


def test_a_file_that_cant_be_linked_is_moved(tmp_path, monkeypatch):
    """The kernel's protected_hardlinks keeps a user from linking a file they don't own and can't write."""
    top, docs = documents(tmp_path)
    real = R.LINK
    monkeypatch.setattr(R, "LINK", lambda src, name, dst: False if name == "b.txt" else real(src, name, dst))
    before = tree(docs)
    R.rebuild(top, "Documents")
    assert tree(docs) == before and (docs / "b.txt").read_text() == "b.txt"


def test_an_fscrypt_folder_isnt_rebuilt(tmp_path, monkeypatch):
    top, docs = documents(tmp_path)
    monkeypatch.setattr(R, "_flags", lambda fd: R.FS_ENCRYPT_FL)
    with pytest.raises(R.Refused, match="fscrypt"):
        R.rebuild(top, "Documents")
    assert os.listdir(top) == ["Documents"]


# ------------------------------------------------------------------ interrupted

def note_host(tmp_path):
    from conftest import make_host
    host = make_host(tmp_path, env={"XDG_RUNTIME_DIR": str(tmp_path)})
    return host


def crash(host, docs_rel: str, kind: str, **more) -> None:
    """The note a clean-up keeps, as a crash leaves it."""
    p = R.note_path(host)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"kind": kind, "scope": "home", "root": str(host.home), "rel": docs_rel, "started": 0, **more}))


@pytest.mark.parametrize("swapped", [False, True])
def test_an_interrupted_rebuild_is_finished_from_its_note(tmp_path, monkeypatch, swapped):
    """SIGKILL, the OOM killer, a logout or a power cut mid-way left entries in a hidden 0700 .NAME.rebuild-… folder
    that nothing recorded or looked for."""
    host = note_host(tmp_path)
    docs = host.home / "Documents"
    (docs / "sub").mkdir(parents=True)
    (docs / "sub/s.txt").write_text("s")
    (docs / "a.txt").write_text("a")
    info = {}

    class Killed(BaseException):
        pass

    def die(*a, **kw):                                   # the process ends here: nothing after it runs
        raise Killed

    real_uncarry, real_reconcile = R._uncarry, R._reconcile
    monkeypatch.setattr(R, "_uncarry", lambda *a: (_ for _ in ()).throw(Killed()))
    if swapped:
        monkeypatch.setattr(R, "_reconcile", die)
    else:
        monkeypatch.setattr(R, "_finish", die)
    with pytest.raises(Killed):
        R.rebuild(host.home, "Documents", lambda i: info.update(i))
    monkeypatch.setattr(R, "_uncarry", real_uncarry)
    monkeypatch.setattr(R, "_reconcile", real_reconcile)
    hidden = sorted(n for n in os.listdir(host.home) if n.startswith("."))
    assert hidden and all(N.REBUILT.match(n) for n in hidden)                     # what a crash leaves
    crash(host, "Documents", "rebuild", **info)
    said = R.interrupted(host)
    assert said["kind"] == "rebuild" and said["path"] == "~/Documents" and "Finish it" in said["text"]
    r = R.recover(host)
    assert "whole again" in r["text"] and not r["commands"]
    assert sorted(os.listdir(host.home)) == ["Documents"] or sorted(os.listdir(host.home)) == [".local", "Documents"]
    assert sorted(os.listdir(docs)) == ["a.txt", "sub"] and (docs / "sub/s.txt").read_text() == "s"
    assert os.stat(docs / "a.txt").st_nlink == 1 and R.interrupted(host) is None
    assert not R.note_path(host).exists()


def test_fillers_a_crash_left_are_removed(tmp_path):
    host = note_host(tmp_path)
    docs = host.home / "Documents"
    docs.mkdir(parents=True)
    (docs / "notes.txt").write_text("mine")
    (docs / "_____").write_text("the user's own, not empty")
    for n in ("_______", "______0", "______1"):
        (docs / n).touch()
    crash(host, "Documents", "fillers", lengths=[7])
    r = R.recover(host)
    assert "3 fillers" in r["text"] and sorted(os.listdir(docs)) == ["_____", "notes.txt"]


def test_a_note_held_by_a_running_copy_isnt_taken_for_an_interrupted_one(tmp_path):
    host = note_host(tmp_path)
    (host.home / "Documents").mkdir(parents=True)
    with R.Note(host, {"scope": "home", "root": str(host.home)}, "Documents", "fillers"):
        assert R.note_path(host).exists() and R.interrupted(host) is None
        with pytest.raises(R.Refused, match="Another copy"):
            R.Note(host, {"scope": "home", "root": str(host.home)}, "Documents", "fillers").__enter__()
    assert not R.note_path(host).exists()


def test_a_clean_up_waits_for_the_interrupted_one_and_looks_again_before_each_folder(root, monkeypatch):  # noqa: F811
    big(monkeypatch, "Documents")
    make_storage(root)
    home = home_folders(root)
    (home / "Music").mkdir()
    host = host_for(root)
    crash(host, "Documents", "fillers", lengths=[3])
    with pytest.raises(R.Refused, match="interrupted"):
        R.run(host, "/", ["Documents"], lambda: Helper(), {})
    R.recover(host)
    # a program opens something in Music while Documents is rebuilt: Music is looked at again, and left alone
    real = R.rebuild

    def rebuild(top, rel, record=lambda i: None):
        out = real(top, rel, record)
        (home / "Music/song.ogg").write_text("x")
        fake_proc(root, "player", home / "Music")
        return out
    monkeypatch.setattr(R, "rebuild", rebuild)
    big(monkeypatch, "Documents", "Music")
    r = R.run(host, "/", ["Documents", "Music"], lambda: Helper(), {})
    f = {x["path"]: x for x in r["folders"]}
    assert f["~/Music"]["state"] == "skipped" and "Close player first" in f["~/Music"]["text"]
    assert f["~/Documents"]["state"] in ("done", "partly")


def test_the_plan_says_what_the_rebuild_does_meanwhile_and_what_it_cant_see(root, monkeypatch):  # noqa: F811
    big(monkeypatch, "Documents")
    make_storage(root)
    home_folders(root)
    host = host_for(root)
    (root / "proc/sys/kernel").mkdir(parents=True, exist_ok=True)
    (root / "proc/sys/kernel/osrelease").write_text("7.0.0\n")
    p = R.plan(host, "/", ["Documents"])
    text = " ".join(p["side_effects"])
    assert "every file stays in the folder" in text and "subfolders are missing" in text
    assert "other accounts" in text and "NFS" in text and "virtual machine" in text
    assert "Linux 5.13" in text and "Clear the journal" in text
    assert str(R.note_path(host)) in text and "deleted as soon as" in text


def test_only_folders_the_listing_showed_can_be_cleaned(cat, root, monkeypatch):  # noqa: F811
    from fastapi.testclient import TestClient

    from daprivacyscanner.server import create_app
    make_storage(root)
    home_folders(root)
    host = host_for(root)
    H = {"X-Token": "t"}
    with TestClient(create_app("t", cat, make_host=lambda: host)) as c:
        for path, body in (("/api/tools/names/plan", {"mount": "/", "folders": ["Documents"]}),
                           ("/api/tools/names/clean", {"mount": "/", "folders": ["Documents"], "not_synced": True}),
                           ("/api/tools/names/check", {"mount": "/", "folders": ["Documents"]})):
            r = c.post(path, headers=H, json=body)
            assert r.status_code == 409 and "weren't in the list" in r.json()["error"], path
        c.app.state.names_listed = ("/", frozenset({"Documents"}))
        assert c.post("/api/tools/names/plan", headers=H, json={"mount": "/", "folders": ["Documents"]}).status_code == 200
        r = c.post("/api/tools/names/plan", headers=H, json={"mount": "/", "folders": ["Documents", ".ssh"]})
        assert r.status_code == 409
        crash(host, "Documents", "fillers", lengths=[3])
        assert c.get("/api/tools/names", headers=H).json()["interrupted"]["path"] == "~/Documents"
        assert "fillers" in c.post("/api/tools/names/recover", headers=H).json()["text"]
        assert c.get("/api/tools/names", headers=H).json()["interrupted"] is None
