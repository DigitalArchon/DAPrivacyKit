"""The fix engine after the review of 2026-11-12: changes recorded before they are made (write-ahead), the root
helper's change ids made by the app and settled later, "Close X first" asked again when a plan is applied, reverts
refused out of order and files put back by lines, deletion anchored to folder descriptors, durable writes."""

import errno
import json
import os
import stat
from pathlib import Path

import pytest

from daprivacyscanner.fix import (CopyQTabSet, DeleteFiles, FixError, FixPlan, GSettingsSet, InUse, RootChange,
                                  WriteFile, _write_atomic, apply_plan, make_writable, merge_back, revert_entry)
from daprivacyscanner.privileged import HelperError
from daprivacyscanner.undo import UndoLog

from conftest import make_host, skip_if_root
from fakes import FakeGSettings

KEY = ("org.gnome.desktop.privacy", "remember-recent-files")


def setup(tmp_path, values=None, **kw):
    host = make_host(tmp_path, **kw)
    gs = FakeGSettings(values or {KEY: "true"})
    host.runner.handlers["gsettings"] = gs
    return host, gs, UndoLog(host.home / ".local/state/daprivacyscanner")


def running(host, pid: int, comm: str, fds: dict[str, str] | None = None) -> None:
    """A process of the fixture's /proc: its name and the files it holds open."""
    d = host.sys_path(f"/proc/{pid}")
    (d / "fd").mkdir(parents=True, exist_ok=True)
    (d / "comm").write_text(comm + "\n")
    for n, target in (fds or {}).items():
        os.symlink(target, d / "fd" / n)


# ------------------------------------------------------------------ write-ahead

class Peek(GSettingsSet):
    """A gsettings change that looks at History while it is being made."""
    seen: list = []

    def __init__(self, log, *a):
        super().__init__(*a)
        self.log = log

    def apply(self, ctx):
        e = next(e for e in self.log.entries() if e["state"] == "applying")
        Peek.seen.append((e["state"], [r["kind"] for r in e["records"]], e["owner"]["pid"]))
        return super().apply(ctx)


def test_the_entry_is_written_before_the_first_step_and_each_step_as_it_completes(tmp_path):
    host, gs, log = setup(tmp_path, {KEY: "true", ("a.b", "c"): "1"})
    Peek.seen = []
    plan = FixPlan("desk.recent_files", "t", [Peek(log, *KEY, "false"), Peek(log, "a.b", "c", "2")])
    res = apply_plan(plan, host, log)
    assert res.ok
    # the first step ran with only itself under way; the second with the first recorded and itself under way
    assert Peek.seen == [("applying", ["pending"], os.getpid()), ("applying", ["gsettings", "pending"], os.getpid())]
    e = log.get(res.entry_id)
    assert e["state"] == "applied" and "owner" not in e and [r["kind"] for r in e["records"]] == ["gsettings"] * 2


def test_an_entry_whose_process_is_gone_reads_interrupted_and_reverts_what_it_records(tmp_path):
    host, gs, log = setup(tmp_path)
    res = apply_plan(FixPlan("desk.recent_files", "t", [GSettingsSet(*KEY, "false")]), host, log)
    entries = log.entries()
    # as a crash part way leaves it: still "applying", by a process that no longer runs, the next step under way
    entries[0].update(state="applying", owner={"pid": 2 ** 22 + 7, "started": "1", "boot": "x"})
    entries[0]["records"].append({"kind": "pending", "step_kind": "file", "text": "Add a line (~/.bashrc)"})
    log._save(entries)
    s = UndoLog.summary(log.get(res.entry_id))
    assert s["state"] == "interrupted" and s["can_revert"]
    assert s["steps"][1]["unknown"] and "may or may not have been made" in s["steps"][1]["text"]
    results = revert_entry(log.get(res.entry_id), host, log)
    assert [r.ok for r in results] == [True] and gs.values[KEY] == "true"
    assert log.get(res.entry_id)["state"] == "reverted"


def test_an_entry_being_applied_by_a_live_process_is_neither_reverted_nor_forgotten(tmp_path):
    host, gs, log = setup(tmp_path)
    log.begin("a" * 32, "desk.recent_files", "t")
    log.backup_dir("a" * 32).mkdir(parents=True)
    (log.backup_dir("a" * 32) / "copy").write_text("x")
    (log.dir / "backups" / "stray").mkdir()
    s = UndoLog.summary(log.get("a" * 32))
    assert s["state"] == "applying" and not s["can_revert"]
    [r] = revert_entry(log.get("a" * 32), host, log)
    assert not r.ok and "being applied right now" in r.message
    log.forget(everything=True)
    # the apply under way keeps its entry and the copies it is writing; what no entry names goes
    assert log.get("a" * 32) is not None and (log.backup_dir("a" * 32) / "copy").exists()
    assert not (log.dir / "backups" / "stray").exists()


def test_nothing_is_changed_when_history_cant_be_written_first(tmp_path, monkeypatch):
    host, gs, log = setup(tmp_path)

    def full(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(log, "begin", full)
    res = apply_plan(FixPlan("desk.recent_files", "t", [GSettingsSet(*KEY, "false")]), host, log)
    assert not res.ok and res.entry_id is None and "History's file couldn't be written" in res.error
    assert gs.values[KEY] == "true"


def test_a_plan_whose_record_cant_be_written_part_way_is_put_back(tmp_path, monkeypatch):
    host, gs, log = setup(tmp_path, {KEY: "true", ("a.b", "c"): "1"})
    real, calls = log.progress, []

    def progress(entry_id, records):
        calls.append(len(records))
        if len(calls) == 3:                                 # the second step's "under way"
            raise OSError(errno.ENOSPC, "No space left on device")
        real(entry_id, records)
    monkeypatch.setattr(log, "progress", progress)
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*KEY, "false"), GSettingsSet("a.b", "c", "2")]), host, log)
    assert not res.ok and "Stopped part way" in res.error
    assert gs.values[KEY] == "true" and gs.values[("a.b", "c")] == "1"
    assert log.get(res.entry_id)["state"] == "failed"


# ------------------------------------------------------------------ root steps: the app's change id, settled later

class Helper:
    """The administrator helper as the app sees it: change requests answered (or not), and list_changes."""

    def __init__(self, answer="ok", listing=None):
        self.answer, self.listing, self.calls = answer, listing, []

    def call(self, action, args, timeout=None):
        self.calls.append((action, dict(args)))
        if action == "list_changes":
            if self.listing is None:
                raise HelperError("unknown action")
            return {"changes": self.listing}
        if action == "revert":
            return {"ok": True, "message": "put back", "ran": ["systemctl revert"]}
        if self.answer == "silent":
            raise HelperError("no answer from the helper within 120 s")
        return {"changed": True, "change_id": args["change_id"], "ran": ["systemctl disable --now x.service"]}


def test_a_root_step_carries_the_change_id_the_app_made(tmp_path):
    host, gs, log = setup(tmp_path)
    host.privileged = Helper()
    res = apply_plan(FixPlan("x", "t", [RootChange("set_service", {"unit": "x.service"}, "Turn off x")]), host, log)
    [(action, args)] = host.privileged.calls
    rec = log.get(res.entry_id)["records"][0]
    assert action == "set_service" and len(args["change_id"]) == 32 and rec["change_id"] == args["change_id"]
    assert rec["resources"] == ["root:set_service:x.service"]


def test_a_root_step_whose_answer_never_came_is_kept_as_not_known_and_settled_from_the_helpers_record(tmp_path):
    host, gs, log = setup(tmp_path)
    host.privileged = Helper(answer="silent")
    plan = FixPlan("x", "t", [GSettingsSet(*KEY, "false"), RootChange("set_service", {"unit": "x.service"}, "Turn off x")])
    res = apply_plan(plan, host, log)
    assert not res.ok and "didn't answer" in res.error
    e = log.get(res.entry_id)
    gsrec, root = e["records"]
    assert e["state"] == "failed" and gsrec["reverted"] and gs.values[KEY] == "true"   # the step before put back
    assert root["outcome"] == "unknown" and UndoLog.step(root)["unknown"]
    cid = root["change_id"]
    # the helper did make it, after the app gave up: History's next look with administrator access settles it
    host.privileged = Helper(listing=[{"change_id": cid, "state": "applied", "action": "set_service", "time": 1,
                                       "text": "x"}])
    assert log.reconcile(host.privileged) == 1
    root = log.get(res.entry_id)["records"][1]
    assert "outcome" not in root and root["change_id"] == cid and UndoLog.summary(log.get(res.entry_id))["can_revert"]
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and ("revert", {"change_id": cid, "force": False}) in host.privileged.calls


def test_a_root_step_the_helper_has_no_record_of_was_never_made(tmp_path):
    host, gs, log = setup(tmp_path)
    host.privileged = Helper(answer="silent")
    res = apply_plan(FixPlan("x", "t", [RootChange("set_service", {"unit": "x.service"}, "Turn off x")]), host, log)
    assert log.reconcile(Helper(listing=[])) == 1
    root = log.get(res.entry_id)["records"][0]
    assert root["outcome"] == "not made" and root["change_id"] is None and not UndoLog.can_undo(root)
    assert not UndoLog.summary(log.get(res.entry_id))["can_revert"]


def test_an_older_helper_without_list_changes_settles_nothing(tmp_path):
    host, gs, log = setup(tmp_path)
    host.privileged = Helper(answer="silent")
    res = apply_plan(FixPlan("x", "t", [RootChange("set_service", {"unit": "x.service"}, "Turn off x")]), host, log)
    assert log.reconcile(Helper(listing=None)) == 0
    assert log.get(res.entry_id)["records"][0]["outcome"] == "unknown"


def test_a_change_the_helper_made_that_history_doesnt_know_is_taken_up_unless_forgotten(tmp_path):
    host, gs, log = setup(tmp_path)
    host.privileged = Helper()
    kept = apply_plan(FixPlan("x", "t", [RootChange("set_service", {"unit": "y.service"}, "Turn off y")]), host, log)
    known = log.get(kept.entry_id)["records"][0]["change_id"]
    stray, gone = "b" * 32, "c" * 32
    listing = [{"change_id": known, "state": "applied", "action": "set_service", "time": 1, "text": "y"},
               {"change_id": stray, "state": "applied", "action": "write_dropin", "time": 2, "text": "Write a drop-in"}]
    assert log.reconcile(Helper(listing=listing)) == 1
    found = log.get(stray)
    assert found["title"] == "Recovered: Write a drop-in" and found["records"][0]["change_id"] == stray
    assert "administrator helper's own record" in UndoLog.via_text(found)
    # forgotten entries' changes stay forgotten: not taken up again
    log.forget(everything=True)
    listing.append({"change_id": gone, "state": "reverted", "action": "x", "time": 3, "text": "z"})
    assert log.reconcile(Helper(listing=listing)) == 0 and log.entries() == []


# ------------------------------------------------------------------ "Close X first", asked again when applied

def test_a_program_started_after_the_plan_was_shown_stops_it_before_anything_changes(tmp_path):
    host, gs, log = setup(tmp_path, home_files={".config/copyq/copyq.conf": "[Tabs]\n1\\name=&clipboard\nsize=1\n"})
    conf = host.home / ".config/copyq/copyq.conf"
    plan = FixPlan("desk.clipboard_history", "t", [
        GSettingsSet(*KEY, "false"),
        CopyQTabSet(conf, "~/.config/copyq/copyq.conf", "&clipboard", "store_items", "false", "Keep it in memory")])
    before = conf.read_text()
    running(host, 4242, "copyq")                            # started after the plan was shown
    res = apply_plan(plan, host, log)
    assert not res.ok and res.blocked and "Close CopyQ first" in res.error and res.entry_id is None
    assert gs.values[KEY] == "true" and conf.read_text() == before and log.entries() == []


def test_a_folder_a_program_opened_since_stops_its_deletion(tmp_path):
    host, gs, log = setup(tmp_path, home_files={".cache/app/a": "x", ".cache/app/b": "y"})
    d = host.home / ".cache/app"
    plan = FixPlan("x", "t", [DeleteFiles(d, [d / "a", d / "b"], "app cache", "~/.cache/app")
                              .unless(InUse("App", held=(d,)))])
    running(host, 77, "app", {"3": str(d / "a")})
    res = apply_plan(plan, host, log, confirmed_irreversible=True)
    assert res.blocked and "Close App first" in res.error and (d / "a").exists()


def test_a_firefox_profile_opened_since_stops_its_prefs(tmp_path):
    from daprivacyscanner.fix import FirefoxPref
    host, gs, log = setup(tmp_path, home_files={".mozilla/firefox/p/prefs.js": 'user_pref("a", 1);\n'})
    prof = host.home / ".mozilla/firefox/p"
    plan = FixPlan("x", "t", [GSettingsSet(*KEY, "false"), FirefoxPref(prof, "Firefox (p)", "b", True, "~/p")])
    (prof / "lock").symlink_to("127.0.0.1:+4242")
    running(host, 4242, "firefox")
    res = apply_plan(plan, host, log)
    assert res.blocked and "Close Firefox (p) first" in res.error and gs.values[KEY] == "true"


# ------------------------------------------------------------------ out of order, and by lines

def test_reverting_an_earlier_change_of_the_same_setting_waits_for_the_later_one(tmp_path):
    """A (true → false), then B (false → true): reverting A first saw true, its own "before", and called it back already;
    B's revert then set false, though the setting was true before either."""
    host, gs, log = setup(tmp_path)
    a = apply_plan(FixPlan("x", "A", [GSettingsSet(*KEY, "false")]), host, log)
    b = apply_plan(FixPlan("y", "B", [GSettingsSet(*KEY, "true")]), host, log)
    [r] = revert_entry(log.get(a.entry_id), host, log)
    assert not r.ok and [x["id"] for x in r.blocked_by] == [b.entry_id] and "Revert the later one first" in r.message
    assert log.get(a.entry_id)["state"] == "applied"
    assert all(x.ok for x in revert_entry(log.get(b.entry_id), host, log))
    assert all(x.ok for x in revert_entry(log.get(a.entry_id), host, log)) and gs.values[KEY] == "true"


def test_two_keys_removed_by_two_entries_dont_come_back_by_reverting_the_first(tmp_path):
    host, gs, log = setup(tmp_path, home_files={".ssh/authorized_keys": "ssh-ed25519 AAA1 one\nssh-ed25519 AAA2 two\n"})
    f = host.home / ".ssh/authorized_keys"
    drop = lambda key: lambda old: "".join(ln for ln in old.splitlines(True) if key not in ln)  # noqa: E731
    one = apply_plan(FixPlan("auth.ssh", "Remove key 1", [WriteFile(f, drop("AAA1"), "Remove 1", "~/.ssh/authorized_keys")]),
                     host, log)
    two = apply_plan(FixPlan("auth.ssh", "Remove key 2", [WriteFile(f, drop("AAA2"), "Remove 2", "~/.ssh/authorized_keys")]),
                     host, log)
    [r] = revert_entry(log.get(one.entry_id), host, log, force=True)          # not even forced
    assert not r.ok and r.blocked_by and f.read_text() == ""
    revert_entry(log.get(two.entry_id), host, log)
    revert_entry(log.get(one.entry_id), host, log)
    assert f.read_text() == "ssh-ed25519 AAA1 one\nssh-ed25519 AAA2 two\n"


def test_a_file_edited_since_gets_only_the_fixs_lines_put_back(tmp_path):
    host, gs, log = setup(tmp_path, home_files={".ssh/config": "Host a\n  User me\n"})
    cfg = host.home / ".ssh/config"
    res = apply_plan(FixPlan("x", "t", [WriteFile(cfg, lambda old: "# DA\nHashKnownHosts yes\n\n" + old, "Add",
                                                  "~/.ssh/config")]), host, log)
    cfg.write_text(cfg.read_text() + "Host b\n  User you\n")                 # edited since, by the user
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.ok and not r.conflict and cfg.read_text() == "Host a\n  User me\nHost b\n  User you\n"
    assert "what was changed in it since stays" in r.message


def test_merge_back_refuses_when_a_change_since_touches_the_fixs_lines():
    before, after = "a\nb\nc\n", "a\nB\nc\n"
    assert merge_back(before, after, "a\nB\nc\nd\n") == "a\nb\nc\nd\n"
    assert merge_back(before, after, "a\nBB\nc\n") is None                    # its own line changed
    # a line the fix removed goes back between the same two lines, while they are still side by side
    assert merge_back("a\nx\nb\n", "a\nb\n", "0\na\nb\n") == "0\na\nx\nb\n"
    assert merge_back("a\nx\nb\n", "a\nb\n", "a\nnew\nb\n") is None


def test_a_conflict_says_what_reverting_anyway_does(tmp_path):
    host, gs, log = setup(tmp_path)
    res = apply_plan(FixPlan("x", "t", [GSettingsSet(*KEY, "false")]), host, log)
    gs.values[KEY] = "'other'"
    [r] = revert_entry(log.get(res.entry_id), host, log)
    assert r.conflict and "back to true, over the value it has now ('other')" in r.force_does


# ------------------------------------------------------------------ deleting from descriptors

def test_a_folder_swapped_for_a_link_after_the_plan_is_never_followed(tmp_path):
    """A Flatpak app can rename the folders of its own cache: one swapped for a link to ~/.ssh between the plan and the
    delete had the listed names there deleted."""
    host, gs, log = setup(tmp_path, home_files={".var/app/x/cache/d/id_ed25519": "cache", ".ssh/id_ed25519": "KEY"})
    root = host.home / ".var/app/x/cache"
    plan = FixPlan("sbx.flatpak_caches", "t", [DeleteFiles(root, [root / "d/id_ed25519"], "x cache", "~/.var/app/x/cache")])
    os.rename(root / "d", root / "d.real")
    (root / "d").symlink_to(host.home / ".ssh")
    res = apply_plan(plan, host, log, confirmed_irreversible=True)
    assert (host.home / ".ssh/id_ed25519").read_text() == "KEY" and "0 files" in res.applied[0]
    # and a root swapped for a link deletes nothing either
    os.rename(root, root.parent / "cache.real")
    root.symlink_to(host.home / ".ssh")
    apply_plan(FixPlan("x", "t", [DeleteFiles(root, [root / "id_ed25519"], "x cache", "~/x")]), host, log,
               confirmed_irreversible=True)
    assert (host.home / ".ssh/id_ed25519").exists()


def test_deleting_never_reaches_another_filesystem(tmp_path, monkeypatch):
    """A folder on another device (a mount) below the root: its files aren't listed, nor deleted."""
    from daprivacyscanner.checks import _util
    host, gs, log = setup(tmp_path, home_files={".cache/x/top": "1", ".cache/x/mnt/f": "2"})
    root, mnt = host.home / ".cache/x", host.home / ".cache/x/mnt"
    real_stat = os.stat

    class St:
        def __init__(self, st):
            self._st = st

        def __getattr__(self, k):
            return self._st.st_dev + 1 if k == "st_dev" else getattr(self._st, k)

    def fake_stat(p, *a, dir_fd=None, follow_symlinks=True):
        st = real_stat(p, *a, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        return St(st) if (dir_fd is None and str(p) == str(mnt)) or (dir_fd is not None and p == "mnt") else st
    real_fstat = os.fstat

    def fake_fstat(fd):
        st = real_fstat(fd)
        return St(st) if os.readlink(f"/proc/self/fd/{fd}") == str(mnt) else st
    monkeypatch.setattr(os, "stat", fake_stat)
    monkeypatch.setattr(os, "fstat", fake_fstat)
    files, _ = _util.files_under(root)
    assert files == [root / "top"]
    DeleteFiles(root, [root / "top", mnt / "f"], "x", "~/x").apply(type("C", (), {"host": host})())
    assert not (root / "top").exists() and (mnt / "f").exists()


def test_whole_entries_and_pruning_through_descriptors(tmp_path):
    host, gs, log = setup(tmp_path, home_files={"T/files/dir/a/b": "1", "T/files/f": "2", "keep/k": "3",
                                                ".cache/c/x/y/z": "4"})
    t = host.home / "T/files"
    (t / "link").symlink_to(host.home / "keep")
    apply_plan(FixPlan("enc.trash", "t", [DeleteFiles(t, [t / "dir", t / "f", t / "link"], "trash", "~/T", whole=True)]),
               host, log, confirmed_irreversible=True)
    assert list(t.iterdir()) == [] and (host.home / "keep/k").exists()
    c = host.home / ".cache/c"
    apply_plan(FixPlan("x", "t", [DeleteFiles(c, [c / "x/y/z"], "c", "~/c")]), host, log, confirmed_irreversible=True)
    assert c.is_dir() and not (c / "x").exists()                            # emptied folders pruned, the root kept


# ------------------------------------------------------------------ writes that last, and the log's own

def test_a_write_reaches_the_disk_before_it_counts_and_keeps_the_files_mode(tmp_path, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: synced.append(os.readlink(f"/proc/self/fd/{fd}")) or real(fd))
    p = tmp_path / "conf"
    p.write_text("old")
    os.chmod(p, 0o640)
    _write_atomic(p, b"new")
    assert p.read_text() == "new" and stat.S_IMODE(p.stat().st_mode) == 0o640
    assert any(".daprivacyscanner-tmp" in s for s in synced) and str(tmp_path) in synced


@skip_if_root
def test_an_undo_log_that_cant_be_read_for_any_reason_is_kept_aside(tmp_path):
    log = UndoLog(tmp_path / "state")
    log.dir.mkdir()
    log.file.write_text(json.dumps({"version": 1, "entries": [{"id": "x", "records": []}]}))
    os.chmod(log.file, 0)
    assert log.entries() == [] and "can't be read" in log.damaged()
    log.add("y" * 32, "x", "t", [])
    assert [e["id"] for e in log.entries()] == ["y" * 32] and list(log.dir.glob("undo.json.unreadable-*"))
    (log.dir / "undo.json").write_bytes(b"\xff\xfe not text")
    assert log.entries() == [] and "can't be read" in log.damaged()


def test_make_writable_never_follows_a_link(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o500)
    tree = tmp_path / "tree"
    (tree / "ro").mkdir(parents=True)
    os.chmod(tree / "ro", 0o500)
    (tree / "link").symlink_to(outside)
    try:
        make_writable(tree)
        assert stat.S_IMODE((tree / "ro").stat().st_mode) == 0o700
        assert stat.S_IMODE(outside.stat().st_mode) == 0o500
    finally:
        os.chmod(outside, 0o700)


# ------------------------------------------------------------------ through the API

def _api(cat, tmp_path, start_helper=None):
    from fastapi.testclient import TestClient
    from daprivacyscanner.server import create_app
    host, gs, log = setup(tmp_path, {("org.gnome.system.location", "enabled"): "true"},
                          env={"XDG_CURRENT_DESKTOP": "GNOME"})
    kw = {"start_helper": start_helper} if start_helper else {}
    return TestClient(create_app("t", cat, make_host=lambda: host, **kw)), host, gs, log, {"X-Token": "t"}


def test_a_plan_refused_because_a_program_started_is_kept_to_apply_again(cat, tmp_path, monkeypatch):
    import shutil
    from daprivacyscanner.runner import Runner
    orig = Runner.plan_fix

    def with_app(self, check_id, params=None, stored=None):
        result, plan = orig(self, check_id, params, stored)
        plan.actions[0].unless(InUse("Test App", names=("testapp",)))
        return result, plan
    monkeypatch.setattr(Runner, "plan_fix", with_app)
    c, host, gs, log, h = _api(cat, tmp_path)
    plan = c.post("/api/fix/tel.location/plan", headers=h).json()["plan"]
    running(host, 99, "testapp")
    r = c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]})
    assert r.status_code == 409 and r.json()["blocked"] and "Close Test App first" in r.json()["error"]
    assert gs.values[("org.gnome.system.location", "enabled")] == "true" and log.entries() == []
    shutil.rmtree(host.sys_path("/proc/99"))                    # closed: the same plan goes through
    assert c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]}).json()["ok"]


def test_revert_says_which_later_change_comes_first_and_can_revert_it_first(cat, tmp_path):
    c, host, gs, log, h = _api(cat, tmp_path)
    key = ("org.gnome.system.location", "enabled")
    plan = c.post("/api/fix/tel.location/plan", headers=h).json()["plan"]
    first = c.post("/api/fix/apply", headers=h, json={"plan_id": plan["id"]}).json()["entry_id"]
    later = apply_plan(FixPlan("tel.location", "Back on", [GSettingsSet(*key, "true")]), host, log).entry_id
    r = c.post(f"/api/undo/{first}/revert", headers=h, json={"force": True}).json()
    assert not r["ok"] and [b["id"] for b in r["blocked_by"]] == [later] and gs.values[key] == "true"
    r = c.post(f"/api/undo/{first}/revert", headers=h, json={"later_first": True}).json()
    assert r["ok"] and set(r["reverted"]) == {first, later} and gs.values[key] == "true"
    assert [e["state"] for e in c.get("/api/undo", headers=h).json()["entries"]] == ["reverted", "reverted"]


def test_history_takes_up_what_the_helper_did_that_it_has_no_entry_for(cat, tmp_path):
    from daprivacyscanner.privileged import FakePrivileged

    class Listing(FakePrivileged):
        def call(self, action, args, timeout=None):
            if action == "list_changes":
                return {"changes": [{"change_id": "d" * 32, "state": "applied", "action": "write_dropin", "time": 5,
                                     "text": "Write /etc/x.conf"}]}
            return super().call(action, args, timeout)
    c, host, gs, log, h = _api(cat, tmp_path, start_helper=Listing)
    assert c.get("/api/undo", headers=h).json()["entries"] == []        # without administrator access: nothing asked
    c.app.state.admin.get(prompt=True)                                  # granted, as for a scan or a fix
    entries = c.get("/api/undo", headers=h).json()["entries"]
    assert [e["title"] for e in entries] == ["Recovered: Write /etc/x.conf"] and entries[0]["can_revert"]
