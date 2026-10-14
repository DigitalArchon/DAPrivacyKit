"""Remove metadata (tools/metadata.py), the Outbox (app.metadata_outbox), the right-click entries
(desk.file_manager_actions) and what app.shared_file_metadata now reads (GIMP, git)."""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest

from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Status
from daprivacyscanner.tools import integration as I
from daprivacyscanner.tools import metadata as M

from conftest import detect, ev, make_host, make_scan
from fakes import FakeUserSystemctl
from test_guides import apply, build, options, revert

# what `mat2 --show` prints (mat2 0.15, mat2.py __print_meta): a file, then a member of a document
MAT2_SHOW = """[+] Metadata for /home/alice/photo.jpg:
    GPSLatitude: 47 deg 36' 22.18" N
    Make: Canon
    Model: Canon EOS 80D
    Artist: Alice Smith
    DateTimeOriginal: 2026:09:01 10:00:00
    Software: GIMP 2.10.36
  [++] Metadata for word/document.xml:
      creator: Alice
"""

EXIFTOOL_JSON = json.dumps([{
    "SourceFile": "/home/alice/photo.jpg", "ExifTool:ExifToolVersion": 12.76, "System:FileName": "photo.jpg",
    "System:FileModifyDate": "2026:10:01 10:00:00+00:00", "File:FileType": "JPEG", "File:Comment": "for Bob",
    "IFD0:Make": "Canon", "IFD0:Model": "Canon EOS 80D", "ExifIFD:BodySerialNumber": "123456",
    "GPS:GPSLatitude": "47 deg 36' 22.18\" N", "XMP-dc:Creator": "Alice Smith", "Composite:GPSPosition": "47, -122",
    "IFD0:Software": "GIMP 2.10.36", "ExifIFD:DateTimeOriginal": "2026:09:01 10:00:00"}])


def test_mat2_show_is_parsed_and_grouped():
    items, supported, err = M.parse_mat2_show(MAT2_SHOW, "photo.jpg")
    assert supported and not err
    groups = {i.key: i.group for i in items}
    assert groups == {"GPSLatitude": "location", "Make": "device", "Model": "device", "Artist": "people",
                      "DateTimeOriginal": "dates", "Software": "software", "creator": "people"}
    assert [i.member for i in items if i.key == "creator"] == ["word/document.xml"]
    items, supported, err = M.parse_mat2_show("[-] /x/a.xyz's format (chemical/x-xyz) is not supported\n", "a.xyz")
    assert not items and not supported and "not supported" in err
    assert M.parse_mat2_show("  No metadata found in /x/clean.png.\n", "clean.png")[0] == []


def test_exiftool_json_leaves_out_what_describes_the_file_on_disk():
    items = M.parse_exiftool(EXIFTOOL_JSON)
    keys = {i.key: i.group for i in items}
    assert "System:FileName" not in keys and "ExifTool:ExifToolVersion" not in keys and "Composite:GPSPosition" not in keys
    assert keys["GPS:GPSLatitude"] == "location" and keys["ExifIFD:BodySerialNumber"] == "device"
    assert keys["XMP-dc:Creator"] == "people" and keys["File:Comment"] == "text"
    assert "File:FileType" not in keys


def fake_mat2(fail_on=(), calls=None):
    """mat2 that writes FILE.cleaned.EXT for each file after "--" (or says the format isn't supported)."""
    def run(argv):
        if calls is not None:
            calls.append(argv)
        if argv[1] == "--list":
            return CommandResult(argv, 0, "[+] Supported formats:\n  - image/jpeg (.jpe, .jpeg, .jpg)\n"
                                          "  - application/pdf (.pdf)\n  - application/x-tar (.tar)\n")
        if argv[1] == "--show":
            return CommandResult(argv, 0, MAT2_SHOW)
        out = []
        for t in argv[argv.index("--") + 1:]:
            target = Path(t)
            if target.suffix in fail_on:
                out.append(f"[-] {target}'s format (x) is not supported")
            else:
                M.cleaned_name(target).write_bytes(b"clean:" + target.read_bytes())
        return CommandResult(argv, 0, "".join(ln + "\n" for ln in out))
    return run


def test_clean_writes_a_copy_beside_and_never_overwrites(tmp_path):
    host = make_host(tmp_path, home_files={"photo.jpg": "img", "photo.cleaned.jpg": "mine"})
    calls = []
    host.runner.handlers["mat2"] = fake_mat2(calls=calls)
    r = M.clean(host, host.home / "photo.jpg")
    assert not r.ok and "already there" in r.message
    assert (host.home / "photo.cleaned.jpg").read_text() == "mine" and calls == []
    (host.home / "photo.cleaned.jpg").unlink()
    r = M.clean(host, host.home / "photo.jpg", lightweight=True)
    assert r.ok and r.output.name == "photo.cleaned.jpg" and (host.home / "photo.jpg").read_text() == "img"
    assert calls[0] == ("mat2", "--lightweight", "--", str(host.home / "photo.jpg"))
    assert r.remaining is not None and r.remaining.tool == "mat2"


def test_a_folder_is_walked_without_links_hidden_files_or_other_mounts(tmp_path, monkeypatch):
    d = tmp_path / "Holiday"
    for rel in ("b.jpg", "a.jpg", "Day 2/c.jpg", ".hidden.jpg", ".git/x", "film.mp4.part", "Day 2/Deeper/d.pdf"):
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(rel)
    os.symlink("/etc/passwd", d / "link.jpg")
    os.symlink(d / "Day 2", d / "linked folder")
    (d / "Mounted").mkdir()
    (d / "Mounted/e.jpg").write_text("e")
    monkeypatch.setattr(M, "_mount_points", lambda: {str(d / "Mounted")})
    lone = tmp_path / "lone.png"
    lone.write_text("x")
    sel = M.collect([lone, d, d / "a.jpg"])              # a.jpg twice: once
    assert [(c.rel, c.root) for c in sel.files] == [("lone.png", None), ("a.jpg", d), ("b.jpg", d), ("Day 2/c.jpg", d),
                                                    ("Day 2/Deeper/d.pdf", d)]
    assert sel.skipped == {"hidden": 2, "links": 2, "unfinished": 1, "other_disks": 1}
    assert [c.rel for c in M.collect([d], hidden=True).files] == [".hidden.jpg", "a.jpg", "b.jpg", ".git/x", "Day 2/c.jpg",
                                                                  "Day 2/Deeper/d.pdf"]
    small = M.collect([d], limit=2)
    assert len(small.files) == 2 and small.truncated


def test_many_files_are_read_in_batches_by_name(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "BATCH", 2)
    host = make_host(tmp_path, home_files={"a.jpg": "a", "b.jpg": "b", "c.xyz": "c"})
    files = [host.home / n for n in ("a.jpg", "b.jpg", "c.xyz")]
    calls = []

    def exiftool(argv):
        calls.append(argv)
        out = [{"SourceFile": p, "GPS:GPSLatitude": "47 N", "IFD0:Model": "Pixel"} for p in argv[argv.index("--") + 1:]
               if not p.endswith(".xyz")]
        out += [{"SourceFile": p, "ExifTool:Error": "Unknown file type"} for p in argv[argv.index("--") + 1:] if p.endswith(".xyz")]
        return CommandResult(argv, 0, json.dumps(out))
    host.runner.handlers["exiftool"] = exiftool
    host.runner.handlers["mat2"] = fake_mat2()
    seen = []
    got = M.read_many(host, M.collect(files), progress=lambda n, p: seen.append(n))
    assert len(calls) == 2 and seen == [2, 3]
    a = got[0]
    assert a["rel"] == "a.jpg" and a["cleanable"] is True and a["count"] == 2
    assert [g["id"] for g in a["groups"]] == ["location", "device"] and a["groups"][0]["sample"][0]["value"] == "47 N"
    assert got[2]["cleanable"] is False and got[2]["error"] == "Unknown file type" and got[2]["count"] == 0
    with pytest.raises(M.Stopped):
        M.show_many(host, files, stop=lambda: True)


def test_mat2_show_of_many_files_is_split_by_file():
    out = ("[+] Metadata for /h/b.jpg:\n    Make: Canon\n  [++] Metadata for word/document.xml:\n      creator: Al\n"
           "  No metadata found in /h/a.png.\n[-] /h/c.xyz's format (chemical/x-xyz) is not supported\n"
           "[+] Metadata for /h/d.jpg:\n    Artist: Bo\n")
    got = M.parse_mat2_show_files(out, ["/h/a.png", "/h/b.jpg", "/h/c.xyz", "/h/d.jpg", "/h/e.jpg"])
    assert set(got) == {"/h/a.png", "/h/b.jpg", "/h/c.xyz", "/h/d.jpg"}       # e.jpg: read on its own
    assert [(i.key, i.member) for i in got["/h/b.jpg"][0]] == [("Make", ""), ("creator", "word/document.xml")]
    assert got["/h/a.png"] == ([], True, "") and got["/h/c.xyz"][1] is False
    assert [i.key for i in got["/h/d.jpg"][0]] == ["Artist"]


def test_a_pdfs_creator_is_its_program_and_complaints_name_the_file():
    out = json.dumps([{"SourceFile": "/h/r.pdf", "PDF:Creator": "Writer", "PDF:Author": "Al", "XMP-dc:Creator": "Bo"}])
    assert {i.key: i.group for i in M.parse_exiftool(out)} == {"PDF:Creator": "software", "PDF:Author": "people",
                                                               "XMP-dc:Creator": "people"}
    items, _, _ = M.parse_mat2_show("[+] Metadata for /h/r.pdf:\n    creator: Writer\n    dc:creator: Bo\n", "/h/r.pdf")
    assert {i.key: i.group for i in items} == {"creator": "software", "dc:creator": "people"}
    _, ok, err = M.parse_mat2_show("[-] /h/dir/n.xyz's format (x) is not supported\n", "/h/dir/n.xyz")
    assert not ok and err == "n.xyz's format (x) is not supported"
    got = M.parse_mat2_show_files("[-] /h/dir/n.xyz's format (x) is not supported\n", ["/h/dir/n.xyz"])
    assert got["/h/dir/n.xyz"][2] == "n.xyz's format (x) is not supported"


def test_cleanable_goes_by_the_name_as_mat2_does():
    fm = {".jpg", ".jpeg", ".pdf", ".tar"}
    assert M.cleanable("IMG_1.JPG", fm) and M.cleanable("a.tar.gz", fm) and not M.cleanable("notes.xyz", fm)
    assert M.cleanable("x.jpg", None) is None


def test_a_folder_is_cleaned_into_a_new_folder_beside_it(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "BATCH", 2)
    host = make_host(tmp_path, home_files={"Holiday/a.jpg": "a", "Holiday/Day 2/b.jpg": "b", "Holiday/Day 2/c.xyz": "c",
                                           "Holiday (cleaned)/mine.txt": "an earlier one", "lone.jpg": "l"})
    d = host.home / "Holiday"
    os.setxattr(d / "a.jpg", "user.xdg.origin.url", b"https://example.com/a.jpg")
    calls = []
    host.runner.handlers["mat2"] = fake_mat2(fail_on=(".xyz",), calls=calls)
    sel = M.collect([d, host.home / "lone.jpg"])
    run = M.clean_many(host, sel.files, check_after=False)
    out = host.home / "Holiday (cleaned 2)"                      # never into a folder already there
    assert run.outputs == {d: out}
    assert (out / "a.jpg").read_text() == "clean:a" and (out / "Day 2/b.jpg").read_text() == "clean:b"
    assert not (out / "Day 2/c.xyz").exists() and sorted(p.name for p in out.rglob("*")) == ["Day 2", "a.jpg", "b.jpg"]
    assert os.listxattr(out / "a.jpg") == []                     # the download's address isn't copied
    assert (host.home / "lone.cleaned.jpg").read_text() == "clean:l"
    assert (d / "a.jpg").read_text() == "a" and (host.home / "Holiday (cleaned)/mine.txt").exists()
    bad = [r for r in run.results if not r.ok]
    assert [r.chosen.rel for r in bad] == ["Day 2/c.xyz"] and "c.xyz's format" in bad[0].message
    assert all(not a.startswith(str(d) + "/") for argv in calls for a in argv[2:])   # mat2 only saw the copies
    view = run.to_dict(host)
    assert view["cleaned"] == 3 and view["failed"] == 1 and view["folders"][0]["output"] == "~/Holiday (cleaned 2)"


def test_a_folder_with_nothing_cleanable_leaves_no_empty_folder(tmp_path):
    host = make_host(tmp_path, home_files={"Notes/a.xyz": "a"})
    host.runner.handlers["mat2"] = fake_mat2(fail_on=(".xyz",))
    run = M.clean_many(host, M.collect([host.home / "Notes"]).files, check_after=False)
    assert run.outputs == {host.home / "Notes": None} and not (host.home / "Notes (cleaned)").exists()


def test_stopping_keeps_what_was_cleaned(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "BATCH", 1)
    host = make_host(tmp_path, home_files={"F/a.jpg": "a", "F/b.jpg": "b"})
    host.runner.handlers["mat2"] = fake_mat2()
    seen = []
    with pytest.raises(M.Stopped) as e:
        M.clean_many(host, M.collect([host.home / "F"]).files, progress=lambda n, p: seen.append(n),
                     stop=lambda: bool(seen))
    assert [r.chosen.rel for r in e.value.run.results] == ["a.jpg"]
    assert (host.home / "F (cleaned)/a.jpg").exists() and not list((host.home / "F (cleaned)").glob(".daprivacy*"))


def test_cleaned_names_follow_mat2():
    assert M.cleaned_name(Path("/a/b.tar.gz")) == Path("/a/b.cleaned.tar.gz")
    assert M.cleaned_name(Path("/a/report.pdf")) == Path("/a/report.cleaned.pdf")


def test_without_the_tools_it_says_what_to_install(tmp_path):
    host = make_host(tmp_path, files={"/etc/os-release": "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"},
                     home_files={"a.jpg": "x"})
    assert "neither is installed" in M.show(host, host.home / "a.jpg").error
    assert not M.clean(host, host.home / "a.jpg").ok
    assert M.status(host)["exiftool"]["install"] == "sudo apt install libimage-exiftool-perl"


def test_the_outbox_cleans_moves_and_never_deletes(tmp_path):
    host = make_host(tmp_path, home_files={"Outbox/photo.jpg": "img", "Outbox/notes.xyz": "x",
                                           "Outbox/film.mp4.part": "partial", "Outbox/.hidden": "h",
                                           "Outbox/Cleaned/photo.jpg": "an earlier one"},
                     env={"XDG_RUNTIME_DIR": str(tmp_path)})
    host.runner.handlers["mat2"] = fake_mat2(fail_on=(".xyz",))
    old = time.time() - 60
    for f in ("photo.jpg", "notes.xyz"):
        os.utime(host.home / "Outbox" / f, (old, old))
    run = M.run_outbox(host)
    box = host.home / "Outbox"
    assert run.cleaned == ["photo.jpg"] and [n for n, _ in run.not_cleaned] == ["notes.xyz"]
    assert (box / "Cleaned/photo (2).jpg").read_text() == "clean:img"               # the earlier one is kept
    assert (box / "Originals/photo.jpg").read_text() == "img"
    assert (box / "Not cleaned/notes.xyz").exists()
    assert (box / "film.mp4.part").exists() and (box / ".hidden").exists()       # left for later / alone
    assert not any(p.name.endswith(".cleaned.jpg") for p in box.rglob("*"))
    # a file still being written waits for the next run
    (box / "new.jpg").write_text("new")
    assert M.run_outbox(host).skipped == ["new.jpg"]
    # without a runtime folder the working copy is made in a hidden folder inside the Outbox, never in /tmp
    host.environ = {k: v for k, v in host.environ.items() if k != "XDG_RUNTIME_DIR"}
    os.utime(box / "new.jpg", (old, old))
    seen = {}
    real = M.clean

    def watching(h, p, **kw):
        seen.setdefault("work", p.parent)
        return real(h, p, **kw)
    M.clean = watching
    try:
        assert M.run_outbox(host).cleaned == ["new.jpg"]
    finally:
        M.clean = real
    assert seen["work"].parent == box and seen["work"].name.startswith(".daprivacyscanner-outbox-")
    assert not seen["work"].exists() and (box / "Cleaned/new.jpg").exists()


def test_outbox_unit_run_waits_for_the_file_that_started_it(tmp_path):
    """systemd starts the unit the moment a file lands, and not again: a run that skipped the file as still being
    written left it there for good (seen on Mint 22.3). The unit's run stays until it has settled."""
    host = make_host(tmp_path, home_files={"Outbox/photo.jpg": "img"}, installed=("mat2",),
                     env={"XDG_RUNTIME_DIR": str(tmp_path / "run")})
    (tmp_path / "run").mkdir()
    host.runner.handlers["mat2"] = fake_mat2()
    box, naps = host.home / "Outbox", []

    def nap(seconds):                                   # time passes: the file settles, and another lands meanwhile
        naps.append(seconds)
        old = time.time() - 60
        os.utime(box / "photo.jpg", (old, old)) if (box / "photo.jpg").exists() else None
        if len(naps) == 1:
            (box / "second.jpg").write_text("img2")
            os.utime(box / "second.jpg", (old, old))
    assert M.run_outbox(host).skipped == ["photo.jpg"]                              # one pass: nothing done
    run = M.run_outbox_settled(host, sleep=nap)
    assert run.cleaned == ["photo.jpg", "second.jpg"] and not run.skipped and len(naps) >= 2
    assert (box / "Cleaned/photo.jpg").exists() and (box / "Originals/second.jpg").exists()
    # a file that never settles is left when the wait is up, not waited on for ever
    (box / "copying.jpg").write_text("x")
    run = M.run_outbox_settled(host, wait=0.0, sleep=lambda s: None)
    assert run.skipped == ["copying.jpg"] and not run.cleaned



def test_outbox_units(tmp_path):
    units = I.outbox_units(tmp_path / ".config", ["/opt/DA Privacy Kit.AppImage"])
    service, path = units.values()
    assert 'ExecStart="/opt/DA Privacy Kit.AppImage" --outbox' in service and "Type=oneshot" in service
    assert "PathChanged=%h/Outbox" in path and "WantedBy=default.target" in path


@pytest.fixture
def program(monkeypatch, tmp_path):
    exe = tmp_path / "bin" / "daprivacyscanner"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(I, "program", lambda environ: [str(exe)])
    return exe


def test_outbox_set_up_and_reverted(cat, tmp_path, program):
    host = make_host(tmp_path, installed=("mat2",))
    sc = FakeUserSystemctl({"daprivacyscanner-outbox.path": "disabled"})
    host.runner.handlers["systemctl"] = sc
    assert detect(cat, "app.metadata_outbox", make_scan(host)).status is Status.WARN
    g = build(cat, host, "app.metadata_outbox")
    plan = options(g)["Set it up"]
    assert [a.kind for a in plan.actions] == ["mkdir", "file", "file", "userunit"]
    log, res = apply(host, plan)
    unit_dir = host.home / ".config/systemd/user"
    assert (unit_dir / "daprivacyscanner-outbox.path").is_file() and (host.home / "Outbox").is_dir()
    assert stat.S_IMODE((host.home / "Outbox").stat().st_mode) == 0o700
    o = detect(cat, "app.metadata_outbox", make_scan(host))
    assert o.status is Status.PASS, o.summary
    revert(host, log, res)
    assert not (unit_dir / "daprivacyscanner-outbox.path").exists() and sc.units["daprivacyscanner-outbox.path"] == "disabled"


def test_outbox_written_by_another_copy_is_noticed(cat, tmp_path, program):
    host = make_host(tmp_path, installed=("mat2",))
    host.runner.handlers["systemctl"] = FakeUserSystemctl({"daprivacyscanner-outbox.path": "enabled"})
    for p, text in I.outbox_units(host.home / ".config", ["/old/place/app.AppImage"]).items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    o = detect(cat, "app.metadata_outbox", make_scan(host))
    assert o.status is Status.WARN and "another copy" in o.summary


def test_right_click_entries_for_installed_file_managers(cat, tmp_path, program):
    host = make_host(tmp_path, installed=("nemo", "dolphin"))
    assert detect(cat, "desk.file_manager_actions", make_scan(host)).status is Status.WARN
    g = build(cat, host, "desk.file_manager_actions")
    plan = options(g)["Add them"]
    assert {a.path.name for a in plan.actions} == {"daprivacyscanner-verify.nemo_action",
                                                    "daprivacyscanner-metadata.nemo_action", "daprivacyscanner.desktop",
                                                    "daprivacyscanner-metadata.desktop"}
    log, res = apply(host, plan)
    nemo = (host.home / ".local/share/nemo/actions/daprivacyscanner-verify.nemo_action").read_text()
    assert f"Exec={program} --tool verify %F" in nemo and "Selection=s" in nemo and "Extensions=nodirs;" in nemo
    nemo = (host.home / ".local/share/nemo/actions/daprivacyscanner-metadata.nemo_action").read_text()
    assert "Extensions=any;" in nemo                                       # folders too
    dolphin = host.home / ".local/share/kio/servicemenus/daprivacyscanner.desktop"
    assert stat.S_IMODE(dolphin.stat().st_mode) == 0o755 and "MimeType=all/allfiles;" in dolphin.read_text()
    folders = (host.home / ".local/share/kio/servicemenus/daprivacyscanner-metadata.desktop").read_text()
    assert "MimeType=all/all;" in folders and "--tool metadata" in folders and "verify" not in folders
    o = detect(cat, "desk.file_manager_actions", make_scan(host))
    assert o.status is Status.PASS and ev(o) == {"Dolphin": "set up", "Nemo": "set up"}
    revert(host, log, res)
    assert not dolphin.exists()


def test_right_click_entries_need_a_file_manager(cat, tmp_path):
    assert detect(cat, "desk.file_manager_actions", make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


def test_nautilus_scripts_take_the_selection_without_globbing(tmp_path):
    e = [x for x in I.file_manager_entries(tmp_path, ["/usr/bin/daprivacyscanner"]) if x.manager == "Nautilus"]
    assert len(e) == 2 and all(x.mode == 0o755 for x in e)
    assert "set -f" in e[0].content and "$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS" in e[0].content


# ------------------------------------------------------------------ app.shared_file_metadata

def test_gimp_exporting_photo_details_is_found_and_turned_off(cat, tmp_path):
    host = make_host(tmp_path, home_files={".config/GIMP/2.10/gimprc": "(theme \"Dark\")\n(export-metadata-xmp no)\n\n"
                                                                      "# end of gimprc\n"})
    o = detect(cat, "app.shared_file_metadata", make_scan(host))
    assert o.status is Status.FAIL and "GIMP 2.10" in o.summary
    assert ev(o)["GIMP 2.10 copies a picture's metadata into what it exports"] == "EXIF, IPTC"
    g = build(cat, host, "app.shared_file_metadata")
    log, res = apply(host, options(g)["Turn them off"])
    text = (host.home / ".config/GIMP/2.10/gimprc").read_text()
    assert "(export-metadata-exif no)" in text and "(export-metadata-iptc no)" in text and text.count("export-metadata-xmp") == 1
    assert text.rstrip().endswith("# end of gimprc") and '(theme "Dark")' in text
    assert detect(cat, "app.shared_file_metadata", make_scan(host)).status is Status.PASS
    revert(host, log, res)


def test_git_identity_is_a_note_never_the_address(cat, tmp_path):
    host = make_host(tmp_path, home_files={".gitconfig": "[user]\n\tname = Alice\n\temail = alice@example.org\n",
                                           ".config/GIMP/3.0/gimprc": "(export-metadata-exif no)\n(export-metadata-xmp no)\n"
                                                                     "(export-metadata-iptc no)\n"})
    o = detect(cat, "app.shared_file_metadata", make_scan(host))
    assert o.status is Status.PASS
    assert ev(o)["Git commits' email"] == "your own address"
    assert any(n.title == "Git commits carry your email address" for n in o.notes)
    assert "alice@example.org" not in json.dumps([e.to_dict() for e in o.evidence] + [n.to_dict() for n in o.notes])


def test_mat2_s_temporary_files_stay_beside_the_file(tmp_path):
    """mat2 writes a document's parts and a PDF's pages as temporary files (tempfile: TMPDIR, else /tmp, on the
    disk on Debian, Ubuntu and Mint): it gets a hidden folder of the app's own beside the file instead, on that file's
    filesystem (the RAM disk, for the browser's), which is gone afterwards."""
    host = make_host(tmp_path, home_files={"Pictures/a.jpg": "x"})
    seen = []

    def mat2(argv):
        tmp = host.runner.envs[-1].get("TMPDIR")
        seen.append(tmp)
        assert tmp and os.path.isdir(tmp) and Path(tmp).name.startswith(M.TMP_PREFIX)
        Path(argv[-1]).with_name("a.cleaned.jpg").write_text("x")
        return CommandResult(tuple(argv), 0)
    host.runner.handlers["mat2"] = mat2
    pic = host.home / "Pictures/a.jpg"
    assert M.clean(host, pic, check_after=False).ok
    assert Path(seen[0]).parent == pic.parent and not os.path.exists(seen[0])
    assert sorted(p.name for p in pic.parent.iterdir()) == ["a.cleaned.jpg", "a.jpg"]


def test_mat2_reaches_its_temporary_folder_by_a_short_name(tmp_path):
    """With Python 3.14 mat2's workers start through a socket in TMPDIR, and a socket's path holds 107 bytes: the hidden
    folder beside a file deep in the user's folders is too long ("AF_UNIX path too long", seen on CachyOS). TMPDIR is a
    link in the runtime folder to that same folder: short, and the files still land beside what is cleaned."""
    deep = "Documents/" + "/".join(["a folder with a long name"] * 5)
    run = tmp_path / "run"
    run.mkdir()
    host = make_host(tmp_path, home_files={f"{deep}/a.jpg": "x"}, env={"XDG_RUNTIME_DIR": str(run)})
    seen = {}

    def mat2(argv):
        tmp = host.runner.envs[-1]["TMPDIR"]
        seen.update(tmp=tmp, real=os.path.realpath(tmp), link=os.path.islink(tmp))
        (Path(tmp) / "part").write_text("temporary")                    # written through the link
        if "--" in argv:
            Path(argv[-1]).with_name("a.cleaned.jpg").write_text("x")
            return CommandResult(tuple(argv), 0)
        return CommandResult(tuple(argv), 1, "", "Traceback (most recent call last):\n  File x\nOSError: AF_UNIX path too long\n")
    host.runner.handlers["mat2"] = mat2
    pic = host.home / deep / "a.jpg"
    assert M.clean(host, pic, check_after=False).ok
    assert seen["link"] and Path(seen["tmp"]).parent == run and len(Path(seen["tmp"]).name) <= 12
    assert Path(seen["real"]).parent == pic.parent and Path(seen["real"]).name.startswith(M.TMP_PREFIX)
    assert not os.path.lexists(seen["tmp"]) and not os.path.exists(seen["real"]) and list(run.iterdir()) == []
    # without a runtime folder: the folder itself, as before
    host.environ = {k: v for k, v in host.environ.items() if k != "XDG_RUNTIME_DIR"}
    (pic.parent / "a.cleaned.jpg").unlink()
    assert M.clean(host, pic, check_after=False).ok and not seen["link"]
    # when mat2 itself fails, the reason is its error, not the first line of a traceback
    (pic.parent / "a.cleaned.jpg").unlink()
    host.runner.handlers["mat2"] = lambda argv: CommandResult(tuple(argv), 1, "", "Traceback (most recent call last):\n  File x\nOSError: AF_UNIX path too long\n")
    assert M.clean(host, pic, check_after=False).message == "mat2 stopped with an error: OSError: AF_UNIX path too long"

