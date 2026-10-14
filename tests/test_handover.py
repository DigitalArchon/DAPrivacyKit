"""Before you hand over a drive (tools/handover.py): which drives are offered, what is found on one
(by exact names; links never followed; look-alikes left alone), deleting exactly the list, and
the endpoints."""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from conftest import make_host
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import handover as HO

H = {"X-Token": "t0ken"}
STICK = "/media/alice/STICK"


def lsblk_json() -> str:
    part = lambda name, fstype, mp, label=None: {"name": name, "type": "part", "fstype": fstype,  # noqa: E731
                                                  "mountpoints": [mp], "rm": False, "hotplug": False, "tran": None,
                                                  "label": label}
    return json.dumps({"blockdevices": [
        {"name": "nvme0n1", "type": "disk", "fstype": None, "mountpoints": [None], "rm": False, "hotplug": False,
         "tran": "nvme", "label": None, "children": [part("nvme0n1p1", "vfat", "/boot/efi"), part("nvme0n1p2", "ext4", "/")]},
        {"name": "sdb", "type": "disk", "fstype": None, "mountpoints": [None], "rm": True, "hotplug": True, "tran": "usb",
         "label": None, "children": [part("sdb1", "vfat", STICK, "STICK")]},
        {"name": "sdc", "type": "disk", "fstype": None, "mountpoints": [None], "rm": False, "hotplug": True, "tran": "usb",
         "label": None, "children": [part("sdc1", "exfat", "/media/alice/OLD", "OLD")]},
        {"name": "sdd", "type": "disk", "fstype": None, "mountpoints": [None], "rm": True, "hotplug": True, "tran": "usb",
         "label": None, "children": [part("sdd1", "iso9660", "/media/alice/Mint", "Linux Mint")]},
        {"name": "sda", "type": "disk", "fstype": None, "mountpoints": [None], "rm": False, "hotplug": True, "tran": "sata",
         "label": None, "children": [part("sda1", "ext4", "/mnt/data")]},
    ]})


MOUNTS = (f"/dev/nvme0n1p2 / ext4 rw 0 0\n/dev/sdb1 {STICK} vfat rw,nosuid 0 0\n"
          "/dev/sdc1 /media/alice/OLD exfat ro 0 0\n/dev/sdd1 /media/alice/Mint iso9660 ro 0 0\n")

TREE = {
    ".Trash-1000/files/holiday.jpg": "x" * 100, ".Trash-1000/info/holiday.jpg.trashinfo": "[Trash Info]\n",
    ".Trash-1001/files/b.txt": "b",
    ".Trash/1000/files/c.txt": "c", ".Trash/1002/files/d.txt": "d",
    ".Spotlight-V100/Store-V2/store.db": "s", ".fseventsd/0001": "f",
    "System Volume Information/IndexerVolumeGuid": "g",
    "Photos/.DS_Store": "ds", "Photos/.directory": "[Dolphin]\n", "Photos/img.jpg": "jpeg",
    "Photos/._notappledouble": "plain text, not AppleDouble",
    "Photos/.sh_thumbnails/normal/x.png": "png",
    "DCIM/.thumbnails/t1.jpg": "t", "Thumbs.db": "t",
    "docs/.~lock.report.odt#": "alice,laptop,/home/alice,05.10.2026 10:00;", "docs/~$report.docx": "owner",
    "docs/report.docx": "docx", "docs/~$notes.txt": "kept: not an office file",
    "nested/.apdisk": "kept: only at the top",
}


@pytest.fixture
def host(tmp_path):
    h = make_host(tmp_path, files={"/proc/mounts": MOUNTS},
                  commands={("lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS,RM,HOTPLUG,TRAN,LABEL"): lsblk_json()})
    top = h.root / STICK.lstrip("/")
    for rel, text in TREE.items():
        (top / rel).parent.mkdir(parents=True, exist_ok=True)
        (top / rel).write_text(text)
    (top / "Photos/._img.jpg").write_bytes(HO.APPLEDOUBLE_MAGIC + b"\x00\x02\x00\x00 kMDItemWhereFroms")
    outside = tmp_path / "outside"
    (outside / ".DS_Store").parent.mkdir(parents=True)
    (outside / ".DS_Store").write_text("not on the drive")
    os.symlink(outside, top / "Photos" / "link")                     # never followed
    os.symlink(outside / ".DS_Store", top / "docs" / ".directory")   # a link named like residue: not a file, kept
    return h


def test_only_removable_drives_are_offered(host):
    d = {x.mount: x for x in HO.drives(host)}
    assert set(d) == {STICK, "/media/alice/OLD"}            # not /, /boot/efi, the ISO stick or the SATA disk
    assert d[STICK].label == "STICK" and d[STICK].transport == "usb" and not d[STICK].blocked
    assert "read-only" in d["/media/alice/OLD"].blocked
    for bad in ("/", "/mnt/data", "/media/alice/OLD", "/media/alice/Mint", "/media/alice/STICK/Photos"):
        with pytest.raises(HO.Refused):
            HO.plan(host, bad)


def test_plan_lists_every_file_by_group(host):
    p = HO.plan(host, STICK)
    g = {x.id: x.to_dict(p.top) for x in p.groups}
    assert list(g) == ["own_trash", "other_trash", "thumbnails", "views", "mac", "windows", "owners"]
    assert sorted(g["own_trash"]["files"]) == [".Trash-1000/files/holiday.jpg", ".Trash-1000/info/holiday.jpg.trashinfo",
                                               ".Trash/1000/files/c.txt"]
    assert sorted(g["other_trash"]["folders"]) == [".Trash-1001", ".Trash/1002"]
    assert sorted(g["thumbnails"]["files"]) == ["DCIM/.thumbnails/t1.jpg", "Photos/.sh_thumbnails/normal/x.png", "Thumbs.db"]
    assert sorted(g["views"]["files"]) == ["Photos/.DS_Store", "Photos/.directory"]
    assert sorted(g["mac"]["files"]) == [".Spotlight-V100/Store-V2/store.db", ".fseventsd/0001", "Photos/._img.jpg"]
    assert g["windows"]["folders"] == ["System Volume Information"]
    assert sorted(g["owners"]["files"]) == ["docs/.~lock.report.odt#", "docs/~$report.docx"]
    every = {f for x in g.values() for f in x["files"]}
    assert not any(f.startswith("Photos/link") for f in every) and "docs/.directory" not in every
    assert sorted(os.path.basename(m) for m in p.media) == ["img.jpg", "report.docx"] and p.media_count == 2
    assert p.in_use == [] and p.to_dict()["files"] == len(every)


def test_clean_deletes_exactly_the_list(host, tmp_path):
    p = HO.plan(host, STICK)
    done = HO.clean(host, p)
    top = p.top
    assert done.skipped == 0 and done.deleted == sum(len(g.files) for g in p.groups)
    left = sorted(str(x.relative_to(top)) for x in top.rglob("*") if x.is_file() or x.is_symlink())
    assert left == ["Photos/._notappledouble", "Photos/img.jpg", "Photos/link", "docs/.directory", "docs/report.docx",
                    "docs/~$notes.txt", "nested/.apdisk"]
    assert not (top / ".Trash-1000").exists() and not (top / ".Trash" / "1000").exists() and (top / "Photos").is_dir()
    assert (tmp_path / "outside" / ".DS_Store").exists()


def test_a_folder_replaced_by_a_link_since_the_list_stops_it(host, tmp_path):
    """Between the list and the deletion, .Trash-1000 becomes a link to a folder with the same names
    elsewhere: nothing is deleted, there or anywhere."""
    p = HO.plan(host, STICK)
    trash = p.top / ".Trash-1000"
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    os.rename(trash, decoy / "real")
    (decoy / "files").mkdir()
    (decoy / "files/holiday.jpg").write_text("not on the drive")
    os.symlink(decoy, trash)
    with pytest.raises(HO.Refused, match="changed since the list was made"):
        HO.clean(host, p)
    assert (decoy / "files/holiday.jpg").exists() and (decoy / "real/files/holiday.jpg").exists()


def test_a_program_using_a_file_stops_it(host):
    p = HO.plan(host, STICK)
    proc = host.root / "proc" / "77"
    (proc / "fd").mkdir(parents=True)
    (proc / "comm").write_text("eog\n")
    (proc / "maps").write_text("")
    os.symlink(os.path.realpath(p.top / ".Trash-1000/files/holiday.jpg"), proc / "fd" / "3")
    with pytest.raises(HO.Refused, match="Close eog first"):
        HO.clean(host, p)
    assert (p.top / ".Trash-1000/files/holiday.jpg").exists()


def test_endpoints(cat, host):
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    assert [d["mount"] for d in c.get("/api/tools/handover", headers=H).json()["drives"]] == [STICK, "/media/alice/OLD"]
    assert c.post("/api/tools/handover/plan", headers=H, json={"mount": "/"}).status_code == 400
    p = c.post("/api/tools/handover/plan", headers=H, json={"mount": STICK}).json()
    assert p["files"] == 16 and p["groups"][0]["title"] == "Your trash on this drive"
    r = c.post("/api/tools/handover/clean", headers=H, json={"plan_id": p["plan_id"]})
    assert r.status_code == 400 and "Confirm" in r.json()["error"]
    r = c.post("/api/tools/handover/clean", headers=H, json={"plan_id": p["plan_id"], "confirm": True}).json()
    assert r["deleted"] == 16
    assert c.post("/api/tools/handover/clean", headers=H, json={"plan_id": p["plan_id"], "confirm": True}).status_code == 400
