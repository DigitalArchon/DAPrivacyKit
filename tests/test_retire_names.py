"""Retire a drive names the drive by what stays with it (the review of 2026-11-12): destructive commands named
/dev/sdX, the commands were asked for by that name alone, the user pastes them later, and a step tells them to
suspend, which can re-letter USB drives; `dd of=/dev/sdb` to a name that has gone writes a file in /dev."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from daprivacyscanner.server import create_app
from daprivacyscanner.tools import retire as RT

from test_retire import H, host, work  # noqa: F401 - the fixture


@pytest.fixture
def named(host):  # noqa: F811
    ids = host.root / "dev/disk/by-id"
    ids.mkdir(parents=True)
    for name, target in {"ata-Samsung_SSD_870_EVO_1TB_S6PNNS0W123456": "sdb",
                         "ata-Samsung_SSD_870_EVO_1TB_S6PNNS0W123456-part1": "sdb1",
                         "ata-Samsung_SSD_870_EVO_1TB_S6PNNS0W123456-part2": "sdb2",
                         "wwn-0x5002538e40000000": "sdb", "wwn-0x5002538e40000000-part1": "sdb1",
                         "nvme-eui.e8238fa6bf530001001b448b4abcdef0": "nvme1n1",
                         "nvme-WD_BLACK_SN770_500GB_22XYZ": "nvme1n1",
                         "ata-WDC_WD40EFAX-68JH4N1_WD-123": "sda"}.items():
        os.symlink(f"../../{target}", ids / name)
    (host.root / "run/udev/data/b8:16").write_text("E:ID_SERIAL_SHORT=S6PNNS0W123456\nE:ID_WWN=0x5002538e40000000\n")
    return host


def test_commands_name_the_drive_by_its_lasting_name(named):
    d = RT.find(named, "sdb")
    sdb = "/dev/disk/by-id/ata-Samsung_SSD_870_EVO_1TB_S6PNNS0W123456"
    assert d.by_id == sdb and d.wwn == "0x5002538e40000000" and d.stable("/dev/sdb1") == sdb + "-part1"
    g = RT.guide(named, "sdb", "sdb", facts={"ata": {"supported": True, "sanitize": {"crypto": True}}})
    assert g.steps[0].commands == [f"lsblk -d -o PATH,MODEL,SERIAL,SIZE {sdb}"]
    cmds = [c for st in work(g) for c in st.commands]
    assert f"sudo cryptsetup erase {sdb}-part1" in cmds
    assert f"sudo hdparm --yes-i-know-what-i-am-doing --sanitize-crypto-scramble {sdb}" in cmds
    assert not any("/dev/sdb" in c for c in cmds if "erase" in c or "hdparm" in c)
    assert "its lasting name" in g.intro
    # a hard disk's overwrite: never creates its output
    cmds = [c for st in work(RT.guide(named, "sda", "sda")) for c in st.commands]
    assert "sudo dd if=/dev/zero of=/dev/disk/by-id/ata-WDC_WD40EFAX-68JH4N1_WD-123 bs=16M oflag=direct conv=nocreat " \
           "status=progress" in cmds
    # NVMe: its model-and-serial name rather than the EUI, sanitize through it too
    facts = {"nvme": {"format": True, "sanitize": {"crypto": True}}}
    nv = [c for st in work(RT.guide(named, "nvme1n1", "nvme1n1", facts=facts)) for c in st.commands]
    assert "sudo nvme sanitize /dev/disk/by-id/nvme-WD_BLACK_SN770_500GB_22XYZ --sanact=4" in nv


def test_a_drive_without_a_lasting_name_says_to_check_it(named):
    g = RT.guide(named, "sdd", "sdd", kind="hdd")
    assert "no lasting name" in g.intro and g.steps[0].commands == ["lsblk -d -o PATH,MODEL,SERIAL,SIZE /dev/sdd"]
    assert any("conv=nocreat" in c and "of=/dev/sdd" in c for st in g.steps for c in st.commands)


def test_the_commands_are_refused_for_another_drive_under_that_name(named):
    listed = RT.identity(RT.find(named, "sdb"))
    assert RT.guide(named, "sdb", "sdb", expected=listed).steps
    (named.root / "run/udev/data/b8:16").write_text("E:ID_SERIAL_SHORT=OTHER999\n")       # re-lettered after a suspend
    with pytest.raises(RT.Refused, match="isn't the one that was listed"):
        RT.guide(named, "sdb", "sdb", expected=listed)
    frozen = RT.guide(named, "sdb", "sdb", facts={"ata": {"supported": True, "frozen": True}})
    unfreeze = next(st for st in frozen.steps if st.title == "Unfreeze it")
    assert any("another /dev name" in e for e in unfreeze.side_effects)


def test_the_endpoints_take_the_listed_drive(cat, named):
    c = TestClient(create_app("t0ken", cat, make_host=lambda: named))
    d = {x["name"]: x for x in c.get("/api/tools/retire", headers=H).json()["drives"]}
    sdb = d["sdb"]
    assert sdb["by_id"].endswith("S6PNNS0W123456") and sdb["identity"][1] == "S6PNNS0W123456"
    ok = c.post("/api/tools/retire/guide", headers=H, json={"disk": "sdb", "typed": "sdb", "drive": sdb["identity"]})
    assert ok.status_code == 200
    (named.root / "run/udev/data/b8:16").write_text("E:ID_SERIAL_SHORT=OTHER999\n")
    for url in ("/api/tools/retire/guide", "/api/tools/retire/facts"):
        r = c.post(url, headers=H, json={"disk": "sdb", "typed": "sdb", "drive": sdb["identity"]})
        assert r.status_code == 400 and "isn't the one that was listed" in r.json()["error"]
