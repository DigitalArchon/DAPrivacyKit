"""Retire a drive (tools/retire.py, helper erase_facts): which drives, what kind each is, what holds
the running system; the guide for each kind (an overwrite for hard disks only, rule 8), shown only
once the drive's name is typed; and what the drive says about erasing itself."""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from conftest import make_host
from daprivacyscanner import helper
from daprivacyscanner.host import CommandResult
from daprivacyscanner.privileged import FakePrivileged
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import retire as RT

H = {"X-Token": "t0ken"}
LSBLK = ("lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS,RM,HOTPLUG,TRAN,LABEL")


def node(name, type_="part", fstype=None, mp=None, children=(), tran=None, rm=False):
    return {"name": name, "type": type_, "fstype": fstype, "mountpoints": [mp], "rm": rm, "hotplug": False,
            "tran": tran, "label": None, "children": list(children)}


TREE = {"blockdevices": [
    node("nvme0n1", "disk", tran="nvme", children=[node("nvme0n1p1", fstype="vfat", mp="/boot/efi"),
         node("nvme0n1p2", fstype="crypto_LUKS", children=[node("luks-root", "crypt", "ext4", "/")])]),
    node("nvme1n1", "disk", tran="nvme", children=[node("nvme1n1p1", fstype="crypto_LUKS")]),
    node("sda", "disk", tran="sata", children=[node("sda1", fstype="ext4", mp="/mnt/old")]),
    node("sdb", "disk", tran="sata", children=[node("sdb1", fstype="crypto_LUKS", children=[node("backup", "crypt", "ext4")]),
                                               node("sdb2", fstype="ntfs")]),
    node("sdc", "disk", tran="usb", rm=True, children=[node("sdc1", fstype="vfat")]),
    node("sdd", "disk", tran="usb", children=[node("sdd1", fstype="exfat")]),
    node("sde", "disk", tran="sata", children=[node("sde1", fstype="swap")]),
    node("vda", "disk", children=[node("vda1", fstype="ext4")]),
    node("mmcblk0", "disk", children=[node("mmcblk0p1", fstype="vfat")]),
]}

DISKS = {   # name: (rotational, removable, model, vendor, transport path part)
    "nvme0n1": ("0", "0", "Samsung SSD 990 PRO 1TB", "", "pci"), "nvme1n1": ("0", "0", "WD_BLACK SN770 500GB", "", "pci"),
    "sda": ("1", "0", "WDC WD40EFAX-68JH4N1", "ATA", "ata1"), "sdb": ("0", "0", "Samsung SSD 870 EVO", "ATA", "ata2"),
    "sdc": ("1", "1", "Flash Disk", "Generic", "usb1"), "sdd": ("1", "0", "Expansion HDD", "Seagate", "usb2"),
    "sde": ("1", "0", "ST1000DM010-2EP102", "ATA", "ata3"), "vda": ("1", "0", "", "0x1af4", "virtio0"),
    "mmcblk0": ("0", "0", "SD32G", "", "mmc0"), "loop0": ("0", "0", "", "", "virtual"),
}


@pytest.fixture
def host(tmp_path):
    files = {"/proc/swaps": "Filename Type Size Used Priority\n/dev/sde1 partition 8388604 0 -2\n",
             "/run/udev/data/b8:16": "E:ID_SERIAL_SHORT=S6PNNS0W123456\n"}
    h = make_host(tmp_path, files=files, commands={LSBLK: json.dumps(TREE)})
    devices = h.root / "sys/devices"
    for name, (rota, rm, model, vendor, bus) in DISKS.items():
        real = devices / bus / "block" / name
        (real / "queue").mkdir(parents=True)
        (real / "device").mkdir()
        (real / "queue/rotational").write_text(rota + "\n")
        (real / "removable").write_text(rm + "\n")
        (real / "size").write_text("7814037168\n")
        (real / "device/model").write_text(model + "\n")
        (real / "device/vendor").write_text(vendor + "\n")
        (real / "dev").write_text("8:16\n" if name == "sdb" else "0:0\n")
        (h.root / "sys/block").mkdir(parents=True, exist_ok=True)
        os.symlink(real, h.root / "sys/block" / name)
    (devices / "mmc0/block/mmcblk0/device/type").write_text("SD\n")
    (devices / "usb1/block/sdc/queue/zoned").write_text("none\n")
    return h


def test_drives_their_kind_and_what_holds_the_system(host):
    d = {x.name: x for x in RT.disks(host)}
    assert "loop0" not in d
    kinds = {n: x.kind for n, x in d.items()}
    assert kinds == {"nvme0n1": "nvme", "nvme1n1": "nvme", "sda": "hdd", "sdb": "ssd", "sdc": "flash", "sdd": "usb-disk",
                     "sde": "hdd", "vda": "virtual", "mmcblk0": "card"}
    assert d["nvme0n1"].system == ["/", "/boot/efi"] and RT.blocked(d["nvme0n1"])
    assert d["sde"].system == ["swap on /dev/sde1"]
    assert d["sda"].mounted == ["/mnt/old"] and not d["sda"].system and d["sda"].smr      # a WD Red EFAX is SMR
    assert d["sdb"].serial == "S6PNNS0W123456" and d["sdb"].luks == ["/dev/sdb1"] and d["sdb"].plain == ["/dev/sdb2"]
    assert d["sdb"].open_crypt == ["backup"]
    assert d["nvme1n1"].controller == "/dev/nvme1" and d["sdb"].size == 7814037168 * 512


def commands(g) -> list[str]:
    return [c for st in g.steps for c in st.commands]


def test_the_name_must_be_typed_and_the_system_drive_is_refused(host):
    with pytest.raises(RT.Refused, match="Type the drive's name, sda"):
        RT.guide(host, "sda", "sdb")
    with pytest.raises(RT.Refused, match="holds the running system"):
        RT.guide(host, "nvme0n1", "nvme0n1")
    with pytest.raises(RT.Refused, match="isn't connected"):
        RT.guide(host, "sdz", "sdz")
    assert RT.guide(host, "sda", "/dev/sda").steps                    # typed with /dev/ is fine too


def test_hard_disk_overwrite_unmounting_first(host):
    g = RT.guide(host, "sda", "sda")
    assert g.advice and g.steps[0].title == "Unmount it" and g.steps[0].commands == ["udisksctl unmount -b /dev/sda1"]
    assert any("SMR" in st.title for st in g.steps)
    cmds = commands(g)
    assert "sudo dd if=/dev/zero of=/dev/sda bs=16M oflag=direct status=progress" in cmds
    assert "sudo cmp /dev/sda /dev/zero" in cmds
    assert not any("security-erase" in c for c in cmds)              # not without knowing it is supported and not frozen
    facts = {"ata": {"supported": True, "frozen": False, "enhanced": True, "enhanced_minutes": 480, "erase_minutes": 470,
                     "sanitize": {}}}
    g = RT.guide(host, "sda", "sda", facts=facts)
    erase = next(st for st in g.steps if st.title.startswith("ATA Secure Erase"))
    assert "480 minutes" in erase.text and "sudo hdparm --user-master u --security-erase-enhanced Eins /dev/sda" in erase.commands
    frozen = RT.guide(host, "sda", "sda", facts={"ata": {**facts["ata"], "frozen": True}})
    assert any(st.title == "Unfreeze it" for st in frozen.steps)
    assert not any(st.title.startswith("ATA Secure Erase") for st in frozen.steps)


@pytest.mark.parametrize("name,kind", [("sdb", None), ("nvme1n1", None), ("sdc", None), ("sdd", None), ("sdd", "ssd"),
                                       ("mmcblk0", None), ("vda", None)])
def test_nothing_but_a_hard_disk_is_offered_an_overwrite(host, name, kind):
    """Rule 8: overwriting is offered for hard disks only; never shred."""
    cmds = " ".join(commands(RT.guide(host, name, name, kind=kind)))
    assert "dd if=" not in cmds and "shred" not in cmds and "of=/dev" not in cmds


def test_an_external_disk_the_user_says_is_a_hard_disk(host):
    cmds = commands(RT.guide(host, "sdd", "sdd", kind="hdd"))
    assert "sudo dd if=/dev/zero of=/dev/sdd bs=16M oflag=direct status=progress" in cmds
    assert not any("security" in c for c in cmds)                     # never ATA security through a USB adapter
    unsure = RT.guide(host, "sdd", "sdd")
    assert unsure.steps[0].title == "There is no reliable erase" and "can't tell" in unsure.steps[0].text


def test_ssd_crypto_erase_and_firmware_erase(host):
    g = RT.guide(host, "sdb", "sdb", from_start=True)
    titles = [st.title for st in g.steps]
    assert titles[0] == "Unmount it" and g.steps[0].commands == ["sudo cryptsetup close backup"]
    crypto = g.steps[1]
    assert crypto.title.startswith("Destroy the keys") and "strong option" not in crypto.title   # sdb2 isn't encrypted
    assert crypto.commands == ["sudo cryptsetup erase /dev/sdb1", "sudo cryptsetup luksDump /dev/sdb1"]
    assert any("/dev/sdb2 isn't encrypted" in e for e in crypto.side_effects)
    fw = next(st for st in g.steps if st.title.startswith("The drive's own erase"))
    assert any("not proof" in e for e in fw.side_effects)
    assert g.steps[-1].title == "If it held secrets"


def test_nvme_sanitize_from_its_facts(host):
    facts = {"nvme": {"format": True, "format_crypto": True, "sanitize": {"crypto": True, "block": True, "overwrite": False}}}
    g = RT.guide(host, "nvme1n1", "nvme1n1", from_start=True, facts=facts)
    assert g.steps[0].title == "Destroy the keys (crypto-erase) — the strong option here"
    assert commands(g)[2:] == ["sudo nvme sanitize /dev/nvme1 --sanact=4", "sudo nvme sanitize /dev/nvme1 --sanact=2",
                               "sudo nvme sanitize-log /dev/nvme1", "sudo nvme format /dev/nvme1n1 --ses=2"]


def test_an_encrypted_external_drive_is_unmounted_inside_out(tmp_path):
    """The mounted filesystem is inside the LUKS volume (and LVM inside that): unmounted first, then
    the volume group, then the encrypted volume: cryptsetup close alone would fail on a mounted one."""
    tree = {"blockdevices": [
        node("nvme0n1", "disk", tran="nvme", children=[node("nvme0n1p1", fstype="ext4", mp="/")]),
        node("sdf", "disk", tran="usb", children=[node("sdf1", fstype="crypto_LUKS", children=[
            node("luks-ab12", "crypt", "ext4", "/media/me/Backup")])]),
        node("sdg", "disk", tran="usb", children=[node("sdg1", fstype="crypto_LUKS", children=[
            node("luks-cd34", "crypt", "LVM2_member", children=[
                node("my--vg-data", "lvm", "ext4", "/media/me/Data"), node("my--vg-swap", "lvm", "swap")])])]),
        node("sdh", "disk", tran="usb", fstype="vfat", mp="/media/me/STICK")]}
    h = make_host(tmp_path, commands={LSBLK: json.dumps(tree)})
    for name in ("nvme0n1", "sdf", "sdg", "sdh"):
        real = h.root / "sys/devices/usb1/block" / name
        (real / "queue").mkdir(parents=True)
        (real / "queue/rotational").write_text("0\n")
        (real / "removable").write_text("0\n")
        (h.root / "sys/block").mkdir(parents=True, exist_ok=True)
        os.symlink(real, h.root / "sys/block" / name)
    assert RT.guide(h, "sdf", "sdf").steps[0].commands == ["udisksctl unmount -b /dev/mapper/luks-ab12",
                                                           "sudo cryptsetup close luks-ab12"]
    d = RT.find(h, "sdg")
    assert d.volume_groups == ["my-vg"]
    assert RT.guide(h, "sdg", "sdg").steps[0].commands == ["udisksctl unmount -b /dev/mapper/my--vg-data",
                                                           "sudo vgchange -an my-vg", "sudo cryptsetup close luks-cd34"]
    assert RT.guide(h, "sdh", "sdh").steps[0].commands == ["udisksctl unmount -b /dev/sdh"]   # no partition table


def test_volume_group_names():
    assert RT.volume_group("vg0-root") == "vg0" and RT.volume_group("my--vg-data") == "my-vg"
    assert RT.volume_group("fedora-home--old") == "fedora"


def test_the_second_drive_of_a_btrfs_root_holds_the_running_system(host):
    """lsblk shows / on one of its drives only; /sys/fs/btrfs lists both."""
    devs = host.root / "sys/fs/btrfs/1234-abcd/devices"
    devs.mkdir(parents=True)
    for k in ("nvme0n1p2", "sda1"):
        (devs / k).touch()
    tree = json.loads(json.dumps(TREE))
    tree["blockdevices"][0]["children"][1] = node("nvme0n1p2", fstype="btrfs", mp="/")
    tree["blockdevices"][2]["children"][0] = node("sda1", fstype="btrfs")
    host.runner.outputs[LSBLK] = CommandResult(LSBLK, 0, json.dumps(tree))
    d = {x.name: x for x in RT.disks(host)}
    assert d["sda"].system == ["/"] and RT.blocked(d["sda"])


def test_emmc_boot_areas_and_multipath_paths_arent_drives(host):
    for name in ("mmcblk0boot0", "mmcblk0rpmb", "nvme0c0n1"):
        real = host.root / "sys/devices/extra/block" / name
        (real / "queue").mkdir(parents=True)
        os.symlink(real, host.root / "sys/block" / name)
    names = {x.name for x in RT.disks(host)}
    assert not names & {"mmcblk0boot0", "mmcblk0rpmb", "nvme0c0n1"} and "mmcblk0" in names


def test_a_drive_of_unknown_kind_isnt_told_to_answer_a_question_it_wasnt_asked(host):
    (host.root / "sys/block/sda/queue/rotational").unlink()
    assert RT.find(host, "sda").kind == "unknown"
    st = next(x for x in RT.guide(host, "sda", "sda").steps if x.title == "There is no reliable erase")
    assert "can't tell what kind" in st.text and "above" not in st.text


def test_an_ssd_with_no_erase_of_its_own_says_so(host):
    g = RT.guide(host, "sdb", "sdb", facts={"ata": {"supported": False, "frozen": False, "sanitize": {}}})
    fw = next(st for st in g.steps if st.title.startswith("The drive's own erase"))
    assert not fw.commands and "neither Sanitize nor ATA Secure Erase" in fw.text


def test_virtual_disk(host):
    g = RT.guide(host, "vda", "vda")
    assert [st.title for st in g.steps] == ["Delete it on the host"] and not commands(g)


# ------------------------------------------------------------------ the helper's erase_facts

HDPARM = """
ATA device, with non-removable media
Commands/features:
	   *	SANITIZE feature set
	   *	CRYPTO_SCRAMBLE_EXT command
	   *	BLOCK_ERASE_EXT command
Security:
	Master password revision code = 65534
		supported
	not	enabled
	not	locked
		frozen
	not	expired: security count
		supported: enhanced erase
	2min for SECURITY ERASE UNIT. 8min for ENHANCED SECURITY ERASE UNIT.
Logical Unit WWN Device Identifier: 5002538e40000000
"""

SMARTCTL = """ATA IDENTIFY DEVICE data:
 59      -    0xb110  Sanitize/sectors per interrupt
 89      -    0x0002  Security erase time
 90      -    0x0004  Enhanced security erase time
128      -    0x0029  Security status
"""


@pytest.fixture
def hroot(tmp_path, monkeypatch):
    r = tmp_path / "hroot"
    for name in ("sda", "nvme0n1"):
        (r / f"sys/class/block/{name}").mkdir(parents=True)
    (r / "sys/class/block/sda1").mkdir(parents=True)
    (r / "sys/class/block/sda1/partition").write_text("1\n")
    monkeypatch.setattr(helper, "ROOT", str(r))
    return r


def test_hdparm_security_section():
    s = helper.parse_hdparm_security(HDPARM)
    assert s == {"supported": True, "enabled": False, "locked": False, "frozen": True, "enhanced": True,
                 "erase_minutes": 2, "enhanced_minutes": 8,
                 "sanitize": {"supported": True, "crypto": True, "block": True, "overwrite": False}}
    assert helper.parse_hdparm_security("no security here") is None


def test_erase_facts_from_smartctl_then_hdparm(hroot, monkeypatch):
    monkeypatch.setattr(helper, "RUN", lambda argv: (0, SMARTCTL, "") if argv[0] == "smartctl" else (127, "", ""))
    f = helper.erase_facts({"disk": "sda"})
    assert f["ata"] == {"supported": True, "enabled": False, "locked": False, "frozen": True, "enhanced": True,
                        "erase_minutes": 4, "enhanced_minutes": 8,
                        "sanitize": {"supported": True, "crypto": True, "overwrite": False, "block": True}}
    monkeypatch.setattr(helper, "RUN", lambda argv: (0, HDPARM, "") if argv[0] == "hdparm" else (127, "", ""))
    assert helper.erase_facts({"disk": "sda"})["source"] == "hdparm -I"
    monkeypatch.setattr(helper, "RUN", lambda argv: (127, "", ""))
    assert "neither smartctl nor hdparm" in helper.erase_facts({"disk": "sda"})["notes"][0]


def test_erase_facts_validates_the_disk(hroot):
    for bad in ("sda1", "../sda", "sdq", "/dev/sda", 3, "loop0"):
        with pytest.raises(helper.Refused):
            helper.erase_facts({"disk": bad})


def test_erase_facts_nvme(hroot, monkeypatch):
    ctrl = bytearray(4096)
    ctrl[256] = 0x02                        # OACS: format
    ctrl[328] = 0x03                        # SANICAP: crypto, block
    ctrl[524] = 0x04                        # FNA: crypto erase
    monkeypatch.setattr(helper, "NVME_ADMIN", lambda path, op, cdw10, *a, **kw: bytes(ctrl) if cdw10 == 1 else None)
    f = helper.erase_facts({"disk": "nvme0n1"})
    assert f["nvme"] == {"format": True, "format_crypto": True, "format_all_namespaces": False,
                         "sanitize": {"crypto": True, "block": True, "overwrite": False}}


# ------------------------------------------------------------------ the endpoints

def test_endpoints(cat, host, hroot, monkeypatch):
    (hroot / "sys/class/block/sdb").mkdir(parents=True)
    monkeypatch.setattr(helper, "RUN", lambda argv: (0, SMARTCTL, "") if argv[0] == "smartctl" else (127, "", ""))
    priv = FakePrivileged()
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host, start_helper=lambda: priv))
    d = c.get("/api/tools/retire", headers=H).json()
    assert len(d["drives"]) == 9 and d["facts"] == {}
    assert c.post("/api/tools/retire/guide", headers=H, json={"disk": "sdb", "typed": "sda"}).status_code == 400
    assert c.post("/api/tools/retire/facts", headers=H, json={"disk": "sdz"}).status_code == 400
    f = c.post("/api/tools/retire/facts", headers=H, json={"disk": "sdb"}).json()
    assert f["facts"]["ata"]["frozen"] and f["admin_active"] and priv.calls == [("erase_facts", '{"disk": "sdb"}')]
    g = c.post("/api/tools/retire/guide", headers=H, json={"disk": "sdb", "typed": "sdb"}).json()["guide"]
    assert any(st["title"] == "Unfreeze it" for st in g["steps"])          # the facts read this session are used
    assert c.get("/api/tools/retire", headers=H).json()["facts"]["sdb"]["ata"]["frozen"]
