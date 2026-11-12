"""The root helper's disk parsers against real filesystems: images the kernel itself wrote (tests/images, made by
make_images.py as root on a throwaway machine, and make_noroot_images.py with e2fsprogs), each with the facts read
there by other means (ioctls of the generator's own, debugfs): inode numbers, generations, extents, owners, and the
names that were deleted. The tests compare the helper's Deleted file names listing and the TRIM test's scan with
those facts, instead of with blocks this suite builds by hand.

The helper runs in-process, as the other helper tests do, with the image as the device in a fixture tree. Only the
walk of the mounted folders is replaced (the image isn't mounted here): `_walk_folders` returns the folders the facts
list, by the walk's own rule (the caller's permission bits on every folder on the way), with their real inode
numbers, generations and extents. Everything after it (the device reads, the folder blocks, the journal and its
descriptors, the checksums that tie a copy to its folder, the inode table, btrfs's leaves) is the helper's own code
on the kernel's own bytes."""

from __future__ import annotations

import json
import lzma
import os
import shutil
from pathlib import Path

import pytest

from daprivacyscanner import helper

IMAGES = Path(__file__).parent / "images"
CALLER = (1000, 1000)
MOUNT = "/media/alice/DISK"
DEVICE = "/dev/sdb1"
BLOCK = 4096


def manifest(name: str) -> dict:
    return json.loads((IMAGES / f"{name}.json").read_text())


@pytest.fixture(scope="session")
def unpacked(tmp_path_factory):
    """Each image decompressed once per session (the tests only read it)."""
    cache = tmp_path_factory.mktemp("images")
    made: dict[str, Path] = {}

    def get(name: str) -> Path:
        if name not in made:
            out = cache / f"{name}.img"
            with lzma.open(IMAGES / f"{name}.img.xz") as z, open(out, "wb") as f:
                shutil.copyfileobj(z, f, 1 << 20)
            os.chmod(out, 0o444)
            made[name] = out
        return made[name]
    return get


def _allowed(e: dict, uid: int, groups: set[int], own_only: bool) -> bool:
    st = os.stat_result((e["mode"], e["ino"], 0, 0, e["uid"], e["gid"], 0, 0, 0, 0))
    return e["uid"] == uid if own_only else helper._caller_may(st, uid, groups, 0o5)


def fact_walk(m: dict):
    """_walk_folders, from the facts: the folders the walk would reach (each one on the way allowed), keyed by
    (tree, inode) as the helper keys them, with ext4's extents (plain ones only) and the generations."""
    btrfs = m["fstype"] == "btrfs"

    def walk(root, uid, groups, own_only, ext4):
        dirs, blocks, gens = {}, [], {}
        entries = m["entries"]
        for rel, e in sorted(entries.items()):
            if e["type"] != "dir":
                continue
            parts = rel.split("/") if rel else []
            way = [""] + ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
            if not all(_allowed(entries[p], uid, groups, own_only) for p in way):
                continue
            tree = e["tree"] if btrfs else 0
            dirs[(tree, e["ino"])] = rel
            if btrfs:
                gens[(tree, e["ino"])] = e["gen"]
            else:
                gens[e["ino"]] = e["gen"]
                ext = [(p, n) for p, n, flags, *_ in e["extents"] if not flags & 0xB8A]
                if ext:
                    blocks.append(((0, e["ino"]), bool(e["flags"] & helper.FS_INDEX_FL), ext))
        return dirs, blocks, False, gens
    return walk


@pytest.fixture
def disk(tmp_path, monkeypatch, unpacked):
    """`disk(name)`: a fixture tree whose /dev/sdb1 is the image, mounted (in /proc/self/mounts) at
    /media/alice/DISK, another disk than the home's: every folder on it the caller's permission bits let them open
    is listed. The mount point holds the live entries the facts list (empty files), for the helper's "is that file
    still there" checks. Returns the facts."""
    def make(name: str) -> dict:
        m = manifest(name)
        r = tmp_path / "root"
        (r / "home/alice").mkdir(parents=True)
        (r / "proc/self").mkdir(parents=True)
        (r / "proc/self/mounts").write_text(f"/dev/nvme0n1p2 / ext4 rw 0 0\n{DEVICE} {MOUNT} {m['fstype']} rw,relatime 0 0\n")
        os.symlink("self/mounts", r / "proc/mounts")
        (r / "dev").mkdir()
        try:
            os.link(unpacked(name), r / DEVICE.lstrip("/"))
        except OSError:
            shutil.copyfile(unpacked(name), r / DEVICE.lstrip("/"))
        top = r / MOUNT.lstrip("/")
        for rel, e in sorted(m["entries"].items()):
            p = top / rel if rel else top
            if e["type"] == "dir":
                p.mkdir(parents=True, exist_ok=True)
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.touch()
        os.chmod(top, 0o777)                         # the caller may write at its top (whoever runs the suite)
        live = {(e["ino"], e["gen"]) for e in m["entries"].values()}
        real_statvfs = os.statvfs
        monkeypatch.setattr(helper, "ROOT", str(r))
        monkeypatch.setattr(helper, "CALLER", (*CALLER, "/home/alice"))
        monkeypatch.setattr(helper, "IS_BLOCK", lambda st: True)
        monkeypatch.setattr(helper, "_NAMES", {})
        monkeypatch.setattr(helper, "_TRIM", {})
        monkeypatch.setattr(helper, "_caller_groups", lambda uid, gid: {gid})
        monkeypatch.setattr(helper, "_walk_folders", fact_walk(m))
        monkeypatch.setattr(helper, "INODE_LIVE", lambda s, ino, gen: (ino, gen) in live)
        monkeypatch.setattr(helper, "NVME_ADMIN", lambda *a, **k: None)

        def cant_clear(s, flags):
            raise helper.Refused("this kernel can't clear the journal")
        monkeypatch.setattr(helper, "CHECKPOINT", cant_clear)
        monkeypatch.setattr(os, "statvfs", lambda p, *a: _Bsize() if str(p).startswith(str(top)) else real_statvfs(p, *a))
        return m
    return make


class _Bsize:
    f_bsize = BLOCK


def call(action, **args):
    reply = helper.handle(json.dumps({"id": 1, "action": action, "args": args}))
    if not reply["ok"]:
        raise helper.Refused(reply["error"])
    return reply["result"]


def listing() -> dict:
    begin = call("names_begin", mount=MOUNT)
    while call("names_step")["more"]:
        pass
    return begin, call("names_result")


def expected(m: dict, folders: set[str]) -> dict[str, list[str]]:
    """What the listing should say, from the facts: each listed folder's deleted names, and each folder deleted
    whole (rm -r) under one, with the names it held."""
    out = {rel: sorted(names) for rel, names in m["deleted"].items() if rel in folders}
    out.update({rel: sorted(names) for rel, names in m["gone"].items()
                if rel.rpartition("/")[0] in folders or rel.rpartition("/")[0] in m["gone"]})
    return out


def walked(m: dict) -> set[str]:
    return set(fact_walk(m)(None, CALLER[0], {CALLER[1]}, False, True)[0].values())


# ------------------------------------------------------------------ ext4, current kernel (names only in the journal)

def test_the_images_facts_are_what_the_tests_rely_on():
    """The generator's facts say what each image is: if a regenerated image differs (another kernel, other
    defaults), these tests are about something else and say so here first."""
    m = manifest("ext4-csum")
    assert m["fstype"] == "ext4" and "metadata_csum" in m["features"] and m["block_size"] == BLOCK
    assert m["entries"]["Big"]["flags"] & helper.FS_INDEX_FL                        # an indexed (htree) folder
    assert not m["entries"]["Documents"]["flags"] & helper.FS_INDEX_FL
    assert "Project X" not in m["entries"] and m["gone"]
    assert m["entries"]["Private"]["mode"] & 0o777 == 0o700 and m["entries"]["Private"]["uid"] != CALLER[0]
    assert any("journal_checksum_v3" in line for line in m["dumpe2fs"])
    assert manifest("ext4-nocsum")["features"].startswith("^metadata_csum")
    assert {manifest(f"btrfs-{c}")["csum"] for c in ("crc32c", "sha256", "blake2", "xxhash")} == {"crc32c", "sha256", "blake2", "xxhash"}


def test_ext4_superblock_journal_and_descriptors_parse_as_the_kernel_wrote_them(unpacked):
    m = manifest("ext4-csum")
    fd = os.open(unpacked("ext4-csum"), os.O_RDONLY)
    try:
        fs = helper.parse_ext4_superblock(os.pread(fd, 1024, 1024))
        assert fs["block_size"] == BLOCK and fs["csum"] and fs["journal"] == "inode" and not fs["fast_commit"]
        dump = {k.strip(): v.strip() for k, _, v in (line.partition(":") for line in m["dumpe2fs"])}
        assert fs["inodes"]["per_group"] == int(dump["Inodes per group"])
        assert fs["inodes"]["size"] == int(dump["Inode size"])
        state, extents, jsb, bad = helper._ext4_journal(fd, BLOCK)
        assert state == "read" and not bad
        assert sum(n for _, n, _ in extents) == int(dump["Total journal blocks"]) == jsb["maxlen"]
        assert jsb["incompat"] & helper.JBD2_CSUM_V3 and jsb["incompat"] & helper.JBD2_64BIT
        # the checksum seed the kernel used: every folder's entry blocks check against it (an indexed folder's first
        # block is its index root, whose checksum is a dx_tail's, over other bytes), and hold its live entries
        basis = [helper._crc32c_raw(1 << i, bytes(BLOCK - 12)) for i in range(32)]
        for rel, e in m["entries"].items():
            if e["type"] != "dir":
                continue
            offsets = [at for phys, length, *_ in e["extents"] for at in range(phys, phys + length, BLOCK)]
            indexed = bool(e["flags"] & helper.FS_INDEX_FL)
            live: set[bytes] = set()
            for at in offsets[1:] if indexed else offsets:
                block = os.pread(fd, BLOCK, at)
                assert block[-12:-4] == helper.EXT4_DIR_TAIL, rel
                key = int.from_bytes(block[-4:], "little") ^ helper._crc32c_raw(0, block[:-12])
                assert key == helper._ext4_seed_key(basis, fs["seed"], e["ino"], e["gen"]), rel
                live |= {n for _, _, n in helper.ext4_dir_entries(block[:-12])} - {b".", b".."}
            assert live == {os.fsencode(k.rpartition("/")[2]) for k in m["entries"]
                            if k and k.rpartition("/")[0] == rel}, rel
    finally:
        os.close(fd)


def test_ext4_a_current_kernel_leaves_no_deleted_name_in_the_folder_and_every_one_in_the_journal(unpacked):
    """Linux 5.13 and later overwrite a deleted entry in its folder's block; jbd2's copies of the block as it was
    before hold the name. The copies are found through the journal's descriptor blocks."""
    m = manifest("ext4-csum")
    fd = os.open(unpacked("ext4-csum"), os.O_RDONLY)
    try:
        homes = {}
        for rel, e in m["entries"].items():
            if e["type"] == "dir":
                for phys, length, *_ in e["extents"]:
                    homes.update({b: rel for b in range(phys // BLOCK, (phys + length) // BLOCK)})
        state, copies, read, bad = helper._journal_copies(fd, BLOCK, set(homes))
        assert state == "read" and not bad
        in_journal: dict[str, set[bytes]] = {}
        for b, cs in copies.items():
            for c in cs:
                in_journal.setdefault(homes[b], set()).update(helper.parse_ext4_dir_block(c, live=True))
        for rel, names in m["deleted"].items():
            if rel in homes.values():
                assert {os.fsencode(n) for n in names} <= in_journal.get(rel, set()), rel
                for phys, length, *_ in m["entries"][rel]["extents"]:
                    for at in range(phys, phys + length, BLOCK):
                        left = helper.parse_ext4_dir_block(os.pread(fd, BLOCK, at))
                        assert not left & {os.fsencode(n) for n in names}, rel
    finally:
        os.close(fd)


def test_ext4_the_listing_names_what_was_deleted_and_nothing_else(disk):
    m = disk("ext4-csum")
    begin, r = listing()
    folders = walked(m)
    assert "Private" not in folders and "lost+found" not in folders and "Shared" in folders
    assert begin["scope"] == "mount" and begin["journal"]["state"] == "read" and begin["folders"] == len(folders)
    got = {f["path"]: f["names"] for f in r["folders"]}
    want = expected(m, folders)
    assert {k: v for k, v in got.items() if k in m["deleted"]} == {k: v for k, v in want.items() if k in m["deleted"]}
    # every name only the journal holds (a current kernel), and nothing of what is still there
    assert all(f["journal"] == f["names"] for f in r["folders"])
    live = {k.rpartition("/")[2] for k in m["entries"]}
    assert not {n for names in got.values() for n in names} & live
    assert r["journal"]["checksums"] and r["count"] == sum(len(v) for v in got.values())


def test_ext4_a_folder_deleted_with_rm_r_is_listed_where_it_was(disk):
    """rm -r of "Project X" and its subfolder: the parent's copy names it, the inode table (or the journal's copy of
    it) gives its generation, its own blocks in the journal name it and its parent."""
    m = disk("ext4-csum")
    _, r = listing()
    gone = {f["path"]: f["names"] for f in r["folders"] if f.get("gone")}
    assert gone == {rel: sorted(names) for rel, names in m["gone"].items()}


def test_ext4_another_accounts_private_folder_is_counted_not_named_until_asked(disk):
    m = disk("ext4-csum")
    _, r = listing()
    assert "Private" not in {f["path"] for f in r["folders"]}
    assert r["journal"]["orphans"] >= 1
    orphans = set(call("names_orphans")["names"])
    assert set(m["deleted"]["Private"]) <= orphans
    assert not orphans & {n for rel, names in m["deleted"].items() if rel != "Private" for n in names} - set(m["deleted"][""])


def test_ext4_fstrim_doesnt_take_the_names_out_of_the_journal(disk):
    """The same filesystem after fstrim (the loop device punched the free blocks out of the image): the journal
    is no free space, and its copies of the folder blocks still name every deleted file."""
    m = disk("ext4-csum-trimmed")
    assert m["trimmed"] and "trimmed" in m["fstrim"]
    _, r = listing()
    got = {f["path"]: f["names"] for f in r["folders"] if not f.get("gone")}
    assert got == {k: v for k, v in expected(m, walked(m)).items() if k in m["deleted"]}


def test_ext4_the_listing_finds_the_names_after_a_clean_up_check(disk):
    m = disk("ext4-csum")
    listing()
    c = call("names_check", paths=["Documents"])
    [f] = c["folders"]
    assert f["there"] and f["folder"] == 0 and f["journal"] == len(m["deleted"]["Documents"])
    assert f["left"] == sorted(m["deleted"]["Documents"])


def test_ext4_without_metadata_csum_nothing_in_the_journal_is_tied_to_a_folder(disk):
    m = disk("ext4-nocsum")
    _, r = listing()
    assert not r["journal"]["checksums"]
    assert [f for f in r["folders"] if f.get("journal")] == []
    orphans = set(call("names_orphans")["names"])
    assert {n for names in m["deleted"].values() for n in names} <= orphans


# ------------------------------------------------------------------ ext4, as kernels before 5.13 left it

def test_ext4_names_left_in_the_folders_own_blocks_are_listed_from_them(disk):
    """e2fsprogs's unlink (debugfs rm), as kernels before 5.13 did: the entry before grows over the deleted one, or
    the first in a block gets inode 0. The names are in the folder's blocks, and the journal is empty."""
    m = disk("ext4-debugfs")
    _, r = listing()
    got = {f["path"]: f for f in r["folders"]}
    assert {k: f["names"] for k, f in got.items()} == {k: sorted(v) for k, v in m["deleted"].items()}
    assert not any(f.get("journal") for f in got.values())


# ------------------------------------------------------------------ the TRIM test's scan

def trim_run(m: dict) -> dict:
    begin = call("trim_begin", mount=MOUNT)
    assert begin["size"] == m["size"] and begin["fstype"] == "ext4"
    helper._TRIM.update(run=bytes.fromhex(m["run"]), tag=m["tag"])    # the records the generator wrote
    for off in range(0, m["size"], 1 << 20):
        call("trim_scan", **{"pass": "after", "offset": off, "length": 1 << 20})
    res = call("trim_result", **{"pass": "after"})
    import base64
    bits = base64.b64decode(res["bits"])
    res["indexes"] = {i for i in range(1 << 12) if bits[i >> 3] & (1 << (i & 7))}
    return res


def test_trim_scan_finds_every_record_the_kernel_wrote_and_kept_the_deleted_ones(disk):
    """Not trimmed: the deleted file's records are still in free space, and the tag's names in the folder's
    blocks and the journal."""
    m = disk("ext4-csum")
    res = trim_run(m)
    assert res["indexes"] == {i for t in m["trim"].values() for i in t["records"]}
    assert res["unreadable"] == 0 and set(res["names"]) == {"0", "1"}


def test_trim_scan_after_fstrim_finds_only_the_kept_files_records(disk):
    m = disk("ext4-csum-trimmed")
    res = trim_run(m)
    assert res["indexes"] == {i for t in m["trim"].values() if not t["deleted"] for i in t["records"]}
    assert "1" in res["names"]                     # its name is still in the journal: TRIM doesn't reach it


# ------------------------------------------------------------------ btrfs

BTRFS = ["btrfs-crc32c", "btrfs-sha256", "btrfs-blake2", "btrfs-xxhash"]


@pytest.mark.parametrize("name", BTRFS)
def test_btrfs_superblock_and_leaves_parse_for_every_checksum_type(unpacked, name):
    m = manifest(name)
    data = unpacked(name).read_bytes()
    fs = helper.parse_btrfs_superblock(data[helper.BTRFS_SUPER:helper.BTRFS_SUPER + 4096])
    kind = {"crc32c": 0, "xxhash": 1, "sha256": 2, "blake2": 3}[m["csum"]]
    assert fs["csum"] == kind and fs["nodesize"] == 16384 and fs["sectorsize"] == BLOCK
    dump = {k.strip(): v.strip() for k, _, v in (line.partition("\t") for line in m["dump_super"])}
    assert fs["fsid"].hex() == dump["fsid"].replace("-", "")
    checked = 0
    i = data.find(fs["fsid"])
    while i != -1:
        at = i - 32
        if at >= 0 and at % BLOCK == 0 and data[at + 100] == 0:
            ok = helper._btrfs_csum_ok(data[at:at + fs["nodesize"]], kind)
            if kind == 1:
                assert ok is None                    # xxhash64 isn't in the standard library
            elif int.from_bytes(data[at + 48:at + 56], "little"):  # a real block (the planted ones are said below)
                checked += ok is True
        i = data.find(fs["fsid"], i + 1)
    assert kind == 1 or checked >= 3


@pytest.mark.parametrize("name", BTRFS)
def test_btrfs_the_listing_names_the_deleted_files_in_folders_the_caller_may_open(disk, name):
    m = disk(name)
    begin, r = listing()
    assert begin["unit"] == "bytes" and begin["total"] == m["size"]
    got = {f["path"]: set(f["names"]) for f in r["folders"]}
    planted = {p["name"] for p in m["planted"]}
    for rel, names in m["deleted"].items():
        if rel == "Private":                         # another account's 0700 folder: not walked, not named
            assert rel not in got
        else:
            assert set(names) <= got.get(rel, set()), rel
    deleted = {n for names in m["deleted"].values() for n in names}
    assert {n for names in got.values() for n in names} <= deleted | planted     # nothing still there, nothing made up


@pytest.mark.xfail(strict=True, reason="helper.parse_btrfs_leaf accepts any block with the fsid, owner and a right "
                   "checksum, so a file whose contents are laid out as a leaf adds made-up names to a folder it isn't "
                   "in (the 2026-11 review; the helper agent is fixing it)")
@pytest.mark.parametrize("name", BTRFS)
@pytest.mark.parametrize("which", ["planted-by-a-file.txt", "planted-bytenr-zero.txt"])
def test_btrfs_a_file_laid_out_as_a_leaf_adds_no_names(disk, name, which):
    """Downloads/innocent.bin is a user's file (no copy-on-write, written in place) whose 16 KiB are a leaf of the FS
    tree, fsid, owner and checksum right, naming Documents as holding a file; innocent-2.bin the same with its
    bytenr 0. Only metadata block groups hold tree blocks: a file's data is no folder's entry."""
    m = disk(name)
    p = next(p for p in m["planted"] if p["name"] == which)
    data = Path(helper.ROOT, DEVICE.lstrip("/")).read_bytes()
    assert p["device_offsets"] and which.encode() in data[p["device_offsets"][0]:p["device_offsets"][0] + 16384]
    _, r = listing()
    assert which not in {n for f in r["folders"] for n in f["names"]}
