"""The Deleted file names tool: the helper's checks after a clean-up (one folder re-read between
fillers; a folder, the blocks it had and the ext4 journal's copies of them), the names in the journal
tied to their folders, and clearing it, on a fixture disk."""

from __future__ import annotations

import os
import struct

import pytest

from daprivacyscanner import helper
from test_trimtest import call, dirent, ext4_block, home_folders, make_storage, root  # noqa: F401 - fixtures

BLOCK = 4096
JOURNAL_AT, JOURNAL_LEN = 512, 64                     # filesystem blocks: 2 MiB into the 4 MiB device


UUID = bytes(range(16))
INODE_TABLE, INODES_PER_GROUP, INODE_SIZE = 400, 8192, 256


def ext4_superblock(journal=True, backup=True, extents=((0, JOURNAL_LEN, JOURNAL_AT),), csum=False, fast_commit=False):
    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0x18, 2)                                       # 4096-byte blocks
    struct.pack_into("<H", sb, 0x38, 0xEF53)
    struct.pack_into("<I", sb, 0x5C, (0x4 if journal else 0) | (0x400 if fast_commit else 0))
    struct.pack_into("<I", sb, 0x64, 0x400 if csum else 0)                    # metadata_csum
    struct.pack_into("<I", sb, 0x28, INODES_PER_GROUP)
    struct.pack_into("<I", sb, 0x04, 1024)                                    # blocks: one group
    struct.pack_into("<I", sb, 0x20, 32768)
    struct.pack_into("<H", sb, 0x58, INODE_SIZE)
    sb[0x68:0x78] = UUID
    struct.pack_into("<I", sb, 0xE0, 8)
    sb[0xFD] = 1 if backup else 0
    struct.pack_into("<HHHHI", sb, 0x10C, 0xF30A, len(extents), 4, 0, 0)
    for i, (lblk, n, phys) in enumerate(extents):
        struct.pack_into("<IHHI", sb, 0x10C + 12 + 12 * i, lblk, n, phys >> 32, phys & 0xFFFFFFFF)
    return bytes(sb)


def jbd2_superblock(incompat=helper.JBD2_64BIT | helper.JBD2_CSUM_V3):
    b = bytearray(BLOCK)
    struct.pack_into(">IIIIII", b, 0, helper.JBD2_MAGIC, 4, 1, BLOCK, JOURNAL_LEN, 1)
    struct.pack_into(">I", b, 40, incompat)
    return bytes(b)


def descriptor(homes, incompat=helper.JBD2_64BIT | helper.JBD2_CSUM_V3):
    b = bytearray(BLOCK)
    struct.pack_into(">III", b, 0, helper.JBD2_MAGIC, helper.JBD2_DESCRIPTOR, 7)
    p = 12
    for i, home in enumerate(homes):
        flags = (helper.JBD2_SAME_UUID if i else 0) | (helper.JBD2_LAST_TAG if i == len(homes) - 1 else 0)
        if incompat & helper.JBD2_CSUM_V3:
            struct.pack_into(">IIII", b, p, home & 0xFFFFFFFF, flags, home >> 32, 0)
            p += 16
        else:
            struct.pack_into(">IHH", b, p, home & 0xFFFFFFFF, 0, flags)
            p += 8
        if not i:
            p += 16                                                            # the journal's UUID
    return bytes(b)


def put(dev, block, data):
    with open(dev, "r+b") as f:
        f.seek(block * BLOCK)
        f.write(data)


FS_SEED = helper._crc32c_raw(0xFFFFFFFF, UUID)
GEN = 0x5EED1234                                      # every listed folder's generation in these tests


def folder_block(ino, entries, gen=GEN):
    """A folder block as ext4 writes it with metadata_csum: entries (inode, name, type) leading exactly
    to the 12-byte tail, whose checksum is seeded with the folder's inode number and generation."""
    b, pos = bytearray(BLOCK), 0
    for i, (child, name, ftype) in enumerate(entries):
        rec = BLOCK - 12 - pos if i == len(entries) - 1 else (8 + len(name) + 3) & ~3
        b[pos:pos + 8 + len(name)] = dirent(child, name, rec, ftype)
        pos += rec
    b[BLOCK - 12:BLOCK - 4] = helper.EXT4_DIR_TAIL
    seed = helper._crc32c_raw(helper._crc32c_raw(FS_SEED, ino.to_bytes(4, "little")), gen.to_bytes(4, "little"))
    struct.pack_into("<I", b, BLOCK - 4, helper._crc32c_raw(seed, bytes(b[:BLOCK - 12])))
    return bytes(b)


def inode_record(gen, deleted=True):
    raw = bytearray(INODE_SIZE)
    struct.pack_into("<H", raw, 0, 0o40755)
    struct.pack_into("<I", raw, 0x14, 1791810135 if deleted else 0)
    struct.pack_into("<H", raw, 0x1A, 0 if deleted else 2)
    struct.pack_into("<I", raw, 0x64, gen)
    return bytes(raw)


def inode(dev, ino, gen, deleted=True):
    """Its record in the inode table (group 0's descriptor at block 1 says where the table is)."""
    gd = bytearray(32)
    struct.pack_into("<I", gd, 8, INODE_TABLE)
    put(dev, 1, bytes(gd))
    with open(dev, "r+b") as f:
        f.seek(INODE_TABLE * BLOCK + (ino - 1) * INODE_SIZE)
        f.write(inode_record(gen, deleted))


def csum_disk(root, monkeypatch, **sb):
    """The fixture disk as an ext4 with metadata_csum and an empty journal; every folder's generation GEN."""
    dev = make_storage(root)
    home = home_folders(root)
    put(dev, 0, bytes(1024) + ext4_superblock(csum=True, **sb))
    put(dev, JOURNAL_AT, jbd2_superblock())
    monkeypatch.setattr(helper, "GENERATION", lambda fd: GEN)
    return dev, home


def everything(mount="/"):
    """A whole listing, as the app steps through it: the phases seen, and the result."""
    call("names_begin", mount=mount)
    phases = []
    while True:
        step = call("names_step")
        phases.append(step["phase"])
        if not step["more"]:
            return phases, call("names_result")


def test_a_folder_blocks_checksum_says_whose_it_is():
    """crc32c is linear: a block's checksum XORed with its crc from state 0 depends only on the seed, so one
    pass over a block finds its folder among all of them."""
    basis = [helper._crc32c_raw(1 << i, bytes(BLOCK - 12)) for i in range(32)]
    block = folder_block(1234567, [(1234567, b".", 2), (2, b"..", 2), (40, b"diary.txt", 1)])
    key = int.from_bytes(block[-4:], "little") ^ helper._crc32c_raw(0, block[:-12])
    assert key == helper._ext4_seed_key(basis, FS_SEED, 1234567, GEN)
    assert key != helper._ext4_seed_key(basis, FS_SEED, 1234567, GEN + 1)            # the inode used again: another folder
    assert key != helper._ext4_seed_key(basis, FS_SEED, 1234568, GEN)
    assert helper.ext4_dir_entries(block[:-12]) == [(1234567, 2, b"."), (2, 2, b".."), (40, 1, b"diary.txt")]
    assert helper.ext4_dir_entries(bytes(BLOCK)) is None and helper.ext4_dir_entries(os.urandom(BLOCK)) is None
    crc = helper._Crc0()                                                             # the kernel's, or the table: the same
    assert crc(b"123456789") == helper._crc32c_raw(0, b"123456789") and helper._crc32c(b"123456789") == 0xE3069283
    crc.close()
    fs = helper.parse_ext4_superblock(ext4_superblock(csum=True, fast_commit=True))
    assert fs["csum"] and fs["seed"] == FS_SEED and fs["fast_commit"]
    assert fs["inodes"] == {"per_group": INODES_PER_GROUP, "size": INODE_SIZE, "desc": 32, "gdt": 1, "groups": 1}
    assert helper.parse_ext4_superblock(ext4_superblock())["csum"] is False


def test_on_a_current_kernel_the_names_are_in_the_journal_and_are_listed_from_it(root, monkeypatch):
    """Linux 5.13 and later: the folder's own block holds nothing of a deleted file, and the journal's copy of
    the block as it was before holds its name."""
    dev, home = csum_disk(root, monkeypatch)
    docs, cache = os.stat(home / "Documents").st_ino, os.stat(home / ".cache/app").st_ino
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(256 * BLOCK, BLOCK)] if os.fstat(fd).st_ino == docs else [])
    now = [(docs, b".", 2), (2, b"..", 2), (os.stat(home / "Documents/keep.txt").st_ino, b"keep.txt", 1)]
    put(dev, 256, folder_block(docs, now))                                          # nothing deleted is left in it
    put(dev, JOURNAL_AT + 5, descriptor([256, 300]))
    put(dev, JOURNAL_AT + 6, folder_block(docs, now + [(13, b"secret-plan.odt", 1), (14, b"tax 2025.pdf", 1)]))
    put(dev, JOURNAL_AT + 7, folder_block(999, [(999, b".", 2), (2, b"..", 2), (50, b"someone-elses.txt", 1)], gen=1))
    b = call("names_begin", mount="/")
    assert b["journal"] == {"state": "read", "bytes": JOURNAL_LEN * BLOCK} and b["total"] == 1
    first = call("names_step")
    assert first == {"done": 1, "total": 1, "unit": "folders", "phase": "folders", "more": True}
    assert call("names_step") == {"done": JOURNAL_LEN * BLOCK, "total": JOURNAL_LEN * BLOCK, "unit": "bytes",
                                  "phase": "journal", "more": False}
    r = call("names_result")
    assert r["folders"] == [{"path": "Documents", "names": ["secret-plan.odt", "tax 2025.pdf"],
                             "journal": ["secret-plan.odt", "tax 2025.pdf"]}] and r["count"] == 2
    assert r["journal"] == {"state": "read", "bytes": JOURNAL_LEN * BLOCK, "names": 2, "orphans": 1, "clearable": False,
                            "fast_commit": False, "checksums": True}
    # another account's folder is counted, and named only when asked for
    assert call("names_orphans") == {"names": ["someone-elses.txt"], "truncated": False, "records": 1}
    # the check after a clean-up still finds them in the journal
    c = call("names_check", paths=["Documents"])["folders"][0]
    assert (c["folder"], c["journal"], c["left"]) == (0, 2, ["secret-plan.odt", "tax 2025.pdf"])
    assert cache                                                                     # (a folder without blocks: nothing of it)


def test_a_checksum_alone_doesnt_tie_a_copy_to_a_folder(root, monkeypatch):
    """32 bits can agree by chance: the journal must also say the copy is of a block the folder has now, or the
    block must name the folder as itself, or hold a file the folder has now under that name and inode."""
    dev, home = csum_disk(root, monkeypatch)
    docs = os.stat(home / "Documents").st_ino
    keep = os.stat(home / "Documents/keep.txt").st_ino
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(256 * BLOCK, BLOCK)] if os.fstat(fd).st_ino == docs else [])
    put(dev, JOURNAL_AT + 5, descriptor([700, 701, 702]))                           # none is a block Documents has now
    put(dev, JOURNAL_AT + 6, folder_block(docs, [(77, b"unproven.txt", 1)]))        # fits the checksum, nothing else
    put(dev, JOURNAL_AT + 7, folder_block(docs, [(docs, b".", 2), (2, b"..", 2), (78, b"by-its-dot.txt", 1)]))
    put(dev, JOURNAL_AT + 8, folder_block(docs, [(keep, b"keep.txt", 1), (79, b"by-a-file-still-there.txt", 1)]))
    # a descriptor at the journal's end whose copy wrapped round to its start
    put(dev, JOURNAL_AT + 63, descriptor([256]))
    put(dev, JOURNAL_AT + 1, folder_block(docs, [(80, b"wrapped.txt", 1)]))
    phases, r = everything()
    assert phases == ["folders", "journal"]
    assert r["folders"] == [{"path": "Documents", "names": ["by-a-file-still-there.txt", "by-its-dot.txt", "wrapped.txt"],
                             "journal": ["by-a-file-still-there.txt", "by-its-dot.txt", "wrapped.txt"]}]
    assert r["journal"]["orphans"] == 1 and call("names_orphans")["names"] == ["unproven.txt"]


def test_a_deleted_folders_names_are_listed_under_the_folder_it_was_in(root, monkeypatch):
    """rm -r, or a folder emptied from the trash: a copy of the folder it was in names it, the inode table has
    its inode as deleted with its generation, and its own first block names itself and that parent."""
    dev, home = csum_disk(root, monkeypatch)
    docs = os.stat(home / "Documents").st_ino
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(256 * BLOCK, BLOCK)] if os.fstat(fd).st_ino == docs else [])
    put(dev, JOURNAL_AT + 5, descriptor([256, 800, 801, 802, 803]))
    put(dev, JOURNAL_AT + 6, folder_block(docs, [(docs, b".", 2), (2, b"..", 2), (12, b"Project X", 2), (20, b"Other", 2)]))
    put(dev, JOURNAL_AT + 7, folder_block(12, [(12, b".", 2), (docs, b"..", 2), (30, b"offer.pdf", 1), (13, b"drafts", 2)], gen=41))
    put(dev, JOURNAL_AT + 8, folder_block(12, [(31, b"second-block.txt", 1)], gen=41))
    put(dev, JOURNAL_AT + 9, folder_block(13, [(13, b".", 2), (12, b"..", 2), (32, b"draft 1.odt", 1)], gen=42))
    # "Other" is deleted too, but the block carrying its checksum says its parent is another folder: not tied
    put(dev, JOURNAL_AT + 10, folder_block(20, [(20, b".", 2), (555, b"..", 2), (33, b"not-under-documents.txt", 1)], gen=43))
    inode(dev, 12, 41)
    inode(dev, 13, 42)
    inode(dev, 20, 43)
    _, r = everything()
    assert r["folders"] == [
        {"path": "Documents", "names": ["Other", "Project X"], "journal": ["Other", "Project X"]},
        {"path": "Documents/Project X", "names": ["drafts", "offer.pdf", "second-block.txt"],
         "journal": ["drafts", "offer.pdf", "second-block.txt"], "gone": True},
        {"path": "Documents/Project X/drafts", "names": ["draft 1.odt"], "journal": ["draft 1.odt"], "gone": True}]
    assert r["journal"]["names"] == 6 and r["journal"]["orphans"] == 1
    with pytest.raises(helper.Refused):                                             # a gone folder has nothing to clean
        call("names_folder", path="Documents/Project X")

    # an inode the table has as in use is somebody's folder now: its blocks stay untied
    inode(dev, 12, 41, deleted=False)
    _, r = everything()
    assert [f["path"] for f in r["folders"]] == ["Documents"] and r["journal"]["orphans"] == 4


def test_a_deleted_folder_whose_inode_was_used_again_is_found_by_the_journals_copy_of_the_inode(root, monkeypatch):
    """Seen on the first real run: after rm -r the next file made took the folder's inode number, with a new
    generation, so the inode table no longer had the folder's. The journal's copy of that part of the table
    still does, and the kernel says no inode of that number and generation exists now."""
    dev, home = csum_disk(root, monkeypatch)
    docs = os.stat(home / "Documents").st_ino
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(256 * BLOCK, BLOCK)] if os.fstat(fd).st_ino == docs else [])
    put(dev, JOURNAL_AT + 5, descriptor([256, 800, INODE_TABLE]))
    put(dev, JOURNAL_AT + 6, folder_block(docs, [(docs, b".", 2), (2, b"..", 2), (12, b"Project X", 2)]))
    put(dev, JOURNAL_AT + 7, folder_block(12, [(12, b".", 2), (docs, b"..", 2), (30, b"offer.pdf", 1)], gen=41))
    put(dev, JOURNAL_AT + 8, bytes(11 * INODE_SIZE) + inode_record(41, deleted=False) + bytes(BLOCK - 12 * INODE_SIZE))
    inode(dev, 12, 99, deleted=False)                                # the number belongs to a new file now
    asked = []
    monkeypatch.setattr(helper, "INODE_LIVE", lambda s, ino, gen: asked.append((ino, gen)) or gen == 99)
    _, r = everything()
    assert [(f["path"], f["names"], f.get("gone")) for f in r["folders"]] == [
        ("Documents", ["Project X"], None), ("Documents/Project X", ["offer.pdf"], True)]
    assert asked == [(12, 41)]                                       # only of a generation whose blocks are in the journal

    # where the kernel can't be asked, a record must have that generation deleted: here none has
    monkeypatch.setattr(helper, "INODE_LIVE", lambda s, ino, gen: None)
    _, r = everything()
    assert [f["path"] for f in r["folders"]] == ["Documents"] and r["journal"]["orphans"] == 1
    # and a folder there now (the kernel says so) is never listed as deleted
    monkeypatch.setattr(helper, "INODE_LIVE", lambda s, ino, gen: True)
    _, r = everything()
    assert [f["path"] for f in r["folders"]] == ["Documents"]


def test_without_checksums_nothing_in_the_journal_can_be_tied_to_a_folder(root, monkeypatch):
    dev = make_storage(root)
    home = home_folders(root)
    docs = os.stat(home / "Documents").st_ino
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(256 * BLOCK, BLOCK)] if os.fstat(fd).st_ino == docs else [])
    put(dev, 0, bytes(1024) + ext4_superblock(fast_commit=True))
    put(dev, JOURNAL_AT, jbd2_superblock())
    put(dev, JOURNAL_AT + 5, descriptor([256]))
    put(dev, JOURNAL_AT + 6, ext4_block([(0, dirent(docs, b".", 12, 2)), (12, dirent(2, b"..", 12, 2)),
                                         (24, dirent(13, b"secret-plan.odt", 4072))]))
    put(dev, JOURNAL_AT + 9, os.urandom(BLOCK))                                     # not a folder block
    _, r = everything()
    assert r["folders"] == [] and r["journal"]["orphans"] == 1 and not r["journal"]["checksums"]
    assert r["journal"]["fast_commit"]
    assert call("names_orphans")["names"] == ["secret-plan.odt"]


def test_clearing_the_journal_is_the_kernels_own_call_on_the_listed_filesystem(root, monkeypatch):
    dev, home = csum_disk(root, monkeypatch)
    docs = os.stat(home / "Documents").st_ino
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(256 * BLOCK, BLOCK)] if os.fstat(fd).st_ino == docs else [])
    put(dev, JOURNAL_AT + 5, descriptor([256]))
    put(dev, JOURNAL_AT + 6, folder_block(docs, [(docs, b".", 2), (2, b"..", 2), (13, b"secret-plan.odt", 1)]))
    put(dev, JOURNAL_AT + 7, folder_block(999, [(50, b"someone-elses.txt", 1)], gen=1))
    with pytest.raises(helper.Refused, match="haven't been listed"):
        call("names_begin", mount="/") and call("names_journal_clear")
    made = []

    def checkpoint(s, flags):                       # what the kernel does: everything written out, the journal zeroed
        made.append((s["mount"], flags))
        if flags == helper.EXT4_CHECKPOINT_ZEROOUT:
            for b in range(1, JOURNAL_LEN):
                put(dev, JOURNAL_AT + b, bytes(BLOCK))
    monkeypatch.setattr(helper, "CHECKPOINT", checkpoint)
    _, r = everything()
    assert r["count"] == 1 and r["journal"]["clearable"] and r["journal"]["orphans"] == 1
    assert made == [("/", helper.EXT4_CHECKPOINT_DRY_RUN)]                           # asked whether it can: nothing done
    assert call("names_journal_clear")["cleared"] and made[-1] == ("/", helper.EXT4_CHECKPOINT_ZEROOUT)
    assert call("names_orphans") == {"names": [], "truncated": False, "records": 0}
    assert call("names_check", paths=["Documents"])["folders"][0]["left"] == []
    _, r = everything()
    assert r["count"] == 0 and r["journal"]["names"] == 0 and r["journal"]["orphans"] == 0

    def refuses(s, flags):
        raise helper.Refused("this kernel can't clear the journal (Linux 5.14 and later can)")
    monkeypatch.setattr(helper, "CHECKPOINT", refuses)
    _, r = everything()
    assert not r["journal"]["clearable"]
    with pytest.raises(helper.Refused, match="5.14"):
        call("names_journal_clear")


def test_jbd2_descriptors_list_the_blocks_their_copies_are_of():
    v3 = helper.JBD2_64BIT | helper.JBD2_CSUM_V3
    assert helper.parse_jbd2_descriptor(descriptor([256, 1 << 33, 7], v3), v3) == [256, 1 << 33, 7]
    assert helper.parse_jbd2_descriptor(descriptor([256, 300], 0), 0) == [256, 300]           # 32-bit tags, no checksums
    assert helper.parse_jbd2_descriptor(bytes(BLOCK), v3) is None
    assert helper.parse_jbd2_superblock(jbd2_superblock()) == {"block_size": BLOCK, "maxlen": JOURNAL_LEN, "first": 1,
                                                               "incompat": v3, "fast_commit": 256}


def test_the_journal_is_found_through_the_superblocks_copy_of_its_inode():
    fs = helper.parse_ext4_superblock(ext4_superblock())
    assert fs["block_size"] == BLOCK and fs["journal"] == "inode"
    assert helper.ext4_extents(fs["journal_map"], lambda n: None) == [(0, JOURNAL_LEN, JOURNAL_AT)]
    assert helper.parse_ext4_superblock(ext4_superblock(journal=False))["journal"] == "none"
    assert helper.parse_ext4_superblock(ext4_superblock(backup=False))["journal"] == "unknown"
    assert helper.parse_ext4_superblock(bytes(1024)) is None
    # a deeper tree: the inode holds an index, the extents are in a block of their own
    index = bytearray(60)
    struct.pack_into("<HHHHI", index, 0, 0xF30A, 1, 4, 1, 0)
    struct.pack_into("<IIH", index, 12, 0, 900, 0)
    leaf = bytearray(BLOCK)
    struct.pack_into("<HHHHI", leaf, 0, 0xF30A, 2, 340, 0, 0)
    struct.pack_into("<IHHI", leaf, 12, 0, 32768, 0, 1000)
    struct.pack_into("<IHHI", leaf, 24, 32768, 100, 0, 40000)
    assert helper.ext4_extents(bytes(index), {900: bytes(leaf)}.get) == [(0, 32768, 1000), (32768, 100, 40000)]


def listed(root, monkeypatch, places):
    """Lists the names on the fixture disk with each folder's blocks at `places` (inode -> offset),
    which the test can change afterwards (a rebuilt folder's new blocks)."""
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(places[os.fstat(fd).st_ino], BLOCK)]
                        if os.fstat(fd).st_ino in places else [])
    b = call("names_begin", mount="/")
    while call("names_step")["done"] < b["total"]:
        pass
    return call("names_result")


def test_after_a_rebuild_the_check_reads_the_folder_its_old_blocks_and_the_journals_copies(root, monkeypatch):
    dev = make_storage(root)
    home = home_folders(root)
    docs = os.stat(home / "Documents").st_ino
    put(dev, 0, bytes(1024) + ext4_superblock())
    put(dev, JOURNAL_AT, jbd2_superblock())
    old_block = [(0, dirent(2, b".", 12, 2)), (12, dirent(2, b"..", 12, 2)), (24, dirent(12, b"keep.txt", 4072))]
    # the journal still has the block from before the file was deleted, and a descriptor near its end
    # whose copies wrap round to the journal's start
    put(dev, JOURNAL_AT + 10, descriptor([256]))
    put(dev, JOURNAL_AT + 11, ext4_block(old_block[:2] + [(24, dirent(12, b"keep.txt", 16)),
                                                           (40, dirent(13, b"secret-plan.odt", 4056))]))
    put(dev, JOURNAL_AT + 63, descriptor([999, 256]))
    put(dev, JOURNAL_AT + 2, ext4_block([(0, dirent(14, b"tax 2025.pdf", 4096))]))
    put(dev, 256, ext4_block(old_block + [(40, dirent(13, b"secret-plan.odt", 24)), (64, dirent(14, b"tax 2025.pdf", 4032))]))
    places = {docs: 256 * BLOCK}
    r = listed(root, monkeypatch, places)
    assert r["folders"] == [{"path": "Documents", "names": ["secret-plan.odt", "tax 2025.pdf"]}]
    assert call("names_folder", path="Documents")["left"] == ["secret-plan.odt", "tax 2025.pdf"]

    places[docs] = 300 * BLOCK                                   # rebuilt: a new folder, its old block freed
    put(dev, 300, ext4_block(old_block))
    c = call("names_check", paths=["Documents"])
    assert c["journal"] == "read" and c["journal_bytes"] == JOURNAL_LEN * BLOCK
    assert c["folders"] == [{"path": "Documents", "there": True, "folder": 0, "freed": 2, "journal": 2,
                             "left": ["secret-plan.odt", "tax 2025.pdf"], "listed": 2}]

    put(dev, 256, bytes(BLOCK))                                  # trimmed
    put(dev, JOURNAL_AT + 11, bytes(BLOCK))                      # the journal wrapped over one copy
    c = call("names_check", paths=["Documents"])["folders"][0]
    assert (c["folder"], c["freed"], c["journal"], c["left"]) == (0, 0, 1, ["tax 2025.pdf"])

    (home / "Documents/tax 2025.pdf").write_text("x")            # a file of that name is there again: not a leftover
    assert call("names_check", paths=["Documents"])["folders"][0]["left"] == []


def test_a_folder_that_grew_still_has_its_old_block_so_nothing_is_counted_as_freed(root, monkeypatch):
    """Fillers make a folder grow: its one-block extent becomes a two-block one over the same first
    block. A name still in that block is in the folder, not in records it had."""
    dev = make_storage(root)
    home = home_folders(root)
    put(dev, 256, ext4_block([(0, dirent(0, b"gone.txt", 4096))]))
    listed(root, monkeypatch, {os.stat(home / "Documents").st_ino: 256 * BLOCK})
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(256 * BLOCK, 2 * BLOCK)])
    c = call("names_check", paths=["Documents"])["folders"][0]
    assert (c["folder"], c["freed"], c["left"]) == (1, 0, ["gone.txt"])


def test_the_checks_cover_only_listed_folders_and_say_why_the_journal_wasnt_read(root, monkeypatch):
    dev = make_storage(root)
    home = home_folders(root)
    put(dev, 256, ext4_block([(0, dirent(0, b"gone.txt", 4096))]))
    places = {os.stat(home / "Documents").st_ino: 256 * BLOCK}
    listed(root, monkeypatch, places)
    with pytest.raises(helper.Refused, match="isn't in the list"):
        call("names_folder", path=".cache/app")
    with pytest.raises(helper.Refused, match="isn't in the list"):
        call("names_check", paths=["../elsewhere"])
    c = call("names_check", paths=["Documents"])
    assert c["journal"] == "unknown" and c["folders"][0]["folder"] == 1          # no superblock on this fixture
    put(dev, 0, bytes(1024) + ext4_superblock(journal=False))
    assert call("names_check", paths=["Documents"])["journal"] == "none"
    os.rename(home / "Documents", home / "Moved")
    os.symlink(home / "Moved", home / "Documents")                                 # never followed
    assert call("names_check", paths=["Documents"])["folders"][0]["there"] is False
    call("names_end")
    with pytest.raises(helper.Refused, match="not looking"):
        call("names_check", paths=["Documents"])


def test_fillers_lower_the_count_as_they_take_the_deleted_entries_places(root, monkeypatch):
    dev = make_storage(root)
    home = home_folders(root)
    docs = os.stat(home / "Documents").st_ino
    head = [(0, dirent(2, b".", 12, 2)), (12, dirent(2, b"..", 12, 2))]
    put(dev, 256, ext4_block(head + [(24, dirent(12, b"keep.txt", 4072)), (40, dirent(13, b"secret-plan.odt", 4056))]))
    listed(root, monkeypatch, {docs: 256 * BLOCK})
    # a filler of the same length took the slot: ext4 writes it at the same place, over the old name
    put(dev, 256, ext4_block(head + [(24, dirent(12, b"keep.txt", 16)), (40, dirent(15, b"0123456789abcde", 4056))]))
    assert call("names_folder", path="Documents")["left"] == []


def test_fstrim_runs_on_the_listed_filesystem(root, monkeypatch):
    make_storage(root)
    home_folders(root)
    ran = []
    monkeypatch.setattr(helper, "TRIM_RUN", lambda argv: ran.append(argv) or (0, "/: 1 GiB (1073741824 bytes) trimmed\n", ""))
    with pytest.raises(helper.Refused, match="only /"):
        call("names_fstrim", mount="/etc")
    assert call("names_fstrim", mount="/") == {"trimmed": 1073741824} and ran == [["fstrim", "-v", "/"]]


# ------------------------------------------------------------------ the tool: where, the list, what can be done

from fastapi.testclient import TestClient  # noqa: E402

from daprivacyscanner.privileged import FakePrivileged  # noqa: E402
from daprivacyscanner.server import create_app  # noqa: E402
from daprivacyscanner.tools import names as N  # noqa: E402
from daprivacyscanner.tools import rebuild as R  # noqa: E402
from test_trimtest import H, host_for  # noqa: E402


def test_the_home_filesystem_is_offered_and_the_system_disk_outside_the_home_isnt(root):
    make_storage(root)
    ts = N.targets(host_for(root))
    assert [(t["mount"], t["scope"], t["blocked"]) for t in ts] == [("/", "home", "")]
    with open(root / "proc/self/mounts", "a") as f:
        f.write("/dev/sdb1 /home xfs rw 0 0\n")
    ts = N.targets(host_for(root))                                              # / without the home isn't offered
    assert [t["mount"] for t in ts] == ["/home"] and "xfs" in ts[0]["blocked"]
    make_storage(root, rotational="1")
    assert N.targets(host_for(root))[0]["no_trim"] == "hdd"                       # names stay listable on a hard disk


def listing(root, folders, fstype="ext4", journal=None):
    """A listing as the helper hands it over (names_result) for the fixture home."""
    return {"folders": [{"path": p, "names": n} for p, n in folders], "count": sum(len(n) for _, n in folders),
            "truncated": False, "fstype": fstype, "scope": "home", "root": str(root / "home/alice"), "unreadable": 0,
            **({"journal": journal} if journal else {})}


JOURNAL = {"state": "read", "bytes": 1 << 30, "names": 3, "orphans": 139, "clearable": True, "fast_commit": False,
           "checksums": True}


def test_names_the_journal_alone_holds_are_cleared_with_it_not_by_cleaning_the_folder(root):
    make_storage(root)
    home_folders(root)
    host = host_for(root)
    r = listing(root, [("Documents", ["old-kernel-leftover.txt", "secret-plan.odt"]), ("Documents/Project X", ["offer.pdf"]),
                       (".cache/app", ["tmp-1234"])], journal=JOURNAL)
    r["folders"][0]["journal"] = ["secret-plan.odt"]
    r["folders"][1].update(journal=["offer.pdf"], gone=True)
    r["folders"][2]["journal"] = ["tmp-1234"]
    v = N.view(host, N.target(host, "/"), r)
    f = {x["rel"]: x for x in v["folders"]}
    assert f["Documents"]["remedy"]["method"] == "fillers" and f["Documents"]["journal_only"] == 1      # one is in the folder
    assert f[".cache/app"]["remedy"]["method"] == "none" and f[".cache/app"]["remedy"]["journal"]
    assert "clearing the journal removes them" in f[".cache/app"]["remedy"]["why"]
    assert f["Documents/Project X"]["gone"] and "This folder is gone" in f["Documents/Project X"]["remedy"]["why"]
    assert v["journal"]["orphans"] == 139 and v["journal"]["clearable"]
    # the same call from a terminal, quoted for a shell
    assert v["journal"]["command"] == ("sudo python3 -c 'import fcntl, os, struct; fcntl.ioctl(os.open(\"/\", os.O_RDONLY), "
                                       "0x4004662B, struct.pack(\"I\", 2))'")
    import shlex
    assert 'os.open("/mnt/it\'s", os.O_RDONLY)' in shlex.split(N.clear_command("/mnt/it's"))[3]


def test_the_app_steps_through_the_folders_then_the_journal_and_clears_it_through_the_helper(root):
    make_storage(root)
    home_folders(root)

    class Listing:
        calls = []
        steps = [{"done": 2, "total": 2, "unit": "folders", "phase": "folders", "more": True},
                 {"done": 1 << 28, "total": 1 << 30, "unit": "bytes", "phase": "journal", "more": True},
                 {"done": 1 << 30, "total": 1 << 30, "unit": "bytes", "phase": "journal", "more": False}]

        def call(self, action, args, timeout=None):
            self.calls.append(action)
            if action == "names_begin":
                return {"fstype": "ext4", "folders": 4, "total": 2, "unit": "folders", "scope": "home", "root": "/home/alice",
                        "journal": {"state": "read", "bytes": 1 << 30}}
            if action == "names_step":
                return self.steps[self.calls.count("names_step") - 1]
            if action == "names_result":
                return listing(root, [("Documents", ["secret-plan.odt"])], journal=JOURNAL)
            if action == "names_journal_clear":
                return {"cleared": True, "seconds": 0.6}
            if action == "names_orphans":
                return {"names": ["a" * 40, "someone-elses.txt"], "truncated": False, "records": 2}
            raise AssertionError(action)
    h, job = Listing(), {}
    r = N.scan(host_for(root), "/", lambda: h, job)
    assert h.calls == ["names_begin", "names_step", "names_step", "names_step", "names_result"]
    assert job["phase"] == N.PHASES["journal"] and (job["done"], job["total"], job["unit"]) == (1 << 30, 1 << 30, "bytes")
    assert r["journal"]["names"] == 3 and "This list reads both" in r["facts"][0]
    assert N.clear_journal(lambda: h) == {"cleared": True, "seconds": 0.6}
    assert N.orphans(lambda: h) == {"names": ["someone-elses.txt"], "hashes": ["a" * 40], "truncated": False, "records": 2}
    with pytest.raises(N.Stopped):
        N.clear_journal(lambda: None)                                              # administrator access ended


def big(monkeypatch, *names):
    """These folders count as large (indexed by ext4): they are rebuilt; the rest get fillers."""
    monkeypatch.setattr(N, "indexed", lambda path: path.name in names)


def test_the_list_groups_hash_names_and_says_what_each_folder_can_have_done(root, monkeypatch):
    big(monkeypatch, "Documents")
    make_storage(root)
    home = home_folders(root)
    host = host_for(root)
    t = N.target(host, "/")
    cache = home / ".cache/mozilla/firefox/x.default/cache2/entries"
    cache.mkdir(parents=True)
    (home / "Dropbox/Work").mkdir(parents=True)
    (home / "Dropbox/.dropbox").write_text("")
    (home / ".local/share/daprivacyscanner").mkdir(parents=True)
    hashes = [f"{i:040X}" for i in range(5)]
    r = N.view(host, t, listing(root, [
        ("", ["old notes.txt"]),
        (".cache/mozilla/firefox/x.default/cache2/entries", hashes + ["short"]),
        (".local/share/daprivacyscanner", ["trim-test"]),
        ("Documents", ["secret-plan.odt", "0123456789abcdef0123456789abcdef", "____12", ".Work.rebuild-0a1b2c3d"]),
        ("Dropbox/Work", ["contract.pdf"])]))
    f = {x["rel"]: x for x in r["folders"]}
    assert f[".cache/mozilla/firefox/x.default/cache2/entries"]["hashes"] == hashes
    assert f[".cache/mozilla/firefox/x.default/cache2/entries"]["names"] == ["short"]
    assert f[".cache/mozilla/firefox/x.default/cache2/entries"]["browser_cache"]
    assert f["Documents"]["hashes"] == [] and len(f["Documents"]["names"]) == 4   # one hash: listed as it is
    assert "what fillers leave" in f["Documents"]["notes"][0] and "while it was rebuilt" in f["Documents"]["notes"][1]
    assert "TRIM test's own folder" in f[".local/share/daprivacyscanner"]["notes"][0]
    assert f[""]["path"] == "~" and f[""]["remedy"]["method"] == "fillers"          # the home can't be swapped
    assert f["Documents"]["remedy"]["method"] == "rebuild" and "A large folder" in f["Documents"]["remedy"]["why"]
    assert f[".cache/mozilla/firefox/x.default/cache2/entries"]["remedy"]["method"] == "fillers"     # a small one
    assert f["Dropbox/Work"]["remedy"] == {"method": "none", "synced": "Dropbox", "why": f["Dropbox/Work"]["remedy"]["why"]}
    assert "permanently" in f["Dropbox/Work"]["remedy"]["why"]
    assert r["commands"] == ["sudo e2fsck -fD /dev/nvme0n1p2"]
    with open(root / "proc/self/mounts", "a") as m:
        m.write("/dev/sdc1 /home/alice/Documents/usb vfat rw 0 0\n")
    assert N.remedy(host, t, {"scope": "home", "root": str(home)}, "Documents")["method"] == "fillers"


def test_on_btrfs_the_list_says_what_continuous_trim_means(root):
    make_storage(root, fstype="btrfs", options="rw,discard=async")
    home_folders(root)
    host = host_for(root)
    t = N.target(host, "/")
    r = N.view(host, t, listing(root, [("Documents", ["a.txt"])], fstype="btrfs"), trim_passed=True)
    assert r["folders"][0]["remedy"] is None and r["commands"] == []
    assert any("the TRIM test passed" in x and "mechanism working" in x for x in r["facts"])
    r = N.view(host, t, listing(root, [("Documents", ["a.txt"])], fstype="btrfs"))
    assert any("if TRIM works on this drive" in x for x in r["facts"])


def test_e2fsck_unlocks_an_encrypted_disk_first(root):
    make_storage(root, luks=True)
    host = host_for(root)
    assert N.e2fsck_commands(host, N.target(host, "/")) == ["sudo cryptsetup open /dev/nvme0n1p2 luks-1",
                                                            "sudo e2fsck -fD /dev/mapper/luks-1"]


# ------------------------------------------------------------------ rebuilding a folder

def tree(folder):
    return sorted((p.relative_to(folder).as_posix(), p.is_symlink(), p.is_dir()) for p in folder.rglob("*"))


@pytest.mark.parametrize("exchange", [True, False])
def test_a_rebuilt_folder_has_everything_it_had_and_the_same_permissions(tmp_path, monkeypatch, exchange):
    top = tmp_path / "home"
    docs = top / "Documents"
    (docs / "sub").mkdir(parents=True)
    (docs / "a.txt").write_text("a")
    (docs / "sub/b.txt").write_text("b")
    os.link(docs / "a.txt", docs / "hard")
    os.symlink("a.txt", docs / "link")
    docs.chmod(0o750)
    os.utime(docs, ns=(1_000_000_000, 2_000_000_000))
    before, ino = tree(docs), os.stat(docs).st_ino
    if not exchange:
        monkeypatch.setattr(R, "EXCHANGE", lambda parent, a, b: False)
    r = R.rebuild(top, "Documents")
    st = os.stat(docs)
    assert r["moved"] == 4 and tree(docs) == before and st.st_ino != ino
    assert oct(st.st_mode & 0o7777) == "0o750" and st.st_mtime_ns == 2_000_000_000
    assert os.listdir(top) == ["Documents"]                                   # nothing of the rebuild left
    assert os.stat(docs / "a.txt").st_ino == os.stat(docs / "hard").st_ino    # entries moved, not copied


def test_extended_attributes_go_with_a_rebuilt_folder(tmp_path):
    top = tmp_path / "home"
    docs = top / "Documents"
    docs.mkdir(parents=True)
    (docs / "a.txt").write_text("a")
    try:
        os.setxattr(docs, "user.daps-test", b"kept")
    except OSError:
        pytest.skip("this filesystem has no user extended attributes")
    R.rebuild(top, "Documents")
    assert os.getxattr(docs, "user.daps-test") == b"kept" and os.listdir(docs) == ["a.txt"]


def test_a_rebuild_that_fails_halfway_puts_everything_back(tmp_path, monkeypatch):
    top = tmp_path / "home"
    docs = top / "Documents"
    docs.mkdir(parents=True)
    for i in range(5):
        (docs / f"{i}.txt").write_text(str(i))
    real, moved = R.MOVE, []

    def move(src, name, dst):
        if len(moved) == 3:
            moved.append(None)                                                    # once
            raise OSError(5, "Input/output error")
        moved.append(name)
        return real(src, name, dst)
    monkeypatch.setattr(R, "MOVE", move)
    with pytest.raises(OSError):
        R.rebuild(top, "Documents")
    monkeypatch.setattr(R, "MOVE", real)
    assert sorted(os.listdir(docs)) == [f"{i}.txt" for i in range(5)] and os.listdir(top) == ["Documents"]


@pytest.mark.parametrize("noreplace", [True, False])
def test_moving_never_replaces_an_entry_already_there(tmp_path, monkeypatch, noreplace):
    """With renameat2's RENAME_NOREPLACE, or without it (looked up first)."""
    if not noreplace:
        monkeypatch.setattr(R, "_renameat2", lambda *a: False)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    (a / "x").write_text("older")
    (b / "x").write_text("newer")
    fa, fb = os.open(a, os.O_RDONLY), os.open(b, os.O_RDONLY)
    try:
        with pytest.raises(FileExistsError):
            R.MOVE(fa, "x", fb)
    finally:
        os.close(fa), os.close(fb)
    assert (b / "x").read_text() == "newer" and (a / "x").read_text() == "older"


def test_a_file_saved_into_the_old_folder_meanwhile_is_never_overwritten(tmp_path, monkeypatch):
    """A program saves a.txt again while the entries are being moved (it holds no file open, so
    holders() didn't stop it), and the roll-back then meets its name: it stops rather than replace
    the newer copy, and the result names the folder the rest are in, with the commands."""
    top = tmp_path / "home"
    docs = top / "Documents"
    docs.mkdir(parents=True)
    for n in ("a.txt", "b.txt", "c.txt"):
        (docs / n).write_text("old " + n)
    real, calls = R.MOVE, []

    def move(src, name, dst):
        calls.append(name)
        if len(calls) == 2:
            (docs / calls[0]).write_text("saved meanwhile")         # a program saves the first one again, in the old folder
            raise OSError(5, "Input/output error")
        return real(src, name, dst)
    monkeypatch.setattr(R, "MOVE", move)
    with pytest.raises(R.Incomplete) as e:
        R.rebuild(top, "Documents")
    first = calls[0]
    assert (docs / first).read_text() == "saved meanwhile"
    hidden = [n for n in os.listdir(top) if n != "Documents"]
    assert len(hidden) == 1 and e.value.folder == hidden[0] and e.value.count == 1
    assert (top / hidden[0] / first).read_text() == f"old {first}"                # nothing lost either
    assert first in e.value.reason

    r = R.result({"encrypted": True, "no_trim": "", "mount": "/"}, [{"path": "~/Documents", "rel": "Documents", "method": "rebuild",
                  "error": e.value.reason, "leftover": f"~/{hidden[0]}", "leftover_count": 1}], None, None, True)
    f = r["folders"][0]
    assert f["state"] == "failed" and "Nothing was deleted or replaced" in f["text"] and hidden[0] in f["text"]
    assert f["commands"] == [f"find ~/{hidden[0]} -mindepth 1 -maxdepth 1 -exec mv -n -t ~/Documents {{}} +",
                             f"rmdir ~/{hidden[0]}"]


def test_a_failure_after_the_swap_names_the_old_folder_and_what_is_left_in_it(tmp_path, monkeypatch):
    top = tmp_path / "home"
    docs = top / "Documents"
    docs.mkdir(parents=True)
    (docs / "a.txt").write_text("a")
    real_exchange = R.EXCHANGE

    def exchange(parent, a, b):
        ok = real_exchange(parent, a, b)
        (top / b / "late.txt").write_text("written to the old folder just before the swap")
        (docs / "late.txt").write_text("and a newer one in the new")
        return ok
    monkeypatch.setattr(R, "EXCHANGE", exchange)
    with pytest.raises(R.Incomplete) as e:
        R.rebuild(top, "Documents")
    assert e.value.count == 1 and (top / e.value.folder / "late.txt").exists()
    assert (docs / "late.txt").read_text() == "and a newer one in the new" and (docs / "a.txt").read_text() == "a"


def test_a_folder_reached_through_a_link_isnt_rebuilt(tmp_path):
    top = tmp_path / "home"
    (tmp_path / "elsewhere").mkdir()
    top.mkdir()
    os.symlink(tmp_path / "elsewhere", top / "Documents")
    with pytest.raises(R.Refused):
        R.rebuild(top, "Documents")


# ------------------------------------------------------------------ fillers

def test_fillers_have_the_deleted_names_lengths_and_are_deleted_afterwards(tmp_path):
    top = tmp_path / "home"
    top.mkdir()
    (top / "keep.txt").write_text("x")
    seen: list[list[str]] = []

    def recheck():
        mine = sorted(n for n in os.listdir(top) if n != "keep.txt")
        lengths = sorted(len(n) for n in mine if n != "_______" or len(seen) > 9)
        seen.append(mine)
        return [n for n in ("secret-plan.odt", "tax.pdf") if lengths.count(len(n)) < 2]   # gone after two rounds
    (top / "_______").write_text("the user's own")                          # a name fillers would take: skipped
    r = R.fillers(top, "", ["secret-plan.odt", "tax.pdf"], recheck)
    assert r == {"written": 4, "rounds": 2, "left": []}
    assert set(seen[0]) == {"_______", "______0", "_______________"}            # the user's, then the fillers'
    assert set(seen[1]) == {"_______", "______0", "______1", "_______________", "______________0"}
    assert sorted(os.listdir(top)) == ["_______", "keep.txt"]                 # the user's file is still there
    assert all(N.FILLER.match(n) for n in R.filler_names(3)) and list(R.filler_names(1)) == ["_"]
    assert len(list(R.filler_names(2))) == 11


def test_fillers_stop_at_the_cap(tmp_path, monkeypatch):
    top = tmp_path / "home"
    top.mkdir()
    monkeypatch.setattr(R, "FILLERS_MAX", 5)
    r = R.fillers(top, "", ["a.txt", "b.txt"], lambda: ["a.txt", "b.txt"])
    assert r["written"] == 5 and r["left"] == ["a.txt", "b.txt"] and os.listdir(top) == []


# ------------------------------------------------------------------ the plan and the whole clean-up

def fake_proc(root, comm, cwd):
    p = root / "proc/4242"
    (p / "fd").mkdir(parents=True)
    (p / "comm").write_text(comm + "\n")
    os.symlink(cwd, p / "cwd")
    (p / "maps").write_text("")


def test_the_plan_says_what_it_would_do_and_what_stops_it(root, monkeypatch):
    big(monkeypatch, "Documents", "app")
    make_storage(root)
    home = home_folders(root)
    (home / ".cache/app/x").write_text("x")
    fake_proc(root, "someapp", home / ".cache/app")
    p = R.plan(host_for(root), "/", ["Documents", ".cache/app", "", "link"])
    f = {x["rel"]: x for x in p["folders"]}
    assert f["Documents"]["method"] == "rebuild" and not f["Documents"]["blockers"] and f["Documents"]["entries"] == 1
    assert f[".cache/app"]["blockers"][0].startswith("Close someapp first")
    assert f[""]["method"] == "fillers" and not f[""]["blockers"]
    assert f["link"]["blockers"]                                               # a link, not a folder
    assert any(s.startswith("Rebuild ~/Documents") for s in p["steps"]) and any(s.startswith("Fillers in ~:") for s in p["steps"])
    assert any(s.startswith("Trim the free space of /") for s in p["steps"])
    assert p["ask_synced"] and any("lose track" in x for x in p["side_effects"])
    assert any("isn't in History" in x for x in p["side_effects"])


class Helper:
    """The helper's answers during a clean-up: fillers clear the names after one round."""

    def __init__(self):
        self.calls, self.round = [], 0

    def call(self, action, args, timeout=None):
        self.calls.append((action, args))
        if action == "names_folder":
            self.round += 1
            return {"left": ["old notes.txt"] if self.round == 1 else []}
        if action == "names_fstrim":
            return {"trimmed": 4096}
        if action == "names_check":
            return {"journal": "read", "journal_bytes": 1 << 20, "unreadable": 0, "folders": [
                {"path": p, "there": True, "folder": 0, "freed": 1 if p == "Documents" else 0, "journal": 0,
                 "left": ["secret-plan.odt"] if p == "Documents" else [], "listed": 1} for p in args["paths"]]}
        raise AssertionError(action)


def test_a_clean_up_rebuilds_fills_trims_and_checks(root, monkeypatch):
    big(monkeypatch, "Documents")
    make_storage(root)
    home = home_folders(root)
    h, job = Helper(), {}
    r = R.run(host_for(root), "/", ["Documents", ""], lambda: h, job)
    assert [a for a, _ in h.calls] == ["names_folder", "names_folder", "names_fstrim", "names_check"]
    assert [s["state"] for s in job["steps"]] == ["done"] * 4
    f = {x["path"]: x for x in r["folders"]}
    assert f["~/Documents"]["state"] == "partly" and "aren't trimmed yet" in f["~/Documents"]["text"]
    assert f["~"]["state"] == "done" and "fillers written in 1 round" in f["~"]["text"]
    assert any("TRIM test shows" in x for x in r["explanation"]) and r["trimmed"] == 4096
    assert (home / "Documents/keep.txt").read_text() == "x" and sorted(os.listdir(home)) == [".cache", "Documents", "link"]


def test_the_server_lists_plans_and_cleans(cat, root, monkeypatch):
    big(monkeypatch, "Documents")
    dev = make_storage(root)
    home = home_folders(root)
    monkeypatch.setattr(helper, "FIEMAP", lambda fd: [(256 * BLOCK, BLOCK)] if os.fstat(fd).st_ino ==
                        os.stat(home / "Documents").st_ino else [])
    monkeypatch.setattr(helper, "TRIM_RUN", lambda argv: (0, "/: 0 B (0 bytes) trimmed\n", ""))
    put(dev, 256, ext4_block([(0, dirent(0, b"gone.txt", 4096))]))
    fake = FakePrivileged()
    fake.alive, fake.close = (lambda: True), (lambda: None)
    host = host_for(root)

    def follow(c, path):
        for _ in range(500):
            job = c.get(path, headers=H).json()["job"]
            if job["state"] not in ("asking", "running"):
                return job
        raise AssertionError("still running")
    with TestClient(create_app("t", cat, make_host=lambda: host, start_helper=lambda: fake)) as c:
        assert [t["mount"] for t in c.get("/api/tools/names", headers=H).json()["targets"]] == ["/"]
        assert c.post("/api/tools/names/start", headers=H, json={}).status_code == 400
        c.post("/api/tools/names/start", headers=H, json={"mount": "/"})
        job = follow(c, "/api/tools/names/job")
        assert job["state"] == "done" and [(f["path"], f["names"], f["remedy"]["method"]) for f in job["result"]["folders"]] \
            == [("~/Documents", ["gone.txt"], "rebuild")]
        assert c.get("/api/tools/names/job", headers=H).json()["job"] is None          # handed over once
        plan = c.post("/api/tools/names/plan", headers=H, json={"mount": "/", "folders": ["Documents"]}).json()["plan"]
        assert plan["folders"][0]["method"] == "rebuild" and plan["ask_synced"]
        assert c.post("/api/tools/names/clean", headers=H, json={"mount": "/", "folders": ["Documents"]}).status_code == 400
        put(dev, 256, bytes(BLOCK))                                                    # what the rebuild and trim leave
        c.post("/api/tools/names/clean", headers=H, json={"mount": "/", "folders": ["Documents"], "not_synced": True})
        job = follow(c, "/api/tools/names/clean")
        assert job["state"] == "done", job["error"]
        assert job["result"]["folders"][0]["state"] == "done" and (home / "Documents/keep.txt").exists()
        assert c.get("/api/tools/names/clean", headers=H).json()["job"] is None
        again = c.post("/api/tools/names/check", headers=H, json={"mount": "/", "folders": ["Documents"]}).json()
        assert again["result"]["folders"][0]["state"] == "done" and "None of its deleted names" in \
            again["result"]["folders"][0]["text"]
        # the journal: cleared by the kernel's call, and its other names only when asked for
        monkeypatch.setattr(helper, "CHECKPOINT", lambda s, flags: None)
        assert c.post("/api/tools/names/journal/clear", headers=H).json()["cleared"]
        assert c.post("/api/tools/names/journal/others", headers=H).json() == {"names": [], "hashes": [], "truncated": False,
                                                                               "records": 0}
        c.post("/api/tools/names/forget", headers=H)
        assert helper._NAMES == {}
        gone = c.post("/api/tools/names/journal/clear", headers=H)                     # no listing: nothing is cleared
        assert gone.status_code == 409 and "list the names again" in gone.json()["error"]


# ------------------------------------------------------------------ fillers by default, and who is watching

def test_a_small_folder_gets_fillers_and_a_rebuild_when_asked(root):
    make_storage(root)
    home_folders(root)
    host = host_for(root)
    t, r = N.target(host, "/"), {"scope": "home", "root": str(root / "home/alice")}
    assert N.remedy(host, t, r, "Documents") == {"method": "fillers", "why": N.FILLERS_WHY}
    assert N.remedy(host, t, r, "Documents", prefer="rebuild")["method"] == "rebuild"
    assert N.remedy(host, t, r, "", prefer="rebuild")["method"] == "fillers"        # the home itself can't be swapped
    p = R.plan(host, "/", ["Documents"], rebuild_rels=["Documents"])
    assert p["folders"][0]["method"] == "rebuild" and "as you asked" in p["folders"][0]["why"]


def watch(root, pid, comm, target, kind="inotify"):
    """A process of the user's with an inotify (or fanotify) mark on `target`, as /proc shows it."""
    st = os.stat(target)
    p = root / f"proc/{pid}"
    (p / "fd").mkdir(parents=True)
    (p / "fdinfo").mkdir()
    (p / "comm").write_text(comm + "\n")
    os.symlink("anon_inode:inotify" if kind == "inotify" else "anon_inode:[fanotify]", p / "fd/7")
    sdev = os.major(st.st_dev) << 20 | os.minor(st.st_dev)
    (p / "fdinfo/7").write_text(f"pos:\t0\nflags:\t00\n{kind} wd:1 ino:{st.st_ino:x} sdev:{sdev:x} mask:fce "
                                "ignored_mask:0 fhandle-bytes:8 fhandle-type:1 f_handle:00\n")
    return p


def test_a_program_watching_the_folder_stops_it_unless_it_only_shows_it(root):
    make_storage(root)
    home = home_folders(root)
    watch(root, 501, "nemo", home / "Documents")
    p = R.plan(host_for(root), "/", ["Documents"])
    [f] = p["folders"]
    assert not f["blockers"] and f["watching"] == ["nemo"] and any("nemo" in x for x in p["side_effects"])
    watch(root, 502, "mysyncd", home / "Documents", kind="fanotify")
    watch(root, 503, "systemd", home / ".cache/app")                  # another folder: not this one's watcher
    [f] = R.plan(host_for(root), "/", ["Documents"])["folders"]
    assert f["blockers"] == [f["blockers"][0]] and f["blockers"][0].startswith("Quit mysyncd first") \
        and "fillers being made and deleted" in f["blockers"][0]


def test_a_folder_mounted_in_another_view_isnt_rebuilt(root, monkeypatch):
    big(monkeypatch, "Documents")
    make_storage(root)
    home = home_folders(root)
    st = os.stat(home / "Documents")
    dev = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    (root / "proc/self/ns").mkdir(parents=True)
    os.symlink("mnt:[4026531841]", root / "proc/self/ns/mnt")
    (root / "proc/self/mountinfo").write_text(f"22 1 {dev} / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n")
    p = root / "proc/600"
    (p / "ns").mkdir(parents=True)
    (p / "fd").mkdir()
    (p / "comm").write_text("org.example.Ap\n")
    os.symlink("mnt:[4026532999]", p / "ns/mnt")
    (p / "mountinfo").write_text(f"40 30 {dev} /home/alice/Documents /home/alice/Documents rw - ext4 /dev/x rw\n")
    [f] = R.plan(host_for(root), "/", ["Documents"])["folders"]
    assert f["method"] == "rebuild" and "org.example.Ap" in f["blockers"][0] and "old, removed folder" in f["blockers"][0]
    (p / "mountinfo").write_text(f"40 30 {dev} /home/alice /home/alice rw - ext4 /dev/x rw\n")   # the whole home: fine
    assert not R.plan(host_for(root), "/", ["Documents"])["folders"][0]["blockers"]


def test_fillers_that_leave_names_offer_a_rebuild(root, monkeypatch):
    make_storage(root)
    home_folders(root)
    monkeypatch.setattr(R, "FILLER_ROUNDS", 2)

    class Stubborn(Helper):
        def call(self, action, args, timeout=None):
            if action == "names_folder":
                return {"left": ["old notes.txt"]}
            if action == "names_check":
                return {"journal": "read", "unreadable": 0, "folders": [
                    {"path": "Documents", "there": True, "folder": 1, "freed": 0, "journal": 0, "left": ["old notes.txt"],
                     "listed": 1}]}
            return super().call(action, args, timeout)
    r = R.run(host_for(root), "/", ["Documents"], lambda: Stubborn(), {})
    [f] = r["folders"]
    assert f["method"] == "fillers" and f["rebuild_offer"] and "Rebuild instead" in f["text"]


def test_ext4_says_what_this_kernel_does_with_a_deleted_name(tmp_path):
    """Since Linux 5.13 ext4 overwrites a name in its folder as the file is deleted (seen on Mint 22.3, kernel 7.0:
    nothing in the folders, everything in the journal): the list is of what older kernels left, and says so."""
    from conftest import make_host
    from daprivacyscanner.tools import names as N

    t = {"fstype": "ext4", "trim": "weekly", "encrypted": True}
    new = N.facts(t, None, wipes=True)
    assert "overwrites a file's name" in new[0] and "What stays is in the journal" in new[0]
    assert "This list reads both" in new[0] and "this disk is encrypted" in new[-1] and len(new) == 2
    old = N.facts(t, None, wipes=False)
    assert old[0].startswith("ext4 keeps a deleted file's name in its folder's own records")
    assert N.facts(t, None)[0] == old[0]                                     # a kernel that can't be told: as before
    # what the helper said of the journal: not read, no checksums to tie its copies by, fast commits
    j = {"state": "read", "checksums": True, "fast_commit": False}
    assert N.facts(t, None, True, j) == new
    assert "on another device" in N.facts(t, None, True, dict(j, state="external"))[1]
    assert "has no journal" in N.facts(t, None, True, dict(j, state="none"))[1]
    assert "keeps no checksums" in N.facts(t, None, True, dict(j, checksums=False))[1]
    assert "fast commits" in N.facts(t, None, True, dict(j, fast_commit=True))[1]
    for release, wipes in (("7.0.0-38-generic", True), ("5.13.0-1", True), ("5.12.19", False), ("5.4.0-200-generic", False),
                           ("4.19.0", False), ("", None)):
        host = make_host(tmp_path / (release or "none"), files={"/proc/sys/kernel/osrelease": release + "\n"})
        assert N.ext4_wipes_names(host) is wipes, release
