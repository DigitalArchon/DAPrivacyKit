#!/usr/bin/env python3
"""Makes the real filesystem images in tests/images, with the facts the tests check them against.

Run it as root on a throwaway Linux machine (a test VM), never on your own: it attaches loop devices, mounts
filesystems and runs fstrim on them, all inside a scratch folder it removes afterwards. Standard library only.

    sudo python3 -I make_images.py OUTDIR

The real kernel makes every change, so the images hold what a real disk would: ext4 (metadata_csum, a journal) with
files created and deleted, an indexed folder, a folder deleted with rm -r, another account's folders, and files of
TRIM test records (one deleted, then the free space trimmed: loop devices pass discards on by punching holes in the
image); ext4 without metadata_csum; btrfs (a subvolume, files deleted, one image per checksum type), with two files
whose contents are shaped as tree leaves naming a folder they aren't in. Each image is written xz-compressed with a
JSON file of facts: every folder's and file's inode number, generation, owner and mode, the folders' extents (FIEMAP),
btrfs tree ids, and the names this script deleted. The facts are read here, with the image mounted, by ioctls of
this script's own, never by the app's code: the tests compare the app's parsers with them.

The images made without root (mke2fs -d, debugfs) are made by make_noroot_images.py.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

UID, GID = 1000, 1000                 # the account the tests take as the caller
OTHER = 4242                          # another account
FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, FS_IOC_GETVERSION = 0x80086601, 0x40086602, 0x80087601
FS_IOC_FIEMAP = 0xC020660B
BTRFS_IOC_INO_LOOKUP = 0xD0009412
FS_NOCOW_FL, FS_NOCOMP_FL = 0x00800000, 0x00000400
TRIM_MAGIC = bytes.fromhex("c5a1e2793d0b48f6a9175ee03c6d2b84")    # helper.TRIM_MAGIC: the TRIM test's records
TRIM_RECORD = 512
RUN = bytes.fromhex("0123456789abcdeffedcba9876543210")
TAG = "5eed5eed5eed5eed"                                          # 16 hex digits, then 4 per file


def sh(*argv: str, check: bool = True) -> str:
    p = subprocess.run(argv, capture_output=True, text=True)
    if check and p.returncode:
        raise SystemExit(f"{' '.join(argv)} failed: {p.stderr.strip()}")
    return p.stdout


def sync() -> None:
    os.sync()
    time.sleep(0.5)
    os.sync()


# ------------------------------------------------------------------ facts, read with ioctls of our own

def ioctl_int(fd: int, request: int) -> int | None:
    buf = bytearray(8)
    try:
        fcntl.ioctl(fd, request, buf, True)
    except OSError:
        return None
    return int.from_bytes(buf[:4], sys.byteorder)


def fiemap(fd: int) -> list[list[int]]:
    """[physical byte offset, length, flags] of each extent (on btrfs the offset is the logical address)."""
    count = 64
    buf = bytearray(32 + 56 * count)
    struct.pack_into("<QQIIII", buf, 0, 0, 0xFFFFFFFFFFFFFFFF, 1, 0, count, 0)    # FIEMAP_FLAG_SYNC
    try:
        fcntl.ioctl(fd, FS_IOC_FIEMAP, buf, True)
    except OSError:
        return []
    out = []
    for i in range(struct.unpack_from("<I", buf, 20)[0]):
        logical, phys, length = struct.unpack_from("<QQQ", buf, 32 + 56 * i)
        flags = struct.unpack_from("<I", buf, 32 + 56 * i + 40)[0]
        out.append([phys, length, flags, logical])
    return out


def tree_id(fd: int) -> int | None:
    args = bytearray(4096)
    args[8:16] = (256).to_bytes(8, "little")
    try:
        fcntl.ioctl(fd, BTRFS_IOC_INO_LOOKUP, args, True)
    except OSError:
        return None
    return int.from_bytes(args[0:8], "little")


def facts(top: str, btrfs: bool) -> dict:
    """Every entry under `top`, as root sees it, without following links or leaving the filesystem."""
    out = {}
    dev = os.lstat(top).st_dev if not btrfs else None

    def visit(path: str, rel: str) -> None:
        st = os.lstat(path)
        kind = "dir" if os.path.isdir(path) and not os.path.islink(path) else "file"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if kind == "dir" else 0))
        try:
            rec = {"type": kind, "ino": st.st_ino, "gen": ioctl_int(fd, FS_IOC_GETVERSION), "uid": st.st_uid,
                   "gid": st.st_gid, "mode": st.st_mode, "flags": ioctl_int(fd, FS_IOC_GETFLAGS), "size": st.st_size}
            if kind == "dir" and not btrfs:
                rec["extents"] = fiemap(fd)
            if btrfs:
                rec["tree"] = tree_id(fd)
            if kind == "file" and rel.startswith(("trim-test/", "Downloads/")):
                rec["extents"] = fiemap(fd)
        finally:
            os.close(fd)
        out[rel] = rec
        if kind == "dir":
            for name in sorted(os.listdir(path)):
                child = os.path.join(path, name)
                if dev is not None and os.lstat(child).st_dev != dev:
                    continue
                visit(child, f"{rel}/{name}" if rel else name)
    visit(top, "")
    return out


# ------------------------------------------------------------------ making files as the kernel would for a user

def mkdir(path: str, uid: int = UID, mode: int = 0o755) -> None:
    os.mkdir(path)
    os.chown(path, uid, uid)
    os.chmod(path, mode)


def write(path: str, data: bytes, uid: int = UID) -> None:
    with open(path, "wb") as f:
        f.write(data)
    os.chown(path, uid, uid)


def trim_record(index: int, file: int) -> bytes:
    head = TRIM_MAGIC + RUN + index.to_bytes(4, "little") + file.to_bytes(2, "little") + b"\0\0" + os.urandom(TRIM_RECORD - 72)
    return head + hashlib.sha256(head).digest()


def no_compress(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        flags = ioctl_int(fd, FS_IOC_GETFLAGS) or 0
        fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack("i", flags | FS_NOCOMP_FL))
    except OSError:
        pass
    finally:
        os.close(fd)


class Loop:
    """An image attached to a loop device and mounted (discards reach the image as punched holes)."""

    def __init__(self, image: str, mount: str, options: str = ""):
        self.image, self.mount, self.options = image, mount, options

    def __enter__(self):
        self.dev = sh("losetup", "--find", "--show", self.image).strip()
        os.makedirs(self.mount, exist_ok=True)
        sh("mount", *(("-o", self.options) if self.options else ()), self.dev, self.mount)
        return self

    def __exit__(self, *exc):
        sync()
        sh("umount", self.mount)
        sh("losetup", "-d", self.dev)


def save(image: str, out: str, name: str, manifest: dict) -> None:
    with open(image, "rb") as f, lzma.open(os.path.join(out, name + ".img.xz"), "wb", preset=9 | lzma.PRESET_EXTREME) as z:
        shutil.copyfileobj(f, z, 1 << 20)
    with open(os.path.join(out, name + ".json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"  {name}: {os.path.getsize(os.path.join(out, name + '.img.xz'))} bytes compressed")


def base_manifest(kind: str, image: str, **more) -> dict:
    p = subprocess.run(["mkfs.btrfs", "--version"] if kind == "btrfs" else ["mke2fs", "-V"], capture_output=True, text=True)
    return {"made_by": "tests/images/make_images.py", "made": time.strftime("%Y-%m-%d"), "kernel": os.uname().release,
            "tool": (p.stdout + p.stderr).splitlines()[0], "fstype": kind, "size": os.path.getsize(image),
            "caller": [UID, GID], **more}


# ------------------------------------------------------------------ ext4

BIG = [f"holiday-photo-{i:04d}-taken-on-the-beach.jpg" for i in range(300)]
BIG_DELETED = BIG[10:50]


def ext4_scenario(m: str) -> tuple[dict, dict, dict]:
    """Returns (deleted names by folder, folders deleted whole: path -> their names, trim files)."""
    for d in ("Documents", "Big", "Project X", "Downloads", "trim-test"):
        mkdir(f"{m}/{d}")
    mkdir(f"{m}/Project X/drafts")
    mkdir(f"{m}/Shared", OTHER, 0o755)                 # another account's folder anyone may open
    mkdir(f"{m}/Private", OTHER, 0o700)                # another account's private folder
    for name in ("keep.txt", "secret-plan.odt", "tax 2025.pdf", "naïve café ünïcode.txt"):
        write(f"{m}/Documents/{name}", b"x" * 100)
    for name in BIG:
        write(f"{m}/Big/{name}", b"")
    write(f"{m}/Project X/offer.pdf", b"%PDF-1.7\n")
    write(f"{m}/Project X/drafts/draft 1.odt", b"PK")
    write(f"{m}/Shared/shared-notes.txt", b"n", OTHER)
    write(f"{m}/Shared/still-shared.txt", b"n", OTHER)
    write(f"{m}/Private/bobs-letter.odt", b"b", OTHER)
    write(f"{m}/Private/bobs-keep.txt", b"b", OTHER)
    trim = {}
    for n, count in ((0, 8), (1, 8)):                  # file 0 is kept, file 1 deleted
        name = f"{TAG}{n:04x}"
        path = f"{m}/trim-test/{name}"
        write(path, b"")
        no_compress(path)
        with open(path, "ab") as f:
            f.write(b"".join(trim_record(n * 100 + i, n) for i in range(count)))
        trim[name] = {"file": n, "records": list(range(n * 100, n * 100 + count)), "deleted": n == 1}
    sync()
    deleted = {"Documents": ["secret-plan.odt", "tax 2025.pdf", "naïve café ünïcode.txt"], "Big": BIG_DELETED,
               "Shared": ["shared-notes.txt"], "Private": ["bobs-letter.odt"], "trim-test": [f"{TAG}0001"]}
    for folder, names in deleted.items():
        for name in names:
            os.unlink(f"{m}/{folder}/{name}")
    shutil.rmtree(f"{m}/Project X")
    sync()
    write(f"{m}/Documents/made-after-rm-r.txt", b"new")   # may take the deleted folder's inode number
    sync()
    gone = {"Project X": ["drafts", "offer.pdf"], "Project X/drafts": ["draft 1.odt"]}
    deleted[""] = ["Project X"]
    return deleted, gone, trim


def make_ext4(scratch: str, out: str, name: str, features: str) -> None:
    img, m = f"{scratch}/{name}.img", f"{scratch}/mnt"
    with open(img, "wb") as f:
        f.truncate(16 << 20)
    sh("mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-O", features, "-U", "5eed0000-0000-4000-8000-00000000e4e4",
       "-E", "hash_seed=5eed0000-0000-4000-8000-0000000000aa,lazy_itable_init=0,lazy_journal_init=0", "-L", "dapk", img)
    with Loop(img, m):
        os.chown(m, UID, GID)                          # the caller's own disk
        deleted, gone, trim = ext4_scenario(m)
        before = facts(m, btrfs=False)
    manifest = base_manifest("ext4", img, features=features, block_size=4096, deleted=deleted, gone=gone, trim=trim,
                             run=RUN.hex(), tag=TAG, entries=before, dumpe2fs=sh("dumpe2fs", "-h", img).splitlines())
    save(img, out, name, manifest)
    if "^metadata_csum" in features:
        return
    # the same filesystem after fstrim: the deleted file's records gone from the image, the journal as it was
    with Loop(img, m):
        trimmed = sh("fstrim", "-v", m).strip()
    manifest.update(fstrim=trimmed, trimmed=True)
    save(img, out, name + "-trimmed", manifest)


# ------------------------------------------------------------------ btrfs

def crc32c(data: bytes) -> int:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    crc = 0xFFFFFFFF
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def btrfs_super(img: str) -> dict:
    with open(img, "rb") as f:
        f.seek(65536)
        sb = f.read(4096)
    return {"fsid": sb[0x20:0x30], "generation": int.from_bytes(sb[0x48:0x50], "little"),
            "nodesize": int.from_bytes(sb[0x94:0x98], "little"), "csum": int.from_bytes(sb[0xc4:0xc6], "little"),
            "sectorsize": int.from_bytes(sb[0x90:0x94], "little")}


def real_leaf_header(img: str, sb: dict) -> bytes:
    """The header of a real leaf of the FS tree (owner 5): its flags and chunk tree UUID, to copy."""
    with open(img, "rb") as f:
        data = f.read()
    i = data.find(sb["fsid"])
    while i != -1:
        at = i - 32
        if at >= 0 and at % 4096 == 0 and data[at + 100] == 0 and int.from_bytes(data[at + 88:at + 96], "little") == 5:
            return data[at:at + 101]
        i = data.find(sb["fsid"], i + 1)
    raise SystemExit("no leaf of the FS tree found")


def planted_leaf(sb: dict, header: bytes, bytenr: int, folder_ino: int, name: bytes) -> bytes:
    """A block laid out as a leaf of the FS tree, checksum and all, whose items say `folder_ino` holds `name`."""
    n = sb["nodesize"]
    block = bytearray(n)
    block[32:48] = sb["fsid"]
    struct.pack_into("<QQ", block, 48, bytenr, int.from_bytes(header[56:64], "little"))
    block[64:80] = header[64:80]
    struct.pack_into("<QQIB", block, 80, sb["generation"], 5, 2, 0)
    transid = sb["generation"] + 1
    item = struct.pack("<QBQ", 300, 1, 0) + struct.pack("<QHHB", transid, 0, len(name), 1) + name
    end = n - 101
    for i, (typ, off) in enumerate(((84, 0x1234), (96, 77))):      # a DIR_ITEM (by name hash) and a DIR_INDEX
        end -= len(item)
        struct.pack_into("<QBQII", block, 101 + 25 * i, folder_ino, typ, off, end, len(item))
        block[101 + end:101 + end + len(item)] = item
    if sb["csum"] == 0:
        struct.pack_into("<I", block, 0, crc32c(bytes(block[32:])))
    elif sb["csum"] == 2:
        block[0:32] = hashlib.sha256(bytes(block[32:])).digest()
    elif sb["csum"] == 3:
        block[0:32] = hashlib.blake2b(bytes(block[32:]), digest_size=32).digest()
    return bytes(block)        # xxhash64: no checksum of our own (the app can't check one either)


def plant(m: str, img: str, rel: str, folder_ino: int, name: bytes, true_bytenr: bool) -> dict:
    """A user's file whose content is such a leaf, written in place (no copy-on-write) once its address is known."""
    path = f"{m}/{rel}"
    sb = btrfs_super(img)
    write(path, b"")
    fd = os.open(path, os.O_RDWR)
    try:
        flags = ioctl_int(fd, FS_IOC_GETFLAGS) or 0
        fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack("i", flags | FS_NOCOW_FL))
        os.pwrite(fd, bytes(sb["nodesize"]), 0)
        os.fsync(fd)
        sync()
        ext = fiemap(fd)
        logical = ext[0][0]
        header = real_leaf_header(img, sb)
        leaf = planted_leaf(sb, header, logical if true_bytenr else 0, folder_ino, name)
        os.pwrite(fd, leaf, 0)
        os.fsync(fd)
    finally:
        os.close(fd)
    sync()
    return {"path": rel, "name": name.decode(), "folder_ino": folder_ino, "logical": logical, "bytenr_true": true_bytenr}


def make_btrfs(scratch: str, out: str, name: str, csum: str) -> None:
    img, m = f"{scratch}/{name}.img", f"{scratch}/mnt"
    with open(img, "wb") as f:
        f.truncate(128 << 20)
    sh("mkfs.btrfs", "-q", "-f", "--csum", csum, "-U", "5eed0000-0000-4000-8000-0000000b7f50", "-L", "dapk", img)
    with Loop(img, m):
        os.chown(m, UID, GID)
        for d in ("Documents", "Downloads"):
            mkdir(f"{m}/{d}")
        sh("btrfs", "subvolume", "create", f"{m}/home")
        os.chown(f"{m}/home", UID, GID)
        mkdir(f"{m}/home/Notes")
        mkdir(f"{m}/Private", OTHER, 0o700)
        for n in ("keep.txt", "secret-plan.odt", "tax 2025.pdf"):
            write(f"{m}/Documents/{n}", b"x" * 100)
        for n in ("keep-notes.md", "diary 2026.md", "passwords-old.txt"):
            write(f"{m}/home/Notes/{n}", b"y" * 100)
        write(f"{m}/Private/bobs-letter.odt", b"b", OTHER)
        sync()
        deleted = {"Documents": ["secret-plan.odt", "tax 2025.pdf"], "home/Notes": ["diary 2026.md", "passwords-old.txt"],
                   "Private": ["bobs-letter.odt"]}
        for folder, names in deleted.items():
            for n in names:
                os.unlink(f"{m}/{folder}/{n}")
        sync()
        docs = os.lstat(f"{m}/Documents").st_ino
        planted = [plant(m, img, "Downloads/innocent.bin", docs, b"planted-by-a-file.txt", True),
                   plant(m, img, "Downloads/innocent-2.bin", docs, b"planted-bytenr-zero.txt", False)]
        entries = facts(m, btrfs=True)
    with open(img, "rb") as f:
        data = f.read()
    sb = btrfs_super(img)
    for p in planted:                                  # where each planted leaf is on the device
        offsets, i = set(), data.find(p["name"].encode())
        while i != -1:
            for at in range(i - i % 4096, max(i - sb["nodesize"], -1), -4096):
                if data[at + 32:at + 48] == sb["fsid"] and int.from_bytes(data[at + 88:at + 96], "little") == 5:
                    offsets.add(at)
                    break
            i = data.find(p["name"].encode(), i + 1)
        p["device_offsets"] = sorted(offsets)
    manifest = base_manifest("btrfs", img, csum=csum, deleted=deleted, planted=planted, entries=entries,
                             dump_super=sh("btrfs", "inspect-internal", "dump-super", img).splitlines())
    save(img, out, name, manifest)


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit("usage: sudo python3 -I make_images.py OUTDIR (as root, on a throwaway machine)")
    out = os.path.abspath(sys.argv[1])
    os.makedirs(out, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix="dapk-images-")
    try:
        make_ext4(scratch, out, "ext4-csum", "metadata_csum,64bit,dir_index")
        make_ext4(scratch, out, "ext4-nocsum", "^metadata_csum,dir_index")
        for csum in ("crc32c", "sha256", "blake2", "xxhash"):
            make_btrfs(scratch, out, f"btrfs-{csum}", csum)
    finally:
        sh("umount", f"{scratch}/mnt", check=False)
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
