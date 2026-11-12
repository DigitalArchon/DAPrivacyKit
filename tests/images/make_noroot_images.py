#!/usr/bin/env python3
"""Makes the ext4 image in tests/images that needs no root: mke2fs -d fills it from a folder, then debugfs deletes
files from it as e2fsprogs's ext2fs_unlink does, which is what kernels before Linux 5.13 did too: the entry before a
deleted one grows over it (rec_len), or, the first in its block, gets its inode number zeroed, and the name stays in
the folder's block, its checksum updated. The journal is empty (debugfs doesn't use it). Standard library and
e2fsprogs only; run it anywhere, as any user:

    python3 -I make_noroot_images.py OUTDIR

The facts (inode numbers, generations, extents, the live entries) are read with debugfs, never by the app's code.
"""

from __future__ import annotations

import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

LONG = [f"scanned-letter-{i:03d}-from-the-tax-office-about-2025.pdf" for i in range(120)]   # 3 blocks, linear
DELETED = {"Documents": ["secret-plan.odt", "tax 2025.pdf"],
           "Letters": [LONG[0], LONG[40], LONG[41], LONG[77], LONG[119]]}


def debugfs(img: str, *requests: str, write: bool = False) -> str:
    """Runs the requests (debugfs takes one -R, so several go in a command file, -f)."""
    with tempfile.NamedTemporaryFile("w", suffix=".cmds", delete=False) as f:
        f.write("".join(r + "\n" for r in requests))
    try:
        p = subprocess.run(["debugfs"] + (["-w"] if write else []) + ["-f", f.name, img], capture_output=True, text=True)
    finally:
        os.unlink(f.name)
    if p.returncode or "rm: " in p.stderr:
        raise SystemExit(p.stderr)
    return p.stdout


def stat(img: str, path: str) -> dict:
    text = debugfs(img, f'stat "{path}"')
    ino = int(re.search(r"Inode: (\d+)", text).group(1))
    gen = int(re.search(r"Generation: (\d+)", text).group(1))
    flags = int(re.search(r"Flags: (0x[0-9a-f]+)", text).group(1), 16)
    mode = int(re.search(r"Mode:\s+(\d+)", text).group(1), 8)
    uid, gid = (int(x) for x in re.search(r"User:\s+(\d+)\s+Group:\s+(\d+)", text).groups())
    extents = []
    for a, b, c, _d in re.findall(r"\((\d+)(?:-(\d+))?\):(\d+)(?:-(\d+))?", text.split("EXTENTS:")[-1]):
        n = int(b or a) - int(a) + 1
        extents.append([int(c) * 4096, n * 4096, 0, int(a) * 4096])
    return {"type": "dir", "ino": ino, "gen": gen, "flags": flags, "mode": 0o40000 | mode, "uid": uid, "gid": gid,
            "extents": extents}


def entries(img: str, path: str) -> list[tuple[int, str]]:
    out = []
    for line in debugfs(img, f'ls -l "{path}"').splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+)\s+\(\d+\)\s+\d+\s+\d+\s+\d+\s+\S+\s+\S+\s+(.*)$", line)
        if m and m.group(3) not in (".", ".."):
            out.append((int(m.group(1)), m.group(3), m.group(2).startswith("4")))
    return out


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 -I make_noroot_images.py OUTDIR")
    out = os.path.abspath(sys.argv[1])
    os.makedirs(out, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix="dapk-noroot-")
    try:
        tree = f"{scratch}/tree"
        for d in ("Documents", "Letters"):
            os.makedirs(f"{tree}/{d}")
        for n in ("keep.txt", "secret-plan.odt", "tax 2025.pdf"):
            with open(f"{tree}/Documents/{n}", "w") as f:
                f.write("x")
        for n in LONG:
            open(f"{tree}/Letters/{n}", "w").close()
        img = f"{scratch}/ext4-debugfs.img"
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-O", "metadata_csum,^dir_index",
                        "-U", "5eed0000-0000-4000-8000-00000000d0d0", "-E", "root_owner=1000:1000", "-d", tree, img, "8M"],
                       check=True)
        # the first entry of Letters' second block too: deleting it zeroes its inode number instead
        second = stat(img, "/Letters")["extents"][0][0] + 4096
        with open(img, "rb") as f:
            f.seek(second)
            head = f.read(264)
        first = head[8:8 + head[6]].decode()
        assert first in LONG and first not in DELETED["Letters"]
        DELETED["Letters"].append(first)
        debugfs(img, *(f'rm "/{d}/{n}"' for d, names in DELETED.items() for n in names), write=True)
        facts = {"": stat(img, "/")}
        for d in ("Documents", "Letters"):
            facts[d] = stat(img, f"/{d}")
            for ino, name, is_dir in entries(img, f"/{d}"):
                facts[f"{d}/{name}"] = {"type": "dir" if is_dir else "file", "ino": ino, "gen": 0}
        manifest = {"made_by": "tests/images/make_noroot_images.py", "made": time.strftime("%Y-%m-%d"),
                    "tool": subprocess.run(["mke2fs", "-V"], capture_output=True, text=True).stderr.splitlines()[0],
                    "fstype": "ext4", "size": os.path.getsize(img), "block_size": 4096, "caller": [1000, 1000],
                    "deleted": DELETED, "gone": {}, "entries": facts}
        with open(img, "rb") as f, lzma.open(f"{out}/ext4-debugfs.img.xz", "wb", preset=9 | lzma.PRESET_EXTREME) as z:
            shutil.copyfileobj(f, z)
        with open(f"{out}/ext4-debugfs.json", "w") as f:
            json.dump(manifest, f, indent=1, sort_keys=True)
            f.write("\n")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
