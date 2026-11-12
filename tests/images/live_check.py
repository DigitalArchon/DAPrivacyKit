#!/usr/bin/env python3
"""The root helper itself, as root, on the real images mounted: what tests/test_real_images.py can't do in-process
(there the walk of the mounted folders is taken from the facts, and the helper runs with ROOT, CALLER and IS_BLOCK
replaced). Here helper.py runs as its own process, as pkexec starts it (PKEXEC_UID, its JSON lines on stdin), on
each image attached read-only to a loop device and mounted read-only, so its walk (FIEMAP, FS_IOC_GETVERSION,
BTRFS_IOC_INO_LOOKUP), the kernel's answer about inodes (open_by_handle_at) and its reads of the device are the real
ones. Its listing is compared with the facts the image was made with.

Run it as root on a throwaway machine (it attaches loop devices and mounts; nothing is written to the images), with
an account of uid 1000 (the images' caller):

    sudo python3 -I live_check.py path/to/src/daprivacyscanner/helper.py path/to/tests/images

Prints one JSON line per image and exits 1 when a listing differs from the facts. Standard library only.
"""

from __future__ import annotations

import json
import lzma
import os
import shutil
import subprocess
import sys
import tempfile

IMAGES = ["ext4-csum", "ext4-csum-trimmed", "ext4-nocsum", "ext4-debugfs", "btrfs-crc32c", "btrfs-sha256",
          "btrfs-blake2", "btrfs-xxhash"]


def sh(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def may_open(e: dict, uid: int, groups: set[int]) -> bool:
    mode = e["mode"]
    bits = (mode >> 6) if e["uid"] == uid else (mode >> 3) if e["gid"] in groups else mode
    return bits & 0o5 == 0o5


def expected(m: dict, uid: int, groups: set[int]) -> tuple[dict, set[str]]:
    walked = set()
    for rel, e in m["entries"].items():
        if e["type"] != "dir":
            continue
        parts = rel.split("/") if rel else []
        way = [""] + ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
        if all(may_open(m["entries"][p], uid, groups) for p in way):
            walked.add(rel)
    want = {rel: sorted(n) for rel, n in m["deleted"].items() if rel in walked}
    want.update({rel: sorted(n) for rel, n in m.get("gone", {}).items()})
    return want, walked


class Helper:
    def __init__(self, path: str, uid: int):
        self.p = subprocess.Popen([sys.executable, "-I", path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                  env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PKEXEC_UID": str(uid)})
        self.n = 0

    def __call__(self, action: str, **args):
        self.n += 1
        self.p.stdin.write(json.dumps({"id": self.n, "action": action, "args": args}) + "\n")
        self.p.stdin.flush()
        reply = json.loads(self.p.stdout.readline())
        if not reply["ok"]:
            raise RuntimeError(f"{action}: {reply['error']}")
        return reply["result"]

    def close(self):
        self.p.stdin.close()
        self.p.wait(10)


def check(helper_py: str, images: str, name: str, scratch: str) -> dict:
    m = json.load(open(os.path.join(images, name + ".json")))
    uid, gid = m["caller"]
    import pwd
    groups = set(os.getgrouplist(pwd.getpwuid(uid).pw_name, gid))
    img = os.path.join(scratch, name + ".img")
    with lzma.open(os.path.join(images, name + ".img.xz")) as z, open(img, "wb") as f:
        shutil.copyfileobj(z, f, 1 << 20)
    mnt = f"/mnt/dapk-live-{name}"
    dev = sh("losetup", "--find", "--show", "--read-only", img).strip()
    out: dict = {"image": name}
    try:
        os.makedirs(mnt, exist_ok=False)
        sh("mount", "-o", "ro", dev, mnt)
        h = Helper(helper_py, uid)
        try:
            begin = h("names_begin", mount=mnt)
            while h("names_step")["more"]:
                pass
            r = h("names_result")
            got = {f["path"]: f["names"] for f in r["folders"]}
            want, walked = expected(m, uid, groups)
            planted = {p["name"] for p in m.get("planted", [])}
            made_up = {k: sorted(set(v) & planted) for k, v in got.items() if set(v) & planted}
            clean = {k: sorted(set(v) - planted) for k, v in got.items() if set(v) - planted}
            unchecked = "^metadata_csum" in m.get("features", "")
            if unchecked:            # without folder blocks' checksums nothing in the journal is any folder's
                want = {}
            out.update(folders=begin["folders"], walked=len(walked), scope=begin["scope"],
                       same=clean == want, got=clean, want=want, planted_listed=made_up, journal=r.get("journal"))
            if m["fstype"] == "ext4" and r.get("journal"):
                out["orphans"] = h("names_orphans")["names"]
                if unchecked:        # every deleted name is there, counted, named only when asked for
                    out["same"] &= {n for v in m["deleted"].values() for n in v} <= set(out["orphans"])
            h("names_end")
        finally:
            h.close()
    finally:
        subprocess.run(["umount", mnt], capture_output=True)
        subprocess.run(["losetup", "-d", dev], capture_output=True)
        if os.path.isdir(mnt):
            os.rmdir(mnt)
        os.unlink(img)
    return out


def main() -> None:
    if os.geteuid() != 0 or len(sys.argv) != 3:
        raise SystemExit("usage: sudo python3 -I live_check.py HELPER.PY IMAGES_DIR (as root, on a throwaway machine)")
    scratch = tempfile.mkdtemp(prefix="dapk-live-")
    bad = 0
    try:
        for name in IMAGES:
            r = check(sys.argv[1], sys.argv[2], name, scratch)
            bad += not r.get("same") or bool(r.get("planted_listed"))      # a file's made-up leaf listed: a failure
            print(json.dumps(r, sort_keys=True), flush=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
