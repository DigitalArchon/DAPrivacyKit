"""The sandboxes' system-call filter (tools/seccomp.py): what each profile refuses, checked two ways. An emulator of
classic BPF runs the program on made-up calls (every rule, both tables, x32, another architecture); and a child
process loads it into the real kernel (no_new_privs and PR_SET_SECCOMP through ctypes) and tries the calls the
review named: keyctl, a user namespace, AF_PACKET, TIOCSTI, and the i386 table through int 0x80, while ordinary calls
(files, threads, Unix and IP sockets, fork) go on working."""

import errno
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from daprivacyscanner.tools import seccomp as S

X86 = platform.machine() in ("x86_64", "amd64")


# ------------------------------------------------------------------ an emulator of the program


def run(prog: bytes, nr: int, args=(0, 0, 0, 0, 0, 0), arch=S.AUDIT_ARCH_X86_64) -> int:
    data = struct.pack("<IIQ6Q", nr & 0xFFFFFFFF, arch, 0, *[a & 0xFFFFFFFFFFFFFFFF for a in (*args, 0, 0, 0, 0, 0, 0)[:6]])
    ins = [struct.unpack_from("<HBBI", prog, i) for i in range(0, len(prog), 8)]
    pc, acc, steps = 0, 0, 0
    while True:
        code, jt, jf, k = ins[pc]
        steps += 1
        assert steps < 1000
        if code == S.LD_ABS:
            acc = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code == S.RET:
            return k
        elif code == S.JA:
            pc += 1 + k
        elif code == S.JEQ:
            pc += 1 + (jt if acc == k else jf)
        elif code == S.JGE:
            pc += 1 + (jt if acc >= k else jf)
        elif code == S.JSET:
            pc += 1 + (jt if acc & k else jf)
        else:
            raise AssertionError(f"unknown instruction {code:#x}")


ALLOW, KILL = S.RET_ALLOW, S.RET_KILL_PROCESS


def err(e):
    return S.RET_ERRNO | e


@pytest.mark.parametrize("profile", S.PROFILES)
def test_every_profile_refuses_the_dangerous_calls_in_both_tables(profile):
    prog = S.program(profile)
    for table in (S.X86_64, S.I386):
        arch = S.AUDIT_ARCH_X86_64 if table is S.X86_64 else S.AUDIT_ARCH_I386
        for name in S.DENIED:
            if name in table:
                assert run(prog, table[name], arch=arch) == err(errno.EPERM), (profile, name, arch)
        for name in S.MISSING:
            assert run(prog, table[name], arch=arch) == err(errno.ENOSYS), (profile, name, arch)


@pytest.mark.parametrize("profile", S.PROFILES)
def test_ordinary_calls_pass(profile):
    prog = S.program(profile)
    # read, write, openat, mmap, futex, exit_group, execve, getpid, prctl, seccomp, landlock_create_ruleset
    for nr in (0, 1, 257, 9, 202, 231, 59, 39, 157, 317, 444):
        assert run(prog, nr) == ALLOW, nr
    # i386: read, write, getpid, exit_group
    for nr in (3, 4, 20, 252):
        assert run(prog, nr, arch=S.AUDIT_ARCH_I386) == ALLOW, nr
    # a thread (CLONE_VM...) and fork are never refused
    assert run(prog, S.X86_64["clone"], (0x003D0F00,)) == ALLOW
    assert run(prog, S.X86_64["clone"], (0x01200011,)) == ALLOW
    assert run(prog, S.X86_64["unshare"], (0x00000200,)) == ALLOW           # CLONE_FS
    assert run(prog, S.X86_64["personality"], (0,)) == ALLOW
    assert run(prog, S.X86_64["personality"], (0xFFFFFFFF,)) == ALLOW
    assert run(prog, S.X86_64["ioctl"], (1, 0x5401)) == ALLOW               # TCGETS
    for fam in (socket.AF_UNIX, socket.AF_INET, socket.AF_INET6):
        assert run(prog, S.X86_64["socket"], (fam, 1, 0)) == ALLOW
    assert run(prog, S.X86_64["socket"], (socket.AF_NETLINK, 3, 0)) == ALLOW     # routing
    assert run(prog, S.X86_64["socket"], (socket.AF_NETLINK, 3, 15)) == ALLOW    # device events
    assert run(prog, S.X86_64["socketpair"], (socket.AF_UNIX, 1, 0)) == ALLOW


@pytest.mark.parametrize("profile", S.PROFILES)
def test_terminal_tricks_personality_and_socket_families_are_refused(profile):
    prog = S.program(profile)
    for table, arch in ((S.X86_64, S.AUDIT_ARCH_X86_64), (S.I386, S.AUDIT_ARCH_I386)):
        for cmd in (S.TIOCSTI, S.TIOCLINUX, S.TIOCSETD):
            assert run(prog, table["ioctl"], (0, cmd), arch=arch) == err(errno.EPERM)
            # the kernel takes the command from the low half: high bits set make no difference
            assert run(prog, table["ioctl"], (0, (1 << 40) | cmd), arch=arch) == err(errno.EPERM)
        assert run(prog, table["personality"], (0x0400000,), arch=arch) == err(errno.EPERM)   # READ_IMPLIES_EXEC
        for fam in (17, 38, 40, 29, 30, 31, 44):          # packet, alg, vsock, can, tipc, bluetooth, xdp
            assert run(prog, table["socket"], (fam, 3, 0), arch=arch) == err(errno.EAFNOSUPPORT), fam
        assert run(prog, table["socket"], (socket.AF_NETLINK, 3, 12), arch=arch) == err(errno.EPROTONOSUPPORT)
        assert run(prog, table["socket"], (socket.AF_NETLINK, 3, 16), arch=arch) == err(errno.EPROTONOSUPPORT)
        assert run(prog, table["socketpair"], (30, 1, 0), arch=arch) == err(errno.EAFNOSUPPORT)
    # i386's socketcall: socket and socketpair, whose arguments the filter can't see, are refused; the rest go on
    sc = S.I386["socketcall"]
    assert run(prog, sc, (S.SYS_SOCKET,), arch=S.AUDIT_ARCH_I386) == err(errno.EAFNOSUPPORT)
    assert run(prog, sc, (S.SYS_SOCKETPAIR,), arch=S.AUDIT_ARCH_I386) == err(errno.EAFNOSUPPORT)
    assert run(prog, sc, (3,), arch=S.AUDIT_ARCH_I386) == ALLOW              # connect, on a socket it has


def test_namespaces_and_mounts_by_profile():
    strict, browser, nesting = (S.program(p) for p in S.PROFILES)
    t = S.X86_64
    for flag in (S.CLONE_NEWUSER, S.CLONE_NEWNET, S.CLONE_NEWNS, S.CLONE_NEWPID, S.CLONE_NEWUSER | S.CLONE_NEWPID):
        assert run(strict, t["clone"], (flag | 17,)) == err(errno.EPERM)
        assert run(strict, t["unshare"], (flag,)) == err(errno.EPERM)
        assert run(browser, t["clone"], (flag | 17,)) == ALLOW
        assert run(browser, t["unshare"], (flag,)) == ALLOW
        assert run(nesting, t["unshare"], (flag,)) == ALLOW
    assert run(strict, t["unshare"], (S.CLONE_NEWTIME,)) == err(errno.EPERM)
    for name in ("mount", "umount2", "pivot_root", "setns"):
        assert run(strict, t[name]) == err(errno.EPERM)
        assert run(browser, t[name]) == err(errno.EPERM)
        assert run(nesting, t[name]) == ALLOW
    assert run(strict, t["chroot"]) == err(errno.EPERM)
    assert run(browser, t["chroot"]) == ALLOW
    assert run(nesting, t["chroot"]) == ALLOW
    # and through the i386 table, the same
    i = S.I386
    assert run(strict, i["clone"], (S.CLONE_NEWUSER,), arch=S.AUDIT_ARCH_I386) == err(errno.EPERM)
    assert run(strict, i["umount"], arch=S.AUDIT_ARCH_I386) == err(errno.EPERM)
    assert run(browser, i["mount"], arch=S.AUDIT_ARCH_I386) == err(errno.EPERM)
    assert run(nesting, i["mount"], arch=S.AUDIT_ARCH_I386) == ALLOW


@pytest.mark.parametrize("profile", S.PROFILES)
def test_x32_and_other_tables(profile):
    prog = S.program(profile)
    assert run(prog, S.X32_BIT | 39) == err(errno.ENOSYS)                  # x32's getpid
    assert run(prog, S.X32_BIT | S.X86_64["keyctl"]) == err(errno.ENOSYS)
    assert run(prog, -1) == err(errno.ENOSYS)
    assert run(prog, 39, arch=0xC00000B7) == KILL                          # aarch64's: can't be reached here


def test_programs_are_well_formed_and_stable():
    for p in S.PROFILES:
        prog = S.program(p)
        assert len(prog) % 8 == 0 and len(prog) // 8 < 4096
        assert prog == S.program(p)
    with pytest.raises(ValueError):
        S.program("lenient")


def test_tables_match_the_kernel_headers():
    """The numbers written down here are the kernel's (where the headers are installed: they are on Debian and
    Ubuntu, libc6-dev / linux-libc-dev)."""
    for table, header in ((S.X86_64, "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"),
                          (S.I386, "/usr/include/x86_64-linux-gnu/asm/unistd_32.h")):
        try:
            text = Path(header).read_text()
        except OSError:
            pytest.skip("no kernel headers here")
        import re
        found = dict(re.findall(r"#define __NR_(\w+)\s+(\d+)", text))
        for name, nr in table.items():
            if name in found:
                assert int(found[name]) == nr, (header, name)


def test_memfd_and_file_hold_the_program(tmp_path):
    fd = S.memfd(S.STRICT)
    try:
        assert os.read(fd, 1 << 20) == S.program(S.STRICT)
    finally:
        os.close(fd)
    path = tmp_path / "filter"
    S.write(path, S.BROWSER)
    assert path.read_bytes() == S.program(S.BROWSER)
    assert path.stat().st_mode & 0o777 == 0o600


# ------------------------------------------------------------------ in the real kernel

CHILD = r"""
import ctypes, errno, json, mmap, os, socket, struct, sys, threading
prog = bytes.fromhex(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
class Prog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
buf = ctypes.create_string_buffer(prog, len(prog))
fp = Prog(len(prog) // 8, ctypes.cast(buf, ctypes.c_void_p))
out = {}
# int 0x80 from this 64-bit process: getpid (20), then keyctl (288) KEYCTL_GET_KEYRING_ID of the session keyring
code = bytes.fromhex("53" "8b c7" "89 f3" "89 d1" "31 d2" "cd 80" "5b" "c3".replace(" ", ""))
m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
m.write(code)
addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
int80 = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int)(addr)
out["int80_before"] = int80(20, 0, 0)
if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(fp), 0, 0):
    print(json.dumps({"load": ctypes.get_errno()})); sys.exit(0)
def call(nr, *a):
    r = libc.syscall(nr, *a)
    return 0 if r >= 0 else ctypes.get_errno()
out["keyctl"] = call(250, 0, -3, 0)
out["unshare_user"] = call(272, 0x10000000)
out["unshare_fs"] = call(272, 0x200)
out["add_key"] = call(248, b"user", b"x", b"y", 1, -3)
out["io_uring"] = call(425, 1, None)
out["clone3"] = call(435, None, 0)
out["x32_getpid"] = call(0x40000000 | 39)
for name, fam, typ, proto in (("packet", 17, 3, 0), ("alg", 38, 5, 0), ("vsock", 40, 1, 0),
                              ("unix", 1, 1, 0), ("inet", 2, 2, 0), ("inet6", 10, 2, 0), ("route", 16, 3, 0),
                              ("netfilter", 16, 3, 12)):
    try:
        socket.socket(fam, typ, proto).close(); out[name] = 0
    except OSError as e:
        out[name] = e.errno
c = ctypes.c_char(b"x")
try:
    tty = os.open("/dev/ptmx", os.O_RDWR | os.O_NOCTTY)
except OSError:
    tty = None
if tty is not None:
    out["tiocsti"] = 0 if libc.ioctl(tty, 0x5412, ctypes.byref(c)) == 0 else ctypes.get_errno()
    out["tcgets"] = 0 if libc.ioctl(tty, 0x5401, ctypes.create_string_buffer(64)) == 0 else ctypes.get_errno()
out["int80_getpid"] = int80(20, 0, 0)
out["int80_keyctl"] = int80(288, 0, -3)
out["int80_unshare"] = int80(310, 0x10000000, 0)
t = threading.Thread(target=lambda: out.__setitem__("thread", 1)); t.start(); t.join()
pid = os.fork()
if pid == 0:
    os._exit(7)
out["fork"] = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
with open(sys.argv[0] if os.path.exists(sys.argv[0]) else "/proc/self/status") as f:
    out["read"] = bool(f.read(10))
out["pid"] = os.getpid()
print(json.dumps(out))
"""


def _in_kernel(profile: str) -> dict:
    r = subprocess.run([sys.executable, "-I", "-c", CHILD, S.program(profile).hex()], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


needs_kernel = pytest.mark.skipif(not X86 or not os.path.exists("/proc/self/status"), reason="an x86-64 Linux kernel")


@needs_kernel
@pytest.mark.parametrize("profile", S.PROFILES)
def test_in_the_real_kernel(profile):
    out = _in_kernel(profile)
    assert "load" not in out, f"the filter couldn't be loaded ({out.get('load')})"
    assert out["keyctl"] == errno.EPERM and out["add_key"] == errno.EPERM
    assert out["io_uring"] == errno.ENOSYS and out["clone3"] == errno.ENOSYS and out["x32_getpid"] == errno.ENOSYS
    assert out["packet"] == errno.EAFNOSUPPORT and out["alg"] == errno.EAFNOSUPPORT and out["vsock"] == errno.EAFNOSUPPORT
    assert out["netfilter"] == errno.EPROTONOSUPPORT
    assert out["unix"] == 0 and out["inet"] == 0 and out["inet6"] in (0, errno.EAFNOSUPPORT) and out["route"] == 0
    if "tiocsti" in out:
        assert out["tiocsti"] == errno.EPERM and out["tcgets"] in (0, errno.ENOTTY, errno.EIO)
    assert out["thread"] == 1 and out["fork"] == 7 and out["read"] is True
    assert out["unshare_fs"] == 0
    if profile == S.STRICT:
        assert out["unshare_user"] == errno.EPERM
    if out["int80_before"] > 0:                       # the kernel has the i386 table (IA32 emulation)
        assert out["int80_getpid"] == out["pid"]
        assert out["int80_keyctl"] == -errno.EPERM
        if profile == S.STRICT:
            assert out["int80_unshare"] == -errno.EPERM


@needs_kernel
@pytest.mark.skipif(not shutil.which("bwrap"), reason="bubblewrap")
def test_bubblewrap_loads_it_from_a_descriptor():
    """bwrap --seccomp FD, as every sandbox starts: inside, keyctl and a user namespace are refused and the rest runs."""
    probe = subprocess.run(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"], capture_output=True)
    if probe.returncode:
        pytest.skip("bubblewrap can't make a sandbox here")
    fd = S.memfd(S.STRICT)
    try:
        r = subprocess.run(["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev",
                            "--proc", "/proc", "--seccomp", str(fd), "--", sys.executable, "-I", "-c",
                            "import ctypes, os; l = ctypes.CDLL(None, use_errno=True); "
                            "print(l.syscall(250, 0, -3, 0), ctypes.get_errno(), "
                            "l.syscall(272, 0x10000000), ctypes.get_errno(), os.getpid())"],
                           pass_fds=(fd,), capture_output=True, text=True, timeout=60)
    finally:
        os.close(fd)
    assert r.returncode == 0, r.stderr
    k, ke, u, ue, pid = r.stdout.split()
    assert (k, ke, u, ue) == ("-1", str(errno.EPERM), "-1", str(errno.EPERM))
