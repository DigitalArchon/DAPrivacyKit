"""A system-call filter for every sandbox (docs/TECHNICAL.md, Tools: the sandbox), built by hand as a seccomp BPF
program and handed to bubblewrap with --seccomp FD. Standard library only.

Without one, a program in a sandbox could ask the kernel for anything a program can, and some of the kernel's least
used parts are where its flaws are found: a user namespace of its own gives a program root's capabilities over the
namespaces it makes with it, and with them nf_tables (packet filtering), the new mount API, and more, all reachable
with no flaw outside the kernel needed. So, as Flatpak's own filter does (flatpak-run.c, setup_seccomp), what no
sandboxed program needs is refused:

- the kernel keyring (add_key, keyctl, request_key), the kernel log (syslog), accounting and quotas, modules, kexec,
  swap, reboot, port I/O, 16-bit code (modify_ldt, vm86), uselib, open_by_handle_at, lookup_dcookie;
- the NUMA calls (move_pages, mbind, get_mempolicy, set_mempolicy, migrate_pages, set_mempolicy_home_node);
- tracing other programs (ptrace), the performance counters (perf_event_open), bpf and userfaultfd;
- io_uring, clone3 and the new mount API (open_tree, move_mount, fsopen, fsconfig, fsmount, fspick, mount_setattr,
  open_tree_attr), refused as missing (ENOSYS), so that programs fall back to the calls they replace: clone3's
  arguments are in memory, where a filter can't look, and clone then gets the same checks as ever (the new mount API
  not under the nesting profile, below);
- personality other than Linux's own (and asking which it is), typing into a terminal (TIOCSTI), the console's
  copy and paste (TIOCLINUX) and changing a terminal's line discipline (TIOCSETD);
- sockets of any family but Unix, IPv4, IPv6 and netlink (refused as unsupported, EAFNOSUPPORT, as Flatpak does), and
  of netlink only routing, socket diagnostics, SELinux's notifications and device events (not netfilter's, which is
  nf_tables, nor generic netlink's families).

And by profile (PROFILES), what makes namespaces and mounts:
- strict: no new namespaces of any kind (clone and unshare with a CLONE_NEW* flag), no mount, umount, pivot_root,
  chroot or setns. For Xephyr's sandbox, the viewer's, tor's, the unpacking sandboxes and trials, which also get
  bubblewrap's --disable-userns;
- browser: namespaces and chroot allowed, which Firefox's own sandbox (Tor and Mullvad Browser's, and Chromium's,
  in Electron apps) needs for its content processes; mount, pivot_root and setns still refused;
- nesting: namespaces, mounts and pivot_root allowed as well, the new mount API too (bubblewrap 0.13 makes its binds
  read-only with mount_setattr and doesn't fall back: "Can't bind mount /usr on /usr: mount_setattr() failed",
  tested on CachyOS), for a bubblewrap started inside the sandbox: Tor Browser's outer sandbox (the gate, which starts
  tor's and the browser's sandboxes), and programs that start sandboxes of their own with bubblewrap (WebKitGTK's web
  processes, glycin's image loaders, GNOME's thumbnailer).
Filters stack: what runs in a sandbox inside another is held to both.

A namespace of its own still reaches some of what a user namespace opens up (traffic control through routing
netlink, under the browser and nesting profiles): the filter can't look into the messages sent there.

The architectures: the program checks which system-call table a call came through (seccomp_data.arch). x86-64's, and
the i386 table, which a 64-bit program reaches with int 0x80 (an x86-64-only filter would let it past everything:
the calls have other numbers there), each with its own numbers; x32's numbers (x86-64's with bit 30 set) are refused
as missing; any other kills the process. On i386, socket and socketpair come through socketcall, whose arguments are
in memory: socketcall's socket and socketpair are refused (a 32-bit program then makes no connections, not even to
the display), the direct socket and socketpair calls are checked as on x86-64. Only on x86-64 computers: elsewhere
there is no filter (supported())."""

from __future__ import annotations

import os
import platform
import stat
import struct

# seccomp_data: int nr, __u32 arch, __u64 instruction_pointer, __u64 args[6]
NR, ARCH, ARGS = 0, 4, 16
AUDIT_ARCH_X86_64, AUDIT_ARCH_I386 = 0xC000003E, 0x40000003
X32_BIT = 0x40000000

RET_KILL_PROCESS, RET_ERRNO, RET_ALLOW = 0x80000000, 0x00050000, 0x7FFF0000
EPERM, ENOSYS, EPROTONOSUPPORT, EAFNOSUPPORT = 1, 38, 93, 97

# classic BPF
LD_ABS, JEQ, JGE, JSET, JA, RET = 0x20, 0x15, 0x35, 0x45, 0x05, 0x06

CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC = 0x00020000, 0x02000000, 0x04000000, 0x08000000
CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWTIME = 0x10000000, 0x20000000, 0x40000000, 0x00000080
NS_CLONE = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET
NS_UNSHARE = NS_CLONE | CLONE_NEWTIME                  # clone() can't take CLONE_NEWTIME: it is a bit of its signal
TIOCSTI, TIOCLINUX, TIOCSETD = 0x5412, 0x541C, 0x5423
AF_UNIX, AF_INET, AF_INET6, AF_NETLINK = 1, 2, 10, 16
# netlink: routing, socket diagnostics, SELinux's notifications (libselinux's AVC, on Fedora), device events (udev's)
NETLINK_OK = (0, 4, 7, 15)
PER_LINUX, PER_LINUX32, PER_QUERY = 0, 0x0008, 0xFFFFFFFF
SYS_SOCKET, SYS_SOCKETPAIR = 1, 8                     # socketcall's numbers for them

# the numbers of the calls named here, by table (linux/arch/x86/entry/syscalls: syscall_64.tbl, syscall_32.tbl)
X86_64 = {
    "ioctl": 16, "socket": 41, "socketpair": 53, "clone": 56, "ptrace": 101, "syslog": 103, "uselib": 134,
    "personality": 135, "modify_ldt": 154, "pivot_root": 155, "chroot": 161, "acct": 163, "mount": 165,
    "umount2": 166, "swapon": 167, "swapoff": 168, "reboot": 169, "iopl": 172, "ioperm": 173, "init_module": 175,
    "delete_module": 176, "quotactl": 179, "lookup_dcookie": 212, "mbind": 237, "set_mempolicy": 238,
    "get_mempolicy": 239, "kexec_load": 246, "add_key": 248, "request_key": 249, "keyctl": 250, "migrate_pages": 256,
    "unshare": 272, "move_pages": 279, "perf_event_open": 298, "open_by_handle_at": 304, "setns": 308,
    "finit_module": 313, "kexec_file_load": 320, "bpf": 321, "userfaultfd": 323, "io_uring_setup": 425,
    "io_uring_enter": 426, "io_uring_register": 427, "open_tree": 428, "move_mount": 429, "fsopen": 430,
    "fsconfig": 431, "fsmount": 432, "fspick": 433, "clone3": 435, "mount_setattr": 442, "quotactl_fd": 443,
    "set_mempolicy_home_node": 450, "open_tree_attr": 467,
}
I386 = {
    "umount": 22, "mount": 21, "ptrace": 26, "acct": 51, "umount2": 52, "ioctl": 54, "chroot": 61, "uselib": 86,
    "swapon": 87, "reboot": 88, "ioperm": 101, "socketcall": 102, "syslog": 103, "iopl": 110, "vm86old": 113,
    "swapoff": 115, "clone": 120, "modify_ldt": 123, "init_module": 128, "delete_module": 129, "quotactl": 131,
    "personality": 136, "vm86": 166, "pivot_root": 217, "lookup_dcookie": 253, "mbind": 274, "get_mempolicy": 275,
    "set_mempolicy": 276, "kexec_load": 283, "add_key": 286, "request_key": 287, "keyctl": 288, "migrate_pages": 294,
    "unshare": 310, "move_pages": 317, "perf_event_open": 336, "open_by_handle_at": 342, "setns": 346,
    "finit_module": 350, "bpf": 357, "socket": 359, "socketpair": 360, "userfaultfd": 374, "io_uring_setup": 425,
    "io_uring_enter": 426, "io_uring_register": 427, "open_tree": 428, "move_mount": 429, "fsopen": 430,
    "fsconfig": 431, "fsmount": 432, "fspick": 433, "clone3": 435, "mount_setattr": 442, "quotactl_fd": 443,
    "set_mempolicy_home_node": 450, "open_tree_attr": 467,
}

DENIED = ("syslog", "uselib", "acct", "modify_ldt", "vm86", "vm86old", "quotactl", "quotactl_fd", "add_key", "keyctl",
          "request_key", "move_pages", "mbind", "get_mempolicy", "set_mempolicy", "migrate_pages",
          "set_mempolicy_home_node", "perf_event_open", "ptrace", "bpf", "userfaultfd", "kexec_load", "kexec_file_load",
          "init_module", "finit_module", "delete_module", "reboot", "swapon", "swapoff", "iopl", "ioperm",
          "lookup_dcookie", "open_by_handle_at")
MOUNT_API = ("open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr", "open_tree_attr")
MISSING = ("clone3", "io_uring_setup", "io_uring_enter", "io_uring_register", *MOUNT_API)
MOUNTING = ("mount", "umount", "umount2", "pivot_root", "setns")

STRICT, BROWSER, NESTING = "strict", "browser", "nesting"
PROFILES = (STRICT, BROWSER, NESTING)


def supported() -> bool:
    """Whether the filter can be built for this computer: x86-64 only (its two tables)."""
    return platform.machine() in ("x86_64", "amd64")


class _Asm:
    """Classic BPF with labels: a conditional jump goes at most 255 instructions on (jt, jf), JA anywhere ahead."""

    def __init__(self) -> None:
        self.code: list[tuple[int, object, object, object]] = []
        self.labels: dict[str, int] = {}

    def at(self, name: str) -> None:
        self.labels[name] = len(self.code)

    def op(self, code: int, k: object = 0, jt: object = 0, jf: object = 0) -> None:
        self.code.append((code, jt, jf, k))

    def _off(self, i: int, target: object, limit: int) -> int:
        if isinstance(target, int):
            return target
        off = self.labels[str(target)] - i - 1
        if not 0 <= off <= limit:
            raise ValueError(f"a jump the filter can't make ({off})")
        return off

    def assemble(self) -> bytes:
        out = []
        for i, (code, jt, jf, k) in enumerate(self.code):
            if code == JA:
                k, jt, jf = self._off(i, k, 0xFFFFFFFF), 0, 0
            else:
                jt, jf = self._off(i, jt, 255), self._off(i, jf, 255)
            out.append(struct.pack("<HBBI", code, jt, jf, int(k)))
        if len(out) > 4096:
            raise ValueError("the filter is too long")
        return b"".join(out)


def _arg(i: int) -> int:
    """The offset of argument i's low 32 bits (x86 is little-endian). Every argument checked here is an int, an
    unsigned int or flags the kernel takes from the low half."""
    return ARGS + 8 * i


def _errno(e: int):
    def emit(a: _Asm, p: str) -> None:
        a.op(RET, RET_ERRNO | e)
    return emit


def _masked(arg: int, mask: int, e: int):
    """Refused with `e` when any bit of `mask` is set in the argument."""
    def emit(a: _Asm, p: str) -> None:
        a.op(LD_ABS, _arg(arg))
        a.op(JSET, mask, 0, 1)
        a.op(RET, RET_ERRNO | e)
        a.op(RET, RET_ALLOW)
    return emit


def _refused_values(arg: int, values: tuple[int, ...], e: int):
    def emit(a: _Asm, p: str) -> None:
        a.op(LD_ABS, _arg(arg))
        for v in values:
            a.op(JEQ, v, f"{p}no", 0)
        a.op(RET, RET_ALLOW)
        a.at(f"{p}no")
        a.op(RET, RET_ERRNO | e)
    return emit


def _allowed_values(arg: int, values: tuple[int, ...], e: int):
    def emit(a: _Asm, p: str) -> None:
        a.op(LD_ABS, _arg(arg))
        for v in values:
            a.op(JEQ, v, f"{p}ok", 0)
        a.op(RET, RET_ERRNO | e)
        a.at(f"{p}ok")
        a.op(RET, RET_ALLOW)
    return emit


def _socket(families: tuple[int, ...]):
    """socket(domain, type, protocol): only `families`, and netlink only for NETLINK_OK's protocols."""
    def emit(a: _Asm, p: str) -> None:
        a.op(LD_ABS, _arg(0))
        for f in families:
            a.op(JEQ, f, f"{p}ok", 0)
        a.op(JEQ, AF_NETLINK, f"{p}nl", 0)
        a.op(RET, RET_ERRNO | EAFNOSUPPORT)
        a.at(f"{p}nl")
        a.op(LD_ABS, _arg(2))
        for proto in NETLINK_OK:
            a.op(JEQ, proto, f"{p}ok", 0)
        a.op(RET, RET_ERRNO | EPROTONOSUPPORT)
        a.at(f"{p}ok")
        a.op(RET, RET_ALLOW)
    return emit


def _rules(profile: str, table: dict[str, int]) -> list[tuple[int, object]]:
    """(number, emit) for every call the profile acts on, in this table; the rest are allowed."""
    if profile not in PROFILES:
        raise ValueError(f"no such profile: {profile}")
    rules: dict[str, object] = {}
    for name in DENIED:
        rules[name] = _errno(EPERM)
    for name in MISSING:
        if not (profile == NESTING and name in MOUNT_API):
            rules[name] = _errno(ENOSYS)
    if profile == STRICT:
        rules["clone"] = _masked(0, NS_CLONE, EPERM)
        rules["unshare"] = _masked(0, NS_UNSHARE, EPERM)
        rules["chroot"] = _errno(EPERM)
    if profile in (STRICT, BROWSER):
        for name in MOUNTING:
            rules[name] = _errno(EPERM)
    rules["ioctl"] = _refused_values(1, (TIOCSTI, TIOCLINUX, TIOCSETD), EPERM)
    rules["personality"] = _allowed_values(0, (PER_LINUX, PER_LINUX32, PER_QUERY), EPERM)
    rules["socket"] = _socket((AF_UNIX, AF_INET, AF_INET6))
    rules["socketpair"] = _allowed_values(0, (AF_UNIX,), EAFNOSUPPORT)
    rules["socketcall"] = _refused_values(0, (SYS_SOCKET, SYS_SOCKETPAIR), EAFNOSUPPORT)
    return sorted((table[n], emit) for n, emit in rules.items() if n in table)


def _dispatch(a: _Asm, rules: list[tuple[int, object]], p: str) -> None:
    """The call's number (in A) looked up among `rules`, halving: at most a few comparisons for a call the filter
    lets through, which most are."""
    if len(rules) <= 4:
        for j, (nr, emit) in enumerate(rules):
            a.op(JEQ, nr, 0, f"{p}e{j}")
            emit(a, f"{p}b{j}")                           # every rule ends in a return
            a.at(f"{p}e{j}")
        a.op(RET, RET_ALLOW)
        return
    mid = len(rules) // 2
    a.op(JGE, rules[mid][0], 0, 1)
    a.op(JA, f"{p}R")
    _dispatch(a, rules[:mid], p + "L")
    a.at(f"{p}R")
    _dispatch(a, rules[mid:], p + "R")


_BUILT: dict[str, bytes] = {}


def program(profile: str) -> bytes:
    """The filter for `profile`, as bubblewrap's --seccomp reads it: struct sock_filter[] (8 bytes each)."""
    if profile not in _BUILT:
        a = _Asm()
        a.op(LD_ABS, ARCH)
        a.op(JEQ, AUDIT_ARCH_X86_64, 0, 1)
        a.op(JA, "x86_64")
        a.op(JEQ, AUDIT_ARCH_I386, 0, 1)
        a.op(JA, "i386")
        a.op(RET, RET_KILL_PROCESS)                      # no other table can be reached from an x86-64 program
        a.at("x86_64")
        a.op(LD_ABS, NR)
        a.op(JGE, X32_BIT, 0, 1)                          # x32's numbers: as on kernels built without it
        a.op(RET, RET_ERRNO | ENOSYS)
        _dispatch(a, _rules(profile, X86_64), "a")
        a.at("i386")
        a.op(LD_ABS, NR)
        _dispatch(a, _rules(profile, I386), "b")
        _BUILT[profile] = a.assemble()
    return _BUILT[profile]


def memfd(profile: str) -> int:
    """A memory file holding the filter, at its start: the descriptor bubblewrap's --seccomp reads (it is passed
    to bubblewrap's process; the caller closes its own copy)."""
    fd = os.memfd_create(f"seccomp-{profile}")
    try:
        os.write(fd, program(profile))
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        os.close(fd)
        raise
    return fd


def write(path: str | os.PathLike, profile: str) -> None:
    """The filter written to a file of the app's (made new, owner only, never through a link): for a sandbox started
    by pasta, which passes its command nothing but stdin, stdout and stderr, so the descriptor is opened on the far side
    (sandbox.Filter.wrap)."""
    tmp = f"{os.fspath(path)}.{os.urandom(4).hex()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, program(profile))
    finally:
        os.close(fd)
    os.replace(tmp, path)


# ------------------------------------------------------------------ programs that start sandboxes of their own

# What says a program starts sandboxes of its own, which the strict profile (and --disable-userns) stop: Electron and
# Chromium (their sandbox needs a user namespace, or they refuse to start: "No usable sandbox!"), CEF, Qt WebEngine,
# WebKitGTK (its web processes run in bubblewrap), glycin (GNOME's image loaders, in bubblewrap). By file name in a
# program's folder (an unpacked archive, an AppImage's listing) and by name inside the program (the libraries it
# links, glycin's loaders' folder).
NESTING_NAMES = {"chrome-sandbox": "an Electron or Chromium app", "app.asar": "an Electron app",
                 "libcef.so": "built on Chromium (CEF)", "QtWebEngineProcess": "built on Qt WebEngine (Chromium)",
                 "WebKitWebProcess": "built on WebKitGTK"}
NESTING_MARKS = ((b"libwebkit2gtk-4.", "built on WebKitGTK"), (b"libwebkitgtk-6.", "built on WebKitGTK"),
                 (b"libQt6WebEngineCore", "built on Qt WebEngine (Chromium)"),
                 (b"libQt5WebEngineCore", "built on Qt WebEngine (Chromium)"), (b"libcef.so", "built on Chromium (CEF)"),
                 (b"libglycin", "it loads pictures with glycin"), (b"glycin-loaders", "it loads pictures with glycin"),
                 (b"chrome-sandbox", "an Electron or Chromium app"), (b"electron.asar", "an Electron app"))
SCAN_MAX = 256 << 20                    # the most of one program read for those names
TREE_MAX = 50000                        # the most names looked at in a program's folder
LISTING_MAX = 16 << 20                  # the most of an AppImage's folder listing read, packed and unpacked


def _scan(path: str, marks=NESTING_MARKS, most: int = SCAN_MAX) -> str | None:
    """The first of `marks` found in the file (read in pieces, never through a link), or None."""
    longest = max(len(m) for m, _ in marks)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        tail, read = b"", 0
        while read < most:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            read += len(chunk)
            data = tail + chunk
            for m, why in marks:
                if m in data:
                    return why
            tail = data[-longest:]
    except OSError:
        return None
    finally:
        os.close(fd)
    return None


def _in_listing(names) -> str | None:
    for i, name in enumerate(names):
        if i > TREE_MAX:
            break
        if name in NESTING_NAMES:
            return NESTING_NAMES[name]
        if name.endswith(".asar"):
            return "an Electron app"
        if name.startswith(("libQt6WebEngineCore.so", "libQt5WebEngineCore.so")):
            return "built on Qt WebEngine (Chromium)"
    return None


def _tree_names(top: str):
    count = 0
    for _dir, dirs, files in os.walk(top):              # links aren't followed
        for n in dirs + files:
            count += 1
            if count > TREE_MAX:
                return
            yield n


def _squashfs_names(path: str) -> bytes | None:
    """An AppImage's (type 2) folder listing: squashfs's directory table, appended to the runtime, unpacked where
    Python can (gzip, xz, lzma; zstd from Python 3.14); None where it can't be read so. Nothing in it is run."""
    import lzma
    import zlib
    try:
        with open(path, "rb", buffering=0) as f:
            head = f.read(64)
            if head[:4] != b"\x7fELF" or head[4] != 2:
                return None
            shoff, = struct.unpack_from("<Q", head, 0x28)
            shentsize, shnum = struct.unpack_from("<HH", head, 0x3A)
            offset = shoff + shentsize * shnum
            f.seek(offset)
            sb = f.read(96)
            if sb[:4] != b"hsqs":
                return None
            compressor, = struct.unpack_from("<H", sb, 20)
            dir_start, frag_start, export_start = struct.unpack_from("<QQQ", sb, 72)
            ends = [x for x in (frag_start, export_start) if dir_start < x < 1 << 62]
            end = min(ends) if ends else dir_start + LISTING_MAX
            if not 0 < end - dir_start <= LISTING_MAX:
                return None
            f.seek(offset + dir_start)
            table = f.read(end - dir_start)
    except (OSError, struct.error, IndexError, ValueError):
        return None
    if compressor == 1:
        unpack = zlib.decompress
    elif compressor in (2, 4):
        fmt = lzma.FORMAT_XZ if compressor == 4 else lzma.FORMAT_ALONE
        unpack = lambda b: lzma.decompress(b, format=fmt)  # noqa: E731
    elif compressor == 6:
        try:
            from compression import zstd                # Python 3.14
        except ImportError:
            return None
        unpack = zstd.decompress
    else:
        return None
    out, i, size_out = [], 0, 0
    try:
        while i + 2 <= len(table) and size_out < LISTING_MAX:
            h, = struct.unpack_from("<H", table, i)
            size, raw = h & 0x7FFF, h & 0x8000
            block = table[i + 2:i + 2 + size]
            got = block if raw else unpack(block)
            out.append(got)
            size_out += len(got)
            i += 2 + size
    except Exception:  # noqa: BLE001 - a listing that can't be read says nothing
        return None
    return b"".join(out)


def nesting_reason(path: str | os.PathLike, folder: str | os.PathLike | None = None) -> str | None:
    """Why the program at `path` (and in `folder`: an unpacked archive's or package's tree) looks like one that starts
    sandboxes of its own, in words ("an Electron app"), or None. A guess from names, never proof either way: the
    trial's tick is the user's."""
    path = os.fspath(path)
    if folder is not None:
        why = _in_listing(_tree_names(os.fspath(folder)))
        if why:
            return why
    listing = _squashfs_names(path)
    if listing is not None:
        for name, why in (*((n.encode(), w) for n, w in NESTING_NAMES.items()), (b".asar", "an Electron app")):
            if name in listing:
                return why
    return _scan(path)


def installed_reason(program: str) -> str | None:
    """nesting_reason for an installed program: the program itself, its folder and the one above it (an Electron
    app's /usr/share/code/code beside chrome-sandbox and resources/app.asar), and for a script the programs it names
    under /usr and /opt (/usr/bin/code is a script that runs /usr/share/code/code)."""
    import re
    real = os.path.realpath(program)
    candidates = [real]
    try:
        with open(real, "rb") as f:
            head = f.read(65536)
    except OSError:
        head = b""
    if head.startswith(b"#!"):
        candidates += [m.decode(errors="replace") for m in re.findall(rb"/(?:usr|opt)/[\w./+-]+", head)[:10]]
    for c in candidates:
        c = os.path.realpath(c)
        here = os.path.dirname(c)
        for d in (here, os.path.dirname(here)) if here not in ("/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin") else ():
            try:
                names = os.listdir(d)
                why = _in_listing(names)
                if not why and "resources" in names:
                    why = _in_listing(os.listdir(os.path.join(d, "resources")))
            except OSError:
                continue
            if why:
                return why
        why = _scan(c)
        if why:
            return why
    return None
