"""The Wayland security context (tools/wayland.py) against a fake compositor that speaks the wire protocol:
the registry, sync, and create_listener with its two file descriptors. Live-tested against Sway 1.12."""

from __future__ import annotations

import array
import os
import socket
import stat
import struct
import threading

import pytest

from daprivacyscanner.tools import wayland as W


def _string(payload: bytes, at: int) -> tuple[str, int]:
    n = struct.unpack_from("<I", payload, at)[0]
    return payload[at + 4:at + 3 + n].decode(), at + 4 + n + (-n % 4)


class FakeCompositor:
    """Answers get_registry with `globals_`, sync with done, and records the security-context requests
    (and checks the descriptors create_listener passes: a listening socket and a pipe's read end)."""

    def __init__(self, path, globals_=("wl_compositor", "zwlr_screencopy_manager_v1", W.MANAGER), refuse=False,
                 sandboxed=None):
        self.path, self.globals, self.refuse = str(path), list(globals_), refuse
        self.sandboxed = sandboxed            # the globals a client of a marked socket gets (it is served when given)
        self.requests, self.fds_ok = [], None
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(self.path)
        self.srv.listen(4)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.client, args=(c,), daemon=True).start()

    def send(self, c, obj, op, payload=b""):
        c.sendall(struct.pack("<II", obj, ((8 + len(payload)) << 16) | op) + payload)

    def client(self, c, globals_=None):
        globals_ = self.globals if globals_ is None else globals_
        buf, registry = b"", None
        while True:
            msg, anc, _, _ = c.recvmsg(4096, socket.CMSG_SPACE(8))
            for level, kind, data in anc:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    fds = array.array("i", data[:len(data) - len(data) % 4])
                    listening = stat.S_ISSOCK(os.fstat(fds[0]).st_mode) and \
                        socket.socket(fileno=os.dup(fds[0])).getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                    self.fds_ok = bool(listening) and stat.S_ISFIFO(os.fstat(fds[1]).st_mode)
                    if self.sandboxed is not None and listening:
                        lsock = socket.socket(fileno=os.dup(fds[0]))
                        threading.Thread(target=self.marked, args=(lsock,), daemon=True).start()
                    for fd in fds:
                        os.close(fd)
            if not msg:
                return
            buf += msg
            while len(buf) >= 8:
                obj, word = struct.unpack_from("<II", buf)
                size, op = word >> 16, word & 0xFFFF
                if len(buf) < size:
                    break
                payload, buf = buf[8:size], buf[size:]
                if obj == 1 and op == 1:                               # get_registry
                    registry = struct.unpack_from("<I", payload)[0]
                    for i, g in enumerate(globals_, 1):
                        b = g.encode() + b"\0"
                        self.send(c, registry, 0, struct.pack("<II", i, len(b)) + b + b"\0" * (-len(b) % 4) + struct.pack("<I", 1))
                elif obj == 1 and op == 0:                             # sync
                    cb = struct.unpack_from("<I", payload)[0]
                    if self.refuse and self.requests:
                        msg = b"nested\0\0"
                        self.send(c, 1, 0, struct.pack("<III", 4, 2, 7) + msg)
                    self.send(c, cb, 0, struct.pack("<I", 0))
                else:
                    name = ""
                    if obj == registry and op == 0:
                        name = _string(payload, 4)[0]
                    elif op in (1, 2, 3) and len(payload) > 4 and obj > 3:
                        name = _string(payload, 0)[0]
                    self.requests.append((obj, op, name))

    def marked(self, lsock):
        """Clients of the marked socket: the sandboxed globals."""
        while True:
            try:
                c, _ = lsock.accept()
            except OSError:
                return
            threading.Thread(target=self.client, args=(c, self.sandboxed), daemon=True).start()

    def close(self):
        self.srv.close()


@pytest.fixture
def short_dir():
    """A folder with a short path: a Unix socket's address is at most 107 bytes."""
    import tempfile
    d = tempfile.mkdtemp(prefix="dapwl-", dir="/tmp")
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def test_the_globals_are_read(short_dir):
    fake = FakeCompositor(f"{short_dir}/wayland-9")
    assert set(W.globals_of(fake.path)) == {"wl_compositor", "zwlr_screencopy_manager_v1", W.MANAGER}
    fake.close()


def test_a_sandbox_socket_is_set_up_and_kept_open_by_the_pipe(short_dir):
    fake = FakeCompositor(f"{short_dir}/wayland-9")
    path = W.Path(f"{short_dir}/sandbox-0")
    w = W.sandbox_socket(fake.path, path, "torbrowser")
    try:
        assert isinstance(w, int) and stat.S_ISSOCK(os.stat(path).st_mode) and stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert fake.fds_ok                                            # a listening socket and the pipe's read end
        names = [r[2] for r in fake.requests]
        assert W.MANAGER in names and W.ENGINE in names and "torbrowser" in names
        ops = [(r[1]) for r in fake.requests if r[0] == 4]             # the context: engine, app, instance, commit, destroy
        assert ops == [1, 2, 3, 4, 0]
        assert not os.get_inheritable(w)                               # passed on only by pass_fds
    finally:
        os.close(w)
        fake.close()


def test_a_compositor_without_the_protocol_gets_none(short_dir):
    fake = FakeCompositor(f"{short_dir}/wayland-9", globals_=("wl_compositor",))
    assert W.sandbox_socket(fake.path, W.Path(f"{short_dir}/sandbox-0"), "x") is None
    assert not os.path.exists(f"{short_dir}/sandbox-0")
    fake.close()


def test_a_refusal_raises_and_leaves_nothing(short_dir):
    fake = FakeCompositor(f"{short_dir}/wayland-9", refuse=True)
    with pytest.raises(W.WaylandError, match="refused it: nested"):
        W.sandbox_socket(fake.path, W.Path(f"{short_dir}/sandbox-0"), "x")
    assert not os.path.exists(f"{short_dir}/sandbox-0")
    fake.close()


def test_a_long_path_is_bound_through_its_folder(tmp_path):
    """A Unix socket's address is at most 107 bytes: a long home folder still gets its sandbox socket."""
    deep = tmp_path / ("x" * 60) / ("y" * 60)
    deep.mkdir(parents=True)
    s = W.socket.socket(W.socket.AF_UNIX)
    W._bind(s, deep / "wayland-0")
    s.listen(1)
    c = W.socket.socket(W.socket.AF_UNIX)
    W._connect(c, str(deep / "wayland-0"))
    assert stat.S_ISSOCK(os.stat(deep / "wayland-0").st_mode)
    c.close()
    s.close()


def test_what_a_sandboxed_client_gets_is_asked_of_the_compositor(short_dir):
    """Through a throwaway marked socket, removed at once: KDE Plasma 6.7 still offers data control there (reading the
    clipboard in the background, tested), which the panel names."""
    fake = FakeCompositor(f"{short_dir}/wayland-9", globals_=("wl_compositor", "ext_data_control_manager_v1", W.MANAGER),
                          sandboxed=("wl_compositor", "ext_data_control_manager_v1"))
    try:
        got = W.sandboxed_globals(fake.path, W.Path(short_dir))
        assert got == {"wl_compositor", "ext_data_control_manager_v1"}
        assert not [p for p in os.listdir(short_dir) if p.startswith("probe-")]
        assert W.RISKY["ext_data_control_manager_v1"].startswith("read and change the clipboard")
    finally:
        fake.close()
    plain = FakeCompositor(f"{short_dir}/wayland-8", globals_=("wl_compositor",))
    assert W.sandboxed_globals(plain.path, W.Path(short_dir)) is None
    plain.close()
