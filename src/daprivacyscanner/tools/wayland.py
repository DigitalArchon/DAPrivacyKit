"""A Wayland socket of the browser's sandbox's own, marked as a sandbox's (docs/TECHNICAL.md, Tools: Tor or Mullvad
Browser in memory): the security-context protocol (wp_security_context_v1, wayland-protocols staging), which
Flatpak uses. The app asks the compositor to listen on a socket of its own; every client that connects there
is a sandboxed one, and compositors that implement the protocol keep what they choose from it: Sway 1.12, recording
the screen, reading the clipboard in the background and the rest of RISKY (tested); KDE Plasma 6.7 still offers data
control, layer shell, output management and input method v1 (reading the clipboard through it was tested), so the
panel asks the compositor (sandboxed_globals) and names what is left. GNOME keeps most of those from every program.

The socket stays open for as long as the sandbox runs: the compositor stops listening once every copy of the
pipe's write end (`close_fd`'s other end) is closed, and bubblewrap holds that one (--sync-fd) until the
sandbox ends. A compositor without the protocol (it isn't in the registry) gets the plain socket, as before,
and the page says what that means there.

Standard library only: the Wayland wire protocol by hand (little-endian words, strings padded to 4 bytes,
file descriptors as SCM_RIGHTS). Nothing is kept: the connection used to set it up is closed at once.

Tested against Sway 1.12 (headless, in a container): a client on the new socket no longer sees the screencopy
and data-control globals that one on the compositor's own socket sees."""

from __future__ import annotations

import array
import os
import socket
import struct
from pathlib import Path

MANAGER = "wp_security_context_manager_v1"
ENGINE = "org.daprivacyscanner"          # the sandbox engine named to the compositor: this app
DISPLAY_ID = 1


# What a sandboxed client shouldn't have, and what a browser taken over could do with it: the panel names those the
# compositor still offers a sandbox's connection (KDE Plasma 6.7 offers data control: reading the clipboard that way
# was tested; Sway 1.12 none of these).
RISKY = {
    "ext_data_control_manager_v1": "read and change the clipboard in the background",
    "zwlr_data_control_manager_v1": "read and change the clipboard in the background",
    "zwlr_screencopy_manager_v1": "record the screen",
    "ext_image_copy_capture_manager_v1": "record the screen",
    "zwlr_layer_shell_v1": "draw over other windows and the panel (a fake password prompt, say)",
    "zwp_virtual_keyboard_manager_v1": "type into other programs",
    "zwlr_virtual_pointer_manager_v1": "move the pointer and click in other programs",
    "zwlr_foreign_toplevel_manager_v1": "list the other windows' titles and act on them",
    "ext_foreign_toplevel_list_v1": "list the other windows' titles",
    "org_kde_plasma_window_management": "list the other windows' titles and act on them",
    "zwp_input_method_manager_v2": "act as the input method, which receives what is typed",
    "zwp_input_method_v1": "act as the input method, which receives what is typed",
    "kde_output_management_v2": "change the screens' arrangement",
    "zwlr_output_manager_v1": "change the screens' arrangement",
}


class WaylandError(Exception):
    pass


def _msg(obj: int, opcode: int, payload: bytes = b"") -> bytes:
    return struct.pack("<II", obj, ((8 + len(payload)) << 16) | opcode) + payload


def _uint(v: int) -> bytes:
    return struct.pack("<I", v)


def _string(s: str) -> bytes:
    b = s.encode() + b"\0"
    return _uint(len(b)) + b + b"\0" * (-len(b) % 4)


def _read_string(payload: bytes, at: int) -> tuple[str, int]:
    n = struct.unpack_from("<I", payload, at)[0]
    text = payload[at + 4:at + 4 + n].rstrip(b"\0").decode(errors="replace")
    return text, at + 4 + n + (-n % 4)


class _Connection:
    def __init__(self, path: str, timeout: float):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self.sock.settimeout(timeout)
        _connect(self.sock, path)
        self.buf = b""
        self.last_id = DISPLAY_ID

    def new_id(self) -> int:
        """The next object id: the server refuses one that leaves a gap."""
        self.last_id += 1
        return self.last_id

    def send(self, data: bytes, fds: tuple[int, ...] = ()) -> None:
        if fds:
            n = self.sock.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
            if n < len(data):                       # a short write: the rest without the descriptors again
                self.sock.sendall(data[n:])
        else:
            self.sock.sendall(data)

    def _event(self) -> tuple[int, int, bytes]:
        while True:
            if len(self.buf) >= 8:
                obj, word = struct.unpack_from("<II", self.buf)
                size = word >> 16
                if size < 8:
                    raise WaylandError("the compositor sent a malformed message")
                if len(self.buf) >= size:
                    payload, self.buf = self.buf[8:size], self.buf[size:]
                    return obj, word & 0xFFFF, payload
            chunk = self.sock.recv(65536)
            if not chunk:
                raise WaylandError("the compositor closed the connection")
            self.buf += chunk

    def roundtrip(self) -> list[tuple[int, int, bytes]]:
        """Every event up to a wl_display.sync's answer; raises on a protocol error."""
        cb = self.new_id()
        self.send(_msg(DISPLAY_ID, 0, _uint(cb)))
        events = []
        while True:
            obj, op, payload = self._event()
            if obj == DISPLAY_ID and op == 0:                     # wl_display.error
                _, code = struct.unpack_from("<II", payload)
                raise WaylandError(f"the compositor refused it: {_read_string(payload, 8)[0]} ({code})")
            if obj == cb and op == 0:                             # wl_callback.done
                return events
            events.append((obj, op, payload))

    def close(self) -> None:
        self.sock.close()


def globals_of(path: str, timeout: float = 5.0) -> dict[str, tuple[int, int]]:
    """The compositor's globals at the socket `path`: interface -> (name, version)."""
    c = _Connection(path, timeout)
    try:
        registry = c.new_id()
        c.send(_msg(DISPLAY_ID, 1, _uint(registry)))              # wl_display.get_registry
        out = {}
        for obj, op, payload in c.roundtrip():
            if obj == registry and op == 0:                       # wl_registry.global
                name = struct.unpack_from("<I", payload)[0]
                iface, at = _read_string(payload, 4)
                out[iface] = (name, struct.unpack_from("<I", payload, at)[0])
        return out
    finally:
        c.close()


def _bind(sock: socket.socket, path: Path) -> None:
    """Binds `sock` at `path`; through the folder's descriptor when the path is too long for a socket's
    address (107 bytes: a long home folder)."""
    if len(os.fsencode(str(path))) < 100:
        sock.bind(str(path))
        return
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        sock.bind(f"/proc/self/fd/{dfd}/{path.name}")
    finally:
        os.close(dfd)


def _connect(sock: socket.socket, path: str) -> None:
    """As _bind, for connecting."""
    if len(os.fsencode(path)) < 100:
        sock.connect(path)
        return
    dfd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        sock.connect(f"/proc/self/fd/{dfd}/{os.path.basename(path)}")
    finally:
        os.close(dfd)


def sandbox_socket(compositor: str, path: Path, app_id: str, timeout: float = 5.0) -> int | None:
    """A socket at `path` (a folder of the app's that no sandbox writes to) that the compositor at
    `compositor` listens on for sandboxed clients. Returns the write end of the pipe that keeps it open
    (to hand to bubblewrap's --sync-fd), or None when the compositor doesn't have the protocol. Raises
    WaylandError (or OSError) when it has it and setting it up failed: the caller decides what then."""
    found = globals_of(compositor, timeout)
    if MANAGER not in found:
        return None
    path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    c = None
    try:
        _bind(listener, path)
        os.chmod(path, 0o600)
        listener.listen(16)
        c = _Connection(compositor, timeout)
        name, _ = found[MANAGER]
        registry, manager, context = c.new_id(), c.new_id(), c.new_id()
        c.send(_msg(DISPLAY_ID, 1, _uint(registry)))
        c.send(_msg(registry, 0, _uint(name) + _string(MANAGER) + _uint(1) + _uint(manager)))      # bind
        c.send(_msg(manager, 1, _uint(context)), fds=(listener.fileno(), read_end))             # create_listener
        c.send(_msg(context, 1, _string(ENGINE)))                                               # set_sandbox_engine
        c.send(_msg(context, 2, _string(app_id)))                                               # set_app_id
        c.send(_msg(context, 3, _string(os.urandom(8).hex())))                                  # set_instance_id
        c.send(_msg(context, 4))                                                                # commit
        c.roundtrip()
        c.send(_msg(context, 0) + _msg(manager, 0))             # destroy both: the listener stays
        c.roundtrip()
    except BaseException:
        os.close(write_end)
        path.unlink(missing_ok=True)
        raise
    finally:
        if c is not None:
            c.close()
        listener.close()
        os.close(read_end)
    return write_end


def sandboxed_globals(compositor: str, folder: Path, timeout: float = 5.0) -> set[str] | None:
    """The globals a client gets on a socket the compositor marks as a sandbox's: a throwaway one in `folder` (a
    folder of the app's), closed at once. None when the compositor doesn't have the protocol."""
    path = folder / f"probe-{os.urandom(4).hex()}"
    sync = sandbox_socket(compositor, path, "org.daprivacyscanner.probe", timeout)
    if sync is None:
        return None
    try:
        return set(globals_of(str(path), timeout))
    finally:
        os.close(sync)                          # the compositor stops listening on it
        path.unlink(missing_ok=True)
