"""Xephyr with a focus keeper: the window manager's one job that the browser needs.

Xephyr runs without a window manager, so its input focus is PointerRoot: it follows the pointer. Moving onto
a menu, which is a window of its own (override-redirect), takes the focus from the browser's window, and the
browser closes its menus when its window loses the focus: they opened and vanished as soon as the mouse moved
(tested in Xephyr: the menu's window unmapped; with the focus set on the browser's window, it stayed open).

This runs in Xephyr's sandbox, by the computer's python3 (its source passed with -c, like torgate.py): it
starts Xephyr (argv), and once its socket is there connects with Xephyr's own cookie and gives the focus to
each normal window the browser maps (not menus, tooltips or other override-redirect windows), and to the one
the pointer enters, so with several (a second browser window, a dialog) the one under the pointer has it.
It creates nothing. With --fill (a program on trial, a Box's app, a viewer: never the browser, which sizes its own
window), it also does a window manager's other job those need: each main window it maps is given the whole display
(no window manager inside would let the user move or resize it, and a program opens at a size of its own, which
left most of the display black or cut the window off), or the largest size the window says it can take, and again
when the display is resized; a dialog (WM_TRANSIENT_FOR) keeps its own size. When every window is gone (the browser
closed) and none comes back within GRACE seconds, it disconnects, so Xephyr's -terminate ends it as before; it then
waits for Xephyr and exits with its status. Anything going wrong here only stops the keeper, never Xephyr.
Stdlib only, the X11 wire protocol by hand (as wayland.py does Wayland's)."""

from __future__ import annotations

import os
import select
import signal
import socket
import struct
import subprocess
import sys
import time

GRACE = 8.0                             # seconds without a window before letting go (Xephyr's -terminate is 10)
FIRST = 120.0                           # seconds to wait for the browser's first window
SOCKET_WAIT = 5.0

# requests and the events they select (X11 protocol, little-endian)
CHANGE_WINDOW_ATTRIBUTES, CONFIGURE_WINDOW, GET_GEOMETRY, QUERY_TREE, GET_PROPERTY, SET_INPUT_FOCUS = 2, 12, 14, 15, 20, 42
CW_EVENT_MASK = 0x800
ENTER_WINDOW_MASK, STRUCTURE_NOTIFY_MASK, SUBSTRUCTURE_NOTIFY_MASK = 0x10, 0x20000, 0x80000
REVERT_TO_POINTER_ROOT = 1
ERROR, REPLY = 0, 1
ENTER_NOTIFY, CREATE_NOTIFY, DESTROY_NOTIFY, UNMAP_NOTIFY, MAP_NOTIFY, CONFIGURE_NOTIFY = 7, 16, 17, 18, 19, 22
# predefined atoms
WM_NORMAL_HINTS, WM_SIZE_HINTS, WM_TRANSIENT_FOR, ANY_PROPERTY_TYPE = 40, 41, 68, 0
P_MAX_SIZE = 32                         # WM_SIZE_HINTS' flag: max_width and max_height (its 8th and 9th words) are set
CONFIG_X, CONFIG_Y, CONFIG_WIDTH, CONFIG_HEIGHT = 1, 2, 4, 8


class XError(Exception):
    pass


def _pad(n: int) -> int:
    return (4 - n % 4) % 4


def setup_request(cookie: bytes) -> bytes:
    name = b"MIT-MAGIC-COOKIE-1"
    return (struct.pack("<BxHHHHxx", ord("l"), 11, 0, len(name), len(cookie)) + name + b"\0" * _pad(len(name))
            + cookie + b"\0" * _pad(len(cookie)))


def parse_setup(data: bytes) -> int:
    """The first screen's root window, from the server's reply to setup_request."""
    return parse_screen(data)[0]


def parse_screen(data: bytes) -> tuple[int, int, int]:
    """The first screen's root window and its size in pixels (width, height), from the reply to setup_request."""
    if data[0] != 1:
        reason = data[8:8 + data[1]].decode(errors="replace")
        raise XError(f"refused: {reason}")
    vendor_len, = struct.unpack_from("<H", data, 24)
    formats = data[29]
    off = 40 + vendor_len + _pad(vendor_len) + 8 * formats
    root, = struct.unpack_from("<I", data, off)
    width, height = struct.unpack_from("<HH", data, off + 20)
    return root, width, height


def cookie_from(xauth: bytes) -> bytes:
    """The MIT-MAGIC-COOKIE-1 in an Xauthority file (the first such entry)."""
    i = 0
    while i + 2 <= len(xauth):
        i += 2                                          # family
        fields = []
        for _ in range(4):                              # address, number, name, data
            n, = struct.unpack_from(">H", xauth, i)
            fields.append(xauth[i + 2:i + 2 + n])
            i += 2 + n
        if fields[2] == b"MIT-MAGIC-COOKIE-1":
            return fields[3]
    raise XError("no cookie in the authority file")


def change_event_mask(window: int, mask: int) -> bytes:
    return struct.pack("<BxHIII", CHANGE_WINDOW_ATTRIBUTES, 4, window, CW_EVENT_MASK, mask)


def set_input_focus(window: int) -> bytes:
    return struct.pack("<BBHII", SET_INPUT_FOCUS, REVERT_TO_POINTER_ROOT, 3, window, 0)


def query_tree(window: int) -> bytes:
    return struct.pack("<BxHI", QUERY_TREE, 2, window)


def get_geometry(drawable: int) -> bytes:
    return struct.pack("<BxHI", GET_GEOMETRY, 2, drawable)


def get_property(window: int, prop: int, kind: int = ANY_PROPERTY_TYPE, longs: int = 32) -> bytes:
    return struct.pack("<BBHIIIII", GET_PROPERTY, 0, 6, window, prop, kind, 0, longs)


def configure(window: int, x: int, y: int, w: int, h: int) -> bytes:
    """ConfigureWindow: the window at (x, y), w by h."""
    return struct.pack("<BxHIHxxiiII", CONFIGURE_WINDOW, 7, window, CONFIG_X | CONFIG_Y | CONFIG_WIDTH | CONFIG_HEIGHT,
                       x, y, w, h)


def property_words(reply: bytes | None) -> list[int]:
    """A GetProperty reply's value as 32-bit words ([] for none, or another format)."""
    if not reply or reply[1] != 32:
        return []
    n, = struct.unpack_from("<I", reply, 16)
    return list(struct.unpack_from(f"<{n}I", reply, 32)) if len(reply) >= 32 + 4 * n else []


def fill_size(hints: list[int], width: int, height: int) -> tuple[int, int]:
    """The size a main window gets on a width x height display: all of it, or the largest the window takes
    (WM_NORMAL_HINTS' maximum)."""
    if len(hints) >= 9 and hints[0] & P_MAX_SIZE and hints[7] > 0 and hints[8] > 0:
        return min(width, hints[7]), min(height, hints[8])
    return width, height


def worth_focus(x: int, y: int, w: int, h: int) -> bool:
    """A window the user can see and use: not GTK's 1x1 or 10x10 helpers, not one placed off the screen."""
    return w > 10 and h > 10 and x + w > 0 and y + h > 0


class Conn:
    """A connection to the X server: requests numbered as sent, replies matched to them, events queued."""

    def __init__(self, path: str, cookie: bytes):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.sock.sendall(setup_request(cookie))
        head = self._read(8)
        rest = self._read(struct.unpack_from("<H", head, 6)[0] * 4)
        self.root, self.width, self.height = parse_screen(head + rest)
        self.seq = 0
        self.events: list[bytes] = []

    def _read(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            got = self.sock.recv(n - len(buf))
            if not got:
                raise XError("the display closed")
            buf += got
        return buf

    def send(self, request: bytes) -> int:
        self.sock.sendall(request)
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def packet(self) -> bytes:
        p = self._read(32)
        if p[0] == REPLY:
            p += self._read(struct.unpack_from("<I", p, 4)[0] * 4)
        return p

    def ask(self, request: bytes) -> bytes | None:
        """A request's reply (None for an error: a window gone meanwhile); events read meanwhile are queued."""
        seq = self.send(request)
        while True:
            p = self.packet()
            if p[0] in (REPLY, ERROR) and struct.unpack_from("<H", p, 2)[0] == seq:
                return p if p[0] == REPLY else None
            if p[0] not in (REPLY, ERROR):
                self.events.append(p)

    def next_event(self, timeout: float) -> bytes | None:
        if self.events:
            return self.events.pop(0)
        if not select.select([self.sock], [], [], timeout)[0]:
            return None
        p = self.packet()
        return None if p[0] in (REPLY, ERROR) else p


class Keeper:
    """The focus on the browser's normal windows (see the module's docstring)."""

    def __init__(self, conn: Conn, fill: bool = False):
        self.c = conn
        self.fill = fill
        self.alive: set[int] = set()            # the root's children, mapped or not: the browser's windows
        self.normal: list[int] = []             # mapped, not override-redirect, worth the focus: newest last
        self.filled: dict[int, list[int]] = {}  # main windows given the display (fill), with their size hints
        self.focused = 0
        conn.send(change_event_mask(conn.root, SUBSTRUCTURE_NOTIFY_MASK | (STRUCTURE_NOTIFY_MASK if fill else 0)))
        tree = conn.ask(query_tree(conn.root))
        if tree:
            n, = struct.unpack_from("<H", tree, 16)
            self.alive.update(struct.unpack_from(f"<{n}I", tree, 32))

    def _focus(self, window: int) -> None:
        if window != self.focused:
            self.c.send(set_input_focus(window))
            self.focused = window

    def _mapped(self, window: int) -> None:
        geo = self.c.ask(get_geometry(window))
        if geo is None:
            return
        x, y, w, h = struct.unpack_from("<hhHH", geo, 12)
        if not worth_focus(x, y, w, h):
            return
        if window in self.normal:
            self.normal.remove(window)
        self.normal.append(window)
        self.c.send(change_event_mask(window, ENTER_WINDOW_MASK | STRUCTURE_NOTIFY_MASK))
        if self.fill and window not in self.filled and not property_words(self.c.ask(get_property(window, WM_TRANSIENT_FOR))):
            self.filled[window] = property_words(self.c.ask(get_property(window, WM_NORMAL_HINTS, WM_SIZE_HINTS, 18)))
            self._size(window)
        self._focus(window)

    def _size(self, window: int) -> None:
        w, h = fill_size(self.filled[window], self.c.width, self.c.height)
        self.c.send(configure(window, (self.c.width - w) // 2, (self.c.height - h) // 2, w, h))

    def _gone(self, window: int) -> None:
        self.filled.pop(window, None)
        if window in self.normal:
            self.normal.remove(window)
            if window == self.focused:
                self.focused = 0
                if self.normal:
                    self._focus(self.normal[-1])

    def handle(self, ev: bytes) -> None:
        code = ev[0] & 0x7F
        if code == CREATE_NOTIFY:
            parent, window = struct.unpack_from("<II", ev, 4)
            if parent == self.c.root:
                self.alive.add(window)
        elif code == MAP_NOTIFY:
            event, window, override = struct.unpack_from("<IIB", ev, 4)
            if event == self.c.root and window in self.alive and not override:
                self._mapped(window)
        elif code == UNMAP_NOTIFY:
            event, window = struct.unpack_from("<II", ev, 4)
            if event == self.c.root:
                self._gone(window)
        elif code == DESTROY_NOTIFY:
            event, window = struct.unpack_from("<II", ev, 4)
            if event == self.c.root:
                self.alive.discard(window)
                self._gone(window)
        elif code == ENTER_NOTIFY:
            window, = struct.unpack_from("<I", ev, 12)
            if window in self.normal:
                self._focus(window)
        elif code == CONFIGURE_NOTIFY and self.fill:
            event, window = struct.unpack_from("<II", ev, 4)
            if event == window == self.c.root:       # the display resized (Xephyr's window, by the user)
                w, h = struct.unpack_from("<HH", ev, 20)
                if (w, h) != (self.c.width, self.c.height):
                    self.c.width, self.c.height = w, h
                    for win in list(self.filled):
                        self._size(win)

    def run(self, running) -> None:
        """Until the browser's windows have been gone for GRACE seconds (or none came within FIRST), or `running()`
        says Xephyr ended."""
        seen = bool(self.alive)
        empty_since = None if seen else time.monotonic()
        while running():
            ev = self.c.next_event(0.5)
            if ev is not None:
                self.handle(ev)
            if self.alive:
                seen, empty_since = True, None
            elif empty_since is None:
                empty_since = time.monotonic()
            elif time.monotonic() - empty_since > (GRACE if seen else FIRST):
                return


def keep_focus(path: str, cookie: bytes, running, fill: bool = False) -> None:
    deadline = time.monotonic() + SOCKET_WAIT
    while not os.path.exists(path):
        if time.monotonic() > deadline or not running():
            return
        time.sleep(0.05)
    conn = Conn(path, cookie)
    try:
        Keeper(conn, fill).run(running)
    finally:
        conn.sock.close()


def main(argv: list[str]) -> int:
    """argv: [--fill] then Xephyr's command (":N" second, "-auth FILE" in it)."""
    fill = bool(argv) and argv[0] == "--fill"
    argv = argv[1:] if fill else argv
    xephyr = subprocess.Popen(argv)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda s, _f: xephyr.send_signal(s))
    try:
        path = f"/tmp/.X11-unix/X{argv[1].lstrip(':')}"
        with open(argv[argv.index("-auth") + 1], "rb") as f:
            cookie = cookie_from(f.read())
        keep_focus(path, cookie, lambda: xephyr.poll() is None, fill)
    except Exception as e:  # noqa: BLE001 - the keeper stops; Xephyr goes on
        print(f"focus keeper stopped: {e}", file=sys.stderr)
    return xephyr.wait()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
