"""Xephyr's focus keeper (tools/xfocus.py): without a window manager the focus follows the pointer, and the
browser's menus closed as soon as the pointer moved onto them. Live-tested in Xephyr (on a private Xvfb, through
the app's own sandboxed command): the menu stayed open, typing reached the browser, a new window got the focus,
and Xephyr still ended by itself after the browser closed. Here: the wire format and the keeper's choices."""

from __future__ import annotations

import struct

from daprivacyscanner.tools import sandbox as S
from daprivacyscanner.tools import xfocus as X

ROOT = 0x220


def test_setup_and_cookie():
    cookie = bytes(range(16))
    assert X.cookie_from(S._xauth_entry("1", cookie)) == cookie
    req = X.setup_request(cookie)
    assert req[:1] == b"l" and struct.unpack_from("<HH", req, 2) == (11, 0) and len(req) % 4 == 0
    assert req[12:30] == b"MIT-MAGIC-COOKIE-1" and req[32:48] == cookie
    vendor = b"The X.Org Foundation"                            # 20 bytes, then one 8-byte format, then the screen
    body = struct.pack("<IIIIHHBBBBBBBB4x", 1, 0x400000, 0x1FFFFF, 256, len(vendor), 65535, 1, 1, 0, 0, 32, 32, 8, 255)
    body += vendor + b"\0" * X._pad(len(vendor)) + b"\0" * 8 + struct.pack("<I", ROOT) + b"\0" * 36
    head = struct.pack("<BxHHH", 1, 11, 0, len(body) // 4)
    assert X.parse_setup(head + body) == ROOT
    refused = struct.pack("<BBHHH", 0, 7, 11, 0, 2) + b"refused"
    try:
        X.parse_setup(refused)
        raise AssertionError("refused setup accepted")
    except X.XError as e:
        assert "refused" in str(e)


def test_requests():
    assert X.set_input_focus(0x40003C) == struct.pack("<BBHII", 42, 1, 3, 0x40003C, 0)       # RevertTo PointerRoot
    assert X.change_event_mask(ROOT, X.SUBSTRUCTURE_NOTIFY_MASK) == struct.pack("<BxHIII", 2, 4, ROOT, 0x800, 0x80000)


class FakeConn:
    """Answers GetGeometry from `geometry`; records what was sent."""

    def __init__(self, geometry):
        self.root, self.sent, self.events, self.geometry = ROOT, [], [], geometry

    def send(self, request):
        self.sent.append(request)

    def ask(self, request):
        if request[0] == X.QUERY_TREE:
            return struct.pack("<BxHIIIH14x", 1, 1, 0, ROOT, 0, 0)
        window, = struct.unpack_from("<I", request, 4)
        g = self.geometry.get(window)
        return None if g is None else struct.pack("<BBHIIhhHHH10x", 1, 24, 1, 0, ROOT, *g, 0)

    def focused(self):
        return [struct.unpack_from("<I", r, 4)[0] for r in self.sent if r[0] == X.SET_INPUT_FOCUS]


def ev(code, *fields, fmt="<II"):
    return (struct.pack("<BxH", code, 1) + struct.pack(fmt, *fields)).ljust(32, b"\0")


def created(w):
    return ev(X.CREATE_NOTIFY, ROOT, w)


def mapped(w, override=False):
    return ev(X.MAP_NOTIFY, ROOT, w, override, fmt="<IIB")


def test_the_browser_s_windows_get_the_focus_and_its_menus_don_t():
    main, menu, helper, second = 0x40003C, 0x400081, 0x40005B, 0x400097
    c = FakeConn({main: (0, 0, 1410, 895), menu: (1080, 85, 317, 543), helper: (-100, -100, 10, 10),
                  second: (0, 0, 1410, 895)})
    k = X.Keeper(c)
    assert c.sent[0] == X.change_event_mask(ROOT, X.SUBSTRUCTURE_NOTIFY_MASK)
    for w in (main, menu, helper, second):
        k.handle(created(w))
    k.handle(mapped(helper))                                    # GTK's 10x10 off the screen: never
    k.handle(mapped(main))
    k.handle(mapped(menu, override=True))                       # a menu: never takes the focus
    assert c.focused() == [main]
    assert X.change_event_mask(main, X.ENTER_WINDOW_MASK | X.STRUCTURE_NOTIFY_MASK) in c.sent
    k.handle(mapped(second))                                    # a new window (Ctrl+N), or a dialog
    k.handle(ev(X.ENTER_NOTIFY, 0, ROOT, main, fmt="<III"))     # the pointer back on the first
    k.handle(ev(X.ENTER_NOTIFY, 0, ROOT, main, fmt="<III"))     # once is enough
    k.handle(ev(X.ENTER_NOTIFY, 0, ROOT, menu, fmt="<III"))     # onto its menu: the focus stays
    assert c.focused() == [main, second, main]
    k.handle(ev(X.UNMAP_NOTIFY, ROOT, main))                    # the focused one closes: the other gets it
    assert c.focused()[-1] == second
    k.handle(ev(X.DESTROY_NOTIFY, ROOT, second))
    assert k.normal == [] and second not in k.alive


def test_it_lets_go_once_the_browser_s_windows_are_gone(monkeypatch):
    """So Xephyr's -terminate still ends it after the browser closes."""
    monkeypatch.setattr(X, "GRACE", 0.0)
    c = FakeConn({})
    k = X.Keeper(c)
    queue = [created(1), ev(X.DESTROY_NOTIFY, ROOT, 1)]
    c.next_event = lambda timeout: queue.pop(0) if queue else None
    k.run(lambda: True)                                         # returns: nothing left
    assert not k.alive

