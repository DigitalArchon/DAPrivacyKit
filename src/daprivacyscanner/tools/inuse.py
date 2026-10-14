"""Who is using my camera or microphone (docs/TECHNICAL.md, Tools): a live view, read-only, as the user.

Three sources, read again each time the page asks (every few seconds while the view is open):

- the processes of this user holding a camera (/dev/video*) or an ALSA capture device
  (/dev/snd/pcmC*D*c) open, from /proc/PID/fd (what `fuser` reads; only the descriptors, not the
  memory maps, so it stays quick enough to repeat);
- PipeWire's graph (`pw-dump`): every stream that takes something in (media.class Stream/Input/*),
  and what it is linked to: a microphone (Audio/Source), what the computer plays (a sink's monitor),
  a camera (Video/Source from v4l2 or libcamera) or the screen (a video stream the compositor or a
  portal produces: xdg-desktop-portal's ScreenCast hands PipeWire such a stream);
- PulseAudio without PipeWire: `pactl -f json list source-outputs`.

Nothing is kept and nothing interacts with the programs or their windows. Other accounts' processes
and system services can't be seen as the user; on X11 any program can read the screen without
going through PipeWire, so nothing shows it. Programs that talk to ALSA through a sound server are
listed under the sound server's streams, not as device holders."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..host import Host

CAMERA = re.compile(r"^/dev/video(\d+)$")
ALSA_CAPTURE = re.compile(r"^/dev/snd/pcmC(\d+)D(\d+)c$")
# they open the devices on behalf of the programs listed in their own graph
SOUND_SERVERS = frozenset({"pipewire", "wireplumber", "pulseaudio", "jackd", "jackdbg", "pipewire-pulse"})
# programs that produce the screen's picture for a ScreenCast session (a pw_stream of their own).
# VERIFY: the process names of GNOME's, KDE's and wlroots' screencast producers on current releases.
SCREEN_PRODUCERS = frozenset({"gnome-shell", "kwin_wayland", "kwin_x11", "mutter", "cinnamon", "muffin",
                              "xdg-desktop-portal-wlr", "xdg-desktop-portal-gnome", "xdg-desktop-portal-kde",
                              "xdg-desktop-portal-hyprland", "xdg-desktop-portal-cosmic", "gamescope"})

WHAT_TITLE = {"camera": "the camera", "microphone": "a microphone", "playback": "what the computer plays",
              "screen": "the screen", "video": "a video source", "audio": "a sound source"}


@dataclass
class Holder:
    pid: int
    name: str

    def to_dict(self) -> dict:
        return {"pid": self.pid, "name": self.name}


@dataclass
class Device:
    kind: str                       # "camera" or "microphone"
    name: str                       # what the device calls itself
    nodes: list[str] = field(default_factory=list)
    holders: list[Holder] = field(default_factory=list)
    via_server: list[str] = field(default_factory=list)     # sound servers holding it for the programs in their graph

    def to_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "nodes": self.nodes,
                "holders": [h.to_dict() for h in self.holders], "via_server": self.via_server}


@dataclass
class Stream:
    app: str                        # the program as it names itself
    binary: str = ""
    pid: int | None = None
    what: str = "audio"             # camera, microphone, playback, screen, video, audio
    source: str = ""                # the device or stream it is linked to
    state: str = ""                 # running, idle, suspended, corked...
    via: str = "pipewire"           # pipewire or pulseaudio

    @property
    def active(self) -> bool:
        return self.state in ("running", "active")

    def to_dict(self) -> dict:
        return {"app": self.app, "binary": self.binary, "pid": self.pid, "what": self.what,
                "what_title": WHAT_TITLE.get(self.what, self.what), "source": self.source, "state": self.state,
                "active": self.active, "via": self.via}


@dataclass
class Snapshot:
    devices: list[Device] = field(default_factory=list)
    streams: list[Stream] = field(default_factory=list)
    server: str = ""                # "pipewire", "pulseaudio" or "" (none answered)
    session: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        using = sorted({s.app for s in self.streams if s.active} | {h.name for d in self.devices for h in d.holders})
        return {"devices": [d.to_dict() for d in self.devices], "streams": [s.to_dict() for s in self.streams],
                "server": self.server, "session": self.session, "notes": self.notes, "using": using}


# ------------------------------------------------------------------ devices and who holds them

def _sys_text(host: Host, path: str) -> str:
    try:
        return (host.read_sys(path) or "").strip()
    except Exception:  # noqa: BLE001 - an unreadable name is just not shown
        return ""


def device_holders(host: Host) -> dict[str, list[Holder]]:
    """Device node -> this user's processes holding it open (cameras and capture devices only)."""
    out: dict[str, list[Holder]] = {}
    me = str(os.getpid()) if host.root == Path("/") else None
    proc = host.sys_path("/proc")
    try:
        pids = [p for p in proc.iterdir() if p.name.isdigit() and p.name != me]
    except OSError:
        return out
    for p in pids:
        try:
            if host.root == Path("/") and p.stat().st_uid != host.uid:
                continue
            fds = list((p / "fd").iterdir())
        except OSError:
            continue
        held = set()
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if CAMERA.match(target) or ALSA_CAPTURE.match(target):
                held.add(target)
        if not held:
            continue
        try:
            name = (p / "comm").read_text().strip()
        except OSError:
            continue
        for t in held:
            out.setdefault(t, []).append(Holder(int(p.name), name))
    return out


def cameras(host: Host) -> list[Device]:
    """The cameras, grouped by name (a webcam usually has two nodes: the picture and its metadata)."""
    by_name: dict[str, Device] = {}
    base = host.sys_path("/sys/class/video4linux")
    try:
        nodes = sorted((p.name for p in base.iterdir() if CAMERA.match(f"/dev/{p.name}")),
                       key=lambda n: int(n[5:]))
    except OSError:
        nodes = []
    for n in nodes:
        name = _sys_text(host, f"/sys/class/video4linux/{n}/name") or n
        by_name.setdefault(name, Device("camera", name)).nodes.append(f"/dev/{n}")
    return list(by_name.values())


def microphones(host: Host) -> list[Device]:
    """Sound cards with a capture device, by the card's name."""
    by_card: dict[str, Device] = {}
    snd = host.sys_path("/dev/snd")
    try:
        nodes = sorted(p.name for p in snd.iterdir() if ALSA_CAPTURE.match(f"/dev/snd/{p.name}"))
    except OSError:
        nodes = []
    for n in nodes:
        card = ALSA_CAPTURE.match(f"/dev/snd/{n}").group(1)
        name = _sys_text(host, f"/proc/asound/card{card}/id") or f"card {card}"
        by_card.setdefault(card, Device("microphone", name)).nodes.append(f"/dev/snd/{n}")
    return list(by_card.values())


def _attach(devices: list[Device], holders: dict[str, list[Holder]], kind: str) -> list[Device]:
    """Holders onto their devices; nodes held that /sys didn't list get a device of their own."""
    known = {n for d in devices for n in d.nodes}
    pattern = CAMERA if kind == "camera" else ALSA_CAPTURE
    for node in sorted(holders):
        if pattern.match(node) and node not in known:
            devices.append(Device(kind, node, [node]))
    for d in devices:
        seen: set[int] = set()
        for node in d.nodes:
            for h in holders.get(node, []):
                if h.pid in seen:
                    continue
                seen.add(h.pid)
                if h.name in SOUND_SERVERS:
                    if h.name not in d.via_server:
                        d.via_server.append(h.name)
                else:
                    d.holders.append(h)
    return devices


# ------------------------------------------------------------------ PipeWire

def _props(obj: dict) -> dict:
    return ((obj.get("info") or {}).get("props")) or {}


def _pid(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_pw_dump(text: str) -> list[Stream]:
    """The streams taking something in, from `pw-dump` JSON, each with what it is linked to."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    nodes, clients, links = {}, {}, []
    for o in data:
        if not isinstance(o, dict):
            continue
        t = o.get("type", "")
        if t.endswith(":Node"):
            nodes[o.get("id")] = o
        elif t.endswith(":Client"):
            clients[o.get("id")] = o
        elif t.endswith(":Link"):
            links.append(o.get("info") or {})
    feeds: dict[int, list[int]] = {}               # input node -> the nodes linked into it
    for ln in links:
        src, dst = ln.get("output-node-id"), ln.get("input-node-id")
        if src is not None and dst is not None and src not in feeds.get(dst, []):
            feeds.setdefault(dst, []).append(src)
    out = []
    for nid, node in nodes.items():
        p = _props(node)
        cls = p.get("media.class") or ""
        if not cls.startswith("Stream/Input/"):
            continue
        client = _props(clients.get(p.get("client.id"), {}))
        get = lambda k: p.get(k) or client.get(k)  # noqa: E731
        binary = get("application.process.binary") or ""
        app = get("application.name") or binary or p.get("node.name") or f"stream {nid}"
        sources = [nodes[s] for s in feeds.get(nid, []) if s in nodes]
        what, source = _what(cls, sources, nodes, clients)
        out.append(Stream(app=_tidy_app(app), binary=binary, pid=_pid(get("application.process.id")), what=what,
                          source=source, state=(node.get("info") or {}).get("state") or ""))
    return out


def _what(cls: str, sources: list[dict], nodes: dict, clients: dict) -> tuple[str, str]:
    video = cls.endswith("/Video")
    if not sources:
        return ("video" if video else "audio"), ""
    s = _props(sources[0])
    scls = s.get("media.class") or ""
    name = s.get("node.description") or s.get("node.nick") or s.get("media.name") or s.get("node.name") or ""
    if scls.startswith("Audio/Source"):
        return "microphone", name
    if scls.startswith("Audio/Sink") or scls.startswith("Audio/Duplex"):
        return "playback", name
    if scls.startswith("Video/Source"):
        if s.get("device.api") in ("v4l2", "libcamera") or s.get("api.v4l2.path") or s.get("api.libcamera.path"):
            return "camera", name
        return "video", name
    if scls.startswith("Stream/Output/Video"):
        producer = _props(clients.get(s.get("client.id"), {}))
        binary = s.get("application.process.binary") or producer.get("application.process.binary") or ""
        node_name = (s.get("node.name") or "").lower()
        if binary in SCREEN_PRODUCERS or "screen" in node_name or "screencast" in node_name:
            return "screen", ""
        return "video", s.get("application.name") or producer.get("application.name") or name
    return ("video" if video else "audio"), name


def _tidy_app(name: str) -> str:
    """Chromium-family browsers name their capture client "<Browser> input"."""
    return re.sub(r"\s+input$", "", name.strip()) or name


def parse_pactl_outputs(text: str) -> list[Stream]:
    """`pactl -f json list source-outputs`: recording streams on PulseAudio (no PipeWire graph)."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for so in data if isinstance(data, list) else []:
        if not isinstance(so, dict):
            continue
        p = so.get("properties") or {}
        source = str(so.get("source", ""))
        what = "playback" if p.get("target.object", "").endswith(".monitor") or source.endswith(".monitor") \
            else "microphone"
        out.append(Stream(app=_tidy_app(p.get("application.name") or p.get("application.process.binary") or "?"),
                          binary=p.get("application.process.binary") or "",
                          pid=_pid(p.get("application.process.id")), what=what, source="",
                          state="corked" if so.get("corked") else "running", via="pulseaudio"))
    return out


# ------------------------------------------------------------------ the snapshot

def snapshot(host: Host) -> Snapshot:
    snap = Snapshot(session=(host.environ.get("XDG_SESSION_TYPE") or "").lower())
    holders = device_holders(host)
    snap.devices = _attach(cameras(host), holders, "camera") + _attach(microphones(host), holders, "microphone")
    r = host.run("pw-dump", timeout=5)
    if r.ok:
        snap.server = "pipewire"
        snap.streams = parse_pw_dump(r.stdout)
    else:
        r = host.run("pactl", "-f", "json", "list", "source-outputs", timeout=5)
        if r.ok:
            snap.server = "pulseaudio"
            snap.streams = parse_pactl_outputs(r.stdout)
    snap.streams.sort(key=lambda s: (not s.active, s.what, s.app.lower()))
    snap.notes = notes(snap)
    return snap


def notes(snap: Snapshot) -> list[str]:
    out = []
    if not snap.server:
        out.append("No sound server answered (neither pw-dump nor pactl), so programs recording through one can't "
                   "be listed; only programs holding a device themselves are.")
    for d in snap.devices:
        if d.via_server and not any(s.what in ("camera", "microphone") and s.active for s in snap.streams):
            out.append(f"{', '.join(d.via_server)} has {d.name} open, but no program is receiving from it right now "
                       "(the sound server keeps a device open for a few seconds after the last stream stops).")
    if snap.session == "x11":
        out.append("This is an X11 session: any program you run can read the screen and what you type without asking "
                   "and without going through PipeWire, so screen capture on X11 doesn't show up here.")
    out.append("Only your own programs are listed: other accounts' programs and system services can't be seen "
               "without administrator access. A program that has the camera open but isn't reading from it shows "
               "up too; many cameras' lights show when it is actually on.")
    return out
