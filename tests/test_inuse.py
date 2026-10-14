"""Camera and microphone (tools/inuse.py): the devices and who holds them, PipeWire's and
PulseAudio's capture streams, and the live view's endpoint."""

from __future__ import annotations

import json
import os

from fastapi.testclient import TestClient

from conftest import make_host
from daprivacyscanner.host import CommandResult
from daprivacyscanner.server import create_app
from daprivacyscanner.tools import inuse

H = {"X-Token": "t0ken"}


def node(nid, cls, client=None, state="running", **props):
    p = {"media.class": cls, **({"client.id": client} if client is not None else {}), **props}
    return {"id": nid, "type": "PipeWire:Interface:Node", "info": {"state": state, "props": p}}


def client(cid, name, binary, pid=None):
    p = {"application.name": name, "application.process.binary": binary}
    if pid:
        p["application.process.id"] = pid
    return {"id": cid, "type": "PipeWire:Interface:Client", "info": {"props": p}}


def link(src, dst):
    return {"id": 900 + src * 10 + dst, "type": "PipeWire:Interface:Link",
            "info": {"output-node-id": src, "output-port-id": 1, "input-node-id": dst, "input-port-id": 2,
                     "state": "active"}}


GRAPH = [
    {"id": 0, "type": "PipeWire:Interface:Core", "info": {}},
    client(30, "Firefox", "firefox", 4242),
    client(31, "Chromium input", "chromium", 5151),
    client(32, "gnome-shell", "gnome-shell"),
    client(33, "OBS Studio", "obs"),
    client(34, "Volume Control", "pavucontrol"),
    node(40, "Audio/Source", **{"node.description": "Built-in Audio Analog Stereo",
                                                             "node.name": "alsa_input.pci"}),
    node(41, "Audio/Sink", **{"node.description": "Built-in Audio Speakers", "node.name": "alsa_output.pci"}),
    node(42, "Video/Source", **{"device.api": "v4l2", "node.description": "Integrated Camera (V4L2)"}),
    node(43, "Stream/Output/Video", client=32, **{"node.name": "gnome-shell-screencast"}),
    node(50, "Stream/Input/Audio", client=30),                                    # Firefox: the microphone
    node(51, "Stream/Input/Video", client=31),                                    # Chromium: the camera
    node(52, "Stream/Input/Video", client=33),                                    # OBS: the screen
    node(53, "Stream/Input/Audio", client=34, state="idle"),                      # a peak meter on the speakers
    node(54, "Stream/Input/Audio", client=30, state="suspended"),                 # not linked to anything
    node(55, "Stream/Output/Audio", client=30),                                   # playing: not capture
    link(40, 50), link(42, 51), link(43, 52), link(41, 53),
]


def test_pw_dump_streams_and_what_they_take_in():
    all_ = inuse.parse_pw_dump(json.dumps(GRAPH))
    assert len(all_) == 5                                   # Stream/Input only: not Firefox's playback
    streams = {s.binary: s for s in all_}
    ff = [s for s in all_ if s.app == "Firefox"]
    assert {(s.what, s.state, s.source) for s in ff} == {("microphone", "running", "Built-in Audio Analog Stereo"),
                                                         ("audio", "suspended", "")}
    cr = next(s for s in streams.values() if s.binary == "chromium")
    assert (cr.app, cr.what, cr.active, cr.pid) == ("Chromium", "camera", True, 5151)     # "<browser> input" tidied
    obs = next(s for s in streams.values() if s.binary == "obs")
    assert obs.what == "screen"
    meter = next(s for s in streams.values() if s.binary == "pavucontrol")
    assert (meter.what, meter.active) == ("playback", False)


def test_pw_dump_that_isnt_json_gives_nothing():
    assert inuse.parse_pw_dump("not json") == [] and inuse.parse_pw_dump('{"a": 1}') == []


def test_pactl_source_outputs():
    text = json.dumps([
        {"index": 7, "source": 1, "corked": False, "properties": {"application.name": "Firefox",
                                                                  "application.process.binary": "firefox",
                                                                  "application.process.id": "77"}},
        {"index": 8, "source": "alsa_output.pci.monitor", "corked": True,
         "properties": {"application.name": "recorder"}}])
    a, b = inuse.parse_pactl_outputs(text)
    assert (a.app, a.what, a.active, a.pid, a.via) == ("Firefox", "microphone", True, 77, "pulseaudio")
    assert (b.what, b.active) == ("playback", False)


def fixture_host(tmp_path, commands=None, session="wayland"):
    host = make_host(tmp_path, files={
        "/sys/class/video4linux/video0/name": "Integrated Camera: Integrated C\n",
        "/sys/class/video4linux/video1/name": "Integrated Camera: Integrated C\n",
        "/sys/class/video4linux/video2/name": "USB Webcam\n",
        "/proc/asound/card0/id": "PCH\n",
        "/dev/snd/pcmC0D0c": "", "/dev/snd/pcmC0D0p": "", "/dev/snd/controlC0": "",
        "/proc/100/comm": "zoom\n", "/proc/200/comm": "pipewire\n", "/proc/300/comm": "arecord\n",
        "/proc/400/comm": "bash\n",
    }, commands=commands or {}, env={"XDG_SESSION_TYPE": session})
    proc = host.root / "proc"
    for pid, targets in {100: ["/dev/video0", "/dev/null"], 200: ["/dev/video1", "/dev/snd/pcmC0D0c"],
                         300: ["/dev/snd/pcmC0D0c"], 400: ["/dev/pts/1"]}.items():
        (proc / str(pid) / "fd").mkdir(parents=True)
        for i, t in enumerate(targets):
            os.symlink(t, proc / str(pid) / "fd" / str(i))
    return host


def test_devices_and_their_holders(tmp_path):
    snap = inuse.snapshot(fixture_host(tmp_path))
    cams = {d.name: d for d in snap.devices if d.kind == "camera"}
    builtin = cams["Integrated Camera: Integrated C"]
    assert builtin.nodes == ["/dev/video0", "/dev/video1"]
    assert [h.name for h in builtin.holders] == ["zoom"] and builtin.via_server == ["pipewire"]
    assert cams["USB Webcam"].holders == []
    mic = next(d for d in snap.devices if d.kind == "microphone")
    assert (mic.name, mic.nodes, [h.name for h in mic.holders]) == ("PCH", ["/dev/snd/pcmC0D0c"], ["arecord"])
    d = snap.to_dict()
    assert d["using"] == ["arecord", "zoom"] and d["server"] == ""
    assert any("No sound server answered" in n for n in d["notes"])


def test_snapshot_uses_pipewire_then_pulseaudio(tmp_path):
    snap = inuse.snapshot(fixture_host(tmp_path / "a", {"pw-dump": json.dumps(GRAPH)}))
    assert snap.server == "pipewire"
    assert [s.active for s in snap.streams] == sorted([s.active for s in snap.streams], reverse=True)   # active first
    pulse = {("pactl", "-f", "json", "list", "source-outputs"): "[]"}
    snap = inuse.snapshot(fixture_host(tmp_path / "b", {**pulse, "pw-dump": CommandResult(("pw-dump",), 1, "", "x")}))
    assert snap.server == "pulseaudio" and snap.streams == []


def test_x11_note(tmp_path):
    d = inuse.snapshot(fixture_host(tmp_path, session="x11")).to_dict()
    assert any("X11 session" in n for n in d["notes"])


def test_endpoint(cat, tmp_path):
    host = fixture_host(tmp_path, {"pw-dump": json.dumps(GRAPH)})
    c = TestClient(create_app("t0ken", cat, make_host=lambda: host))
    d = c.get("/api/tools/inuse", headers=H).json()
    assert {"Firefox", "Chromium", "OBS Studio", "zoom", "arecord"} <= set(d["using"])
    assert all(s["what_title"] for s in d["streams"])
    assert c.get("/api/tools/inuse").status_code == 403
