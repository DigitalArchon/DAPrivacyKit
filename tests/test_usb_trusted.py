"""kern.usb_trusted: every USB device trusted at once, unless USBGuard runs or the kernel holds new
devices back; its How to… sets USBGuard up."""

from __future__ import annotations

from daprivacyscanner.catalogue import effective_severity
from daprivacyscanner.host import CommandResult
from daprivacyscanner.model import Outcome, Status

from conftest import detect, ev, make_host, make_scan
from fakes import FakeGSettings

CHECK = "kern.usb_trusted"
HUBS = {"/sys/bus/usb/devices/usb1/authorized_default": "1\n", "/sys/bus/usb/devices/usb2/authorized_default": "1\n",
        "/sys/bus/usb/devices/1-1/authorized": "1\n"}


def test_no_usb(cat, tmp_path):
    assert detect(cat, CHECK, make_scan(make_host(tmp_path))).status is Status.NOT_APPLICABLE


def test_every_device_trusted(cat, tmp_path):
    o = detect(cat, CHECK, make_scan(make_host(tmp_path, files=HUBS)))
    assert o.status is Status.WARN and ev(o) == {"The kernel authorises": "every device", "USBGuard": "not installed"}
    assert effective_severity(cat[CHECK], {"device": "laptop", "virtualization": "none"}).value == 3
    assert effective_severity(cat[CHECK], {"device": None, "virtualization": "vm"}).value == 0
    assert cat[CHECK].kind == "info"         # how nearly every Linux machine is set up: listed, never counted


def test_usbguard_running_passes(cat, tmp_path):
    host = make_host(tmp_path, files={**HUBS, "/usr/sbin/usbguard-daemon": ""},
                     commands={"systemctl is-active usbguard.service": "active\n"})
    assert detect(cat, CHECK, make_scan(host)).status is Status.PASS


def test_gnome_protection_without_the_daemon(cat, tmp_path):
    host = make_host(tmp_path, files={**HUBS, "/usr/sbin/usbguard-daemon": ""},
                     commands={"systemctl is-active usbguard.service": CommandResult((), 3, "inactive\n")})
    host.runner.handlers["gsettings"] = FakeGSettings({("org.gnome.desktop.privacy", "usb-protection"): "true",
                                                       ("org.gnome.desktop.privacy", "usb-protection-level"): "'lockscreen'"})
    o = detect(cat, CHECK, make_scan(host))
    assert o.status is Status.WARN and ev(o)["USBGuard"] == "installed, not running (inactive)"
    assert ev(o)["GNOME's USB protection"] == "on (lockscreen)" and o.notes[0].title.startswith("GNOME's USB")


def test_kernel_holding_new_devices_back_passes(cat, tmp_path):
    files = {k: "0\n" if k.endswith("authorized_default") else v for k, v in HUBS.items()}
    assert detect(cat, CHECK, make_scan(make_host(tmp_path, files=files))).status is Status.PASS


def test_how_to_names_the_package_and_the_gnome_group(cat, tmp_path):
    from daprivacyscanner.checks import load_all
    host = make_host(tmp_path, files={"/etc/os-release": "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"})
    g = load_all()[CHECK](cat[CHECK]).plan_guide(make_scan(host), Outcome(Status.WARN, "x"))
    assert g.steps[0].commands == ["sudo apt install usbguard"] and not g.plans
    assert "IPCAllowedGroups=sudo" in g.steps[-1].text
