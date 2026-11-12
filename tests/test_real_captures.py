"""The parsers and the context against real machines: what the released AppImage's `--capture` and a few read-only
commands printed on four installs (tests/samples/<distro>/, see tests/samples/README.md), checked against what is
known about each machine. Four KVM guests on unencrypted virtio disks: CachyOS (KDE Plasma, btrfs, ufw on, zram),
Omarchy (Hyprland, btrfs, ufw on, a swap file and zram), Fedora 44 Workstation (GNOME, btrfs, firewalld, SELinux,
zram) and Ubuntu 26.04 (GNOME, ext4, a swap file, ufw off, snaps)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from daprivacyscanner import appversions, blockdev, context, helper, ini, network, storage
from daprivacyscanner.checks.network import nm_default, resolved_announces, resolved_links
from daprivacyscanner.host import CommandResult, FakeRunner, Host

SAMPLES = Path(__file__).parent / "samples"
CACHY, OMARCHY, FEDORA, UBUNTU = "cachyos-rolling", "omarchy-4.0.6", "fedora-44", "ubuntu-26.04"
ALL = [CACHY, OMARCHY, FEDORA, UBUNTU]


def text(distro: str, rel: str) -> str:
    return (SAMPLES / distro / rel).read_text()


def has(distro: str, rel: str) -> bool:
    return (SAMPLES / distro / rel).exists()


def sysfs(root: Path, distro: str) -> None:
    """The block layer's sysfs as captured (links, files, folders), under the fixture root."""
    for path, (kind, value) in sorted(json.loads(text(distro, "sysfs/block.json")).items()):
        p = root / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        if kind == "link":
            os.symlink(value, p)
        elif kind == "dir":
            p.mkdir(exist_ok=True)
        else:
            p.write_text(value)


def captured(tmp_path: Path, distro: str) -> Host:
    """A host whose files and commands are what the machine gave."""
    root = tmp_path / "root"
    home = root / "home/user"
    home.mkdir(parents=True)
    files = {"/proc/mounts": "misc/proc-mounts.txt", "/proc/swaps": "misc/proc-swaps.txt",
             "/proc/cmdline": "misc/proc-cmdline.txt", "/etc/os-release": "misc/os-release.txt",
             "/etc/fstab": "misc/fstab.txt", "/etc/resolv.conf": "misc/resolv.conf.txt"}
    for path, rel in files.items():
        if has(distro, rel):
            (root / path.lstrip("/")).parent.mkdir(parents=True, exist_ok=True)
            (root / path.lstrip("/")).write_text(text(distro, rel))
    sysfs(root, distro)
    virt = text(distro, "misc/detect-virt.txt")
    commands = {
        ("lsblk", "-J", "-o", blockdev.COLUMNS): text(distro, "lsblk/lsblk.json"),
        ("lsblk", "-J", "-b", "-o", blockdev.COLUMNS_PARTITIONS): text(distro, "lsblk/lsblk-partitions.json"),
        network.SS_ARGS: text(distro, "ss/ss.txt"),
        ("hostnamectl", "chassis"): text(distro, "misc/hostnamectl-chassis.txt"),
        ("systemd-detect-virt", "--vm"): CommandResult((), 0 if virt.strip() != "none" else 1, virt),
        ("systemd-detect-virt", "--container"): CommandResult((), 1, "none\n"),
        ("resolvectl", "status"): text(distro, "misc/resolvectl-status.txt"),
        ("nmcli", "-t", "-f", "TYPE", "connection", "show", "--active"): text(distro, "misc/nmcli-active.txt"),
        ("systemctl", "--version"): text(distro, "misc/systemctl-version.txt"),
        ("ip", "rule", "show"): text(distro, "ip/rule.txt"),
    }
    return Host(home=home, environ={"HOME": str(home)}, runner=FakeRunner(commands), root=root, uid=1000)


# ------------------------------------------------------------------ the samples themselves

def test_the_captures_name_no_account_network_or_disk():
    """Every sample was sanitised (--capture's Sanitiser, then FAT serials): no home folder but the placeholder's, no
    private address, MAC or disk UUID but the placeholders (partition type GUIDs name a kind of partition, kept)."""
    bad = re.compile(r"/home/(?!user\b)\w+|\b192\.168\.|(?<![:\w.])10\.\d+\.\d+\.\d+\b|\b172\.(1[6-9]|2\d|3[01])\.|"
                     r"\b(?!00:11:22:33:44:55)([0-9a-f]{2}:){5}[0-9a-f]{2}\b|"
                     r"(?<!\"parttype\": \")\b(?!12345678-1234-4321-8765-123456789abc)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                     re.I)
    for distro in ALL:
        for p in sorted((SAMPLES / distro).rglob("*")):
            if p.is_file():
                m = bad.search(p.read_text(errors="replace"))
                assert m is None, f"{p.relative_to(SAMPLES)}: {m.group(0)}"


@pytest.mark.parametrize("distro", ALL)
def test_capture_names_each_install_after_its_os_release(tmp_path, distro):
    """The folder's name is --capture's distro_name (ID-VERSION_ID, or rolling). Not called here: capture.capture's
    `out=sys.stdout` default is bound when the module is first imported, and imported during this test it kept this
    test's captured stream, so test_server's capsys saw nothing of a later capture."""
    release = (captured(tmp_path, distro).read_sys("/etc/os-release") or "")
    get = lambda k: (re.search(rf'^{k}="?([^"\n]*)', release, re.M) or [None, ""])[1]  # noqa: E731
    assert f"{get('ID')}-{get('VERSION_ID') or 'rolling'}".lower() == distro


# ------------------------------------------------------------------ lsblk, the storage stack, swap

ROOT_FS = {CACHY: ("vda2", "part", "btrfs"), OMARCHY: ("vda2", "part", "btrfs"), FEDORA: ("vda3", "part", "btrfs"),
           UBUNTU: ("vda2", "part", "ext4")}


@pytest.mark.parametrize("distro", ALL)
def test_lsblk_finds_the_root_filesystem_and_its_encryption(distro):
    devices = blockdev.parse_lsblk(text(distro, "lsblk/lsblk.json"))
    a = blockdev.assess_fde(devices)
    assert a.value == "none"
    assert (a.root.name, a.root.type, a.root.fstype) == ROOT_FS[distro]
    assert not any(d.removable for d in devices if not d.is_image)
    assert blockdev.luks_devices(devices) == []
    # the listing with sizes, partition types and UUIDs is the same tree
    parts = blockdev.parse_lsblk(text(distro, "lsblk/lsblk-partitions.json"))
    assert [d.name for d in parts] == [d.name for d in devices]
    assert all(d.size for d in parts if d.type in ("disk", "part"))
    assert {d.parttype for d in parts if d.type == "part" and d.fstype == "vfat"} == {"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"}


def test_ubuntus_snap_images_are_images_not_unencrypted_data(tmp_path):
    devices = blockdev.parse_lsblk(text(UBUNTU, "lsblk/lsblk.json"))
    loops = [d for d in devices if d.type == "loop"]
    assert len(loops) >= 10 and all(d.is_image for d in loops if d.mountpoints)
    assert blockdev.assess_fde(devices).unencrypted == ["/"]


@pytest.mark.parametrize("distro", ALL)
def test_the_storage_stack_from_the_real_sysfs(tmp_path, distro):
    host = captured(tmp_path, distro)
    stacks = storage.stacks(host)
    root = next(s for s in stacks if s.mount == "/")
    assert [x.kind for x in root.layers] == ["partition", "disk"]
    assert [(d.transport, d.rotational) for d in root.drives] == [("virtio", True)]  # QEMU says so: no TRIM test
    # libvirt's discard=unmap passes TRIM on; a partition has no queue of its own in sysfs, so it reports nothing
    assert root.stop is None and all(x.discard_max for x in root.layers if x.kind != "partition")
    assert all(x.discard_max is None for x in root.layers if x.kind == "partition")
    # btrfs on a device that takes discards mounts with discard=async by default since Linux 6.2: continuous TRIM
    assert root.continuous == (root.fstype == "btrfs") and root.fstype == ROOT_FS[distro][2]
    assert len(stacks) == 1                            # the home is on the root's filesystem


@pytest.mark.parametrize("distro,swaps", [
    (CACHY, [("/dev/zram0", "partition")]), (OMARCHY, [("/swap/swapfile", "file"), ("/dev/zram0", "partition")]),
    (FEDORA, [("/dev/zram0", "partition")]), (UBUNTU, [("/swap.img", "file")])])
def test_swap_on_the_guests(tmp_path, distro, swaps):
    assert [s[:2] for s in context.read_swaps(captured(tmp_path, distro))] == swaps


# ------------------------------------------------------------------ the context

@pytest.mark.parametrize("distro", ALL)
def test_the_context_keys_from_a_real_machine(tmp_path, distro):
    host = captured(tmp_path, distro)
    devices = blockdev.read_devices(host)
    assert context.detect_fde(devices, "", host).value == "none"
    v = context.detect_virtualization(host)
    assert v.value not in (None, "none"), v
    d = context.detect_device(host, v.value)
    assert d.value is None, d                       # a VM: the host can't be seen
    e = context.detect_exposed_services(host)
    assert e.value is True                         # every one of them has sshd on all interfaces
    assert context.detect_vpn_active(host).value is False


# ------------------------------------------------------------------ listening sockets

EXPOSED = {
    CACHY: {("tcp", 22), ("tcp", 5355), ("udp", 5355), ("tcp", 1716), ("udp", 1716)},   # LLMNR, KDE Connect
    OMARCHY: {("tcp", 22)},
    FEDORA: {("tcp", 22), ("tcp", 5355), ("udp", 5355), ("tcp", 27500)},
    UBUNTU: {("tcp", 22)},
}


@pytest.mark.parametrize("distro", ALL)
def test_ss_what_listens_on_every_interface(distro):
    listeners = network.parse_ss(text(distro, "ss/ss.txt"))
    assert listeners and all(s.proto in ("tcp", "udp") for s in listeners)
    assert {(s.proto, s.port) for s in network.exposed(listeners)} == EXPOSED[distro]
    # the stub resolver is bound to lo by name: never exposed
    stub = [s for s in listeners if s.host_part == "127.0.0.53"]
    assert stub and all(s.interface == "lo" and not s.wildcard for s in stub)


def test_ss_names_the_users_own_programs_only():
    cachy = network.parse_ss(text(CACHY, "ss/ss.txt"))
    assert {s.process for s in cachy if s.process} == {"kdeconnectd"} and all(s.pid for s in cachy if s.process)


# ------------------------------------------------------------------ firewalls

def test_nftables_chains_that_filter_incoming_connections():
    """ufw (CachyOS, Omarchy) and firewalld (Fedora) filter what comes in; Ubuntu's ruleset is empty (ufw off)."""
    count = {d: helper.nft_input_filters(text(d, "misc/nft-ruleset.txt")) for d in ALL}
    assert count[UBUNTU] == 0
    assert count[CACHY] >= 1 and count[OMARCHY] >= 1 and count[FEDORA] >= 1


def test_ufw_status_on_the_machines_with_ufw():
    assert network.parse_ufw_status(text(UBUNTU, "misc/ufw-status-verbose.txt")) is None          # inactive
    o = network.parse_ufw_status(text(OMARCHY, "misc/ufw-status-verbose.txt"))
    assert o.default_allows is False and o.allows(53317, "tcp") and o.allows(22, "tcp") and o.allows(80, "tcp") is False
    c = network.parse_ufw_status(text(CACHY, "misc/ufw-status-verbose.txt"))
    assert c.default_allows is False and c.allows(22, "tcp") and c.allows(80, "tcp") is False


@pytest.mark.xfail(strict=True, reason="network.parse_ufw_status (network.py:146) needs two spaces before ALLOW, but ufw "
                   "prints a rule whose To column overflows ('1714:1764/udp (KDE Connect) ALLOW IN') with one: CachyOS's "
                   "KDE Connect rules are dropped unseen (not even counted unparsed), so allows(1716) says False while "
                   "ufw lets it in")
def test_ufw_rules_whose_to_column_overflows_are_read():
    c = network.parse_ufw_status(text(CACHY, "misc/ufw-status-verbose.txt"))
    assert c.allows(1716, "udp") is not False and c.allows(1716, "tcp") is not False


def test_firewalld_fedora_workstations_zone_opens_every_high_port():
    z = network.parse_firewalld_zone(text(FEDORA, "misc/firewall-list-all.txt"),
                                     {"ssh": ["22/tcp"], "dhcpv6-client": ["546/udp"], "samba-client": ["137/udp", "138/udp"]})
    assert z.default_allows is False and z.unparsed == 0
    assert z.allows(27500, "tcp") and z.allows(22, "tcp") and z.allows(1025, "udp") and z.allows(631, "tcp") is False
    zones = text(FEDORA, "misc/firewall-cmd-zones.txt")
    assert [ln.split()[0] for ln in zones.splitlines() if ln.strip() and not ln[0].isspace()] == ["FedoraWorkstation"]


# ------------------------------------------------------------------ name resolution, NetworkManager

def test_resolved_links_and_whether_they_answer_llmnr(tmp_path):
    want = {CACHY: True, OMARCHY: None, FEDORA: False, UBUNTU: None}
    for distro in ALL:
        links = resolved_links(captured(tmp_path / distro, distro))
        assert links and "Global" in links
        up = [n for n, s in links.items() if n != "Global" and s["default_route"]]
        assert len(up) == 1 and links[up[0]]["servers"], (distro, links)
        if want[distro] is not None:
            assert resolved_announces(links, "llmnr") is want[distro], distro
    fedora = resolved_links(captured(tmp_path / "f2", FEDORA))
    assert fedora["enp1s0"]["llmnr"] == "resolve"                       # Fedora's LLMNR=resolve only asks


@pytest.mark.parametrize("distro,wifi_mac", [(FEDORA, ("stable-ssid", "connection.22-wifi-mac-addr")),
                                             (CACHY, None), (UBUNTU, None)])
def test_networkmanagers_merged_defaults(distro, wifi_mac):
    cfg = ini.parse(text(distro, "misc/networkmanager-config.txt"))
    got = nm_default(cfg, "wifi.cloned-mac-address", "wifi")
    assert (got if got != (None, None) else None) == wifi_mac
    assert nm_default(cfg, "ethernet.cloned-mac-address", "ethernet") == (None, None)


# ------------------------------------------------------------------ installed versions

@pytest.mark.parametrize("distro,tool", [(UBUNTU, "dpkg-query"), (FEDORA, "rpm"), (CACHY, "pacman"), (OMARCHY, "pacman")])
def test_installed_versions_from_the_real_package_managers(tmp_path, distro, tool):
    apps = appversions.load()
    names = sorted({p for a in apps for p in a.packages})
    listing = text(distro, f"misc/packages-{ {'dpkg-query': 'dpkg', 'rpm': 'rpm', 'pacman': 'pacman'}[tool] }.txt")
    argv = {"dpkg-query": ("dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\n", *names),
            "rpm": ("rpm", "-q", "--qf", "%{NAME}\t%{VERSION}\n", *names), "pacman": ("pacman", "-Q", *names)}[tool]
    commands = {argv: listing}
    if has(distro, "misc/flatpak-list-app-version.txt"):
        commands[("flatpak", "list", "--app", "--columns=application,version")] = text(distro, "misc/flatpak-list-app-version.txt")
    host = Host(home=tmp_path, environ={"HOME": str(tmp_path)}, runner=FakeRunner(commands), root=tmp_path, uid=1000)
    got = appversions.installed(host, apps)
    assert got, distro
    firefox = got.get("firefox")
    if distro in (FEDORA, CACHY):
        assert firefox is not None and firefox.version[0] >= 150 and firefox.source.startswith("package")
    if distro == FEDORA:            # Evince and Text Editor from Flathub, which apps.yaml doesn't list
        assert not any(i.source == "Flatpak" for i in got.values())
