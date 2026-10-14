import os

import pytest

from daprivacyscanner import blockdev, network
from daprivacyscanner.catalogue import CONTEXT_KEYS
from daprivacyscanner.context import (detect_autologin, detect_context, detect_device, detect_exposed_services,
                                    detect_fde, detect_hibernation, detect_multi_user, detect_session,
                                    detect_tpm_unlock_no_pin)
from daprivacyscanner.host import CommandResult

from conftest import make_host, sample, skip_if_root

LSBLK = ("lsblk", "-J", "-o", blockdev.COLUMNS)
LSBLK_OLD = ("lsblk", "-J", "-o", blockdev.COLUMNS_OLD)


def devices(name):
    return blockdev.parse_lsblk(sample(f"lsblk/{name}"))


# ------------------------------------------------------------------ fde

@pytest.mark.parametrize("name, expected, unencrypted", [
    ("mint-22-ext4-plain.json", "none", ["/"]),
    ("ubuntu-24.04-luks-lvm.json", "full", []),           # snap squashfs loops don't count
    ("fedora-40-btrfs-luks.json", "full", []),            # the USB stick doesn't count
    ("debian-12-partial.json", "partial", ["/srv/data"]),
    ("opensuse-tw-btrfs-plain.json", "none", ["/"]),
    ("arch-zfs-root.json", None, []),                     # / isn't visible: unknown, not 'none'
    ("util-linux-2.32-mountpoint.json", "full", []),      # old column names and "0"/"1" flags
])
def test_fde(name, expected, unencrypted):
    v = detect_fde(devices(name))
    assert v.value == expected
    assert [e.value for e in v.evidence if e.label == "Not encrypted"] == unencrypted


@pytest.mark.parametrize("mount, lsattr, expected, method", [
    ("ecryptfs", "", "home", "eCryptfs"),                                 # mounted over the home folder at login
    ("ext4", "----------E---e----------- {home}\n", "home", "fscrypt"),     # the filesystem's own encryption
    ("ext4", "--------------e----------- {home}\n", "none", None),
])
def test_home_folder_encrypted_on_a_plain_disk(tmp_path, mount, lsattr, expected, method):
    host = make_host(tmp_path)
    home = str(host.home)
    src = "/home/.ecryptfs/alice/.Private" if mount == "ecryptfs" else "/dev/sda2"
    host.sys_path("/proc").mkdir(parents=True, exist_ok=True)
    host.sys_path("/proc/mounts").write_text(f"/dev/sda2 / ext4 rw 0 0\n{src} {home} {mount} rw 0 0\n")
    host.runner.outputs[("lsattr", "-d", home)] = CommandResult((), 0, lsattr.format(home=home))
    v = detect_fde(devices("mint-22-ext4-plain.json"), host=host)
    assert v.value == expected
    assert (method is None) or method in {e.label: e.value for e in v.evidence}["Home folder"]


def test_home_folder_on_its_own_luks_volume(tmp_path):
    """A plain / with /home on dm-crypt (a LUKS /home partition, or systemd-homed's image)."""
    data = {"blockdevices": [{"name": "sda", "type": "disk", "children": [
        {"name": "sda1", "type": "part", "fstype": "ext4", "mountpoints": ["/"]},
        {"name": "sda2", "type": "part", "fstype": "crypto_LUKS", "children": [
            {"name": "home", "type": "crypt", "fstype": "ext4", "mountpoints": ["/home"]}]}]}]}
    host = make_host(tmp_path)
    devs = blockdev.parse_lsblk(__import__("json").dumps(data))
    v = detect_fde(devs, host=host)
    assert v.value == "none"                                            # the fixture's home isn't under /home
    host.home = __import__("pathlib").Path("/home/alice")
    assert detect_fde(devs, host=host).value == "home"


def test_ostree_root_is_read_from_sysroot():
    """Silverblue and Kinoite: / is a composefs overlay, the real root is mounted at /sysroot."""
    data = {"blockdevices": [{"name": "nvme0n1", "type": "disk", "children": [
        {"name": "nvme0n1p3", "type": "part", "fstype": "crypto_LUKS", "children": [
            {"name": "luks-1", "type": "crypt", "fstype": "btrfs",
             "mountpoints": ["/sysroot", "/var", "/sysroot/ostree/deploy/fedora/var", "/etc"]}]}]}]}
    assert detect_fde(blockdev.parse_lsblk(__import__("json").dumps(data))).value == "full"


def test_internal_sata_hotplug_isnt_removable_usb_is():
    """SATA ports report HOTPLUG when the firmware allows hot-swapping, for internal drives too."""
    data = {"blockdevices": [
        {"name": "sda", "type": "disk", "hotplug": True, "tran": "sata", "children": [
            {"name": "sda1", "type": "part", "fstype": "ext4", "mountpoints": ["/data"]}]},
        {"name": "sdb", "type": "disk", "hotplug": True, "tran": "usb", "children": [
            {"name": "sdb1", "type": "part", "fstype": "exfat", "mountpoints": ["/media/alice/STICK"]}]},
        {"name": "sdc", "type": "disk", "hotplug": True, "children": [{"name": "sdc1", "type": "part"}]}]}
    devs = {d.name: d for d in blockdev.parse_lsblk(__import__("json").dumps(data))}
    assert not devs["sda1"].removable and devs["sdb1"].removable and devs["sdb1"].transport == "usb"
    assert devs["sdc1"].removable                                      # transport unknown: HOTPLUG decides


def test_crypt_ancestry_through_lvm():
    devs = {d.name: d for d in devices("ubuntu-24.04-luks-lvm.json")}
    assert devs["ubuntu--vg-ubuntu--lv"].encrypted
    assert not devs["nvme0n1p2"].encrypted


def test_removable_is_inherited_from_the_disk():
    devs = {d.name: d for d in devices("util-linux-2.32-mountpoint.json")}
    assert devs["sdc1"].removable and not devs["sda1"].removable


def test_lsblk_falls_back_to_old_columns(tmp_path):
    host = make_host(tmp_path, commands={
        LSBLK: CommandResult(LSBLK, 1, "", "lsblk: unknown column: MOUNTPOINTS"),
        LSBLK_OLD: sample("lsblk/util-linux-2.32-mountpoint.json"),
    })
    assert detect_context(host)["fde"] == "full"


def test_fde_unknown_without_lsblk(tmp_path):
    ctx = detect_context(make_host(tmp_path))
    assert ctx["fde"] is None and "not installed" in ctx.values["fde"].note
    assert ctx["tpm_unlock_no_pin"] is None


# ------------------------------------------------------------------ device

@pytest.mark.parametrize("files, commands, expected", [
    ({"/sys/class/dmi/id/chassis_type": "10\n"}, {}, "laptop"),
    ({"/sys/class/dmi/id/chassis_type": "3\n"}, {}, "desktop"),
    ({"/sys/class/dmi/id/chassis_type": "1\n"}, {"hostnamectl chassis": "server\n"}, "desktop"),
    ({"/sys/class/dmi/id/chassis_type": "1\n"}, {"hostnamectl chassis": "vm\n"}, None),
    ({"/sys/class/dmi/id/chassis_type": "2\n"}, {"hostnamectl chassis": "convertible\n"}, "laptop"),
    ({"/sys/class/dmi/id/chassis_type": "2\n", "/sys/class/power_supply/BAT0/type": "Battery\n"}, {}, "laptop"),
    # a wireless mouse's battery is not the system's
    ({"/sys/class/dmi/id/chassis_type": "2\n", "/sys/class/power_supply/hidpp_battery_0/type": "Battery\n",
      "/sys/class/power_supply/hidpp_battery_0/scope": "Device\n"}, {}, None),
    ({}, {}, None),
])
def test_device(tmp_path, files, commands, expected):
    assert detect_device(make_host(tmp_path, files=files, commands=commands)).value == expected


# ------------------------------------------------------------------ multi_user

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""


@pytest.mark.parametrize("extra, expected", [
    ("", False),
    ("bob:x:1001:1001::/home/bob:/usr/bin/zsh\n", True),
    ("svc:x:1002:1002::/srv:/usr/sbin/nologin\n", False),
    ("guest:x:1003:1003::/home/guest:/bin/false\n", False),
    ("old:x:1004:1004::/home/old:\n", True),             # an empty shell field means /bin/sh
])
def test_multi_user(tmp_path, extra, expected):
    host = make_host(tmp_path, commands={"getent passwd": PASSWD + extra})
    assert detect_multi_user(host).value is expected


def test_multi_user_falls_back_to_etc_passwd_and_login_defs(tmp_path):
    host = make_host(tmp_path, files={"/etc/passwd": PASSWD + "bob:x:501:501::/home/bob:/bin/bash\n",
                                      "/etc/login.defs": "UID_MIN 500\nUID_MAX 60000\n"})
    v = detect_multi_user(host)
    assert v.value is True and "/etc/passwd" in v.note and "500" in v.note


# ------------------------------------------------------------------ session

@pytest.mark.parametrize("env, expected", [
    ({"XDG_SESSION_TYPE": "wayland"}, "wayland"),
    ({"XDG_SESSION_TYPE": "x11", "WAYLAND_DISPLAY": "wayland-0"}, "x11"),
    ({"XDG_SESSION_TYPE": "tty", "WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, "wayland"),
    ({"DISPLAY": ":0"}, "x11"),
    ({"XDG_SESSION_TYPE": "tty"}, None),
])
def test_session(tmp_path, env, expected):
    assert detect_session(make_host(tmp_path, env=env)).value == expected


# ------------------------------------------------------------------ hibernation

SWAPS_FILE = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swap/swapfile                          file\t\t16777212\t0\t\t-2\n"
SWAPS_ZRAM = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/zram0                              partition\t8388604\t\t0\t\t100\n"


def power(state="freeze mem disk", disk="[platform] shutdown reboot suspend test_resume", swaps=SWAPS_FILE,
          cmdline="BOOT_IMAGE=/vmlinuz root=UUID=x ro quiet resume=UUID=abcd", resume="0:0",
          image_size=str(6 * 2**30)):
    f = {"/sys/power/state": state, "/sys/power/disk": disk, "/proc/swaps": swaps, "/proc/cmdline": cmdline,
         "/sys/power/resume": resume, "/sys/power/image_size": image_size}
    return {k: v for k, v in f.items() if v is not None}


@pytest.mark.parametrize("files, commands, expected", [
    (power(), {}, True),
    (power(swaps=SWAPS_ZRAM), {}, False),                                     # zram can't hold an image
    (power(image_size=str(32 * 2**30)), {}, False),                           # swap too small
    (power(disk="[disabled]"), {}, False),                                    # lockdown
    (power(state="freeze mem"), {}, False),
    (power(cmdline="ro quiet", resume="259:3"), {}, True),
    (power(cmdline="ro quiet"), {}, False),
    ({**power(cmdline="ro quiet"), "/sys/firmware/efi/x": ""}, {"systemctl --version": "systemd 255 (255.4)\n"}, True),
    ({**power(cmdline="ro quiet"), "/sys/firmware/efi/x": ""}, {"systemctl --version": "systemd 254 (254.1)\n"}, False),
    ({}, {}, None),
])
def test_hibernation(tmp_path, files, commands, expected):
    assert detect_hibernation(make_host(tmp_path, files=files, commands=commands)).value is expected


# ------------------------------------------------------------------ tpm_unlock_no_pin

def test_tpm_false_without_encrypted_volumes(tmp_path):
    v = detect_tpm_unlock_no_pin(make_host(tmp_path), devices("mint-22-ext4-plain.json"))
    assert v.value is False


def test_tpm_unknown_without_root_when_volumes_are_encrypted(tmp_path):
    host = make_host(tmp_path, files={"/etc/crypttab": "luks-0f2c none none discard,tpm2-device=auto\n"})
    v = detect_tpm_unlock_no_pin(host, devices("fedora-40-btrfs-luks.json"))
    assert v.value is None
    assert ("Volumes with tpm2-device= in /etc/crypttab", 1) in [(e.label, e.value) for e in v.evidence]


@skip_if_root
def test_tpm_unreadable_crypttab_is_partial(tmp_path):
    host = make_host(tmp_path, files={"/etc/crypttab": "x\n"})
    os.chmod(host.sys_path("/etc/crypttab"), 0)
    v = detect_tpm_unlock_no_pin(host, devices("fedora-40-btrfs-luks.json"))
    assert v.value is None and v.partial


# ------------------------------------------------------------------ autologin

DM = "/etc/systemd/system/display-manager.service"


@pytest.mark.parametrize("files, unit, expected", [
    ({"/etc/gdm3/custom.conf": "[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=alice\n"}, "gdm3", True),
    ({"/etc/gdm3/custom.conf": "[daemon]\n# AutomaticLoginEnable=true\n"}, "gdm3", False),
    ({"/etc/gdm/custom.conf": "[daemon]\nTimedLoginEnable=true\nTimedLogin=alice\n"}, "gdm", True),
    ({"/etc/gdm3/daemon.conf": "[daemon]\nAutomaticLoginEnable=true\n"}, "gdm3", True),   # Debian's file
    ({"/etc/sddm.conf.d/kde_settings.conf": "[Autologin]\nRelogin=false\nSession=plasma\nUser=alice\n"}, "sddm", True),
    ({"/etc/sddm.conf.d/kde_settings.conf": "[Autologin]\nUser=\n"}, "sddm", False),
    # a later layer turns it off again
    ({"/usr/lib/sddm/sddm.conf.d/default.conf": "[Autologin]\nUser=alice\n", "/etc/sddm.conf": "[Autologin]\nUser=\n"},
     "sddm", False),
    # Plasma Login Manager (KDE's fork of SDDM): SDDM's key, in its own files
    ({"/etc/plasmalogin.conf": "[Autologin]\nSession=plasma\nUser=alice\n"}, "plasmalogin", True),
    ({"/etc/plasmalogin.conf": "[Autologin]\nSession=plasma\n"}, "plasmalogin", False),
    ({"/usr/lib/plasmalogin/plasmalogin.conf.d/10-x.conf": "[Autologin]\nUser=alice\n",
      "/etc/plasmalogin.conf.d/99-daprivacyscanner-autologin.conf": "[Autologin]\nUser=\n"}, "plasmalogin", False),
    ({"/etc/sddm.conf": "[Autologin]\nUser=alice\n"}, "plasmalogin", False),
    ({"/etc/lightdm/lightdm.conf": "[Seat:*]\nautologin-user=alice\n"}, "lightdm", True),
    ({"/etc/lightdm/lightdm.conf.d/70-linuxmint.conf": "[SeatDefaults]\nautologin-user=alice\n"}, "lightdm", True),
    ({"/etc/lightdm/lightdm.conf": "[Seat:*]\n#autologin-user=alice\n"}, "lightdm", False),
    ({"/usr/share/lightdm/lightdm.conf.d/50-guest.conf": "[Seat:*]\nautologin-guest=true\n"}, "lightdm", True),
    ({"/etc/lightdm/lightdm.conf": "[Seat:*]\nautologin-guest=false\n"}, "lightdm", False),
    # the app's own override, after a packaged file that set it
    ({"/usr/share/lightdm/lightdm.conf.d/50-guest.conf": "[Seat:*]\nautologin-user=alice\n",
      "/etc/lightdm/lightdm.conf.d/99-daprivacyscanner-autologin.conf": "[Seat:*]\nautologin-user=\nautologin-guest=false\n"},
     "lightdm", False),
    ({"/etc/greetd/config.toml": "[default_session]\ncommand='tuigreet'\n[initial_session]\ncommand='sway'\nuser='alice'\n"},
     "greetd", True),
    ({"/etc/greetd/config.toml": "[default_session]\ncommand='tuigreet'\n"}, "greetd", False),
    # an inactive display manager's config doesn't count
    ({"/etc/sddm.conf": "[Autologin]\nUser=alice\n"}, "gdm3", False),
    # no display-manager.service: every known one is checked
    ({"/etc/sddm.conf": "[Autologin]\nUser=alice\n"}, None, True),
    ({"/etc/systemd/system/getty@tty1.service.d/override.conf":
      "[Service]\nExecStart=\nExecStart=-/sbin/agetty -o '-p -f -- \\\\u' --noclear --autologin alice %I $TERM\n"},
     "gdm3", True),
    ({}, "lightdm", False),
])
def test_autologin(tmp_path, files, unit, expected):
    links = {DM: f"/lib/systemd/system/{unit}.service"} if unit else {}
    assert detect_autologin(make_host(tmp_path, files=files, links=links)).value is expected


@skip_if_root
def test_autologin_unreadable_config_is_unknown(tmp_path):
    host = make_host(tmp_path, files={"/etc/sddm.conf.d/kde_settings.conf": "[Autologin]\nUser=alice\n"},
                     links={DM: "/usr/lib/systemd/system/sddm.service"})
    os.chmod(host.sys_path("/etc/sddm.conf.d/kde_settings.conf"), 0)
    v = detect_autologin(host)
    assert v.value is None and v.partial


# ------------------------------------------------------------------ exposed_services

@pytest.mark.parametrize("name, expected, ports", [
    ("mint-22.txt", True, ["22/tcp", "3389/tcp"]),
    ("ubuntu-24.04-localhost-only.txt", False, []),
    # LLMNR (5355) listens on all interfaces under systemd-resolved defaults
    ("fedora-40.txt", True, ["5355/tcp", "5355/udp"]),
])
def test_exposed_services(tmp_path, name, expected, ports):
    host = make_host(tmp_path, commands={network.SS_ARGS: sample(f"ss/{name}")},
                     files={"/proc/sys/net/ipv4/ip_local_port_range": "32768\t60999\n"})
    v = detect_exposed_services(host)
    assert v.value is expected
    assert [e.value.split(" ")[0] for e in v.evidence if e.label == "Listening"] == ports


def test_ss_parsing_details():
    s = network.parse_ss(sample("ss/fedora-40.txt"))
    scoped = [x for x in s if x.interface]
    assert {x.interface for x in scoped} == {"lo", "wlp0s20f3"}
    assert not any(x.wildcard for x in scoped)
    assert next(x for x in s if x.port == 41641).process == "tailscaled"


def test_exposed_services_unknown_without_ss(tmp_path):
    assert detect_exposed_services(make_host(tmp_path)).value is None


# ------------------------------------------------------------------ all together

def test_detect_context_fills_every_key(tmp_path):
    host = make_host(tmp_path, commands={LSBLK: sample("lsblk/fedora-40-btrfs-luks.json"),
                                         network.SS_ARGS: sample("ss/ubuntu-24.04-localhost-only.txt"),
                                         "getent passwd": PASSWD},
                     files={"/sys/class/dmi/id/chassis_type": "10\n", **power(swaps=SWAPS_ZRAM)},
                     env={"XDG_SESSION_TYPE": "wayland", "XDG_CURRENT_DESKTOP": "GNOME"},
                     links={DM: "/usr/lib/systemd/system/gdm.service"})
    ctx = detect_context(host)
    assert set(ctx.values) == set(CONTEXT_KEYS)
    assert ctx.vars() == {"fde": "full", "virtualization": "none", "device": "laptop", "multi_user": False, "session": "wayland",
                          "hibernation": False, "tpm_unlock_no_pin": None, "autologin": False,
                          "exposed_services": False, "vpn_active": False, "ipv6_global": False}


IF_INET6 = ("00000000000000000000000000000001 01 80 10 80       lo\n"
            "fe800000000000000a0027fffe123456 02 40 20 80   wlp2s0\n"
            "fd001234000000000000000000000001 02 40 00 00   wlp2s0\n")


def test_ipv6_global(tmp_path):
    from daprivacyscanner.context import detect_ipv6_global
    assert detect_ipv6_global(make_host(tmp_path, files={"/proc/net/if_inet6": IF_INET6})).value is False
    v = detect_ipv6_global(make_host(tmp_path / "b", files={"/proc/net/if_inet6": IF_INET6 +
                           "2a0212340000000012345678abcdef01 02 40 00 00   wlp2s0\n"}))
    assert v.value is True and v.evidence[0].value == "wlp2s0" and v.notes


def test_vpn_active(tmp_path):
    from daprivacyscanner.context import detect_vpn_active
    host = make_host(tmp_path, files={"/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\nINTERFACE=wg0\n",
                                      "/sys/class/net/wlp2s0/uevent": "DEVTYPE=wlan\n",
                                      "/proc/net/route": "Iface\tDestination\nwg0\t00000000\t00000000\n"})
    v = detect_vpn_active(host)
    assert v.value is True and {e.label: e.value for e in v.evidence}["Carrying internet traffic"] == "wg0"
    assert detect_vpn_active(make_host(tmp_path / "b")).value is False


# wg-quick, NetworkManager's WireGuard and VPN apps send everything into the tunnel with policy
# routing; the main table (/proc/net/route) still has its default route on the LAN
LAN_ROUTE = "Iface\tDestination\nwlp2s0\t00000000\t0101A8C0\n"
VIA_WG = "1.1.1.1 dev wg0 table 51820 src 10.64.0.2 uid 1000 \n    cache \n"
VIA_LAN = "1.1.1.1 via 192.168.1.1 dev wlp2s0 src 192.168.1.20 uid 1000 \n    cache \n"
NO_V6 = CommandResult(("ip",), 2, "", "RTNETLINK answers: Network is unreachable\n")


def test_vpn_active_follows_policy_routing(tmp_path):
    from daprivacyscanner.context import detect_vpn_active
    files = {"/sys/class/net/wg0/uevent": "DEVTYPE=wireguard\n", "/sys/class/net/wlp2s0/uevent": "DEVTYPE=wlan\n",
             "/proc/net/route": LAN_ROUTE}
    host = make_host(tmp_path, files=files, commands={"ip -4 route get 1.1.1.1": VIA_WG,
                                                      "ip -6 route get 2606:4700:4700::1111": NO_V6})
    v = detect_vpn_active(host)
    assert v.value is True and {e.label: e.value for e in v.evidence}["Carrying internet traffic"] == "wg0"
    split = make_host(tmp_path / "b", files=files, commands={"ip -4 route get 1.1.1.1": VIA_LAN,
                                                             "ip -6 route get 2606:4700:4700::1111": NO_V6})
    v = detect_vpn_active(split)
    assert v.value is False and v.notes[0].title == "A tunnel is up but carries only some traffic"


def test_tap_devices_of_virtual_machines_are_not_vpns(tmp_path):
    from daprivacyscanner.network import vpn_links
    host = make_host(tmp_path, files={"/sys/class/net/vnet0/tun_flags": "0x1002\n",       # libvirt: TAP
                                      "/sys/class/net/tailscale0/tun_flags": "0x1001\n",  # TUN
                                      "/sys/class/net/tun0/tun_flags": "0x1001\n"})
    assert vpn_links(host) == ["tailscale0", "tun0"]


def test_a_crashing_detector_does_not_stop_the_scan(tmp_path, monkeypatch):
    import daprivacyscanner.context as c

    monkeypatch.setattr(c, "detect_session", lambda host: 1 / 0)
    ctx = detect_context(make_host(tmp_path))
    assert ctx["session"] is None and "ZeroDivisionError" in ctx.values["session"].note


def test_proton_full_tunnel_from_a_real_capture(tmp_path):
    """Captured on Mint 22.3 with Proton VPN's Linux app (2026-10-04): its rules send everything to its own
    table, the main table's default route stays on the LAN."""
    from daprivacyscanner.context import detect_vpn_active
    files = {"/sys/class/net/proton0/uevent": "DEVTYPE=wireguard\n", "/sys/class/net/pvpnksintrf0/uevent": "",
             "/sys/class/net/enp6s18/uevent": "", "/proc/net/route": "Iface\tDestination\nenp6s18\t00000000\t0101A8C0\n"}
    host = make_host(tmp_path, files=files, commands={
        "ip -4 route get 1.1.1.1": sample("ip/mint-22-proton-route-get-4.txt"),
        "ip -6 route get 2606:4700:4700::1111": sample("ip/mint-22-proton-route-get-6.txt")})
    assert network.internet_route(host, 4) == network.internet_route(host, 6) == {"proton0"}
    v = detect_vpn_active(host)
    assert v.value is True and {e.label: e.value for e in v.evidence}["VPN interfaces"] == "proton0"


def test_a_vpn_address_inside_the_tunnel_is_not_a_public_ipv6_address(tmp_path):
    from daprivacyscanner.context import detect_ipv6_global
    tunnel = "2a07b944000000000000000000020002 06 80 00 80   proton0\n"
    host = make_host(tmp_path, files={"/sys/class/net/proton0/uevent": "DEVTYPE=wireguard\n",
                                      "/proc/net/if_inet6": IF_INET6 + tunnel})
    v = detect_ipv6_global(host)
    assert v.value is False and v.note.endswith("outside the VPN tunnel")
    v = detect_ipv6_global(make_host(tmp_path / "b", files={
        "/sys/class/net/proton0/uevent": "DEVTYPE=wireguard\n",
        "/proc/net/if_inet6": IF_INET6 + tunnel + "2a0212340000000012345678abcdef01 02 40 00 00   wlp2s0\n"}))
    assert v.value is True and v.evidence[0].value == "wlp2s0"
