# Command output samples

Fixtures for the parsers. Each file is the output of one command, used through `FakeRunner`.

| File | Source |
|---|---|
| `lsblk/mint-22-ext4-plain.json` | **Captured** on Linux Mint 22 (Cinnamon, VM): `lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS,RM,HOTPLUG` |
| `ss/mint-22.txt` | **Captured** on the same machine: `ss -tulpnH` (PIDs replaced with 1000) |
| `ip/mint-22-proton-*.txt` | **Captured** on Linux Mint 22.3 (VM) with Proton VPN's Linux app connected (2026-10-04): `ip -4/-6 route get <public address>` and `ip rule show`, addresses replaced |
| `luksdump/*`, `clevis/*` | **Hand-written** from the formats of cryptsetup 2.7 / systemd 255 and clevis 19 (salts and digests are made up): the machines below have no encrypted disk. |
| `kwallet/blank.*`, `kwallet/protected.*` | **Made by KWallet 6.30** (Arch, its own backend library: `kwallet/make-wallet.cpp`, `kwallet/build.sh`): a wallet with an empty password and one with a password, each with its `.salt`. The only entry is a made-up one. |
| `verify/*` | **Downloaded** 2026-10-04 from the projects' own servers: Linux Mint 22.3's sha256sum.txt and its .gpg (mirrors.edge.kernel.org/linuxmint), Fedora 44 Workstation's clearsigned CHECKSUM (dl.fedoraproject.org), Ubuntu 24.04's SHA256SUMS and .gpg (releases.ubuntu.com), Debian's current SHA512SUMS and .sign (cdimage.debian.org). Real signatures, for Verify a download. |
| `gpg/list-keys.txt` | **Made by GnuPG 2.4.4** (Mint 22, throwaway keyring, 2026-10-05): `gpg --with-colons --with-keygrip --fixed-list-mode --list-keys` over an Ed25519, an RSA 1024, a DSA 2048 and an expired key (made with --faked-system-time); user ids replaced, and a weak subkey and someone else's key added by hand. |
| `thumbnails/kde-dolphin-ztxt.png` | **Made by Dolphin** (KDE Gear 26.08.2, KIO's thumbnailer, Plasma 6.7, CachyOS VM, 2026-10-17) for a picture the app's test made, its text chunks kept and the image data cut: Qt writes a `Thumb::URI` longer than 40 characters, and `Software`, as zTXt. |
| `aur/tor-browser-bin-16.0.1-1.sh` | **Installed** from the AUR's tor-browser-bin 16.0.1-1 (built with makepkg on the CachyOS VM, 2026-11-11): its /usr/bin/tor-browser, which unpacks Tor Browser into ~/.local/opt/tor-browser/app and runs its start script there (GPL-3.0-or-later, its header). The tests make tor-browser-alpha-bin's from it, as that package does. |
| `cachyos-rolling/`, `omarchy-4.0.6/`, `fedora-44/`, `ubuntu-26.04/` | **Captured** 2026-11-12 by DA Privacy Kit 0.1.0b8's `--capture` (lsblk, ss, ip, misc) on four installs, with a few more read-only commands beside it, sanitised by the same Sanitiser (user and host names, disk UUIDs, MAC and IP addresses, PIDs), FAT volume serials replaced, package listings cut to the packages apps.yaml names (as the app's own query by name prints them): `lsblk/lsblk-partitions.json` (`lsblk -J -b -o ...,SIZE,PARTTYPE,UUID`, partition type GUIDs kept), `ss/ss-tunpH.txt`, `ip/*-addr.txt` and `ip/*route-all.json`, `sysfs/block.json` (the block layer's sysfs: links, the files storage.py reads, udev's ID_FS_* lines), `misc/proc-mounts.txt`, `proc-cmdline.txt`, `fstab.txt`, `resolv.conf.txt`, `findmnt.json`, `nmcli-active-name-type-device.txt`, `nmcli-uuid-type.txt`, `detect-virt.txt`, `mokutil-sb.txt`, `fstrim-timer.txt`, `uname.txt`, `flatpak-list-app-version.txt` (`--app` only), `packages-*.txt`, `snap-list-plain.txt`; as root (read-only): `misc/nft-ruleset.txt`, `misc/ufw-status-verbose.txt`, `misc/firewall-list-all.txt` (firewalld's default zone). The machines: four KVM guests on unencrypted virtio disks: CachyOS (KDE Plasma 6 on Wayland, btrfs subvolumes, zram, ufw active), Omarchy 4.0.6 (Arch, Hyprland, btrfs, a swap file and zram, ufw active), Fedora 44 Workstation (GNOME, btrfs, zram, firewalld, SELinux enforcing), Ubuntu 26.04 (GNOME, ext4, a swap file, snaps, ufw inactive). `tests/test_real_captures.py` feeds them to the parsers and the context. |
| `../images/*` | **Made by the kernel** (Linux 7.0, e2fsprogs 1.47.0, btrfs-progs 6.6.3) with `tests/images/make_images.py`, run as root on a throwaway machine, and by e2fsprogs alone with `make_noroot_images.py`: ext4 and btrfs images, each with a JSON file of facts read there (`tests/test_real_images.py`; `tests/images/live_check.py` runs the real helper as root on them, mounted read-only, on a throwaway machine). |
| everything else | **Hand-written** in each tool's format, modelled on the distro's default install. Replace with real captures. |

The aim is captured samples from Ubuntu, Fedora, Debian, Arch and openSUSE, on both
GNOME and KDE. CachyOS, Omarchy (Arch), Fedora and Ubuntu are captured (above); Debian and openSUSE, and an
encrypted Fedora or Ubuntu install (the hand-written `lsblk/fedora-40-btrfs-luks.json`, `ubuntu-24.04-luks-lvm.json`),
aren't yet. `daprivacyscanner --capture DIR` writes
sanitised samples of every command the parsers read (user and host names, addresses and PIDs
replaced) into `DIR/<distro>/`; review them, copy what is useful here under the file names above,
and update this table.
