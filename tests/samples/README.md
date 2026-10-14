# Command output samples

Fixtures for the parsers. Each file is the output of one command, used through `FakeRunner`.

| File | Source |
|---|---|
| `lsblk/mint-22-ext4-plain.json` | **Captured** on Linux Mint 22 (Cinnamon, VM): `lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINTS,RM,HOTPLUG` |
| `ss/mint-22.txt` | **Captured** on the same machine: `ss -tulpnH` (PIDs replaced with 1000) |
| `ip/mint-22-proton-*.txt` | **Captured** on Linux Mint 22.3 (VM) with Proton VPN's Linux app connected (2026-10-04): `ip -4/-6 route get <public address>` and `ip rule show`, addresses replaced |
| `luksdump/*`, `clevis/*` | **Hand-written** from the formats of cryptsetup 2.7 / systemd 255 and clevis 19 (salts and digests are made up). |
| `kwallet/blank.*`, `kwallet/protected.*` | **Made by KWallet 6.30** (Arch, its own backend library: `kwallet/make-wallet.cpp`, `kwallet/build.sh`): a wallet with an empty password and one with a password, each with its `.salt`. The only entry is a made-up one. |
| `verify/*` | **Downloaded** 2026-10-04 from the projects' own servers: Linux Mint 22.3's sha256sum.txt and its .gpg (mirrors.edge.kernel.org/linuxmint), Fedora 44 Workstation's clearsigned CHECKSUM (dl.fedoraproject.org), Ubuntu 24.04's SHA256SUMS and .gpg (releases.ubuntu.com), Debian's current SHA512SUMS and .sign (cdimage.debian.org). Real signatures, for Verify a download. |
| `gpg/list-keys.txt` | **Made by GnuPG 2.4.4** (Mint 22, throwaway keyring, 2026-10-05): `gpg --with-colons --with-keygrip --fixed-list-mode --list-keys` over an Ed25519, an RSA 1024, a DSA 2048 and an expired key (made with --faked-system-time); user ids replaced, and a weak subkey and someone else's key added by hand. |
| everything else | **Hand-written** in each tool's format, modelled on the distro's default install. Replace with real captures. |

The aim is captured samples from Ubuntu, Fedora, Debian, Arch and openSUSE, on both
GNOME and KDE. Only the Mint captures above are real so far. `daprivacyscanner --capture DIR` writes
sanitised samples of every command the parsers read (user and host names, addresses and PIDs
replaced) into `DIR/<distro>/`; review them, copy what is useful here under the file names above,
and update this table.
