# Roadmap

Work decided on and not built yet, in no particular order unless noted. Each item keeps the decisions already
made about it, so they aren't argued again when it is picked up. An item that is built is deleted here: what it
became is in the code, privacy-checks.yaml and docs/TECHNICAL.md. The same for a test: once it has been run, what
it showed goes into the code and its comments, and its line goes.

## To build

- A microVM engine for Try an app and Boxes (the 2026-10-05 design: bubblewrap for trials, a microVM for Boxes
  unless the app needs a GPU). Not built: it relies on muvm (libkrun with a desktop app's window on the host's
  screen), which is in neither CachyOS's repositories nor the AUR, and Mint 22.3 has no libkrun, muvm, crosvm,
  Firecracker or cloud-hypervisor at all (checked 2026-10-13); CachyOS has libkrun, krun and krunvm, which run
  container images without a window. `trial.ENGINES` is where it goes: an engine has `probe` and `command`. A
  QEMU engine would run on both but is a project of its own (the kernel image is root-only on Mint; the guest
  needs its own start-up and a compositor).
- Try an app: a report of what the program tried and was refused (it needs tracing: seccomp's user notification
  or ptrace); the session D-Bus through a filtering proxy (xdg-dbus-proxy) for apps that need notifications or a
  portal's file chooser; a file to open handed in through a folder like a Box's Exchange.
- What does this app keep?: the same summary for an app that is already running (attach by its cgroup, without
  starting it); system services' records about the app (the journal, the print spooler), which need the helper
  to keep root's events for the named units only.
- Boxes: refuse to revert one while its app runs ("Close X first"); a Box's settings changed without making it
  again; its own icon in the menu (the app's, not a shield).
- A whole-disk search for a string or a file the user names (the owner's idea, 2026-10-13: a backstop for leaks
  the catalogue doesn't know). Judged too big for now. What was worked out: a raw search proves presence, never
  absence (compressed, encoded and encrypted stores, and scans of documents, hide the text); on an SSD free space
  holds roughly what was deleted since the last trim; exact copies of a file can be found by hashing its blocks;
  resized pictures only among live files, by perceptual hash. A live-file search with decoders first, the raw
  scan second.
- An inventory of folders no check claims that look like records of what was opened (the same day's second
  idea): framework shapes (Chromium, QtWebEngine, WebKitGTK, Firefox-shaped profiles), PNGs carrying Thumb::URI
  outside the known thumbnail folders, database schemas, and counts of the home folder's path. `kind: info`.
- Deleted file names: read ext4's fast-commit records (the `fast_commit` feature, off by default: names in
  records of their own at the journal's end, each with its folder's inode number). The list says they aren't
  read, and Clear the journal removes them (tested on a scratch image, kernel 7.0). An inode number alone
  doesn't prove whose a record is, so they would go with the names shown only when asked for.
- On Mint with automatic login, programs started from Cinnamon have no SSH_AUTH_SOCK though the systemd user
  environment has it, so the app sees no SSH agent there: read the user manager's environment as well.
- The browser's /etc in the sandbox (`sandbox.ETC_KEPT`): whole folders are bound read-only (/etc/ssl, /etc/pki,
  /etc/xdg, /etc/alternatives, /etc/fonts), and a corporate CA in the certificate store, or /etc/xdg/autostart's
  list of installed programs, names the organisation or the install to a browser that was taken over. Trim per
  browser to what each reads (Tor Browser has its own certificate store; the Go transports read the system bundle
  for the fronted TLS: the bundle file alone, not the folder), tested by starting each without the rest.
- The browser's sandbox: a time namespace, so that when the computer was started (`/proc/stat`'s btime,
  `/proc/uptime`, and the clocks CLOCK_BOOTTIME and CLOCK_MONOTONIC) no longer links sessions before a restart (the
  page says so meanwhile, and to restart between sessions). bubblewrap has no option for one (0.9, 0.11 and 0.13,
  checked 2026-10-17); `unshare --user --map-root-user --time --boottime N --monotonic N` in front of it works, and
  Linux 7.0 applies the offset to btime and uptime too (tested); under pasta the fence's script already runs as
  root of pasta's namespace, so `unshare --time` alone there; Tor Browser's inner sandbox would inherit the outer
  one's. A random offset per start, and a probe: AppArmor's restriction on user namespaces refuses `unshare`
  without a profile, and the start goes on without it then, said.
- On Cinnamon's Wayland session the sandboxed browser's window opens without keyboard focus while the stock one
  gets it (Mullvad Browser, 2026-10-09). Find out why (an activation token the sandbox doesn't pass?), and whether
  KWin does the same.
- What starts at login: the apps the background portal lets run in the background, which the list doesn't show.
- Refreshing the bundled signing keys from inside the app, as a user-started online action (subkeys rotate, e.g.
  Tor Browser's). Until then, `packaging/check-signing-keys.py` before each release.
- Projects whose keys need a chain (Qubes: a master key certifies per-release keys) or whose pages turn scripts
  away (openSUSE): add once they can be checked properly.
- Tor or Mullvad Browser in memory: Tor Browser for 64-bit ARM once the project publishes a stable build (only
  x86_64 and i686 have a download index now).
- The RAM disk: offer to close it when the app quits, optionally close it at logout or after idle time, and a
  `--ramdisk open|close|status` terminal command.
- ~/Ephemeral: mount it with `noswap` too where the kernel has it (Linux 6.4+), as the RAM disk does.
- Right-click entries: Caja (~/.config/caja/scripts); a single running window, so a second right-click opens the
  tool in the window already open instead of a new one.
- Darktable and Shotwell export-metadata settings for app.shared_file_metadata.
- Checks that still see too little (what is left of a review of every check and its fix, 2026-10-07):
  - Sandbox permissions: remembered screen-sharing permissions in the portal's permission store (table names to be
    confirmed); Snap's connected interfaces (`camera`, `audio-record`, `removable-media`, `personal-files`), which
    have no counterpart of the Flatpak check; and whether a Flatpak's X11 socket (on an X11 session, every window
    and keystroke) or PulseAudio's (the microphone without asking; most apps have it) counts as broad access.
  - Remote content in mail: KMail isn't checked.
  - Content blocking: only uBlock Origin (and Lite) count, so a browser with another blocker is reported as
    blocking nothing.
  - File search: locate's database, which lists file names, also on drives under /mnt or /run/media where the
    distribution doesn't exclude them.
  - Secrets kept with the built-in key: Signal's `encryptedKey` under `basic_text`, and safeStorage's choice for
    Electron apps that aren't forced, which nothing on the disk shows.
  - Media players: Showtime (GNOME 49) and music players (Rhythmbox, Elisa, Strawberry). PDF readers: qpdfview,
    MuPDF and Foliate.
  - Snapshots: ones made by hand (listing them needs root: a helper action) and LVM snapshots.
  - Shell history: IPython's and Atuin's SQLite histories (the app only counts in databases, and can't clean lines
    out of them).
  - Editors: GNOME Text Editor's drafts and Sublime Text's session.
  - Telemetry: ubuntu-insights, and Chrome's "Make searches and browsing better".

## Not planned

Decided 2026-10-12:
- **Desktops.** The app is made for and tested on Cinnamon (Linux Mint) and KDE Plasma 6. GNOME, Xfce and KDE
  Plasma 5 are not tested and not supported: what the code does for them stays as it is, no tests for them are
  listed here, and the README and the manual say so.
- English only, unless someone contributes translations.
- No CI for now.
- Applying and reverting fixes stays in the window (the terminal is for testing).

## Tests still needed

What unit tests, a CachyOS VM (KDE Plasma 6.7, Wayland), a Mint PC (Cinnamon, X11, LUKS on NVMe) and containers
couldn't show. Grouped by what each needs.

### The repository made public, and the first release

- `packaging/verify-release.sh v<version>` against the published release.
- The welcome warning's "report a bug" link and the old-copy note's releases link (GitHub's "not found" page while
  the repository is private).

### By hand, in the window

- Try an app, What does this app keep? and Boxes were tried through the app's API on both machines, never by
  clicking: the three panels in the real window, start to finish; the polkit prompt for the watch; a Box started
  from the desktop's menu, and the error dialog when its program is gone.
- Try an app: the graphics card given to a trial (ticked by default) on NVIDIA and on Mesa; sound; a display of
  its own (Xephyr) on Cinnamon; an Electron AppImage and a .deb of one (their own sandbox inside the trial's);
  the observed network on CachyOS (pasta wasn't installed there when it was tried).
- What does this app keep?: a long session with a browser running beside it (does the queue overflow?); a Flatpak
  and a Snap app (matched by their scopes: only the scripted and native cases were run); an encrypted home
  (eCryptfs, fscrypt) and a home on NFS, where the watch may be refused.

- A screen reader (Orca) reads a dialog's title when it opens, and a toast; the rows of the checks list by
  keyboard.
- On KDE: the browser panel following a running browser, and the file chooser. Add a file to upload… leaves no
  entry in ~/.local/share/recently-used.xbel; in --browser mode with zenity or kdialog, the panel's note shows.
- A row whose fix doesn't cover the machine shows "no fix here" with the reason.
- Before you travel: after a scan with administrator access, each row's Fix…, Guide… and How to… opens the right
  one, and Check again shows the change.
- The clipboard fix's page: the dry run with the long evaluateScript command, the confirmation for the D-Bus clear,
  and History showing the tray step and CopyQ's setting with their hand undo.
- The browser panel with hibernation possible, OpenSnitch at log level 2 (or its list in a file), Klipper keeping
  history and crash dumps kept: each box shows, and its button opens the right guide or fix. With little free
  memory "Turn swap off for this session" is refused; zram with writeback set up shows the swap warning.
- Easy fixes with a real password prompt: one prompt for every root fix chosen; declined, the root ones are
  reported as not applied and the others applied. After a restart: the thumbnail cache empty, /tmp in memory.
- On a machine without disk encryption: "Full-disk encryption not enabled" is critical (10) on a desktop too; swap
  and hibernation findings show; the Easy fixes dialog and the finding's details start with "Until then", and each
  item's button opens the right guide.
- Nemo's actions in Nemo and Dolphin's service menus on Plasma 6, on files and on a folder; Remove metadata on a
  folder of real camera photos (large files, maker notes).
- The TempOutbox with files copied in from Nemo and Dolphin (a large copy must wait until it settles), and a move
  across filesystems leaving the only copy in Originals.
- Cinnamon: switch a system startup entry off and on again in Startup Applications. Does Cinnamon copy it into
  ~/.config/autostart, so "What starts at login" counts it as one of yours?
- ~/Ephemeral's guide: the Cryptomator step's Flatpak id (org.cryptomator.Cryptomator on Flathub), and that a
  Flatpak or AppImage install is recognised as installed.

### The browser in memory, by hand

- Tor Browser sandboxed: the padlock's circuit display shows the relays; about:support → Sandbox shows user
  namespaces in use; its Browse… dialog shows /home/user/tor-browser/Browser with To upload and Downloads, nothing
  of the real home, and can't delete an upload. On KDE (Wayland): typing, menus, the file dialog, copy and paste
  inside it; a screenshot tool run from the browser's side can't capture. The same on a wlroots desktop (Sway,
  Hyprland) if one is at hand (tried on Sway in a container only).
- Bridges: built-in meek, lines from bridges.torproject.org pasted as "Bridges I have…", and a reachable address
  that isn't a bridge (it leaves "Tor connecting" stuck, with tor's warning under it).
- Without the sandbox (a fresh ~/TempBrowser), Tor Browser's own Connect page works. After a sandboxed run,
  starting it unticked is refused with "has run in the sandbox".
- A failed start says why: Wayland with the compositor's socket gone, a bridge setting that stops tor.
- Both RAM disks open: closing one leaves the other. "Open the folder" opens To upload and Downloads in the file
  manager; a file dragged into To upload shows in the browser's Browse… dialog. Quitting the app with the browser
  still running leaves ~/TempBrowser open, and the next start shows it open.
- Xephyr ("a display of its own"): Tor Browser in it; uBlock's and NoScript's popups; a download's Save dialog and
  the print dialog take the keyboard; a non-US keyboard layout types what it should; the window can be resized.
- Sound ticked: the risk note shows, Tor Browser asks before starting with sound, a video plays (and is silent
  without). On PulseAudio itself (not PipeWire), whether a sandboxed `pactl load-module module-null-sink` is
  accepted (it is on PipeWire 1.0.5).
- View offline…: a .docx in LibreOffice and a picture in the desktop's viewer; a PDF that loads a remote image
  shows none; a Flatpak viewer on Wayland; a Flatpak viewer with home access (LibreOffice, Okular): its Open dialog
  can't see the home folder; a Snap default is refused with what to choose instead.
- KWin: whether it actually lets a sandboxed client use layer shell or input method v1 (offered; only the
  clipboard was tried). If it does, worth reporting to KDE: a security context should keep those, and data
  control, from it.
- In the GPU runs, Tor Browser in Xephyr sometimes took 2 to 3 minutes to finish the fingerprint page against 35
  seconds (2 of 4 runs, 2026-10-09); every run fetched httpbin.org through Tor, so probably that request,
  unconfirmed.

### Mullvad VPN connected

- Mullvad Browser set up for Mullvad VPN (the card's tick). Sandboxed, it was tried on KDE Plasma 6.7 (Wayland,
  2026-10-12): pages load through Zurich (am.i.mullvad.net says ch-zrh-wg-socks5-001 while the computer is in
  Stockholm), none loads with the VPN off, and a restart of the browser keeps both. Still to try: Settings shows DNS
  over HTTPS off (the profile holds network.trr.mode 5); turning the proxy off in the extension, and choosing
  another location there (one in 10.124.2.x too); the same with Local network sharing off; started unsandboxed;
  unticked and set up again: the browser starts as before, no Data/profiles.ini.

### Other distributions and kernels

- A real Ubuntu 24.04 (the restriction was only switched on, on Mint 22.3, with the same AppArmor): the panel's
  box, both profiles (bubblewrap's and pasta's), Start with the sandbox unticked; with apport, a crashed browser
  leaves no core in /var/crash. Debian: pasta's fence under its AppArmor profile for passt.
- A kernel before 6.12 (Ubuntu 24.04 with its first kernel): the panel's Landlock warning, and kern.landlock fails
  with How to… giving the HWE kernel. One where Landlock is built in but not in lsm=: How to… gives the lsm= option
  keeping the modules active now.
- The release check's How to… commands (mintupgrade, do-release-upgrade, dnf system-upgrade with DNF5), and a real
  `pro attach`.
- KDE Plasma 6.8: a clipboard a running app clears stays empty (KWin's lastSelectionOwner guard, in 6.7.90).
- X11: the clipboard empties when its owner quits, and CopyQ's command puts it back.
- qdbus's name on openSUSE (the package is qt6-tools-qdbus), and dbus-send where there is none; CopyQ's package
  name on openSUSE, and the Flatpak CopyQ's folders.
- The OpenSnitch guide on Mint (1.5.8): applying a step that restarts the daemon with its window open shows the
  done dialog at once; if OpenSnitch asks about the app's connection to 127.0.0.1, the step says so after 4
  seconds, and allowing it lets the guide update.
- Location services where GeoClue is older than 2.7 (the fix edits geoclue.conf).
- An eCryptfs home: the browser and View offline… still start with the fresh session keyring.
- Verify a download with sqv in place of gpgv on IVPN's .deb (a SHA-1 clearsigned list, which sqv may refuse): note
  what it says.
- SSH: the agent socket paths of KDE's and of systemd's ssh-agent.service (Fedora, Arch, openSUSE); an
  AuthorizedKeysFile other than the default (sshd_config is root-only on Fedora).
- GnuPG: whether pinentry's "Save in password manager" bypasses gpg-agent's cache times; the listing with
  --lock-never on a keyboxd setup.
- What starts at login: Plasma 6's place for login scripts (autostart-scripts was Plasma 5's).
- btrfs without the discard option: Deleted file names' "Trim now and check again".
- Deleted file names from the journal (tried on the Mint PC: ext4 on LVM on LUKS on NVMe, kernel 7.0,
  metadata_csum, a 1 GB journal). Still to try: a hard disk (how long reading and zeroing the journal take);
  an ext4 made before 2016 or without metadata_csum (everything counted, nothing listed by folder); a real
  filesystem with fast_commit on; a second ext4 disk (every folder the user can open); /home shared by two
  accounts (one never sees the other's names in the list); a kernel before 5.14 (the page says the journal
  can't be cleared); a folder emptied from the trash in Nemo and Dolphin (listed as a deleted folder).
- A filesystem an older kernel left names in (made and used on Linux 5.12 or before): fillers in a small and in an
  indexed folder (the inode unchanged, how many rounds), "Rebuild instead…" after the cap, a rebuild with an ACL
  and an SELinux label (Fedora) and while a program saves into the folder; "Quit X first" with Syncthing,
  Nextcloud's client or VS Code watching, a note only for Nemo; a Flatpak app given the folder stops its rebuild.

### Accounts and apps

- br.account_sync with Brave Sync and Vivaldi Sync set up: both read as end-to-end encrypted (a risk at 2), and
  the sync keys in their Preferences are the ones the check reads (`sync.has_setup_completed`).
- br.https_only in Vivaldi and Edge, set in their own settings pages and read back (Chromium and Brave were).
- Signal Desktop with a keyring running and its key in plain text in config.json: it moves it to encryptedKey at
  the next start, as the remedy says.
- Site permissions: Chromium's exception keys on current releases (geolocation may move to
  geolocation_with_options), Brave's and Vivaldi's settings pages, and that Firefox with "Block new requests" still
  lets a site be allowed from the address bar.
- VS Code: `workbench.localHistory.enabled: false` stops new Local History entries (Code - OSS 1.138 made
  `User/History`; the entries and the setting are still to be seen working).
- The disk cache check: the cache folders of LibreWolf, Waterfox, Zen, Floorp and Snap Firefox.
- Recent files: a folder in place of a Flatpak GTK app's `recently-used.xbel` (in `~/.var/app/ID/data`) stops it as
  it stops native GTK.
- Zeitgeist itself: the user's own service files that run `/bin/false` keep it from starting again (tried with a
  dummy service on dbus-broker; Zeitgeist isn't packaged for Arch).
- Remote desktop: the process names of Chrome Remote Desktop, NoMachine and Sunshine, seen running.
- NetworkManager 1.52 as the first version that reads the hostname default (tested on 1.58).
- The large downloads: a Qubes 4.3 ISO, a Whonix or Kicksecure image, a Manjaro or EndeavourOS ISO and a CachyOS
  ISO, each with its signature beside it: "Verified". A Garuda or Bazzite ISO with its checksum file: "Not damaged,
  but not verified", saying the project signs nothing.

### Hardware

- A network with public IPv6 addresses: Mullvad Browser can't open the router's page by its global address, nor
  reach another device on the same network; sites over IPv6 still load.
- Wi-Fi: the MAC address default (stable) on a real driver, and on one that can't change its address if one is to
  hand; with GeoClue's Wi-Fi lookup off, an app asking for the location (`/usr/libexec/geoclue-2.0/demos/where-am-i`)
  gets none or only a coarse one, and nothing reaches the lookup service (`sudo ss -tp` while it asks).
- Bluetooth hidden with a generic name, then pairing headphones (from the computer) and a phone (making it
  discoverable in the Bluetooth settings while pairing).
- A dual-boot machine: unused partitions with Windows beside it (BitLocker off and on), an OEM install's recovery
  partitions, an MBR disk (PARTTYPE 0x27, 0xef).
- AMD graphics (radeonsi): the browsers' fingerprint in the sandbox against the stock start script (which WebGL
  value differs there). "Allow the graphics card" on Intel or AMD: Mesa draws through the render node alone, and
  WebGL then matches the stock browser's (only NVIDIA was tested).
- A camera and a microphone (Tools → Camera and microphone, while the view is open):
  - a video call in Firefox and in Chromium or Brave: the camera listed as open by the browser (directly, or
    through PipeWire's camera portal), the microphone as "now";
  - the camera idle: does PipeWire or WirePlumber keep /dev/video* open anyway (shown as held by the sound server,
    with nothing receiving)? If it does, the note "keeps a device open for a few seconds after the last stream
    stops" is wrong for cameras;
  - a screen share on KDE (Wayland) from a browser or OBS: listed as "the screen"; if not, note the producing
    program's name and its node.name (`pw-dump`) for `SCREEN_PRODUCERS`;
  - a recorder of the computer's own sound (OBS desktop audio): listed as "what the computer plays";
  - a system with PulseAudio and no PipeWire, if one is at hand (`pactl -f json` needs pactl 16+).
- USB sticks (Before you hand over a drive):
  - one used on macOS and on Windows: .DS_Store, ._ files, .Spotlight-V100, .fseventsd, .Trashes, System Volume
    Information and $RECYCLE.BIN found, deleted, and the stick still reads on both after;
  - one with files in its trash (.Trash-1000), thumbnails (.sh_thumbnails), a LibreOffice lock file;
  - an ext4 stick with another account's .Trash-UID: skipped and counted, not an error;
  - an image open from the stick's trash in an image viewer: "Close … first";
  - an internal disk or the home's filesystem never offered; a read-only mount offered but not choosable.
- Drives (Retire a drive; reading only, except on a spare one):
  - "Read what the drive says" on a SATA hard disk and a SATA SSD (with and without smartmontools): the frozen
    state and erase times against `sudo hdparm -I /dev/sdX` (NVMe was compared with nvme-cli); after `systemctl
    suspend` and waking, a frozen drive reads as not frozen;
  - a USB stick, an SD card in a built-in reader (mmcblk) and in a USB reader, an external USB hard disk and an
    external USB SSD: the kind each is shown as (sticks often say "rotational"), and the guide's text;
  - a mounted second drive gets "Unmount it" first; an external LUKS drive unlocked and mounted from the file
    manager gets "udisksctl unmount" for the volume, then "cryptsetup close"; one with LVM inside LUKS gets
    "vgchange -an" between them; a machine with eMMC (mmcblk0boot0/1, rpmb) lists the chip once; a btrfs RAID1
    root makes both drives refused;
  - the commands themselves, run once on a spare drive of each kind: nvme-cli's `sanitize --sanact` and `format
    --ses`, `hdparm --security-erase` on a hard disk, `dd` then `cmp` reporting EOF; and whether ATA security
    through a USB adapter (refused here) works on any;
  - the drive-managed SMR model list (`DM_SMR` in tools/retire.py) against the makers' current lists.
