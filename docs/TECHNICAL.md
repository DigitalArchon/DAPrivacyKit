# DA Privacy Kit: technical implementation

This document explains how DA Privacy Kit works inside: its processes and trust boundaries, how a
scan and a fix run, and, in detail, what the advanced tools actually do on the machine. It is written for
people who want to audit the app, reason about what it protects against, or work on it.

For how to use the app, see [MANUAL.md](MANUAL.md). The rules the design is held to are listed first
([Design rules](#design-rules): the code's comments cite them by number), and the check catalogue is
[privacy-checks.yaml](../privacy-checks.yaml); where this document and the code differ, the code is right and
this document is out of date.

Paths below are relative to `src/daprivacyscanner/` unless they start with `/` or `~`.

---

## Contents

[Design rules](#design-rules), then:

1. [Processes and trust boundaries](#1-processes-and-trust-boundaries)
2. [The local web server](#2-the-local-web-server)
3. [The scan engine](#3-the-scan-engine)
4. [Fixes, guides and the undo log](#4-fixes-guides-and-the-undo-log)
5. [The privileged helper](#5-the-privileged-helper)
6. [Network access](#6-network-access)
7. [Tor or Mullvad Browser in memory](#7-tor-or-mullvad-browser-in-memory)
8. [The RAM disk](#8-the-ram-disk)
9. [Verify a download](#9-verify-a-download)
10. [The TRIM test](#10-the-trim-test)
11. [Deleted file names](#11-deleted-file-names)
12. [Drives: hand over and retire](#12-drives-hand-over-and-retire)
13. [The other tools](#13-the-other-tools)
14. [What the app stores](#14-what-the-app-stores)
15. [Testing](#15-testing)

---

## Design rules

Ten rules the scan and the fixes are held to, and five for the tools. The sections after them say how each is
carried out.

1. **Context first.** What the machine is (disk encryption, a virtual machine, a laptop or a desktop, several
   accounts, the session, hibernation, automatic login, services reachable from outside, a VPN, a public IPv6
   address) is worked out before any other check runs. A check's severity here is its base severity as the last
   matching modifier changes it, and a risk is always rated below the problem it could become. Severity 0 means
   it doesn't apply. What can't be determined is unknown, never guessed and never taken for the benign case: the
   severity is then the range of what every value it could have would give, ranked at its highest, and the result
   says what would settle it ([section 3](#3-the-scan-engine)).
2. **One result model.** Every check answers with a status (pass, fail, warn, unknown, not applicable, error), its
   severity on this machine, its evidence (paths, values and counts, never secrets, account addresses or file
   contents), its kind and whether it can be fixed here. A finding is a failure or a warning, above severity 0,
   of a check whose kind is `finding`: caches and histories (`hygiene`) and inventories (`info`) are listed, never
   counted. What couldn't be checked is never hidden and never a pass.
3. **Privilege separation.** The app and every `scope: user` check run as the user; the app is never run as root.
   Root work goes through a small helper started with pkexec, which offers only named actions, checks every
   argument itself, reads only the files on its list and never writes content the app sends. Declined, system
   checks say what they couldn't see ([section 5](#5-the-privileged-helper)). What it reads beyond files is for the
   caller alone: a watch of one app returns what the caller's own processes did, never another account's. A
   session is always the installed, root-owned helper (the fallback only installs it, running the bytes whose hash
   the app gave), on a socket pair, ending itself when unused; what can't be undone, what returns other accounts'
   data, installing or removing the helper and turning remote access back on ask for the password again, each
   time. Every change is journalled before it is made.
4. **Read-only by default.** A scan changes nothing, the user's home folder included: programs that write as they read (dnf5 copying the system's metadata, flatpak making an installation) get folders of their own in the runtime folder, removed at once, and nothing a scan runs starts a socket-activated service.
5. **Fix tiers.** `auto`: applied after one confirmation, and reversible. `guided`: step by step, each step
   explained with its side effects and confirmed on its own. `advice`: explained, with the commands for this
   machine where that helps; the app never makes the change. `feature`: an optional set-up, not a finding
   ([section 4](#4-fixes-guides-and-the-undo-log)).
6. **The value before is kept.** Before a setting or a file is changed, what was there goes into the undo log, so
   every applied fix can be reverted from History. The entry is written, and on the disk, before the first step and
   added to as each step completes, so a fix cut short (a crash, a power cut) is still in History. Reverts go newest
   first where two changes touch the same thing, and a file edited since gets only the fix's lines back. Deleting
   caches and histories is the exception: it can't be undone, so it is confirmed on its own. The log is a record too:
   it never holds deleted paths or the names of Wi-Fi networks.
7. **Dry run.** Every fix can show exactly what it would do, and what is shown is what is done.
8. **No secure-delete claims.** No `shred`, no overwriting of files on a disk: on SSDs and copy-on-write
   filesystems it promises what it can't keep. Encryption is what protects deleted data. Two exceptions, where
   overwriting does what it says: a RAM disk's files are overwritten before it is closed (its pages are memory),
   and Retire a drive gives, and never runs, the commands that overwrite a whole hard disk.
9. **Exports.** A report can be exported as text or JSON, redacted for sharing (`report.Redactor`: a path under the
   home folder goes whole, wherever it appears: one the report names as a path is replaced exactly, longest first; one
   in a sentence is taken to its quote, to what is on the disk, or to the last word with a "/" and on through its last
   name's words up to a word a sentence goes on with; in a folder of the user's own nothing after `~/` stays, in a
   dot-folder the programs' folders stay up to the first name with a space, a character beyond letters, digits and
   `._+@-`, or anything in a trash folder's files). What the app keeps between runs
   is the least that does the job ([section 14](#14-what-the-app-stores)), and "Export everything" hands all of
   it over. An export is a file readable by the user alone (0600), whether `--export` writes it or the window's
   Save… does (the app writes it itself: a download the window's WebKitGTK writes has the umask's mode, 0664 on
   Mint and Ubuntu, tested), never over a file there (the next free name, "NAME (2).txt", instead) nor through
   a link.
10. **No network in a scan.** The app never phones home and a scan works offline. Online tests run only when the
    user starts them, after naming every host each one contacts; the same for the one tool that downloads, and for
    Check for updates…, the app's only look at a newer version of itself, never made by itself
    ([section 6](#6-network-access)).

### Tools

Tools are what the user starts on files, folders or drives they choose, where checks scan the machine.

- They run only when started, on what the user chose and the companions next to it (a signature, a checksum
  list), send nothing anywhere (the browser download apart, which names its hosts first), and keep nothing
  afterwards: no log, no history, nothing in reports or exports (the browser's download apart, kept on the disk for
  next time only when the user ticks it, and said).
- They never change the file they were given: a cleaned copy is a new file beside it. The two that delete or
  change something (Before you hand over a drive, Presentation mode) show it first, or put it back.
- They may show the user what is in their own file (its metadata, a signer's name): rule 2's limits on evidence
  are for checks and reports.
- They use the system's own programs (gpgv, mat2, exiftool, bubblewrap…), never bundled ones, and say which is
  missing and how to install it.
- They take paths from the file chooser or from `--tool`, and the server accepts only absolute paths of files
  the user can read, never reached through a link inside `~/TempBrowser`, which the browser there could have made.

---

## 1. Processes and trust boundaries

```
 ┌──────────────────────────── your user account ─────────────────────────────┐
 │                                                                            │
 │  pywebview window (WebKitGTK 4.1)  ──HTTP 127.0.0.1──►  FastAPI server     │
 │  or your browser (--browser)          X-Token header     (app.py, server.py)│
 │                                                          │                 │
 │                                                          │ checks, fixes,  │
 │                                                          │ tools, as you   │
 │                                                          ▼                 │
 │                                              host.py: files, commands      │
 │                                                          │                 │
 │                                       JSON lines on stdin/stdout           │
 └──────────────────────────────────────────────────────────┼─────────────────┘
                                                            │ pkexec (polkit)
                                                ┌───────────▼───────────┐
                                                │ helper.py, as root    │
                                                │ named actions only    │
                                                └───────────────────────┘
```

- **The app** (UI, server, every `scope: user` check, every tool's user-side work) runs as you. It is
  never run as root.
- **The helper** (`helper.py`) is the only code that runs as root. It is started through `pkexec`
  when something needs it, speaks a line-based JSON protocol, exposes a fixed list of named actions,
  and validates every argument itself: it doesn't trust the app.
- **Sandboxes** (bubblewrap) are started by the app for the browser in memory, for View offline…, Try an app and
  Boxes. Whatever runs inside them is treated as hostile: each gets a system-call filter (`tools/seccomp.py`), on
  X11 a display of its own unless the user says otherwise, and nothing it writes is shown as the app's own words.

Programs the app runs get the host's environment (`hostenv.host_env`): the AppImage runtime's variables
(`APPIMAGE`, `APPDIR`, `ARGV0`, `OWD`…) are left out, and variables the app changed for itself only (such as
`GI_TYPELIB_PATH`, for its bundled typelibs) are given back as they were, so a host program never picks up
the AppImage's libraries.

What the app sets up to run later (the scheduled scan's timer, the Outbox's units, the right-click entries, a
Box's menu entry) starts this copy of the app by its path (`launch.scan_command`). They are refused while that
path, or a folder on it (along the path as given and along the real one), belongs to another account or can be
written by others, a world-writable folder like `/tmp` whatever its sticky bit, or one its group can write unless
that group is the account's own private one (`launch.unsafe_place`, `integration.command_problem`): once the
file was gone another account could put its own program there, and the entry would run it as this user. The
refusal says why and what to do (move the AppImage into a folder of one's own and set it up again).

---

## 2. The local web server

The UI is plain HTML/CSS/JS (`web/`) served by FastAPI on 127.0.0.1, on a random port. The app binds the socket
itself and hands it to uvicorn as it is (`app._listen`): a port picked, closed and bound again could be taken by
another program in between.

- **This account's programs only.** Any account on the computer can connect to 127.0.0.1. Every connection,
  the page and its script included, is refused unless the program on the other end is this account's: the
  server looks the client's socket up in the kernel's table (`/proc/net/tcp` and `tcp6`, readable by every
  account, the owner's uid included; `peer.py`) and refuses what it can't find.
- **Launch token.** The window (or browser) is opened at `/?t=<launch token>`. The server exchanges that
  token once for the session token, handed to the page in its body (`data-token`, taken off at once) and
  then forgets it, so the token in the browser's history is worthless a moment later. The page keeps the
  session token in its session storage, which belongs to this origin alone, port included, and sends it
  with every API call in the `X-Token` header. Not a cookie: cookies ignore ports, so in `--browser` mode the
  browser would send one to every other local server on 127.0.0.1 the user visits (a dev server, a sync
  client's page, a server another account runs), which would then hold the session. In `--browser` mode the
  link is therefore for the tab it opens in: another tab, or a page opened without the link, is refused.
  The link never goes on a command line, where every account can read it (`/proc/*/cmdline`): `--browser`
  hands the browser a launcher page in `$XDG_RUNTIME_DIR/daprivacyscanner` (0700, the file 0600; a private
  folder in /tmp without a runtime folder) that opens it, as Jupyter does, removed once the link has been
  used (`app.launcher_file`); the terminal shows the link too, for a browser that can't read that file (a
  Snap's). The browser keeps the session token in its session files while the app runs; only this account's
  programs can use it, and the page drops it at Quit, worthless anyway once the server has ended (a new
  token each run). The `--browser` warning says so.
- **Every route** but the page's shell (`GET /` and `/static/`) needs the `X-Token` header, checked for all
  of them at once in the server's guard (a route that forgot its own check isn't left open). A cross-site
  form can't set it, and a cross-site `fetch` that sets it needs a CORS preflight the server never answers.
  Tokens are compared with `hmac.compare_digest`; a header beyond ASCII is simply wrong (403), never an
  error.
- **DNS rebinding.** Requests whose `Host` header isn't the server's own address are refused.
- **Headers on every answer.** The Content Security Policy (`default-src 'self'`, no inline script, no
  frames, no objects, no form actions, and `frame-ancestors 'none'`, which a `<meta>` can't say),
  `Cross-Origin-Resource-Policy: same-origin` (a website can't load the app's page, script or icon to tell
  it is running, or which version), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`. API answers are `no-store` and carry `X-Admin-Active` (whether
  administrator access is held now), which the page's badge follows, also when the access ended by itself.
  No CDN or remote asset is ever loaded.
- **Links** in the UI open in the default browser through `/api/open`, by name, from `about.LINKS` only:
  the page can't make the server open an arbitrary URL.
- **Background work** (`jobs.py`). Long work the page follows (the online tests, the TRIM test, Deleted file
  names and their clean-up, Remove metadata, setting up a browser, What does this app keep?) is a job, one of
  each kind at a time, with a `cancel` flag its work looks at. What blocks for long (a job's work, a file
  chooser, the password prompt) runs on a daemon thread of its own (`jobs.in_thread`); requests' short work
  on a pool of its own size. The report is changed only on the event loop; work on a thread gets a copy.
- **Quitting** (`app.state.shutdown`, from the page's Quit in `--browser` mode, the window closed, a logout's
  SIGTERM or SIGHUP, Ctrl+C; once): nothing new starts, every job is told to stop and a file chooser left open
  is closed, then up to 10 seconds for the jobs and 120 for a fix, a revert or a set-up under way (never cut
  short), then ~/TempBrowser is closed, a trial discarded, administrator access dropped, Presentation mode
  turned off, and the process ends at once (`os._exit`, `app.finish`). Before, nothing was stopped and Python
  waited for the threads at exit: after the window closed an invisible process went on running the online
  tests, a download, mat2 or a dialog, and with GLib's signal handlers still installed and its loop gone, a
  logout's SIGTERM did nothing.

---

## 3. The scan engine

### The catalogue

`privacy-checks.yaml` is the source of truth: 143 entries in nine categories (encryption, auth, network,
telemetry, browser, desktop, apps, sandbox, kernel), of which 11 are online tests and 5 are features (set-ups). Each entry has a stable `id`, a base `severity`
(0–10), `modifiers`, a `scope` (`user`, `system` or `online`), a fix `tier` (`auto`, `guided`, `advice`,
`feature`), a `kind` (`finding`, `hygiene`, `info`), plain-language `why` and `remedy`, and developer notes
(`detect`, `fix`, `verify`). `catalogue.py` loads and validates it; a test enforces that every entry has an
implementation.

### Context first

Before any check runs, `context.py` computes the context keys: `fde`, `virtualization`, `device`,
`multi_user`, `session`, `hibernation`, `tpm_unlock_no_pin`, `autologin`, `exposed_services`, `vpn_active`,
`ipv6_global`. A check's **effective severity** is its base severity, overridden by the last modifier
whose `when` expression (`expr.py`) matches. Severity 0 means not applicable. A key that can't be
determined is *unknown*, never guessed, and never read as the benign branch (the owner's decision of
2026-11-12: without administrator access a laptop that unlocks from the TPM, with automatic login on, showed
automatic login at 6, not 10). `catalogue.effective_severity` evaluates the modifiers for every value the unknown
names could take (a context key's values, or true and false for a check's own finding): the severity is the
highest of them, by which it is ranked, counted and notified about (scheduled scans too), `severity_low` the
lowest, and `uncertain_on` the names whose value changes it (an unknown before a modifier that decides it anyway
changes nothing). The page's row and summary, the text and JSON reports and the terminal show the range
("6–10") with what would settle it: a context key unknown only for want of administrator access says so
(`ContextValue.needs_admin`). A risk lowers both ends. Not applicable means 0 whatever the unknowns turn out to be.

`tpm_unlock_no_pin` keeps its first name but means "the disk unlocks with nothing typed": from the TPM alone (a
systemd-tpm2 token without a PIN; a Clevis tpm2 binding, through its LUKS2 token or luksmeta on LUKS1; Ubuntu's
TPM-backed encryption, snapd's `ubuntu-fde` token, whose KeyData has no passphrase or PIN parameters), a FIDO2 key
that asks for no PIN or touch, or a key file anyone holding the disk can read (on storage that isn't encrypted, or in
an initramfs on a plain /boot: `rd.luks.key=FILE`, `cryptkey=rootfs:FILE`, Debian's `KEYFILE_PATTERN` for the root
volume). The headers are read by the helper (`cryptsetup luksDump`, and `--dump-json-metadata`, which needs no token
plugin: without systemd's plugin the text dump prints no `tpm2-pin`, which is no answer, never "no PIN"); crypttab and
the kernel command line are read without it, so a key file is found by an unprivileged scan too. What can't be told
(no plugin and no JSON, `try-empty-password`) is unknown. An empty passphrase in a keyslot isn't tried.

`fde` comes from lsblk, with what its columns leave out read from /sys and udev's database (`blockdev.add_sysfs_facts`):
a device-mapper device's DM UUID (lsblk calls dm-verity and dm-integrity "crypt"; they encrypt nothing), a loop device's
backing file (an ext4 image is as encrypted as the filesystem its file is on) and a mounted partition's type (an EFI
system or recovery partition mounted outside /boot holds no one's data). ZFS datasets and bcachefs never show in lsblk's
mount points: each is judged by its own encryption (`zfs get encryption`, which any user may ask), and one that can't
be told leaves `fde` unknown rather than "full" (`context.native_filesystems`; `storage_of` uses the same, so a path on
an unencrypted ZFS /home is never "on an encrypted disk"). A drive that encrypts itself (Opal) can't be seen: the
finding says so. `multi_user` counts systemd-homed's accounts (UIDs 60001–60513) and is unknown, with a note, where
nsswitch.conf takes accounts from SSSD, LDAP, winbind or NIS (they aren't listed) and only one local account is found.
`autologin` reads LightDM's /etc/xdg layer, greetd's config as its unit names it (COSMIC's cosmic-greeter.toml),
openSUSE's /etc/sysconfig/displaymanager, getty units written whole (NixOS), members of a group the login screen's PAM
lets in with no password (Mint's and Ubuntu's nopasswdlogin) and enabled units with PAMName= and an account's User=.

A check's modifiers may also use names the check itself sets. One is shared: `data_on_encrypted_disk`, which
the runner sets for the findings about data kept on the disk (`Check.stored_at` says where: the user's folders
unless the check says otherwise; `_util.on_encrypted_disk` answers from `fde`, and from each path's filesystem
where only some are encrypted). Disk encryption keeps that data safe while the computer is off, not from malware
or someone using it while it is on, so each modifier on it is one lower than the severity it would otherwise
have (never below 1, a test checks every combination), and the runner adds a note saying so.

### Running checks

`runner.py` runs the checks in a small thread pool (so checks share no mutable state), reporting each as it
finishes. A check gets a deadline of its own (`DEADLINE`, three minutes; longer for the few in `DEADLINES`, such as
`kern.updates`, which waits on dnf): one still running then, usually reading a network folder or disk that no longer
answers, is reported as couldn't check ("it took too long") and the scan finishes without it. A thread can't be
stopped, so the pool's threads are daemon threads (a stuck one never keeps the app from quitting), a new one takes
the stuck one's place, and what it returns later is dropped. The rescan after a fix runs the same way. Checks reach the
system only through `host.py` (system root, home, environment, command runner), which lets the test suite
point them at fixture trees. Per-app data is found through one resolver (`paths.py`) that honours the XDG
variables and enumerates Flatpak (`~/.var/app/<id>/…`) and Snap (`~/snap/<name>/…`) locations. Desktop
differences (KDE 5/6, GNOME, gsettings) live in `desktop.py`.

Each check returns a `CheckResult` (`model.py`): `status` (`pass`, `fail`, `warn`, `unknown`,
`not_applicable`, `error`), `effective_severity`, `evidence` (paths, values, counts; never file contents,
secrets or account addresses), `kind`, `fixable`, and `notes` (things that aren't findings, such as
"hibernation is one step away"). A **finding** is `fail` or `warn` with severity above 0 and kind
`finding`; the server and the page use the same rule. `unknown` is never a pass and never fixable;
`needs_root()` marks a result as needing administrator access. A pass claims only what was read: one that would rest
on a stale or partial source is couldn't tell, or says what it rests on (kern.updates passes only on package lists
refreshed in the last week, and says when; enc.boot_no_secureboot passes on an encrypted /boot or a UKI only with
Secure Boot checking the boot loader and keys of the machine's own). A system folder is listed with
`_util.sys_children`, which raises `Unreadable` for one that can't be opened (never "empty": a test forbids `children()`
of a `sys_path` in the check modules), and a command's output is taken with `_util.output`, None when it failed.
Process names come from `procnames.comm`, which reads /proc/PID/comm as bytes (the kernel cuts a name mid-character at
15 bytes, and any process can set its own).

**Browsers.** `browsers.yaml` is the one registry of where each browser keeps its profiles (`profiles`: a family,
Chromium or Firefox, and each edition's folders, native, Flatpak and Snap), and of what it ships its settings as
(`defaults`, read from its own source: Firefox's `firefox.js`, `librewolf.cfg`, the forks' `omni.ja`, Chromium's
features; a fork `inherits` the rest from its upstream). `_util.chromium_dirs` and `mozilla_profiles` go by it, so
every settings check reads every browser it lists (Zen, Waterfox, Floorp, Helium, ungoogled-chromium, Cromite with
Firefox, LibreWolf and the Chromium family). A setting a profile leaves unset is its browser's default, and one no
table gives is "couldn't tell", never upstream's assumed; a Chromium-family default that changed with a version
(HTTPS-First mode on by default from 157) goes by the folder's `Last Version`. An installed browser the checks have
no reader for is named in a note and makes the result partial; with nothing read, the check couldn't check rather
than saying no profiles were found. Firefox's `/etc` policies count for its native install and Snap only, Chromium's
managed policies for native installs only.

**What a pass claims.** A pass says only what was read: the firewall's verdict leaves out Docker's published
ports (forwarded before its input rules), the system's DNS is judged on the links lookups go to, a package mirror
list is "over HTTPS" only when it asks for HTTPS mirrors, a clipboard or crash-reporting pass names the programs it
knows, and an online test's public resolver or hosting network passes only where this computer's own routes agree.

Databases are only read through `sqlite_count()`: read-only, `immutable=1`, so a scan never takes a lock
on an app's database. An immutable reader doesn't see a write-ahead log, where an app using one keeps its newest records
until a checkpoint (KDE's activity database, Klipper's history, Vorta's settings): when the `-wal` file holds records,
the database is opened read-only as the app's own readers are (a shared read lock, which never holds the app up), or
read from a copy made in memory (`$XDG_RUNTIME_DIR` or `/dev/shm`, never the disk). A scan modifies nothing (rule 4)
and never touches the network (rule 10).

### After a scan

`history.py` keeps a baseline of the last scan (statuses and severities only; inventory entries as salted
HMACs, never names) so the next scan can say what is new, resolved or worse, and a store of accepted
findings with the severity each was accepted at. An accepted finding comes back when its severity rises
above that; until then it is in none of what changed since the last scan (new, resolved, changed, not checked
again: `acceptedHidden` on the page, `history.hidden` for the terminal's line), and "accepted", never "to do",
in Before you travel. A problem that a later scan couldn't check (no administrator access that time, an online test
not run) is never resolved: the baseline carries what it was when last checked (`last`), the page and the
text report say so on its row ("not checked again"), and it isn't new when a scan finds it again.

---

## 4. Fixes, guides and the undo log

### Plans

A fix builds a `FixPlan` from the machine as it is (`fix.py`). Building it changes nothing: the plan *is*
the dry run (`--dry-run CHECK` prints it). A fix's `can()` returns `True` or `No(reason)`; an empty plan is
never offered, and its reason is shown as "no fix here". A plan carries `via`, how it was offered: the
runner stamps a guide's option plans with the guide's title, step and option (`_stamp`), and Easy fixes
as such; an auto fix's entry records `{"fix": true}`. The History entry keeps it (`UndoLog.via_text`
puts it in words).

Settings are changed through reversible actions that record before and after: `GSettingsSet`,
`XfconfSet`, `KConfigSet`, `NmSet`, `BluetoothSet`, `UserUnitSet`, `WriteFile`, `ChmodPath`, `MakeDir`,
`FileCommand` (a command whose only lasting effect is one of the user's files, backed up first, such as
`flatpak override --user`), `HashKnownHosts` (`ssh-keygen -H`, the original kept in the backups) and
`FirefoxPref` (one pref at a time in `prefs.js`, with the browser closed; never `user.js`, which would pin
it). `SettingLines` changes the lines of one setting in a file its program rewrites as it exits (LibreOffice's
`registrymodifications.xcu`, `gimprc`), recording and putting back those lines alone: a whole-file backup would
undo everything the program saved since. `KConfigSet` takes a `then` command as `WriteFile` does (the screen
locker's configure call). A daemon stopped as a listed step is waited for (`Command(wait_gone=…)`) before what it
holds is deleted; a process's name is at most 15 characters (`zeitgeist-daemo`). `DeleteFiles(whole=True)`
deletes each listed entry whole (a trashed folder, a link as a link, never through it). `MakeDir(owned=…)` names
what the app itself puts in a folder it made, removed with it. A file write that would leave the file as it is
(`WriteFile.noop`, an option applied before) is no
step: the plan leaves it out, so a guide doesn't offer it again and History doesn't record a change that
changed nothing. A `WriteFile` may name a command run after writing and again after reverting (`then`):
`bus_reload` has the session bus read its service files again, which dbus-broker needs before it sees a user
service file (an override starting `/bin/false`) in a folder made since it started. KDE settings are compared
with the value the program reads, the user's file over the distribution's in `/etc/xdg` (`kset`), as the
checks read them. The dry run lists a folder's `mkdir` once, at the first step that makes it
(`FixPlan.step_commands`). Root changes are
`RootChange` actions: the helper makes them and keeps the previous state in its own journal
(`/var/lib/daprivacyscanner/changes`); the undo log holds only the change id. The irreversible actions are
`DeleteFiles`, `ClearInFile`, `Command` and `RootClear` (deleting as root: old crash dumps, journal files):
a plan holding one needs a separate confirmation (`apply_plan` refuses without it), and deleted paths are
never written to the log.

"Close X first" is asked again when a plan is applied, not only when it is shown (a plan is applied up to 15
minutes later, and a program started meanwhile would have its files deleted under it, or its settings written and
then overwritten as it quits). Every step that needs a program closed carries what the plan's builder checked
(`InUse`: the program's processes, the folders none of the user's processes may hold a file in, a lock link, a
Flatpak id; `Action.unless`, `guarded`); CopyQ's settings steps carry it themselves, and `FirefoxPref` asks whether
its profile is open. `apply_plan` runs every step's `precheck` before the first one (`Precheck` reads the processes,
what they hold open and the Flatpak apps running once for the plan), and refuses with the same plain reason the plan
would give, changing nothing; the server keeps the plan, so it can be applied once the program is closed.

`DeleteFiles` deletes from descriptors: the root folder is opened one name at a time without following a link (from
the home's real path, or from /), each folder below it opened the same way and checked to be on the root's
filesystem, each file unlinked by its name in its folder's descriptor, folders deleted whole and the emptied ones
pruned the same way. Checking a path and then deleting by the same path left a gap a Flatpak app started after the
plan was made could use: it can swap a folder of its own cache for a link to `~/.ssh` between the two. `files_under`
stays on the root's filesystem too, so a plan never lists what is in another filesystem mounted inside.

Writes reach the disk before they count: `_write_atomic` writes a temporary file, fsyncs it, renames it over the old
one and fsyncs the folder (on XFS or f2fs a file could otherwise be empty after a power cut), keeping an existing
file's mode, owner and SELinux label (and ACLs); `make_writable` changes a folder's mode through a descriptor opened
without following a link.

### The undo log

`undo.py` keeps `$XDG_STATE_HOME/daprivacyscanner/undo.json` (directory 0700, written atomically through a
temporary file of each write's own, fsynced, then the folder). Every change to it, as to the other files there, is a
read-modify-write under the folder's lock (`history.locked`, an flock on `.lock`): the window, scheduled scans and
other copies of the app write it too, and one saving what it had read before another's change lost that change. A log
that can't be read (not JSON, not an undo log, not text, or an error reading it) is kept aside
(`undo.json.unreadable-<time>`), never written over, and History says so until "Forget everything" deletes it.

A fix is recorded before it is made (write-ahead): `apply_plan` writes the entry, `applying` and naming its process
(pid, start time, boot id), before the first step; before each step, the step as under way (`Action.under_way`); after
it, its record; then `applied` or `failed`. When the entry can't be written first, nothing is changed; when it can't
be written part way, the plan stops there and is put back. An entry still `applying` whose process is gone shows as
`interrupted` (`UndoLog.state_of`), revertible for the steps it records, a step under way marked "not known". A root
step's change id is made by the app (`RootChange.under_way`), recorded, and sent to the helper as `change_id`; a step
whose answer never came (the app gives up after 120 s while the helper may finish) is kept as `outcome: unknown` with
that id, left out of the rollback, and settled from the helper's own record (`list_changes`, `UndoLog.reconcile`):
made, it can be reverted; never made, there is nothing to undo; begun and not finished, its revert asks the helper.
Reconciling also takes up a change the helper made that no entry knows of (the app stopped before recording it,
History's file lost), as an entry of its own. It runs when History opens with administrator access and nothing else
uses the helper, and when access is given for a fix or a revert; an older helper without `list_changes` is left
alone. The ids of forgotten entries' root changes are kept (only the ids), so forgetting isn't undone by taking them
up again. "Forget" waits for a fix or revert of this window, never drops an entry another copy is applying, and with
everything deletes only the backup folders no entry left names.

Reverts go in order. Every record names what it changed (`Action.resources`: a file, a setting, a key, a unit), and
an entry can't be reverted while an entry applied after it that changed one of the same things is still in place
(`UndoLog.blocking`): reverting out of order put back an old value or a whole old file over that change (an
authorized key trusted again while the entry that removed it still read applied; A true → false then B false → true
ended on false). The answer's `blocked_by` names them, and the page offers to revert them first (`later_first`, newest
first, then this one); Revert anyway doesn't lift this. A file the app doesn't wholly own is put back by lines when it
was edited since (`WriteFile` keeps a copy of what it wrote; `merge_back` takes back only the fix's lines while they
are still as the fix left them, lines it removed going back between the same two lines), so changes made since stay;
when they overlap, it is a conflict. Revert refuses to overwrite a value changed since the fix, unless forced, and
every conflict says what reverting anyway does (`force_does`: the whole file put back, a setting set over its new
value), which the page shows before it does it. A value already back where it was before (put back by hand) is no
conflict. A root change that fails part way is journalled by the helper before its error goes back, and kept as the
failed step's record, so it can be put back. systemctl's exit status never decides a
unit's or a mount's state (`disable --now` answers 0 when the stop job failed): the unit's state and the mount
table do. Every revert says what it put back, and a value already put back by hand (a file, a unit's state, a kernel
setting) is no conflict. A root change the helper found already so leaves no History entry. `set_service` can mask
the units it turns off (`mask`), for a unit another one wants and would start again at boot (cups-browsed's
`Wants=avahi-daemon.service`); reverting unmasks them first. Every action carries an `undo_hint`
(how to undo it by hand). History shows, for each step, exactly what it did: the commands it ran
(`Action.ran`, rebuilt from the record, so older entries show theirs too), the lines it wrote into a file
(`changed_lines`: "+ added", "- removed", at most 40; never known_hosts', whose lines are the server names
hashing hides), the files the helper wrote, the command that undoes it by hand, and once reverted, what
putting it back ran. Every command is quoted so it can be pasted into a shell (`fix.shell`). The dry run
shows the same beforehand: under a root step, the commands the helper will run after it
(`helper.planned`) and the lines it will write (`helper.planned_files`, reading nothing that needs root).
A revert is a full revert that breaks nothing else: the folders a change made (recorded when it
was applied, by the helper for root changes) and a KDE config file that kwriteconfig created are removed
again, deepest first, each only while it is empty or holds only what the fix put there. A folder that holds
anything added since stays, with everything in it, and the revert says so, naming what is there. After each
fix the result of its check is stored
(`set_outcome`); if a later scan finds the problem again, the fix is reported as undone, with which steps
were changed back: only when that result was a pass (a check that couldn't be checked then, such as an online
test after its guide, was never seen resolved), and not once the user has reverted it, even in part, or
reverted another fix of the same check since.

`apply_plan` rolls a failed attempt back step by step (each rollback's commands collected as a revert's
are) and, when any step had run, keeps the attempt as a `failed` entry with its `error`, the step it failed
at (`failed_step`), each step marked reverted with `revert_ran`, and a step that couldn't be put back left
revertible from History. An attempt that changed nothing leaves no entry. A copy the failing step had taken
into the backups, which no record names, is deleted (a plain copy of known_hosts when ssh-keygen failed:
nothing would ever have forgotten or expired it); "Forget everything" deletes every backup folder no entry left names. `/api/fix/apply` and
`/api/easy/apply` answer with each entry as made (`UndoLog.summary`), which the page shows at once
(`doneDialog`). "Export everything" (`report.changes_of`) carries all of it: commands, lines, files,
folders, what reverting ran, `via`, failures.

### Guides

A `Guide` (`guide.py`, `checks/guides/`) is a list of steps. A step either offers options (each a
`FixPlan`, applied and confirmed on its own) or gives commands for the user to run (passphrases, PINs,
fstab, crypttab). A step can take `Input`s; the page sends them back and the guide is rebuilt with them,
so the dry run always matches what is applied. Advice checks may have a guide whose steps are commands
only.

Commands for the user are written for the form this machine's files have, and checked by running them on
copies in the tests. A line added to a system file (/etc/fstab, /etc/crypttab, /etc/default/limine) gets a
newline first when the file's last line has none (`guides.append_line`): `tee -a` alone glued it onto that
line. GRUB's `GRUB_CMDLINE_LINUX_DEFAULT` is changed in double quotes, single quotes or none, and added
when missing (a `grub.d` file that sets it again is named). A changed /etc/kernel/cmdline is taken by what
makes the boot entries: `sdbootutil update-all-entries`, mkinitcpio's presets (`mkinitcpio -P`, which
builds Arch's unified kernel images without kernel-install), `kernel-install add-all` from systemd 255,
else each kernel added in turn. USBGuard's policy is made with `-P`, so a keyboard without a serial number
isn't bound to its port, with `systemd.mask=usbguard.service` from the boot menu as the way back. A home
folder given a btrfs subvolume of its own gets it at the filesystem's top level (`@home`, mounted from
fstab, SELinux labels restored where enforcing): one made in place is nested in the system's subvolume and
left behind by a rollback. tel.countme is a guide: on DNF5 one override file of the app's own
(/etc/dnf/repos.override.d, `[*] countme=0`, an Easy fix); on DNF4 the repository files are edited, which
makes rpm keep their packages' new versions as `.rpmnew`, so that option has no Easy key. Turning automatic
login off is blocked while an account it logs in has a locked or empty password (`passwd -S` for one's own,
the helper's /etc/shadow reading for another's).

An option that would cut the connection the machine is used through from another one is refused or keeps it
open (`guides.remote_access`, `remote_session`): this session's SSH (SSH_CONNECTION, its server port) and xrdp
(XRDP_SESSION), and the remote desktop programs running here by process name (VNC servers, GNOME Remote Desktop,
NoMachine, Sunshine, and TeamViewer, AnyDesk and RustDesk, which go through their makers' relays and need no
incoming port unless they listen), each with the ports it listens on (its own sockets, else its usual ports). The
SSH server and xrdp can't be turned off from inside their own session; SSH keys only, over SSH, needs a key in
`~/.ssh/authorized_keys` and says to log in with it from a second terminal before closing the connection; turning
ufw on lets the remote ports in (ufw_enable's allow list); firewalld is started only when its default zone, read
from its files (`/etc/firewalld` first, then `/usr/lib/firewalld`), lets them in, else the step gives the
`firewall-offline-cmd --add-port` commands that do so first. A remote desktop program of another account's whose
port can't be told refuses both firewalls. Saved Wi-Fi networks someone set to the hardware address are an option
of their own in net.mac_permanent's guide, never part of its Easy fix.

An online test's guide is never built by running the test: `Runner.plan_fix(stored=…)` takes the result the
report keeps and `Outcome.from_dict` turns it back into the outcome the guide reads (the issuer seen, the
ports forwarded, the resolver answering); the server passes the kept result for `scope: online` checks and
answers 400 ("run this online test first") when there is none, as `--dry-run` does from the saved last
report. Two online checks are `guided` and borrow another guide built for them: `net.dns_encryption_in_use`
offers `net.dns_unencrypted`'s provider options, `net.ipv6_reachable` offers `net.exposed_services`' options
for the services listening now. The rescan after such a fix runs the online check without a network, so its
row is unknown until the test is run again. The How to… guides for the other online findings
(`checks/guides/advice.py`) read the machine as it is: NetworkManager's active connections by name, the
device IPv6 leaves through outside the tunnel, the IPv4 gateway for the router's page, resolv.conf.

### Easy fixes

`Runner.plan_easy` detects each check with an `easy` entry again and gathers, for those that fail or
warn, the auto fix's plan or the guide's options tagged with the catalogue's `easy.option` key (in steps
not done yet); `/api/easy/plan` then leaves out findings the user accepted. `/api/easy/apply` accepts only
plans that `/api/easy/plan` built, and only for 15 minutes (`PLAN_TTL`). Administrator access is asked for
once; if it is declined, the root plans are skipped and the rest applied. Each is applied as its own History
entry; a failure is rolled back and the rest go on; then one rescan. A result's `easy`, which the summary's
count and the row's badge go by, is true only while that fix has something left to apply (`_easy_left` for a
guide's option, the plan itself for an auto fix): a check can go on failing with its Easy fix in place (a
list that still has entries, a change that waits for a restart), and is then neither counted nor listed.

### Rescan

After a fix or revert, the context is recomputed and every check whose severity depends on a changed key
is run again (`Runner.rescan`), and every check whose detection reads one (`Check.reads_context`, kept in
step with the checks' source by a test: the hibernation image, the services listening). The services
listening have changed also when the list of them has, though some still listen.

---

## 5. The privileged helper

- **How it starts.** A session is always the root-owned copy with its own polkit action
  (`/usr/libexec/daprivacyscanner/daprivacyscanner-helper`), run as `pkexec <that path>`. Until it is installed
  (or while the installed one is another version's, `PROTOCOL`), administrator access isn't available
  (`privileged.HelperNotInstalled`): the page, `--scan --admin` and the error say to install it, and the page offers
  it. Installing (`--install-helper`, the page, `packaging/install-helper.sh` with sudo) runs this version's
  `helper.py` once, only to install or remove itself: `pkexec /usr/bin/python3 -I -c LOADER <file> <sha256>`, where
  the loader (`privileged.LOADER`) reads the file once, checks it against the SHA-256 of what the app read from its
  own package, and runs exactly those bytes with `--install-only` (they are what `install_self` installs). A file
  that a process of the user's changed while the prompt stood is refused, never run as root. From an AppImage the
  file is a private copy, since root can't read the AppImage's FUSE mount. `-I` keeps user site-packages and the
  script directory off `sys.path`. Standard library only.
- **What it inherits.** pkexec keeps the caller's umask, working folder and resource limits: the helper sets
  umask 022, works from `/`, lifts the limits that would cut a write or a read short (file size, address space,
  data, CPU) and turns off crash dumps before anything else (`_harden`). Every folder it makes gets its mode set
  (`_makedirs`), its own state folders (`OWN_DIRS`: /var/lib/daprivacyscanner, its journal, /run/daprivacyscanner)
  are root's and get their modes back where an older helper made them under the user's umask, and a state file it
  reads (a journal entry, swap.json, a RAM disk's record) must be root's, writable by root alone and have one name
  (`_read(trusted=True)`), else it is refused or ignored.
- **Protocol.** One JSON object per line (`{"id", "action", "args"}`), one reply per line, over a socket pair: the
  helper's stdin and stdout are one end, the app holds the other. A pipe's end could be opened again by any process
  of the same user through `/proc/<app>/fd/N` (and requests written with an id the app skipped as late); a socket's
  can't (ENXIO). A request line is at most `MAX_REQUEST` (4 MiB). It exits at end of input, after `HELPER_IDLE` (6
  minutes) without a request, and after `HELPER_LIFETIME` (12 hours) however it is used; while work holds the access
  the app sends `keepalive` every minute. `{"action": "cancel", "args": {"id": n}}` stops request n while it runs
  (the long loops look for it: the TRIM test's reads, the listing of deleted names, the traffic watch); it answers
  "Stopped." and the cancel itself is never answered. The app sends it when the user stops a tool or closes its
  panel.
- **Asking again.** The session's prompt covers reads and reversible, journalled changes. What can't be undone as
  root (`clear_crash_dumps`, `vacuum_journal`, `clear_journal_files`, `clear_syslog`, `clear_opensnitch_log`,
  `snapper_cleanup`), what returns other accounts' data (`observe_traffic`: every account's lookups and
  connections; `names_orphans`), installing or removing the helper in a session (`install_self`,
  `uninstall_self`; the install-only copy's own start asked for exactly that), and a revert that turns a
  remote-access service back on (`REMOTE_ACCESS`: ssh, xrdp, TeamViewer, AnyDesk, RustDesk, Cockpit, Samba) ask
  polkit again, each time (`helper.CONSENT`), for `au.com.digitalarchon.daprivacyscanner.sensitive` (auth_admin,
  never kept): the helper runs `pkcheck --action-id … --process <app pid>,<start time>,<uid>
  --allow-user-interaction --detail what "<what it is about to do>"`, the prompt naming it (`$(what)` in the action's
  message), on the app's own process (its parent, checked to be the same one). Declined, nothing is done, and the
  answer says so (`declined`; `privileged.ConsentDeclined`); the app waits the prompt's time on top of the
  request's (`call_timeout`).
- **Services.** `set_service` turns each unit on its list only the way the app does (`SERVICES`): the remote-access
  services, file sharing, crash reporters, syslog daemons and motd-news off (Avahi masked too), firewalld, the weekly
  TRIM timer and OpenSnitch on, tmp.mount enabled from the next boot. No request turns remote access on or a
  firewall off; a revert puts back what the journal recorded.
- **Actions.** Detection (`luks_dump`, `clevis_list`, `read_file` for allowlisted files,
  `empty_password_accounts` (names, never hashes), `sshd_settings`, `firewall_summary`, `ufw_status`,
  `observe_traffic`, `erase_facts`); changes (`write_dropin`, `edit_config`, `set_service`, `set_sysctl`,
  `ufw_enable`, `browser_policy`, `block_extensions`, `mount_tmpfs`, `enable_tmp_mount`, `revert`,
  `clear_crash_dumps`, `vacuum_journal`, `clear_journal_files`, `snapper_cleanup`); tools (`ramdisk_open`, `ramdisk_close`,
  `swap_off`, `swap_on`, `trim_*`, `names_*`, `watch_*`); and `install_self` / `uninstall_self`. What
  `install_self` installs is the source the helper read as it started (`own_source`), never the file as it is
  when the request comes: the helper that isn't installed yet runs from a copy in the user's runtime folder,
  which anything running as the user can change after it was authorised. The same source is what the watch's
  child runs (passed in a memory file only root holds), never the file as it is when the watch begins.
- **Validation.** It never writes content the app sends: files are generated from validated settings or
  edited by fixed rules, and only units, sysctls and policies on its own lists can be touched. The calling
  user and their home come from `PKEXEC_UID`, never from the request. Folders under the home are opened
  one component at a time with `O_NOFOLLOW` and must belong to the caller.
- **The journal.** A change request may carry `change_id` (32 lowercase hex, never used before; the app's
  `PkexecHelper.call` gives every change one), which its journal entry then has; without one the helper makes one.
  Before anything changes, the entry is written and fsynced with its folder (state `intent`: what it is about to do
  and what is there now), then marked `applied`, or `failed` with what was put back. Entries record the caller's
  uid; a revert refuses another account's. What has nothing left to put back (a revert, a failure undone whole)
  leaves the journal (whose folders go once empty) for a line in /run/daprivacyscanner/done, gone at a reboot and
  after 7 days. `list_changes` answers the caller's changes, `{change_id, state, action, time, text}`: an app whose
  request got no answer (`timed_out`, with the change id) can learn what became of it. A forced revert puts back
  what it can when a unit's package is gone since (the app's own files above all) and says what it left.
- **Mounts in the home.** A folder kept in memory is mounted by the helper itself on the folder it opened one name
  at a time (`/proc/self/fd/N`), never by systemd at that moment (it would hand the path to mount(8), which looks it
  up again while the user's programs run); `systemctl enable` without `--now` then has systemd take the mount up as
  its unit (active). Reverting unmounts it through the folder above it, opened the same way
  (`umount2("/proc/self/fd/N/<name>", UMOUNT_NOFOLLOW)`), after checking it is a tmpfs of the user's, then disables
  the unit. ~/Ephemeral "until logout" is ordered `Before=user@UID.service` (as the RAM disk's drop-in is): systemd
  mounts it before the user's manager starts anything, and unmounts it after every program of theirs has ended. A
  folder made for the user is made under a random name, checked, given away by its descriptor and only then renamed
  into place without replacing anything (`_new_folder`, `renameat2(RENAME_NOREPLACE)`).
- **Disks read.** btrfs tree blocks are taken only inside the metadata and system chunks (read from the chunk tree,
  found through the superblock's bootstrap chunks), carrying the logical address that place has and the chunk tree's
  UUID, with every checksum kind checked (crc32c, xxhash64 in Python, SHA-256, BLAKE2b): a file another account wrote
  shaped as a leaf plants no names; a block that only looks like one never stops the listing; a filesystem with mixed
  block groups is refused, said why. ext4: a group descriptor size outside 32-1024 (a power of two), a journal whose
  extents name the same blocks twice or lie past the device, or more inode-table descriptors than the device holds,
  aren't read; folders that are gone are looked for in a bounded number of journal blocks. A folder's blocks found at
  the start are read later only if they still carry that folder's checksum (metadata_csum), else after the folder is
  opened again and asked again. Whether a name is still there, and the copies tied to a folder by its entries, are
  looked up in the folder opened as the listing reached it (`_open_kept`, `stat(dir_fd=…, follow_symlinks=False)`),
  never by a path root would follow through a link. The walk and `_open_kept` run with the caller's file access
  (`_as_caller`: setfsuid, setfsgid and their groups), so access control lists decide as the kernel does. The
  traffic watch's lookups go into a memory file (memfd), never /tmp.
- **What it did.** Every change answers with `ran`: each command it ran, in order, quoted for a shell (a
  setting written straight to its file, a sysctl or a tmpfs mount, as the command that does the same;
  crash dumps deleted as `rm -f` by pattern, never by name; a file a revert restores from the journal as a
  `#` line, since no command does the same), and `files`, the paths it wrote. Reads aren't listed. History
  shows them.
- **Lifetime.** One authorisation covers a scan and the fixes after it. Access ends when the user drops
  it, after 5 idle minutes (`server.ADMIN_IDLE`, looked at every few seconds by a timer of the session's own, not
  only when the page asks), when the app quits, or straight after a scan that found nothing a root fix could act
  on, unless something has asked for it since (`AdminSession.drop_unless_claimed`: a tool between its
  `with_root` and its `hold`) or a request is in hand. A scan, applying a fix and a revert hold it while they run,
  and applying uses the access there is then, never the one the dry run had. Long work holds it for as long as it runs (the TRIM test, a listing of deleted
  names, a watch of an app, which says so before it starts and drops the access when it ends, and the online tests
  given access, whose traffic watch asks the helper every few seconds). The watch and the TRIM test and listing
  don't run at once, nor is the helper installed or removed while any of these runs: the helper does one call at a
  time, so a disk read for minutes held the watch's polling and its End behind it, and installing the helper ended
  the watch with everything it had seen.

---

## 6. Network access

A scan never uses the network. Online tests (`scope: online`) run only when the user starts them, after
the page has listed every host each one contacts (`contacts` in the YAML; endpoints configurable in
`~/.config/daprivacyscanner/online.json`). All network access goes through `online.Net`, which opens https
addresses only, plain http only to this computer or the local network (an address in the private, loopback or
link-local ranges, `localhost`, a `.local` name: the router's UPnP description), never `file:`, `ftp:` or `data:`
(`online.check_url`; the opener has no handler for them); it follows a redirect only to the host and port asked
(http to https there) or to one the call names on the https port, and never from https to http. A download reads
what arrives as it arrives, and Stop shuts its connection down, so a stalled server doesn't hold Stop up; an
online test's answer has its timeout as a whole. The test suite uses `FakeNet` and never goes online. The browser download (section 7) is the only tool that uses the network,
also through `online.Net`, and only when the user starts it. Check for updates… (below) is the app's only look at
a newer version of itself, also only when the user clicks it.

### Check for updates…

Code: `update.py`, the server's `/api/update*` routes, `openUpdate()` in app.js (the owner's decisions of
2026-11-12). It never runs by itself: no timer, nothing at start-up, nothing in a scan. The dialog (from the welcome
warning, beside the version, and from the old-copy note) gets `GET /api/update` first, which contacts nothing and
says what this copy is (`situation`) and the hosts of each step, and names them before each runs, with the proxy
warning the online tests give (it goes out directly, as they do).

1. **Check** (`latest`): `GET https://api.github.com/repos/DigitalArchon/DAPrivacyKit/releases/latest` through
   `online.Net` (https only, no proxy, the generic User-Agent, nothing about the computer; GitHub's 60 questions an
   hour per address are said when it refuses). The answer is read strictly: the tag `v<version>` (PEP 440, compared
   as PEP 440 orders versions, `update.version`; a local part refused), not a draft or a pre-release, and the assets
   `DAPrivacyKit-<version>-x86_64.AppImage` and its `.asc` by exact name, each uploaded, its size capped (256 MB,
   64 KB) and its address exactly `https://github.com/DigitalArchon/DAPrivacyKit/releases/download/<tag>/<name>`;
   anything else, nothing is downloaded. GitHub's own SHA-256 of the asset (`digest`), when it gives one, is checked
   after the download as a check against damage, never as trust.
2. **Download** (`download`, a job of its own with progress and Stop): into a new hidden folder beside the running
   AppImage (`$APPIMAGE`'s real path, `.DAPrivacyKit-update-<random>`, 0700: the same filesystem, so putting it in
   place is one rename), through `online.Net.download` capped at the size the release gives, the signature first.
   GitHub serves release assets by redirecting `github.com` to its file servers, `release-assets.githubusercontent.com`
   (seen on 2026-11-12) or `objects.githubusercontent.com` (before 2025): those are the only redirects followed.
   Refused before anything is contacted where the AppImage couldn't be replaced, and where there isn't room.
3. **Verify** (`verify`): Verify a download on it with the `digitalarchon` project of `signing-keys.yaml` alone (its
   pinned primaries, the subkeys they bind, a `role: successor`; never the user's keyring, never another project's
   key): anything but *verified* by it, over the file itself, is refused and deleted; so is a signature dated in the
   future. Then the version the file itself says it is (`read_version`): a file's name says nothing (an older
   release, genuinely signed, renamed as the latest, passes the signature check), and its contents can't be read
   without running it (a zstd squashfs, which Python's standard library can't read before 3.14), so the verified file
   is run once with `--version`, as the user, under the host's environment (`APPIMAGE_EXTRACT_AND_RUN` passed on
   when this copy runs with it), stdin from /dev/null, for at most 60 seconds. app.py prints `DA Privacy Kit
   <version>` there before anything else runs (keep that line). It must be the release's version and newer than this
   copy's: a downgrade, the same version, or a release before 0.1.0b9 (no `--version`) is refused and deleted.
4. **Replace** (`replace`, once the user has seen `plan`: the exact paths, the commands that do the same by hand,
   how to check it by hand and how to go back, and confirmed): refused where another account could change the file
   or a folder it is in (`launch.unsafe_place`), where the file isn't the user's or its folder not writable by them,
   when the running file has changed since the download began (another copy updated it), or the download since it
   was verified (its SHA-256 again). The running file is kept beside it as `.<name>.<version>.old`, a hard link (two
   renames on a filesystem without them, put back if the second fails), and the new one renamed over the path with
   the running file's mode: the path stays, since timers, the Outbox's unit, the right-click entries and Boxes start
   the AppImage by it; its name keeps the old version number, said. The record of what the new copy is to remove,
   `$XDG_STATE_HOME/daprivacyscanner/update.json` (the path, the kept file's name, device, inode, size and time, the
   two versions), is written then.
5. **Restart now** (`restart`) starts the new copy (with `--browser` in browser mode), watched for 3 seconds: one that
   stops at once is said, with the hand undo, and this copy stays; otherwise the page quits this one through Quit.
   **Later** leaves it. The new copy's first page (`/api/state`, `finish_pending`) removes the kept file: the recorded
   name, beside the AppImage, a plain file of the user's with the recorded device, inode, size and time, nothing
   else; a file put there since is left alone. The old copy running again (Later, or put back by hand) removes
   nothing.

One copy at a time (`owner.hold("update")`, from the download until it is put in place or discarded); a download not
put in place is deleted when its dialog closes and when the app quits, and hidden folders a copy that ended left go
when the dialog opens while no copy holds the lock (`tidy`: only the names the app gives, the folder once empty).
Not an AppImage (a source tree: `git -C <tree> pull --ff-only`; a package someone made: its package manager) and a
development build (`about.dev_build`, or a `+dev` name or version) get how to update instead, and nothing is
contacted. AppImage updaters can use the release's `.zsync` (packaging/README.md); the app itself doesn't.

---

## 7. Tor or Mullvad Browser in memory

Code: `tools/browser.py` (lifecycle), `tools/sandbox.py` (bubblewrap command lines), `tools/torgate.py`
(Tor Browser's gate and control-port filter), `tools/wayland.py` (Wayland security context),
`tools/transfer.py` (files in and out), `tools/sniff.py` (what a download really is), `tools/viewer.py`
(View offline…), `tools/ramdisk.py` and the helper's `ramdisk_open` / `ramdisk_close` / `swap_off` /
`swap_on`.

### 7.1 What it is for, and the threat model

Tor Browser and Mullvad Browser already keep no history between sessions. This tool adds three things:

1. **Nothing on the disk.** The browser's program files, profile, caches, downloads and the desktop
   libraries' state all live in a tmpfs (`~/TempBrowser`) mounted without swap where the kernel allows it.
   Closing it overwrites every file with zeros and unmounts it.
2. **Containment.** The browser runs in a bubblewrap sandbox. The assumption is that a website may get
   past the browser's own protections (Firefox's content sandbox). The app's sandbox then keeps that
   compromised browser from your files, keys, keyring, session bus, other programs, this computer's
   identity, and (for Tor Browser) any network but Tor's.
3. **A verified, current copy.** The browser is downloaded from the project's own servers, verified
   against a pinned signing key, refused if it isn't the latest release, and never updated in place.

What it doesn't cover: what websites and the network see while you browse, the clipboard, files you copy
out, and the kernel itself (a kernel exploit escapes any namespace sandbox).

### 7.2 Where everything lives

```
~/TempBrowser/                         tmpfs, mounted by the helper (mode 0700, nosuid, nodev, noswap)
├── .trackerignore, .nomedia           LocalSearch/Tracker never indexes this folder
├── .downloads/                        archive + .asc while downloading/verifying; removed afterwards
├── .tor-browser.unpacking/            staging during unpack, renamed when complete
├── tor-browser/                       the unpacked browser (read-only in the sandbox, except:)
│   └── Browser/
│       ├── TorBrowser/Data/Browser/   profile: writable
│       ├── TorBrowser/Data/Tor/       tor's data: writable for tor, hidden from the browser (tmpfs over it)
│       ├── Downloads/                 writable
│       ├── To upload/                 read-only in the sandbox; the app copies files in
│       ├── .config/ibus/              made by the app (the start script would try to)
│       └── .local/share -> /dev/null  made by the app (the start script's guard against recent files)
├── .tor-browser-session/              XDG_CONFIG/CACHE/DATA/STATE_HOME and TMPDIR: wiped at every start
│   └── config, cache, data, state, tmp
└── .tor-browser-app/                  the app's private folder: never given to any sandbox
    ├── etc/                           the sandbox's own passwd, group, hostname, hosts, machine-id,
    │                                  timezone, resolv.conf, cmdline, boot_id
    ├── tor/                           torrc, status.json, socks, control, tor-control, control_auth_cookie
    ├── Xauthority, x11/, xauth-*      X11 only
    ├── wayland-0                      the compositor-marked Wayland socket
    ├── xephyr.log                     Xephyr's own errors (the sandbox's start log is a memory file)
    ├── release.json                   version, signature time, set-up time, security level, checks
    ├── bridges.json                   the bridges chosen in the panel
    ├── sandboxed                      mark: this copy has run in the sandbox
    └── view/                          View offline…'s own files
```

Mullvad Browser has the same layout under `mullvad-browser/`, `.mullvad-browser-session/` and
`.mullvad-browser-app/`; its writable paths are `Data` (beside `Browser`) and `Browser/Downloads`, and it
has no `tor/`.

Every folder the app makes or uses under `~/TempBrowser` is reached by `browser._dir`: opened one
component at a time with `O_NOFOLLOW | O_DIRECTORY`, and each must belong to the user and be on the RAM
disk's device. A link planted by a browser (one that ran unsandboxed, say) is refused.

### 7.3 Step 1: the RAM disk

`~/TempBrowser` is a RAM disk of its own, separate from the RAM disk tool's `~/RAMDisk`; the helper accepts
only these two names (`ramdisk.NAMES`), never a path. The panel opens it with programs allowed to run
(no `noexec`), 1536 MB by default, at least 1024 MB (`browser.MIN_MB`), at most half the memory.

The helper's `ramdisk_open`:

1. Validates the size (50–65536 MB and at most half of `MemTotal`) and the `noexec` flag.
2. Takes the user and home from `PKEXEC_UID`.
3. Opens (or makes) `~/TempBrowser` one component at a time without following links; each must be the
   caller's. Refuses if the folder already has files on the disk (a mount would hide them, not remove them).
4. `fchmod`s the underlying folder to 0500, so nothing can be saved in it while the RAM disk is closed.
5. Mounts tmpfs through `/proc/self/fd/<fd>` (so the mount can't be redirected by a link swapped in
   between), with `MS_NOSUID | MS_NODEV`, `size=<n>M,mode=0700,uid=<uid>,gid=<gid>`, and `noswap` when the
   kernel has it (Linux 6.4+; retried without it on `EINVAL`).
6. Writes nothing to `/etc`: a reboot ends it. What closing needs (whether the helper made the folder,
   its previous mode) goes to `/run/daprivacyscanner/ramdisk/`, and onto the folder itself as an extended
   attribute (`user.daprivacyscanner.ramdisk`, where the filesystem keeps them): /run is empty after a
   reboot, and the close then still knows whether to remove the folder or which mode to give it back,
   rather than guessing (it used to take a folder of the user's for its own and remove it, or leave one
   at the 0500 an open RAM disk has). The attribute is the user's folder's, so it is checked, and the
   worst a forged one can do is what the user could do themselves to their own empty folder. Opening a folder
   an earlier open left (a restart ended its mount) keeps that open's record: written over with the 0500 the
   folder had then, it made the close leave the folder empty and read-only for good (found in the review of
   2026-10-17). Such a folder can also be put back without opening it: the panel's *Put the folder back*
   (`ramdisk.put_back`, as the user, since it is their own empty folder: removed when the record says the app made
   it, its mode back otherwise, 0700 when nothing records it).
7. Keeps the mount out of the journal: systemd makes a mount unit of every mount it sees and logged
   `home-<user>-TempBrowser.mount: Deactivated successfully.` at every close, in a journal kept on the disk, a
   timeline of the sessions (found in the review of 2026-10-17). Before mounting, the helper writes a drop-in for
   that unit in `/run/systemd/system/<unit>.d/` (gone at a reboot) with `LogLevelMax=notice`: systemd reads it as it
   makes the unit, at the mount, with no `daemon-reload` (whose own lines would say as much), and logs only the
   unit's warnings and errors (tested on Mint 22.3, systemd 255). For `~/TempBrowser` it also has `BindsTo=` and
   `Before=user@UID.service`, so that systemd unmounts it once the user's manager has stopped at the end of their
   session (below, Closing; read the same way on systemd 255 and CachyOS's). The close removes it. What stays in the journal:
   pkexec's line each time administrator access is given to the app (when, not what for); the close dialog says so.

### 7.4 Step 2: getting the browser

**Downloading** (user-started; the dialog names the hosts first):

| | Tor Browser | Mullvad Browser |
|---|---|---|
| Index | `https://aus1.torproject.org/torbrowser/update_3/release/download-<platform>.json` | `https://cdn.mullvad.net/browser/update_responses/update_1/release/download-<platform>.json` |
| Hosts allowed | aus1.torproject.org, dist.torproject.org | cdn.mullvad.net |
| Platforms | linux-x86_64, linux-i686 | linux-x86_64 |

`browser.release` reads `{"version", "binary", "sig"}` from the index and refuses unless:

- both URLs are `https` on the browser's own hosts;
- `sig` is exactly `binary + ".asc"`;
- the file name matches `<folder>-linux-(x86_64|i686)-<version>.tar.xz`;
- the version in the file name equals the index's `version`.

The signature, then the archive, are streamed by `online.Net.download` to `.part` files in
`~/TempBrowser/.downloads` (capped at 600 MB, redirects only to the allowed hosts), then renamed. Anything
stopped or failed is deleted. Like the online tests, the download and every version check go out directly, never
through a proxy set in the environment: when one is (`online.proxy_vars`), the download dialog, the picked archive's
and the kept copy's checks and the start's check say so first, since those hosts then see this computer's own
address (they went past `HTTPS_PROXY` and `ALL_PROXY` silently before the review of 2026-10-17).

**Or an archive the user picked.** `browser.copy_in` opens it (and its `.asc`) with `O_NONBLOCK`, checks it
is a regular file of at most 600 MB and that there is room, and copies it into `.downloads` with
`O_EXCL | O_NOFOLLOW`. What is verified and unpacked is that copy, never the user's file (which could
change between the check and the unpack on a shared or removable disk). The user's file is never touched.
Then `check_latest` asks the project's index for the latest version and refuses an older archive.

**Or the kept copy** (`tools/kept.py`, the owner's request of 2026-10-17). The download dialog's *Keep the download
for next time*, off by default, keeps the archive and its signature in `$XDG_CACHE_HOME/daprivacyscanner/browsers/<id>/`
(the folders 0700, the files 0600), on the disk. The dialog says first what that means: they tell anyone who looks
at the computer that the browser was set up here (nothing of the browsing is in them), and deleting them doesn't
erase them from the disk (rule 8). It is kept only once the set-up has succeeded (verified and unpacked, the version
inside checked): copied from the verified file in `.downloads`, never fetched again, into `.<id>.new-<random>` beside
the kept one, verified there once more (never an unverified file kept), then put in place of the older copy by two
renames (the old folder aside, the new one in, the old removed: never an old archive beside a new signature). One
kept copy per browser; a folder or a link in place of the app's folders is refused, and a keep that fails leaves
the set-up done, with the reason on the job. *Set up from the kept copy (version X, kept on DATE)…* then goes the
picked archive's way exactly: `copy_in`, `check_latest` (a newer version out: refused, `Outdated`, and the page offers
the download of the new one with *Keep the download* ticked, so it takes the old one's place, and *Delete the old
copy…*, beside the refusal and in the dialog once unticked: unticked by default, the old copy stayed, and every
later set-up offered it and refused it, after another request to the index), the app's own keys, the version inside the archive,
and `accept_unchecked` within `RECENT_DAYS` where the index can't be reached. The dialog names the index host. The
panel lists the kept copies whether or not `~/TempBrowser` is open, each with *Delete…* (refused while that browser is
being set up, `owner.hold`). Kept copies aren't in History, reports or exports; `packaging/uninstall.sh` removes the
folder, with `--keep-data` too.

### 7.5 Step 3: verification

`browser.verified` runs Verify a download (section 9) on the archive **with the app's own keys only**
(`use_keyring=False`: the user's GnuPG keyring is not consulted). It accepts only the level *verified*
with a good signature by the project `torbrowser` in `signing-keys.yaml`, the Tor Browser Developers key,
which signs both browsers. Anything else (a good signature by any other key, intact-only, bad) is refused
and nothing is unpacked.

**Where the index can't be reached** (the project's server blocked, typical where people get Tor Browser
from GetTor or a mirror), a picked archive is accepted only once its signature verifies *and* the
signature's hashed creation time (`keys.signature_created`, trustworthy once the signature is good) is
within 30 days (`RECENT_DAYS`). The job and the card say the check couldn't be made, and how old the signature was
when that decided (`unchecked_days` in the release record, written again when a start after a day is accepted the
same way: the card used to say how long before the set-up it was signed, which a start weeks later didn't go by).

### 7.6 Step 4: unpacking

`browser.unpack`, from the verified archive:

1. Refuses if `~/TempBrowser/<folder>` already exists (the browser in it may be running).
2. Reads every member first. Refuses the whole archive if any member is outside `<folder>/`, contains
   `..`, is absolute, or is anything but a regular file or a folder (no links, devices, FIFOs, hard links).
3. Reads the archive's own version file (`Browser/tbb_version.json` for Tor Browser,
   `Browser/version.json` for Mullvad Browser) and refuses unless it equals the version in the archive's
   name. Without this, a correctly signed *old* release renamed as the latest would pass both the
   signature and the newer-version checks.
4. Refuses if the unpacked size plus 64 MB exceeds the free space.
5. Extracts into `.<folder>.unpacking/`: folders 0700, files created with `O_EXCL | O_NOFOLLOW` at 0600,
   then 0700 if the archive marked them executable. Owner-only permissions throughout.
6. Renames the staging folder into place. On any error, or Stop, the staging folder is removed (Stop is looked
   for between files: before the review of 2026-10-17 it went unheard until the end).

The downloaded archive and signature are then deleted (`tidy`): they are public files, and their memory is
given back. A copy of the app killed during a set-up left the staging folder (some 350 MB of memory) and the
download's files until the next set-up of that browser: the panel's status removes them (`tidy_leftovers`) while
no copy of the app is setting that browser up (`owner.hold`).

### 7.7 Step 5: the security level

`browser.preset_security` (Tor Browser only) sets the **Safest** level in the profile the archive ships
(`Browser/TorBrowser/Data/Browser/profile.default/prefs.js`, appended, `O_NOFOLLOW`):

- `browser.security_level.security_slider = 1`, `security_custom = false`, `noscript_inited = false`;
- every pref that the browser's own `modules/SecurityLevel.sys.mjs` (read out of `omni.ja`) sets for
  Safest in its `kSecuritySettings` table.

Setting the table's prefs as well as the slider means the browser starts at Safest without asking for a
restart. Live-tested: check.torproject.org reports JavaScript disabled. The user can lower it with the
shield button for as long as the RAM disk is open.

Mullvad Browser starts at Standard, its own default (it creates its profile at first start, so nothing is
preset).

`record_release` writes `release.json`: version, signature creation time, source, set-up time, last check,
security level, and whether the latest-version check couldn't be made. A copy unpacked but never recorded (its
set-up interrupted) doesn't start; its card offers *Remove this copy…* (`remove_copy`: its folder, its session
folder and the app's private folder for it overwritten and deleted, the other browser left as it is), where only
closing all of `~/TempBrowser` took it away before the review of 2026-10-17.

### 7.8 Step 6: before each start

`browser.start` refuses, with the reason, unless:

- `~/TempBrowser` is open, programs may run from it, and nothing else is mounted there;
- the start script is a regular file owned by the user, and the browser isn't already running;
- **freshness** (`check_before_start`): a copy set up more than 24 hours ago first asks the project's index
  for the latest version (one https request, directly, not through Tor; the start dialog says so and names
  the host). If a newer version is out, it doesn't start. If the index can't be reached, it starts only
  while its signature is less than 30 days old. One successful check covers starts for the next hour. A
  release signed more than 56 days (`STALE_DAYS`) before it was set up is flagged on its card even when the
  index agreed (an old index and an old archive served together by someone in the way);
- **no unsandboxed start after a sandboxed one.** If the `sandboxed` mark exists, starting without the
  sandbox is refused: a website may have left something in the profile that would then run outside.

`browser.prepare` then makes the folders the start needs (profile, Downloads, To upload, `.config/ibus`,
`.local/share → /dev/null`), wipes and recreates the session folder (nothing a previous run left there
carries over), and copies the archive's GTK settings (recent files off) into it.

### 7.9 The sandbox: what every browser sandbox has

`sandbox.probe` first runs a sandbox like the browser's around `/usr/bin/true`. If bubblewrap is missing
or can't create namespaces, the sandbox is unavailable and the panel says why. When AppArmor's
`kernel.apparmor_restrict_unprivileged_userns=1` is the cause (Ubuntu 24.04+), the panel gives two
workarounds as commands, each with its cost: an AppArmor profile for `/usr/bin/bwrap` with `userns`
(Ubuntu's documented way), or turning the sysctl off until a restart.

The host's `bwrap` and `pasta` are always called by full path from system folders, never through `PATH`
(a folder the user can write to, such as `~/.local/bin`, could hold another). Neither is bundled.

**Namespaces and privileges** (`sandbox.namespaces`):

```
--unshare-all            new user, mount, PID, IPC, UTS, cgroup and network namespaces
[--share-net]            only where the sandbox is to have the computer's network
--new-session            setsid: no TIOCSTI typing into the terminal that started it
--cap-drop ALL
--uid 1000 --gid 1000    always uid 1000, "user"
--hostname localhost
--clearenv               the environment is built from scratch
```

**The system-call filter** (`tools/seccomp.py`; the review of 2026-11-12). Without one, code inside could ask the
kernel for anything a program can: a user namespace of its own gives it root's capabilities over the namespaces it
makes, and with them nf_tables, the new mount API and more. Every bubblewrap the app starts gets a seccomp BPF program,
built by hand (stdlib only), as Flatpak's own filter does:

- refused (EPERM): the kernel keyring (`add_key`, `keyctl`, `request_key`), `syslog`, `acct`, quotas, modules,
  `kexec`, swap, `reboot`, port I/O, 16-bit code (`modify_ldt`, `vm86`), `uselib`, `open_by_handle_at`,
  `lookup_dcookie`, the NUMA calls, `ptrace`, `perf_event_open`, `bpf`, `userfaultfd`; `personality` other than
  Linux's own (and asking); `ioctl` TIOCSTI, TIOCLINUX and TIOCSETD;
- refused as missing (ENOSYS), so programs fall back: `clone3` (its arguments are in memory, where a filter can't
  look; `clone` then gets the checks), `io_uring_*`, and the new mount API (`open_tree`, `move_mount`, `fsopen`,
  `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `open_tree_attr`) but under the nesting profile;
- sockets of any family but Unix, IPv4, IPv6 and netlink refused as unsupported (EAFNOSUPPORT), and of netlink only
  routing, socket diagnostics, SELinux's notifications and device events (EPROTONOSUPPORT for the rest: nf_tables's
  netfilter, generic netlink's families).

By profile: **strict** (no namespaces of any kind through `clone` or `unshare`, no `mount`, `umount`, `pivot_root`,
`chroot` or `setns`) for Xephyr's sandbox, the viewer's, tor's, the unpacking sandboxes and trials, which also get
bubblewrap's `--disable-userns` where it has it (0.8+), and Tor Browser's gate; **browser** (namespaces and `chroot`
allowed, which Firefox's content sandbox and Chromium's need; no mounts, `pivot_root` or `setns`) for Mullvad Browser's
sandbox and Tor Browser's; **nesting** (namespaces, mounts and the new mount API: bubblewrap 0.13 makes its binds
read-only with `mount_setattr` and doesn't fall back, tested on CachyOS) for a trial or Box ticked to start sandboxes
of its own. Filters stack: what runs in a sandbox inside another is held to both. Under Ubuntu's AppArmor profile for
bubblewrap (`bwrap-userns-restrict`, Ubuntu 26.04) what bubblewrap starts has no capabilities, so namespaces stay out
of reach whatever the profile allows: Firefox's own sandbox then runs without its namespaces, its own filter kept, and
the panel says so (`sandbox.bwrap_confined`).

The program checks which system-call table a call came through: x86-64's, and i386's, which a 64-bit program reaches
with `int 0x80` (an x86-64-only filter lets it past everything: the numbers differ), each with its own numbers;
x32's numbers are refused as missing; any other table kills the process. On i386, `socket` and `socketpair` through
`socketcall` (arguments in memory) are refused, so a 32-bit program makes no connections, the direct calls checked
as on x86-64. x86-64 only: elsewhere there is no filter, and the panel says so. Tested in an emulator and in the real
kernel (`tests/test_seccomp.py`: keyctl, a user namespace, AF_PACKET, AF_ALG, netfilter's netlink, TIOCSTI and the
i386 table refused; files, threads, fork and Unix and IP sockets working).

How it gets there (`sandbox.Filter`, `make_filter`): a memory file passed to bubblewrap (`--seccomp FD`); under pasta,
which passes its command nothing but stdin, stdout and stderr, a file in the runtime folder opened as descriptor 3 by
a shell just before bubblewrap (`Filter.wrap`), which bubblewrap reads and closes before anything runs inside
(tested: nothing in the sandbox holds it). Tor Browser's keeper gets the programs for tor's, the gate's and the
browser's sandboxes in its configuration and makes their descriptors itself (`torgate.with_filters`, for
`@SECCOMP:profile@` placeholders).

What a namespace of its own still reaches, under the browser and nesting profiles: traffic control and the rest of
routing netlink in a network namespace it makes, which the filter can't look into. Live-tested (2026-11-12): both
browsers on a private Xvfb on Mint 22.3 (bubblewrap 0.9, Tor Browser in Xephyr, check.torproject.org) and on KDE
Plasma 6.7 Wayland on CachyOS (bubblewrap 0.13.1): Tor bootstrapped, pages loaded, Firefox's content processes had
user namespaces of their own and three filters (ours, the then outer one's, their own). Tor Browser 16.0.1 in the
side-by-side sandboxes (section 7.12), the same day: on Ubuntu 26.04 (GNOME, Wayland, bubblewrap 0.11.1, AppArmor)
and on CachyOS; on Ubuntu Firefox's content processes stayed in the browser's user namespace (AppArmor, above), with
two filters (ours, their own); on CachyOS they had their own.

**Programs that start sandboxes of their own** (`seccomp.nesting_reason`, `installed_reason`): Electron and Chromium
(whose sandbox needs a user namespace), CEF, Qt WebEngine, WebKitGTK and glycin (GNOME's image loaders, in
bubblewrap). Recognised by names in an unpacked tree (`chrome-sandbox`, `*.asar`…), an AppImage's own listing (the
squashfs directory table after its runtime, unpacked where Python can: gzip, xz, lzma, zstd from Python 3.14; nothing
of it is run) or names inside the program (the libraries it links), and for an installed app the program's folders and
what a script runs. A trial or Box of one is pre-ticked "Let it start sandboxes of its own" (the nesting profile), its
cost said; a viewer that is gets it, said in its notes. Under the strict profile glycin runs its loaders without its
own sandbox ("Glycin running without sandbox", inside the app's: tested on CachyOS), and an Electron app may start with
its own sandbox off.

**Filesystem** (`sandbox.system`, `etc_argv`, `proc_masks`, `_folder`):

| Inside | What it is |
|---|---|
| `/usr`, `/bin`, `/lib`… | The host's, read-only (merged-/usr links kept as links) |
| `/proc` | A new procfs for the sandbox's PID namespace |
| `/dev` | bubblewrap's minimal `/dev` (null, zero, full, random, urandom, tty, a new pts, shm). No camera, sound card or GPU (`/dev/dri`) |
| `/sys/devices/system/cpu` | Read-only (Firefox reads it). Nothing else of `/sys` |
| `/tmp` | Empty tmpfs |
| `/etc` | A tmpfs of its own, then remounted read-only (below) |
| `/home/user/<folder>` | The browser's folder, read-only, with its profile and Downloads bound writable |
| `/home/user/.session` | The session folder (the XDG folders) |
| `/run/user/1000` | Made with mode 0700; holds the display and sound sockets bound read-only |

No home folder, no session D-Bus (so no keyring, portals or notifications), no SSH or GPG agent.

**`/etc` is built, not filtered.** A list of things to hide always misses something (disk UUIDs in
`/etc/kernel/cmdline` or `mdadm.conf`, package mirrors and the time zone that say where you are, proxy
credentials, a Firefox policy of the computer's). So `/etc` is an empty tmpfs holding only:

- from the computer (`ETC_KEPT`): `ld.so.cache`, `ld.so.conf`, `ld.so.conf.d`, `nsswitch.conf`,
  `host.conf`, `gai.conf`, `protocols`, `services`, `mime.types`, `os-release`, `mtab`, `alternatives`,
  `fonts`, `ssl`, `pki`, `ca-certificates`, `crypto-policies`, `gtk-2.0`, `gtk-3.0`, `gtk-4.0`, `xdg`,
  `pulse`, `alsa`, `asound.conf`, `drirc`, `vulkan`, `glvnd`, `locale.alias`. A link is kept as a link
  when its target is inside the sandbox (`/usr`, `/proc` or another kept entry); otherwise its target is
  bound in its place;
- the sandbox's own (`ETC_OWN`, written by `identity_files` into the private folder):

  | File | Content |
  |---|---|
  | `passwd` | `root`, `user` (1000, home `/home/user`), `nobody` |
  | `group` | `root`, `user`, `nogroup` |
  | `hostname` | `localhost` |
  | `hosts` | `127.0.0.1 localhost`, `::1 localhost` |
  | `machine-id` | `b08dfa6083e7567a1921a715000001fb` (Whonix's: the same for everyone, so it says nothing) |
  | `timezone`, `localtime` | `Etc/UTC` (with `TZ=UTC` in the environment) |

- `resolv.conf`, depending on the network (sections 7.12, 7.13).

**`/proc` masks**, in the browsers' sandboxes and tor's: `/proc/cmdline` is covered with `ro quiet` (the real one
names the disks' UUIDs), and `/proc/sys/kernel/random/boot_id` with a new random UUID at every start (the
real one is the same for every session until a restart, which would let sessions be linked);
`/proc/partitions` and `/proc/swaps` with their header line only (the disks' names and sizes, swap's file or
device); `/proc/bus` (the input devices' list, with a Bluetooth keyboard's or mouse's hardware address and
devices' serial numbers; PCI's), `/proc/scsi` (the disks' models) and, unless the graphics card is given,
`/proc/driver` (`nvidia/gpus/*/information` holds the card's serial number, readable whether or not the card
was given: matched `nvidia-smi` on the lab) with an empty tmpfs made read-only; each only where this kernel
has it (`proc_masks`, a mount point must already be there). Only a sandbox nothing inside of which mounts a
procfs gets these: once a file of a procfs is covered, the kernel refuses to let anything inside mount a procfs
of its own (tested), which a bubblewrap inside it would need to do. Firefox's own sandbox doesn't, nor does tor:
the browsers' sandboxes and tor's get them (Tor Browser's no longer start one inside another, section 7.12).

**Environment** (`sandbox._env`), and nothing else:

```
HOME=/home/user  USER=user  LOGNAME=user  PATH=/usr/local/bin:/usr/bin:/bin
XDG_RUNTIME_DIR=/run/user/1000  TZ=UTC
XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_DATA_HOME, XDG_STATE_HOME, TMPDIR → /home/user/.session/…
LANG, LANGUAGE, LC_CTYPE, LC_MESSAGES (from the host: the user's language; not the regional formats,
  LC_TIME, LC_NUMERIC and the rest, nor LC_ALL: they say the country where the language doesn't)
the display's variables (section 7.10); PULSE_SERVER when sound is allowed (section 7.11)
__GL_SHADER_DISK_CACHE=0  MESA_SHADER_CACHE_DISABLE=true   (NO_SHADER_CACHE, last, over anything else)
```

The start script moves `HOME` into its own folder, but GTK, fontconfig and Mesa follow the XDG variables:
pointing them into the session folder keeps their state in memory too.

**No shader cache** (`sandbox.NO_SHADER_CACHE`; tor-browser#40054). The graphics drivers keep the shaders pages
compile through WebGL in a cache on the disk, and a page can time one of its own: from the cache it was ready
in 67 ms against 1450 ms (40 programs, stock Mullvad Browser 15.0.24 on Mesa's llvmpipe, on the lab), in the
session after a restart and every one after it. A second site, or the same one after New Identity, can tell the
computer drew it before. The start scripts turn NVIDIA's cache off (`export __GL_SHADER_DISK_CACHE=0`,
tor-browser-build#41017, since December 2023), never Mesa's, which follows `XDG_CACHE_HOME` (else `HOME`): stock,
it lands in the browser's own folder (`Browser/.cache/mesa_shader_cache`, kept between sessions); in the app's
sandbox, before this, in the session folder for the length of a run (107 files, with the card not given). Every
start now sets both, sandboxed or not; without the sandbox a cache folder of the user's own
(`__GL_SHADER_DISK_CACHE_PATH`, `MESA_SHADER_CACHE_DIR`, `MESA_GLSL_CACHE_DIR`), outside the RAM disk, isn't passed
on (`SHADER_CACHE_PATHS`). Tested on the lab (Quadro P620 with NVIDIA 580, Mesa 25): with the card given, the
page ran on it and no cache was written anywhere (session folder, browser folder, `~/.cache`, `~/.nv`); without
it, none either.

For the user's own Tor Browser and Mullvad Browser, `br.shader_cache` blocks Mesa's cache for each browser alone:
the start script gives the browser a home folder of its own, and a file where each of Mesa's cache folders would be
in its `.cache` (`mesa_shader_cache`, `mesa_shader_cache_db`) makes Mesa run without one ("not a directory---
disabling"; on the lab the same shader took 1417 and 1383 ms in two sessions, against 1450 and 67 ms). Games and
other programs keep their caches: no variable is set for the session. A copy started without its start script keeps
its cache with every other program's: `br.start_script` finds one (a package's own program that runs the browser's
program from a folder holding the start script: the AUR's `mullvad-browser-bin`, whose `/usr/bin/mullvad-browser`
also leaves GTK's recent-files list and dconf open, tested) and gives it a menu entry of the account's own, under the
package's id, that runs the start script with `--profile` and the profile it used. Its cache is then the one every native program
writes, other browsers included, and a site can link visits across browsers through it. On the CachyOS VM, with fresh
profiles, two sites and the browsers ended between runs, a shader compiled in Firefox ESR 153 was ready in 111-129 ms
instead of about 830 in that Mullvad Browser 15, and the other way round, in all 6 runs; with the regular Firefox 159
(Mozilla's build and CachyOS's package) once in 12 (133 ms; another run 425 ms). Which builds link depends on how each
hands Mesa its shaders, so the check
names every other browser installed natively (Flatpaks and Snaps keep caches of their own) and rates 8 when there is
one, 7 when there isn't; never lower on an encrypted disk, which does nothing against a website timing a cache. Without
`is-packaged-app` beside it the start script makes the browser's own folder its home: the AUR's
`mullvad-browser-latest-bin` puts that folder in `/opt` with `system-install` alone, so the fix isn't offered there and
says why (`script_unusable`), rather than start the browser in a home it can't write to.

The AUR's `tor-browser-bin` and `tor-browser-alpha-bin` start the browser through its script, from a copy their
`/usr/bin/tor-browser` unpacks into `~/.local/opt/<package>/app`, but empty that folder first (`rm -rf app/*`) whenever
the package's version changes: the block lasts until the next update. So their copy (`unpacked_by`, found through the
menu entry, `tor-browser.desktop` or `tor-browser-alpha-bin.desktop`, even before its first start) also gets a menu
entry of the account's own under the package's id, its commands run through `env` with both of `NO_SHADER_CACHE`'s
variables, marked at its top and made again when the package's entry changes. Tested on the CachyOS VM with
tor-browser-bin 16.0.1: before, the same shader took 1033 ms, then 67 ms in the next session; with the fix, 1033 ms
in both; after a simulated update (its `VERSION` changed, so the next start unpacks it again, removing the block),
1017 ms in two sessions from the menu with nothing cached, while a start typed in a terminal cached 132 files (the check's
note says so). A copy blocked but without the entry (0.1.0b7's fix) is a risk of 4, blocked until the next update.

**Before bubblewrap: crash dumps and the kernel keyring.** Every start (sandboxed or not, Xephyr, and View
offline…) is wrapped by `sandbox.fresh_keyring`, which runs the host's `/usr/bin/python3 -I -c KEYRING`
just before `execv`ing the real command:

1. Writes `0` to `/proc/self/coredump_filter` (inherited by every child, kept across `exec`): a crash dump
   holds no memory, should one be written.
2. Sets `RLIMIT_CORE` to (1, 1) (`NO_CORE`), at which the kernel skips the dump altogether, logging only the
   process's number and name; (0, 0) only where the hard limit is already 0 and can't be raised. Not 0: with a
   pipe in `core_pattern` (systemd-coredump) the kernel ignores a limit of 0 and runs the handler, which kept
   the dump (tested: a 35 MB core with the limit at 0; 48 KB without memory with the filter) and wrote the
   program's command line, environment and the paths of its open files into the journal.
3. `keyctl(KEYCTL_JOIN_SESSION_KEYRING, NULL)`: joins a new, empty, anonymous session keyring, so nothing
   started can reach the login session's kernel keyring (where eCryptfs keeps an encrypted home's key and
   some Kerberos setups their tickets; nothing but session membership guards it). The user keyring is
   already the sandbox's own (user namespaces have their own). Where `keyctl` is refused (`EPERM`,
   `ENOSYS`: a container's seccomp), the keyring is out of reach anyway and the start goes on.

Without python3 only the core limit is applied, through `prlimit --core=1:1`.

**Landlock** (where the kernel has ABI 6, Linux 6.12+): whatever shares a network namespace with the
computer is also scoped with `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL`: it can't
connect to abstract Unix sockets outside its domain (the session's hidden sockets, XWayland's) or signal
processes outside it. Applied by a few lines of python3 inside the sandbox (`sandbox.LANDLOCK`,
`landlock_create_ruleset` with only `scoped = 3`, `PR_SET_NO_NEW_PRIVS`, `landlock_restrict_self`) just
before `exec`. It is applied to Mullvad Browser's sandbox and to tor's (just before tor). Tor Browser's sandbox
and the gate's have network namespaces of their own, which already separate abstract sockets.

**Output.** The browser's own stdin, stdout and stderr go to `/dev/null` (`sh -c 'exec "$0" "$@"
</dev/null >/dev/null 2>&1'`); only the sandbox's set-up errors reach the start log, a memory file
(`sandbox.log_file`: what the sandbox can see of its descriptor names no path). The start script runs
in the foreground, never with `--detach`: bubblewrap returns when its command does.

**PID 1.** bubblewrap's own init was the sandbox's PID 1, and everything in the sandbox could read its
environment (the user, the home folder, `SESSION_MANAGER` with the computer's name, anything exported in the
session), its command line (every folder it binds, in the user's home) and its open files (found in the review of
2026-10-17, tested on Mint and CachyOS). So bubblewrap, pasta and the wrappers before them start with
`sandbox.SPAWN_ENV` (a `PATH` and nothing else); where the command is `STAY`, which reaps, it is the sandbox's
PID 1 (`--as-pid-1`), and bubblewrap's own processes are outside the sandbox's PID namespace, out of its sight;
the viewer's bubblewrap, whose command can't be PID 1, reads its options from a memory file (`--args`,
`sandbox.sealed`; bubblewrap closes it once read), so its command line names only paths inside, and so does
Mullvad Browser's where the computer has no python3 for `STAY` (under pasta, which may pass its command nothing
but stdin, stdout and stderr, the options come as stdin and the Wayland pipe as stdout, `--sync-fd 1`).

**A browser that restarts itself.** Firefox restarts as a new process (about:profiles' *Restart normally…*,
an add-on or a language that asks for it, the Troubleshoot Mode question after crashes): the old process
ends, and the start script, which was waiting for it, returns. bubblewrap returns with its command while
whatever is left runs on under the sandbox's init, so Tor Browser's gate took the restart for the browser
closing and stopped tor (tested with Tor Browser 15.0.24: `firefox.real` left alone with the two inits, tor's
sockets gone, no page loading), and pasta, which ends with its command, would have taken Mullvad Browser's
network. The sandbox's command is therefore a few lines of python3 around the start script (`sandbox.STAY`):
a child subreaper, to which the sandbox's orphans come, that ends only once the start script has ended and
no program from the browser's folder is left (by `/proc/PID/exe`; a program from `/usr` that lingers isn't
waited for), with the script's status. It stays outside Landlock's scopes, which go round the start script
alone. Without python3 on the computer (Mullvad Browser only: Tor Browser's sandbox needs it anyway) the start
script is the command, as before.

### 7.10 The display

**Wayland.** Only a Wayland socket is given: no X11 socket and no `DISPLAY`, so the browser is a native
Wayland client and not an XWayland one (where X11 programs can watch each other). Inside it is
`/run/user/1000/wayland-0`, with `WAYLAND_DISPLAY=wayland-0`, `XDG_SESSION_TYPE=wayland`,
`MOZ_ENABLE_WAYLAND=1`, `GDK_BACKEND=wayland`.

Where the compositor has the **security-context protocol** (`wp_security_context_manager_v1`, as Flatpak
uses), `wayland.sandbox_socket` speaks the wire protocol by hand (stdlib only) to:

1. create a listening socket at `.<folder>-app/wayland-0` (0600) and a pipe;
2. bind the manager, call `create_listener(listen_fd, close_fd)` with the socket and the pipe's read end,
   `set_sandbox_engine("org.daprivacyscanner")`, `set_app_id(<browser id>)`, a random `set_instance_id`,
   and `commit`;
3. close its own connection. The compositor keeps listening on that socket until every copy of the pipe's
   write end is closed. bubblewrap holds that end (`--sync-fd`) for as long as the sandbox runs, so the
   socket stops accepting connections when the sandbox ends.

Clients on that socket are marked as sandboxed, and the compositor withholds what it chooses from them.
The panel asks the compositor what it still offers a marked client (`wayland_exposure`: a throwaway
marked socket in the runtime folder, removed at once, cached a minute), and lists whatever is in
`wayland.RISKY`: clipboard data control, screen copy, layer shell, virtual keyboard and pointer, foreign
toplevel lists and Plasma window management, input methods, output management. Results so far:

- **Sway 1.12**: none of them offered to a marked client (tested in a container: both browsers render,
  and the socket refuses connections once the sandbox ends).
- **KDE Plasma 6.7**: still offers data control, layer shell, output management and input method v1; a
  client of the marked socket read another program's clipboard in the background (tested with
  `wl-paste`). The panel shows these as risks with what to do.
- **GNOME** keeps privileged protocols from every client anyway.

Without the protocol, or if setting it up fails, the compositor's own socket is used and the panel says
what that means (wlroots desktops let any client capture the screen and read the clipboard).

Under pasta, which passes its command nothing but stdin, stdout and stderr (tested), the pipe goes in as
stdin and bubblewrap holds it as `--sync-fd 0`; the browser itself gets `/dev/null`.

**X11.** The X server's socket is bound at `/tmp/.X11-unix/X<n>` where `<n>` is a display number nobody
uses (99–199, neither a socket file nor an abstract socket): libxcb tries the abstract socket of its
display first and only falls back to the path when nobody listens there, so an unused number makes it use
the bound path. An X authority file of its own is written with only that display's cookie, for any host.
Given the X server's socket, a sandbox protects files and the network, not the screen: any X11 client can read
other windows and every key typed (XRecord) and type into them (XTEST), a terminal included, with no kernel flaw
needed, and the sandbox's other walls fall with it. So (the owner's decision of 2026-11-12, `sandbox.own_display`) on
X11 **a display of its own is the default** wherever Xephyr is installed, for the browsers, trials, Boxes and View
offline…; the real display only when the user has ticked that it may (`real_display` in the start's request; the
browser panel's "Give it a display of its own" unticked, or, without Xephyr, "Let … use this display anyway", with
the risk named and the command that installs Xephyr; a Box's "Let it use this display (X11)" in its guide). A start
that would get neither is refused, saying why. A Flatpak trial or viewer is given the X server's socket by Flatpak
(it takes the socket of `$DISPLAY`, which Xephyr's private socket isn't): only with the tick. The panel says all
this, with `sbx.x11_session`'s How to….

A display reached over TCP (SSH forwarding) needs the network: Tor Browser's sandbox refuses it, and
Mullvad Browser then runs without pasta.

**A display of its own (Xephyr)**, the default on X11 where it is installed (`sandbox.nested`):

- Xephyr (the host's; its package named per distribution) runs in a sandbox of its own with **no
  network**, the computer's X socket bound by path, and the computer's cookie, under the strict system-call filter
  and `--disable-userns`. It is the only thing given the real display.
- It listens only on its socket file in the private folder (`-nolisten tcp -nolisten local`), with a
  fresh random 16-byte MIT-MAGIC-COOKIE-1, `-no-host-grab`, `-resizeable`, and `-terminate 10` (it ends
  10 seconds after its last client disconnects: the browser's start runs short-lived X clients first).
- It runs under a focus keeper (`tools/xfocus.py`, run by the computer's python3 in Xephyr's sandbox, the X11
  protocol by hand): without a window manager, X's focus follows the pointer, so moving onto a menu (an
  override-redirect window) took the focus from the browser's window and the browser closed the menu. The keeper
  sets the input focus (revert to PointerRoot) on each normal window the browser maps and on the one the pointer
  enters, never on menus, tooltips or GTK's 10×10 helpers; it disconnects 8 seconds after the browser's windows
  are gone, so `-terminate` still ends Xephyr. Without python3, Xephyr runs alone. For a program on trial, a Box's
  app or a viewer (`--fill`, never the browser's, which sizes its own window for resistFingerprinting) it also gives
  each main window it maps the whole display (ConfigureWindow), or the largest size its WM_NORMAL_HINTS allow, centred,
  and again when the display is resized; a dialog (WM_TRANSIENT_FOR) keeps its size. Without it a program opened at a
  size of its own in the corner, and with no window manager inside it couldn't be moved or resized (live-tested on a
  private Xvfb: GNOME Calculator in a trial and xreader for View offline… filled their displays).
- A viewer's display (View offline…) is started for it and named with it when ~/TempBrowser is closed
  (`viewer.displays`), never ended as the browser's while the viewer runs; it ends by itself once the viewer has
  (tested: both gone within 25 seconds of the viewer).
- The browser's sandbox gets only Xephyr's socket, under an unused display number, with Xephyr's cookie.
- Size (`screen_size`): the work area from `_NET_WORKAREA` (else `xdpyinfo`'s screen less 48 px for a
  panel), clamped to 800×600 … 1400×1100. There is no window manager inside to stretch the window, and
  `resistFingerprinting` sizes the page from the available room in 200×100 steps, so this keeps the page
  the size it would be outside (fingerprints compared live: nothing else differed).
- Costs, said on the page: no copy and paste with other windows, one window.

### 7.11 Sound

Off by default. When ticked, the PulseAudio (or pipewire-pulse) socket is bound at
`/run/user/1000/pulse/native` with `PULSE_SERVER` set. That socket gives far more than sound (tested from
a sandbox holding only it, PipeWire 1.0): the microphone, the real user and host names, other programs
using sound, and modules loaded on request. `module-tunnel-sink` made the server, outside the sandbox and
on the computer's network, connect to an address it was given, and `module-native-protocol-tcp` opened a
TCP listener. Under Tor Browser that connection reveals the real address. The panel lists this under the
box, and asks again before Tor Browser starts with sound.

### 7.12 Tor Browser's network: three sandboxes side by side and a filter

Tor Browser has no network of its own. It runs in a sandbox of its own, beside tor's and the gate's, all three
started by a keeper outside any sandbox:

```
host
└─ python3 KEYRING wrapper → python3 -I -c <torgate.py source> <config>   the keeper: no sandbox, reads only
   │                                                                    exit statuses and the gate's "ready"
   ├─ bwrap  GATE  --unshare-all  (own network namespace: loopback only; strict filter, --disable-userns)
   │     only the tor/ folder, at /run/user/1000/tor; /etc of its own, no resolv.conf
   │  └─ python3 -I -c <torgate.py source> <gate config>   the control-port filter, listening on
   │        /run/user/1000/tor/control (0600); tor's log on its stdin, "ready" on its stdout
   ├─ bwrap  TOR   --unshare-all --share-net  (computer's network; Landlock scopes; strict filter, --disable-userns)
   │     /etc of its own with the computer's resolver (tor and its transports need DNS); /proc masks
   │     TorBrowser/Tor read-only, Data/Tor writable, tor/ at /run/user/1000/tor; nothing of the browser's
   │  └─ tor  (Tor Browser's own binary, from its folder) and its pluggable transports
   │        SocksPort    unix:/run/user/1000/tor/socks
   │        ControlPort  unix:/run/user/1000/tor/tor-control  (cookie auth)
   └─ bwrap  BROWSER  --unshare-all  (own network namespace: loopback only; browser filter)
         /etc of its own, no resolv.conf at all; /proc masks; tor's data folder covered by an empty tmpfs
         only the socks and control sockets bound in, from tor-sockets/ (below)
         TOR_SKIP_LAUNCH=1  TOR_SOCKS_IPC_PATH=…/socks  TOR_CONTROL_IPC_PATH=…/control
         └─ STAY → start-tor-browser → firefox
```

**Why side by side.** Until 2026-11-12 the browser's sandbox and tor's were started by the gate inside an outer
sandbox. Ubuntu's AppArmor profile for bubblewrap (`bwrap-userns-restrict`, on in Ubuntu 26.04) runs whatever a
bubblewrap starts in its `unpriv_bwrap` profile, without capabilities even as root of a namespace of its own, so a
bubblewrap started inside one can't make its namespaces: Tor Browser didn't start there at all ("No permissions to
create a new namespace"; the kernel's log: `apparmor="DENIED" operation="capable" profile="unpriv_bwrap"
comm="bwrap" capname="sys_admin"`). Each is now the first bubblewrap, started by the keeper, which that profile
allows; no profile is added or changed. What each holds is no more than before, and the filter now runs with no
network and nothing of the browser's (it was in the outer sandbox, on the computer's network, with the display's
socket, the profile and the browser's processes).

**The keeper** (`tools/torgate.py`, `keep`) is passed as source with `python3 -I -c` (the AppImage that started it
may be unmounted by the time the browser closes) and imports nothing of the app's. It:

1. starts the gate's sandbox, then tor's (each with `--die-with-parent`, its options read from a memory file,
   `--args`, since its own init is its PID 1, and its filter's descriptor made from the program in the
   configuration), tor's output going to the gate through a pipe:
   ```
   tor --defaults-torrc <shipped>/torrc-defaults -f /run/user/1000/tor/torrc
       DataDirectory <Data/Tor>  ClientOnionAuthDir <Data/Tor>/onion-auth
       GeoIPFile <shipped>/geoip  GeoIPv6File <shipped>/geoip6
       +__ControlPort unix:/run/user/1000/tor/tor-control
       +__SocksPort "unix:/run/user/1000/tor/socks IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth"
       CookieAuthentication 1  CookieAuthFile /run/user/1000/tor/control_auth_cookie
   ```
   with `HOME`, a minimal `PATH` and `LD_LIBRARY_PATH` for tor's own libraries (`--setenv`, after
   `--clearenv`). `<shipped>` is where the archive keeps tor's defaults and GeoIP files: beside tor
   (`TorBrowser/Tor`) from Tor Browser 16, in `Data/Tor` before; the defaults hold the pluggable transports'
   `ClientTransportPlugin` lines, without which no bridge can be used (16.0.1 with the old place: "there is no
   configured transport called obfs4"). tor and its pluggable transports, which parse what the network sends them (Snowflake's: WebRTC
   from volunteers' proxies), get nothing of the browser's: its display's socket and X cookie, sound's socket,
   profile and Downloads (found in the review of 2026-10-17: tor's `/tmp` held `.X11-unix` and `.Xauthority`).
   Its own PID namespace means tor can't watch the gate by its PID (`__OwningControllerProcess`): it dies with
   the keeper instead (`--die-with-parent`);
2. waits for the gate's "ready" (up to 90 seconds): tor's sockets and cookie are there, its filter listens. Then
   it hard-links the two sockets the browser may use into `tor-sockets/`, a folder of the app's that no sandbox is
   given, and checks there that each is a socket of the user's (`link_sockets`): tor's sandbox can write in `tor/`,
   and bubblewrap resolves a bind's source on the computer, so a link tor left in a socket's place would have had a
   file of the home bound into the browser's sandbox. A hard link of a link is a link, refused there, and nothing
   can swap it between the check and the bind;
3. starts the browser's sandbox (its PID 1 is `sandbox.STAY`, so it lasts as long as any browser process does) and
   waits for it. If the gate ends first, the browser goes too (SIGTERM, then SIGKILL after 5 seconds), as when it
   died with the gate. SIGTERM to the keeper is passed to the browser's sandbox the same way;
4. once the browser has ended, closes the pipe that tells the gate so; the gate stops tor (`halt`: `SIGNAL HALT`
   over its control port, so that it saves its state, as on SIGTERM, then waited for by its log's end; a signal to
   tor's bubblewrap would end tor at once, unsaved). What is left after that is ended (SIGTERM, then SIGKILL), the
   links removed, and the keeper ends with the browser's status. Killing the keeper ends all three at once
   (`--die-with-parent`; tested on Ubuntu 26.04: nothing left).

**The gate** (`gate`), in its sandbox:

1. follows tor's log on its stdin: `Bootstrapped N%` lines update `status.json` (`starting`, `connecting`,
   `connected`, `failed`, `stopped`, with progress, summary and the last warning). The panel reads it every 2
   seconds while the browser runs. It waits up to 60 seconds for the sockets and cookie, else says why
   ("tor didn't start: …") and ends, and the keeper starts no browser;
2. asks tor for its version on its own connection (for the PROTOCOLINFO reply);
3. listens on the browser's control socket and filters every connection (below), then says "ready";
4. when told the browser has ended, closes the filter, halts tor and removes the sockets.

Live-tested on 2026-11-12 with Tor Browser 16.0.1: on Ubuntu 26.04 (GNOME, Wayland, bubblewrap 0.11.1, AppArmor's
profile on) check.torproject.org said the browser uses Tor, the security level was Safest with no restart asked and
no bar, a page's no-JavaScript fallback was taken; obfs4 and Snowflake bridges connected (the circuit display with
its countries); the gate had only a loopback interface and the tor folder; Quit halted tor (its state file written
at that moment) and left nothing running; killing the keeper left nothing; killing the gate ended the browser and
tor. On CachyOS (KDE Plasma, Wayland, bubblewrap 0.13.1, the compositor's marked socket) the same, with Firefox's own
content processes in namespaces of their own; on Mint 22.3 (X11, bubblewrap 0.9) in Xephyr, where
check.torproject.org also said "JavaScript is disabled".

**The control-port filter.** Each browser connection gets its own upstream connection to tor,
authenticated by the filter with the cookie, which the browser never sees. The browser's commands are
handled line by line (lines over 64 KiB end the connection):

| Command | Handling |
|---|---|
| `AUTHENTICATE …` | Answered `250 OK` by the filter itself (any credentials) |
| `PROTOCOLINFO` | Answered by the filter: `AUTH METHODS=NULL`, tor's real version |
| `QUIT` | Answered and closed |
| `GETINFO k…` | Forwarded only if every key matches: `version`, `status/bootstrap-phase`, `status/circuit-established`, `circuit-status`, `net/listeners/socks`, `ns/purpose/bridge`, `ns/id/<40 hex>`, `ip-to-country/<address>` |
| `GETCONF k…` | Forwarded only for `Bridge`, `ClientTransportPlugin`, `UseBridges` |
| `SETEVENTS e…` | Forwarded only for `CIRC`, `STREAM`, `STATUS_CLIENT`, `EXTENDED` |
| `SIGNAL NEWNYM` | Forwarded (New identity / new circuit) |
| `ONION_CLIENT_AUTH_VIEW [addr]`, `…_ADD addr x25519:<key> [ClientName=…] [Flags=Permanent]`, `…_REMOVE addr` | Forwarded, each argument checked against a strict pattern (v3 onion address, base64 key) |
| A multi-line command (`+…`) | Its data skipped; refused |
| Anything else | `510 Command filtered` |

So `SETCONF`, `RESETCONF`, `SAVECONF`, `LOADCONF`, `SIGNAL SHUTDOWN`/`HALT`/`RELOAD`, `GETINFO address`,
`ADD_ONION`, `MAPADDRESS`, `TAKEOWNERSHIP` and the rest are refused: a compromised browser can't point tor
at a proxy or bridge of its choosing (which would reveal the address), learn the real address, or stop tor.
Live-tested: check.torproject.org says the browser uses Tor; from inside, the internet, 127.0.0.1 and the X
server's abstract socket are unreachable; `SETCONF`, `SAVECONF`, `SIGNAL SHUTDOWN` and `GETINFO address`
are refused; the circuit display works with nothing refused (logged: `SETEVENTS CIRC STREAM`,
`circuit-status`, `ns/id`, `ip-to-country`).

**Bridges.** With `TOR_SKIP_LAUNCH`, Tor Browser turns its own Connect page and bridge settings off
(`TorConnect` and `TorSettings` only run when it starts tor itself), so the panel chooses:

- *Directly*, or the built-in **obfs4**, **Snowflake** or **meek** bridges, read from the browser's own
  `chrome/toolkit/content/global/pt_config.json` in `omni.ja`;
- or **Bridges I have…**: pasted lines (a leading `Bridge ` is fine), at most 50, each matching
  `[transport] address:port [40-hex fingerprint] [key=value…]` where the transport is one
  `torrc-defaults` knows (obfs4, webtunnel, snowflake, meek_lite, conjure). Anything else is refused.

The choice is kept in `bridges.json` (in the RAM disk) and written into the app's own `torrc` at each start
as `UseBridges 1` and `Bridge …` lines. The pluggable transports are tor's own (`lyrebird`,
`snowflake-client`, `conjure-client`, from `torrc-defaults`), run by tor in its sandbox.

**A VPN underneath.** The card notes that a trustworthy VPN adds a second layer: if the browser were ever
made to connect around Tor, sites would see the VPN's address; the cost is that the VPN sees when Tor is
used.

### 7.13 Mullvad Browser's network: pasta and a fence

Mullvad Browser needs ordinary internet access. Where pasta (the `passt` package) works here
(`probe_pasta`), it gets a network namespace of its own:

```
host
└─ python3 KEYRING wrapper
   └─ pasta --config-net --quiet --no-map-gw --no-icmp -t none -u none -T none -U none --dns-forward 169.254.0.1
            -M 9a:55:9a:55:9a:55 -I eth0 -a 10.0.2.15 -n 24 -g 10.0.2.2 [-a fd00::15 -g fe80::9855:9aff:fe55:9a55 | -4] --
      └─ /bin/sh -c '<fence rules> ; exec "$0" "$@"'      (as root of pasta's namespace)
         └─ python3 -I -c <dnsfilter.py> <config> …        (binds 127.0.0.1:53, forks the filter, execs on)
            └─ /bin/sh -c 'exec 3<"$0" …' <filter file>     (the system-call filter as descriptor 3)
               └─ bwrap --unshare-all --share-net --seccomp 3 …   (pasta's namespace, not the computer's)
                  /etc/resolv.conf: nameserver 127.0.0.1, options edns0
                  └─ python3 STAY → python3 LANDLOCK → start-mullvad-browser → firefox
```

- `--no-map-gw`: the host's loopback services aren't reachable through the gateway address. No ports
  are forwarded in either direction (`-t/-u/-T/-U none`).
- DNS goes to pasta's forwarder at 169.254.0.1, which forwards to the computer's resolver. That resolver answers
  more than the internet's names: tested from pasta's namespace on Mint 22.3 (systemd-resolved, 2026-11-12),
  `_gateway` gave the router's address, `_outbound` this computer's address on the local network, `_localdnsstub`
  127.0.0.53, the computer's own name its addresses, and reverse lookups of the router's and this computer's
  addresses their names (`OPNsense.localdomain`, the hostname); a router's DNS answers its devices' names, and a
  single label can go out as LLMNR. So the sandbox's lookups go first to **the lookups' filter**
  (`tools/dnsfilter.py`, `sandbox.dns_filter`): the computer's python3, started by the fence's script as root of
  pasta's namespace, binds 127.0.0.1:53 there (UDP and TCP; the sandbox's resolv.conf names it), forks, and the
  parent execs on into bubblewrap. It refuses (REFUSED) a query with more than one question, a single label, a name
  under local, localhost, lan, home, internal, localdomain, intranet, corp, private or home.arpa, and a reverse lookup
  (in-addr.arpa, ip6.arpa) of a network that overlaps a refused one (the fence's ranges, the computer's own networks,
  NAT64's forms of them); and an answer with an A or AAAA record in a refused network, whole (Mullvad's proxies,
  which the fence lets through, excepted). The rest it passes to the forwarder over one socket marked with SO_MARK
  `0x5ec` (which needs the namespace's CAP_NET_ADMIN: the sandbox has none, tested), and the fence's pref-50 rule lets
  only marked UDP to 169.254.0.1:53 through; the sandbox's own queries to the forwarder are refused (EACCES, tested).
  Reverse-path filtering is turned off in pasta's namespace (`rp_filter`, loose on Ubuntu and Mint and copied into
  new namespaces), whose check of the forwarder's answers is an unmarked lookup that met the prohibit rule: the
  answers were dropped (tested). The filter dies with bubblewrap (the parent-death signal, and a look at its parent
  every second; nothing was left running, tested), drops every capability once its sockets are made, sets
  no_new_privs, applies Landlock's limits on files (none allowed) and the strict system-call filter. TCP clients are
  answered over the same UDP upstream. What it can't tell: a network whose resolver answers names under its own public
  domain (a company's split DNS) still gets those resolved, though not to local addresses. Without python3 the sandbox
  asks the forwarder itself, as before, and the panel says the lookups go to the computer's resolver as they are.
  Over TCP the forwarder itself is used only without the filter, and only where pasta forwards that too: pasta
  2026-01-20 does, 2024-02-20 (Mint 22.3, Ubuntu 24.04) sent the connection on to 169.254.0.1 itself, where it timed
  out (tested). `probe_fence` connects to it from inside (2 seconds at most, once per run of the app) and the fence
  lets TCP through only where that worked; elsewhere it is refused at once. The sandbox's resolver asks with EDNS0,
  so a large answer comes over UDP.
- `--no-icmp`: pasta passes the namespace's pings on from ping sockets of the computer's, to any host; nothing in a
  sandbox needs to ping (the review of 2026-11-12; Try an app had it already).
- Abstract Unix sockets belong to the network namespace, so the session's are out of reach.
- **Addresses of its own** (`sandbox.pasta_opts`). By default pasta copies the computer's interface name, its
  addresses (the global IPv6 address, which a VPN hides and whose EUI-64 form holds the hardware address), its
  routes and its gateway, and shows the gateway's hardware address inside: the computer's own (pasta 2024-02-20,
  Mint 22.3) or, since newer pasta mirrors the computer's neighbour table, the router's (2026-01-20, Fedora 44),
  which public Wi-Fi maps can place; all of it readable without privileges (netlink). So the namespace has
  `eth0`, pasta's hardware address the same for everyone (`-M`, newer pasta's own default), IPv4 10.0.2.15/24
  through 10.0.2.2 (what VirtualBox and QEMU give their guests) and IPv6 fd00::15/64 through the link-local
  address of that hardware address. The gateways must be addresses the computer has no neighbour at, or newer
  pasta shows that neighbour's hardware address (tested with fe80::1, a common router address, and with
  10.0.2.2): the IPv4 network moves to 10.0.3.0/24 (then 172.31.250.0/24) when one of the computer's networks
  overlaps it, and only pasta's own hardware address makes the IPv6 gateway. An IP version the computer has no
  default route for is left out (`-4`, `-6`): newer pasta otherwise made up an IPv6 network through fe80::1. With
  `-a` and `-g` pasta copies no routes or addresses (2024-02-20 and 2026-01-20, tested).

**The fence** (`sandbox.fence`, needs iproute2's `ip`). pasta connects anywhere the computer can, so before
bubblewrap starts, policy-routing rules are added inside pasta's namespace (as its root; the sandbox inside
has no capabilities to change them):

| Pref | Rule |
|---|---|
| 40 | `lookup main to 10.64.0.1 ipproto tcp dport 1080` and `to 10.124.0.0/22 … dport 1080`: Mullvad VPN's SOCKS5 proxies inside its tunnel, which Mullvad Browser's extension uses to change the browser's country (from mullvad.net/help/socks5-proxy and Mullvad's proxy list, which also uses 10.124.2.x). Only reachable while Mullvad VPN is connected |
| 50 | `lookup main to 169.254.0.1 ipproto udp dport 53 fwmark 0x5ec`: pasta's DNS forwarder, for the lookups' filter's queries alone (without the filter: unmarked, and `… ipproto tcp dport 53` where pasta forwards DNS over TCP) |
| 100 | `prohibit` to 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT, Tailscale), 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 |
| 100 | `prohibit` to fc00::/7, fe80::/10, ff00::/8, and NAT64's forms of the IPv4 ranges above and of 127.0.0.0/8 in 64:ff9b::/96 and 64:ff9b:1::/96 (`sandbox.nat64`: on an IPv6-only network with NAT64, 64:ff9b::c0a8:101 is the router at 192.168.1.1 through the network's translator; the rest of the prefix is how such a network reaches the IPv4 internet, and stays open. A provider's own NAT64 prefix can't be known from here) (tolerated if pasta has no IPv6) |
| 100 | `prohibit` to **the computer's own networks** (`host_networks`, listed on the computer with `ip -j address show` and `ip -j route show table all type unicast` just before pasta starts): every address of the computer's on every interface (but loopback's) and the network it is on, a point-to-point link's far end, and the unicast routes of every routing table, merged, those inside the ranges above left out; the IPv4 ones in NAT64's forms too. Not the default routes, nor the routes through one interface that between them cover at least a sixteenth of IPv4 (or of IPv6's 2000::/3): a VPN that carries everything but the local network does it with broad routes in place of a default one (WireGuard's "exclude private IPs", OpenVPN's 0.0.0.0/1 and 128.0.0.0/1) |
| 100 | `prohibit` to **every unicast route pasta copied except the default one**, should a pasta version copy any |

pasta connects from the computer's side, so the namespace's own routes say nothing of where it can reach: before
the computer's own networks were listed, the browser reached services on the computer's addresses on other
interfaces (a second network card, a VPN's own), the ranges a split VPN routes, Docker's and libvirt's public IPv6
networks, and the local network's IPv6 prefix while a VPN held the default route (found in the review of
2026-10-17 in throwaway namespaces; refused since). Routes added after the start (a VPN connected later) are
fenced from the next start. The listing fails closed: when `ip` can't list them, or there are more than 4096
(`FENCE_MAX`), the panel says the local network can't be fenced off, and a start the panel showed fenced is
refused. The router's own public (WAN) address can't be fenced: the computer doesn't know it without asking the
internet, and many routers answer their settings page on it from inside.

`prohibit` rules sit ahead of the main table, so no route can be more specific than them. If any IPv4 or
own-route rule fails, the start stops ("The local network could not be fenced off"). Tested in a namespace
with a made-up public /64, a routed second subnet and a public /16; live-tested with a router and a Docker
bridge refused, the internet and DNS reached, and the Mullvad extension switching the sandboxed browser
from Budapest to Stockholm while the computer stayed in Budapest.

Without `ip` it runs unfenced and the panel says so. **Without pasta** it shares the computer's network: a
prominent danger box says a compromised browser could then read this computer's and the router's hardware
addresses (netlink and the neighbour table need no `/sys`; tested), reach every device on the network and
this computer's services, and gives the command that installs passt. Its `/etc/resolv.conf` then holds only
the computer's `nameserver` and `options` lines; search domains, which can name the network, are dropped.
A failed probe is retried after 15 seconds, so installing passt shows when the panel is reopened.

### 7.14 Starting and watching

The final command is spawned with `cwd=/` (never the RAM disk), `sandbox.SPAWN_ENV` (none of the app's
environment), stdin and stdout `/dev/null`, stderr to the start log (a memory file), `start_new_session=True`, and
the Wayland pipe passed if there is one. One start at a time per browser, in every copy of the app (a lock in the
runtime folder, `owner.hold`): another copy's start would empty the session folder this one's browser runs in.
Then:

- the `sandboxed` mark is written;
- the start is watched for 3 seconds: if it exits with an error, the reason is said in the app's own words, matched
  from what only the sandbox's set-up writes (`sandbox.START_REASONS`: bubblewrap's, pasta's, the fence's, the
  Landlock and keyring wrappers', the filter's, the gate's "tor didn't start"), the line that said it only quoted as
  the start log's (`sandbox.start_reason`: one line, cut short, control characters and those that reorder or hide
  text shown as their codes, `visible`); anything else by its exit status. Xephyr is killed, and the mark is removed
  if this was the copy's first start and the log says the sandbox stopped before the browser ran (`NEVER_RAN`). The
  review of 2026-11-12 found the log within the sandbox's reach: `STAY`, which holds it as its stderr, was dumpable,
  so anything inside could open `/proc/1/fd/2` and write a sentence of its choosing after "couldn't start:", or the
  lines that shed the mark. `STAY` now makes itself undumpable before it starts anything (its `/proc` entries are
  root's, which nothing inside is: tested with the real bubblewrap, `/proc/1/environ`, `/proc/1/fd` and writing to
  `/proc/1/fd/2` refused), and the browser's own output goes nowhere (`QUIET`). Without python3 (no `STAY`)
  bubblewrap's own init holds the log within the browser's reach, so the log is no proof then and the mark stays;
- tor's status (`tor_status`: status.json, which tor's sandbox can write) is shown as tor's own words, quoted after
  "Tor says:", made visible and cut short; a viewer's failure the same (its stderr is the log, which a file it opened
  can steer);
- a later failure is reported by the panel (`launch_problem`, which also reaps the process), by its exit
  status alone: once the browser has run, the log could hold anything a website that took it over wrote into
  it, which the page would show as the app's own words. It stays on
  the card until the user dismisses it (OK) or starts the browser again: said once, the panel's next poll drew the
  card without it two seconds later (found in the review of 2026-10-17).

**Is it running?** A process of the user's is the browser when `/proc/PID/exe` points into its folder on
the RAM disk, or (seen from outside, a sandboxed program's path is the one it sees) to
`/home/user/<folder>/…` on the RAM disk's device.

**Without the sandbox** (unticked, or bubblewrap can't run): `start-tor-browser --detach` in its folder,
with the host's environment and the XDG folders pointed into the session folder. The page says it can
then reach your files. Tor Browser then starts tor itself, with its own Connect page.

### 7.15 Before the start: what still puts a session on the disk

The panel checks, and offers a fix for, what can write the session to disk however it runs (`risks`):

- **Swap that reaches a disk** (anything in `/proc/swaps` except zram without a writeback device). It
  takes the browser's own memory, not only the RAM disk's. *Turn swap off for this session* calls the
  helper's `swap_off`: devices come from `/proc/swaps`, never the request; refused unless memory can take
  back what is in swap plus 512 MB; what was turned off, with priorities, is recorded in
  `/run/daprivacyscanner/swap.json` so `swap_on` puts back exactly that. The equivalent `swapoff`/`swapon`
  commands are shown. A warning appears when the browser (~2 GB) plus the RAM disk's size exceed what is
  free. A reboot turns swap back on anyway.
- **Thumbnails kept on disk** of what is in To upload and Downloads, if the user opens them in a file
  manager: the thumbnail guide.
- **Crash dumps kept on disk** (`enc.coredumps_retained`): the browser's own are already empty (7.9);
  other programs' aren't.
- **File search**: Baloo indexes a RAM disk under the home folder, contents included, and isn't trusted to
  forget (a folder excluded afterwards stayed in its index across a restart, tested on Plasma 6.7). So the
  panel's button applies `desk.indexers`' `baloo_off` option: indexing off and the index deleted (a fix,
  in History). LocalSearch/Tracker never enters `~/TempBrowser` (the `.trackerignore` and `.nomedia`
  marks), but either indexer covers what is saved out of the browser into folders it indexes.

### 7.16 Files in and out

**Add a file to upload…** copies the user's file (never moves or links it) into `Browser/To upload`, which
the sandbox sees read-only. With mat2 installed, the copy is cleaned of metadata first by default, in a
staging folder at the RAM disk's top that no sandbox is given; only the cleaned copy goes in. The page
says the file's name goes with it. The file is never reached through a link the browser could have planted
(`transfer._open_chosen`): its path is refused when it goes through a link inside `~/TempBrowser`
(`pick.resolved`), and a file there is opened one name at a time from the RAM disk's top, without following
links (the browser could plant one between the check and the open), and only as a plain file with one link on
the RAM disk's own device, as a finished download. Save…'s folder is reached the same way (a folder link the
browser planted could lead to an autostart folder).

**The TempOutbox** (`transfer.run_outbox`) does the same for files the user copies in with the file
manager. Each browser has its own, `~/TempBrowser/Outbox for Tor Browser` or `… for Mullvad Browser`, at the
RAM disk's top, which no sandbox is given, holding `Originals` and `Not cleaned`. It is made when the browser
is set up (`default_outbox`) where mat2 is installed, unless the permanent Outbox is set up and watching
(`permanent_outbox`: its path unit, and the link in `default.target.wants`, read from the files so the panel
can ask every few seconds); then the panel says to use `~/Outbox` and copy from `~/Outbox/Cleaned`. The panel
turns it off (`remove_outbox`: refused while anything is in it, since an original may be the user's only copy)
and on. A thread of the app's (`create_app(watch_outbox=True)`, every 2 seconds) looks into each set-up
browser's TempOutbox while `~/TempBrowser` is mounted (`ramdisk.mounted`: the mount table only): every regular
file at its top, not hidden or named as a partial copy (`.part`, `.crdownload`, `~`: counted apart on the panel), is
taken once it has finished arriving: its size and mtime the same as at the last look, unchanged for 2 seconds, and
open for writing by no program of the user's (`open_for_writing`, from `/proc/PID/fdinfo`: a file manager holds
the file so while a copy pauses; with the mtime alone, a copy that paused 5 seconds was cleaned half-way and passed
on as cleaned, found in the 2026-10-17 review). It is opened without following links, cleaned through the staging
folder, and looked at again before anything reaches To upload: one that changed while it was cleaned goes no
further and waits. Then it goes into that browser's To upload under a free name (`_add_fd`, what Add a file to
upload… does), and the original into `Originals`; one that can't be cleaned (mat2 doesn't know the format, no
room) or can't be read goes into `Not cleaned` and is never passed on. Folders put there are left as they are;
without mat2 nothing is touched. No desktop notification is sent (a notification history can keep the names on the
disk): the last 20 events are kept in memory for the panel, which follows the status every 2 seconds while a
TempOutbox is on, and forgotten when `~/TempBrowser` is wiped. Closing it stops a run after the file under way
(`transfer.STOP`) and waits for that one (`OUTBOX_LOCK`) before it looks for programs using the disk, and holds
both until the files are overwritten (`browser.outboxes_stopped`): the TempOutbox's own mat2 was taken for one.
Closing, or quitting, deletes the TempOutbox with the rest, `Originals` and `Not cleaned` included, which may hold the
user's only copy of a file, and nothing named them: the Outbox's box says so plainly, with what they hold, and the
close dialog lists, counted, what waits in each TempOutbox and what those two hold (`transfer.outbox_files`).

**Downloads.** The browser owns its Downloads folder and could fill it with anything, including a link to
`~/.ssh/id_ed25519` that points nowhere inside the sandbox but at the real key outside. So
`transfer.downloads` reads the folder one name at a time without following links (every folder from the
RAM disk down) and lists only finished downloads: regular files on the RAM disk's device, one hard link,
no `.part`, unchanged for 2 seconds, no larger than the RAM disk and not sparse (`transfer.plain`: a file of
holes 8 EiB long was hashed for ever, found in the 2026-10-17 review). Each is judged by content (`sniff.py`,
from an open descriptor, at most 16 MB read; a ZIP's index only when its end record says it is at most 20,000
entries and 2 MB, since `zipfile` loads all of it first: a million entries took 3.6 s and 534 MB), and its
SHA-256 taken, remembered while unchanged (device, inode, size, mtime and ctime, which no program can set back:
with the mtime alone, a picture rewritten as a program of the same size stayed "a PNG picture"). One download
is judged at a time, for at most a second per listing: a listing that finds one being judged goes on without
it (counted among the things not listed), so a slow file never holds every server thread, and closing
`~/TempBrowser` stops a digest under way (`transfer.STOP`):

- programs whatever their name: ELF, Windows PE, Mach-O, Java, Android, `#!` scripts, `.desktop`
  launchers, Windows shortcuts ("it is a Linux program, though its name says pdf file");
- disk images (ISO 9660 and UDF at 32 KiB, DMG, qcow2, VHDX, VMDK, or by name): never presented as safe,
  since opening one mounts it;
- archives: their contents aren't checked, but a ZIP's programs are listed;
- macros: OOXML's VBA project (`vbaProject.bin`, or a part of any name by its content type or the relationship
  to it, from `[Content_Types].xml` and the `.rels` parts, each read bounded: 256 KB of each, 200 parts), Excel 4.0
  macro sheets and ActiveX controls the same way, OLE2 `_VBA_PROJECT`, OpenDocument Basic/Scripts, macro-format
  names; in a
  PDF, JavaScript, `/Launch` and embedded files. Finding none proves nothing (a PDF's objects can be
  compressed), and the page never calls a file safe;
- documents that can fetch from the internet when opened (PDF, office, HTML, SVG…): named, with View
  offline… suggested.

**Save…** and **View offline…** never use the browser's file directly. `transfer.snapshot` first copies it
into a folder of the app's at the RAM disk's top that no sandbox is given, judges the copy again, and
continues only if it matches the listing's `check` (a digest of its size, verdict and SHA-256) that the
page sent back; otherwise 409 with the new verdict. Save… writes a new file in a folder the user chose, under
a cleaned name (no control characters, slashes, leading dot or dash, at most 200 bytes), never over an
existing file and never executable.

**View offline…** (`viewer.py`) opens the copy in the desktop's own viewer for its type (`xdg-mime query
default`, then its `.desktop` file's `Exec`), with **no network at all**:

- a program from `/usr` or `/opt` runs in bubblewrap with no network namespace sharing (loopback only), an
  `/etc` of its own holding only what programs read (`sandbox.app_etc`, as a trial's: it was the computer's
  whole `/etc` with a list of what to cover over it, which missed what no list foresees — the review of
  2026-11-12, under Try an app above), an empty home in memory with only that file read-only in it (bound by
  itself, never through a link in its place: `sandbox.bind_source`), and the display (a compositor-marked
  Wayland socket where possible). No sound, no D-Bus, no other file, and no resolver at all. No `/proc` masks
  (glycin-based viewers start sandboxes of their own);
- a Flatpak app runs in Flatpak's own sandbox with what it declares for itself dropped (`flatpak run --sandbox`)
  and only this given back (`viewer.FLATPAK_RUN`): the display (`--socket=wayland`, or `x11` with `ipc`), the
  filtered session bus with its own name (`--own-name`: Text Editor 51 won't start without it), `--unshare=network`,
  `--no-talk-name=org.gtk.vfs.*`, `--nosocket=pulseaudio`, and the copy's folder read-only (`--filesystem=…:ro`, in
  place of the document portal). Of the launcher's own options only the branch, architecture and command are kept.
  The review of 2026-10-17 found the launcher's permissions with only the network and folders taken away too much:
  GVFS's daemons, outside the sandbox, fetched a web address for it and read the trash, and the sound server's socket
  let it load a module that connected out; and its per-app `/tmp` kept what it remembered after `~/TempBrowser` had
  closed. Under `--sandbox` (tested with Flatpak 1.14.6 on Mint 22.3: Evince 48 and Text Editor 51 open the file)
  none of those reach it, and it has no `~/.var/app/<id>`: its home and `/tmp` are the sandbox's own, in memory.
  It isn't started while `flatpak ps` lists it (already open, it is handed the file over the session bus and opens
  it itself, with its network and history: Text Editor recorded it, Flatpak Firefox fetched the page's pictures),
  and a web browser from Flatpak (by `browsers.yaml`'s menu entries, or its entry's `WebBrowser` category) isn't
  used: the page says to choose a document viewer, or a browser from the distribution's packages, which runs in
  the app's own sandbox. A link clicked in it can still open in the default browser through a portal, and the page
  says so; a screen reader can't read it;
- a Snap, or a program in the home folder, isn't started.

Either runs under a keeper (`viewer.KEEPER`, the computer's python3, which waits for it) and with
`--die-with-parent`: the whole sandbox ends when the keeper does, so ending any part of it ends all of it (a
SIGTERM to bubblewrap left its init, the sandbox's PID 1, which ignores one from outside, and the viewer running
under no process the app knew), while quitting the app leaves an open viewer open. A viewer that ends within the
2-second watch has shown nothing (it can't go on in the background: its sandbox ends with it), and the page says
so: xreader did with one already open from an earlier view; a Flatpak viewer may have handed the file to a copy
opened meanwhile.

The viewer's own files live in `.<folder>-app/view`, never over the browser's. An earlier view's copy stays while
its viewer runs (it may have read the file and closed it), while a program holds it open or has it mapped (matched
by inode, since a sandbox sees another path), and for a minute when neither can be told (a viewer still starting,
or another copy of the app's view); otherwise it is removed at the next view. Live-tested: xreader showed a PDF from
its sandbox.

The two folders are also ordinary folders on the user's side (the panel's buttons open them in the file
manager); using the buttons adds the checks above.

### 7.17 Closing

**Close and overwrite…** (or quitting the app) runs `ramdisk.wipe` then the helper's `ramdisk_close`
(section 8). It is refused while anything uses the RAM disk. Users are found by path and by device
(`ramdisk.on_device`: cwd, open files and memory maps on the tmpfs's device, since `/proc` shows sandboxed
paths as the sandbox sees them). A running browser is named as the browser ("Close Tor Browser first"),
together with the processes around it: its parents up through `bwrap`, `python3`, `sh`, `bash`, `env`,
`pasta`, and what those started (tor, its transports), stopping at the app's own process. A viewer
View offline… started is named "Firefox (opened by View offline…)" or similar. Any other program of the
user's is named as itself. A display of its own (Xephyr in its sandbox) goes under the browser's name while the
browser runs; once the browser has quit it still holds its socket folder for up to 18 seconds (`-terminate 10`, then
the focus keeper's 8), and closing was refused meanwhile ("Close Xephyr, bwrap, python3 first") and quitting left
the disk open (found in the review of 2026-10-17): the close now ends it (`end_display`: SIGTERM, then SIGKILL after
3 seconds), the app having started it for a browser that is gone. Only Xephyr, the bubblewrap processes above it
and the focus keeper's python3 inside are ended, never a python3 that isn't bubblewrap's child (a copy of the app).

Closing is refused while a browser is being set up or started, in this copy (its job, a start under way) or in
another (`owner.hold` on both browsers' keys, held for the length of the close, so none starts meanwhile): a close
during a set-up wiped the download or the unpacking under it, and the job failed with an error naming neither
(found in the review of 2026-10-17). The page hides the button while its own set-up runs. Quitting leaves the disk
to a copy that is setting a browser up in it (that copy takes it over as it shows the panel), while its own set-up
ends with it.

When the app quits with the browser still running, `~/TempBrowser` stays open until it is closed from the
app later or the computer restarts. What quitting did is printed only to a terminal: it names programs ("Tor
Browser still uses it"), and off a terminal stderr is a log on the disk (`~/.xsession-errors`, the journal; found in
the review of 2026-10-17). Anything else using it keeps it open too, a viewer View offline… opened above all (quitting
leaves the viewer open), and the window said nothing of it: so quitting asks first when something other than the
browser would keep it open (`browser.left_open_by`, `GET /api/quit`), from the page's Quit in `--browser` mode and,
in the window, as it is closed (`app.CloseGuard`, on pywebview's closing event). The close is put off only while
`~/TempBrowser` is open and this copy's (the mount table, read in GTK's thread); what uses it is looked for in a
thread, and the page asked with `run_js`, the script run as it is (`evaluate_js` wraps it in an `eval`, which the
page's Content-Security-Policy refuses). Quit anyway closes the window through `POST /api/quit`; closing it again
within 20 seconds, a page that can't ask, and a signal (a logout) close it as before. A quit that left it open
(something using it or mounted inside it, the unmount's password declined) says why to the panel at the next start: a
note in the runtime folder (`daprivacyscanner/tempbrowser-left-open.json`, 0600, in memory, gone at logout; none
without a runtime folder), taken by the copy that owns the disk then as its browser panel is shown, shown there until
OK, and removed once the disk is closed. When the app is told to end by a signal (SIGTERM or SIGHUP: logging out, shutting down;
`--browser` mode handles them too, where Python would otherwise end without closing anything), it closes the RAM disk
as on Quit, asking for the password if it has to (the owner's decision of 2026-10-17): the files are overwritten in a
thread of their own while administrator access is asked for, never after the password, and it is unmounted once both
are done. At a logout the prompt can't come up: systemd stops Plasma's polkit agent (`plasma-polkit-agent.service`)
as the logout begins, and a menu-started app, in a scope of its own, gets its SIGTERM only when the user's manager
stops, about 10 seconds after the last session (tested on CachyOS: the files were gone 0.3 s after the SIGTERM, pkexec
found no agent). So the helper's drop-in for the mount unit (step 7 of opening) binds it to the user's manager:
systemd unmounts it once that has stopped, after every process of the user's has ended, the app's overwrite
included, with no password (tested on CachyOS with a real Plasma logout, window mode: Plasma closed the window, the
app overwrote the files within a second, user@1000.service stopped 10 s after the last session, and the RAM disk with
it, nothing about it in the journal). The empty folder left underneath is put back as the user by the app at its next
start (`ramdisk.put_back`, the start's background work). A user who lingers (`loginctl enable-linger`) keeps the
manager running, and the RAM disk with it, until it is closed or a restart. On Cinnamon (tested on Mint 22.3, X11)
neither half holds: the app, not a session-management client, ends with the X server before its clean-up runs, and
processes Mint leaves in the logged-out session (the location agent, the printer applet) keep the user's manager
running, so the page says to quit the app before logging out.

**Which copy closes it** (`tools/owner.py`, the owner's decision of 2026-10-17). Every right-click entry starts a
copy of the app of its own, and quitting one closed `~/TempBrowser` under another, with a download not saved yet
(seen on the lab). The copy that opened it owns it: a token at the RAM disk's top (`.daprivacyscanner-owner`, which
no sandbox is given) and an `flock` on a file of that token's name in the runtime folder, which the kernel releases
however the copy ends. Only the owner closes it when it quits and empties its TempOutboxes; Close and overwrite…
works from any copy, and its mark goes first, so a disk opened there later is nobody's until claimed. A disk whose
owner has ended is taken over by the next copy that shows the browser panel, never by a copy that only quits.

### 7.18 What the sandbox doesn't hide

Said on the page: the kernel's version and build (any program can ask `uname`), the distribution
(`os-release`, which libraries read), and the processor's model and known flaws
(`/sys/devices/system/cpu`). With no `/dev/dri`, pages render on the processor (WebGL and video work,
slower): this also keeps the GPU drivers, a large part of the kernel, out of reach.

Also said on the page, since the sandbox can't cover them (found in the review of 2026-10-17):

- **When the computer was started.** `/proc/stat`'s `btime`, `/proc/uptime`, and the clocks every program
  reads (`CLOCK_BOOTTIME`, `CLOCK_MONOTONIC`) stay the same for every session until a restart, like the boot
  id (which is covered). A time namespace would shift them (Linux 7.0 applies its offset to `btime` and
  `uptime` too: tested), but bubblewrap has none (0.9, 0.11 and 0.13, the lab's), and covering the files alone
  would leave the clocks. The page says to restart between sessions that should be kept apart.
- **The login session's number** (`/proc/self/sessionid`, 235 on the lab's Mint; and `loginuid`, the
  computer's own user id), the same until the user logs out: the kernel's audit fields, which no sandbox can
  change.
- **The names of the devices the sandbox's folders come from**, in `/proc/self/mountinfo` (`/usr` is bound from
  the root filesystem): `/dev/mapper/vgmint-root` on Mint, `luks-<UUID>` on Fedora, `<hostname>-vg` on Debian. A
  per-process file, which can't be covered.
- **With the graphics card given**, `/proc/driver` (NVIDIA's driver reads its files there) and so the card's
  serial number (`/proc/driver/nvidia/gpus/*/information`; NVIDIA's driver gives it to any program that may use
  the card anyway): said under the box (`gpuRisks`).
- **The installation's own id** (the review of 2026-11-12): `statfs("/usr")`'s `f_fsid` is a fold of the root
  filesystem's UUID, the same inside the sandbox as outside (a bind keeps the filesystem: tested), and the inode
  numbers and dates of `/usr`'s files are this installation's own. None of them changes at a restart, so, unlike the
  boot time, they link sessions across restarts too; only a copy of `/usr` could hide them. Said on the page, in the
  browser panel and Try an app's.

The lookups under pasta are filtered (section 7.13): what the computer's resolver would answer about the local
network isn't passed on.

---

## 8. The RAM disk

`tools/ramdisk.py`; helper `ramdisk_open`, `ramdisk_close`. `~/RAMDisk` is opened on demand; size and
`noexec` are the user's choice. Mounting is as in section 7.3.

**Closing** (as the user, then the helper):

1. Refused while a process of the user's holds anything in it ("Close X first"), and while another filesystem
   is mounted inside it, a vault, a share or a drive ("Unmount X first": its files aren't the RAM disk's, and
   the RAM disk can't be unmounted around it).
2. `ramdisk.wipe` walks the tree with `os.fwalk(follow_symlinks=False)`, only on the tmpfs's own device
   (links and other filesystems mounted inside are skipped). Each regular file is opened `O_WRONLY |
   O_NOFOLLOW`, re-checked with `fstat`, and every data region (`SEEK_DATA` / `SEEK_HOLE`) is overwritten
   with zeros in place, then `fsync`ed. Then everything on that device is deleted, deepest first, never
   anything in another filesystem mounted inside. A folder or file the user closed (no write or search permission)
   is opened first, without following links, and changed by its own descriptor (`fchmod`; one it can't read is
   opened `O_PATH` and changed through `/proc/self/fd`, its own inode, no name looked up again), only while it is
   still a folder or regular file on that device (`ramdisk._chmod_entry`): `chmod` by name, with the folder's
   descriptor, followed a link put there since it was checked (the review of 2026-11-12).
3. The helper unmounts it (never lazily: a lazy unmount would leave files reachable through whatever holds
   them; `EBUSY` is refused) and puts the folder back: removed if the helper made it, its old permissions
   restored otherwise (from the state in /run, or after a reboot from the folder's own attribute).

Overwriting is meaningful here (rule 8's exception) because a tmpfs's files are memory pages that a write
replaces in place: the files still there when it closes. It doesn't reach what was deleted or replaced while it
was open (a save that writes a new copy and renames it over the old one, as the browser's session store does every
few seconds, frees the old copy's pages unzeroed), what programs hold in their own memory, copies other programs
made (thumbnails, recent-file records, the clipboard), file names, or pages swapped out where `noswap` wasn't
available; the close dialog says so, and that clearing freed memory is the kernel's `init_on_free` (the
`kern.init_on_free` check's chip, or, where the command line turns it on, `ramdisk.init_on_free`, that those
pages were cleared too).

---

## 9. Verify a download

`tools/verify.py`, `tools/keys.py`, `tools/packages.py`, `signing-keys.yaml`.

It keeps two questions apart: is the file **intact** (does it match a checksum), and **who made it** (is
it, or a checksum list holding its hash, signed by a key the app lists).

- **Keys.** `signing-keys.yaml` holds each project's release key, exported minimal and pinned to
  fingerprints confirmed on the project's own site, with the date: Linux Mint, Ubuntu, Debian, Fedora, Arch
  Linux, CachyOS, Kali Linux, Tails, Tor Browser Developers (Tor Browser and Mullvad Browser), Mullvad VPN,
  VeraCrypt, KeePassXC, Proton VPN, IVPN, Qubes OS, Whonix and Kicksecure, openSUSE, Manjaro, EndeavourOS,
  Cryptomator, Mozilla, and Digital Archon (this app's own releases, `docs/release-key.asc`). `keys.py` parses the OpenPGP packets itself, recomputes every bundled key's
  fingerprint (v4 SHA-1, v5/v6 SHA-256) and refuses a key block whose primary keys aren't exactly the
  pinned fingerprints. Keys may also come from the user's GnuPG keyring (read only, never imported into)
  and from key files the user chooses. The app never fetches a key.
- **Checking OpenPGP signatures:** the host's `gpgv`, with a temporary home and keyrings of the app's own, run
  twice and apart (`KeySet.runs`): against the app's listed keys alone, then against the user's own copies (a
  chosen key file, their keyring) alone. gpgv uses the first copy of a key it finds, so in one run a stale copy
  of a listed key hid the revocation the app's copy holds, the app's copy hid one made since that only the
  user's holds, and a project's stolen signing subkey re-wrapped as a primary key of the thief's (in a key file
  or the keyring, read first) was found good. Each signature counts as the worst of the two (`combined`): a
  revocation anywhere first; otherwise good by any copy beats expired (an expiry can be extended). gpgv
  reports a key both expired and revoked as expired only (EXPKEYSIG, tested with 2.4.4), so the revocations
  are also read from every copy's packets (`keys.revoked_keys`, the keybox's blocks with `keybox_blocks`).
  A signature is a project's only when VALIDSIG's primary key (its last field) is a pinned primary
  (`keys.pinned`): a v4 fingerprint is the same for a key whether its packet is a primary or a subkey, so a
  subkey's fingerprint never stands for the project. A signing subkey the app's copy doesn't have (a project's
  newer one, from the user's copy, bound to the pinned primary as gpgv checks) is the project's, with a note.
  Where gpgv is missing, `sqv` (Sequoia) checks detached signatures, against the listed keys and the chosen key
  files, apart in the same way (it can't read GnuPG's keybox). A good signature by a signing subkey is mapped to
  its primary key in the keyring it came from.
- **SSH signatures** (`ssh-keygen -Y check-novalidate -n file`): checked against the key the signature carries,
  so anyone can make a good one; the key's fingerprint is shown, and the result says so. There is no list of SSH
  keys, so an SSH signature is never *verified*.
- **minisign signatures:** need the project's minisign public key, chosen as a key file; a good one is
  shown with its key id. It is never *verified* either, since the app lists no minisign keys.
- **Checksum lists:** GNU (`hash  name`, `hash *name`), BSD (`SHA256 (name) = hash`) and bare hashes; the
  algorithm from the BSD tag, else from the length (`b2sums` is BLAKE2b). In a clearsigned list only the
  text inside the signed block counts (RFC 9580 7.1, dash-escaping undone), read as GnuPG reads it (`clearsigned`:
  lines end at `\n`, the armour line only at a line's start): a file with that line anywhere else, or more than
  once, is taken as changed since it was signed, since gpgv checks the one real message and passes over the rest
  (a line of someone else's above Fedora's real list, behind a marker hidden at a line's end, was read as signed).
  gpgv is given that message alone and writes out the text it checked, which must be what the app read; a
  clearsigned file chosen itself is the published file only with nothing but white space around its message. A
  pasted checksum may carry spaces, a `sha256:` prefix or a whole `hash  name` line.
- **Companions:** signatures and checksum lists next to the file are found automatically; if the user
  picked the signature, the file it signs is used. Recognised file names tell the user what to download
  when the companions are missing.
- **Packages** carry their own signatures (`packages.py`). A `.deb`: a dpkg-sig member (`_gpg<role>`, a
  clearsigned list of every other member's MD5, SHA-1 and size: every member must be listed and match) or
  a debsigs member (a detached signature over `debian-binary`, `control.tar.*` and `data.tar.*` joined). An
  `.rpm`: the signature header's tags 1002/1006 (over header and payload), or 267/268/278 (over the header
  only, which must then hold the payload digest, tag 5092, checked; without it the contents aren't covered,
  and the result says so). What a signature covers that can be large (the header too) is streamed to gpgv
  through a named pipe, once for each check, never copied into memory-backed `/run`; a header value must lie in
  the header's own store, and a signature value larger than 64 KB is refused (its size is the package's to set).

**Verdicts** (`verify.decide`), in this order:

| Level | Title | When |
|---|---|---|
| `bad` | Don't use this file | Any bad signature, a revoked key (known to any copy of it), a checksum in a list that doesn't match, or a pasted checksum that doesn't match |
| `verified` | Verified: made by *project* | A good signature by a listed project's key over the file, over a checksum list containing its hash, or inside the package, when the file's name is that project's or no project's; or the file's SHA-256 is one a project publishes on its own site (`checksums` in the YAML, with a note that a newer release needs the app updated). A signature over SHA-1 or MD5 (VALIDSIG's hash algorithm), or a signed list holding only an MD5 or SHA-1 for the file, gets a note that it is weak |
| `other_project` | Not verified: signed by *X*, but named as *Y*'s file | A good signature by a listed project's key on a file named as another project's (`keys.all_for_file`): otherwise the weakest listed key (some are one person's, some a build server's) would verify a Tails image |
| `expired` | Not verified: signed with a key that has expired / its signature has expired | EXPKEYSIG or EXPSIG: the date in a signature is the signer's own claim, so whoever holds an expired key can sign today and date it back |
| `signed` | Not verified: signed by an unknown key | A good signature by any other key (keyring, chosen key file, SSH, minisign), with its fingerprint to compare with the project's site; for SSH, that the signature carries its own key and anyone can make one |
| `intact` | Not damaged, but not verified | A checksum matches; MD5 and SHA-1 alone get a note that they are weak |
| `unchecked` | Not verified: nothing to check it against / its signature couldn't be checked | No companion, or signatures that couldn't be checked (no key, no tool) |

A project that signs nothing (`unsigned: true`: Garuda Linux, Bazzite) is *intact* at best, and the
result says that is as far as a check can go. A *verified*, *other_project* or *signed* result says when the good
signature it rests on was made ("Signed on 4 November 2026", local time): an older release renamed as a newer one
still matches its own signature, and only its date gives it away. The page's badge is green only for a good
signature by a listed key (`Signature.badge`).

`daprivacyscanner --verify FILE [--key KEYFILE] [--checksum HEX]` prints the same report; exit status 0
when verified, 1 for anything less, 2 when the file or a key couldn't be read.

---

## 10. The TRIM test

`tools/trimtest.py`; helper `trim_begin`, `trim_scan`, `trim_result`, `trim_fstrim`, `trim_end`.

Question: once deleted data on an SSD has been trimmed, can it still be read back from the drive?

1. **Target.** `/`, the filesystem holding the home, or another ext4 or btrfs filesystem on a `/dev`
   device (not a loop device) mounted under `/mnt`, `/media`, `/run/media`, `/srv`, `/data`, or wherever the
   user can create files at its top; never `/boot`, `/efi`, Snap or pseudo filesystems. btrfs only on one
   device. The request names the mount point; the helper (`_trim_mount`) accepts only `/`, the home's
   filesystem, or such a mount whose top the caller may write to, and finds the device from the mount table
   itself. Hard disks, virtual machines and stacks where a layer passes no discards get their answer without
   a test.
2. **Begin.** The helper picks a random 16-byte run ID and a tag for file names, and reports what each
   drive under the filesystem says about itself.
3. **Write.** As the user, about 253 MB of test files (four of 63 MB, eight of 64 KB, and three of 512 to
   1536 bytes, small enough for btrfs to keep inline) in a folder of the test's own: under
   `$XDG_DATA_HOME/daprivacyscanner/trim-test` on the home's filesystem, `/var/tmp` on `/` when the home is
   elsewhere, or a hidden folder at the top of another disk. It is a btrfs subvolume where possible (so
   snapshots taken meanwhile can't keep the files) and marked `FS_NOCOMP_FL` (`chattr +m`), since with
   `compress=zstd` (CachyOS's default) a small file of repeating records is stored compressed in a form the
   scan can't recognise; `compress-force` overrides the flag. Every record carries the run ID and a
   checksum over a random payload.
4. **Baseline.** The helper reads the whole block device (the decrypted one under LUKS), read-only, with
   `O_DIRECT` (past the page cache), in 512 MB requests, and counts the run's records. It must find all of
   them, or the test stops there; only btrfs's small inline files are excepted (untested, and said so).
5. **Delete, trim, rescan.** The files are deleted (the folder kept, as when someone deletes files from a
   folder they keep), the filesystem is synced twice (the commit that frees the blocks must be on the disk
   before fstrim can trim them), `fstrim` runs, and the device is read again. A third read follows 180
   seconds after the trim when the first rescan still found data, or when the drive doesn't report that
   trimmed blocks read as zeros or 0xFF. No btrfs balance (fstrim already trims free space inside block
   groups; a balance rewrites the user's data) and no `drop_caches` (O_DIRECT bypasses the cache).
6. **Unreadable parts.** A read that fails with EIO is retried in 64 KiB pieces; pieces the drive can't
   read are zero-filled (so nothing stale is counted), counted, and kept as ranges (up to 1000 per pass).
   The result names them and gives `smartctl -a`.
7. **Verdict** (`result_view`), from the deleted test data read back in the last pass, what the drive
   says a trimmed block reads as (NVMe DLFEAT through the helper's own identify ioctl; SATA DRAT/RZAT from
   `smartctl --identify`, else `hdparm -I`), and the kernel's discard counters (`/sys/block/*/stat`):

   | Data read back | Drive | Verdict |
   |---|---|---|
   | none | received no discards | inconclusive: the data was probably overwritten, not trimmed |
   | none | parts readable at the baseline unreadable now | inconclusive: deleted data could hide there |
   | none | its discard counters couldn't be read | inconclusive: whether the trim reached it can't be seen |
   | none | otherwise | **pass** |
   | some, not all | reports zeros or 0xFF, and discards reached it | **fail**, headed "TRIM cleared most of the deleted test data, but not all" (or "only part of"): usually blocks at the edges of what was freed, smaller than the drive's own unit |
   | some | reports zeros or 0xFF, or received no discards | **fail** |
   | some | promises nothing about trimmed blocks | inconclusive |

   It also reports how much fstrim trimmed, how much TRIM reached the drive, how much was written between
   the trim and the rescan (reuse also hides data), and how many of the test files' names are still on the
   disk (on ext4 they stay in the journal, and under kernels before 5.13 in the folder's block; the result
   points at Deleted file names).
8. **Clean-up.** The test folder is removed whatever happens. One left by a test that didn't finish (the
   app crashed) is removed at the next start, by the names the test makes only.

A pass means nobody can read the deleted data back by plugging the drive in, even with the encryption key.
It says nothing about the flash chips themselves (chip-off, vendor diagnostic modes), nor copies the
filesystem keeps; and without the discard mount option it holds only from the next weekly fstrim.

**Drive encryption** is reported from what the drive says: ATA IDENTIFY word 69 bit 4 and word 59's CRYPTO
SCRAMBLE (`smartctl --identify=wn`, else `hdparm`), TCG Level 0 Discovery (Opal, Enterprise, Opalite and
Ruby have an encryption engine, Pyrite doesn't; through the helper's NVMe Security Receive, or
`sedutil-cli --query` for SATA, which Linux allows only with `libata.allow_tpm=1`), and crypto-erase support
(NVMe SANICAP/FNA). Always "the drive says", never "doesn't encrypt", and never instead of disk encryption.

The helper's reads here return counts and offsets of the run's own records only, never what else the device
holds.

---

## 11. Deleted file names

`tools/names.py` lists, `tools/rebuild.py` clears; helper `names_*`.

- **Scope.** On the home's filesystem, folders under the caller's home that they own; on another disk,
  every folder the caller's permission bits let them open. No links followed, no other mounts entered.
- **ext4.** Each folder's blocks (FIEMAP), and the deleted directory entries left in them: what kernels
  before Linux 5.13 left, since later ones overwrite an entry as its file is deleted. Then the whole
  journal, whose copies of folder blocks as they were before are where the names are now (a 1 GB journal
  on NVMe: under two seconds).
  - *Whose a copy is.* With `metadata_csum` every folder block ends in a crc32c over the block, seeded
    with the filesystem's seed, the folder's inode number and its generation. crc32c is linear, so the
    stored checksum XORed with the block's crc from state 0 depends on the seed alone: one pass over a
    block (by the kernel's crc32c through `AF_ALG`, else a table) gives a key that is looked up among the
    listed folders' keys (`_ext4_seed_key`; the generation from `FS_IOC_GETVERSION`). 32 bits can agree
    by chance, so a second thing must agree too: the jbd2 descriptor says the copy is of a block the
    folder has now, or the block names the folder as itself (`.`), or an entry in it is a file the folder
    holds now under that name and inode.
  - *A folder that is gone* (`rm -r`, a folder emptied from the trash): a tied copy of the folder it was
    in names it as a subfolder. Its inode's generation is read from the inode table and from the journal's
    copies of that block of the table, since a freed inode number is often used again at once, under a new
    generation. The kernel is asked whether an inode of that number and generation exists now
    (`open_by_handle_at` with ext4's handle of the two, as an NFS server asks; "stale" means deleted or used
    again), so a live folder outside the listing is never shown as deleted; where it can't be asked, a
    record of the inode must show it deleted. Blocks in the journal carry that inode's checksum, and one of
    them is its first block, naming itself and that parent. And it must have been a folder the listing would
    have covered while it was there, by the same rule (the caller's own, or one they could open, from the owner
    and mode every record of its inode gives): another account's private folder deleted from a shared one stays
    untied. Followed downwards, so a deleted tree is listed folder by folder.
  - *What can't be tied* (other accounts' folders, the system's, a folder whose inode was used again, and
    on a filesystem without `metadata_csum` everything) is counted and never named in the list.
    `names_orphans` returns those names only when the user asks for them, after the page has said whose
    they can be and that many are of files still there.
  - *Fast commits* (the `fast_commit` feature, off by default) keep names in records of their own at the
    journal's end, which the list doesn't read; the result says so.
- **Clearing the journal** (`names_journal_clear`): `EXT4_IOC_CHECKPOINT` with its zero-out flag (Linux
  5.14) on the listed filesystem's mount point. The kernel writes everything in the journal to its place,
  then zeroes the journal, the fast-commit area too. Whether the kernel can is asked beforehand with the
  call's dry-run flag. Nothing is journalled by the helper and nothing can be undone: there is nothing to
  undo. The page shows the same call as a line of Python, since no program on the system makes it.
- **btrfs.** The whole device is read for those subvolumes' tree blocks (fsid, owner, checksum), their
  directory items and stale item headers. As long as one TRIM-test pass. An entry older than the folder it would be
  tied to (its transaction against the folder's generation, `FS_IOC_GETVERSION`) was a previous holder's of that
  inode number, which btrfs uses again after a remount: left out, so another account's deleted folder is never shown
  under the caller's new one.
- **The list** goes to the page once and is dropped by the server as it hands it over. The helper keeps it
  in memory only, for the checks after a clean-up, until the window closes. Never saved, logged or
  exported.
- **Clearing on ext4** (as the user, after a dry-run plan and confirmation; never synced folders, never
  other users'): *fillers* for small folders (empty files with names as long as each deleted one, a round
  at a time, re-read until the names are gone; the folder stays the same inode) or a *rebuild* for large
  indexed folders (a new folder with the same group, mode, flags, xattrs and ACLs; every file, link and special
  file given a second name in it, a hard link, so the folder keeps every file at its own path until the swap,
  and only its subfolders, and what can't be linked (protected_hardlinks, EMLINK), moved with
  `renameat2(RENAME_NOREPLACE)`, last; then swapped with `RENAME_EXCHANGE` while the name is still the folder
  they came from; then the old folder's names reconciled (`_reconcile`: a second name of the same file dropped,
  what was made meanwhile moved in, a file saved over meanwhile put in place of the stale link, one deleted
  meanwhile deleted); rolled back on failure). Emptying the folder at its live path before the swap had left
  it partly or wholly empty to a backup, a sync client's scan or an app starting, for as long as the moves
  took (the review of 2026-11-12). A folder encrypted with fscrypt isn't rebuilt. Each folder is looked at
  again just before it is done (holders, watchers, mounts), since the folders before it can take minutes. While
  a folder is done, a recovery note (`rebuild.Note`, `$XDG_STATE_HOME/daprivacyscanner/names-interrupted.json`,
  0600: the folder's place, the temporary names, the fillers' lengths; a lock in the runtime folder tells a
  running copy's from an interrupted one) is kept, and deleted when that folder is done, whatever the outcome:
  after a crash, a logout or a power cut the panel offers **Finish it** (`rebuild.recover`: the entries sorted
  back by identity, the hidden folder removed, fillers left in the folder removed), and a clean-up waits until
  it is done. Only folders the last listing showed can be planned, cleaned or checked (`names_listed`, their
  paths only, forgotten with the listing). The plan says what the moves mean for programs reading the folder
  meanwhile, what the app can't see (other accounts' and the system's programs, NFS, Samba and virtual
  machines' shares), and, on Linux 5.13 and later, that these clean-ups reach only names left in folders'
  own records before, Clear the journal being the one to use first. Fillers
  are also used wherever a folder can't be swapped (the home itself, a disk's top folder, one with a disk
  mounted in it) or TRIM never reaches the drive. Either is refused for a folder that isn't the user's, is
  immutable or append-only, or is watched (inotify/fanotify marks from `/proc/PID/fdinfo`) by a program
  other than a file manager, desktop or indexer ("Quit X first"). A rebuild is also refused while a process
  holds anything in the folder ("Close X first"), while a socket is in it, and while the folder is mounted
  in another mount namespace (a Flatpak app, a container) or elsewhere in this one. Fillers: at most 4000
  files and 60 rounds per folder. Then fstrim where TRIM reaches the drive, and a check of the folder's
  blocks, its old blocks and the ext4 journal's copies; names left in the journal offer the clear.
- **btrfs:** *Trim now and check again*. Never a balance.

---

## 12. Drives: hand over and retire

**Before you hand over a drive** (`tools/handover.py`): removable or external mounted drives only, never
the system's, the home's or a read-only one. Leftovers are found by exact names, without following links
or entering other filesystems: trash folders (`.Trash-UID`, `.Trash/UID`, `.Trashes`, `$RECYCLE.BIN`,
`RECYCLER`), thumbnails, `.directory`, `.DS_Store`, AppleDouble `._` files (by magic number), macOS
system folders, `System Volume Information`, and lock files that name the user. Every file is listed;
deletion needs confirmation and is refused while a program holds one.

**Retire a drive** (`tools/retire.py`; helper `erase_facts`): every whole drive with its kind, transport,
serial, SMR status, LUKS and plain partitions, and what is mounted or open. Drives holding the running
system are refused. Commands only, run by the user, each naming the exact device, shown only after the user
types the drive's name. The device is named by its lasting name in `/dev/disk/by-id` (`retire.by_id_names`, the
one with the bus, model and serial first, its partitions' `-partN` for `cryptsetup`), since the user pastes the
commands later and `/dev/sdX` changes when a drive is plugged in or out, after a suspend (the Unfreeze step's) or a
restart; a drive without one is named by `/dev/sdX`, and the guide says to check it before each command. Every guide
starts with `lsblk -d -o PATH,MODEL,SERIAL,SIZE` on that name; `dd` gets `conv=nocreat` (a name that has gone
otherwise becomes a regular file in devtmpfs); and the page sends the drive's identity as it listed it (model,
serial, size, WWN: `retire.identity`) with the request for the commands and for its facts, refused for another
drive under that name (`same_drive`):

- **Hard disk:** ATA Secure Erase where supported, not frozen and not behind USB; and one zero pass with
  `dd`, checked with `cmp` (rule 8's second exception: overwriting works on a known hard disk, apart from
  remapped sectors).
- **SSD, NVMe, eMMC:** `cryptsetup erase` where there is LUKS (then `luksDump` to see no keyslots), "the
  strong option" when it was encrypted from the start; the firmware's own erase (hdparm Sanitize or Secure
  Erase, `nvme sanitize`, `nvme format --ses`, `blkdiscard --secure`) offered but never presented as proof;
  destruction for what held secrets unencrypted.
- **USB sticks, SD cards, external disks of unknown kind:** no reliable erase, said so.
- **Virtual disks:** delete it on the host.

What the drive supports comes from `erase_facts` (smartctl/hdparm identify words; NVMe Identify Controller
OACS, FNA and SANICAP via the helper's ioctl), read on request and kept for the session only, with the
drive they came from (its model, serial, size and WWN, `retire.identity`): another drive given its name later
(sdb is whichever drive came second) doesn't get them.

---

## 13. The other tools

- **Remove metadata** (`tools/metadata.py`): shows what each file carries (`exiftool -json -G1 -a -s`,
  else `mat2 --show`), grouped by what it gives away, and writes cleaned copies with mat2 (cleaning is mat2
  only, since exiftool can't clean every format). The user chooses files, folders or both (`collect`): a
  folder is walked sorted, without following links or entering another mount (`/proc/self/mounts`), hidden
  names and unfinished downloads left out (hidden ones on request), the same file once, at most 5,000
  files; what was left out is counted by reason. Both programs take many files per call, so they run in
  batches of 40 (`show_many`): exiftool's JSON names each file (`SourceFile`), mat2's `--show` too (in no
  order, split by its `[+] Metadata for FILE:` headers); a file a batch didn't account for is read alone.
  Whether mat2 will clean a file is known beforehand: it goes by the name's type (`mimetypes.guess_type`,
  libmat2's parser_factory), and `mat2 --list` prints the types with their extensions (`cleanable`). Reading
  and cleaning are a background job (`/api/tools/metadata/read`, `/clean`, `/job`, `/stop`), one at a time;
  the page gets each file's summary (each group's count and first items) and asks for one file's
  everything when it is opened (`/show`). A file chosen on its own gets its copy beside it
  (`FILE.cleaned.EXT`, never over one), cleaned from a copy in a hidden folder there; the ticked files of
  a folder go into a new folder beside it, `NAME (cleaned)` (or `(cleaned 2)`…, never one already there),
  with the same subfolders, cleaned from copies in a hidden working folder inside it (contents and mode
  only: no extended attributes, where browsers keep a download's address; the mode with the owner's read
  and write added, as the Outbox's copy has it, since mat2 writes to a copy of an MP3, OGG or FLAC it
  makes with the mode, and crashed on a read-only one). Each copy is read from a
  descriptor of the file the listing saw (its device and inode; a folder's opened without following a
  link: the browser can swap one in for a listed download, and mat2 followed it, its cleaned copy of
  whatever the link pointed to landing where the browser sees it), so mat2 cleans nothing else and never
  writes into the user's folder. On `~/TempBrowser` (its own filesystem) those working copies and mat2's
  temporary files go in a folder of the app's at the RAM disk's top, `.cleaning-<random>`, which no sandbox is
  given, never beside the file or inside the cleaned folder, where the browser's sandbox can write and could swap
  them for a link just before mat2 opens them (the owner's decision of 2026-11-05); a file mat2 can't
  clean gets no copy and is listed, and a folder with nothing cleaned is removed. A copy counts only when
  the run that made it exited 0: mat2 cleans each file of a run in a process of its own, and one that
  crashes leaves a copy that looks cleaned (a read-only MP3's with every tag, a binary PPM's empty) and
  names no file, so the files of a failed run it didn't complain of are cleaned again, together while it
  names the one to blame, else one at a time (`_mat2_each`). Each copy is read again
  afterwards: the page flags copies that still say where, who or which device, or carry a title, comment or
  description with something in it (`FileMeta.telling`; not what every file of its kind has: an MP3
  frame's copyright bit, a video track's handler, a codec's name). Stopping keeps what was
  cleaned. For a PDF, mat2's normal mode redraws every page as an image (text can't be selected any
  more); *Lightweight* keeps the text and removes less. Linux allows any bytes in a file name: one that
  isn't UTF-8 reaches Python as lone surrogates, which UTF-8 can't encode, so the server's JSON escapes
  everything beyond ASCII (`server.JSONResponse`, every response): the page shows such a name with a
  replacement character and sends the same escaped path back, which names the file again.

  Both programs run in a sandbox of their own (`run_tool`, `sandboxed_argv`, `sandbox_why`; the review of
  2026-11-12): they parse whatever the file holds, and the files are the ones nobody vouches for — a download from
  the browser in memory, anything dropped in the Outbox, which is cleaned without being asked. exiftool is perl
  with a history of its own (CVE-2021-22204 ran a command from a DjVu file's metadata) and mat2 pulls in poppler,
  GdkPixbuf, mutagen and ffmpeg's libraries. The sandbox is View offline…'s: bubblewrap with no network, no home
  folder (an empty `/home/user`), no display, no session bus, `/usr` read-only, an `/etc` of its own
  (`sandbox.app_etc`), the files to read bound read-only one by one where they are (not their folder), and only the
  app's own working folder writable, bound where it is, so the tools name files as the app does and their output
  lands where it would. mat2's temporary folder is bound a second time at `/tmp/work` with `TMPDIR` pointing there,
  which is short whatever the real path is (the socket limit `_tmp_beside`'s link was for); `mat2 --show`, with no
  `TMPDIR` of its own, unpacks an archive into the sandbox's `/tmp`, in memory, where before it used the computer's
  `/tmp` on the disk. One sandbox per batch, as the batches already are. Where bubblewrap can't run here the tools
  run as they did and both the panel and the TempOutbox say so (`status`'s `sandbox`, `browser.sandbox_status`'s
  `mat2_sandbox`). Live-tested on Mint 22.3: exiftool read the same 54 and 23 tags from a JPEG and a PDF sandboxed
  and not; mat2 cleaned a file beside itself and a folder into `NAME (cleaned)` with its subfolders; and a shell in
  the tools' sandbox had an empty home, could not reach the real home or the network, could not write to the file it
  was given, and saw 44 entries in `/etc` with no `/etc/environment`.

  The **Outbox** (`app.metadata_outbox`) is a systemd user path unit that runs
  `daprivacyscanner --outbox` when files land in `~/Outbox`: each is cleaned into `~/Outbox/Cleaned` and the
  original moved to `~/Outbox/Originals`; a file mat2 can't clean goes to `~/Outbox/Not cleaned`, and so
  does one whose cleaned copy still says what the page would flag (nobody looks in `Cleaned` before
  sharing what is there), and one that couldn't be cleaned at all (unreadable, no room, an error: one file's
  trouble never stops the rest, and the notification counts it). A file has arrived as the TempOutbox's do:
  unchanged for 2 seconds, open for writing by no program of the user's (`transfer.open_for_writing`), unchanged
  while it is copied and cleaned (read through one descriptor, never a link), and unchanged since the run's last
  look (`OutboxLooks`); a stalled copy was cleaned half-written before. The working copy goes in the runtime folder
  when it has room for it and the cleaned copy (`_outbox_work`), else in a hidden folder inside `~/Outbox`, on the
  disk the original is on, never `/tmp`. A run that stops anyway says so in a notification. Nothing is deleted.
- **File chooser** (`tools/pick.py`): pywebview's dialog in the window (GTK's recent-files recording
  turned off for the app, which outranks the desktop's setting), zenity or kdialog in a browser, else a
  typed path. The server accepts only absolute paths of regular files the user can read (and, for Remove
  metadata, folders they can open), resolved one name at a time (`pick.resolved`) and refused when the way goes
  through a link inside `~/TempBrowser`: the browser writes there, and a link it planted (`Downloads/notes.txt`
  pointing at `~/.ssh/id_ed25519`) made Add a file to upload… copy the key where the browser reads it (found in the
  2026-10-17 review). Links anywhere else are the user's own, and followed.
- **Try an app** (`tools/trial.py`, with `tools/homewatch.py`, `tools/bait.py`, `tools/pcap.py` and
  `tools/sandbox.py`'s pieces): a program the user doesn't know yet, run in a sandbox with a throwaway home, and
  a report of what it did. One trial at a time; no administrator access.
  - **What can be tried** (`prepare_file`, `prepare_app`; a file is judged by its first bytes, `classify`): an
    AppImage (type 2: run with `APPIMAGE_EXTRACT_AND_RUN`, since it can't mount itself in a sandbox; type 1 is
    refused, saying why), a program, a script; an archive (tar, zip), unpacked by the computer's python3 inside a
    sandbox with no network that sees only the file and the folder (`UNPACK`: at most 8 GB, and never more than
    is free where the trial lives less 128 MB, `unpack_limit`, and 200,000 files, counted before each is written;
    a .deb compressed with zstd, which tarfile reads only from Python 3.14, through `dpkg-deb --fsys-tarfile`
    into the same counts: found in the 2026-10-17 review, a zip bomb was unpacked in full into the runtime folder
    the whole session uses, and `dpkg-deb -x` had no limit at all), after which the user picks the
    program in it (`candidates`: a menu entry's program first, then programs near the top; a link is resolved
    inside the tree, never onto the computer); a .deb, unpacked the same way and never installed (its maintainer
    scripts aren't run, its dependencies aren't installed, and the page says so); an installed app from the menu,
    whose program must be in the system's folders; a Flatpak app. A Snap is refused. The file chosen is copied
    into the trial's folder: the original is neither changed nor run.
  - **The trial's folder** (`places`): in memory (`$XDG_RUNTIME_DIR/daprivacyscanner-trial/<id>`, a tmpfs) or on
    the disk (`$XDG_CACHE_HOME/...`) for something large, 0700, holding `home` (the throwaway home), `app` (the
    copy or the unpacked tree) and `private` (the sandbox's own files, which it is never given). Discarding
    overwrites it in place and deletes it in memory, and only deletes it on the disk (rule 8; the page says that
    doesn't erase it). The runtime folder isn't kept out of swap: where swap reaches a disk (any but zram without
    a writeback device) or the computer can hibernate, the page says so beside "In memory" and in the result, in
    place of saying nothing of the trial touches the disk (`status`'s `swap` and `hibernation`; found in the
    2026-10-17 review). A trial in memory has no size limit of its own, and the runtime folder is the whole session's:
    while it runs, its free room is looked at every second (`trial.RoomWatch`), and below `ROOM_KEPT` the trial is
    ended as End ends it, its result kept, saying that memory was nearly full (a browser's cache, or a program
    writing on purpose, had filled it, and the session's programs couldn't write their runtime files); a start with
    less room than that is refused. Quitting the app discards it (the window's Quit as well as `--browser` mode's); folders left
    by a copy of the app that has ended are removed at the next start. Each trial's folder is locked (`flock` on
    the folder) by the copy that made it, so another copy (a right-click entry's) never takes a running trial
    for a leftover.
  - **The sandbox** (the `bubblewrap` engine; engines sit behind `ENGINES`): every namespace, `--die-with-parent`
    (Stop ends bubblewrap, and its sandbox, in a session of its own, must go with it: without it KWrite ran on
    after Stop, tested), no capabilities, a new session, an environment built from scratch, `/usr` read-only, an
    `/etc` of its own holding only what programs read (`sandbox.app_etc`, below), the throwaway home at
    `/home/user`, the program read-only at `/app`, the display (on Wayland a socket the compositor marks as a
    sandbox's where it has the protocol; on X11 Xephyr, a display of its own, wherever it is installed, its focus
    keeper sizing the program's windows to it, and the X server's own socket only when the user ticks that it may:
    `sandbox.own_display`; a Flatpak app, which Flatpak gives the X server's socket, only with the tick), no session
    D-Bus, keyring or agents, and the kernel keyring and crash-dump protections every start gets
    (`sandbox.KEYRING`). The system-call filter: strict, with `--disable-userns` where bubblewrap has it, or the
    nesting profile when "Let it start sandboxes of its own" is ticked (pre-ticked where `seccomp.nesting_reason`
    found an Electron, Chromium, CEF, Qt WebEngine, WebKitGTK or glycin program: live-tested on CachyOS with Obsidian
    1.15.1's AppImage, which ran and checked for updates through the observed network; GNOME Calculator and Meld ran
    under the strict one, on Xephyr on Mint and on Wayland on CachyOS, Meld's glycin saying its loaders ran without
    their own sandbox). The unpacking sandbox gets the strict one too. Unlike the browser's innermost sandbox, it gets no `/proc` masks (`sandbox.proc_masks`):
    once a file of a `/proc` is covered, the kernel refuses a new `/proc` mount inside, and programs that start a
    bubblewrap sandbox of their own mount one: WebKitGTK's web processes (Yelp, Epiphany, Evolution, any GNOME app
    with a web view) and GNOME's thumbnailer (tested on Fedora 44 with GNOME 50 on 2026-10-17, in a sandbox like the
    trial's: a WebKit page loaded without the masks and failed with them, "Can't mount proc"; glycin 2.1's image
    loaders mount no `/proc` and worked either way). The program can read the kernel command line (often the
    disks' UUIDs), the boot id and the rest of what `/proc` tells any program, and the page and the Box's guide
    say so. (WebKitGTK's sandbox also binds `/sys/block` and more of `/sys`, which a trial isn't given, since it
    would show the drives' serial numbers: its web pages don't load in a trial as it is, tested the same day.)
    The graphics card when ticked, off by default (the owner's decision of 2026-11-12, reversing the earlier
    "on, so that a trial feels as the app would": the card's drivers, in the kernel and in the program, then handle
    what the program sends them, which is the widest way out of this sandbox there is; the tick says what it gives
    and what it costs, and the panel and the manual say first that a trial is a way to watch a program, not a
    guarantee against one built to break out) and sound when ticked (PulseAudio's socket, which gives a program what it gives the browser: the page lists it
    under the tick, `soundRisks`, and the Box's guide in its help, both saying the sound server can be made to
    connect out past a trial's network; they said only "the microphone" until the 2026-10-17 review). Its
    command is `STAY`, a subreaper that waits for everything
    the program starts (a launcher that starts the real program and ends) but not for the session's own helpers
    once the program has ended (`HELPERS`: a D-Bus daemon started on demand stays for good, and the trial would
    never end by itself: seen with Xed). The whole command (and Xephyr's) runs under `TETHER`, the computer's
    python3, which ends it as soon as the copy of the app that started it has ended (a pidfd on it): bubblewrap's
    `--die-with-parent` answers to its parent, which under the observed network is pasta, so with the app killed
    pasta was adopted by init and the sandbox ran on, online and unobserved (found in the 2026-10-17 review on
    Mint 22.3). The kernel's parent-death signal answers to the parent thread, and the app starts trials from
    worker threads, so `TETHER` (one thread) sets it on its command and ends with the app; Stop's signals pass
    through it to the command, and the command's exit status comes back through it. A Box's run is started the
    same way, by its `--box` process. `STAY`, the sandbox's PID 1 (`--as-pid-1`), sets its own parent-death
    signal as it starts: bubblewrap's `--die-with-parent` sets it before the exec, and under Ubuntu's AppArmor
    profile for bubblewrap the exec into its `unpriv_bwrap` domain clears it, so with bubblewrap ended (Stop, or
    the app killed) the sandbox ran on with the program (tested on Ubuntu 26.04 on 2026-10-17; bubblewrap's own
    init, not exec'd, keeps it, and Mint 22.3 was unaffected).
  - **A .deb's files where it expects them**: a first bubblewrap that is root of its own user namespace mounts an
    overlay of the package's `usr` over `/usr`, then starts the sandbox proper inside that view; the package's
    `opt` is bound at `/opt`. Bubblewrap 0.9 (Mint 22.3) has no overlay option of its own; this needs none
    (`probe_overlay` tries it first). Tested with Ubuntu's `hello` and `galculator` packages.
  - **What it may take of the computer** (`capped`, `limits`, `probe_capped`): the sandbox holds a program to the
    trial's folder, and `RoomWatch` holds a trial in memory to the room in the runtime folder, but nothing held what
    it took of the computer itself — a program asking for memory until there is none has the kernel kill something
    else (the app, the session, the desktop), and one starting processes without end fills the user's own limit, so
    nothing of theirs can start either (the review of 2026-11-12). So the whole command runs in a transient scope of
    the app's own: `systemd-run --user --scope --collect --quiet --description=…` (a description of its own, so the
    journal doesn't name the program, as What does this app keep? learned) with `MemoryMax` at `MEMORY_SHARE` (70%)
    of the computer's memory, at least 1 GB, and `TasksMax=1024`. `systemd-run --scope` becomes the command's own
    process, so `TETHER` still answers to the app, Stop still reaches the group and a Box started from the menu is
    unchanged; its environment gains only `XDG_RUNTIME_DIR` (`cap_env`: all it needs to reach the user's bus, tested,
    and it says only the user's number, which the sandbox has as its own; with python3 on the computer `STAY` is the
    sandbox's PID 1, so nothing the program can see carries even that). `probe_capped` tries it once around `true`
    (a user manager without the memory or pids controller refuses the properties) and caches the answer: where it
    can't be done the trial runs as before and the panel says plainly that nothing limits it. A Flatpak app moves
    itself into a scope of Flatpak's own, which this one doesn't hold: not capped, and the panel says so. A program
    killed for the limit is said as the limit, not only as a signal (`ended_words`). Live-tested on Mint 22.3 with
    the cap at 200 MB and 20 tasks: a program allocating 50 MB at a time was killed by the kernel at the cap (exit
    137) with the computer untouched, and one forking 200 children was stopped at the task limit; and on Arch (the
    Omarchy VM), where the probe passed and Nautilus ran capped at 4.3 GB and 1024 tasks.
  - **What a Flatpak trial's portals leave** (`portal_marks`, `portal_changes`): `--sandbox` drops what the app
    declares, but the filtered session bus, which GTK 4 apps need to start at all, reaches the desktop's portals as
    it does for every Flatpak app — among them OpenURI, which asks the desktop to open a web address in the user's
    own browser (with the browser's network, though the trial may have none), and Background, which asks to start
    the app at every login and is recorded as an autostart entry outside the sandbox. Current portals ask the user
    first, and the trial's notes say so and say to refuse what wasn't expected; after the trial the app compares the
    autostart folder's entries and the portals' permission store (`$XDG_DATA_HOME/flatpak/db/*`) with what they were
    at the start, and the result names what is new or changed (`portal`, a warning on the page with what to do).
  - **Its own /etc** (`sandbox.app_etc`, for a trial, a Box and View offline…): a tmpfs with `ETC_KEPT` (the
    browser's list) and `ETC_APPS` as the computer has them, the sandbox's own `passwd`, `group`, `hostname`,
    `hosts` and `machine-id`, the computer's time zone (so an app shows the times the user expects; the browser's
    sandbox has UTC), pasta's resolver when the network is observed and no `resolv.conf` at all without a network,
    then read-only. It was the computer's whole `/etc` with a list of what to cover over it, which missed, as such
    a list always does (found in the review of 2026-11-12): `passwd-` and `group-`, the copies those files' editors
    leave behind, 0644 on Mint and Arch, with the account's name and the user's full name; the time zone and
    keyboard layout as separate files; `/etc/environment` and `profile.d`, where a proxy's password or a token put
    there for every program lives; the package mirrors (apt's sources, `pacman.conf`, `yum.repos.d`: the country, a
    company's own mirror); the display manager's settings, which name the account that logs in automatically; and
    the app's own mount units in `/etc/systemd/system`, whose names hold the path of the user's home. `ETC_APPS`
    adds what an app on trial needs beyond a browser: `dbus-1` (GTK and Qt apps start a session bus of their own),
    `at-spi2`, XML catalogues, the magic files, `inputrc`, `terminfo`, `shells`, what names the distribution, and
    LibreOffice's `/etc/libreoffice`. Tested on Mint 22.3 on a private Xvfb display with xed, xreader and
    gnome-calculator (GTK 3), baobab and gnome-font-viewer (GTK 4) and LibreOffice Writer: each started and drew its
    window as before (Writer opens no window on a bare Xvfb either way, checked against the computer's whole `/etc`),
    and a Qt 5 program drew its window with the same 267 font families and the same style either way;
    and on Arch (the Omarchy VM, Hyprland) with Nautilus (GTK 4) through the marked Wayland socket, where the
    sandbox's `/etc` had 31 entries, 798 fonts were found in it, and `passwd-`, `group-`, `pacman.conf`,
    `environment`, `locale.conf`, `profile.d`, `sddm.conf.d` and `resolv.conf` were all absent.
    The real paths of its folders are still in `/proc/self/mountinfo`'s root field (a Box's `home` under the user's
    home, a disk trial's under the cache folder), which bubblewrap's bind mounts can't hide: the panel, the manual
    and the Box's guide say so.
  - **Bind sources** (`sandbox.bind_source`, through `trial.package_part` and `trial.own_part`): bubblewrap, and the
    kernel for an overlay's lower folder, resolve a bind source on the computer, outside any sandbox, and tarfile's
    "tar" filter keeps members inside the folder but not where a link points. So a crafted .deb whose `./opt` was a
    link to `/` (or `../../..`) had the computer's own files bound at `/opt`, the session bus's socket among them,
    and one whose `./usr` was a link to the home laid the home over `/usr` (found in the review of 2026-11-12, both
    ways of laying it over); a Box kept from such a trial copied the link and did the same at every run. Every bind
    source from a tree the app didn't write itself (the package's `usr` and `opt`, the trial's or Box's `home`,
    `app` and `Exchange`, View offline…'s copy) is opened part by part without following a link
    (`O_PATH | O_NOFOLLOW`), each part a real folder and the last a folder (or, for the viewer's copy, a regular
    file). A package's top-level folder linked to another folder inside the package is bound where it leads
    (`in_tree`); one linked out of it is refused, once unpacked and again at every start (`LINKED_PART`). Links
    further inside the tree are left as they are: they resolve inside the sandbox, which is what real packages
    need (a package's `/usr/bin/x -> /opt/X/x`). Not `--ro-bind-fd`: under pasta, bubblewrap gets no descriptors
    but its first three, and nothing but the app writes these trees while a trial runs, so a check as the command
    is built is enough.
  - **A Flatpak app** (the `flatpak` engine) runs in Flatpak's own sandbox: `flatpak run --sandbox` drops what the
    app declares for itself, and the trial grants back the display, `--filesystem=home`, the filtered session
    bus (`--session-bus`: without it GTK 4 apps, which start their image loaders through a portal, stop at once:
    Evince 48, tested) and what was ticked. `HOME` points at the throwaway home, so its data goes to
    `<home>/.var/app/<id>` and "home" is the made-up one (the real `/home` isn't in its sandbox: tested with
    Flatpak 1.14); its real data in `~/.var/app` isn't touched. It can still ask the desktop's portals, which the
    page says. One of them, Flatpak's own (`flatpak-spawn`, which GTK 4's image loaders use, so it can't be taken
    away), starts another copy of the app with the permissions the app declares, not `--sandbox`, and this
    command's options on top, "home" meaning the real one (found in the 2026-10-17 review on Mint 22.3, Flatpak
    1.14.6: a copy of Text Editor, which declares host, listed the real home and ran on after Stop). So the trial
    takes back on its command line everything the app declares (`taken_back`, from `flatpak info
    --show-permissions` and the overrides: filesystems, host and home, sockets, devices, shared, features; then
    what the trial gives), which the copy inherits, and gives the throwaway home by its path, not as "home"
    (tested there: the copy saw the trial's home and not the real one), and takes away the bus names it declares
    and GVFS (`--no-talk-name`, `--system-no-talk-name`: GVFS fetches over the network for its callers, gio cat
    http:// working with no network, found by the review of View offline…). What Flatpak gives every copy stays:
    its real data folder in `~/.var/app`. Flatpak 1.14.6 (Mint 22.3) and 1.17.6 (Fedora 44) then refuse to start
    such a copy at all: they pass a taken-away bus name or shared namespace on in a form their own `flatpak run`
    rejects ("--none-name", "--noshare"), while a sandboxed copy (`flatpak-spawn --sandbox`, as GTK 4's image
    loaders start one) takes none of these options and still starts (tested on both). `--own-name=<app id>`
    gives back its own name on the bus, which `--sandbox` takes away: without it an app that runs one instance
    (a GApplication) ends at once, "Failed to register" (GNOME Text Editor on Fedora 44, tested; found by the
    review of View offline…). Such copies are found by the options Flatpak
    records for each instance (the trial's home's path in `extra-args`, checked against the sandbox's PID
    namespace) and ended with the trial (`end_flatpak_copies`), which the result says; the page says all this
    before the start, and the Box's guide too.
  - **The network**: none, or its own through pasta (`--pcap` into a pipe), fenced off from the local network
    (`sandbox.fence(proxies=False)`: Mullvad Browser's proxy exception isn't for a program on trial) with its
    lookups through the filter in front of pasta's forwarder (`sandbox.pasta_command`, section 7.13), refused
    when pasta or the fence isn't usable; never the computer's own network. `tools/pcap.py` reads the packets as
    they come and keeps only sums per host: connections, ports, bytes each way. Each connection is named on its
    own, by the name in its first message (TLS's SNI, an HTTP Host line), else the DNS answer that had given the
    address it connected to, else the address, and connections with one name are one host: one address serves
    many sites, and naming by address had shown two TLS connections to 1.1.1.1, naming two sites, as one host
    under the last DNS answer for it (found in the 2026-10-17 review). DNS over TCP is read as over UDP; lookups
    sent to pasta's forwarder are the sandbox's own and no host, while DNS sent to any other server (one of the
    program's own choosing) is listed; a TCP connection is counted once however often its first packet is sent
    again (a lookup hanging on a silent server had counted as five). Names looked up and never used are listed
    apart. Every IP packet the program sends counts for its destination: IPv6's extension headers are walked to
    the transport's (a Fragment header, which any datagram larger than the link takes, or a Routing header, which
    anyone may add, had hidden where a packet went), a datagram's later fragments go with its first, and what isn't
    TCP or UDP (ICMP, SCTP, fragments whose first piece wasn't seen) is listed under its protocol's name; IPv6's
    neighbour discovery and replies nobody asked for aren't hosts. A host's ports are capped at 32 ("and more").
    No packet or payload is kept. A
    Flatpak can't be put behind pasta (it would run as root of pasta's namespace): none, or its usual network,
    unobserved.
  - **The watch** (`tools/homewatch.py`): inotify on every folder under the throwaway home, as the user. It
    records what is opened, changed, made, deleted and renamed, in the records `activity.summarise` reads (here
    with file names: the home is made up), and leaves its own listings out (a folder it looks through when it
    appears isn't counted as listed by the program). Each decoy file also has a watch on its own inode, which
    counts its openings: a folder's watch reports a file by the name it was opened under in that folder, so a
    decoy linked into another folder and read there, or read after its folder was renamed, went unseen (the
    2026-10-17 review's suspicion, confirmed by a test).
  - **Decoys** (`tools/bait.py`): made-up SSH and GnuPG keys, Firefox, Chrome and Thunderbird profiles with real
    SQLite files, a keyring, wallets, cloud and Git credentials, a shell history, documents and a photo: 34
    files, new for each trial, from random bytes. A program that opens them has gone looking; the page shows it
    while the trial runs and warns in the result. Folders every program uses (`~/.config`, `~/.local`) aren't
    decoys.
  - **The result**, in memory until discarded: the decoys opened or listed, the hosts contacted, what it wrote in
    its home (folders with counts and the files' names), what is left there, the last of its output when it
    failed, and the command that ran it.
  - Tried through the API on Mint 22.3 (X11; a script, an AppImage, tar, zip, .deb with xz and zstd, Xed,
    Flatpak Evince, the observed network with the local network refused) and CachyOS (KDE Plasma 6.7 on Wayland;
    KWrite through the marked socket).
- **A Box** (`app.boxes`, a feature; `tools/box.py`): an app kept in the trial's sandbox for good, with a home of
  its own. `~/Boxes/<name>/` holds `box.json` (what it runs and what it gets: written by the guide, and read
  back strictly, `box.parse`, since it is a file in the user's home), `home` (all it can write to), `Exchange`
  (bound at `~/Exchange` inside, or, for a Flatpak, shared at its own path with `--filesystem`: the one way files
  go in and out), `app` (the program, for one kept from a
  trial of a downloaded file) and `runs.json`. The guide offers the menu's apps whose program is in the
  system's folders, Flatpak apps, and the program on trial now (`trial.CURRENT`, copied in with `CopyTree`), and
  takes the network (none, or observed; a Flatpak's: none, or its usual one), the graphics card and sound as
  inputs. A program on trial that its Box already holds under the same name, as another copy (a newer release:
  `box.same_program` compares names, links and contents), replaces the one there with `CopyTree(replace=True)`,
  which moves the old copy into History's backups and puts it back on revert, and the guide says so (found in
  the 2026-10-17 review: the newer copy was silently not kept). A Box is named after its program without what each
  release adds to a file's name (`box.program_name`: the version, the architecture, the file type, words like
  beta), so a newer release is the same Box, and the guide's "Keep it in" offers "Replace the program of Box X"
  for one of the same program (its home, Exchange and settings kept); a folder that holds only a reverted Box's
  home, Exchange and runs.json is taken up again by a new set-up of that name, which says so. The guide starts
  at "Choose an app", blocked until one is chosen, and leaves the desktop's settings pages out of its list
  (`menu.App.panel`). At a logout, when systemd sends every process of the session's unit SIGTERM at once, the
  program gets the time to end as it chooses: its sandbox starts under TETHER's hold, SIGTERM and SIGHUP blocked,
  which bubblewrap and pasta keep pending (bubblewrap has no handler, and pasta's ended it at once, taking the
  sandbox with it), while STAY unblocks them and starts the program with every signal at its default; the
  launcher's stop() ends what ignores it after a few seconds, and systemd's SIGKILL anything after its own
  timeout. A Flatpak Box, with nothing of the app's inside its sandbox to pass the signal on, is as before. Its actions: `MakeDir` (0700), `CopyTree`, `WriteFile` for `box.json` and for a menu entry
  (`daprivacyscanner-box-<name>.desktop`) that runs `daprivacyscanner --box <name>` with this copy of the app.
  `--box` (`app.box_cli`, `box.run_to_end`) starts it as a trial is started (`box.as_trial`: no decoys, the
  sandbox's own files in the runtime folder and removed after the run), stays until its program has ended, and
  says a problem in a desktop dialog (`app.show_error`): one that keeps it from starting (`box.problem`: its home
  or program missing, an installed program gone, a Flatpak app no longer installed, asked of `flatpak info`), and
  a program that fails within `box.FAILED_AT_ONCE` (10) seconds, with the last of its output, which goes to the
  dialog or a terminal, never to the journal (found in the 2026-10-17 review: a Box whose program failed as it
  started ended with exit status 0, saying nothing). One run at a time: the launcher holds a kernel lock
  (flock) on a file in the Box's runtime folder for as long as it runs, which `box.running` tries, so a second
  launcher is refused and a process number used again by something else can't pass for it. The Tools panel
  starts a Box by running that same
  command on its own, so a Box never depends on the window. Each run is watched only while it runs and kept as
  numbers (`record_run`): when, how long, files written and deleted, files put in Exchange (a watch of their own:
  the bound folder was an empty mount point to the home's), hosts contacted, how many of those were new, bytes sent; hosts as salted HMACs (64 bits, the salt in the same file), never names (a boxed browser's
  hosts would be a history), the last 30 runs. The HMACs let anyone who can read `runs.json` test a guess (was
  this site contacted?), and the panel and the guide say so (the owner's decision of 2026-10-17: they stay, to
  count new hosts, and the text no longer says that nothing about the sites is kept); the Box's home holds the
  app's own records anyway. Reverting removes the menu entry, the settings and a copied program; `home` and `Exchange` stay when
  they hold anything, and the message says so. `packaging/uninstall.sh` removes the menu entries and leaves
  `~/Boxes`. Tried through the API on Mint 22.3 (a scripted app with the observed network, twice: the second
  run counted no new host; Flatpak Evince) and CachyOS (KWrite on Wayland), and reverted.
- **What does this app keep?** (`tools/appwatch.py`, `tools/activity.py`, `tools/menu.py`; helper `watch_begin`,
  `watch_poll`, `watch_end`): the scan knows where the apps in `apps.yaml` keep their data; this shows what any
  one app does on this machine, with the user's real profile. The user picks an app from the menu (`menu.apps`:
  the .desktop files the menu shows), the tool starts it in a systemd scope of its own (`systemd-run --user
  --scope`, so every process it starts is in one cgroup; Flatpak and Snap move an app into a scope of theirs,
  matched by name: `app-flatpak-<id>-*.scope`, `snap.<name>.*.scope`; with a `--description` of its own, since
  the journal otherwise says "Started …scope - /usr/bin/xed.") and the helper watches the filesystems
  with fanotify until the user ends it. An app that is already running is refused ("Close X first": started
  again it would hand over to the open copy, which isn't in the scope): a Flatpak by `flatpak ps`, a Snap by its
  cgroup (`snap.<name>.…scope`), anything else by a process of the user's that runs its program or, when the menu
  entry's command is a script, what the script starts (`appwatch._signs`: the programs it names and their
  folders, its own folder, the one above a `bin`; a tool it uses from a shared folder, zenity, doesn't count), or
  runs a script it names with its interpreter. Before, LibreOffice's `soffice` script, Firefox's and Mint's Python
  tools were never found running: LibreOffice open already was started again, handed over, and the result was
  empty. An app that runs but opens no file of its own or the user's for 20 seconds (`quiet`: oosplash waiting
  after handing over) is said to have perhaps handed over, on the page and in the result, whose "What your other
  programs wrote meanwhile" (per program and folder, counted) is where a copy already open, or a background
  service of the app's own, shows.
  - **The watch** (in the helper, a child process of its own): `FAN_MARK_FILESYSTEM` on the filesystems holding
    the caller's home, `/tmp`, `/var/tmp`, `/dev/shm`, the runtime folder and `/`, and whatever is mounted inside
    any of those or under `/media`, `/mnt` and `/run/media` (a disk at `~/Data`, a tmpfs at `~/.cache/thumbnails`,
    `~/RAMDisk`: before, they were neither watched nor said not to be), each once (by the device number in
    mountinfo: every tmpfs is its own, a btrfs's subvolumes are one). The mount table is read again every 3
    seconds (`_Filesystems.replan`): a disk mounted during the watch is watched from then on, one unmounted is let
    go. What can't be watched is listed with why, in words (`_watch_why`): a FUSE filesystem can't be looked into
    as root, among them the document portal, through which a Flatpak app opens the files the user chooses (the
    portal opens them for it, so they aren't the app's: said in the limits too) and GVFS's. A filesystem mark sees
    every mount namespace, so a Flatpak app is seen too. Events carry the folder's handle and the file's name
    (`FAN_REPORT_DIR_FID | FAN_REPORT_NAME`), turned into a path of this namespace with `open_by_handle_at`
    through the filesystem's mount, opened for each look-up and only while it is still that filesystem (held open,
    it kept a disk from being unmounted until the watch ended). The kernel refuses a filesystem mark made through
    a btrfs subvolume (EXDEV, on Linux 7.2 too), so a btrfs is looked through its top level: where the system
    mounted it, there; otherwise the child mounts it (`subvolid=5`) in a mount namespace of its own, a slave of the
    system's (what is mounted later shows in it; what it mounts never goes the other way), then maps each path
    back through where the subvolumes are mounted; a subvolume mounted nowhere gives no path. Tried on Mint (ext4)
    and CachyOS (btrfs): a tmpfs mounted in the home during the watch was watched, a file written in it by the app
    recorded, and it could be unmounted while the watch went on. However the watch ends (`watch_end`, the access
    dropped, the app quitting: the helper's input ends, or the helper is gone and the child gets SIGTERM), the
    child unmounts what it mounted and removes its folders in `/run/daprivacyscanner-watch` (they were left
    behind). They are named by the child's process, and a helper removes only its own child's and those of a child
    that has ended: every copy of the app has a helper and a watch of its own, and since Linux 3.18 an rmdir of a
    folder that is a mount point only in another mount namespace detaches that mount, which cut another copy's
    watch off from every path on that btrfs. Network shares mounted in the home or under /mnt and /media aren't
    watched, and say so: looking at one whose computer can't be reached waits for as long as it can't be. Opens, executions, changes, creations, deletions and renames are watched; not each read (an open is the read), nor folders being listed. The kernel's queue keeps
    its own limit (never `FAN_UNLIMITED_QUEUE`, with which a reader behind six busy programs let it grow from 470 MB
    to 1.7 GB of kernel memory in 25 seconds, the events' processes long gone by the time they were read): when it
    is full the kernel drops what comes next and says so, which is counted, and the page says that some of what
    happened is missing. Folders' handles are remembered as paths, so a second group per filesystem reports
    folders renamed, moved or removed (`FAN_ONDIR`, in a group of its own since on the main one it would also
    report every folder listed), and what is remembered is forgotten then: files made in `~/d2` were reported
    under `~/d1`, its name before (tested on Mint, before and after).
  - **Whose event it is**: the process's cgroup when the event is read, which must be one of the request's
    units under the caller's own `user-UID.slice`; the request can't name another account's. A process is looked
    up again when it runs a program (systemd-run and `flatpak run` move themselves into the scope first, then
    run the app: without that the app's first files went to "another program", tested). Events of other accounts
    and of root are dropped at once and only counted; a process that ended before it could be looked up is
    counted per folder under the caller's home, never named.
  - **What is kept**, in the child's memory only: the app's files under the home, the temporary folders and
    other disks, one record each (flags, opens, writes, and in how many different minutes it was written; 60,000
    at most, then counted per folder); for the system's folders, counts per folder; and the files the caller's
    other programs wrote meanwhile in programs' data and the temporary folders, one record each (30,000 at most,
    then changes per program and folder, which the result says), while in the user's own folders and on other
    disks, which are never searched for records, their changes are counted per program and folder (a build's
    thousands of files filled the 30,000, and the thumbnail written after them was dropped, unsaid). `watch_end`
    hands it over once and the child ends.
  - **The summary** (`activity.summarise`): totals; folders with counts, each as deep as says whose it is
    (`~/.config/Foo/Cache`, `~/.var/app/<id>/data/x`, `~/Documents/Work`); the files written to regularly (in three
    or more different minutes), named with what kind of file they are, programs' files only (a document of the
    user's own or on another disk, saved as often, is counted, never named); the sensitive places it opened
    (`activity.SENSITIVE`: SSH and GnuPG keys, keyrings, browsers' and mail profiles, wallets, shell histories),
    by kind; and how many of the user's own files it opened. The user's own files are never listed: that list
    would itself be a recent-files record. A file of the app's own (programs' data, temporary folders) that it
    only opened, yet whose date moved during the watch, counts as changed "by its date" (`appwatch._changed_by_date`):
    writes through a memory map (SQLite's `-shm`, an LMDB database) make no fanotify event, and it showed as read.
  - **Who recorded what was opened** (`activity.find_records`): the files written during the watch, by the app
    or by another program of the user's, are read as the user for the paths of the user's files the app opened,
    and of the files it opened in `/tmp` or `/var/tmp` that another program made (an attachment, a download), in
    every spelling programs use (`activity._spellings`): as they are, and as `file://` addresses percent-encoded as
    Python, GLib (which leaves `()'&!$*+,=@`) and Qt (`;` too) do, each also escaped for XML as a bookmark file
    has it (`&amp;`, `&apos;` or `&#39;`), in UTF-8 and UTF-16 (the first version missed "Report (final).txt" in
    the recent-files list). A PNG's text chunks are unpacked (Qt writes a thumbnail's `Thumb::URI` longer than 40
    characters compressed, as zTXt: Dolphin's thumbnails were never matched), and GVFS's metadata is read by its
    own paths, relative to the home folder (`/Documents/x`), whole in its journal and split into names in its
    database (`_gvfs_journal`, `_gvfs_tree`: Xed's cursor positions were never matched). gvfsd-metadata writes its
    journal through a memory map, which fanotify never reports, nor does the file's date always move (a second
    `gio set` during a watch on Mint left neither): so its files are searched at the end whatever was seen, for the
    paths whose entries grew since the watch began (`gvfs_snapshot`, taken then: keyed hashes of each database and
    path with their counts, in the server's memory, never in the job the page reads). Those that hold them
    are named with who wrote them: the thumbnail, the recent-files list, the desktop's notes on files, the app's
    own history. Other compressed and encrypted stores can't be read this way, and the result says so.
  - **Administrator access** is held from start to end, which the page says before it starts
    (`appwatch.WARNING`); it is dropped as soon as the watch ends, unless it was active before. Never always
    on: one app, one session, started and ended by the user, or ending itself `KEEPS_LEFT` (180) seconds after the
    app has ended (or was never seen running: it handed over to a copy already open) or its panel was closed,
    with its result kept as End keeps it (the access was otherwise held until End, however long after). The result lives in the app's memory until it is
    dismissed or the app quits; nothing is saved, put in a report or exported.
  - Tried through the app's API with the real helper on Mint 22.3 (ext4 on LUKS, kernel 7.0) and CachyOS (btrfs
    with `/home` on a subvolume, kernel 7.2), with a scripted app and with Xed and KWrite.
- **Camera and microphone** (`tools/inuse.py`): every 3 seconds, the user's processes with `/dev/video*`
  or ALSA capture devices open (`/proc/PID/fd`), and PipeWire's graph (`pw-dump`: every `Stream/Input/*`
  node and what it is linked to: a microphone, a monitor, a camera, a screen-capture stream); `pactl`
  without PipeWire. Read-only.
- **Presentation mode** (`tools/presentation.py`): notification banners and clipboard history off
  together (GNOME, Cinnamon, KDE's Do Not Disturb via the notification server's `Inhibit` D-Bus call held
  by the app's connection and Klipper turned off through Plasma 6's system tray, Xfce, GPaste, CopyQ), each a
  reversible action; where Klipper can't be reached (Plasma 5, a Clipboard widget, Plasma not running) a note
  says it keeps recording. While on, what to put back is in
  `$XDG_STATE_HOME/daprivacyscanner/presentation.json` (0600), so a crash leaves a way back.
- **Before you travel** (`tools/travel.py`): the scan's own checks that matter on a trip, with their last
  results and buttons. No detection of its own.
- **Folders kept in memory** (`mount_tmpfs`: `~/.cache/thumbnails`, `~/.local/share/gvfs-metadata`, and
  `~/Ephemeral`, a feature): a systemd mount unit of the helper's own in `/etc/systemd/system`, for the
  calling user's folder (user and home from `PKEXEC_UID`; each folder on the way opened without following
  links and the user's; `ConditionPathIsDirectory` and `ConditionPathIsSymbolicLink=!` on each, so systemd
  skips the mount, never redirects it, if one has become a link or gone; `nosuid,nodev`, `noexec` unless
  chosen; wanted, not required, by `local-fs.target`). It is written only once the folder is empty (a mount
  would hide its files, not remove them). Only `~/Ephemeral` may allow programs or be emptied at logout
  (bound to and wanted by `user@UID.service`, with `LazyUnmount=yes` so logout isn't held up); its folder on
  disk is made read-only for its owner, so nothing lands there if the mount is ever missing.

---

## 14. What the app stores

| Where | What | Notes |
|---|---|---|
| `$XDG_STATE_HOME/daprivacyscanner/` (0700) | `last-report.json`, `last-scan.json` (baseline), `accepted.json`, `undo.json` and file backups (an `undo.json` or `accepted.json` that couldn't be read, kept aside under its name, `.unreadable-` and the time), and `.lock`, the folder's lock file; each written to a temporary file, synced, renamed into place, its folder synced | Never holds deleted paths or Wi-Fi network names; the last report is saved without the entries of what starts at login (the baseline keeps hashes of them) and without the addresses and lookup names the online tests saw or the Wi-Fi networks a check names |
| `$XDG_CONFIG_HOME/daprivacyscanner/` | `ui.json` (welcome dismissed), `online.json` (endpoints) | |
| `/var/lib/daprivacyscanner/changes` | The helper's journal of root changes | Root-owned |
| `/run/daprivacyscanner/` | RAM disk state, swap state | Gone at reboot |
| `/run/systemd/system/<unit>.d/50-daprivacyscanner.conf` | `LogLevelMax=notice` for an open RAM disk's mount unit; for ~/TempBrowser's also `BindsTo=`/`Before=user@UID.service` (unmounted when the session has ended) | Root-owned; removed at the close, gone at reboot |
| `~/TempBrowser`, `~/RAMDisk` | Tool data | In memory only |
| `$XDG_CACHE_HOME/daprivacyscanner/browsers/` (0700) | Tor Browser's or Mullvad Browser's archive and signature, one per browser | Only when the download dialog's tick asks for it; deleted from the panel; on the disk, so it says the browser was set up here |
| `$XDG_STATE_HOME/daprivacyscanner/update.json` (0600) | After Check for updates… put a new copy in place: the AppImage's path, the old copy's name and identity, the two versions | Until the new copy's first start, which removes the old copy and the record |
| Beside the AppImage | `.DAPrivacyKit-update-<random>/` (0700): a release's AppImage and `.asc` while it is downloaded, verified and waiting for the user; `.<name>.<version>.old`: the old copy, after a replacement | The download goes when it is put in place, discarded, its dialog closed or the app quits; the old copy at the new one's first start |

Tools keep nothing afterwards: no log, no history, nothing in reports or exports. The one exception is the
browser's download, kept on the disk for next time when the user ticks it (section 7.4).

---

## 15. Testing

- Every check is unit-tested against fixture home directories and fake `/etc` trees, never the developer's
  system. Command output (`lsblk -J`, `ss`, `cryptsetup luksDump`, `flatpak info`…) is mocked with samples
  captured on Ubuntu, Fedora, Debian, Arch and openSUSE, GNOME and KDE (`--capture DIR` writes sanitised
  ones).
- Every auto fix is applied and reverted from the undo log in a test. Every `can()` is called on a bare
  machine.
- The suite never goes online (`FakeNet`) and never applies fixes to a real machine.
- Behaviour described above as "tested" or "live-tested" was checked on real systems: Linux Mint 22,
  Sway 1.12 in a container, and KDE Plasma 6.7 on CachyOS.
- `packaging/test-appimage.sh` smoke-tests the AppImage on Ubuntu, Debian, Fedora, Arch and CachyOS.
