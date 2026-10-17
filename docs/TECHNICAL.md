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
   it doesn't apply. What can't be determined is unknown, never guessed, and the result says so ([section
   3](#3-the-scan-engine)).
2. **One result model.** Every check answers with a status (pass, fail, warn, unknown, not applicable, error), its
   severity on this machine, its evidence (paths, values and counts, never secrets, account addresses or file
   contents), its kind and whether it can be fixed here. A finding is a failure or a warning, above severity 0,
   of a check whose kind is `finding`: caches and histories (`hygiene`) and inventories (`info`) are listed, never
   counted. What couldn't be checked is never hidden and never a pass.
3. **Privilege separation.** The app and every `scope: user` check run as the user; the app is never run as root.
   Root work goes through a small helper started with pkexec, which offers only named actions, checks every
   argument itself, reads only the files on its list and never writes content the app sends. Declined, system
   checks say what they couldn't see ([section 5](#5-the-privileged-helper)). What it reads beyond files is for the
   caller alone: a watch of one app returns what the caller's own processes did, never another account's.
4. **Read-only by default.** A scan changes nothing, the user's home folder included: programs that write as they read (dnf5 copying the system's metadata, flatpak making an installation) get folders of their own in the runtime folder, removed at once, and nothing a scan runs starts a socket-activated service.
5. **Fix tiers.** `auto`: applied after one confirmation, and reversible. `guided`: step by step, each step
   explained with its side effects and confirmed on its own. `advice`: explained, with the commands for this
   machine where that helps; the app never makes the change. `feature`: an optional set-up, not a finding
   ([section 4](#4-fixes-guides-and-the-undo-log)).
6. **The value before is kept.** Before a setting or a file is changed, what was there goes into the undo log, so
   every applied fix can be reverted from History. Deleting caches and histories is the exception: it can't be
   undone, so it is confirmed on its own. The log is a record too: it never holds deleted paths or the names of
   Wi-Fi networks.
7. **Dry run.** Every fix can show exactly what it would do, and what is shown is what is done.
8. **No secure-delete claims.** No `shred`, no overwriting of files on a disk: on SSDs and copy-on-write
   filesystems it promises what it can't keep. Encryption is what protects deleted data. Two exceptions, where
   overwriting does what it says: a RAM disk's files are overwritten before it is closed (its pages are memory),
   and Retire a drive gives, and never runs, the commands that overwrite a whole hard disk.
9. **Exports.** A report can be exported as text or JSON, redacted for sharing. What the app keeps between runs
   is the least that does the job ([section 14](#14-what-the-app-stores)), and "Export everything" hands all of
   it over.
10. **No network in a scan.** The app never phones home and a scan works offline. Online tests run only when the
    user starts them, after naming every host each one contacts; the same for the one tool that downloads
    ([section 6](#6-network-access)).

### Tools

Tools are what the user starts on files, folders or drives they choose, where checks scan the machine.

- They run only when started, on what the user chose and the companions next to it (a signature, a checksum
  list), send nothing anywhere (the browser download apart, which names its hosts first), and keep nothing
  afterwards: no log, no history, nothing in reports or exports.
- They never change the file they were given: a cleaned copy is a new file beside it. The two that delete or
  change something (Before you hand over a drive, Presentation mode) show it first, or put it back.
- They may show the user what is in their own file (its metadata, a signer's name): rule 2's limits on evidence
  are for checks and reports.
- They use the system's own programs (gpgv, mat2, exiftool, bubblewrap…), never bundled ones, and say which is
  missing and how to install it.
- They take paths from the file chooser or from `--tool`, and the server accepts only absolute paths of files
  the user can read.

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
- **Sandboxes** (bubblewrap) are started by the app for the browser in memory and for View offline….
  Whatever runs inside them is treated as hostile.

Programs the app runs get the host's environment (`hostenv.host_env`): the AppImage runtime's variables
(`APPIMAGE`, `APPDIR`, `ARGV0`, `OWD`…) are left out, and variables the app changed for itself only (such as
`GI_TYPELIB_PATH`, for its bundled typelibs) are given back as they were, so a host program never picks up
the AppImage's libraries.

---

## 2. The local web server

The UI is plain HTML/CSS/JS (`web/`) served by FastAPI on 127.0.0.1, on a random port.

- **Launch token.** The window (or browser) is opened at `/?t=<launch token>`. The server exchanges that
  token once for the session token, handed to the page in its body (`data-token`, taken off at once) and
  then forgets it, so the token in the process's command line or the browser's history is worthless a
  moment later. The page keeps the session token in its session storage, which belongs to this origin
  alone, port included, and sends it with every API call in the `X-Token` header. Not a cookie: cookies
  ignore ports, so in `--browser` mode the browser would send one to every other local server on
  127.0.0.1 the user visits (a dev server, a sync client's page, a server another account runs), which
  would then hold the session. In `--browser` mode the link is therefore for the tab it opens in: another
  tab, or a page opened without the link, is refused.
- **Every API call** needs the `X-Token` header (a cross-site form can't set it, and a cross-site `fetch`
  that sets it needs a CORS preflight the server never answers). Tokens are compared with
  `hmac.compare_digest`; a header beyond ASCII is simply wrong (403), never an error. The launch link
  passes through the browser's command line for a moment in `--browser` mode, where any account on the
  computer can read it (`/proc/*/cmdline`): it is good once, so one that was taken first leaves the real
  page refused with a message saying so.
- **DNS rebinding.** Requests whose `Host` header isn't the server's own address are refused.
- **Content Security Policy.** `default-src 'self'`, no inline script, no frames, no objects, no form
  actions. No CDN or remote asset is ever loaded.
- **Links** in the UI open in the default browser through `/api/open`, by name, from `about.LINKS` only:
  the page can't make the server open an arbitrary URL.

---

## 3. The scan engine

### The catalogue

`privacy-checks.yaml` is the source of truth: 133 entries in nine categories (encryption, auth, network,
telemetry, browser, desktop, apps, sandbox, kernel), of which 11 are online tests and 3 are features. Each entry has a stable `id`, a base `severity`
(0–10), `modifiers`, a `scope` (`user`, `system` or `online`), a fix `tier` (`auto`, `guided`, `advice`,
`feature`), a `kind` (`finding`, `hygiene`, `info`), plain-language `why` and `remedy`, and developer notes
(`detect`, `fix`, `verify`). `catalogue.py` loads and validates it; a test enforces that every entry has an
implementation.

### Context first

Before any check runs, `context.py` computes the context keys: `fde`, `virtualization`, `device`,
`multi_user`, `session`, `hibernation`, `tpm_unlock_no_pin`, `autologin`, `exposed_services`, `vpn_active`,
`ipv6_global`. A check's **effective severity** is its base severity, overridden by the last modifier
whose `when` expression (`expr.py`) matches. Severity 0 means not applicable. A key that can't be
determined is *unknown*, never guessed; modifiers that depend on it aren't applied, and the result says
so.

A check's modifiers may also use names the check itself sets. One is shared: `data_on_encrypted_disk`, which
the runner sets for the findings about data kept on the disk (`Check.stored_at` says where: the user's folders
unless the check says otherwise; `_util.on_encrypted_disk` answers from `fde`, and from each path's filesystem
where only some are encrypted). Disk encryption keeps that data safe while the computer is off, not from malware
or someone using it while it is on, so each modifier on it is one lower than the severity it would otherwise
have (never below 1, a test checks every combination), and the runner adds a note saying so.

### Running checks

`runner.py` runs the checks in a small thread pool (so checks share no mutable state). Checks reach the
system only through `host.py` (system root, home, environment, command runner), which lets the test suite
point them at fixture trees. Per-app data is found through one resolver (`paths.py`) that honours the XDG
variables and enumerates Flatpak (`~/.var/app/<id>/…`) and Snap (`~/snap/<name>/…`) locations. Desktop
differences (KDE 5/6, GNOME, gsettings) live in `desktop.py`.

Each check returns a `CheckResult` (`model.py`): `status` (`pass`, `fail`, `warn`, `unknown`,
`not_applicable`, `error`), `effective_severity`, `evidence` (paths, values, counts; never file contents,
secrets or account addresses), `kind`, `fixable`, and `notes` (things that aren't findings, such as
"hibernation is one step away"). A **finding** is `fail` or `warn` with severity above 0 and kind
`finding`; the server and the page use the same rule. `unknown` is never a pass and never fixable;
`needs_root()` marks a result as needing administrator access.

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

### The undo log

`undo.py` keeps `$XDG_STATE_HOME/daprivacyscanner/undo.json` (directory 0700, written atomically). Revert
refuses to overwrite a value changed since the fix, unless forced; a value already back where it was before
(put back by hand) is no conflict. A root change that fails part way is journalled by the helper before its error
goes back, and kept as the failed step's record, so it can be put back. systemctl's exit status never decides a
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
were changed back.

`apply_plan` rolls a failed attempt back step by step (each rollback's commands collected as a revert's
are) and, when any step had run, keeps the attempt as a `failed` entry with its `error`, the step it failed
at (`failed_step`), each step marked reverted with `revert_ran`, and a step that couldn't be put back left
revertible from History. An attempt that changed nothing leaves no entry. `/api/fix/apply` and
`/api/easy/apply` answer with each entry as made (`UndoLog.summary`), which the page shows at once
(`doneDialog`). "Export everything" (`report.changes_of`) carries all of it: commands, lines, files,
folders, what reverting ran, `via`, failures.

### Guides

A `Guide` (`guide.py`, `checks/guides/`) is a list of steps. A step either offers options (each a
`FixPlan`, applied and confirmed on its own) or gives commands for the user to run (passphrases, PINs,
fstab, crypttab). A step can take `Input`s; the page sends them back and the guide is rebuilt with them,
so the dry run always matches what is applied. Advice checks may have a guide whose steps are commands
only.

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
is run again (`Runner.rescan`).

---

## 5. The privileged helper

- **How it starts.** `pkexec /usr/bin/python3 -I helper.py` from a source tree (the polkit prompt then
  names python3), or a root-owned copy with its own polkit action
  (`/usr/libexec/daprivacyscanner/daprivacyscanner-helper`) installed by `--install-helper` /
  `packaging/install-helper.sh`, run as `pkexec <that path>`. From an AppImage it runs a private copy, since root can't read the
  AppImage's FUSE mount. `-I` keeps user site-packages and the script directory off `sys.path`. Standard
  library only.
- **Protocol.** One JSON object per line on stdin (`{"id", "action", "args"}`), one reply per line on
  stdout. It exits at end of input.
- **Actions.** Detection (`luks_dump`, `clevis_list`, `read_file` for allowlisted files,
  `empty_password_accounts` (names, never hashes), `sshd_settings`, `firewall_summary`, `ufw_status`,
  `observe_traffic`, `erase_facts`); changes (`write_dropin`, `edit_config`, `set_service`, `set_sysctl`,
  `ufw_enable`, `browser_policy`, `block_extensions`, `mount_tmpfs`, `enable_tmp_mount`, `revert`,
  `clear_crash_dumps`, `vacuum_journal`, `clear_journal_files`, `snapper_cleanup`); tools (`ramdisk_open`, `ramdisk_close`,
  `swap_off`, `swap_on`, `trim_*`, `names_*`, `watch_*`); and `install_self` / `uninstall_self`. What
  `install_self` installs is the source the helper read as it started (`own_source`), never the file as it is
  when the request comes: the helper that isn't installed yet runs from a copy in the user's runtime folder,
  which anything running as the user can change after it was authorised.
- **Validation.** It never writes content the app sends: files are generated from validated settings or
  edited by fixed rules, and only units, sysctls and policies on its own lists can be touched. The calling
  user and their home come from `PKEXEC_UID`, never from the request. Folders under the home are opened
  one component at a time with `O_NOFOLLOW` and must belong to the caller.
- **What it did.** Every change answers with `ran`: each command it ran, in order, quoted for a shell (a
  setting written straight to its file, a sysctl or a tmpfs mount, as the command that does the same;
  crash dumps deleted as `rm -f` by pattern, never by name; a file a revert restores from the journal as a
  `#` line, since no command does the same), and `files`, the paths it wrote. Reads aren't listed. History
  shows them.
- **Lifetime.** One authorisation covers a scan and the fixes after it. Access ends when the user drops
  it, after 5 idle minutes (`server.ADMIN_IDLE`), when the app quits, or straight after a scan that found
  nothing a root fix could act on. Long work holds it for as long as it runs (the TRIM test, a listing of deleted
  names, a watch of an app, which says so before it starts and drops the access when it ends). The watch and the
  other two don't run at once, nor is the helper installed or removed while any of them runs: the helper does one
  call at a time, so a disk read for minutes held the watch's polling and its End behind it, and installing the
  helper ended the watch with everything it had seen.

---

## 6. Network access

A scan never uses the network. Online tests (`scope: online`) run only when the user starts them, after
the page has listed every host each one contacts (`contacts` in the YAML; endpoints configurable in
`~/.config/daprivacyscanner/online.json`). All network access goes through `online.Net`, which follows a
redirect only to the host asked or one the call names, and never from https to http. The test suite uses
`FakeNet` and never goes online. The browser download (section 7) is the only tool that uses the network,
also through `online.Net`, and only when the user starts it.

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
   past the browser's own protections (Firefox's content sandbox). The outer sandbox then keeps that
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
   worst a forged one can do is what the user could do themselves to their own empty folder.

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
stopped or failed is deleted.

**Or an archive the user picked.** `browser.copy_in` opens it (and its `.asc`) with `O_NONBLOCK`, checks it
is a regular file of at most 600 MB and that there is room, and copies it into `.downloads` with
`O_EXCL | O_NOFOLLOW`. What is verified and unpacked is that copy, never the user's file (which could
change between the check and the unpack on a shared or removable disk). The user's file is never touched.
Then `check_latest` asks the project's index for the latest version and refuses an older archive.

### 7.5 Step 3: verification

`browser.verified` runs Verify a download (section 9) on the archive **with the app's own keys only**
(`use_keyring=False`: the user's GnuPG keyring is not consulted). It accepts only the level *verified*
with a good signature by the project `torbrowser` in `signing-keys.yaml`, the Tor Browser Developers key,
which signs both browsers. Anything else (a good signature by any other key, intact-only, bad) is refused
and nothing is unpacked.

**Where the index can't be reached** (the project's server blocked, typical where people get Tor Browser
from GetTor or a mirror), a picked archive is accepted only once its signature verifies *and* the
signature's hashed creation time (`keys.signature_created`, trustworthy once the signature is good) is
within 30 days (`RECENT_DAYS`). The job and the card say the check couldn't be made.

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
6. Renames the staging folder into place. On any error the staging folder is removed.

The downloaded archive and signature are then deleted (`tidy`): they are public files, and their memory is
given back.

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
security level, and whether the latest-version check couldn't be made.

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

Nested user namespaces stay allowed, so Firefox's own content sandbox keeps working inside.

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

**`/proc` masks**, in the innermost sandbox only: `/proc/cmdline` is covered with `ro quiet` (the real one
names the disks' UUIDs), and `/proc/sys/kernel/random/boot_id` with a new random UUID at every start (the
real one is the same for every session until a restart, which would let sessions be linked);
`/proc/partitions` and `/proc/swaps` with their header line only (the disks' names and sizes, swap's file or
device); `/proc/bus` (the input devices' list, with a Bluetooth keyboard's or mouse's hardware address and
devices' serial numbers; PCI's), `/proc/scsi` (the disks' models) and, unless the graphics card is given,
`/proc/driver` (`nvidia/gpus/*/information` holds the card's serial number, readable whether or not the card
was given: matched `nvidia-smi` on the lab) with an empty tmpfs made read-only; each only where this kernel
has it (`proc_masks`, a mount point must already be there). Only the
innermost sandbox gets these: once a file of a procfs is covered, the kernel refuses to let anything
inside mount a procfs of its own (tested), which Tor Browser's inner sandbox needs to do. Firefox's own
sandbox doesn't.

**Environment** (`sandbox._env`), and nothing else:

```
HOME=/home/user  USER=user  LOGNAME=user  PATH=/usr/local/bin:/usr/bin:/bin
XDG_RUNTIME_DIR=/run/user/1000  TZ=UTC
XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_DATA_HOME, XDG_STATE_HOME, TMPDIR → /home/user/.session/…
LANG, LANGUAGE, LC_CTYPE, LC_MESSAGES (from the host: the user's language; not the regional formats,
  LC_TIME, LC_NUMERIC and the rest, nor LC_ALL: they say the country where the language doesn't)
the display's variables (section 7.10); PULSE_SERVER when sound is allowed (section 7.11)
```

The start script moves `HOME` into its own folder, but GTK, fontconfig and Mesa follow the XDG variables:
pointing them into the session folder keeps their state in memory too.

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
before `exec`. It is applied to Mullvad Browser's sandbox and to Tor Browser's outer sandbox (tor). Tor
Browser's inner sandbox has its own network namespace, which already separates abstract sockets.

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
`sandbox.sealed`; bubblewrap closes it once read), so its command line names only paths inside.

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
On X11 the sandbox protects files and the network, not the screen: any X11 client can read other windows
and inject keystrokes. The panel says so, with `sbx.x11_session`'s How to….

A display reached over TCP (SSH forwarding) needs the network: Tor Browser's sandbox refuses it, and
Mullvad Browser then runs without pasta.

**A display of its own (Xephyr)**, optional on X11 (`sandbox.nested`):

- Xephyr (the host's; its package named per distribution) runs in a sandbox of its own with **no
  network**, the computer's X socket bound by path, and the computer's cookie. It is the only thing given
  the real display.
- It listens only on its socket file in the private folder (`-nolisten tcp -nolisten local`), with a
  fresh random 16-byte MIT-MAGIC-COOKIE-1, `-no-host-grab`, `-resizeable`, and `-terminate 10` (it ends
  10 seconds after its last client disconnects: the browser's start runs short-lived X clients first).
- It runs under a focus keeper (`tools/xfocus.py`, run by the computer's python3 in Xephyr's sandbox, the X11
  protocol by hand): without a window manager, X's focus follows the pointer, so moving onto a menu (an
  override-redirect window) took the focus from the browser's window and the browser closed the menu. The keeper
  sets the input focus (revert to PointerRoot) on each normal window the browser maps and on the one the pointer
  enters, never on menus, tooltips or GTK's 10×10 helpers; it disconnects 8 seconds after the browser's windows
  are gone, so `-terminate` still ends Xephyr. Without python3, Xephyr runs alone.
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

### 7.12 Tor Browser's network: two sandboxes and a filter

Tor Browser has no network of its own. It runs as two nested sandboxes, and tor in a third:

```
host
└─ python3 KEYRING wrapper
   └─ bwrap  OUTER   --unshare-all --share-net   (computer's network; Landlock scopes)
      │   /etc with the computer's resolver (tor and its transports need DNS)
      │   tor's data folder writable here; tor/ folder at /run/user/1000/tor
      │   sandbox identity files at /run/identity
      └─ python3 -I -c <torgate.py source> <config>
         ├─ bwrap  TOR  --unshare-user --unshare-pid …   (the outer one's network; no display, sound or profile)
         │  └─ tor  (Tor Browser's own binary, from its folder) and its pluggable transports
         │     SocksPort    unix:/run/user/1000/tor/socks
         │     ControlPort  unix:/run/user/1000/tor/tor-control  (cookie auth)
         ├─ control-port filter, listening on /run/user/1000/tor/control (0600)
         └─ bwrap  INNER  --unshare-all   (own network namespace: loopback only)
               /etc built from the outer one's, no resolv.conf at all
               /proc masks; tor's data folder covered by an empty tmpfs
               only the socks and control sockets of tor/ bound in
               TOR_SKIP_LAUNCH=1  TOR_SOCKS_IPC_PATH=…/socks  TOR_CONTROL_IPC_PATH=…/control
               └─ start-tor-browser → firefox
```

**The gate** (`tools/torgate.py`) is passed as source with `python3 -I -c` (the AppImage that started it
may be unmounted by the time the browser closes) and imports nothing of the app's. It:

1. applies Landlock's scopes when the kernel has them;
2. starts tor, in a sandbox of its own inside the outer one:
   ```
   bwrap --die-with-parent --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup-try
         --new-session --cap-drop ALL  <the system, read-only>  --ro-bind /etc /etc
         --proc /proc --dev /dev --tmpfs /tmp  --ro-bind <TorBrowser/Tor> (tor and its transports)
         --bind <Data/Tor>  --bind /run/user/1000/tor  --chdir <Browser> --
   tor --defaults-torrc <Data/Tor>/torrc-defaults -f /run/user/1000/tor/torrc
       DataDirectory <Data/Tor>  ClientOnionAuthDir <Data/Tor>/onion-auth
       GeoIPFile <Data/Tor>/geoip  GeoIPv6File <Data/Tor>/geoip6
       +__ControlPort unix:/run/user/1000/tor/tor-control
       +__SocksPort "unix:/run/user/1000/tor/socks IPv6Traffic PreferIPv6 KeepAliveIsolateSOCKSAuth"
       CookieAuthentication 1  CookieAuthFile /run/user/1000/tor/control_auth_cookie
   ```
   with `HOME`, a minimal `PATH` and `LD_LIBRARY_PATH` for tor's own libraries; it waits up to 60 seconds
   for the sockets and cookie. The outer sandbox holds what the inner one binds from it: the display's socket
   and X cookie, sound's socket, the browser's profile and Downloads; and its processes see the inner ones.
   tor needs none of it, and its pluggable transports parse what the network sends them (Snowflake's: WebRTC
   from volunteers' proxies), so tor and they run without it (found in the review of 2026-10-17: tor's `/tmp`
   held `.X11-unix` and `.Xauthority`; since, empty, and the profile out of sight, tested on Mint 22.3 and
   CachyOS). Its own PID namespace means tor can no longer watch the gate by its PID
   (`__OwningControllerProcess`): it dies with the gate instead (`--die-with-parent`);
3. follows tor's log: `Bootstrapped N%` lines update `status.json` (`starting`, `connecting`, `connected`,
   `failed`, `stopped`, with progress, summary and the last warning). The panel reads it every 2 seconds
   while the browser runs;
4. asks tor for its version on its own connection (for the PROTOCOLINFO reply);
5. listens on the browser's control socket and filters every connection (below);
6. runs the inner sandbox and waits for it; on exit (or SIGTERM) it closes the filter, stops tor (`halt`:
   `SIGNAL HALT` over its control port, so that it saves its state, as on SIGTERM, then waited for; a signal to
   tor's bubblewrap would end tor at once, unsaved; SIGTERM, then SIGKILL after 10 seconds, only if it hasn't
   gone: tested, tor gone and its state file written in about a second), and removes the sockets. The inner
   sandbox's command lasts as long as any browser process does (`sandbox.STAY`, above, its PID 1), and the inner
   sandbox is started with `--die-with-parent`: when its command is over, or the gate is gone, it is killed and everything
   in it with it. A browser is never left running with tor gone.

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
   └─ pasta --config-net --quiet --no-map-gw -t none -u none -T none -U none --dns-forward 169.254.0.1
            -M 9a:55:9a:55:9a:55 -I eth0 -a 10.0.2.15 -n 24 -g 10.0.2.2 [-a fd00::15 -g fe80::9855:9aff:fe55:9a55 | -4] --
      └─ /bin/sh -c '<fence rules> ; exec "$0" "$@"'      (as root of pasta's namespace)
         └─ bwrap --unshare-all --share-net …              (pasta's namespace, not the computer's)
            /etc/resolv.conf: nameserver 169.254.0.1, options edns0
            └─ python3 LANDLOCK → start-mullvad-browser → firefox
```

- `--no-map-gw`: the host's loopback services aren't reachable through the gateway address. No ports
  are forwarded in either direction (`-t/-u/-T/-U none`).
- DNS goes to pasta's forwarder at 169.254.0.1, which forwards to the computer's resolver. Over TCP only
  where pasta forwards that too: pasta 2026-01-20 does, 2024-02-20 (Mint 22.3, Ubuntu 24.04) sent the
  connection on to 169.254.0.1 itself, where it timed out (tested). `probe_fence` connects to it from inside
  (2 seconds at most, once per run of the app) and the fence lets TCP through only where that worked;
  elsewhere it is refused at once. The sandbox's resolver asks with EDNS0, so a large answer comes over UDP.
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
| 50 | `lookup main to 169.254.0.1 ipproto udp dport 53`, and `… ipproto tcp dport 53` where pasta forwards DNS over TCP: pasta's DNS forwarder, for DNS alone |
| 100 | `prohibit` to 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (CGNAT, Tailscale), 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 |
| 100 | `prohibit` to fc00::/7, fe80::/10, ff00::/8 (tolerated if pasta has no IPv6) |
| 100 | `prohibit` to **the computer's own networks** (`host_networks`, listed on the computer with `ip -j address show` and `ip -j route show table all type unicast` just before pasta starts): every address of the computer's on every interface (but loopback's) and the network it is on, a point-to-point link's far end, and the unicast routes of every routing table, merged, those inside the ranges above left out. Not the default routes, nor the routes through one interface that between them cover at least a sixteenth of IPv4 (or of IPv6's 2000::/3): a VPN that carries everything but the local network does it with broad routes in place of a default one (WireGuard's "exclude private IPs", OpenVPN's 0.0.0.0/1 and 128.0.0.0/1) |
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
- the start is watched for 3 seconds: if it exits with an error, the log's last lines (pasta's notices
  left out) are shown, Xephyr is killed, and the mark is removed if this was the copy's first start (no
  website ever reached it);
- a later failure is reported once by the panel (`launch_problem`, which also reaps the process), by its exit
  status alone: once the browser has run, the log could hold anything a website that took it over wrote into
  it (the sandbox can reach the log's descriptor), which the page would show as the app's own words.

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
says the file's name goes with it.

**The TempOutbox** (`transfer.run_outbox`) does the same for files the user copies in with the file
manager. Each browser has its own, `~/TempBrowser/Outbox for Tor Browser` or `… for Mullvad Browser`, at the
RAM disk's top, which no sandbox is given, holding `Originals` and `Not cleaned`. It is made when the browser
is set up (`default_outbox`) where mat2 is installed, unless the permanent Outbox is set up and watching
(`permanent_outbox`: its path unit, and the link in `default.target.wants`, read from the files so the panel
can ask every few seconds); then the panel says to use `~/Outbox` and copy from `~/Outbox/Cleaned`. The panel
turns it off (`remove_outbox`: refused while anything is in it, since an original may be the user's only copy)
and on. A thread of the app's (`create_app(watch_outbox=True)`, every 2 seconds) looks into each set-up
browser's TempOutbox while `~/TempBrowser` is mounted (`ramdisk.mounted`: the mount table only): every regular
file at its top, not hidden or partial and unchanged for 2 seconds, is opened without following links, cleaned
through the staging folder into that browser's To upload under a free name (`_add_fd`, what Add a file to
upload… does), and moved into `Originals`; one that can't be cleaned (mat2 doesn't know the format, no room)
goes into `Not cleaned` and is never passed on. Folders put there are left as they are; without mat2 nothing is
touched. No desktop notification is sent (a notification history can keep the names on the disk): the last 20
events are kept in memory for the panel, which follows the status every 2 seconds while a TempOutbox is on, and
forgotten when `~/TempBrowser` is wiped, which waits for a run in progress (`OUTBOX_LOCK`).

**Downloads.** The browser owns its Downloads folder and could fill it with anything, including a link to
`~/.ssh/id_ed25519` that points nowhere inside the sandbox but at the real key outside. So
`transfer.downloads` reads the folder one name at a time without following links (every folder from the
RAM disk down) and lists only finished downloads: regular files on the RAM disk's device, one hard link,
no `.part`, unchanged for 2 seconds. Each is judged by content (`sniff.py`, from an open descriptor, at
most 16 MB read, cached while unchanged):

- programs whatever their name: ELF, Windows PE, Mach-O, Java, Android, `#!` scripts, `.desktop`
  launchers, Windows shortcuts ("it is a Linux program, though its name says pdf file");
- disk images (ISO 9660 and UDF at 32 KiB, DMG, qcow2, VHDX, VMDK, or by name): never presented as safe,
  since opening one mounts it;
- archives: their contents aren't checked, but a ZIP's programs are listed;
- macros: OOXML `vbaProject.bin`, OLE2 `_VBA_PROJECT`, OpenDocument Basic/Scripts, macro-format names; in a
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

- a program from `/usr` or `/opt` runs in bubblewrap with no network namespace sharing (loopback only),
  the computer's `/etc` read-only with what names the user or computer covered (`identity`: passwd, group,
  hostname, hosts, machine-id, fstab, crypttab, krb5.conf…; folders such as `ssh`, `NetworkManager`,
  `wireguard`, `cups` replaced by empty tmpfs), an empty home in memory with only that file read-only in
  it, and the display (a compositor-marked Wayland socket where possible). No sound, no D-Bus, no other
  file. No `/proc` masks (glycin-based viewers start sandboxes of their own);
- a Flatpak app runs with `flatpak run --unshare=network` and `--nofilesystem` for home, host and every
  folder its permissions grant (`flatpak info --show-permissions`; taking away home alone left
  `~/Downloads` readable, tested). A link clicked in it can still open in the default browser through a
  portal, and the page says so;
- a Snap, or a program in the home folder, isn't started.

The viewer's own files live in `.<folder>-app/view`, never over the browser's. Earlier views' copies that
no program holds open or has mapped (matched by inode, since a sandbox sees another path) are removed at
the next view. Live-tested: xreader showed a PDF from its sandbox.

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
user's is named as itself.

When the app quits with the browser still running, `~/TempBrowser` stays open until it is closed from the
app later or the computer restarts.

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

---

## 8. The RAM disk

`tools/ramdisk.py`; helper `ramdisk_open`, `ramdisk_close`. `~/RAMDisk` is opened on demand; size and
`noexec` are the user's choice. Mounting is as in section 7.3.

**Closing** (as the user, then the helper):

1. Refused while a process of the user's holds anything in it ("Close X first").
2. `ramdisk.wipe` walks the tree with `os.fwalk(follow_symlinks=False)`, only on the tmpfs's own device
   (links and other filesystems mounted inside are skipped). Each regular file is opened `O_WRONLY |
   O_NOFOLLOW`, re-checked with `fstat`, and every data region (`SEEK_DATA` / `SEEK_HOLE`) is overwritten
   with zeros in place, then `fsync`ed. Then everything is deleted.
3. The helper unmounts it (never lazily: a lazy unmount would leave files reachable through whatever holds
   them; `EBUSY` is refused) and puts the folder back: removed if the helper made it, its old permissions
   restored otherwise (from the state in /run, or after a reboot from the folder's own attribute).

Overwriting is meaningful here (rule 8's exception) because a tmpfs's files are memory pages that a write
replaces in place. It doesn't reach copies other programs made (thumbnails, recent-file records, the
clipboard), file names, or pages swapped out where `noswap` wasn't available; the page says so.

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
- **Checking OpenPGP signatures:** the host's `gpgv`, with a temporary home and keyrings of the app's own.
  Where gpgv is missing, `sqv` (Sequoia) checks detached signatures, against the listed keys and chosen key
  files only (it can't read GnuPG's keybox). A good signature by a signing subkey is mapped to its primary
  key.
- **SSH signatures** (`ssh-keygen -Y check-novalidate -n file`): checked for being good, and the key's
  fingerprint shown. There is no list of SSH keys, so an SSH signature is never *verified*.
- **minisign signatures:** need the project's minisign public key, chosen as a key file; a good one is
  shown with its key id. It is never *verified* either, since the app lists no minisign keys.
- **Checksum lists:** GNU (`hash  name`, `hash *name`), BSD (`SHA256 (name) = hash`) and bare hashes; the
  algorithm from the BSD tag, else from the length (`b2sums` is BLAKE2b). In a clearsigned list only the
  text inside the signed block counts (RFC 9580 7.1, dash-escaping undone). A pasted checksum may carry
  spaces, a `sha256:` prefix or a whole `hash  name` line.
- **Companions:** signatures and checksum lists next to the file are found automatically; if the user
  picked the signature, the file it signs is used. Recognised file names tell the user what to download
  when the companions are missing.
- **Packages** carry their own signatures (`packages.py`). A `.deb`: a dpkg-sig member (`_gpg<role>`, a
  clearsigned list of every other member's MD5, SHA-1 and size: every member must be listed and match) or
  a debsigs member (a detached signature over `debian-binary`, `control.tar.*` and `data.tar.*` joined). An
  `.rpm`: the signature header's tags 1002/1006 (over header and payload), or 267/268/278 (over the header
  only, which must then hold the payload digest, tag 5092, checked; without it the contents aren't covered,
  and the result says so). What a signature covers that can be large is streamed to gpgv through a named
  pipe, never copied into memory-backed `/run`.

**Verdicts** (`verify.decide`), in this order:

| Level | Title | When |
|---|---|---|
| `bad` | Don't use this file | Any bad signature, a revoked key, a checksum in a list that doesn't match, or a pasted checksum that doesn't match |
| `verified` | Verified: made by *project* | A good signature by a listed project's key over the file, over a checksum list containing its hash, or inside the package; or the file's SHA-256 is one a project publishes on its own site (`checksums` in the YAML, with a note that a newer release needs the app updated) |
| `signed` | Signed, by a key the app doesn't list | A good signature by any other key (keyring, chosen key file, SSH, minisign), with its fingerprint to compare with the project's site |
| `intact` | Not damaged, but not verified | A checksum matches; MD5 and SHA-1 alone get a note that they are weak |
| `unchecked` | Nothing to check it against | No companion, or signatures that couldn't be checked (no key, no tool) |

A project that signs nothing (`unsigned: true`: Garuda Linux, Bazzite) is *intact* at best, and the
result says that is as far as a check can go. An expired key's signature still counts, with a note.

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
   | none | otherwise | **pass** |
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
    them is its first block, naming itself and that parent. Followed downwards, so a deleted tree is listed
    folder by folder.
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
  directory items and stale item headers. As long as one TRIM-test pass.
- **The list** goes to the page once and is dropped by the server as it hands it over. The helper keeps it
  in memory only, for the checks after a clean-up, until the window closes. Never saved, logged or
  exported.
- **Clearing on ext4** (as the user, after a dry-run plan and confirmation; never synced folders, never
  other users'): *fillers* for small folders (empty files with names as long as each deleted one, a round
  at a time, re-read until the names are gone; the folder stays the same inode) or a *rebuild* for large
  indexed folders (a new folder with the same group, mode, flags, xattrs and ACLs, every entry moved with
  `renameat2(RENAME_NOREPLACE)`, then swapped with `RENAME_EXCHANGE`, rolled back on failure). Fillers
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
types the drive's name:

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
OACS, FNA and SANICAP via the helper's ioctl), read on request and kept for the session only.

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
  (`FILE.cleaned.EXT`, never over one); the ticked files of a folder go into a new folder beside it,
  `NAME (cleaned)` (or `(cleaned 2)`…, never one already there), with the same subfolders, cleaned from
  copies in a hidden working folder inside it (contents and mode only: no extended attributes, where
  browsers keep a download's address), so mat2 never writes into the user's folder; a file mat2 can't
  clean gets no copy and is listed, and a folder with nothing cleaned is removed. Each copy is read again
  afterwards: the page flags copies that still say where, who or which device. Stopping keeps what was
  cleaned. For a PDF, mat2's normal mode redraws every page as an image (text can't be selected any
  more); *Lightweight* keeps the text and removes less. Linux allows any bytes in a file name: one that
  isn't UTF-8 reaches Python as lone surrogates, which UTF-8 can't encode, so the server's JSON escapes
  everything beyond ASCII (`server.JSONResponse`, every response): the page shows such a name with a
  replacement character and sends the same escaped path back, which names the file again. The **Outbox** (`app.metadata_outbox`) is a systemd user path unit that runs
  `daprivacyscanner --outbox` when files land in `~/Outbox`: each is cleaned into `~/Outbox/Cleaned` and the
  original moved to `~/Outbox/Originals`; a file mat2 can't clean goes to `~/Outbox/Not cleaned`. Nothing is
  deleted.
- **File chooser** (`tools/pick.py`): pywebview's dialog in the window (GTK's recent-files recording
  turned off for the app, which outranks the desktop's setting), zenity or kdialog in a browser, else a
  typed path. The server accepts only absolute paths of regular files the user can read (and, for Remove
  metadata, folders they can open).
- **Try an app** (`tools/trial.py`, with `tools/homewatch.py`, `tools/bait.py`, `tools/pcap.py` and
  `tools/sandbox.py`'s pieces): a program the user doesn't know yet, run in a sandbox with a throwaway home, and
  a report of what it did. One trial at a time; no administrator access.
  - **What can be tried** (`prepare_file`, `prepare_app`; a file is judged by its first bytes, `classify`): an
    AppImage (type 2: run with `APPIMAGE_EXTRACT_AND_RUN`, since it can't mount itself in a sandbox; type 1 is
    refused, saying why), a program, a script; an archive (tar, zip), unpacked by the computer's python3 inside a
    sandbox with no network that sees only the file and the folder (`UNPACK`), after which the user picks the
    program in it (`candidates`: a menu entry's program first, then programs near the top; a link is resolved
    inside the tree, never onto the computer); a .deb, unpacked the same way and never installed (its maintainer
    scripts aren't run, its dependencies aren't installed, and the page says so); an installed app from the menu,
    whose program must be in the system's folders; a Flatpak app. A Snap is refused. The file chosen is copied
    into the trial's folder: the original is neither changed nor run.
  - **The trial's folder** (`places`): in memory (`$XDG_RUNTIME_DIR/daprivacyscanner-trial/<id>`, a tmpfs) or on
    the disk (`$XDG_CACHE_HOME/...`) for something large, 0700, holding `home` (the throwaway home), `app` (the
    copy or the unpacked tree) and `private` (the sandbox's own files, which it is never given). Discarding
    overwrites it in place and deletes it in memory, and only deletes it on the disk (rule 8; the page says that
    doesn't erase it). Quitting the app discards it (the window's Quit as well as `--browser` mode's); folders left
    by a copy of the app that has ended are removed at the next start. Each trial's folder is locked (`flock` on
    the folder) by the copy that made it, so another copy (a right-click entry's) never takes a running trial
    for a leftover.
  - **The sandbox** (the `bubblewrap` engine; engines sit behind `ENGINES`): every namespace, `--die-with-parent`
    (Stop ends bubblewrap, and its sandbox, in a session of its own, must go with it: without it KWrite ran on
    after Stop, tested), no capabilities, a new session, an environment built from scratch, `/usr` read-only, the
    computer's `/etc` with what names the user or computer covered (`sandbox.identity`), the throwaway home at
    `/home/user`, the program read-only at `/app`, the display (on Wayland a socket the compositor marks as a
    sandbox's where it has the protocol; on X11 the X server's, with a warning, or Xephyr when ticked), no session
    D-Bus, keyring or agents, and the kernel keyring and crash-dump protections every start gets
    (`sandbox.KEYRING`). The graphics card when ticked (on by default: the owner's decision, so that a trial
    feels as the app would) and sound when ticked. Its command is `STAY`, a subreaper that waits for everything
    the program starts (a launcher that starts the real program and ends) but not for the session's own helpers
    once the program has ended (`HELPERS`: a D-Bus daemon started on demand stays for good, and the trial would
    never end by itself: seen with Xed).
  - **A .deb's files where it expects them**: a first bubblewrap that is root of its own user namespace mounts an
    overlay of the package's `usr` over `/usr`, then starts the sandbox proper inside that view; the package's
    `opt` is bound at `/opt`. Bubblewrap 0.9 (Mint 22.3) has no overlay option of its own; this needs none
    (`probe_overlay` tries it first). Tested with Ubuntu's `hello` and `galculator` packages.
  - **A Flatpak app** (the `flatpak` engine) runs in Flatpak's own sandbox: `flatpak run --sandbox` drops what the
    app declares for itself, and the trial grants back the display, `--filesystem=home`, the filtered session
    bus (`--session-bus`: without it GTK 4 apps, which start their image loaders through a portal, stop at once:
    Evince 48, tested) and what was ticked. `HOME` points at the throwaway home, so its data goes to
    `<home>/.var/app/<id>` and "home" is the made-up one (the real `/home` isn't in its sandbox: tested with
    Flatpak 1.14); its real data in `~/.var/app` isn't touched. It can still ask the desktop's portals, which the
    page says.
  - **The network**: none, or its own through pasta (`--pcap` into a pipe), fenced off from the local network
    (`sandbox.fence(proxies=False)`: Mullvad Browser's proxy exception isn't for a program on trial), refused
    when pasta or the fence isn't usable; never the computer's own network. `tools/pcap.py` reads the packets as
    they come and keeps only sums per host: connections, ports, bytes each way. A host is named by the DNS
    answer that gave its address, else the name in a TLS connection's first message, else an HTTP Host line,
    else its address; names looked up and never connected to are listed apart. No packet or payload is kept. A
    Flatpak can't be put behind pasta (it would run as root of pasta's namespace): none, or its usual network,
    unobserved.
  - **The watch** (`tools/homewatch.py`): inotify on every folder under the throwaway home, as the user. It
    records what is opened, changed, made, deleted and renamed, in the records `activity.summarise` reads (here
    with file names: the home is made up), and leaves its own listings out (a folder it looks through when it
    appears isn't counted as listed by the program).
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
  inputs. Its actions: `MakeDir` (0700), `CopyTree`, `WriteFile` for `box.json` and for a menu entry
  (`daprivacyscanner-box-<name>.desktop`) that runs `daprivacyscanner --box <name>` with this copy of the app.
  `--box` (`app.box_cli`, `box.run_to_end`) starts it as a trial is started (`box.as_trial`: no decoys, the
  sandbox's own files in the runtime folder and removed after the run), stays until its program has ended, and
  says a problem in a desktop dialog (`app.show_error`). One run at a time: the launcher holds a kernel lock
  (flock) on a file in the Box's runtime folder for as long as it runs, which `box.running` tries, so a second
  launcher is refused and a process number used again by something else can't pass for it. The Tools panel
  starts a Box by running that same
  command on its own, so a Box never depends on the window. Each run is watched only while it runs and kept as
  numbers (`record_run`): when, how long, files written and deleted, hosts contacted, how many of those were
  new, bytes sent; hosts as salted HMACs, never names (a boxed browser's hosts would be a history), the last 30
  runs. Reverting removes the menu entry, the settings and a copied program; `home` and `Exchange` stay when
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
    behind). Opens, executions, changes, creations, deletions and renames are watched; not each read (an open is the read), nor folders being listed. The kernel's queue keeps
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
    on: one app, one session, started and ended by the user. The result lives in the app's memory until it is
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
| `$XDG_STATE_HOME/daprivacyscanner/` (0700) | `last-report.json`, `last-scan.json` (baseline), `accepted.json`, `undo.json` and file backups | Never holds deleted paths or Wi-Fi network names; the last report is saved without the entries of what starts at login (the baseline keeps hashes of them) and without the addresses and lookup names the online tests saw or the Wi-Fi networks a check names |
| `$XDG_CONFIG_HOME/daprivacyscanner/` | `ui.json` (welcome dismissed), `online.json` (endpoints) | |
| `/var/lib/daprivacyscanner/changes` | The helper's journal of root changes | Root-owned |
| `/run/daprivacyscanner/` | RAM disk state, swap state | Gone at reboot |
| `~/TempBrowser`, `~/RAMDisk` | Tool data | In memory only |

Tools keep nothing afterwards: no log, no history, nothing in reports or exports.

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
