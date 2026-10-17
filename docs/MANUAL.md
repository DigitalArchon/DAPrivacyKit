# DA Privacy Kit: user manual

DA Privacy Kit looks over your Linux computer for common privacy problems, explains what each one
means for you, and fixes the ones it can fix safely. A scan only reads: it never changes anything and
never uses the network.

It is not antivirus, and it doesn't replace a system built for anonymity such as Tails or Qubes OS. It
makes an ordinary Linux desktop leak less.

For how the advanced tools work inside, see [TECHNICAL.md](TECHNICAL.md).

---

## Contents

1. [Install and start](#1-install-and-start)
2. [The window](#2-the-window)
3. [Run a scan](#3-run-a-scan)
4. [Read the results](#4-read-the-results)
5. [Fix what it finds](#5-fix-what-it-finds)
6. [History: undo a fix](#6-history-undo-a-fix)
7. [Save or share the report](#7-save-or-share-the-report)
8. [Online tests](#8-online-tests)
9. [Tools](#9-tools)
10. [Set-ups that last](#10-set-ups-that-last)
11. [From a terminal](#11-from-a-terminal)
12. [What the app keeps, and removing it](#12-what-the-app-keeps-and-removing-it)
13. [Troubleshooting](#13-troubleshooting)
14. [Report a problem](#14-report-a-problem)

---

## 1. Install and start

The app is one file, an AppImage. Nothing needs installing.

```sh
chmod +x DAPrivacyKit-*.AppImage
./DAPrivacyKit-*.AppImage
```

It runs on Ubuntu 24.04 and Linux Mint 22, Debian 13, and current Fedora, Arch and CachyOS, on 64-bit
Intel or AMD processors.

**Desktops.** The app is made for and tested on two: Cinnamon (Linux Mint) and KDE Plasma 6. GNOME, Xfce
and KDE Plasma 5 are not tested and not supported. The app has checks and fixes for their settings, but
none of that has been tried on a real machine: a result may be wrong, and a fix may not do what it says.
If you use it there anyway, look at each fix's dry run before applying it, and at History after.

**Check the download.** Each release is signed with the Digital Archon release key, fingerprint
`3AA5 C061 33BB C05A 4151  EA41 5B59 48EB 785E D3AF` (the key is `docs/release-key.asc` in the project's repository). With the `.asc`
from the release page next to the AppImage, `gpg --import release-key.asc` once, then `gpg --verify
DAPrivacyKit-*.AppImage.asc` says whether it is the file that was published; check that the fingerprint it shows
is this one. A copy of the app you already have does the same for the next one with **Verify a download**.
Each release also has a `.sha256` file beside the AppImage. With both in one folder,
`sha256sum -c DAPrivacyKit-*.AppImage.sha256` says whether the download arrived whole. Every release can
also be rebuilt from its source to the very same file, which shows it is what the source says it is:
[packaging/README.md](../packaging/README.md) has the one command for that.

**Updates.** The app never goes online to look for a newer version of itself. A release's page is where new
ones appear; once your copy is more than three months old, the app says so at the top of the window, with the
address. To update, download the new AppImage and use it in place of the old one: what the app keeps
(History, accepted findings, your settings) carries on.

**The window needs WebKitGTK 4.1.** Most desktops have it. If yours doesn't, the app doesn't start: it says
what to install (in a message box when started from the menu). It never opens in your web browser by itself:
there, any browser extension allowed on all sites could read the page, with your findings and file names, and
the browser may send what you type to an online spell checker or keep it. `daprivacyscanner --browser` runs it
in the browser anyway, if you accept that; the page then says so at the top.

| Distribution | Package |
|---|---|
| Debian, Ubuntu, Mint | `gir1.2-webkit2-4.1` |
| Fedora | `webkit2gtk4.1` |
| Arch, CachyOS | `webkit2gtk-4.1` |

**Install the administrator helper, once (recommended).** Some checks and fixes need root (for example,
reading disk encryption settings or turning on the firewall). The app never runs as root; it asks a
small helper to do those few things, and you approve each session with your password. Install the helper
so the password prompt names the app rather than "python3":

```sh
./DAPrivacyKit-*.AppImage --install-helper
```

You can also do this from the app when it offers. `--uninstall-helper` removes it.

**The first time it starts,** a short notice explains what the app is and isn't. Tick *Don't show this
again* to hide it. Click the app's name at the top left to read it again.

---

## 2. The window

Across the top:

| Item | What it does |
|---|---|
| **Scan** | Runs a scan. Read-only. |
| **with administrator access** | Tick it before scanning to let checks that need root read what they need. You are asked for your password. |
| **Unprivileged / Administrator** badge | Whether administrator access is active now. **Drop** ends it at once. |
| **Filter checks…** | Type to narrow the list. |
| **show not applicable** | Also lists checks that don't apply to this computer. |
| **What a scan reads…** | Exactly what a scan looks at, and what it never does. |
| **Tools…** | The tools (section 9) and set-ups that last (section 10). |
| **Online tests…** | Tests that need the network (section 8). |
| **History** | Fixes you have applied, with Revert (section 6). |
| **Light / Dark** | Switches the theme. |
| **Export…** | Saves or copies the report (section 7). |
| **Quit** | Closes the app (and anything it must close, such as the browser's RAM disk). |

Below that are two panes:

- **Context** (left): facts about this computer that decide how serious each problem is, such as
  whether the disk is encrypted, whether it is a laptop, or whether a VPN is on.
- **Checks** (right): every check and its result.

---

## 3. Run a scan

1. Decide whether to tick **with administrator access**. Without it, checks that need root can only
   partly look, and say so. With it, you type your password once; the access lasts for the
   scan and the fixes that follow, and ends after 5 idle minutes, when you click **Drop**, or right after
   a scan that found nothing a root fix could act on.
2. Click **Scan**. It takes a few seconds to a minute.

The app opens on your last report next time, marked as saved until you scan again. The saved report
leaves out names and addresses that are only worth showing while the app runs (what starts at login, the
addresses the online tests saw): scan again to see them. Each new scan says
what is **new**, **resolved** or **changed** since the last one.

---

## 4. Read the results

### Kinds of result

Use the buttons above the list to switch between them.

| View | What it shows |
|---|---|
| **Findings** | Real problems to act on. Only these are counted. |
| **Hygiene** | Leftovers of normal use: caches, histories, the trash. Worth cleaning, not counted as problems. |
| **Info** | Things worth knowing, neither pass nor fail: which VPN you use, what starts when you log in, which apps sync your data. |
| **Accepted** | Findings you have accepted as known risks (see below). |
| **All** | Everything. |

The second set of buttons chooses the source: **Scan**, **Online** (the online tests) or **All**.

### Each row

- **Status**: passed, failed, a warning, couldn't be checked, or not applicable. Coloured only when
  there is a problem.
- **Severity**, from 1 to 10: **9+** critical, **7+** high, **4+** medium, **1+** low. The same problem can
  be more serious on one computer than another; a missing screen lock matters more on a laptop than on a
  desktop at home. The context decides, and the details say why. Data left on the disk (saved secrets,
  histories, caches) is one lower when the disk is encrypted: safe while the computer is off, though not from
  malware or someone using it while it is on.

Click a row for its details:

- **Why it matters**: what leaks, and to whom.
- **What was found**: the evidence (settings, counts, paths). It never shows passwords, file contents
  or account names.
- **What to do**: plain instructions, naming the button that does it.

### "Couldn't be checked"

These are listed first, never hidden. Most need administrator access: use **Scan with administrator
access** at the top of the list. A check that couldn't look is never counted as a pass.

### Accepting a risk

If a finding is a risk you have decided to live with, open it and click **Accept the risk…**. You can add
a reason (kept with the report; in a redacted export it is redacted like the rest). It is then hidden, not
counted and not notified about, left out of what changed since the last scan, and no longer "to do" in
Before you travel, unless its severity rises; then it comes
back with a note saying why. **Un-accept** brings it back at any time (in the row, its details, or the
*Accepted* view).

---

## 5. Fix what it finds

Each problem's details offer one of these buttons:

| Button | What happens |
|---|---|
| **Fix…** | An automatic fix. You see exactly what it will change (the dry run), then confirm once. It can be reverted from History. |
| **Guide…** | A step-by-step guide. Each step explains itself and its side effects. Steps the app can do have their own options, each shown and confirmed on its own. Steps that need you (a passphrase, a disk setting) give you the exact commands to run. |
| **How to…** | Instructions for this computer that you carry out yourself. The app doesn't make these changes (for example, encrypting a disk). |
| **Clean…** | Deletes caches or history. You see each place first, and confirm separately, because deleting can't be undone. |
| **Set up…** | Sets up an optional feature (section 10). |

Some rows say **no fix here** and explain why, and what you can do instead. Every problem the scan or
the online tests can find has one of these buttons, except two whose advice is the whole answer (a VPN
provider that is hard to trust; phone-home traffic, whose list names the check that stops each
connection).

**If a program has to be closed first,** the fix says so ("Close Firefox first"). The app never closes
your programs for you.

**After a fix is applied**, a dialog shows exactly what it did: each step, the commands it ran, the lines
it wrote, and the command that undoes it by hand. The same is kept in History (section 6). A fix that
fails part-way is rolled back; if it had already changed something, the dialog shows what was put back,
and the attempt stays in History, marked failed.

### Easy fixes…

After a scan, **Easy fixes…** in the summary gathers the fixes that cost you nothing or next to nothing:
no questions, nothing you would notice day to day, and all revertible. Each one says what it does and
what it costs. Untick any you don't want, look over the dry run, and apply. Anything that deletes files
is confirmed on its own, by name. Each fix is applied separately and appears separately in History, and
when they are done, a dialog lists every one with what it did.

If your disk isn't encrypted, the Easy fixes dialog starts with what to do meanwhile: ways to keep the
most sensitive things off the unencrypted disk until you can encrypt it.

### Fixes being undone

If something (an update, another program, you) later changes a fixed setting back, the next scan shows a
red banner at the top saying which fix was undone. **Fix again…** reapplies it.

---

## 6. History: undo a fix

**History** lists every fix you have applied, newest first, with what each step changed and where the
change came from: the Fix… button, an Easy fix, or a guide's step and option. Under each step,
**Exactly what it did** shows the commands it ran (as root, for a system change), the lines it wrote into a
file, the files and folders it made, the command that undoes it by hand, and, once reverted, what putting
it back ran. You can copy any of them.

An attempt that failed after changing something is listed too, marked **failed**, with what went wrong and
what was put back. If a step couldn't be put back, its Revert button is there.

- **Revert** puts back what was there before, and removes any file or folder the fix created. If the
  setting has been changed again since, the app won't overwrite that without asking (**Revert anyway**).
  A folder the fix created that now holds something else (yours, or another program's) is kept, and
  the message says what is in it. Root changes are reverted as administrator.
- Deletions (caches, history) can't be reverted. They are listed as such.
- **Forget reverted and old entries** or **Forget everything** clears History and its backups.
- History also offers to remove the administrator helper.

---

## 7. Save or share the report

**Export…** saves the report as text or JSON, or copies it.

- **Redact** removes your name, the computer's name, account and network names, addresses, and paths in
  your home folder, so you can share the report for help.
- **Export everything…** also includes accepted findings and every change in History, with everything
  History shows: what each step ran and wrote, how to undo it by hand, what reverting ran, where the change
  came from, and failed attempts. Keep it with your backups. It never includes the backed-up files themselves.

---

## 8. Online tests

Some problems only show from the network: DNS leaking around your VPN, your router forwarding ports to
this computer, encrypted connections being intercepted, and similar. **Online tests…** lists each test and
every server it contacts, before anything runs. Nothing about your computer is sent beyond what each test
needs, and the results never leave your computer. The tests connect directly, never through a proxy set in
your environment (`ALL_PROXY`, `https_proxy`): if one is set, the dialog says so, since the servers then see
this computer's own address rather than the proxy's.

What a test finds has a **Guide…** or **How to…** like any other problem, written for this computer from
the test's own result: the VPN connection to change, by name; the connection IPv6 leaks through; the
issuer that intercepts HTTPS and the command that removes its certificate; the program behind each port
the router forwards; your router's page. Opening a guide never runs the test again. After applying a
Guide… step (switching to a DNS provider that supports DNS over TLS, closing a service the internet
reaches over IPv6), the row shows **couldn't be checked** until you run the test again, which the guide's
last step says to do.

To see your computer from outside, run this on another computer:

```sh
./DAPrivacyKit-*.AppImage --probe ADDRESS
```

---

## 9. Tools

Open them with **Tools…**. Tools work only on what you choose, only when you start them. They send nothing
anywhere (apart from the browser download, which names its servers first) and keep no record afterwards.

### Verify a download

Checks that a file you downloaded (an ISO, a package, an app) is exactly what its makers published.

1. Put the file's signature (`.asc`, `.sig`, `.minisig`) or checksum list (`SHA256SUMS`…) in the same
   folder. If they are missing, the tool says what to download.
2. Click **Verify a file…** and choose the file. Or paste a checksum from the download page.

The answer is one of:

- **Verified**: signed by the project's own key. The app carries the keys of Linux Mint, Ubuntu, Debian,
  Fedora, Arch Linux, CachyOS, Kali, Tails, Qubes OS, Whonix, openSUSE, Manjaro, EndeavourOS, Tor Browser
  and Mullvad Browser, Mullvad VPN, Proton VPN, IVPN, VeraCrypt, KeePassXC, Cryptomator and Mozilla, and the
  one this app's own releases are signed with (Digital Archon's).
- **Signed, by a key the app doesn't list**: the signature is good, but the app can't tell whose key it
  is. Compare the fingerprint shown with the one on the project's website. Keys from your own GnuPG
  keyring or a key file you choose, SSH signatures and minisign signatures end up here.
- **Not damaged, but not verified**: a checksum matches. That proves the download isn't damaged, but not
  that nobody swapped both the file and its checksum.
- **Nothing to check it against**: no signature or checksum was found. The tool says what to download.
- **Don't use this file**: a signature or checksum doesn't match, or the key was revoked.

From a terminal: `daprivacyscanner --verify FILE` (exit status 0 when verified, 1 otherwise).

### Remove metadata

Photos and documents carry hidden details: where a photo was taken, who wrote a document, with which
device and software. Click **Choose files…**, then add what to look at: **Add files…** (one or several),
**Add a folder…** (with everything in its subfolders), or type a path and press Enter. **Show what they
carry** lists every file with what it gives away. With many files, the buttons above the list narrow it
(**Where it was made**, **Who made it**, **The device**, **Nothing found**, **Can't be cleaned**), the box
finds a file by name, and clicking a file opens what it carries (**Show everything** for the rest).

Tick the files to clean (all of them are ticked at first, except those mat2 can't clean), then click
**Make clean copies**. The originals are never changed:

- a file you chose on its own gets its clean copy beside it (`photo.cleaned.jpg`);
- the files of a folder go into a new folder beside it, `Holiday (cleaned)`, with the same subfolders. A
  file that can't be cleaned gets no copy there and is listed, so nothing in that folder passes for clean.

The result says what is still in the copies, and **Open the folder** shows them. Hidden files and folders
(names starting with a dot) are left out unless you tick **Include hidden files**; links aren't followed,
and folders on another disk aren't entered. A folder of up to 5,000 files is read in one go; **Stop** ends
reading or cleaning (what was cleaned by then stays). For a PDF, cleaning turns every page into a picture
(you can't select the text any more); tick **Lightweight (keep PDF text)** to keep the text, which removes
a little less. Needs `mat2` (the tool gives the install command). Right-click entries (below) open it on
the files or folders you right-clicked.

### RAM disk

A folder in memory, `~/RAMDisk`, for work that shouldn't touch the disk.

1. Click **Open…**, choose a size (up to half your memory) and whether programs may run from it, then
   **Open**. Needs your password.
2. Use `~/RAMDisk` like any folder.
3. When you are done, click **Close and overwrite…**. The app overwrites every file in it, then removes it.
   Restarting the computer also ends it.

If a program still has a file open there, closing is refused and names the program ("Close X first").
Copies that other programs made (thumbnails, recent-file lists) are outside it; the tool says so.

### Tor or Mullvad Browser in memory

Runs **Tor Browser** (hides your address through the Tor network) or **Mullvad Browser** (Tor Browser's
anti-tracking, without Tor; use it with a VPN) entirely from memory, in a sandbox. Nothing of the browser
is left on your disk afterwards.

1. Click **Set up…**.
2. **Open the RAM disk** (`~/TempBrowser`, 1536 MB by default, at least 1024 MB). Needs your password.
3. Click **Download…** on the browser you want. The app names the servers it will contact
   (torproject.org or mullvad.net), downloads the browser into memory, and checks its signature. Nothing
   is unpacked unless the signature is right. You can instead pick an archive you downloaded yourself
   (with its `.asc` file beside it) and click **Check and unpack**.
4. Choose the options:
   - **Run it in a sandbox** (keep it ticked): the browser can't see your files, keys or other
     programs. Untick only if you need a screen reader or an input method for Chinese, Japanese or Korean.
   - **Allow sound**: leave it off unless you need it. The sound server is outside the sandbox and gives
     away more than sound; the panel lists what.
   - **Give it a display of its own (Xephyr)**, on X11 only: stops the browser and other windows from
     seeing or typing into each other. It costs copy and paste between them.
   - For Tor Browser, **how it connects**: directly, or through a built-in bridge (obfs4, Snowflake, meek)
     or **Bridges I have…**. Use bridges where Tor is blocked. (Tor Browser's own Connect page is
     switched off in the sandbox; choose here instead.)
5. Click **Start Tor Browser** or **Start Mullvad Browser**.

Tor Browser starts at the **Safest** security level (JavaScript off on most sites). If a site needs more,
lower it with the shield button in the browser's toolbar. Mullvad Browser starts at **Standard**.

**Files in and out.** The browser sees only its own folders:

- **The Outbox** (`~/TempBrowser/Outbox for Tor Browser`, or for Mullvad Browser): copy files into it with
  your file manager, and the app removes their metadata and puts the clean copies in *To upload*. The
  originals go to *Originals* inside it, and a file that can't be cleaned to *Not cleaned* (it isn't passed
  on). A file is passed on once it has finished arriving; one named as a copy still under way (`.part`,
  `.crdownload`) is left alone until it has its real name. It is made with the browser, and the panel lists what
  it did; **Turn it off** removes it once it is empty. Copy rather than move: everything in `~/TempBrowser` goes when it is closed. The app empties it
  while it is open. If you have the permanent Outbox (`~/Outbox`) set up, the panel says to use that one
  instead, and to copy the clean files from `~/Outbox/Cleaned` into *To upload*.
- **Add a file to upload…** copies one of your files into the browser's *To upload* folder, cleaned of
  metadata first by default. The file's name goes with it. A file you drag into *To upload* yourself goes
  as it is. A link inside `~/TempBrowser` is never followed (the browser could have made one that points at a
  file of yours): choose the file itself.
- Finished downloads are listed in the panel. The app says what each really is, whatever its name (a
  program disguised as a PDF is named as a program). **Save…** copies one out to a folder you choose.
  **View offline…** opens a document or picture in your usual viewer with no network, so the document
  can't contact anyone. A viewer from Flatpak must be closed first (if it is open, it would be given the file
  with its network), and a web browser from Flatpak isn't used: choose a document viewer as the default for that
  kind of file instead.

**Before you start, the panel may warn about:**

- **Swap on disk**: memory can be written to disk. **Turn swap off for this session** stops that until
  you turn it back on or restart. It says first if you don't have enough memory.
- **Thumbnails, crash dumps or file search** that would keep copies on the disk, each with a button to
  fix it.
- **No passt installed** (Mullvad Browser): without it, the browser can see your local network. Install
  `passt` with the command shown. With it, the local network is fenced off, all but your router's public
  address, which your computer doesn't know: many routers show their settings page there too, so give that
  page a password of its own.
- **X11 desktop**: the sandbox protects your files but not your screen. Wayland is safer.

**What the sandbox can't hide** from a website that got past the browser's own protections is listed in the
panel: among it, when the computer was started, which stays the same until you restart. Restart between
sessions you want kept apart.

**It is for one session, or a few over a day.** It doesn't update itself. If you start it more than 24
hours after setting it up, it first checks for a newer version and won't start if one is out: save what
you need, close `~/TempBrowser`, and set it up again.

**Finishing:** quit the browser, then **Close and overwrite…** (or just quit the app, which closes
`~/TempBrowser` too). Closing is refused while the browser runs. Only the window that opened `~/TempBrowser`
closes it when you quit: a window the right-click entries opened (Verify download…, Remove metadata…) leaves it
as it is.

### Try an app

Run a program you don't know yet where it can do no harm: in a sandbox, with a made-up home folder in place
of yours. **Try something…**, then choose:

- **A file you downloaded**: an AppImage, a program, a script, an archive (tar, zip) or a `.deb` package. A
  copy is tried; the file itself isn't changed or run. A `.deb` is unpacked, never installed.
- **An app that is installed**: started with a throwaway home, as on a first run. Your real profile isn't
  touched.

Before it starts you choose its **network** (none, or its own with your local network fenced off and the
hosts it contacts listed; the second needs the `passt` package) and what it gets (the graphics card, sound,
on X11 a display of its own). Then **Start the trial**, use the program, and close it or **End the trial**.

You see:

- **Decoy files**: the trial puts made-up SSH keys, browser profiles, wallets and documents in its home. A
  program that opens them has gone looking for things it has no business with.
- **Network**: the hosts it contacted, with how much it sent to each. What it sent is encrypted and can't be
  read.
- **What it wrote in its home**: on your computer these files would be in your home folder.

**Discard the trial** removes everything of it. A sandbox isn't a guarantee: it keeps a program from your
files, but not a program built to break out of sandboxes. Don't run what you know to be hostile. And a trial
shows what a program does while you watch, not what it would do next week.

### What does this app keep?

The scan knows where many apps keep their data, but not every app. This tool shows what any one app does on
your computer. Close the app, choose it under **Choose an app…**, and **Start the app and watch it**. Use
it as you normally do, then **End the watch and show what it did**.

It needs administrator access from the start until you end it, because only root can watch which files a
program opens. The window says so first. End the watch as soon as is practical; the access is given up the
moment it ends.

You get:

- **Who recorded what you opened**: files written during the watch that hold the names of the files you
  opened (an attachment or download opened from a temporary folder counts too), such as a thumbnail, a
  recent-files list, the desktop's notes on files or the app's own history, and which program wrote each.
- **Files it writes to all the time**, by name, with what kind of file each is. Your own documents saved
  again and again are counted here, not named.
- **Sensitive places it opened**, such as your SSH keys or a browser's profile. An app opening its own
  profile is normal; anything else deserves a second look.
- **Where it read and wrote**: its folders with counts of files read, changed, made and deleted.
- **What your other programs wrote meanwhile**, counted per program and folder: an app that hands its work to
  a background program of its own shows here. If the app was already open somewhere, the window says so
  before you start; if it hands over to a copy it couldn't see, the result says it opened nothing.

Your own files are counted, never listed, and nothing is saved: the result is gone when you dismiss it or
quit. The tool can't see what other accounts or system services record, nor inside compressed or encrypted
files.

### TRIM test

Checks that your SSD really drops data once it is deleted. The app writes about 250 MB of test files,
deletes them, trims the disk and reads the whole disk back to see whether any test data survives. It
takes a while (the screen says how long) and needs your password. Click **Test…**, choose the disk, and
click **Start the test**.

- **Pass**: once trimmed, deleted data can't be read back by plugging the drive in somewhere else.
- **Fail** or **inconclusive**: the result explains, and offers **Turn on TRIM…** where TRIM isn't
  reaching the drive.

Only encryption protects deleted data against every method. The test also says whether the drive claims
to encrypt by itself (treat that as a bonus, never a replacement).

### Deleted file names

Even after a file is deleted, its name can stay readable on the disk. Click **Look…**, choose the
filesystem, and see which names remain. The list is shown once and never saved.

- **ext4**: current kernels (Linux 5.13 and later) overwrite a name in its folder as the file is deleted,
  but the filesystem's journal keeps copies of the folder's records as they were before, names and all,
  until it has wrapped round: minutes to hours on a busy computer, days on an idle one. The list reads the
  journal and the folders. A folder you deleted is listed where it was, marked *deleted folder*.
  - **Clear the journal…** removes the names in the journal at once. The kernel writes everything the
    journal holds to its place and overwrites the journal with zeros; nothing is lost, and it takes about
    a second on an SSD. It clears the journal of the whole filesystem, so every folder's names and every
    account's. Needs Linux 5.14 or later; on an older kernel the names go by themselves as the journal
    wraps. Files you delete afterwards leave their names in the journal again.
  - The journal also holds records of folders the app can't tie to one of yours: other accounts', the
    system's, folders whose traces are too faint. It counts them and doesn't show their names.
    **Show those names…** does, after telling you whose they can be; many are of files that still exist.
    Clearing the journal removes them with the rest.
  - Names an older kernel left in a folder's own records: tick the folders and click **Clean the chosen
    folders…**. The app overwrites the old names in place (or rebuilds a large folder, **Rebuild
    instead…**). It won't touch folders a sync service uses, or ones a program is using.
- **btrfs**: **Trim now and check again**.

Clearing takes the names off the filesystem. A drive's flash chips can keep an old copy until the drive
reuses the space: only disk encryption protects against someone who reads the chips.

### Before you hand over a drive

Before you give someone a USB stick, SD card or external disk: **Choose a drive…** lists what it carries
besides your files (trash, thumbnails, files other systems leave, lock files with your name). You see
every file before anything is deleted. Deleting doesn't erase; to erase, see *Retire a drive*.

### Retire a drive

Selling or throwing out a drive: what really erases it depends on the kind of drive. **Choose a drive…**,
type its name to confirm, and the tool gives the right commands for that exact drive, which you run
yourself. It is honest about what works:

- **Encrypted SSD**: destroying the encryption key (crypto-erase) is the strong option.
- **Hard disk**: one pass of zeros, checked, or the drive's own Secure Erase.
- **USB stick or SD card**: there is no reliable erase. Destroy it if it held secrets unencrypted.

The drive the system runs from is refused.

### Before you travel

A checklist of the scan's checks that matter on a trip (at a border, in a hotel, on airport Wi-Fi), each
with its last result and its fix, guide or instructions.

### Presentation mode

Before you share your screen, **Turn on…** hides notification banners and pauses clipboard history
(on KDE Plasma 6, Klipper is turned off in the system tray and back on afterwards; where the app can't
reach it, it says so). **Presentation mode · Turn off** in the top bar puts everything back as it was. Quitting the app also
turns it off. While it is on, **What it changed…** lists each setting it changed, the commands that did
it, and how each goes back by hand. It isn't a fix: nothing of it is in History.

### Camera and microphone

**Show…** lists, live, which programs are using the camera, a microphone, or recording the screen. It only
looks; nothing is stopped.

---

## 10. Set-ups that last

These are in the Tools panel too. Each is set up through a short guide, and removed from History like a
fix.

- **~/Ephemeral**: a folder kept in memory permanently. Whatever you put there is gone at every restart,
  or at every logout if you choose that. For files that should last but stay private, the guide suggests
  an encrypted Cryptomator vault.
- **~/Outbox**: drop a file in, and a cleaned copy (metadata removed) appears in `~/Outbox/Cleaned`; the
  original moves to `~/Outbox/Originals`. A file that can't be cleaned goes to `~/Outbox/Not cleaned`.
  Nothing is deleted.
- **Right-click entries**: adds *Verify download…* and *Remove metadata…* to the file manager (Nemo,
  Dolphin, Nautilus).
- **A Box for an app**: keeps an app you need but don't fully trust in a sandbox for good, with a home
  folder of its own in `~/Boxes`. It starts from the menu as *NAME (in its Box)* and can't read your files.
  To give it a file, put the file in the Box's `Exchange` folder; the app finds it in `~/Exchange` (a Flatpak
  app at the folder's own path, `~/Boxes/NAME/Exchange`). You can
  make a Box from an installed app, a Flatpak app, or a program you have just tried (**Keep it in a Box…** in
  *Try an app*). **Open…** in the Tools panel lists your Boxes with each one's last runs in numbers: how
  long, how many files written, how many hosts contacted and how many of those were new. No names of sites
  or files are kept. Reverting a Box in History removes its menu entry and settings; its data in `~/Boxes`
  stays until you delete it.

---

## 11. From a terminal

The window is how the app is meant to be used. These options are there for testing, and for what the
app itself sets up: scheduled scans, the file manager's right-click entries and the Outbox call
them. A terminal scan shows the same results as the window, but fixes are applied and reverted only
in the window, where each one is shown before it is made.

| Command | What it does |
|---|---|
| `daprivacyscanner` | Opens the window. `--browser` opens it in your web browser instead. |
| `daprivacyscanner --scan` | Scans and prints the report. Add `--json`, `--redact`, `--admin`. Exit status 1 when there are findings. |
| `daprivacyscanner --schedule daily` | Scans every day (or `weekly`; `off` stops it) and notifies you only of new or worse findings, fixes that were undone, and new programs that start at login. It says how many, never which: a notification can show on the lock screen and stay in its history, so open the app to see which. |
| `daprivacyscanner --dry-run [CHECK]` | Prints what a fix or guide would do, without doing it. `--dry-run easy` shows the Easy fixes. For an online test, the guide is built from its result in the saved last report, once it has run. |
| `daprivacyscanner --online` | Runs the online tests (after listing who they contact). |
| `daprivacyscanner --verify FILE` | Verify a download. `--key KEYFILE`, `--checksum HEX` add a key or a checksum. Exit status 0 when verified. |
| `daprivacyscanner --tool verify\|metadata FILE…` | Opens the window on that tool. |
| `daprivacyscanner --export FILE` | Writes everything the app keeps, for your backups. |
| `daprivacyscanner --probe ADDRESS` | From another computer: which ports of ADDRESS answer. |
| `daprivacyscanner --install-helper` / `--uninstall-helper` | Installs or removes the administrator helper. |

With the AppImage, use `./DAPrivacyKit-*.AppImage` in place of `daprivacyscanner`.

---

## 12. What the app keeps, and removing it

Inside, the app goes by `daprivacyscanner`: its command, the folders below, its helper, and the units, menu
entries and settings files it writes for you carry that name.

| Where | What |
|---|---|
| `~/.local/state/daprivacyscanner/` | The last report, the summary of the last scan (statuses only), accepted findings, and History with its backups. |
| `~/.config/daprivacyscanner/` | Window preferences (`ui.json`) and online test settings (`online.json`). |
| `/var/lib/daprivacyscanner/changes` | The helper's record of root changes, so they can be reverted. |

History can forget its entries and the last report.

**To remove the app completely**, first revert in History any fix you want undone: the fixes you applied
don't need the app and stay in place, but once History is gone they can only be undone by hand (**Export
everything** in History writes down how, for each). Then run the uninstall script from the project's
repository, [packaging/uninstall.sh](../packaging/uninstall.sh):

```sh
bash uninstall.sh --dry-run     # shows what it would remove
bash uninstall.sh               # asks before each part
```

It turns off scheduled scans, removes the Outbox's watcher and the file manager's right-click entries (they
run the app, and would be left pointing at nothing), the two folders above, and, with your password, the
helper and its record of root changes. It leaves your own files (~/Outbox and what is in it, ~/Ephemeral)
and every setting a fix changed, and lists the files in `/etc` that fixes wrote. `--keep-data` keeps History
and your settings for a later reinstall. It works without the app, so also after the AppImage is deleted.
Last, delete the AppImage itself.

By hand, the same is: remove the helper (History, or `--uninstall-helper`), turn off scheduled scans
(`--schedule off`), revert the Outbox and the right-click entries in History, delete the two folders above
and `/var/lib/daprivacyscanner`, and delete the AppImage.

---

## 13. Troubleshooting

**The password prompt says "python3".** The helper isn't installed root-owned. Run `--install-helper`.

**The app says it needs WebKitGTK 4.1 and doesn't start.** Install it; see section 1.

**Many checks say "couldn't be checked".** Scan with administrator access.

**A fix says "Close X first".** Close that program and try again. The app never closes programs for
you.

**The browser tool says the sandbox can't be used (Ubuntu 24.04 and later).** Ubuntu's AppArmor stops
bubblewrap. The panel gives two ways round it, with what each costs.

**The browser won't start: "a newer version is out".** Save what you need from its Downloads, click
**Close and overwrite…**, and set it up again.

**Something is wrong on GNOME, Xfce or KDE Plasma 5.** Those desktops aren't supported; see section 1.

**Closing a RAM disk is refused.** A program still uses a file in it. The message names the program;
close it first.

---

## 14. Report a problem

The app is a public beta, and it never reports anything by itself: a problem reaches the project only
if you send it.

- **A check that is wrong about your computer, a fix that doesn't do what it says, or anything else
  that isn't a security hole:** open an issue at
  <https://github.com/DigitalArchon/DAPrivacyKit/issues>. Say which distribution and desktop, and
  the app's version (at the top of a report). A report helps: **Export…** with **Redact** ticked leaves
  out names, the host name, addresses and paths under your home folder. Read it before you attach it,
  since an issue is public, and never attach an unredacted one.
- **A security hole** (the helper doing more than it should, a way out of the browser's sandbox, a
  secret in a report): email it privately, as [SECURITY.md](../SECURITY.md) describes, and don't open
  an issue for it.

