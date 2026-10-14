"""Tools (docs/TECHNICAL.md, Tools): what the user starts on files or folders they choose, listed in the
Tools panel apart from the checks. Each runs only when started, sends nothing anywhere (except the
browser download, which names the hosts it contacts first) and keeps nothing afterwards; the
catalogue's `feature` entries (set-ups that last) are listed beside them.

    verify      Verify a download: is this file the one its makers published? (verify.py, keys.py)
    metadata    Remove metadata: what a file carries, and a clean copy beside it (metadata.py)
    ramdisk     The RAM disk: a folder in memory opened on demand, overwritten when closed (ramdisk.py)
    browser     Tor Browser or Mullvad Browser in the RAM disk: downloaded, verified and run from memory (browser.py)
    trim        The TRIM test: once deleted data is trimmed, can it still be read back from the drive? (trimtest.py)
    names       Deleted file names: which names of deleted files the disk still holds, and clearing them
                (names.py lists them and clears ext4's journal, rebuild.py clears them from ext4 folders)
    handover    Before you hand over a drive: a USB drive's trash, thumbnails and other leftovers, listed and deleted (handover.py)
    retire      Retire a drive: how to erase a whole drive before it goes, for its kind; commands the user runs (retire.py)
    travel      Before you travel: a checklist from the scan's own checks, with why each matters on a trip (travel.py)
    presentation  Presentation mode: notification banners and clipboard history off while sharing the screen (presentation.py)
    inuse       Camera and microphone: which programs are using the camera, a microphone or the screen now (inuse.py)
    trial       Try an app: a program you don't know yet, run in a sandbox with a throwaway home and decoy files;
                what it wrote, which decoys it looked at, which hosts it contacted (trial.py; homewatch.py watches
                the home, bait.py makes the decoys, pcap.py sums up the network, sandbox.py's pieces build the sandbox)
    keeps       What does this app keep?: one app watched while you use it, then where it read and wrote
                (appwatch.py starts it and reads the helper's watch; activity.py sums it up; menu.py lists the apps)
"""

from __future__ import annotations

# The panel's groups, in order: (id, heading). The page gives each a colour and each tool an icon of its own.
GROUPS = [
    ("files", "Your files"),
    ("memory", "Private browsing and memory"),
    ("apps", "Apps"),
    ("drives", "Disks and drives"),
    ("everyday", "Everyday"),
]

# Each tool: its group, a one-line summary shown on its tile, and the full text behind "More about it".
TOOLS = [
    {"id": "verify", "group": "files", "short": "Is this download the one its makers published, unchanged and signed by them?",
     "title": "Verify a download",
     "text": "Check that a file you downloaded is the one its makers published: unchanged, and signed by them. "
             "Uses the signature or checksum list next to it, or a checksum you paste.",
     "button": "Verify a file…"},
    {"id": "metadata", "group": "files", "short": "See what a photo or document gives away, and make a clean copy to share.",
     "title": "Remove metadata",
     "text": "See what a photo or document gives away besides what you see in it (where it was taken, who made it, "
             "with what device), and make a clean copy to share. The original isn't changed.",
     "button": "Choose files…"},
    {"id": "ramdisk", "group": "memory", "short": "A folder in memory for work that shouldn't touch the disk.",
     "title": "RAM disk",
     "text": "A folder in memory (~/RAMDisk) for work that shouldn't touch the disk, opened when you want it. Closing "
             "it here overwrites what is in it and removes it. The browser in memory has one of its own (~/TempBrowser).",
     "button": "Open…"},
    {"id": "browser", "group": "memory", "short": "Tor Browser or Mullvad Browser, run from memory in a sandbox.",
     "title": "Tor or Mullvad Browser in memory",
     "text": "Download Tor Browser or Mullvad Browser into a RAM disk of its own (~/TempBrowser), check its "
             "signature, and run it from there, in a sandbox: neither keeps your history, and run from memory the "
             "browser itself leaves nothing on the disk. Closing ~/TempBrowser, or quitting the app, removes it.",
     "button": "Set up…"},
    {"id": "trial", "group": "apps", "short": "Run a program you don't trust yet in a sandbox, and see what it does.",
     "title": "Try an app",
     "text": "Run a downloaded program, an archive, a .deb or an installed app in a sandbox with a throwaway home: "
             "none of your files are within its reach. You see what it writes, which decoy files it looks at (made-up "
             "SSH keys, browser profiles, wallets) and, if you let it online, which hosts it contacts. Then it is "
             "all discarded.",
     "button": "Try something…"},
    {"id": "keeps", "group": "apps", "short": "Use an app as usual, then see where it read and wrote your data.",
     "title": "What does this app keep?",
     "text": "Pick an app, use it as you normally do, then see what it did with files: where it keeps its own data, "
             "which files it writes to all the time, which of your folders it opened files in, and which other "
             "programs recorded what you opened. Needs administrator access while it watches. Nothing is kept.",
     "button": "Choose an app…"},
    {"id": "trim", "group": "drives", "short": "Does your SSD really drop the data you delete?",
     "title": "TRIM test",
     "text": "Check that data you delete is really dropped by your SSD: the app writes test files, deletes them, trims "
             "the disk and reads the whole disk to see whether any of it can still be read back. Takes a while.",
     "button": "Test…"},
    {"id": "names", "group": "drives", "short": "Which names of deleted files the disk still holds, and clearing them.",
     "title": "Deleted file names",
     "text": "See which names of files you deleted can still be read from the disk, and clear them: on ext4 from "
             "the journal and the folders they were in, on btrfs by trimming. The list is shown once and never saved.",
     "button": "Look…"},
    {"id": "handover", "group": "drives", "short": "What a USB stick or external disk carries besides your files.",
     "title": "Before you hand over a drive",
     "text": "Before you give a USB stick, SD card or external disk to someone: what it carries besides your files "
             "(trash, thumbnails, other systems' leftovers), every file listed before anything is deleted.",
     "button": "Choose a drive…"},
    {"id": "retire", "group": "drives", "short": "How to really erase a drive before it goes, for its kind.",
     "title": "Retire a drive",
     "text": "Selling, giving away or throwing out a drive: what really erases it depends on the kind of drive, and "
             "the app says honestly what works. Commands you run yourself, for the exact drive.",
     "button": "Choose a drive…"},
    {"id": "travel", "group": "everyday", "short": "A checklist for a laptop that crosses borders and stays in hotels.",
     "title": "Before you travel",
     "text": "A checklist for a trip: what protects this laptop at a border, in a hotel room or on an airport's Wi-Fi, "
             "from the scan's own checks, with a fix or a guide where there is one.",
     "button": "Open the checklist…"},
    {"id": "presentation", "group": "everyday", "short": "Notifications and clipboard history off while you share your screen.",
     "title": "Presentation mode",
     "text": "Before you share your screen: notification banners and clipboard history off, so nothing private pops up. "
             "Turning it off puts them back as they were.",
     "button": "Turn on…"},
    {"id": "inuse", "group": "everyday", "short": "Which programs are using the camera, a microphone or the screen now.",
     "title": "Camera and microphone",
     "text": "See which programs are using the camera, a microphone or the screen right now, updated while you watch. "
             "Only looks: nothing is stopped or changed.",
     "button": "Show…"},
]
