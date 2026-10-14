"""Before you travel (docs/TECHNICAL.md, Tools): a checklist built from checks the scan already makes, each
with why it matters when the laptop crosses a border, sits in a hotel room or joins an airport's
Wi-Fi, plus the RAM disk (it should be closed). No detection of its own: the page shows each
check's result from the last scan, with the same Fix…, Guide… and How to… buttons as the list.

ITEMS is checked against the catalogue by the tests: a check renamed or removed fails them."""

from __future__ import annotations

from ..host import Host

INTRO = ("A laptop that travels can be lost, stolen, searched at a border, or left in a hotel room, and it joins "
         "networks you don't control. What protects it then is mostly settled before you leave: the disk encrypted, "
         "the keys out of memory when it is off, nothing that unlocks it without you, and as little as possible "
         "that says where it has been.")

# (check id, why it matters when travelling), in the order to deal with them
ITEMS: list[tuple[str, str]] = [
    ("enc.fde_missing", "Without disk encryption, whoever holds the laptop for a few minutes (a border check, a hotel "
                        "room) can copy everything on it from a USB stick, without your password."),
    ("enc.unmounted_unencrypted", "A Windows partition beside this system, or a second disk, is copied just as "
                                  "easily when it isn't encrypted, whatever protects this one."),
    ("kern.suspend_keys_in_ram", "Asleep, the laptop keeps the disk's key in memory: power it off rather than "
                                 "putting it to sleep before a border, a flight, or leaving it in a room. Off, the disk "
                                 "is locked."),
    ("enc.hibernate_unencrypted", "Hibernating writes all of memory, keys included, to the disk: if that isn't "
                                  "encrypted, powering off this way leaves the keys behind."),
    ("enc.tpm_no_pin", "If the disk unlocks itself at boot, someone who switches it on gets as far as the login "
                       "screen with the disk already open: a PIN makes powering off mean locked."),
    ("auth.autologin", "With automatic login, switching the laptop on opens your session: anything on it is a "
                       "click away."),
    ("auth.screen_lock", "A laptop left open for a moment (a security tray, a café) should lock itself quickly."),
    ("auth.lockscreen_notifications", "Messages shown on the lock screen are read by whoever holds the laptop, "
                                      "without unlocking it."),
    ("net.bluetooth", "Bluetooth left on and discoverable announces the laptop, and often your name, to everyone "
                      "nearby on the train or in the airport."),
    ("net.mac_permanent", "Hotel and airport networks recognise the laptop by its permanent Wi-Fi address from one "
                          "visit, or one country, to the next."),
    ("net.open_autoconnect", "A saved open network (a café's, an airport's) is joined by name alone: anyone can make "
                             "a hotspot with that name and the laptop joins it."),
    ("br.https_only", "On a hotel's or an airport's network, whoever runs it can make a page load without "
                      "encryption, then read and change it: the browser should ask first."),
    ("net.wifi_history", "Saved Wi-Fi networks are a list of places you have been, with when you were last there."),
    ("br.account_sync", "A browser signed in to a sync account brings your history and passwords onto any device "
                        "signed in to it, and back. Signing out for the trip limits what the laptop carries only if "
                        "you also tick deleting the data on this device when the browser offers it: otherwise what "
                        "was synced stays."),
    ("enc.removable_unencrypted", "USB sticks and external drives travel too, and are easier to lose than the "
                                  "laptop."),
]

ADVICE = [
    "Power the laptop off, rather than putting it to sleep, before a border, a flight or leaving it unattended: off, "
    "an encrypted disk is locked.",
    "Take only what you need: files you won't use on the trip are safer at home, on an encrypted drive.",
    "Back it up before you go, so a laptop kept or broken is a cost, not a loss.",
    "Close the RAM disk and sign out of accounts you won't use while away.",
    "A fingerprint can be taken from you more easily than a password: if fingerprint login is set up, consider "
    "using the password for the trip.",
]


def status(host: Host) -> dict:
    """The checklist, and the RAM disks' state (the items that aren't checks): the RAM disk tool's,
    and the browser's (~/TempBrowser)."""
    from . import ramdisk
    disks = [ramdisk.status(host, n) for n in ramdisk.NAMES]
    view = [{"name": d.path.name, "path": "~/" + d.path.name, "open": d.open, "files": d.files} for d in disks]
    return {"intro": INTRO, "items": [{"id": i, "why": w} for i, w in ITEMS], "advice": ADVICE,
            "ramdisk": view[0], "ramdisks": view}
