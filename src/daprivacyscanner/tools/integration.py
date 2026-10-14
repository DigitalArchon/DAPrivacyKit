"""What the tools add to the desktop when set up (features in the catalogue): the Outbox's systemd
user units (app.metadata_outbox) and the file managers' right-click entries
(desk.file_manager_actions). The check and its guide both build the files here, so "is it set up?"
and "what Set up… writes" can't drift apart. Each file says it was written by the app; reverting
the set-up in History removes it."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..launch import desktop_exec, scan_command, shell_words, systemd_exec

MARK = "Written by DA Privacy Kit. Revert it in the app's History to remove it."
OUTBOX_UNIT = "daprivacyscanner-outbox"


def program(environ) -> list[str]:
    """How the units and menu entries start this program (tests replace it)."""
    return scan_command(environ)


# ------------------------------------------------------------------ the Outbox

def outbox_units(config_home: Path, command: list[str]) -> dict[Path, str]:
    """The path unit (watching ~/Outbox) and the service it starts, by their paths."""
    d = Path(config_home) / "systemd" / "user"
    service = (f"# {MARK}\n[Unit]\nDescription=Clean metadata from files put in ~/Outbox (DA Privacy Kit)\n\n"
               f"[Service]\nType=oneshot\nExecStart={systemd_exec(command + ['--outbox'])}\nNice=10\n")
    path = (f"# {MARK}\n[Unit]\nDescription=Watch ~/Outbox for files to clean of metadata (DA Privacy Kit)\n\n"
            "[Path]\n# files written into ~/Outbox start the service, which cleans them into ~/Outbox/Cleaned\n"
            "PathChanged=%h/Outbox\nUnit=" + OUTBOX_UNIT + ".service\n\n[Install]\nWantedBy=default.target\n")
    return {d / f"{OUTBOX_UNIT}.service": service, d / f"{OUTBOX_UNIT}.path": path}


# ------------------------------------------------------------------ right-click entries

@dataclass(frozen=True)
class Entry:
    manager: str            # "Nemo", "Dolphin", "Nautilus"
    program: str            # its executable, to tell whether it is installed
    path: Path
    content: str
    mode: int = 0o644


TOOLS = (("verify", "Verify download…", "Check that this file is the one its makers published (DA Privacy Kit)",
          "security-high"),
         ("metadata", "Remove metadata…", "See and remove hidden details: location, author, device (DA Privacy Kit)",
          "edit-clear"))


def file_manager_entries(data_home: Path, command: list[str]) -> list[Entry]:
    """Verify download… on one file; Remove metadata… on files and folders too (Dolphin's service menus
    take one set of types per file, so each tool has its own)."""
    data_home = Path(data_home)
    out = []
    for tool, name, comment, icon in TOOLS:
        out.append(Entry("Nemo", "nemo", data_home / "nemo" / "actions" / f"daprivacyscanner-{tool}.nemo_action",
                         f"[Nemo Action]\n# {MARK}\nActive=true\nName={name}\nComment={comment}\n"
                         f"Exec={shell_words(command + ['--tool', tool])} %F\nIcon-Name={icon}\n"
                         f"Selection={'s' if tool == 'verify' else 'notnone'}\n"
                         f"Extensions={'nodirs' if tool == 'verify' else 'any'};\n"))
    for tool, name, _, icon in TOOLS:
        out.append(Entry("Dolphin", "dolphin", data_home / "kio" / "servicemenus" /
                         ("daprivacyscanner.desktop" if tool == "verify" else f"daprivacyscanner-{tool}.desktop"),
                         f"[Desktop Entry]\n# {MARK}\nType=Service\n"
                         f"MimeType={'all/allfiles' if tool == 'verify' else 'all/all'};\n"
                         "X-KDE-ServiceTypes=KonqPopupMenu/Plugin\n"
                         f"Actions=daprivacyscanner-{tool};\nX-KDE-Submenu=DA Privacy Kit\n"
                         f"\n[Desktop Action daprivacyscanner-{tool}]\nName={name}\nIcon={icon}\n"
                         f"Exec={desktop_exec(command + ['--tool', tool])} %F\n", 0o755))   # Plasma 6 runs only executable ones
    for tool, name, _, _ in TOOLS:
        title = name.rstrip("…") + " (DA Privacy Kit)"
        out.append(Entry("Nautilus", "nautilus", data_home / "nautilus" / "scripts" / title,
                         f"#!/bin/sh\n# {MARK}\n# Nautilus lists the selected files one per line; no globbing.\nset -f\n"
                         "IFS='\n'\n"
                         f"exec {shell_words(command + ['--tool', tool])} $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\n", 0o755))
    return out


def command_exists(command: list[str]) -> bool:
    return bool(command) and os.path.isfile(command[0]) and os.access(command[0], os.X_OK)
