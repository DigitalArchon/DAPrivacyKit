"""Fixture hosts: a fake system root (/etc, /proc, /sys), a fixture home directory and
captured command output. Tests never read the developer's real system."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from daprivacyscanner import catalogue
from daprivacyscanner.host import FakeRunner, Host

SAMPLES = Path(__file__).parent / "samples"


def sample(rel: str) -> str:
    return (SAMPLES / rel).read_text()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def make_host(tmp_path: Path, *, files: dict[str, str] | None = None, home_files: dict[str, str] | None = None,
              links: dict[str, str] | None = None, commands: dict | None = None, installed=(),
              env: dict[str, str] | None = None) -> Host:
    """`files`: absolute paths on the fake system ("/etc/gdm3/custom.conf"). `home_files`:
    paths relative to the fixture home. `links`: symlinks on the fake system, path -> target.
    `commands`: argv (string or tuple) -> stdout or CommandResult."""
    root, home = tmp_path / "root", tmp_path / "home" / "alice"
    root.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)
    for p, text in (files or {}).items():
        _write(root / p.lstrip("/"), text)
    for p, text in (home_files or {}).items():
        _write(home / p, text)
    for p, target in (links or {}).items():
        link = root / p.lstrip("/")
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, link)
    environ = {"HOME": str(home), **(env or {})}
    return Host(home=home, environ=environ, runner=FakeRunner(commands or {}, installed), root=root, uid=1000)


@pytest.fixture(scope="session")
def cat() -> catalogue.Catalogue:
    return catalogue.load(Path(__file__).resolve().parents[1] / catalogue.CATALOGUE_NAME)


skip_if_root = pytest.mark.skipif(os.geteuid() == 0, reason="root can read files whatever their mode")


def make_scan(host: Host, *, desktop=("gnome",), gnome_major=46, plasma_major=None, devices=None, listeners=None,
              **context):
    """A Scan for one check, with context values given directly (unset keys are unknown) and
    devices / listeners from samples."""
    from daprivacyscanner.checks import Scan
    from daprivacyscanner.context import Context, ContextValue
    from daprivacyscanner.desktop import GNOME, KDE, DesktopInfo
    from daprivacyscanner.paths import PathResolver

    values = {k: context.get(k) if isinstance(context.get(k), ContextValue) else ContextValue(k, context.get(k))
              for k in catalogue.CONTEXT_KEYS}
    ctx = Context(values, DesktopInfo(tuple(desktop), plasma_major, gnome_major), devices, listeners)
    paths = PathResolver(host.home, host.environ)
    return Scan(host, paths, ctx, KDE(host, paths, ctx.desktop), GNOME(host, ctx.desktop), host.privileged)


def detect(cat, check_id: str, scan):
    """Run one check's detection (not the runner: no severity, no not-applicable short cut)."""
    from daprivacyscanner.checks import load_all

    return load_all()[check_id](cat[check_id]).detect(scan)


def lsblk(name: str):
    from daprivacyscanner import blockdev

    return blockdev.parse_lsblk(sample(f"lsblk/{name}"))


def ev(outcome) -> dict:
    """Evidence as {label: value} (the last one wins for repeated labels)."""
    return {e.label: e.value for e in outcome.evidence}
