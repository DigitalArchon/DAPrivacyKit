"""Fixture hosts: a fake system root (/etc, /proc, /sys), a fixture home directory and
captured command output. Tests never read the developer's real system.

That is enforced here, for every test (`_isolated`, autouse), rather than left to convention: each test runs in a
working directory of its own, with HOME, the XDG folders and GNUPGHOME in a temporary folder and no session bus or
display to reach, and Python's sockets refuse anything but Unix sockets and loopback addresses (a test that tries is
failed, even when the code under test took the refusal for being offline). Programs a test starts are not covered:
they get the same environment, which keeps them out of the real home, but not off the network."""

from __future__ import annotations

import errno
import ipaddress
import os
import socket
from pathlib import Path

import pytest

from daprivacyscanner import catalogue
from daprivacyscanner.host import FakeRunner, Host

SAMPLES = Path(__file__).parent / "samples"

# what the developer's session would give a program: none of it reaches a test
_SESSION_VARS = ("DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "SSH_AUTH_SOCK",
                 "GPG_AGENT_INFO", "PULSE_SERVER", "XDG_SESSION_ID", "XDG_SEAT", "XDG_VTNR", "SESSION_MANAGER",
                 "http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "no_proxy",
                 "NO_PROXY", "DAPRIVACYSCANNER_SIGNING_KEYS")
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "testserver"}


def _is_local(host) -> bool:
    if host is None or host in ("", b""):
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host).strip("[]").split("%", 1)[0]
    if host.lower() in _LOCAL_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _NetworkGuard:
    """Python's socket calls, refused unless they stay on this computer: AF_UNIX, or an AF_INET/AF_INET6 address
    that is loopback. Every refusal is recorded, and the test fails at its end."""

    def __init__(self):
        self.tried: list[str] = []

    def _check(self, sock, address) -> None:
        if getattr(sock, "family", None) not in (socket.AF_INET, socket.AF_INET6):
            return
        host = address[0] if isinstance(address, tuple) and address else address
        if not _is_local(host):
            self.tried.append(f"{address!r}")
            raise OSError(errno.ENETUNREACH, f"tests never go online (tried {address!r}; tests/conftest.py)")

    def install(self, monkeypatch) -> None:
        guard = self
        real = {name: getattr(socket.socket, name) for name in ("connect", "connect_ex", "sendto")}
        real_sendmsg = socket.socket.sendmsg
        real_getaddrinfo, real_create = socket.getaddrinfo, socket.create_connection

        def connect(self, address):
            guard._check(self, address)
            return real["connect"](self, address)

        def connect_ex(self, address):
            guard._check(self, address)
            return real["connect_ex"](self, address)

        def sendto(self, data, *args):
            guard._check(self, args[-1])
            return real["sendto"](self, data, *args)

        def sendmsg(self, buffers, ancdata=(), flags=0, address=None):
            if address is not None:
                guard._check(self, address)
                return real_sendmsg(self, buffers, ancdata, flags, address)
            return real_sendmsg(self, buffers, ancdata, flags)

        def getaddrinfo(host, *args, **kwargs):
            if not _is_local(host):
                guard.tried.append(f"getaddrinfo({host!r})")
                raise socket.gaierror(socket.EAI_NONAME, f"tests never look up names ({host!r}; tests/conftest.py)")
            return real_getaddrinfo(host, *args, **kwargs)

        def create_connection(address, *args, **kwargs):
            if not _is_local(address[0]):
                guard.tried.append(f"{address!r}")
                raise OSError(errno.ENETUNREACH, f"tests never go online (tried {address!r}; tests/conftest.py)")
            return real_create(address, *args, **kwargs)

        monkeypatch.setattr(socket.socket, "connect", connect)
        monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
        monkeypatch.setattr(socket.socket, "sendto", sendto)
        monkeypatch.setattr(socket.socket, "sendmsg", sendmsg)
        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket, "create_connection", create_connection)


@pytest.fixture(autouse=True)
def _isolated(request, tmp_path_factory, monkeypatch):
    """Every test: a working directory of its own (litter lands there, not in the checkout), HOME, the XDG folders and
    GNUPGHOME in a temporary folder, none of the session's buses, displays, agents or proxies, and no network beyond
    loopback. `@pytest.mark.real_environment` leaves the environment alone (the network guard stays)."""
    from daprivacyscanner import privileged

    guard = _NetworkGuard()
    guard.install(monkeypatch)
    base = tmp_path_factory.mktemp("isolated")
    # whether the administrator helper is installed was read from this computer's /usr/libexec (the page's state, the
    # helper started): a developer's machine with it installed gave other answers than one without
    monkeypatch.setattr(privileged, "INSTALLED_HELPER", base / "not-installed" / "daprivacyscanner-helper")
    if request.node.get_closest_marker("real_environment") is None:
        home, run = base / "home", base / "run"
        for d in (home, run, base / "cwd", base / "gnupg"):
            d.mkdir(mode=0o700)
        monkeypatch.chdir(base / "cwd")
        monkeypatch.setenv("HOME", str(home))
        for var, rel in (("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"),
                         ("XDG_CACHE_HOME", ".cache"), ("XDG_STATE_HOME", ".local/state")):
            monkeypatch.setenv(var, str(home / rel))
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))
        monkeypatch.setenv("GNUPGHOME", str(base / "gnupg"))
        for var in _SESSION_VARS:
            monkeypatch.delenv(var, raising=False)
    yield
    if guard.tried:
        pytest.fail("the test tried to reach the network: " + ", ".join(guard.tried), pytrace=False)


def pytest_configure(config):
    config.addinivalue_line("markers", "real_environment: keep the developer's environment variables and working "
                                       "directory for this test (the network guard stays)")
    # Each test runs in a folder of its own, so a relative PYTHONPATH (PYTHONPATH=src) would no longer reach the
    # programs a test starts: they would import an installed copy of the package instead (the dev venv's editable
    # install, which in a worktree is another checkout's code), or none at all.
    if os.environ.get("PYTHONPATH"):
        os.environ["PYTHONPATH"] = os.pathsep.join(str(Path(p).resolve()) if p else p
                                                   for p in os.environ["PYTHONPATH"].split(os.pathsep))


def pytest_terminal_summary(terminalreporter):
    """A skipped front-end test is easy to miss among thousands of dots: say it at the end, in capitals."""
    for rep in terminalreporter.stats.get("skipped", []):
        if "test_web.py" in rep.nodeid:
            terminalreporter.write_sep("!", "THE FRONT-END TEST (tests/test_web.py) WAS SKIPPED", red=True, bold=True)
            reason = rep.longrepr[2] if isinstance(rep.longrepr, tuple) else str(rep.longrepr)
            terminalreporter.write_line(f"  {reason}")
            terminalreporter.write_line("  npm ci --prefix tests/web installs the pinned jsdom; packaging/check.sh "
                                        "requires it.")


def sample(rel: str) -> str:
    return (SAMPLES / rel).read_text(encoding="utf-8")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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
