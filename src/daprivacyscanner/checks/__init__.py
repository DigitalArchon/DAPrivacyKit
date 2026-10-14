"""Check implementations. Each subclasses Check, sets `id` to a catalogue id, and is
registered with @register. The catalogue (privacy-checks.yaml) is updated first, then the code.

    @register
    class TrashCheck(Check):
        id = "enc.trash"

        def detect(self, scan: Scan) -> Outcome:
            ...

Import the modules that define checks in load_all(), so the registry is complete."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, ClassVar

from ..model import Outcome

if TYPE_CHECKING:
    from ..catalogue import CheckSpec
    from ..context import Context
    from ..desktop import GNOME, KDE
    from ..host import Host
    from ..paths import PathResolver
    from ..fix import FixPlan
    from ..guide import Guide
    from ..online import Net
    from ..privileged import Privileged


_OPEN_FILES_LOCK = threading.Lock()
_INSTALLED_LOCK = threading.Lock()


@dataclass
class Scan:
    """Everything a check may use. Checks read the system only through these."""
    host: "Host"
    paths: "PathResolver"
    context: "Context"
    kde: "KDE"
    gnome: "GNOME"
    privileged: "Privileged | None" = None    # the polkit helper, when root was granted
    net: "Net | None" = None                  # online tests only: the network (never in a normal scan)
    online: dict | None = None                # online tests only: their settings (online.load_settings)
    stop: Callable[[], bool] | None = None    # online tests only: the user stopped them; return early
    params: dict = field(default_factory=dict)  # a guide's inputs as the user set them (guide.Input); never trusted
    _open_files: list | None = field(default=None, repr=False, compare=False)
    _installed_apps: dict | None = field(default=None, repr=False, compare=False)

    def stopped(self) -> bool:
        return self.stop is not None and self.stop()

    def open_files(self) -> list[tuple[str, frozenset[str]]]:
        """What this user's processes hold open (_util.open_files), read once for this Scan."""
        from ._util import open_files

        with _OPEN_FILES_LOCK:
            if self._open_files is None:
                self._open_files = open_files(self.host)
            return self._open_files

    def installed_apps(self) -> dict:
        """The version of each app in apps.yaml installed here (appversions.installed), read once for this Scan."""
        from .. import appversions

        with _INSTALLED_LOCK:
            if self._installed_apps is None:
                self._installed_apps = appversions.installed(self.host, appversions.load())
            return self._installed_apps


class No(str):
    """What a fix's or guide's `can` returns when it doesn't cover this machine: false, with the
    reason in words for the user, shown in place of the Fix… button ("The fix covers GNOME only…")."""

    def __bool__(self) -> bool:
        return False


class Check:
    id: ClassVar[str]
    # Set by load_all() for checks with an auto fix (checks/fixes.py) or a guide
    # (checks/guides.py); fix_needs_root when applying the auto fix needs the privileged helper.
    supports_fix: ClassVar[bool] = False
    fix_needs_root: ClassVar[bool] = False

    def __init__(self, spec: "CheckSpec"):
        self.spec = spec
        self.last_outcome: Outcome | None = None

    def detect(self, scan: Scan) -> Outcome:
        """Read-only. Never modifies anything (rule 4)."""
        raise NotImplementedError

    def stored_at(self, scan: Scan) -> list[str]:
        """Where what the check finds is kept, for a check whose modifiers use data_on_encrypted_disk (the runner
        asks whether all of it is on encrypted storage): the user's own folders unless the check says otherwise."""
        p = scan.paths
        return [str(d) for d in (scan.host.home, p.config_home, p.data_home, p.cache_home, p.state_home)]

    def can_fix(self, scan: Scan, outcome: Outcome) -> "bool | No":
        """Environment-specific fixability, on top of the tier (e.g. the tool it needs is installed):
        True, or No with the reason."""
        from .fixes import FIXES
        from .guides import GUIDES

        entry = FIXES.get(self.id) or GUIDES.get(self.id)
        if entry is None or entry.can is None:
            return True
        r = entry.can(scan)
        return True if r else r if isinstance(r, No) else No("")

    def plan_fix(self, scan: Scan, outcome: Outcome) -> "FixPlan":
        """The dry run: what the fix would do on this machine now. Changes nothing."""
        from .fixes import FIXES

        return FIXES[self.id].plan(self, scan, outcome)

    def plan_guide(self, scan: Scan, outcome: Outcome) -> "Guide":
        """The guided fix's steps on this machine now, each option with its dry run. Changes nothing."""
        from .guides import GUIDES

        return GUIDES[self.id].plan(self, scan, outcome)


REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    if not getattr(cls, "id", None):
        raise TypeError(f"{cls.__name__} has no id")
    if cls.id in REGISTRY and REGISTRY[cls.id] is not cls:
        raise TypeError(f"two implementations of {cls.id}: {REGISTRY[cls.id].__name__} and {cls.__name__}")
    REGISTRY[cls.id] = cls
    return cls


CHECK_MODULES = ("encryption", "auth", "network", "telemetry", "browser", "desktop", "apps", "sandbox", "kernel",
                 "online")


def load_all() -> dict[str, type[Check]]:
    """Import every check module, which registers its checks, then the fixes for them."""
    import importlib

    for name in CHECK_MODULES:
        importlib.import_module(f"{__name__}.{name}")
    from .fixes import FIXES
    from .guides import GUIDES

    for check_id, entry in FIXES.items():
        if check_id in REGISTRY:
            REGISTRY[check_id].supports_fix = True
            REGISTRY[check_id].fix_needs_root = entry.needs_root
    for check_id in GUIDES:
        if check_id in REGISTRY:
            REGISTRY[check_id].supports_fix = True
    return REGISTRY
