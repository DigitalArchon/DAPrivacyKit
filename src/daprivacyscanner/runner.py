"""Runs a scan: context first, then every implemented check, each turned into a CheckResult
with its effective severity and fixability. A scan never modifies anything."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from . import appversions
from .catalogue import (Catalogue, CatalogueError, CheckSpec, Scope, Severity, Tier, as_warning, describe_when,
                        effective_severity, modifier_states)
from .checks import Check, No, Scan, load_all
from .checks._util import ENCRYPTED_DISK_NOTE, ON_ENCRYPTED_DISK, on_encrypted_disk
from .context import Context, ContextValue, detect_context
from .desktop import GNOME, KDE
from .fix import FixPlan
from .guide import Guide, name_checks
from .host import FormatChanged, Host, Unreadable
from .model import CheckResult, Evidence, Note, Outcome, Status
from .paths import PathResolver

Progress = Callable[[str, int, int], None]      # (check id, done, total)
# Checks are independent and spend their time waiting on subprocesses, so several run at once.
WORKERS = 6


@dataclass
class ScanReport:
    started: float
    duration_ms: int
    context: Context
    results: dict[str, CheckResult]
    # catalogue checks with no implementation yet, with their severity in this context
    not_implemented: dict[str, Severity] = field(default_factory=dict)
    # each check's modifiers evaluated on this machine: True, False, or None (unknown)
    modifiers: dict[str, list[bool | None]] = field(default_factory=dict)
    privileged: bool = False
    online_pending: list[str] = field(default_factory=list)     # online checks a normal scan doesn't run
    # notes online checks add to other checks' results (e.g. a port the router forwards, on net.exposed_services)
    extra_notes: dict[str, list] = field(default_factory=dict)
    catalogue: Catalogue | None = field(default=None, repr=False)
    # rescan: context keys that couldn't be read again (no root now) and kept their earlier value
    kept_context: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[CheckResult]:
        return sorted((r for r in self.results.values() if r.is_finding), key=lambda r: -r.effective_severity)

    @property
    def hygiene(self) -> list[CheckResult]:
        return sorted((r for r in self.results.values() if r.is_hygiene), key=lambda r: -r.effective_severity)

    def dependents(self, keys: Iterable[str]) -> list[str]:
        """Checks whose severity modifiers use any of these context keys."""
        keys = set(keys)
        return [r.id for r in self.results.values()
                if any(m.when.names & keys for m in self.catalogue[r.id].modifiers)] if self.catalogue else []

    def to_dict(self) -> dict:
        return {
            "started": self.started, "duration_ms": self.duration_ms, "privileged": self.privileged,
            "context": self.context.to_dict(),
            "results": {k: r.to_dict() for k, r in self.results.items()},
            "not_implemented": {k: {"effective_severity": s.value, "base_severity": s.base,
                                    "modifier": s.modifier, "uncertain_on": list(s.uncertain_on)}
                                for k, s in self.not_implemented.items()},
            "modifiers": self.modifiers, "online_pending": self.online_pending,
            "extra_notes": {k: [n.to_dict() for n in v] for k, v in self.extra_notes.items()},
        }


class Runner:
    def __init__(self, catalogue: Catalogue, host: Host, registry: dict[str, type[Check]] | None = None,
                 net=None, online: dict | None = None, workers: int = WORKERS):
        """Root access comes from host.privileged: the helper, when the user granted it. `net`
        and `online` (settings) are given only to run online tests (scan_online). `workers`:
        how many checks run at once (1 runs them one after another, in catalogue order)."""
        self.catalogue = catalogue
        self.host = host
        self.net, self.online = net, online
        self.workers = max(1, workers)
        self.registry = load_all() if registry is None else registry
        unknown = sorted(set(self.registry) - set(catalogue.checks))
        if unknown:
            raise CatalogueError(f"implemented checks missing from the catalogue: {', '.join(unknown)}")

    def _scan(self, context: Context) -> Scan:
        paths = PathResolver(self.host.home, self.host.environ)
        return Scan(self.host, paths, context, KDE(self.host, paths, context.desktop),
                    GNOME(self.host, context.desktop), self.host.privileged, self.net, self.online)

    def plan_fix(self, check_id: str, params: dict | None = None,
                 stored: dict | None = None) -> tuple[CheckResult, FixPlan | Guide | None]:
        """Detect one check again on the machine as it is now and, if it can be fixed, build the
        fix's plan (the dry run) or, for a guided fix or a feature, its guide (built with the
        guide's inputs as given in `params`). Changes nothing. A plan that deletes files says what
        deleting does and doesn't do on this machine (rule 8).

        An online test isn't run again (it contacts other machines, only when the user starts it): its
        guide is built from `stored`, its result as the report keeps it; without one it can't be planned."""
        check = self.registry[check_id](self.catalogue[check_id])
        scan = self._scan(detect_context(self.host))
        scan.params = dict(params or {})
        given = Outcome.from_dict(stored) if stored and check.spec.scope is Scope.ONLINE else None
        result = self.run_check(check, scan, given)
        if result.how_to:
            # an advice check's guide explains and gives commands; the app changes nothing (rule 5)
            plan = check.plan_guide(scan, check.last_outcome)
            if plan.plans:
                raise ValueError(f"{check_id} is advice: its guide can't offer changes")
            plan.advice = True
            plan.name_checks(self._title)
            return result, plan
        # a guide stays open once its check passes: the page reloads it after each step it applies,
        # its later steps (a lasting default, a folder in memory) still apply, and a feature set up
        # is reviewed through it. Its steps say what is done.
        guide_open = (result.status is Status.PASS and check.spec.tier in (Tier.GUIDED, Tier.FEATURE)
                      and check.supports_fix and _safe_can_fix(check, scan, check.last_outcome))
        if not (result.fixable or guide_open):
            return result, None
        if check.spec.tier in (Tier.GUIDED, Tier.FEATURE):
            plan = check.plan_guide(scan, check.last_outcome)
            plans = plan.plans
        else:
            plan = check.plan_fix(scan, check.last_outcome)
            plans = [plan]
        self._explain(scan, plans, check_id)
        if isinstance(plan, Guide):
            plan.name_checks(self._title)
            _stamp(plan)
        else:
            plan.side_effects = [name_checks(x, self._title) for x in plan.side_effects]
            plan.blockers = [name_checks(x, self._title) for x in plan.blockers]
        return result, plan

    def _explain(self, scan: Scan, plans: list[FixPlan], check_id: str | None = None) -> None:
        """A plan that deletes files says what deleting does and doesn't do on this machine (rule 8). A plan for an
        app newer than its check was made for says so first (appversions.plan_note)."""
        newer = appversions.plan_note(check_id, scan) if check_id else None
        for p in plans if newer else ():
            if newer not in p.side_effects:
                p.side_effects.insert(0, newer)
        if any(p.irreversible for p in plans):
            from .checks.encryption import deleted_data_note
            note = deleted_data_note(scan)
            for p in plans:
                if p.irreversible and note not in p.side_effects:
                    p.side_effects.append(note)

    def plan_easy(self, check_ids: Iterable[str] | None = None) -> list[tuple[CheckResult, list[FixPlan]]]:
        """The Easy fixes (the catalogue's `easy`) of the checks that fail or warn now: each check
        detected again on the machine as it is, with its auto fix's plan, or its guide's options
        with the catalogue's key (in steps not done yet). Checks with nothing left to change are
        left out. One context for all of them; changes nothing."""
        wanted = set(check_ids) if check_ids is not None else None
        scan = self._scan(detect_context(self.host))
        out = []
        for spec in self.catalogue:
            if spec.easy is None or spec.id not in self.registry or (wanted is not None and spec.id not in wanted):
                continue
            check = self.registry[spec.id](spec)
            result = self.run_check(check, scan)
            if not (result.easy and result.found):
                continue
            if spec.tier is Tier.AUTO:
                plans = [check.plan_fix(scan, check.last_outcome)]
            else:
                guide = check.plan_guide(scan, check.last_outcome)
                from .checks.guides import GUIDES
                stray = {o.key for s in guide.steps for o in s.options if o.key} - GUIDES[spec.id].keys
                if stray:
                    raise ValueError(f"{spec.id}: option keys its guide doesn't declare: {', '.join(sorted(stray))}")
                _stamp(guide)
                plans = guide.keyed(spec.easy.option)
            plans = [p for p in plans if not p.empty or p.blockers]
            if not plans:
                continue
            self._explain(scan, plans, spec.id)
            for p in plans:
                p.side_effects = [name_checks(x, self._title) for x in p.side_effects]
                p.blockers = [name_checks(x, self._title) for x in p.blockers]
                p.via = {**p.via, "easy": True}       # History says it was applied as an Easy fix
            out.append((result, plans))
        return out

    def _title(self, check_id: str) -> str | None:
        return self.catalogue[check_id].title if check_id in self.catalogue.checks else None

    def scan(self, only: Iterable[str] | None = None, progress: Progress | None = None) -> ScanReport:
        """The read-only scan. Online checks are never part of it (rule 10): they are listed as
        pending, to be run with scan_online when the user starts them."""
        started, t0 = time.time(), time.monotonic()
        context = detect_context(self.host)
        scan = self._scan(context)
        wanted = set(only) if only is not None else None
        pending = [s.id for s in self.catalogue if s.scope is Scope.ONLINE]
        specs = [s for s in self.catalogue if (wanted is None or s.id in wanted) and s.scope is not Scope.ONLINE]

        results: dict[str, CheckResult] = {}
        pending_sev: dict[str, Severity] = {}
        states: dict[str, list[bool | None]] = {}
        todo = []
        for spec in specs:
            impl = self.registry.get(spec.id)
            if impl is None:
                pending_sev[spec.id] = effective_severity(spec, context.vars())
                states[spec.id] = modifier_states(spec, context.vars())
            else:
                todo.append((spec, impl))
        done = 0

        def one(item):
            spec, impl = item
            return spec, self.run_check(impl(spec), scan)

        if self.workers > 1 and len(todo) > 1:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                finished = list(pool.map(one, todo))
        else:
            finished = [one(t) for t in todo]
        for spec, result in finished:                 # catalogue order, whatever order they finished in
            results[spec.id] = result
            states[spec.id] = modifier_states(spec, {**context.vars(), **result.findings})
            done += 1
            if progress:
                progress(spec.id, done, len(todo))
        report = ScanReport(started, int((time.monotonic() - t0) * 1000), context, results, pending_sev, states,
                            self.host.privileged is not None, pending if only is None else [], catalogue=self.catalogue)
        return report

    def rescan(self, check_ids: Iterable[str], previous: Mapping[str, Any] | None = None) -> ScanReport:
        """After a fix or a revert: the context again (a fix may have changed it, e.g. autologin
        off), the given checks, and every check whose severity depends on a context key that
        changed since `previous` (the report's context: {"values": {key: {"value": ...}}}).

        A key known before but unknown now is kept as it was (listed in `kept_context`): a fix
        doesn't make the machine unknowable, the difference is that administrator access has
        ended since the scan, and without that rule every root-only key would read as changed
        and the checks depending on it would turn into "couldn't check"."""
        context = detect_context(self.host)
        wanted, kept = set(check_ids), []
        before = {k: v.get("value") for k, v in ((previous or {}).get("values") or {}).items()}
        for key, cv in context.values.items():
            if cv.value is None and before.get(key) is not None:
                context.values[key] = ContextValue(key, before[key], note="From the last scan: it can't be read "
                                                   "again without administrator access")
                kept.append(key)
        if previous:
            changed = {k for k, v in context.vars().items() if k in before and v != before[k]}
            wanted |= {s.id for s in self.catalogue if s.scope is not Scope.ONLINE
                       and any(m.when.names & changed for m in s.modifiers)}
        scan = self._scan(context)
        results, states = {}, {}
        for spec in self.catalogue:
            if spec.id in wanted and spec.id in self.registry:
                results[spec.id] = self.run_check(self.registry[spec.id](spec), scan)
                states[spec.id] = modifier_states(spec, {**context.vars(), **results[spec.id].findings})
        return ScanReport(time.time(), 0, context, results, {}, states, self.host.privileged is not None, [],
                          catalogue=self.catalogue, kept_context=kept)

    def scan_online(self, ids: Iterable[str], progress: Progress | None = None,
                    stop: Callable[[], bool] | None = None,
                    on_result: Callable[[str, CheckResult, list, dict], None] | None = None) -> ScanReport:
        """Run the chosen online checks. Only called when the user starts them, with a Net.
        `progress(id, done, total)` is called as each check starts; `stop()` is asked before each
        one (a check already running finishes); `on_result(id, result, modifier states, notes
        for other checks)` gets each result as soon as it is in."""
        if self.net is None or self.online is None:
            raise ValueError("online tests need a network and their settings")
        started, t0 = time.time(), time.monotonic()
        context = detect_context(self.host)
        scan = self._scan(context)
        scan.stop = stop
        specs = [s for s in self.catalogue if s.id in set(ids) and s.scope is Scope.ONLINE]
        results, states, extra = {}, {}, {}
        for i, spec in enumerate(specs):
            impl = self.registry.get(spec.id)
            if impl is None:
                continue
            if stop is not None and stop():
                break
            if progress:
                progress(spec.id, i, len(specs))
            check = impl(spec)
            results[spec.id] = self.run_check(check, scan)
            states[spec.id] = modifier_states(spec, {**context.vars(), **results[spec.id].findings})
            mine = getattr(check, "notes_for_others", {})
            for target, notes in mine.items():
                extra.setdefault(target, []).extend(notes)
            if on_result:
                on_result(spec.id, results[spec.id], states[spec.id], mine)
        return ScanReport(started, int((time.monotonic() - t0) * 1000), context, results, {}, states,
                          self.host.privileged is not None, [], extra)

    def run_check(self, check: Check, scan: Scan, given: Outcome | None = None) -> CheckResult:
        """`given`: an outcome in place of detecting (an online test's kept result, for its guide)."""
        spec = check.spec
        values = scan.context.vars()
        before = effective_severity(spec, values)
        if before.not_applicable:
            return CheckResult(spec.id, Status.NOT_APPLICABLE, 0, [], False,
                               summary=f"Not applicable here: {_why_na(spec, before)}", base_severity=spec.severity,
                               kind=spec.kind)

        t0 = time.monotonic()
        error = ""
        try:
            outcome = check.detect(scan) if given is None else given
            if not isinstance(outcome, Outcome):
                raise TypeError(f"detect() returned {type(outcome).__name__}, not Outcome")
            stray = set(outcome.findings) - spec.finding_names
            if stray:
                raise ValueError(f"findings not used by the catalogue's modifiers: {', '.join(sorted(stray))}")
        except Unreadable as e:
            outcome = self._unreadable(spec, scan, e)
            error = "" if outcome.partial else str(e)
        except FormatChanged as e:
            outcome = _format_changed(scan, e)
        except Exception as e:  # noqa: BLE001 - a broken check is reported, the scan goes on
            outcome = Outcome(Status.ERROR, "The check failed")
            error = f"{type(e).__name__}: {e}"
        if outcome.status is not Status.ERROR:
            try:
                outcome = appversions.annotate(spec.id, scan, outcome)
            except Exception:  # noqa: BLE001 - a version that can't be read adds nothing
                pass
        ms = int((time.monotonic() - t0) * 1000)
        check.last_outcome = outcome
        if ON_ENCRYPTED_DISK in spec.finding_names and ON_ENCRYPTED_DISK not in outcome.findings:
            try:
                outcome.findings[ON_ENCRYPTED_DISK] = on_encrypted_disk(scan, *check.stored_at(scan))
            except Exception:  # noqa: BLE001 - unsure means the modifier isn't applied
                outcome.findings[ON_ENCRYPTED_DISK] = None

        sev = effective_severity(spec, {**values, **outcome.findings})
        status = outcome.status
        if status is Status.WARN:
            sev = as_warning(spec, sev)          # a risk is rated below the problem it could become
        if sev.not_applicable and status is not Status.ERROR:
            status = Status.NOT_APPLICABLE
            outcome.summary = f"Not applicable here: {_why_na(spec, sev)}"
        # root fixes are offered without root: applying one asks for it. "Couldn't check" has
        # nothing to fix yet.
        offered = (status in (Status.FAIL, Status.WARN) and spec.tier in (Tier.AUTO, Tier.GUIDED, Tier.FEATURE)
                   and check.supports_fix)
        can = _safe_can_fix(check, scan, outcome) if offered else False
        fixable, no_fix, fix_root = bool(can), "", False
        if offered and not can:
            no_fix = name_checks(can if isinstance(can, No) else "", self._title) or f"{'Fix…' if spec.tier is Tier.AUTO else 'The guide'} doesn't cover this machine."
        elif fixable and spec.tier is Tier.AUTO:
            # the dry run, now: a fix with nothing to change here isn't offered (its notes say why)
            fixable, no_fix, fix_root = _auto_plan(check, scan, outcome, self._title)
        how_to = (status in (Status.FAIL, Status.WARN) and spec.tier is Tier.ADVICE and check.supports_fix
                  and bool(_safe_can_fix(check, scan, outcome)))
        # an Easy fix only while it has something left to apply: the page counts these, and plan_easy lists them
        easy = fixable and spec.easy is not None and (spec.tier is Tier.AUTO or _easy_left(check, scan, outcome))
        notes = outcome.notes
        decided = next((m for m in spec.modifiers if m.when.source == sev.modifier), None)
        if status in (Status.FAIL, Status.WARN) and decided is not None and ON_ENCRYPTED_DISK in decided.when.names:
            notes = [*notes, ENCRYPTED_DISK_NOTE]
        # a check that refers to another by id in what it says ("see enc.fde_missing") shows its title
        notes = [replace(n, title=name_checks(n.title, self._title), text=name_checks(n.text, self._title)) for n in notes]
        return CheckResult(
            spec.id, status, sev.value, outcome.evidence, fixable, summary=name_checks(outcome.summary, self._title),
            base_severity=spec.severity, partial=outcome.partial, uncertain_on=sev.uncertain_on,
            findings=dict(outcome.findings), notes=notes, error=error, duration_ms=ms, kind=spec.kind,
            severity_reason=_severity_reason(spec, sev), needs_admin=outcome.needs_admin and status is Status.UNKNOWN,
            how_to=how_to, items=list(outcome.items), easy=easy, as_warning=sev.as_warning,
            no_fix=no_fix, fix_root=fix_root,
        )

    def _unreadable(self, spec: CheckSpec, scan: Scan, e: Unreadable) -> Outcome:
        """A system check without root reports partial detection rather than failing (rule 3)."""
        where = scan.host.display(Path(str(e)))
        if spec.scope is Scope.SYSTEM and scan.privileged is None:
            return Outcome(Status.UNKNOWN, "Couldn't check: this needs administrator access",
                           [Evidence.path("Needs administrator access", where)], partial=True, needs_admin=True)
        return Outcome(Status.ERROR, f"Couldn't read {where}")


def _format_changed(scan: Scan, e: FormatChanged) -> Outcome:
    """A file the check reads isn't in the form it expects: couldn't check, never a pass."""
    where = scan.host.display(Path(str(e.path)))
    return Outcome(Status.UNKNOWN, f"Couldn't check: {where} isn't in the form this check expects",
                   [Evidence.path("Not in the expected form", where)],
                   notes=[Note("limitation", "A file isn't in the form this check expects",
                               f"{where}: {e.what}. The file may be damaged, or the program that keeps it may store "
                               "this differently since this version of DA Privacy Kit was made: look for a newer "
                               "version of DA Privacy Kit.")])


def _stamp(guide: Guide) -> None:
    """Each option's plan knows the guide, step and option it was offered as (FixPlan.via), so the
    History entry can say where the change came from."""
    for n, step in enumerate(guide.steps, 1):
        for o in step.options:
            o.plan.via = {"guide": guide.title, "step": n, "step_title": step.title, "option": o.label,
                          "options": len(step.options)}


def _severity_reason(spec: CheckSpec, sev: Severity) -> str:
    """The modifier that decided the severity, in words ("device type is laptop"), and that it was
    lowered as a risk; empty when it is the check's base severity."""
    m = next((m for m in spec.modifiers if m.when.source == sev.modifier), None)
    parts = [describe_when(m.when)] if m else []
    if sev.as_warning:
        parts.append(f"it is a risk rather than a confirmed problem ({spec.warn_lower} lower, never below 1)")
    return "; ".join(parts)


def _why_na(spec: CheckSpec, sev: Severity) -> str:
    return _severity_reason(spec, sev) or "its severity is 0 here"


def _safe_can_fix(check: Check, scan: Scan, outcome: Outcome) -> "bool | No":
    try:
        return check.can_fix(scan, outcome)
    except Exception:  # noqa: BLE001 - unsure means not offered
        return No("")


def _auto_plan(check: Check, scan: Scan, outcome: Outcome, title: Callable[[str], str | None]) -> tuple[bool, str, bool]:
    """(fixable, why not, needs root) from an auto fix's plan on this machine now. A plan that
    can't be built is still offered: opening it shows the error."""
    try:
        plan = check.plan_fix(scan, outcome)
    except Exception:  # noqa: BLE001
        return True, "", check.fix_needs_root
    if plan.empty and not plan.blockers:
        why = " ".join(name_checks(x, title) for x in plan.side_effects)
        return False, why or "There is nothing here that Fix… can change.", False
    return True, "", plan.needs_root


def _easy_left(check: Check, scan: Scan, outcome: Outcome) -> bool:
    """Whether a guide's Easy option still has something to apply on this machine now (or is blocked:
    "Close X first"). The check can go on failing with it in place (a list that still has entries once
    its lasting setting is set, a change that waits for a restart): it is then no longer an Easy fix.
    A guide that can't be built is still offered: opening it shows the error."""
    try:
        plans = check.plan_guide(scan, outcome).keyed(check.spec.easy.option)
    except Exception:  # noqa: BLE001
        return True
    return any(not p.empty or p.blockers for p in plans)
