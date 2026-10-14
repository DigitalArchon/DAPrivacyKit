"""Guided fixes (docs/TECHNICAL.md, design rule 5): a walk-through of numbered steps, each explained with its
side effects. A step is one of:

- an explanation only;
- options the app can carry out: each option is a FixPlan with its own dry run, applied only
  when the user picks it and confirms that step (and recorded in the undo log like any fix);
- commands for the user to run themselves, where the change needs their input (a passphrase,
  a PIN) or is too risky to automate (sudoers, disk entries in fstab, crypttab).

Building a guide changes nothing; it is built from the machine as it is now, so after a step is
applied the guide is built again and that step shows as done."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from .fix import FixPlan

CHECK_ID = re.compile(r"\b(?:enc|auth|net|desk|br|app|sbx|kern|tel)\.[a-z0-9_]+\b")


def name_checks(text: str, title_of: Callable[[str], str | None]) -> str:
    """A check's id in text shown to the user, replaced by its title in quotes."""
    return CHECK_ID.sub(lambda m: f"“{t}”" if (t := title_of(m.group(0))) else m.group(0), text)


@dataclass
class Option:
    label: str
    plan: FixPlan
    detail: str = ""
    recommended: bool = False
    key: str = ""               # names the option to the catalogue (`easy.option`); declared by its guide

    def to_dict(self) -> dict:
        return {"label": self.label, "detail": self.detail, "recommended": self.recommended, "key": self.key,
                "plan": self.plan.to_dict(), "dry_run": self.plan.dry_run()}


@dataclass
class Input:
    """A choice the user makes before the step's options are built (a size, a yes/no): the page
    shows it, and building the guide again with the new value (Scan.params) rebuilds the options'
    plans, so the dry run always shows exactly what applying does. The guide validates values
    itself and falls back to the default; the helper validates again."""
    name: str
    label: str
    kind: str                               # "number", "choice" or "bool"
    value: object
    default: object
    help: str = ""
    min: int | None = None
    max: int | None = None
    unit: str = ""
    choices: list[tuple[str, str]] = field(default_factory=list)      # (value, label), for "choice"

    def to_dict(self) -> dict:
        return {"name": self.name, "label": self.label, "kind": self.kind, "value": self.value, "default": self.default,
                "help": self.help, "min": self.min, "max": self.max, "unit": self.unit,
                "choices": [list(c) for c in self.choices]}

    @staticmethod
    def read(params: dict, name: str, kind: str, default, low: int | None = None, high: int | None = None,
             choices: tuple = ()):
        """A value from the user's params, checked; the default when missing or not allowed."""
        v = params.get(name, default)
        if kind == "number":
            ok = isinstance(v, int) and not isinstance(v, bool) and (low is None or v >= low) and (high is None or v <= high)
        elif kind == "bool":
            ok = isinstance(v, bool)
        else:
            ok = v in choices
        return v if ok else default


@dataclass
class Step:
    title: str
    text: str = ""
    options: list[Option] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)        # for the user to run in a terminal
    side_effects: list[str] = field(default_factory=list)
    done: bool = False                                       # nothing left to do here
    inputs: list[Input] = field(default_factory=list)        # choices that shape the options (Input)
    parts: list[tuple[str, str]] = field(default_factory=list)   # (heading, text): an explanation in sections

    def __post_init__(self):
        # options with nothing to change are dropped; a step that had only those is done
        had = bool(self.options)
        self.options = [o for o in self.options if not o.plan.empty or o.plan.blockers]
        if had and not self.options and not self.commands:
            self.done = True

    def to_dict(self) -> dict:
        return {"title": self.title, "text": self.text, "options": [o.to_dict() for o in self.options],
                "commands": self.commands, "side_effects": self.side_effects, "done": self.done,
                "inputs": [i.to_dict() for i in self.inputs], "parts": [list(p) for p in self.parts]}


@dataclass
class Guide:
    check_id: str
    title: str
    intro: str = ""
    steps: list[Step] = field(default_factory=list)
    advice: bool = False        # an advice check's guide: steps the user takes, never options

    @property
    def plans(self) -> list[FixPlan]:
        return [o.plan for s in self.steps for o in s.options]

    def keyed(self, key: str) -> list[FixPlan]:
        """The plans of the options with this key, in steps that aren't done (an Easy fix)."""
        return [o.plan for s in self.steps if not s.done for o in s.options if o.key == key]

    def name_checks(self, title_of: Callable[[str], str | None]) -> None:
        """Other checks are referred to by id in the code ("see enc.fde_missing"); the user sees
        their titles."""
        named = lambda text: name_checks(text, title_of)  # noqa: E731
        self.intro = named(self.intro)
        for st in self.steps:
            st.title, st.text = named(st.title), named(st.text)
            st.side_effects = [named(x) for x in st.side_effects]
            st.parts = [(named(head), named(text)) for head, text in st.parts]
            for i in st.inputs:
                i.label, i.help = named(i.label), named(i.help)
            for o in st.options:
                o.label, o.detail = named(o.label), named(o.detail)
                o.plan.side_effects = [named(x) for x in o.plan.side_effects]
                o.plan.blockers = [named(x) for x in o.plan.blockers]

    def to_dict(self) -> dict:
        return {"check_id": self.check_id, "title": self.title, "intro": self.intro, "advice": self.advice,
                "steps": [s.to_dict() for s in self.steps]}

    def dry_run(self) -> str:
        lines = [f"Guide for {self.check_id}: {self.title}"]
        if self.intro:
            lines.append(f"  {self.intro}")
        for i, s in enumerate(self.steps, 1):
            lines.append(f"\n  Step {i}: {s.title}" + (" (done)" if s.done else ""))
            if s.text:
                lines.append(f"    {s.text}")
            for head, text in s.parts:
                lines.append(f"    {head}: {text}")
            for i in s.inputs:
                shown = ("yes" if i.value else "no") if i.kind == "bool" else \
                    dict(i.choices).get(i.value, i.value) if i.kind == "choice" else i.value
                lines.append(f"    Choice: {i.label}: {shown}{(' ' + i.unit) if i.unit else ''}")
            for o in s.options:
                lines.append(f"    Option: {o.label}" + (" (recommended)" if o.recommended else ""))
                lines += ["    " + ln for ln in o.plan.dry_run("    ").splitlines()[1:]]
            for c in s.commands:
                lines.append(f"    $ {c}")
            for e in s.side_effects:
                lines.append(f"    Note: {e}")
        return "\n".join(lines)
