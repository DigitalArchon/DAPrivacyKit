"""The check result model (docs/TECHNICAL.md, design rule 2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

# Evidence is paths, values and counts. It is never file contents: a value longer than this
# is a sign that something is being quoted, and is refused.
MAX_EVIDENCE_TEXT = 300


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    UNKNOWN = "unknown"            # couldn't be checked here (needs root, a tool is missing): never a pass, never a finding
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


# The words the user reads for a status (the page's STATUS_LABEL says the same). A failure is a
# Problem, a warning a Risk: possible, partial, or not happened yet, rated below the problem
# (catalogue.as_warning). Neither word says how serious it is; the severity does.
STATUS_WORD = {"pass": "Pass", "fail": "Problem", "warn": "Risk", "unknown": "Couldn't check",
               "not_applicable": "Not applicable", "error": "Error"}


# What a check's fail means (privacy-checks.yaml `kind`): a finding to act on; hygiene, the
# residue of normal use (caches, histories) that most machines have and that is cleaned rather
# than fixed; or information, an inventory the user should know about but can't "fail".
KINDS = ("finding", "hygiene", "info")


@dataclass(frozen=True)
class Evidence:
    kind: Literal["path", "value", "count", "note"]
    label: str
    value: str | int | bool | None = None
    # the label is a name the user chose (a key file, a wallet): redaction replaces it wherever it appears
    named: bool = False

    def __post_init__(self):
        if self.value is not None and not isinstance(self.value, (str, int, bool)):
            raise TypeError(f"evidence values are scalars, not {type(self.value).__name__}")
        for text in (self.label, self.value):
            if isinstance(text, str) and len(text) > MAX_EVIDENCE_TEXT:
                raise ValueError("evidence is paths, values and counts, never file contents "
                                 f"(got {len(text)} characters)")

    @classmethod
    def path(cls, label: str, path: str) -> "Evidence":
        return cls("path", label, path)

    @classmethod
    def val(cls, label: str, value: str | int | bool | None, named: bool = False) -> "Evidence":
        return cls("value", label, value, named)

    @classmethod
    def count(cls, label: str, n: int) -> "Evidence":
        return cls("count", label, n)

    @classmethod
    def note(cls, text: str) -> "Evidence":
        return cls("note", text)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "label": self.label, "value": self.value, **({"named": True} if self.named else {})}


@dataclass(frozen=True)
class Note:
    """Information for the user that is not a finding: a risk that would apply if something
    changed ("hibernation is one step away"), or a limit on what the scan can see ("in a VM,
    the host's disk encryption is invisible")."""
    kind: Literal["info", "risk", "limitation"]
    title: str
    text: str
    related: tuple[str, ...] = ()       # check ids

    def to_dict(self) -> dict:
        return {"kind": self.kind, "title": self.title, "text": self.text, "related": list(self.related)}


@dataclass
class Outcome:
    """What a check's detection returns. The runner adds severity and fixability."""
    status: Status
    summary: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    # values for the names a check's modifiers use that aren't context keys
    # (e.g. desk.thumbnails sets thumbnails_reference_removable_or_container)
    findings: dict[str, bool | None] = field(default_factory=dict)
    # detection was incomplete, typically because a scope: system check ran without root
    partial: bool = False
    notes: list[Note] = field(default_factory=list)
    # couldn't be checked only because it needs administrator access (a scan with it would)
    needs_admin: bool = False
    # an inventory's entries, each named as the user would recognise it ("~/.config/autostart/x.desktop"):
    # the baseline keeps only a salted hash of each, so the next scan can say which are new
    items: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Outcome":
        """A result as the report keeps it (CheckResult.to_dict), back as the outcome that made it: a guide for an
        online test is built from the result the user saw, since the test contacts other machines and runs only
        when they start it."""
        try:
            status = Status(d.get("status", "unknown"))
        except ValueError:
            status = Status.UNKNOWN
        return cls(status, str(d.get("summary", "")),
                   [Evidence(e.get("kind", "value"), e["label"], e.get("value"), bool(e.get("named"))) for e in d.get("evidence") or []
                    if isinstance(e, dict) and "label" in e],
                   dict(d.get("findings") or {}), bool(d.get("partial")),
                   [Note(n.get("kind", "info"), n.get("title", ""), n.get("text", ""), tuple(n.get("related") or ()))
                    for n in d.get("notes") or [] if isinstance(n, dict)],
                   items=list(d.get("items") or []))


@dataclass
class CheckResult:
    id: str
    status: Status
    effective_severity: int
    evidence: list[Evidence]
    fixable: bool
    summary: str = ""
    base_severity: int = 0
    partial: bool = False
    kind: str = "finding"
    # names whose unknown value could have changed the severity
    uncertain_on: tuple[str, ...] = ()
    findings: dict[str, bool | None] = field(default_factory=dict)
    notes: list[Note] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0
    severity_reason: str = ""      # what decided the severity, in words; empty for the base severity
    needs_admin: bool = False
    how_to: bool = False           # an advice check with a guide of its own: steps the user takes
    items: list[str] = field(default_factory=list)      # an inventory's entries (Outcome.items)
    easy: bool = False             # its fix is an Easy fix (the catalogue's `easy`) with something left to apply here
    # a problem whose fix (auto or guided) doesn't cover this machine: why, in words, shown in place
    # of the Fix… button; empty otherwise
    no_fix: str = ""
    fix_root: bool = False         # its auto fix, as planned at the scan, goes through the helper
    as_warning: bool = False       # a warning: rated below what the check failing would be (catalogue.as_warning)

    @property
    def found(self) -> bool:
        """Failed or warned with a severity above 0, whatever the check's kind."""
        return self.status in (Status.FAIL, Status.WARN) and self.effective_severity > 0

    @property
    def is_finding(self) -> bool:
        """Shown to the user as a problem to act on: found, and the check is about a finding
        (not hygiene or information). The page uses the same rule."""
        return self.found and self.kind == "finding"

    @property
    def is_hygiene(self) -> bool:
        return self.found and self.kind == "hygiene"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "status": self.status.value, "effective_severity": self.effective_severity,
            "base_severity": self.base_severity, "evidence": [e.to_dict() for e in self.evidence],
            "fixable": self.fixable, "summary": self.summary, "partial": self.partial,
            "uncertain_on": list(self.uncertain_on), "findings": dict(self.findings),
            "notes": [n.to_dict() for n in self.notes], "error": self.error,
            "duration_ms": self.duration_ms, "kind": self.kind, "severity_reason": self.severity_reason,
            "needs_admin": self.needs_admin, "how_to": self.how_to, "easy": self.easy,
            "is_finding": self.is_finding, "is_hygiene": self.is_hygiene,
            **({"items": list(self.items)} if self.items else {}),
            **({"no_fix": self.no_fix} if self.no_fix else {}),
            **({"fix_root": True} if self.fix_root else {}),
            **({"as_warning": True} if self.as_warning else {}),
        }
