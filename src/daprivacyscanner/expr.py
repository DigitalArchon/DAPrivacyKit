"""The `when` expressions of severity modifiers in privacy-checks.yaml.

A deliberately small language, parsed here rather than handed to eval():

    expr := or_      or_ := and_ ("or" and_)*      and_ := not_ ("and" not_)*
    not_ := "not" not_ | cmp                       cmp  := atom (("==" | "!=") atom)?
    atom := NAME | 'string' | true | false | "(" expr ")"

Evaluation is three-valued (Kleene): a name whose value is unknown (None, or missing) makes
the result None unless the rest of the expression decides it anyway (`False and x` is False).
The caller decides what an unknown condition means; see catalogue.effective_severity."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

Value = Any  # str | bool | None

_TOKEN = re.compile(r"\s*(?:(?P<op>==|!=|\(|\))|'(?P<str>[^'\\]*)'|(?P<name>[A-Za-z_][A-Za-z0-9_]*))")
_KEYWORDS = {"and", "or", "not", "true", "false"}


class ExprError(ValueError):
    pass


@dataclass(frozen=True)
class Node:
    kind: str                      # name | lit | not | and | or | eq | ne
    value: Any = None              # the name, or the literal
    args: tuple["Node", ...] = ()


def _tokenize(src: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    src = src.rstrip()
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m or m.end() == pos:
            raise ExprError(f"unexpected text at {pos}: {src[pos:]!r}")
        pos = m.end()
        if m.group("op"):
            out.append(("op", m.group("op")))
        elif m.group("str") is not None:
            out.append(("str", m.group("str")))
        else:
            word = m.group("name")
            out.append(("kw", word) if word in _KEYWORDS else ("name", word))
    return out


# how deep brackets and `not`s may nest: each level is a call of the parser and of the evaluator, and 2000 of them
# raised RecursionError rather than the language's own error (property tests, 2026-11-12)
MAX_DEPTH = 100


class _Parser:
    def __init__(self, src: str):
        self.src = src
        self.toks = _tokenize(src)
        self.i = 0
        self.depth = 0

    def deeper(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ExprError(f"brackets or `not`s nested more than {MAX_DEPTH} deep in {self.src[:60]!r}…")

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, kind: str, value: str | None = None) -> bool:
        t = self.peek()
        if t and t[0] == kind and (value is None or t[1] == value):
            self.i += 1
            return True
        return False

    def parse(self) -> Node:
        node = self.or_()
        left = self.peek()
        if left is not None:
            raise ExprError(f"unexpected {left[1]!r} in {self.src!r}")
        return node

    def or_(self) -> Node:
        node = self.and_()
        while self.take("kw", "or"):
            node = Node("or", args=(node, self.and_()))
        return node

    def and_(self) -> Node:
        node = self.not_()
        while self.take("kw", "and"):
            node = Node("and", args=(node, self.not_()))
        return node

    def not_(self) -> Node:
        if self.take("kw", "not"):
            self.deeper()
            node = Node("not", args=(self.not_(),))
            self.depth -= 1
            return node
        return self.cmp()

    def cmp(self) -> Node:
        left = self.atom()
        for op, kind in (("==", "eq"), ("!=", "ne")):
            if self.take("op", op):
                return Node(kind, args=(left, self.atom()))
        return left

    def atom(self) -> Node:
        t = self.peek()
        if t is None:
            raise ExprError(f"unexpected end of {self.src!r}")
        self.i += 1
        kind, val = t
        if kind == "name":
            return Node("name", val)
        if kind == "str":
            return Node("lit", val)
        if kind == "kw" and val in ("true", "false"):
            return Node("lit", val == "true")
        if kind == "op" and val == "(":
            self.deeper()
            node = self.or_()
            if not self.take("op", ")"):
                raise ExprError(f"missing ')' in {self.src!r}")
            self.depth -= 1
            return node
        raise ExprError(f"unexpected {val!r} in {self.src!r}")


@dataclass(frozen=True)
class Expr:
    source: str
    root: Node

    def _nodes(self):
        """Every node, without recursing (a chain of 2000 `and`s is as deep as it is long)."""
        stack = [self.root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(n.args)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(n.value for n in self._nodes() if n.kind == "name")

    def comparisons(self) -> list[tuple[str, Any]]:
        """(name, literal) pairs compared with == or !=, for validating literals."""
        pairs: list[tuple[str, Any]] = []
        for n in self._nodes():
            if n.kind in ("eq", "ne"):
                a, b = n.args
                if a.kind == "name" and b.kind == "lit":
                    pairs.append((a.value, b.value))
                elif b.kind == "name" and a.kind == "lit":
                    pairs.append((b.value, a.value))
        return pairs

    def evaluate(self, values: Mapping[str, Value]) -> bool | None:
        try:
            return _truth(_eval(self.root, values))
        except RecursionError:                      # a tree built by hand, deeper than the parser allows
            raise ExprError(f"{self.source[:60]!r}… is nested too deep to evaluate") from None


def parse(src: str) -> Expr:
    try:
        return Expr(src, _Parser(src).parse())
    except RecursionError:
        raise ExprError(f"{src[:60]!r}… is nested too deep") from None


def _truth(v: Value) -> bool | None:
    return None if v is None else bool(v)


def _eval(n: Node, values: Mapping[str, Value]) -> Value:
    if n.kind == "name":
        return values.get(n.value)
    if n.kind == "lit":
        return n.value
    if n.kind == "not":
        v = _truth(_eval(n.args[0], values))
        return None if v is None else not v
    if n.kind in ("eq", "ne"):
        a, b = (_eval(x, values) for x in n.args)
        if a is None or b is None:
            return None
        return (a == b) if n.kind == "eq" else (a != b)
    if n.kind in ("and", "or"):
        # `a and b and c` parses as ((a and b) and c): the chain's terms are gathered down its left side in a loop,
        # so a long one doesn't recurse once per term. Kleene's and/or are associative: the same answer either way.
        kind, terms = n.kind, []
        while n.kind == kind:
            terms.append(n.args[1])
            n = n.args[0]
        terms.append(n)
        got = [_truth(_eval(t, values)) for t in reversed(terms)]
        decides = kind == "or"                      # True decides an `or`, False an `and`
        if decides in got:
            return decides
        return None if None in got else not decides
    raise ExprError(f"bad node {n.kind}")
