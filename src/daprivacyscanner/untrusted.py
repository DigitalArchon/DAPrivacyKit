"""JSON from outside the app, read with a limit on how deep it nests (the DA apps' one security standard,
2026-11-14): an online test's or GitHub's answer, a browser's download index, the page's requests to the server,
online.json. Python's parser recurses: an answer of a few MB of "[" raised RecursionError, which no `except
ValueError` caught, and anything nested deeper than any real answer is refused all the same. The helper, which
imports nothing of the app's, has its own copy of the walk (helper._loads)."""

from __future__ import annotations

import json
from typing import Any

MAX_DEPTH = 200


class TooDeep(ValueError):
    """Nested deeper than MAX_DEPTH levels: a ValueError, so whatever refuses an unreadable answer refuses it too."""


def nests_deeper(data: Any, limit: int = MAX_DEPTH) -> bool:
    """Whether `data` (as json.loads made it) nests past `limit` levels. Walked, never recursed into."""
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(item, dict):
            children: Any = item.values()
        elif isinstance(item, list):
            children = item
        else:
            continue
        stack.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    return False


def loads(text: str | bytes | bytearray) -> Any:
    """json.loads, refusing (TooDeep) what nests past MAX_DEPTH, whether the parser itself gave up (RecursionError)
    or not."""
    try:
        data = json.loads(text)
    except RecursionError:
        raise TooDeep(f"it nests far deeper than {MAX_DEPTH} levels") from None
    if nests_deeper(data):
        raise TooDeep(f"it nests deeper than {MAX_DEPTH} levels")
    return data
