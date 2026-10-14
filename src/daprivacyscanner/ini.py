"""A tolerant reader for the INI dialects desktop Linux uses: display manager configs (GDM,
SDDM, LightDM), KDE's KConfig files, Qt's QSettings files and .desktop files. configparser is too strict for them
(duplicate keys, KDE's nested [A][B] groups and [$i] flags, keys before any group)."""

from __future__ import annotations

import re

Group = tuple[str, ...]
_KDE_FLAGS = re.compile(r"\[\$[a-z]+\]$")
_KDE_ESCAPES = {"s": " ", "t": "\t", "n": "\n", "r": "\r", "\\": "\\"}


def parse(text: str, kde: bool = False) -> dict[Group, dict[str, str]]:
    """{group: {key: value}}. The last occurrence of a key wins. Keys before any group are in
    group (). A header "[A][B]" is the group ("A", "B"). With `kde`, [$i]-style flags are
    removed from keys and groups, and KConfig escapes (\\s, \\n, ...) are decoded."""
    out: dict[Group, dict[str, str]] = {(): {}}
    group: Group = ()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            if kde:
                line = _KDE_FLAGS.sub("", line)
            group = tuple(part for part in line[1:-1].split("][")) if kde else (line[1:-1].strip(),)
            out.setdefault(group, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if kde:
            key = _KDE_FLAGS.sub("", key)
            value = _kde_unescape(value)
        out[group][key] = value
    return out


def merge(*parsed: dict[Group, dict[str, str]]) -> dict[Group, dict[str, str]]:
    """Layered config files, lowest precedence first (e.g. drop-in directories)."""
    out: dict[Group, dict[str, str]] = {}
    for p in parsed:
        for group, keys in p.items():
            out.setdefault(group, {}).update(keys)
    return out


def get(parsed: dict[Group, dict[str, str]], group: str | Group, key: str) -> str | None:
    g = (group,) if isinstance(group, str) else tuple(group)
    return parsed.get(g, {}).get(key)


def truthy(value: str | None) -> bool | None:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("true", "yes", "on", "1"):
        return True
    if v in ("false", "no", "off", "0", ""):
        return False
    return None


def _kde_unescape(v: str) -> str:
    if "\\" not in v:
        return v
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v) and v[i + 1] in _KDE_ESCAPES:
            out.append(_KDE_ESCAPES[v[i + 1]])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


# ------------------------------------------------------------------ QSettings (Qt's INI format)

_QS_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", '"': '"', "\\": "\\"}
_QS_ESCAPE = {v: k for k, v in _QS_ESCAPES.items()}


def qsettings_value(raw: str) -> str:
    """A QSettings string as it is stored in an INI file: quoted when it has to be, with the C escapes
    QSettings writes (a backslash before n, quote, backslash; x and hex digits for other control characters)."""
    raw = raw.strip()
    if not (len(raw) >= 2 and raw[0] == raw[-1] == '"'):
        return raw
    return re.sub(r'\\(x[0-9a-fA-F]{1,4}|.)',
                  lambda m: chr(int(m.group(1)[1:], 16)) if m.group(1)[0] == "x" and len(m.group(1)) > 1
                  else _QS_ESCAPES.get(m.group(1), m.group(1)), raw[1:-1])


def qsettings_quote(value: str) -> str:
    """A string as QSettings stores it in an INI file (the reverse of qsettings_value)."""
    plain = value == value.strip() and not any(c in value for c in '",;=\\') and value.isprintable()
    if plain:
        return value
    out, hexed = [], False
    for c in value:
        if c in _QS_ESCAPE:
            out.append("\\" + _QS_ESCAPE[c])
        elif not c.isprintable() and c != " " or hexed and c in "0123456789abcdefABCDEF":
            out.append(f"\\x{ord(c):x}")      # as Qt does, a hex digit after one is escaped too
            hexed = True
            continue
        else:
            out.append(c)
        hexed = False
    return '"' + "".join(out) + '"'


def qsettings_list(raw: str) -> list[str]:
    """A QStringList as QSettings stores it: comma-separated, items with a comma quoted."""
    return [qsettings_value(x) for x in re.findall(r'\s*("(?:[^"\\]|\\.)*"|[^,]*)\s*(?:,|$)', raw) if x.strip()]


def qsettings_array(parsed: dict[Group, dict[str, str]], group: str) -> list[dict[str, str]]:
    """A QSettings array ([group] N\\key=value, numbered from 1, and size=), in order; values as stored."""
    entries: dict[int, dict[str, str]] = {}
    for key, value in parsed.get((group,), {}).items():
        n, _, prop = key.partition("\\")
        if prop and n.isdigit():
            entries.setdefault(int(n), {})[prop] = value
    return [entries[n] for n in sorted(entries)]


def qsettings_set_array(text: str | None, group: str, entries: list[dict[str, str]]) -> str:
    """`text` with the array's group written anew from `entries` (values as stored), the rest left as it is;
    the group is added at the end when there was none, and removed when `entries` is empty."""
    lines = (text or "").splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.strip() == f"[{group}]"), None)
    end = start
    if start is not None:
        end = next((i for i in range(start + 1, len(lines)) if lines[i].strip().startswith("[")), len(lines))
        kept = [ln for ln in lines[start + 1:end] if "=" in ln and not re.match(r"\s*(\d+\\|size\s*=)", ln)]
        before, after = lines[:start], lines[end:]
    else:
        kept, before, after = [], lines, []
    while before and not before[-1].strip():
        before.pop()
    section = [f"{n}\\{k}={v}" for n, e in enumerate(entries, 1) for k, v in e.items()] + kept
    if entries:
        section.append(f"size={len(entries)}")
    out = before + ([""] if before and section else []) + ([f"[{group}]"] + section if section else [])
    out += [""] + after if after else []
    return "\n".join(out).strip("\n") + "\n" if any(ln.strip() for ln in out) else ""


def qsettings_set(text: str | None, group: str, key: str, value: str | None) -> str:
    """`text` with one key of a QSettings group set to `value` (as stored; None removes it), every other line left
    as it is: the key's line changed where it is, or added at the end of its group, or the group added at the end
    of the file. A group left empty by a removal goes too."""
    lines = (text or "").splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.strip() == f"[{group}]"), None)
    if start is None:
        if value is None:
            return text or ""
        while lines and not lines[-1].strip():
            lines.pop()
        return "\n".join(lines + ([""] if lines else []) + [f"[{group}]", f"{key}={value}"]) + "\n"
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip().startswith("[")), len(lines))
    at = next((i for i in range(start + 1, end) if lines[i].split("=", 1)[0].strip() == key and "=" in lines[i]), None)
    if value is None:
        if at is None:
            return text or ""
        del lines[at]
        end -= 1
        if not any(ln.strip() for ln in lines[start + 1:end]):
            del lines[start:end]
            while start < len(lines) and start > 0 and not lines[start - 1].strip() and not lines[start].strip():
                del lines[start]
    elif at is not None:
        lines[at] = f"{key}={value}"
    else:
        last = end
        while last > start + 1 and not lines[last - 1].strip():
            last -= 1
        lines.insert(last, f"{key}={value}")
    out = "\n".join(lines).strip("\n")
    return out + "\n" if out else ""


def qsettings_get(text: str | None, group: str, key: str) -> str | None:
    """One key of a QSettings group, as stored; None when it isn't set."""
    return get(parse(text or ""), group, key)
