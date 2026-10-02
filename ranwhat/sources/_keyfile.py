"""Reading one or two named settings out of a .env or simple YAML file.

These files sit beside API keys. Only lines that start with a name asked
for are looked at; every other line is skipped unread, and nothing from the
file is ever logged, printed or hashed.
"""

from __future__ import annotations

import re

# A .env or a config file is a few kilobytes. Past this it is something else.
MAX_BYTES = 1 << 20

_COMMENT = re.compile(r"\s#")


def _value(text):
    """The value after `=` or `:`, with matching quotes stripped. An
    unquoted value ends at a ` #` comment, as both formats define it."""
    text = text.strip()
    if text[:1] in ("'", '"'):
        end = text.find(text[0], 1)
        if end != -1:
            tail = text[end + 1:].strip()
            if not tail or tail.startswith("#"):
                return text[1:end]
        return text
    m = _COMMENT.search(text)
    return text[:m.start()].rstrip() if m else text


def read_keys(path, names):
    """{name: value} for each of `names` set in `path`, exactly as named.

    A line counts when it starts with the name (no indent, so a nested YAML
    key never matches) followed by `=` (.env, spaces around it allowed) or
    `:` and a space or the end of the line (a YAML scalar). The last
    setting of a name wins. A file that cannot be read gives {}."""
    wanted = set(n for n in names if n)
    found = {}
    if not wanted:
        return found
    try:
        with open(path, "r", encoding="utf-8", errors="replace",
                  newline="") as fh:
            text = fh.read(MAX_BYTES)
    except (OSError, ValueError):
        return found
    if text.startswith("\ufeff"):
        text = text[1:]
    for line in text.split("\n"):
        line = line.rstrip("\r")
        for name in wanted:
            if not line.startswith(name):
                continue
            rest = line[len(name):]
            after = rest.lstrip(" \t")
            if after.startswith("="):
                found[name] = _value(after[1:])
            elif rest.startswith(":") and (len(rest) == 1 or rest[1] in " \t"):
                found[name] = _value(rest[1:])
    return found
