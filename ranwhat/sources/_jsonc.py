"""VS Code's settings.json: JSON with comments and trailing commas.

Used to read one setting (roo-cline.customStoragePath and the like) that
moves an extension's storage. Anything that does not come out as JSON is
None; the caller then looks in the default place.
"""

from __future__ import annotations

import json

# A settings file is kilobytes. Past this it is not one.
MAX_BYTES = 16 << 20


def strip(text):
    """`text` with // and /* */ comments outside strings removed and
    trailing commas before ] or } dropped, or None when a block comment is
    never closed. Line breaks are kept, so error positions stay meaningful."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif c == "/" and text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif c == "/" and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                return None
            out.append(" " + "\n" * text.count("\n", i, end))
            i = end + 2
        else:
            out.append(c)
            i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text):
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "]}":
                i += 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def loads(text):
    """The decoded document, or None."""
    if not isinstance(text, str):
        return None
    if text.startswith("\ufeff"):
        text = text[1:]
    cleaned = strip(text)
    if cleaned is None:
        return None
    try:
        return json.loads(cleaned)
    except (ValueError, RecursionError):
        return None


def load(path):
    """The decoded settings file, or None when it cannot be read or parsed."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(MAX_BYTES + 1)
    except (OSError, ValueError):
        return None
    if len(text) > MAX_BYTES:
        return None
    return loads(text)


def setting(path, key):
    """One top-level setting from a settings file, or None."""
    doc = load(path)
    return doc.get(key) if isinstance(doc, dict) else None
