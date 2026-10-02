"""JSON Lines, read the way every agent's writer means them.

Lines are split on b"\\n" only. str.splitlines() also breaks on U+2028,
U+2029, \\x1c to \\x1e, \\x85 and others, and Copilot CLI lines hold raw
U+2028; splitting there cuts a record in two and loses both halves.

Bytes that are not UTF-8 are decoded with surrogateescape, so they come
back unchanged if the text is ever written out again.
"""

from __future__ import annotations

import json

BOM = "\ufeff"


def decode_line(raw, first=False):
    """The text of one binary line: UTF-8 with surrogateescape, line ending
    stripped, and a byte order mark dropped from the first line."""
    text = raw.decode("utf-8", "surrogateescape").rstrip("\r\n")
    if first and text.startswith(BOM):
        text = text[1:]
    return text


def iter_json_lines(path, counts=None):
    """Yield (line_no, obj) for every line of `path` that is JSON.

    line_no counts from 1 and includes blank lines, so it matches what an
    editor shows. Blank lines are skipped. A complete line that does not
    parse is skipped and counted in counts["unparsed"] when `counts` is a
    dict. A last line with no newline that does not parse is a record the
    agent is still writing: skipped, not counted, no warning.

    Opening the file can raise OSError; the caller decides what to say."""
    with open(path, "rb") as fh:
        for index, raw in enumerate(fh, 1):
            text = decode_line(raw, first=index == 1)
            if not text.strip():
                continue
            try:
                obj = json.loads(text)
            except (ValueError, RecursionError):
                if raw.endswith(b"\n") and counts is not None:
                    counts["unparsed"] = counts.get("unparsed", 0) + 1
                continue
            yield index, obj
