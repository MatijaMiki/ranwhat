"""Terminal presentation: width, rules and colour.

Width was hardcoded at 62 for rules and 70 for prose, which is unreadable in
both directions. On a narrow window the output wrapped twice, once by this
tool and again by the terminal, producing ragged half-lines. On a wide one it
used a third of the screen.

Colour honours NO_COLOR (no-color.org) and TERM=dumb, and only engages on a
tty, so piping to a file or a pager still produces plain text. colour() is
the one place that decides, for every module that paints.
"""
from __future__ import annotations

import os
import shutil
import sys

# Below this, indentation and bars cost more than they convey.
MIN_WIDTH = 46
# Prose stops being readable past roughly this many characters per line, so a
# wide terminal gets whitespace rather than very long measures.
MAX_WIDTH = 96

BRAND = (0xE9, 0x84, 0x71)


def width(stream=None):
    """Usable columns, clamped to something readable."""
    stream = stream or sys.stdout
    try:
        cols = shutil.get_terminal_size().columns
    except Exception:
        cols = 80
    if os.environ.get("RANWHAT_WIDTH"):
        try:
            cols = int(os.environ["RANWHAT_WIDTH"])
        except ValueError:
            pass
    return max(MIN_WIDTH, min(MAX_WIDTH, cols - 2))


def rule(char="─", stream=None):
    return "  " + char * (width(stream) - 2)


def _colour_depth(stream=None):
    """0 = none, 8 = basic ANSI, 24 = truecolour.

    NO_COLOR counts when set to anything but the empty string, as
    no-color.org defines it."""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return 0
    try:
        if not stream.isatty():
            return 0
    except Exception:             # no isatty, or a closed stream
        return 0
    if os.environ.get("TERM") == "dumb":
        return 0
    ct = os.environ.get("COLORTERM", "").lower()
    if "truecolor" in ct or "24bit" in ct:
        return 24
    return 8


def colour(stream=None):
    """Whether escapes may be written to `stream` (default stdout). Every
    colour in the package asks this, so NO_COLOR, TERM=dumb and a pipe turn
    all of it off, not only the wordmark."""
    return _colour_depth(stream) > 0


def sgr(code, s):
    """`s` in SGR `code`, for a caller that has asked colour() already."""
    return "\033[%sm%s\033[0m" % (code, s)


def paint(code, s, stream=None):
    """`s` in SGR `code`, or `s` as it is where colour() says no."""
    if not colour(stream):
        return s
    return sgr(code, s)


def brand(s, stream=None):
    """The wordmark colour, in truecolour where the terminal supports it.

    Falls back to plain ANSI rather than approximating: a wrong-looking orange
    is worse than no orange, and this is decoration, not information.
    """
    depth = _colour_depth(stream)
    if depth == 24:
        r, g, b = BRAND
        return "\033[38;2;%d;%d;%dm%s\033[0m" % (r, g, b, s)
    if depth == 8:
        return "\033[33m%s\033[0m" % s
    return s


def wrap(text, indent="  ", stream=None, first=None, limit=None):
    """Fold prose to the terminal, without importing textwrap for one job.

    `first` replaces `indent` on the first line only, for a bullet or a label
    with the rest of the text hanging under it. It counts against the width
    like any other text. A word longer than the line gets a line to itself.
    `limit` is the width, when the caller measured it already.
    """
    if limit is None:
        limit = width(stream)
    start = indent if first is None else first
    out, line = [], ""
    for word in text.split():
        lead = indent if out else start
        if line and len(lead) + len(line) + 1 + len(word) > limit:
            out.append(lead + line)
            line = word
        else:
            line = word if not line else line + " " + word
    if line:
        out.append((indent if out else start) + line)
    return out


# One copy, so check can print it once instead of once per section. Kept at
# 40 characters so it fits MIN_WIDTH without wrapping.
FOOTER = "  Read locally. Nothing was transmitted."


class Progress:
    """A single self-overwriting status line on stderr, for terminals only.

    Clearing with "\\r" plus spaces left a row of blanks at the top of the
    report on a terminal, and every fragment in a redirected log. So nothing
    is written unless the stream is a terminal, and the line is erased with
    EL ("\\033[K") instead. A failure here must never cost the report: the
    callback runs inside the scan, and an exception out of it means no
    findings are printed at all.
    """

    def __init__(self, stream=None):
        self.stream = stream if stream is not None else sys.stderr
        self.dirty = False
        try:
            self.enabled = bool(self.stream.isatty()
                                and os.environ.get("TERM") != "dumb")
        except Exception:
            self.enabled = False

    def _columns(self):
        # The stream's own terminal, not shutil.get_terminal_size(), which
        # measures stdout: with stdout redirected it answers 80 on a narrow
        # window, the line wraps, and "\r" can no longer reach its start.
        try:
            cols = os.get_terminal_size(self.stream.fileno()).columns
        except (AttributeError, ValueError, OSError):
            cols = 0
        return cols if cols > 0 else 80

    def update(self, text):
        if not self.enabled:
            return
        # Set first: a write that fails halfway may still have put text up.
        self.dirty = True
        room = self._columns() - 1
        if os.environ.get("RANWHAT_WIDTH"):
            room = min(room, width())         # as wide as the report, no wider
        try:
            self.stream.write("\r" + text[:max(1, room)] + "\033[K")
            self.stream.flush()
        except Exception:
            self.enabled = False

    def clear(self):
        if not self.dirty:
            return
        self.dirty = False
        try:
            self.stream.write("\r\033[K")
            self.stream.flush()
        except Exception:
            pass
