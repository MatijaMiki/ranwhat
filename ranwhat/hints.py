"""Hints: a dim line or two pointing at something the output just made
relevant, such as the feed, under a report that found scopes the bundled
catalogue could not rate.

A hint is advice nobody asked for, so the rules make it easy to ignore and
impossible to trip over:

  Only on a terminal. On a pipe it would end up in a log, or in the input
  of a script that never asked for it.

  Never with --json. That output is read by a program, and the caller says
  so (json=True) rather than this module guessing from argv.

  Once per key in a process, however many reports earn it.

  RANWHAT_NO_HINTS=1 turns every one off.

  Decided offline. Nothing here reaches the network or imports anything
  that can, so a hint is never why a command went online: whatever one
  depends on, the caller has already read from this machine.
"""
from __future__ import annotations

import os
import sys

from . import term

_SHOWN = set()


def silenced():
    """RANWHAT_NO_HINTS set to anything but empty or 0."""
    return os.environ.get("RANWHAT_NO_HINTS", "").strip() not in ("", "0")


def allowed(key, stream=None, json=False):
    """Whether hint() would write `key` now. For a caller whose lines cost
    something to work out, so it can skip that when nothing would print."""
    if json or key in _SHOWN or silenced():
        return False
    stream = stream if stream is not None else sys.stderr
    try:
        return bool(stream.isatty())
    except Exception:             # no isatty, or a closed stream
        return False


def hint(key, lines, stream=None, json=False):
    """Write `lines` dim to `stream` (stderr when not given), each as it is,
    and return whether they were written."""
    stream = stream if stream is not None else sys.stderr
    if not lines or not allowed(key, stream, json):
        return False
    _SHOWN.add(key)
    try:
        # stdout first, so on a shared terminal the hint lands under the
        # output it follows rather than inside it.
        sys.stdout.flush()
        stream.write("".join(term.paint("2", line, stream) + "\n" for line in lines))
        stream.flush()
    except Exception:
        # A hint is never worth an error: what it follows has printed.
        pass
    return True


def reset():
    """Forget which hints were shown. For tests."""
    _SHOWN.clear()
