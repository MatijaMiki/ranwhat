"""Timestamps, in whatever unit the agent wrote them, as ISO 8601.

Each adapter names its unit. Nothing here guesses one from the size of the
number: watch._as_iso divides by 1000 once above 1e11, which turns Muse
Code's microsecond recorded_at (about 1.79e15) into the year 58000.
"""

from __future__ import annotations

import datetime
import re

_DIVISOR = {"s": 1.0, "ms": 1e3, "us": 1e6}

# Below this many seconds since 1970 (March 1973) a number is not a time any
# agent recorded: it is an unset field, or a value given the wrong unit.
_PLAUSIBLE = 1e8

_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_NUMBER = re.compile(r"\s*[0-9]+(?:\.[0-9]*)?\s*\Z")

_STAMP = re.compile(
    r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,]\d+)?"
    r"\s*(Z|[+-]\d\d(?::?\d\d)?)?\Z", re.I)


def parse_stamp(stamp):
    """(datetime, zoned) for an ISO 8601 timestamp, or (None, False). Parsed
    by hand: Python 3.9's fromisoformat takes neither Z nor every fraction.

    Same behaviour as watch._parse_stamp, which it replaces."""
    m = _STAMP.match(stamp.strip()) if isinstance(stamp, str) else None
    if not m:
        return None, False
    zone = m.group(7)
    try:
        when = datetime.datetime(*(int(g) for g in m.groups()[:6]))
        if zone:
            if zone.upper() == "Z":
                tz = datetime.timezone.utc
            else:
                digits = zone[1:].replace(":", "")
                offset = datetime.timedelta(hours=int(digits[:2]),
                                            minutes=int(digits[2:4] or 0))
                tz = datetime.timezone(-offset if zone[0] == "-" else offset)
            when = when.replace(tzinfo=tz)
    except (ValueError, OverflowError):
        return None, False
    return when, bool(zone)


def iso_utc(value, unit):
    """`value` as "YYYY-MM-DDTHH:MM:SSZ", or None when it is not a time.

    unit is "s", "ms" or "us" for a number (an int, a float, or a string of
    digits, as some databases store them), or "iso" for a string. A zoned
    string is converted to UTC. A string with no zone is returned as
    written, stripped: which zone it meant is not known, and
    parse_stamp reads it as local time. Any other unit is a programming
    error and raises ValueError."""
    if unit == "iso":
        if not isinstance(value, str):
            return None
        when, zoned = parse_stamp(value)
        if when is None:
            return None
        if not zoned:
            return value.strip()
        try:
            return when.astimezone(datetime.timezone.utc).strftime(_FORMAT)
        except (ValueError, OverflowError):
            return None
    if unit not in _DIVISOR:
        raise ValueError("unknown timestamp unit %r" % (unit,))
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        if not _NUMBER.match(value):
            return None
        value = float(value)
    if not isinstance(value, (int, float)):
        return None
    try:
        seconds = value / _DIVISOR[unit]
        if not seconds >= _PLAUSIBLE:       # also catches NaN
            return None
        return datetime.datetime.fromtimestamp(
            seconds, datetime.timezone.utc).strftime(_FORMAT)
    except (ValueError, OverflowError, OSError):
        return None
