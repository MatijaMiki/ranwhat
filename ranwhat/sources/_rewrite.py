"""Masking a secret in a file whose writer is someone else's code.

The file is changed byte for byte where the secret was, and nowhere else.
Re-serialising would also change key order, spacing and escapes, which a
writer we do not control might care about. So every encoding the value can
take in the file is replaced in the raw text, and the result is checked
before it is installed:

- jsonl: the same number of lines; every line that parsed still parses;
  and each line decodes to exactly what the old line decodes to with the
  values masked in its strings (and in strings that are JSON themselves).
- json: the same check on the whole document.
- text: the same number of lines.
- always: no encoding of any value is left.

Anything else refuses the file. A file written in the last QUIET_SECONDS is
refused too: an agent appending to it would keep writing to the old inode
after the replace, and lose everything it wrote. That is worse than the
secret.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time

from .base import MaskResult

QUIET_SECONDS = 120

KINDS = ("jsonl", "json", "text")

IN_USE = "in use"
CHANGED = "changed while reading"
ALTERED = "would alter more than the secret"
READ_ONLY = "read-only"

TMP_SUFFIX = ".ranwhat-tmp"

# Patched by tests: os.replace refusing with PermissionError means another
# process has the file open only on Windows.
_WINDOWS = os.name == "nt"

# The same flags as clean._write_like: O_NOFOLLOW so a symlink planted at
# the temp path fails the write, O_BINARY so Windows writes bytes as given.
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
           | getattr(os, "O_BINARY", 0))

# JSON nested in a JSON string, nested in a JSON string...: this many levels
# are opened when checking a line. Deeper text is compared as text.
_NEST_MAX = 4

_GO_ESCAPES = (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
               ("\u2028", "\\u2028"), ("\u2029", "\\u2029"))


def _body(value, ascii_only):
    """The value as it sits between the quotes of a JSON string."""
    return json.dumps(value, ensure_ascii=ascii_only)[1:-1]


def _go_body(value):
    """Go encoding/json's form: also \\u0026, \\u003c, \\u003e for &, <, >,
    and \\u2028, \\u2029, which Go always escapes."""
    out = _body(value, False)
    for raw, escaped in _GO_ESCAPES:
        out = out.replace(raw, escaped)
    return out


def encodings(value):
    """Every form `value` can take in the text of a JSON or text file,
    longest first: itself, its JSON string body (Unicode and ASCII), Go's
    form, and the JSON body of each JSON body (a value inside a JSON string
    inside a JSON line, like a function call's arguments)."""
    forms = {value, _body(value, False), _body(value, True), _go_body(value)}
    for once in (_body(value, False), _body(value, True)):
        forms.add(_body(once, False))
        forms.add(_body(once, True))
    forms.discard("")
    return sorted(forms, key=lambda f: (-len(f), f))


def _utf8(text):
    """UTF-8 bytes, with bytes that were not UTF-8 (surrogateescape) given
    back as they were. A lone surrogate from a JSON escape has no such byte
    and is encoded as itself."""
    try:
        return text.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return text.encode("utf-8", "surrogatepass")


def _byte_list(text):
    """The UTF-8 bytes of `text` as the inside of a compact JSON integer
    list: "115,107,95"."""
    return ",".join(str(b) for b in _utf8(text))


def _byte_pattern(value):
    """The value's bytes as whole numbers inside a JSON integer list: the
    match must start after [ or , and end before , or ]."""
    return re.compile(r"(?<=[\[,])" + re.escape(_byte_list(value))
                      + r"(?=[,\]])")


def _marker(value):
    from .. import clean            # not at import: sources never import clean
    return clean.REDACTION % clean._fingerprint(value)


def _plan(values):
    """[(value, marker)] for the distinct non-empty values, longest first."""
    distinct = sorted(set(v for v in values if isinstance(v, str) and v),
                      key=lambda v: (-len(v), v))
    return [(v, _marker(v)) for v in distinct]


def _replace_text(text, plan, byte_arrays):
    for value, marker in plan:
        for form in encodings(value):
            if form in text:
                text = text.replace(form, marker)
        if byte_arrays:
            text = _byte_pattern(value).sub(_byte_list(marker), text)
    return text


def _leftover(text, plan, byte_arrays):
    """True when any encoding of any value is still in `text`."""
    for value, _marker_text in plan:
        if any(form in text for form in encodings(value)):
            return True
        if byte_arrays and _byte_pattern(value).search(text):
            return True
    return False


# Decoding for the check. Objects become ("obj", pairs) so key order and
# duplicate keys are compared too; NaN and Infinity become ("const", name)
# so they compare equal to themselves; a string that is itself a JSON object
# or array becomes ("json", decoded). json never produces a tuple, so the
# tags cannot collide with data.

def _pairs(pairs):
    return ("obj", tuple(pairs))


def _const(name):
    return ("const", name)


def _decode(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_const)


def _expand(node, depth=0):
    if isinstance(node, str):
        if depth < _NEST_MAX and node.lstrip()[:1] in ("{", "["):
            try:
                inner = _decode(node)
            except ValueError:
                return node
            if isinstance(inner, list) or (isinstance(inner, tuple)
                                           and inner[0] == "obj"):
                return ("json", _expand(inner, depth + 1))
        return node
    if isinstance(node, list):
        return [_expand(v, depth) for v in node]
    if isinstance(node, tuple) and node[0] == "obj":
        return ("obj", tuple((k, _expand(v, depth)) for k, v in node[1]))
    return node


def _mask_str(text, plan):
    for value, marker in plan:
        if value in text:
            text = text.replace(value, marker)
    return text


def _is_byte_array(node):
    return bool(node) and all(type(v) is int and 0 <= v <= 255 for v in node)


def _mask(node, plan, byte_arrays):
    """The decoded structure with every value masked in every string, key
    and nested JSON string (and, for byte-array formats, in every array of
    bytes read as UTF-8)."""
    if isinstance(node, str):
        return _mask_str(node, plan)
    if isinstance(node, list):
        if byte_arrays and _is_byte_array(node):
            text = bytes(node).decode("utf-8", "surrogateescape")
            return list(_utf8(_mask_str(text, plan)))
        return [_mask(v, plan, byte_arrays) for v in node]
    if isinstance(node, tuple) and node[0] == "obj":
        return ("obj", tuple((_mask_str(k, plan), _mask(v, plan, byte_arrays))
                             for k, v in node[1]))
    if isinstance(node, tuple) and node[0] == "json":
        return ("json", _mask(node[1], plan, byte_arrays))
    return node


def _same_but_masked(old, new, plan, byte_arrays):
    """True when `new` decodes to `old` decoded and masked. False when it
    does not, when `new` does not decode, or when the check cannot run."""
    try:
        before = _expand(_decode(old))
        after = _expand(_decode(new))
        return after == _mask(before, plan, byte_arrays)
    except (ValueError, RecursionError):
        return False


def _parses(text):
    try:
        _decode(text)
        return True
    except (ValueError, RecursionError):
        return False


def _verify(kind, old, new, plan, byte_arrays):
    """True when `new` changes nothing in `old` but the secret."""
    if _leftover(new, plan, byte_arrays):
        return False
    if kind == "json":
        return _same_but_masked(old.lstrip("\ufeff"), new.lstrip("\ufeff"),
                                plan, byte_arrays)
    old_lines, new_lines = old.split("\n"), new.split("\n")
    if len(old_lines) != len(new_lines):
        return False
    if kind == "text":
        return True
    for index, (was, now) in enumerate(zip(old_lines, new_lines)):
        if index == 0:
            was, now = was.lstrip("\ufeff"), now.lstrip("\ufeff")
        was, now = was.rstrip("\r"), now.rstrip("\r")
        if not was.strip():
            if now != was:
                return False
            continue
        # A line with no escapes holds every string exactly as written, so
        # a value in any of them was in the raw text, and the raw text was
        # masked: an untouched line like that has nothing left to check.
        if was == now and "\\" not in was and not byte_arrays:
            continue
        if not _parses(was):
            continue            # not JSON before: only the raw text changed
        if not _same_but_masked(was, now, plan, byte_arrays):
            return False
    return True


def _install(path, st0, data):
    """Steps 6 to 8: write beside the file with its mode, check it has not
    changed since it was read, and replace it. Returns None or a reason."""
    tmp = path + TMP_SUFFIX
    try:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        fd = os.open(tmp, _CREATE, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
            if os.name != "nt":
                os.fchmod(fh.fileno(), stat.S_IMODE(st0.st_mode))
        st1 = os.stat(path)
        if (st1.st_size != st0.st_size or st1.st_mtime_ns != st0.st_mtime_ns
                or (st0.st_ino and st1.st_ino != st0.st_ino)):
            return CHANGED
        try:
            os.replace(tmp, path)
        except PermissionError:
            if _WINDOWS:
                return IN_USE
            raise
        return None
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def rewrite_file(path, values, kind, byte_arrays=False, now=None):
    """Mask every value in the file at `path` and return a MaskResult.

    kind is the store's format: "jsonl", "json" or "text"; anything else
    (sqlite, jsonl.zst) is read-only and never opened for writing.
    byte_arrays: the format also carries text as JSON lists of bytes
    (Grok Build). A symlink is followed, so the file that holds the secret
    is the one masked. Raises OSError only for a failure none of the
    MaskResult reasons describe (a directory that cannot be written)."""
    if kind not in KINDS:
        return MaskResult(path, skipped=READ_ONLY)
    plan = _plan(values)
    if not plan:
        return MaskResult(path)
    real = os.path.realpath(path)
    st0 = os.stat(real)
    if not stat.S_ISREG(st0.st_mode):
        return MaskResult(path, skipped=READ_ONLY)
    with open(real, "rb") as fh:
        raw = fh.read()
    old = raw.decode("utf-8", "surrogateescape")
    new = _replace_text(old, plan, byte_arrays)
    if new == old:
        return MaskResult(path)             # nothing to mask: a second run
    if (time.time() if now is None else now) - st0.st_mtime < QUIET_SECONDS:
        return MaskResult(path, skipped=IN_USE)
    if not _verify(kind, old, new, plan, byte_arrays):
        return MaskResult(path, skipped=ALTERED)
    from .. import clean
    backup = clean._backup(real)
    try:
        reason = _install(real, st0, new.encode("utf-8", "surrogateescape"))
    except BaseException:
        _discard(backup)
        raise
    if reason:
        # Nothing was installed, so the copy is only one more place the
        # secret is written down.
        _discard(backup)
        return MaskResult(path, skipped=reason)
    return MaskResult(path, changed=True, backup=backup)


def _discard(backup):
    try:
        os.unlink(backup)
    except OSError:
        pass
