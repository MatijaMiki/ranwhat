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

The values found in a file grow with it, so nothing here asks each value
of the whole file, or of every string in it: every form of every value is
found in one pass over the text (_Forms), and the new text is built in
one more. Searching the file once per form, and every string of every
line once per value, was quadratic: a Codex rollout of 2,700 keys, a
megabyte, took 3.9 seconds to mask, sixteen times what a quarter of it
took.
"""

from __future__ import annotations

import json
import os
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


def _marker(value):
    from .. import clean            # not at import: sources never import clean
    return clean.REDACTION % clean._fingerprint(value)


def _plan(values):
    """[(value, marker)] for the distinct non-empty values, longest first."""
    distinct = sorted(set(v for v in values if isinstance(v, str) and v),
                      key=lambda v: (-len(v), v))
    return [(v, _marker(v)) for v in distinct]


# How _Forms finds its strings: (shortest, window, stride). A form at
# least `shortest` long holds, wherever it starts, one of the windows of
# the text that start every `stride` characters, a whole window of
# `window` characters (window + stride - 1 <= shortest). So the text is
# read one window every `stride` characters, each looked up among the
# windows the forms hold at `stride` offsets in a row. A form shorter than
# the last tier, which no rule of clean's finds (a password in a URL is at
# least four characters), is looked for by itself.
_TIERS = ((24, 12, 13), (12, 6, 7), (6, 3, 4), (4, 4, 1))


class _Forms(object):
    """Strings to replace, each with what replaces it and its rank, and
    every place any of them occurs in a text, found in one pass over it
    whatever their number.

    A form's windows are taken where the other forms hold them least:
    keys that share a prefix (sk-ant-api03-, a JWT's header) would
    otherwise all be asked at every copy of it."""

    def __init__(self, entries):
        """entries: (form, replacement, rank, bounded) for each form; a
        bounded one counts only between [ or , and , or ] (a byte list)."""
        self.forms = []             # distinct forms
        self.entries = []           # per form: [(rank, replacement, bounded)]
        ids = {}
        for form, replacement, rank, bounded in entries:
            if not form:
                continue
            i = ids.get(form)
            if i is None:
                i = ids[form] = len(self.forms)
                self.forms.append(form)
                self.entries.append([])
            self.entries[i].append((rank, replacement, bounded))
        self.short = []             # form ids looked for by themselves
        self.tiers = []             # (window, stride, {window: [(id, offset)]})
        tiers = [[] for _ in _TIERS]
        for i, form in enumerate(self.forms):
            for t, (shortest, _window, _stride) in enumerate(_TIERS):
                if len(form) >= shortest:
                    tiers[t].append(i)
                    break
            else:
                self.short.append(i)
        for (_shortest, window, stride), ids in zip(_TIERS, tiers):
            if ids:
                self.tiers.append((window, stride,
                                   self._index(ids, window, stride)))

    @classmethod
    def encoded(cls, plan, byte_arrays=False):
        """Every encoding of every value in `plan`, [(value, marker)]
        longest first, each replaced by the marker, ranked as replacing
        each in turn would: value by value, and each value's forms longest
        first, then its byte list."""
        entries = []
        for value, marker in plan:
            for form in encodings(value):
                entries.append((form, marker, len(entries), False))
            if byte_arrays:
                entries.append((_byte_list(value), _byte_list(marker),
                                len(entries), True))
        return cls(entries)

    @classmethod
    def raw(cls, plan):
        """The values themselves, for the strings of decoded JSON."""
        return cls([(value, marker, rank, False)
                    for rank, (value, marker) in enumerate(plan)])

    def _index(self, ids, window, stride):
        shared = {}
        for i in ids:
            form = self.forms[i]
            for key in {form[o:o + window]
                        for o in range(len(form) - window + 1)}:
                shared[key] = shared.get(key, 0) + 1
        index = {}
        for i in ids:
            form = self.forms[i]
            costs = [shared[form[o:o + window]]
                     for o in range(len(form) - window + 1)]
            # `stride` windows in a row, from the least shared start
            total = best = sum(costs[:stride])
            base = 0
            for b in range(1, len(costs) - stride + 1):
                total += costs[b + stride - 1] - costs[b - 1]
                if total < best:
                    best, base = total, b
            for o in range(base, base + stride):
                index.setdefault(form[o:o + window], []).append((i, o))
        return index

    def occurrences(self, text):
        """(start, form id) for every place a form occurs in `text`,
        overlapping ones too, in no particular order."""
        found = []
        forms = self.forms
        for window, stride, index in self.tiers:
            get = index.get
            for i in range(0, len(text) - window + 1, stride):
                hits = get(text[i:i + window])
                if hits is not None:
                    for fid, offset in hits:
                        start = i - offset
                        if start >= 0 and text.startswith(forms[fid], start):
                            found.append((start, fid))
        for fid in self.short:
            form = forms[fid]
            at = text.find(form)
            while at != -1:
                found.append((at, fid))
                at = text.find(form, at + 1)
        return found

    def _candidates(self, text, found):
        """(rank, start, end, replacement) for each entry of each place
        found that may be replaced there."""
        out = []
        for start, fid in found:
            end = start + len(self.forms[fid])
            for rank, replacement, bounded in self.entries[fid]:
                if bounded and not _between_items(text, start, end):
                    continue
                out.append((rank, start, end, replacement))
        return out

    def replace(self, text):
        """`text` with every form replaced, as replacing each in turn, by
        rank, would have it (_claims), built in one pass."""
        candidates = self._candidates(text, self.occurrences(text))
        if not candidates:
            return text
        return _apply(text, _claims(candidates, len(text)))

    def occur_in(self, text):
        """True when any form occurs in `text`."""
        return bool(self._candidates(text, self.occurrences(text)))

    def mask_each(self, texts):
        """`texts` with every form replaced in each, one pass over all of
        them together; `texts` itself when none holds any."""
        joined = "\0".join(texts)
        found = self.occurrences(joined)
        if not found:
            return texts
        starts, at = [], 0
        for text in texts:
            starts.append(at)
            at += len(text) + 1
        per, k, last = {}, 0, len(starts) - 1
        for start, fid in sorted(found):
            while k < last and starts[k + 1] <= start:
                k += 1
            begin = start - starts[k]
            end = begin + len(self.forms[fid])
            if end > len(texts[k]):
                continue            # across the join of two strings
            for rank, replacement, _bounded in self.entries[fid]:
                per.setdefault(k, []).append((rank, begin, end, replacement))
        if not per:
            return texts
        out = list(texts)
        for k, candidates in per.items():
            out[k] = _apply(texts[k], _claims(candidates, len(texts[k])))
        return out


def _between_items(text, start, end):
    """True when text[start:end] is whole items of a JSON integer list."""
    return (start > 0 and text[start - 1] in "[,"
            and end < len(text) and text[end] in ",]")


def _claims(candidates, size):
    """(start, end, replacement) for the candidates, (rank, start, end,
    replacement), that replacing each rank in turn, left to right, would
    make: each the first of its rank that overlaps no claim before it.
    Sorted by start."""
    by_start = sorted((c[1], c[2], c[0], c[3]) for c in candidates)
    if all(a[1] <= b[0] for a, b in zip(by_start, by_start[1:])):
        return [(start, end, rep) for start, end, _rank, rep in by_start]
    taken = bytearray(size)
    chosen = []
    for rank, start, end, rep in sorted(candidates):
        if taken.find(1, start, end) == -1:
            taken[start:end] = b"\x01" * (end - start)
            chosen.append((start, end, rep))
    chosen.sort()
    return chosen


def _apply(text, claims):
    out, at = [], 0
    for start, end, rep in claims:
        out.append(text[at:start])
        out.append(rep)
        at = end
    out.append(text[at:])
    return "".join(out)


def _replace_text(text, plan, byte_arrays, forms=None):
    """`text` with every encoding of every value in `plan` replaced by its
    marker (and for a byte-array format, every byte list of one)."""
    forms = forms or _Forms.encoded(plan, byte_arrays)
    return forms.replace(text)


def _leftover(text, plan, byte_arrays, forms=None):
    """True when any encoding of any value is still in `text`."""
    forms = forms or _Forms.encoded(plan, byte_arrays)
    return forms.occur_in(text)


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


def _is_byte_array(node):
    return bool(node) and all(type(v) is int and 0 <= v <= 255 for v in node)


def _texts(node, byte_arrays, out):
    """Every string, key and nested JSON string of a decoded structure
    (and, for byte-array formats, every array of bytes read as UTF-8),
    appended to `out` in the order _rebuild takes them back."""
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, list):
        if byte_arrays and _is_byte_array(node):
            out.append(bytes(node).decode("utf-8", "surrogateescape"))
        else:
            for v in node:
                _texts(v, byte_arrays, out)
    elif isinstance(node, tuple) and node[0] == "obj":
        for k, v in node[1]:
            out.append(k)
            _texts(v, byte_arrays, out)
    elif isinstance(node, tuple) and node[0] == "json":
        _texts(node[1], byte_arrays, out)
    return out


def _rebuild(node, byte_arrays, texts):
    """The structure with each of its _texts taken, in turn, from the
    iterator `texts`."""
    if isinstance(node, str):
        return next(texts)
    if isinstance(node, list):
        if byte_arrays and _is_byte_array(node):
            return list(_utf8(next(texts)))
        return [_rebuild(v, byte_arrays, texts) for v in node]
    if isinstance(node, tuple) and node[0] == "obj":
        return ("obj", tuple((next(texts), _rebuild(v, byte_arrays, texts))
                             for k, v in node[1]))
    if isinstance(node, tuple) and node[0] == "json":
        return ("json", _rebuild(node[1], byte_arrays, texts))
    return node


def _mask(node, raw, byte_arrays):
    """The decoded structure with every value (_Forms.raw) masked in every
    string, key and nested JSON string (and, for byte-array formats, in
    every array of bytes read as UTF-8). The node itself when none holds
    one."""
    texts = _texts(node, byte_arrays, [])
    masked = raw.mask_each(texts)
    if masked is texts:
        return node
    return _rebuild(node, byte_arrays, iter(masked))


def _same_but_masked(old, new, raw, byte_arrays, before=None):
    """True when `new` decodes to `old` decoded and masked. False when it
    does not, when `new` does not decode, or when the check cannot run.
    `before`, when given, is `old` decoded already; `new` None is `old`
    unchanged."""
    try:
        if before is None:
            before = _decode(old)
        before = _expand(before)
        after = before if new is None else _expand(_decode(new))
        return after == _mask(before, raw, byte_arrays)
    except (ValueError, RecursionError):
        return False


def _verify(kind, old, new, plan, byte_arrays, forms=None):
    """True when `new` changes nothing in `old` but the secret. Each line
    is decoded once, and the values looked for in all its strings at
    once, so the check costs what reading the file does."""
    if _leftover(new, plan, byte_arrays, forms):
        return False
    if kind == "json":
        return _same_but_masked(old.lstrip("\ufeff"), new.lstrip("\ufeff"),
                                _Forms.raw(plan), byte_arrays)
    old_lines, new_lines = old.split("\n"), new.split("\n")
    if len(old_lines) != len(new_lines):
        return False
    if kind == "text":
        return True
    raw = _Forms.raw(plan)
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
        try:
            decoded = _decode(was)
        except (ValueError, RecursionError):
            continue            # not JSON before: only the raw text changed
        # An untouched line with escapes may still hold a value in a form
        # no encoding has: it is checked against itself, masked.
        if not _same_but_masked(was, None if was == now else now, raw,
                                byte_arrays, before=decoded):
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
    forms = _Forms.encoded(plan, byte_arrays)
    new = forms.replace(old)
    if new == old:
        return MaskResult(path)             # nothing to mask: a second run
    if (time.time() if now is None else now) - st0.st_mtime < QUIET_SECONDS:
        return MaskResult(path, skipped=IN_USE)
    if not _verify(kind, old, new, plan, byte_arrays, forms):
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
