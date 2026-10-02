"""What check and watch know of the values clean finds, kept between runs.

check and watch mask in what they print every value clean finds anywhere in
the history, whatever --days says: a password read in one session is no less
a password where a later command types it with no key beside it. They knew
such a value only through stretches of what they showed, looked up in the
transcripts within a budget, and a stretch could not isolate a value glued
to letters, digits or ._- inside a longer run: on a real history watch
printed values that clean finds and check masked.

So each transcript's values are kept in an index, one per transcript root,
under ranwhat's state directory (RANWHAT_HOME, ~/.ranwhat by default), and a
transcript is read again only when its size or modification time changes.
check's own read for secrets (clean.scan) hands the index what it finds, so
a transcript in its window is read for them once, not twice.

The index holds no value. For each it keeps 16 bits of a keyed BLAKE2b of
its first PREFIX characters (a tag a great many beginnings share, so it
tells whoever holds the key no more than 16 bits of them), its length, a
keyed BLAKE2b of the whole value, and a keyed BLAKE2b of the fingerprint its
mask keeps, so a value clean has masked is still known by the mask; clean
adds each value before it masks one. The key is 32 random bytes per install,
in a file of its own beside the index. Both are written 0600, never through
a symlink, and replaced whole. A damaged index, or one of another version or
key, is rebuilt. Where nothing can be written, it is built in memory each
run.

What a lost index knew of a value clean has masked is lost with it: the
transcripts keep only the mask's fingerprint, 48 bits of an unkeyed SHA-256
with no length. A copy the mask did not reach is then found by that
fingerprint, where a piece of what check and watch print is all of it, and
in what an action shows, every stretch of up to Matcher._STRETCH_LONGEST
characters, within a budget.

Text is masked by looking at every place a value could start: the PREFIX
characters there are hashed, and each value whose tag they have is
compared whole.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat

from . import agents, clean
from .watch import _transcripts, claude_projects

# 2: 16 bits of the head hash, not 64. An index of version 1 is read, its
# head hashes cut to that, and written again.
VERSION = 2
# A value clean returns is never shorter than this (clean._MIN_ASSIGNED),
# so its first PREFIX characters are always its own. A shorter one is
# looked for by all of it.
PREFIX = min(6, clean._MIN_ASSIGNED)

_HEAD_SIZE, _VALUE_SIZE, _MASK_SIZE, _KEY_ID_SIZE = 8, 16, 16, 8
# What is kept of the head hash. With the key, the whole 64 bits of it let
# anyone find the first six characters on their own, and then the rest:
# two small searches instead of one large one. 16 bits are shared by a
# great many beginnings, and save such a search no more than 16 bits;
# every place a tag leads to is confirmed by the hash of the whole value.
_TAG_SIZE = 2
_KEY_SIZE = 32

# O_NOFOLLOW: a symlink planted where the key or the index goes fails the
# write rather than sending it elsewhere. O_BINARY: Windows would otherwise
# open the descriptor in text mode.
_CREATE = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
           | getattr(os, "O_BINARY", 0))
_READ = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


def home():
    """ranwhat's state directory, as feed.home() names it. Not imported
    from there: feed imports the network stack, which check and watch
    never load."""
    return os.environ.get("RANWHAT_HOME") or os.path.join(
        os.path.expanduser("~"), ".ranwhat")


def index_dir():
    return os.path.join(home(), "known")


def _hasher(key, person, size):
    return hashlib.blake2b(digest_size=size, key=key, person=person)


class _Hashes(object):
    """The three keyed hashes, kept ready to copy: a copy of a keyed
    state costs less than keying a new one, at every place in a text.
    Of the head hash only its first _TAG_SIZE bytes are ever kept."""

    def __init__(self, key):
        self.head = _hasher(key, b"ranwhat:head", _HEAD_SIZE)
        self.value = _hasher(key, b"ranwhat:value", _VALUE_SIZE)
        self.mask = _hasher(key, b"ranwhat:mask", _MASK_SIZE)
        self.key_id = _hasher(key, b"ranwhat:key", _KEY_ID_SIZE).digest().hex()

    @staticmethod
    def _of(state, data):
        h = state.copy()
        h.update(data)
        return h.digest()

    def entry(self, value):
        """(tag, length, value, mask) for value: its hashes and length."""
        data = _bytes(value)
        head = _bytes(value[:PREFIX])
        return (self._of(self.head, head)[:_TAG_SIZE], len(value),
                self._of(self.value, data), self.of_mask(clean._fingerprint(value)))

    def of_mask(self, fingerprint):
        return self._of(self.mask, fingerprint.encode("ascii", "replace"))


def _bytes(text):
    # Every character as itself, a lone half of a surrogate pair too:
    # json.loads gives one for an escaped \\ud800, and it is still a copy.
    return text.encode("utf-8", "surrogatepass")


def _merge(spans):
    merged = []
    for lo, hi in sorted(spans):
        if merged and lo < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


class Matcher(object):
    """Every value the index knows, ready to be found in text: where each
    copy is (spans), or text with each masked as clean masks one (mask).
    False when it knows none."""

    _CACHED = 64
    # A value known only by its mask is looked for, in what an action
    # shows (merged with shown), in every stretch of each run between
    # blanks and quotes from clean._MIN_ASSIGNED characters up to this
    # many: one glued to letters or digits on both sides (old<VALUE>9) is
    # no piece of anything else there. Up to this many stretches are
    # hashed for it in all, about a second's worth; past it, and in all
    # else, it is found where a piece of the text is all of it.
    _STRETCH_LONGEST = 64
    _STRETCHES = 1 << 20
    _RUNS_CACHED = 4096

    def __init__(self, hashes, entries, orphans=()):
        self._hashes = hashes
        # PREFIX, or a shorter length -> {tag: {length: value hashes}}.
        # By length, so a thousand keys that start alike (sk_live_...) cost
        # a hash for each length they have where one may start, not one
        # for each key.
        self._heads = {}
        self.longest = 0
        for head, n, value in entries:
            size = min(PREFIX, n)
            lengths = self._heads.setdefault(size, {}).setdefault(head, {})
            lengths.setdefault(n, set()).add(value)
            self.longest = max(self.longest, n)
        for heads in self._heads.values():
            for head, lengths in heads.items():
                # The longest first.
                heads[head] = sorted(lengths.items(), reverse=True)
        # Masks no known value took the place of: masked before the index
        # knew it. Such a value is known by its mask's fingerprint alone.
        self._orphans = frozenset(orphans)
        self._cache = {}
        self._runs = {}             # a run -> where in it a stretch is one
        self._stretches = self._STRETCHES

    @classmethod
    def of(cls, values, key=None):
        """A Matcher for values, under key (a new one when None)."""
        hashes = _Hashes(key or os.urandom(_KEY_SIZE))
        return cls(hashes, [e[:3] for e in map(hashes.entry, set(values))])

    def __bool__(self):
        return bool(self._heads or self._orphans)

    __nonzero__ = __bool__

    def spans(self, text):
        """(start, end) of every copy in text of every value known, in
        order, overlapping where copies do."""
        if not text or not self:
            return []
        found = self._cache.get(text)
        if found is not None:
            return found
        found = []
        data = _bytes(text)
        plain = len(data) == len(text)         # ASCII: a character is a byte
        n = len(text)
        tag = _TAG_SIZE
        head_of, value_of = self._hashes.head.copy, self._hashes.value.copy
        for size, heads in self._heads.items():
            get = heads.get
            for i in range(n - size + 1):
                h = head_of()
                h.update(data[i:i + size] if plain else _bytes(text[i:i + size]))
                candidates = get(h.digest()[:tag])
                if not candidates:
                    continue
                for length, values in candidates:
                    if i + length > n:
                        continue
                    h = value_of()
                    h.update(data[i:i + length] if plain else _bytes(text[i:i + length]))
                    if h.digest() in values:
                        found.append((i, i + length))
        if self._orphans:
            found += self._orphan_spans(text)
        found.sort()
        if len(self._cache) >= self._CACHED:
            self._cache.clear()
        self._cache[text] = found
        return found

    def _orphan_spans(self, text):
        """Where a piece of text (clean._pieces) is a value known by its
        mask alone. The pieces of a text cost what it is long, so any text
        is asked, however long: a command of many refspecs shown whole."""
        out = []
        for piece in clean._pieces(text, urls=True):
            if self._hashes.of_mask(clean._fingerprint(piece)) in self._orphans:
                at = text.find(piece)
                while at != -1:
                    out.append((at, at + len(piece)))
                    at = text.find(piece, at + 1)
        return out

    def _stretch_spans(self, text, lo, hi):
        """Where a stretch of a run in text[lo:hi] is a value known by its
        mask alone, and of the runs it cuts at either end as far as such a
        value can reach, while the budget lasts: a run that would take more
        than is left is not asked."""
        out = []
        shortest, longest = clean._MIN_ASSIGNED, self._STRETCH_LONGEST
        n = len(text)
        while lo > 0 and longest > 1 and _in_run(text[lo - 1]):
            lo, longest = lo - 1, longest - 1
        longest = self._STRETCH_LONGEST
        while hi < n and longest > 1 and _in_run(text[hi]):
            hi, longest = hi + 1, longest - 1
        for m in clean._EVIDENCE_RUN.finditer(text, lo, hi):
            run = m.group()
            if len(run) < shortest:
                continue
            found = self._runs.get(run)
            if found is None:
                cost = _stretches(len(run), shortest, self._STRETCH_LONGEST)
                if cost > self._stretches:
                    continue
                self._stretches -= cost
                found = self._stretches_in(run)
                if len(self._runs) >= self._RUNS_CACHED:
                    self._runs.clear()
                self._runs[run] = found
            at = m.start()
            out += [(at + i, at + j) for i, j in found]
        return out

    def _stretches_in(self, run):
        """(start, end) of each stretch of run that is a value known by its
        mask alone. Each start is hashed once and extended a character at
        a time, as clean._fingerprint encodes the value."""
        shortest, longest = clean._MIN_ASSIGNED, self._STRETCH_LONGEST
        try:
            data = run.encode("ascii")
            chars = [data[k:k + 1] for k in range(len(run))]
        except UnicodeEncodeError:
            chars = [c.encode("utf-8", "replace") for c in run]
        of_mask, orphans, sha256 = self._hashes.of_mask, self._orphans, hashlib.sha256
        n, found = len(run), []
        for i in range(n - shortest + 1):
            h = sha256(b"".join(chars[i:i + shortest - 1]))
            for j in range(i + shortest, min(n, i + longest) + 1):
                h.update(chars[j - 1])
                if of_mask(h.copy().hexdigest()[:12]) in orphans:
                    found.append((i, j))
        return found

    def merged(self, text, spans=(), shown=None):
        """The merged (start, end) of spans and every copy of a known value.
        `shown`, (start, end), is the part of text an action shows: there,
        and in the runs it cuts, as far as such a value can reach, a value
        known by its mask alone is looked for in every stretch too
        (_stretch_spans), so that what is shown can be widened over one it
        would cut and masked whole."""
        found = self.spans(text)
        if shown is not None and self._orphans and text:
            found = found + self._stretch_spans(text, *shown)
        if not found:
            return tuple(spans)
        return tuple(_merge(list(spans) + found))

    def mask(self, text):
        """text with every copy of every known value replaced by its hint,
        as clean.mask_for_display replaces what the rules find. Copies that
        overlap go under one hint."""
        if not isinstance(text, str):
            return text
        spans = self.spans(text)
        if not spans:
            return text
        return clean.mask_for_display(text, _merge(spans))


def _in_run(char):
    """Whether char is in a run as clean._EVIDENCE_RUN finds one."""
    return not (char.isspace() or char in "\"'`")


def _stretches(n, shortest, longest):
    """How many stretches of shortest to longest characters a run of n
    has: what _stretches_in hashes for it."""
    if n < shortest:
        return 0
    each = longest - shortest + 1
    if n < longest:
        m = n - shortest + 1
        return m * (m + 1) // 2
    return (n - longest + 1) * each + (each - 1) * each // 2


def _write_new(path, data):
    """Write data to path whole, 0600: a new file beside it, then os.replace."""
    tmp = "%s.%d.tmp" % (path, os.getpid())
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, _CREATE, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            if hasattr(os, "fchmod"):
                os.fchmod(fh.fileno(), 0o600)
            fh.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def _read(path, limit=None):
    fd = os.open(path, _READ)
    with os.fdopen(fd, "rb") as fh:
        return fh.read() if limit is None else fh.read(limit)


def _stored_key(where):
    """This install's key, or None where there is none or it is damaged."""
    try:
        key = _read(os.path.join(where, "key"), _KEY_SIZE + 1)
    except OSError:
        return None
    return key if len(key) == _KEY_SIZE else None


def _store_key(where, key):
    """Keep key as this install's, in a 0700 directory. False where
    nothing can be written there."""
    try:
        os.makedirs(where, mode=0o700, exist_ok=True)
        if os.name != "nt":
            os.chmod(where, 0o700)
        _write_new(os.path.join(where, "key"), key)
    except OSError:
        return False
    return True


def _writable(where):
    """Whether the nearest directory there is, at or above where, takes
    a new file."""
    while not os.path.lexists(where):
        parent = os.path.dirname(where)
        if parent == where:
            return False
        where = parent
    return os.path.isdir(where) and os.access(where, os.W_OK | os.X_OK)


_HEX = re.compile("[0-9a-f]*\\Z")


def _hex(text, size):
    if not (isinstance(text, str) and len(text) == 2 * size and _HEX.match(text)):
        raise ValueError("not a digest")
    return bytes.fromhex(text)


class Index(object):
    """The index of one transcript root: for each transcript (its resolved
    path), its size and modification time when it was read, the values
    clean finds in it, and the masks it holds.

    Every other agent's files are in it too, wherever each keeps them (its
    default, or `paths`, {source id: path}): a value found in a Codex
    session is masked where a Claude Code transcript shows it, and the
    other way round. Whatever --source a run is limited to, every agent is
    indexed: a value is no less a secret for being found by an agent the
    report leaves out."""

    def __init__(self, root, where, key, stored, paths=None):
        self.root = root
        self.paths = dict(paths or {})
        self.where = where
        name = hashlib.sha256(_bytes(os.path.realpath(root))).hexdigest()[:16]
        self.path = os.path.join(where, "index-%s.json" % name)
        self._key = key
        self._stored = stored           # whether the key is on disk already
        self._hashes = _Hashes(key)
        self.values = {}                # value hash -> (tag, length, mask hash)
        self.files = {}                 # path -> (size, mtime_ns, value hashes, masks)
        self.kept = True                # until a write fails: then in memory
        self.rescanned = 0
        self._taken = {}                # path -> what clean found there (take)
        self._migrated = False          # read from an older version: write it again

    @classmethod
    def open(cls, root=None, paths=None):
        """The index of root (default: claude_projects()) as it was kept,
        or an empty one. Nothing is written until update has something to
        keep. `paths`, {source id: path}, points the other agents
        elsewhere."""
        root = root or claude_projects()
        where = index_dir()
        key = _stored_key(where)
        index = cls(root, where, key or os.urandom(_KEY_SIZE), key is not None,
                    paths)
        if key is not None:
            try:
                index._load(json.loads(_read(index.path).decode("utf-8")))
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                index.values, index.files = {}, {}
        return index

    @property
    def first(self):
        """Whether nothing is known yet, so every transcript is read for
        its secrets: a first run, or one after the index was lost. Not
        where nothing can be kept, which reads them all on every run."""
        return not self.files and (self._stored or _writable(self.where))

    def _load(self, doc):
        """Take doc as this index, or raise: one wrong part and it is all
        read again, as for none at all."""
        version = doc["version"]
        if (version not in (1, VERSION) or doc["key"] != self._hashes.key_id
                or doc["prefix"] != PREFIX):
            raise ValueError("another index")
        # Version 1 kept the whole head hash: its tag is the start of it.
        head_size = _HEAD_SIZE if version == 1 else _TAG_SIZE
        values = {}
        for value, entry in doc["values"].items():
            head, n, mask = entry
            if type(n) is not int or n < 1:
                raise ValueError("a length")
            values[_hex(value, _VALUE_SIZE)] = (_hex(head, head_size)[:_TAG_SIZE], n,
                                                _hex(mask, _MASK_SIZE))
        files = {}
        for path, entry in doc["files"].items():
            size, mtime, held, masks = entry
            if not (type(size) is int and type(mtime) is int
                    and isinstance(held, list) and isinstance(masks, list)):
                raise ValueError("a transcript")
            held = frozenset(_hex(v, _VALUE_SIZE) for v in held)
            if not held <= values.keys():
                raise ValueError("a value it does not hold")
            files[path] = (size, mtime, held, frozenset(_hex(m, _MASK_SIZE) for m in masks))
        self.values, self.files = values, files
        self._migrated = version != VERSION

    def take(self, path, st, values, fingerprints):
        """What clean found reading the transcript at path: the values the
        rules find there and the fingerprint each mask in it keeps, as
        clean.values_in returns them. st is its os.stat from before it was
        read, or for another agent's file its agents.signature. update
        keeps this in place of a read of its own while the transcript is
        still that size and that age: one written to since is read again,
        so nothing it gained in the meantime is missed."""
        if not hasattr(st, "st_mode"):          # a signature, not a stat
            size, mtime = st
        elif stat.S_ISREG(st.st_mode):
            size, mtime = st.st_size, st.st_mtime_ns
        else:
            return
        try:
            real = os.path.realpath(path)
        except OSError:
            return
        self._taken[real] = (size, mtime, set(values), set(fingerprints))

    def _adapter_files(self):
        """{resolved path: (size, mtime_ns, path, (source, store))} for
        every file of every agent clean searches through its adapter."""
        out = {}
        for source in agents.searched():
            _locations, stores = agents.discover(source, self.paths.get(source.id))
            for store in stores:
                signed = agents.signature(store.path, store.format)
                if signed is None:
                    continue
                try:
                    real = os.path.realpath(store.path)
                except OSError:
                    continue
                out.setdefault(real, signed + (store.path, (source, store)))
        return out

    def update(self, progress=None):
        """Read again each transcript under the root that is new or has
        changed since it was read, but for one clean has just read as it
        is now (take), forget those gone, keep the index, and return a
        Matcher for every value it knows. `progress` is called with
        (index, total, path) before each one is read."""
        now = self._adapter_files()
        for path in _transcripts(self.root):
            try:
                st = os.stat(path)
                real = os.path.realpath(path)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                now[real] = (st.st_size, st.st_mtime_ns, path, None)
        stale = [real for real, (size, mtime, _path, _adapter) in now.items()
                 if self.files.get(real, (None, None))[:2] != (size, mtime)]
        stale.sort(key=lambda real: now[real][1], reverse=True)     # newest first
        gone = [real for real in self.files if real not in now]
        found = {}
        for real in stale:
            taken = self._taken.get(real)
            if taken is not None and taken[:2] == now[real][:2]:
                found[real] = taken[2:]
        self._taken.clear()
        unread = [real for real in stale if real not in found]
        for i, real in enumerate(unread, 1):
            path, adapter = now[real][2:]
            if progress:
                progress(i, len(unread), path)
            self.rescanned += 1
            got = (clean.values_in(path) if adapter is None
                   else clean.values_in_store(*adapter))
            if got is not None:         # unreadable now: what it held is kept
                found[real] = got
        read = {}
        for real, (values, fingerprints) in found.items():
            held = set()
            for value in values:
                head, n, full, mask = self._hashes.entry(value)
                self.values[full] = (head, n, mask)
                held.add(full)
            masks = {self._hashes.of_mask(fp) for fp in fingerprints}
            read[real] = (now[real][0], now[real][1], held, masks)
        # A mask keeps the fingerprint of the value it took the place of,
        # so a transcript holding one still holds that value for anything
        # that may show a copy the mask did not reach.
        by_mask = {}
        for full, (_head, _n, mask) in self.values.items():
            by_mask.setdefault(mask, set()).add(full)
        for real, (size, mtime, held, masks) in read.items():
            for mask in masks:
                held |= by_mask.get(mask, set())
            self.files[real] = (size, mtime, frozenset(held), frozenset(masks))
        for real in gone:
            del self.files[real]
        # What no transcript holds, whole or by its mask, is forgotten.
        used, masks = set(), set()
        for _size, _mtime, held, held_masks in self.files.values():
            used |= held
            masks |= held_masks
        self.values = {full: e for full, e in self.values.items()
                       if full in used or e[2] in masks}
        if read or gone or self._migrated:
            self._save()
        return self.matcher()

    def remember(self, values):
        """Keep values, which clean is about to mask, by their fingerprints,
        before any transcript loses one: a transcript read again with a
        mask that took the place of one is known to hold it, though nothing
        finds the value there any more. Kept at once, so a session that
        ends any way at all after the mask, or a check run meanwhile, still
        knows it. One that no transcript holds is forgotten on the next
        update. Nothing is written when each is known already."""
        new = False
        for value in values:
            head, n, full, mask = self._hashes.entry(value)
            new = new or full not in self.values
            self.values[full] = (head, n, mask)
        if new:
            self._save()

    def matcher(self):
        known_masks = {mask for _head, _n, mask in self.values.values()}
        orphans = set()
        for _size, _mtime, _held, masks in self.files.values():
            orphans |= masks - known_masks
        return Matcher(self._hashes, [(head, n, full) for full, (head, n, _mask)
                                      in self.values.items()], orphans)

    def _save(self):
        """Keep the index, whole, or keep it in memory for this run."""
        if not self.kept:
            return
        if not self._stored:
            self._stored = _store_key(self.where, self._key)
            if not self._stored:
                self.kept = False
                return
        doc = {"version": VERSION, "key": self._hashes.key_id, "prefix": PREFIX,
               "values": {full.hex(): [head.hex(), n, mask.hex()]
                          for full, (head, n, mask) in self.values.items()},
               "files": {path: [size, mtime, sorted(v.hex() for v in held),
                                sorted(m.hex() for m in masks)]
                         for path, (size, mtime, held, masks) in self.files.items()}}
        try:
            _write_new(self.path, json.dumps(doc, sort_keys=True).encode("utf-8"))
            self._migrated = False
        except OSError:
            self.kept = False
