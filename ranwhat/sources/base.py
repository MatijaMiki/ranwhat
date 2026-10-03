"""The shapes every agent adapter speaks, and the Source interface.

An adapter finds an agent's stores, yields the tool calls in them for
watch, yields every piece of stored text for clean, and says whether its
files can be rewritten. It is read-only everywhere except mask().

Nothing in this package imports watch or clean at import time, so watch
can import the registry without a cycle. The masker reaches clean's backup
and redaction marker from inside a function, when it runs.

Ported sources (claude-code, openclaw) hand ToolCall the input exactly as
watch passed it to evaluate() before the port. OpenClaw's is always a dict,
which decode_input leaves alone. Claude Code's is whatever the transcript
holds, so it passes decode=False: a string there was judged as a string,
and parsing it would judge a different call.
"""

from __future__ import annotations

import json
import os
import sys
import time

from . import _paths

FORMATS = ("jsonl", "json", "text", "sqlite", "jsonl.zst")
ROLES = ("transcript", "side")
MASKING = ("rewrite", "read-only")
KINDS = ("shell", "read", "write", "fetch", "other")
ACTORS = ("agent", "user")
STATUSES = (None, "declined")
SKIPPED = (None, "read-only", "in use", "changed while reading",
           "would alter more than the secret")

# Formats that are never rewritten: a database belongs to a running agent,
# and a compressed file cannot be changed byte for byte.
READ_ONLY_FORMATS = ("sqlite", "jsonl.zst")

# Formats whose mtime is the time of their last write, so a --days
# prefilter by mtime is safe. Not SQLite: a live database's newest rows can
# sit in its -wal file while the main file keeps an old mtime.
PREFILTERED_FORMATS = ("jsonl", "json", "text", "jsonl.zst")

WHY_READ_ONLY = {
    "sqlite": "It is a database the agent keeps open; ranwhat only reads it.",
    "jsonl.zst": "It is compressed; ranwhat does not rewrite compressed files.",
}

# Why a store a reader gave up on part way was not read (Source.stopped).
STOPPED = "a %s stopped it part way"

# Per-run counters every adapter keeps, so a format change shows up as a
# jump in `ranwhat sources --json` instead of as silence.
COUNTERS = ("unparsed", "unknown", "unreadable_stores", "unreadable_calls")


class _Record(object):
    """A plain record with fixed fields: compared by value, printed by
    field, and turned into a dict for --json."""
    __slots__ = ()

    def as_dict(self):
        out = {}
        for name in self.__slots__:
            value = getattr(self, name)
            if isinstance(value, (tuple, frozenset)):
                value = sorted(value) if isinstance(value, frozenset) else list(value)
            out[name] = value
        return out

    def __eq__(self, other):
        return (type(other) is type(self)
                and all(getattr(self, n) == getattr(other, n)
                        for n in self.__slots__))

    def __ne__(self, other):
        return not self == other

    __hash__ = None

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, ", ".join(
            "%s=%r" % (n, getattr(self, n)) for n in self.__slots__))


def _check(field, value, allowed):
    if value not in allowed:
        raise ValueError("%s must be one of %r, not %r" % (field, allowed, value))


class Location(_Record):
    """One place a source looks."""
    __slots__ = ("source", "path", "how", "exists", "found")

    def __init__(self, source, path, how, exists=False, found=0):
        self.source = source
        self.path = path
        self.how = how                  # "default", "env CODEX_HOME", "--path", ...
        self.exists = bool(exists)
        self.found = int(found)         # stores there, whatever their age


class Store(_Record):
    """One history file or database."""
    __slots__ = ("source", "path", "format", "role", "unit", "session",
                 "project", "mtime", "masking", "why_read_only")

    def __init__(self, source, path, format, role="transcript", unit="session",
                 session=None, project=None, mtime=0.0, masking=None,
                 why_read_only=None):
        _check("format", format, FORMATS)
        _check("role", role, ROLES)
        if masking is None:
            masking = "read-only" if format in READ_ONLY_FORMATS else "rewrite"
        _check("masking", masking, MASKING)
        if format in READ_ONLY_FORMATS and masking != "read-only":
            raise ValueError("a %s store is always read-only" % format)
        if masking == "read-only" and not why_read_only:
            why_read_only = WHY_READ_ONLY.get(
                format, "ranwhat does not rewrite this file.")
        self.source = source
        self.path = path
        self.format = format
        self.role = role
        self.unit = unit
        self.session = session
        self.project = project
        self.mtime = mtime
        self.masking = masking
        self.why_read_only = why_read_only if masking == "read-only" else None


def decode_input(value):
    """A tool call's input as a dict.

    A dict is kept. A string is parsed as JSON (function-call arguments are
    usually a JSON string); one that does not parse becomes {"_raw": text}.
    Anything else, parsed or not, becomes {"_value": value}, the shape watch
    already reads. None is {}."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            return {"_raw": value}
        if isinstance(value, dict):
            return value
    return {"_value": value}


class ToolCall(_Record):
    """One call the agent (or the user, through the agent) made.

    kind None is for the two ported sources only: watch judges those
    exactly as it does today, by tool name. An adapter that recognises a
    tool name from its spec sets kind and known=True. For a name it does not
    know, known is False and kind is "other"; watch then judges it by name.
    tool_input is decoded here (see decode_input), unless decode is False:
    then it is kept exactly as recorded, for Claude Code."""
    __slots__ = ("source", "store", "session", "project", "timestamp",
                 "tool_name", "tool_call_id", "kind", "known", "actor",
                 "status", "not_after", "command", "workdir", "paths",
                 "tool_input", "consumed", "output")

    def __init__(self, source, store, tool_name, tool_input=None, kind=None,
                 known=False, session=None, project=None, timestamp=None,
                 tool_call_id=None, actor="agent", status=None,
                 not_after=None, command=None, workdir=None, paths=(),
                 consumed=(), output=None, decode=True):
        if kind is not None:
            _check("kind", kind, KINDS)
        if known and kind is None:
            raise ValueError("a known tool name needs a kind")
        if not known and kind not in (None, "other"):
            raise ValueError("a tool name the adapter does not know is "
                             "kind 'other', not %r" % (kind,))
        _check("actor", actor, ACTORS)
        _check("status", status, STATUSES)
        if isinstance(paths, str):
            paths = (paths,)
        if isinstance(consumed, str):
            consumed = (consumed,)
        self.source = source
        self.store = store
        self.session = session
        self.project = project
        self.timestamp = timestamp
        self.tool_name = tool_name
        self.tool_call_id = tool_call_id
        self.kind = kind
        self.known = bool(known)
        self.actor = actor
        self.status = status
        self.not_after = not_after
        self.command = command
        self.workdir = workdir
        self.paths = tuple(paths)
        self.tool_input = decode_input(tool_input) if decode else tool_input
        self.consumed = frozenset(consumed)
        self.output = output


class SecretText(_Record):
    """One piece of stored text for clean to search."""
    __slots__ = ("node", "call", "attached", "where")

    def __init__(self, node, call=None, attached=None, where=""):
        self.node = node            # a string, or decoded JSON to walk
        self.call = call            # the ToolCall whose output this is
        self.attached = attached    # the file name this is the content of
        self.where = where          # "line 412", "session ses_1, part prt_9"


class MaskResult(_Record):
    """What mask() did to one store."""
    __slots__ = ("path", "changed", "skipped", "backup")

    def __init__(self, path, changed=False, skipped=None, backup=None):
        _check("skipped", skipped, SKIPPED)
        self.path = path
        self.changed = bool(changed)
        self.skipped = skipped
        self.backup = backup


def newest_first(stores, since_days=None):
    """Stores sorted newest first. With since_days, a store whose format
    allows it (not SQLite) and whose mtime is older than the window is
    dropped: its last write was before the window opened."""
    stores = list(stores)
    if since_days:
        cutoff = time.time() - since_days * 86400
        stores = [s for s in stores
                  if s.format not in PREFILTERED_FORMATS or s.mtime >= cutoff]
    stores.sort(key=lambda s: s.mtime or 0, reverse=True)
    return stores


class Source(object):
    """One agent. Subclasses set the class attributes and override
    default_paths, stores, tool_calls and secret_texts."""

    id = ""                 # stable CLI id, e.g. "codex"
    name = ""               # display name, e.g. "Codex"
    unit = "session"        # default Store.unit
    env = ()                # the agent's own override variables, for messages
    path_means = ""         # what `--path <id>=PATH` points at
    needs_projects = False  # found through other sources' project dirs
    checked = ""            # the agent release the spec was checked against
    searched = True         # False: clean does not search it for secrets
    byte_arrays = False     # stores carry text as JSON byte lists (Grok Build)

    def __init__(self):
        self.reset()

    # -- per-run bookkeeping ------------------------------------------------

    def reset(self):
        """Start a run: zero the counters and forget earlier warnings."""
        self.counts = dict.fromkeys(COUNTERS, 0)
        self.unreadable = {}        # reason -> number of stores
        self._warned = set()

    def count(self, counter, n=1):
        self.counts[counter] = self.counts.get(counter, 0) + n

    def unreadable_store(self, reason):
        """A store that could not be read, and the one-line reason the
        report gives ("compressed, needs Python 3.14 or the zstd command")."""
        self.count("unreadable_stores")
        self.unreadable[reason] = self.unreadable.get(reason, 0) + 1

    def warn(self, key, message):
        """Print a warning on stderr once per key per run."""
        if key in self._warned:
            return
        self._warned.add(key)
        print("  warning: %s" % message, file=sys.stderr)

    def stopped(self, store, error):
        """A store a reader gave up on part way, on an error nothing below
        it caught: counted once a run, whichever pass met it, as a file not
        read, and named by the error's class only, since what an error says
        can quote what it was reading."""
        key = ("stopped", store.path)
        if key not in self._warned:
            self.unreadable_store(STOPPED % type(error).__name__)
        self.warn(key, "stopped reading %s %s part way (%s)"
                  % (self.name or self.id, store.path, type(error).__name__))

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """Pure: [(path, how)] for this agent on `platform` ("darwin",
        "linux", "win32"), given an environment mapping and a home
        directory. No I/O."""
        return []

    def project_paths(self, projects):
        """For needs_projects sources: [(path, how)] to look at, given the
        project directories other sources found."""
        return []

    def locations(self, override=None, projects=()):
        """Where to look now: `override` (from --path; a path or a list of
        them) if given, else default_paths(os.environ, _paths.home(),
        sys.platform), read at call time, never at import. Each path is
        expanded and made absolute, repeats are dropped, and each says
        whether it exists and how many stores it holds. Never raises."""
        try:
            if override:
                items = [override] if isinstance(override, str) else list(override)
                pairs = [(p, "--path") for p in items]
            else:
                pairs = list(self.default_paths(
                    os.environ, _paths.home(), _paths.platform_name()))
                if self.needs_projects:
                    pairs += list(self.project_paths(projects))
            out, seen = [], set()
            for path, how in pairs:
                if not path:
                    continue
                path = os.path.abspath(os.path.expanduser(path))
                key = os.path.normcase(path)
                if key in seen:
                    continue
                seen.add(key)
                out.append(Location(self.id, path, how,
                                    exists=os.path.exists(path)))
            for loc in out:
                if loc.exists:
                    loc.found = len(list(self.stores([loc])))
            return out
        except Exception as e:      # one adapter must not stop the others
            self.warn("locations", "could not work out where %s keeps its "
                      "history (%s)" % (self.name or self.id, type(e).__name__))
            return []

    def stores(self, locations, since_days=None):
        """Every store at those locations, newest first (newest_first). A
        since_days prefilter by mtime only where mtime is the last write."""
        return []

    def store(self, path, format, **fields):
        """A Store for `path` with this source's id and unit and the file's
        mtime, or None when it cannot be stat'ed."""
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            return None
        fields.setdefault("unit", self.unit)
        return Store(self.id, path, format, mtime=mtime, **fields)

    # -- what is in a store -------------------------------------------------

    def tool_calls(self, store):
        """Yield a ToolCall for every distinct call in the store, once,
        with its own timestamp. Never raises: a store that cannot be read
        warns once and yields nothing."""
        return iter(())

    def secret_texts(self, store):
        """Yield a SecretText for every string the store holds, including
        copies the agent no longer replays. Never the agent's own login
        material."""
        return iter(())

    # -- masking ------------------------------------------------------------

    def in_use(self, store):
        """True when the agent is known to have this store open (a lock file
        with a live pid). Default: not known."""
        return False

    def mask(self, store, values):
        """Mask these exact values in this store. Read-only stores, and
        stores in use, are refused without being opened for writing."""
        from . import _rewrite
        if store.masking != "rewrite":
            return MaskResult(store.path, skipped="read-only")
        if self.in_use(store):
            return MaskResult(store.path, skipped="in use")
        return _rewrite.rewrite_file(store.path, values, store.format,
                                     byte_arrays=self.byte_arrays)
