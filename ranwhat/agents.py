"""Which agents a run reads, where they keep their history, and how much
of it a report read.

The glue between the adapters (ranwhat/sources) and the commands. watch,
clean, the index of the values clean finds (known.py) and the CLI each ask
here where an agent's stores are, so every pass of one run finds the same
ones, and say here, in the same words, how much they read.

Claude Code and OpenClaw keep the readers they had before the adapters
(design 3.9): watch.scan_all, clean.scan and watch.scan_openclaw. Every
other agent is read through its adapter, and so is OpenClaw for secrets
(searched()).

Nothing here imports watch, clean or known: each of them imports this.
"""

from __future__ import annotations

import os

from . import sources as registry

# The two sources read by their own code in watch and clean.
PORTED = ("claude-code", "openclaw")


def chosen(selected=None):
    """The adapters to read, in registry order: the ids in `selected`, or
    every one when it is None."""
    return registry.sources(None if selected is None else list(selected))


def adapters(selected=None):
    """chosen(selected), without the two ported sources."""
    return [s for s in chosen(selected) if s.id not in PORTED]


def searched(selected=None):
    """The adapters clean searches for secrets through secret_texts, in
    registry order: chosen(selected) that are searched, but Claude Code,
    which clean.scan reads. OpenClaw is one of them (design 3.9's
    follow-up), though watch reads its tool calls with its own reader."""
    return [s for s in chosen(selected)
            if s.searched and s.id != "claude-code"]


# What discover found, kept for the length of one command (run()): check
# asks it three times of each agent (its read for secrets, the index, its
# read for actions), and an agent's files are listed once. None outside a
# command, so a caller that changes files between two reads sees them.
_RUN = None


class run(object):
    """`with agents.run():` one command's reads of every agent share what
    discover found."""

    def __enter__(self):
        global _RUN
        _RUN = {}
        return self

    def __exit__(self, *exc):
        global _RUN
        _RUN = None
        return False


def discover(source, override=None, since_days=None):
    """(locations, stores) for one adapter: every place it looks, read now,
    and every store at the places that exist, newest first. A place that
    does not exist costs its stat and nothing more, so an agent that is not
    on this machine is never listed. Never raises: an adapter that fails
    warns once, and the others are still read."""
    key = (source.id, override, since_days)
    if _RUN is not None and key in _RUN:
        locations, stores = _RUN[key]
        return list(locations), list(stores)
    found = _discover(source, override, since_days)
    if _RUN is not None:
        _RUN[key] = found
    return list(found[0]), list(found[1])


def _discover(source, override, since_days):
    try:
        locations = list(source.locations(override))
    except Exception as error:      # one adapter must not stop the others
        source.warn("locations", "could not work out where %s keeps its "
                                 "history (%s)" % (source.name, error))
        return [], []
    present = [loc for loc in locations if loc.exists]
    if not present:
        return locations, []
    try:
        stores = list(source.stores(present, since_days))
    except Exception as error:
        source.warn("stores", "could not list %s's history (%s)"
                    % (source.name, error))
        stores = []
    return locations, stores


def transcripts(stores):
    """The stores tool calls are read from."""
    return [s for s in stores if s.role == "transcript"]


def signature(path, format=None):
    """(size, mtime_ns) that changes whenever what the store holds may
    have, or None when it cannot be stat'ed. A database's newest rows can
    sit in its -wal file while the database itself is unchanged, so for
    one the -wal counts too."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    size, mtime = st.st_size, st.st_mtime_ns
    if format == "sqlite":
        try:
            wal = os.stat(path + "-wal")
            size, mtime = size + wal.st_size, max(mtime, wal.st_mtime_ns)
        except OSError:
            pass
    return size, mtime


# -- words ------------------------------------------------------------------

def name(source_id):
    """An agent's display name, or its id when no adapter has it."""
    try:
        return registry.get(source_id).name
    except KeyError:
        return source_id


def unit(source_id):
    """What one store of this agent is called: transcript, session..."""
    try:
        return registry.get(source_id).unit
    except KeyError:
        return "file"


def plural(n, word):
    """"1 session", "2 sessions"."""
    if n == 1:
        return "1 %s" % word
    if word.endswith(("s", "sh", "ch", "x")):
        return "%d %ses" % (n, word)
    if word.endswith("y") and word[-2:-1] not in "aeiou":
        return "%d %sies" % (n, word[:-1])
    return "%d %ss" % (n, word)


def amount(counts, others=None):
    """How much a report read, agent by agent in registry order, naming
    only the agents it read anything of: "Claude Code: 429 transcripts;
    Codex: 12 sessions". `others`, {id: n}, are the files each read beside
    its transcripts (clean reads prompt histories and saved outputs too):
    "Codex: 12 sessions and 3 other files"."""
    others = others or {}
    order = list(registry.ids())
    ids = sorted((i for i in set(counts) | set(others)
                  if counts.get(i) or others.get(i)),
                 key=lambda i: (order.index(i) if i in order else len(order), i))
    parts = []
    for i in ids:
        what = [plural(counts[i], unit(i))] if counts.get(i) else []
        if others.get(i):
            what.append(plural(others[i], "other file" if what else "file"))
        parts.append("%s: %s" % (name(i), " and ".join(what)))
    return "; ".join(parts)


def read_words(counts, others=None):
    """"Read Claude Code: 429 transcripts; Codex: 12 sessions", or None
    when nothing was read."""
    said = amount(counts, others)
    return "Read " + said if said else None


def notes(selected=None, locations=None):
    """Sentences on what this run could not read of each agent's history,
    agent by agent: the files it could not read and why (each adapter
    counts them as it reads), and what the adapter's own notes() says.
    `locations`, {id: [Location]}, are where each looked, for notes()."""
    out = []
    for source in adapters(selected):
        for reason, n in sorted(source.unreadable.items()):
            out.append("%s %s not read: %s." % (
                plural(n, "%s file" % source.name),
                "was" if n == 1 else "were", reason))
        extra = getattr(source, "notes", None)
        if extra is not None:
            try:
                out += list(extra((locations or {}).get(source.id, [])))
            except Exception:       # a note is never worth the report
                pass
    return out
