"""ranwhat ledger: a record of what watch flagged, that shows if it was altered.

`ranwhat ledger record` reads what `watch` reads, applies the ignore file
as `watch` does, and appends to a file on this machine one line for each
flagged action it has not recorded before. Each line holds, for one action:

  id      the 16 hex characters of watch.action_id: a hash, not the action
  agent   which agent ran it (one of ranwhat sources' ids)
  at      when, as UTC to the second, or null when the agent wrote no time
  hits    the rule id and severity of each rule it tripped

and the same three facts about the line itself: its place in the file (n),
when it was written (time), and the SHA-256 of the line before it (prev). The
line's own hash is made over all of that, so the lines form a chain: change
one, and its hash no longer fits it; take one out or put two in the other
order, and the next line no longer fits the one before.

Never in it: a command, a path, evidence, a working directory, a session id,
a project, a tool name, file contents or a secret. These are push's five
facts (push.py), built field by field from a record, so a field an adapter
adds tomorrow cannot reach the file.

What it shows, and what it cannot. `verify` reports the first line that does
not fit, and why. It cannot tell a file that was cut short at its end, or
rewritten whole by someone who can write to it, from a file that was never
longer: a chain has no memory of lines it no longer holds. The head, the
hash of the last line, is what closes that. `record` prints it, and
`verify --head HASH` compares the file with a copy kept somewhere else.

Nothing here touches the network. This module imports the standard library
and push and watch only.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import time

from . import push
from . import watch

VERSION = 1
GENESIS = "0" * 64
FILE = "ledger.jsonl"

# Seconds to wait for another ranwhat that is writing, and the age past which
# a lock file is taken to belong to one that died.
LOCK_WAIT = 15.0
LOCK_STALE = 60.0

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[0-9a-f]{16}\Z")
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_WORD = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_FIELDS = frozenset(("v", "n", "prev", "time", "id", "agent", "at", "hits",
                     "hash"))
# Many entries make a large file, and a ledger is read whole to extend it:
# past this it is not read, and a person is told, rather than a machine
# slowed for minutes.
MAX_BYTES = 64 * 1024 * 1024

_O_BINARY = getattr(os, "O_BINARY", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class LedgerError(Exception):
    """Something stopped ledger, and the message says what and what it left."""


def home():
    """ranwhat's state directory, as known.home() names it."""
    return os.environ.get("RANWHAT_HOME") or os.path.join(
        os.path.expanduser("~"), ".ranwhat")


def default_path():
    return os.path.join(home(), FILE)


# ---------- the chain ----------

def canonical(entry):
    """The bytes a line is hashed as: its fields but the hash, as JSON with
    sorted keys, no spaces and ASCII only, so the same entry is the same
    bytes on every platform and Python."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def digest(entry):
    return hashlib.sha256(b"ranwhat-ledger-v1\n" + canonical(entry)).hexdigest()


def seal(entry):
    """entry with its hash."""
    out = dict(entry)
    out["hash"] = digest(out)
    return out


def dumps(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _shape(entry):
    """None when entry is a line this version writes, else why not. Looked
    at before the hash, so a line that was edited into another shape is
    called what it is."""
    if not isinstance(entry, dict):
        return "is not a record"
    if set(entry) != _FIELDS:
        return "has fields ranwhat does not write"
    if entry["v"] != VERSION or not _is_int(entry["v"]):
        return "is of a version this ranwhat does not read"
    if not _is_int(entry["n"]) or entry["n"] < 1:
        return "has no place in the file"
    for key in ("prev", "hash"):
        if not isinstance(entry[key], str) or not _HASH.match(entry[key]):
            return "has a %s that is not a SHA-256" % key
    if not isinstance(entry["time"], str) or not _STAMP.match(entry["time"]):
        return "has no time"
    if not isinstance(entry["id"], str) or not _ID.match(entry["id"]):
        return "has no action id"
    if not isinstance(entry["agent"], str) or not _WORD.match(entry["agent"]):
        return "has no agent"
    at = entry["at"]
    if at is not None and (not isinstance(at, str) or not _STAMP.match(at)):
        return "has a time that is not one"
    hits = entry["hits"]
    if not isinstance(hits, list) or not 1 <= len(hits) <= push.MAX_HITS:
        return "has no hits"
    for hit in hits:
        if (not isinstance(hit, dict) or set(hit) != {"rule", "severity"}
                or not isinstance(hit["rule"], str)
                or not _WORD.match(hit["rule"])
                or hit["severity"] not in push.RANK):
            return "has a hit ranwhat does not write"
    return None


class Report(object):
    """What verify found: `ok`, how many lines it read, the head (the hash
    of the last line that fitted), and, when not ok, the line that did not
    fit (`line`, from 1) and `why`."""

    def __init__(self):
        self.ok = True
        self.exists = False
        self.entries = 0
        self.head = GENESIS
        self.line = None
        self.why = None
        self.items = []             # the entries that fitted, oldest first
        self.ids = set()

    def broken(self, line, why):
        self.ok, self.line, self.why = False, line, why
        return self

    def as_dict(self):
        out = {"ok": self.ok, "exists": self.exists, "entries": self.entries,
               "head": self.head if self.entries else None}
        if not self.ok:
            out["broken_at_line"] = self.line
            out["why"] = self.why
        return out


def check(data, head=None):
    """Verify the bytes of a ledger. Entries are read as far as they fit; the
    first that does not ends the check, and is the Report's `line`. With
    `head`, the last line's hash must be it too."""
    report = Report()
    report.exists = bool(data)
    if not data:
        return _against(report, head)
    if not data.endswith(b"\n"):
        # A crash, or a cut, mid-line. The lines before are still checked,
        # so the first fault is the one that is named.
        lines = data.split(b"\n")
        partial = len(lines)
        lines = lines[:-1]
    else:
        lines = data.split(b"\n")[:-1]
        partial = None
    previous = GENESIS
    for number, raw in enumerate(lines, 1):
        raw = raw.rstrip(b"\r")
        if not raw.strip():
            return report.broken(number, "is empty")
        try:
            entry = json.loads(raw.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            return report.broken(number, "is not a ranwhat ledger line")
        why = _shape(entry)
        if why:
            return report.broken(number, why)
        if entry["hash"] != digest(entry):
            return report.broken(
                number, "does not match its hash: it was changed after it "
                "was written")
        if entry["prev"] != previous:
            return report.broken(
                number, "does not follow the line before it: a line was "
                "taken out, put in, or moved")
        if entry["n"] != number:
            return report.broken(
                number, "is numbered %d where line %d belongs" % (
                    entry["n"], number))
        if entry["id"] in report.ids:
            return report.broken(number, "records an action already recorded")
        report.ids.add(entry["id"])
        previous = entry["hash"]
        report.entries = number
        report.head = previous
        report.items.append(entry)
    if partial is not None:
        return report.broken(partial, "ends the file without finishing the "
                             "line: a write was cut short")
    return _against(report, head)


def _against(report, head):
    if head is not None and report.ok and report.head != head:
        which = ("the file is empty" if not report.entries
                 else "its last line is %d (%s...)" % (
                     report.entries, report.head[:12]))
        report.ok = False
        report.line = report.entries or None
        report.why = ("the head given is not where this file ends: " + which
                      + ". Lines may have been cut off its end, or added to it")
    return report


# ---------- the file ----------

def _read(path):
    """The bytes of the ledger, b'' when there is none. Not through a
    symlink: one planted where the ledger goes would be read as it."""
    try:
        if os.path.islink(path):
            raise LedgerError("%s is a symlink; not reading the ledger "
                              "through it." % path)
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _O_BINARY)
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise LedgerError("cannot read %s: %s" % (path, exc.strerror or exc))
    try:
        size = os.fstat(fd).st_size
        if size > MAX_BYTES:
            raise LedgerError("%s is larger than ranwhat reads (%d MB)."
                              % (path, MAX_BYTES // (1024 * 1024)))
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def verify(path=None, head=None):
    """A Report on the ledger at path (the default one when None)."""
    path = path or default_path()
    if head is not None and not _HASH.match(head):
        raise LedgerError("--head is the 64 hex characters ranwhat ledger "
                          "record printed.")
    data = _read(path)
    report = check(data, head)
    report.exists = bool(data)
    return report


@contextlib.contextmanager
def _locked(path):
    """Exclusive use of the ledger while a line is added, between ranwhat
    processes: a lock file made with O_EXCL, which every platform honours.
    One older than LOCK_STALE belongs to a process that died, and goes."""
    lock = path + ".lock"
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise LedgerError("cannot make %s: %s" % (directory, exc.strerror or exc))
    deadline = time.monotonic() + LOCK_WAIT
    while True:
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | _NOFOLLOW | _O_BINARY, 0o600)
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - os.stat(lock).st_mtime > LOCK_STALE:
                    os.unlink(lock)
                    continue
            except OSError:
                continue
            if time.monotonic() > deadline:
                raise LedgerError(
                    "another ranwhat is writing %s (or died holding %s). "
                    "Nothing was recorded." % (path, lock))
            time.sleep(0.02)
        except OSError as exc:
            raise LedgerError("cannot lock %s: %s" % (path, exc.strerror or exc))
    try:
        yield
    finally:
        try:
            os.unlink(lock)
        except OSError:
            pass


def actions(records):
    """The actions `records` (watch's, after the ignore file) describe, each
    as {id, agent, at, hits}: push's five facts and nothing else of a
    record, oldest first. A record with no action id, or no hit of a rule
    and severity ranwhat knows, is left out; so is a second with an id."""
    rules, agents = push.rule_ids(), push.agent_ids()
    out, seen = [], set()
    for record in records:
        if not isinstance(record, dict) or record.get("source") not in agents:
            continue
        hits = push._hits(record, rules)
        rid = record.get("id")
        if not hits or not isinstance(rid, str) or not _ID.match(rid) \
                or rid in seen:
            continue
        seen.add(rid)
        epoch = watch._epoch(record.get("timestamp"))
        out.append({
            "id": rid, "agent": record["source"],
            "at": push._utc(epoch) if epoch is not None else None,
            "hits": [{"rule": r, "severity": hits[r]} for r in sorted(hits)
                     ][:push.MAX_HITS]})
    out.sort(key=lambda a: (a["at"] is None, a["at"] or "", a["id"]))
    return out


def record(items, path=None, now=None):
    """Append to the ledger the `items` (from actions()) it does not hold,
    and return (added, already_held, Report of the file after). A ledger that
    does not verify is not extended: a chain built onto a broken one would
    look sound from the break on."""
    path = path or default_path()
    stamp = push._utc(time.time() if now is None else now)
    with _locked(path):
        data = _read(path)
        report = check(data)
        if not report.ok:
            raise LedgerError(
                "the ledger does not verify (line %d %s), so nothing was "
                "added. ranwhat ledger verify says more; to start again, "
                "move %s away." % (report.line, report.why, path))
        held, previous, number = set(report.ids), report.head, report.entries
        lines, added = [], 0
        for item in items:
            if item["id"] in held:
                continue
            held.add(item["id"])
            number += 1
            entry = seal({
                "v": VERSION, "n": number, "prev": previous, "time": stamp,
                "id": item["id"], "agent": item["agent"], "at": item["at"],
                "hits": item["hits"]})
            previous = entry["hash"]
            lines.append(dumps(entry))
            added += 1
        if lines:
            blob = ("\n".join(lines) + "\n").encode("ascii")
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND
                             | _NOFOLLOW | _O_BINARY, 0o600)
            except OSError as exc:
                raise LedgerError("cannot write %s: %s" % (
                    path, exc.strerror or exc))
            try:
                view = memoryview(blob)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            except OSError as exc:
                raise LedgerError("writing %s failed: %s. The ledger may "
                                  "end in a cut line; ranwhat ledger verify "
                                  "says." % (path, exc.strerror or exc))
            finally:
                os.close(fd)
        return added, len(items) - added, check(_read(path))


def entries(path=None, last=None):
    """The entries that fitted, oldest first, or the `last` few. A file that
    stops fitting is read as far as it does; verify says where."""
    items = check(_read(path or default_path())).items
    return items[-last:] if last else items
