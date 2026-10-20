"""What watch and check leave out: the ignore file, and ranwhat ignore.

An action someone expected (their own release, a deletion they asked for)
is listed again on every run, and a report that lists the same expected
things every time stops being read. The ignore file names what to leave
out: one action by the id watch prints beside it, or every action a rule
flags whose command is a given one, word for word, where it ran and until
when. A baseline is the same file: ranwhat ignore all writes the id of
every action listed now, so later runs list only what is new.

It is one plain-text file, $RANWHAT_HOME/ignore (~/.ranwhat/ignore), or the
file --ignore names; never one found in the working tree, which is what an
agent writes most easily, and never one an environment variable points at,
so a cron run and a terminal run read the same. A line format, not JSON,
whose one bad comma voids everything, and not TOML, which Python 3.9 and
3.10 cannot read without a dependency:

  ID [ID ...] [ack]
  RULE ['COMMAND'] [in=DIR] [until=YYYY-MM-DD]

Several ids on a line are the copies of one action (watch's ids). ack is
the one way to leave out a change an agent made to ranwhat's own settings,
and only ranwhat ignore on a terminal writes it. A line it cannot read is
skipped, named in every report, and leaves nothing out.

What a pattern line is matched against is the whole command a hit is in,
split into words as the shell splits it (watch's _subject), not the cut
evidence the report prints: two npm publish commands sent to two
registries print one evidence and are two commands. in= is where the
command ran, followed through the cds before it in the same call. Only *
is special, within one word; nothing else is a pattern, since [ and ? are
ordinary in commands and URLs.

What is never left out, whatever the file says:

- a secret (secret.literal): ranwhat clean masks it, or keeps it when it
  is no secret, and the action is listed until then;
- what was decoded from base64 or the like, but by its id: it is no
  command the transcript shows;
- a change to ranwhat's own state or guard (watch.UNIGNORABLE), but by an
  ack line: an agent that could write this file could otherwise write the
  line that hides its own write;
- a critical action, but by its id or by an entry that names its program
  in full, with in= and an until= at most CRITICAL_DAYS ahead.

Every report says how many actions it left out, and by which lines, and
--no-ignore lists them all again. The live hook never reads this file: what
someone leaves out of a report after the fact is still asked about before
it runs.

Matching is linear in what it reads: a * is matched by finding each piece
of the pattern in turn, never by backtracking, and entries are looked up
by rule, word count and program, so a file of a hundred thousand ids and
hundreds of patterns costs little more than one of a few.
"""

from __future__ import annotations

import datetime
import json
import os
import posixpath
import re
import shlex
import stat
import time

from . import known
from . import watch

FILE = "ignore"
# The name a repository's own file goes by, by convention. Read only when
# named (--ignore .ranwhatignore, or the Action's ignore-file input); the
# agent.config rule lists a write to one anywhere.
REPO_NAME = ".ranwhatignore"
MAX_BYTES = 16 << 20
MAX_LINE = 8192
# A pattern past these is no command anyone types and means to match word
# for word.
MAX_PATTERN = 1024
MAX_WORDS = 64
# How far ahead until= may be on an entry that leaves out a critical
# action, and how far ahead ranwhat ignore writes it: a year, so a
# critical action someone expected is looked at again at least that often.
CRITICAL_DAYS = 400
PROPOSE_DAYS = 365
# ranwhat ignore - reads at most this much of watch --json or check --json.
MAX_REPORT = 64 << 20
# What a comment ranwhat writes after an id quotes of the action.
MAX_COMMENT = 120

SECRET = "secret.literal"

_ID = re.compile(r"[0-9a-fA-F]{16}\Z")
_HEXISH = re.compile(r"[0-9a-fA-F]+\Z")
_DATE = re.compile(r"\d{4}-\d\d-\d\d\Z")
# key= at the start of a word after the pattern: in=, until=, or one this
# version does not know.
_KEY = re.compile(r"([A-Za-z_][\w-]*)=")
_DRIVE = re.compile(r"[A-Za-z]:/")
# A comment or a quote: where splitting a line on blanks would read it
# otherwise than the shell does.
_SPECIAL = re.compile(r"""[#'"\\]""")
_IN_DOUBLE = re.compile(r'["\\]')
_QUOTING = re.compile(r"""['"\\]""")
_BLANKS = re.compile(r"[ \t\r\n]+")
_SHELL_BLANK = " \t\r\n"
# What a written comment or entry must never hold: a control character, or
# one that some reader takes for a line break. The file is read a line at
# a time on \n alone, never with str.splitlines, which breaks at \x0b,
# \x1c and the rest; a command quoted in a comment is still kept clear of
# every one of them.
_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]")
# A word written into the file as it is: anything else is quoted.
_PLAIN_WORD = re.compile(r"[\w@%+=:,./~-]+\Z")

HEADER = """\
# ranwhat ignore file: what ranwhat watch and check leave out. Each report
# says how many actions this file left out, and by which line; ranwhat watch
# --no-ignore lists them all again. One entry a line:
#
#   ID [ID ...]
#       one action, by the 16-character id watch prints beside it.
#       ranwhat ignore ID and ranwhat ignore all write these.
#   RULE ['COMMAND'] [in=DIR] [until=YYYY-MM-DD]
#       every action RULE flags whose command is COMMAND, word for word.
#       * in a word stands for any run of characters within that word.
#       A path stands in for COMMAND when the rule flagged a file a tool read
#       or wrote. in=DIR: only what ran in DIR or below it. until=: the last
#       day it applies. Without COMMAND, every action RULE flags.
#
# A critical action is left out only by its ID, or by an entry whose COMMAND
# names its program in full, with in=DIR and an until= no more than 400 days
# ahead. A secret is never left out here: ranwhat clean masks it, or keeps
# it. A change an agent makes to this file is always listed.
# A # starts a comment at the start of a line or after a space.
"""

# What an entry lacks to leave out a critical action, as --json names it,
# and as a note says it.
_MISSING = {
    "command": "it names no command",
    "program": "its command does not name the program in full",
    "path": "its path is not a full path, with * only in its last part",
    "in=": "it has no in=",
    "until=": "it has no until=",
    "until<=400": "its until= is more than %d days ahead" % CRITICAL_DAYS,
}
_CRITICAL_RULE = ("A critical action is left out only by its id, or by an "
                  "entry that names its program in full, with in= and an "
                  "until= no more than %d days ahead." % CRITICAL_DAYS)


class IgnoreError(Exception):
    """A file that cannot be used where it must be (--ignore), or written
    where ranwhat ignore must add to it. The message is the one to print."""


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def default_path():
    """$RANWHAT_HOME/ignore, ~/.ranwhat/ignore by default."""
    return os.path.join(known.home(), FILE)


def shown(path):
    """A path as the reader types it back: under ~ when it is in home."""
    return watch._shown_path(path, 4096)


def _expand(path):
    """path with a leading ~ (alone, or before a slash) put in for home.
    ~user is left: it is no folder from the root, and is refused."""
    if path == "~" or path.startswith(("~/", "~\\")):
        return os.path.expanduser("~") + path[1:]
    return path


def _windows(path):
    return os.name == "nt" or bool(_DRIVE.match(path)) or path.startswith("//")


def _absolute(path):
    """The path from the root a path names, with ~ put in for home, \\
    read as /, . and .. walked, and in lower case where it is a Windows
    path (case is no part of a name there); None when it is not from the
    root (/x, X:/x or //server/share)."""
    if not isinstance(path, str) or not path:
        return None
    p = _expand(path).replace("\\", "/")
    if not (p.startswith("/") or _DRIVE.match(p)):
        return None
    windows = _windows(p)
    p = posixpath.normpath(p)
    return p.lower() if windows else p


def _parts(norm):
    """The components of a normalised path; the root is one empty one."""
    if norm in ("/", "//"):
        return [""]
    return norm.rstrip("/").split("/")


def inside(directory, root):
    """Whether directory is root or below it, compared a component at a
    time: ~/work/mylib does not hold ~/work/mylib-old. False when either
    is not from the root, or not known."""
    a, b = _absolute(directory), _absolute(root)
    if a is None or b is None:
        return False
    pa, pb = _parts(a), _parts(b)
    return pa[:len(pb)] == pb


def _join(directory, path):
    """path under directory, when path is relative: with / between them
    whichever way directory is spelt."""
    return directory.replace("\\", "/").rstrip("/") + "/" + path


def _directory(record, hit):
    """Where the command a hit is about ran: the call's own folder (cwd),
    moved by any cd before the command in the same call (_cd). None when
    either is not known: a cd ranwhat cannot follow, or a call whose agent
    wrote no folder down."""
    cwd = record.get("cwd") if isinstance(record.get("cwd"), str) else None
    if hit.get("_on") != "command":
        return cwd
    cd = hit.get("_cd")
    if not isinstance(cd, str):
        return None
    if _absolute(cd):
        return cd
    if not cwd or not _absolute(cwd):
        return None
    return _join(cwd, cd) if cd else cwd


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def glob(pattern, text):
    """Whether text is pattern, where * stands for any run of characters,
    an empty one too, and nothing else is special; anchored at both ends,
    case and all. Each piece between the *s is found after the one before
    it, the first place it is: what is left for the rest is then the most
    it can be, so no other choice could match where this one does not, and
    no place is tried twice."""
    if "*" not in pattern:
        return pattern == text
    pieces = pattern.split("*")
    head, tail = pieces[0], pieces[-1]
    if (len(head) + len(tail) > len(text) or not text.startswith(head)
            or not text.endswith(tail)):
        return False
    pos, end = len(head), len(text) - len(tail)
    for piece in pieces[1:-1]:
        if not piece:
            continue
        at = text.find(piece, pos, end)
        if at < 0:
            return False
        pos = at + len(piece)
    return True


def match_words(pattern_words, subject_words):
    """Whether a command, split into words, is the pattern's, word for
    word: as many words, each matched by its own (glob). An extra argument
    is never taken in, so `npm publish` is not `npm publish --registry x`,
    and a * never crosses from one word into the next."""
    if subject_words is None or len(pattern_words) != len(subject_words):
        return False
    return all(glob(p, s) for p, s in zip(pattern_words, subject_words))


def match_path(pattern, subject, cwd=None):
    """Whether the path a tool read or wrote is the pattern's: both from
    the root (a relative one under cwd, the call's folder), as many
    components, each matched by its own. A * stays within its component."""
    p = _absolute(pattern)
    if p is None or not isinstance(subject, str) or not subject:
        return False
    s = _absolute(subject)
    if s is None:
        if not isinstance(cwd, str) or not _absolute(cwd):
            return False
        s = _absolute(_join(cwd, subject))
        if s is None:
            return False
    pp, sp = _parts(p), _parts(s)
    return len(pp) == len(sp) and all(glob(a, b) for a, b in zip(pp, sp))


# ---------------------------------------------------------------------------
# Reading the file
# ---------------------------------------------------------------------------

def _uncomment(line):
    """line up to the comment in it, or None when a quote in it is not
    closed. A # starts a comment at the start of the line, or after a
    blank, outside quotes, as in the shell: rm#x is one word. Inside '...'
    nothing is special; elsewhere a backslash takes the next character as
    it is. Read a special character at a time, so a line costs what it is
    long."""
    pos, escaped = 0, -1
    while True:
        m = _SPECIAL.search(line, pos)
        if not m:
            return line
        i, c = m.start(), m.group()
        if c == "#":
            if i == 0 or (line[i - 1] in _SHELL_BLANK and escaped != i - 1):
                return line[:i]
            pos = i + 1
        elif c == "'":
            close = line.find("'", i + 1)
            if close < 0:
                return None
            pos = close + 1
        elif c == '"':
            j = i + 1
            while True:
                found = _IN_DOUBLE.search(line, j)
                if not found:
                    return None
                if found.group() == "\\":
                    j = found.start() + 2
                    continue
                break
            pos = found.end()
        else:
            escaped = i + 1
            pos = i + 2


def _split(text):
    """text split into words as the shell splits them, or None when its
    quotes do not close. With no quote or backslash in it, on blanks, as
    watch._argv splits a command: shlex takes a character at a time."""
    if not _QUOTING.search(text):
        return [w for w in _BLANKS.split(text) if w]
    try:
        return shlex.split(text, comments=False, posix=True)
    except ValueError:
        return None


def _printable(text, limit=80):
    return watch._fit(watch._printable(text), limit)


class Entry(object):
    """A pattern line: RULE ['COMMAND'] [in=DIR] [until=YYYY-MM-DD]."""

    __slots__ = ("line", "rule", "pattern", "words", "path", "path_parts",
                 "within", "within_parts", "within_text", "until", "text")

    def __init__(self, line, rule, pattern=None, words=None, within=None,
                 within_text=None, until=None, text=""):
        self.line, self.rule, self.pattern, self.words = line, rule, pattern, words
        # The pattern as a path from the root, for a hit on a path a tool
        # read or wrote; None when it names none. A path with a blank in it
        # is quoted as one word, and is many words to a command.
        self.path = _absolute(pattern) if pattern is not None else None
        self.path_parts = _parts(self.path) if self.path else None
        self.within, self.within_text, self.until = within, within_text, until
        self.within_parts = _parts(within) if within else None
        self.text = text

    def expired(self, today):
        return self.until is not None and today > self.until

    def kind(self):
        """What the pattern is: a path, a command, or None for none."""
        if self.pattern is None:
            return None
        return ("path" if self.path is not None and len(self.words) == 1
                else "command")

    def covers(self, record, hit, today):
        """Whether this entry matches this hit of this record: its rule,
        its command or path, where it ran, and the day. A hit on what a
        call decoded, or on all of its text (a secret), is matched by no
        pattern and no rule-wide entry: only an id names those."""
        if hit.get("rule") != self.rule:
            return False
        return self.matches(_Facts(record, hit), today)

    def matches(self, facts, today):
        """covers, for a hit read once into _Facts: each entry of a rule is
        asked of the same hit, which is split into words only once."""
        if facts.on not in ("command", "path") or self.expired(today):
            return False
        if self.pattern is not None:
            if facts.on == "command":
                if not match_words(self.words, facts.words):
                    return False
            else:
                theirs = facts.path_parts
                if (self.path_parts is None or theirs is None
                        or len(theirs) != len(self.path_parts)
                        or not all(glob(a, b) for a, b in
                                   zip(self.path_parts, theirs))):
                    return False
        if self.within_parts is not None:
            where = facts.where_parts()
            if where is None or where[:len(self.within_parts)] != self.within_parts:
                return False
        return True

    def missing(self, on, today):
        """What this entry lacks to leave out a critical hit on a command or
        a path: [] when it may. Its command must name the program in full
        (the first word that is not NAME=value has no *, and no word is
        only *s); a path must be from the root, with a * only in its last
        part and something else there too; a command needs in=, and either
        needs an until= no more than CRITICAL_DAYS ahead."""
        out = []
        if self.pattern is None:
            out.append("command")
        elif on == "path":
            parts = _parts(self.path) if self.path else None
            if (not parts or any("*" in p for p in parts[:-1])
                    or not parts[-1].strip("*")):
                out.append("path")
        else:
            program = next((w for w in self.words
                            if not watch._ASSIGNMENT.match(w)), "")
            if "*" in program or not program or any(
                    not w.strip("*") for w in self.words):
                out.append("program")
        if self.within is None and on != "path":
            out.append("in=")
        if self.until is None:
            out.append("until=")
        elif self.until > today + datetime.timedelta(days=CRITICAL_DAYS):
            out.append("until<=400")
        return out


class Parsed(object):
    """What a file holds: each id and the line it is on, each entry, and
    each line skipped with why."""

    def __init__(self):
        self.ids = {}           # id -> line, for a plain id line
        self.acks = {}          # id -> line, for an ack line
        self.id_lines = 0       # lines of ids, ack ones too
        self.ack_lines = 0
        self.entries = []       # every Entry read, expired ones too
        self.skipped = []       # (line, why)
        self.blocks = []        # [first, last, lines, label, ack]
        self.lines = 0
        self._index = {}        # rule -> _Index

    def index(self, rule):
        return self._index.get(rule)


class _Facts(object):
    """What one hit is about, read once for every entry asked of it: what
    it is on, its command's words or its path's parts, and, only when an
    entry has in=, the parts of the folder it ran in."""

    __slots__ = ("on", "words", "path_parts", "_record", "_hit", "_where")

    def __init__(self, record, hit):
        self.on = hit.get("_on")
        self.words = self.path_parts = None
        self._record, self._hit, self._where = record, hit, False
        subject = hit.get("_subject")
        if not isinstance(subject, str):
            return
        if self.on == "command":
            self.words = watch._argv(subject)
        elif self.on == "path":
            path = _absolute(subject)
            cwd = record.get("cwd")
            if path is None and isinstance(cwd, str) and _absolute(cwd):
                path = _absolute(_join(cwd, subject))
            self.path_parts = _parts(path) if path else None

    def where_parts(self):
        if self._where is False:
            where = _absolute(_directory(self._record, self._hit))
            self._where = _parts(where) if where else None
        return self._where


def _program_key(words):
    """What an entry's command, or a hit's, is looked up by: how many
    words, its first two words (one alone has an empty second)."""
    return len(words), words[0], words[1] if len(words) > 1 else ""


class _Index(object):
    """A rule's entries, ready to be looked up for one hit: the ones with
    no pattern; the commands by their word count and first two words, a
    word with a * in it standing for any (looked at for every command of
    that count whose words before it match); and the paths by how many
    parts they have. A hit is then asked of the few entries that may match
    it, not of every entry of its rule."""

    def __init__(self):
        self.whole = []
        self.commands = {}
        self.paths = {}

    def add(self, entry):
        if entry.pattern is None:
            self.whole.append(entry)
            return
        n, first, second = _program_key(entry.words)
        if "*" in first:
            key = (n, None, None)
        elif "*" in second:
            key = (n, first, None)
        else:
            key = (n, first, second)
        self.commands.setdefault(key, []).append(entry)
        if entry.path_parts is not None:
            self.paths.setdefault(len(entry.path_parts), []).append(entry)

    def candidates(self, facts):
        """The entries that may match this hit, in the order of their
        lines."""
        found = list(self.whole)
        if facts.on == "command" and facts.words:
            n, first, second = _program_key(facts.words)
            get = self.commands.get
            found += get((n, first, second), ())
            found += get((n, first, None), ())
            found += get((n, None, None), ())
        elif facts.on == "path" and facts.path_parts is not None:
            found += self.paths.get(len(facts.path_parts), ())
        if len(found) > 1:
            found = sorted(set(found), key=lambda e: e.line)
        return found


_HEADING = re.compile(r"#\s*(ranwhat ignore [^,]{1,20}),\s*(\d{4}-\d\d-\d\d)")
# A line of ids alone, with ack or not, and a comment after a blank or
# none: what ranwhat ignore writes. A # after a blank starts a comment as
# _uncomment reads one, and any other line is read the long way.
_ID_LINE = re.compile(r"[ \t]*((?:[0-9a-fA-F]{16}[ \t]+)*[0-9a-fA-F]{16})"
                      r"(?:[ \t]+(ack))?(?:[ \t]+#.*|[ \t]*)\Z", re.S)


def parse(text, today=None):
    """Parsed for the text of an ignore file. Lines are split on \\n alone,
    each with one trailing \\r taken off: a CRLF file reads as it was
    written, and no other character a reader may break a line at makes
    one here, so a command quoted in a comment can never start an entry."""
    today = today or datetime.date.today()
    rules = {r.id for r in watch.RULES}
    parsed = Parsed()
    if text.startswith("\ufeff"):
        text = text[1:]
    block, label = None, None
    lines = text.split("\n")
    parsed.lines = len(lines) - (1 if lines and lines[-1] == "" else 0)
    for n, raw in enumerate(lines, 1):
        if raw.endswith("\r"):
            raw = raw[:-1]
        if len(raw) > MAX_LINE:
            parsed.skipped.append((n, "it is longer than %d characters" % MAX_LINE))
            block = label = None
            continue
        plain = _ID_LINE.match(raw)
        if plain:
            # Most of a baseline: ids, perhaps ack, and the comment ranwhat
            # wrote, read by one match, as the rest of this loop reads it.
            ack = plain.group(2) is not None
            ids = plain.group(1).lower().split()
        else:
            rest = _uncomment(raw)
            words = None if rest is None else _split(rest)
            if words is None:
                parsed.skipped.append((n, "a quote in it is not closed"))
                block = label = None
                continue
            if not words:
                if raw.strip():             # a comment alone
                    block = None
                    heading = _HEADING.match(raw.strip())
                    label = "%s, %s" % heading.groups() if heading else None
                continue
            ack = len(words) > 1 and words[-1] == "ack"
            ids = words[:-1] if ack else words
        if plain or all(_ID.match(w) for w in ids):
            ids = [w.lower() for w in ids]
            into = parsed.acks if ack else parsed.ids
            for i in ids:
                into.setdefault(i, n)
            parsed.id_lines += 1
            parsed.ack_lines += ack
            if block is not None and block[4] == ack and block[1] == n - 1:
                block[1], block[2] = n, block[2] + 1
            else:
                block = [n, n, 1, label, ack]
                parsed.blocks.append(block)
                label = None
            continue
        block = label = None
        entry, why = _entry(n, words, rest.strip(), rules)
        if entry is None:
            parsed.skipped.append((n, why))
            continue
        parsed.entries.append(entry)
        if not entry.expired(today):
            parsed._index.setdefault(entry.rule, _Index()).add(entry)
    return parsed


def _entry(n, words, text, rules):
    """(Entry, None) for a pattern line's words, or (None, why not)."""
    rule = words[0]
    if _ID.match(rule):
        return None, "a line of ids holds ids alone, and ack at its end"
    if rule == SECRET:
        return None, ("secrets are left alone with keep, in ranwhat clean's "
                      "review")
    if rule not in rules:
        return None, "there is no rule %s" % _printable(rule, 60)
    rest = list(words[1:])
    pattern = None
    if rest and not rest[0].startswith(("in=", "until=")):
        pattern = rest.pop(0)
    within = within_text = until = None
    seen = set()
    for word in rest:
        key = _KEY.match(word)
        if not key:
            return None, ("%s is one word too many; quote the command as one "
                          "word: %s 'COMMAND'" % (_printable(word, 40), rule))
        name, value = key.group(1), word[key.end():]
        if name not in ("in", "until"):
            return None, "there is no %s=; an entry takes in= and until=" % (
                _printable(name, 40))
        if name in seen:
            return None, "%s= is given twice" % name
        seen.add(name)
        if name == "in":
            within = _absolute(value.rstrip("/\\") or value)
            if within is None:
                return None, ("in=%s is not a folder from the root, such as "
                              "in=~/work/app" % _printable(value, 60))
            within_text = value
        else:
            try:
                if not _DATE.match(value):
                    raise ValueError(value)
                until = datetime.date.fromisoformat(value)
            except ValueError:
                return None, ("until=%s is not a date written YYYY-MM-DD"
                              % _printable(value, 40))
    split = None
    if pattern is not None:
        if not pattern.strip():
            return None, "its command is empty"
        if len(pattern) > MAX_PATTERN:
            return None, "its command is longer than %d characters" % MAX_PATTERN
        split = _split(pattern)
        if split is None:
            return None, "a quote in its command is not closed"
        if not split:
            return None, "its command is empty"
        if len(split) > MAX_WORDS:
            return None, "its command has more than %d words" % MAX_WORDS
    return Entry(n, rule, pattern, split, within, within_text, until, text), None


# ---------------------------------------------------------------------------
# The file in force for a run
# ---------------------------------------------------------------------------

def _read(path):
    """(text, None), or (None, why it cannot be used). Raises OSError where
    it cannot be opened at all: FileNotFoundError when there is none.

    A symlink is followed (a dotfiles manager links this file), but what
    it reaches must be a regular file, this user's, that other users
    cannot write: a file another account can change would let it decide
    what this one's reports leave out. A group may write it, since under
    umask 002 ~/.ranwhat is made group-writable. Checked on the open file,
    so what was checked is what is read. Not on Windows, whose ACLs these
    bits do not describe."""
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NONBLOCK", 0))       # a FIFO must not block
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "is not a regular file"
        if os.name != "nt" and hasattr(os, "geteuid"):
            if st.st_uid != os.geteuid():
                return None, "belongs to another user"
            if st.st_mode & 0o002:
                return None, "can be written by other users"
        if st.st_size > MAX_BYTES:
            return None, "is larger than %d MiB" % (MAX_BYTES >> 20)
        chunks, size = [], 0
        while size <= MAX_BYTES:
            chunk = os.read(fd, min(1 << 20, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > MAX_BYTES:
        return None, "is larger than %d MiB" % (MAX_BYTES >> 20)
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "is not UTF-8 text"


class Verdict(object):
    """What the file says of one record: hidden or not, by what (id, ack
    or pattern lines), and why a record it names is listed anyway."""

    __slots__ = ("hidden", "how", "lines", "note", "anyway")

    def __init__(self, hidden=False, how=None, lines=(), note=None, anyway=()):
        self.hidden, self.how, self.lines = hidden, how, list(lines)
        self.note, self.anyway = note, list(anyway)


class Ignore(object):
    """The ignore file in force for one run, and, once split has run,
    what it left out and what it would have, for every report to say."""

    def __init__(self, path=None, parsed=None, unused=None, explicit=False,
                 today=None, exists=None):
        self.path = path
        self.parsed = parsed or Parsed()
        self.unused = unused            # why it is not used, or None
        self.explicit = explicit
        self.today = today or datetime.date.today()
        self.exists = bool(parsed) if exists is None else exists
        self.mark = False
        self._reset()

    def _reset(self):
        self.left = []                  # records left out, or marked
        self.critical = 0
        self.by_id = 0
        self.by_line = {}               # line -> how many, by its first line
        self.acked = {}                 # line -> how many
        self.anyway = {}                # line -> [how many, missing]
        self.secret_listed = 0
        self.guard_listed = 0

    @property
    def show(self):
        return shown(self.path) if self.path else ""

    @classmethod
    def none(cls, path=None):
        """A run with nothing left out and nothing to say."""
        return cls(path, exists=False)

    @classmethod
    def open(cls, path=None, explicit=False, today=None):
        """The file at path (default_path() when None). Absent and not
        named, nothing is left out and nothing is said; unusable and not
        named, nothing is left out, and every report says why. Named with
        --ignore, absent or unusable is an IgnoreError: a run told to use
        a file must not quietly use none."""
        named = path
        path = os.path.expanduser(path) if path else default_path()
        try:
            text, why = _read(path)
        except (FileNotFoundError, NotADirectoryError) as error:
            # A file where the state folder would be holds no ignore file
            # either: nothing is left out, and nothing is said.
            if explicit:
                raise IgnoreError("cannot use --ignore %s (%s)"
                                  % (named, error.strerror or error))
            return cls.none(path)
        except OSError as error:
            why = "could not be read (%s)" % (error.strerror or error)
            text = None
        if text is None:
            if explicit:
                raise IgnoreError("cannot use --ignore %s (it %s)" % (named, why))
            return cls(path, unused=why, explicit=explicit, today=today,
                       exists=True)
        return cls(path, parse(text, today), explicit=explicit, today=today,
                   exists=True)

    # -- matching ----------------------------------------------------------

    def verdict(self, record):
        """Whether the file leaves out this record, and by what. A record is
        left out whole or not at all: by every id it has, or by an entry
        for each of its hits; never by an entry for one hit and not the
        other. A change to ranwhat's own state is left out only by ack
        lines, and a secret never."""
        parsed = self.parsed
        hits = [h for h in (record.get("hits") or ()) if isinstance(h, dict)]
        ids = _ids_of(record)
        guard = any(h.get("why") in watch.UNIGNORABLE for h in hits)
        secret = any(h.get("rule") == SECRET for h in hits)
        lines = [parsed.ids.get(i) or parsed.acks.get(i) for i in ids]
        by_id = bool(ids) and all(lines)
        if guard:
            if by_id and all(i in parsed.acks for i in ids) and not secret:
                return Verdict(True, "ack", sorted(set(lines)))
            named = any(lines) or self._named(record, hits)
            return Verdict(note="guard" if named else None)
        if by_id:
            if secret:
                return Verdict(note="secret")
            return Verdict(True, "id", sorted(set(lines)))
        covered, hit_lines, anyway = self._covered(record, hits)
        if covered and not secret:
            return Verdict(True, "lines", hit_lines)
        if covered:
            return Verdict(note="secret")
        return Verdict(anyway=anyway)

    def _matching(self, record, hit):
        """The entries that match one hit, in the order of their lines."""
        index = self.parsed.index(hit.get("rule"))
        if index is None or hit.get("_on") not in ("command", "path"):
            return []
        facts = _Facts(record, hit)
        return [e for e in index.candidates(facts) if e.matches(facts, self.today)]

    def _named(self, record, hits):
        """Whether any entry matches any hit of a record, critical or not:
        for one only an ack line may leave out, to say why it is listed."""
        return any(self._matching(record, hit) for hit in hits
                   if hit.get("rule") != SECRET)

    def _covered(self, record, hits):
        """(whether an entry covers every hit but a secret, the first line
        that does for each, [(line, missing)] for a critical hit an entry
        matched that may not leave out a critical action)."""
        today = self.today
        lines, anyway, any_hit = [], [], False
        covered = True
        for hit in hits:
            if hit.get("rule") == SECRET:
                continue
            any_hit = True
            found = self._matching(record, hit)
            if found and hit.get("severity") == watch.CRITICAL:
                on = hit.get("_on")
                good = [e for e in found if not e.missing(on, today)]
                if not good:
                    anyway.append((found[0].line, found[0].missing(on, today)))
                found = good
            if not found:
                covered = False
                continue
            lines.append(found[0].line)
        if not any_hit:
            covered = False
        return covered, sorted(set(lines)), anyway

    def split(self, records, mark=False):
        """The records the report lists, in order. The others are kept in
        self.left. mark (--no-ignore): every record is listed, and each the
        file would leave out carries "ignored", the lines that do."""
        self._reset()
        self.mark = mark
        if not self.exists or self.unused:
            return list(records)
        listed = []
        for record in records:
            if not isinstance(record, dict):
                listed.append(record)
                continue
            v = self.verdict(record)
            if v.hidden:
                self.left.append(record)
                if record.get("severity") == watch.CRITICAL:
                    self.critical += 1
                if v.how == "ack":
                    for line in v.lines[:1]:
                        self.acked[line] = self.acked.get(line, 0) + 1
                elif v.how == "id":
                    self.by_id += 1
                else:
                    first = v.lines[0]
                    self.by_line[first] = self.by_line.get(first, 0) + 1
                if mark:
                    record["ignored"] = v.lines
                    listed.append(record)
                continue
            listed.append(record)
            if v.note == "secret":
                self.secret_listed += 1
            elif v.note == "guard":
                self.guard_listed += 1
            for line, missing in v.anyway:
                seen = self.anyway.setdefault(line, [0, missing])
                seen[0] += 1
        return listed

    @property
    def hidden(self):
        """How many records the file leaves out of this run's report."""
        return 0 if self.mark else len(self.left)

    def failing(self, floor):
        """How many records it left out are at or above floor."""
        from . import sarif
        if self.mark:
            return 0
        return sum(1 for r in self.left if sarif.at_least(r.get("severity"), floor))

    # -- what every report says ---------------------------------------------

    def _entry_text(self, line):
        for entry in self.parsed.entries:
            if entry.line == line:
                return _printable(entry.text, 100)
        return ""

    def expired(self):
        return [(e.line, e.until) for e in self.parsed.entries
                if e.expired(self.today)]

    def _left_words(self, one=False):
        """What the first note says it left out: "2 by id and 1 by line 4
        (publish 'npm publish')", up to five lines named, then how many
        other lines; for one action, "by id" or "by line 4 (...)"."""
        parts = []
        if self.by_id:
            parts.append("by id" if one else "%d by id" % self.by_id)
        lines = sorted(self.by_line)
        for line in lines[:5]:
            said = "by line %d (%s)" % (line, self._entry_text(line))
            parts.append(said if one else "%d %s" % (self.by_line[line], said))
        if len(lines) > 5:
            parts.append("%d by %d other lines" % (
                sum(self.by_line[l] for l in lines[5:]), len(lines) - 5))
        return _and(parts)

    def notes(self):
        """Sentences under a text report: what was left out and by what,
        apart from what an ack line left out, then each line that names a
        critical action it may not leave out, each action listed though
        the file names it, each expired and skipped line, and a file not
        used."""
        out, show = [], self.show
        if self.unused:
            return ["%s %s, so it was not used: nothing is ignored."
                    % (show, self.unused)] + self._line_notes()
        if self.mark and self.left:
            n = len(self.left)
            out.append("--no-ignore: %s above %s %s %s leaves out; %s marked "
                       "with the line that does." % (
                           _actions(n), "is" if n == 1 else "are",
                           "one" if n == 1 else "ones", show,
                           "it is" if n == 1 else "each is"))
        elif self.left:
            plain = self.by_id + sum(self.by_line.values())
            if plain:
                critical = sum(1 for r in self.left
                               if r.get("severity") == watch.CRITICAL
                               and not _guarded(r))
                if plain == 1:
                    text = "1 action is not listed: %s leaves it out %s." % (
                        show, self._left_words(one=True))
                else:
                    text = "%s are not listed: %s leaves out %s." % (
                        _actions(plain), show, self._left_words())
                if critical:
                    text += (" It is critical." if plain == 1 else
                             " %d of them %s critical." % (
                                 critical, "is" if critical == 1 else "are"))
                text += " --no-ignore lists %s." % ("it" if plain == 1 else "them")
                out.append(text)
            out += self._acked_note()
        return out + self._line_notes()

    def _acked_note(self):
        """What an ack line left out, said apart from the rest, always."""
        acked = sum(self.acked.values())
        if not acked or self.mark:
            return []
        return ["%s an agent made to ranwhat's own settings %s not listed: you "
                "acknowledged %s on %s of %s." % (
                    _count(acked, "change"), "is" if acked == 1 else "are",
                    "it" if acked == 1 else "them", _lines(sorted(self.acked)),
                    self.show)]

    def _line_notes(self):
        out, show = [], self.show
        for line in sorted(self.anyway):
            n, missing = self.anyway[line]
            out.append("Line %d of %s (%s) matches %s but does not leave %s "
                       "out: %s. %s" % (
                           line, show, self._entry_text(line),
                           _count(n, "critical action"),
                           "it" if n == 1 else "them", _missing_words(missing),
                           _CRITICAL_RULE))
        if self.secret_listed:
            n = self.secret_listed
            out.append("%s %s matches %s still listed: %s a secret, which "
                       "ranwhat clean masks, or keeps if it is no secret." % (
                           _actions(n), show, "is" if n == 1 else "are",
                           "it holds" if n == 1 else "each holds"))
        if self.guard_listed:
            n = self.guard_listed
            out.append("%s that changed ranwhat's own settings %s listed though "
                       "%s names %s: such a change is left out only once "
                       "acknowledged on a terminal, with ranwhat ignore ID." % (
                           _actions(n), "is" if n == 1 else "are", show,
                           "it" if n == 1 else "them"))
        for line, until in self.expired():
            out.append("Line %d of %s (%s) expired on %s, and leaves nothing "
                       "out now." % (line, show, self._entry_text(line),
                                     until.isoformat()))
        for line, why in self.parsed.skipped:
            out.append("Line %d of %s is not an entry (%s), and was skipped."
                       % (line, show, why))
        return out

    def stderr_lines(self):
        """What --json says on stderr, a sentence a line, whenever the file
        left anything out or has something wrong with it: the list on
        stdout must stay what it was."""
        out, show = [], self.show
        if self.unused:
            return ["ranwhat: " + n for n in self.notes()]
        plain = self.by_id + sum(self.by_line.values())
        if plain and not self.mark:
            ways = []
            if self.by_id:
                ways.append("%d by id" % self.by_id)
            for line in sorted(self.by_line):
                ways.append("%d by line %d" % (self.by_line[line], line))
            critical = sum(1 for r in self.left
                           if r.get("severity") == watch.CRITICAL
                           and not _guarded(r))
            if critical:
                ways[-1] += "; %d critical" % critical
            out.append("ranwhat: %s %s not in this output: %s leaves %s out "
                       "(%s). --no-ignore includes %s." % (
                           _actions(plain), "is" if plain == 1 else "are", show,
                           "it" if plain == 1 else "them", ", ".join(ways),
                           "it" if plain == 1 else "them"))
        # Under --no-ignore each record marks itself with "ignored": there
        # is nothing "above" to point at.
        rest = self._acked_note() + self._line_notes()
        return out + ["ranwhat: " + n for n in rest]

    def summary(self):
        """check --json's "ignored", or None when there is nothing to say."""
        doc = {"file": self.path, "applied": not self.mark,
               "actions": len(self.left), "critical": self.critical,
               "by_id": self.by_id, "acknowledged": sum(self.acked.values()),
               "entries": [{"line": line, "entry": self._entry_text(line),
                            "actions": n} for line, n in sorted(self.by_line.items())],
               "listed_anyway": [{"line": line, "actions": n,
                                  "missing": [_json_missing(m) for m in missing]}
                                 for line, (n, missing) in sorted(self.anyway.items())],
               "secret_listed": self.secret_listed,
               "guard_listed": self.guard_listed,
               "expired": [{"line": line, "until": until.isoformat()}
                           for line, until in self.expired()],
               "skipped": [{"line": line, "why": why}
                           for line, why in self.parsed.skipped],
               "unused": self.unused}
        if not (self.left or self.anyway or self.secret_listed or self.guard_listed
                or doc["expired"] or doc["skipped"] or self.unused):
            return None
        return doc

    def sarif(self):
        """runs[0].properties.ignored, or None when nothing was left out."""
        if self.mark or not self.left:
            return None
        return {"actions": len(self.left), "critical": self.critical,
                "acknowledged": sum(self.acked.values())}


def _guarded(record):
    return any(isinstance(h, dict) and h.get("why") in watch.UNIGNORABLE
               for h in record.get("hits") or ())


def _ids_of(record):
    """Every id a record is known by, lower case; [] when it has none of
    the right shape."""
    ids = record.get("ids") or [record.get("id")]
    if not isinstance(ids, (list, tuple)):
        return []
    out = [i.lower() for i in ids if isinstance(i, str) and _ID.match(i)]
    return out if len(out) == len(ids) else []


def _and(parts):
    parts = list(parts)
    if len(parts) < 2:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def _count(n, word):
    from .agents import plural
    return plural(n, word)


def _actions(n):
    return _count(n, "action")


def _lines(lines):
    if len(lines) == 1:
        return "line %d" % lines[0]
    return "lines " + _and(str(l) for l in lines)


def _missing_words(missing):
    if "in=" in missing and "until=" in missing:
        rest = [m for m in missing if m not in ("in=", "until=")]
        return _and([_MISSING[m] for m in rest] + ["it has no in= and no until="])
    return _and(_MISSING[m] for m in missing)


def _json_missing(code):
    return "until= within %d days" % CRITICAL_DAYS if code == "until<=400" else code


# ---------------------------------------------------------------------------
# What ranwhat ignore writes
# ---------------------------------------------------------------------------

def _safe_comment(text):
    """text with every control and line-separator character taken out."""
    return _UNSAFE.sub("", text).replace("\x85", "")


# A word the file's own splitting gives back as it is: no blank, quote or
# backslash in it. A ~ or a * means nothing to it, so neither is quoted.
_PLAIN_FOR_SPLIT = re.compile(r"""[^\s'"\\]+\Z""")


def join_words(words):
    """words as one command, each quoted only where splitting it again
    needs that (shlex.join quotes a ~ or a * as the shell would expand it,
    which this file does not)."""
    return " ".join(w if _PLAIN_FOR_SPLIT.match(w) else shlex.quote(w)
                    for w in words)


def quote_command(command):
    """command as one word of the file: in single quotes, or in double ones
    when it holds a single quote and nothing a double quote changes."""
    if "'" not in command:
        return "'%s'" % command
    if '"' not in command and "\\" not in command:
        return '"%s"' % command
    return shlex.quote(command)


def dir_word(path):
    """A path as one word of the file: under ~ when it is in home, and
    quoted when it needs to be (a blank, a quote, a Windows path's \\).
    ~ is put back for home when the file is read, quoted or not."""
    home, p = os.path.expanduser("~"), path
    if os.name == "nt" or _DRIVE.match(p.replace("\\", "/")):
        # A Windows path, written with / as the file reads it either way,
        # so a folder joined to a cd is under ~ as much as one given whole.
        home, p = home.replace("\\", "/"), p.replace("\\", "/")
    if home not in ("", "/", "~") and (p == home or p.startswith(home + "/")):
        p = "~" + p[len(home):]
    return p if _PLAIN_WORD.match(p) else shlex.quote(p)


def _rank(hit):
    return {"critical": 2, "high": 1, "medium": 0}.get(hit.get("severity"), -1)


def _worst(record):
    hits = [h for h in record.get("hits") or () if isinstance(h, dict)]
    return sorted(hits, key=lambda h: -_rank(h)), hits


def _when(record):
    stamp = record.get("timestamp")
    if watch._epoch(stamp) is None:
        return "time unknown"
    return watch._local_time(stamp)[:16]


def describe(record):
    """The comment ranwhat writes after an action's ids: what it was, so the
    file can be read without watch beside it. The command when the worst
    hit has one of at most MAX_COMMENT characters, with where it ran; the
    path for a path; else the rule and its evidence, cut. Then how many
    hits more, the agent and the time. Masked as the report is, and with
    no character that could break the line."""
    hits, _all = _worst(record)
    if not hits:
        return _safe_comment("%s  (%s, %s)" % (
            "action", watch._SOURCE_NAMES.get(record.get("source"),
                                              record.get("source") or "?"),
            _when(record)))
    worst = hits[0]
    rule = str(worst.get("rule"))
    on, subject = worst.get("_on"), worst.get("_subject")
    text = None
    if on == "command" and isinstance(subject, str):
        words = watch._argv(subject)
        if words:
            quoted = quote_command(join_words(words))
            if len(quoted) <= MAX_COMMENT:
                text = "%s %s" % (rule, quoted)
                where = _directory(record, worst)
                if where:
                    text += " in=%s" % dir_word(where)
    elif on == "path" and isinstance(subject, str) and len(subject) <= MAX_COMMENT:
        text = "%s %s" % (rule, dir_word(subject))
    if text is None:
        text = "%s: %s" % (rule, watch._fit(str(worst.get("evidence") or ""),
                                            MAX_COMMENT))
    if len(hits) > 1:
        text += " (+%d more)" % (len(hits) - 1)
    name = watch._SOURCE_NAMES.get(record.get("source"), record.get("source") or "?")
    text += "  (%s, %s)" % (name, _when(record))
    return _safe_comment(text)


def id_line(record, ack=False):
    """The line that leaves out this record by its ids."""
    return "%s%s  # %s" % (" ".join(_ids_of(record)), " ack" if ack else "",
                           describe(record))


class Proposal(object):
    """Entries that would leave out every action like this one: for each
    hit, its command (or path), where it ran, and for a critical one until
    a year from today."""

    __slots__ = ("lines", "parts")

    def __init__(self, lines, parts):
        self.lines, self.parts = lines, parts   # parts: (kind, what, dir, until)


def proposal(record, today=None):
    """(Proposal, None), or (None, why ranwhat cannot write one). Not
    offered for a hit with no command or path to match (a secret, all of a
    call's text), one decoded from base64 or the like, a command or path
    holding a control character, or a critical command whose folder is
    not known. Each line is read back and must leave the record out, so
    nothing is offered that would not do what it says."""
    today = today or datetime.date.today()
    hits, _all = _worst(record)
    if not hits:
        return None, "it tripped no rule"
    lines, parts = [], []
    for hit in hits:
        rule = str(hit.get("rule"))
        on, subject = hit.get("_on"), hit.get("_subject")
        critical = hit.get("severity") == watch.CRITICAL
        if rule == SECRET:
            return None, ("it holds a secret, which ranwhat clean masks, or "
                          "keeps if it is no secret")
        if on == "decoded":
            return None, ("part of what it ran was decoded first, from "
                          "base64 or the like, and only its id names that")
        if on not in ("command", "path") or not isinstance(subject, str) or not subject:
            return None, "ranwhat has no command or path of it to match"
        if _UNSAFE.search(subject) or "\x85" in subject:
            return None, "its command holds a control character"
        until = today + datetime.timedelta(days=PROPOSE_DAYS) if critical else None
        if on == "command":
            words = watch._argv(subject)
            if not words:
                return None, "its command cannot be split into words"
            joined = join_words(words)
            if len(words) > MAX_WORDS or len(joined) > MAX_PATTERN:
                return None, "its command is too long to match word for word"
            where = _directory(record, hit)
            if critical and not where:
                return None, "ranwhat does not know which folder it ran in"
            line = "%s %s" % (rule, quote_command(joined))
            if where:
                line += " in=%s" % dir_word(where)
            parts.append(("command", joined, where, until))
        else:
            path = subject
            if not _absolute(path):
                cwd = record.get("cwd")
                if not isinstance(cwd, str) or not _absolute(cwd):
                    return None, "ranwhat does not know which folder it ran in"
                path = _join(cwd, path)
            line = "%s %s" % (rule, dir_word(path))
            parts.append(("path", path, None, until))
        if until:
            line += " until=%s" % until.isoformat()
        if _UNSAFE.search(line) or "\x85" in line:
            return None, "the folder it ran in holds a control character"
        if line not in lines:
            lines.append(line)
    check = Ignore(parsed=parse("\n".join(lines), today), today=today, exists=True)
    if not check.verdict(record).hidden:
        return None, "no entry ranwhat can write would leave it out; its id does"
    return Proposal(lines, parts), None


def unusable(show, why):
    """What ranwhat ignore says of a file it will not add to."""
    if why == "can be written by other users":
        return ("ranwhat ignore: %s can be written by other users, so ranwhat "
                "does not use it; chmod o-w it first. Nothing was added." % show)
    return ("ranwhat ignore: %s %s, so ranwhat does not use it. Nothing was "
            "added." % (show, why))


def add(path, items, heading=None, default=False):
    """Add lines to the file at path, which is made with HEADER when there
    is none. items are (ids or None, line): a line whose ids are all in the
    file already, or a pattern line it holds already, is not added again.
    The file is read again under a lock and written whole, 0600, through a
    new file put in its place: two runs adding at once both land, and a
    reader never sees half a file. A symlink to it (a dotfiles manager's)
    is written through, and stays a symlink. default: path is the file in
    ~/.ranwhat, whose folder is made, 0700, when there is none.

    Returns (first line added, last line added, how many were there
    already); (None, None, n) when nothing was added. Raises IgnoreError
    with what to print."""
    show = shown(path)
    real = os.path.realpath(path)
    folder = os.path.dirname(real)
    if default and not os.path.isdir(folder):
        try:
            # Another run may make it meanwhile: that is no error.
            os.makedirs(folder, 0o700, exist_ok=True)
        except OSError as error:
            raise IgnoreError("ranwhat ignore: cannot write %s (%s); nothing "
                              "was added." % (show, error.strerror or error))
    with known._locked(real + ".lock") as held:
        if not held:
            raise IgnoreError("ranwhat ignore: another ranwhat is writing %s; "
                              "nothing was added. Try again." % show)
        try:
            text, why = _read(real)
        except (FileNotFoundError, NotADirectoryError):
            text, why = None, None
        except OSError as error:
            raise IgnoreError("ranwhat ignore: cannot read %s (%s); nothing "
                              "was added." % (show, error.strerror or error))
        if why:
            raise IgnoreError(unusable(show, why))
        if text is None:
            text = HEADER
        parsed = parse(text)
        # An ack line is there already only as an ack: a plain id line for
        # the same action does not leave out a change to ranwhat's settings.
        present, acked = set(parsed.ids) | set(parsed.acks), set(parsed.acks)
        entries = {e.text for e in parsed.entries}
        new, there = [], 0
        for ids, line in items:
            ack = bool(ids) and line.split("#", 1)[0].split()[-1:] == ["ack"]
            if ids and all(i in (acked if ack else present) for i in ids):
                there += 1
                continue
            if ids is None and (_uncomment(line) or "").strip() in entries:
                there += 1
                continue
            if ids:
                present.update(ids)
                if ack:
                    acked.update(ids)
            new.append(_safe_comment(line.replace("\t", " ")))
        if not new:
            return None, None, there
        if text and not text.endswith("\n"):
            text += "\n"
        if heading:
            text += "# " + _safe_comment(heading) + "\n"
        first = text.count("\n") + 1
        text += "\n".join(new) + "\n"
        try:
            known._write_new(real, text.encode("utf-8"))
        except OSError as error:
            raise IgnoreError("ranwhat ignore: cannot write %s (%s); nothing "
                              "was added." % (show, error.strerror or error))
        return first, first + len(new) - 1, there


def read_report(stream):
    """The records of what ranwhat watch --json or check --json printed, as
    [(ids, guarded, record)], from stream (at most MAX_REPORT bytes). A
    record whose id is not of the right shape is passed over: it cannot
    be named. Raises IgnoreError for anything that is not such a report."""
    bad = IgnoreError("ranwhat ignore -: stdin is not the JSON ranwhat watch "
                      "--json or check --json prints.")
    raw = getattr(stream, "buffer", None)
    try:
        data = (raw or stream).read(MAX_REPORT + 1)
    except (OSError, ValueError):
        raise bad
    if len(data) > MAX_REPORT:
        raise IgnoreError("ranwhat ignore -: stdin is larger than %d MiB."
                          % (MAX_REPORT >> 20))
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8-sig")
        doc = json.loads(data)
    except (ValueError, RecursionError):
        raise bad
    records = doc.get("actions") if isinstance(doc, dict) else doc
    if not isinstance(records, list):
        raise bad
    out = []
    for record in records:
        if not isinstance(record, dict):
            raise bad
        ids = _ids_of(record)
        if not ids:
            continue
        out.append((ids, _guarded(record), record))
    return out


def now_heading(what, days=None, n=0):
    """The comment above a block ranwhat ignore all or - adds."""
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime())
    text = "ranwhat ignore %s, %s" % (what, when)
    if days:
        text += ", last %s" % watch._days(days)
    return "%s: %s" % (text, _actions(n))
