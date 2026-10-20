"""
Local agent watch: a flight recorder for agents running on this machine.

Not antivirus. There is no adversary and no signature -- you asked the agent
to do things. So this does not try to decide whether an action was permitted.
It records what happened and raises a narrow set of actions you would want to
know about regardless of intent.

Precision over recall, deliberately. A watcher that fires on every file write
gets muted in a day, and a muted watcher records nothing anyone reads.

Sources are pluggable. Claude Code writes JSONL session transcripts locally,
which makes it the source that can be validated against real data today; an
OTLP receiver slots in behind the same Action Record interface.
"""

from __future__ import annotations

import bisect
import collections
import contextlib
import datetime
import functools
import shlex
import hashlib
import itertools
import json
import ntpath
import os
import posixpath
import re
import time

from . import agents as _agents
from . import decode
from . import sources as _registry
from . import term
from .sources import _sqlite
from .sources import claude_code as _claude
from .sources import openclaw as _openclaw

# Claude Code's and OpenClaw's reading lives in their adapters
# (ranwhat/sources/claude_code.py and openclaw.py, design 3.9). The names
# below are those adapters' own functions, kept here for the CLI, clean
# and the tests that use them.
claude_projects = _claude.projects_dir


# Resolved once, at import, for the --root default and clean.scan's, so one
# run of either command reads one directory. Code that can pass root=None
# should: it gets claude_projects() at the time of the call.
CLAUDE_PROJECTS = claude_projects()

CRITICAL, HIGH, MEDIUM = "critical", "high", "medium"


class Rule(object):
    def __init__(self, rid, severity, title, why, patterns=(), scan_raw=False,
                 paths=False, find=None, hide=None, keep_source=False,
                 writes=None):
        self.id = rid
        self.severity = severity
        self.title = title
        self.why = why
        self.patterns = [p if hasattr(p, "search") else re.compile(p, re.I)
                         for p in patterns]
        # Most rules see only the parts of a shell command that actually
        # execute. A rule with scan_raw sees every string the call carried,
        # because for it the mere presence of the string is the finding: a
        # real key pasted into a grep pattern or a subagent's prompt has
        # still been leaked.
        self.scan_raw = scan_raw
        # Also judged on the paths a file-reading tool opened. Read on
        # ~/.aws/credentials is the same act as cat on it.
        self.paths = paths
        # Tried before the patterns, for what a regex cannot say in linear
        # time: text -> (start, end) of the first match, or None.
        self.find = find
        # For a shell command: text -> the same text, the same length, with
        # what the rule must not judge blanked out. Offsets survive, so the
        # evidence still quotes the command as it was written.
        self.hide = hide
        # Judged on the command with the source of other-language one-liners
        # kept: python3 -c "exec(base64.b64decode(...))" is a command whose
        # payload the other rules must not read, and this one must.
        self.keep_source = keep_source
        # Also judged on what a call writes. `echo 'x' >> ~/.zshrc` writes,
        # whatever it prints, and the text the other rules read drops echo
        # as text, so a shell command is judged as written instead, with
        # only its here-documents' bodies set aside (_write_view). Write on
        # ~/.zshrc is the same act, so the paths a file-writing tool wrote
        # are judged too, as Read's are for cred.read: by this find, given
        # them one per line.
        self.writes = writes

    def match(self, text):
        """(start, end) of the first match, or None."""
        if self.find is not None:
            span = self.find(text)
            if span:
                return span
        for p in self.patterns:
            m = p.search(text)
            if m:
                return m.span()
        return None


_SEARCH_CMD = re.compile(
    r"^\s*(?:sudo\s+)?(?:grep|egrep|fgrep|rg|ripgrep|ag|ack|find|locate|mdfind)\b")
_SEARCH_ACTS = re.compile(r"-delete\b|-exec\b|-ok\b|\|\s*xargs\b")
# git grep searches the tree, and git log given -S, -G or --grep searches
# history, for a string: neither runs it. Options before the subcommand
# may take a value (git -C repo grep). git grep -O hands what it finds to
# a program of its own choosing, which is no search.
_GIT_SEARCH = re.compile(
    r"^\s*(?:sudo\s+)?git(?:\s+-[^\s|;&]+(?:\s+[^\s|;&-][^\s|;&]*)?)*\s+"
    r"(?:grep\b|log\b(?=[\s\S]*\s(?:-[SG]|--grep\b|--pickaxe-)))")
_GIT_PAGER = re.compile(r"(?<!\S)(?:-O|--open-files-in-pager\b)")


class _Found(object):
    """A match that is not a regex's: its span."""

    def __init__(self, start, end):
        self._span = (start, end)

    def span(self):
        return self._span


class _Gap(object):
    """head, anything but a separator, then tail: what the regex
    head[^|;&]*tail finds, in linear time, with search() as a compiled
    regex has it.

    As one regex every head read on to the end of its stretch looking for
    the tail, and 64,000 characters of `git push ` took three seconds. A
    later head in the same stretch can reach only tails the first one
    reaches, so only the first head in each stretch is tried."""

    def __init__(self, head, tail, stops="|;&"):
        self.head = re.compile(head, re.I)
        self.tail = re.compile(tail, re.I)
        self.stop = re.compile("[%s]" % re.escape(stops))

    def search(self, text, pos=0):
        while True:
            head = self.head.search(text, pos)
            if not head:
                return None
            stop = self.stop.search(text, head.end())
            end = stop.start() if stop else len(text)
            tail = self.tail.search(text, head.end(), end)
            if tail:
                return _Found(head.start(), tail.end())
            if not stop:
                return None
            pos = stop.end()

    def match(self, text, pos=0):
        """What search finds, when its head starts at pos; else None."""
        head = self.head.match(text, pos)
        if not head:
            return None
        stop = self.stop.search(text, head.end())
        tail = self.tail.search(text, head.end(), stop.start() if stop else len(text))
        return _Found(head.start(), tail.end()) if tail else None


# Commands whose arguments are literal text, never a path being acted on.
# `cat` is deliberately absent: `cat ~/.aws/credentials` really is a read.
_TEXT_ONLY = re.compile(r"^\s*(?:sudo\s+)?(?:echo|printf|print)\b")

# `git rm --cached` unstages; it does not touch the working tree.
_GIT_RM_CACHED = re.compile(r"^\s*(?:sudo\s+)?git\s+rm\b[^|;&]*--cached\b")

# A comment is not a command.
_COMMENT = re.compile(r"(?:^|\s)#.*$")


def _is_inert(segment, into_shell=False):
    """True when a segment cannot perform the action its text mentions.
    Text piped into a shell (echo "rm -rf ~" | sh) is run by it."""
    if not segment.strip() or segment.lstrip().startswith("#"):
        return True
    if _GIT_RM_CACHED.match(segment) or (_TEXT_ONLY.match(segment) and not into_shell):
        return True
    return _is_search(segment)


def _is_search(segment):
    """True when this segment only looks for text, rather than acting on it.

    Judged per segment: `cat README | grep "rm -rf"` used to escape
    suppression entirely, because the `cat` half is not a search.
    """
    if not segment or not segment.strip():
        return False
    if _GIT_SEARCH.match(segment):
        return not _GIT_PAGER.search(segment)
    return bool(_SEARCH_CMD.match(segment)) and not _SEARCH_ACTS.search(segment)


# ---------------------------------------------------------------------------
# Evidence.
#
# A record is read by a person and often pasted somewhere else, so it must
# never carry the credential it warns about. Every value clean would report
# is replaced by its hint, the same way clean shows it.
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=32)
def _secret_spans(text):
    """Merged (start, end) of every occurrence of every value clean would
    report in text. clean decides, shapes, placeholders and fixtures alike,
    so the two commands cannot disagree about what is a credential.

    Cached because a hit asks twice, once to find a secret and once to mask
    the evidence around it. Imported late: clean imports this module."""
    from . import clean
    return clean.secret_spans(text)


# A test of a value that leaves it unflagged by secret.literal: one clean's
# review was told to keep (known.Kept), set for a run by sparing().
_SPARE = None


@contextlib.contextmanager
def sparing(spare):
    """For the run inside it, secret.literal leaves every value `spare` is
    true of (None: none): a value someone chose to keep is no finding."""
    global _SPARE
    before, _SPARE = _SPARE, spare
    try:
        yield
    finally:
        _SPARE = before


def _first_secret(text):
    """Span of the earliest credential in text, so the evidence sits on it
    and not on a fixture beside it. A value kept (_SPARE) is none."""
    spans = _secret_spans(text)
    if _SPARE is not None:
        spans = [(lo, hi) for lo, hi in spans if not _SPARE(text[lo:hi])]
    return spans[0] if spans else None


# Terminal control characters. A command carrying \033[2J or a tab is text
# to report, not something to replay on the reader's terminal.
# And half of a UTF-16 surrogate pair: Node writes one alone for an emoji
# cut in two, and no UTF-8 stream will print it.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")

# Command separators, the same ones _command_spans splits at. A match spanning
# lines (a private key) is bounded without the newline, or it would lose the
# `cat <<EOF` that says where it went.
#
# The blanks before a separator are taken from where they start, never from
# inside them (_AT_BLANKS): tried from every blank of a long run, each try
# read on to the end of the run looking for a separator, and sixty thousand
# blanks took seventeen seconds.
_AT_BLANKS = r"(?:(?!\s)|(?<!\s))\s*"
_BREAKS = re.compile(_AT_BLANKS + r"(?:\|\||&&|;|\||\n)\s*")
_INLINE_BREAKS = re.compile(_AT_BLANKS + r"(?:\|\||&&|;|\|)\s*")


def _printable(text):
    return _CONTROL.sub(" ", text)


def _evidence(text, span, before=20, after=70, known=None):
    """Evidence a human can judge. 'rm -rf' alone tells you nothing; you need
    to see what it was pointed at.

    The window stops at the command's own separators. `cat .env ; rm -rf ~/x`
    is two findings, and the deletion shown as the evidence for the read
    made the read look like a deletion. A match that spans a separator (a
    pipe to curl) keeps it.

    Secrets are masked by spans found in the whole text first. A window
    edge that falls inside a value would otherwise show the half it kept,
    which nothing looking at the window alone can recognise as a secret.
    `known`, a known.Matcher, adds every copy of every value clean finds
    anywhere in the history, wherever it starts: one typed glued to what
    is around it (xY3PASSWORD4Kq) is shown by its hint, whole or not at
    all, as one the rules find.
    """
    from . import clean
    start, end = span
    breaks = _INLINE_BREAKS if "\n" in text[start:end] else _BREAKS
    lo, hi = max(0, start - before), min(len(text), end + after)
    # Start on a word when one begins close by: "…t > key.pem" is `cat`.
    k = lo
    while k > 0 and lo - k < 12 and not text[k - 1].isspace() \
            and text[k - 1] not in ";|&":
        k -= 1
    if k == 0 or text[k - 1].isspace() or text[k - 1] in ";|&":
        lo = k
    for m in breaks.finditer(text, lo, hi):
        if m.end() <= start:
            lo = m.end()
        elif m.start() >= end:
            hi = m.start()
            break
    lo, hi, spans, shown = _masked_window(text, lo, hi, known)
    snippet = _printable(shown).strip()
    if not spans and lo == 0 and hi == len(text) and not _CONTROL.search(text):
        # All of text, in which the rules found nothing: a second look at
        # the same text finds the same. Once a value is masked the text is
        # not the same, and a second look can read what its hint now
        # stands apart from (<AKIA…>curl -u admin:...).
        evidence = snippet
    else:
        evidence = clean.mask_for_display(
            ("…" if lo > 0 else "") + snippet + ("…" if hi < len(text) else ""))
    if known:
        evidence = known.mask(evidence)
    return _masked_here(evidence)


def _masked_window(text, lo, hi, known=None, stretches=True):
    """(lo, hi, spans, shown): text[lo:hi] with each secret in it given by
    its hint, as clean shows it, once lo and hi are widened over any
    secret they would cut. A window edge inside a value would show the half
    it kept, which nothing reading the window alone can tell is a secret.
    spans are where the secrets are in all of text.

    What _evidence shows of a hit, and what a hit's subject holds
    (_subject_of), so the two are masked the same way. `known`, a
    known.Matcher, adds every copy of every value clean finds anywhere in
    the history. With stretches, what is about to be shown is asked too
    for a value known only by its mask, in every stretch, glued to letters
    or not, and in what the window would cut (known.Matcher.merged): a
    search with a budget for the whole run, which the evidence printed is
    given all of."""
    from . import clean
    spans = _secret_spans(text)
    if known:
        spans = known.merged(text, spans, shown=(lo, hi) if stretches else None)
    for s, e in spans:
        if s < lo < e:
            lo = s
        if s < hi < e:
            hi = e
    out, pos = [], lo
    for s, e in spans:
        if e <= lo or s >= hi:
            continue
        out.append(text[pos:s])
        out.append(clean.DISPLAY_MASK % clean._hint(text[s:e]))
        pos = e
    out.append(text[pos:hi])
    return lo, hi, spans, "".join(out)


def _masked_here(evidence):
    """evidence, noted as masked already (see _MASKED_HERE)."""
    if len(_MASKED_HERE) >= _MASKED_HERE_MAX:
        _MASKED_HERE.clear()
    _MASKED_HERE.add(evidence)
    return evidence


# Evidence _evidence has masked, which render need not mask again. It masks
# each hit's evidence for records this module did not build, and asked
# clean a third time about every one it did.
_MASKED_HERE = set()
_MASKED_HERE_MAX = 100000


# Paths whose entire purpose is to be thrown away.
_EPHEMERAL_BASENAMES = {
    "build", "dist", "target", "out", "node_modules", "__pycache__",
    ".venv", "venv", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".next", ".nuxt", ".turbo", ".parcel-cache", ".cache", "coverage",
    ".gradle", "vendor", ".terraform", "tmp", ".tox", ".eggs",
}
_TMP_PREFIXES = ("/tmp/", "/private/tmp/", "/var/folders/",
                 "/private/var/folders/", "/var/tmp/")
# Generated directories whose name varies but whose suffix does not.
_EPHEMERAL_SUFFIXES = (".egg-info", ".dist-info", ".egg-link")

# Deleting one of these is not routine under any circumstances.
_CATASTROPHIC = {"/", "~", "$HOME", "${HOME}", "~/", "/*", "$HOME/", "/Users",
                 "/home", "/usr", "/etc", "/var", "/System", "/Applications"}

_RM_ARGS = re.compile(r"\brm\s+(?:-[A-Za-z]+\s+)*([^|;&\n]+)")


_REDIRECT = re.compile(r"^\d*(?:>>?|<|&>)")


def _rm_targets(text):
    """Extract what a deletion was actually pointed at.

    Skips flags and shell redirections: `2>/dev/null` trailing an `rm` is not
    a path being removed, and treating it as one made every quietened
    cleanup look like a deletion of something real.
    """
    targets = []
    for m in _RM_ARGS.finditer(text):
        tokens = m.group(1).split()
        skip_next = False
        for raw in tokens:
            if skip_next:
                skip_next = False
                continue
            if raw.startswith("-"):
                continue
            if _REDIRECT.match(raw):
                if _REDIRECT.match(raw).end() == len(raw):
                    skip_next = True      # "> file" written with a space
                continue
            # The ) of a subshell or a $( ) it closes: (rm -rf ~). As many
            # as close one opened before the word, counted once: a count and
            # a copy for each ) made a run of them quadratic.
            extra = raw.count(")") - raw.count("(")
            if extra > 0:
                raw = raw[:len(raw) - min(extra, len(raw) - len(raw.rstrip(")")))]
            targets.append(raw.strip("\"\'"))
    return targets


def _is_ephemeral(target):
    """True when a path is throwaway by construction.

    Judged on every component, not just the basename: ~/.cache/uv/git-v0 is
    cache, and node_modules/foo/bar is still node_modules. Checking only the
    last segment missed both.
    """
    if not target:
        return False
    # /tmp/../Users/me and build/../src climb out of the throwaway directory
    # they name, so the name says nothing about what is deleted.
    if ".." in target.split("/"):
        return False
    if target.startswith(_TMP_PREFIXES) or target in ("/tmp", "/private/tmp"):
        return True
    parts = [p for p in target.rstrip("/").split("/") if p]
    if not parts:
        return False
    if parts[-1].endswith(_EPHEMERAL_SUFFIXES):
        return True
    return any(p in _EPHEMERAL_BASENAMES for p in parts)


def _normalise_target(t):
    """Trim a trailing slash without erasing the root itself -- "/".rstrip("/")
    is the empty string, which silently loses the one target that matters
    most."""
    return t if len(t) <= 1 else t.rstrip("/")


def _home():
    return os.path.expanduser("~")


# Home as the shell spells it: ~, $HOME, ${HOME}, and ${HOME:?}, ${HOME:-x}
# and the rest that expand to it while it is set. Then ~name, a user's
# home, which sits beside this one.
_HOME_PREFIX = re.compile(r"(?:~|\$HOME\b|\$\{HOME(?::?[-=?][^}]*)?\})(?=/|$)")
_USER_HOME = re.compile(r"~([A-Za-z_][\w.-]*)(?=/|$)")
# A last part that matches everything in a directory: *, .*, {*,.*}, .[!.]*
# A string test, not a regex: with * in the classes on both sides of the
# one * it had to hold, a run of them was split at every place, and 64,000
# did not finish in twenty seconds.
_GLOB_ONLY = "*?.{},[]!^"


def _everything_in(t):
    """Where the last part of t starts, at its /, when that part only
    matches everything in the directory before it; or -1."""
    slash = t.rfind("/")
    last = t[slash + 1:]
    return slash if slash != -1 and "*" in last and not last.strip(_GLOB_ONLY) else -1


def _as_absolute(target, home):
    """The absolute path a target names, with home put in for ~, $HOME and
    ${HOME}, a last part that matches everything in it dropped, and every
    . and .. walked; or None when it is not absolute. Quotes are the
    shell's, so they go: "$HOME"/.. is $HOME/.."""
    t = target.replace('"', "").replace("'", "")
    m = _HOME_PREFIX.match(t) or _USER_HOME.match(t)
    if m:
        if not home.startswith("/"):
            return None
        if m.re is _USER_HOME:
            base = posixpath.join(posixpath.dirname(home.rstrip("/")), m.group(1))
        else:
            base = home
        t = base + t[m.end():]
    if not t.startswith("/"):
        return None
    everything = _everything_in(t)
    if everything != -1:
        t = t[:everything] or "/"
    # POSIX keeps a leading // as it is, and //Users/me is /Users/me.
    return posixpath.normpath("/" + t.lstrip("/"))


def _is_catastrophic(t):
    """The target is the root, a system directory, the home directory or
    anything above it, however it is spelled: rm -rf /Users/<you> deletes
    what rm -rf ~ does, and ~/.. is /Users."""
    if _normalise_target(t) in _CATASTROPHIC or t in ("/*", "~/*", "$HOME/*"):
        return True
    if not t.startswith(("/", "~", "$", '"', "'")):
        return False
    home = _home()
    path = _as_absolute(t, home)
    if path is None:
        return False
    if path in _CATASTROPHIC:
        return True
    return (home.startswith("/") and home != "/"
            and (home + "/").startswith(path.rstrip("/") + "/"))


# Deletions that are not `rm`, so they have no target the refiner can judge.
# A temp `rm` alongside one of these says nothing about what it removed.
_FIND_DELETE = _Gap(r"find\s+", r"-delete\b")
_SHRED_OR_TRUNCATE = re.compile(r"shred\s+|truncate\s+-s\s*0")


def _unjudged_deletion(text):
    return bool(_FIND_DELETE.search(text) or _SHRED_OR_TRUNCATE.search(text))

# A link or mount made earlier in the same command can point a temp path
# anywhere: `ln -s ~ /tmp/h; rm -rf /tmp/h/Documents` deletes Documents.
_LINKING = re.compile(
    r"^\s*(?:sudo\s+)?(?:\S*/)?(?:ln|mount|bindfs|mount_nullfs)\s")


def _linked_before_rm(text):
    linked = False
    for segment in _commands(text):
        segment = _KEY_PREFIX.sub("", segment)
        if _LINKING.match(segment):
            linked = True
        elif linked and _RM_ARGS.search(segment):
            return True
    return False


def _refine_deletion(text, severity, tool_input=None):
    """Re-rank a deletion by what it was aimed at, not just the verb used."""
    flat = _rm_targets(text)
    if not flat:
        return severity
    if any(_is_catastrophic(t) for t in flat):
        return CRITICAL
    targets, vouched, escalate = _deletion_context(text, tool_input)
    if escalate or any(_is_catastrophic(t) for t in targets):
        return CRITICAL
    if not targets or _unjudged_deletion(text) or _linked_before_rm(text):
        return severity
    for t in targets:
        if _is_ephemeral(t):
            continue
        if vouched.get(t):
            vouched[t] -= 1           # each resolution vouches for one target
            continue
        return severity
    return None          # routine build/temp cleanup: not worth surfacing


# ---------------------------------------------------------------------------
# Same-command context for deletions.
#
# `SB=/private/tmp/.../bs ; rm -rf "$SB"` and `cd /tmp ; rm -rf iconlab`
# both delete a temp directory, but the target alone reads as a real one.
# This resolves the little context a command sets up for itself, and nothing
# more: a wrong resolution hides a real deletion, so anything the walker does
# not model ends resolution rather than being guessed at.
# ---------------------------------------------------------------------------

def _is_scalar(value):
    return value is None or isinstance(value, (bool, int, float))


def _deletion_context(text, tool_input):
    """(targets, vouched, escalate) for a deletion.

    The command's own earlier statements are resolved only when every other
    key is a scalar (Claude Code's timeout, run_in_background) or prose.
    Any other shape keeps the flat targets and resolves nothing: an argv
    key continues the command, and an env or workdir can change what the
    same words delete.
    """
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or not all(
            k == "command" or k in _CONTENT_KEYS or _is_scalar(v)
            for k, v in tool_input.items()):
        return _rm_targets(text), {}, False
    targets = _rm_targets(_executable_text(command))
    vouched, escalate = {}, False
    for target, path, trusted in _resolved_deletions(command):
        if _is_catastrophic(path):
            escalate = True
        elif trusted and _under_temp(path):
            vouched[target] = vouched.get(target, 0) + 1
    return targets, vouched, escalate


_TEMP_ROOTS = (("tmp",), ("private", "tmp"), ("var", "folders"),
               ("private", "var", "folders"), ("var", "tmp"))
_PATH_CHARS = re.compile(r"[A-Za-z0-9._@%+,:=-]+\Z")
_GLOB_CHARS = re.compile(r"[*?]")


def _clean_literal_path(path):
    """An absolute path that means exactly what it says: no expansion, no
    whitespace, no globs, and no `.`/`..` to walk it somewhere else."""
    if not path or not path.startswith("/"):
        return False
    parts = [p for p in path.split("/") if p]
    return all(_PATH_CHARS.match(p) and p not in (".", "..") for p in parts)


def _under_temp(path):
    """True for a resolved path strictly inside a temp root.

    `/tmp` itself, `/tmp/.` and `/tmp/*` are the whole temp directory, not
    something in it, so they never qualify. Globs only in the last component.
    """
    if not path or not path.startswith("/"):
        return False
    parts = [p for p in path.split("/") if p]
    if any(p in (".", "..") for p in parts):
        return False
    for i, p in enumerate(parts):
        if not _PATH_CHARS.match(_GLOB_CHARS.sub("", p) or "x"):
            return False
        if i < len(parts) - 1 and _GLOB_CHARS.search(p):
            return False
    for root in _TEMP_ROOTS:
        if tuple(parts[:len(root)]) == root and len(parts) > len(root):
            return not _GLOB_CHARS.search(parts[len(root)])
    return False


# Anything outside printable ASCII is refused outright: Python strips \r,
# \v, \f and Unicode spaces as whitespace, the shell does not, so
# `cd /tmp\r ; rm -rf src` fails the cd and deletes ./src.
_UNMODELLED_CHAR = re.compile(r"[^\t\n\x20-\x7e]")
_BRACED_PARAM = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")
_PARAM = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9#?$!@*-])")


def _dollar_end(s, i, quoted):
    """End of a `$` expansion the walker models, or None to stop."""
    nxt = s[i + 1:i + 2]
    if nxt == "{":
        m = _BRACED_PARAM.match(s, i)     # ${x:-y}, ${!x}, ${x/a/b}: no
        return m.end() if m else None
    if nxt == "(" or (not quoted and nxt in ("'", '"')):
        return None                       # $(...), $'...', $"..."
    m = _PARAM.match(s, i)
    return m.end() if m else i + 1


def _simple_commands(command, limit=256):
    """Split shell source into simple commands as the shell would.

    Returns [(op_before, words, op_after)], each word (raw, value, expands).
    Quote-aware, as _command_spans is, so `echo "x; cd /tmp"` holds no cd, and
    comments are comments even when they contain `<<`. Stops at the first
    construct it does not model -- subshells, groups, command substitution,
    heredocs, process substitution, case -- and returns only what came
    before it, because nothing after such a construct can be trusted.
    """
    out, words, op_before = [], [], None
    raw, val = [], []
    state = {"in_word": False, "expands": False, "redirect": False}
    i, n = 0, len(command)

    def end_word():
        if state["in_word"]:
            if state["redirect"]:
                state["redirect"] = False     # a redirect target, not an arg
            else:
                words.append(("".join(raw), "".join(val), state["expands"]))
        del raw[:], val[:]
        state["in_word"] = state["expands"] = False

    while i < n:
        c = command[i]
        if c in " \t":
            end_word()
            i += 1
        elif c == "#" and not state["in_word"]:
            j = command.find("\n", i)
            i = n if j < 0 else j
        elif c == "&" and command.startswith(">", i + 1):
            end_word()                        # &> and &>> redirect output
            if state["redirect"]:
                return out
            i += 3 if command.startswith(">>", i + 1) else 2
            state["redirect"] = True
        elif c in ";&|\n":
            end_word()
            if state["redirect"] or command.startswith((";;", ";&"), i):
                return out
            if command.startswith(("&&", "||"), i):
                op, i = command[i:i + 2], i + 2
            elif command.startswith("|&", i):
                op, i = "|", i + 2
            else:
                op, i = c, i + 1
            if not words:
                if op == "\n":
                    continue                  # blank line, or `&&` + newline
                return out
            out.append((op_before, list(words), op))
            if len(out) >= limit:
                return out
            del words[:]
            op_before = op
        elif c in "<>":
            if command.startswith(("<<", "<(", ">("), i):
                return out
            if state["in_word"] and "".join(raw).isdigit():
                del raw[:], val[:]            # `2>`: a descriptor, not a word
                state["in_word"] = state["expands"] = False
            else:
                end_word()
            if state["redirect"]:
                return out
            i += 1
            if i < n and command[i] in ">&|":
                i += 1
            state["redirect"] = True
        elif c in "(){}`":
            return out
        elif c == "'":
            j = command.find("'", i + 1)
            if j < 0:
                return out
            raw.append(command[i:j + 1])
            val.append(command[i + 1:j])
            state["in_word"] = True
            i = j + 1
        elif c == '"':
            j = i + 1
            while True:
                if j >= n:
                    return out
                d = command[j]
                if d == '"':
                    break
                if d == "`":
                    return out
                if d == "\\" and j + 1 < n:
                    e = command[j + 1]
                    if e in '$`"\\':
                        val.append(e)
                    elif e != "\n":
                        val.append(d + e)
                    j += 2
                elif d == "$":
                    k = _dollar_end(command, j, True)
                    if k is None:
                        return out
                    val.append(command[j:k])
                    state["expands"] = True
                    j = k
                else:
                    val.append(d)
                    j += 1
            raw.append(command[i:j + 1])
            state["in_word"] = True
            i = j + 1
        elif c == "\\":
            if i + 1 >= n:
                return out
            if command[i + 1] != "\n":        # backslash-newline joins lines
                raw.append(command[i:i + 2])
                val.append(command[i + 1])
                state["in_word"] = True
            i += 2
        elif c == "$":
            k = _dollar_end(command, i, False)
            if k is None:
                return out
            raw.append(command[i:k])
            val.append(command[i:k])
            state["in_word"] = state["expands"] = True
            i = k
        else:
            if c == "~" and not state["in_word"]:
                state["expands"] = True
            raw.append(c)
            val.append(c)
            state["in_word"] = True
            i += 1
    end_word()
    if words and not state["redirect"]:
        out.append((op_before, list(words), None))
    return out


# Words that start compound commands, and builtins that run code or rebind
# names. After any of these the walker cannot follow the shell, so it stops.
_RESERVED = {"if", "then", "else", "elif", "fi", "for", "while", "until",
             "do", "done", "case", "esac", "select", "function", "coproc",
             "!", "[[", "]]", "time"}
_OPAQUE_BUILTINS = {"eval", "source", ".", "trap", "alias", "enable", "exec"}

# Commands that cannot change the shell's directory or variables, so context
# survives them. Anything else -- including a function or alias from the
# user's shell snapshot, like zoxide's `z` or oh-my-zsh's `-` -- may cd or
# reassign invisibly, so it clears everything resolved so far.
_KEEPS_STATE = {"ls", "mkdir", "echo", "printf", "true", "false", ":", "cp",
                "touch", "cat", "test", "[", "pwd", "sleep", "set", "rm"}

# Commands that can make a temp path an alias for somewhere else.
_ALIASING = {"ln", "mount", "bindfs", "mount_nullfs", "mv"}
_LINK_FLAG = re.compile(r"-[A-Za-z]*[sl]|--(?:link|symbolic-link)\b")

# Only plain upper-case names are tracked. The shells reserve many names
# whose assignment is ignored or whose expansion is computed ($DIRSTACK is
# the cwd in bash; zsh ignores USERNAME=...), and lower-case zsh has dozens.
_TRACKABLE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_SHELL_SPECIAL = {
    "HOME", "PWD", "OLDPWD", "IFS", "CDPATH", "PATH", "ENV", "SHELL", "USER",
    "LOGNAME", "USERNAME", "UID", "EUID", "GID", "EGID", "PPID", "RANDOM",
    "SRANDOM", "SECONDS", "LINENO", "SHLVL", "DIRSTACK", "GROUPS", "BASHPID",
    "HISTCMD", "FUNCNAME", "EPOCHSECONDS", "EPOCHREALTIME", "OPTARG",
    "OPTIND", "REPLY", "TTY", "TTYIDLE", "ERRNO", "ARGC", "HOST", "HOSTNAME",
    "HOSTTYPE", "MACHTYPE", "OSTYPE", "VENDOR", "PIPESTATUS", "SHELLOPTS",
    "BASHOPTS", "LINES", "COLUMNS", "FPATH", "MANPATH", "MODULE_PATH",
    "ZDOTDIR", "PSVAR", "PROMPT_COMMAND", "TMOUT", "KEYBOARD_HACK"}
_SPECIAL_PREFIXES = ("BASH", "ZSH_", "ZLE_", "COMP_", "READLINE_", "HIST",
                     "LC_", "TRY_BLOCK_", "PS")
_ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)\Z", re.S)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_VAR_REF = re.compile(
    r'(?:\$(?P<a>[A-Za-z_][A-Za-z0-9_]*)|\$\{(?P<b>[A-Za-z_][A-Za-z0-9_]*)\}'
    r'|"\$(?P<c>[A-Za-z_][A-Za-z0-9_]*)(?P<cs>/[A-Za-z0-9._@%+,:=/-]*)?"'
    r'|"\$\{(?P<d>[A-Za-z_][A-Za-z0-9_]*)\}(?P<ds>/[A-Za-z0-9._@%+,:=/-]*)?")'
    r'(?P<s>/[A-Za-z0-9._@%+,:=/*?-]*)?\Z')


def _forget_mentioned(env, texts):
    """Drop every tracked name used other than as a plain $NAME or ${NAME}.

    `read SB`, `unset SB`, `printf -v SB`, `SB+=x`, `${SB:-x}` and a prefix
    assignment all change or reinterpret it. Run over dequoted values too,
    so `read S\\B` and `export S''B=...` are seen for what the shell sees.
    One pass over the text, whatever the number of names.
    """
    for text in texts:
        for m in _IDENT.finditer(text):
            name = m.group()
            if name not in env:
                continue
            s = m.start()
            if s >= 1 and text[s - 1] == "$":
                continue
            if text[s - 2:s] == "${" and text[m.end():m.end() + 1] == "}":
                continue
            del env[name]


def _assigned_value(raw_value):
    """The literal an assignment stores, if it is a clean absolute path."""
    if any(ch in raw_value for ch in "$`~\\"):
        return None
    value = raw_value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    if "'" in value or '"' in value:
        return None
    return value if _clean_literal_path(value) else None


def _resolve(word, env, cwd):
    """The absolute path a word names, or None when that is not certain."""
    raw = word[0]
    m = _VAR_REF.match(raw)
    if m:
        name = m.group("a") or m.group("b") or m.group("c") or m.group("d")
        if name not in env:
            return None
        return env[name] + (m.group("cs") or m.group("ds") or "") + (m.group("s") or "")
    # zsh expands a leading `=cmd` to that command's path.
    if raw.startswith("=") or any(ch in raw for ch in "$~'\"\\{`"):
        return None
    if raw.startswith("/"):
        return raw
    if cwd:
        return cwd.rstrip("/") + "/" + raw
    return None


def _resolved_deletions(command, depth=0, aliased=False):
    """(target, path, trusted) for each `rm` target this command resolves
    through its own earlier statements.

    Only a variable assigned earlier in the same command, as its own
    unconditional statement, and a `cd` that certainly ran, are followed.
    `rm` must be the command word: `ssh host rm -rf app` and
    `docker exec web rm -rf uploads` delete somewhere else entirely.
    """
    found = []
    if (depth > 3 or not command or len(command) > MAX_SCAN_CHARS
            or _UNMODELLED_CHAR.search(command)):
        return found
    env, cwd, fixed = {}, None, False
    for op_before, words, op_after in _simple_commands(command):
        raws = [w[0] for w in words]
        values = [w[1] for w in words]
        if (raws[0] in _RESERVED or values[0] in _OPAQUE_BUILTINS
                or any("IFS" in r for r in raws)):
            break
        if env:
            _forget_mentioned(env, raws + values)
        # A cd that is not certain to have run lasts only through an
        # unbroken && chain: `cd /x && true ; rm y` may run rm anywhere.
        if cwd and not fixed and op_before != "&&":
            cwd = None
        unconditional = op_before in (None, ";", "\n")

        if len(words) == 1 and _ASSIGNMENT.match(raws[0]):
            name, rest = _ASSIGNMENT.match(raws[0]).groups()
            value = _assigned_value(rest)
            if (value and unconditional and op_after in (None, ";", "\n", "&&")
                    and _TRACKABLE.match(name) and name not in _SHELL_SPECIAL
                    and not name.startswith(_SPECIAL_PREFIXES)
                    and (name in env or len(env) < 32)):
                env[name] = value
            else:
                env.pop(name, None)
            continue

        k = 0
        while k < len(words) and _ASSIGNMENT.match(raws[k]):
            k += 1                            # prefix assignments: forgotten above
        argv, rest = values[k:], words[k:]
        if not argv:
            continue
        base = argv[0].rsplit("/", 1)[-1]

        if base == "cd" and not k:
            cwd, fixed = None, False
            if len(argv) == 2 and unconditional:
                path = _resolve(rest[1], env, None)
                if path and _clean_literal_path(path):
                    path = path.rstrip("/") or "/"
                    # /tmp and /var/tmp exist on every macOS and Linux box,
                    # so `cd /tmp ;` can be trusted without an &&. Nothing
                    # else can: `cd /tmp/work ; rm -rf out` may run in ./
                    if path in ("/tmp", "/var/tmp") and op_after in (
                            None, ";", "\n", "&&"):
                        cwd, fixed = path, True
                    elif op_after == "&&":
                        cwd = path
            continue

        if base == "rm" or (base == "sudo" and len(argv) > 1
                            and argv[1].rsplit("/", 1)[-1] == "rm"):
            # sudoers `runcwd` can start sudo somewhere else, so a sudo rm
            # only resolves through variables, never through the cwd.
            here = cwd if base == "rm" else None
            for w in rest[1 if base == "rm" else 2:]:
                if w[1].startswith("-"):
                    continue
                path = _resolve(w, env, here)
                if path:
                    found.append((w[0].strip("\"'"), path, not aliased))
            continue

        if base in _SHELL_INTERPRETERS:
            flag = next((j for j, a in enumerate(argv) if a in _PAYLOAD_FLAGS), None)
            # A body with $ in it was expanded by THIS shell first, with
            # values the inner walk would not know.
            if flag is not None and flag + 1 < len(rest) and not rest[flag + 1][2]:
                found.extend(_resolved_deletions(rest[flag + 1][1], depth + 1, aliased))
            aliased = True
        elif (base in _ALIASING or base in _FOREIGN_INTERPRETERS
              or (base == "cp" and any(_LINK_FLAG.match(a) for a in argv[1:]))):
            aliased = True
        if base not in _KEEPS_STATE or k:
            env, cwd, fixed = {}, None, False
    return found


# ---------------------------------------------------------------------------
# Credential access: what is being touched, and how.
#
# On a lightly used machine this rule looked fine. On a working one it fired
# on .env.example (a template with no secrets in it), on a PUBLIC ssh key, on
# `rsync --exclude .env` (which is the agent protecting the file), and on
# `git check-ignore`, which reads nothing at all.
# ---------------------------------------------------------------------------

# Templates ship in the repo on purpose and hold placeholder values.
_NOT_SECRET_SUFFIXES = (".example", ".sample", ".template", ".dist",
                        ".defaults", ".pub")

# A service account's key file has service-account somewhere in its name
# before .json. The name up to the first one is taken by a lookahead and
# matched again by reference, which cannot backtrack: as two runs around
# the words, every service_account in one long word read on to its end,
# and 63K of them took two seconds. A path may start with a drive or a
# variable (C:/, %USERPROFILE%/, $env:HOME/), once _slashed has read it.
#
# ranwhat's own two are named with their folder: a file called key or token
# is anyone's. Its token is its account's credential, and its key is what a
# kept secret is hashed under, so whoever holds it can write kept.json to
# keep any value out of every report.
_CRED_PATH = re.compile(
    r"(?:^|[\s\"'=(])((?:[\w./~$%:-]*/)?(?:\.env[\w.-]*|credentials|"
    r"\.netrc|id_[a-z0-9]+(?:\.pub)?|[\w.-]*\.pem|[\w.-]*\.key|\.kube/config|"
    r"\.ranwhat/+(?:known/+(?:\./)?key|token)\b|"
    r"(?:\$\{?|%|\$env:)RANWHAT_HOME[}%]?/+(?:known/+(?:\./)?key|token)\b|"
    r"(?=(?P<account>[\w.-]*?service[-_]account))(?P=account)[\w.-]*\.json))",
    re.I)

# Commands that handle a file without ever reading its contents.
_NON_READING = re.compile(
    r"^\s*(?:sudo\s+)?(?:ls|ll|stat|file|test|\[|cp|mv|rm|touch|chmod|chown|"
    r"mkdir|basename|dirname|realpath|readlink|du|wc)\b")
_GIT_METADATA = re.compile(r"^\s*(?:sudo\s+)?git\s+(?:check-ignore|ls-files|status|add)\b")

_KEY_PREFIX = re.compile(r"^\s*(?:command|file_path|path|pattern|args?)\s+")

# The command redacts as it goes -- that is care, not exposure: it
# replaces values with nothing or a mask, or runs a sed whose substitution
# writes ***.
_REDACTING = re.compile(
    r"s[/|#;,]\s*=\.\*|=<(?:set|redacted|present)>|:\*\*\*|<redacted", re.I)
_SED_SUBSTITUTION = re.compile(r"\bs[/|#;,]")


def _redacting(segment):
    """Whether one command masks what it reads. The sed test was one regex
    with two runs in it, and a sed in front of each of 142,000 s/ did not
    finish; it is three lookups in one command now."""
    if _REDACTING.search(segment):
        return True
    sed = segment.lower().find("sed")
    script = _SED_SUBSTITUTION.search(segment, sed + 3) if sed != -1 else None
    return script is not None and segment.find("***", script.end()) != -1


def _cred_targets(text):
    return [m.group(1) for m in _CRED_PATH.finditer(text)]


def _is_template(target):
    """A template or a public key: named like a secret, holding none."""
    base = target.rstrip("/").split("/")[-1].lower()
    return base.endswith(_NOT_SECRET_SUFFIXES)


# A credential file handed to what uses it, not read out: loaded into the
# shell, given to a program as its env file, identity, kubeconfig or key
# file, or named by a variable that a program reads. Each alternative
# names the file it hands over; -i is an identity only beside ssh and its
# kin, and everything after ssh-add is one.
_HANDED_OVER = re.compile(
    r"^\s*(?:sudo\s+)?(?:source|\.)\s+['\"]?(?P<source>[^\s'\";&|]+)"
    r"|--(?:env-file|kubeconfig|key-file|keyfile|identity-file|private-key)"
    r"(?:=|\s+)['\"]?(?P<flag>[^\s'\";&|]+)"
    r"|(?:^|\s)-i\s*['\"]?(?P<identity>[^\s'\";&|]+)"
    r"|-o\s*['\"]?IdentityFile[= ]['\"]?(?P<option>[^\s'\";&|]+)"
    r"|(?:^|\s)[A-Za-z_][A-Za-z0-9_]*=['\"]?(?P<variable>[^\s'\";&|]+)")
# ssh and its kin as a program: not the .ssh directory a key sits in, which
# made any -i before ~/.ssh/id_rsa an identity (base64 -i prints the key).
_SSH_LIKE = re.compile(r"(?<![\w.-])(?:ssh|scp|sftp|sshfs|autossh)(?![\w.-])")
_SSH_ADD = re.compile(r"^\s*(?:sudo\s+)?ssh-add\b")
# What rsync and tar are told to skip.
_EXCLUDED = re.compile(r"--exclude(?:=|\s+)['\"]?(\S+)")

# A command that prints the environment, or a variable from it. declare
# and typeset print with -p or -x among their flags, which a lookahead
# finds: two runs of letters around the p could split a run of p's in n
# squared ways, and 63,000 of them did not finish in twenty seconds.
_PRINTS_ENVIRONMENT = re.compile(
    r"^\s*(?:sudo\s+)?(?:printenv\b|env(?:\s+-0)?\s*$|set\s*$|export(?:\s+-p)?\s*$"
    r"|(?:declare|typeset)\s+-(?=[A-Za-z]*[px])[A-Za-z]+\s*$"
    r"|(?:echo|printf|print)\b.*\$)")

# What prints what a file handed over holds, though the command does not
# start by printing: an interpreter or a here-string reading a variable,
# echo in a shell the file was handed to, printenv anywhere (op run --
# printenv), env as the last word (docker run --env-file .env alpine env),
# and the subcommands that print the configuration or secrets they were
# given: docker compose config, kubectl config view --raw, kubectl get
# secret -o yaml. Each was critical before handing over was told from
# reading, and became silent.
_READS_ENVIRONMENT = re.compile(
    r"\bos\.environ\b|\bprocess\.env\b|\bgetenv\b|\bENV\[|\$ENV\{|\bDeno\.env\b"
    r"|<<<\s*[\"']?\$")
_ECHO_WORD = re.compile(r"(?<![\w.-])(?:echo|printf)(?![\w.-])")
_OUTPUT_FORMAT = re.compile(
    r"(?<![\w-])(?:-o\s*|--output[=\s]\s*)['\"]?(?:ya?ml|json|jsonpath|go-template"
    r"|template)")
_WORD_QUOTES = "\"'`()"


def _shows_what_it_was_handed(segment):
    """Whether one command prints what a credential file handed to it, or
    to the shell, holds. Each test is one pass over the command."""
    if _READS_ENVIRONMENT.search(segment):
        return True
    echo = _ECHO_WORD.search(segment)
    if echo and segment.find("$", echo.end()) != -1:
        return True
    words = [w.strip(_WORD_QUOTES) for w in segment.split()]
    names = [w.rsplit("/", 1)[-1] for w in words]
    if "printenv" in names:
        return True
    commands = [n for n in names if n and not n.startswith("-")]
    if commands and commands[-1] == "env":
        return True
    compose = next((i for i, n in enumerate(names)
                    if n in ("compose", "docker-compose")), None)
    if compose is not None and "config" in names[compose + 1:]:
        return True
    pairs = set(zip(names, names[1:]))
    if "kubectl" in names:
        if ("config", "view") in pairs and ("--raw" in names or "--flatten" in names):
            return True
        if any(a == "get" and (b in ("secret", "secrets")
                               or b.startswith(("secret/", "secrets/")))
               for a, b in pairs) and _OUTPUT_FORMAT.search(segment):
            return True
    return False


_PRINTED_WHY = ("The agent handed a file whose only purpose is to hold secrets "
                "to the shell or a program, and the same command printed what "
                "it holds. Whatever it printed is now in a model context you "
                "do not control.")


def _all_handed_over(segment, found):
    """Whether every credential path found in segment sits inside a file the
    segment hands over. One pass over the segment for what it hands over,
    then a lookup per path: a regex built per path and run over the whole
    segment made five thousand ssh -i keys take three seconds."""
    if _SSH_ADD.match(segment):
        return True
    ssh = _SSH_LIKE.search(segment) is not None
    spans = [m.span(m.lastgroup) for m in _HANDED_OVER.finditer(segment)
             if m.lastgroup != "identity" or ssh]
    starts = [lo for lo, _hi in spans]
    for m in found:
        i = bisect.bisect_right(starts, m.start(1)) - 1
        if i < 0 or m.end(1) > spans[i][1]:
            return False
    return True


def _prints_environment(tool_input):
    """Whether the command prints the environment, a variable in it, or
    what a file handed to a program holds. Asked of the command as
    written: echo is dropped from what runs, since its words are text, but
    here it is the printing, and an interpreter's source is where it reads
    the variable."""
    if not isinstance(tool_input, dict):
        return False
    command = " ; ".join(c for c in (_words(tool_input.get(k)) for k in _COMMAND_KEYS)
                         if c)
    return any(_PRINTS_ENVIRONMENT.match(segment) or _shows_what_it_was_handed(segment)
               for segment in _commands(_strip_heredocs(command)[:MAX_SCAN_CHARS]))


# A variable set to a credential file's path, and each place it is read
# back. One pass: an assignment starts only where a name does.
_SET_OR_EXPANDED = re.compile(
    r"(?<![A-Za-z0-9_$])(?P<name>[A-Za-z_][A-Za-z0-9_]*)=['\"]?"
    r"(?P<value>[^\s'\";&|]+)"
    r"|\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))")


def _with_paths_put_back(text):
    """text with each $NAME and ${NAME} read after NAME was set to a
    credential file's path replaced by that path. Only a prefix hands a
    file to the program it runs (KUBECONFIG=~/.kube/config kubectl): a bare
    assignment hands it to nothing, and `F=~/.aws/credentials; cat "$F"`
    reads the file as `cat ~/.aws/credentials` does. Read as handed over,
    it was dropped, where it had been critical.

    What is put back is held to MAX_SCAN_CHARS: a long path read back
    thousands of times would otherwise grow the text by their product."""
    if "$" not in text or "=" not in text:
        return text
    paths, out, pos, added = {}, [], 0, 0
    for m in _SET_OR_EXPANDED.finditer(text):
        name = m.group("name")
        if name:
            if _CRED_PATH.match(m.group("value")):
                paths[name] = m.group("value")
            else:
                paths.pop(name, None)
            continue
        path = paths.get(m.group("braced") or m.group("bare"))
        if path is not None:
            added += len(path)
            if added > MAX_SCAN_CHARS:
                break
            out.append(text[pos:m.start()])
            out.append(path)
            pos = m.end()
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def _refine_credential(text, severity, tool_input=None):
    """Re-rank a credential match by what the command did with the file.
    Reading it is critical. Handing it to a program (source .env, docker
    --env-file, ssh -i, kubectl --kubeconfig) puts none of it in the
    model's context, unless the command then prints the environment, and
    that is reported as what it is, with its own why. A variable that
    names the file is judged where it is read back."""
    text = _with_paths_put_back(text)
    targets = _cred_targets(text)
    if not targets:
        return severity

    # Named after --exclude, it is named only in order to be skipped. Every
    # argument is collected once and a target looked up among them: a
    # regex built per target was a pass over the command each.
    excluded = sorted(m.group(1) for m in _EXCLUDED.finditer(text))

    def skipped(t):
        i = bisect.bisect_left(excluded, t)
        return i < len(excluded) and excluded[i].startswith(t)

    real = {t for t in targets if not _is_template(t) and not skipped(t)}
    if not real:
        return None

    # Which segment actually touched it?
    handed = False
    for segment in _commands(text):
        segment = _KEY_PREFIX.sub("", segment)
        found = [m for m in _CRED_PATH.finditer(segment) if m.group(1) in real]
        if not found:
            continue
        if _NON_READING.match(segment) or _GIT_METADATA.match(segment):
            continue                      # moved, listed, or asked about
        if _redacting(segment):
            return MEDIUM                 # read, but deliberately masked
        if _all_handed_over(segment, found):
            handed = True
            continue
        return severity
    if handed and _prints_environment(tool_input):
        return severity, _PRINTED_WHY
    return None


# Where a command writes rather than reads: an output redirection and its
# target (>, >>, >|, 1>, &>), and every file tee copies its input into.
# Not `2>&1` or `>&2`, which name a descriptor, and not `<>`, which reads.
_OUTPUT_REDIRECT = re.compile(
    r"(?<![<>&\d])(?:\d+|&)?>>?\|?[ \t]*"
    r"(?:'[^'\n]*'|\"[^\"\n]*\"|[^\s;&|<>()'\"]+)")
_TEE = re.compile(r"\s*(?:sudo\s+)?(?:\S*/)?tee(?=\s|$)")
_WORD = re.compile(r"\S+")
_INPUT = re.compile(r"\d*<+")


def _without_writes(text):
    """text with every file it only writes blanked out, at the same offsets.

    `cat > .env <<'EOF'` and `echo PORT=1 | tee .env` create a credential
    file; neither reads one, and both were reported as a read. A redirection
    from a file (`tee copy < .env`) is a read, and is kept."""
    if ">" not in text and "tee" not in text:
        return text
    text = _OUTPUT_REDIRECT.sub(lambda m: " " * len(m.group()), text)
    if "tee" not in text:
        return text
    chars = list(text)
    for start, end, _op in _command_spans(text):
        tee = _TEE.match(text, start, end)
        if not tee:
            continue
        feeding = False
        for w in _WORD.finditer(text, tee.end(), end):
            if feeding:
                feeding = False           # what `<` reads: keep it
                continue
            op = _INPUT.match(w.group())
            if op:
                feeding = op.end() == len(w.group())
                continue
            chars[w.start():w.end()] = " " * (w.end() - w.start())
    return "".join(chars)


# A backslash between the parts of a Windows path: after a drive, a name
# or a variable (%USERPROFILE%, $env:USERPROFILE, ~), and before a name.
# Not one escaping in a POSIX shell (sed 's/\.env/', grep '\.ssh'), which
# follows a separator or a quote.
_WINDOWS_SEPARATOR = re.compile(r"(?<=[\w.~%$:-])\\(?=[\w.~%$-])")


def _slashed(text):
    """text with each backslash that separates the parts of a Windows path
    read as /, at the same offsets. The credential rules know only /, and
    no agent's read of C:\\Users\\u\\.ssh\\id_rsa or C:\\proj\\.env was
    reported."""
    return _WINDOWS_SEPARATOR.sub("/", text) if "\\" in text else text


_DRIVE = re.compile(r"[A-Za-z]:[\\/]")


def _credential_text(text):
    """What cred.read judges in a shell command: what it reads, with each
    word slashed that has no / in it, or names a drive. One with a / and
    no drive is a POSIX script, where a backslash escapes, and
    sed 's/config\\.env/x/' read no .env."""
    text = _without_writes(text)
    if "\\" not in text:
        return text
    return _WORD.sub(lambda m: _slashed(m.group()) if "/" not in m.group()
                     or _DRIVE.search(m.group()) else m.group(), text)


def _refine_read_path(text, severity, tool_input=None):
    """A path a file-reading tool opened. There is no verb to judge, since
    reading is all the tool does, so only templates and public keys are
    let go."""
    targets = _cred_targets(text)
    if targets and all(_is_template(t) for t in targets):
        return None
    return severity


# rm as a command word: first, after a separator, quote or bracket, as the
# last part of a path (/bin/rm), or escaped (\\rm, which skips an alias of
# rm -i). Then the option words that follow it.
_RM_WORD = re.compile(r"(?<![^\s;&|(`'\"/\\])rm(?=\s)")
_OPTION_WORD = re.compile(r"\s+(-\S*)")


def _rm_recursive_force(text):
    """Span of an rm told to recurse and to force, however the flags are
    spelled: -rf, -Rf, -r -f, -f -r, --recursive --force, and any other
    options between them. Only one cluster was matched, so `rm -r -f ~/x`
    went unreported.

    Not a regex: with lookaheads, every `rm` inside a long run of option
    words walked the rest of the run, and 64,000 characters of ` -rm` took
    fifteen seconds. Here each option word is walked once, since an rm
    inside a run already walked could only see a part of the same run."""
    pos = 0
    while True:
        m = _RM_WORD.search(text, pos)
        if not m:
            return None
        end, recursive, force = m.end(), False, False
        while True:
            word = _OPTION_WORD.match(text, end)
            if not word or word.group(1) == "--":
                break
            flag = word.group(1).lower()
            if flag.startswith("--"):
                recursive = recursive or flag == "--recursive"
                force = force or flag == "--force"
            elif flag[1:].isalpha():
                recursive = recursive or "r" in flag
                force = force or "f" in flag
            end = word.end()
        if recursive and force:
            return m.start(), end
        pos = end


# The command word of a stage, after any sudo, VAR=value or directory: one
# that reads local files and is given something to read, and one that
# sends to the network.
_STAGE_PREFIX = r"(?:sudo\s+(?:-\S+\s+)*)?(?:\w+=\S*\s+)*(?:\S*/)?"
_FILE_READER = re.compile(
    _STAGE_PREFIX + r"(?P<reader>cat|tar|zip|base64|tac|head|tail|less|more|gzip"
    r"|bzip2|xz|zstd|lz4|xxd|od|strings|jq|yq|sed|awk|gawk)\s+[^\s|;]")
_NETWORK_SENDER = re.compile(_STAGE_PREFIX + r"(?:curl|wget|nc)(?![\w.-])")
_SPACES = re.compile(r"\s*")
# Readers whose words are all files to print: given anything, they read it.
_READS_ANY_WORD = frozenset(("cat", "tar", "zip", "base64"))
# Filters, whose first word is their program and only the ones after it
# are files: jq '.a' reads its input, jq '.a' f.json reads f.json.
_FILTERS = frozenset(("jq", "yq", "sed", "awk", "gawk"))
# Options of head and tail that take the next word as their value.
_COUNT_OPTIONS = frozenset(("-n", "-c", "--lines", "--bytes"))


def _reads_a_file(name, stage):
    """Whether the stage, run by the reader `name`, is given a file to
    read rather than reading its input: ps aux | head -20, dmesg | tail
    and curl ... | jq '.items' read what is piped in."""
    if name in _READS_ANY_WORD:
        return True
    words = _argv(stage)
    if words is None:
        words = stage.split()
    files, skip = 0, False
    for word in words[1:]:
        if skip:
            skip = False
        elif word.startswith("-"):
            skip = word in _COUNT_OPTIONS and name in ("head", "tail")
        else:
            files += 1
    return files > (1 if name in _FILTERS else 0)


def _file_piped_out(text):
    """Span from a command that reads local files to the curl, wget or nc
    its output is piped into, however many stages sit between them
    (`tar czf - src | gzip | curl -T - …`), or None.

    Read from what _executable_text kept, split where the shell splits it,
    so a quoted or escaped | joins nothing. Not a regex: one stage at a
    time is linear however many readers a long command holds."""
    reader = None
    for start, end, op in _command_spans(text):
        at = _SPACES.match(text, start, end).end()
        if reader is not None:
            sender = _NETWORK_SENDER.match(text, _peel(text, at, end), end)
            if sender:
                return reader, sender.end()
        else:
            found = _FILE_READER.match(text, _peel(text, at, end), end)
            if found and _reads_a_file(found.group("reader"),
                                       text[found.start("reader"):end]):
                reader = at
        if op != "|":
            reader = None
    return None


# exec.remote: a script fetched from the network and run in the same command.
#
# Split where the shell splits it, one stage at a time, so a quoted or
# escaped | joins nothing: echo "curl https://x | sh" prints a line and runs
# nothing. A fetcher at the head of a pipeline is remembered through every
# stage after it, so curl ... | tee x | sh and curl ... | gunzip | sh are
# found as well as curl ... | sh. Downloading to a file and running it in a
# later command is two calls, each judged on its own, and is not this rule.
_FETCH_WORD = (r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)"
               r"(?![\w.-])")
_FETCHER = re.compile(_STAGE_PREFIX + _FETCH_WORD, re.I)
# Shells run what they are piped as a script, unless given -c (the input is
# then data for a command string) or -n (nothing runs).
_STDIN_SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh", "fish", "ash"))
# Interpreters read a program from standard input only when given none of
# their own: python3 - and a bare python3 do, python3 -m json.tool and
# python3 -c do not, which is how a fetched JSON document is read.
_STDIN_INTERPRETERS = re.compile(r"(?:python[0-9.]*|perl|ruby|node|php)\Z")
_STDIN_FLAGS = frozenset(("-", "-u", "-s", "-S", "-B", "-q", "-l"))
# A word that redirects: 2>&1, >out, &>log, < file. When the operator stands
# by itself, the word after it names the file it points at. <( ) and >( ) are
# process substitutions, not redirections.
_REDIRECT_WORD = re.compile(r"(?:\d*|&)(?:>>?&?|<<<?-?|<&|<>|<)(?!\()")
# Options whose value is the next word, and what asks a program for its
# version or usage and runs nothing.
_SHELL_VALUE_OPTIONS = frozenset(("-o", "-O", "+o", "+O", "--rcfile",
                                  "--init-file"))
_INFO_FLAGS = frozenset(("--version", "--help"))
_INTERPRETER_INFO_FLAGS = frozenset(("-V", "-VV", "-h"))
_INTERPRETER_VALUE_OPTIONS = frozenset(("-W", "-X"))


@functools.lru_cache(maxsize=1)
def _hands_on():
    """What may stand before the program that reads a pipe: sudo, env, nohup
    and their options. Built on first use, since _HANDS_ON is defined below
    the rules."""
    return re.compile(r"\s*(?:" + _HANDS_ON + r")*")


# What may stand before a program that reads a pipe, as _HANDS_ON describes
# it (sudo -u root env FOO=1 nohup ...), read a word at a time.
#
# A pattern behind (?:_HANDS_ON)* that can fail ran in time exponential in
# the words: the word after an option is its value, or the program the next
# item starts with, and in `sudo -u sudo -u sudo -u ...` each reading goes
# on to the end and fails there, 2**n of them, before the tail is given up
# on. Python 3.9's re has no atomic group to cut one off. Here the readings
# a word leaves open are a short list of states, one step each. The list is
# kept in the order the regex tries them in, and the tail that matches along
# the best of them is the one returned, so what is found is what _HANDS_ON
# found, in one pass. tests/test_watch_more_rules.py holds the two together.
# _HANDS_ON itself is only ever read without a tail, by _hands_on().
_HAND_WORD = re.compile(r"\s*([^\s|;&]+)")


class _AfterHandsOn:
    """`\\s*(?:_HANDS_ON)*` and then `tail`, with two methods:
    match(text, pos, endpos), as a compiled pattern's, whose result ends
    where the tail does, and starts(text), the words a program or the tail
    may start with. The state of a program is where in its words it is:
    "sudo" may be given options (so may doas and exec), "sudo option" has
    just been given one, whose value may be the next word, "env" and "env
    option" the same for env's options and assignments, "nice" and "nice -n"
    for nice, and "nothing" may take no more.

    A tail that reads on to the next opener, as exec.remote's does, is also
    given as `scan`: what starts it, and what is left of it when that does
    not match. It names the opener it ends on `opener`. The tail is tried at
    every word that may end a program, and each try read on to the end of
    the stage again, so a run of `sudo -u sh ` was quadratic, whether the
    opener was never there or only at the end. What a try found holds for the
    tries after it, as far as the opener it found, so each reads only past
    the one before."""

    def __init__(self, tail, flags=0, scan=None):
        self.tail = re.compile(tail, flags)
        self._scan = scan and tuple(re.compile(p, flags) for p in scan)
        self._program = re.compile(
            r"(?:[^\s|;&]*/)?(?:(?P<sudo>sudo|doas|exec)|(?P<env>env)"
            r"|(?P<command>command)|(?P<nothing>nohup)|(?P<nice>nice))", flags)
        self._assignment = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=", flags)
        self._command_option = re.compile(r"-p", flags)
        self._nice_option = re.compile(r"-n", flags)
        self._number = re.compile(r"-?\d+", flags)

    def _next(self, state, word):
        """The state a program in `state` is left in by `word`, or None when
        it is not one of its words."""
        flag = word[0] == "-"
        if state == "sudo":
            return "sudo option" if flag else None
        if state == "sudo option":
            if flag:
                return "sudo option"
            return None if word[0] == "=" else "sudo"
        if state in ("env", "env option"):
            if flag:
                return "env option"
            if self._assignment.match(word):
                return "env"
            # an option's value has no = in it
            return "env" if state == "env option" and "=" not in word else None
        if state == "command":
            return "command" if self._command_option.fullmatch(word) else None
        if state == "nice":
            if self._nice_option.fullmatch(word):
                return "nice -n"
            return "nothing" if self._number.fullmatch(word) else None
        if state == "nice -n":
            return "nothing" if self._number.fullmatch(word) else None
        return None

    def starts(self, text):
        """Each word, with where it starts, that a program or the tail may
        start with, once the words before it are read in any way they can
        be: what match() tries the tail at, without the tail."""
        pos, end = 0, len(text)
        states = [None]
        while states:
            word = _HAND_WORD.match(text, pos, end)
            if word is None:
                break
            start, pos, word = word.start(1), word.end(), word.group(1)
            yield start, word
            after = [s for s in (self._next(state, word) for state in states
                                 if state is not None) if s is not None]
            program = self._program.fullmatch(word)
            if program:
                after.append(program.lastgroup)
            states = list(dict.fromkeys(after))

    def _tail(self, text, start, end, seen):
        """self.tail.match(text, start, end), but without reading on again
        what an earlier try, whose result `seen` keeps, has read."""
        if not self._scan:
            return self.tail.match(text, start, end)
        lead, rest = self._scan
        reads_on = lead.match(text, start, end)
        if reads_on is None or seen.get("dead"):
            return rest.match(text, start, end)
        before = seen.get("found")
        if before is not None and reads_on.end() <= before.start("opener"):
            return before                   # no opener sooner: the same one
        found = self.tail.match(text, start, end)
        if found is not None and found.group("opener") is not None:
            seen["found"] = found
        else:
            seen["dead"] = True             # none further on, for any later try
        return found

    def match(self, text, pos=0, endpos=None):
        end = len(text) if endpos is None else min(endpos, len(text))
        states, found = [None], None        # None: no program is being read
        seen = {}
        while states:
            word = _HAND_WORD.match(text, pos, end)
            if word is None:
                break
            start, pos, word = word.start(1), word.end(), word.group(1)
            after, boundary = [], False
            for state in states:
                if state is not None:
                    follows = self._next(state, word)
                    if follows is not None and follows not in after:
                        after.append(follows)
                if boundary:
                    continue
                # Every state may end its program here, and the word then
                # starts the next one or the tail: the regex tries a program
                # first, the tail only once none is left to try.
                boundary = True
                program = self._program.fullmatch(word)
                if program and program.lastgroup not in after:
                    after.append(program.lastgroup)
                tail = self._tail(text, start, end, seen)
                if tail:
                    # The regex stops at its first match. The readings it
                    # tries before this one are in `after`, and may still
                    # match further on; those it tries after are dropped.
                    found = tail
                    break
            states = after
        return found


# The words that may stand before a program, with no tail: for where each
# could start.
_HANDS_ON_WORDS = _AfterHandsOn(r"(?!)")


class _IntoShell:
    """`\\|&?\\s*(?:_HANDS_ON)*` and then a shell, with the one method of a
    compiled pattern that its caller uses: search(text)."""

    # A pipe and a word that starts a program or is a shell, which a chain
    # that ends in one starts with. Anything else is not worth walking.
    _PIPE = re.compile(
        r"\|&?(?=\s*(?:[^\s|;&]*/)?"
        r"(?:sh|bash|zsh|dash|ksh|fish|sudo|doas|env|command|exec|nohup|nice)"
        r"(?![\w.-]))")
    _SHELL = _AfterHandsOn(
        r"(?:[^\s|;&]*/)?(?:sh|bash|zsh|dash|ksh|fish)(?![\w.-])")

    def search(self, text):
        for pipe in self._PIPE.finditer(text):
            found = self._SHELL.match(text, pipe.end())
            if found:
                return found
        return None


@functools.lru_cache(maxsize=1)
def _runs_substitution():
    """A shell, eval or source given what a fetcher printed, with no pipe:
    bash <(curl ...), sh -c "$(curl ...)", eval "$(curl ...)", iex (irm ...)."""
    shell = (r"(?:(?:sh|bash|zsh|dash|ksh|fish|ash|eval|source)(?![\w.-])"
             r"|\.(?=\s))")
    powershell = r"(?:iex|invoke-expression)\s*\(?"
    fetched = r"\s*" + _STAGE_PREFIX + _FETCH_WORD
    return _AfterHandsOn(
        r"(?:[^\s|;&]*/)?(?:" + shell + r"[^|;&]*?(?P<opener><\(|\$\(|`)|"
        + powershell + r")" + fetched,
        re.I,
        scan=(r"(?:[^\s|;&]*/)?" + shell,
              r"(?:[^\s|;&]*/)?" + powershell + fetched))


# What ends a word in starts(), besides blanks: a stage that holds one has
# words that stage.split() cuts differently.
_SEPARATORS = re.compile(r"[|;&]")


def _without_redirects(words):
    """(words without the redirections, whether one replaces the standard
    input). `sh 2>&1` and `sh >/dev/null` still read the pipe: their
    redirections are not operands. `sh < file` and `sh <<< text` read
    something else."""
    kept, replaced, skip = [], False, False
    for word in words:
        if skip:
            skip = False
            continue
        found = _REDIRECT_WORD.match(word)
        if not found:
            kept.append(word)
            continue
        if found.end() == len(word):
            skip = True                      # the target is the next word
        if "<" in found.group() and not word.startswith(("1", "2")):
            replaced = True
    return kept, replaced


# At most this many words that may read a program from a pipe are tried
# behind a stage's option words, whether it is quoted or not: each costs a
# read of the rest of the stage, so this keeps the whole linear. A stage
# with more of them than this (`sudo -E sh sh sh ... bash -s`, seventeen
# shells deep) is judged by its first sixteen, and a word that is the value
# of an option (`sudo -u sh`) is one of them, as the regexes this replaced
# read it.
_MOST_READERS_TRIED = 16


def _is_reader(word):
    """Whether this word names a program that may read a program from its
    input: a shell, an interpreter or iex, quoted or not."""
    name = word.strip("'\"").rsplit("/", 1)[-1].lower()
    return (name in _STDIN_SHELLS or _STDIN_INTERPRETERS.match(name) is not None
            or name in ("iex", "invoke-expression", "busybox", "$shell", "${shell}"))


def _reads_script(words, at=0):
    """Whether the program that words[at:] runs reads a script from its
    input."""
    if at >= len(words):
        return False
    name = words[at].rsplit("/", 1)[-1].lower()
    if name in ("iex", "invoke-expression"):
        return True
    # `busybox sh` is the shell, whose words follow it: the program moves on
    # by one, the words are not copied (a slice, or islice, would count to at).
    if name == "busybox" and at + 1 < len(words) and words[at + 1] in _STDIN_SHELLS:
        at += 1
        name = words[at]
    elif name in ("$shell", "${shell}"):
        name = "sh"
    args = (words[i] for i in range(at + 1, len(words)))
    if name in _STDIN_SHELLS:
        letters, operand, skip = set(), False, False
        for word in args:
            if skip:
                skip = False
            elif word == "--":
                break
            elif word in _INFO_FLAGS:
                return False
            elif word in _SHELL_VALUE_OPTIONS:
                skip = True
            elif word.startswith("-"):
                if not word.startswith("--"):
                    letters.update(word[1:])
                    skip = word[-1] in "oO"
            elif not word.startswith("+"):
                operand = True
                break
        if letters & set("cn"):
            return False
        return not operand or "s" in letters
    if _STDIN_INTERPRETERS.match(name):
        flags = _STDIN_FLAGS | {"-i"} if name.startswith("python") else _STDIN_FLAGS
        skip = False
        for word in args:
            if skip:
                skip = False
            elif word in _INFO_FLAGS or word in _INTERPRETER_INFO_FLAGS:
                return False
            elif word in _INTERPRETER_VALUE_OPTIONS:
                skip = True
            elif word not in flags:
                return False
        return True
    return False


# Known gaps: xargs sh -c and tee >(sh) run what they are piped through a
# third program, and are not followed. The stage that reads the pipe is the
# one named. A lone & does not split a command (`curl ... | sh & next` is
# read as sh given & and next), and a quoted -c string (sh -lc 'curl ... |
# sh') is not read as a command of its own here.
def _runs_stdin(stage):
    """Whether a stage runs what it is piped as a program, as it stands or
    behind the wrappers that _peel reads, timeout and nice among them,
    which what stands before a shell (_HANDS_ON) does not."""
    if _runs_stdin_here(stage):
        return True
    at = _peel(stage)
    return at > 0 and _runs_stdin_here(stage[at:])


def _runs_stdin_here(stage):
    # A redirection that replaces the standard input, anywhere in the stage
    # (`sh < file`, `sudo -E <<<x -H bash -s`), leaves nothing piped to read.
    if _without_redirects(_argv(stage) or stage.split())[1]:
        return False
    rest = stage[_hands_on().match(stage).end():]
    if _reads_script(_without_redirects(_argv(rest) or rest.split())[0]):
        return True
    # _hands_on reads an option's value greedily, and in `sudo -E bash -s`
    # takes bash for the value of -E, which leaves `-s` to be read. The
    # words before the program may as well end anywhere else they could:
    # the program is tried wherever one that reads a script starts.
    #
    # Where the stage has no quoting, no separator and no redirection, its
    # words are the ones starts() walks and a reader's place among them is
    # its index, so each is tried without splitting the stage again.
    # Otherwise each is read from its own start, with its redirections
    # filtered as above.
    plain = None
    if not (_QUOTING.search(stage) or _SEPARATORS.search(stage)):
        words = stage.split()
        if not any(_REDIRECT_WORD.match(w) for w in words):
            plain = words
    tried = 0
    for index, (start, word) in enumerate(_HANDS_ON_WORDS.starts(stage)):
        if not _is_reader(word):
            continue
        tried += 1
        if tried > _MOST_READERS_TRIED:
            break
        if plain is not None and plain[index:index + 1] == [word]:
            if _reads_script(plain, index):
                return True
            continue
        rest = stage[start:]
        if _reads_script(_without_redirects(_argv(rest) or rest.split())[0]):
            return True
    return False


def _remote_run(text, depth=0):
    """Span from a fetcher to the shell or interpreter that runs what it
    fetched, or None. Each stage is read as the command it runs, so the &
    that puts the shell in the background (`curl ... | sh &`), the ( ) of a
    subshell and a wrapper in front (timeout, nohup, env, sudo ...) hide
    neither. A shell's -c string is a command of its own: bash -c 'curl ... |
    sh', which the text reduces to `bash -c curl ... | sh`, is a fetch, and
    one still quoted is read two deep."""
    fetched, substitution = None, _runs_substitution()
    for start, end, op in _command_spans(text):
        at = _SPACES.match(text, start, end).end()
        found = substitution.match(text, at, end)
        if found is None:
            found = substitution.match(text, _peel(text, at, end), end)
        if found:
            return at, found.end()
        stage = _normalised(text[at:end])
        if depth < 2:
            name = _command_word(stage)
            if name in _STDIN_SHELLS and _remote_run(
                    _shell_string(name, _stage_words(stage)) or "", depth + 1):
                return at, end
        if fetched is not None and stage and _runs_stdin(stage):
            return fetched, end
        if fetched is None:
            run = _normalised(_unwrap_c(stage))
            if _FETCHER.match(run) or _FETCHER.match(run, _peel(run)):
                fetched = at
        if op != "|":
            fetched = None
    return None


# perm.open: a mode that lets every account on the machine change the files.
_CHMOD = re.compile(_STAGE_PREFIX + r"chmod(?![\w.-])")
# -R and the other options, as opposed to a mode: -w and -rwx are modes.
_CHMOD_FLAG = re.compile(r"-[RfvcHLPh]+\Z|--[a-z-]+(?:=.*)?\Z")
_SYMBOLIC_MODE = re.compile(r"([ugoa]*)([-+=])([rwxXst]*|[ugo])\Z")
# Where a recursive change reaches past the project: the root, the home
# directory and the directories an operating system keeps its own files in.
_SYSTEM_PATHS = frozenset((
    "", "~", "$HOME", "${HOME}", "/etc", "/usr", "/var", "/home", "/bin",
    "/sbin", "/lib", "/opt", "/root", "/boot", "/Users", "/System", "/Library"))
_SCRATCH_PATHS = ("/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/",
                  "$TMPDIR", "${TMPDIR")


def _opens_to_others(mode):
    """Whether this chmod mode makes a file writable by everyone: an octal
    one whose last digit has the write bit, except one with the sticky bit,
    which is how /tmp is kept safe; or a symbolic one that gives a or o the
    w bit. +w with no who follows the umask, and is the owner's."""
    if re.fullmatch(r"[0-7]{3,4}", mode):
        sticky = len(mode) == 4 and (int(mode[0]) & 1) != 0
        return (int(mode[-1]) & 2) != 0 and not sticky
    for clause in mode.split(","):
        found = _SYMBOLIC_MODE.match(clause)
        if (found and found.group(2) != "-" and "w" in found.group(3)
                and ("a" in found.group(1) or "o" in found.group(1))):
            return True
    return False


def _chmod_parse(stage):
    """(recursive, targets) of a chmod that leaves what it names writable by
    everyone, or None."""
    head = _CHMOD.match(stage)
    if not head:
        return None
    rest = stage[head.end():]
    recursive, mode, targets = False, None, []
    for word in _argv(rest) or rest.split():
        if word == "--" and mode is None:
            continue
        if mode is None and _CHMOD_FLAG.match(word):
            if word.startswith("--reference"):
                return None
            if word == "--recursive" or (word[:2] != "--" and "R" in word):
                recursive = True
        elif mode is None:
            mode = word
        else:
            targets.append(word)
    if mode is None or not _opens_to_others(mode):
        return None
    return recursive, targets


def _chmod_open(text):
    """Span of the first chmod that opens files to every user, or None."""
    for start, end, _op in _command_spans(text):
        at = _SPACES.match(text, start, end).end()
        run = _peel(text, at, end)
        if _CHMOD.match(text, run, end) and _chmod_parse(text[run:end]):
            return at, end
    return None


def _refine_permissions(text, severity, tool_input=None):
    """How far the chmod reaches. Critical for a recursive change of /, the
    home directory or a system directory; high for any other recursive
    change; medium for a named file or directory; and nothing for a
    scratch path under /tmp, where a world-writable mode is ordinary."""
    for start, end, _op in _command_spans(text):
        at = _SPACES.match(text, start, end).end()
        run = _peel(text, at, end)
        parsed = _CHMOD.match(text, run, end) and _chmod_parse(text[run:end])
        if parsed:
            break
    else:
        return severity
    recursive, targets = parsed
    cleaned = [re.sub(r"/\*?\Z", "", t) for t in targets]
    scratch = bool(targets) and all(t.startswith(_SCRATCH_PATHS) for t in targets)
    if recursive and any(t in _SYSTEM_PATHS for t in cleaned):
        return CRITICAL
    if recursive:
        return MEDIUM if scratch else HIGH
    return None if scratch else MEDIUM


# container.destructive: volumes removed, or every container with them.
_CONTAINER_HINT = re.compile(r"docker|podman|nerdctl", re.I)
_CONTAINER_CLIS = frozenset(("docker", "podman", "nerdctl"))
_COMPOSE_CLIS = frozenset(("docker-compose", "podman-compose"))
_PS_SUBSTITUTION = re.compile(
    r"(?:\$\(|`)\s*(?:docker|podman|nerdctl)\s+(?:container\s+)?(?:ps|ls)\b")


def _wipes_container_data(stage):
    """Whether a stage removes volumes, or every container: system prune
    with --all or --volumes, volume rm or prune, compose down -v, and rm
    given every id that ps lists. A plain system prune, one named
    container and the images are left alone; each is a pull or a recreate
    away."""
    if not _CONTAINER_HINT.search(stage):
        return False
    rest = stage[_peel(stage):]
    rest = rest[re.match(_STAGE_PREFIX, rest).end():]
    words = _argv(rest) or rest.split()
    if not words:
        return False
    name, args = words[0], words[1:]
    flags = [w for w in args if w.startswith("-")]
    plain = [w for w in args if not w.startswith("-")]
    letters = set("".join(f[1:] for f in flags if not f.startswith("--")))

    def after(*pair):
        return any(plain[i:i + len(pair)] == list(pair)
                   for i in range(len(plain)))

    if name in _CONTAINER_CLIS:
        if after("system", "prune"):
            return "--volumes" in flags or "--all" in flags or "a" in letters
        if after("volume", "prune") or after("volume", "rm") \
                or after("volume", "remove"):
            return True
        if after("compose", "down"):
            return "--volumes" in flags or "v" in letters
        if after("rm") or after("container", "rm"):
            return bool(_PS_SUBSTITUTION.search(rest))
        return False
    if name in _COMPOSE_CLIS:
        return after("down") and ("--volumes" in flags or "v" in letters)
    if name == "xargs":
        # docker ps -aq | xargs docker rm -f
        for i, word in enumerate(plain):
            if word in _CONTAINER_CLIS:
                tail = plain[i + 1:]
                return tail[:1] == ["rm"] or tail[:2] == ["container", "rm"]
    return False


def _container_wipe(text):
    """Span of the first stage that wipes container data, or None."""
    for start, end, _op in _command_spans(text):
        at = _SPACES.match(text, start, end).end()
        if _wipes_container_data(text[at:end]):
            return at, end
    return None


# exec.encoded: decoded text, run in the command that decoded it.
#
# `echo cm0gLXJmIH4v | base64 -d | sh` hides what it runs from every rule
# that reads the command: the deletion is in the encoding. Decoded and
# handed to a shell, `eval` or an interpreter is the act, and it is reported
# whether or not the text can be read back. Decoding to a file, to a filter
# or to the terminal is not: base64 -d > key.pem and curl ... | base64 -d |
# jq read an encoding, and run nothing.
#
# As exec.remote does, one stage at a time, on the splitter that knows quotes,
# so a command that only mentions the pipeline (an echo, a grep pattern, a
# commit message, a heredoc) is data. Each finder keys on the command word of
# a stage, never on text inside one of its arguments. Linear throughout: a
# stage is read once, by regexes anchored where they start, and shlex splits
# only a stage whose command word is one of these or that follows a decoder.
#
# What a literal decodes to is read in decode.py, which never runs it. It is
# then judged by the other rules (_decoded_hits), so an encoded rm -rf ~/ is
# reported twice: as a decoded command run, and as the deletion.
_ENCODED = "exec.encoded"
# Most findings read from one text; characters one finding's evidence spans;
# variables remembered; a producer's length shown with what it feeds.
_ENC_FINDINGS = 4
_ENC_SPAN = 240
_ENC_NAMES = 16
_ENC_PRODUCER = 120
# Payloads decoded in one call, over every level.
MAX_PAYLOADS = 4

_Encoded = collections.namedtuple("_Encoded", "span via literal")
# Decoded text flowing out of the stages so far: where it began, the decoders
# it went through, the literal it came from (None when it is not known) and
# whether that literal is what the last decoder was given.
_Pipe = collections.namedtuple("_Pipe", "start via literal adjacent")

_ENC_HINTS = ("base64", "base32", "b64", "b32", "a2b_", "xxd", "openssl",
              "unhex", "fromhex", "hex2bin", "atob", "buffer", "decode",
              "powershell", "pwsh", "frombase64")
_ENC_ESCAPES = re.compile(
    r"(?<![\w-])rev(?![\w-])|\\x[0-9a-fA-F]|\\0?[0-7]{3}|\\u[0-9a-fA-F]{4}")


def _may_decode(text):
    """Whether text holds anything that could be a decoder: a name, or the
    escapes printf turns into letters. Only a way not to read the rest of a
    call that has none of them, which is nearly every call."""
    low = text.lower()
    return (any(hint in low for hint in _ENC_HINTS)
            or _ENC_ESCAPES.search(text) is not None)


_ENC_SEPARATORS = re.compile(r"[|;&\n]")


def _flatten_substitutions(text):
    """text with the separators inside every $( ), ` ` and <( ) turned to
    _, the same length. _command_spans splits at the pipes of an unquoted
    $( ): `eval $(echo X | base64 -d)` is two stages there, and is the one
    command of a decoder inside a substitution here."""
    spans = _substitution_spans(text, process=True)
    if not spans:
        return text
    out, pos = [], 0
    for lo, hi in spans:
        out.append(text[pos:lo])
        out.append(_ENC_SEPARATORS.sub("_", text[lo:hi]))
        pos = hi
    out.append(text[pos:])
    return "".join(out)


# time with -p, the one option the shell's time takes. What else stands in
# front of the command is peeled by _peel, with the options of each.
_ENC_LEADING = re.compile(
    r"(?:\s*(?:\(|\{(?=\s)|(?:then|do|else|elif|if|while|until|time(?:\s+-p)?)"
    r"(?=\s)))+\s*")


# The wrappers _normalised leaves on a stage: what sudo and env give the
# command that follows (a user, a variable) is what other rules judge.
_KEPT_WRAPPERS = frozenset(("sudo", "doas", "env"))


def _normalised(stage):
    """The command a stage runs: without the ( or { that groups it, a
    leading then, do, else, if, while or time, the wrappers in front of it
    (nice, timeout, setsid, nohup ... with their options, but not sudo or
    env), a
    trailing &, and the ) or } that closes a group opened before it."""
    found = _ENC_LEADING.match(stage)
    if found:
        stage = stage[found.end():]
    stage = stage[_peel(stage, keep=_KEPT_WRAPPERS):]
    stage = stage.rstrip(" \t\r\n&")
    extra = stage.count(")") - stage.count("(")
    if extra > 0:
        closing = len(stage) - len(stage.rstrip(")"))
        stage = stage[:len(stage) - min(extra, closing)].rstrip(" \t\r\n&")
    if stage.endswith("}") and stage.count("}") > stage.count("{"):
        stage = stage[:-1].rstrip(" \t\r\n;&")
    return stage


# bash -c 'echo X | base64 -d | sh' is reduced to `bash -c echo X | base64 -d
# | sh`: the first stage then is the shell, its flag and what its string
# starts with.
_ENC_INLINED = re.compile(
    r"(?:sh|bash|zsh|dash|ksh)\s+(?:-[A-Za-z]+\s+)*?-[A-Za-z]*c\s+"
    r"(?:-[A-Za-z]+\s+)*")
_ENC_PREFIX = re.compile(_STAGE_PREFIX)
_ENC_WORD = re.compile(r"[\"']?([^\s'\"\\|;&<>()$`]+)")
# The programs a stage's words are read for, whatever else it is.
_ENC_HEADS = frozenset((
    "base64", "base32", "openssl", "xxd", "rev", "eval", "source", ".",
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "perl", "ruby", "node",
    "nodejs", "php", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "iex", "invoke-expression"))


def _unwrap_c(stage):
    """stage without the shell and its -c in front, when its string was
    inlined. A string still quoted (bash -lc '...' is not reduced) is read
    as the operand of the shell, by _exec_operand."""
    found = _ENC_INLINED.match(stage)
    if not found or stage[found.end():found.end() + 1] in ("'", '"'):
        return stage
    return stage[found.end():]


def _after_prefix(stage):
    """stage without the wrappers (sudo, env, timeout ...), VAR=value and
    directory in front of its command."""
    rest = stage[_peel(stage):]
    rest = rest[_ENC_PREFIX.match(rest).end():]
    # what stood before the wrappers, assignments, may have hidden them
    rest = rest[_peel(rest):]
    return rest[_ENC_PREFIX.match(rest).end():]


def _command_word(stage):
    """The program a stage runs, by its base name and in lower case, read
    without splitting the stage into words."""
    found = _ENC_WORD.match(_after_prefix(stage))
    return found.group(1).rsplit("/", 1)[-1].lower() if found else ""


def _known_head(name):
    return name in _ENC_HEADS or name.startswith("python")


def _stage_words(stage):
    rest = _after_prefix(stage)
    return _argv(rest) or rest.split()


_ENC_CLUSTER = re.compile(r"-[A-Za-z0-9]+")
_ENC_XXD = re.compile(r"-[abCcdEeghilnoprRsuv]{1,4}")
# echo's options, which the decoders and the rules that judge writes skip.
_ECHO_FLAGS = re.compile(r"-[neE]+")
_ENC_PRINTF_ARGUMENT = re.compile(r"%s(?:\\n)?")


def _decoder_kind(name, words):
    """The kind of decoding a stage does of its input, or None: base64 or
    base32 given -d, openssl base64 -d, xxd -r, and rev."""
    args = words[1:]
    if name in ("base64", "base32"):
        for word in args:
            if word in ("--decode", "-d", "-D") or (
                    word[:2] != "--" and _ENC_CLUSTER.fullmatch(word)
                    and ("d" in word or "D" in word)):
                return name
        return None
    if name == "openssl" and args[:1] in (["base64"], ["enc"]):
        if "-out" in args or not ("-d" in args or "-decode" in args):
            return None
        if args[0] == "base64" or any(a in ("-base64", "-a", "-A")
                                      for a in args):
            return "base64"
        return None
    if name == "xxd":
        # A second name is the file it writes. A here-string and its text
        # are what it reads.
        names, skip = 0, False
        for word in args:
            if skip:
                skip = False
            elif word == "<<<":
                skip = True
            elif not word.startswith(("-", "<")):
                names += 1
        if names > 1:
            return None
        for word in args:
            if word == "-revert" or (_ENC_XXD.fullmatch(word) and "r" in word):
                return "hex"
        return None
    if name == "rev":
        return "rev"
    return None


def _escape_decoder(name, words):
    """("printf", format) of a printf, or an echo -e, whose text spells
    letters with escapes: \\x72\\x6d. Colour codes and newlines format, and
    do not count. A plain echo prints its backslashes as they are."""
    args = words[1:]
    if name == "printf":
        if "-v" in args:
            return None
        fmt = next((w for w in args if not w.startswith("-")), None)
        if fmt is None:
            return None
    elif name == "echo":
        escapes, i = False, 0
        while i < len(args) and _ECHO_FLAGS.fullmatch(args[i]):
            for letter in args[i][1:]:
                if letter in "eE":
                    escapes = letter == "e"
            i += 1
        if not escapes:
            return None
        fmt = " ".join(args[i:])
    else:
        return None
    if decode.unescape(fmt)[1] < decode.MIN_ESCAPES:
        return None
    return "printf", fmt


def _here_string(words):
    for i, word in enumerate(words):
        if word == "<<<" and i + 1 < len(words):
            return words[i + 1]
        if word.startswith("<<<") and len(word) > 3:
            return word[3:]
    return None


def _produced_literal(stage):
    """What an echo or printf stage writes, when it writes one word and that
    is plain: the text a decoder after it is given."""
    words = _stage_words(stage)
    if not words:
        return None
    name = words[0].rsplit("/", 1)[-1].lower()
    if name == "echo":
        i = 1
        while i < len(words) and _ECHO_FLAGS.fullmatch(words[i]):
            i += 1
        literal = " ".join(words[i:])
    elif name == "printf":
        args = words[1:]
        if len(args) == 2 and _ENC_PRINTF_ARGUMENT.fullmatch(args[0]):
            literal = args[1]
        elif len(args) == 1 and "%" not in args[0]:
            literal = args[0]
        else:
            return None
    else:
        return None
    return literal if literal and len(literal) < decode.MAX_ENCODED_CHARS else None


# An unquoted > that sends the standard output to a file: >, >>, >|, 1> and
# &>, but not 2>, 2>&1 or >&2. A quoted string and an escape are skipped.
_ENC_REDIRECT = re.compile(
    r"""(?P<skip>'[^']*'?|"(?:[^"\\]|\\[\s\S])*"?|\\[\s\S]?)"""
    r"""|(?:(?<!\w)(?P<fd>\d+)|&)?>>?(?P<dup>&)?""")


def _stdout_redirected(stage):
    for m in _ENC_REDIRECT.finditer(stage):
        if m.group("skip") is None and not m.group("dup") \
                and m.group("fd") in (None, "1"):
            return True
    return False


def _reads_stdin_program(stage, name, words):
    """Whether a stage runs what it is piped as a program: _runs_stdin, and
    a shell or source given /dev/stdin."""
    if _runs_stdin(stage):
        return True
    if (name in _STDIN_SHELLS or name in ("source", ".")) \
            and "/dev/stdin" in words[1:]:
        letters = set()
        for word in words[1:]:
            if word.startswith("-") and not word.startswith("--"):
                letters.update(word[1:])
        return not letters & set("cn")
    return False


# A stage whose program runs a string it is given: eval, source, a shell
# with -c, an interpreter with its payload flag. Given the result of a
# substitution that decodes, it runs what that decoded.
_ENC_RUNNER = re.compile(
    r"(?:eval|source|sh|bash|zsh|dash|ksh|fish|ash|python[0-9.]*|perl|ruby"
    r"|node|nodejs|php)(?![\w.-])|\.(?=\s)")
_ENC_OPTION = re.compile(r"\s+(-[A-Za-z]+)")
_ENC_SUBSTITUTION_NEXT = re.compile(r"\s*\"?(?:\$\(|`)")
_ENC_PROCESS_FORM = re.compile(r"(?:\s+-[A-Za-z-]+)*\s*(?:<\s*)?(?=<\()")
_ENC_HERE_FORM = re.compile(
    r"(?:\s+-[A-Za-z-]+)*\s*<<<\s*(?=\"?(?:\$\(|`))")
# The flag of each language that is followed by the program text.
_ENC_PAYLOAD_LETTERS = {"python": "c", "perl": "eE", "ruby": "e",
                        "node": "ep", "nodejs": "ep", "php": "r"}
_ENC_LANGUAGE = re.compile(r"(python)[0-9.]*\Z|(perl|ruby|node|nodejs|php)\Z")
# Options that take the next word as their value.
_ENC_VALUE_OPTIONS = {"python": ("-W", "-X"), "perl": ("-I",),
                      "ruby": ("-r", "-I", "-C", "-W"),
                      "node": ("-r", "--require", "-C"),
                      "nodejs": ("-r", "--require", "-C"),
                      "php": ("-d", "-c")}


def _language(name):
    found = _ENC_LANGUAGE.match(name)
    return (found.group(1) or found.group(2)) if found else None


def _payload_option_end(tail, letters, last_only):
    """Where, in the options of tail, the one that carries a command string
    ends when a substitution follows it at once, or None. last_only: the
    flag is the last letter of a cluster (python -Sc, perl -le)."""
    pos = 0
    while True:
        found = _ENC_OPTION.match(tail, pos)
        if not found:
            return None
        pos = found.end()
        option = found.group(1)
        carries = (option[-1] in letters if last_only
                   else any(ch in letters for ch in option[1:]))
        if carries and _ENC_SUBSTITUTION_NEXT.match(tail, pos):
            return pos


def _exec_substitutions(stage, spans):
    """The spans, of those of the stage's substitutions, whose text the
    stage's program runs: all of an eval's or a source's; for a shell the one
    after -c, the script operand <( ) or the <<<; for an interpreter the one
    after its payload flag."""
    if not spans:
        return ()
    rest = _after_prefix(stage)
    found = _ENC_RUNNER.match(rest)
    if not found:
        return ()
    word = found.group()
    pos = len(stage) - len(rest) + found.end()
    if word in ("eval", "source", "."):
        return [span for span in spans if span[0] >= pos]
    tail = stage[pos:]
    if word in _STDIN_SHELLS:
        ends = []
        end = _payload_option_end(tail, "c", False)
        if end is not None:
            ends.append(end)
        for form in (_ENC_PROCESS_FORM, _ENC_HERE_FORM):
            matched = form.match(tail)
            if matched:
                ends.append(matched.end())
    else:
        language = _language(word)
        end = (_payload_option_end(tail, _ENC_PAYLOAD_LETTERS[language], True)
               if language else None)
        ends = [] if end is None else [end]
    for end in ends:
        first = [span for span in spans if span[0] >= pos + end]
        if first:
            return first[:1]
    return ()


def _exec_operand(name, words):
    """The text a stage runs as shell source: what eval is given, or the
    first word after a shell's options when one of them is -c (-c, -lc, -ec).
    None for any other stage."""
    if name == "eval":
        return " ".join(words[1:])
    if name in _STDIN_SHELLS:
        carries, skip = False, False
        for i, word in enumerate(words[1:], 1):
            if skip:
                skip = False
            elif word == "--":
                return words[i + 1] if carries and i + 1 < len(words) else None
            elif word in _SHELL_VALUE_OPTIONS:
                skip = True
            elif word[:1] in ("-", "+") and len(word) > 1:
                carries = carries or (
                    word[0] == "-" and word[:2] != "--"
                    and _ENC_CLUSTER.fullmatch(word) is not None
                    and "c" in word)
            else:
                return word if carries else None
    return None


def _interpreter_payload(name, words):
    """The program text an interpreter one-liner was given, or None."""
    language = _language(name)
    if language is None:
        return None
    letters = _ENC_PAYLOAD_LETTERS[language]
    takes_value = _ENC_VALUE_OPTIONS[language]
    args = words[1:]
    i = 0
    while i < len(args):
        word = args[i]
        if word in ("--eval", "--print"):
            return args[i + 1] if i + 1 < len(args) else None
        if word.startswith("--eval="):
            return word[len("--eval="):]
        if word.startswith("-") and not word.startswith("--") and len(word) > 1:
            if _ENC_CLUSTER.fullmatch(word) and word[-1] in letters:
                return args[i + 1] if i + 1 < len(args) else None
            if word in takes_value:
                i += 1
        elif not word.startswith("--"):
            return None
        i += 1
    return None


_ENC_POWERSHELLS = ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
_ENC_POWERSHELL_BLOB = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}\Z")
_ENC_POWERSHELL_EXPRESSION = re.compile(r"(?<![\w-])(?:iex|invoke-expression)(?![\w-])")
_ENC_POWERSHELL_LITERAL = re.compile(
    r"frombase64string\(\s*['\"]([A-Za-z0-9+/]{8,}={0,2})['\"]", re.I)


def _powershell_encoded(name, words, stage):
    """(kind, literal) of a PowerShell run of encoded text: -EncodedCommand
    (any prefix of it, and -ec) given a base64 operand, or an iex of what
    FromBase64String gave. None otherwise."""
    if name in _ENC_POWERSHELLS:
        args = words[1:]
        for i, word in enumerate(args):
            flag = word[1:].lower()
            if word[:1] == "-" and flag and (
                    "file".startswith(flag) or "command".startswith(flag)):
                break               # what follows is the script's, or text
            if word[:1] == "-" and flag and (
                    "encodedcommand".startswith(flag) or flag == "ec"):
                if i + 1 < len(args) and _ENC_POWERSHELL_BLOB.match(args[i + 1]):
                    return "utf16b64", args[i + 1]
    elif name not in ("iex", "invoke-expression"):
        return None
    low = stage.lower()
    if "frombase64string" in low and _ENC_POWERSHELL_EXPRESSION.search(low):
        found = _ENC_POWERSHELL_LITERAL.search(stage)
        return "base64", (found.group(1) if found else None)
    return None


_ENC_ASSIGN = re.compile(
    r"(?:(?:export|declare|local|readonly|typeset)\s+(?:-\S+\s+)*)?"
    r"([A-Za-z_]\w*)\+?=")
_ENC_NAME_VALUE = re.compile(r"[A-Za-z_]\w*\+?=")
_ENC_VARIABLE = re.compile(r"\$\{?([A-Za-z_]\w*)")
_ENC_VARIABLE_WORD = re.compile(
    r"(?:\"\$\{?([A-Za-z_]\w*)\}?\"|\$\{?([A-Za-z_]\w*)\}?)(?:\s|\Z)")
# What a single quote hides: '$K' is the two characters, never the value.
_ENC_SINGLE_QUOTED = re.compile(r"(\"(?:[^\"\\]|\\[\s\S])*\"?)|'[^']*'?")


def _enc_assignment(stage, spans):
    """The name a stage assigns, when every word of it is NAME=value (with
    the substitutions in them blanked, as `export NAME=$(...)` has them), or
    None. PYTHONPATH=x python3 -c ... is a command, not an assignment."""
    found = _ENC_ASSIGN.match(stage)
    if not found:
        return None
    blanked = stage
    for lo, hi in reversed(spans):
        blanked = blanked[:lo] + "_" * (hi - lo) + blanked[hi:]
    rest = blanked[found.start(1):]
    words = _argv(rest) or rest.split()
    if words and all(_ENC_NAME_VALUE.match(word) for word in words):
        return found.group(1)
    return None


def _tracked_run(text, tracked):
    """(via, literal) of the first variable in text that holds decoded text,
    outside single quotes."""
    if "'" in text:
        text = _ENC_SINGLE_QUOTED.sub(lambda m: m.group(1) or "", text)
    for found in _ENC_VARIABLE.finditer(text):
        got = tracked.get(found.group(1))
        if got:
            return got
    return None


class _EncodedBudget(object):
    """The characters of nested text (a substitution's body, an eval's
    string) still to be read in one call."""

    def __init__(self, chars):
        self.chars = chars


def _walk_encoded(text, depth, budget, want_output=False):
    """([_Encoded], output) of text. output, with want_output, is (via,
    literal) of the first pipeline of text whose decoded stream is still
    flowing at its end: what a substitution hands to the command around it.

    State, stage by stage: `state` is decoded text flowing out of the
    stages so far, `pending` the echo or printf stage that may have written
    the literal the next decoder reads, `tracked` the variables that hold
    decoded text."""
    found, output = [], None
    if not text or depth > 3:
        return found, output
    state = pending = None
    tracked = {}
    for start, end, op in _command_spans(_flatten_substitutions(text)):
        if len(found) >= _ENC_FINDINGS:
            break
        at = _SPACES.match(text, start, end).end()
        stage = _normalised(text[at:end])
        if not stage or stage[0] == "#":
            if op != "|":
                state = pending = None
            continue
        core = _unwrap_c(stage)
        name = _command_word(core)
        spans = (_substitution_spans(stage, process=True)
                 if "$(" in stage or "`" in stage or "<(" in stage else [])
        assigned = _enc_assignment(stage, spans) if "=" in stage else None

        # A pipeline inside a substitution, and what it hands on. A name
        # assigned again holds what the new value is.
        if assigned:
            tracked.pop(assigned, None)
        walked = {}
        for lo, hi in spans:
            if budget.chars <= 0:
                break
            budget.chars -= hi - lo
            inner, handed = _walk_encoded(stage[lo:hi], depth + 1, budget, True)
            walked[(lo, hi)] = handed
            if inner:
                found.append(_Encoded((at, end), inner[0].via, inner[0].literal))
            if assigned and handed and len(tracked) < _ENC_NAMES:
                tracked[assigned] = handed
        for span in _exec_substitutions(stage, spans):
            handed = walked.get(span)
            if handed:
                found.append(_Encoded((at, end), handed[0], handed[1]))
                break

        flowing = state is not None
        words = (_stage_words(core)
                 if flowing or tracked or _known_head(name) else None)
        if words and not assigned:
            operand = _exec_operand(name, words)
            if tracked and (name in ("eval", "source", ".")
                            or operand is not None):
                got = _tracked_run(stage, tracked)
                if got:
                    found.append(_Encoded((at, end), got[0], got[1]))
            if operand and depth < 3 and budget.chars > 0 \
                    and _may_decode(operand):
                budget.chars -= len(operand)
                inner, _handed = _walk_encoded(operand, depth + 1, budget)
                if inner:
                    found.append(_Encoded((at, end), inner[0].via,
                                          inner[0].literal))
            program = _interpreter_payload(name, words)
            hit = decode.scan_source(program) if program else None
            if hit:
                found.append(_Encoded((at, end), (hit[0],), hit[1]))
            hit = _powershell_encoded(name, words, stage)
            if hit:
                found.append(_Encoded((at, end), (hit[0],), hit[1]))
        if tracked and not assigned:
            ref = _ENC_VARIABLE_WORD.match(_after_prefix(core))
            if ref and (ref.group(1) or ref.group(2)) in tracked:
                got = tracked[ref.group(1) or ref.group(2)]
                found.append(_Encoded((at, end), got[0], got[1]))

        decoder = None
        if words and not assigned:
            decoder = _decoder_kind(name, words)
            if decoder and _stdout_redirected(core):
                decoder = None
        if flowing and words and _reads_stdin_program(core, name, words):
            found.append(_Encoded((state.start, end), state.via, state.literal))
            state = None
        elif decoder:
            if flowing:
                state = _Pipe(state.start,
                              (state.via + (decoder,))[:decode.MAX_LEVELS + 1],
                              state.literal if state.adjacent else None, True)
            else:
                literal, begin = _here_string(words), at
                if literal is None and pending is not None:
                    literal = _produced_literal(pending[1])
                    if literal is not None and len(pending[1]) <= _ENC_PRODUCER:
                        begin = pending[0]
                state = _Pipe(begin, (decoder,), literal, True)
        elif (op == "|" or want_output) and name in ("echo", "printf") \
                and not assigned:
            state, got = None, None
            if "\\" in core:
                got = _escape_decoder(name, words or _stage_words(core))
            if got:
                state = _Pipe(at, (got[0],), got[1], True)
            elif tracked:
                got = _tracked_run(core, tracked)
                if got:
                    state = _Pipe(at, got[0], got[1], True)
        elif flowing:
            state = state._replace(literal=None, adjacent=False)
        pending = ((at, core) if op == "|" and state is None
                   and name in ("echo", "printf") else None)
        if op != "|":
            if want_output and state is not None and output is None:
                output = (state.via, state.literal)
            state = pending = None
    return found, output


_ENC_CONTINUATION = re.compile(r"\\\r?\n")


def _joined_lines(text):
    """text with each backslash-newline turned to blanks, the same length: a
    command a shell reads as one line, `sh \\<newline> -x`, is one here."""
    if "\\" not in text:
        return text
    return _ENC_CONTINUATION.sub(lambda m: " " * len(m.group()), text)


@functools.lru_cache(maxsize=64)
def _encoded_findings(text):
    """The decoded commands run in text, as _Encoded: the span of the whole
    act (the decoder, or the echo that feeds it, to what runs it), the
    decoders it went through and the literal it decodes, when it has one."""
    text = _joined_lines(text)
    found, _output = _walk_encoded(text, 0, _EncodedBudget(2 * MAX_SCAN_CHARS))
    return tuple(f._replace(span=(f.span[0], min(f.span[1], f.span[0] + _ENC_SPAN)))
                 for f in found[:_ENC_FINDINGS])


def _encoded_run(text):
    """Span of the first decoded command run in text, or None."""
    found = _encoded_findings(text)
    return found[0].span if found else None


# cred.metadata: the instance's own credentials asked of a cloud metadata
# service.
#
# AWS, GCP, Azure, Alibaba and Oracle each hand the role a machine runs as a
# short-lived token, at a link-local address, to anything on the machine
# that asks. Asking is the first move of an SSRF, and of an agent turned
# against the account it works in: the token comes back ready to use and
# grants whatever the role can. A plain metadata read (instance-id, the
# region, the IMDSv2 token PUT on its own) is in every bootstrap script and
# CI job, says nothing worth asking about, and is not reported at all.
#
# As exec.remote does, one stage at a time on the quote-aware splitter, keyed
# on a fetcher as the stage's command word, so the URL in an echo, a grep
# pattern, a heredoc or a commit message is data. The command word is read
# past what hands a stage on (sudo, env, nohup, command, exec, timeout), a
# shell's -c string is a command of its own, as persist reads one, and so is
# PowerShell's `$r = Invoke-WebRequest ...`, the form Microsoft's managed
# identity docs give. The host must be a literal in the same word as the
# credential path: that is what tells the metadata service from an API with
# iam/security-credentials in a path of its own. And that word must be one
# the fetcher fetches, starting with the URL (_URL_LEAD): the same URL in a
# -d body, a --data-urlencode query or an httpie item is data the request
# carries, as when a SIEM or log search looks for SSRF attempts, or an
# issue is filed about one. So an SSRF payload handed to another app as a
# parameter (?url=http://169.254.169.254/...) is not reported either: it
# would reach that app's machine's credentials, not this one's. Not seen: a
# host reached only through a variable, a fetch in another language's
# source, and one run somewhere else (ssh, kubectl exec, docker exec), whose
# words are not read.
_METADATA_FETCHER = re.compile(
    _STAGE_PREFIX + r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod"
    r"|http|https|xh)(?:\.exe)?(?![\w.-])", re.I)
# A PowerShell assignment, which the stage's command follows.
_PS_ASSIGNED = re.compile(r"\$[\w:]+[ \t]*=[ \t]*")
# What ends a URL's word.
_URL_STOPS = " \t\n'\""
# The services' addresses, and then the paths that hand out credentials.
# 169.254.169.254 is AWS's, GCP's, Azure's and Oracle's, and is also spelled
# as one decimal or hex number; 100.100.100.200 is Alibaba's; GCP's has two
# names and AWS's an IPv6 address. The paths: the role's (AWS, Alibaba), a
# service account's token or identity (GCP), a managed identity's token
# (Azure), the instance principal's certificate and key (Oracle). A _Gap,
# the host and then the path in the rest of its word, in linear time.
_METADATA_CREDENTIALS = _Gap(
    r"(?<![\w.])(?:169\.254\.169\.254|100\.100\.100\.200)(?!\d)"
    r"|(?<![\w.-])metadata\.google\.internal|(?<=//)metadata(?=[:/])"
    r"|\[fd00:ec2::254\]|(?<![\w.])(?:2852039166|0xa9fea9fe)(?![\w.])",
    r"/(?:iam/security-credentials|ram/security-credentials"
    r"|metadata/identity/oauth2/token|opc/v[12]/identity"
    r"|service-accounts/[^\s'\"/?#]+/(?:token|identity))(?![\w-])",
    _URL_STOPS)
# The container credential agents of ECS (169.254.170.2) and EKS Pod
# Identity (169.254.170.23), which also serve task metadata: only a URL
# that names credentials asks for them.
_CONTAINER_CREDENTIALS = _Gap(
    r"(?<![\w.])169\.254\.170\.(?:23|2)(?!\d)|\[fd00:ec2::23\]",
    r"credential", _URL_STOPS)
# The variables that name a credential endpoint and nothing else: the
# container credential URI of ECS and EKS, and an Azure App Service's or
# Function's managed identity endpoint. PowerShell's ${env:NAME} as well.
_CREDENTIALS_ENDPOINT = re.compile(
    r"\$(?:\{(?:env:)?|env:)?(?:AWS_CONTAINER_CREDENTIALS_(?:RELATIVE|FULL)_URI"
    r"|IDENTITY_ENDPOINT|MSI_ENDPOINT)\b", re.I)
_METADATA_SIGNALS = (_METADATA_CREDENTIALS, _CONTAINER_CREDENTIALS,
                     _CREDENTIALS_ENDPOINT)
# Where a fetched URL starts in its word: past curl's --url= or
# PowerShell's -Uri:, what the shell expands at its start, a scheme, the
# user a URL may name (http://user@169.254.169.254/ asks the same service),
# and a variable that only leads to the one naming the endpoint. What the
# shell expands: a brace list, {http://.../,http://x}; a substitution, with
# the echo or printf in it that prints the URL, "$(printf 'http://.../%s'
# "$ROLE")", or PowerShell's "$($env:IDENTITY_ENDPOINT)?resource=..."; a
# default, ${IMDS:-http://...}; a variable before another,
# "$ECS_AGENT$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI". Read only from where
# the word starts, never searched for in it: ?q=$IDENTITY_ENDPOINT is in a
# URL to another host. Every part may be empty and each alternative starts
# with a literal of its own, so a word is read once.
_URL_LEAD = re.compile(
    r"(?:--url=|-uri:)?"
    r"(?:\{|\$\((?:[ \t]*(?:echo|printf)[ \t]+(?:(?:-[neE]+|--)[ \t]+)*['\"]?)?"
    r"|\$\{\w+:?[-=]|\$\{?[A-Za-z_]\w*\}?(?=\$))*"
    r"(?:[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?)?"
    r"(?:\$\{?[A-Za-z_]\w*\}?(?=\$))*", re.I)


# What each of _METADATA_SIGNALS holds, in lower case: a call that holds
# none of them asks no metadata service for anything, and is not read.
_METADATA_HINTS = ("169.254.", "100.100.100.200", "metadata", "fd00:ec2",
                   "2852039166", "0xa9fea9fe", "credentials_", "identity_endpoint",
                   "msi_endpoint")


def _fetched_credentials(stage):
    """Where the first word of a fetch's stage that is a credential URL, or
    a credential endpoint's variable, ends; or None. A word counts only
    when one starts it, past _URL_LEAD, as read by the shell: one met inside
    another word is data the request carries. Each word is read once, by
    regexes anchored where it starts. bash's $'...' quotes as '...' does,
    but for its escapes, and _dequoted would leave its $ before the URL."""
    for word in _WORD_ANYWHERE.finditer(stage):
        text = word.group()
        read = _dequoted(text[1:] if text[:2] == "$'" else text)
        lead = _URL_LEAD.match(read).end()
        if any(signal.match(read, lead) for signal in _METADATA_SIGNALS):
            return word.end()
    return None


def _metadata_fetch(text, depth=0):
    """Span from a fetcher to the end of the first credential URL it asks a
    metadata service for, or None. A substitution's body, and a shell's -c
    string, are read as commands of their own: CREDS=$(curl ...) asks as
    much as curl does, and so does bash -lc 'curl ...', which is then the
    span."""
    if depth == 0:
        low = text.lower()
        if not any(hint in low for hint in _METADATA_HINTS):
            return None
    for start, end, _op in _command_spans(text):
        at = _SPACES.match(text, start, end).end()
        stage = text[at:end]
        assigned = _PS_ASSIGNED.match(stage)
        command = _normalised(stage[assigned.end():] if assigned else stage)
        # bash -c "curl ..." is reduced to `bash -c curl ...`.
        run = _after_prefix(_unwrap_c(_after_prefix(command)))
        if _METADATA_FETCHER.match(run):
            found = _fetched_credentials(stage)
            if found is not None:
                return at, at + found
        if depth >= 3:
            continue
        name = _command_word(command)
        if name in _SHELL_STRING_HEADS:
            operand = _shell_string(name, _stage_words(command))
            if operand and _metadata_fetch(operand, depth + 1):
                return at, end
        if "$(" in stage or "`" in stage:
            for lo, hi in _substitution_spans(stage):
                inner = _metadata_fetch(stage[lo:hi], depth + 1)
                if inner:
                    return at + lo + inner[0], at + lo + inner[1]
    return None


# ---------------------------------------------------------------------------
# What a shell command writes, for the rules that judge it.
#
# persist and agent.config are about where a command writes and what. The
# text the other rules read drops echo and printf as text, and with them
# `echo 'export PATH=…' >> ~/.zshrc`, whose redirect is the whole act. So
# these two read the command as it was written, with only the bodies of its
# here-documents set aside, and kept beside it as what was written. They
# read it a stage at a time on the quote-aware splitter: a > inside quotes or
# a comment writes nothing, and a stage that only prints (an echo, a commit
# message) writes only where it is redirected. A sh -c string and a
# substitution's body are read as commands of their own, three deep.
# ---------------------------------------------------------------------------

class _WriteView(str):
    """A command as the rules that judge what it writes read it (see
    _write_view): a str, with the body of each here-document taken out of
    it kept as .bodies, (where its operator ends in the text, the body)."""
    bodies = ()


@functools.lru_cache(maxsize=32)
def _write_view(command):
    """command as a _WriteView, cut to MAX_SCAN_CHARS after its bodies are
    taken out, as _shell_text cuts what it reduced."""
    bodies = []
    view = _WriteView(_strip_heredocs(command, keep_tail=True,
                                      bodies=bodies)[:MAX_SCAN_CHARS])
    view.bodies = tuple(b for b in bodies if b[0] <= MAX_SCAN_CHARS)
    return view


def _joined_view(view):
    """A write view with each backslash-newline read as blanks, as the shell
    joins the two lines (_joined_lines), its bodies kept: `RANWHAT_HOOK=0 \\`
    and then `claude` on the next line is one command, whose words split
    as written held a newline for a word. The rules that read a write view
    are given it as what they judge, so their evidence quotes the command
    as it was written."""
    joined = _joined_lines(view)
    if joined is view:
        return view
    joined = _WriteView(joined)
    joined.bodies = getattr(view, "bodies", ())
    return joined


# An output redirection outside quotes, escapes and comments: >, >>, >|, &>,
# N> and N>>. Not <>, and not from inside a run of digits: the lookbehind
# lets only the first digit of a run start one, so a long run is read once.
# Then the word it writes to, read from the text as it was written; >&2,
# 2>&1 and >( ) have none.
_FILE_REDIRECT_OP = re.compile(r"(?<![<>&\d])(?:\d+|&)?>>?\|?")
_SHELL_WORD = r"""(?:'[^'\n]*'|"(?:[^"\\\n]|\\.)*"|\\.|[^\s;&|<>()'"\\])+"""
_TARGET_WORD = re.compile(r"[ \t]*(" + _SHELL_WORD + ")")
# The same word, where each is found by a search: with the blanks before it
# in the pattern, each place in a long run of them read on to its end.
_WORD_ANYWHERE = re.compile(_SHELL_WORD)
# The parts of a shell word, each begun by a character of its own.
_WORD_PART = re.compile(
    r"""'([^']*)'?|"((?:[^"\\]|\\[\s\S])*)"?|\\([\s\S]?)|([^'"\\]+)""")
_DOUBLE_QUOTED_ESCAPE = re.compile(r'\\([$`"\\])')


def _unquoted(text):
    """text with every quoted string, escape and comment blanked, at the
    same offsets."""
    return _HIDDEN.sub(lambda m: " " * len(m.group()), text)


def _dequoted(word):
    """A shell word as the program it is given reads it, quotes taken off
    and escapes read. Not shlex, which builds a word a character at a
    time."""
    if not _QUOTING.search(word):
        return word
    out = []
    for m in _WORD_PART.finditer(word):
        single, double, escaped, plain = m.groups()
        if single is not None:
            out.append(single)
        elif double is not None:
            out.append(_DOUBLE_QUOTED_ESCAPE.sub(r"\1", double))
        elif escaped is not None:
            out.append(escaped)
        else:
            out.append(plain)
    return "".join(out)


def _uncommented(stage):
    """stage without the comment that ends it, when one does."""
    if "#" not in stage:
        return stage
    for m in _HIDDEN.finditer(stage):
        if m.group()[:1] == "#":
            return stage[:m.start()].rstrip()
    return stage


def _redirects(stage):
    """(start, end, target, appends) for each redirection of stage's output
    to a file: where the operator starts, where the word it writes to ends,
    that word as the shell reads it, and whether it appends."""
    if ">" not in stage:
        return []
    found = []
    for op in _FILE_REDIRECT_OP.finditer(_unquoted(stage)):
        word = _TARGET_WORD.match(stage, op.end())
        if word:
            found.append((op.start(), word.end(), _dequoted(word.group(1)),
                          op.group().rstrip("|").endswith(">>")))
    return found


def _here_string_word(stage):
    """The word a here-string gives stage's input, as read, or None."""
    if "<<<" not in stage:
        return None
    at = _unquoted(stage).find("<<<")
    word = _TARGET_WORD.match(stage, at + 3) if at >= 0 else None
    return _dequoted(word.group(1)) if word else None


# What prints its words: echo, printf, and PowerShell's Write-Output.
_PRINTERS = frozenset(("echo", "printf", "write-output"))


def _without_redirect_text(stage):
    """stage with each redirection of its output to a file blanked."""
    parts, pos = [], 0
    for start, end, _target, _appends in _redirects(stage):
        parts.append(stage[pos:start])
        parts.append(" ")
        pos = end
    parts.append(stage[pos:])
    return "".join(parts)


def _printed(stage):
    """What an echo or printf stage prints, read without splitting it into
    words: what follows the program, as read, with its redirections and
    echo's options left out. printf's words are a line each: in printf
    '%s\\n' 'curl ... | sh' the format is not the start of the command."""
    rest = _without_redirect_text(_after_prefix(stage))
    words = [_dequoted(m.group()) for m in _WORD_ANYWHERE.finditer(rest)]
    first = 1
    program = words[0].rsplit("/", 1)[-1].lower() if words else ""
    if program == "echo":
        while first < len(words) and _ECHO_FLAGS.fullmatch(words[first]):
            first += 1
    return ("\n" if program == "printf" else " ").join(words[first:])


# A PowerShell here-string, @'...'@ or @"..."@, which is a stage of its own.
_PS_HERE_STRING = re.compile(r"""@(['"])\r?\n?([\s\S]*?)\r?\n?\1@\Z""")


def _quoted_literal(stage):
    """The text of a stage that is only a quoted string, or a PowerShell
    here-string, as read: PowerShell writes one to its output, so
    `'Set-Alias ll ls' >> $PROFILE` and `@'...'@ | Set-Content f` write it.
    None for any other stage."""
    if stage[:1] not in ("'", '"', "@"):
        return None
    rest = _without_redirect_text(stage).strip() if ">" in stage else stage
    here = _PS_HERE_STRING.match(rest)
    if here:
        return here.group(2)
    word = _TARGET_WORD.match(rest)
    if not word or word.end() != len(rest) or rest[:1] not in ("'", '"'):
        return None
    return _dequoted(word.group(1))


def _posix_home():
    """This user's home as the rules that judge writes read a path: on
    Windows, where it is USERPROFILE (C:\\Users\\me), with its backslashes
    read as / and its drive taken off, /Users/me, as a path written there
    is read. Git Bash reads ~/.bashrc from it, so ~ must resolve there too:
    left as it was, no ~ or $HOME path was a startup file on Windows."""
    home = _home()
    if home.startswith("/"):
        return home
    return _undriven(_slashed(home).replace("\\", "/"))


def _home_relative(path):
    """path below a home directory, as a path relative to it: this user's,
    or the one /home/<name>/, /Users/<name>/ or /root/ starts; else None."""
    home = _posix_home().rstrip("/")
    if home.startswith("/") and path.startswith(home + "/"):
        return path[len(home) + 1:]
    found = _OTHER_HOME.match(path)
    return path[found.end():] if found else None


# Git Bash, which Claude Code runs Bash through on Windows, spells a home
# /c/Users/<name>: its drive as a folder of one letter.
_OTHER_HOME = re.compile(r"(?:/[A-Za-z])?/(?:home|Users)/[^/]+/|/(?:var/)?root/")
_REMOTE_PATH = re.compile(r"[^/\s]{2,}:")


_Wrote = collections.namedtuple("_Wrote", "target how detail")


# Programs whose own words name a file they write, and the options of each
# that take the next word as their value. Each is read as GNU and BSD both
# read it, and a word that is neither is taken for an operand: what is
# written is the last of those, which a value read as one rarely is.
_WRITERS = frozenset((
    "tee", "sponge", "sed", "gsed", "perl", "cp", "mv", "install", "ln", "rsync",
    "curl", "wget", "dd", "rm", "unlink", "shred", "truncate", "yq",
    "add-content", "set-content", "out-file", "new-item", "copy-item",
    "move-item", "remove-item", "invoke-webrequest", "iwr",
    "invoke-restmethod", "irm"))
_COPY_VALUES = {
    "cp": frozenset(("-S", "--suffix")),
    "mv": frozenset(("-S", "--suffix")),
    "ln": frozenset(("-S", "--suffix")),
    "install": frozenset(("-m", "--mode", "-o", "--owner", "-g", "--group",
                          "-S", "--suffix")),
    "rsync": frozenset((
        "-e", "--rsh", "--exclude", "--include", "--exclude-from",
        "--include-from", "-f", "--filter", "--files-from", "--log-file",
        "--password-file", "--chmod", "--chown", "--rsync-path", "-T",
        "--temp-dir", "--partial-dir", "--backup-dir", "--suffix",
        "--compare-dest", "--copy-dest", "--link-dest", "-B", "--block-size",
        "--timeout", "--port", "--bwlimit", "-M", "--remote-option")),
}
_COPY_HOW = {"cp": "copy", "install": "copy", "rsync": "copy", "mv": "move",
             "ln": "link"}
# Letters of a curl cluster that take a value, after which the rest of it is
# that value: -sSLo FILE is -o's, -H... a header's.
_CURL_VALUE_LETTERS = frozenset("AbcCdDeEFHKmoQrTuUwxXyYz")
# PowerShell's writers, and their named parameters that take a value.
_PS_WRITERS = frozenset(("add-content", "set-content", "out-file", "new-item"))
_PS_VALUES = frozenset((
    "-path", "-filepath", "-literalpath", "-destination", "-value",
    "-encoding", "-itemtype", "-name", "-stream", "-delimiter", "-filter",
    "-include", "-exclude", "-credential", "-width", "-inputobject",
    "-type"))
_PS_PATHS = frozenset(("-path", "-filepath", "-literalpath"))
_STARTUP_FOLDER = "/start menu/programs/startup"
# PowerShell's downloaders, which write a file given -OutFile.
_PS_FETCHERS = frozenset(("invoke-webrequest", "iwr", "invoke-restmethod", "irm"))
# PowerShell's cmdlets that write, copy, move or remove a file. A backslash
# is no escape to PowerShell, so their words are read with each one between
# a path's parts as /: unquoted, $HOME\.claude\settings.json read as POSIX
# words lost its backslashes, $HOME.claudesettings.json.
_PS_CMDLETS = _PS_WRITERS | _PS_FETCHERS | frozenset((
    "copy-item", "move-item", "remove-item"))
# PowerShell's aliases of its writers. Not sc, which is sc.exe, Windows'
# service control, to anyone who types it outside Windows PowerShell 5.1.
_PS_ALIASES = {"copy": "copy-item", "cpi": "copy-item", "move": "move-item",
               "mi": "move-item", "ni": "new-item"}


def _writer_name(name):
    """A program's name as the rules that judge writes look it up: without
    .exe (curl.exe is what Windows PowerShell users type, its curl being
    Invoke-WebRequest), and a PowerShell alias by the cmdlet it stands for."""
    if name.endswith(".exe"):
        name = name[:-4]
    return _PS_ALIASES.get(name, name)


def _as_written(name, stage):
    """stage as its program reads it: slashed for one of _PS_CMDLETS."""
    return _slashed(stage) if name in _PS_CMDLETS else stage


def _operands(args, values=frozenset()):
    """args without their options and the values they take, up to `--`
    and everything after it."""
    out, skip, options = [], False, True
    for word in args:
        if skip:
            skip = False
        elif options and word == "--":
            options = False
        elif options and word[:1] == "-" and len(word) > 1:
            skip = word in values
        else:
            out.append(word)
    return out


# The letters of a sed or perl cluster after which the rest of it, or else
# the next word, is a script (-e), a file of one (-f), or another value.
_SCRIPT_LETTERS = {"sed": "e", "gsed": "e", "perl": "eE"}
_SCRIPT_FILE_LETTERS = {"sed": "f", "gsed": "f", "perl": ""}
_VALUE_LETTERS = {"sed": "l", "gsed": "l", "perl": "IMmxCdD"}


def _in_place(name, args):
    """(scripts, files) of a sed or perl told to edit files in place, or
    None: -i, -i.bak, BSD's -i '', --in-place, or a cluster holding i. The
    scripts are what -e gives, or else the first operand; one read from a
    file (-f) is shown as nothing."""
    inplace, scripts, operands, i = False, [], [], 0
    script, script_file = _SCRIPT_LETTERS[name], _SCRIPT_FILE_LETTERS[name]
    while i < len(args):
        word = args[i]
        i += 1
        if word in ("--expression", "--file"):
            scripts.append(args[i] if word == "--expression" and i < len(args)
                           else "")
            i += 1
        elif word.startswith(("--expression=", "--file=")):
            scripts.append(word.split("=", 1)[1] if word[2] == "e" else "")
        elif word == "--in-place" or word.startswith("--in-place="):
            inplace = True
        elif word == "-i":
            inplace = True
            if i < len(args) and args[i] == "":
                i += 1                         # BSD's -i '': no backup
        elif word[:1] == "-" and word[1:2] != "-" and len(word) > 1:
            for k, letter in enumerate(word[1:], 1):
                if letter == "i":
                    inplace = True
                    break                      # the rest is a suffix
                if letter in script or letter in script_file:
                    value = word[k + 1:]
                    if not value and i < len(args):
                        value, i = args[i], i + 1
                    scripts.append(value if letter in script else "")
                    break
                if letter in _VALUE_LETTERS[name]:
                    break                      # the rest is a value
        elif word != "--":
            operands.append(word)
    if not inplace:
        return None
    if scripts:
        return scripts, operands
    return operands[:1], operands[1:]


def _copied(name, args):
    """(destinations, sources) of cp, mv, install, ln or rsync: the
    destination named, and inside it the name of each source, since which
    of the two it writes depends on what is there. install -d makes
    directories and writes none; a remote destination is no file here."""
    values = _COPY_VALUES[name]
    target_dir, operands, skip, options = None, [], False, True
    for k, word in enumerate(args):
        if skip:
            skip = False
        elif options and word == "--":
            options = False
        elif options and word in ("-t", "--target-directory"):
            target_dir = args[k + 1] if k + 1 < len(args) else None
            skip = True
        elif options and word.startswith("--target-directory="):
            target_dir = word.split("=", 1)[1]
        elif options and word[:1] == "-" and len(word) > 1:
            if name == "install" and (word == "--directory" or (
                    word[1:2] != "-" and "d" in word[1:])):
                return [], []
            skip = word in values
        else:
            operands.append(word)
    if target_dir is None:
        if len(operands) < 2:
            return [], []
        target_dir, operands = operands[-1], operands[:-1]
    if name == "rsync" and _REMOTE_PATH.match(target_dir):
        return [], operands
    inside = [target_dir.rstrip("/") + "/" + s.rstrip("/").rsplit("/", 1)[-1]
              for s in operands if s.rstrip("/")]
    return [target_dir] + inside, operands


def _fetched_to(name, args):
    """The file curl -o, wget -O, dd of= or Invoke-WebRequest -OutFile
    writes, or None. PowerShell takes a parameter by any prefix of its name
    that no other shares: -OutF is -OutFile's, -O is not."""
    for k, word in enumerate(args):
        value = args[k + 1] if k + 1 < len(args) else None
        if name in _PS_FETCHERS:
            key, colon, inline = word.partition(":")
            if len(key) >= 5 and "-outfile".startswith(key.lower()):
                return inline if colon else value
        elif name == "dd":
            if word.startswith("of="):
                return word[3:]
        elif name == "curl":
            if word in ("-o", "--output"):
                return value
            if word.startswith("--output="):
                return word[9:]
            if word[:1] == "-" and word[1:2] != "-":
                for j, letter in enumerate(word[1:], 1):
                    if letter == "o":
                        return word[j + 1:] or value
                    if letter in _CURL_VALUE_LETTERS:
                        break
        elif name == "wget":
            if word in ("-O", "--output-document"):
                return value
            if word.startswith("--output-document="):
                return word[18:]
            if word[:1] == "-" and word[1:2] != "-" and "O" in word:
                return word[word.index("O") + 1:] or value
    return None


def _powershell_written(name, args, stage):
    """(target, value) for each file one of PowerShell's writers writes:
    the path it is given by name, or by place."""
    named, positional, skip = {}, [], None
    for word in args:
        if skip is not None:
            named[skip] = word
            skip = None
        elif word[:1] == "-" and len(word) > 1:
            key = word.lower()
            if key in _PS_VALUES:
                skip = key
        else:
            positional.append(word)
    value = named.get("-value")
    if name in ("copy-item", "move-item"):
        target = named.get("-destination") or (positional[1:2] or [None])[0]
    else:
        path = next((named[k] for k in _PS_PATHS if k in named), None)
        target = path or (positional[:1] or [None])[0]
        if value is None and name in ("add-content", "set-content"):
            # -Value by place: the word after the path, or the first when
            # the path is named.
            given = positional if path else positional[1:]
            value = given[0] if given else None
    found = [(target, value)] if target else []
    # PowerShell does not escape with \, and a path that ends in \" is cut
    # wrong by a POSIX split: the Startup folder is found in the text too,
    # which both callers have already slashed (_as_written).
    if name != "remove-item" and _STARTUP_FOLDER in stage.lower():
        found.append(("shell:startup", value))
    return found


def _stage_writes(name, args, stage):
    """_Wrote(target, how, detail) for each file a stage writes or removes:
    by its program's own words when args are given (the stage's words
    after the program, its redirections left out), then by each of its
    redirections. how is >, >>, tee, tee -a, sed (detail: the scripts),
    edit (yq -i; detail: the program), copy, move or link (detail: the
    sources), fetch, write (detail: the text written, when it is shown) or
    remove."""
    found = []
    if args is not None:
        if name in ("tee", "sponge"):
            # sponge (moreutils) soaks up its input and then writes it, so
            # jq ... f | sponge f writes f as tee would.
            appends = any(a in ("-a", "--append") or (
                a[:1] == "-" and a[1:2] != "-" and "a" in a) for a in args)
            how = "tee -a" if appends else "tee"
            found += [_Wrote(t, how, None) for t in _operands(args) if t != "-"]
        elif name in ("sed", "gsed", "perl"):
            edited = _in_place(name, args)
            if edited:
                found += [_Wrote(t, "sed", edited[0]) for t in edited[1]]
        elif name == "yq":
            if any(a in ("-i", "--inplace") for a in args):
                words = [w for w in _operands(args) if w not in ("e", "eval")]
                found += [_Wrote(t, "edit", words[0]) for t in words[1:2]]
        elif name in _COPY_VALUES:
            targets, sources = _copied(name, args)
            found += [_Wrote(t, _COPY_HOW[name], sources) for t in targets]
        elif name in ("curl", "wget", "dd") or name in _PS_FETCHERS:
            target = _fetched_to(name, args)
            if target and target != "-":
                found.append(_Wrote(target, "fetch", None))
        elif name in ("rm", "unlink", "shred"):
            found += [_Wrote(t, "remove", None) for t in _operands(args)]
        elif name == "truncate":
            if any(a in ("-s0", "--size=0") or a == "0" for a in args):
                found += [_Wrote(t, "remove", None) for t in _operands(
                    args, frozenset(("-s", "--size", "-r", "--reference")))]
        elif name in _PS_WRITERS or name in ("copy-item", "move-item",
                                             "remove-item"):
            how = "remove" if name == "remove-item" else "write"
            found += [_Wrote(t, how, v)
                      for t, v in _powershell_written(name, args, stage)]
    found += [_Wrote(target, ">>" if appends else ">", None)
              for _s, _e, target, appends in _redirects(stage)]
    return found


# The shells whose string _shell_string reads: the POSIX ones, and
# PowerShell and cmd, through which Claude Code's Bash tool on Windows, Git
# Bash, runs every cmdlet and every cmd built-in.
_SHELL_STRING_HEADS = _STDIN_SHELLS | frozenset((
    "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe"))


def _shell_string(name, words):
    """The string a shell stage is given to run, or None: a POSIX shell's
    -c string; what follows PowerShell's -Command (or a prefix of it: -c,
    -com), which takes every word after it, and not -File's script or
    -EncodedCommand's blob, which exec.encoded reads; what follows cmd's
    /c or /k, or //c as Git Bash has it typed."""
    if not words:
        return None
    if name.endswith(".exe"):
        name = name[:-4]
    if name in _STDIN_SHELLS:
        return _exec_operand(name, words)
    if name in ("powershell", "pwsh"):
        for i, word in enumerate(words[1:], 1):
            flag = word[1:].lower()
            if word[:1] not in "-/" or not flag:
                continue
            if "file".startswith(flag) or "encodedcommand".startswith(flag) \
                    or flag == "ec":
                return None
            if flag == "c" or (len(flag) >= 3 and "command".startswith(flag)):
                return " ".join(words[i + 1:]) or None
        return None
    if name == "cmd":
        for i, word in enumerate(words[1:], 1):
            if word[:1] == "/" and word.lstrip("/").lower() in ("c", "k", "r"):
                return " ".join(words[i + 1:]) or None
    return None


# persist: something left to run again by itself, after the session.
#
# A crontab installed, a launch agent or systemd unit written or loaded, a
# Windows service created or pointed at another program, a scheduled task
# created, a Run key set, a login item put in an autostart or Startup
# folder: each runs again on its own, with your permissions, after the agent
# has gone, and nothing in the project shows it. It is what a
# prompt-injected agent reaches for (ATT&CK T1053, T1543, T1547, T1037,
# T1546), and what an agent asked to write code rarely does. Each is high,
# so the hook asks first.
#
# Two kinds are medium, recorded and never interrupting, because they are
# among the commonest legitimate things an agent does: a packaged service
# enabled by name (systemctl enable docker, brew services start, sc config
# x start= auto), which runs the package's own code, and a change to a
# shell startup file (an export PATH line, eval "$(pyenv init -)", the brew
# shellenv line). A startup file is high by what goes into it, not by its
# name: a line that fetches and runs a script, decodes and runs one, or
# opens /dev/tcp, or a startup file that comes straight from the network.
#
# Left out by design: git hooks and core.hooksPath (pre-commit and husky run
# only in the repository), docker run --restart, pm2, at, the SysV and
# OpenRC enable commands, and authorized_keys (access, not code).
_PERSIST_HINTS = ("cron", "launch", "systemctl", "systemd", "schtasks",
                  "currentversion", "startup", "scheduledtask", "brew",
                  "autostart", "init.d", "rc.local", "bashrc", "zshrc",
                  "kshrc", "profile", "zshenv", "zlog", "bash_log", "fish",
                  "bash_aliases", "binpath", "start=", "new-service",
                  "set-service")

_STARTUP_WHY = ("A shell startup file was changed. What it holds runs in every "
                "shell you open from now on, so the change outlives the "
                "session. Most such changes add a PATH line or a tool's init.")
_STARTUP_RUN_WHY = ("A shell startup file now runs a script fetched from the "
                    "network or hidden in an encoding, or opens a connection "
                    "out. It does that in every shell you open from now on, "
                    "with your permissions, and nothing on screen shows it.")
_SERVICE_WHY = ("A service was set to start at boot or at login. What it runs "
                "is usually a package's own, and it now starts every time, "
                "whether or not the session is running.")

# Where a scheduler or service manager finds what it runs: a file of jobs,
# or a directory each file in which is one. And the shell's startup files,
# with ~/.bash_aliases among them: Debian's and Ubuntu's default .bashrc
# sources it, and tells you to put your additions there.
_JOB_FILES = frozenset(("/etc/crontab", "/etc/anacrontab", "/etc/rc.local"))
_JOB_DIRS = (
    "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
    "/etc/cron.weekly/", "/etc/cron.monthly/", "/var/spool/cron/",
    "/usr/lib/cron/tabs/", "/var/cron/tabs/", "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/", "/etc/systemd/system/", "/etc/systemd/user/",
    "/usr/lib/systemd/system/", "/usr/lib/systemd/user/",
    "/lib/systemd/system/", "/lib/systemd/user/", "/etc/xdg/autostart/",
    "/etc/init.d/")
_JOB_HOME = ("Library/LaunchAgents/", ".config/systemd/user/",
             ".local/share/systemd/user/", ".config/autostart/")
_STARTUP_SYSTEM = frozenset((
    "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zshrc",
    "/etc/zprofile", "/etc/zshenv", "/etc/zlogin", "/etc/zsh/zshrc",
    "/etc/zsh/zprofile", "/etc/zsh/zshenv", "/etc/zsh/zlogin"))
_STARTUP_HOME = frozenset((
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".bash_aliases", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
    ".kshrc", ".config/fish/config.fish"))
_DRIVE_LETTER = re.compile(r"[A-Za-z]:(?=/)")
# PowerShell's profile, by its variable or by its file.
_PROFILE_VARIABLE = re.compile(
    r"\$profile(?:\.(?:currentuser|allusers)(?:currenthost|allhosts))?\Z", re.I)
_PS_PROFILE_FOLDERS = frozenset(("powershell", "windowspowershell"))


def _undriven(path):
    """A slashed path without the drive it starts with: C:/Users/me is
    /Users/me, as _posix_home reads this user's home on Windows."""
    drive = _DRIVE_LETTER.match(path)
    return path[drive.end():] if drive else path


def _persist_place(target):
    """"job" when target is where a scheduler or service manager finds what
    it runs, "startup" when it is a shell's startup file, else None. A
    relative path is none: ./docker/.bashrc is a project's file."""
    t = _slashed(target.strip())
    low = t.lower()
    if _STARTUP_FOLDER in low or low.startswith(("shell:startup",
                                                 "shell:common startup")):
        return "job"
    folder, _sep, name = low.rstrip("/").rpartition("/")
    if _PROFILE_VARIABLE.match(t) or (
            folder.rpartition("/")[2] in _PS_PROFILE_FOLDERS
            and (name == "profile.ps1" or (name.startswith("microsoft.")
                                           and name.endswith("_profile.ps1")))):
        return "startup"
    path = _as_absolute(_undriven(t), _posix_home())
    if path is None:
        return None
    if path in _JOB_FILES or (path + "/").startswith(_JOB_DIRS):
        return "job"
    if path in _STARTUP_SYSTEM or path.startswith("/etc/profile.d/"):
        return "startup"
    rel = _home_relative(path)
    if rel is None:
        return None
    if (rel + "/").startswith(_JOB_HOME):
        return "job"
    if rel in _STARTUP_HOME or rel.startswith(".config/fish/conf.d/"):
        return "startup"
    return None


# The Run keys, whose every value Windows runs at login. A key as Git Bash
# leaves it, unquoted, has lost its backslashes, so it is matched without
# them too. String tests, from the end.
_RUN_KEYS = ("currentversion/run", "currentversion/runonce",
             "currentversion/runonceex", "currentversion/runservices",
             "currentversion/runservicesonce",
             "currentversion/policies/explorer/run")
_RUN_KEYS_JOINED = tuple(k.replace("/", "") for k in _RUN_KEYS)
_SLASHES = re.compile(r"[\\/]+")
_SYSTEMCTL_VALUES = frozenset((
    "-M", "-H", "--host", "--machine", "-t", "--type", "-p", "--property",
    "--root", "-o", "--output", "-n", "--lines", "-s", "--signal", "--state"))
# Programs that schedule or enable by a verb of their own, by the name
# _writer_name gives them: sc.exe is sc.
_PERSIST_VERBS = frozenset((
    "crontab", "launchctl", "systemctl", "brew", "schtasks", "reg",
    "register-scheduledtask", "new-itemproperty", "set-itemproperty", "sc",
    "new-service", "set-service"))
# PowerShell's start types that start a service at boot.
_AUTOMATIC = frozenset(("automatic", "automaticdelayedstart"))


def _is_run_key(word):
    key = _SLASHES.sub("/", word).strip("/").lower()
    return key.endswith(_RUN_KEYS) or key.replace("/", "").endswith(_RUN_KEYS_JOINED)


def _crontab_installs(args):
    """Whether crontab, given args, installs a table: from a file, or from
    its input given - or nothing. -l lists, -r removes, -e opens an editor,
    which an agent with no terminal does not get to."""
    skip = False
    for word in args:
        if skip:
            skip = False
        elif word == "-u":
            skip = True
        elif word in ("--help", "--version"):
            return False
        elif word[:1] == "-" and word != "-" and not word.startswith("-u"):
            if set(word[1:]) & set("lreTVh"):
                return False
    return True


# crontab -l | grep -v job | crontab -: the way to take a line out of a
# table without crontab -e, whose editor an agent has no terminal for. What
# reaches crontab - is the table it already had with lines dropped and none
# added or changed, so it schedules nothing new. Read strictly, and what is
# not known to only drop lines leaves crontab - an install: grep's -o, -n or
# -c, a sed script with s, a, r or e in it, a file read as well, or a table
# listed for one user (or through sudo) and put back for another, can each
# hand crontab a line it did not have.
_TABLE_STAGES = frozenset(("crontab", "grep", "egrep", "sed", "gsed"))
# grep's options that only choose which lines it keeps; -e and -f give the
# patterns, and with them no word is the pattern.
_GREP_KEEPS = frozenset("vEFGPiwxs")
_GREP_KEEPS_LONG = frozenset((
    "--invert-match", "--extended-regexp", "--fixed-strings", "--basic-regexp",
    "--perl-regexp", "--ignore-case", "--word-regexp", "--line-regexp",
    "--no-messages"))
_SED_KEEPS = frozenset("nErsu")
_SED_KEEPS_LONG = frozenset((
    "--quiet", "--silent", "--regexp-extended", "--posix", "--separate",
    "--unbuffered", "--sandbox"))
# One sed command that deletes: an address, or two (a line, $, /regex/,
# first~step, +N), maybe negated, then d, then ; or a newline. Anchored and
# read one after another, so a script is read once.
_SED_ADDRESS = r"(?:\d+(?:~\d+)?|\$|/(?:[^/\\\n]|\\.)*/[IM]*)"
_SED_DELETE = re.compile(
    _SED_ADDRESS + r"(?:[ \t]*,[ \t]*(?:" + _SED_ADDRESS + r"|[+~]\d+))?"
    r"[ \t]*!?[ \t]*d[ \t]*(?:[;\n][\s;]*|\Z)")
_SED_GAP = re.compile(r"[\s;]*")


def _only_deletes(script):
    """Whether a sed script is nothing but lines deleted by address. An
    empty one, as a script read from a file (-f) is given, is not known to
    be."""
    pos = _SED_GAP.match(script).end()
    if pos == len(script):
        return False
    while pos < len(script):
        found = _SED_DELETE.match(script, pos)
        if not found:
            return False
        pos = found.end()
    return True


def _crontab_form(args):
    """(user, rest) of crontab's args: the user -u names, "" for none, and
    the other words."""
    user, rest, k = "", [], 0
    while k < len(args):
        word = args[k]
        if word == "-u":
            user, k = (args[k + 1] if k + 1 < len(args) else ""), k + 2
            continue
        if word.startswith("-u"):
            user = word[2:]
        else:
            rest.append(word)
        k += 1
    return user, rest


def _grep_drops(args):
    """Whether grep, given args, only drops lines of what it is piped: no
    option but those that choose which lines it keeps, and no file."""
    patterns, operands, k = False, 0, 0
    while k < len(args):
        word = args[k]
        k += 1
        if word == "--":
            operands += len(args) - k
            break
        if word in ("--regexp", "--file"):
            patterns, k = True, k + 1
        elif word.startswith(("--regexp=", "--file=")):
            patterns = True
        elif word[:2] == "--":
            if word not in _GREP_KEEPS_LONG:
                return False
        elif word[:1] == "-" and len(word) > 1:
            for j, letter in enumerate(word[1:], 1):
                if letter in "ef":
                    patterns = True
                    k += 1 if j + 1 == len(word) else 0
                    break
                if letter not in _GREP_KEEPS:
                    return False
        else:
            operands += 1
    return operands == (0 if patterns else 1)


def _sed_drops(args):
    """Whether sed, given args, only drops lines of what it is piped: each
    script nothing but deletes (_only_deletes), no file, not in place."""
    scripts, operands, k = [], [], 0
    while k < len(args):
        word = args[k]
        k += 1
        if word == "--":
            operands += args[k:]
            break
        if word == "--expression":
            scripts.append(args[k] if k < len(args) else "")
            k += 1
        elif word.startswith("--expression="):
            scripts.append(word[13:])
        elif word[:2] == "--":
            if word not in _SED_KEEPS_LONG:
                return False
        elif word[:1] == "-" and len(word) > 1:
            for j, letter in enumerate(word[1:], 1):
                if letter == "e":
                    value = word[j + 1:]
                    if not value and k < len(args):
                        value, k = args[k], k + 1
                    scripts.append(value)
                    break
                if letter not in _SED_KEEPS:
                    return False
        else:
            operands.append(word)
    if not scripts:
        scripts, operands = operands[:1], operands[1:]
    return bool(scripts) and not operands and all(map(_only_deletes, scripts))


def _table_piped(stage, first, table):
    """(table, refilled) for one stage of crontab -l | grep -v job |
    crontab -. table: whose crontab, unchanged but for lines dropped, the
    pipe out of this stage carries: (what stands before crontab, the user
    -u names), or None. refilled: the stage is the crontab - that installs
    that same table back. first: the stage starts a pipeline."""
    if not first and table is None:
        return None, False
    name = _writer_name(_command_word(stage))
    if name not in _TABLE_STAGES:
        return None, False
    words = _stage_words(stage)
    args, replaced = _without_redirects(words[1:])
    if replaced:
        return None, False                     # it reads a file, not the pipe
    if name == "crontab":
        user, rest = _crontab_form(args)
        mine = (tuple(stage[:len(stage) - len(_after_prefix(stage))].split()), user)
        if first:
            return (mine if rest == ["-l"] else None), False
        return None, rest == ["-"] and mine == table
    if first:
        return None, False
    drops = _grep_drops(args) if name in ("grep", "egrep") else _sed_drops(args)
    return (table if drops else None), False


def _deletes_only(name, wrote):
    """Whether a sed told to edit a file in place only deletes lines from
    it: sed '/old-job/d' /etc/crontab takes a job out, and adds none."""
    return (name in ("sed", "gsed") and wrote.how == "sed" and bool(wrote.detail)
            and all(map(_only_deletes, wrote.detail)))


# The tables in crontab's format, where each line is a job or a setting and
# a line taken out runs nothing new. In any other job's file a line taken
# out can be what kept it from running: Hidden=true in an autostart entry,
# <key>Disabled</key> in a launchd plist, a unit's ConditionPathExists= or
# ExecCondition=, the exit 0 near the top of rc.local, an init script or a
# cron.daily script. Debian keeps at's jobs, which are scripts, in
# /var/spool/cron/atjobs/.
_CRONTAB_FILES = frozenset(("/etc/crontab", "/etc/anacrontab"))
_CRONTAB_DIRS = ("/etc/cron.d/", "/var/spool/cron/", "/usr/lib/cron/tabs/",
                 "/var/cron/tabs/")
_AT_DIRS = ("/var/spool/cron/atjobs/", "/var/spool/cron/atspool/")


def _crontab_table(target):
    """Whether target, as persist reads a path (_persist_place), is a table
    in crontab's format: /etc/crontab, a file in /etc/cron.d, a user's
    table in cron's spool."""
    path = _as_absolute(_undriven(_slashed(target.strip())), _posix_home())
    if path is None:
        return False
    if path in _CRONTAB_FILES:
        return True
    folder = path + "/"
    return folder.startswith(_CRONTAB_DIRS) and not folder.startswith(_AT_DIRS)


def _persist_verb(name, args):
    """(severity, kind) of a stage that schedules or enables something by a
    verb of its own, or None. kind is "job" for an entry the call itself
    makes, and "service" for one a package already holds, enabled by name."""
    first = args[0].lower() if args else ""
    if name == "crontab":
        return (HIGH, "job") if _crontab_installs(args) else None
    if name == "launchctl":
        if first in ("load", "bootstrap", "submit"):
            return HIGH, "job"
        return (MEDIUM, "service") if first == "enable" else None
    if name == "systemctl":
        words, skip = [], False
        for word in args:
            if skip:
                skip = False
            elif word[:1] == "-":
                skip = word in _SYSTEMCTL_VALUES
            else:
                words.append(word)
        if words[:1] == ["link"]:
            return HIGH, "job"
        if words[:1] in (["enable"], ["reenable"]):
            # A unit named by its path is a file of the agent's own.
            if any("/" in unit for unit in words[1:]):
                return HIGH, "job"
            return MEDIUM, "service"
        return None
    if name == "brew":
        plain = [w for w in args if w[:1] != "-"]
        return (MEDIUM, "service") if plain[:2] == ["services", "start"] else None
    if name == "schtasks":
        # /create, or //create from Git Bash, which reads /c as a path.
        return (HIGH, "job") if any(
            w[:1] in "/-" and w.lstrip("/-").lower() == "create"
            for w in args) else None
    if name == "reg":
        return (HIGH, "job") if first == "add" and any(
            _is_run_key(w) for w in args[1:2]) else None
    if name == "register-scheduledtask":
        return HIGH, "job"
    if name in ("new-itemproperty", "set-itemproperty"):
        return (HIGH, "job") if any(_is_run_key(w) for w in args) else None
    if name == "sc":
        return _sc_verb(first, [w.lower() for w in args])
    if name == "new-service":
        return HIGH, "job"             # it starts automatically by default
    if name == "set-service":
        low = [w.lower() for w in args]
        if any("-binarypathname".startswith(w) and len(w) > 2 for w in low):
            return HIGH, "job"
        automatic = any(_option_value(low, k, "-startuptype") in _AUTOMATIC
                        or (w.startswith("-startuptype:") and w[13:] in _AUTOMATIC)
                        for k, w in enumerate(low))
        return (MEDIUM, "service") if automatic else None
    return None


def _sc_verb(first, low):
    """(severity, kind) of sc, Windows' service control, or None: a service
    created, or an existing one pointed at another program (binPath=), is a
    job; one set to start at boot (start= auto) is a service enabled by
    name. sc's options are written `name= value`, or `name=value`."""
    if first == "create":
        return HIGH, "job"
    if first != "config":
        return None
    if any(w.startswith("binpath=") for w in low):
        return HIGH, "job"
    for k, word in enumerate(low):
        if word.startswith("start="):
            value = word[6:] or (low[k + 1] if k + 1 < len(low) else "")
            if value in ("auto", "delayed-auto"):
                return MEDIUM, "service"
    return None


def _escalates(content, depth=0):
    """Whether text written to a startup file runs what the session cannot
    show: a script fetched from the network (exec.remote's own finder),
    one decoded from an encoding (exec.encoded's), or a connection opened
    through /dev/tcp or /dev/udp. Judged as the command it is, never run.
    A shell's quoted -c string is read as a command of its own, two deep:
    a line meant to run from .bashrc without holding it up is often
    `nohup sh -c "curl ... | sh" >/dev/null 2>&1 &`."""
    if not content:
        return False
    content = content[:MAX_SCAN_CHARS]
    if "/dev/tcp/" in content or "/dev/udp/" in content:
        return True
    shell = _shell_text("Bash", {"command": content})
    if _remote_run(shell):
        return True
    if depth < 2:
        for start, end, _op in _command_spans(shell):
            stage = _normalised(shell[start:end].strip())
            name = _command_word(stage)
            if name in _SHELL_STRING_HEADS and _escalates(
                    _shell_string(name, _stage_words(stage)), depth + 1):
                return True
    source = _shell_text("Bash", {"command": content}, keep_source=True)
    return bool(source) and _encoded_run(source) is not None


def _startup_content(name, stage, before):
    """What a stage that writes a startup file shows of what it writes: its
    own echo or printf, its here-string, and what the echo or printf piped
    into it printed; a stage that is only a quoted string, which PowerShell
    writes out, itself or piped in."""
    parts = []
    if name in _PRINTERS:
        parts.append(_printed(stage))
    here = _here_string_word(stage)
    if here:
        parts.append(here)
    literal = _quoted_literal(stage)
    if literal:
        parts.append(literal)
    if before is not None:
        if _command_word(before) in _PRINTERS:
            parts.append(_printed(before))
        literal = _quoted_literal(before)
        if literal:
            parts.append(literal)
    return "\n".join(parts)


def _shown_written(wrote):
    """What a write shows of the text it puts in a file: what a sed or perl
    script adds (a, i, c, and the right of s), and the value a PowerShell
    writer is given."""
    if wrote.how == "sed":
        return [text for script in wrote.detail for text in _sed_changes(script)[1]]
    if wrote.how == "write" and wrote.detail:
        return [wrote.detail]
    return []


_Persisted = collections.namedtuple("_Persisted",
                                    "start end severity kind fed_from")
# What may run a stage's words as a command of their own, or write.
_PERSIST_HEADS = _PERSIST_VERBS | _WRITERS


@functools.lru_cache(maxsize=32)
def _persistence(text, depth=0):
    """_Persisted(start, end, severity, kind, fed_from) for each stage of a
    write view that leaves something to run again by itself, in order.
    kind is "job", "service" or "startup"; fed_from is where what is piped
    into the stage starts, the fetch a startup file is written from among
    it, so the evidence shows the job line echo hands to crontab - and the
    curl that tee -a ~/.bashrc writes out.

    Linear: a word of the command is read only by a regex anchored where it
    starts, a stage is split into words only when its program is one of
    _PERSIST_HEADS or a shell, or a filter in a pipe that crontab -l starts
    (_table_piped), and what a startup file is given is judged once, on
    that stage's own text."""
    if not text or depth > 3 or not _may_persist(text):
        return ()
    found, before, fetched, piped, table = [], None, None, None, None
    for start, end, op in _command_spans(text):
        at = _SPACES.match(text, start, end).end()
        stage = _normalised(_unwrap_c(_uncommented(text[at:end])))
        if stage:
            table, refilled = _table_piped(stage, before is None, table)
            finding = _persisted_stage(stage, at, end, before, fetched, depth,
                                       refilled)
            if finding and finding.fed_from is None and before is not None:
                finding = finding._replace(fed_from=piped)
            if finding:
                found.append(finding)
            if fetched is None and _FETCHER.match(stage):
                fetched = at
        if op == "|":
            before, piped = stage, at if piped is None else piped
        else:
            before = fetched = piped = table = None
    return tuple(found)


def _persisted_stage(stage, at, end, before, fetched, depth, refilled=False):
    """The _Persisted of one stage, or None: see _persistence. refilled:
    the stage is a crontab - given back its own table, lines dropped
    (_table_piped)."""
    name = _writer_name(_command_word(stage))
    stage = _as_written(name, stage)
    words = (_stage_words(stage)
             if name in _PERSIST_HEADS or name in _SHELL_STRING_HEADS else None)
    if depth < 3:
        inner = ()
        operand = _shell_string(name, words)
        if operand:
            inner = _persistence(_write_view(operand), depth + 1)
        elif "$(" in stage or "`" in stage:
            inner = tuple(f for lo, hi in _substitution_spans(stage)
                          for f in _persistence(stage[lo:hi], depth + 1))
        top = _worst(inner)
        if top:
            return _Persisted(at, end, top.severity, top.kind, None)
    args = _without_redirects(words[1:])[0] if words else None
    if name in _PERSIST_VERBS and not refilled:
        verb = _persist_verb(name, args)
        if verb:
            return _Persisted(at, end, verb[0], verb[1], None)
    if _shortcut_to_startup(stage):
        return _Persisted(at, end, HIGH, "job", None)
    place, written, shown, downloaded = None, [], set(), False
    deleting = None                    # (scripts, whether they only delete)
    for wrote in _stage_writes(name, args if name in _WRITERS else None, stage):
        if wrote.how != "remove":
            here = _persist_place(wrote.target)
            if here == "job":
                # A sed gives every file it edits the same scripts: they
                # are read once, however many tables it edits.
                if deleting is None or deleting[0] is not wrote.detail:
                    deleting = wrote.detail, _deletes_only(name, wrote)
                if deleting[1] and _crontab_table(wrote.target):
                    continue
                return _Persisted(at, end, HIGH, "job", None)
            if here == "startup":
                # Each target of one way of writing is given the same text:
                # a sed's scripts are read once, however many files it edits.
                if (wrote.how, id(wrote.detail)) not in shown:
                    shown.add((wrote.how, id(wrote.detail)))
                    written += _shown_written(wrote)
                downloaded = downloaded or wrote.how == "fetch"
            place = place or here
    if place != "startup":
        return None
    # A startup file from the network, or one given what fetches, decodes
    # and runs, or connects out.
    if downloaded or _FETCHER.match(stage):
        return _Persisted(at, end, HIGH, "startup", None)
    if fetched is not None:
        return _Persisted(at, end, HIGH, "startup", fetched)
    content = "\n".join([_startup_content(name, stage, before)] + written)
    severity = HIGH if _escalates(content) else MEDIUM
    return _Persisted(at, end, severity, "startup", None)


def _shortcut_to_startup(stage):
    """Whether a stage makes a shortcut in the Startup folder, the way
    PowerShell adds a login item: (New-Object -ComObject WScript.Shell)
    .CreateShortcut("...\\Startup\\x.lnk"), its .Save() a statement after."""
    low = stage.lower()
    if ".createshortcut(" not in low:
        return False
    low = _slashed(low)
    return (_STARTUP_FOLDER in low or "shell:startup" in low
            or 'getfolderpath("startup")' in low
            or "getfolderpath('startup')" in low)


def _may_persist(text):
    """Whether text could name anything persist reports. Only a way not to
    read the rest of a call that names none, which is nearly every call."""
    low = text.lower()
    return any(hint in low for hint in _PERSIST_HINTS)


def _persist_run(text):
    """Span of the first of the stages that persist the worst, from the
    fetch that feeds it when one does."""
    top = _worst(_persistence(text))
    if top is None:
        return None
    return (top.start if top.fed_from is None else top.fed_from), top.end


def _refine_persistence(text, severity, tool_input=None):
    """High for a job the call itself makes, and for a startup file given
    what runs unseen, whether it shows in the command or in the body of a
    here-document that writes the file: cat >> ~/.zshrc <<'EOF', and cat
    <<'EOF' | tee -a ~/.bashrc, where the body is cat's and tee writes it.
    Medium for any other startup file change, and for a service enabled
    by name."""
    found = _persistence(text)
    if any(f.kind == "job" for f in found):
        return HIGH
    startup = [f for f in found if f.kind == "startup"]
    if any(f.severity == HIGH for f in startup):
        return HIGH, _STARTUP_RUN_WHY
    if startup:
        starts = [f.start if f.fed_from is None else f.fed_from for f in startup]
        spans = _command_spans(text)
        span_starts = [start for start, _end, _op in spans]
        for pos, body in getattr(text, "bodies", ()):
            i = bisect.bisect_right(starts, pos) - 1
            if i < 0 or pos > startup[i].end:
                continue
            if pos < startup[i].start:
                # In a stage piped into the writer: only cat passes its
                # body on as it is; a python or sed given one is a program.
                lo, hi, _op = spans[bisect.bisect_right(span_starts, pos) - 1]
                if _command_word(_normalised(text[lo:hi].strip())) != "cat":
                    continue
            if _escalates(body):
                return HIGH, _STARTUP_RUN_WHY
        return MEDIUM, _STARTUP_WHY
    return MEDIUM, _SERVICE_WHY


def _persist_written(text):
    """Span of the first path a file tool wrote that is a job's place, else
    of the first that is a startup file's, else None."""
    first, pos = None, 0
    for line in text.split("\n"):
        place = _persist_place(line) if line else None
        if place == "job":
            return pos, pos + len(line)
        if place == "startup" and first is None:
            first = pos, pos + len(line)
        pos += len(line) + 1
    return first


def _refine_persist_written(text, severity, tool_input=None):
    """A job's file is high; a startup file is high when what was written
    into it runs what the session cannot show, and medium otherwise."""
    if any(_persist_place(line) == "job" for line in text.split("\n") if line):
        return HIGH
    written = "\n".join(t for t, _pattern in _written_change(tool_input).new)
    if _escalates(written):
        return HIGH, _STARTUP_RUN_WHY
    return MEDIUM, _STARTUP_WHY


# agent.config: what an agent may do without asking, loosened.
#
# The one kind of call that can switch off ranwhat's own guard, and no rule
# saw it: a Write to ~/.claude/settings.json reached none, `echo '{...}' >
# ~/.claude/settings.json` was an echo, dropped as text, and `ranwhat hook
# uninstall` matched nothing. Claude Code reloads its settings when the file
# changes, so the write is the last act; no later call runs it to be judged.
# The hook's ask is the one place the guard can stop its own removal.
#
# Judged on what is launched (claude, codex or gemini with approvals or the
# sandbox off, the hook uninstalled or told to stand aside, ranwhat itself
# uninstalled, an MCP server added) and on what is written to an agent's
# configuration, by a file tool or the shell, or removed from it.
#
# Severity follows what is switched off. Critical: ranwhat's guard itself,
# every hook, or every prompt of every new session on the machine
# (bypassPermissions in user or managed settings; approvals never and no
# sandbox in Codex's user config). High: one agent launched with no
# approvals, a broad allow rule, a deny or ask rule taken out, a settings
# file removed or emptied, what revoke lists as grants worth taking back.
# Medium, never interrupting, for set-up that is often what the user asked
# for: an MCP server or a hook added, one of Codex's two switches, another
# event's hooks taken out, a whole user settings file rewritten with nothing
# in it to judge.
#
# Content is read here, and only here: for a path that is an agent's own
# configuration, as configuration (key and value markers, and the list each
# permission rule sits in), never split into commands, never handed to
# another rule. Claude Code reads the file itself, so no later call runs it,
# and _CONTENT_KEYS's rule does not apply: an Edit of settings.json is the
# same act as /permissions. Write on scripts/ci.sh holding `claude
# --dangerously-skip-permissions` stays a file's content, judged when run.
_AGENT_HINTS = ("claude", "codex", "gemini", "ranwhat", "mcp", "settings",
                "config.toml")

_AGENT_WHY = ("An agent changed what it, or another agent, may do without "
              "asking you: a permission, a hook, an approval or sandbox "
              "setting, or the ranwhat hook itself. Claude Code applies its "
              "settings as they change, so a change like this holds for the "
              "session that made it and for every one after.")
_GUARD_OFF_WHY = ("The ranwhat hook, or every hook, was taken out or told to "
                  "stand aside. The calls it would have asked you about now "
                  "run without a word, in this session and the ones after it.")
_LAUNCH_WHY = ("An agent was started with its approvals or its sandbox "
               "switched off. Whatever it does runs with your permissions, "
               "and nothing asks you first.")
_UNINSTALL_WHY = ("ranwhat itself was uninstalled. Claude Code lets a call "
                  "through when its hook fails to start, so the guard is off "
                  "until ranwhat is installed again.")
_STATE_WHY = ("An agent changed what ranwhat reports: its ignore file, the "
              "secrets clean was told to keep, its key, or where ranwhat "
              "keeps them, or it ran ranwhat ignore. What a change like this "
              "leaves out is missing from watch and check from then on, so "
              "the change itself is always listed.")
# The whys of a change to ranwhat's own guard or its own state. Whatever
# later lets a report leave an action out must not let it leave out one of
# these: an agent that could write the ignore file could otherwise write the
# line that hides its own write.
UNIGNORABLE = frozenset((_GUARD_OFF_WHY, _UNINSTALL_WHY, _STATE_WHY))


def _may_loosen(text):
    """Whether text could name anything agent.config reports. Only a way not
    to read the rest of a call that names none, which is nearly every call."""
    low = text.lower()
    return any(hint in low for hint in _AGENT_HINTS)


def _worse(a, b):
    """The worse of two (severity, why) verdicts, the first of two equal
    ones; None is no verdict."""
    if a is None or (b is not None and _RANK[b[0]] > _RANK[a[0]]):
        return b
    return a


def _worst(found):
    """The first of the worst of found, or None."""
    top = None
    for f in found:
        if top is None or _RANK[f.severity] > _RANK[top.severity]:
            top = f
    return top


def _program(word):
    """A program's name as a word runs it: its base name, in lower case,
    without .exe."""
    name = word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


# What may stand before the program a stage runs, and which of its options
# take the next word as their value. timeout is given a duration too.
_LEAD_VALUES = {
    "sudo": frozenset(("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U",
                       "-T", "--user", "--group", "--chdir", "--host",
                       "--prompt", "--role", "--type", "--other-user",
                       "--close-from", "--command-timeout")),
    "doas": frozenset(("-u", "-C")),
    "env": frozenset(("-u", "-C", "-S", "-P", "--unset", "--chdir",
                      "--split-string")),
    "nice": frozenset(("-n", "--adjustment")),
    "timeout": frozenset(("-s", "-k", "--signal", "--kill-after")),
    "exec": frozenset(("-a",)),
    "time": frozenset(("-f", "-o", "--format", "--output")),
    "caffeinate": frozenset(("-t", "-w")),
    "ionice": frozenset(("-c", "-n", "-p", "-P", "-u", "--class",
                         "--classdata", "--pid", "--pgid", "--uid")),
    "stdbuf": frozenset(("-i", "-o", "-e", "--input", "--output", "--error")),
    "command": frozenset(), "nohup": frozenset(), "setsid": frozenset()}
# Runners that fetch a package and run its program, and their options that
# take a value. The first word after them is the package, or the program
# when an option named the package: either way it is read as a program.
_RUNNER_VALUES = frozenset((
    "-p", "--package", "-c", "--call", "--prefix", "--registry", "--cache",
    "-w", "--workspace", "--node-options", "--from", "--with",
    "--with-requirements", "--python", "--index", "--index-url",
    "--extra-index-url", "--default-index", "--constraints", "--cache-dir",
    "--directory", "--project", "--config-file", "--spec", "--pip-args"))
_AGENT_PACKAGES = {"@anthropic-ai/claude-code": "claude",
                   "@openai/codex": "codex", "@google/gemini-cli": "gemini"}
_VERSION_SPEC = re.compile(r"[@=<>!~\[;]")
_AGENTS = frozenset(("claude", "codex", "gemini"))
_AGENT_INFO = frozenset(("--help", "-h", "--version", "-v", "-V"))
_MCP_ADD = frozenset(("add", "add-json", "add-from-claude-desktop"))
# The programs whose launch is judged: the agents, ranwhat, what installs
# and uninstalls a Python package, the runners, and what sets a variable
# for every program started after it (_switch_kept).
_AGENT_HEADS = frozenset((
    "claude", "codex", "gemini", "ranwhat", "pip", "pip3", "pipx", "uv",
    "uvx", "npx", "bunx", "pnpx", "pnpm", "yarn", "bun", "py", "setx",
    "launchctl", "systemctl"))
# setx's options that take the next word as their value.
_SETX_VALUES = frozenset(("/s", "/u", "/p", "/k", "/f", "/a", "/r", "/d"))
# PowerShell's way to set a variable for the user, or the machine, for good:
# RANWHAT_HOOK, judged by its value, or RANWHAT_HOME, by being set at all.
# The value is quoted, read to its closing quote, which a folder with a
# blank in it needs, or bare, read to the comma: neither runs past a quote,
# so a long run of them is read once.
_SET_ENVIRONMENT = re.compile(
    r"""setenvironmentvariable\s*\(\s*(['"])(ranwhat_hook|ranwhat_home)\1\s*,\s*"""
    r"""(?:(['"])([^'"]*)\3|([^'",)]*))\s*,\s*['"]?"""
    r"""(?:\[(?:system\.)?environmentvariabletarget\]::)?(?:user|machine)\b""",
    re.I)


def _switch_kept(program, args):
    """The name and value of each variable a program sets for every program
    started after it, not only for its own children: setx (Windows' user or
    machine environment, which every new terminal reads), launchctl setenv
    (every app launchd starts) and systemctl set-environment (every unit
    the manager starts). RANWHAT_HOOK=0 set so turns the hook off for each
    session that starts after it, and RANWHAT_HOME set so moves ranwhat's
    state, its ignore file and the secrets clean was told to keep among it,
    for each ranwhat that starts after it."""
    if program == "setx":
        names, skip = [], False
        for word in args:
            if skip:
                skip = False
            elif word[:1] in "/-" and len(word) > 1:
                skip = word.lower().replace("-", "/") in _SETX_VALUES
            else:
                names.append(word)
        return [(names[0].upper(), names[1])] if len(names) > 1 else []
    plain = [w for w in args if w[:1] != "-"]
    if program == "launchctl" and plain[:1] == ["setenv"]:
        pairs = plain[1:]
        return list(zip(pairs[0::2], pairs[1::2]))
    if program == "systemctl" and plain[:1] == ["set-environment"]:
        return [m.groups() for m in map(_ASSIGNMENT.match, plain[1:]) if m]
    return []


def _package_program(spec):
    """The program a runner's package runs: its name without a version,
    and an agent's package by the agent's name."""
    name = spec.lower()
    if name.startswith("@"):
        at = name.find("@", 1)
        name = name[:at] if at > 0 else name
    else:
        name = _VERSION_SPEC.split(name, 1)[0]
    return _AGENT_PACKAGES.get(name) or _program(name)


def _runner_end(name, words, i):
    """Where the words of a runner (npx, bunx, uvx, pnpm dlx, yarn dlx, bun
    x, pipx run, uv run, uv tool run) that starts at words[i] end, or None
    when words[i] starts none."""
    if name in ("npx", "bunx", "uvx", "pnpx"):
        return i + 1
    j = i + 1
    while j < len(words) and words[j][:1] == "-":
        j += 1
    sub = words[j] if j < len(words) else ""
    if (name in ("pnpm", "yarn") and sub == "dlx") or (name == "bun" and sub == "x") \
            or (name in ("pipx", "uv") and sub == "run"):
        return j + 1
    if name == "uv" and sub == "tool" and words[j + 1:j + 2] == ["run"]:
        return j + 2
    return None


def _python_module(words, i):
    """(module, where its arguments start) of python -m at words[i], or
    None: a script, -c's one-liner or the standard input runs no module."""
    j = i + 1
    while j < len(words):
        word = words[j]
        if word[:1] != "-" or word == "-" or word[:2] == "--":
            return None
        for k, letter in enumerate(word[1:], 1):
            if letter == "m":
                if k + 1 < len(word):
                    return word[k + 1:].lower(), j + 1
                return (words[j + 1].lower(), j + 2) if j + 1 < len(words) else None
            if letter == "c":
                return None
            if letter in "WX":
                if k + 1 == len(word):
                    j += 1                     # the value is the next word
                break
        j += 1
    return None


def _lead_end(words, i=0, bare=False, keep=()):
    """(where the program of a stage's words starts, its assignments): past
    the VAR=value words and the wrappers of _LEAD_VALUES with their options.
    The one step every rule that reads a stage's program word takes, so a
    wrapper is peeled in the same way by all of them: sudo -u root and
    sudo --, env -i VAR=x, nice -n 10, ionice -c 3, timeout -k 5 -s INT 60,
    stdbuf -oL. Read a word at a time, as _AfterHandsOn reads what stands
    before a shell, so no reading of the words is ever tried twice. With
    `bare`, assignments that start the stage are left in it (an assignment
    is a command of its own), and only those after a wrapper are skipped.
    The wrappers named in `keep` are left in the stage, where they end the
    peeling: the rules that judge what sudo or env gives a command read them."""
    assigns, n, wrapped = {}, len(words), False
    while i < n:
        word = words[i]
        found = _ASSIGNMENT.match(word)
        if found and bare and not wrapped:
            break
        if found:
            assigns[found.group(1)] = found.group(2)
            i += 1
            continue
        name = _program(word)
        if name not in _LEAD_VALUES or name in keep:
            break
        values, i, wrapped = _LEAD_VALUES[name], i + 1, True
        # env - clears the environment: its one lone dash is an option
        while i < n and words[i][:1] == "-" and (words[i] != "-"
                                                 or name == "env"):
            if words[i] == "--":
                i += 1
                break
            i += 2 if words[i] in values else 1
        if name == "timeout" and i < n:
            i += 1                             # the duration
    return i, assigns


# How many of a stage's first words _peel reads: a stage with more wrappers
# than this is judged by the wrappers it shows, and its cost stays constant.
_MOST_LEAD_WORDS = 48
_LEAD_WORD = re.compile(r"[^\s|;&]+")


def _peel(text, pos=0, end=None, keep=()):
    """Where the program of the stage that starts at text[pos] begins,
    past the wrappers and assignments that _lead_end skips; pos when none
    stands in front of it, or nothing follows them; `keep` as _lead_end
    has it. Reads at most
    _MOST_LEAD_WORDS words, whatever the length of the stage."""
    found = list(itertools.islice(
        _LEAD_WORD.finditer(text, pos, len(text) if end is None else end),
        _MOST_LEAD_WORDS))
    at = _lead_end([m.group() for m in found], 0, True, keep)[0]
    return found[at].start() if 0 < at < len(found) else pos


def _launched(words):
    """(program, args, assignments) of what a stage's words run: past its
    assignments, sudo, env, nohup, nice, time, timeout, command and exec
    with their options (_lead_end), a runner that fetches a package, and
    python -m. program is None when the words run nothing."""
    i, assigns = _lead_end(words)
    n = len(words)
    if i >= n:
        return None, [], assigns
    name = _program(words[i])
    end = _runner_end(name, words, i)
    if end is not None:
        i = end
        while i < n and words[i][:1] == "-":
            if words[i] == "--":
                i += 1
                break
            i += 2 if words[i] in _RUNNER_VALUES else 1
        if i >= n:
            return None, [], assigns
        return _package_program(words[i]), words[i + 1:], assigns
    if name.startswith("python") or name == "py":
        module = _python_module(words, i)
        if module:
            # The package's own modules run ranwhat as `-m ranwhat` does.
            if module[0] in ("ranwhat.cli", "ranwhat.__main__"):
                return "ranwhat", words[module[1]:], assigns
            return module[0], words[module[1]:], assigns
    return name, words[i + 1:], assigns


def _is_ranwhat(word):
    return _program(_VERSION_SPEC.split(word.lower(), 1)[0]) == "ranwhat"


# ranwhat's own long options, as its parser has them (cli._main), those that
# take a value and those that take none, which a test holds to the parser.
_RANWHAT_VALUES = frozenset((
    "--days", "--source", "--path", "--root", "--state-dir", "--ignore",
    "--html", "--sarif", "--fail-on", "--scope", "--mode", "--controls",
    "--window-days", "--seed", "--mine", "--aws-profile", "--aws-key-id",
    "--aws-region", "--github-org", "--token", "--google", "--github",
    "--slack", "--stripe"))
_RANWHAT_FLAGS = frozenset((
    "--help", "--json", "--pull-usage", "--apply", "--no-interactive",
    "--save-token", "--status", "--force", "--no-browser", "--local",
    "--no-ignore"))
_RANWHAT_OPTIONS = tuple(sorted(_RANWHAT_VALUES | _RANWHAT_FLAGS))


def _ranwhat_takes_value(option):
    """Whether a --word given to ranwhat takes the next word as its value:
    an option that does, by its name or by a prefix no other option shares,
    which argparse takes for it. A prefix two share is refused by argparse,
    and then nothing runs."""
    if option in _RANWHAT_VALUES or option in _RANWHAT_FLAGS:
        return option in _RANWHAT_VALUES
    found = [o for o in _RANWHAT_OPTIONS if o.startswith(option)]
    return len(found) == 1 and found[0] in _RANWHAT_VALUES


def _ranwhat_positionals(args):
    """The words ranwhat reads as its command and what follows it, in
    order: past each option and the value it takes, given as the next word
    or after =, and everything after --. One word at a time."""
    found, i, n = [], 0, len(args)
    while i < n:
        word = args[i]
        i += 1
        if word == "--":
            found.extend(args[i:])
            break
        if word[:2] == "--":
            name, equals, _value = word.partition("=")
            if not equals and _ranwhat_takes_value(name):
                i += 1
        elif word[:1] != "-" or word == "-":
            found.append(word)
    return found


def _option_value(args, k, option):
    """The value of option at args[k], given as --option=value or as the
    next word; None when args[k] is not that option."""
    word = args[k]
    if word == option:
        return args[k + 1] if k + 1 < len(args) else ""
    if word.startswith(option + "="):
        return word[len(option) + 1:]
    return None


def _settings_launch(value):
    """What claude --settings switches off, when given settings inline."""
    if "{" not in value:
        return None                            # a file's name: not shown
    parts = [(value, False)]
    if _count(_DISABLE_ALL_HOOKS, parts) or _switched_off(parts):
        return CRITICAL, _GUARD_OFF_WHY
    return (HIGH, _LAUNCH_WHY) if _count(_BYPASS, parts) else None


def _claude_launch(args, hook_off):
    verdict = (CRITICAL, _GUARD_OFF_WHY) if hook_off else None
    for k, word in enumerate(args):
        mode = _option_value(args, k, "--permission-mode")
        settings = _option_value(args, k, "--settings")
        if word == "--dangerously-skip-permissions" or mode == "bypassPermissions":
            verdict = _worse(verdict, (HIGH, _LAUNCH_WHY))
        elif settings is not None:
            verdict = _worse(verdict, _settings_launch(settings))
        elif word == "--allow-dangerously-skip-permissions":
            verdict = _worse(verdict, (MEDIUM, _LAUNCH_WHY))
    return verdict


def _codex_launch(args):
    never = full = False
    for k, word in enumerate(args):
        if word in ("--dangerously-bypass-approvals-and-sandbox", "--yolo"):
            return HIGH, _LAUNCH_WHY
        approval = (_option_value(args, k, "-a")
                    or _option_value(args, k, "--ask-for-approval"))
        sandbox = (_option_value(args, k, "-s")
                   or _option_value(args, k, "--sandbox"))
        setting = (_option_value(args, k, "-c")
                   or _option_value(args, k, "--config") or "")
        key, _sep, value = setting.partition("=")
        value = value.strip().strip("\"'")
        never = never or approval == "never" or (
            key.strip() == "approval_policy" and value == "never")
        full = full or sandbox == "danger-full-access" or (
            key.strip() == "sandbox_mode" and value == "danger-full-access")
    if never and full:
        return HIGH, _LAUNCH_WHY
    return (MEDIUM, _LAUNCH_WHY) if never or full else None


def _gemini_launch(args):
    for k, word in enumerate(args):
        if word in ("--yolo", "-y") or _option_value(
                args, k, "--approval-mode") == "yolo":
            return HIGH, _LAUNCH_WHY
    return None


def _launch_verdict(program, args, assigns, hook_off):
    """(severity, why) of what launching program with args switches off,
    or None. hook_off: RANWHAT_HOOK was set off by an earlier statement."""
    from . import hook
    if program == "ranwhat":
        # argparse prints its usage and exits on -h or --help before any
        # verb runs, and never takes either for an option's value, so
        # `ranwhat hook uninstall --help`, which an agent asked how to
        # remove the hook may well run, removes nothing. After -- it is an
        # operand.
        head = args[:args.index("--")] if "--" in args else args
        if "-h" in head or "--help" in head:
            return None
        # The verb is looked for after "hook", not at a place: ranwhat reads
        # its options anywhere, `ranwhat --scope project hook uninstall` and
        # `ranwhat hook --sc user uninstall` uninstall too, and uninstall
        # takes no option but --scope, whose value is user, project or local.
        rest = args[args.index("hook") + 1:] if "hook" in args else []
        if "uninstall" in rest:
            return CRITICAL, _GUARD_OFF_WHY
        # ranwhat ignore with an action's id, all or - adds to the ignore
        # file; bare, or with only options, it lists the file and changes
        # nothing. Read by place, past the options and their values, so
        # `ranwhat watch --ignore ignore` names a file and adds nothing.
        words = _ranwhat_positionals(args)
        if words[:1] == ["ignore"] and len(words) > 1:
            return CRITICAL, _STATE_WHY
        return None
    if program in ("setx", "launchctl", "systemctl"):
        verdict = None
        for name, value in _switch_kept(program, args):
            if name == "RANWHAT_HOME":
                verdict = _worse(verdict, (CRITICAL, _STATE_WHY))
            elif name == hook.OFF_ENV and hook.is_off(value):
                verdict = _worse(verdict, (CRITICAL, _GUARD_OFF_WHY))
        return verdict
    if program in ("pip", "pip3", "pipx") or (
            program == "uv" and args[:1] in (["pip"], ["tool"])):
        # No exemption for help here: pip's own options take values
        # (`pip --log --help uninstall -y ranwhat` logs to a file named
        # --help, and uninstalls), and -v and --version inside its
        # subcommand print nothing and stop nothing.
        if "uninstall" in args and any(_is_ranwhat(a) for a in args):
            return HIGH, _UNINSTALL_WHY
        return None
    if program not in _AGENTS:
        return None
    if "--" in args:
        args = args[:args.index("--")]
    if any(a in _AGENT_INFO for a in args):
        return None                            # asks for its usage: runs nothing
    if args[:1] == ["mcp"]:
        return (MEDIUM, _AGENT_WHY) if args[1:2] and args[1] in _MCP_ADD else None
    if program == "claude":
        # The hook runs in Claude Code's own environment: RANWHAT_HOOK
        # reaches it only through the claude it is set for.
        own = assigns.get(hook.OFF_ENV)
        return _claude_launch(args, hook.is_off(own) if own is not None else hook_off)
    return _codex_launch(args) if program == "codex" else _gemini_launch(args)


_PS_HOOK_SET = re.compile(r"\$env:RANWHAT_HOOK=(.*)\Z", re.I | re.S)


def _hook_state(words, off):
    """Whether RANWHAT_HOOK is off after a statement that only sets or
    unsets variables (export and its kin, or bare assignments), given
    whether it was off before."""
    from . import hook
    head = words[0] if words else ""
    if head == "unset":
        return False if hook.OFF_ENV in words[1:] else off
    if head[:5].lower() == "$env:":
        # PowerShell takes $env:NAME = "v" with blanks around the = or
        # without, $env:NAME="v" being the usual one-liner, and reads a
        # variable's name in any case: the words are read joined.
        found = _PS_HOOK_SET.match("".join(words))
        return hook.is_off(found.group(1)) if found else off
    items = ([w for w in words[1:] if w[:1] != "-"]
             if head in ("export", "declare", "typeset", "local", "readonly")
             else words)
    if not items or not all(_ASSIGNMENT.match(w) for w in items):
        return off
    for word in items:
        name, value = _ASSIGNMENT.match(word).groups()
        if name == hook.OFF_ENV:
            off = hook.is_off(value)
    return off


class _Change(object):
    """What one call did to one file, as far as the call shows it: text put
    in (new) and taken out (old), each as (text, pattern), pattern when it
    is a sed address or a jq path rather than the file's own text; whether
    the whole file was replaced, or the file removed; and a verdict (blind)
    for a change judged the worst it could be without being shown. Built
    once and never changed after, so its verdicts, one for each kind of
    file it reaches, are kept on it (_judged)."""
    __slots__ = ("new", "old", "whole", "removed", "blind", "verdicts")

    def __init__(self, whole=False, removed=False):
        self.new, self.old, self.blind = [], [], None
        self.whole, self.removed = whole, removed
        self.verdicts = {}

    def add(self, produced):
        new, old, blind = produced
        self.new.extend(new)
        self.old.extend(old)
        self.blind = _worse(self.blind, blind)


# The markers a change is judged by. Each starts with a literal, so each is
# one pass.
_DISABLE_ALL_HOOKS = re.compile(r"""disableAllHooks["']?\s*[:=]\s*true\b""")
# Not after $ or a word character: [ "$RANWHAT_HOOK" = "0" ], a prompt or a
# status line that shows the guard is off, reads the variable and sets
# nothing, and MY_RANWHAT_HOOK is another name. ${RANWHAT_HOOK=0} does set
# it, so { is let through.
_HOOK_SWITCH = re.compile(
    r"""(?<![\w$])RANWHAT_HOOK["']?\s*[:=]\s*["']?([^\s"',;}]*)""")
# fish sets a variable with no = in it: set -gx RANWHAT_HOOK 0.
_FISH_HOOK_SWITCH = re.compile(
    r"""\bset[ \t]+(?:-[A-Za-z-]+[ \t]+)*RANWHAT_HOOK[ \t]+["']?([^\s"';]*)""")
# RANWHAT_HOME set, and the folder it is set to, read as _HOOK_SWITCH reads
# the hook's. Not ${RANWHAT_HOME:-x}, :+ or :?, which read it; ${RANWHAT_HOME:=x}
# sets it. fish's set is read with a value only: `set -q RANWHAT_HOME &&`
# asks whether it is set.
_HOME_SWITCH = re.compile(
    r"""(?<![\w$])RANWHAT_HOME["']?\s*(?:=|:(?![-+?]))\s*["']?([^\s"',;}]*)""")
_FISH_HOME_SWITCH = re.compile(
    r"""\bset[ \t]+(?:-[A-Za-z-]+[ \t]+)*RANWHAT_HOME[ \t]+["']?([^\s"';&|]+)""")
# Case-sensitive: disableBypassPermissionsMode is a guardrail, not a hole.
_BYPASS = re.compile(r"(?<![\w$])bypassPermissions(?!\w)")
_ALL_PROJECT_SERVERS = re.compile(
    r"""enableAllProjectMcpServers["']?\s*[:=]\s*true\b""")
_SKIP_BYPASS_PROMPT = re.compile(
    r"""skipDangerousModePermissionPrompt["']?\s*[:=]\s*true\b""")
_PRE_TOOL_USE = re.compile(r'"PreToolUse"\s*:')
_HOOK_ENTRY = re.compile(r'"type"\s*:\s*"(?:command|http|mcp_tool|prompt|agent)"')
_HOOKS_KEY = re.compile(r'"hooks"\s*:')
_MCP_ENTRY = re.compile(r'"(?:command|url|httpUrl)"\s*:|mcpServers')
_CODEX_NEVER = re.compile(r"""approval_policy["']?\s*=\s*["']?never\b""")
_CODEX_FULL = re.compile(
    r"""sandbox_mode["']?\s*=\s*["']?danger-full-access\b""")
_CODEX_SERVER = re.compile(r"(?m)^[ \t]*\[mcp_servers\.")
_AGENT_WORD = re.compile(r"\b(?:claude|codex|gemini)\b")
_BYPASS_FLAG = re.compile(
    r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox"
    r"|--yolo\b|--permission-mode[=\s]+bypassPermissions"
    r"|--approval-mode[=\s]+yolo")
# A JSON string, read one at a time from where it opens: one never closed
# is the rest of the text, read once.
_JSON_MARK = re.compile(r'["\[\]]')
_JSON_STRING_REST = re.compile(r'(?:[^"\\]|\\[\s\S])*"')
_JSON_AFTER = re.compile(r"\s*(:\s*\[|:)?")


def _json_unquoted(raw):
    """A JSON string's text as read. One with no escape in it reads as it
    is, without the parser: json.loads gives it back, or refuses a control
    character in it, and then it is given back as it is all the same."""
    if "\\" not in raw:
        return raw
    try:
        return json.loads('"%s"' % raw)
    except ValueError:
        return raw


@functools.lru_cache(maxsize=16)
def _json_strings(text):
    """(value, key) of each JSON string in text that is not itself a key.
    key is that of the list it sits in ("allow", "deny"), which a string
    followed by `: [` opens and `]` closes; a list opened with no key is
    its parent's. One outside every list the fragment opens has "?": an
    Edit's fragment may begin inside a list, and not say which. A tuple,
    kept for the next rule that asks of the same text: _ours and
    _permission_rules each read every part of a change."""
    found, stack, pos = [], [], 0
    while True:
        mark = _JSON_MARK.search(text, pos)
        if mark is None:
            return tuple(found)
        if mark.group() == '"':
            rest = _JSON_STRING_REST.match(text, mark.end())
            if rest is None:
                return tuple(found)
            value = _json_unquoted(text[mark.end():rest.end() - 1])
            after = _JSON_AFTER.match(text, rest.end())
            pos = after.end()
            if after.group(1) is None:
                found.append((value, stack[-1] if stack else "?"))
            elif after.group(1).endswith("["):
                stack.append(value)
        elif mark.group() == "[":
            stack.append(stack[-1] if stack else "?")
            pos = mark.end()
        else:
            if stack:
                stack.pop()
            pos = mark.end()


def _count(regex, parts):
    return sum(len(regex.findall(text)) for text, _pattern in parts)


def _guard_entries(text):
    """How many hook entries the PreToolUse lists in text hold, the event
    ranwhat's hook is one of: each list read from the [ its key opens to
    the ] that closes it, or to the end of a fragment that stops inside it.
    A string at a time, as _json_strings reads, so a bracket in a command
    is none, and once: the lists of a settings file do not nest in each
    other."""
    count, pos, depth, opened = 0, 0, 0, None
    while True:
        mark = _JSON_MARK.search(text, pos)
        if mark is None:
            break
        if mark.group() == '"':
            rest = _JSON_STRING_REST.match(text, mark.end())
            if rest is None:
                break
            pos = rest.end()
            if opened is None and text[mark.end():pos - 1] == "PreToolUse":
                after = _JSON_AFTER.match(text, pos)
                if after.group(1) and after.group(1).endswith("["):
                    opened, pos = (after.end(), depth), after.end()
                    depth += 1
        elif mark.group() == "[":
            depth, pos = depth + 1, mark.end()
        else:
            depth, pos = depth - 1, mark.end()
            if opened is not None and depth == opened[1]:
                count += len(_HOOK_ENTRY.findall(text, opened[0], mark.start()))
                opened = None
    if opened is not None:
        count += len(_HOOK_ENTRY.findall(text, opened[0]))
    return count


def _switched_off(parts):
    """How many times parts set RANWHAT_HOOK to a value that turns the
    hook off, as the hook itself reads one."""
    from . import hook
    return sum(1 for text, _pattern in parts
               for switch in (_HOOK_SWITCH, _FISH_HOOK_SWITCH)
               for m in switch.finditer(text) if hook.is_off(m.group(1)))


def _homes_set(parts):
    return collections.Counter(
        m.group(1) for text, _pattern in parts
        for switch in (_HOME_SWITCH, _FISH_HOME_SWITCH) for m in switch.finditer(text))


def _home_moved(change):
    """Whether change sets RANWHAT_HOME to a folder it did not set it to
    before: one put in, or one changed, as an Edit changes it. Every ranwhat
    started where the file is read then keeps its state there, an ignore
    file and the secrets clean was told to keep among it, and that folder
    may be one the agent filled. One taken out only puts the state back in
    ~/.ranwhat."""
    return bool(_homes_set(change.new) - _homes_set(change.old))


# ranwhat named as a word, in a pattern.
_RANWHAT_WORD = re.compile(r"(?<![\w-])ranwhat(?![\w-])", re.I)


def _ours(parts):
    """How many times parts hold the ranwhat hook's command, as install and
    uninstall recognise it. In JSON it is read inside each string, since
    the quote that closes one ends the command too, and in an Edit's
    fragment that holds no whole string (-m ranwhat hook run, cut from
    inside one) as it is.

    A pattern (a sed address, either side of an s command, what grep -v
    leaves out) is a regex the agent wrote, and is never compiled: one that
    names ranwhat as a word takes out the line that holds the hook, wherever
    it is (/ranwhat/d, /-m ranwhat/d, /ranwhat.*run/d), and counts as well
    as the command it may also hold. So the two sides of
    s/ranwhat hook run/ranwhat hook run --mode deny/ balance, and
    s/ranwhat hook run/ranwhat --version/ does not."""
    from . import hook
    found = 0
    for text, pattern in parts:
        if pattern:
            found += len(hook._OURS.findall(text)) + len(_RANWHAT_WORD.findall(text))
            continue
        strings = _json_strings(text)
        if strings:
            found += sum(1 for value, _key in strings if hook._OURS.search(value))
        else:
            found += len(hook._OURS.findall(text))
    return found


def _permission_rules(parts):
    counted = collections.Counter()
    for text, _pattern in parts:
        for value, key in _json_strings(text):
            counted[key, value] += 1
    return counted


def _set(regex, change):
    """Whether change puts in more of what regex finds than it takes out."""
    return _count(regex, change.new) > _count(regex, change.old)


def _blanked(scope, change):
    """Whether a whole settings file was written with nothing in it, as `:
    > f` leaves it: empty, or, in user or managed settings, an empty object.
    The hook's entry and the deny rules go with everything else. A
    project's `{}` is how one starts."""
    if not (change.whole and change.new) or change.old or change.blind:
        return False
    empty = ("", "{}") if scope in ("user", "managed") else ("",)
    return all("".join(text.split()) in empty for text, _pattern in change.new)


def _judge_claude(scope, change):
    """(severity, why) of a change to Claude Code settings, or None."""
    from . import revoke
    new, old = change.new, change.old
    verdict = change.blind
    if (_ours(old) > _ours(new) or _set(_DISABLE_ALL_HOOKS, change)
            or _switched_off(new) > _switched_off(old)):
        verdict = _worse(verdict, (CRITICAL, _GUARD_OFF_WHY))
    # The settings' env reaches every ranwhat Claude Code starts: the
    # plugin's own `uvx ranwhat watch` among them.
    if _home_moved(change):
        verdict = _worse(verdict, (CRITICAL, _STATE_WHY))
    if _set(_BYPASS, change):
        verdict = _worse(verdict, (CRITICAL if scope in ("user", "managed")
                                   else HIGH, _AGENT_WHY))
    before, after = _permission_rules(old), _permission_rules(new)
    for (key, rule), _n in (after - before).items():
        # As revoke judges an allow rule, so watch never flags one revoke
        # would not take back. One whose list the call does not show may
        # be an allow rule as much as a deny one.
        if key == "allow" and revoke._risky_rule(rule):
            verdict = _worse(verdict, (HIGH, _AGENT_WHY))
        elif key == "?" and "(" in rule and revoke._risky_rule(rule):
            verdict = _worse(verdict, (MEDIUM, _AGENT_WHY))
    if any(key in ("deny", "ask") for key, _rule in before - after):
        verdict = _worse(verdict, (HIGH, _AGENT_WHY))
    if _set(_ALL_PROJECT_SERVERS, change):
        verdict = _worse(verdict, (HIGH, _AGENT_WHY))
    # High when a PreToolUse hook, ranwhat's kind, is taken out, or the
    # event itself. Any other change to the hooks, or to the statusLine,
    # a command Claude Code runs on its own as it runs a hook, is medium:
    # an Edit often shows the whole hooks object to be unique, and a
    # formatter or a Stop hook taken out of it is no guard gone.
    pre_new, pre_old = _count(_PRE_TOOL_USE, new), _count(_PRE_TOOL_USE, old)
    guards_new = sum(_guard_entries(text) for text, _pattern in new)
    guards_old = sum(_guard_entries(text) for text, _pattern in old)
    entries_new, entries_old = _count(_HOOK_ENTRY, new), _count(_HOOK_ENTRY, old)
    if pre_old > pre_new or (pre_old and guards_old > guards_new):
        verdict = _worse(verdict, (HIGH, _AGENT_WHY))
    elif (pre_new, entries_new, _count(_HOOKS_KEY, new)) != (
            pre_old, entries_old, _count(_HOOKS_KEY, old)):
        verdict = _worse(verdict, (MEDIUM, _AGENT_WHY))
    if _set(_SKIP_BYPASS_PROMPT, change):
        verdict = _worse(verdict, (MEDIUM, _AGENT_WHY))
    if change.removed or _blanked(scope, change):
        verdict = _worse(verdict, (HIGH, _AGENT_WHY))
    if verdict is None and change.whole and scope in ("user", "managed"):
        # What the file held before is not shown: the ranwhat hook may be
        # gone from it. Recorded, since nothing in the call says it is.
        verdict = MEDIUM, _AGENT_WHY
    return verdict


def _judge_config(kind, change):
    """(severity, why) of change to an agent's configuration of kind
    (kind, scope), as _config_kind gives it, or None."""
    kind, scope = kind
    if kind == "claude":
        return _judge_claude(scope, change)
    if kind == "codex":
        never, full = _set(_CODEX_NEVER, change), _set(_CODEX_FULL, change)
        if never and full:
            return (CRITICAL if scope == "user" else HIGH), _AGENT_WHY
        if never or full or _set(_CODEX_SERVER, change):
            return MEDIUM, _AGENT_WHY
        return None
    if kind in ("mcp", "gemini"):
        if _set(_MCP_ENTRY, change) or (kind == "gemini" and (
                _set(_HOOKS_KEY, change) or _set(_HOOK_ENTRY, change))):
            return MEDIUM, _AGENT_WHY
        return None
    if kind == "ranwhat":
        # ranwhat's own state: its ignore file, the secrets clean was told
        # to keep, the key they are kept under, or its folder. Any change an
        # agent makes to one may leave something out of every later report,
        # an append or an edit as much as a copy or a link put in its place:
        # taking `until=` off a line widens it. Only the whole file or
        # folder taken out, or emptied, is let go: then ranwhat leaves out
        # less, never more.
        if change.removed and not change.new and change.blind is None:
            return None
        return CRITICAL, _STATE_WHY
    # A shell's startup file: only what turns the hook off, moves ranwhat's
    # state, or makes an agent start with its approvals off every time it
    # is typed.
    if _switched_off(change.new) > _switched_off(change.old):
        return CRITICAL, _GUARD_OFF_WHY
    if _home_moved(change):
        return CRITICAL, _STATE_WHY
    flagged = [sum(1 for text, _p in parts for line in text.split("\n")
                   if _BYPASS_FLAG.search(line) and _AGENT_WORD.search(line))
               for parts in (change.new, change.old)]
    return (HIGH, _AGENT_WHY) if flagged[0] > flagged[1] else None


def _judged(kind, change):
    """_judge_config(kind, change), once for each kind of file a change
    reaches. One text written to many files (tee f f f, a redirect for each,
    a cp of one source again and again) was judged again for each, at the
    cost of the text each time: a 60KB command took 17 seconds, past the
    ten Claude Code gives the hook before it goes on without it."""
    if kind not in change.verdicts:
        change.verdicts[kind] = _judge_config(kind, change)
    return change.verdicts[kind]


_CLAUDE_DIRS = frozenset(("$claude_config_dir", "${claude_config_dir}"))
_CODEX_DIRS = frozenset(("$codex_home", "${codex_home}"))
_GEMINI_SYSTEM_DIRS = frozenset(("gemini-cli", "geminicli"))
# A shell's startup files by name, for a path that begins with what the
# shell expands and ranwhat cannot: $ZDOTDIR/.zshrc, ${ZDOTDIR:-$HOME}/.zshrc,
# the way install scripts spell zsh's.
_RC_FILES = frozenset((".bashrc", ".bash_profile", ".bash_login", ".profile",
                       ".bash_aliases", ".zshrc", ".zprofile", ".zshenv",
                       ".zlogin"))
_HOME_WORDS = frozenset(("~", "$home", "${home}", "%userprofile%",
                         "$env:userprofile", "$env:home"))
# C:/Users/<name>, and Git Bash's /c/Users/<name> (see _OTHER_HOME).
_A_HOME = re.compile(r"(?:[a-z]:|/[a-z])?/(?:home|users)/[^/]+\Z|/(?:var/)?root\Z")


def _is_home(folder):
    """Whether folder is a home directory, however it is spelled."""
    low = folder.lower()
    if low in _HOME_WORDS or _A_HOME.match(low):
        return True
    home = _posix_home()
    return _same_folder(folder, posixpath.normpath("/" + home.lstrip("/")))


def _user_settings_folder(folder):
    """Whether folder is where this machine's Claude Code keeps its user
    settings, CLAUDE_CONFIG_DIR's when that is set."""
    from . import hook
    settings = _undriven(hook.settings_path("user").replace("\\", "/"))
    return _same_folder(folder, posixpath.dirname(settings))


def _same_folder(folder, path):
    """Whether folder, as a write names it, is path, an absolute path with
    no drive. Read as persist reads a path (_persist_place), its drive taken
    off and ~ put in from _posix_home: left to _as_absolute as it was, a
    Windows path (C:/Users/me/claude-work, the CLAUDE_CONFIG_DIR that
    `ranwhat hook install` wrote to) was no path at all, and a home not
    spelled X:/Users/<name> no home. In any case under a Windows home,
    since Windows' file names are."""
    found = _as_absolute(_undriven(_slashed(folder)), _posix_home())
    if found is None:
        return False
    if not _home().startswith("/"):
        return found.lower() == path.lower()
    return found == path


def _starts_shells(path, t, name):
    """Whether a file sets up every shell, or every session, that starts:
    a startup file where a shell reads it (persist's _persist_place: in a
    home directory or /etc, /etc/profile.d, fish's conf.d, PowerShell's
    profile), one named under an expansion ranwhat cannot resolve, the
    environment a login is given (/etc/environment, environment.d), or an
    .envrc, which direnv loads wherever it is. A project's .devcontainer/.zshrc
    or docker/.bashrc is none: a container's shell reads it, and an agent
    run there with its approvals off is the set-up such images are for."""
    if name == ".envrc" or (name in _RC_FILES and t[:1] == "$"):
        return True
    if _persist_place(path) == "startup":
        return True
    absolute = _as_absolute(t, _posix_home())
    if absolute is None:
        return False
    rel = _home_relative(absolute) or ""
    return absolute == "/etc/environment" or (
        rel.startswith(".config/environment.d/") and rel.endswith(".conf"))


def _flat(path):
    """path with the // and the . and .. parts a shell or a file system
    takes out taken out, as a file tool opens it: ~/.ranwhat/./ignore and
    ~/.ranwhat/x/../ignore are the ignore file. Only when there is one, so
    a path with a variable in it is otherwise left as written."""
    if "//" not in path and "/." not in path:
        return path
    flat = posixpath.normpath(path)
    if flat.startswith("//"):
        flat = flat[1:]
    return path if flat == "." else flat


def _config_kind(path):
    """(kind, scope) of an agent's configuration file, or None. kind is
    claude, codex, gemini, mcp (a file of MCP servers) or rc (a shell's
    startup file, read only for the agents it starts: see _starts_shells).
    Named by its file and the folder it sits in, so .claude/worktrees/,
    .claude/agents/ and a settings.json under tests/fixtures/ are none. A
    path relative to an unknown directory is a project's."""
    t = _flat(_slashed(path.strip()).replace('"', "").replace("'", ""))
    folder, _sep, name = t.rstrip("/").rpartition("/")
    holder, _sep, parent = folder.rpartition("/")
    low_parent = parent.lower()
    if name in ("settings.json", "settings.local.json"):
        if parent == ".claude":
            if _is_home(holder):
                return "claude", "user"
            return "claude", "local" if name == "settings.local.json" else "project"
        if name == "settings.json" and (low_parent in _CLAUDE_DIRS
                                        or _user_settings_folder(folder)):
            return "claude", "user"
        if parent == ".gemini":
            return "gemini", "user" if _is_home(holder) else "project"
        if low_parent in _GEMINI_SYSTEM_DIRS:
            return "gemini", "system"
    if name == "managed-settings.json" or (
            parent == "managed-settings.d" and name.endswith(".json")):
        return "claude", "managed"
    if name == ".mcp.json":
        return "mcp", "project"
    if name == ".claude.json":
        return "mcp", "user"
    if name == "managed-mcp.json":
        return "mcp", "managed"
    if parent == ".codex" or low_parent in _CODEX_DIRS:
        if name == "config.toml":
            home = low_parent in _CODEX_DIRS or _is_home(holder)
            return "codex", "user" if home else "project"
        if name.endswith(".config.toml"):
            return "codex", "profile"
    # ranwhat's own: an ignore file, the one in its folder or one a
    # repository keeps, which is read only when named but may be named in
    # CI; and the secrets clean was told to keep, with the key that makes
    # an entry in that file, beside the index in known/.
    # (the base name compared in lower case: macOS and Windows keep their
    # file names case-insensitively, so .RANWHATIGNORE is the same file)
    low = name.lower()
    if low == ".ranwhatignore" or (
            low == "ignore" and _ranwhat_home_folder(folder)):
        return "ranwhat", "ignore"
    if low in ("kept.json", "key") and low_parent == "known" \
            and _ranwhat_home_folder(holder):
        return "ranwhat", "state"
    if _starts_shells(path, t, name):
        return "rc", "user"
    return None


# ranwhat's state folder as a path names it under a variable ranwhat cannot
# resolve: POSIX shells, cmd and PowerShell.
_RANWHAT_DIRS = frozenset(("$ranwhat_home", "${ranwhat_home}", "%ranwhat_home%",
                           "$env:ranwhat_home"))


def _ranwhat_home_folder(folder):
    """Whether folder is ranwhat's state folder: one named .ranwhat, where
    ranwhat keeps it in any home, one named by RANWHAT_HOME, or the one
    RANWHAT_HOME names on this machine, wherever that is. The last is read
    only when a call names a file by a path; the shell's words reach this
    rule only when they name ranwhat (_may_loosen)."""
    name = folder.rstrip("/").rpartition("/")[2].lower()
    if name == ".ranwhat" or name in _RANWHAT_DIRS:
        return True
    if not folder:
        return False
    from . import known
    state = _undriven(os.path.abspath(known.home()).replace("\\", "/"))
    return _same_folder(folder, posixpath.normpath("/" + state.lstrip("/")))


def _config_folder_kind(path):
    """(kind, scope) of a folder that holds an agent's configuration
    (.claude, .codex, .gemini, CLAUDE_CONFIG_DIR, CODEX_HOME), or ranwhat's
    own state (_ranwhat_home_folder, and the known/ in it), named with or
    without a trailing / or /*, or None."""
    t = _slashed(path.strip()).replace('"', "").replace("'", "")
    if t.endswith("/*"):
        t = t[:-2]
    t = _flat(t)
    holder, _sep, name = t.rstrip("/").rpartition("/")
    low = name.lower()
    if name == ".claude" or low in _CLAUDE_DIRS:
        return "claude", "user" if low in _CLAUDE_DIRS or _is_home(holder) else "project"
    if name == ".codex" or low in _CODEX_DIRS:
        return "codex", "user"
    if name == ".gemini":
        return "gemini", "user"
    if _ranwhat_home_folder(t) or (low == "known" and _ranwhat_home_folder(holder)):
        return "ranwhat", "home"
    return None


# jq and yq: what a program sets, what it takes out, and what it removes
# without saying what was there. A token at a time, each begun by a
# character of its own, so the program is read once.
_JQ_TOKEN = re.compile(
    r'"(?:[^"\\]|\\[\s\S])*"?|//=|[|+\-*/%]=|[=!<>]=|[()\[\]{}|=,]')
_JQ_KEY = re.compile(r'\.([A-Za-z_][\w-]*)|\[\s*"([^"]*)"\s*\]')
# del, then the blanks before the ( it opens, in what a ( is preceded by.
_JQ_DEL = re.compile(r"(?<![\w$.])del[ \t]*\Z")
_JQ_LISTS = frozenset(("allow", "deny", "ask"))
_JQ_EMPTY = frozenset(("{}", "[]", "null", ""))
_JQ_FILTERS = re.compile(r"\b(?:select|del|map_values|map|to_entries)\s*\(")
_JQ_TWO_VALUES = frozenset(("--arg", "--argjson", "--slurpfile", "--rawfile"))
_JQ_ONE_VALUE = frozenset(("--indent", "-L", "-o", "--output-format", "-p",
                           "--input-format", "-I"))


def _jq_keys(path):
    return [m.group(1) or m.group(2) for m in _JQ_KEY.finditer(path)]


def _jq_program(args):
    """The program a jq or yq stage is given, or None when it reads one
    from a file."""
    i = 0
    while i < len(args):
        word = args[i]
        if word in ("-f", "--from-file"):
            return None
        if word in _JQ_TWO_VALUES:
            i += 3
        elif word in _JQ_ONE_VALUE:
            i += 2
        elif word[:1] == "-" and len(word) > 1:
            i += 1
        elif word in ("e", "eval", "ea", "eval-all"):
            i += 1                             # yq's subcommand
        else:
            return word
    return None


def _jq_hooks_gone(keys):
    """What taking out, or emptying, the hooks at keys (a path through
    "hooks" or "PreToolUse") does. ranwhat's hook is a PreToolUse one: the
    guard may go with the hooks themselves, with PreToolUse, or with an
    event the path does not name (.hooks[$e], .hooks."PreToolUse"); the
    hooks of any other event are a hook changed. The first "hooks" is the
    object's own, so .hooks.Stop[0].hooks names Stop."""
    if "PreToolUse" in keys or not keys[keys.index("hooks") + 1:]:
        return CRITICAL, _GUARD_OFF_WHY
    return MEDIUM, _AGENT_WHY


def _jq_changes(program):
    """(new, old, blind) of a jq or yq program. Each assignment is read as
    the key it sets and the value it is given ("defaultMode":
    "bypassPermissions"; "allow": [...], a list's own key kept), -= as a
    value taken out; a clause that assigns nothing is shown as it is, so an
    object merged in (. + {...}) is judged by what it holds. del() of the
    hooks, or the hooks set empty or filtered, is judged the worst it could
    be for the event it names (_jq_hooks_gone). The deny or ask rules taken
    out by del(), set empty or filtered, or every permission taken out by
    del() or set empty, are a deny or ask rule taken out: what was there is
    not shown, and may have been the rule that stopped the agent."""
    new, old, blind = [], [], None
    clauses, deletes, opened = [], [], []
    depth, start, assign, deleting = 0, 0, None, 0
    for m in _JQ_TOKEN.finditer(program):
        token = m.group()
        if token[0] == '"':
            continue
        if token in "([{":
            depth += 1
            is_del = token == "(" and _JQ_DEL.search(
                program, max(0, m.start() - 16), m.start()) is not None
            # Only the outermost del() is read: one inside it is in its text.
            opened.append((m.end(), is_del, is_del and not deleting))
            deleting += is_del
        elif token in ")]}":
            depth = max(0, depth - 1)
            if opened:
                body, is_del, outermost = opened.pop()
                deleting -= is_del
                if outermost:
                    deletes.extend(program[body:m.start()].split(","))
        elif depth == 0 and token == "|":
            clauses.append((start, m.start(), assign))
            start, assign = m.end(), None
        elif depth == 0 and assign is None and token.endswith("=") \
                and token not in ("==", "!=", "<=", ">="):
            assign = (m.start(), m.end(), token)
    clauses.append((start, len(program), assign))
    for lo, hi, assign in clauses:
        if assign is None:
            new.append((program[lo:hi], False))
            continue
        keys = _jq_keys(program[lo:assign[0]])
        key = keys[-1] if keys else ""
        value = program[assign[1]:hi].strip()
        emptied = assign[2] in ("=", "|=") and value in _JQ_EMPTY
        if "hooks" in keys or "PreToolUse" in keys:
            if emptied or _JQ_FILTERS.search(value):
                blind = _worse(blind, _jq_hooks_gone(keys))
        elif (key in ("deny", "ask") and (emptied or _JQ_FILTERS.search(value))) \
                or (key == "permissions" and emptied):
            blind = _worse(blind, (HIGH, _AGENT_WHY))
        shown = ('"%s": [%s]' if key in _JQ_LISTS else '"%s": %s') % (key, value)
        (old if assign[2] == "-=" else new).append((shown, False))
    for path in deletes:
        keys = _jq_keys(path)
        if "hooks" in keys or "PreToolUse" in keys:
            blind = _worse(blind, _jq_hooks_gone(keys))
        elif keys[-1:] in (["deny"], ["ask"], ["permissions"]):
            blind = _worse(blind, (HIGH, _AGENT_WHY))
    return new, old, blind


@functools.lru_cache(maxsize=64)
def _sed_part(delimiter):
    """What runs up to the next delimiter of a sed command that is not
    escaped."""
    return re.compile(r"(?:[^\\%s]|\\[\s\S])*" % re.escape(delimiter))


def _sed_changes(script):
    """(old, new) of a sed or perl script, each a list of patterns: what an
    s command matches and what it puts in its place, what an address
    deletes (d) or changes (c), and what a, i and c add. One pass over the
    script, a command at a time."""
    old, new, addresses, i, n = [], [], [], 0, len(script)
    while i < n:
        c = script[i]
        if c in ";\n}":
            addresses, i = [], i + 1
        elif c in " \t{!,$+~0123456789":
            i += 1
        elif c == "/" or (c == "\\" and i + 1 < n):
            delimiter = "/" if c == "/" else script[i + 1]
            body = i + 1 if c == "/" else i + 2
            stop = _sed_part(delimiter).match(script, body).end()
            addresses.append(script[body:stop])
            i = stop + 1
        elif c in "sy" and i + 1 < n:
            delimiter = script[i + 1]
            first = _sed_part(delimiter).match(script, i + 2).end()
            second = _sed_part(delimiter).match(script, min(first + 1, n)).end()
            if c == "s":
                old.append(script[i + 2:first])
                new.append(script[first + 1:second])
            i, addresses = second + 1, []
            while i < n and script[i] not in ";\n}":
                i += 1                         # the flags
        elif c == "d":
            old.extend(addresses)
            addresses, i = [], i + 1
        elif c in "aic":
            stop = script.find("\n", i + 1)
            stop = n if stop < 0 else stop
            text = script[i + 1:stop].lstrip()
            if text.startswith("\\"):
                text = text[1:].lstrip(" \t")
                if not text and stop < n:     # a\ and the text on the next line
                    after = script.find("\n", stop + 1)
                    text = script[stop + 1:n if after < 0 else after]
                    stop = n if after < 0 else after
            new.append(text)
            if c == "c":
                old.extend(addresses)
            addresses, i = [], stop + 1
        else:
            i += 1
    return old, new


_GREPS = frozenset(("grep", "egrep", "fgrep"))
# grep's options that take the next word as their value.
_GREP_VALUES = frozenset(("-e", "-f", "-m", "-A", "-B", "-C", "-d", "-D",
                          "--regexp", "--file", "--max-count", "--context",
                          "--after-context", "--before-context"))


def _inverted_pattern(args):
    """The pattern grep -v leaves the lines of out, or None when it is not
    told to: given by -e, or as its first operand."""
    inverted, pattern, operands, skip = False, None, [], None
    for word in args:
        if skip is not None:
            if skip in ("-e", "--regexp") and pattern is None:
                pattern = word
            skip = None
        elif word in ("-v", "--invert-match"):
            inverted = True
        elif word.startswith("--regexp="):
            pattern = pattern if pattern is not None else word[9:]
        elif word in _GREP_VALUES:
            skip = word
        elif word[:1] == "-" and word[1:2] != "-" and len(word) > 1:
            for k, letter in enumerate(word[1:], 1):
                if letter == "v":
                    inverted = True
                elif "-" + letter in _GREP_VALUES:
                    if letter == "e" and pattern is None:
                        pattern = word[k + 1:] or None
                    if k + 1 == len(word):
                        skip = "-" + letter
                    break                      # the rest is its value
        elif word[:2] != "--":
            operands.append(word)
    if not inverted:
        return None
    return pattern if pattern is not None else (operands[:1] or [None])[0]


def _produced(name, words, stage):
    """(new, old, blind) of what a stage puts out: what an echo or printf
    prints, a here-string's word, and what a jq or yq program sets and
    takes out. Anything else shows nothing of what it writes."""
    new, old, blind = [], [], None
    if name in _PRINTERS:
        new.append((_printed(stage), False))
    elif name in ("jq", "yq") and words:
        program = _jq_program(words[1:])
        if program:
            new, old, blind = _jq_changes(program)
    elif name in _GREPS and words:
        # grep -v PAT f > tmp && mv tmp f is sed -i '/PAT/d' f.
        left_out = _inverted_pattern(words[1:])
        if left_out is not None:
            old.append((left_out, True))
    here = _here_string_word(stage)
    if here:
        new.append((here, False))
    literal = _quoted_literal(stage)
    if literal:
        new.append((literal, False))
    return new, old, blind


def _file_key(target):
    return _as_absolute(target, _posix_home()) or target


# How many of the stages piped into a stage are read for what it writes.
# A pipeline of writers is read once this way, however long it is.
_PIPED_READ = 4


def _change_of(wrote, name, produced, piped, here, files):
    """The _Change one write of a stage makes: what the stage and those
    piped into it put out, its here-documents, a sed's scripts, a yq's
    program; for a copy, what this call wrote to the source."""
    how = wrote.how
    if how in (">", ">>", "tee", "tee -a"):
        change = _Change(whole=how in (">", "tee"))
        for earlier in piped[-_PIPED_READ:]:
            change.add(earlier)
        change.add(produced)
        change.new.extend((body, False) for body in here)
        if how == ">" and name in ("", ":", "true") and not here \
                and not piped and not produced[0]:
            change.removed = True              # `: > f` empties it
    elif how == "sed":
        change = _Change()
        for script in wrote.detail:
            removed, added = _sed_changes(script)
            change.old.extend((p, True) for p in removed)
            change.new.extend((p, True) for p in added)
    elif how == "edit":
        change = _Change()
        change.add(_jq_changes(wrote.detail))
    elif how in ("copy", "move", "link"):
        sources = wrote.detail or ()
        if list(sources) == ["/dev/null"]:
            return _Change(removed=True)       # cp /dev/null f empties it
        change = (files.get(_file_key(sources[0])) if len(sources) == 1
                  else None) or _Change(whole=True)
    elif how == "remove":
        change = _Change(removed=True)
    else:
        change = _Change(whole=True)
        if wrote.detail:
            change.new.append((wrote.detail, False))
        elif how == "write":
            # A PowerShell writer given no value writes what it is piped.
            for earlier in piped[-_PIPED_READ:]:
                change.add(earlier)
    return change


_Loosened = collections.namedtuple("_Loosened", "start end severity why")


@functools.lru_cache(maxsize=32)
def _loosened(text, bodies=(), depth=0):
    """_Loosened(start, end, severity, why) for each stage of a write view
    that loosens what an agent may do, in order. bodies are the view's
    here-documents (_WriteView.bodies): what the stage at their place
    writes.

    Linear: a stage is split into words only when its program is one this
    rule reads, the files it writes are found as persist finds them, and
    each distinct change is built once and judged once for each kind of
    file it reaches, however many files it is written to."""
    if not text or depth > 3 or not _may_loosen(text):
        return ()
    found, files, piped, hook_off = [], {}, [], False
    positions = [pos for pos, _body in bodies]
    for start, end, op in _command_spans(text):
        at = _SPACES.match(text, start, end).end()
        stage = _normalised(_unwrap_c(_uncommented(text[at:end])))
        produced = ([], [], None)
        if stage:
            here = [body for _pos, body in bodies[
                bisect.bisect_left(positions, at):bisect.bisect_right(positions, end)]]
            name = _writer_name(_command_word(stage))
            verdict, produced = _loosened_stage(stage, name, here, piped, files,
                                                hook_off, depth)
            if name == "cat" and here and op == "|":
                # cat <<'EOF' | sudo tee f, the way a root-owned file is
                # written: what cat is given is what tee writes. A python
                # or sed given a here-document puts out something else.
                produced = (produced[0] + [(body, False) for body in here],
                            produced[1], produced[2])
            # In any case: PowerShell's $env:ranwhat_hook is the same name.
            if "RANWHAT_HOOK" in stage.upper():
                hook_off = _hook_state(_argv(stage) or stage.split(), hook_off)
            if verdict:
                found.append(_Loosened(at, end, verdict[0], verdict[1]))
        if op == "|":
            piped.append(produced)
        else:
            piped = []
    return tuple(found)


def _loosened_stage(stage, name, here, piped, files, hook_off, depth):
    """(verdict, what the stage puts out) of one stage: see _loosened."""
    from . import hook
    verdict = None
    if "SETENVIRONMENTVARIABLE" in stage.upper():
        for found in _SET_ENVIRONMENT.finditer(stage):
            if found.group(2).upper() == "RANWHAT_HOME":
                verdict = _worse(verdict, (CRITICAL, _STATE_WHY))
            elif hook.is_off(found.group(4) if found.group(3) else found.group(5)):
                verdict = _worse(verdict, (CRITICAL, _GUARD_OFF_WHY))
    # A stage that starts with one of _LEAD_VALUES's wrappers (caffeinate,
    # stdbuf, timeout with options) is read past it to what it runs:
    # _command_word only reads past sudo, env and their kin. So is one whose
    # command word is an option, which no program's name is: what is left
    # when _command_word read a wrapper's options wrong (`sudo -- claude`,
    # `nice --adjustment=5 claude`), and _launched reads them right.
    if (name in _AGENT_HEADS or name in _LEAD_VALUES or name[:1] == "-"
            or name.startswith("python") or name in _SHELL_STRING_HEADS):
        program, args, assigns = _launched(_argv(stage) or stage.split())
        operand = _shell_string(program, [program] + args) if program else None
        if operand and depth < 3:
            view = _write_view(operand)
            top = _worst(_loosened(view, view.bodies, depth + 1))
            verdict = _worse(verdict, top and (top.severity, top.why))
        elif program:
            verdict = _worse(verdict, _launch_verdict(program, args, assigns,
                                                      hook_off))
    # A substitution runs before the stage it is in, whatever that stage
    # launches: in caffeinate -i git commit -m "$(claude -p x
    # --dangerously-skip-permissions)" the agent starts as it would bare,
    # and python3 x.py "$(ranwhat hook uninstall)" takes the hook out.
    if depth < 3 and ("$(" in stage or "`" in stage):
        top = _worst([f for lo, hi in _substitution_spans(stage)
                      for f in _loosened(stage[lo:hi], (), depth + 1)])
        verdict = _worse(verdict, top and (top.severity, top.why))
    stage = _as_written(name, stage)
    words = (_stage_words(stage) if name in _WRITERS or name in ("jq", "yq")
             or name in _GREPS else None)
    args = _without_redirects(words[1:])[0] if words else None
    produced = _produced(name, words, stage)
    moved, built = None, {}
    for wrote in _stage_writes(name, args if name in _WRITERS else None, stage):
        # What a stage writes does not depend on where: every target of one
        # way of writing (a redirect, tee, a sed's scripts, a copy's
        # sources) is given the one change, built once.
        key = (wrote.how, id(wrote.detail))
        change = built.get(key)
        if change is None:
            change = built[key] = _change_of(wrote, name, produced, piped, here,
                                              files)
        files[_file_key(wrote.target)] = change
        kind = _config_kind(wrote.target)
        if kind is None:
            # A folder is judged when it is removed, and ranwhat's own when
            # anything is put there: cp -r, mv or ln -s onto ~/.ranwhat puts
            # in place an ignore file, or kept secrets, no call shows.
            folder = _config_folder_kind(wrote.target)
            if folder and (wrote.how == "remove" or folder[0] == "ranwhat"):
                kind = folder
        if kind:
            verdict = _worse(verdict, _judged(kind, change))
        if wrote.how == "move" and moved is None:
            # A file moved away is gone from where it was.
            moved = wrote.detail
            for source in moved:
                gone = _config_kind(source)
                if gone:
                    verdict = _worse(verdict, _judge_config(gone, _Change(removed=True)))
    return verdict, produced


def _agent_unguarded(text):
    """Span of the stage whose loosening is the worst, the first of equals."""
    top = _worst(_loosened(text, getattr(text, "bodies", ())))
    return (top.start, top.end) if top else None


def _refine_agent_shell(text, severity, tool_input=None):
    """What that stage switches off, and why it matters."""
    top = _worst(_loosened(text, getattr(text, "bodies", ())))
    return (top.severity, top.why) if top else None


def _agent_config_path(text):
    """Span of the first path a file tool wrote that is an agent's
    configuration, or None."""
    pos = 0
    for line in text.split("\n"):
        if line and _config_kind(line):
            return pos, pos + len(line)
        pos += len(line) + 1
    return None


def _refine_agent_config(text, severity, tool_input=None):
    """The worst of what the call puts in and takes out of each agent
    configuration file it writes, read from its input; None when it
    loosens nothing. The input is read once, whatever the paths: what its
    content and edits put in, the same for each, is judged once for each
    kind of file, and a patch's sections once for each file they name.
    Read again for each path, 256 paths written with one 64KB content took
    17 seconds. Run only after _agent_config_path found one of the paths,
    so at least one is an agent's configuration."""
    kinds = {}
    for line in text.split("\n"):
        kind = _config_kind(line) if line else None
        if kind:
            kinds.setdefault(line, kind)
    common, sections = _written_parts(tool_input)
    for section in sections:
        if section.header is None:
            _add_section(common, section)
    headers = _Headers([s for s in sections if s.header is not None])
    verdict = None
    for path, kind in kinds.items():
        verdict = _worse(verdict, _judged(kind, common))
        for change in headers.changes_of(path):
            verdict = _worse(verdict, _judged(kind, change))
    return verdict


REFINERS = {"fs.destructive": _refine_deletion,
            "cred.read": _refine_credential,
            "perm.open": _refine_permissions,
            "persist": _refine_persistence,
            "agent.config": _refine_agent_shell}
PATH_REFINERS = {"cred.read": _refine_read_path}
# For the paths a file tool wrote (Rule.writes).
WRITE_REFINERS = {"persist": _refine_persist_written,
                  "agent.config": _refine_agent_config}


RULES = [
    Rule("cred.read", CRITICAL,
         "Credential material accessed",
         "The agent read a file whose only purpose is to hold secrets. Whatever "
         "it read is now in a model context you do not control.",
         [r"(?:^|[\s\"'=/])\.env(?:\.[\w-]+)?\b",
          r"\.aws/credentials", r"\.ssh/id_[\w]+", r"\.netrc",
          r"\.config/gcloud", _Gap(r"service[-_]account", r"\.json", "\n"),
          r"security\s+find-generic-password", r"\.kube/config",
          # ranwhat's own: its account token, and the key kept secrets are
          # hashed under (see _CRED_PATH).
          # (a doubled / or a ./ in the path is the same file)
          r"\.ranwhat/+(?:known/+(?:\./)?key|token)\b",
          r"RANWHAT_HOME[}%]?/+(?:known/+(?:\./)?key|token)\b"],
         paths=True, hide=_credential_text),

    # clean's own rules decide what is a credential, fixtures and
    # placeholders included, so watch never flags a value clean ignores or
    # misses a shape clean knows. A second copy of the list had drifted: it
    # missed OpenAI, Anthropic and AWS secret keys and JWTs, and flagged
    # values clean had already ruled out.
    Rule("secret.literal", CRITICAL,
         "Secret-shaped string in a tool call",
         "A credential-shaped value appeared verbatim in a tool call. If it is "
         "real, rotate it: even if the call was benign, the value is now in the "
         "transcript and in a model context you do not control.",
         scan_raw=True, find=_first_secret),

    Rule("git.destructive", HIGH,
         "Destructive git operation",
         "History rewriting or branch deletion. This is the class of action "
         "that destroys the record of what else happened.",
         [_Gap(r"git\s+push\b", r"--force(?!-with-lease)"),
          _Gap(r"git\s+push\b", r"\s-f\b"),
          r"git\s+reset\s+--hard",
          r"git\s+branch\s+-D\b",
          r"git\s+clean\s+-[a-z]*f",
          r"git\s+filter-branch", r"git\s+remote\s+remove"]),

    Rule("publish", CRITICAL,
         "Package or release published",
         "Something was pushed to a registry other people may install from. "
         "Supply-chain reach, and usually irreversible.",
         [r"npm\s+publish", r"yarn\s+publish", r"pnpm\s+publish",
          r"twine\s+upload", r"cargo\s+publish", r"gem\s+push",
          r"gh\s+release\s+create", r"docker\s+push"]),

    Rule("fs.destructive", HIGH,
         "Bulk or recursive deletion",
         "Recursive deletion. Recoverable only if something else was backing "
         "it up.",
         [_FIND_DELETE,
          r"git\s+rm\s+-r", r"shred\s+", r"truncate\s+-s\s*0"],
         find=_rm_recursive_force),

    Rule("cloud.destructive", CRITICAL,
         "Cloud resource destroyed or modified",
         "A write or delete against cloud infrastructure. What it touched "
         "depends on the account its credentials belong to.",
         [r"aws\s+[\w-]+\s+delete-[\w-]+", r"aws\s+[\w-]+\s+terminate-[\w-]+",
          r"aws\s+s3\s+rm\b", r"aws\s+s3\s+rb\b",
          r"aws\s+iam\s+(?:put|attach|create)-[\w-]+",
          r"kubectl\s+delete", r"gcloud\s+[\w-]+\s+delete",
          r"terraform\s+(?:destroy|apply\s+-auto-approve)",
          r"drop\s+(?:table|database)\s"]),

    Rule("money", CRITICAL,
         "Financial API called",
         "A call against a payments API. With a live key, calls like this "
         "move real money.",
         [r"api\.stripe\.com/v1/(?:charges|refunds|transfers|payouts)",
          r"api\.paypal\.com", r"\bstripe\s+(?:charges|refunds|payouts)\s+create"]),

    Rule("audit.tamper", CRITICAL,
         "Log or history tampering",
         "An action whose effect is to remove the record of other actions.",
         [r"history\s+-c", r">\s*~?/?\.(?:bash|zsh)_history",
          _Gap(r"rm\s+", r"\.(?:bash|zsh)_history"),
          r"aws\s+cloudtrail\s+(?:delete|stop)-",
          _Gap(r"rm\s+-rf?\s+", r"\.git\b")]),

    Rule("exfil.shape", HIGH,
         "Local file piped to the network",
         "File contents sent outbound in a single command. This is the shape of "
         "exfiltration whether or not that was the intent.",
         [_Gap(r"curl\s+", r"(?:--data-binary|-d)\s*@"),
          _Gap(r"curl\s+", r"-F\s+[\"']?file=@")],
         find=_file_piped_out),

    Rule("exec.remote", HIGH,
         "Downloaded script run without being read",
         "A script fetched from the network was handed straight to a shell or "
         "an interpreter. Whatever the server sent at that moment ran with "
         "your permissions, and nothing on disk shows what it was.",
         find=_remote_run),

    Rule("perm.open", HIGH,
         "Files made writable by every user",
         "A mode that lets any account on the machine, and any process running "
         "as one, change these files. Done recursively it also strips "
         "protections the files relied on, which is slow to undo by hand.",
         find=_chmod_open),

    Rule("container.destructive", HIGH,
         "Container data wiped",
         "Volumes, or every container, removed. Whatever a database or service "
         "kept in them is gone unless a backup exists.",
         find=_container_wipe),

    Rule(_ENCODED, HIGH,
         "Decoded command run",
         "Encoded text was decoded and run in one command. What ran is not "
         "readable in the transcript, which is the point of encoding it, and "
         "it ran with your permissions.",
         find=_encoded_run, keep_source=True),

    # The rules after exec.encoded were added after it, at the end, so the
    # index each rule has in a SARIF document stays the one it had.
    Rule("cred.metadata", CRITICAL,
         "Cloud instance credentials requested",
         "A request to a cloud metadata service for the instance's own "
         "credentials: the IAM role, service account or managed identity the "
         "machine runs as. The short-lived token it hands back is now in a "
         "model context you do not control, and it grants whatever that role "
         "can do in the account.",
         find=_metadata_fetch),

    Rule("persist", HIGH,
         "Startup or scheduled job installed",
         "Something was set to run again on its own: on a schedule, at boot "
         "or at login. It runs with your permissions after the session has "
         "ended, when nothing is watching, and goes on running until someone "
         "finds it.",
         find=_persist_run, writes=_persist_written, hide=_joined_view),

    Rule("agent.config", HIGH,
         "Agent guardrails loosened", _AGENT_WHY,
         find=_agent_unguarded, writes=_agent_config_path, hide=_joined_view),
]


# Keys whose values are file content or prose, never run. An agent writing a
# script that contains "rm -rf" has not deleted anything; running it is a
# separate tool call that this watcher will see on its own. Beside a shell
# command, only these and scalars let _deletion_context resolve it.
_CONTENT_KEYS = {"content", "new_string", "old_string", "body", "text",
                 "file_text", "patch", "diff", "prompt",
                 # Prose the agent wrote for a human to read. A description
                 # that says "clean up the rm -rf targets" is not a deletion.
                 "description", "explanation", "reason", "thought", "title"}

_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
# A line that could end a here-document: the word alone, then nothing but
# blanks.
_TERMINATOR = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)[^\S\n]*$", re.M)


def _strip_heredocs(command, keep_tail=False, bodies=None):
    """Remove heredoc bodies. The body is data being written to disk, not a
    sequence of commands being executed. A << with no line of its word
    after it is not one (1 << x in a python -c string), and is kept.

    keep_tail keeps the rest of the line that opens one: the `| sh` of
    `base64 -d <<EOF | sh` is a command the shell runs, whatever its input.

    The operator stays as it was written, `<<'EOF'`. A placeholder here
    was quoted as evidence, and read as `<redacted` by _REDACTING, which
    made any read beside a heredoc look deliberately masked.

    Given a list, bodies is given (where the operator ends in what is
    returned, the body) for each one taken out: the rules that judge what
    a command writes read the body as what was written, and this is the
    one place that decides where a body begins and ends.

    Every line that could end one is found first, in one pass. As one regex
    each << read on to the end of the command looking for its terminator:
    a megabyte of them took minutes, and this runs before the command is
    cut to MAX_SCAN_CHARS."""
    if not command or "<<" not in command:
        return command
    ends = {}                     # word -> starts and ends of its lines
    for m in _TERMINATOR.finditer(command):
        starts, stops = ends.setdefault(m.group(1), ([], []))
        starts.append(m.start())
        stops.append(m.end())
    out, copied, pos, size = [], 0, 0, 0
    while True:
        op = _HEREDOC.search(command, pos)
        if not op:
            break
        lines = ends.get(op.group(2))
        i = bisect.bisect_left(lines[0], op.end()) if lines else 0
        if not lines or i == len(lines[0]):
            pos = op.start() + 1          # no terminator: not a heredoc
            continue
        out.append(command[copied:op.end()])
        size += op.end() - copied
        newline = command.find("\n", op.end(), lines[0][i])
        if bodies is not None:
            bodies.append((size, command[newline + 1:lines[0][i]]
                           if newline >= 0 else ""))
        if keep_tail:
            tail = command[op.end():newline if newline >= 0 else op.end()]
            out.append(tail)
            size += len(tail)
        copied = pos = lines[1][i]
    out.append(command[copied:])
    return "".join(out)


# Interpreters whose -c/-e payload is source in ANOTHER language. "rm -rf"
# inside a Python string is a string, not a deletion. Shell interpreters are
# the exception: their payload really is shell, so we recurse into it.
_FOREIGN_INTERPRETERS = {"python", "python2", "python3", "node", "nodejs",
                         "perl", "ruby", "php", "osascript", "awk", "jq"}
_SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh"}
_PAYLOAD_FLAGS = {"-c", "-e", "--eval", "--command"}
_INTERPRETERS = _FOREIGN_INTERPRETERS | _SHELL_INTERPRETERS

# What hides a separator from the shell, or is one. Hidden: a quoted
# string (to the end of the command when it is never closed), an escaped
# character (a backslash-newline joins two lines) and a comment. Then the
# separators, |, |&, ;, &&, || and a newline, with the blanks around each;
# not the | of a >| redirection. |& pipes stderr too, and is a |.
#
# Split on every separator, quoted or not, a grep alternation, an echo or
# a commit message was cut into pieces, and each piece after a quoted |
# or ; was judged as a command of its own: grep -E "a|rm -rf|b" f was a
# deletion. One regex pass, which skips what cannot matter in C.
#
# In $'...' a backslash escapes the quote. Read as '...', the \' in
# $'it\'s' closed it, and its last quote opened a string that never
# closed, so nothing after it was split or judged.
#
# Every alternative starts with a character of its own, so the regex skips
# in C to the next one that can start a match. Begun with a lookaround,
# it was tried at every character: a long argument (a base64 blob to
# echo) took a quarter of a millisecond a few kilobytes, three times as
# long. A separator starts at the first blank of the run before it, or on
# itself, as _AT_BLANKS lets it; a newline only where no blank is before
# it, as there.
_ANSI_C = r"""\$'(?:[^'\\]|\\[\s\S])*(?P<aq>')?"""
_HIDING = (_ANSI_C + r"""|'[^']*(?P<sq>')?|"(?:[^"\\]|\\[\s\S])*(?P<dq>")?|\\[\s\S]?"""
           r"""|#(?<![^ \t\n;&|(]#)[^\n]*""")
_SEPARATOR_MARK = r"(?:\|\||&&|;|\|&|\|(?<!>\|))"
_HIDING_OR_SEPARATOR = re.compile(
    _HIDING + r"|(?P<op>\s(?<!\s\s)\s*(?:" + _SEPARATOR_MARK + r"|\n)\s*"
    r"|" + _SEPARATOR_MARK + r"\s*|\n(?<!\s\n)\s*)")


@functools.lru_cache(maxsize=64)
def _command_spans(text):
    """(start, end, separator) of each command in text, split where the
    shell splits it. The separator is the one after it, without its
    blanks: "|" when the shell pipes it into the next, "" for the last.
    The rules that hide what they must not judge, and the one that follows
    a pipe, each ask it of the same command, so it is split once."""
    spans, pos = [], 0
    for m in _HIDING_OR_SEPARATOR.finditer(text):
        op = m.group("op")
        if op is not None:
            op = op.strip() or "\n"
            spans.append((pos, m.start(), "|" if op == "|&" else op))
            pos = m.end()
    spans.append((pos, len(text), ""))
    return tuple(spans)


def _commands(text):
    """The commands in text, split where the shell splits them."""
    return [text[start:end] for start, end, _op in _command_spans(text)]

# Fallback for when the payload contains quoting that shlex cannot parse --
# which is common, because the payload is source code in another language.
# Truncating at the flag is always safe: nothing after it is shell.
_FOREIGN_PAYLOAD = re.compile(
    r"^\s*(?:sudo\s+)?(?:%s)\b[^|;&]*?\s(-c|-e|--eval)\s"
    % "|".join(sorted(_FOREIGN_INTERPRETERS)))


_FOREIGN_OPEN = re.compile(
    r"(?:^|[\s;&|])(?:sudo\s+)?(?:%s)\s+(?:-[A-Za-z]+\s+)*(?:-c|-e|--eval)\s+(['\"])"
    % "|".join(sorted(_FOREIGN_INTERPRETERS)))


def _neutralize_foreign_payloads(command, bodies=None):
    """Blank out the source payload of a non-shell interpreter.

    Must run on the whole command before splitting on shell operators,
    because the payload frequently contains ';' and '|' of its own and
    splitting first tears it into fragments that no longer look like an
    interpreter call.

    The payload becomes an ellipsis between its own quotes, so evidence
    around it reads as the command with its source elided, not as a
    placeholder name. Given a list, bodies is given every command
    substitution the shell runs in a payload before handing it over.
    """
    out, pos = [], 0
    while True:
        m = _FOREIGN_OPEN.search(command, pos)
        if not m:
            out.append(command[pos:])
            break
        quote = m.group(1)
        i = m.end()
        while i < len(command):
            if command[i] == "\\":
                i += 2
                continue
            if command[i] == quote:
                break
            i += 1
        out.append(command[pos:m.end()])
        if bodies is not None and quote == '"':
            # The shell runs a $( ) in a double-quoted payload before the
            # interpreter sees it.
            bodies.extend(_substitutions(command[m.end():i], quoted=True))
        # The closing quote stays, so the quotes around the payload still
        # balance and _real_pipes reads what follows as unquoted.
        out.append("…" + (quote if i < len(command) else ""))
        pos = min(i + 1, len(command))
    return "".join(out)


# A command substitution, $( ) or `...`, runs before the command it sits
# in, inside double quotes as much as outside them. Single quotes, $'...',
# a backslash and a comment hide one; a double quote does not. Inside $( )
# the quoting starts afresh, and a ( opened there is closed before it is.
# Each context has what can change it found by one regex, so a run of
# characters that cannot is read in C.
_SUB_OUTSIDE = re.compile(_ANSI_C + r"""|'[^']*'?|\\[\s\S]?|\$\(|["`]"""
                          r"""|(?<![^ \t\n;&|(])#[^\n]*""")
_SUB_INSIDE = re.compile(_ANSI_C + r"""|'[^']*'?|\\[\s\S]?|\$\(|["`()]"""
                         r"""|(?<![^ \t\n;&|(])#[^\n]*""")
_SUB_QUOTED = re.compile(r"""\\[\s\S]?|\$\(|["`]""")
_SUB_BACKTICKS = re.compile(r"""\\[\s\S]?|`""")
_SUB_CONTEXT = {"top": _SUB_OUTSIDE, "$(": _SUB_INSIDE, '"': _SUB_QUOTED,
                "`": _SUB_BACKTICKS}


# The same contexts for a command that also runs a process substitution,
# <( ): a body opens at `<(` as it does at `$(`. In double quotes <( is text.
_SUB_OUTSIDE_PROCESS = re.compile(
    _ANSI_C + r"""|'[^']*'?|\\[\s\S]?|(?:\$|<)\(|["`]"""
    r"""|(?<![^ \t\n;&|(])#[^\n]*""")
_SUB_INSIDE_PROCESS = re.compile(
    _ANSI_C + r"""|'[^']*'?|\\[\s\S]?|(?:\$|<)\(|["`()]"""
    r"""|(?<![^ \t\n;&|(])#[^\n]*""")
_SUB_CONTEXT_PROCESS = dict(_SUB_CONTEXT, top=_SUB_OUTSIDE_PROCESS,
                            **{"$(": _SUB_INSIDE_PROCESS})


def _substitution_spans(text, quoted=False, process=False):
    """(start, end) in text of the body of each outermost $( ) and `...` of
    it that the shell runs, in order, read as far as MAX_SCAN_CHARS. One
    left open runs to the end. A substitution inside another is in the
    text of the outer one, and is found when that is judged. quoted: text
    is inside double quotes. process: a <( ) opens a body too."""
    end = min(len(text), MAX_SCAN_CHARS)
    contexts = _SUB_CONTEXT_PROCESS if process else _SUB_CONTEXT
    stack = [['"' if quoted else "top", 0, 0]]     # [kind, body start, parens]
    spans, opened, pos = [], 0, 0
    while pos < end:
        context = stack[-1]
        m = contexts[context[0]].search(text, pos, end)
        if not m:
            break
        token, pos = m.group(), m.end()
        if token == "$(" or token == "<(" or (token == "`" and context[0] != "`"):
            stack.append(["$(" if token == "<(" else token, pos, 0])
            opened += 1
        elif token == '"':
            if context[0] == '"':
                stack.pop()
            else:
                stack.append(['"', pos, 0])
        elif token == "(":
            context[2] += 1
        elif (token == ")" and not context[2]) or token == "`":
            stack.pop()
            opened -= 1
            if not opened:
                spans.append((context[1], m.start()))
        elif token == ")":
            context[2] -= 1
    for context in stack:
        if context[0] in ("$(", "`"):
            spans.append((context[1], end))           # left open
            break
    return spans


def _substitutions(text, quoted=False):
    """The text inside each outermost $( ) and `...` of text that the shell
    runs, in order: see _substitution_spans."""
    return [text[lo:hi] for lo, hi in _substitution_spans(text, quoted)]


def _segments(command):
    """Each command in command, and whether the shell pipes its output into
    the next one."""
    for start, end, op in _command_spans(command):
        yield command[start:end], op == "|"


# Programs whose quoted arguments are text, never run: words to print, a
# pattern to search for, a message or a body. Any other program may run
# one as shell, and a list of the ones that do (sh -c, ssh, eval, watch)
# missed heroku run, nix-shell --run, concurrently and ansible -a. git and
# its kin only in a subcommand that takes a message or a pattern, with
# any options before it (git -C repo commit), since git rebase --exec runs
# its argument.
_TAKES_TEXT = re.compile(
    r"\s*(?:sudo\s+(?:-\S+\s+)*)?(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:\S*/)?"
    r"(?:echo|printf|grep|egrep|fgrep|zgrep|rg|ag|ack"
    r"|(?:git|hg|jj|svn)(?:\s+-\S+(?:\s+[^\s-]\S*)?)*\s+"
    r"(?:commit|log|tag|grep|notes|show|shortlog|describe|stash)"
    r"|gh\s+(?:pr|issue|release|gist|api|repo|label|search))(?![\w.-])")
# Text piped into a shell is run by it: echo "ls; rm -rf ~" | sh. What may
# stand between the pipe and the shell hands its input on: sudo or doas
# and their options, one of which may take a value (sudo -u USER bash),
# env with its options and assignments, command -p, exec and its options,
# nohup and nice. A value is the word after an option that is not one,
# so a run of options is read once. Nothing that can fail may follow it in
# a regex, which would try each word as a value and as a program in turn,
# 2**n ways: _AfterHandsOn reads the same words, so the two are changed
# together.
_OPTIONS = r"(?:\s+-[^\s|;&]*(?:\s+[^\s|;&=-][^\s|;&]*)?)*"
_HANDS_ON = (
    r"(?:[^\s|;&]*/)?(?:(?:sudo|doas)" + _OPTIONS
    + r"|env(?:\s+-[^\s|;&]*(?:\s+[^\s|;&=-][^\s|;&=]*)?"
    r"|\s+[A-Za-z_][A-Za-z0-9_]*=[^\s|;&]*)*"
    r"|command(?:\s+-p)*|exec" + _OPTIONS + r"|nohup|nice(?:\s+-n)?(?:\s+-?\d+)?)\s+")
_INTO_SHELL = _IntoShell()
_HIDDEN = re.compile(_HIDING)
_INNER_SEPARATOR = re.compile(r"\|\||&&|;|\||\n")


def _quoted_commands_elided(segment, run_as_shell=False):
    """segment with what follows a separator inside a quoted string elided,
    when the program it is given to takes it as text.

    The pieces after a quoted separator are not commands: `git commit -m
    "note; rm -rf ~/x"` deletes nothing. What comes before the first one
    is kept, and every other program keeps it all, since it may run it
    (`heroku run "ls; rm -rf x"`)."""
    if (run_as_shell or ("'" not in segment and '"' not in segment)
            or not _TAKES_TEXT.match(segment)):
        return segment
    out, pos = [], 0
    for m in _HIDDEN.finditer(segment):
        quote = m.group()[:1]
        if quote not in ("'", '"', "$"):
            continue
        sep = _INNER_SEPARATOR.search(segment, m.start() + 1, m.end())
        if not sep:
            continue
        closed = m.group("sq") or m.group("dq") or m.group("aq") or ""
        out.append(segment[pos:sep.start()] + "…" + closed)
        pos = m.end()
    out.append(segment[pos:])
    return "".join(out)


_QUOTING = re.compile(r"""['"\\]""")
_SHELL_BLANKS = re.compile(r"[ \t\r\n]+")


def _argv(segment):
    """shlex.split(segment), or None when that cannot be had.

    With no quote and no backslash in it, the same words come from a split
    on blanks, in C. shlex builds each word a character at a time, by
    concatenation, which made one long quoted word quadratic: eleven
    seconds for a megabyte. A segment that long is not split at all."""
    if not _QUOTING.search(segment):
        return [w for w in _SHELL_BLANKS.split(segment) if w]
    if len(segment) > MAX_SCAN_CHARS:
        return None
    try:
        return shlex.split(segment)
    except ValueError:
        return None


# A first word with no quote or backslash in it, which shlex would give
# back as it is.
_PLAIN_FIRST_WORD = re.compile(r"\s*([^\s'\"\\]+)(?:\s|$)")


def _reduce_segment(segment, depth, into_shell=False, keep_source=False):
    """What runs of one segment, or None when nothing does. into_shell
    says the command pipes into a shell, which runs what was text.
    keep_source leaves the source of another language's one-liner in."""
    foreign = None if keep_source else _FOREIGN_PAYLOAD.match(segment)
    if foreign:
        return segment[:foreign.end()]

    # Only an interpreter's segment is ever cut to its command, so any
    # other runs as it is, but for what follows a quoted separator, and is
    # not split into words to find that out.
    first = _PLAIN_FIRST_WORD.match(segment)
    if first and first.group(1).rsplit("/", 1)[-1] not in _INTERPRETERS:
        return _quoted_commands_elided(segment, into_shell)

    argv = _argv(segment)
    if argv is None:
        return segment                    # unbalanced quotes: keep it all
    if not argv:
        return None

    binary = os.path.basename(argv[0]).split("/")[-1]
    payload_idx = next((i for i, a in enumerate(argv) if a in _PAYLOAD_FLAGS), None)

    if (binary in _FOREIGN_INTERPRETERS and payload_idx is not None
            and not keep_source):
        return " ".join(argv[:payload_idx + 1])
    if binary in _SHELL_INTERPRETERS and payload_idx is not None:
        # The string is the first word that is no option: bash -c -l '...'.
        at = payload_idx + 1
        while at < len(argv) and argv[at].startswith("-") and len(argv[at]) > 1:
            at += 1
        head = " ".join(argv[:at])
        body = argv[at] if at < len(argv) else ""
        return head + " " + _executable_text(body, depth + 1,
                                             keep_source=keep_source)
    return _quoted_commands_elided(segment, into_shell)


def _executable_text(command, depth=0, limit=None, keep_source=False):
    """Reduce a shell command to only the parts that are actually executed.

    Drops heredoc bodies and the source payloads of foreign interpreters,
    recursing into shell interpreters. This is what stops a script that
    *contains* a dangerous string from reading as a dangerous action.

    What is kept is joined by ` | ` where the shell pipes one into the
    next, and by ` ; ` otherwise. Joined by ` ; ` throughout, no rule
    could see a pipe, and `tar czf - src | curl -T - …` went unreported.
    A search dropped from the middle of a pipe passes on what it reads,
    so `cat .env | grep -v '#' | curl …` is still one pipe; echo does not.

    With a limit, it stops once that many characters are kept: the rest
    would only be cut off after, and reducing it all cost a second or two
    a megabyte.

    With keep_source, the source of a python, perl or node one-liner stays,
    and what is piped stays whichever program reads it: for the rule that
    judges what such a source decodes and runs.
    """
    if not command or depth > 3:
        return command or ""
    command = _strip_heredocs(command, keep_tail=keep_source)
    bodies = []
    if keep_source:
        into_shell = "|" in command
    else:
        command = _neutralize_foreign_payloads(command, bodies)
        into_shell = "|" in command and _INTO_SHELL.search(command) is not None

    out, flowing, kept_chars = [], False, 0
    for raw, piped in _segments(command):
        segment = _COMMENT.sub("", raw).strip()
        kept = (None if not segment or _is_inert(segment, into_shell)
                else _reduce_segment(segment, depth, into_shell, keep_source))
        if kept != raw.strip() and ("$(" in raw or "`" in raw):
            # What was dropped as text may hold a command the shell runs
            # first: echo "$(rm -rf ~)", git commit -m "$(ls; cat .env)".
            bodies += _substitutions(raw)
        if kept is None:
            flowing = flowing and piped and _is_search(segment)
            continue
        if out:
            out.append(" | " if flowing else " ; ")
        out.append(kept)
        flowing = piped
        kept_chars += len(kept) + 3
        if limit is not None and kept_chars >= limit:
            break

    # Each substitution is a command of its own, after the rest, so a pipe
    # the rest is joined by stays as the shell has it.
    for body in dict.fromkeys(bodies):
        if limit is not None and kept_chars >= limit:
            break
        inner = _executable_text(body, depth + 1, limit, keep_source)
        if inner:
            out.append(" ; " if out else "")
            out.append(inner)
            kept_chars += len(inner) + 3
    return "".join(out)


# ---------------------------------------------------------------------------
# What a tool call executes.
#
# Rules about actions judge only text that runs. A Workflow script or a
# subagent's prompt is prose for another model: one that said "read the
# .env" and quoted `rm -rf "$SB"` was reported as a credential read and a
# deletion, though the call itself ran nothing. Whatever the subagent then
# runs is a tool call of its own, and is judged when it is made.
# ---------------------------------------------------------------------------

# Tools that hand their input to a shell: Claude Code's Bash, OpenClaw's
# exec (bash in older releases), and the names other agents and MCP servers
# give the same thing. Matched on the name after any mcp__server__ or
# dotted namespace prefix, ignoring case.
_SHELL_TOOLS = {"bash", "sh", "zsh", "shell", "exec", "powershell", "terminal",
                "run_command", "execute_command", "run_shell_command",
                "shell_command", "run_terminal_cmd", "run_in_terminal",
                "local_shell", "execute_bash"}
# Where they carry the command. The OpenClaw reader stores arguments that
# were a bare string as _raw, and a list as _value. Other keys (workdir,
# timeout, host) configure the run and are never run themselves.
_COMMAND_KEYS = ("command", "cmd", "_raw", "_value")
# An argv that continues the command: {"command": "rm", "args": ["-rf", "x"]}.
_ARGV_KEYS = ("args", "argv", "arguments")

# Tools that read a file's contents into the context, and where they name
# it. Search tools are not here: grep and find in Bash are judged as
# searches, and the Grep and Glob tools are the same thing.
_READ_TOOLS = {"read", "notebookread", "read_file", "readfile",
               "read_text_file", "read_multiple_files"}
_PATH_KEYS = ("file_path", "path", "notebook_path", "filePath", "file",
              "filename", "paths")


def _base_name(tool_name):
    name = tool_name if isinstance(tool_name, str) else ""
    return name.rsplit("__", 1)[-1].rsplit(".", 1)[-1].lower()


def _words(value):
    if isinstance(value, (list, tuple)):
        try:
            return " ".join(str(c) for c in value)
        except RecursionError:
            # An item nested deeper than str() recurses is no word of a
            # command, and stopped the whole store; the strings beside it are.
            return " ".join(c for c in value if isinstance(c, str))
    return value if isinstance(value, str) else ""


def _shell_text(tool_name, tool_input, keep_source=False):
    """The parts of a shell tool's command that run, or "" for any other
    tool. A command longer than MAX_SCAN_CHARS is cut after reduction, not
    before, so a heredoc keeps the terminator that marks its body as data.
    With keep_source the source of other languages' one-liners stays in, and
    a command with nothing in it that could be an encoding is "": the one
    rule that reads it has nothing to find there."""
    if _base_name(tool_name) not in _SHELL_TOOLS:
        return ""
    commands = _commands_of(tool_input)
    if keep_source and not any(_may_decode(c) for c in commands):
        return ""
    parts = [_executable_text(c, limit=MAX_SCAN_CHARS, keep_source=keep_source)
             for c in commands]
    return " ; ".join(p for p in parts if p)[:MAX_SCAN_CHARS]


def _commands_of(tool_input):
    """The commands a shell tool was given, as written: each of its command
    keys, with an argv that continues the last."""
    if not isinstance(tool_input, dict):
        tool_input = {"_value": tool_input}
    commands = [c for c in (_words(tool_input.get(k)) for k in _COMMAND_KEYS)
                if c]
    argv = " ".join(a for a in (_words(tool_input.get(k)) for k in _ARGV_KEYS)
                    if a)
    if argv:
        commands = commands[:-1] + [" ".join(commands[-1:] + [argv])]
    return commands


def _writes_text(tool_name, tool_input):
    """A shell tool's command as the rules that judge what it writes read
    it (_write_view), or "" for any other tool, and for a command that
    names nothing either of them reports: then neither has anything to
    find, and nearly every call is one."""
    if _base_name(tool_name) not in _SHELL_TOOLS:
        return ""
    return _writes_of(" ; ".join(_commands_of(tool_input)))


def _writes_of(command):
    if not command or not (_may_persist(command) or _may_loosen(command)):
        return ""
    return _write_view(command)


def _read_paths(tool_name, tool_input):
    """The paths a file-reading tool opened, one per line, or ""."""
    if (_base_name(tool_name) not in _READ_TOOLS
            or not isinstance(tool_input, dict)):
        return ""
    found = []
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        for path in (value if isinstance(value, (list, tuple)) else [value]):
            if isinstance(path, str) and path:
                found.append(_read_path_as_named(path))
    return "\n".join(found)[:MAX_SCAN_CHARS]


def _read_path_as_named(path):
    """A path a file tool read, written as the credential rule names
    ranwhat's own: with its // and . and .. parts taken out, and under
    $RANWHAT_HOME when it is a file in the folder RANWHAT_HOME names on
    this machine, which only a literal path can say."""
    flat = _flat(_slashed(path))
    for tail in ("/known/key", "/token"):
        if flat.endswith(tail) and _ranwhat_home_folder(flat[:-len(tail)]):
            return "$RANWHAT_HOME" + tail
    return flat if flat != _slashed(path) else path


# Tools that write or edit a file, and those of them that are given a
# patch, whose file headers name what it writes. str_replace_editor's view
# reads.
_WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "write_file",
                "replace", "edit_file", "create_file", "write_to_file",
                "replace_in_file", "str_replace_editor",
                "str_replace_based_edit_tool", "apply_patch", "applypatch"}
_PATCH_KEYS = ("patch", "diff", "input")
_PATCH_FILE = re.compile(
    r"^(?:\*\*\* (?:Add|Update|Delete) File: |\*\*\* Move to: |\+\+\+ (?:b/)?)"
    r"([^\t\n]+)", re.M)
_MOST_WRITTEN = 256


def _written_paths(tool_name, tool_input):
    """The paths a file-writing tool wrote, one per line, or ""."""
    if (_base_name(tool_name) not in _WRITE_TOOLS
            or not isinstance(tool_input, dict)
            or tool_input.get("command") == "view"):
        return ""
    found = []
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        for path in (value if isinstance(value, (list, tuple)) else [value]):
            if isinstance(path, str) and path:
                found.append(path)
    for key in _PATCH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str):
            found.extend(m.group(1).strip() for m in
                         _PATCH_FILE.finditer(value[:MAX_SCAN_CHARS]))
    found = [p for p in dict.fromkeys(found) if p and p != "/dev/null"]
    return "\n".join(found[:_MOST_WRITTEN])[:MAX_SCAN_CHARS]


_PatchSection = collections.namedtuple("_PatchSection",
                                       "header added removed whole gone")


def _patch_sections(patch):
    """A patch read once, into the section each file header starts: the
    lines it adds and takes out (+ and -, a SEARCH and REPLACE block's
    halves), and whether it adds or deletes the file whole. Lines before
    any header are a section whose header is None: a diff that names no
    file is about the one the tool was given."""
    sections, current, side = [], [None, [], [], False, False], None
    for line in patch.split("\n"):
        header = _PATCH_FILE.match(line)
        if header or line.startswith("--- "):
            if header:
                sections.append(current)
                current = [header.group(1).strip(), [], [],
                           line.startswith("*** Add File: "),
                           line.startswith("*** Delete File: ")]
                side = None
            continue
        if line.startswith("<<<<<<< SEARCH"):
            side = current[2]
        elif line.startswith("=======") and side is current[2]:
            side = current[1]
        elif line.startswith(">>>>>>> REPLACE"):
            side = None
        elif side is not None:
            side.append(line)
        elif line[:1] == "+":
            current[1].append(line[1:])
        elif line[:1] == "-":
            current[2].append(line[1:])
    sections.append(current)
    return [_PatchSection(*section) for section in sections
            if section[0] is not None or section[1] or section[2]]


def _add_section(change, section):
    if section.added:
        change.new.append(("\n".join(section.added), False))
    if section.removed:
        change.old.append(("\n".join(section.removed), False))
    change.whole = change.whole or section.whole
    change.removed = change.removed or section.gone


# What an edit puts in and takes out, by the names agents give the two
# halves: Claude Code's, Gemini's and Cline's; OpenCode's and Grok's
# oldString and newString; Pi's oldText and newText. Kimi nests each edit
# under `edit`, one or a list, as old and new, which are read only there:
# at the top of an input they could be anything.
_NEW_KEYS = ("new_string", "new_str", "new_text", "new_source", "newString",
             "newText")
_OLD_KEYS = ("old_string", "old_str", "old_text", "oldString", "oldText")


def _edits_of(value):
    """The dicts an edits or edit value holds: a list of them, or one."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [e for e in value[:_MOST_WRITTEN] if isinstance(e, dict)]
    return []


def _written_parts(tool_input):
    """(change, sections) of what a file tool's input writes: the change
    its content and edits make, whatever file it wrote, and the sections of
    its patches (_patch_sections). Each value is read as far as
    MAX_SCAN_CHARS, and all of them as far as MAX_WRITTEN_CHARS."""
    change, sections = _Change(), []
    if not isinstance(tool_input, dict):
        return change, sections
    budget = [MAX_WRITTEN_CHARS]

    def strings(source, keys):
        for key in keys:
            value = source.get(key)
            if isinstance(value, str) and budget[0] > 0:
                value = value[:min(MAX_SCAN_CHARS, budget[0])]
                budget[0] -= len(value)
                yield value

    for value in strings(tool_input, ("content", "file_text", "contents", "text")):
        change.new.append((value, False))
        change.whole = True
    sources = [(s, _NEW_KEYS, _OLD_KEYS) for s in
               [tool_input] + _edits_of(tool_input.get("edits"))]
    sources += [(s, _NEW_KEYS + ("new",), _OLD_KEYS + ("old",))
                for s in _edits_of(tool_input.get("edit"))]
    for source, new_keys, old_keys in sources:
        change.new.extend((v, False) for v in strings(source, new_keys))
        change.old.extend((v, False) for v in strings(source, old_keys))
    for value in strings(tool_input, _PATCH_KEYS):
        sections += _patch_sections(value)
    return change, sections


def _written_change(tool_input):
    """The _Change a file tool made to every file it wrote, read from its
    input (_written_parts)."""
    change, sections = _written_parts(tool_input)
    for section in sections:
        _add_section(change, section)
    return change


def _tails(path):
    """path, and each part of it that follows a /."""
    yield path
    at = path.find("/")
    while at >= 0:
        yield path[at + 1:]
        at = path.find("/", at + 1)


class _Headers(object):
    """The files a patch's headers name, each with the _Change its sections
    make, found for a path as a header names it whether either is the
    longer: .claude/settings.json is /repo/.claude/settings.json. Each
    header is kept under every part of it that follows a /, and a path is
    looked up whole and by each such part of it, so a path is never
    compared with every header: 256 paths written by a patch of as many
    headers were each read against all of them."""

    def __init__(self, sections):
        self.changes, self.under = collections.OrderedDict(), {}
        for section in sections:
            header = _slashed(section.header)
            if header not in self.changes:
                self.changes[header] = _Change()
                for tail in _tails(header):
                    self.under.setdefault(tail, []).append(header)
            _add_section(self.changes[header], section)

    def changes_of(self, path):
        """The _Change of each header that names path."""
        path = _slashed(path.strip())
        found = list(self.under.get(path, ()))
        tails = _tails(path)
        next(tails)
        found += [tail for tail in tails if tail in self.changes]
        return [self.changes[header] for header in dict.fromkeys(found)]


def _input_strings(obj, depth=0):
    """Every string a tool input carries, keys aside: what clean would read
    in the same call."""
    if depth > 6:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            for s in _input_strings(item, depth + 1):
                yield s
    elif isinstance(obj, dict):
        for value in obj.values():
            for s in _input_strings(value, depth + 1):
                yield s


def _raw_strings(tool_input):
    """The strings scan_raw rules read, each cut to MAX_SCAN_CHARS and all of
    them to MAX_RAW_CHARS, so a call carrying a large file stays cheap."""
    out, budget = [], MAX_RAW_CHARS
    for s in _input_strings(tool_input):
        if budget <= 0:
            break
        s = s[:min(MAX_SCAN_CHARS, budget)]
        out.append(s)
        budget -= len(s)
    return out


# How deep _masked and _shallow follow a recorded value before cutting it
# to "…": a record is masked and written as JSON by walks that recurse.
_CUT_DEPTH = 32


def _masked(obj, depth=0, known=None):
    from . import clean
    if isinstance(obj, str):
        # The spans the rules found for this text already, when they did,
        # and with known every copy of a value clean finds anywhere.
        spans = _secret_spans(obj)
        if known:
            spans = known.merged(obj, spans)
        return clean.mask_for_display(obj, spans)
    if depth > _CUT_DEPTH:
        return "…"
    if isinstance(obj, (list, tuple)):
        return [_masked(o, depth + 1, known) for o in obj]
    if isinstance(obj, dict):
        # Keys too: an input may be keyed by what it holds.
        return {_masked(str(k), depth + 1, known): _masked(v, depth + 1, known)
                for k, v in obj.items()}
    return obj


def _payload(tool_input, known=None):
    """The whole call as one string, for telling calls apart. The judged text
    cannot do it: it is empty for most tools, which made every Workflow call
    that leaked a key the same call.

    Credentials are masked first. Its hash is printed as payload_hash, and a
    hash over a short password is a dictionary oracle for it: so with
    known, a known.Matcher, every value clean finds anywhere is masked too,
    a password typed where no rule reads one among them."""
    try:
        return json.dumps(_masked(tool_input, known=known), sort_keys=True,
                          ensure_ascii=False, default=str)
    except (TypeError, ValueError, RecursionError):
        return "unhashable"


def _hash(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


# A command longer than this is a data blob, not something a human wrote.
# Matching past it costs real time on large transcripts and finds nothing.
MAX_SCAN_CHARS = 64000
# Every string in one call together, for the rules that read them all.
MAX_RAW_CHARS = 4 * MAX_SCAN_CHARS
# How much of a file tool's input is read for what it writes, every value
# together (_written_parts): each is cut at MAX_SCAN_CHARS, and a MultiEdit
# of 256 edits of that size, 32MB, took half a minute to read. Far more
# than one answer of a model's holds, so no edit can be hidden behind
# others that fill it.
MAX_WRITTEN_CHARS = 16 * MAX_SCAN_CHARS


# ---------------------------------------------------------------------------
# What a hit is about.
#
# A hit's evidence is a window of 90 characters, cut where it reads best:
# `npm publish … --registry https://registry.npmjs.org/` and the same
# command sent to another registry printed the same evidence, and so did
# `cd /tmp/evil && npm publish` and a plain `npm publish`. What ranwhat
# ignore matches an entry against must tell those apart, so the scan keeps
# beside each hit what it was found in, whole (judge(subjects=True)):
#
#   _on       "command": a command the call ran (the shell text, the same
#             with a one-liner's source kept, or the command as the rules
#             that judge writes read it); "path": a path a tool read or
#             wrote; "raw": any string the call carried; "decoded": a
#             command the call decoded and ran.
#   _subject  for a command, every command of the call the match touches,
#             from the one it starts in to the one it ends in, each split
#             where the shell splits it; for a path, its line. Masked as
#             the evidence is, never cut, and left out over MAX_SUBJECT.
#   _cd       for a command, where the commands before it in the same call
#             moved: "" for nowhere, a path (absolute, or relative to where
#             the call ran), or None when that cannot be told.
#
# They are the scan's own: public() takes them out of every record printed
# as JSON, and evaluate(), which the hook calls, does not make them.
# ---------------------------------------------------------------------------

# Longer than this, a subject is no command anyone would match word for
# word: it is left out, and only the action's id names it.
MAX_SUBJECT = 4096

# Moves the shell into a directory: cd DIR and pushd DIR.
_CHDIR = frozenset(("cd", "pushd"))
# After one of these, where the shell is cannot be told from the text:
# popd goes back to a directory not named, source and . run a file, eval
# runs text, and exec runs something else in the shell's place.
_LOSES_DIR = frozenset(("popd", "source", ".", "eval", "exec"))
# What a directory a cd names cannot hold and still be read as written: an
# expansion, a substitution or a glob.
_NOT_LITERAL_DIR = re.compile(r"[$`*?\[]")
# Longer than this, a directory is none anyone keeps work in, and is not
# known: `cd a && ` four thousand times, each joined to the one before,
# made each join as long as all of them, and the call a quadratic cost.
_LONGEST_DIR = 1024


def _runs_a_shell(words):
    """Whether these words, a command split on blanks, hand a shell a
    command of its own (sudo bash -c 'cd /x && …'): _executable_text puts
    that command inline after the shell's name, and a cd in it would read
    as one this shell ran, though only that shell moved."""
    for k, word in enumerate(words):
        if posixpath.basename(word.strip("'\"")) in _SHELL_INTERPRETERS:
            return any(w.startswith("-") and "c" in w for w in words[k + 1:k + 4])
    return False


# Words that may stand before the command a stage runs: a variable put in
# its environment, `!`, `time`, and the keywords a compound statement's
# parts begin with. A cd behind any of them still moves the shell (`X= cd
# /x`, `if true; then cd /x; fi`, `! cd /x`), and is not told by its first
# word.
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_LEADING = frozenset(("!", "time", "if", "then", "do", "else", "elif", "while",
                      "until", "case", "for", "select", "function", "in"))


def _bare(word):
    """word as the shell reads it once its quotes and escapes are taken
    out: c''d and c\\d are cd."""
    return _QUOTING.sub("", word)


_CONTINUED = re.compile(r"\\\r?\n")

# A stage that defines what a later word means: a function (f() { ... },
# function f ...), a trap, an alias. What a name does after that cannot be
# read from the text, so no folder after it is known.
_REDEFINES = re.compile(
    r"\s*(?:function\b|[\w.:@%+-]+\s*\(\s*\)|(?:builtin\s+|command\s+)?(?:trap|alias)\b)")


def _moved(stage, where, cdpath=False):
    """Where the shell is after one command of a call, given where it was
    before it ("" where the call started, None not known): a plain cd or
    pushd to a directory written out in full moves it, there or below
    where it was; a ~ is the home directory. Anything that may move it in
    a way the text does not show (cd alone, cd -, popd, source, eval, a
    subshell or a group, a shell given a command of its own, a cd behind a
    variable, a keyword, a `!` or `time`, or quoted so that it does not
    read as cd, a relative cd when the call sets CDPATH) leaves it not
    known: the fail-open choice here is the one that fails to leave an
    action out. Every other command leaves it where it was. Only the words
    before a command are looked at, so a long call costs what it is long."""
    head = stage.strip()
    if not head:
        return where
    if "\\\n" in head or "\\\r\n" in head:
        # a backslash and a newline are taken out before a word is read
        head = _CONTINUED.sub("", head)
    if head[0] in "({":
        return None
    words = head.split(None, 12)
    # The command word: what follows the words that only prepare for it.
    k = 0
    while k < len(words):
        bare = _bare(words[k])
        if _ASSIGN.match(words[k]) or bare in _LEADING or (
                bare.endswith(")") and k + 1 < len(words)):
            k += 1
            continue
        break
    if k >= 12:
        # twelve words were passed over and the command word is not among
        # the ones split out: words[12] holds all the rest of the stage
        return None
    prefixed = k > 0
    if k >= len(words):
        return where
    name = _bare(words[k])
    if name in ("builtin", "command"):
        # options between it and the command (command -p cd, builtin -- cd)
        j = k + 1
        while j < len(words) and _bare(words[j]).startswith("-"):
            j += 1
        if j < len(words) and _bare(words[j]) in _CHDIR | _LOSES_DIR:
            return None
        return where
    if name in _LOSES_DIR or _runs_a_shell(head.split()):
        return None
    if name not in _CHDIR:
        if words[0] in ("case", "for", "select") and any(
                _bare(w) in _CHDIR | _LOSES_DIR for w in words[1:]):
            return None
        return where
    if prefixed or words[k] not in _CHDIR:
        return None
    argv = _argv(head)
    if not argv or len(argv) != 2 or argv[0] not in _CHDIR:
        return None
    target = argv[1]
    if not target or target == "-" or _NOT_LITERAL_DIR.search(target):
        return None
    if target == "~" or target.startswith("~/"):
        target = _home() + target[1:]
    elif target.startswith("~"):
        return None                         # another user's home
    if not target.startswith("/"):
        if where is None or cdpath:
            return None
        target = posixpath.join(where, target) if where else target
    if len(target) > _LONGEST_DIR:
        return None
    target = posixpath.normpath(target)
    return "" if target == "." else target


@functools.lru_cache(maxsize=64)
def _directories(text):
    """Where the shell is before each command of text (_command_spans),
    as _moved tells it. Each hit on the same call asks it of the same
    text, so each call's commands are walked once."""
    out, where = [], ""
    # CDPATH may send a relative cd anywhere: its effect cannot be read.
    cdpath = "CDPATH" in text
    redefined = False
    for start, end, _op in _command_spans(text):
        out.append(where)
        stage = text[start:end]
        if _REDEFINES.match(stage):
            # from here on a name may mean anything, a cd included
            redefined = True
        where = None if redefined else _moved(stage, where, cdpath)
    return tuple(out)


def _shown_whole(text, lo, hi, known):
    """text[lo:hi] masked as _evidence masks a window, and never cut; None
    when it is longer than MAX_SUBJECT. A second look at a part of text
    that clean found a value in, or that is not all of text, can read what
    a hint now stands apart from, as _evidence's does.

    A value known only by its mask is found where it is a piece of the
    text, and not looked for in every stretch: that search has a budget
    for the whole run, so what it masks would depend on how much else the
    run read before (watch over one agent or every one), and an entry
    matched against it would hide an action in one report and not the
    other. Nor does a subject, wider than evidence, spend what is left of
    that budget for the evidence printed after it."""
    from . import clean
    if hi - lo > MAX_SUBJECT:
        return None
    lo, hi, spans, shown = _masked_window(text, lo, hi, known, stretches=False)
    if hi - lo > MAX_SUBJECT:
        return None
    shown = shown.strip()
    if spans or lo > 0 or hi < len(text):
        shown = clean.mask_for_display(shown)
    return known.mask(shown) if known else shown


def _subject_of(hit, on, text, span, known, later=None, earlier=None):
    """hit with what it is about: _on, and for a command or a path its
    _subject, and for a command its _cd (see above). later is where the
    same rule matches again further on in text, or None; earlier is where
    it matches before the span, or None. The rule's match is not always the
    first command it trips (it may prefer one of its patterns to another),
    so an earlier command is looked for as much as a later one."""
    hit["_on"] = on
    lo, hi = span
    last = max(lo, hi - 1)
    if on == "command":
        spans = _command_spans(text)
        starts = [s for s, _e, _op in spans]
        first = max(0, bisect.bisect_right(starts, lo) - 1)
        end = max(first, bisect.bisect_right(starts, last) - 1)
        if (later is not None and bisect.bisect_right(starts, later) - 1 > end
                or earlier is not None
                and bisect.bisect_right(starts, earlier) - 1 < first):
            # The rule is tripped again by a later command of the call. The
            # scan keeps one hit a rule, and an entry written for the first
            # command must not leave out the second with it: `npm publish
            # && npm publish --registry <elsewhere>` is one hit. Said of
            # neither, so that only an action's id names it, and in= has
            # nowhere to be judged from.
            hit["_several"] = True
            hit["_cd"] = None
            return hit
        subject = _shown_whole(text, spans[first][0], spans[end][1], known)
        where = _directories(text)[first]
        if where:
            from . import clean
            where = clean.mask_for_display(where)
            where = known.mask(where) if known else where
        hit["_cd"] = where
    elif on == "path":
        start = text.rfind("\n", 0, lo) + 1
        stop = text.find("\n", last)
        if (later is not None and stop != -1 and later > stop
                or earlier is not None and earlier < start):
            hit["_several"] = True      # as for a command, above
            return hit
        subject = _shown_whole(text, start, len(text) if stop == -1 else stop,
                               known)
    else:
        return hit
    if subject is not None:
        hit["_subject"] = subject
    return hit


def _matches_again(rule, match, refine, seen, span, tool_input):
    """Where in seen the rule matches again after the span it hit, or None:
    one more scan of the rest of the text. A refiner that would drop that
    match drops it here too."""
    cut = span[1]
    if cut >= len(seen):
        return None
    rest = seen[cut:]
    again = match(rest)
    if not again:
        return None
    if refine and refine(rest, rule.severity, tool_input) is None:
        return None
    return cut + again[0]


def _matches_before(rule, match, refine, seen, span, tool_input):
    """Where in seen the rule matches before the span it hit, or None: one
    scan of the text ahead of it, for the rule's match is not always the
    first command it trips. Together with _matches_again a call costs three
    matches a rule and never more, however often the command repeats."""
    cut = span[0]
    if cut <= 0:
        return None
    head = seen[:cut]
    before = match(head)
    if not before:
        return None
    if refine and refine(head, rule.severity, tool_input) is None:
        return None
    return before[0]


def _rule_hits(rules, shell, source, paths, raw, tool_input, known,
               writes=None, written="", subjects=False):
    """The hits of `rules` on a call: its judged shell text, the same text
    with the source of one-liners kept (source(), asked only by a rule that
    wants it), the paths a file-reading tool opened, every string the call
    carried, the command as the rules that judge writes read it (writes(),
    asked only by them) and the paths a file-writing tool wrote. One hit
    per rule. With subjects, each hit says what it is about (_subject_of)."""
    hits = []
    for rule in rules:
        # (text, what the rule judges in it, refiners, how it is matched,
        # what the text is). The two texts differ only by what rule.hide
        # blanks and by a Windows path's backslashes read as /, so a span
        # in one is a span in both.
        if rule.scan_raw:
            texts = [(s, s, REFINERS, rule.match, "raw") for s in raw]
        else:
            if rule.keep_source:
                text = source()
            elif rule.writes:
                text = writes() if writes else ""
            else:
                text = shell
            seen = rule.hide(text) if rule.hide and text else text
            texts = [(text, seen, REFINERS, rule.match, "command")]
            if rule.paths:
                texts.append((paths, _slashed(paths), PATH_REFINERS, rule.match,
                              "path"))
            if rule.writes:
                texts.append((written, _slashed(written), WRITE_REFINERS,
                              rule.writes, "path"))
        for subject, seen, refiners, match, on in texts:
            if not subject:
                continue
            span = match(seen)
            if not span:
                continue
            severity, why = rule.severity, rule.why
            refine = refiners.get(rule.id)
            if refine:
                # a severity, None to drop the hit, or (severity, why) when
                # the rule's own why does not fit what happened
                severity = refine(seen, severity, tool_input)
                if severity is None:
                    continue
                if isinstance(severity, tuple):
                    severity, why = severity
            evidence = _evidence(subject, span, known=known)
            if rule.id == _ENCODED:
                evidence = _elided(evidence, _encoded_findings(seen))
            hit = {"rule": rule.id, "severity": severity,
                   "title": rule.title, "why": why, "evidence": evidence}
            if subjects:
                around = on in ("command", "path")
                _subject_of(hit, on, subject, span, known,
                            _matches_again(rule, match, refine, seen, span,
                                           tool_input) if around else None,
                            _matches_before(rule, match, refine, seen, span,
                                            tool_input) if around else None)
            hits.append(hit)
            break
    return hits


# A long run of what base64 is spelt in, or of printf escapes.
_OPAQUE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}|(?:\\(?:x[0-9A-Fa-f]{2}|[0-7]{3})){4,}")
_OPAQUE_MIN = 20


def _elided(evidence, findings):
    """evidence with the encoded text it shows replaced by its size. What
    was hidden in an encoding is shown decoded, and masked, by the hit that
    judges it; the encoding itself would give a secret back to anyone who
    decodes it, and it is no help in telling the command from another."""
    for found in sorted({(f.literal, f.via[:1]) for f in findings if f.literal},
                        key=lambda f: -len(f[0])):
        literal, via = found
        if len(literal) >= _OPAQUE_MIN and literal in evidence:
            label = decode.LABELS.get(via[0], "encoded") if via else "encoded"
            evidence = evidence.replace(literal, "<%s, %d chars>"
                                        % (label, len(literal)))

    def hide(m):
        token = m.group()
        if token.count("/") * 12 > len(token):
            return token                  # a path
        return "<encoded, %d chars>" % len(token)

    return _masked_here(_OPAQUE.sub(hide, evidence))


def _no_source():
    return ""


def _decoded_hits(source, seen, known, subjects=False):
    """What the text a call decoded and ran trips in the other rules, as
    hits whose evidence says where the text came from. Judged as the shell
    command it is, never run: decode.py reads it as text and the rules read
    it as they read any command, with no tool input to resolve a path by,
    so a target is judged as the worst it could be. At most MAX_PAYLOADS are
    decoded, to two levels (a payload that decodes to another). A rule the
    call tripped already, `seen`, is not reported twice. With subjects,
    each is about "decoded" text, and has no subject: what was hidden in an
    encoding is no command the transcript shows, to be matched by one."""
    hits, budget, judged = [], [MAX_PAYLOADS], set()
    rules = [r for r in RULES if r.id != _ENCODED]

    def judge(text, levels, path):
        for found in _encoded_findings(text):
            if budget[0] <= 0:
                return
            if len(found.via) > levels:
                continue
            # The same payload, however often a command runs it, is judged
            # once: its cost is the rules' cost on it, again for each copy.
            if (path + found.via, found.literal) in judged:
                continue
            judged.add((path + found.via, found.literal))
            decoded = decode.decode_via(found.via, found.literal)
            if decoded is None:
                continue
            budget[0] -= 1
            how = path + found.via
            label = " then ".join(decode.LABELS[kind] for kind in how)
            shell = _executable_text(decoded, limit=MAX_SCAN_CHARS)[:MAX_SCAN_CHARS]
            for hit in _rule_hits(rules, shell, _no_source, "",
                                  [decoded[:MAX_SCAN_CHARS]], None, known,
                                  writes=functools.partial(_writes_of, decoded)):
                if hit["rule"] in seen:
                    continue
                seen.add(hit["rule"])
                hit["evidence"] = _masked_here(
                    "decoded %s: %s" % (label, hit["evidence"]))
                if subjects:
                    hit["_on"] = "decoded"
                hits.append(hit)
            left = levels - len(found.via)
            if left > 0 and _may_decode(decoded):
                judge(_executable_text(decoded, limit=MAX_SCAN_CHARS,
                                       keep_source=True)[:MAX_SCAN_CHARS],
                      left, how)

    judge(source, decode.MAX_LEVELS, ())
    return hits


def evaluate(tool_name, tool_input, known=None, written=None, subjects=False):
    """Return (hits, payload) for one tool call: the rules it trips, and the
    whole input as masked text for telling flagged calls apart ("" when
    nothing tripped, since then there is nothing to tell apart). `known`,
    a known.Matcher, is every value clean finds in the history, masked in
    both wherever a copy starts. `written`, the paths an adapter found the
    call wrote, stands for the ones its tool name would give. With
    subjects, each hit also says what it is about (_subject_of), for the
    scan; the hook asks without, and pays nothing for it."""
    shell = _shell_text(tool_name, tool_input)
    paths = _read_paths(tool_name, tool_input)
    raw = _raw_strings(tool_input)
    if written is None:
        written = _written_paths(tool_name, tool_input)
    else:
        written = "\n".join(p for p in written if isinstance(p, str) and p)
        written = written[:MAX_SCAN_CHARS]
    kept, views = [], []

    def source():
        # Asked only by a rule that judges source, and read once.
        if not kept:
            kept.append(_shell_text(tool_name, tool_input, keep_source=True))
        return kept[0]

    def writes():
        # Asked only by the rules that judge writes, and read once.
        if not views:
            views.append(_writes_text(tool_name, tool_input))
        return views[0]

    hits = _rule_hits(RULES, shell, source, paths, raw, tool_input, known,
                      writes, written, subjects)
    if any(h["rule"] == _ENCODED for h in hits) and source():
        hits.extend(_decoded_hits(source(), {h["rule"] for h in hits}, known,
                                  subjects))
    return hits, (_payload(tool_input, known) if hits else "")


# A name in neither _SHELL_TOOLS nor _READ_TOOLS: what a call is judged
# under when the adapter knows its kind but found no command or paths in it.
NEUTRAL = "ranwhat:%s"


def judge(call, known=None):
    """(hits, payload) for one sources.ToolCall (design 3.5), with `known`
    masked as evaluate masks it.

    A call of a ported source (kind None) and one whose tool name its
    adapter does not know are judged by name, exactly as evaluate judges
    them. A known shell call is judged as the command it ran, with the
    input keys the adapter turned into that command left out and any
    working directory kept; a known read, by the paths it opened; a known
    write, by the paths it wrote, with its input as it was, so a payload's
    hash stays what it was. Anything else, and a call whose command or
    paths were not found, answers only to the rules that read every
    string: file content is not an action.

    Each hit says what it is about (_subject_of): what a record from the
    scan is matched by."""
    if call.kind is None or not call.known:
        return evaluate(call.tool_name, call.tool_input, known, subjects=True)
    rest = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.kind == "shell" and call.command:
        judged = dict(rest, command=call.command)
        if call.workdir:
            judged["workdir"] = call.workdir   # keeps _deletion_context conservative
        return evaluate("Bash", judged, known, subjects=True)
    if call.kind == "read" and call.paths:
        return evaluate("Read", dict(rest, paths=list(call.paths)), known,
                        subjects=True)
    if call.kind == "write" and call.paths:
        return evaluate(NEUTRAL % call.kind, call.tool_input, known,
                        written=call.paths, subjects=True)
    return evaluate(NEUTRAL % call.kind, call.tool_input, known, subjects=True)


def _shallow(value, depth=0):
    """value as recorded, cut where _masked cuts a payload. A record is
    masked and written as JSON by walks that recurse, and one id nested
    past the stack stopped watch and check before they printed anything."""
    if depth > _CUT_DEPTH:
        return "…"
    if isinstance(value, (list, tuple)):
        return [_shallow(v, depth + 1) for v in value]
    if isinstance(value, dict):
        return {k: _shallow(v, depth + 1) for k, v in value.items()}
    return value


# ---------------------------------------------------------------------------
# Which action a record is.
#
# Each record has an id of 16 hex characters, the same on every run over
# the same history, for ranwhat ignore to name it by. It is a hash of
#
#   - the agent and the tool's name;
#   - when the call was made, as the agent wrote it, or the session where
#     it wrote no time;
#   - the call's id as the agent wrote it, or the hash of its input where
#     it wrote none;
#   - the rules it tripped, each with its severity, secret.literal aside.
#
# An agent that replays a call (a resumed session, a subagent's copy)
# writes both its time and its id again as they were, and neither can be
# chosen by what the model is told: an id the API issued, a time the
# client stamped. The input's hash is the last resort, since it changes
# when the index learns a value in it, or clean masks one. The session is
# only for a call with no time: a call replayed into another session is
# read from whichever file is newer first, so its session changes from
# run to run where its time does not. What the call's text says, its
# evidence and the transcript it is in are no part of it.
#
# The rules are there so that a later ranwhat that flags an old call for
# something more, or rates it otherwise, lists it again: what was
# expected of it before says nothing of what it is now. secret.literal is
# not, since clean masking the value takes it away; no entry ever hides a
# secret, so nothing is lost.
#
# A record stands for every copy of its call the scan found and kept one
# of (scan_all, scan_source, scan_openclaw_db): copies with no time, read
# from two sessions, or an OpenClaw call run again. Each copy has its own
# id, and "ids" holds them all, in order, where there is more than one;
# "id" is the first. Whichever copy is read first, the record's ids are
# the same, and one more copy is a new id among them.
# ---------------------------------------------------------------------------

_ACTION_ID = "ranwhat-action/1"
_SECRET_LITERAL = "secret.literal"


def action_id(record):
    """The id of one copy of an action, from what _record put in it."""
    pairs = sorted({(str(h.get("rule")), str(h.get("severity")))
                    for h in record.get("hits", ())
                    if h.get("rule") != _SECRET_LITERAL})
    stamp, call_id = record.get("timestamp"), record.get("tool_call_id")
    when = (["t", stamp] if isinstance(stamp, str) and stamp
            else ["s", record.get("session")])
    which = (["c", call_id] if call_id not in (None, "", [], {})
             else ["p", record.get("payload_hash")])
    parts = [_ACTION_ID, record.get("source"), record.get("tool_name"),
             when, which, [list(p) for p in pairs]]
    try:
        text = json.dumps(parts, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str)
    except (TypeError, ValueError):
        # An id an adapter gave as an object keyed by more than strings,
        # which sort_keys cannot order: as text, which still tells it apart.
        text = json.dumps([str(p) for p in parts], ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:16]


def _absolute_dir(path):
    """Whether path names a directory from the root of the machine the
    agent ran on, not this one: /x, X:\\x, X:/x or \\\\server\\share.
    os.path.isabs on Linux calls C:\\proj relative."""
    return isinstance(path, str) and (path.startswith(("/", "\\\\"))
                                      or bool(_DRIVE.match(path)))


def _cwd_of(call):
    """The directory a call ran in, when its agent says: the working
    directory it gave the call, joined to its project when it is relative,
    or the project where it gave none. A Claude Code project is a slug of
    the path, not the path, so only its own cwd is taken. None when no
    absolute one is known."""
    workdir, project = call.workdir, call.project
    if _absolute_dir(workdir):
        return workdir
    if isinstance(workdir, str) and workdir and _absolute_dir(project):
        joined = ntpath if not project.startswith("/") else posixpath
        return joined.join(project, workdir)
    if _absolute_dir(project) and call.source != "claude-code":
        return project
    return None


def _record(call, hits, payload, source):
    """The Action Record for a judged call that tripped a rule. Its tool's
    id is kept as the agent wrote it, an object too, so it is cut as a
    payload is. Its own id comes first (action_id), and "cwd" is where it
    ran, when that is known (_cwd_of)."""
    record = {"source": source, "session": call.session,
              "project": call.project}
    cwd = _cwd_of(call)
    if cwd:
        record["cwd"] = cwd
    record.update((
        ("timestamp", call.timestamp),
        ("tool_name", call.tool_name),
        ("tool_call_id", _shallow(call.tool_call_id)),
        ("payload_hash", _hash(payload)),
        ("severity", max(hits, key=lambda h: ["medium", "high", "critical"]
                         .index(h["severity"]))["severity"]),
        ("hits", hits),
    ))
    out = {"id": action_id(record)}
    out.update(record)
    return out


def _finish_ids(record, ids):
    """record with the ids of every copy of it the scan kept it for: "ids",
    sorted, after "id", which is the first of them. Nothing changes for a
    record that is one copy."""
    if len(ids) < 2:
        return record
    ids = sorted(ids)
    rest = [(k, v) for k, v in record.items() if k not in ("id", "ids")]
    record.clear()
    record["id"] = ids[0]
    record["ids"] = ids
    record.update(rest)
    return record


def public(records):
    """records as --json prints them: copies without the keys a scan keeps
    for itself, on the record and on each hit (a hit's _on, _subject and
    _cd). What a command matched is in its evidence already, masked; these
    are for ranwhat ignore, and change with how a rule reads a command."""
    out = []
    for record in records:
        if not isinstance(record, dict):
            out.append(record)
            continue
        shown = {k: v for k, v in record.items()
                 if not (isinstance(k, str) and k.startswith("_"))}
        hits = shown.get("hits")
        if isinstance(hits, list):
            shown["hits"] = [
                {k: v for k, v in hit.items()
                 if not (isinstance(k, str) and k.startswith("_"))}
                if isinstance(hit, dict) else hit for hit in hits]
        out.append(shown)
    return out


def _adapter_record(call, hits, payload):
    """_record for a call read through an adapter other than the two
    ported ones (design 3.5): its kind too, who ran it when that was the
    user, and that it never ran when the agent says so. "source" is the
    adapter's id, and "project" the call's working directory."""
    record = _record(call, hits, payload, call.source)
    record["kind"] = call.kind
    if call.actor == "user":
        record["actor"] = "user"
    if call.status == "declined":
        record["status"] = "declined"
    return record


# --------------------------------------------------------------------------
# Source: Claude Code JSONL transcripts
# --------------------------------------------------------------------------

_iter_claude_tool_calls = _claude.tool_uses
transcript_place = _claude.place
_transcripts = _claude.transcripts
discover = _claude.discover


def _claude_source():
    """The registry's Claude Code adapter, which counts what this run could
    not read for the report's notes (agents.notes), as _openclaw_source."""
    try:
        return _registry.get("claude-code")
    except KeyError:
        return _claude.ClaudeCodeSource()


def scan_transcript(path, source="claude-code", known=None):
    """Produce Action Records for one transcript, with `known` masked in
    them as evaluate masks it. A reader that fails part way keeps what it
    read until then, as scan_source does for every other adapter."""
    src = _claude_source()
    store = src.store_at(path)
    records = []
    try:
        for call in src.tool_calls(store):
            hits, payload = judge(call, known)
            if hits:
                records.append(_record(call, hits, payload, source))
    except Exception as error:          # one transcript must not stop the rest
        src.stopped(store, error)
    return records


def _epoch(stamp):
    """Seconds since the epoch for an action's own timestamp, or None when
    it has none that can be read. A stamp with no zone is taken as local
    time, which is how _local_time shows it."""
    when, _zoned = _parse_stamp(stamp)
    if when is None:
        return None
    try:
        return when.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _cutoff(since_days):
    return time.time() - since_days * 86400 if since_days else None


def _in_window(record, cutoff):
    """False only for an action whose own time is before the cutoff. One
    with no readable time is kept: dropping it could hide the one action
    that mattered, and render says it may be older."""
    if cutoff is None:
        return True
    when = _epoch(record.get("timestamp"))
    return when is None or when >= cutoff


def scan_all(root=None, since_days=None, limit=None, progress=None, known=None,
             unread=None):
    """Scan every transcript, reporting each distinct action once.

    The same tool call appears in more than one transcript -- resumed
    sessions and sidechains both replay it -- so without this the report
    shows the identical command two and three times.

    With since_days, an action is reported only if it happened inside the
    window. Windowing by file alone listed a 2025 deletion under "over 1
    days" because its transcript had been written to today.

    `progress` is called with (index, total, path) before each transcript
    is read, as clean.scan calls it: reading a large history takes
    seconds, and a run that shows nothing for that long looks hung.

    `known`, a known.Matcher, is masked in each record as evaluate masks it.

    Returns (records, how many transcripts it read): one this run counted
    as a file not read (agents.notes names it) is not among them. `unread`,
    a dict, is then given under "claude-code" how many it went through
    that were, so a caller can tell none read from none there.

    The record kept for a call has the id of every copy of it (_finish_ids).
    """
    records, scanned, seen = [], 0, {}
    cutoff = _cutoff(since_days)
    paths = discover(root, since_days)
    total = min(len(paths), limit) if limit else len(paths)
    for path in paths:
        if limit and scanned >= limit:
            break
        scanned += 1
        if progress:
            progress(scanned, total, path)
        for record in scan_transcript(path, known=known):
            if not _in_window(record, cutoff):
                continue
            key = (record["tool_name"], record["payload_hash"],
                   record.get("timestamp"))
            kept = seen.get(key)
            if kept is not None:
                kept[1].add(record["id"])
                continue
            seen[key] = (record, {record["id"]})
            records.append(record)
    for record, ids in seen.values():
        _finish_ids(record, ids)
    records.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    read = _claude_source().read_of(paths[:scanned])
    if unread is not None:
        unread["claude-code"] = scanned - read
    return records, read


_RANK = {MEDIUM: 0, HIGH: 1, CRITICAL: 2}

_STAMP = re.compile(
    r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,]\d+)?"
    r"\s*(Z|[+-]\d\d(?::?\d\d)?)?\Z", re.I)


def _parse_stamp(stamp):
    """(datetime, zoned) for an ISO 8601 timestamp, or (None, False). Parsed
    by hand: Python 3.9's fromisoformat takes neither Z nor every fraction.
    The window, the report's count of undated actions and each line ask it
    of the same stamp, so each is parsed once."""
    return _parse_text_stamp(stamp) if isinstance(stamp, str) else (None, False)


@functools.lru_cache(maxsize=4096)
def _parse_text_stamp(stamp):
    m = _STAMP.match(stamp.strip())
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


def _local_time(stamp):
    """A timestamp as the reader's wall clock shows it.

    Transcripts record UTC. Printed with the Z cut off, a reader in Tokyo saw
    an action from 7pm as 10am. A stamp with no zone is printed as written,
    because there is nothing to convert it from."""
    when, zoned = _parse_stamp(stamp)
    if when is None:
        return _printable(stamp[:19].replace("T", " ")).strip() \
            if isinstance(stamp, str) else ""
    if zoned:
        try:
            when = when.astimezone()
        except (ValueError, OverflowError, OSError):
            return when.strftime("%Y-%m-%d %H:%M:%S UTC")
    return when.strftime("%Y-%m-%d %H:%M:%S")


def _fit(text, limit):
    """text cut to `limit` columns, ending in an ellipsis where it was cut."""
    if len(text) <= limit:
        return text
    return text[:max(0, limit - 1)].rstrip() + "…"


def _days(days):
    return "1 day" if days == 1 else "%d days" % days


def _shown_path(path, limit):
    """A path as the reader may type it back: ~ for home, and cut in the
    middle on a narrow terminal, so where it starts and where it ends both
    stay readable."""
    home = os.path.expanduser("~")
    if home not in ("", "/", "~") and (path == home
                                       or path.startswith(home + os.sep)):
        path = "~" + path[len(home):]
    path = _printable(path)
    if len(path) <= limit:
        return path
    keep = max(2, limit - 1)
    return path[:keep // 2] + "…" + path[len(path) - (keep - keep // 2):]


# How to point Claude Code's reader elsewhere. --root takes the directory
# the transcripts are in and CLAUDE_CONFIG_DIR the one above it, and "pass
# --root PATH or set CLAUDE_CONFIG_DIR" gave them as one: --root ~/.claude
# read nothing, and the hint repeated the advice that had just failed.
ELSEWHERE = ("--root DIR/projects or set CLAUDE_CONFIG_DIR=DIR, where DIR "
             "is what Claude Code uses in place of ~/.claude")


def projects_hint(place, limit=4096):
    """For a Claude Code place that holds no transcript but whose projects
    directory does, which flag reads it, with its paths cut to limit."""
    inner = place["projects"]
    shown = _shown_path(inner["path"], limit)
    config = "CLAUDE_CONFIG_DIR="
    return ("--root takes the projects directory, and %s holds %d "
            "transcript(s). To read them, pass --root %s or set %s%s instead."
            % (shown, inner["found"], shown, config,
               _shown_path(place["path"], max(8, limit - len(config)))))


def _nothing_read(days, places, width):
    """Lines for a scan that read no transcript. Never an all-clear: a
    mistyped --root, a fresh machine and history kept elsewhere all read
    nothing, and each printed "Nothing flagged"."""
    from .report import DIM, YEL

    def say(text, paint):
        return ["  " + paint(line[2:]) for line in term.wrap(text)]

    found = sum(p["found"] for p in places or ())
    if found and days:
        # All of it older than the window: --days, not --root, is the fix.
        return (say("No transcripts from the last %s, so nothing was "
                    "checked." % _days(days), YEL)
                + say("%d older transcript(s) found. Pass a larger --days "
                      "to read them." % found, DIM) + [""])
    if places is None:
        L = say("No transcripts found%s, so nothing was checked." % (
            " in the last %s" % _days(days) if days else ""), YEL)
        L += say("If your agent history is kept somewhere else, pass %s, "
                 "or --state-dir PATH for OpenClaw." % ELSEWHERE, DIM)
        if days:
            L += say("To read further back, pass a larger --days.", DIM)
        return L + [""]
    L = say("No transcripts found, so nothing was checked.", YEL)
    L.append(DIM("  Looked in:"))
    # Names in a column as wide as the longest, but never so wide that a
    # path has no room beside it: then it goes on the line under its name.
    names = [_SOURCE_NAMES.get(p["source"], p["source"]) for p in places]
    pad = max([12] + [len(n) for n in names])
    for name, p in zip(names, places):
        if 4 + pad + 1 + 16 <= width:
            L.append(DIM("    %-*s %s" % (pad, name, _shown_path(
                p["path"], width - 5 - pad))))
        else:
            L.append(DIM("    " + _fit(name, width - 4)))
            L.append(DIM("      " + _shown_path(p["path"], width - 6)))
    sources = [p["source"] for p in places]
    inner = [p for p in places if p.get("projects")]
    for p in inner:
        L += say(projects_hint(p, width - 4), DIM)
    if "claude-code" in sources and not inner:
        L += say("If Claude Code keeps its history somewhere else, pass %s."
                 % ELSEWHERE, DIM)
    for source_id in dict.fromkeys(sources):
        if source_id in _agents.PORTED:
            continue
        source = _registry.get(source_id)
        L += say("For %s, pass --path %s=PATH, where PATH is %s."
                 % (source.name, source.id, source.path_means), DIM)
    if "openclaw" in sources:
        L += say("For OpenClaw, pass --state-dir PATH or set "
                 "OPENCLAW_STATE_DIR.", DIM)
    L += say("ranwhat sources lists every agent ranwhat reads, and where "
             "each keeps its history.", DIM)
    return L + [""]


def _total(scanned):
    return sum(scanned.values()) if isinstance(scanned, dict) else scanned


def _scanned_words(scanned):
    """What a scan read, in its own units. An OpenClaw database is one per
    agent, not a transcript: counted as one, check said 2 transcripts where
    clean, which then read no OpenClaw, said 1. (A report that read
    anything names each agent instead: _head.)"""
    if not isinstance(scanned, dict):
        return "%d transcript(s)" % scanned
    transcripts, databases = scanned.get("claude-code", 0), scanned.get("openclaw", 0)
    if not databases:
        return "%d transcript(s)" % transcripts
    if not transcripts:
        return "%d OpenClaw database(s)" % databases
    return "%d transcript(s) and %d OpenClaw database(s)" % (transcripts, databases)


@functools.lru_cache(maxsize=256)
def _why_lines(why, width):
    """A hit's why, wrapped under it. A rule's why is the same for every
    hit, so each is wrapped once a report."""
    lines = term.wrap(why, indent=" " * 9, limit=width)
    if lines:
        lines[0] = "      -> " + lines[0][9:]
    return tuple(lines)


# The header of watch's report: its name, and what it is.
TITLE = ("  ranwhat watch  ", "· local agent flight recorder")


def render(records, scanned, days, footer=True, locations=None, notes=None,
           title=TITLE, complete=True, unread=0, ignored=0):
    """`footer=False` is for check, which prints one footer for all sections.
    It gates only the closing rule and footer line, never a finding.

    `ignored` is how many actions the ignore file left out of `records`
    (ignore.py): the count line says so, and with none left to list the
    report says that nothing flagged is not ignored, never a bare "Nothing
    flagged", which would read as nothing having happened. Each record
    carries its id at the end of its line, for ranwhat ignore to name it
    by, and under --no-ignore the lines of the file that would leave it out
    ("ignored"); neither is ever cut.

    `complete` is False when a store, line or call went unread this run
    (agents.all_read): then nothing flagged is not said to be everything.

    `title` is the header, (name, what it is): check gives its own when
    this is all it prints above its tail, with nothing read. A header too
    wide for the terminal puts what it is on the line under the name.

    `scanned` is how many transcripts were read, or what
    scan_sources_counted returned, which keeps OpenClaw's databases apart.

    `locations` is what locations() returned for the same scan. With it, a
    scan that read nothing says where it looked, or that everything there
    is older than the window; without it, it still says nothing was read
    rather than that nothing was flagged.

    `notes` are sentences printed under the records: what an agent's
    history held that could not be read (notes()).

    `unread` is how many files the scan found and could not read
    (scan_sources_counted's). With some, a scan that read nothing is not
    one that found nothing: its notes say why, under "Nothing flagged",
    which `complete` keeps from being said of everything.

    A record with several hits is headed by its most severe one, and each
    hit's evidence and why print under that hit's own title: a deletion
    listed under "Credential material accessed" reads as a credential read.
    Evidence is cut to the terminal and marked where it was cut, and each
    why is wrapped rather than sliced mid-word."""
    from . import clean
    from .report import painters
    BOLD, DIM, RED, YEL, GRN, CYA = painters()
    colour = {CRITICAL: RED, HIGH: YEL, MEDIUM: CYA}
    width = term.width()
    head = _head(scanned, days)
    # Each record says which agent ran it, unless every one is Claude
    # Code's: then the line above says so once.
    labelled = isinstance(scanned, dict) and any(
        n for source, n in scanned.items() if source != "claude-code")
    scanned = _total(scanned)
    name, tagline = title
    if len(name + tagline) <= width:
        L = ["", BOLD(name) + DIM(tagline)]
    else:
        L = ["", BOLD(name.rstrip()), DIM("  " + tagline[2:])]
    L += [DIM(term.rule("-"))] + head + [""]
    notes = [DIM(line) for note in notes or () for line in term.wrap(note)]
    if not records and not scanned and not unread:
        L += _nothing_read(days, locations, width)
        return "\n".join(L)
    if not records:
        if ignored:
            said = ("Every call was read; each one that tripped a rule is "
                    "left out by your ignore file, as the note below says."
                    if complete else
                    "Each call that was read and tripped a rule is left out "
                    "by your ignore file, as the note below says, but some "
                    "could not be read.")
            L += ["  " + GRN("Nothing flagged that is not ignored.")]
        else:
            said = ("Every call was read; none tripped a rule." if complete else
                    "No call that was read tripped a rule, but some could not "
                    "be read.")
            L += ["  " + GRN("Nothing flagged.")]
        L += [DIM(line) for line in term.wrap(said, limit=width)] + [""]
        if notes:
            L += notes + [""]
        return "\n".join(L)

    counts = {}
    for r in records:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    L.append("  " + "  ".join(colour[k](BOLD("%d %s" % (v, k)))
                              for k, v in sorted(counts.items()))
             + (DIM("   (%d ignored)" % ignored) if ignored else ""))
    undated = sum(1 for r in records if _epoch(r.get("timestamp")) is None)
    if undated and days:
        # Kept by the window, since it cannot be placed in it or out of it,
        # so not claimed to be inside it.
        note = ("1 of these has no readable time, so it may be older"
                if undated == 1 else
                "%d of these have no readable time, so they may be older"
                % undated)
        L += [DIM(line) for line in term.wrap(
            "%s than %s." % (note, _days(days)))]
    L.append("")
    for r in records:
        hits = sorted(r["hits"], key=lambda h: -_RANK.get(h.get("severity"), -1))
        title = hits[0]["title"]
        where = "  ".join(p for p in (
            _local_time(r.get("timestamp")),
            _SOURCE_NAMES.get(r.get("source"), "") if labelled else "",
            _printable(str(r.get("tool_name") or ""))) if p)
        marks = [p for p in (_RAN.get(r.get("actor")), _RAN.get(r.get("status")),
                             _ignored_by(r.get("ignored")), _shown_id(r)) if p]
        ran = "  ".join(marks)
        meta = "  ".join(p for p in (where, ran) if p)
        paint = colour.get(r["severity"], DIM)
        if meta and len("  * %s   %s" % (title, meta)) <= width:
            L.append("  " + paint("* ") + BOLD(title) + DIM("   " + meta))
        else:
            # Too long for one line: when and where go on the next, and
            # who ran it, the lines that leave it out and its id on lines
            # of their own when they do not fit there, never cut: a cut
            # there read a declined deletion as one that ran, and an id
            # cut short names no action.
            L.append("  " + paint("* ") + BOLD(_fit(title, width - 4)))
            if meta and len("      " + meta) <= width:
                L.append(DIM("      " + meta))
            else:
                if where:
                    L.append(DIM(_fit("      " + where, width)))
                line = ""
                for mark in marks:
                    if line and len("      " + line + "  " + mark) > width:
                        L.append(DIM("      " + line))
                        line = ""
                    line = line + "  " + mark if line else mark
                if line:
                    L.append(DIM("      " + line))
        for i, h in enumerate(hits):
            if i:
                label = "%s (%s)" % (h["title"], h["severity"])
                if len(label) > width - 6:
                    label = _fit(h["title"], width - 6)
                L.append("    " + colour.get(h["severity"], DIM)("+ ")
                         + BOLD(label))
            # Masked again here, for records this module did not build.
            evidence = h.get("evidence") or ""
            if evidence not in _MASKED_HERE:
                evidence = clean.mask_for_display(evidence)
            L.append(DIM("      " + _fit(_printable(evidence), width - 6)))
            L += [DIM(line) for line in _why_lines(h.get("why") or "", width)]
        L.append("")
    if notes:
        L += notes + [""]
    if footer:
        L += [DIM(term.rule("-")), DIM(term.FOOTER), ""]
    return "\n".join(L)


# What the meta line of a record adds for a command the user typed into
# the agent, and for one the agent says never ran (design 3.5).
_RAN = {"user": "(you ran this)", "declined": "(declined, did not run)"}
_ID_SHAPE = re.compile(r"[0-9a-f]{16}\Z")


def _ignored_by(lines):
    """What the meta line says of an action --no-ignore lists that the
    ignore file would leave out: the lines that do."""
    if not isinstance(lines, list) or not lines:
        return ""
    lines = [str(n) for n in lines if isinstance(n, int)]
    if not lines:
        return ""
    return "(ignored by line%s %s)" % ("s" if len(lines) > 1 else "",
                                       ", ".join(lines))


def _shown_id(record):
    """An action's id, as ranwhat ignore takes it; "" for a record no scan
    gave one."""
    found = record.get("id")
    return found if isinstance(found, str) and _ID_SHAPE.match(found) else ""


def _head(scanned, days):
    """The line under the title: what was read, and how far back. A scan
    that read anything names each agent and how much of its history it
    read ("Read Claude Code: 429 transcripts; Codex: 12 sessions"), only
    the agents it read; one given a bare count, as before."""
    said = _agents.read_words(scanned) if isinstance(scanned, dict) else None
    if not said:
        head = "  %s scanned" % _scanned_words(scanned)
        if days:
            head += ", last %s" % _days(days)
        return [head]
    if days:
        said += ", last %s" % _days(days)
    return term.wrap(said)


# --------------------------------------------------------------------------
# Source: OpenClaw (ranwhat/sources/openclaw.py: where it is, the schema
# discovered at runtime, and tool calls recognised by shape)
# --------------------------------------------------------------------------

OPENCLAW_STATE_DEFAULT = _openclaw.STATE_DEFAULT
openclaw_state_dir = _openclaw.state_dir
openclaw_databases = _openclaw.databases
_open_readonly = _sqlite.open_readonly
_quote_ident = _sqlite.quote_ident
_as_iso = _openclaw.as_iso
_find_tool_calls = _openclaw.find_tool_calls


def _openclaw_source():
    """The registry's OpenClaw adapter: the one clean and the index read
    with, so a database that cannot be read warns once a run and is named
    in the report's notes (agents.notes)."""
    try:
        return _registry.get("openclaw")
    except KeyError:
        return _openclaw.OpenClawSource()


def scan_openclaw_db(path, source="openclaw", known=None, src=None,
                     cutoff=None):
    """Action Records for one OpenClaw database, with `known` masked in
    them as evaluate masks it. A call repeated in the database is one
    record, its latest copy since `cutoff` (an epoch, or None for all of
    them). Kept as the first copy and windowed after, a call run again
    inside the window went unreported when it had also run before it.
    `src` is the adapter that reads it, a fresh one by default.

    The record kept for a call has the id of every copy of it inside the
    window, whichever copy it is (_finish_ids): each run is an action of
    its own, so one run more is something new to list."""
    src = src or _openclaw.OpenClawSource()
    store = src.store_at(path)
    records, seen, aliases = [], {}, []
    try:
        for call in src.tool_calls(store):
            hits, payload = judge(call, known)
            if not hits:
                continue
            record = _record(call, hits, payload, source)
            if not _in_window(record, cutoff):
                continue
            key = (call.tool_name, record["payload_hash"])
            at = seen.setdefault(key, len(records))
            if at == len(records):
                records.append(record)
                aliases.append({record["id"]})
                continue
            aliases[at].add(record["id"])
            if (_epoch(record["timestamp"]) or 0) > (
                    _epoch(records[at]["timestamp"]) or 0):
                records[at] = record
    except Exception as error:          # one database must not stop the rest
        src.stopped(store, error)
    for record, ids in zip(records, aliases):
        _finish_ids(record, ids)
    return records


def scan_openclaw(state_dir=None, since_days=None, known=None, progress=None,
                  done=0, total=None, dbs=None, unread=None):
    """Every database is read whatever its mtime: a live agent's recent
    rows can sit in its -wal file while the database itself looks old.
    With since_days, each action is kept by its own time, as in scan_all.
    `progress` is called with (done + i, total, path) before the i-th.
    `dbs` are the databases, when the caller has listed them already.
    Returns (records, how many databases it read), and fills `unread`,
    as scan_all does."""
    records, cutoff = [], _cutoff(since_days)
    dbs = openclaw_databases(state_dir) if dbs is None else dbs
    total = done + len(dbs) if total is None else total
    src = _openclaw_source()
    for i, db in enumerate(dbs, 1):
        if progress:
            progress(done + i, total, db)
        records.extend(scan_openclaw_db(db, known=known, src=src, cutoff=cutoff))
    read = src.read_of(dbs)
    if unread is not None:
        unread["openclaw"] = len(dbs) - read
    return records, read


# The sources watch reads: every adapter in the registry, in its order,
# Claude Code first and OpenClaw near the end (design 4.2). Claude Code and
# OpenClaw are read by scan_all and scan_openclaw above, the others through
# their adapters.
SOURCES = _registry.ids()
_SOURCE_NAMES = {i: _registry.get(i).name for i in SOURCES}


def _in_window_call(record, call, cutoff):
    """_in_window, and for a call with no readable time of its own, the
    latest time it can have happened (design 3.5): a call cannot be newer
    than the last write of the store that holds it, so a two-year-old
    session does not show up in every --days 30 report."""
    if cutoff is None:
        return True
    when = _epoch(record.get("timestamp"))
    if when is not None:
        return when >= cutoff
    latest = _epoch(call.not_after) if call.not_after else None
    return latest is None or latest >= cutoff


def scan_source(source, stores, since_days=None, known=None, progress=None,
                done=0, total=None):
    """Action Records for the tool calls in these stores of one adapter,
    each distinct action once, as scan_all reports Claude Code's. `stores`
    are its transcripts (agents.discover). `progress` is called with (done
    + i, total, path) before the i-th is read. An adapter that fails part
    way warns once, and what it read until then is kept. The record kept
    for a call has the id of every copy of it, as scan_all's has: a call
    with no time, read in two sessions, is one record whichever session is
    read first."""
    records, seen = [], {}
    cutoff = _cutoff(since_days)
    total = len(stores) + done if total is None else total
    for i, store in enumerate(stores, 1):
        if progress:
            progress(done + i, total, store.path)
        try:
            for call in source.tool_calls(store):
                hits, payload = judge(call, known)
                if not hits:
                    continue
                record = _adapter_record(call, hits, payload)
                if not _in_window_call(record, call, cutoff):
                    continue
                key = (record["tool_name"], record["payload_hash"],
                       record.get("timestamp"))
                kept = seen.get(key)
                if kept is not None:
                    kept[1].add(record["id"])
                    continue
                seen[key] = (record, {record["id"]})
                records.append(record)
        except Exception as error:      # one adapter must not stop the others
            source.stopped(store, error)
    for record, ids in seen.values():
        _finish_ids(record, ids)
    return records


def scan_sources_counted(sources=SOURCES, root=None, state_dir=None,
                         since_days=None, progress=None, known=None,
                         paths=None, unread=None):
    """Scan every requested local agent source into one record stream.

    Returns (records, {source: how many it read}): Claude Code transcripts,
    OpenClaw databases, and each other agent's transcripts (its sessions,
    in its own words). A store this run counted as a file not read, in this
    pass or an earlier one, is not among them (agents.notes names it), and
    `unread`, a dict, is given how many of each agent's there were, so a
    caller can tell a scan that could read none of what it found from one
    that found nothing. Zero
    read is not an all-clear: locations() says whether there was anything
    to read at all. `progress` is scan_all's, counting every source's
    transcripts together, and `known` (a known.Matcher) is masked in every
    record.

    root and state_dir point Claude Code and OpenClaw elsewhere; `paths`,
    {source id: path}, points any source, and a root or state_dir given
    as well wins over it."""
    paths = paths or {}
    root = root or paths.get("claude-code")
    state_dir = state_dir or paths.get("openclaw")
    records, counts = [], {}
    unread = {} if unread is None else unread
    # Only the agents with transcripts to read are counted: one that is
    # not on this machine is not named in the report.
    others = []
    for source in _agents.adapters(sources):
        _locations, stores = _agents.discover(source, paths.get(source.id),
                                              since_days)
        stores = _agents.transcripts(stores)
        if stores:
            others.append((source, stores))
    # Listed once, for the progress total and for reading them.
    databases = openclaw_databases(state_dir) if "openclaw" in sources else []
    extra = sum(len(stores) for _source, stores in others) + len(databases)
    done = 0
    if "claude-code" in sources:
        step = progress
        if progress and extra:
            def step(i, total, path):
                progress(i, total + extra, path)
        recs, counts["claude-code"] = scan_all(root=root, since_days=since_days,
                                               progress=step, known=known,
                                               unread=unread)
        records += recs
        done = counts["claude-code"] + unread.get("claude-code", 0)
    for source, stores in others:
        records += scan_source(source, stores, since_days, known, progress,
                               done, done + extra)
        counts[source.id] = source.read_of(store.path for store in stores)
        unread[source.id] = len(stores) - counts[source.id]
        done += len(stores)
        extra -= len(stores)
    if "openclaw" in sources:
        recs, counts["openclaw"] = scan_openclaw(
            state_dir=state_dir, since_days=since_days, known=known,
            progress=progress, done=done, total=done + extra, dbs=databases,
            unread=unread)
        records += recs
    records.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return records, counts


def scan_sources(sources=SOURCES, root=None, state_dir=None, since_days=None):
    """scan_sources_counted, with every source's count added up."""
    records, counts = scan_sources_counted(sources, root, state_dir, since_days)
    return records, sum(counts.values())


def locations(sources=SOURCES, root=None, state_dir=None, paths=None,
              asked=()):
    """Where each requested source keeps its history, and how many
    transcripts are there whatever their age:
    [{"source": ..., "path": ..., "found": n}], JSON as it is.

    What tells "nothing to read" from "read, and nothing tripped": no
    transcripts found anywhere means a wrong --root, a fresh machine, or
    history kept somewhere else, and must not read as an all-clear.

    Claude Code and OpenClaw are always named when asked for, as before.
    Any other agent is named where it keeps transcripts, where `paths`
    ({source id: path}) points it, and, at every place it looks, when
    `asked` (the ids --source named) holds it: --source grok on a machine
    with no ~/.grok said "Looked in:" and nothing under it. In a run of
    every agent, one that is not on this machine is not listed (`ranwhat
    sources` lists every one)."""
    paths = paths or {}
    root = root or paths.get("claude-code")
    state_dir = state_dir or paths.get("openclaw")
    out = []
    if "claude-code" in sources:
        path = root or claude_projects()
        place = {"source": "claude-code", "path": path,
                 "found": len(_transcripts(path))}
        # --root takes the projects directory, and ~/.claude is the obvious
        # path to give it. With none there, one holding transcripts inside
        # it is named, as "projects": {"path": ..., "found": n}.
        inner = os.path.join(path, "projects")
        if not place["found"] and os.path.isdir(inner):
            n = len(_transcripts(inner))
            if n:
                place["projects"] = {"path": inner, "found": n}
        out.append(place)
    asked = set(asked or ())
    for source in _agents.adapters(sources):
        pointed = paths.get(source.id)
        named = pointed or source.id in asked
        for loc in source.locations(pointed):
            n = (len(_agents.transcripts(source.stores([loc])))
                 if loc.found else 0)
            if n or named:
                out.append({"source": source.id, "path": loc.path, "found": n})
    if "openclaw" in sources:
        path = state_dir or openclaw_state_dir()
        out.append({"source": "openclaw", "path": path,
                    "found": len(openclaw_databases(path))})
    return out
