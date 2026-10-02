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
import datetime
import functools
import shlex
import hashlib
import json
import os
import posixpath
import re
import time

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
                 paths=False, find=None, hide=None):
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


def _first_secret(text):
    """Span of the earliest credential in text, so the evidence sits on it
    and not on a fixture beside it."""
    spans = _secret_spans(text)
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
    spans = _secret_spans(text)
    if known:
        # What is about to be shown is asked too for a value known only by
        # its mask, in every stretch, glued to letters or not, and in what
        # the window would cut (known.Matcher).
        spans = known.merged(text, spans, shown=(lo, hi))
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
    snippet = _printable("".join(out)).strip()
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
# and 63K of them took two seconds.
_CRED_PATH = re.compile(
    r"(?:^|[\s\"'=(])((?:[\w./~$-]*/)?(?:\.env[\w.-]*|credentials|"
    r"\.netrc|id_[a-z0-9]+(?:\.pub)?|[\w.-]*\.pem|[\w.-]*\.key|\.kube/config|"
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
            sender = _NETWORK_SENDER.match(text, at, end)
            if sender:
                return reader, sender.end()
        else:
            found = _FILE_READER.match(text, at, end)
            if found and _reads_a_file(found.group("reader"),
                                       text[found.start("reader"):end]):
                reader = at
        if op != "|":
            reader = None
    return None


REFINERS = {"fs.destructive": _refine_deletion,
            "cred.read": _refine_credential}
PATH_REFINERS = {"cred.read": _refine_read_path}


RULES = [
    Rule("cred.read", CRITICAL,
         "Credential material accessed",
         "The agent read a file whose only purpose is to hold secrets. Whatever "
         "it read is now in a model context you do not control.",
         [r"(?:^|[\s\"'=/])\.env(?:\.[\w-]+)?\b",
          r"\.aws/credentials", r"\.ssh/id_[\w]+", r"\.netrc",
          r"\.config/gcloud", _Gap(r"service[-_]account", r"\.json", "\n"),
          r"security\s+find-generic-password", r"\.kube/config"],
         paths=True, hide=_without_writes),

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
          r"aws\s+s3\s+rm\b", r"aws\s+iam\s+(?:put|attach|create)-[\w-]+",
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


def _strip_heredocs(command):
    """Remove heredoc bodies. The body is data being written to disk, not a
    sequence of commands being executed. A << with no line of its word
    after it is not one (1 << x in a python -c string), and is kept.

    The operator stays as it was written, `<<'EOF'`. A placeholder here
    was quoted as evidence, and read as `<redacted` by _REDACTING, which
    made any read beside a heredoc look deliberately masked.

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
    out, copied, pos = [], 0, 0
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


def _substitutions(text, quoted=False):
    """The text inside each outermost $( ) and `...` of text that the shell
    runs, in order, read as far as MAX_SCAN_CHARS. One left open runs to
    the end. A substitution inside another is in the text of the outer
    one, and is found when that is judged. quoted: text is inside double
    quotes."""
    end = min(len(text), MAX_SCAN_CHARS)
    stack = [['"' if quoted else "top", 0, 0]]     # [kind, body start, parens]
    bodies, opened, pos = [], 0, 0
    while pos < end:
        context = stack[-1]
        m = _SUB_CONTEXT[context[0]].search(text, pos, end)
        if not m:
            break
        token, pos = m.group(), m.end()
        if token == "$(" or (token == "`" and context[0] != "`"):
            stack.append([token, pos, 0])
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
                bodies.append(text[context[1]:m.start()])
        elif token == ")":
            context[2] -= 1
    for context in stack:
        if context[0] in ("$(", "`"):
            bodies.append(text[context[1]:end])       # left open
            break
    return bodies


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
# so a run of options is read once.
_OPTIONS = r"(?:\s+-[^\s|;&]*(?:\s+[^\s|;&=-][^\s|;&]*)?)*"
_HANDS_ON = (
    r"(?:[^\s|;&]*/)?(?:(?:sudo|doas)" + _OPTIONS
    + r"|env(?:\s+-[^\s|;&]*(?:\s+[^\s|;&=-][^\s|;&=]*)?"
    r"|\s+[A-Za-z_][A-Za-z0-9_]*=[^\s|;&]*)*"
    r"|command(?:\s+-p)*|exec" + _OPTIONS + r"|nohup|nice(?:\s+-n)?(?:\s+-?\d+)?)\s+")
_INTO_SHELL = re.compile(
    r"\|&?\s*(?:" + _HANDS_ON + r")*(?:[^\s|;&]*/)?"
    r"(?:sh|bash|zsh|dash|ksh|fish)(?![\w.-])")
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


def _reduce_segment(segment, depth, into_shell=False):
    """What runs of one segment, or None when nothing does. into_shell
    says the command pipes into a shell, which runs what was text."""
    foreign = _FOREIGN_PAYLOAD.match(segment)
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

    if binary in _FOREIGN_INTERPRETERS and payload_idx is not None:
        return " ".join(argv[:payload_idx + 1])
    if binary in _SHELL_INTERPRETERS and payload_idx is not None:
        head = " ".join(argv[:payload_idx + 1])
        body = argv[payload_idx + 1] if payload_idx + 1 < len(argv) else ""
        return head + " " + _executable_text(body, depth + 1)
    return _quoted_commands_elided(segment, into_shell)


def _executable_text(command, depth=0, limit=None):
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
    """
    if not command or depth > 3:
        return command or ""
    command = _strip_heredocs(command)
    bodies = []
    command = _neutralize_foreign_payloads(command, bodies)

    out, flowing, kept_chars = [], False, 0
    into_shell = "|" in command and _INTO_SHELL.search(command) is not None
    for raw, piped in _segments(command):
        segment = _COMMENT.sub("", raw).strip()
        kept = (None if not segment or _is_inert(segment, into_shell)
                else _reduce_segment(segment, depth, into_shell))
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
        inner = _executable_text(body, depth + 1, limit)
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
        return " ".join(str(c) for c in value)
    return value if isinstance(value, str) else ""


def _shell_text(tool_name, tool_input):
    """The parts of a shell tool's command that run, or "" for any other
    tool. A command longer than MAX_SCAN_CHARS is cut after reduction, not
    before, so a heredoc keeps the terminator that marks its body as data."""
    if _base_name(tool_name) not in _SHELL_TOOLS:
        return ""
    if not isinstance(tool_input, dict):
        tool_input = {"_value": tool_input}
    commands = [c for c in (_words(tool_input.get(k)) for k in _COMMAND_KEYS)
                if c]
    argv = " ".join(a for a in (_words(tool_input.get(k)) for k in _ARGV_KEYS)
                    if a)
    if argv:
        commands = commands[:-1] + [" ".join(commands[-1:] + [argv])]
    parts = [_executable_text(c, limit=MAX_SCAN_CHARS) for c in commands]
    return " ; ".join(p for p in parts if p)[:MAX_SCAN_CHARS]


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
                found.append(path)
    return "\n".join(found)[:MAX_SCAN_CHARS]


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


def _masked(obj, depth=0, known=None):
    from . import clean
    if isinstance(obj, str):
        # The spans the rules found for this text already, when they did,
        # and with known every copy of a value clean finds anywhere.
        spans = _secret_spans(obj)
        if known:
            spans = known.merged(obj, spans)
        return clean.mask_for_display(obj, spans)
    if depth > 32:
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


def evaluate(tool_name, tool_input, known=None):
    """Return (hits, payload) for one tool call: the rules it trips, and the
    whole input as masked text for telling flagged calls apart ("" when
    nothing tripped, since then there is nothing to tell apart). `known`,
    a known.Matcher, is every value clean finds in the history, masked in
    both wherever a copy starts."""
    shell = _shell_text(tool_name, tool_input)
    paths = _read_paths(tool_name, tool_input)
    raw = _raw_strings(tool_input)

    hits = []
    for rule in RULES:
        # (subject, what the rule judges in it, refiners). The two differ
        # only by what rule.hide blanks, so a span in one is a span in both.
        if rule.scan_raw:
            subjects = [(s, s, REFINERS) for s in raw]
        else:
            seen = rule.hide(shell) if rule.hide and shell else shell
            subjects = [(shell, seen, REFINERS)]
            if rule.paths:
                subjects.append((paths, paths, PATH_REFINERS))
        for subject, seen, refiners in subjects:
            if not subject:
                continue
            span = rule.match(seen)
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
            hits.append({"rule": rule.id, "severity": severity,
                         "title": rule.title, "why": why,
                         "evidence": _evidence(subject, span, known=known)})
            break
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
    working directory kept; a known read, by the paths it opened. Anything
    else, and a shell or read call whose command or paths were not found,
    answers only to the rules that read every string: file content is not
    an action."""
    if call.kind is None or not call.known:
        return evaluate(call.tool_name, call.tool_input, known)
    rest = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.kind == "shell" and call.command:
        judged = dict(rest, command=call.command)
        if call.workdir:
            judged["workdir"] = call.workdir   # keeps _deletion_context conservative
        return evaluate("Bash", judged, known)
    if call.kind == "read" and call.paths:
        return evaluate("Read", dict(rest, paths=list(call.paths)), known)
    return evaluate(NEUTRAL % call.kind, call.tool_input, known)


def _record(call, hits, payload, source):
    """The Action Record for a judged call that tripped a rule."""
    return {
        "source": source,
        "session": call.session,
        "project": call.project,
        "timestamp": call.timestamp,
        "tool_name": call.tool_name,
        "tool_call_id": call.tool_call_id,
        "payload_hash": _hash(payload),
        "severity": max(hits, key=lambda h: ["medium", "high", "critical"]
                        .index(h["severity"]))["severity"],
        "hits": hits,
    }


# --------------------------------------------------------------------------
# Source: Claude Code JSONL transcripts
# --------------------------------------------------------------------------

_iter_claude_tool_calls = _claude.tool_uses
transcript_place = _claude.place
_transcripts = _claude.transcripts
discover = _claude.discover


def scan_transcript(path, source="claude-code", known=None):
    """Produce Action Records for one transcript, with `known` masked in
    them as evaluate masks it."""
    src = _claude.ClaudeCodeSource()
    records = []
    for call in src.tool_calls(src.store_at(path)):
        hits, payload = judge(call, known)
        if hits:
            records.append(_record(call, hits, payload, source))
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


def scan_all(root=None, since_days=None, limit=None, progress=None, known=None):
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
    """
    records, scanned, seen = [], 0, set()
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
            if key in seen:
                continue
            seen.add(key)
            records.append(record)
    records.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return records, scanned


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
    for p in places:
        L.append(DIM("    %-12s %s" % (_SOURCE_NAMES.get(p["source"], p["source"]),
                                       _shown_path(p["path"], width - 17))))
    sources = [p["source"] for p in places]
    inner = [p for p in places if p.get("projects")]
    for p in inner:
        L += say(projects_hint(p, width - 4), DIM)
    if "claude-code" in sources and not inner:
        L += say("If Claude Code keeps its history somewhere else, pass %s."
                 % ELSEWHERE, DIM)
    if "openclaw" in sources:
        L += say("For OpenClaw, pass --state-dir PATH or set "
                 "OPENCLAW_STATE_DIR.", DIM)
    return L + [""]


def _total(scanned):
    return sum(scanned.values()) if isinstance(scanned, dict) else scanned


def _scanned_words(scanned):
    """What a scan read, in its own units. An OpenClaw database is one per
    agent, not a transcript, and clean, which counts transcripts, reads
    none: counted together, check said 2 where clean said 1."""
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


def render(records, scanned, days, footer=True, locations=None):
    """`footer=False` is for check, which prints one footer for all sections.
    It gates only the closing rule and footer line, never a finding.

    `scanned` is how many transcripts were read, or what
    scan_sources_counted returned, which keeps OpenClaw's databases apart.

    `locations` is what locations() returned for the same scan. With it, a
    scan that read nothing says where it looked, or that everything there
    is older than the window; without it, it still says nothing was read
    rather than that nothing was flagged.

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
    head = "  %s scanned" % _scanned_words(scanned)
    scanned = _total(scanned)
    if days:
        head += ", last %s" % _days(days)
    L = ["", BOLD("  ranwhat watch  ") + DIM("· local agent flight recorder"),
         DIM(term.rule("-")), head, ""]
    if not records and not scanned:
        L += _nothing_read(days, locations, width)
        return "\n".join(L)
    if not records:
        L += ["  " + GRN("Nothing flagged."),
              DIM("  Every tool call was read, none tripped a rule."), ""]
        return "\n".join(L)

    counts = {}
    for r in records:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    L.append("  " + "  ".join(colour[k](BOLD("%d %s" % (v, k)))
                              for k, v in sorted(counts.items())))
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
        meta = "  ".join(p for p in (
            _local_time(r.get("timestamp")),
            _printable(str(r.get("tool_name") or ""))) if p)
        paint = colour.get(r["severity"], DIM)
        if meta and len("  * %s   %s" % (title, meta)) <= width:
            L.append("  " + paint("* ") + BOLD(title) + DIM("   " + meta))
        else:
            # Too long for one line: when and where go on the next.
            L.append("  " + paint("* ") + BOLD(_fit(title, width - 4)))
            if meta:
                L.append(DIM(_fit("      " + meta, width)))
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
    if footer:
        L += [DIM(term.rule("-")), DIM(term.FOOTER), ""]
    return "\n".join(L)


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


def scan_openclaw_db(path, source="openclaw", known=None):
    """Action Records for one OpenClaw database, with `known` masked in
    them as evaluate masks it. A call repeated in the database is one
    record, the first, whatever its time."""
    src = _openclaw.OpenClawSource()
    records, seen = [], set()
    for call in src.tool_calls(src.store_at(path)):
        hits, payload = judge(call, known)
        if not hits:
            continue
        key = (call.tool_name, _hash(payload))
        if key in seen:
            continue
        seen.add(key)
        records.append(_record(call, hits, payload, source))
    return records


def scan_openclaw(state_dir=None, since_days=None, known=None):
    """Every database is read whatever its mtime: a live agent's recent
    rows can sit in its -wal file while the database itself looks old.
    With since_days, each action is kept by its own time, as in scan_all."""
    records, cutoff = [], _cutoff(since_days)
    dbs = openclaw_databases(state_dir)
    for db in dbs:
        records.extend(r for r in scan_openclaw_db(db, known=known)
                       if _in_window(r, cutoff))
    return records, len(dbs)


# The sources watch reads, in registry order: Claude Code first, OpenClaw
# last. The other adapters in the registry are not read here yet: each
# joins when watch and clean are wired to it (design 3.5 and 3.6), and
# SOURCES is then every registry id.
_READ_HERE = ("claude-code", "openclaw")
SOURCES = tuple(i for i in _registry.ids() if i in _READ_HERE)
_SOURCE_NAMES = {i: _registry.get(i).name for i in SOURCES}


def scan_sources_counted(sources=SOURCES, root=None, state_dir=None,
                         since_days=None, progress=None, known=None,
                         paths=None):
    """Scan every requested local agent source into one record stream.

    Returns (records, {source: how many it read}): Claude Code transcripts,
    OpenClaw databases. Zero read is not an all-clear: locations() says
    whether there was anything to read at all. `progress` is scan_all's,
    and `known` (a known.Matcher) is masked in every record.

    root and state_dir point Claude Code and OpenClaw elsewhere; `paths`,
    {source id: path}, points any source, and a root or state_dir given
    as well wins over it."""
    paths = paths or {}
    root = root or paths.get("claude-code")
    state_dir = state_dir or paths.get("openclaw")
    records, counts = [], {}
    if "claude-code" in sources:
        recs, counts["claude-code"] = scan_all(root=root, since_days=since_days,
                                               progress=progress, known=known)
        records += recs
    if "openclaw" in sources:
        recs, counts["openclaw"] = scan_openclaw(state_dir=state_dir,
                                                 since_days=since_days, known=known)
        records += recs
    records.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return records, counts


def scan_sources(sources=SOURCES, root=None, state_dir=None, since_days=None):
    """scan_sources_counted, with every source's count added up."""
    records, counts = scan_sources_counted(sources, root, state_dir, since_days)
    return records, sum(counts.values())


def locations(sources=SOURCES, root=None, state_dir=None):
    """Where each requested source keeps its history, and how many
    transcripts are there whatever their age:
    [{"source": ..., "path": ..., "found": n}], JSON as it is.

    What tells "nothing to read" from "read, and nothing tripped": no
    transcripts found anywhere means a wrong --root, a fresh machine, or
    history kept somewhere else, and must not read as an all-clear."""
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
    if "openclaw" in sources:
        path = state_dir or openclaw_state_dir()
        out.append({"source": "openclaw", "path": path,
                    "found": len(openclaw_databases(path))})
    return out
