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

import datetime
import functools
import glob
import shlex
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
import time

from . import term

CLAUDE_PROJECTS = os.path.expanduser("~/.claude/projects")

CRITICAL, HIGH, MEDIUM = "critical", "high", "medium"


class Rule(object):
    def __init__(self, rid, severity, title, why, patterns=(), scan_raw=False,
                 paths=False, find=None):
        self.id = rid
        self.severity = severity
        self.title = title
        self.why = why
        self.patterns = [re.compile(p, re.I) for p in patterns]
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


# Commands whose arguments are literal text, never a path being acted on.
# `cat` is deliberately absent: `cat ~/.aws/credentials` really is a read.
_TEXT_ONLY = re.compile(r"^\s*(?:sudo\s+)?(?:echo|printf|print)\b")

# `git rm --cached` unstages; it does not touch the working tree.
_GIT_RM_CACHED = re.compile(r"^\s*(?:sudo\s+)?git\s+rm\b[^|;&]*--cached\b")

# A comment is not a command.
_COMMENT = re.compile(r"(?:^|\s)#.*$")


def _is_inert(segment):
    """True when a segment cannot perform the action its text mentions."""
    if not segment.strip() or segment.lstrip().startswith("#"):
        return True
    if _TEXT_ONLY.match(segment) or _GIT_RM_CACHED.match(segment):
        return True
    return _is_search(segment)


def _is_search(segment):
    """True when this segment only looks for text, rather than acting on it.

    Judged per segment: `cat README | grep "rm -rf"` used to escape
    suppression entirely, because the `cat` half is not a search.
    """
    if not segment or not segment.strip():
        return False
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
    spans = []
    for value, _label in clean.find_secrets(text):
        at = text.find(value)
        while at != -1:
            spans.append((at, at + len(value)))
            at = text.find(value, at + 1)
    merged = []
    for lo, hi in sorted(spans):
        if merged and lo < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return tuple(merged)


def _first_secret(text):
    """Span of the earliest credential in text, so the evidence sits on it
    and not on a fixture beside it."""
    spans = _secret_spans(text)
    return spans[0] if spans else None


# Terminal control characters. A command carrying \033[2J or a tab is text
# to report, not something to replay on the reader's terminal.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Command separators, the same ones _SPLIT_OPS splits on. A match spanning
# lines (a private key) is bounded without the newline, or it would lose the
# `cat <<EOF` that says where it went.
_BREAKS = re.compile(r"\s*(?:\|\||&&|;|\||\n)\s*")
_INLINE_BREAKS = re.compile(r"\s*(?:\|\||&&|;|\|)\s*")


def _printable(text):
    return _CONTROL.sub(" ", text)


def _evidence(text, span, before=20, after=70):
    """Evidence a human can judge. 'rm -rf' alone tells you nothing; you need
    to see what it was pointed at.

    The window stops at the command's own separators. `cat .env ; rm -rf ~/x`
    is two findings, and the deletion shown as the evidence for the read
    made the read look like a deletion. A match that spans a separator (a
    pipe to curl) keeps it.

    Secrets are masked by spans found in the whole text first. A window
    edge that falls inside a value would otherwise show the half it kept,
    which nothing looking at the window alone can recognise as a secret.
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
    return clean.mask_for_display(
        ("…" if lo > 0 else "") + snippet + ("…" if hi < len(text) else ""))


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


def _is_catastrophic(t):
    return _normalise_target(t) in _CATASTROPHIC or t in ("/*", "~/*", "$HOME/*")


# Deletions that are not `rm`, so they have no target the refiner can judge.
# A temp `rm` alongside one of these says nothing about what it removed.
_UNJUDGED_DELETION = re.compile(
    r"find\s+[^|;&]*-delete\b|shred\s+|truncate\s+-s\s*0")

# A link or mount made earlier in the same command can point a temp path
# anywhere: `ln -s ~ /tmp/h; rm -rf /tmp/h/Documents` deletes Documents.
_LINKING = re.compile(
    r"^\s*(?:sudo\s+)?(?:\S*/)?(?:ln|mount|bindfs|mount_nullfs)\s")


def _linked_before_rm(text):
    linked = False
    for segment in _SPLIT_OPS.split(text):
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
    if not targets or _UNJUDGED_DELETION.search(text) or _linked_before_rm(text):
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
    Quote-aware, unlike _SPLIT_OPS, so `echo "x; cd /tmp"` holds no cd, and
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

_CRED_PATH = re.compile(
    r"(?:^|[\s\"'=(])((?:[\w./~$-]*/)?(?:\.env[\w.-]*|credentials|"
    r"\.netrc|id_[a-z0-9]+(?:\.pub)?|[\w.-]*\.pem|[\w.-]*\.key))",
    re.I)

# Commands that handle a file without ever reading its contents.
_NON_READING = re.compile(
    r"^\s*(?:sudo\s+)?(?:ls|ll|stat|file|test|\[|cp|mv|rm|touch|chmod|chown|"
    r"mkdir|basename|dirname|realpath|readlink|du|wc)\b")
_GIT_METADATA = re.compile(r"^\s*(?:sudo\s+)?git\s+(?:check-ignore|ls-files|status|add)\b")

_KEY_PREFIX = re.compile(r"^\s*(?:command|file_path|path|pattern|args?)\s+")

# The command redacts as it goes -- that is care, not exposure.
_REDACTING = re.compile(
    r"s[/|#;,]\s*=\.\*|=<(?:set|redacted|present)>|:\*\*\*|<redacted"
    r"|sed[^|;&]*\bs[/|#;,][^|;&]*\*\*\*", re.I)


def _cred_targets(text):
    return [m.group(1) for m in _CRED_PATH.finditer(text)]


def _is_template(target):
    """A template or a public key: named like a secret, holding none."""
    base = target.rstrip("/").split("/")[-1].lower()
    return base.endswith(_NOT_SECRET_SUFFIXES)


def _refine_credential(text, severity, tool_input=None):
    targets = _cred_targets(text)
    if not targets:
        return severity

    real = []
    for t in targets:
        if _is_template(t):
            continue                      # template or public key
        if re.search(r"--exclude(?:=|\s+)['\"]?%s" % re.escape(t), text):
            continue                      # named only in order to be skipped
        real.append(t)

    if not real:
        return None

    # Which segment actually touched it?
    for segment in _SPLIT_OPS.split(text):
        if not any(t in segment for t in real):
            continue
        segment = _KEY_PREFIX.sub("", segment)
        if _NON_READING.match(segment) or _GIT_METADATA.match(segment):
            continue                      # moved, listed, or asked about
        if _REDACTING.search(segment):
            return MEDIUM                 # read, but deliberately masked
        return severity
    return None


def _refine_read_path(text, severity, tool_input=None):
    """A path a file-reading tool opened. There is no verb to judge, since
    reading is all the tool does, so only templates and public keys are
    let go."""
    targets = _cred_targets(text)
    if targets and all(_is_template(t) for t in targets):
        return None
    return severity


# rm as a command word: first, after a separator, quote or bracket, or as the
# last part of a path (/bin/rm). Then the option words that follow it.
_RM_WORD = re.compile(r"(?<![^\s;&|(`'\"/])rm(?=\s)")
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
          r"\.config/gcloud", r"service[-_]account.*\.json",
          r"security\s+find-generic-password", r"\.kube/config"],
         paths=True),

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
         [r"git\s+push\b[^|;&]*--force(?!-with-lease)",
          r"git\s+push\b[^|;&]*\s-f\b",
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
         [r"find\s+[^|;&]*-delete\b",
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
          r"rm\s+[^|;&]*\.(?:bash|zsh)_history",
          r"aws\s+cloudtrail\s+(?:delete|stop)-", r"rm\s+-rf?\s+[^|;&]*\.git\b"]),

    Rule("exfil.shape", HIGH,
         "Local file piped to the network",
         "File contents sent outbound in a single command. This is the shape of "
         "exfiltration whether or not that was the intent.",
         [r"(?:cat|tar|zip|base64)\s+[^|;&]+\|\s*(?:curl|wget|nc)\b",
          r"curl\s+[^|;&]*(?:--data-binary|-d)\s*@",
          r"curl\s+[^|;&]*-F\s+[\"']?file=@"]),
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

_HEREDOC = re.compile(
    r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1.*?^\2\s*$",
    re.S | re.M)


def _strip_heredocs(command):
    """Remove heredoc bodies. The body is data being written to disk, not a
    sequence of commands being executed."""
    if not command or "<<" not in command:
        return command
    return _HEREDOC.sub("<<REDACTED_HEREDOC", command)


# Interpreters whose -c/-e payload is source in ANOTHER language. "rm -rf"
# inside a Python string is a string, not a deletion. Shell interpreters are
# the exception: their payload really is shell, so we recurse into it.
_FOREIGN_INTERPRETERS = {"python", "python2", "python3", "node", "nodejs",
                         "perl", "ruby", "php", "osascript", "awk", "jq"}
_SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh"}
_PAYLOAD_FLAGS = {"-c", "-e", "--eval", "--command"}

_SPLIT_OPS = re.compile(r"\s*(?:\|\||&&|;|\||\n)\s*")

# Fallback for when the payload contains quoting that shlex cannot parse --
# which is common, because the payload is source code in another language.
# Truncating at the flag is always safe: nothing after it is shell.
_FOREIGN_PAYLOAD = re.compile(
    r"^\s*(?:sudo\s+)?(?:%s)\b[^|;&]*?\s(-c|-e|--eval)\s"
    % "|".join(sorted(_FOREIGN_INTERPRETERS)))


_FOREIGN_OPEN = re.compile(
    r"(?:^|[\s;&|])(?:sudo\s+)?(?:%s)\s+(?:-[A-Za-z]+\s+)*(?:-c|-e|--eval)\s+(['\"])"
    % "|".join(sorted(_FOREIGN_INTERPRETERS)))


def _neutralize_foreign_payloads(command):
    """Blank out the source payload of a non-shell interpreter.

    Must run on the whole command before splitting on shell operators,
    because the payload frequently contains ';' and '|' of its own and
    splitting first tears it into fragments that no longer look like an
    interpreter call.
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
        out.append("FOREIGN_SOURCE")
        pos = min(i + 1, len(command))
    return "".join(out)


def _executable_text(command, depth=0):
    """Reduce a shell command to only the parts that are actually executed.

    Drops heredoc bodies and the source payloads of foreign interpreters,
    recursing into shell interpreters. This is what stops a script that
    *contains* a dangerous string from reading as a dangerous action.
    """
    if not command or depth > 3:
        return command or ""
    command = _strip_heredocs(command)
    command = _neutralize_foreign_payloads(command)

    kept = []
    for segment in _SPLIT_OPS.split(command):
        segment = _COMMENT.sub("", segment).strip()
        if not segment or _is_inert(segment):
            continue
        foreign = _FOREIGN_PAYLOAD.match(segment)
        if foreign:
            kept.append(segment[:foreign.end()])
            continue

        try:
            argv = shlex.split(segment)
        except ValueError:
            kept.append(segment)          # unbalanced quotes: keep it all
            continue
        if not argv:
            continue

        binary = os.path.basename(argv[0]).split("/")[-1]
        payload_idx = next((i for i, a in enumerate(argv) if a in _PAYLOAD_FLAGS), None)

        if binary in _FOREIGN_INTERPRETERS and payload_idx is not None:
            kept.append(" ".join(argv[:payload_idx + 1]))
            continue
        if binary in _SHELL_INTERPRETERS and payload_idx is not None:
            head = " ".join(argv[:payload_idx + 1])
            body = argv[payload_idx + 1] if payload_idx + 1 < len(argv) else ""
            kept.append(head + " " + _executable_text(body, depth + 1))
            continue
        kept.append(segment)

    return " ; ".join(kept)


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
    parts = [_executable_text(c) for c in commands]
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


def _masked(obj, depth=0):
    from . import clean
    if isinstance(obj, str):
        return clean.mask_for_display(obj)
    if depth > 32:
        return "…"
    if isinstance(obj, (list, tuple)):
        return [_masked(o, depth + 1) for o in obj]
    if isinstance(obj, dict):
        return {str(k): _masked(v, depth + 1) for k, v in obj.items()}
    return obj


def _payload(tool_input):
    """The whole call as one string, for telling calls apart. The judged text
    cannot do it: it is empty for most tools, which made every Workflow call
    that leaked a key the same call.

    Credentials are masked first. Its hash is printed as payload_hash, and a
    hash over a short password is a dictionary oracle for it."""
    try:
        return json.dumps(_masked(tool_input), sort_keys=True,
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


def evaluate(tool_name, tool_input):
    """Return (hits, payload) for one tool call: the rules it trips, and the
    whole input as masked text for telling flagged calls apart ("" when
    nothing tripped, since then there is nothing to tell apart)."""
    shell = _shell_text(tool_name, tool_input)
    paths = _read_paths(tool_name, tool_input)
    raw = _raw_strings(tool_input)

    hits = []
    for rule in RULES:
        if rule.scan_raw:
            subjects = [(s, REFINERS) for s in raw]
        else:
            subjects = [(shell, REFINERS)]
            if rule.paths:
                subjects.append((paths, PATH_REFINERS))
        for subject, refiners in subjects:
            if not subject:
                continue
            span = rule.match(subject)
            if not span:
                continue
            severity = rule.severity
            refine = refiners.get(rule.id)
            if refine:
                severity = refine(subject, severity, tool_input)
                if severity is None:
                    continue
            hits.append({"rule": rule.id, "severity": severity,
                         "title": rule.title, "why": rule.why,
                         "evidence": _evidence(subject, span)})
            break
    return hits, (_payload(tool_input) if hits else "")


# --------------------------------------------------------------------------
# Source: Claude Code JSONL transcripts
# --------------------------------------------------------------------------

def _iter_claude_tool_calls(path):
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            msg = entry.get("message")
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    yield entry, block


def scan_transcript(path, source="claude-code"):
    """Produce Action Records for one transcript."""
    records = []
    session = os.path.splitext(os.path.basename(path))[0]
    project = os.path.basename(os.path.dirname(path))

    for entry, block in _iter_claude_tool_calls(path):
        tool = block.get("name", "?")
        tool_input = block.get("input", {})
        hits, payload = evaluate(tool, tool_input)
        if not hits:
            continue
        records.append({
            "source": source,
            "session": session,
            "project": project,
            "timestamp": entry.get("timestamp"),
            "tool_name": tool,
            "tool_call_id": block.get("id"),
            "payload_hash": _hash(payload),
            "severity": max(hits, key=lambda h: ["medium", "high", "critical"]
                            .index(h["severity"]))["severity"],
            "hits": hits,
        })
    return records


def discover(root=CLAUDE_PROJECTS, since_days=None):
    paths = sorted(glob.glob(os.path.join(root, "*", "*.jsonl")),
                   key=lambda p: os.path.getmtime(p), reverse=True)
    if since_days:
        cutoff = time.time() - since_days * 86400
        paths = [p for p in paths if os.path.getmtime(p) >= cutoff]
    return paths


def scan_all(root=CLAUDE_PROJECTS, since_days=None, limit=None):
    """Scan every transcript, reporting each distinct action once.

    The same tool call appears in more than one transcript -- resumed
    sessions and sidechains both replay it -- so without this the report
    shows the identical command two and three times.
    """
    records, scanned, seen = [], 0, set()
    for path in discover(root, since_days):
        if limit and scanned >= limit:
            break
        scanned += 1
        for record in scan_transcript(path):
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
    by hand: Python 3.9's fromisoformat takes neither Z nor every fraction."""
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


def render(records, scanned, days, footer=True):
    """`footer=False` is for check, which prints one footer for all sections.
    It gates only the closing rule and footer line, never a finding.

    A record with several hits is headed by its most severe one, and each
    hit's evidence and why print under that hit's own title: a deletion
    listed under "Credential material accessed" reads as a credential read.
    Evidence is cut to the terminal and marked where it was cut, and each
    why is wrapped rather than sliced mid-word."""
    from . import clean
    from .report import BOLD, DIM, RED, YEL, CYA, GRN
    colour = {CRITICAL: RED, HIGH: YEL, MEDIUM: CYA}
    width = term.width()
    L = ["", BOLD("  ranwhat watch  ") + DIM("· local agent flight recorder"),
         DIM(term.rule("-")),
         "  %d source(s) over %d days" % (scanned, days), ""]
    if not records:
        L += ["  " + GRN("Nothing flagged."),
              DIM("  Every tool call was read, none tripped a rule."), ""]
        return "\n".join(L)

    counts = {}
    for r in records:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    L.append("  " + "  ".join(colour[k](BOLD("%d %s" % (v, k)))
                              for k, v in sorted(counts.items())))
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
            evidence = _printable(clean.mask_for_display(h.get("evidence") or ""))
            L.append(DIM("      " + _fit(evidence, width - 6)))
            why = term.wrap(h.get("why") or "", indent=" " * 9)
            if why:
                why[0] = "      -> " + why[0][9:]
            L += [DIM(line) for line in why]
        L.append("")
    if footer:
        L += [DIM(term.rule("-")), DIM(term.FOOTER), ""]
    return "\n".join(L)


# --------------------------------------------------------------------------
# Source: OpenClaw
#
# OpenClaw keeps per-agent transcripts in SQLite at
#   $OPENCLAW_STATE_DIR/agents/<agentId>/agent/openclaw-agent.sqlite
# documented only as "append-only, tree-structured (id + parentId)" holding
# conversation, tool calls and compaction summaries. The table and column
# names are not documented, and pinning them from a guess would break on the
# next release. So the schema is discovered at runtime and tool calls are
# recognised by shape rather than by column name.
#
# The database is opened read-only. It belongs to a running agent.
# --------------------------------------------------------------------------

OPENCLAW_STATE_DEFAULT = os.path.expanduser("~/.openclaw")


def openclaw_state_dir():
    """Read the env var when asked, not at import time -- a caller that sets
    OPENCLAW_STATE_DIR after importing was silently ignored."""
    return os.environ.get("OPENCLAW_STATE_DIR", OPENCLAW_STATE_DEFAULT)

# Keys that carry a tool's name, and keys that carry its arguments, across the
# shapes in circulation (Anthropic tool_use, OpenAI function calls, and the
# various framework wrappers).
_NAME_KEYS = ("name", "toolName", "tool_name", "tool", "function_name")
_ARG_KEYS = ("input", "arguments", "args", "params", "parameters", "toolInput")


def openclaw_databases(state_dir=None):
    root = state_dir or openclaw_state_dir()
    return sorted(glob.glob(os.path.join(
        root, "agents", "*", "agent", "openclaw-agent.sqlite")))


def _open_readonly(path):
    """Read-only, and resilient to the agent holding a WAL lock."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=5)
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return conn, None
    except sqlite3.Error:
        pass
    # Live WAL: work on a copy rather than touching the agent's database.
    tmp = tempfile.mkdtemp(prefix="ranwhat-")
    copy = os.path.join(tmp, os.path.basename(path))
    try:
        shutil.copy2(path, copy)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(path + suffix):
                shutil.copy2(path + suffix, copy + suffix)
        return sqlite3.connect("file:%s?mode=ro" % copy, uri=True), tmp
    except (OSError, sqlite3.Error):
        return None, tmp


_TIME_COL = re.compile(r"^(created_?at|timestamp|ts|time|updated_?at|date)$", re.I)


def _time_columns(conn, table):
    return [r[1] for r in conn.execute("PRAGMA table_info(%s)"
                                       % _quote_ident(table))
            if _TIME_COL.match(r[1] or "")]


def _as_iso(value):
    """Rows carry epoch seconds, epoch millis or an ISO string depending on
    the writer. Normalise what we can and drop what we cannot."""
    if value in (None, ""):
        return None
    if isinstance(value, str):
        if not value[:4].isdigit():
            return None
        # Converted to UTC and marked so, as Claude Code's stamps are, so
        # render can show it in the reader's zone. A stamp with no zone is
        # left without one: which zone it meant is not known.
        when, zoned = _parse_stamp(value)
        if zoned:
            try:
                return when.astimezone(datetime.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OverflowError):
                pass
        return value[:19]
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n > 1e11:          # milliseconds
        n /= 1000.0
    if n < 1e8:           # not a plausible epoch
        return None
    try:
        return datetime.datetime.fromtimestamp(
            n, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return None


def _quote_ident(name):
    """Escape a SQLite identifier by doubling quotes.

    Stripping them instead was safe but silently wrong: a table whose name
    contains a quote became a name that does not exist, the query errored,
    and its rows were skipped without a word.
    """
    return '"%s"' % name.replace('"', '""')


def _text_columns(conn, table):
    cols = []
    for row in conn.execute("PRAGMA table_info(%s)" % _quote_ident(table)):
        name, ctype = row[1], (row[2] or "").upper()
        if ctype in ("", "TEXT", "BLOB", "JSON") or "CHAR" in ctype:
            cols.append(name)
    return cols


def _find_tool_calls(obj, depth=0):
    """Recognise tool calls by shape, anywhere in a decoded JSON structure.

    Deduplicated: an OpenAI-style {"function": {...}} matches both the explicit
    branch and the generic walk that recurses into it.
    """
    found = _find_tool_calls_raw(obj, depth)
    out, seen = [], set()
    for name, args in found:
        key = (name, json.dumps(args, sort_keys=True, default=str)[:512])
        if key not in seen:
            seen.add(key)
            out.append((name, args))
    return out


def _find_tool_calls_raw(obj, depth=0):
    found = []
    if depth > 8:
        return found
    if isinstance(obj, list):
        for item in obj:
            found.extend(_find_tool_calls_raw(item, depth + 1))
        return found
    if not isinstance(obj, dict):
        return found

    # OpenAI-style: {"function": {"name": ..., "arguments": "<json string>"}}
    fn = obj.get("function")
    if isinstance(fn, dict) and any(k in fn for k in _NAME_KEYS):
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"_raw": args}
        found.append((str(next(fn[k] for k in _NAME_KEYS if k in fn)), args or {}))

    name = next((obj[k] for k in _NAME_KEYS if isinstance(obj.get(k), str)), None)
    args = next((obj[k] for k in _ARG_KEYS if isinstance(obj.get(k), (dict, str))), None)
    if name and args is not None:
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"_raw": args}
        if obj.get("type") in (None, "tool_use", "tool_call", "function_call", "tool"):
            found.append((name, args))

    for value in obj.values():
        if isinstance(value, (dict, list)):
            found.extend(_find_tool_calls_raw(value, depth + 1))
        elif isinstance(value, str) and value[:1] in ("{", "["):
            try:
                found.extend(_find_tool_calls_raw(json.loads(value), depth + 1))
            except ValueError:
                pass
    return found


def _warn(message):
    import sys as _sys
    print("  warning: %s" % message, file=_sys.stderr)


def scan_openclaw_db(path, source="openclaw"):
    conn, tmpdir = _open_readonly(path)
    if conn is None:
        _warn("could not open %s (permissions, or the agent holds it locked)"
              % path)
        return []

    agent_id = path.split(os.sep + "agents" + os.sep)[-1].split(os.sep)[0] \
        if os.sep + "agents" + os.sep in path else "openclaw"
    records, seen = [], set()

    try:
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'")]
        except sqlite3.Error as e:
            # Not a database, encrypted, or truncated mid-write. One bad file
            # must not take the rest of the scan down with it.
            _warn("cannot read %s (%s)" % (path, e))
            return []
        for table in tables:
            cols = _text_columns(conn, table)
            if not cols:
                continue
            tcols = _time_columns(conn, table)
            quoted = ", ".join(_quote_ident(c) for c in cols + tcols)
            try:
                rows = conn.execute("SELECT %s FROM %s"
                                    % (quoted, _quote_ident(table)))
            except sqlite3.Error:
                continue
            n_text = len(cols)
            for row in rows:
                stamp = next((_as_iso(v) for v in row[n_text:]
                              if _as_iso(v)), None)
                for cell in row[:n_text]:
                    if not isinstance(cell, (str, bytes)):
                        continue
                    if isinstance(cell, bytes):
                        try:
                            cell = cell.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                    if cell[:1] not in ("{", "["):
                        continue
                    try:
                        payload = json.loads(cell)
                    except ValueError:
                        continue
                    for tool, tool_input in _find_tool_calls(payload):
                        if not isinstance(tool_input, dict):
                            tool_input = {"_value": tool_input}
                        hits, payload = evaluate(tool, tool_input)
                        if not hits:
                            continue
                        key = (tool, _hash(payload))
                        if key in seen:
                            continue
                        seen.add(key)
                        records.append({
                            "source": source,
                            "session": agent_id,
                            "project": table,
                            "timestamp": stamp,
                            "tool_name": tool,
                            "tool_call_id": None,
                            "payload_hash": _hash(payload),
                            "severity": max(
                                hits, key=lambda h: ["medium", "high", "critical"]
                                .index(h["severity"]))["severity"],
                            "hits": hits,
                        })
    finally:
        conn.close()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return records


def scan_openclaw(state_dir=None):
    records = []
    dbs = openclaw_databases(state_dir)
    for db in dbs:
        records.extend(scan_openclaw_db(db))
    return records, len(dbs)


SOURCES = ("claude-code", "openclaw")


def scan_sources(sources=SOURCES, root=None, state_dir=None, since_days=None):
    """Scan every requested local agent source into one record stream."""
    records, scanned = [], 0
    if "claude-code" in sources:
        recs, n = scan_all(root=root or CLAUDE_PROJECTS, since_days=since_days)
        records += recs
        scanned += n
    if "openclaw" in sources:
        recs, n = scan_openclaw(state_dir=state_dir)
        records += recs
        scanned += n
    records.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return records, scanned
