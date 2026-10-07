"""Aider (design section 7, Aider-AI/aider).

Verified against Aider's own code at tag v0.86.2 (aider/io.py, aider/
commands.py, aider/coders/base_coder.py, aider/main.py, aider/args.py) and,
for the input history, prompt-toolkit 3.0.52 (history.py FileHistory), the
version Aider pins.

Where: Aider writes into the repository it runs in, not into a folder of
its own. The chat log is <git root>/.aider.chat.history.md, or
./.aider.chat.history.md outside a repository (args.py, main.py: the git
root is found from the current directory), and AIDER_CHAT_HISTORY_FILE
(--chat-history-file, chat-history-file: in .aider.conf.yml) moves it. So
this looks at the file that variable names, at the home directory (Aider
run outside any repository from ~), and at the current directory and the
git root above it (locations), read when ranwhat runs: run ranwhat inside a
repository to read that repository's history. Config files are not read.

The chat log (one store, "chat history", every session of that repository
appended one after another; io.py append_chat_history) is Markdown:
- "\\n# aider chat started at YYYY-MM-DD HH:MM:SS\\n\\n" starts a session,
  in local time with no zone (io.py InputOutput.__init__). There is no
  other time in the file.
- What the user typed: every line as "#### <line>  " (two trailing spaces,
  a Markdown hard break), the input verbatim, slash commands and "!cmd"
  too (io.py user_input).
- Aider's own messages and questions: "> <text>  " (tool_output,
  tool_error, confirm_ask "<question> (Y)es/(N)o... [Yes]: <first letter
  of the answer>"). A message of several lines has "> " on its first line
  only (tool_output) or on each (tool_error).
- The model's reply: raw Markdown with no prefix (ai_output). It can hold
  lines that look like either of the above, so only lines that start with
  "#### " or "> " AND end with the two spaces Aider adds are taken as
  Aider's, and only Aider's exact phrasings are read from them.

Calls, all from that log (tool names are this adapter's, Aider has none):
- "/run X", "!X" (and any prefix Aider resolves to /run, as Commands.run
  does), "/test X" and "/git X" ("git X", shell=True): shell, run by the
  user (commands.py cmd_run, cmd_test, cmd_git). "> Executing: X" lines of
  /load are read as typed input. The output of /run, "!" and /test is never
  logged (run_cmd prints it); /git's is (tool_output), and is kept as that
  call's output.
- A command the model suggested: its "> X" subject lines, then "> Run shell
  command(s)? ... [Yes]: y" (base_coder.py handle_shell_commands). Every
  non-blank line that is not a "#" comment is one command. Only "y" runs
  them (explicit_yes_required); "n", "s" (skip all), "d" (don't ask
  again) and "a" are "declined".
- "> Added F to the chat" (/add), "> Added F to the chat." and "> Added F
  to the chat (read-only)." (the files named at launch, written before the
  first input), "> Added P to read-only files." and "> Added N files from
  directory P to read-only files." (/read-only): reads by the user. The file
  went to the model whole. A refused /add ("Can not add P, which is not
  within ROOT", "Can't add F which is in gitignore", "Skipping F due to
  aiderignore or --subtree-only.") is a read the user asked for that Aider
  never made: "declined", so the attempt is still seen.
- "> F" then "> Add file to the chat? ... [Yes]: y|a" (a file the user's
  message or the model's reply named): a read, "declined" for any other
  answer; by the user before the reply, by the agent after it.
- "> Scraping URL..." (/web, or a URL in a message the user agreed to add):
  a fetch by the user; "> URL" then "> Add URL to the chat? ...: n" is a
  declined one.
- "> Applied edit to F": a write by the agent; "Did not apply edit to F
  (--dry-run)" a declined one.
Paths are kept as Aider wrote them: relative ones are relative to the git
root, which is the folder of a .aider.chat.history.md under its own name,
given as each call's project and working directory.

Times: a call has none of its own. Each is given the session's header as
its session and, as the latest time it can have happened (not_after), the
next session's header, or the file's last write for the last session. The
log is only appended to, so whatever follows a call was written after it.

The input history (.aider.input.history beside the log, role "side", read
for clean only) is prompt_toolkit's: "\\n# <local time>\\n" then "+<line>"
for each line of an entry. It holds everything the user typed, answers to
questions included.

Every line of both files goes to clean, the launch line too: Aider writes
its whole command line to the log at every start, and scrubs only
--openai-api-key and --anthropic-api-key, so "--api-key provider=KEY" is
there in the clear (main.py, format_settings.py). The lines of a
SEARCH/REPLACE block in a reply are handed over as the content of the file
named above it, so a secret in an edited .env is credited to .env.

Not read: .aider.llm.history, which only --llm-history-file turns on, at a
path the user chooses and nothing here can find; .aider.conf.yml and .env,
where Aider takes its keys from; Aider's cache and analytics folders.
"""

from __future__ import annotations

import collections
import os
import re

from . import _lines, _paths, _stamps, base
from .base import Location, SecretText, Source, ToolCall

ENV = "AIDER_CHAT_HISTORY_FILE"

CHAT = ".aider.chat.history.md"
INPUT = ".aider.input.history"

HERE = "current directory"

DECLINED = "declined"

# Aider's slash commands at v0.86.2 (commands.py: every cmd_* method, "_"
# written "-"). A typed word is resolved against them as Commands.run
# does: the one command it starts, or the one it names exactly.
COMMANDS = (
    "/add", "/architect", "/ask", "/chat-mode", "/clear", "/code",
    "/commit", "/context", "/copy", "/copy-context", "/diff", "/drop",
    "/edit", "/editor", "/editor-model", "/exit", "/git", "/help", "/lint",
    "/load", "/ls", "/map", "/map-refresh", "/model", "/models",
    "/multiline-mode", "/paste", "/quit", "/read-only", "/reasoning-effort",
    "/report", "/reset", "/run", "/save", "/settings", "/test",
    "/think-tokens", "/tokens", "/undo", "/voice", "/weak-model", "/web")

# Tool names, this adapter's own: Aider records no tool names.
RUN = "/run"
BANG = "!"
TEST = "/test"
GIT = "/git"
SUGGESTED = "shell command"         # a command the model suggested
ADD = "/add"
READ_ONLY = "/read-only"
LAUNCH = "launch"                   # files named on Aider's command line
MENTION = "file mention"
WEB = "/web"
URL_MENTION = "url mention"
EDIT = "edit"

_HEADER = re.compile(r"# aider chat started at (.*)\Z")
_STAMP = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\Z")

_OPTIONS = r" \(Y\)es/\(N\)o(?:/\(A\)ll)?(?:/\(S\)kip all)?(?:/\(D\)on't ask again)?"
_SHELL_Q = re.compile(r"Run shell commands?\?" + _OPTIONS + r" \[Yes\]: ([a-z])\Z")
_FILE_Q = re.compile(r"Add file to the chat\?" + _OPTIONS + r" \[Yes\]: ([a-z])\Z")
_URL_Q = re.compile(r"Add URL to the chat\?" + _OPTIONS + r" \[Yes\]: ([a-z])\Z")
# confirm_ask with a group answer already given logs the question as typed
# input too ("#### Run shell command? ... [Yes]: skip"), before its "> " line.
_ECHO = re.compile(r".*\?" + _OPTIONS + r" \[(?:Yes|No)\]: [a-z']+\Z")

# What confirm_ask logs (tool_error) after an answer it does not take,
# before it asks again: between the subject and the question.
_RETRY = re.compile(r"Please answer with one of: yes, no, skip, all(?:, don't)?\Z")

_ADDED = re.compile(r"Added (.+) to the chat\Z")
_LAUNCHED = re.compile(r"Added (.+) to the chat(?: \(read-only\))?\.\Z")
_RO_DIR = re.compile(r"Added \d+ files from directory (.+) to read-only files\.\Z")
_RO_FILE = re.compile(r"Added (.+) to read-only files\.\Z")
_OUTSIDE = re.compile(r"Can not add (.+), which is not within .+\Z")
_IGNORED = re.compile(r"Can't add (.+) which is in gitignore\Z")
_SKIPPED = re.compile(r"Skipping (.+) due to aiderignore or --subtree-only\.\Z")
_APPLIED = re.compile(r"Applied edit to (.+)\Z")
_DRY_RUN = re.compile(r"Did not apply edit to (.+) \(--dry-run\)\Z")
_SCRAPING = re.compile(r"Scraping (.+)\.\.\.\Z")
_EXECUTING = re.compile(r"Executing: (.+)\Z")

# A private key's first and last lines, as clean finds one; the longest
# (an RSA 4096 key) is about 50 lines of base64.
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_PEM_MOST = 200

# SEARCH/REPLACE markers (editblock_coder.py HEAD, UPDATED).
_HUNK_HEAD = re.compile(r"<{5,9} SEARCH>?\s*\Z")
_HUNK_END = re.compile(r">{5,9} REPLACE\s*\Z")
FENCE = "```"

# How many earlier lines are kept to find a question's subject. A longer
# block of suggested commands is counted as unknown.
_WINDOW = 256

# prompt_toolkit's input history: "# <time>" before each entry, "+<line>".
_INPUT_STAMP = "# "
_INPUT_LINE = "+"


def _string(value):
    return value if isinstance(value, str) and value else None


def _hard(text, prefix):
    """The content of a line Aider wrote with `prefix` ("> " or "#### ") and
    a hard break (two trailing spaces), or None for any other line."""
    if text.startswith(prefix) and text.endswith("  ") and len(text) >= len(prefix) + 2:
        return text[len(prefix):-2]
    if prefix == "> " and text == ">  ":
        return ""           # an empty message: ">" and the two spaces
    return None


def resolve(word):
    """The slash command `word` runs, as Commands.run resolves it: the only
    command it starts, or the one it names exactly; None when it is
    ambiguous or no command."""
    matches = [c for c in COMMANDS if c.startswith(word)]
    if len(matches) == 1:
        return matches[0]
    if word in matches:
        return word
    return None


def _hunk_file(before):
    """The file a SEARCH/REPLACE block edits, from the lines just above its
    SEARCH marker (nearest first), as editblock_coder.find_filename looks
    back: past fence lines, at most three. None when there is none that is
    one word."""
    for line in before[:3]:
        text = line.strip()
        if text.startswith(FENCE):
            name = text[len(FENCE):]
            if name and ("." in name or "/" in name) and not name.split()[1:]:
                return name
            continue
        text = text.rstrip(":").lstrip("#").strip().strip("`").strip("*")
        if text and text != "..." and not text.split()[1:]:
            return text
        return None
    return None


def _git_root(start):
    """The folder at or above `start` that holds .git (a folder, or a file
    for a worktree), as git finds the repository Aider runs in; or None."""
    path = start
    for _ in range(256):
        if os.path.exists(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent
    return None


def _same(path):
    """A key that is equal for two spellings of one place: the folder's
    links resolved, the file name kept as it is."""
    folder, name = os.path.split(os.path.abspath(path))
    try:
        folder = os.path.realpath(folder)
    except (OSError, ValueError):
        pass
    return os.path.normcase(os.path.join(folder, name))


def _is_file(path):
    try:
        return os.path.isfile(path)
    except (OSError, ValueError):
        return False


class _Pem(object):
    """A private key both files write a line at a time: the log quotes each
    line of an input ("#### "), Aider's own output and a reply's lines are
    lines of their own, and clean finds a key only whole, BEGIN to END in
    one text. So the lines from a BEGIN line to its END line are handed
    over once more, joined, as one text."""
    __slots__ = ("lines", "where", "call", "attached")

    def __init__(self):
        self.reset()

    def reset(self):
        self.lines = None

    def step(self, content, where, call=None, attached=None):
        """Take one line's content; the key's SecretText at its END line."""
        content = content.rstrip()
        if self.lines is None:
            m = _PEM_BEGIN.search(content)
            if m and not _PEM_END.search(content, m.end()):
                self.lines = [content[m.start():]]
                self.where, self.call, self.attached = where, call, attached
            return None
        self.lines.append(content)
        m = _PEM_END.search(content)
        if m:
            self.lines[-1] = content[:m.end()]
            text = SecretText("\n".join(self.lines), call=self.call,
                              attached=self.attached, where=self.where)
            self.reset()
            return text
        if len(self.lines) > _PEM_MOST:
            self.reset()
        return None


class _Session(object):
    """The session a call is in: its header's time, and the calls waiting
    for the next header to know how late they can be."""
    __slots__ = ("stamp", "calls")

    def __init__(self, stamp=None):
        self.stamp = stamp
        self.calls = []


class AiderSource(Source):
    id = "aider"
    name = "Aider"
    unit = "chat history"
    env = (ENV,)
    path_means = "a folder holding .aider.chat.history.md, or the file itself"
    checked = "0.86.2"

    def reset(self):
        Source.reset(self)
        self._bad = set()       # stores already counted as unreadable
        self._tallied = set()   # stores whose odd lines are counted

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """AIDER_CHAT_HISTORY_FILE when set, and the chat log in the home
        directory, where Aider writes when it is run there outside any
        repository. Each is the log itself, not its folder: a folder that
        is there (home always is) would be listed on every run, and a log
        that is not there costs one stat. Pure: the current directory is
        added by locations."""
        out = []
        moved = _string(env.get(ENV))
        if moved:
            out.append((moved, "env " + ENV))
        out.append((_paths.join(platform, home, CHAT), "default"))
        return out

    def project_paths(self, projects):
        """Each project folder: Aider writes its log at a repository's
        root. Not used while needs_projects is False."""
        return [(p, "project") for p in projects if _string(p)]

    @staticmethod
    def here():
        """The chat log in the current directory and in the git root above
        it, read now. Finding the root costs a stat of each folder on the
        way up to it."""
        cwd = os.getcwd()
        out = [os.path.join(cwd, CHAT)]
        root = _git_root(cwd)
        if root:
            out.append(os.path.join(root, CHAT))
        return out

    def locations(self, override=None, projects=()):
        """As Source.locations, and without --path also the current
        directory and its git root ("current directory"), read at call
        time: Aider keeps its history in the repository it ran in."""
        found = Source.locations(self, override, projects)
        if override:
            return self._input_alone(found)
        try:
            # Compared by real path: the current directory comes back from
            # getcwd() resolved (/private/var on macOS) where the home
            # directory may be spelled through a link (/var).
            seen = set(_same(loc.path) for loc in found)
            for path in self.here():
                path = os.path.abspath(path)
                key = _same(path)
                if key in seen:
                    continue
                seen.add(key)
                loc = Location(self.id, path, HERE, exists=os.path.exists(path))
                if loc.exists:
                    loc.found = len(list(self.stores([loc])))
                found.append(loc)
        except Exception as e:      # one adapter must not stop the others
            self.warn("locations", "could not work out where %s keeps its "
                      "history (%s)" % (self.name, type(e).__name__))
        return self._input_alone(found)

    def _input_alone(self, found):
        """A place whose chat log is not there but whose input history is
        (AIDER_CHAT_HISTORY_FILE moves only the log; a log deleted on its
        own) is a place that exists: only those are asked for stores, and
        the input history holds everything the user typed. One more stat,
        only where the log is missing."""
        try:
            for loc in found:
                if (loc.exists or os.path.basename(loc.path) != CHAT
                        or not _is_file(os.path.join(os.path.dirname(loc.path),
                                                     INPUT))):
                    continue
                loc.exists = True
                loc.found = len(list(self.stores([loc])))
        except Exception as e:      # one adapter must not stop the others
            self.warn("locations", "could not work out where %s keeps its "
                      "history (%s)" % (self.name, type(e).__name__))
        return found

    def stores(self, locations, since_days=None):
        """The chat log and the input history at each location: a folder
        holds them under their own names; a file is the chat log (any name),
        with the input history beside it."""
        found, seen = [], set()

        def add(path, role, unit, project):
            key = os.path.normcase(os.path.abspath(path))
            if key in seen or not _is_file(path):
                return
            seen.add(key)
            store = self.store(path, "text", role=role, unit=unit,
                               project=project)
            if store is not None:
                found.append(store)

        for loc in locations:
            path = loc.path
            try:
                folder_given = os.path.isdir(path)
            except (OSError, ValueError):
                continue
            if folder_given:
                folder, chat = path, os.path.join(path, CHAT)
            else:
                folder, chat = os.path.dirname(path), path
            # Relative paths in the log are relative to the git root, the
            # folder of a log under its own name; elsewhere it is unknown.
            project = folder if os.path.basename(chat) == CHAT else None
            add(chat, "transcript", self.unit, project)
            add(os.path.join(folder, INPUT), "side", "input history", folder)
        return base.newest_first(found, since_days)

    # -- masking ------------------------------------------------------------

    def mask(self, store, values):
        """As Source.mask, but a value of several lines (a private key read
        whole, _Pem) is masked a line at a time: in the file each of its
        lines sits on a line of its own, behind "#### " or "+" in an input,
        and only its lines of 16 characters or more are masked, so a short
        one does not mask the same text elsewhere."""
        out = []
        for value in values:
            if isinstance(value, str) and "\n" in value:
                out.extend(part for part in (l.strip() for l in value.split("\n"))
                           if len(part) >= 16 and not _PEM_BEGIN.search(part)
                           and not _PEM_END.search(part))
            else:
                out.append(value)
        return Source.mask(self, store, out)

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read Aider %s %s (%s)"
                  % (store.unit, store.path, reason))

    def _lines(self, store):
        """(line_no, text) for every line, CRLF or LF, bytes that are not
        UTF-8 kept as surrogates. Raises OSError."""
        with open(store.path, "rb") as fh:
            for line_no, raw in enumerate(fh, 1):
                yield line_no, _lines.decode_line(raw, first=line_no == 1)

    def tool_calls(self, store):
        """Every call in the log, in order, each once (see the module
        notes). A file that is not an Aider chat log warns once and yields
        nothing."""
        if store.role != "transcript":
            return
        for kind, item in self._scan(store, texts=False):
            if kind == "call":
                yield item

    def secret_texts(self, store):
        """Every line of the store. In the log, /git's output is tied to its
        call, and a SEARCH/REPLACE block to the file it edits."""
        if store.role != "transcript":
            for text in self._input_texts(store):
                yield text
            return
        for kind, item in self._scan(store, texts=True):
            if kind == "text":
                yield item

    def _input_texts(self, store):
        """The input history, one SecretText for each line: what was typed
        on it, without prompt_toolkit's "+"."""
        tally = store.path not in self._tallied
        self._tallied.add(store.path)
        started = False
        pem = _Pem()
        try:
            for line_no, text in self._lines(store):
                if not text:
                    continue
                if not started:
                    started = True
                    if not text.startswith(_INPUT_STAMP):
                        self._bad_store(store, "not an Aider input history")
                        return
                if text.startswith(_INPUT_LINE):
                    text = text[1:]
                elif not text.startswith(_INPUT_STAMP) and tally:
                    self.count("unknown")
                yield SecretText(text, where="line %d" % line_no)
                if text.startswith(_INPUT_STAMP):
                    pem.reset()
                else:
                    key = pem.step(text, "line %d" % line_no)
                    if key is not None:
                        yield key
        except OSError as e:
            self._bad_store(store, e.strerror or type(e).__name__)

    # -- the chat log ---------------------------------------------------------

    def _scan(self, store, texts):
        """("call", ToolCall) and, with texts, ("text", SecretText) for the
        log. Calls wait for the end of their session (the next header, or
        the end of the file) to be given not_after; texts are yielded as
        their line is read."""
        try:
            for item in self._parse(store, texts):
                yield item
        except OSError as e:
            self._bad_store(store, e.strerror or type(e).__name__)

    def _parse(self, store, texts):
        tally = store.path not in self._tallied
        self._tallied.add(store.path)
        mtime = _stamps.iso_utc(store.mtime, "s")
        recent = collections.deque(maxlen=_WINDOW)
        session = _Session()
        started = False         # the first line with something on it was read
        startup = False         # after a header, before the first input
        replied = False         # model text since the last input
        typed = []              # (line_no, text) of the input being read
        git = None              # [call, lines] of /git output being read
        hunk = None             # the file a SEARCH/REPLACE block edits
        pem = _Pem()            # a private key being read, line by line

        def end_git():
            if git is not None:
                lines = list(git[1])
                while lines and not lines[-1].strip():
                    lines.pop()
                if lines and lines[-1].endswith("  "):
                    lines[-1] = lines[-1][:-2]      # the hard break
                git[0].output = "\n".join(lines) if lines else None

        def close(next_stamp):
            """Yield the session's calls, bounded by the next header."""
            bound = mtime
            if (next_stamp is not None and (session.stamp is None
                                            or next_stamp >= session.stamp)):
                bound = next_stamp
            for call in session.calls:
                call.not_after = bound
                yield "call", call
            del session.calls[:]

        for line_no, text in self._lines(store):
            where = "line %d" % line_no
            if not started and text:
                started = True
                if not _HEADER.match(text):
                    self._bad_store(store, "not an Aider chat history")
                    return
            header = _HEADER.match(text)
            prev_blank = bool(recent) and recent[-1][1] == ""
            is_input = _hard(text, "#### ")
            # An input ends at the first line that is not one of its lines.
            if git is not None and (header or (is_input is not None
                                               and prev_blank)):
                end_git()
                git = None
            if typed and (is_input is None or header):
                new = self._input(store, session, typed)
                if self._real(typed):
                    replied = False
                typed = []
                if new is not None:
                    end_git()
                    git = [new, []]     # its output starts on this line
            if header:
                end_git()
                git = None
                stamp = header.group(1)
                if not _STAMP.match(stamp) or _stamps.parse_stamp(stamp)[0] is None:
                    if tally:
                        self.count("unparsed")
                    stamp = None
                for item in close(stamp):
                    yield item
                session = _Session(stamp or header.group(1))
                startup, replied, hunk = True, False, None
                pem.reset()
                recent.clear()
                if texts:
                    yield "text", SecretText(text, where=where)
                continue
            owner = git[0] if git is not None else None
            if git is not None:
                git[1].append(text[2:] if not git[1] and text.startswith("> ")
                              else text)
            if is_input is not None:
                if not typed:
                    startup = False
                typed.append((line_no, is_input))
                hunk = None
            message = _hard(text, "> ")
            if message is not None and owner is None:
                hunk = None
                self._message(store, session, line_no, message, recent,
                              startup, replied, tally)
            elif (is_input is None and message is None and text
                  and owner is None):
                replied = True
                if _HUNK_HEAD.match(text):
                    hunk = _hunk_file([t for _n, t in reversed(recent)])
                elif _HUNK_END.match(text):
                    if texts:
                        yield "text", SecretText(text, attached=hunk,
                                                 where=where)
                    hunk = None
                    recent.append((line_no, text))
                    continue
            if texts:
                yield "text", SecretText(text, call=owner, attached=hunk,
                                         where=where)
                if is_input is not None:
                    content = is_input
                elif message is not None:
                    content = message
                elif text.startswith("> "):
                    content = text[2:]
                else:
                    content = text
                key = pem.step(content, where, owner, hunk)
                if key is not None:
                    yield "text", key
            recent.append((line_no, text))
        if typed:
            self._input(store, session, typed)
        end_git()
        for item in close(None):
            yield item

    @staticmethod
    def _real(typed):
        """True for what the user typed, False for a question's answer that
        confirm_ask logged as typed input (_ECHO)."""
        return not (len(typed) == 1 and _ECHO.match(typed[0][1]))

    def _base(self, store, session, line_no, **fields):
        fields.setdefault("project", store.project)
        return dict(session=session.stamp, tool_call_id="line %d" % line_no,
                    **fields)

    def _shell(self, store, session, line_no, name, command, actor="agent",
               status=None):
        call = ToolCall(
            self.id, store.path, name, {"command": command}, kind="shell",
            known=True, command=command, consumed=("command",), actor=actor,
            status=status, workdir=store.project,
            **self._base(store, session, line_no))
        session.calls.append(call)
        return call

    def _file(self, store, session, line_no, name, kind, path, actor,
              status=None):
        consumed = ("path",) if kind == "read" else ()
        session.calls.append(ToolCall(
            self.id, store.path, name, {"path": path}, kind=kind, known=True,
            paths=(path,), consumed=consumed, actor=actor, status=status,
            workdir=store.project, **self._base(store, session, line_no)))

    def _fetch(self, store, session, line_no, name, url, status=None):
        session.calls.append(ToolCall(
            self.id, store.path, name, {"url": url}, kind="fetch", known=True,
            actor="user", status=status, **self._base(store, session, line_no)))

    def _input(self, store, session, typed):
        """The call for one typed input, when it runs a command: the /git
        call is returned, so its output can be tied to it."""
        line_no = typed[0][0]
        return self._command(store, session, line_no,
                             "\n".join(t for _n, t in typed))

    def _command(self, store, session, line_no, inp):
        """As Commands.run: "!" runs the rest; a slash word is resolved
        (resolve). Only what runs a shell is a call here: /add, /read-only
        and /web are read from what Aider answered."""
        if not inp or inp[0] not in "/!":
            return None
        if inp.startswith("!"):
            command = inp[1:].strip()
            if command:
                self._shell(store, session, line_no, BANG, command, actor="user")
            return None
        words = inp.strip().split()
        if not words:
            return None
        name = resolve(words[0])
        rest = inp[len(words[0]):].strip()
        if name == "/run" and rest:
            self._shell(store, session, line_no, RUN, rest, actor="user")
        elif name == "/test" and rest:
            self._shell(store, session, line_no, TEST, rest, actor="user")
        elif name == "/git":
            return self._shell(store, session, line_no, GIT, "git " + rest,
                               actor="user")
        return None

    def _subject(self, recent, tally):
        """[(line_no, text)] of the subject confirm_ask wrote above its
        question: one "> " line, then the raw lines of a subject of several
        lines (tool_output quotes only the first). None when there is none."""
        items = list(recent)
        i = len(items) - 1
        # An answer confirm_ask did not take is followed by its error, and
        # the question asked again: the subject is above the errors.
        while i >= 0 and _RETRY.match(_hard(items[i][1], "> ") or ""):
            i -= 1
        if i >= 0 and items[i][1].startswith("#### ") and _ECHO.match(
                _hard(items[i][1], "#### ") or ""):
            i -= 1
            if i >= 0 and items[i][1] == "":
                i -= 1
        raw = []
        while i >= 0:
            line_no, text = items[i]
            if text.startswith("> "):
                return [(line_no, text[2:])] + raw[::-1]
            if text == "" or text.startswith("#### ") or _HEADER.match(text):
                break
            raw.append((line_no, text))
            i -= 1
        if tally:
            self.count("unknown")
        return None

    def _message(self, store, session, line_no, message, recent, startup,
                 replied, tally):
        """The call, if any, that one of Aider's "> " lines records."""
        m = _SHELL_Q.match(message)
        if m:
            subject = self._subject(recent, tally)
            status = None if m.group(1) == "y" else DECLINED
            for no, text in subject or ():
                command = text.strip()
                if command and not command.startswith("#"):
                    self._shell(store, session, no, SUGGESTED, command,
                                status=status)
            return
        m = _FILE_Q.match(message)
        if m:
            subject = self._subject(recent, tally)
            if subject and len(subject) == 1 and subject[0][1].strip():
                status = None if m.group(1) in ("y", "a") else DECLINED
                self._file(store, session, subject[0][0], MENTION, "read",
                           subject[0][1].strip(),
                           "agent" if replied else "user", status)
            return
        m = _URL_Q.match(message)
        if m:
            subject = self._subject(recent, tally)
            # A yes is a fetch, read from its "Scraping" line.
            if (subject and len(subject) == 1 and subject[0][1].strip()
                    and m.group(1) not in ("y", "a")):
                self._fetch(store, session, subject[0][0], URL_MENTION,
                            subject[0][1].strip(), DECLINED)
            return
        if startup:
            m = _LAUNCHED.match(message)
            if m:
                self._file(store, session, line_no, LAUNCH, "read", m.group(1),
                           "user")
                return
        m = _EXECUTING.match(message)
        if m:
            self._command(store, session, line_no, m.group(1))
            return
        for pattern, name, kind, actor, status in (
                (_ADDED, ADD, "read", "user", None),
                (_RO_DIR, READ_ONLY, "read", "user", None),
                (_RO_FILE, READ_ONLY, "read", "user", None),
                (_OUTSIDE, ADD, "read", "user", DECLINED),
                (_IGNORED, ADD, "read", "user", DECLINED),
                (_SKIPPED, ADD, "read", "user", DECLINED),
                (_DRY_RUN, EDIT, "write", "agent", DECLINED),
                (_APPLIED, EDIT, "write", "agent", None)):
            m = pattern.match(message)
            if m:
                self._file(store, session, line_no, name, kind, m.group(1),
                           actor, status)
                return
        m = _SCRAPING.match(message)
        if m:
            self._fetch(store, session, line_no, WEB, m.group(1))
