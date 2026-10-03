"""Factory Droid: the `droid` CLI and `droid exec` (design section 7.10).

Droid keeps one JSON Lines file per session under ~/.factory/sessions:
flat in the folder (the legacy layout), in a folder per project named after
the working directory with its slashes turned into dashes
("-Users-me-proj"), or under btw/ for side-question forks. Line 1 is a
session_start record; every later message line holds Anthropic-style
content blocks: tool_use in assistant messages, tool_result in user ones.
A command the user runs in bash mode (a prompt starting with "!") is a user
message too: its one text block is the JSON string of a bash_result record,
{"type", "command", "stdout", "stderr", "exitCode"}. Those are the user's
own shell calls (actor "user").

Beside them, clean also reads the full text of outputs the transcript keeps
cut short, and the prompts the user typed:
- Execute keeps at most 16,384 bytes of a command's output in its result
  (8 KiB of head, 8 KiB of tail, "[... truncated N bytes from middle
  section ...]" between them). The whole output stays in the OS temp folder
  as droid-terminal-<6 chars>/<terminal id>.log (0600), and the result
  names it: "Full command output saved to: <path> (<size>)". stores() reads
  each transcript for those notices and follows only ones that name such a
  file inside the OS temp folder as ranwhat finds it, checked as a string
  before the path is looked up, so a notice never makes it touch a network
  share.
- Execute with fireAndForget starts a background process whose whole
  stdout and stderr go to <OS temp folder>/droid-bg-<Date.now()>.out. The
  file outlives Droid, and the result names it on an "Output: <path>" line
  ("Background process started (PID: n)" or "... completed (...)", then
  "Command: ...", "Output: ...", "Status: ..."). stores() follows those
  lines too, only to such a file, and only inside the OS temp folder. The
  process may still be writing to it, and nothing verified tells whether
  it is, so it is read-only.
- Grep, LS, FetchUrl, WebSearch, Task, TaskOutput, ConnectorSearch, mcp_*
  and connectors_* results over 40,000 characters (Task and TaskOutput:
  100,000) are cut to 75% head and 25% tail with "[... truncated N
  characters from middle section ...]", and the whole text is written to
  artifacts/tool-outputs/<tool id>-<call id>-<8 digits>.log, named after the
  internal tool id (grep_tool_cli, fetch_url, ...). Execute's capped result
  never reaches that size. The result names the file in a system reminder,
  "The full result is saved to <path>.", and a log whose name carries the
  id of the call whose result names it is tied to that call, as a terminal
  log is: its secrets get the origin they would have in the transcript.
- state/history.json, and the older history.json at the root that Droid
  moves there: [{command, timestamp (ISO), type ("message",
  "slash_command" or "bash_command"), mode ("chat" or "bash")}].

The CLI is closed source. The layout is from Factory's Apache-2.0 SDK
(@factory/droid-sdk 0.9.1, whose listSessions() reads this folder) and the
official 0.231.0 binary's embedded JavaScript. Fields the design does not
list are not read, and nothing here guesses a key name.

Not stores, never opened: the *.settings.json beside each session,
sessions/.favorites, cache/, logs/ and settings.json.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import time

from . import _lines, _paths, _stamps, base
from .base import SecretText, Source, ToolCall

ENV = "FACTORY_HOME_OVERRIDE"

# The folder Droid keeps everything in, under the home directory (or under
# FACTORY_HOME_OVERRIDE, which replaces it). Development builds use the
# second name.
ROOT = ".factory"
DEV_ROOT = ".factory-dev"
ROOTS = (ROOT, DEV_ROOT)

SESSIONS = "sessions"
FORKS = "btw"                       # side-question forks
TOOL_OUTPUTS = ("artifacts", "tool-outputs")
HISTORIES = (("state", "history.json"), ("history.json",))

# tool name -> kind, exactly as the spec writes the names.
SHELL = {"Execute"}
READ = {"Read"}
WRITE_WITH_PATH = {"Create", "Edit"}
WRITE = {"MultiEdit", "ApplyPatch"}         # arguments unverified: no paths
FETCH = {"FetchUrl", "WebSearch"}
OTHER = {"LS", "Glob", "Grep", "Task", "TodoWrite", "AskUser"}
# "Script" is deliberately absent: what it runs is unverified, so it is
# judged by its name like any tool this adapter does not know.

# A command the user ran in bash mode: the record type, used as the tool
# name. Droid writes it with JSON.stringify (type first, no spaces); only
# a text that names the type is parsed, however it is spaced.
USER_SHELL = "bash_result"
_USER_SHELL_MARK = '"bash_result"'
_USER_SHELL_OUTPUTS = ("stdout", "stderr")

# Record types the spec lists, and agent_turn_outcome ({turnId, reason,
# resultKind, result?, schemaFingerprint?}), which the 0.231.0 binary
# appends to the session file at the end of a turn. Anything else is
# counted as unknown. None of them but message carries a call.
TYPES = ("session_start", "message", "todo_state", "compaction_state",
         "agent_turn_outcome")

# Execute's notice naming the file that holds a command's whole output, on
# a line of its own, then the size in brackets (Droid prints "35KB" or
# "1.2MB"; any size is taken, since the path is what is checked).
_SAVED = "Full command output saved to: "
_SAVED_BYTES = _SAVED.encode("utf-8")
_SAVED_LINE = re.compile(
    r"^" + re.escape(_SAVED) + r"(.+) \([^()\n]+\)$", re.M)

# The only files such a notice is followed to: <temp>/droid-terminal-<6
# chars, from mkdtemp>/<terminal id>.log, the terminal id a UUID.
_TERMINAL_DIR = "droid-terminal-"
_TERMINAL_LOG = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.log\Z")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

# A result over its tool's limit, written whole to artifacts/tool-outputs:
# $c() names the file ${_r(toolId)}-${_r(toolCallId)}-${8 digits}.log,
# where _r() turns every character but letters, digits, ".", "_" and "-"
# into "-" and keeps 200 of them, and Hc() names that path in a system
# reminder, a sentence of its own: "The full result is saved to <path>.
# When your conclusion depends on ...". Only a log already found in the
# tool-outputs folder of the transcript's own Droid folder, under the name
# the notice gives, is tied: the notice sits beside the tool's own output,
# so it never makes ranwhat open a file, and the folder may have moved
# since (read through --path from a copy).
_SPILL = "The full result is saved to "
_SPILL_BYTES = _SPILL.encode("utf-8")
_SPILL_LINE = re.compile(re.escape(_SPILL) + r"(.+?\.log)\.(?=\s|$)", re.M)
_SPILL_NAME = re.compile(r"(.+)-[0-9]{8}\.log\Z")
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")

# A background Execute's result: its first line, then the line naming the
# file the process writes all its output to. That file is
# <temp>/droid-bg-<Date.now()>.out (13 digits from 2001 to 2286), in the
# OS temp folder itself, which may be a link (/tmp on macOS), so only the
# file is checked.
_BACKGROUND = ("Background process started (", "Background process completed (")
_BACKGROUND_BYTES = b"Background process "
_OUTPUT = "Output: "
_BACKGROUND_OUT = re.compile(r"droid-bg-[0-9]{13}\.out\Z")
BACKGROUND_WHY = ("A command Droid started in the background may still be "
                  "writing to it, so ranwhat only reads it; stop that command, "
                  "then delete the file.")

# The first line is the session_start record. A longer first line is not
# read for the store's project; the transcript itself still is.
_HEADER_MAX = 1 << 16

# A log is read and handed to clean in pieces of at most this many bytes,
# so a log larger than clean's per-string limit is still searched to its
# end and this adapter never holds a background process's ever-growing
# output in memory whole. Each piece after the first starts _OVERLAP to
# 2 * _OVERLAP bytes before the one before it ended, so a value up to
# _OVERLAP bytes long lies whole in one of them: a private key block spans
# lines, and a line with no break in it is cut inside a word. A 4096-bit
# RSA key in PEM is about 3.2 KB.
_CHUNK = 256 * 1024
_OVERLAP = 32 * 1024
# Where a piece ends, in order of preference: after the last line end in
# its second half; else after the last carriage return there (progress
# bars redraw a line with them); else after the last space or tab. No key
# holds any of them. The next piece starts the same way, in the _OVERLAP
# bytes before the last _OVERLAP bytes of the piece.
_CUTS = ((b"\n",), (b"\r",), (b" ", b"\t"))


def _kind(name):
    """(kind, known) for a tool name."""
    if name in SHELL:
        return "shell", True
    if name in READ:
        return "read", True
    if name in WRITE_WITH_PATH or name in WRITE:
        return "write", True
    if name in FETCH:
        return "fetch", True
    if name in OTHER:
        return "other", True
    return "other", False


def _string(value):
    return value if isinstance(value, str) and value else None


def output_text(content):
    """The text of a tool_result's content: a string as it is, or the text
    blocks of a list joined by newlines (images carry no text). None when
    there is no text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = [b.get("text") for b in content
                 if isinstance(b, dict) and b.get("type") == "text"
                 and isinstance(b.get("text"), str)]
        if texts:
            return "\n".join(texts)
    return None


def _blocks(obj):
    """The content blocks of a message line, or []."""
    message = obj.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict)]


def _role(obj):
    message = obj.get("message")
    return message.get("role") if isinstance(message, dict) else None


def _bash_result(block):
    """The bash_result record a user message's text block holds, decoded,
    when it names a command. Else None."""
    if block.get("type") != "text":
        return None
    text = block.get("text")
    if not (isinstance(text, str) and text.lstrip()[:1] == "{"
            and _USER_SHELL_MARK in text):
        return None
    try:
        record = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not (isinstance(record, dict) and record.get("type") == USER_SHELL
            and _string(record.get("command"))):
        return None
    return record


def _key(path):
    return os.path.normcase(os.path.abspath(path))


def _plain(path, want):
    """True when `path` itself (not what a link points at) passes `want`
    and is neither a symbolic link nor, on Windows, a junction."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return False
    if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return False
    return want(st.st_mode)


def _temp_path(path):
    """`path`, absolute and with no "..", made normal when it lies inside
    the OS temp folder, where Droid writes its terminal logs and background
    outputs. Else None. Compared as strings, nothing looked up: a path in a
    tool result can name a network share (\\\\host\\share), and on Windows
    only looking it up sends the user's credentials to that host. What is
    looked up after is the normal form, the one that was checked."""
    if not os.path.isabs(path) or ".." in re.split(r"[\\/]+", path):
        return None
    path = os.path.abspath(path)
    folder = os.path.join(os.path.normcase(os.path.abspath(
        tempfile.gettempdir())), "")
    return path if os.path.normcase(path).startswith(folder) else None


def _terminal_log(path):
    """`path` when it is a Droid terminal log: an absolute path inside the
    OS temp folder to droid-terminal-<chars>/<uuid>.log, the file regular
    and the folder a real one (neither is a link). Else None.

    The notice that names it sits in a tool result, beside the command's
    own output, so its path is checked before anything is read: a line
    that only looks like the notice can point at nothing else."""
    path = _temp_path(path)
    if path is None:
        return None
    folder, name = os.path.split(path)
    base_name = os.path.basename(folder)
    if not (_TERMINAL_LOG.match(name) and base_name.startswith(_TERMINAL_DIR)
            and len(base_name) > len(_TERMINAL_DIR)):
        return None
    if not (_plain(folder, stat.S_ISDIR) and _plain(path, stat.S_ISREG)):
        return None
    return path


def _saved_paths(text):
    """The paths every "Full command output saved to:" line in `text`
    names, in order."""
    if not text or _SAVED not in text:
        return []
    return [m.group(1) for m in _SAVED_LINE.finditer(text)]


def _spill_paths(text):
    """The paths every "The full result is saved to <path>." sentence in
    `text` names, in order."""
    if not text or _SPILL not in text:
        return []
    return [m.group(1) for m in _SPILL_LINE.finditer(text)]


def _spill_name(path, cid):
    """The file name in `path` when it is a tool output log of the call
    `cid`: <tool id>-<call id as _r() writes it>-<8 digits>.log. Else
    None. Either separator is taken: the notice was written on the machine
    Droid ran on."""
    if not cid:
        return None
    name = re.split(r"[\\/]", path)[-1]
    m = _SPILL_NAME.match(name)
    if m is None:
        return None
    tail = "-" + (_UNSAFE.sub("-", cid)[:200] or "unknown")
    if not (m.group(1).endswith(tail) and len(m.group(1)) > len(tail)):
        return None
    return name


def _background_output(path):
    """`path` when it is a Droid background process's output: an absolute
    path inside the OS temp folder to droid-bg-<13 digits>.out, a regular
    file and not a link or junction. Else None. As with a terminal log, the
    line naming it sits beside text the agent wrote (the command), so the
    path is checked before anything is read."""
    path = _temp_path(path)
    if path is None or not _BACKGROUND_OUT.match(os.path.basename(path)):
        return None
    if not _plain(path, stat.S_ISREG):
        return None
    return path


def _background_paths(text):
    """The paths on the "Output: " lines of a background Execute's result,
    in order. [] for any other text."""
    if not text or not text.startswith(_BACKGROUND):
        return []
    return [line[len(_OUTPUT):] for line in text.split("\n")[1:]
            if line.startswith(_OUTPUT)]


def _cut(buf, low, size):
    """Where to cut `buf`: after the last of the first kind of _CUTS found
    in buf[low:size], else at `size` moved back to the start of a UTF-8
    character. `buf` is longer than `size`."""
    for marks in _CUTS:
        cut = max(buf.rfind(m, low, size) for m in marks) + 1
        if cut:
            return cut
    cut = size
    while cut > size - 3 and 0x80 <= buf[cut] < 0xC0:
        cut -= 1                    # buf[cut] continues a character
    return cut


def _read_header(path):
    """The session_start record on the first line of `path`, or None."""
    try:
        with open(path, "rb") as fh:
            raw = fh.readline(_HEADER_MAX)
    except OSError:
        return None
    if not raw.endswith(b"\n"):
        return None             # too long, or still being written
    try:
        obj = json.loads(_lines.decode_line(raw, first=True))
    except (ValueError, RecursionError):
        return None
    if isinstance(obj, dict) and obj.get("type") == "session_start":
        return obj
    return None


def _files(folder, suffix):
    """Regular files directly in `folder` whose names end with `suffix`,
    leaving out dot-files. [] when the folder cannot be listed."""
    out = []
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return out
    for entry in entries:
        if entry.name.startswith(".") or not entry.name.endswith(suffix):
            continue
        try:
            if entry.is_file():
                out.append(entry.path)
        except OSError:
            continue
    return out


def _subfolders(folder):
    """The session folders inside sessions/: every "-<sanitized cwd>"
    folder, and btw/."""
    out = []
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return out
    for entry in entries:
        if not (entry.name.startswith("-") or entry.name == FORKS):
            continue
        try:
            if entry.is_dir():
                out.append(entry.path)
        except OSError:
            continue
    return out


class DroidSource(Source):
    id = "droid"
    name = "Droid"
    unit = "session"
    env = (ENV,)
    path_means = ("a folder holding .factory (what FACTORY_HOME_OVERRIDE "
                  "means)")
    checked = "0.231.0"
    # Said after masking (design 3.7). A running Droid reads its prompt
    # history once, keeps it in memory and writes all of it back on every
    # prompt, so a masked history.json gets the value back however long
    # Droid has sat idle; and the cloud copy is out of reach.
    mask_note = ("If Droid is running, close it first, or it may write the "
                 "value back: it keeps its prompt history in memory and "
                 "saves all of it on every prompt. Droid also mirrors "
                 "sessions to Factory's cloud by default (cloudSessionSync); "
                 "the copy there is unchanged.")

    def reset(self):
        Source.reset(self)
        self._bad = set()       # stores already counted as unreadable
        self._tallied = set()   # stores whose skipped lines are counted
        # (path, mtime_ns, size) of a transcript -> [(log, tool_use id,
        # kind)] its results name, so stores() reads a transcript once a
        # run. A log is a terminal log, a background process's output, or
        # the name of a tool output log its result spilled into.
        self._saved = {}
        # log key -> (transcript Store, tool_use id): whose output the log
        # is. Transcript path -> the ids of the calls whose logs it owns,
        # filled beside it, so finding a log's call never walks every log.
        # Within a run these only grow, so a set's size is its version.
        # And transcript path -> (that size when read, {id: ToolCall}).
        self._log_owner = {}
        self._owner_ids = {}
        self._owner_calls = {}

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """~/.factory, and ~/.factory-dev for development builds. When
        FACTORY_HOME_OVERRIDE is set it replaces the home directory, so both
        folders are looked for under it instead."""
        join = _paths.pathmod(platform).join
        moved = env.get(ENV)
        if isinstance(moved, str) and moved:
            how = "env " + ENV
            return [(join(moved, ROOT), how), (join(moved, DEV_ROOT), how)]
        return [(join(home, ROOT), "default"), (join(home, DEV_ROOT), "probed")]

    @staticmethod
    def roots(path):
        """The Droid folders a location stands for. A folder named .factory
        or .factory-dev is one; any other folder (what --path droid= means)
        is one that holds them."""
        if os.path.basename(os.path.normpath(path)) in ROOTS:
            return [path]
        return [os.path.join(path, name) for name in ROOTS]

    def stores(self, locations, since_days=None):
        """Every transcript, tool-output log and prompt history under the
        locations, and every terminal log and background output a
        transcript's Execute results name inside the OS temp folder (Droid
        and ranwhat both find it from TMPDIR, or TEMP and TMP on Windows).
        With since_days, a transcript last written before the window is not
        read for those: its commands' logs were written before it was. A
        background process can outlive that, so its output, still growing
        inside the window, is missed when its session is not."""
        found, seen, transcripts = [], set(), []
        # each Droid folder's tool-output logs, by name, for the notices
        # in its own transcripts to be tied to
        outputs = {}
        cutoff = time.time() - since_days * 86400 if since_days else None

        def add(path, format, **fields):
            key = _key(path)
            if key in seen:
                return None
            seen.add(key)
            store = self.store(path, format, **fields)
            if store is not None:
                found.append(store)
            return store

        for loc in locations:
            for root in self.roots(loc.path):
                sessions = os.path.join(root, SESSIONS)
                folders = [sessions] + _subfolders(sessions)
                for folder in folders:
                    for path in _files(folder, ".jsonl"):
                        header = _read_header(path) or {}
                        stem = os.path.splitext(os.path.basename(path))[0]
                        store = add(path, "jsonl", role="transcript",
                                    session=_string(header.get("id")) or stem,
                                    project=_string(header.get("cwd")))
                        if store is not None:
                            transcripts.append((store, root))
                logs = os.path.join(root, *TOOL_OUTPUTS)
                named = outputs.setdefault(_key(root), {})
                for path in _files(logs, ".log"):
                    store = add(path, "text", role="side", unit="tool output")
                    if store is not None:
                        named[os.path.normcase(os.path.basename(path))] = store
                for parts in HISTORIES:
                    path = os.path.join(root, *parts)
                    if os.path.isfile(path):
                        add(path, "json", role="side", unit="prompt history")
        for transcript, root in transcripts:
            if cutoff is not None and transcript.mtime < cutoff:
                continue
            for log, cid, kind in self._saved_outputs(transcript.path):
                spill = None
                if kind == "spill":
                    spill = outputs.get(_key(root), {}).get(os.path.normcase(log))
                    if spill is None:
                        continue
                    log = spill.path
                key = _key(log)
                if key not in self._log_owner:
                    self._log_owner[key] = (transcript, cid)
                    if cid is not None:
                        self._owner_ids.setdefault(transcript.path, set()).add(cid)
                where = {"session": transcript.session,
                         "project": transcript.project}
                if spill is not None:
                    # already a store, and of the session whose call it is
                    if self._log_owner[key][0].path == transcript.path:
                        spill.session = transcript.session
                        spill.project = transcript.project
                elif kind == "background":
                    add(log, "text", role="side", unit="background output",
                        masking="read-only", why_read_only=BACKGROUND_WHY,
                        **where)
                else:
                    add(log, "text", role="side", unit="command output", **where)
        return base.newest_first(found, since_days)

    def _saved_outputs(self, path):
        """[(log, tool_use id, kind)] for every log a tool_result of the
        transcript at `path` names: a Droid terminal log on a "Full command
        output saved to:" line ("terminal"), a background process's output
        on an "Output: " line of a background Execute's result
        ("background"), and the name of a tool output log of that very call
        in a "The full result is saved to" notice ("spill": a name, not a
        path, for stores() to look for in tool-outputs). Only lines holding
        one of those are parsed. Read once per version of the file per run;
        a file that cannot be read gives [] here and warns when it is read
        for itself."""
        try:
            st = os.stat(path)
        except OSError:
            return []
        version = (_key(path), st.st_mtime_ns, st.st_size)
        if version in self._saved:
            return self._saved[version]
        out = []
        try:
            with open(path, "rb") as fh:
                for raw in fh:
                    if (_SAVED_BYTES not in raw and _BACKGROUND_BYTES not in raw
                            and _SPILL_BYTES not in raw):
                        continue
                    try:
                        obj = json.loads(_lines.decode_line(raw))
                    except (ValueError, RecursionError):
                        continue
                    if not (isinstance(obj, dict) and obj.get("type") == "message"):
                        continue
                    for block in _blocks(obj):
                        if block.get("type") != "tool_result":
                            continue
                        cid = _string(block.get("tool_use_id"))
                        text = output_text(block.get("content"))
                        for named in _saved_paths(text):
                            log = _terminal_log(named)
                            if log is not None:
                                out.append((log, cid, "terminal"))
                        for named in _background_paths(text):
                            log = _background_output(named)
                            if log is not None:
                                out.append((log, cid, "background"))
                        for named in _spill_paths(text):
                            name = _spill_name(named, cid)
                            if name is not None:
                                out.append((name, cid, "spill"))
        except OSError:
            out = []
        self._saved[version] = out
        return out

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read Droid %s %s (%s)"
                  % (store.unit, store.path, reason))

    def _tally(self, store):
        """True the first time a store is read this run: watch and clean
        both read it, and its skipped lines are counted once."""
        first = store.path not in self._tallied
        self._tallied.add(store.path)
        return first

    def _records(self, store):
        """(line_no, record) for every JSON object line of a transcript.
        Lines that do not parse, and records of a type the spec does not
        list, are counted. A store with lines but none of them JSON warns
        once; a store that cannot be opened warns once and yields nothing.
        A last line still being written is skipped quietly."""
        tally = self._tally(store)
        counts = {}
        parsed = 0
        try:
            for line_no, obj in _lines.iter_json_lines(store.path, counts):
                parsed += 1
                if not isinstance(obj, dict):
                    if tally:
                        self.count("unknown")
                    continue
                if tally and obj.get("type") not in TYPES:
                    self.count("unknown")
                yield line_no, obj
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        finally:
            if tally:
                self.count("unparsed", counts.get("unparsed", 0))
        if not parsed and counts.get("unparsed"):
            self._bad_store(store, "not JSON Lines")

    def _call(self, store, block, line, header):
        """The ToolCall for one tool_use block."""
        name = block.get("name")
        name = name if isinstance(name, str) else ""
        kind, known = _kind(name)
        tool_input = base.decode_input(block.get("input"))
        command, paths, consumed = None, (), ()
        if name in SHELL:
            command = _string(tool_input.get("command"))
            if command:
                consumed = ("command",)
        elif name in READ or name in WRITE_WITH_PATH:
            path = _string(tool_input.get("file_path"))
            if path:
                paths = (path,)
                if name in READ:
                    consumed = ("file_path",)
        return ToolCall(
            self.id, store.path, name, tool_input, kind=kind, known=known,
            tool_call_id=_string(block.get("id")), command=command,
            paths=paths, consumed=consumed,
            **self._where(store, line, header))

    def _user_call(self, store, record, line, header):
        """The ToolCall for a bash_result: a command the user ran in bash
        mode, with its output. Its id is the message line's."""
        command = record["command"]
        texts = [record.get(k) for k in _USER_SHELL_OUTPUTS
                 if isinstance(record.get(k), str)]
        output = "\n".join(t for t in texts if t) if texts else None
        return ToolCall(
            self.id, store.path, USER_SHELL, {"command": command},
            kind="shell", known=True, actor="user",
            tool_call_id=_string(line.get("id")), command=command,
            consumed=("command",), output=output,
            **self._where(store, line, header))

    @staticmethod
    def _where(store, line, header):
        """The session, project and time a call on this line has."""
        timestamp = _stamps.iso_utc(line.get("timestamp"), "iso")
        not_after = None
        if timestamp is None:
            not_after = _stamps.iso_utc(store.mtime, "s")
        stem = os.path.splitext(os.path.basename(store.path))[0]
        return {"session": _string(header.get("id")) or stem,
                "project": _string(header.get("cwd")),
                "timestamp": timestamp, "not_after": not_after}

    @staticmethod
    def _user_shells(obj):
        """[(index, block, bash_result)] for every bash_result in a user
        message line's content."""
        if obj.get("type") != "message" or _role(obj) != "user":
            return []
        out = []
        for index, block in enumerate(_blocks(obj)):
            record = _bash_result(block)
            if record is not None:
                out.append((index, block, record))
        return out

    def tool_calls(self, store):
        """Every tool_use in a transcript, once per id (the first copy), with
        its tool_result's text as output when the transcript holds one; and
        every command the user ran in bash mode, once per message id, with
        its stdout and stderr as output.

        A call is yielded when its result arrives, and calls still waiting
        for one at the end of the file are yielded then, so a long session
        is not held in memory whole."""
        if store.role != "transcript":
            return
        header = {}
        pending = {}            # id -> ToolCall still waiting for its result
        done = set()            # ids already yielded
        shells = set()          # (message id, block index) already yielded
        for _line_no, obj in self._records(store):
            rtype = obj.get("type")
            if rtype == "session_start":
                if not header:
                    header = obj
                continue
            if rtype != "message":
                continue            # todo_state, compaction_state, ...: no calls
            for block in _blocks(obj):
                btype = block.get("type")
                if btype == "tool_use":
                    call = self._call(store, block, obj, header)
                    cid = call.tool_call_id
                    if cid is None:
                        yield call          # nothing to pair it with
                    elif cid not in done and cid not in pending:
                        pending[cid] = call
                elif btype == "tool_result":
                    cid = block.get("tool_use_id")
                    call = pending.pop(cid, None) if isinstance(cid, str) else None
                    if call is not None:
                        call.output = output_text(block.get("content"))
                        done.add(cid)
                        yield call
            for index, _block, record in self._user_shells(obj):
                mid = _string(obj.get("id"))
                if mid is not None:
                    if (mid, index) in shells:
                        continue            # a replayed copy
                    shells.add((mid, index))
                yield self._user_call(store, record, obj, header)
        for call in pending.values():
            yield call

    def secret_texts(self, store):
        """Every string the store holds. In a transcript that is every line,
        whatever its type, with each tool_result's content, and each bash
        mode command's stdout and stderr, handed over on their own and tied
        to the call that produced them. A terminal log or background output
        is tied to the Execute call whose result named it, and a tool
        output log to the call whose result spilled into it."""
        if store.format == "jsonl":
            return self._transcript_texts(store)
        if store.format == "json":
            return self._history_texts(store)
        return self._log_texts(store)

    def _transcript_texts(self, store):
        header = {}
        calls = {}              # tool_use id -> ToolCall, first copy
        for line_no, obj in self._records(store):
            where = "line %d" % line_no
            if obj.get("type") == "session_start" and not header:
                header = obj
            blocks = _blocks(obj) if obj.get("type") == "message" else []
            results = []
            for block in blocks:
                if block.get("type") == "tool_use":
                    cid = block.get("id")
                    if isinstance(cid, str) and cid and cid not in calls:
                        calls[cid] = self._call(store, block, obj, header)
                elif block.get("type") == "tool_result":
                    results.append(block)
            shells = self._user_shells(obj)
            if not results and not shells:
                yield SecretText(obj, where=where)
                continue
            # The line without its results' content and without its bash
            # mode output (the command stays: what the user typed has no
            # origin), then each of those with the call it belongs to.
            swap = {}
            for block in results:
                swap[id(block)] = {k: v for k, v in block.items()
                                   if k != "content"}
            for _index, block, record in shells:
                swap[id(block)] = dict(block, text={
                    k: v for k, v in record.items()
                    if k not in _USER_SHELL_OUTPUTS})
            rest = dict(obj)
            message = dict(obj["message"])
            message["content"] = [swap.get(id(b), b) for b in message["content"]]
            rest["message"] = message
            yield SecretText(rest, where=where)
            for block in results:
                cid = block.get("tool_use_id")
                call = calls.get(cid) if isinstance(cid, str) else None
                yield SecretText(block.get("content"), call=call, where=where)
            for _index, _block, record in shells:
                outputs = {k: record[k] for k in _USER_SHELL_OUTPUTS if k in record}
                yield SecretText(outputs, where=where,
                                 call=self._user_call(store, record, obj, header))

    def _read_text(self, store):
        try:
            with open(store.path, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return None
        return raw.decode("utf-8", "surrogateescape")

    def _history_texts(self, store):
        text = self._read_text(store)
        if text is None:
            return
        try:
            doc = json.loads(text.lstrip(_lines.BOM))
        except (ValueError, RecursionError):
            # Searched as text instead: the history is one document, so one
            # entry nested deeper than this Python decodes would otherwise
            # hide every prompt beside it. Nothing in it goes unread, and it
            # holds no calls, so it is not counted as a file not read.
            self.warn(store.path, "Droid prompt history %s is not JSON, so "
                      "its text was searched as it is" % store.path)
            for item in self._log_texts(store):
                yield item
            return
        if not isinstance(doc, list):
            yield SecretText(doc, where="whole file")
            return
        for index, entry in enumerate(doc, 1):
            yield SecretText(entry, where="entry %d" % index)

    def _log_texts(self, store):
        """A tool-output log, terminal log or background output, or a
        prompt history that is not JSON, read in overlapping pieces of at
        most _CHUNK bytes, each cut after a line end where the piece holds
        one (see _CUTS). The pieces of each are tied to the call whose
        result named it, when stores() found that call this run."""
        try:
            fh = open(store.path, "rb")
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        with fh:
            call, looked = None, False
            buf, line_no, end = b"", 1, False
            while buf or not end:
                if not end and len(buf) <= _CHUNK:
                    try:
                        block = fh.read(_CHUNK)
                    except OSError as e:
                        self._bad_store(store, e.strerror or str(e))
                        return
                    end = not block
                    buf += block
                    continue
                if len(buf) > _CHUNK:
                    cut = _cut(buf, _CHUNK // 2, _CHUNK)
                    start = _cut(buf, cut - 2 * _OVERLAP, cut - _OVERLAP)
                else:
                    cut = start = len(buf)
                if not looked:
                    call, looked = self._log_call(store), True
                yield SecretText(buf[:cut].decode("utf-8", "surrogateescape"),
                                 call=call, where="line %d" % line_no)
                line_no += buf.count(b"\n", 0, start)
                buf = buf[start:]

    def _log_call(self, store):
        """The call a terminal log, background output or tool output log
        holds the output of, or None. The transcript that named it is read
        again only when stores() has tied more of its calls to logs since it
        was last read, so it is read once for all the logs it names."""
        owner = self._log_owner.get(_key(store.path))
        if owner is None or owner[1] is None:
            return None
        transcript, cid = owner
        wanted = self._owner_ids.get(transcript.path, ())
        cached = self._owner_calls.get(transcript.path)
        if cached is None or cached[0] != len(wanted):
            # read to the end, not stopped early, so the transcript's
            # skipped lines are counted in full
            calls = {c.tool_call_id: c for c in self.tool_calls(transcript)
                     if c.tool_call_id in wanted}
            cached = self._owner_calls[transcript.path] = (len(wanted), calls)
        return cached[1].get(cid)
