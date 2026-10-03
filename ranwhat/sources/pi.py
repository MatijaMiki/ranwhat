"""Pi coding agent (design section 7.11).

Pi (earendil-works/pi, npm @earendil-works/pi-coding-agent, formerly
badlogic/pi-mono) keeps one JSON Lines file per session under its agent
folder: sessions/--<cwd>--/<timestamp>_<sessionId>.jsonl, where <cwd> is
the working directory with its leading separator removed and "/", "\\" and
":" turned into "-". Line 1 is the session header; every later line is an
entry of a tree (id, parentId), and every branch of that tree ran.

A "message" entry holds one message:
- assistant: content blocks, among them {"type": "toolCall", "id", "name",
  "arguments": {...}};
- toolResult: {"toolCallId", "toolName", "content": [text and image
  blocks], "isError", "details"?}, a line of its own after the call;
- bashExecution: a command the user ran with "!" or "!!": {"command",
  "output", "exitCode", "cancelled", "truncated", "fullOutputPath"?,
  "excludeFromContext"?}. Not in the design's spec; read from v0.99.2's
  core/messages.ts and AgentSession.recordBashResult, which appends it to
  the session.
- system, user, custom (hookMessage before format version 3): no call.

Two facts from Pi's own code (v0.99.2) that the design's spec does not
list:
- A tool can call other tools while it runs (ctx.executeTool; the built-in
  codemode tool does it for every tools.<name>() in its script, and with
  codemode.mode "only" every bash, read and write goes that way). Those
  calls are kept on the calling tool's result, in
  toolResult.nestedCalls = {"calls": [{"id": "<callerId>/<n>", "name",
  "arguments"?, "argumentsBytes"?, "status", "durationMs"?, "error"?}],
  "complete"} (ai/src/types.ts NestedToolCallRecord; core/
  nested-tool-calls.ts). Their results are not kept. Each one is a call
  here, mapped by name like any other. Pi leaves "arguments" out (and
  sets "argumentsBytes") once they pass 8 KiB for one call or 32 KiB in
  all; such a call is counted as unreadable. Pi records at most 256 such
  calls for one model-issued call (deeper calls included) and drops the
  rest without a trace but "complete": false; a record that is full and
  incomplete is counted (CAPPED), since calls may be missing from it.
  "complete" is also false when arguments were left out or a call had
  not finished, so it is not read as "calls were dropped" on its own.
- An assistant message whose stopReason is "aborted" or "error" is saved
  with its toolCall blocks, but none of them ran: the agent loop stops
  before running tools (agent/src/agent-loop.ts; so since the coding
  agent's first release), and "continue" refuses to resume from an
  assistant message. Those calls are "declined". With "length", Pi 0.80.4
  and later runs none of the calls either and answers each with an error
  result 'Tool call "<name>" was not executed: the response hit the
  output token limit...'; earlier versions ran them. Pi does not write its
  version into a session, so such a call is "declined" only when that
  result is in the file. A call Pi refused to run, whatever the message
  stopped on, is "declined" too when its error result (or a nested
  record's error) is one of Pi's own texts for it: the tool is not loaded,
  the arguments fail its schema, or a tool_call hook blocked it without a
  reason of its own (agent-loop.ts prepareToolCall). A hook's own reason,
  as Pi's permission-gate example gives, reads like any failed run.

Format versions: 3 is current. Version 2 is the same tree with the role
"hookMessage" where 3 says "custom". Version 1 has no "version" in its
header and no id or parentId on its entries. Pi migrates a file when it
loads it; one it has not loaded since is read here as it is.

Where (v0.99.2): PI_CODING_AGENT_DIR, else ~/.pi/agent (config.ts
getAgentDir; the same under the home directory on Windows, not checked
there). PI_CODING_AGENT_SESSION_DIR (also --session-dir and the sessionDir
setting, which are not read here) puts new sessions flat in another folder,
<dir>/<timestamp>_<sessionId>.jsonl, with no per-cwd folder (main.ts,
SessionManager.create). The variable is not in the design's spec; it is
read because it is the agent's own override and its layout is verified.

Not read: anything in the agent folder outside sessions/ (auth.json,
settings.json, models.json, the debug log), and the full output of a
truncated bash command, which Pi spills to a temporary file and names in
details.fullOutputPath (bash tool) or fullOutputPath (bashExecution).
"""

from __future__ import annotations

import json
import os

from . import _lines, _paths, _stamps, base
from .base import SecretText, Source, ToolCall

ENV = "PI_CODING_AGENT_DIR"
SESSION_ENV = "PI_CODING_AGENT_SESSION_DIR"

ROOT = (".pi", "agent")
SESSIONS = "sessions"
SUFFIX = ".jsonl"

# A copy of watch._PATH_KEYS: where a read or write names its file. Pi's
# read and write take "path" (v0.99.2, core/tools/read.ts and write.ts);
# the design has the adapter take whichever of watch's own keys the
# arguments hold. Not imported: nothing in ranwhat.sources imports watch.
# tests/test_source_pi.py checks the two stay equal.
PATH_KEYS = ("file_path", "path", "notebook_path", "filePath", "file",
             "filename", "paths")

SHELL = "bash"
READ = "read"
WRITE = "write"
USER_SHELL = "bashExecution"            # the role, used as the tool name

DECLINED = "declined"

# stopReason values after which Pi runs none of the message's tool calls
# (agent-loop.ts runLoop returns before executeToolCalls).
NEVER_RAN = ("aborted", "error")

# stopReason "length": since 0.80.4 every call of the message is answered
# with this error instead of being run (agent-loop.ts
# failToolCallsFromTruncatedMessage). %s is the toolCall's name.
LENGTH = "length"
NOT_EXECUTED = ('Tool call "%s" was not executed: the response hit the '
                'output token limit')

# The error results Pi writes instead of running a call it will not run
# (see the module notes; agent-loop.ts prepareToolCall, ai validation.ts
# validateToolArguments). Not "Operation aborted": read and write also
# throw it part way. %s is the call's name.
NOT_FOUND = "Tool %s not found"
INVALID = 'Validation failed for tool "%s":'
BLOCKED = "Tool execution was blocked"

# How many nested calls Pi records for one model-issued call
# (core/nested-tool-calls.ts NESTED_CALL_LIMITS.maxCalls); a further call is
# not recorded at all, and the record says "complete": false.
NESTED_MAX_CALLS = 256

# The counter for tool calls whose nested-call record is full and
# incomplete: an unknown number of calls they made is not in the file.
CAPPED = "nested_capped"

# Entry types the format lists (docs/session-format.md). Others are counted.
TYPES = ("session", "message", "model_change", "thinking_level_change",
         "usage", "compaction", "context_edit", "branch_summary", "custom",
         "custom_message", "label", "session_info")

# Message roles Pi writes to a session (SessionManager.appendMessage takes
# Message | CustomMessage | BashExecutionMessage); "hookMessage" is the
# version 2 name of "custom". Others are counted.
ROLES = ("system", "user", "assistant", "toolResult", USER_SHELL, "custom",
         "hookMessage")

# The header is the first line. A longer first line is not read for the
# store's session and project; the transcript itself still is.
_HEADER_MAX = 1 << 16

_BAD = object()         # a line that is not JSON


def _string(value):
    return value if isinstance(value, str) and value else None


def _expand(value, home, platform):
    """`value` with a leading ~ made the home directory, the way Pi's
    normalizePath does it: "~" and "~/..." everywhere, "~\\..." on
    Windows too."""
    win = _paths.platform_name(platform) == "win32"
    if value == "~":
        return home
    if value.startswith("~/") or (win and value.startswith("~\\")):
        return _paths.join(platform, home, value[2:])
    return value


def output_text(content):
    """The text of a tool result's content: the text blocks joined by
    newlines (images carry no text), or a string as it is. None when there
    is no text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = [b.get("text") for b in content
                 if isinstance(b, dict) and b.get("type") == "text"
                 and isinstance(b.get("text"), str)]
        if texts:
            return "\n".join(texts)
    return None


def _refused(text, name):
    """True for the error text Pi writes instead of running a call to
    `name` (NOT_FOUND, INVALID, BLOCKED)."""
    if not isinstance(text, str):
        return False
    return text == BLOCKED or (name is not None and (
        text == NOT_FOUND % name or text.startswith(INVALID % name)))


def session_from_name(path):
    """The session id in a file name <timestamp>_<sessionId>.jsonl. The
    timestamp holds no "_"; a name without one is its own id."""
    stem = os.path.basename(path)
    if stem.endswith(SUFFIX):
        stem = stem[:-len(SUFFIX)]
    return stem.split("_", 1)[1] if "_" in stem else stem


def _pi_path(value):
    """A path as Pi's read and write tools take it: one leading "@" is
    dropped before the path is resolved, so "@.env" reads ./.env
    (core/tools/path-utils.ts resolveToCwd, stripAtPrefix)."""
    return value[1:] if value.startswith("@") else value


def _paths_in(arguments):
    """(paths, keys): the values of PATH_KEYS in a call's arguments, in that
    order, as Pi resolves them (_pi_path), and the keys they came from."""
    paths, keys = [], []
    for key in PATH_KEYS:
        value = arguments.get(key)
        found = [p for p in (_pi_path(v) for v in (
            value if isinstance(value, (list, tuple)) else [value])
            if isinstance(v, str)) if p]
        if found:
            paths.extend(found)
            keys.append(key)
    return tuple(paths), tuple(keys)


def _classify(name, arguments):
    """(kind, known, command, paths, consumed) for a call to the tool
    `name` with these (decoded) arguments: Pi's bash, read and write by the
    spec, any other name unknown."""
    if name == SHELL:
        command = _string(arguments.get("command"))
        return "shell", True, command, (), ("command",) if command else ()
    if name == READ:
        paths, keys = _paths_in(arguments)
        return "read", True, None, paths, keys
    if name == WRITE:
        paths, _keys = _paths_in(arguments)
        return "write", True, None, paths, ()
    return "other", False, None, (), ()


def _read_header(path):
    """The session header on the first line of `path`, or None."""
    try:
        with open(path, "rb") as fh:
            raw = fh.readline(_HEADER_MAX)
    except OSError:
        return None
    try:
        obj = json.loads(_lines.decode_line(raw, first=True))
    except (ValueError, RecursionError):
        return None
    if isinstance(obj, dict) and obj.get("type") == "session":
        return obj
    return None


def _entries(folder):
    try:
        return list(os.scandir(folder))
    except OSError:
        return []


def _files(folder):
    """Session files directly in `folder` (*.jsonl, not dot-files)."""
    out = []
    for entry in _entries(folder):
        if entry.name.startswith(".") or not entry.name.endswith(SUFFIX):
            continue
        try:
            if entry.is_file():
                out.append(entry.path)
        except OSError:
            continue
    return out


def _folders(folder):
    """The per-cwd folders in sessions/ (any folder, as Pi lists them;
    not dot-folders)."""
    out = []
    for entry in _entries(folder):
        if entry.name.startswith("."):
            continue
        try:
            if entry.is_dir():
                out.append(entry.path)
        except OSError:
            continue
    return out


class PiSource(Source):
    id = "pi"
    name = "Pi"
    unit = "session"
    env = (ENV, SESSION_ENV)
    path_means = "a Pi agent folder (what PI_CODING_AGENT_DIR means)"
    checked = "0.99.2"
    # Said after masking (design 3.7). Pi appends by path, so a masked file
    # keeps what it writes next, but an open session is held in memory, and
    # a fork or clone made from it is written from there.
    mask_note = ("If Pi is open on this session, close it first: a fork made "
                 "from it later is copied from memory, value included.")

    def reset(self):
        Source.reset(self)
        self.counts.setdefault(CAPPED, 0)
        self._bad = set()       # stores already counted as unreadable
        self._tallied = set()   # stores whose skipped lines are counted
        self._calls_tallied = set()     # stores whose bad calls are counted

    def notes(self, locations=None, platform=None):
        """Lines for `ranwhat sources` and the reports: calls this run could
        not read, and calls Pi did not record."""
        out = []
        n = self.counts.get("unreadable_calls", 0)
        if n == 1:
            out.append("1 Pi tool call made inside another tool (a codemode "
                       "script, for example) could not be read: Pi kept no "
                       "arguments for it, as it does once they pass 8 KiB "
                       "for one call or 32 KiB in all.")
        elif n:
            out.append("%d Pi tool calls made inside another tool (a "
                       "codemode script, for example) could not be read: Pi "
                       "kept no arguments for them, as it does once they "
                       "pass 8 KiB for one call or 32 KiB in all." % n)
        n = self.counts.get(CAPPED, 0)
        if n == 1:
            out.append("1 Pi tool call (a codemode script, for example) made "
                       "%d calls to other tools, as many as Pi records for "
                       "one call. Pi kept nothing of any it made after "
                       "those, so they were not checked." % NESTED_MAX_CALLS)
        elif n:
            out.append("%d Pi tool calls (codemode scripts, for example) "
                       "each made %d calls to other tools, as many as Pi "
                       "records for one call. Pi kept nothing of any they "
                       "made after those, so they were not checked."
                       % (n, NESTED_MAX_CALLS))
        return out

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """PI_CODING_AGENT_DIR when set, else ~/.pi/agent; and the folder
        PI_CODING_AGENT_SESSION_DIR names, when set, beside it (sessions
        written before it was set are still in the agent folder)."""
        out = []
        moved = _string(env.get(ENV))
        if moved:
            out.append((_expand(moved, home, platform), "env " + ENV))
        else:
            out.append((_paths.join(platform, home, *ROOT), "default"))
        flat = _string(env.get(SESSION_ENV))
        if flat:
            out.append((_expand(flat, home, platform), "env " + SESSION_ENV))
        return out

    @staticmethod
    def session_folders(location):
        """The folders whose *.jsonl files are sessions: the folder itself
        for PI_CODING_AGENT_SESSION_DIR, else each folder in its sessions/
        (an agent folder, from the default, PI_CODING_AGENT_DIR or --path)."""
        if location.how == "env " + SESSION_ENV:
            return [location.path]
        return _folders(os.path.join(location.path, SESSIONS))

    def stores(self, locations, since_days=None):
        found, seen = [], set()
        for loc in locations:
            for folder in self.session_folders(loc):
                for path in _files(folder):
                    key = os.path.normcase(os.path.abspath(path))
                    if key in seen:
                        continue
                    seen.add(key)
                    header = _read_header(path) or {}
                    session = (_string(header.get("id"))
                               or session_from_name(path))
                    store = self.store(path, "jsonl", role="transcript",
                                       session=session,
                                       project=_string(header.get("cwd")))
                    if store is not None:
                        found.append(store)
        return base.newest_first(found, since_days)

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason)
        self.warn(store.path, "could not read Pi %s %s (%s)"
                  % (store.unit, store.path, reason))

    @staticmethod
    def _first(store, tallied):
        """True the first time a store is read this run: watch and clean
        both read it, and what it skipped is counted once."""
        first = store.path not in tallied
        tallied.add(store.path)
        return first

    def _records(self, store):
        """(line_no, obj, text) for every line with something on it. obj is
        _BAD for a line that is not JSON (counted when it is complete; a
        last line with no newline is one still being written): tool_calls
        passes over it, and secret_texts hands its text to clean. Records
        of a type the format does not list are counted. A store that cannot
        be opened warns once and yields nothing; one with lines but none of
        them JSON warns once when it has been read."""
        tally = self._first(store, self._tallied)
        parsed = bad = 0
        try:
            with open(store.path, "rb") as fh:
                for line_no, raw in enumerate(fh, 1):
                    text = _lines.decode_line(raw, first=line_no == 1)
                    if not text.strip():
                        continue
                    try:
                        obj = json.loads(text)
                    except (ValueError, RecursionError):
                        if raw.endswith(b"\n"):
                            bad += 1
                        yield line_no, _BAD, text
                        continue
                    parsed += 1
                    if tally and self._unknown(obj):
                        self.count("unknown")
                    yield line_no, obj, text
        except OSError as e:
            self._bad_store(store, e.strerror or str(e))
            return
        finally:
            if tally:
                self.count("unparsed", bad)
        if bad and not parsed:
            self._bad_store(store, "not JSON Lines")

    @staticmethod
    def _unknown(obj):
        if not isinstance(obj, dict) or obj.get("type") not in TYPES:
            return True
        if obj.get("type") == "message":
            message = obj.get("message")
            return not (isinstance(message, dict)
                        and message.get("role") in ROLES)
        return False

    def _base(self, store, entry, header, message):
        """The fields every call from this entry shares."""
        timestamp = (_stamps.iso_utc(entry.get("timestamp"), "iso")
                     or _stamps.iso_utc(message.get("timestamp"), "ms"))
        return dict(
            session=_string(header.get("id")) or store.session,
            project=_string(header.get("cwd")),
            timestamp=timestamp,
            not_after=None if timestamp else _stamps.iso_utc(store.mtime, "s"))

    def _call(self, store, block, entry, header, message):
        """The ToolCall for one toolCall content block. Declined when its
        message stopped in a way after which Pi runs no tool (NEVER_RAN)."""
        name = _string(block.get("name")) or ""
        namespace = _string(block.get("namespace"))
        arguments = base.decode_input(block.get("arguments"))
        if namespace:
            # An OpenAI Responses namespace: a tool loaded from elsewhere,
            # never one of Pi's own. Judged by its name.
            name = "%s.%s" % (namespace, name)
            kind, known, command, paths, consumed = _classify(None, {})
        else:
            kind, known, command, paths, consumed = _classify(name, arguments)
        status = DECLINED if message.get("stopReason") in NEVER_RAN else None
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            tool_call_id=_string(block.get("id")), command=command,
            paths=paths, consumed=consumed, status=status,
            **self._base(store, entry, header, message))

    def _nested(self, store, entry, header, message, seen, capped, tally):
        """The ToolCalls for the calls a tool made while it ran, kept on its
        result as nestedCalls.calls (see the module notes), once per record
        id. Their results are not kept; a failed one's error text is the
        output, and one Pi refused to run is "declined" (_refused). A
        record without arguments (too large for Pi to keep) is
        yielded and counted as unreadable; one that is not an object is
        counted as unknown. A list Pi filled to its limit and marked
        incomplete is counted once per calling tool call (CAPPED): calls
        after the limit left nothing in the file."""
        nested = message.get("nestedCalls")
        records = nested.get("calls") if isinstance(nested, dict) else None
        if not isinstance(records, list):
            return
        if (nested.get("complete") is False
                and len(records) >= NESTED_MAX_CALLS):
            caller = message.get("toolCallId")
            if not isinstance(caller, str) or caller not in capped:
                if isinstance(caller, str):
                    capped.add(caller)
                if tally:
                    self.count(CAPPED)
        shared = None
        for record in records:
            if not isinstance(record, dict):
                if tally:
                    self.count("unknown")
                continue
            rid = _string(record.get("id"))
            if rid is not None:
                if rid in seen:
                    continue
                seen.add(rid)
            if "arguments" not in record and tally:
                self.count("unreadable_calls")
            name = _string(record.get("name")) or ""
            arguments = base.decode_input(record.get("arguments"))
            kind, known, command, paths, consumed = _classify(name, arguments)
            error = record.get("error")
            refused = record.get("status") == "error" and _refused(error, name)
            if shared is None:
                shared = self._base(store, entry, header, message)
            yield ToolCall(
                self.id, store.path, name, arguments, kind=kind, known=known,
                tool_call_id=rid, command=command, paths=paths,
                consumed=consumed, status=DECLINED if refused else None,
                output=error if isinstance(error, str) else None, **shared)

    @staticmethod
    def _not_executed(message, output, name):
        """True for the result Pi writes, instead of running it, for a call
        from a message stopped by "length" (NOT_EXECUTED)."""
        return (name is not None and message.get("isError") is True
                and isinstance(output, str)
                and output.startswith(NOT_EXECUTED % name))

    def _user_shell(self, store, entry, header, message):
        """The ToolCall for a bashExecution message: a command the user ran,
        its output in the same message. A cancelled command still ran."""
        command = _string(message.get("command"))
        output = message.get("output")
        recorded = {k: message[k] for k in ("command",) if k in message}
        return ToolCall(
            self.id, store.path, USER_SHELL, recorded, kind="shell",
            known=True, actor="user", tool_call_id=_string(entry.get("id")),
            command=command, consumed=("command",) if command else (),
            output=output if isinstance(output, str) else None,
            **self._base(store, entry, header, message))

    @staticmethod
    def _message(obj):
        """The message of a "message" entry, or None."""
        if not isinstance(obj, dict) or obj.get("type") != "message":
            return None
        message = obj.get("message")
        return message if isinstance(message, dict) else None

    @staticmethod
    def _tool_calls_in(message):
        content = message.get("content")
        if message.get("role") != "assistant" or not isinstance(content, list):
            return []
        return [b for b in content
                if isinstance(b, dict) and b.get("type") == "toolCall"]

    def tool_calls(self, store):
        """Every call in the file, on every branch of its tree, once per id
        (the first copy), with its result's text as output when the file
        holds one, and after it the calls it made while it ran (nested
        calls). A call is yielded when its result arrives, and calls still
        waiting at the end of the file are yielded then, so a long session
        is not held in memory whole. A call that never ran is "declined"
        (see the module notes)."""
        if store.role != "transcript":
            return
        tally = self._first(store, self._calls_tallied)
        header = {}
        pending = {}            # toolCall id -> ToolCall awaiting its result
        done = set()            # ids already yielded
        nested = set()          # nested call ids already yielded
        capped = set()          # toolCall ids whose full record is counted
        cut = {}                # toolCall id -> name, its message hit "length"
        for _line_no, obj, _text in self._records(store):
            if obj is _BAD:
                continue
            if isinstance(obj, dict) and obj.get("type") == "session":
                if not header:
                    header = obj
                continue
            message = self._message(obj)
            if message is None:
                continue
            role = message.get("role")
            if role == USER_SHELL:
                eid = _string(obj.get("id"))
                if eid is None or eid not in done:
                    if eid is not None:
                        done.add(eid)
                    yield self._user_shell(store, obj, header, message)
                continue
            if role == "toolResult":
                cid = message.get("toolCallId")
                call = pending.pop(cid, None) if isinstance(cid, str) else None
                if call is not None:
                    call.output = output_text(message.get("content"))
                    refused = message.get("isError") is True and _refused(
                        call.output, _string(message.get("toolName")))
                    if self._not_executed(message, call.output,
                                          cut.pop(cid, None)) or refused:
                        call.status = DECLINED
                    done.add(cid)
                    yield call
                for inner in self._nested(store, obj, header, message,
                                          nested, capped, tally):
                    yield inner
                continue
            length = message.get("stopReason") == LENGTH
            for block in self._tool_calls_in(message):
                call = self._call(store, block, obj, header, message)
                cid = call.tool_call_id
                if cid is None:
                    yield call          # nothing to pair it with
                elif cid not in done and cid not in pending:
                    pending[cid] = call
                    if length:
                        cut[cid] = _string(block.get("name")) or ""
        for call in pending.values():
            yield call

    def secret_texts(self, store):
        """Every line of the file, whatever its type. A tool result's
        content, and a bashExecution's output, are handed over on their own
        and tied to the call that produced them; the rest of that line is
        handed over without them. A line that is not JSON is handed over as
        text."""
        if store.role != "transcript":
            return
        header = {}
        calls = {}              # toolCall id -> ToolCall, first copy
        for line_no, obj, text in self._records(store):
            where = "line %d" % line_no
            if obj is _BAD:
                yield SecretText(text, where=where)
                continue
            if (not header and isinstance(obj, dict)
                    and obj.get("type") == "session"):
                header = obj
            message = self._message(obj)
            role = message.get("role") if message is not None else None
            if role == "toolResult" and "content" in message:
                cid = message.get("toolCallId")
                call = calls.get(cid) if isinstance(cid, str) else None
                yield SecretText(self._without(obj, message, "content"),
                                 where=where)
                yield SecretText(message["content"], call=call, where=where)
                continue
            if role == USER_SHELL and "output" in message:
                call = self._user_shell(store, obj, header, message)
                yield SecretText(self._without(obj, message, "output"),
                                 where=where)
                yield SecretText(message["output"], call=call, where=where)
                continue
            if message is not None:
                for block in self._tool_calls_in(message):
                    call = self._call(store, block, obj, header, message)
                    cid = call.tool_call_id
                    if cid is not None and cid not in calls:
                        calls[cid] = call
            yield SecretText(obj, where=where)

    @staticmethod
    def _without(obj, message, key):
        """The entry with `key` left out of its message."""
        rest = dict(obj)
        rest["message"] = {k: v for k, v in message.items() if k != key}
        return rest
