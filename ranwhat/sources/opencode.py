"""OpenCode (anomalyco/opencode, formerly sst/opencode; the CLI at opencode.ai).

Not Charm's Crush, which began as the Go project opencode-ai/opencode and
keeps a database of another shape in each project.

Verified from OpenCode's own source at v2.0.24 and v1.18.35 (the two
release lines, both current), v1.2.0 (the first with a database) and
v1.1.65 (the last that wrote JSON files only). Nothing of it was run.

Where: one data folder, $XDG_DATA_HOME/opencode, else
~/.local/share/opencode, on every system, Windows and macOS included
(xdg-basedir in v1, global.ts and v2's util global-roots.ts: neither
branches by OS). OPENCODE_DB names the database: an absolute path as it is,
anything else under the data folder, ":memory:" none at all (v2 cli
database-path.ts, v1.18 core database/database.ts path()). Without it the
file is opencode.db, or opencode-<channel>.db for a build of another
channel; v2 imports opencode-next.db, a database of its betas, once. So
every opencode*.db in the data folder is read, and the file OPENCODE_DB
names when it is set.

The database (SQLite, WAL mode) holds two formats, both read, and a v2
user's usually holds both:
- v1 (v1.2.0 to v1.18.x; core session/sql.ts): session, message and part
  tables. message.data and part.data are the v1 objects as JSON, less the
  id, sessionID and messageID the columns hold. A tool call is a part
  {"type": "tool", "callID", "tool", "state": {"status", "input",
  "output"?, "error"?, "metadata"?, "time": {"start", "end"?}}} (schema
  v1/session.ts ToolPart). The message carries path.cwd and, for an
  assistant, parentID: the user message it answers.
- v2 (v2.0.x; schema.gen.ts): session_v2 and session_message, one row per
  message, data the message less its id and type. An assistant row holds
  its tool calls in data.content: {"type": "tool", "id", "name", "state":
  {"status", "input", "content"?: [{"type": "text", "text"} | {"type":
  "file", "uri", ...}], "error"?: {"type", "message"}, "metadata"?},
  "time": {"created", "ran"?, "completed"?}} (schema session-message.ts).
  v2 copies every v1 session into these tables once (core database/
  v1-migration.bun.ts), keeping the v1 tool names and argument keys and
  each call's id, and never drops the v1 tables. v1.18 also writes
  session_message, of an earlier shape, when OPENCODE_EXPERIMENTAL_EVENT_
  SYSTEM is on. So session_message is read first, whichever tables its
  sessions are in, and then each v1 tool part whose call (session and
  call id) it did not hold.

Before v1.2.0 OpenCode kept JSON files under <data>/storage (v1.1.65
storage/storage.ts; pretty-printed with two spaces, compact where its own
migrations rewrote them): session/<projectID>/<sessionID>.json,
message/<sessionID>/<messageID>.json, part/<messageID>/<partID>.json, the
same v1 objects whole. v1.2.0 copied them into the database once and left
them where they were. Each session file is a store, read for its calls
through its message and part files; each message and part file is a store
of its own, searched and masked as one JSON file (a JSON file has to be
one file to be rewritten byte for byte). A session the database holds too
gives no calls from its files: the database is the newer copy. Its files
are still searched, since they are copies on disk. So are
storage/session_diff/<sessionID>.json (the files a session changed, before
and after) and storage/todo/<sessionID>.json, and the full output of a
tool OpenCode cut short, kept as plain text in <data>/tool-output/tool_*
for a week.

Tool names, from each version's own tools (v1.1.65 tool/*.ts, v1.18.35
tool/ and core/tool, v2.0.24 core/tool/plugin/*.ts "export const name"):
- shell: bash (v1, and v1 calls copied into v2), shell (v2): command, and
  workdir when given; else, in v1, the message's path.cwd, where it ran.
- read: read, with filePath (v1) or path (v2).
- write: write, edit, multiedit (filePath, edits[].filePath), apply_patch
  (v1) and patch (v2) (the files the patch text names).
- fetch: webfetch, websearch.
- others OpenCode has: glob, grep, list, task, subagent, todowrite,
  todoread, question, skill, lsp, batch, plan_enter, plan_exit, invalid,
  codesearch, execute. execute (v1.18's code mode, and v2's) runs a script
  that calls other tools (MCP tools, v2's opencode.* and fetch); it keeps
  them in state.metadata.toolCalls as {"tool", "status", "input"?}, read
  here as calls of their own, by name. Their results are not kept.
Any other name (an MCP tool, a plugin's) is not known, and judged by name.

Output: v1 state.output (else metadata.output, else the error); v2 the
text of state.content (else the error's message).

Calls that never ran ("declined"):
- v1: state.status "error" and state.error one of the permission texts
  (v1.1.65 permission/next.ts and permission/index.ts; v1.18 core
  v1/permission.ts), with the "Error: " v1.1.65 put before them: "The user
  rejected permission to use this specific tool call." (and the same with
  " You may try again with different parameters."), "...with the following
  feedback: <text>", and "The user has specified a rule which prevents you
  from using this specific tool call. ...". "Tool execution aborted" only
  when the state still has the "raw" of a call never started (pending):
  OpenCode writes it over a running call too, which did run.
- v2 (core session/runner/step.ts, to-session-error.ts, permission.ts,
  runner/publish-llm-event.ts): error.type "permission.rejected" (a rule
  denied it, or the user declined with feedback); "aborted" with "The user
  declined this tool call" or "Interaction cancelled because the location
  shut down"; "tool.input-json" (its arguments were not JSON, so it was not
  run); and a v1 call copied into v2, "tool.execution" with one of the v1
  texts above. Not "Tool execution interrupted": that call may have run.

Commands the user ran with "!" (actor "user"):
- v2: a session_message row of type "shell" {"shellID", "command",
  "status", "output"?: {"output", ...}, "time"} (core session/session.ts,
  message-updater.ts); v1.18's experimental rows have "callID" and an
  "output" string.
- v1 (v1.1.65 and v1.18 session/prompt.ts shell): a user message whose one
  part is the synthetic text "The following tool was executed by the user",
  then an assistant message (parentID that message) with one bash part.
  Copied into v2, that user message is a "synthetic" row with the same
  text, just before the assistant row.

Timestamps are milliseconds since 1970 everywhere. A call's session is its
session id, its project the session's directory.

Not read: auth.json and mcp-auth.json (OpenCode's own provider keys and MCP
logins), the database tables credential, account, account_state,
control_account (logins and tokens), session_share and
storage/session_share/ (share secrets), event (a log of what
session_message already holds), kv, permission, project and the others not
listed in SEARCHED_TABLES; snapshot/ (a git object store) and worktree/
(checkouts), log/, and the -wal and -shm files themselves (SQLite reads
them). Nor the pre-1.0 layout under <data>/project/, which OpenCode copied
into storage/ long ago. The database is opened read-only, and nothing is
written beside it.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat

from . import _paths, _sqlite, _stamps, base
from .base import SecretText, Source, ToolCall

DB_ENV = "OPENCODE_DB"
DATA_ENV = "XDG_DATA_HOME"
FOLDER = "opencode"
MEMORY = ":memory:"

DB_PREFIX = "opencode"
DB_SUFFIX = ".db"
PRIMARY_DB = "opencode.db"

STORAGE = "storage"
SESSION_DIR = "session"
MESSAGE_DIR = "message"
PART_DIR = "part"
# Flat folders of storage/ searched for secrets: <sessionID>.json each.
FLAT_DIRS = ("session_diff", "todo")
TOOL_OUTPUT = "tool-output"
TOOL_OUTPUT_PREFIX = "tool_"
JSON_SUFFIX = ".json"

SHELL = ("bash", "shell")
READ = ("read",)
WRITE = ("write", "edit", "multiedit", "apply_patch", "patch")
FETCH = ("webfetch", "websearch")
OTHER = ("glob", "grep", "list", "task", "subagent", "todowrite", "todoread",
         "question", "skill", "lsp", "batch", "plan_enter", "plan_exit",
         "invalid", "codesearch", "execute")
CODE_MODE = "execute"

# Where read, write and edit name their file: filePath in v1, path in v2.
PATH_KEYS = ("filePath", "path")
PATCH_HEADERS = ("*** Add File:", "*** Delete File:", "*** Update File:",
                 "*** Move to:")

# The tool name a command the user ran is recorded under.
USER_SHELL = "shell"
USER_MARKER = "The following tool was executed by the user"

DECLINED = "declined"

# v1's texts for a call it did not run (see the module notes).
V1_PREFIX = "Error: "
V1_REJECTED = "The user rejected permission to use this specific tool call."
V1_REJECTED_LEGACY = ("The user rejected permission to use this specific "
                      "tool call. You may try again with different "
                      "parameters.")
V1_FEEDBACK = ("The user rejected permission to use this specific tool call "
               "with the following feedback: ")
V1_DENIED = ("The user has specified a rule which prevents you from using "
             "this specific tool call.")
V1_ABORTED = "Tool execution aborted"

# v2's.
V2_REJECTED = "permission.rejected"
V2_ABORTED = "aborted"
V2_DECLINES = ("The user declined this tool call",
               "Interaction cancelled because the location shut down")
V2_NOT_JSON = "tool.input-json"
V2_EXECUTION = "tool.execution"

# session_message types (v2 schema session-message.ts; v1.18's had
# "unknown" too). Others are counted.
V2_TYPES = ("agent-switched", "model-switched", "location-switched", "user",
            "synthetic", "system", "skill", "shell", "assistant",
            "compaction", "idle", "unknown")
# v1 part types (v1.1.65 message-v2.ts; v1.18 schema v1/session.ts).
V1_PART_TYPES = ("text", "subtask", "reasoning", "file", "tool", "step-start",
                 "step-finish", "snapshot", "patch", "agent", "retry",
                 "compaction")

# Tables searched for secrets, and nothing else: what the sessions hold.
# None: every text column; else the columns named.
SEARCHED_TABLES = (("session_v2", None), ("session", None),
                   ("session_message", ("data",)), ("message", None),
                   ("part", ("data",)), ("todo", None),
                   ("session_input", None), ("session_pending", None),
                   ("session_inbox", None))
SPLIT_TABLES = ("session_message", "part")

WHY_READ_ONLY = ("OpenCode keeps this in a database; delete the session in "
                 "OpenCode.")
NOT_OPENED = "could not be opened"
NOT_DATABASE = "not a readable SQLite database"
DAMAGED = "part of it is damaged"

# Plain text is handed to clean in pieces of about this many characters,
# cut at a line end.
_CHUNK = 4 << 20
# A session file larger than this is not read for its directory in
# stores(); the file is still read whole as a store.
_HEAD_MAX = 1 << 20

_BAD = object()         # a file that is not JSON


def _string(value):
    return value if isinstance(value, str) and value else None


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _ms(value):
    return _stamps.iso_utc(value, "ms")


def _regular(path):
    """True for a regular file (not a FIFO, which open() would wait on)."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def _entries(folder):
    try:
        return list(os.scandir(folder))
    except (OSError, ValueError):
        return []


def _files(folder, suffix=JSON_SUFFIX, prefix=""):
    """Regular files directly in `folder` with that suffix and prefix, by
    name (OpenCode's ids sort in the order it made them)."""
    out = []
    for entry in _entries(folder):
        name = entry.name
        if name.startswith(".") or not name.endswith(suffix) \
                or not name.startswith(prefix):
            continue
        try:
            if entry.is_file():
                out.append(entry.path)
        except OSError:
            continue
    return sorted(out)


def _folders(folder):
    out = []
    for entry in _entries(folder):
        if entry.name.startswith("."):
            continue
        try:
            if entry.is_dir():
                out.append(entry.path)
        except OSError:
            continue
    return sorted(out)


def _stem(path):
    name = os.path.basename(path)
    return name[:-len(JSON_SUFFIX)] if name.endswith(JSON_SUFFIX) else name


def databases(folder):
    """Every opencode*.db file in the data folder, by name."""
    return _files(folder, DB_SUFFIX, DB_PREFIX)


def env_database(data, env=None):
    """The file OPENCODE_DB names, for the data folder `data`, or None
    (unset, empty, or ":memory:")."""
    env = os.environ if env is None else env
    value = _string(env.get(DB_ENV))
    if not value or value == MEMORY:
        return None
    return os.path.normpath(os.path.join(data, value))


# -- tool calls -----------------------------------------------------------

def _patch_paths(text):
    """The files an apply_patch / patch text names."""
    out = []
    if not isinstance(text, str):
        return out
    for line in text.split("\n"):
        line = line.strip()
        for header in PATCH_HEADERS:
            if line.startswith(header):
                path = line[len(header):].strip()
                if path:
                    out.append(path)
                break
    return out


def _paths_in(arguments):
    """(paths, keys): the strings at PATH_KEYS, and the keys they were at."""
    paths, keys = [], []
    for key in PATH_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            paths.append(value)
            keys.append(key)
    return paths, keys


def classify(name, arguments):
    """(kind, known, command, paths, consumed, workdir) for a call to the
    tool `name` with these (decoded) arguments."""
    if name in SHELL:
        command = _string(arguments.get("command"))
        return ("shell", True, command, (), ("command",) if command else (),
                _string(arguments.get("workdir")))
    if name in READ:
        paths, keys = _paths_in(arguments)
        return "read", True, None, tuple(paths), tuple(keys), None
    if name in WRITE:
        paths, _keys = _paths_in(arguments)
        for edit in _list(arguments.get("edits")):
            path = _string(_dict(edit).get("filePath"))
            if path and path not in paths:
                paths.append(path)
        for path in _patch_paths(arguments.get("patchText")):
            if path not in paths:
                paths.append(path)
        return "write", True, None, tuple(paths), (), None
    if name in FETCH:
        return "fetch", True, None, (), (), None
    if name in OTHER:
        return "other", True, None, (), (), None
    return "other", False, None, (), (), None


def _v1_declined(text, state):
    """True for a v1 error text that says the call never ran."""
    if not isinstance(text, str):
        return False
    if text.startswith(V1_PREFIX):
        text = text[len(V1_PREFIX):]
    if text in (V1_REJECTED, V1_REJECTED_LEGACY):
        return True
    if text.startswith(V1_FEEDBACK) or text.startswith(V1_DENIED):
        return True
    return text == V1_ABORTED and "raw" in state


def _v2_declined(error, state):
    """True for a v2 tool error that says the call never ran. A string
    error (v1.18's experimental rows) is read as v1's."""
    if isinstance(error, str):
        return _v1_declined(error, state)
    if not isinstance(error, dict):
        return False
    kind, message = error.get("type"), error.get("message")
    if kind in (V2_REJECTED, V2_NOT_JSON):
        return True
    if kind == V2_ABORTED:
        return message in V2_DECLINES
    if kind == V2_EXECUTION:
        return _v1_declined(message, {})
    return False


def _error_text(error):
    if isinstance(error, str):
        return error
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        return error["message"]
    return None


def content_text(content):
    """The text items of a v2 tool's content, joined by newlines."""
    texts = [item.get("text") for item in _list(content)
             if isinstance(item, dict) and item.get("type") == "text"
             and isinstance(item.get("text"), str)]
    return "\n".join(texts) if texts else None


def _v1_output(state):
    for value in (state.get("output"), _dict(state.get("metadata")).get("output"),
                  state.get("error")):
        if isinstance(value, str):
            return value
    return None


def _without(obj, key):
    return {k: v for k, v in obj.items() if k != key}


def _no_data_uri(item, key):
    """A file item with a data: URI left out (an attached image's bytes)."""
    value = item.get(key)
    if isinstance(value, str) and value.startswith("data:"):
        return _without(item, key)
    return item


class OpenCodeSource(Source):
    id = "opencode"
    name = "OpenCode"
    unit = "session"
    env = (DB_ENV,)
    path_means = ("an OpenCode data folder (~/.local/share/opencode), or "
                  "its database file")
    checked = "2.0.24 and 1.18.35"

    def reset(self):
        Source.reset(self)
        self._bad = set()           # stores counted as unreadable
        self._tallied = set()       # files and stores whose skips are counted
        self._sessions = {}         # database path -> session ids it holds

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """$XDG_DATA_HOME/opencode, else ~/.local/share/opencode, on every
        system; and the database OPENCODE_DB names, when it is set and is
        not ":memory:" (an absolute path as it is, else under the data
        folder)."""
        plat = _paths.platform_name(platform)
        pm = _paths.pathmod(plat)
        moved = _string(env.get(DATA_ENV))
        data = pm.join(_paths.xdg_data_home(env, home, plat), FOLDER)
        out = [(data, "env " + DATA_ENV if moved else "default")]
        db = _string(env.get(DB_ENV))
        if db and db != MEMORY:
            out.append((pm.join(data, db), "env " + DB_ENV))
        return out

    def stores(self, locations, since_days=None):
        found, seen = [], set()

        def add(store):
            if store is None:
                return None
            key = os.path.normcase(os.path.abspath(store.path))
            if key in seen:
                return None
            seen.add(key)
            found.append(store)
            return store

        for loc in locations:
            path = loc.path
            if _regular(path):
                add(self._database(path))
                continue
            if not os.path.isdir(path):
                continue
            for db in databases(path):
                add(self._database(db))
            self._storage(path, add)
            for out in _files(os.path.join(path, TOOL_OUTPUT), "",
                              TOOL_OUTPUT_PREFIX):
                add(self.store(out, "text", role="side", unit="tool output"))
        return base.newest_first(found, since_days)

    def _database(self, path):
        return self.store(path, "sqlite", unit="database",
                          why_read_only=WHY_READ_ONLY)

    def _storage(self, data, add):
        """The stores of the JSON tree under data/storage: a transcript
        per session file, a side store per message, part, session_diff and
        todo file. A session's mtime is that of the newest of its files,
        so --days keeps a session whose parts are newer than it."""
        root = os.path.join(data, STORAGE)
        if not os.path.isdir(root):
            return
        transcripts, projects = {}, {}
        for folder in _folders(os.path.join(root, SESSION_DIR)):
            for path in _files(folder):
                info = self._head(path)
                sid = _string(info.get("id")) or _stem(path)
                project = _string(info.get("directory"))
                store = add(self.store(path, "json", role="transcript",
                                       session=sid, project=project))
                if store is not None:
                    transcripts.setdefault(sid, store)
                    projects.setdefault(sid, project)
        owner = {}                  # message id -> session id
        for folder in _folders(os.path.join(root, MESSAGE_DIR)):
            sid = os.path.basename(folder)
            for path in _files(folder):
                owner[_stem(path)] = sid
                self._newer(transcripts.get(sid), add(self.store(
                    path, "json", role="side", unit="message", session=sid,
                    project=projects.get(sid))))
        for folder in _folders(os.path.join(root, PART_DIR)):
            sid = owner.get(os.path.basename(folder))
            for path in _files(folder):
                self._newer(transcripts.get(sid), add(self.store(
                    path, "json", role="side", unit="part", session=sid,
                    project=projects.get(sid))))
        for name in FLAT_DIRS:
            for path in _files(os.path.join(root, name)):
                sid = _stem(path)
                add(self.store(path, "json", role="side", unit=name,
                               session=sid, project=projects.get(sid)))

    @staticmethod
    def _newer(transcript, side):
        if transcript is not None and side is not None \
                and side.mtime > transcript.mtime:
            transcript.mtime = side.mtime

    @staticmethod
    def _head(path):
        """A session file's object, for its id and directory, or {}."""
        if not _regular(path):
            return {}
        try:
            with open(path, "rb") as fh:
                raw = fh.read(_HEAD_MAX + 1)
        except OSError:
            return {}
        if len(raw) > _HEAD_MAX:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8", "surrogateescape")
                             .lstrip("\ufeff"))
        except (ValueError, RecursionError):
            return {}
        return obj if isinstance(obj, dict) else {}

    # -- bookkeeping --------------------------------------------------------

    def _unreadable(self, store, reason, message):
        """Count a store that could not be read (or not whole) once a run,
        and warn once. The message never quotes what was read."""
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, message)

    def _first(self, key):
        first = key not in self._tallied
        self._tallied.add(key)
        return first

    def _load(self, path, store=None):
        """(obj, text) for a JSON file: obj is _BAD when it is not JSON
        (counted once a run, when there is something in it), and (None,
        None) when it cannot be read (warned and counted against `store`,
        when given)."""
        try:
            if not _regular(path):
                raise OSError("not a file")
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            if store is not None:
                self._unreadable(store, NOT_OPENED, "could not read OpenCode "
                                 "%s %s (%s)" % (store.unit, path,
                                                 e.strerror or str(e)))
            return None, None
        text = raw.decode("utf-8", "surrogateescape")
        if text.startswith("\ufeff"):
            text = text[1:]
        try:
            return json.loads(text), text
        except (ValueError, RecursionError):
            if text.strip() and self._first(("unparsed", path)):
                self.count("unparsed")
            return _BAD, text

    # -- building calls -----------------------------------------------------

    def _call(self, store, name, arguments, call_id, ms, fallback_ms,
              session, project, cwd=None, actor="agent", status=None,
              output=None):
        arguments = base.decode_input(arguments)
        kind, known, command, paths, consumed, workdir = classify(
            name, arguments)
        if kind == "shell" and not workdir:
            workdir = cwd
        timestamp = _ms(ms) or _ms(fallback_ms)
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            session=session, project=project, timestamp=timestamp,
            tool_call_id=call_id, actor=actor, status=status,
            not_after=None if timestamp else _stamps.iso_utc(store.mtime, "s"),
            command=command, workdir=workdir, paths=paths, consumed=consumed,
            output=output)

    def _nested(self, store, parent, metadata):
        """The calls an execute (code mode) call made, from its metadata's
        toolCalls, by name: OpenCode keeps no id or result for them."""
        if parent.tool_name != CODE_MODE:
            return
        for n, record in enumerate(_list(_dict(metadata).get("toolCalls")), 1):
            if not isinstance(record, dict):
                continue
            name = _string(record.get("tool")) or ""
            arguments = base.decode_input(record.get("input"))
            yield ToolCall(
                self.id, store.path, name, arguments, kind="other",
                known=False, session=parent.session, project=parent.project,
                timestamp=parent.timestamp, not_after=parent.not_after,
                tool_call_id="%s/%d" % (parent.tool_call_id or "", n))

    def _v1_part_call(self, store, part, session, project, message,
                      users, fallback_ms):
        """The ToolCall for a v1 tool part, given its message (for cwd and
        whether it answers a "!" command, `users` holding those user
        message ids)."""
        state = _dict(part.get("state"))
        name = _string(part.get("tool")) or ""
        user = (name in SHELL and message.get("role") == "assistant"
                and _string(message.get("parentID")) in users)
        declined = (state.get("status") == "error"
                    and _v1_declined(state.get("error"), state))
        return self._call(
            store, name, state.get("input"), _string(part.get("callID")),
            _dict(state.get("time")).get("start"), fallback_ms, session,
            project, cwd=_string(_dict(message.get("path")).get("cwd")),
            actor="user" if user else "agent",
            status=DECLINED if declined else None, output=_v1_output(state))

    def _v1_part_items(self, store, part, call, where):
        """SecretTexts of one v1 part: its outputs tied to the call, the
        rest as it is, with any data: URI left out."""
        if call is None:
            if part.get("type") == "file":
                part = _no_data_uri(part, "url")
            return [SecretText(part, where=where)]
        state = _dict(part.get("state"))
        rest = dict(state)
        out = []
        if "output" in rest:
            out.append(SecretText(rest.pop("output"), call=call, where=where))
        metadata = rest.get("metadata")
        if isinstance(metadata, dict) and "output" in metadata:
            out.append(SecretText(metadata["output"], call=call, where=where))
            rest["metadata"] = _without(metadata, "output")
        if isinstance(rest.get("attachments"), list):
            rest["attachments"] = [_no_data_uri(a, "url") if isinstance(a, dict)
                                   else a for a in rest["attachments"]]
        node = dict(part, state=rest)
        return [SecretText(node, where=where)] + out

    def _v2_tool_call(self, store, item, session, project, fallback_ms,
                      user):
        state = _dict(item.get("state"))
        name = _string(item.get("name")) or ""
        error = state.get("error")
        declined = state.get("status") == "error" and _v2_declined(error, state)
        output = content_text(state.get("content"))
        if output is None:
            output = _error_text(error)
        return self._call(
            store, name, state.get("input"), _string(item.get("id")),
            _dict(item.get("time")).get("created"), fallback_ms, session,
            project, actor="user" if user and name in SHELL else "agent",
            status=DECLINED if declined else None, output=output)

    def _v2_shell_call(self, store, data, row_id, session, project,
                       fallback_ms):
        command = _string(data.get("command"))
        output = data.get("output")
        if isinstance(output, dict):
            output = output.get("output")
        return self._call(
            store, USER_SHELL, {"command": command} if command else {},
            _string(data.get("callID")) or _string(data.get("shellID"))
            or row_id, _dict(data.get("time")).get("created"), fallback_ms,
            session, project, actor="user",
            output=output if isinstance(output, str) else None)

    # -- the database -------------------------------------------------------

    def _check_magic(self, store):
        """True when the file is a SQLite database to open. An empty or
        missing file holds nothing; one that is not a database warns."""
        if not _regular(store.path):
            if os.path.exists(store.path):
                self._unreadable(store, NOT_DATABASE, "%s is not a SQLite "
                                 "database" % store.path)
            return False
        try:
            with open(store.path, "rb") as fh:
                magic = fh.read(len(_sqlite.SQLITE_MAGIC))
        except OSError as e:
            self._unreadable(store, NOT_OPENED, "cannot read %s (%s)"
                             % (store.path, e.strerror or type(e).__name__))
            return False
        if not magic:
            return False
        if magic != _sqlite.SQLITE_MAGIC:
            self._unreadable(store, NOT_DATABASE, "%s is not a SQLite database"
                             % store.path)
            return False
        return True

    def _db(self, store, texts):
        """Read one database: ToolCalls (texts False) or SecretTexts (texts
        True). Never raises for what is in it: a database that cannot be
        opened, or a table that fails part way, warns and is counted, and
        what was read until then is kept."""
        if not self._check_magic(store):
            return
        with _sqlite.readonly(store.path) as conn:
            if conn is None:
                self._unreadable(store, NOT_OPENED, "could not open %s "
                                 "(permissions, or OpenCode holds it locked)"
                                 % store.path)
                return
            try:
                tables = set(_sqlite.tables(conn))
            except sqlite3.Error as e:
                self._unreadable(store, NOT_DATABASE, "cannot read %s: %s (%s)"
                                 % (store.path, NOT_DATABASE,
                                    type(e).__name__))
                return
            tally = self._first(("db", store.path))
            directories = self._directories(store, conn, tables)
            seen = set()        # (session, call id) read from session_message
            for item in self._guarded(store, "session_message",
                                      self._v2_rows(store, conn, tables,
                                                    directories, seen, texts,
                                                    tally)):
                yield item
            for item in self._guarded(store, "part",
                                      self._v1_rows(store, conn, tables,
                                                    directories, seen, texts,
                                                    tally)):
                yield item
            if texts:
                for table, cols in SEARCHED_TABLES:
                    if table in tables and table not in SPLIT_TABLES:
                        for item in self._guarded(store, table, self._cells(
                                conn, table, cols)):
                            yield item

    def _guarded(self, store, table, rows):
        """rows, stopping at an sqlite3.Error, which is warned about by its
        class only (what SQLite says can quote a cell)."""
        try:
            for item in rows:
                yield item
        except sqlite3.Error as e:
            self._unreadable(store, DAMAGED, "stopped reading table %s of %s "
                             "(%s)" % (table, store.path, type(e).__name__))
        finally:
            rows.close()

    def _directories(self, store, conn, tables):
        """{session id: directory} from session_v2 and session."""
        out = {}
        for table in ("session_v2", "session"):
            if table not in tables:
                continue
            try:
                cols = _sqlite.columns(conn, table)
                if "id" not in cols or "directory" not in cols:
                    continue
                for row in _sqlite.iter_rows(conn, table, ("id", "directory")):
                    sid, directory = row["id"], row["directory"]
                    if isinstance(sid, str) and isinstance(directory, str):
                        out.setdefault(sid, directory)
            except sqlite3.Error as e:
                self._unreadable(store, DAMAGED, "stopped reading table %s "
                                 "of %s (%s)" % (table, store.path,
                                                 type(e).__name__))
        return out

    @staticmethod
    def _json_cell(value):
        """A data cell decoded, or _BAD."""
        if isinstance(value, bytes):
            value = value.decode("utf-8", "surrogateescape")
        if not isinstance(value, str):
            return _BAD
        try:
            return json.loads(value)
        except (ValueError, RecursionError):
            return _BAD

    def _v2_rows(self, store, conn, tables, directories, seen, texts, tally):
        """session_message, in session and seq order: tool calls from
        assistant rows, a user's command from shell rows."""
        if "session_message" not in tables:
            return
        cols = set(_sqlite.columns(conn, "session_message"))
        want = ("id", "session_id", "type", "seq", "time_created", "data")
        if not set(want) <= cols:
            if tally:
                self.count("unknown")
            return
        rows = conn.execute(
            "SELECT id, session_id, type, time_created, data FROM "
            "session_message ORDER BY session_id, seq")
        current, user_next = None, False
        for row_id, sid, kind, created, raw in rows:
            where = "session_message %s" % (row_id,)
            data = self._json_cell(raw)
            if sid != current:
                current, user_next = sid, False
            if not isinstance(data, dict):
                if data is _BAD and raw and self._first(
                        ("unparsed", store.path, "session_message", row_id)):
                    self.count("unparsed")
                if texts and raw:
                    yield SecretText(data if data is not _BAD else
                                     self._text(raw), where=where)
                continue
            if kind not in V2_TYPES and self._first(
                    ("unknown", store.path, "session_message", row_id)):
                self.count("unknown")
            project = directories.get(sid)
            if kind == "synthetic":
                user_next = data.get("text") == USER_MARKER
                if texts:
                    yield SecretText(data, where=where)
                continue
            if kind == "shell":
                call = self._v2_shell_call(store, data, row_id, sid, project,
                                           created)
                if call.tool_call_id:
                    seen.add((sid, call.tool_call_id))
                if not texts:
                    yield call
                    continue
                output = data.get("output")
                yield SecretText(_without(data, "output"), where=where)
                if output is not None:
                    yield SecretText(output, call=call, where=where)
                continue
            if kind != "assistant":
                if kind == "user":
                    user_next = False
                if texts:
                    yield SecretText(data, where=where)
                continue
            user, user_next = user_next, False
            content = data.get("content")
            rest = []
            outputs = []
            for item in _list(content):
                if not isinstance(item, dict) or item.get("type") != "tool":
                    rest.append(item)
                    continue
                call = self._v2_tool_call(store, item, sid, project, created,
                                          user)
                if call.tool_call_id:
                    seen.add((sid, call.tool_call_id))
                state = _dict(item.get("state"))
                if not texts:
                    yield call
                    for inner in self._nested(store, call,
                                              state.get("metadata")):
                        yield inner
                    continue
                kept = dict(state)
                if "content" in kept:
                    output = kept.pop("content")
                    if isinstance(output, list):
                        output = [_no_data_uri(c, "uri") if isinstance(c, dict)
                                  else c for c in output]
                    outputs.append(SecretText(output, call=call, where=where))
                rest.append(dict(item, state=kept))
            if texts:
                node = dict(data, content=rest) if isinstance(content, list) \
                    else data
                yield SecretText(node, where=where)
                for out in outputs:
                    yield out

    @staticmethod
    def _text(raw):
        return raw.decode("utf-8", "surrogateescape") \
            if isinstance(raw, bytes) else raw

    def _users(self, conn):
        """Ids of the v1 user messages that stand for a "!" command: their
        part is the synthetic USER_MARKER text."""
        users = set()
        rows = conn.execute("SELECT message_id, data FROM part WHERE data "
                            "LIKE ?", ("%" + USER_MARKER + "%",))
        for message_id, raw in rows:
            part = self._json_cell(raw)
            if (isinstance(part, dict) and part.get("type") == "text"
                    and part.get("synthetic") is True
                    and part.get("text") == USER_MARKER):
                users.add(message_id)
        return users

    def _v1_rows(self, store, conn, tables, directories, seen, texts, tally):
        """v1 parts: each tool part's call, unless session_message held it
        (seen). For secrets, every part, and each message row's data as it
        is (a generic table, read in _db)."""
        if "part" not in tables:
            return
        cols = set(_sqlite.columns(conn, "part"))
        if not {"id", "message_id", "session_id", "time_created",
                "data"} <= cols:
            if tally:
                self.count("unknown")
            return
        users = self._users(conn)
        joined = "message" in tables and {"id", "data"} <= set(
            _sqlite.columns(conn, "message"))
        sql = ("SELECT p.id, p.session_id, p.time_created, p.data, %s FROM "
               "part p %s" % (
                   "m.data" if joined else "NULL",
                   "LEFT JOIN message m ON m.id = p.message_id"
                   if joined else ""))
        if not texts:
            sql += " WHERE p.data LIKE '%\"tool\"%'"
        for part_id, sid, created, raw, mraw in conn.execute(sql):
            where = "part %s" % (part_id,)
            part = self._json_cell(raw)
            if not isinstance(part, dict):
                if part is _BAD and raw and self._first(
                        ("unparsed", store.path, "part", part_id)):
                    self.count("unparsed")
                if texts and raw:
                    yield SecretText(part if part is not _BAD
                                     else self._text(raw), where=where)
                continue
            if part.get("type") not in V1_PART_TYPES and self._first(
                    ("unknown", store.path, "part", part_id)):
                self.count("unknown")
            call = None
            if part.get("type") == "tool":
                message = self._json_cell(mraw)
                call = self._v1_part_call(
                    store, part, sid, directories.get(sid),
                    message if isinstance(message, dict) else {}, users,
                    created)
            if not texts:
                if call is None or (sid, call.tool_call_id) in seen:
                    continue
                yield call
                for inner in self._nested(store, call, _dict(
                        part.get("state")).get("metadata")):
                    yield inner
                continue
            for item in self._v1_part_items(store, part, call, where):
                yield item

    def _cells(self, conn, table, cols):
        """SecretTexts for the text cells of a table: JSON decoded, else
        the text."""
        names = _sqlite.columns(conn, table)
        if cols is not None:
            names = [c for c in names if c in cols]
        if not names:
            return
        for index, row in enumerate(_sqlite.iter_rows(conn, table, names), 1):
            for col in names:
                value = self._text(row[col])
                if not isinstance(value, str) or not value:
                    continue
                node = value
                if value[:1] in ("{", "["):
                    decoded = self._json_cell(value)
                    if decoded is not _BAD:
                        node = decoded
                yield SecretText(node, where="%s row %d, %s"
                                 % (table, index, col))

    def _session_ids(self, path):
        """The session ids a database holds (session_v2 and session), read
        once a run; empty when it cannot be read."""
        if path in self._sessions:
            return self._sessions[path]
        ids = set()
        self._sessions[path] = ids
        if not _regular(path):
            return ids
        try:
            with open(path, "rb") as fh:
                if fh.read(len(_sqlite.SQLITE_MAGIC)) != _sqlite.SQLITE_MAGIC:
                    return ids
        except OSError:
            return ids
        with _sqlite.readonly(path) as conn:
            if conn is None:
                return ids
            try:
                tables = set(_sqlite.tables(conn))
                for table in ("session_v2", "session"):
                    if table in tables:
                        for (sid,) in conn.execute(
                                "SELECT id FROM %s" % _sqlite.quote_ident(table)):
                            if isinstance(sid, str):
                                ids.add(sid)
            except sqlite3.Error:
                pass
        return ids

    # -- the JSON tree ------------------------------------------------------

    @staticmethod
    def _data_of(session_file):
        """The data folder of storage/session/<projectID>/<id>.json."""
        return os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(session_file))))

    def _in_database(self, data, sid):
        paths = databases(data)
        named = env_database(data)
        if named and named not in paths:
            paths.append(named)
        return any(sid in self._session_ids(p) for p in paths)

    def _json_calls(self, store):
        """The calls of one JSON session: its message files in id order,
        each with its part files. None when the database holds the
        session."""
        session, _text = self._load(store.path, store)
        if session is None:
            return
        info = session if isinstance(session, dict) else {}
        sid = _string(info.get("id")) or store.session or _stem(store.path)
        project = _string(info.get("directory")) or store.project
        data = self._data_of(store.path)
        if self._in_database(data, sid):
            return
        storage = os.path.join(data, STORAGE)
        users = set()
        for mpath in _files(os.path.join(storage, MESSAGE_DIR, sid)):
            message, _t = self._load(mpath)
            if not isinstance(message, dict):
                continue
            mid = _string(message.get("id")) or _stem(mpath)
            role = message.get("role")
            for ppath in _files(os.path.join(storage, PART_DIR, mid)):
                part, _t = self._load(ppath)
                if not isinstance(part, dict):
                    continue
                if (self._first(("part", ppath))
                        and part.get("type") not in V1_PART_TYPES):
                    self.count("unknown")
                if role == "user":
                    if (part.get("type") == "text"
                            and part.get("synthetic") is True
                            and part.get("text") == USER_MARKER):
                        users.add(mid)
                    continue
                if part.get("type") != "tool":
                    continue
                call = self._v1_part_call(
                    store, part, sid, project, message, users,
                    _dict(message.get("time")).get("created"))
                yield call
                for inner in self._nested(store, call, _dict(
                        part.get("state")).get("metadata")):
                    yield inner

    def _json_texts(self, store):
        obj, text = self._load(store.path, store)
        if obj is None:
            return
        where = "whole file"
        if obj is _BAD:
            yield SecretText(text, where=where)
            return
        if store.unit == "part" and isinstance(obj, dict):
            call = None
            if obj.get("type") == "tool":
                call = self._v1_part_call(
                    store, obj, _string(obj.get("sessionID")) or store.session,
                    store.project, {}, (), None)
            for item in self._v1_part_items(store, obj, call, where):
                yield item
            return
        yield SecretText(obj, where=where)

    def _plain_texts(self, store):
        """A tool output file, in pieces cut at line ends."""
        try:
            if not _regular(store.path):
                raise OSError("not a file")
            with open(store.path, "r", encoding="utf-8",
                      errors="surrogateescape", newline="") as fh:
                offset = 0
                while True:
                    chunk = fh.read(_CHUNK)
                    if not chunk:
                        return
                    if len(chunk) == _CHUNK:
                        tail = fh.readline()
                        chunk += tail
                    yield SecretText(chunk, where="from character %d"
                                     % offset if offset else "whole file")
                    offset += len(chunk)
        except OSError as e:
            self._unreadable(store, NOT_OPENED, "could not read OpenCode %s "
                             "%s (%s)" % (store.unit, store.path,
                                          e.strerror or str(e)))

    # -- the interface ------------------------------------------------------

    def tool_calls(self, store):
        """Every call in a database (session_message first, then v1 parts
        it did not hold), or in a JSON session the database does not hold.
        Side stores hold none of their own."""
        if store.format == "sqlite":
            return self._db(store, False)
        if store.format == "json" and store.role == "transcript":
            return self._json_calls(store)
        return iter(())

    def secret_texts(self, store):
        """Every message, part and session a store holds (see
        SEARCHED_TABLES for a database), a tool's output tied to its call;
        a JSON file that does not parse as its text; a tool output file as
        text. Never OpenCode's logins or share secrets."""
        if store.format == "sqlite":
            return self._db(store, True)
        if store.format == "json":
            return self._json_texts(store)
        if store.format == "text":
            return self._plain_texts(store)
        return iter(())
