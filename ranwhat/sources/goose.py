"""Goose (aaif-goose/goose, formerly block/goose): CLI and desktop app.

Checked against Goose v1.53.0 (tag v1.53.0, commit 76da81cb). The CLI
(`goose`) and the desktop app (Electron plus the `goosed` server) both use
the goose crate's SessionManager, so they share one store.

Where (crates/goose/src/config/paths.rs): GOOSE_PATH_ROOT/data when the
variable is set and absolute (a relative one is ignored); otherwise the
data folder of etcetera's app strategy for Block/Block/goose, which is the
XDG one on Linux and on macOS too: ${XDG_DATA_HOME:-~/.local/share}/goose,
XDG_DATA_HOME read only when absolute (etcetera 0.11.0 base_strategy/
xdg.rs); and %APPDATA%\\Block\\goose\\data on Windows. On macOS
~/Library/Application Support/Block/goose, which a comment in paths.rs
names but no code writes, is probed too. Sessions live in its sessions/
folder.

What is there:
- sessions/sessions.db, a SQLite database in WAL mode (session_manager.rs
  SESSIONS_FOLDER, DB_NAME, create_schema; schema version 16 at v1.53.0,
  first written by v1.10.0). It is opened read-only through _sqlite and
  never written to, nothing is made beside it, and only the columns read
  here are asked for, each looked up first (older databases are migrated
  in place with ALTER TABLE ADD COLUMN, so a column may be missing):
  sessions(id, working_dir, name, description) and messages(id,
  session_id, role, content_json, created_timestamp), in (session,
  created_timestamp, id) order as Goose reads them back. A database
  migrated through version 10 also has thread_messages, of the same shape;
  no current code writes it, but what it holds is read too.
- sessions/<name>.jsonl, one per session from Goose 1.9 and earlier
  (v1.9.3 session/storage.rs): line 1 the session's metadata
  ({"working_dir", "description", "extension_data", "recipe", ...}), every
  later line one Message. Goose 1.10 and later import every such file into
  sessions.db once, under its file name as the session id, and leave the
  file where it is (session/legacy.rs). A file whose name is a session id
  in the database is a second copy: it is still searched for secrets and
  can be masked, and its calls are read from the database, so none is
  counted twice, except a call the database does not hold: the import
  keeps only lines that still parse in the version importing them. The
  .backup and .tmp files beside them are not read.

A message's content (content_json, or "content" in a jsonl line) is an
array of blocks tagged by "type" (goose-provider-types conversation/
message.rs). A call is a "toolRequest" block (and the older
"frontendToolRequest"): {"id", "toolCall": {"status": "success", "value":
{"name", "arguments"}}}; a toolCall whose status is "error" holds no name
and never ran. Its result is the "toolResponse" block with the same id,
in a later user-role message: {"id", "toolResult": {"status": "success",
"value": {"content": [blocks], "isError"}}} (a bare array of blocks before
about v1.10), or {"status": "error", "error": "<code>: <message>"}.

Tool names (extension_manager/mod.rs): a platform extension's tools are
bare names; every other extension's are "<extension>__<tool>". The
developer tools are shell {command}, write {path, content}, edit {path,
before, after}, tree {path} and read_image {path} (platform_extensions/
developer, v1.27.0 and later), and before that the developer extension's
developer__shell {command}, developer__text_editor {command: view | write
| str_replace | insert | undo_edit, path, ...} and
developer__image_processor {path} (goose-mcp developer/
rmcp_developer.rs, v1.26.0). Code mode's execute_bash {command} runs a
command too (platform_extensions/code_execution.rs). Those names, bare or
under "developer__", are Goose's own; the same names under any other
extension belong to a server the user added, and are judged by name.

A call that never ran is "declined": the user turned it down, or a
permission rule did, and Goose answered it with DECLINED_RESPONSE; or
chat mode skipped it, with CHAT_MODE_TOOL_SKIPPED_RESPONSE
(agents/tool_execution.rs).

Times: created_timestamp (and "created" in a jsonl line) are epoch
seconds; Goose divides anything above 1e10 by 1000 (session_manager.rs
MILLISECOND_TIMESTAMP_THRESHOLD), and so does this reader.

Not read: anything outside sessions/: Goose's keyring entries,
config.yaml and secrets.yaml (its configuration and, with the keyring
off, its keys), the OAuth token folders under its config folder, the logs
and history.txt under its state folder. Nor, inside the store, a
session's extension_data and recipe (in the database, and "extension_data"
and "recipe" on a jsonl file's first line): they hold the extensions Goose
was configured with, environment variables and headers included, which is
Goose's own configuration, as OpenClaw's auth tables are OpenClaw's login.
A session's metadata_json and token counts hold nothing typed.
"""

from __future__ import annotations

import json
import os
import sqlite3

from . import _lines, _paths, _sqlite, _stamps, base
from .base import SecretText, Source, ToolCall

ENV = "GOOSE_PATH_ROOT"

APP = "goose"
VENDOR = "Block"                        # etcetera's author, on Windows
SESSIONS = "sessions"
DB_NAME = "sessions.db"
SUFFIX = ".jsonl"

# What clean's report says of a database that holds a secret.
WHY_READ_ONLY = ("Goose keeps this in a database; delete the session in "
                 "Goose.")

# Why a database was not read, as the report's notes give it.
NOT_OPENED = "could not be opened"
NOT_DATABASE = "not a readable SQLite database"
DAMAGED = "part of it is damaged"

DECLINED = "declined"

# The text Goose answers a call with instead of running it
# (tool_execution.rs DECLINED_RESPONSE, CHAT_MODE_TOOL_SKIPPED_RESPONSE, the
# same from v1.9.3 to v1.53.0 but for "Goose chat mode", capitalised in
# v1.9.3). The whole text, alone in the result: a command's output that
# only starts with it ran.
DECLINED_RESPONSE = ("The user has declined to run this tool. DO NOT attempt "
                     "to call this tool again. If there are no alternative "
                     "methods to proceed, clearly explain the situation and "
                     "STOP.")
SKIPPED_RESPONSES = tuple(
    "Let the user know the tool call was skipped in %s chat mode. DO NOT "
    "apologize for skipping the tool call. DO NOT say sorry. Provide an "
    "explanation of what the tool call would do, structured as a plan for "
    "the user. Again, DO NOT apologize. **Example Plan:**\n 1. **Identify "
    "Task Scope** - Determine the purpose and expected outcome.\n 2. "
    "**Outline Steps** - Break down the steps.\n If needed, adjust the "
    "explanation based on user preferences or questions." % goose
    for goose in ("goose", "Goose"))

# Anything above this is milliseconds (session_manager.rs
# MILLISECOND_TIMESTAMP_THRESHOLD).
MS_THRESHOLD = 10000000000

# Blocks that hold a call, and the one that holds its result.
REQUESTS = ("toolRequest", "frontendToolRequest")
RESPONSE = "toolResponse"

# Every block type Goose writes, now (message.rs MessageContent) and in
# data written before (v1.9.3). Others are counted as unknown.
BLOCKS = ("text", "image", "document", "toolRequest", "toolResponse",
          "toolConfirmationRequest", "actionRequired", "thinking",
          "redactedThinking", "systemNotification", "error",
          "frontendToolRequest", "contextLengthExceeded",
          "summarizationRequested", "conversationCompacted", "reasoning")

ROLES = ("user", "assistant")

# The developer extension's key when its tools were prefixed (<= v1.26).
OWN_PREFIX = "developer"

SHELL_TOOLS = ("shell", "execute_bash")
WRITE_TOOLS = ("write", "edit")
EDITOR = "text_editor"
EDITOR_READS = ("view",)
EDITOR_WRITES = ("write", "str_replace", "insert", "undo_edit")
IMAGE_TOOLS = ("read_image", "image_processor")
OTHER_TOOLS = ("tree", "analyze", "screen_capture", "list_windows")

# Where Goose's own file tools name their file.
PATH_KEY = "path"

# Configuration, not conversation: never searched (see the module notes).
CONFIG_KEYS = ("extension_data", "recipe")

# Tables of the database a transcript is read from, in this order.
MESSAGE_TABLES = ("messages", "thread_messages")

_BAD = object()         # text that is not JSON


def _string(value):
    return value if isinstance(value, str) and value else None


def _isabs(value, platform):
    return _paths.pathmod(platform).isabs(value)


def stamp(value):
    """created_timestamp as ISO UTC: epoch seconds, or milliseconds when it
    is above MS_THRESHOLD, as Goose reads it."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except ValueError:
            return None
    if not isinstance(value, (int, float)):
        return None
    if value > MS_THRESHOLD:
        value = value / 1000.0
    return _stamps.iso_utc(value, "s")


def split_name(name):
    """(extension, tool) for a tool name, split on its last "__" as Goose
    splits it (agents/agent.rs); extension is None for a bare name."""
    if "__" in name:
        prefix, _sep, tool = name.rpartition("__")
        return prefix, tool
    return None, name


def _is_url(value):
    return value.lower().startswith(("http://", "https://"))


def classify(name, arguments):
    """(kind, known, command, paths, consumed) for a call to `name` with
    these (decoded) arguments: Goose's own developer tools, bare or under
    "developer__"; any other name, or those names under another extension,
    unknown."""
    prefix, tool = split_name(name)
    if prefix not in (None, OWN_PREFIX):
        return "other", False, None, (), ()
    path = _string(arguments.get(PATH_KEY))
    paths = (path,) if path else ()
    if tool in SHELL_TOOLS:
        command = _string(arguments.get("command"))
        return "shell", True, command, (), ("command",) if command else ()
    if tool in WRITE_TOOLS:
        return "write", True, None, paths, ()
    if tool == EDITOR:
        command = arguments.get("command")
        if command in EDITOR_READS:
            return "read", True, None, paths, (PATH_KEY,) if paths else ()
        if command in EDITOR_WRITES or "diff" in arguments:
            return "write", True, None, paths, ()
        return "other", True, None, (), ()
    if tool in IMAGE_TOOLS:
        if path and _is_url(path):
            return "fetch", True, None, (), ()
        return "read", True, None, paths, (PATH_KEY,) if paths else ()
    if tool in OTHER_TOOLS:
        return "other", True, None, (), ()
    return "other", False, None, (), ()


def result_blocks(result):
    """The content blocks of a toolResult's value: value.content when it is
    an object, the value itself when it is a list (before ~v1.10)."""
    if not isinstance(result, dict):
        return []
    value = result.get("value")
    if isinstance(value, dict):
        value = value.get("content")
    return value if isinstance(value, list) else []


def output_text(result):
    """The text of a toolResult: its text blocks (and the text of an
    embedded resource) joined by newlines, or the error a failed one
    holds. None when there is no text."""
    if not isinstance(result, dict):
        return None
    if result.get("status") == "error":
        return _string(result.get("error"))
    texts = []
    for block in result_blocks(result):
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            texts.append(block["text"])
        elif block.get("type") == "resource":
            resource = block.get("resource")
            if isinstance(resource, dict) and isinstance(
                    resource.get("text"), str):
                texts.append(resource["text"])
    return "\n".join(texts) if texts else None


def never_ran(result):
    """True when Goose answered the call instead of running it: the result
    is that one text, whole and alone. Goose writes the declined text as an
    error result (isError true, from v1.20; a bare array before), the
    chat-mode one as a success, and neither with structuredContent, which
    every shell result has. So a command that echoes the text, and then
    fails, still ran."""
    if not isinstance(result, dict) or result.get("status") != "success":
        return False
    value = result.get("value")
    blocks = result_blocks(result)
    if len(blocks) != 1 or not isinstance(blocks[0], dict) \
            or blocks[0].get("type") != "text":
        return False
    text = blocks[0].get("text")
    if isinstance(value, dict):
        if "structuredContent" in value:
            return False
        error = value.get("isError")
        if text == DECLINED_RESPONSE:
            return error is not False
        return text in SKIPPED_RESPONSES and error is not True
    return text == DECLINED_RESPONSE or text in SKIPPED_RESPONSES


def _entries(folder):
    try:
        return list(os.scandir(folder))
    except OSError:
        return []


class _Message(object):
    """One message, from a database row or a jsonl line."""
    __slots__ = ("session", "project", "role", "content", "created",
                 "where", "raw", "text")

    def __init__(self, session, project, role, content, created, where,
                 raw=None, text=None):
        self.session = session
        self.project = project
        self.role = role
        self.content = content      # the list of blocks, or _BAD
        self.created = created
        self.where = where
        self.raw = raw              # the decoded value as it was stored
        self.text = text            # the stored text, when it is not JSON


class GooseSource(Source):
    id = "goose"
    name = "Goose"
    unit = "file"           # sessions.db holds many sessions; see agents.amount
    env = (ENV,)
    path_means = "a Goose data folder (the one holding sessions/)"
    checked = "1.53.0"
    mask_note = ("Goose 1.10 and later copied this session into its "
                 "sessions.db when they first ran, and ranwhat only reads "
                 "that: delete the session in Goose to remove the copy.")

    def reset(self):
        Source.reset(self)
        self._bad = set()           # stores already counted as unreadable
        self._tallied = set()       # stores whose odd records are counted
        self._ids = {}              # database path -> its session ids
        self._db_calls = {}         # (database path, session) -> call ids

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """GOOSE_PATH_ROOT/data when set and absolute (what Goose reads),
        else the XDG data folder on Linux and macOS (and the Application
        Support folder probed on macOS), %APPDATA%\\Block\\goose\\data on
        Windows."""
        plat = _paths.platform_name(platform)
        join = _paths.pathmod(plat).join
        root = env.get(ENV)
        if isinstance(root, str) and root and _isabs(root, plat):
            return [(join(root, "data"), "env " + ENV)]
        if plat == "win32":
            return [(join(_paths.appdata(env, home), VENDOR, APP, "data"),
                     "default")]
        data = env.get("XDG_DATA_HOME")
        if not (isinstance(data, str) and data and _isabs(data, plat)):
            data = join(home, ".local", "share")
        out = [(join(data, APP), "default")]
        if plat == "darwin":
            out.append((join(_paths.application_support(home), VENDOR, APP),
                        "probed"))
        return out

    @staticmethod
    def session_folders(location):
        """The sessions/ folder of a data folder, and the folder itself when
        it holds sessions.db (--path given the sessions folder)."""
        out = [os.path.join(location.path, SESSIONS)]
        if os.path.isfile(os.path.join(location.path, DB_NAME)):
            out.append(location.path)
        return out

    def stores(self, locations, since_days=None):
        """sessions.db, whatever its mtime (base.newest_first keeps a
        database: its newest rows can sit in its -wal), and every legacy
        *.jsonl beside it."""
        found, seen = [], set()
        for loc in locations:
            for folder in self.session_folders(loc):
                for entry in _entries(folder):
                    name = entry.name
                    is_db = name == DB_NAME
                    if not is_db and (name.startswith(".")
                                      or not name.endswith(SUFFIX)):
                        continue
                    try:
                        if not entry.is_file():
                            continue
                    except OSError:
                        continue
                    key = os.path.normcase(os.path.abspath(entry.path))
                    if key in seen:
                        continue
                    seen.add(key)
                    if is_db:
                        store = self.store(entry.path, "sqlite",
                                           unit="database",
                                           why_read_only=WHY_READ_ONLY)
                    else:
                        header = self._header(entry.path) or {}
                        store = self.store(
                            entry.path, "jsonl", role="transcript",
                            unit="session", session=name[:-len(SUFFIX)],
                            project=_string(header.get("working_dir")))
                    if store is not None:
                        found.append(store)
        return base.newest_first(found, since_days)

    # -- bookkeeping --------------------------------------------------------

    def _bad_store(self, store, reason, message=None):
        """Count a store that could not be read, or not to its end, once a
        run, and warn once. The message never holds what SQLite said: an
        error can quote a cell."""
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, message or "could not read Goose %s %s (%s)"
                  % (store.unit, store.path, reason))

    def _first(self, store):
        """True the first time a store is read this run: watch and clean
        both read it, and what it skipped is counted once."""
        first = store.path not in self._tallied
        self._tallied.add(store.path)
        return first

    # -- the database -------------------------------------------------------

    def _is_database(self, store):
        """True when the file starts as a SQLite database does; a file that
        is not one is said so without opening it in SQLite, which would copy
        it to a temp folder first. An empty file holds nothing."""
        try:
            with open(store.path, "rb") as fh:
                magic = fh.read(len(_sqlite.SQLITE_MAGIC))
        except FileNotFoundError:
            return False
        except OSError as e:
            self._bad_store(store, NOT_OPENED, "cannot read %s (%s)"
                            % (store.path, type(e).__name__))
            return False
        if not magic:
            return False
        if magic != _sqlite.SQLITE_MAGIC:
            self._bad_store(store, NOT_DATABASE, "cannot read %s: %s"
                            % (store.path, NOT_DATABASE))
            return False
        return True

    def _database(self, store, tally):
        """("session", id, {column: value}) for every session, then
        ("message", _Message) for every message of every MESSAGE_TABLES
        table, in (session, created_timestamp, id) order, read from a
        cursor through a read-only open. A database that cannot be opened
        or read warns and is counted; the copy a locked one is read from is
        removed however the reader stops."""
        if not self._is_database(store):
            return
        with _sqlite.readonly(store.path) as conn:
            if conn is None:
                self._bad_store(store, NOT_OPENED, "could not open %s "
                                "(permissions, or Goose holds it locked)"
                                % store.path)
                return
            try:
                tables = set(_sqlite.tables(conn))
            except sqlite3.Error as e:
                self._bad_store(store, NOT_DATABASE, "cannot read %s: %s (%s)"
                                % (store.path, NOT_DATABASE,
                                   type(e).__name__))
                return
            projects = {}
            if "sessions" not in tables and "messages" not in tables:
                if tally:
                    self.count("unknown")
                return
            if "sessions" in tables:
                for item in self._read(store, conn, "sessions", self._sessions):
                    sid, row = item
                    if isinstance(sid, str):
                        projects[sid] = _string(row.get("working_dir"))
                    yield ("session", sid, row)
            for table in MESSAGE_TABLES:
                if table not in tables:
                    continue
                for message in self._read(
                        store, conn, table,
                        lambda c, t: self._messages(c, t, projects)):
                    yield ("message", message)

    def _read(self, store, conn, table, reader):
        """What reader(conn, table) yields, until SQLite fails part way:
        then warn and count it, keeping what was read."""
        index = 0
        try:
            for item in reader(conn, table):
                index += 1
                yield item
        except sqlite3.Error as e:
            self._bad_store(store, DAMAGED, "stopped reading table %s of %s "
                            "after %d rows (%s)" % (table, store.path, index,
                                                    type(e).__name__))

    @staticmethod
    def _sessions(conn, table):
        cols = _sqlite.columns(conn, table)
        wanted = [c for c in ("id", "working_dir", "name", "description")
                  if c in cols]
        if "id" not in wanted:
            return
        for row in _sqlite.iter_rows(conn, table, wanted):
            yield row["id"], row

    @staticmethod
    def _messages(conn, table, projects):
        cols = _sqlite.columns(conn, table)
        if not all(c in cols for c in ("role", "content_json")):
            return
        session_col = "session_id" if "session_id" in cols else None
        wanted = [c for c in ("id", "session_id", "thread_id", "role",
                              "content_json", "created_timestamp")
                  if c in cols]
        order = [c for c in (session_col, "created_timestamp", "id")
                 if c and c in cols]
        sql = "SELECT %s FROM %s" % (
            ", ".join(_sqlite.quote_ident(c) for c in wanted),
            _sqlite.quote_ident(table))
        if order:
            sql += " ORDER BY " + ", ".join(_sqlite.quote_ident(c)
                                            for c in order)
        for index, values in enumerate(conn.execute(sql), 1):
            row = dict(zip(wanted, values))
            session = row.get("session_id")
            if session is None:
                session = row.get("thread_id")
            if isinstance(session, bytes):
                session = session.decode("utf-8", "surrogateescape")
            text = row.get("content_json")
            if isinstance(text, bytes):
                text = text.decode("utf-8", "surrogateescape")
            raw = _BAD
            if isinstance(text, str):
                try:
                    raw = json.loads(text)
                except (ValueError, RecursionError):
                    raw = _BAD
            rowid = row.get("id")
            where = "%s row %s" % (table, rowid if isinstance(rowid, int)
                                   else index)
            if isinstance(session, str):
                where += ", session %s" % session
            yield _Message(
                session if isinstance(session, str) else None,
                projects.get(session) if isinstance(session, str) else None,
                row.get("role"), raw if isinstance(raw, list) else _BAD,
                row.get("created_timestamp"), where, raw=raw,
                text=text if isinstance(text, str) else None)

    def _db_ids(self, folder):
        """The session ids in sessions.db in `folder`, read once a run; an
        empty set when there is none, or it cannot be read (it says so when
        it is read itself)."""
        path = os.path.join(folder, DB_NAME)
        key = os.path.normcase(os.path.abspath(path))
        if key in self._ids:
            return self._ids[key]
        ids = set()
        self._ids[key] = ids
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
                if "id" in _sqlite.columns(conn, "sessions"):
                    for (sid,) in conn.execute('SELECT "id" FROM "sessions"'):
                        if isinstance(sid, str):
                            ids.add(sid)
            except sqlite3.Error:
                pass
        return ids

    # -- legacy jsonl -------------------------------------------------------

    @staticmethod
    def _header(path):
        """The metadata object on a jsonl file's first line, or None."""
        try:
            with open(path, "rb") as fh:
                raw = fh.readline(1 << 16)
        except OSError:
            return None
        try:
            obj = json.loads(_lines.decode_line(raw, first=True))
        except (ValueError, RecursionError):
            return None
        return obj if isinstance(obj, dict) and "role" not in obj else None

    def _jsonl(self, store, tally):
        """("header", line_no, obj) for the first line, ("message",
        _Message) for every later one; a line that is not JSON is a
        _Message whose content is _BAD (counted when complete: a last line
        with no newline is one still being written). A store that cannot be
        opened warns once; one with lines but none of them JSON too."""
        parsed = bad = 0
        project = store.project
        try:
            with open(store.path, "rb") as fh:
                first = True
                for line_no, raw in enumerate(fh, 1):
                    text = _lines.decode_line(raw, first=line_no == 1)
                    if not text.strip():
                        continue
                    where = "line %d" % line_no
                    try:
                        obj = json.loads(text)
                    except (ValueError, RecursionError):
                        if raw.endswith(b"\n"):
                            bad += 1
                        first = False
                        yield ("message", _Message(
                            store.session, project, None, _BAD, None, where,
                            raw=_BAD, text=text))
                        continue
                    parsed += 1
                    if first and isinstance(obj, dict) and "role" not in obj:
                        first = False
                        yield ("header", line_no, obj)
                        continue
                    first = False
                    message = obj if isinstance(obj, dict) else {}
                    content = message.get("content")
                    if not isinstance(content, list):
                        content = _BAD
                    yield ("message", _Message(
                        store.session, project, message.get("role"), content,
                        message.get("created"), where, raw=obj, text=None))
        except OSError as e:
            self._bad_store(store, e.strerror or type(e).__name__)
            return
        finally:
            if tally:
                self.count("unparsed", bad)
        if bad and not parsed:
            self._bad_store(store, "not JSON Lines")

    # -- both ---------------------------------------------------------------

    def _items(self, store, tally):
        if store.format == "sqlite":
            return self._database(store, tally)
        return self._jsonl(store, tally)

    def _tally(self, store, message):
        """Count a message, or a block in it, of a shape Goose does not
        write, and a database row whose content is not JSON (a jsonl line
        that is not is counted as it is read)."""
        if message.content is _BAD:
            if message.raw is not _BAD:
                self.count("unknown")
            elif store.format == "sqlite":
                self.count("unparsed")
            return
        if message.role not in ROLES:
            self.count("unknown")
        for block in message.content:
            if not isinstance(block, dict) or block.get("type") not in BLOCKS:
                self.count("unknown")

    def _call(self, store, block, message):
        """The ToolCall for one toolRequest block, or None when it holds no
        call (its toolCall failed to parse, and never ran)."""
        request = block.get("toolCall")
        if not isinstance(request, dict) or request.get("status") != "success":
            return None
        value = request.get("value")
        if not isinstance(value, dict):
            return None
        name = _string(value.get("name"))
        if name is None:
            return None
        arguments = base.decode_input(value.get("arguments"))
        kind, known, command, paths, consumed = classify(name, arguments)
        timestamp = stamp(message.created)
        cid = block.get("id")
        return ToolCall(
            self.id, store.path, name, arguments, kind=kind, known=known,
            session=message.session, project=message.project,
            timestamp=timestamp,
            not_after=None if timestamp else _stamps.iso_utc(store.mtime, "s"),
            tool_call_id=cid if isinstance(cid, str) else None,
            command=command, paths=paths, consumed=consumed)

    @staticmethod
    def _blocks(message, kinds):
        if message.content is _BAD:
            return []
        return [b for b in message.content
                if isinstance(b, dict) and b.get("type") in kinds]

    def _imported(self, store):
        """For a jsonl file whose session is also in the database beside it
        (Goose imported it), the ids of the calls the database holds for
        that session: those are read there. None for any other store.

        Goose's import keeps only the lines that still parse as a Message
        of the version importing them (legacy.rs load_session): one that
        went from 1.9 to 1.50 or later dropped every message holding a
        frontendToolRequest, whatever else it held. So a call the database
        does not hold is read from the file."""
        if store.format != "jsonl" or store.session is None:
            return None
        folder = os.path.dirname(store.path)
        if store.session not in self._db_ids(folder):
            return None
        return self._db_call_ids(folder, store.session)

    def _db_call_ids(self, folder, session):
        """The ids of the toolRequest blocks sessions.db in `folder` holds
        for one session, read once a run."""
        path = os.path.normcase(os.path.abspath(os.path.join(folder,
                                                             DB_NAME)))
        key = (path, session)
        if key in self._db_calls:
            return self._db_calls[key]
        ids = set()
        self._db_calls[key] = ids
        with _sqlite.readonly(path) as conn:
            if conn is None:
                return ids
            try:
                tables = set(_sqlite.tables(conn))
                for table in MESSAGE_TABLES:
                    if table not in tables:
                        continue
                    cols = _sqlite.columns(conn, table)
                    if not {"session_id", "content_json"} <= set(cols):
                        continue
                    sql = ("SELECT content_json FROM %s WHERE session_id = ? "
                           "AND content_json LIKE '%%oolRequest%%'"
                           % _sqlite.quote_ident(table))
                    for (raw,) in conn.execute(sql, (session,)):
                        if isinstance(raw, bytes):
                            raw = raw.decode("utf-8", "surrogateescape")
                        try:
                            blocks = json.loads(raw)
                        except (TypeError, ValueError, RecursionError):
                            continue
                        for block in blocks if isinstance(blocks, list) else ():
                            if (isinstance(block, dict)
                                    and block.get("type") in REQUESTS
                                    and isinstance(block.get("id"), str)):
                                ids.add(block["id"])
            except sqlite3.Error:
                pass
        return ids

    def tool_calls(self, store):
        """Every call, once per (session, id), with its result's text as
        output when the store holds one and "declined" when Goose answered
        it instead of running it. A call is yielded when its result
        arrives, and those still waiting when their session ends then.
        Never raises: a store that cannot be read warns and is counted."""
        try:
            for call in self._tool_calls(store):
                yield call
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    def _tool_calls(self, store):
        imported = self._imported(store)
        if imported is not None:
            for call in self._calls(store):
                if call.tool_call_id not in imported:
                    yield call
            return
        for call in self._calls(store):
            yield call

    def _calls(self, store):
        tally = self._first(store)
        pending = {}            # (session, id) -> ToolCall awaiting result
        done = set()            # (session, id) already yielded
        current = None
        for item in self._items(store, tally):
            if item[0] != "message":
                continue
            message = item[1]
            if tally:
                self._tally(store, message)
            if message.session != current:
                for call in pending.values():
                    yield call
                pending = {}
                current = message.session
            for block in self._blocks(message, REQUESTS + (RESPONSE,)):
                cid = block.get("id")
                key = (message.session, cid) if isinstance(cid, str) else None
                if block.get("type") == RESPONSE:
                    call = pending.pop(key, None) if key else None
                    if call is None:
                        continue
                    result = block.get("toolResult")
                    call.output = output_text(result)
                    if never_ran(result):
                        call.status = DECLINED
                    done.add(key)
                    yield call
                    continue
                call = self._call(store, block, message)
                if call is None:
                    continue
                if key is None:
                    yield call          # nothing to pair it with
                elif key not in done and key not in pending:
                    pending[key] = call
        for call in pending.values():
            yield call

    def secret_texts(self, store):
        """Every message (the database's content_json of every row, or every
        line of a jsonl file), every session's name and description, and a
        jsonl file's first line without its configuration (CONFIG_KEYS). A
        toolResponse block's result is handed over on its own, tied to the
        call it answers; the rest of its message without it. Text that is
        not JSON is handed over as it is. Never raises."""
        try:
            for text in self._secret_texts(store):
                yield text
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    def _secret_texts(self, store):
        tally = self._first(store)
        calls = {}              # (session, id) -> ToolCall, first copy
        for item in self._items(store, tally):
            if item[0] == "session":
                _sid, row = item[1], item[2]
                for col in ("name", "description"):
                    value = row.get(col)
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", "surrogateescape")
                    if isinstance(value, str) and value:
                        yield SecretText(value, where="sessions row %s, %s"
                                         % (_sid, col))
                continue
            if item[0] == "header":
                rest = {k: v for k, v in item[2].items()
                        if k not in CONFIG_KEYS}
                yield SecretText(rest, where="line %d" % item[1])
                continue
            message = item[1]
            if tally:
                self._tally(store, message)
            if message.raw is _BAD:
                if message.text:
                    yield SecretText(message.text, where=message.where)
                continue
            if message.content is _BAD:
                yield SecretText(message.raw, where=message.where)
                continue
            for block in self._blocks(message, REQUESTS):
                call = self._call(store, block, message)
                cid = block.get("id")
                if call is not None and isinstance(cid, str):
                    calls.setdefault((message.session, cid), call)
            rest, results = [], []
            for block in message.content:
                if (isinstance(block, dict) and block.get("type") == RESPONSE
                        and "toolResult" in block):
                    results.append(block)
                else:
                    rest.append(block)
            if not results:
                yield SecretText(message.raw, where=message.where)
                continue
            for block in results:
                cid = block.get("id")
                call = (calls.get((message.session, cid))
                        if isinstance(cid, str) else None)
                yield SecretText(block["toolResult"], call=call,
                                 where=message.where)
                outer = {k: v for k, v in block.items() if k != "toolResult"}
                rest.append(outer)
            if isinstance(message.raw, dict):
                node = dict(message.raw, content=rest)
            else:
                node = rest
            yield SecretText(node, where=message.where)
