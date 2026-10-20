"""Zed (zed-industries/zed): the editor's agent panel, its native threads.

Checked against Zed's main branch (crates/agent/src/db.rs, thread.rs,
legacy_thread.rs, tools/*.rs, crates/paths/src/paths.rs, crates/util/src/
path_list.rs, crates/language_model_core), read twice, once by each of two
researchers working from source and once more here for the tool names and
their input structs. No live database was available: the fixtures are built
from those structs, not captured. Zed's external ACP agents (Claude Code,
Codex, Gemini CLI inside the panel) keep their own history, which ranwhat
reads through their own adapters; whether Zed keeps a copy of it was not
checked, and none is read here.

Where (paths.rs data_dir(), db.rs): <data dir>/threads/threads.db, with the
data dir
- macOS: ~/Library/Application Support/Zed
- Linux and FreeBSD: $FLATPAK_XDG_DATA_HOME/zed when that is set, else
  dirs::data_local_dir()/zed, which is $XDG_DATA_HOME/zed (the variable
  read only when absolute, as the dirs crate reads it), else
  ~/.local/share/zed
- Windows: %LOCALAPPDATA%\\Zed
- `zed --user-data-dir <dir>` makes <dir> the whole data dir. That is a
  command-line flag, not a variable, so it cannot be found from the
  environment: it is `--path <dir>` here. ZED_STATELESS makes Zed keep the
  database in memory, so there is nothing to find. No other variable moves
  the data dir. The Flatpak sandbox's own data folder is not probed: its
  name was not verified.
A --path may name the data dir, its threads/ folder, or threads.db itself.

What is there: one SQLite database, opened read-only through _sqlite and
never written to (a copy is read when Zed holds it locked). One table:
threads(id TEXT PRIMARY KEY, summary TEXT NOT NULL, updated_at TEXT NOT
NULL, data_type TEXT NOT NULL, data BLOB NOT NULL), and columns added later
by ALTER TABLE, each of which may be missing or NULL in an older database:
parent_id (set on a subagent's thread), folder_paths (the workspace
folders, sorted, joined by a newline), folder_paths_order, created_at.
Times are RFC 3339 strings. A thread is one row, rewritten whole on every
save. Only the columns read here are asked for, each looked up first, and
the data cell is read one row at a time.

data is the thread as JSON (serde, DbThread), either as plain text
(data_type "json", the legacy form) or zstd-compressed (data_type "zstd",
what Zed writes now). Either is decoded by what the bytes are, not only by
data_type, and a TEXT cell is taken back to the bytes SQLite holds. zstd
needs Python 3.14 or the zstd command (_zstd.py); without them the store is
counted as unreadable and says why, and its plain rows are still read. The
JSON holds "version" ("0.3.0" now), "title", "updated_at", "messages", and
more (model, profile, subagent_context, sandbox_grants, draft_prompt,
detailed_summary, initial_project_snapshot, ...). messages is a list of the
externally tagged enum Message: {"User": {"id", "content": [...]}},
{"Agent": {"content": [...], "tool_results": {...}, "reasoning_details"}},
the string "Resume", or {"Compaction": ...}; the last two hold no call.
An agent's content is a list of {"Text": s}, {"Thinking": {...}},
{"RedactedThinking": s} and {"ToolUse": {"id", "name", "raw_input" (a JSON
string), "input", "is_input_complete", "thought_signature"}}. input is
{"type": "json", "value": {...}} or {"type": "text", "value": "..."}; older
rows hold the bare value, and raw_input is the fallback when input is
empty. tool_results maps a tool use id to {"tool_use_id", "tool_name",
"is_error", "content", "output"}: content a list of {"Text": s} (or
{"text": s}) and {"Image": ...}, or one bare such value or string; output
is normally null.

A row whose "version" is not "0.3.0" (or has none) is Zed's agent-1 format,
which Zed upgrades on load (legacy_thread.rs): messages with a "role",
"segments", "tool_uses" [{"id", "name", "input"}] and "tool_results"
[{"tool_use_id", "is_error", "content", "output"}]. That shape is read
too, from the research's account of the upgrade and not from a captured
row: a call is a tool_uses entry, its result the tool_results entry with
the same id, which Zed stores in the next message. Zed's System messages
are dropped by the upgrade and hold nothing typed. The pre-SQLite LMDB
store, if a very old install still has one, is not read.

Tools (tools/*.rs; the NAME of each, with its input struct): terminal and
sandboxed_terminal {command, cd, timeout_ms, head_lines, tail_lines; the
sandboxed one also allow_hosts, allow_all_hosts, fs_write_paths,
allow_fs_write_all, unsandboxed, reason}, edit_file {path, edits},
write_file {path, content}, read_file {path, start_line, end_line},
list_directory {path}, delete_path {path}, create_directory {path, reason},
copy_path and move_path {source_path, destination_path}, fetch {url}, grep
{regex, include_pattern, ...}, find_path {glob, offset}. Other tools Zed
registers (diagnostics, rename, apply_code_action, spawn_agent, skill, and
the rest) had no NAME or input read, and any tool added since is also
unknown: they are kind "other", known False, and judged by name. An MCP
server's tools are the user's, and judged by name as well.
"cd" is the root folder the command runs in: Zed's own wording is one of
the project's root directories, usually given by its name. It is made the
call's workdir as the matching folder_paths entry when one has that name,
as written otherwise.

Times: none per call. Zed stores a thread's created_at and updated_at and
nothing on a message. A call has no timestamp, and not_after is the
thread's updated_at (its last save, after which no call of it ran).

Results: a terminal's output is plain text in the result's content, with
no structured exit code: "Command executed successfully.", the raw output,
or "Command "<cmd>" failed with exit code N." and the output. is_error is
true for a failure and for a call that was cancelled before it finished
(Zed writes "Tool canceled by user" for it). A call answered with that text
never ran: it is "declined". Whether Zed writes a particular result when
the user refuses a tool permission was not verified, so a refusal is read
as whatever result the thread holds.

Not read: anything outside threads.db: Zed's settings.json (language-model
and context-server configuration, keys included), its credentials in the
system keychain, its logs, and the thread's model, profile and
sandbox_grants (configuration, not conversation).
"""

from __future__ import annotations

import json
import os
import sqlite3

from . import _paths, _sqlite, _stamps, _zstd, base
from .base import SecretText, Source, ToolCall

ENV = "FLATPAK_XDG_DATA_HOME"       # the one variable Zed's data dir reads
APP = "zed"
THREADS = "threads"
DB_NAME = "threads.db"
TABLE = "threads"

WHY_READ_ONLY = ("Zed keeps this in a database it holds open; delete the "
                 "thread in Zed's history.")

NOT_OPENED = "could not be opened"
NOT_DATABASE = "not a readable SQLite database"
DAMAGED = "part of it is damaged"

DECLINED = "declined"
CANCELED = "Tool canceled by user"

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# A thread is the whole conversation in one cell. More than this stored, or
# after decompression, is not a conversation, and reading it would take the
# machine's memory.
MAX_STORED = 256 << 20
MAX_DECODED = 512 << 20

SHELL_TOOLS = ("terminal", "sandboxed_terminal")
READ_TOOLS = {"read_file": ("path",), "list_directory": ("path",)}
WRITE_TOOLS = {"edit_file": ("path",), "write_file": ("path",),
               "delete_path": ("path",), "create_directory": ("path",),
               "copy_path": ("source_path", "destination_path"),
               "move_path": ("source_path", "destination_path")}
FETCH_TOOLS = ("fetch",)
OTHER_TOOLS = ("grep", "find_path")

_BAD = object()             # a cell that is not a thread


def _string(value):
    return value if isinstance(value, str) and value else None


def _isabs(value, platform):
    return _paths.pathmod(platform).isabs(value)


def classify(name, arguments):
    """(kind, known, command, paths, consumed) for a call to `name`."""
    if name in SHELL_TOOLS:
        command = _string(arguments.get("command"))
        return "shell", True, command, (), ("command",) if command else ()
    keys = READ_TOOLS.get(name)
    if keys is not None:
        paths = tuple(p for p in (_string(arguments.get(k)) for k in keys) if p)
        return "read", True, None, paths, keys[:1] if paths else ()
    keys = WRITE_TOOLS.get(name)
    if keys is not None:
        paths = tuple(p for p in (_string(arguments.get(k)) for k in keys) if p)
        return "write", True, None, paths, ()
    if name in FETCH_TOOLS:
        return "fetch", True, None, (), ()
    if name in OTHER_TOOLS:
        return "other", True, None, (), ()
    return "other", False, None, (), ()


def tool_input(use):
    """A ToolUse's arguments: input's value ({"type": "json" | "text",
    "value": ...}), or the bare value older rows hold, or raw_input when
    those are empty."""
    value = use.get("input")
    if isinstance(value, dict) and value.get("type") in ("json", "text") \
            and "value" in value:
        value = value["value"]
    if value in (None, "", {}) and isinstance(use.get("raw_input"), str):
        value = use["raw_input"]
    return value


def _content_texts(content):
    """The text of a result's content: a list of {"Text": s} / {"text": s}
    (or strings), or one such value."""
    if content is None:
        return []
    if not isinstance(content, list):
        content = [content]
    out = []
    for item in content:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for key in ("Text", "text"):
                value = item.get(key)
                if isinstance(value, str):
                    out.append(value)
                    break
                if isinstance(value, dict) and isinstance(
                        value.get("text"), str):
                    out.append(value["text"])
                    break
    return out


def output_text(result):
    """The text of a tool result, or None when it has none."""
    if not isinstance(result, dict):
        return _string(result)
    texts = _content_texts(result.get("content"))
    if not texts and isinstance(result.get("output"), str):
        texts = [result["output"]]
    return "\n".join(texts) if texts else None


def never_ran(result):
    """True when the result is the text Zed gives a call it cancelled."""
    if not isinstance(result, dict):
        return False
    texts = _content_texts(result.get("content"))
    return len(texts) == 1 and texts[0].strip() == CANCELED


def _bytes(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    return None


class _Thread(object):
    """One row of the threads table, decoded."""
    __slots__ = ("id", "summary", "project", "folders", "updated", "created",
                 "doc", "where")

    def __init__(self, id, summary, folders, updated, created, doc, where):
        self.id = id
        self.summary = summary
        self.folders = folders
        self.project = folders[0] if folders else None
        self.updated = updated
        self.created = created
        self.doc = doc              # the decoded dict, or _BAD
        self.where = where


class ZedSource(Source):
    id = "zed"
    name = "Zed"
    unit = "database"
    env = (ENV,)
    path_means = "Zed's data folder (the one holding threads/threads.db)"
    checked = "main (2026-10)"
    mask_note = ("Zed keeps its threads in a database it holds open, and "
                 "ranwhat only reads it: delete the thread in Zed to remove "
                 "it.")

    def reset(self):
        Source.reset(self)
        self._bad = set()
        self._tallied = set()

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """Zed's data dir: Application Support/Zed on macOS, %LOCALAPPDATA%
        \\Zed on Windows, $FLATPAK_XDG_DATA_HOME/zed else $XDG_DATA_HOME/zed
        (only when absolute) else ~/.local/share/zed elsewhere."""
        plat = _paths.platform_name(platform)
        join = _paths.pathmod(plat).join
        if plat == "darwin":
            return [(join(_paths.application_support(home), "Zed"),
                     "default")]
        if plat == "win32":
            return [(join(_paths.localappdata(env, home), "Zed"), "default")]
        flatpak = env.get(ENV)
        if isinstance(flatpak, str) and flatpak:
            return [(join(flatpak, APP), "env " + ENV)]
        data = env.get("XDG_DATA_HOME")
        if not (isinstance(data, str) and data and _isabs(data, plat)):
            data = join(home, ".local", "share")
        return [(join(data, APP), "default")]

    @staticmethod
    def databases(location):
        """The threads.db candidates for a location: the data dir's, the
        folder's own, or the file itself."""
        path = location.path
        if os.path.isfile(path):
            return [path]
        return [os.path.join(path, THREADS, DB_NAME),
                os.path.join(path, DB_NAME)]

    def stores(self, locations, since_days=None):
        """threads.db, whatever its mtime (base.newest_first keeps a
        database: its newest rows can sit in its -wal)."""
        found, seen = [], set()
        for loc in locations:
            for path in self.databases(loc):
                key = os.path.normcase(os.path.abspath(path))
                if key in seen:
                    continue
                try:
                    if not os.path.isfile(path):
                        continue
                except OSError:
                    continue
                seen.add(key)
                store = self.store(path, "sqlite", unit="database",
                                   why_read_only=WHY_READ_ONLY)
                if store is not None:
                    found.append(store)
        return base.newest_first(found, since_days)

    # -- bookkeeping --------------------------------------------------------

    def _bad_store(self, store, reason, message=None):
        """Count a store that could not be read, or not to its end, once a
        run, and warn once. Never what SQLite said: an error can quote a
        cell."""
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn((store.path, reason), message or "could not read Zed %s %s "
                  "(%s)" % (store.unit, store.path, reason))

    def _first(self, store):
        first = store.path not in self._tallied
        self._tallied.add(store.path)
        return first

    # -- the database -------------------------------------------------------

    def _is_database(self, store):
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

    def _decode(self, store, raw, data_type, tally, where):
        """The thread dict in a data cell, or _BAD (counted)."""
        data = _bytes(raw)
        if data is None:
            if tally:
                self.count("unknown")
            return _BAD
        compressed = data.startswith(ZSTD_MAGIC) or (
            isinstance(data_type, str) and data_type.lower() == "zstd")
        if compressed:
            if not _zstd.available():
                self._bad_store(store, "compressed, " + _zstd.NEEDS)
                return _BAD
            data = _zstd.decompress(data, MAX_DECODED)
            if data is None:
                if tally:
                    self.count("unparsed")
                self.warn((store.path, "zstd"), "cannot decompress a thread "
                          "of %s (%s)" % (store.path, where))
                return _BAD
        try:
            doc = json.loads(data.decode("utf-8", "surrogateescape")
                             .lstrip("﻿"))
        except (ValueError, RecursionError):
            if tally:
                self.count("unparsed")
            return _BAD
        if not isinstance(doc, dict):
            if tally:
                self.count("unknown")
            return _BAD
        return doc

    def _threads(self, store, tally):
        """A _Thread for every row of threads.db, in rowid order, read from
        a cursor through a read-only open. A database that cannot be opened
        or read warns and is counted; the copy a locked one is read from is
        removed however the reader stops."""
        if not self._is_database(store):
            return
        with _sqlite.readonly(store.path) as conn:
            if conn is None:
                self._bad_store(store, NOT_OPENED, "could not open %s "
                                "(permissions, or Zed holds it locked)"
                                % store.path)
                return
            index = 0
            try:
                if TABLE not in _sqlite.tables(conn):
                    if tally:
                        self.count("unknown")
                    return
                cols = _sqlite.columns(conn, TABLE)
                if "data" not in cols:
                    if tally:
                        self.count("unknown")
                    return
                wanted = [c for c in ("id", "summary", "updated_at",
                                      "created_at", "folder_paths",
                                      "data_type") if c in cols]
                sql = "SELECT rowid, length(data), %s FROM %s ORDER BY rowid" \
                    % (", ".join(_sqlite.quote_ident(c) for c in wanted)
                       or "NULL", _sqlite.quote_ident(TABLE))
                fetch = "SELECT data FROM %s WHERE rowid = ?" \
                    % _sqlite.quote_ident(TABLE)
                for values in conn.execute(sql):
                    index += 1
                    row = dict(zip(wanted, values[2:]))
                    rowid, size = values[0], values[1]
                    tid = row.get("id")
                    if isinstance(tid, bytes):
                        tid = tid.decode("utf-8", "surrogateescape")
                    tid = tid if isinstance(tid, str) else None
                    where = "threads row %s" % (tid or rowid)
                    if isinstance(size, int) and size > MAX_STORED:
                        if tally:
                            self.count("unparsed")
                        self.warn((store.path, rowid), "a thread of %s is "
                                  "too large to read (%s)"
                                  % (store.path, where))
                        continue
                    cell = conn.execute(fetch, (rowid,)).fetchone()
                    doc = _BAD if cell is None else self._decode(
                        store, cell[0], row.get("data_type"), tally, where)
                    folders = row.get("folder_paths")
                    if isinstance(folders, bytes):
                        folders = folders.decode("utf-8", "surrogateescape")
                    folders = [f for f in folders.split("\n") if f] \
                        if isinstance(folders, str) else []
                    summary = row.get("summary")
                    yield _Thread(
                        tid, summary if isinstance(summary, str) else None,
                        folders, row.get("updated_at"), row.get("created_at"),
                        doc, where)
            except sqlite3.Error as e:
                self._bad_store(store, DAMAGED, "stopped reading %s after %d "
                                "rows (%s)" % (store.path, index,
                                               type(e).__name__))

    # -- tool calls ---------------------------------------------------------

    @staticmethod
    def _workdir(thread, cd, platform=None):
        """The folder a terminal's `cd` names: an absolute path as it is,
        else the thread's folder of that name, else as written."""
        cd = _string(cd)
        if cd is None:
            return None
        for plat in ("linux", "win32"):
            if _isabs(cd, plat):
                return cd
        for folder in thread.folders:
            tail = folder.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            if tail == cd.strip("/\\"):
                return folder
        return cd

    def _not_after(self, thread, store, doc):
        for value in (thread.updated, doc.get("updated_at") if doc
                      is not _BAD else None):
            stamp = _stamps.iso_utc(value, "iso")
            if stamp:
                return stamp
        return _stamps.iso_utc(store.mtime, "s")

    def _call(self, store, thread, use, not_after):
        if not isinstance(use, dict):
            self.count("unreadable_calls")
            return None
        name = _string(use.get("name"))
        if name is None:
            self.count("unreadable_calls")
            return None
        args = base.decode_input(tool_input(use))
        kind, known, command, paths, consumed = classify(name, args)
        cid = use.get("id")
        workdir = self._workdir(thread, args.get("cd")) \
            if kind == "shell" else None
        return ToolCall(
            self.id, store.path, name, args, kind=kind, known=known,
            session=thread.id, project=thread.project, timestamp=None,
            not_after=not_after,
            tool_call_id=cid if isinstance(cid, str) else None,
            command=command, workdir=workdir, paths=paths,
            consumed=consumed)

    @staticmethod
    def _messages(thread):
        doc = thread.doc
        messages = doc.get("messages") if doc is not _BAD else None
        return messages if isinstance(messages, list) else []

    def _agent_parts(self, message):
        """(tool uses, {id: result}) of one message of either format, or
        None for a message that holds no call (and is not odd)."""
        if message == "Resume":
            return [], {}
        if not isinstance(message, dict):
            return None
        agent = message.get("Agent")
        if isinstance(agent, dict):
            content = agent.get("content")
            uses = [c["ToolUse"] for c in content
                    if isinstance(c, dict) and "ToolUse" in c] \
                if isinstance(content, list) else []
            results = agent.get("tool_results")
            if isinstance(results, list):       # tolerated: a list of results
                results = {r.get("tool_use_id"): r for r in results
                           if isinstance(r, dict)}
            return uses, results if isinstance(results, dict) else {}
        if "User" in message or "Compaction" in message:
            return [], {}
        if "role" in message:                   # agent-1, upgraded on load
            uses = message.get("tool_uses")
            results = message.get("tool_results")
            if isinstance(results, dict):
                pass
            elif isinstance(results, list):
                results = {r.get("tool_use_id"): r for r in results
                           if isinstance(r, dict)}
            else:
                results = {}
            return (uses if isinstance(uses, list) else []), results
        return None

    def tool_calls(self, store):
        """Every call, once per (thread, id), with its result's text as
        output when the thread holds one and "declined" when Zed cancelled
        it. A call is yielded when its result arrives, and those still
        waiting when its thread ends then. Never raises: a store that
        cannot be read warns and is counted."""
        try:
            for call in self._calls(store):
                yield call
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    def _calls(self, store):
        tally = self._first(store)
        for thread in self._threads(store, tally):
            if thread.doc is _BAD:
                continue
            not_after = self._not_after(thread, store, thread.doc)
            pending, done = {}, set()
            for message in self._messages(thread):
                parts = self._agent_parts(message)
                if parts is None:
                    if tally:
                        self.count("unknown")
                    continue
                uses, results = parts
                for use in uses:
                    cid = use.get("id") if isinstance(use, dict) else None
                    if isinstance(cid, str) and (cid in pending
                                                 or cid in done):
                        continue
                    call = self._call(store, thread, use, not_after)
                    if call is None:
                        continue
                    if call.tool_call_id is None:
                        yield call
                    else:
                        pending[cid] = call
                for cid, result in results.items():
                    call = pending.pop(cid, None) \
                        if isinstance(cid, str) else None
                    if call is None:
                        continue
                    call.output = output_text(result)
                    if never_ran(result):
                        call.status = DECLINED
                    done.add(cid)
                    yield call
            for call in pending.values():
                yield call

    # -- secret texts -------------------------------------------------------

    def secret_texts(self, store):
        """Every thread's summary, and the thread without its model and
        profile (configuration), with each tool result handed over on its
        own, tied to the call it answers. Never raises."""
        try:
            for text in self._secret_texts(store):
                yield text
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    def _secret_texts(self, store):
        tally = self._first(store)
        for thread in self._threads(store, tally):
            if thread.summary:
                yield SecretText(thread.summary,
                                 where=thread.where + ", summary")
            doc = thread.doc
            if doc is _BAD:
                continue
            not_after = self._not_after(thread, store, doc)
            rest = {k: v for k, v in doc.items()
                    if k not in ("messages", "model", "profile",
                                 "sandbox_grants")}
            yield SecretText(rest, where=thread.where)
            calls = {}
            for index, message in enumerate(self._messages(thread), 1):
                where = "%s, message %d" % (thread.where, index)
                parts = self._agent_parts(message)
                if parts is None or not parts[1]:
                    if parts is not None:
                        for use in parts[0]:
                            call = self._call(store, thread, use, not_after)
                            if call is not None and call.tool_call_id:
                                calls.setdefault(call.tool_call_id, call)
                    yield SecretText(message, where=where)
                    continue
                uses, results = parts
                for use in uses:
                    call = self._call(store, thread, use, not_after)
                    if call is not None and call.tool_call_id:
                        calls.setdefault(call.tool_call_id, call)
                for cid, result in results.items():
                    call = calls.get(cid) if isinstance(cid, str) else None
                    yield SecretText(result, call=call, where=where)
                stripped = self._without_results(message)
                yield SecretText(stripped, where=where)

    @staticmethod
    def _without_results(message):
        """An Agent message without its tool_results (handed over alone)."""
        if isinstance(message, dict) and isinstance(message.get("Agent"),
                                                    dict):
            agent = {k: v for k, v in message["Agent"].items()
                     if k != "tool_results"}
            return dict(message, Agent=agent)
        if isinstance(message, dict):
            return {k: v for k, v in message.items() if k != "tool_results"}
        return message
