"""Amazon Q Developer: the IDE plugins' chat history and the legacy CLI's.

Checked against aws/language-servers lsp-codewhisperer v0.0.131 (commit
625fb213, the agentic chat server every Amazon Q IDE plugin runs: VS Code,
JetBrains, Visual Studio and Eclipse) and aws/amazon-q-developer-cli
v1.19.7 (commit cf39ab62, `q chat`; unmaintained, Kiro CLI replaced it).
Every fact below was read from those sources by two researchers; the tool
argument names were fetched again here (fsRead.ts, fsWrite.ts, fsReplace.ts,
listDirectory.ts, grepSearch.ts, fileSearch.ts, tools/fs_read.rs,
fs_write.rs, mod.rs).

Two stores, one adapter:

IDE (chatDb.ts). ~/.aws/amazonq/history/chat-history-<workspaceId>.json,
one file per workspace, on every OS (the language server takes
os.homedir(), so only HOME / USERPROFILE moves it; there is no variable of
its own). The workspaceId is a one-way hash (SHA-256 of the workspace file
path, or MD5 of the folder's path, or "no-workspace"), so the project comes
from the calls themselves (executeBash's cwd). Each file is a LokiJS 1.5
database serialised whole with JSON.stringify: {"collections": [{"name":
"tabs", "data": [tab, ...]}, {"name": "settings", ...}], ...}. A tab is
{"historyId", "updatedAt" (epoch milliseconds, or an ISO string in older
files), "tabType", "title", "conversations": [{"conversationId",
"updatedAt" (ISO), "messages": [...]}], "modelId"?}. A message is {"body",
"type": "prompt" | "answer", "timestamp"? (ISO; missing on tabs ported from
the pre-LSP chat), "toolUses"? ([{"toolUseId", "name", "input"}], on an
answer), "userInputMessageContext"? ({"toolResults": [{"toolUseId",
"status": "success" | "error", "content": [{"json": ...} | {"text": ...}]}]
on the prompt that follows the answer; results are not on the call)}. A
call has no time of its own: its answer message's timestamp is used, else
the conversation's or tab's updatedAt as an upper bound (not_after). The
language server rewrites the whole file about once a second and not
atomically, so a read can meet half a file: it is read again once if the
file changed under it, and a file that still does not parse is counted as
not read. A file over MAX_FILE is not read. Images are stored as byte maps
and are neither parsed for calls nor searched.

CLI (database/mod.rs, migration 007). data.sqlite3 under the data folder
of the `dirs` crate: $XDG_DATA_HOME (when absolute) or ~/.local/share
(Linux), ~/Library/Application Support (macOS), %LOCALAPPDATA% (Windows),
then amazon-q/. Table conversations(key TEXT PRIMARY KEY, value TEXT):
key the working directory, value serde_json of ConversationState, of which
history is a list of {"user", "assistant", "request_metadata"}. user is
{"content": {"Prompt": {...}} | {"ToolUseResults": {"tool_use_results":
[...]}} | {"CancelledToolUses": {"prompt", "tool_use_results": [...]}},
"timestamp" (RFC 3339, or null on a tool-result turn), "env_context":
{"env_state": {"current_working_directory", ...}}}; assistant is
{"Response": {"message_id", "content"}} or {"ToolUse": {"message_id",
"content", "tool_uses": [{"id", "name", "orig_name", "args",
"orig_args"}]}}; a result is {"tool_use_id", "content": [{"Json": ...} |
{"Text": ...}], "status": "Success" | "Error"} and sits in the NEXT
entry's user. A call's time is request_metadata.request_start_timestamp_ms
of its entry (milliseconds), else only the file's last write is known. The
database is opened read-only through _sqlite and only conversations is
selected; auth_kv (Builder ID / SSO credentials), state and the legacy
Fig-era history table (commands the user typed) are never queried. Only one
conversation per directory is kept by Amazon Q, and the last turn's
results are missing when the user quit right after a tool ran.

Tool names. IDE (toolConstants.ts): executeBash {command, cwd,
explanation?}, fsRead {paths}, fsWrite {path, command: create | append,
fileText}, fsReplace {path, diffs}, listDirectory {path}, grepSearch
{query, path?}, fileSearch {path, queryName}; codeReview and every MCP
tool are other (an MCP tool's name is whatever the server calls it, so it
is judged by name). CLI (tools/mod.rs): execute_bash (execute_cmd on
Windows) {command, summary?}, fs_read {operations: [{mode: Line |
Directory | Search, path, ...} | {mode: Image, image_paths}]}, fs_write
{command: create | str_replace | insert | append, path, ...}; use_aws,
gh_issue and report_issue (the model-facing name; gh_issue is the
tool_index.json key), introspect, knowledge, thinking, todo_list,
delegate and MCP tools are other. The fs_read operation `mode` strings are read from the
Rust enum's names; their exact case on disk is not checked, so operations
are read by their path keys, whatever the mode.

A call is "declined" when its result is Amazon Q's own text for a tool use
the user turned down, whole and alone: "Tool use was cancelled by the user"
(chatDb.ts, conversation.rs), status error. "Command stopped by user" is
not declined: the command had started.

Not read: the IDE's settings collection (model list), every other file in
~/.aws/amazonq (the CLI's .cli_bash_history is what the user typed to the
prompt, not the agent's actions), and Kiro CLI, the closed-source
successor, whose format has no primary source. Masking: the IDE files are
read-only, because the running language server keeps the database in
memory and overwrites the file within a second; delete the chat in the IDE.
The unverified: the Windows home for the IDE is taken to be USERPROFILE
(os.homedir()), not checked on a Windows machine.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time

from . import _paths, _sqlite, _stamps, base
from .base import SecretText, Source, ToolCall

XDG = "XDG_DATA_HOME"

IDE_DIR = (".aws", "amazonq", "history")
IDE_PREFIX = "chat-history-"
IDE_SUFFIX = ".json"
CLI_FOLDER = "amazon-q"
CLI_DB = "data.sqlite3"
TABLE = "conversations"

# An IDE file larger than this is not read (the language server trims all
# its files to 150 MB in all once they pass 200 MB; one file cannot be
# bigger than that).
MAX_FILE = 256 << 20
# A CLI conversation row larger than this is not read.
MAX_ROW = 256 << 20
# A stored output kept on a ToolCall is cut here (clean.MAX_STRING).
OUTPUT_MAX = 1000000

DECLINED = "declined"
CANCELLED = "Tool use was cancelled by the user"

WHY_READ_ONLY_IDE = ("The Amazon Q language server keeps this chat in "
                     "memory and rewrites the file every second; delete the "
                     "chat in the IDE.")
WHY_READ_ONLY_CLI = ("Amazon Q's CLI keeps this in a database; delete the "
                     "conversation with q chat or remove the file.")

NOT_OPENED = "could not be opened"
NOT_DATABASE = "not a readable SQLite database"
DAMAGED = "part of it is damaged"
NOT_JSON = "not complete JSON (truncated, or still being written)"
TOO_LARGE = "too large to read"

MESSAGE_TYPES = ("prompt", "answer")

SHELL_TOOLS = ("executeBash", "execute_bash", "execute_cmd")
IDE_READS = ("fsRead", "listDirectory", "grepSearch", "fileSearch")
IDE_WRITES = ("fsWrite", "fsReplace")
CLI_WRITES = ("fs_write",)
OTHER_TOOLS = ("codeReview", "use_aws", "gh_issue", "report_issue",
               "introspect", "knowledge", "thinking", "todo_list", "delegate")


# What _read_ide returns for a file with nothing to read (JSON null is
# something, and unknown).
NOTHING = object()


def _string(value):
    return value if isinstance(value, str) and value else None


def _isabs(value, platform):
    return _paths.pathmod(platform).isabs(value)


def _strings(value):
    """The non-empty strings of a list; () for anything else."""
    if not isinstance(value, list):
        return ()
    return tuple(v for v in value if isinstance(v, str) and v)


def _stamp(value):
    """A message or tab time as ISO UTC: an ISO string, or a number of
    epoch milliseconds (what LokiJS writes for a Date on an indexed field)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        return _stamps.iso_utc(value, "iso")
    if isinstance(value, (int, float)):
        return _stamps.iso_utc(value, "ms")
    return None


def classify(name, args):
    """(kind, known, command, paths, consumed, workdir) for a call to `name`
    with these (decoded) arguments, IDE or CLI. Any other name, an MCP
    tool's included, is unknown."""
    if name in SHELL_TOOLS:
        command = _string(args.get("command"))
        return ("shell", True, command, (), ("command",) if command else (),
                _string(args.get("cwd")))
    if name == "fsRead":
        paths = _strings(args.get("paths"))
        return "read", True, None, paths, ("paths",) if paths else (), None
    if name in ("listDirectory", "grepSearch", "fileSearch"):
        path = _string(args.get("path"))
        return ("read", True, None, (path,) if path else (),
                ("path",) if path else (), None)
    if name in IDE_WRITES or name in CLI_WRITES:
        path = _string(args.get("path"))
        return "write", True, None, (path,) if path else (), (), None
    if name == "fs_read":
        paths = []
        operations = args.get("operations")
        for op in operations if isinstance(operations, list) else ():
            if isinstance(op, dict):
                if _string(op.get("path")):
                    paths.append(op["path"])
                paths.extend(_strings(op.get("image_paths")))
        return ("read", True, None, tuple(paths),
                ("operations",) if paths else (), None)
    if name in OTHER_TOOLS:
        return "other", True, None, (), (), None
    return "other", False, None, (), (), None


def _text_of(block):
    """The text of one result block ({json} / {text} on the IDE, {Json} /
    {Text} in the CLI): a shell result's stdout and stderr, the text of
    anything with a content string, else the block compactly as JSON."""
    if not isinstance(block, dict):
        return None
    for key in ("text", "Text"):
        if isinstance(block.get(key), str):
            return block[key]
    for key in ("json", "Json"):
        if key in block:
            return _json_text(block[key])
    return None


def _json_text(value):
    node = value
    if isinstance(node, dict) and isinstance(node.get("output"), dict):
        node = node["output"].get("content", node["output"])
    if isinstance(node, str):
        return node
    if isinstance(node, dict) and ("stdout" in node or "stderr" in node):
        parts = [node[k] for k in ("stdout", "stderr")
                 if isinstance(node.get(k), str) and node[k]]
        return "\n".join(parts)
    try:
        return json.dumps(node, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        return None


def output_text(blocks):
    """The text of a result's content blocks joined by newlines, cut at
    OUTPUT_MAX; None when there is none."""
    if not isinstance(blocks, list):
        return None
    texts = [t for t in (_text_of(b) for b in blocks) if t]
    if not texts:
        return None
    return "\n".join(texts)[:OUTPUT_MAX]


def never_ran(blocks, status):
    """True for a result that is Amazon Q's cancelled text, alone, as an
    error."""
    if not isinstance(status, str) or status.lower() != "error":
        return False
    if not isinstance(blocks, list) or len(blocks) != 1:
        return False
    return _text_of(blocks[0]) == CANCELLED


def _entries(folder):
    try:
        return list(os.scandir(folder))
    except OSError:
        return []


class AmazonQSource(Source):
    id = "amazon-q"
    name = "Amazon Q"
    unit = "file"       # a workspace file holds many tabs, a database many
    env = (XDG,)
    path_means = ("an Amazon Q history folder (chat-history-*.json) or the "
                  "CLI's data folder (data.sqlite3)")
    checked = "language-servers 0.0.131, Q Developer CLI 1.19.7"

    def reset(self):
        Source.reset(self)
        self._bad = set()
        self._tallied = set()

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """~/.aws/amazonq/history for the IDE plugins on every OS, and the
        CLI's amazon-q data folder: $XDG_DATA_HOME (absolute) or
        ~/.local/share on Linux, Application Support on macOS,
        %LOCALAPPDATA% on Windows."""
        plat = _paths.platform_name(platform)
        join = _paths.pathmod(plat).join
        out = [(join(home, *IDE_DIR), "default")]
        if plat == "win32":
            out.append((join(_paths.localappdata(env, home), CLI_FOLDER),
                        "default"))
        elif plat == "darwin":
            out.append((join(_paths.application_support(home), CLI_FOLDER),
                        "default"))
        else:
            data = env.get(XDG)
            if isinstance(data, str) and data and _isabs(data, plat):
                out.append((join(data, CLI_FOLDER), "env " + XDG))
            else:
                out.append((join(home, ".local", "share", CLI_FOLDER),
                            "default"))
        return out

    def stores(self, locations, since_days=None):
        """Every chat-history-*.json in a location (or its history/ folder),
        and a data.sqlite3 there; a location that is one of those files is
        taken as it is."""
        found, seen = [], set()

        def add(path, is_db):
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                return
            seen.add(key)
            if is_db:
                store = self.store(path, "sqlite", unit="database",
                                   why_read_only=WHY_READ_ONLY_CLI)
            else:
                store = self.store(path, "json", masking="read-only",
                                   why_read_only=WHY_READ_ONLY_IDE)
            if store is not None:
                found.append(store)

        for loc in locations:
            if os.path.isfile(loc.path):
                name = os.path.basename(loc.path)
                if name.startswith(IDE_PREFIX) and name.endswith(IDE_SUFFIX):
                    add(loc.path, False)
                elif name == CLI_DB or name.endswith(".sqlite3"):
                    add(loc.path, True)
                continue
            for folder in (loc.path, os.path.join(loc.path, "history")):
                for entry in _entries(folder):
                    name = entry.name
                    if name.startswith("."):
                        continue
                    ide = name.startswith(IDE_PREFIX) \
                        and name.endswith(IDE_SUFFIX)
                    if not ide and name != CLI_DB:
                        continue
                    try:
                        if not entry.is_file():
                            continue
                    except OSError:
                        continue
                    add(entry.path, not ide)
        return base.newest_first(found, since_days)

    # -- bookkeeping --------------------------------------------------------

    def _bad_store(self, store, reason, message=None):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, message or "could not read Amazon Q %s (%s)"
                  % (store.path, reason))

    def _first(self, store):
        first = store.path not in self._tallied
        self._tallied.add(store.path)
        return first

    # -- the IDE's JSON -----------------------------------------------------

    def _read_ide(self, store):
        """The decoded file, or NOTHING (counted and warned, once) when it is
        empty, too large, unreadable or not JSON. A file that changed while
        it was read, or does not parse and changed since, is read once
        more: the language server rewrites it in place."""
        for attempt in (0, 1):
            try:
                before = os.stat(store.path)
                if before.st_size > MAX_FILE:
                    self._bad_store(store, TOO_LARGE, "cannot read %s: %s "
                                    "(%d MB)" % (store.path, TOO_LARGE,
                                                 before.st_size >> 20))
                    return NOTHING
                with open(store.path, "rb") as fh:
                    raw = fh.read(MAX_FILE + 1)
                after = os.stat(store.path)
            except FileNotFoundError:
                return NOTHING
            except OSError as e:
                self._bad_store(store, NOT_OPENED, "cannot read %s (%s)"
                                % (store.path, type(e).__name__))
                return NOTHING
            text = raw.decode("utf-8", "surrogateescape")
            if text.startswith("\ufeff"):
                text = text[1:]
            if not text.strip():
                return NOTHING
            changed = (before.st_size, before.st_mtime) != \
                (after.st_size, after.st_mtime)
            try:
                return json.loads(text)
            except (ValueError, RecursionError):
                if attempt == 0 and changed:
                    time.sleep(0.05)
                    continue
                self._bad_store(store, NOT_JSON)
                return NOTHING
        return NOTHING

    def _tabs(self, store, tally):
        """Every tab dict in the file's "tabs" collection."""
        doc = self._read_ide(store)
        if doc is NOTHING:
            return
        collections = doc.get("collections") if isinstance(doc, dict) else None
        tabs = None
        for collection in collections if isinstance(collections, list) else ():
            if isinstance(collection, dict) and collection.get("name") == "tabs":
                tabs = collection.get("data")
        if not isinstance(tabs, list):
            if tally:
                self.count("unknown")
            return
        for tab in tabs:
            if isinstance(tab, dict):
                yield tab
            elif tally:
                self.count("unknown")

    @staticmethod
    def _messages(tab, tally, counter):
        """(conversation, message) for every message of a tab, in order."""
        conversations = tab.get("conversations")
        for conv in conversations if isinstance(conversations, list) else ():
            if not isinstance(conv, dict):
                if tally:
                    counter("unknown")
                continue
            messages = conv.get("messages")
            for message in messages if isinstance(messages, list) else ():
                if not isinstance(message, dict) \
                        or message.get("type") not in MESSAGE_TYPES:
                    if tally:
                        counter("unknown")
                    continue
                yield conv, message

    def _ide_calls(self, store, tally):
        seen = set()
        for tab in self._tabs(store, tally):
            session = _string(tab.get("historyId"))
            calls, pending = [], {}
            for conv, message in self._messages(tab, tally, self.count):
                if message["type"] == "answer":
                    uses = message.get("toolUses")
                    for use in uses if isinstance(uses, list) else ():
                        call = self._ide_call(store, tab, conv, message, use,
                                              session, tally)
                        if call is None:
                            continue
                        cid = call.tool_call_id
                        if cid is not None:
                            if cid in seen:
                                continue
                            seen.add(cid)
                            pending[cid] = call
                        calls.append(call)
                    continue
                context = message.get("userInputMessageContext")
                results = context.get("toolResults") \
                    if isinstance(context, dict) else None
                for result in results if isinstance(results, list) else ():
                    if not isinstance(result, dict):
                        continue
                    call = pending.pop(result.get("toolUseId"), None) \
                        if isinstance(result.get("toolUseId"), str) else None
                    if call is None:
                        continue
                    blocks = result.get("content")
                    call.output = output_text(blocks)
                    if never_ran(blocks, result.get("status")):
                        call.status = DECLINED
            project = next((c.workdir for c in calls if c.workdir), None)
            for call in calls:
                if call.project is None:
                    call.project = project
                yield call

    def _ide_call(self, store, tab, conv, message, use, session, tally):
        if not isinstance(use, dict) or not _string(use.get("name")):
            if tally:
                self.count("unknown")
            return None
        name = use["name"]
        args = base.decode_input(use.get("input"))
        kind, known, command, paths, consumed, workdir = classify(name, args)
        timestamp = _stamp(message.get("timestamp"))
        not_after = None
        if timestamp is None:
            not_after = (_stamp(conv.get("updatedAt"))
                         or _stamp(tab.get("updatedAt"))
                         or _stamps.iso_utc(store.mtime, "s"))
        cid = use.get("toolUseId")
        return ToolCall(
            self.id, store.path, name, args, kind=kind, known=known,
            session=session, project=workdir, timestamp=timestamp,
            not_after=not_after, tool_call_id=cid if isinstance(cid, str)
            and cid else None, command=command, workdir=workdir,
            paths=paths, consumed=consumed)

    def _ide_texts(self, store, tally):
        for tab in self._tabs(store, tally):
            session = _string(tab.get("historyId"))
            head = {k: v for k, v in tab.items()
                    if k not in ("conversations", "meta", "$loki")}
            yield SecretText(head, where="tab %s" % (session or "?"))
            calls = {}
            for conv, message in self._messages(tab, tally, self.count):
                where = "tab %s" % (session or "?")
                uses = message.get("toolUses")
                for use in uses if isinstance(uses, list) else ():
                    call = self._ide_call(store, tab, conv, message, use,
                                          session, False)
                    if call is not None and call.tool_call_id:
                        calls.setdefault(call.tool_call_id, call)
                rest = {k: v for k, v in message.items() if k != "images"}
                context = rest.get("userInputMessageContext")
                results = context.get("toolResults") \
                    if isinstance(context, dict) else None
                if isinstance(results, list) and results:
                    rest["userInputMessageContext"] = dict(
                        context, toolResults=[])
                    for result in results:
                        cid = result.get("toolUseId") \
                            if isinstance(result, dict) else None
                        yield SecretText(
                            result.get("content") if isinstance(result, dict)
                            else result,
                            call=calls.get(cid) if isinstance(cid, str)
                            else None, where=where)
                yield SecretText(rest, where=where)

    # -- the CLI's database -------------------------------------------------

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

    def _rows(self, store, tally):
        """(key, state) for every row of conversations whose value is a JSON
        object; a row that is not counts as unparsed, an oversized one too.
        Only conversations is selected."""
        if not self._is_database(store):
            return
        with _sqlite.readonly(store.path) as conn:
            if conn is None:
                self._bad_store(store, NOT_OPENED, "could not open %s "
                                "(permissions, or Amazon Q holds it locked)"
                                % store.path)
                return
            index = 0
            try:
                if TABLE not in _sqlite.tables(conn):
                    if tally:
                        self.count("unknown")
                    return
                cols = _sqlite.columns(conn, TABLE)
                if not {"key", "value"} <= set(cols):
                    if tally:
                        self.count("unknown")
                    return
                sql = ('SELECT "key", CASE WHEN length(CAST("value" AS BLOB))'
                       ' > ? THEN NULL ELSE "value" END, '
                       'length(CAST("value" AS BLOB)) FROM "conversations"')
                for key, value, size in conn.execute(sql, (MAX_ROW,)):
                    index += 1
                    if value is None:
                        if tally:
                            self.count("unparsed")
                        self.warn((store.path, index), "a conversation in "
                                  "%s is %d MB; not read"
                                  % (store.path, (size or 0) >> 20))
                        continue
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", "surrogateescape")
                    try:
                        state = json.loads(value)
                    except (TypeError, ValueError, RecursionError):
                        if tally:
                            self.count("unparsed")
                        continue
                    if not isinstance(state, dict):
                        if tally:
                            self.count("unknown")
                        continue
                    yield key if isinstance(key, str) else None, state
            except sqlite3.Error as e:
                self._bad_store(store, DAMAGED, "stopped reading %s after %d "
                                "rows (%s)" % (store.path, index,
                                               type(e).__name__))

    @staticmethod
    def _entries_of(state, tally, counter):
        history = state.get("history")
        for entry in history if isinstance(history, list) else ():
            if isinstance(entry, dict):
                yield entry
            elif tally:
                counter("unknown")

    @staticmethod
    def _results_of(entry):
        """The tool_use_results list of an entry's user message, or []."""
        user = entry.get("user")
        content = user.get("content") if isinstance(user, dict) else None
        if not isinstance(content, dict):
            return []
        for key in ("ToolUseResults", "CancelledToolUses"):
            part = content.get(key)
            if isinstance(part, dict) \
                    and isinstance(part.get("tool_use_results"), list):
                return part["tool_use_results"]
        return []

    def _cli_calls(self, store, tally):
        seen = set()
        for key, state in self._rows(store, tally):
            session = _string(state.get("conversation_id"))
            pending = {}
            for entry in self._entries_of(state, tally, self.count):
                for result in self._results_of(entry):
                    if not isinstance(result, dict):
                        continue
                    rid = result.get("tool_use_id")
                    call = pending.pop(rid, None) \
                        if isinstance(rid, str) else None
                    if call is not None:
                        blocks = result.get("content")
                        call.output = output_text(blocks)
                        if never_ran(blocks, result.get("status")):
                            call.status = DECLINED
                        yield call
                assistant = entry.get("assistant")
                use = assistant.get("ToolUse") \
                    if isinstance(assistant, dict) else None
                if not isinstance(use, dict):
                    continue
                uses = use.get("tool_uses")
                for item in uses if isinstance(uses, list) else ():
                    call = self._cli_call(store, key, session, entry, item,
                                          tally)
                    if call is None:
                        continue
                    if call.tool_call_id is not None:
                        marker = (key, session, call.tool_call_id)
                        if marker in seen:
                            continue
                        seen.add(marker)
                        pending[call.tool_call_id] = call
                    else:
                        yield call
            for call in pending.values():
                yield call

    def _cli_call(self, store, key, session, entry, item, tally):
        if not isinstance(item, dict) or not _string(item.get("name")):
            if tally:
                self.count("unknown")
            return None
        name = item["name"]
        args = base.decode_input(item.get("args"))
        kind, known, command, paths, consumed, _w = classify(name, args)
        workdir = None
        if kind == "shell":
            user = entry.get("user")
            env = user.get("env_context") if isinstance(user, dict) else None
            state = env.get("env_state") if isinstance(env, dict) else None
            workdir = _string(state.get("current_working_directory")) \
                if isinstance(state, dict) else None
            workdir = workdir or key
        meta = entry.get("request_metadata")
        ms = meta.get("request_start_timestamp_ms") \
            if isinstance(meta, dict) else None
        timestamp = _stamp(ms) if isinstance(ms, (int, float)) else None
        cid = item.get("id")
        return ToolCall(
            self.id, store.path, name, args, kind=kind, known=known,
            session=session, project=key, timestamp=timestamp,
            not_after=None if timestamp else _stamps.iso_utc(store.mtime, "s"),
            tool_call_id=cid if isinstance(cid, str) and cid else None,
            command=command, workdir=workdir, paths=paths, consumed=consumed)

    def _cli_texts(self, store, tally):
        for key, state in self._rows(store, tally):
            session = _string(state.get("conversation_id"))
            where = "conversation %s" % (session or "?")
            rest = {k: v for k, v in state.items() if k != "history"}
            yield SecretText(rest, where=where)
            calls = {}
            for entry in self._entries_of(state, tally, self.count):
                assistant = entry.get("assistant")
                use = assistant.get("ToolUse") \
                    if isinstance(assistant, dict) else None
                uses = use.get("tool_uses") if isinstance(use, dict) else None
                for item in uses if isinstance(uses, list) else ():
                    call = self._cli_call(store, key, session, entry, item,
                                          False)
                    if call is not None and call.tool_call_id:
                        calls.setdefault(call.tool_call_id, call)
                user = entry.get("user")
                node = dict(entry)
                for result in self._results_of(entry):
                    rid = result.get("tool_use_id") \
                        if isinstance(result, dict) else None
                    yield SecretText(
                        result.get("content") if isinstance(result, dict)
                        else result,
                        call=calls.get(rid) if isinstance(rid, str) else None,
                        where=where)
                if isinstance(user, dict) \
                        and isinstance(user.get("content"), dict):
                    content = {}
                    for part, value in user["content"].items():
                        if isinstance(value, dict) \
                                and "tool_use_results" in value:
                            value = {k: v for k, v in value.items()
                                     if k != "tool_use_results"}
                        content[part] = value
                    node["user"] = dict(user, content=content)
                yield SecretText(node, where=where)

    # -- both ---------------------------------------------------------------

    def tool_calls(self, store):
        """Every call, once per tool use id, with its result's text as
        output when the store holds one and "declined" when the user
        cancelled it. Never raises: a store that cannot be read warns and
        is counted."""
        try:
            tally = self._first(store)
            items = (self._ide_calls(store, tally) if store.format == "json"
                     else self._cli_calls(store, tally))
            for call in items:
                yield call
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    def secret_texts(self, store):
        """Every tab (title and context) and message of an IDE file, with
        each tool result handed over on its own, tied to its call; for the
        CLI, every conversation's state and each entry likewise. Never
        raises."""
        try:
            tally = self._first(store)
            items = (self._ide_texts(store, tally) if store.format == "json"
                     else self._cli_texts(store, tally))
            for text in items:
                yield text
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)
