"""Cursor: the editor's agent and composer chats, and the Cursor CLI.

Cursor is closed source and publishes no storage format. What is read here
was checked against a real dump of one Cursor 3.6 agent session
(empathic/toolpath @ 77dc16a, test-fixtures/cursor/convo.json, with its
format notes docs/agents/formats/cursor.md) and against open-source readers
their authors checked on real installs up to Cursor 3.21 (composerData _v
18; kkrlstrm/cursor-logger @ ec814de, cursor_logger/parse.py) and the CLI
to cursor-agent 2026.10.01 (nikolaylosev/sessionlens-vscode @ 5bd3a37,
cursor-db.js; S2thend/cursor-history @ c7f8806, specs/015-cursor-store-
stack/research.md; CHATS-lab/VibeLens @ 19040ec, ingest/parsers/cursor.py;
tuo-lei/vibe-replay @ d2418bf, provider-cursor/src/cursor/).

Two kinds of store, both SQLite, both only ever read:

1. The editor. Its user folder is <parent>/Cursor/User, where <parent> is
   %APPDATA% on Windows, ~/Library/Application Support on macOS and
   ${XDG_CONFIG_HOME:-~/.config} on Linux (Cursor ignores VS Code's
   VSCODE_PORTABLE and VSCODE_APPDATA). Every chat is in one database,
   globalStorage/state.vscdb, table cursorDiskKV (key TEXT UNIQUE, value
   BLOB), whose chat values are UTF-8 JSON:
   - composerData:<composerId>: one chat. createdAt and lastUpdatedAt in
     ms; workspaceIdentifier {id, uri {fsPath}} or {configPath}, and
     trackedGitRepos[].repoPath, when it has them (the 3.6 dump has
     neither). A chat from before _v 3 holds its messages inline, in
     "conversation": [bubble, ...].
   - bubbleId:<composerId>:<bubbleId>: one message ("bubble"). createdAt
     is an ISO string in 2026 builds, missing on some. A tool call is
     its toolFormerData: {tool, toolCallId, name, params (a JSON string),
     rawArgs (a JSON string, some builds), result (a JSON string, an
     object for todo_write, or absent), status, userDecision?,
     additionalData {startedAtMs, status, userDecision?, ...} (a Python
     repr string in some builds)}. The call and its result are in the
     same bubble. A user bubble can hold a stub toolFormerData with no
     name and no toolCallId: that is no call. Bubbles that no composer
     lists any more (a rewind or an edit) are read too: what they ran,
     ran. The composer segment of the key is opaque (a sub-agent's holds
     a newline), so a key is split at its last ":".
   - composer.content.<sha256>: the raw text of a file before or after an
     edit (edit_file_v2's result names them, beforeContentId and
     afterContentId), and messageRequestContext:<composerId>:<id>: the
     context sent with a prompt.
   The chat list (each chat's workspace) is ItemTable's
   composer.composerHeaders, {"allComposers": [{composerId,
   workspaceIdentifier, ...}]}; one build kept it in cursorDiskKV under
   "composerHeaders". A head with only a workspace id is looked up in
   workspaceStorage/<id>/workspace.json ({"folder": "file:///..."}).

   The database can be gigabytes, so it is read by key range (key >= x
   AND key < y, which uses the key's unique index; a LIKE would not), one
   row at a time. Siblings state.vscdb.backup and state.vscdb.corrupted.*
   are never opened. workspaceStorage/*/state.vscdb is not read: since the
   composer replaced the old chat panel its cursorDiskKV is empty (the
   toolpath notes, sampled on 3.6), and the panel's old
   workbench.panel.aichat.view.aichat.chatdata (2024) held no tool call.

2. The CLI (cursor-agent): ~/.cursor/chats/<md5 of cwd>/<agentId>/store.db,
   and its ACP variant ~/.cursor/acp-sessions/<id>/store.db, with
   meta.json beside it ({"cwd": ...}). Table blobs (id, data): message
   leaves are JSON {role, content: [blocks]} with blocks {type:
   "tool-call", toolCallId, toolName, args} and, in a role "tool"
   message, {type: "tool-result", toolCallId, toolName, result}; a
   Shell result is the text "Exit code: N\\n\\nCommand output: ...".
   The rest of the blobs are protobuf tree nodes, passed over without a
   word. Every JSON leaf is read, on every branch. Table meta, key "0",
   is hex-encoded JSON {agentId, createdAt, ..., blobEncryptionKey?}:
   only agentId is kept. Messages carry no time of their own and no
   decline marker.

A call never ran ("declined") when its record says so (cursor-logger
parse.py; the toolpath and vibe-replay notes): result {"rejected": true};
userDecision "rejected" in toolFormerData or additionalData; status
"cancelled"; status "loading" or "running", or none at all, with no
result. Whatever else it says, a call ran when it shows it started: a
shell command with additionalData.startedAtMs (the time its terminal
started), an exit code, any output, or a stop part way (endedReason
...ABORTED, notInterrupted false); and an edit with a result (Cursor
writes an edit to the file first, and a "rejected" review undoes it).
Status "error" with no result is a call that ran and failed (the toolpath
notes; cursor-logger reads it as a failure, not as never run). When one
toolCallId is in several bubbles, a copy that ran wins over a declined one.

A call's time is its bubble's createdAt, else additionalData.startedAtMs,
else timingInfo.clientStartTime when it is an epoch after 2000 (it is
sometimes elapsed ms). Without one, not_after is the newest of its chat's
lastUpdatedAt and every dated bubble of that chat (lastUpdatedAt is the
time of the user's last prompt: in the 3.6 dump every bubble is later),
else the newer mtime of the database and its -wal (a live database's
newest rows are in the -wal).

Not read, on purpose: ItemTable (VS Code's shared state: Cursor's own
login, cursorAuth/*, and other extensions' tokens and secret:// keys)
except its one chat-list key, which is read for workspaces and never
searched for secrets; composerData's blobEncryptionKey and
speculativeSummarizationEncryptionKey, and the CLI meta's
blobEncryptionKey, which are dropped as soon as they are read;
~/.config/cursor/auth.json; ~/.cursor/mcp.json; the CLI's cursorDiskKV
agentKv:blob rows; and ~/.cursor/projects/*/agent-transcripts/*.jsonl,
which repeat what the CLI and editor stores hold without results, ids or
times (its assistant text is often "[REDACTED]").
"""

from __future__ import annotations

import ast
import contextlib
import json
import os
import re
import sqlite3
import stat

from urllib.parse import unquote

from . import _paths, _sqlite, _stamps, base
from .base import SecretText, Source, Store, ToolCall

USER = ("Cursor", "User")
HOME_DIR = ".cursor"

GLOBAL = ("globalStorage", "state.vscdb")
WORKSPACES = "workspaceStorage"
WORKSPACE_JSON = "workspace.json"
CLI_DIRS = (("chats", 2), ("acp-sessions", 1))   # folder, depth of store.db
CLI_DB = "store.db"
CLI_META = "meta.json"

KV = "cursorDiskKV"
ITEMS = "ItemTable"
HEADERS_KEY = "composer.composerHeaders"        # in ItemTable
HEADERS_KV = "composerHeaders"                  # in cursorDiskKV, one build

COMPOSER = "composerData:"
BUBBLE = "bubbleId:"
CONTEXT = "messageRequestContext:"
CONTENT = "composer.content."

# Keys that hold an encryption key, never handed to clean or kept.
KEYS = ("blobEncryptionKey", "speculativeSummarizationEncryptionKey")
# Such a key's value in a row's text, for a row that is not JSON (cut
# short, or damaged): the string, closed or not, is blanked.
_KEY_VALUE = re.compile(r'("(?:%s)"\s*:\s*)"(?:[^"\\]|\\.)*"?'
                        % "|".join(KEYS))

# What clean's report says of a database that holds a secret.
WHY_READ_ONLY = "Cursor keeps this in a database; delete the chat in Cursor."

NOT_OPENED = "could not be opened"
NOT_DATABASE = "not a readable SQLite database"
DAMAGED = "part of it is damaged"

DECLINED = "declined"

# Tool names, editor and CLI, mapped to a kind. The editor's from the
# numeric enum the toolpath notes extracted from Cursor's workbench code
# and from the names in real bubbles; the CLI's (and the Cursor SDK's
# lower-case ones) from vibe-replay's tool-mapping.ts and sessionlens'
# fixtures. Any other name is unknown: kind "other", judged by its name,
# MCP tools (mcp-<server>-<tool>, call_mcp_tool) among them.
SHELL = ("run_terminal_command_v2", "run_terminal_cmd", "Shell", "shell")
READ = ("read_file_v2", "read_file", "Read", "ReadFile", "read")
WRITE = ("edit_file_v2", "edit_file", "search_replace", "write",
         "delete_file", "Write", "WriteFile", "StrReplace", "EditFile",
         "MultiEdit", "Delete", "edit")
FETCH = ("web_search", "web_fetch", "fetch_pull_request", "WebFetch",
         "WebSearch")
OTHER = ("ripgrep_raw_search", "ripgrep_search", "glob_file_search",
         "file_search", "list_dir", "list_dir_v2", "codebase_search",
         "semantic_search_full", "read_semsearch_files", "search_symbols",
         "go_to_definition", "read_lints", "fix_lints", "task", "task_v2",
         "await_task", "todo_read", "todo_write", "create_plan",
         "update_current_step", "ask_question", "switch_mode",
         "fetch_rules", "knowledge_base", "deep_search", "create_diagram",
         "list_mcp_resources", "get_mcp_tools", "reflect",
         "Grep", "Glob", "LS", "Task", "Subagent", "TodoWrite")
KINDS = {}
for _kind, _names in (("shell", SHELL), ("read", READ), ("write", WRITE),
                      ("fetch", FETCH), ("other", OTHER)):
    for _name in _names:
        KINDS[_name] = _kind

# Where a read or a write names its file, in the order they are looked
# for: the editor's targetFile (read_file_v2, delete_file),
# relativeWorkspacePath (edit_file_v2; an absolute path in practice),
# effectiveUri (read_file_v2, the same file), file_path and target_file
# (search_replace, edit_file); the CLI's path.
PATH_KEYS = ("targetFile", "relativeWorkspacePath", "effectiveUri",
             "file_path", "target_file", "filePath", "path")

# Before this many ms since 1970 (2000-01-01), timingInfo holds elapsed
# time, not a date.
_EPOCH_2000_MS = 946684800000

# A Python-repr additionalData is parsed only up to this size.
_REPR_MAX = 1 << 16
# meta.json and workspace.json are read only up to this size.
_SMALL_MAX = 1 << 20

_BAD = object()         # a value that is not JSON


def _string(value):
    return value if isinstance(value, str) and value else None


def local_path(value):
    """A recorded path as the local path it names: a file:// URI made a
    path (percent-escapes decoded, a Windows drive's leading "/" dropped);
    anything else as it is. None for an empty value or another host."""
    value = _string(value)
    if value is None or not value.lower().startswith("file://"):
        return value
    rest = value[len("file://"):]
    if rest.lower().startswith("localhost/"):
        rest = rest[len("localhost"):]
    if not rest.startswith("/"):
        return None
    path = unquote(rest)
    if len(path) > 2 and path[2] == ":" and path[1].isalpha():
        path = path[1:]
    return path or None


def _text(value):
    """A cell as text: bytes read as UTF-8, any other byte kept."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "surrogateescape")
    return value if isinstance(value, str) else None


def _json(value):
    """A cell's JSON, None for an empty one, _BAD for one that is not
    JSON."""
    text = _text(value)
    if text is None or not text.strip():
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return _BAD


def _object(value):
    """value as a dict: a dict kept, a JSON string of one parsed, a
    Python-repr string of one (some builds' additionalData) read with
    ast.literal_eval, which evaluates no code. {} otherwise."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        out = json.loads(value)
    except (ValueError, RecursionError):
        out = None
        if len(value) <= _REPR_MAX and value.lstrip()[:1] == "{":
            try:
                out = ast.literal_eval(value)
            except (ValueError, SyntaxError, TypeError, MemoryError,
                    RecursionError):
                out = None
    return out if isinstance(out, dict) else {}


def _decoded(value):
    """A JSON-string field (params, result) decoded, or as it is."""
    if isinstance(value, str) and value[:1] in ("{", "["):
        try:
            return json.loads(value)
        except (ValueError, RecursionError):
            return value
    return value


def _without_keys(node, raw=None, depth=0):
    """node with every encryption key (KEYS) left out, at any depth. A
    cell whose text (raw) names none of them is returned as it is."""
    if depth == 0 and raw is not None:
        text = _text(raw) or ""
        if not any(key in text for key in KEYS):
            return node
    if depth > 200:
        return node
    if isinstance(node, dict):
        return {k: _without_keys(v, None, depth + 1)
                for k, v in node.items() if k not in KEYS}
    if isinstance(node, list):
        return [_without_keys(v, None, depth + 1) for v in node]
    return node


def _scrubbed(text):
    """A row's raw text with every encryption key's value blanked."""
    if not text or not any(key in text for key in KEYS):
        return text
    return _KEY_VALUE.sub(r'\1""', text)


def _workspace(ident):
    """The folder a workspaceIdentifier names: uri.fsPath (or its path
    for a file: URI), else configPath (a .code-workspace file)."""
    if not isinstance(ident, dict):
        return None
    for key in ("uri", "configPath"):
        uri = ident.get(key)
        if isinstance(uri, str):
            found = local_path(uri)
        elif isinstance(uri, dict):
            found = _string(uri.get("fsPath"))
            if found is None and uri.get("scheme") in (None, "file"):
                found = _string(uri.get("path"))
            if found is None:
                found = local_path(uri.get("external"))
        else:
            found = None
        if found:
            return found
    return None


def _repo(composer):
    repos = composer.get("trackedGitRepos")
    if isinstance(repos, list) and repos and isinstance(repos[0], dict):
        return _string(repos[0].get("repoPath"))
    return None


def _number_time(value):
    """A bubble's createdAt when it is a number (some readers saw them):
    ms above 1e10, else seconds."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return _stamps.iso_utc(value, "ms" if value > 1e10 else "s")


def _bubble_time(bubble, data):
    """The call's own time (see the module notes), or None."""
    created = bubble.get("createdAt")
    stamp = (_stamps.iso_utc(created, "iso") if isinstance(created, str)
             else _number_time(created))
    if stamp:
        return stamp
    stamp = _stamps.iso_utc(data.get("startedAtMs"), "ms")
    if stamp:
        return stamp
    timing = bubble.get("timingInfo")
    start = timing.get("clientStartTime") if isinstance(timing, dict) else None
    if (isinstance(start, (int, float)) and not isinstance(start, bool)
            and start >= _EPOCH_2000_MS):
        return _stamps.iso_utc(start, "ms")
    return None


def _paths_in(arguments):
    """(paths, keys): the local paths PATH_KEYS name, once each, and the
    keys they came from."""
    paths, keys = [], []
    for key in PATH_KEYS:
        value = arguments.get(key)
        found = False
        for item in value if isinstance(value, list) else [value]:
            path = local_path(item) if isinstance(item, str) else None
            if path:
                found = True
                if path not in paths:
                    paths.append(path)
        if found:
            keys.append(key)
    return tuple(paths), tuple(keys)


def classify(name, arguments, result=None):
    """(kind, known, command, paths, consumed, workdir) for a call to
    `name` with these decoded arguments. A shell call's workdir is its
    cwd, else the directory the editor says it ended in."""
    kind = KINDS.get(name)
    if kind is None:
        return "other", False, None, (), (), None
    if kind == "shell":
        command = _string(arguments.get("command"))
        workdir = _string(arguments.get("cwd"))
        if workdir is None and isinstance(result, dict):
            workdir = _string(result.get("resultingWorkingDirectory"))
        consumed = ()
        if command:
            # parsingResult is the editor's own parse of that command.
            consumed = tuple(k for k in ("command", "parsingResult")
                             if k in arguments)
        return "shell", True, command, (), consumed, workdir
    if kind == "read":
        paths, keys = _paths_in(arguments)
        return "read", True, None, paths, keys, None
    if kind == "write":
        paths, _keys = _paths_in(arguments)
        return "write", True, None, paths, (), None
    return kind, True, None, (), (), None


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _ran(result, data):
    """True when a shell record shows the command started: its terminal
    started (startedAtMs), it exited with a code, it printed something,
    or it was stopped part way."""
    if _number(data.get("startedAtMs")) and data["startedAtMs"] > 0:
        return True
    if not isinstance(result, dict):
        return False
    ended = result.get("endedReason")
    return ((isinstance(ended, str) and ended.upper().endswith("ABORTED"))
            or result.get("notInterrupted") is False
            or _number(result.get("exitCode"))
            or _number(result.get("exitCodeV2"))
            or bool(_string(result.get("output"))))


def declined(former, result, data, kind=None):
    """True when the editor's record says the call never ran (see the
    module notes). kind is the call's (classify)."""
    if isinstance(result, dict) and result.get("rejected") is True:
        return True
    if _ran(result, data):
        return False
    if kind == "write" and result is not None and result not in ("", {}):
        return False            # written; a rejected review undid it
    if "rejected" in (former.get("userDecision"), data.get("userDecision")):
        return True
    # "loading", "running" or no status with no result is not taken for
    # declined: a call that is still running, or whose result the editor
    # had not saved yet, looks the same, and a command that ran must never
    # be shown as one that did not.
    return former.get("status") == "cancelled"


def _later(a, b):
    """The later of two UTC stamps ("...Z"), either of which may be None;
    a stamp of no zone is not compared."""
    a = a if isinstance(a, str) and a.endswith("Z") else None
    b = b if isinstance(b, str) and b.endswith("Z") else None
    return max(a, b) if a and b else (a or b)


def _former_args(former):
    """The call's arguments: params, else rawArgs, decoded."""
    params = base.decode_input(former.get("params"))
    if params and "_raw" not in params and "_value" not in params:
        return params
    raw = base.decode_input(former.get("rawArgs"))
    if raw and "_raw" not in raw and "_value" not in raw:
        return raw
    return params or raw


def _output(kind, result):
    """What the call returned, as text: a command's output, a file's
    contents; the result itself when it is not JSON."""
    if isinstance(result, str):
        return result or None
    if isinstance(result, dict):
        key = {"shell": "output", "read": "contents"}.get(kind)
        if key:
            return _string(result.get(key))
    return None


def _key_parts(key, prefix):
    """(composerId, rest) for a key <prefix><composerId>:<rest>, split at
    the last ":" (a composer id can hold a newline, never a ":")."""
    body = key[len(prefix):]
    composer, _sep, rest = body.rpartition(":")
    return composer, rest


def _shown(key):
    return key.replace("\n", "\\n").replace("\r", "\\r")


def _range(prefix):
    """(low, high) bounds of every key starting with `prefix`."""
    return prefix, prefix[:-1] + chr(ord(prefix[-1]) + 1)


def _wal_mtime(path, mtime):
    """The newer of mtime and the -wal's: a live database's newest rows
    are in its -wal."""
    try:
        return max(mtime or 0.0, os.stat(path + "-wal").st_mtime)
    except OSError:
        return mtime


def _read_small(path):
    """A small JSON file's object, or {}. Only a regular file is read: a
    FIFO there would block the read for good."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_BINARY", 0))
    except (OSError, ValueError):
        return {}
    try:
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return {}
            raw = fh.read(_SMALL_MAX + 1)
    except OSError:
        return {}
    if len(raw) > _SMALL_MAX:
        return {}
    value = _json(raw)
    return value if isinstance(value, dict) else {}


def _entries(folder):
    try:
        return [e for e in os.scandir(folder) if not e.name.startswith(".")]
    except OSError:
        return []


def _is_dir(entry):
    try:
        return entry.is_dir()
    except OSError:
        return False


def _is_file(path):
    try:
        return os.path.isfile(path)
    except (OSError, ValueError):
        return False


def cli_databases(root):
    """Every CLI store.db under a ~/.cursor folder: chats/<hash>/<id>/
    and acp-sessions/<id>/."""
    out = []
    for name, depth in CLI_DIRS:
        folders = [os.path.join(root, name)]
        for _ in range(depth):
            folders = [e.path for f in folders for e in _entries(f)
                       if _is_dir(e)]
        out += [p for p in (os.path.join(f, CLI_DB) for f in folders)
                if _is_file(p)]
    return out


class CursorSource(Source):
    id = "cursor"
    name = "Cursor"
    # What `ranwhat sources` and the reports count Cursor's stores in: the
    # editor keeps every chat in one database, the CLI one per chat.
    unit = "database"
    env = ()
    path_means = ("a Cursor user folder (the one holding globalStorage/), "
                  "or ~/.cursor for the Cursor CLI")
    checked = ("Cursor 3.6 to 3.21 (editor); cursor-agent 2026.07.09 to "
               "2026.10.01 (CLI)")
    read_only = True        # SQLite, every store of it

    def reset(self):
        Source.reset(self)
        self._bad = set()       # stores already counted as unreadable
        self._tallied = set()   # stores whose skipped rows are counted

    # -- where to look ------------------------------------------------------

    def default_paths(self, env, home, platform):
        """The editor's user folder (<parent>/Cursor/User, _paths.
        editor_parent) and ~/.cursor, the CLI's. Cursor reads no variable
        that moves either."""
        parent = _paths.editor_parent(env, home, platform)
        return [(_paths.join(platform, parent, *USER), "default"),
                (_paths.join(platform, home, HOME_DIR), "default")]

    def _store(self, path, cli):
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            return None
        session = project = None
        if cli:
            folder = os.path.dirname(path)
            session = os.path.basename(folder)
            project = _string(_read_small(
                os.path.join(folder, CLI_META)).get("cwd"))
        return Store(self.id, path, "sqlite", unit=self.unit, session=session,
                     project=project, mtime=mtime,
                     why_read_only=WHY_READ_ONLY)

    def stores(self, locations, since_days=None):
        """The editor's globalStorage/state.vscdb and every CLI store.db
        under each location (either kind of folder, or one of those files
        named directly), whatever their mtime."""
        found, seen = [], set()
        for loc in locations:
            path = loc.path
            pairs = []
            if _is_file(path):
                pairs.append((path, os.path.basename(path) == CLI_DB))
            else:
                main = os.path.join(path, *GLOBAL)
                if _is_file(main):
                    pairs.append((main, False))
                pairs += [(p, True) for p in cli_databases(path)]
            for db, cli in pairs:
                key = os.path.normcase(os.path.abspath(db))
                if key in seen:
                    continue
                seen.add(key)
                store = self._store(db, cli)
                if store is not None:
                    found.append(store)
        return base.newest_first(found, since_days)

    # -- reading ------------------------------------------------------------

    def _bad_store(self, store, reason, detail=None):
        if store.path not in self._bad:
            self._bad.add(store.path)
            self.unreadable_store(reason, store.path)
        self.warn(store.path, "could not read Cursor %s %s (%s)"
                  % (store.unit, store.path, detail or reason))

    def _first(self, store):
        """True the first time a store's rows are tallied this run."""
        first = store.path not in self._tallied
        self._tallied.add(store.path)
        return first

    @contextlib.contextmanager
    def _open(self, store):
        """A read-only connection to the store, or None. A file that is
        not SQLite is said so without opening it; an empty one holds
        nothing to read."""
        try:
            with open(store.path, "rb") as fh:
                magic = fh.read(len(_sqlite.SQLITE_MAGIC))
        except FileNotFoundError:
            yield None
            return
        except OSError as e:
            self._bad_store(store, NOT_OPENED, type(e).__name__)
            yield None
            return
        if not magic:
            yield None
            return
        if magic != _sqlite.SQLITE_MAGIC:
            self._bad_store(store, NOT_DATABASE)
            yield None
            return
        with _sqlite.readonly(store.path) as conn:
            if conn is None:
                self._bad_store(store, NOT_OPENED)
            yield conn

    def _is_cli(self, store):
        return os.path.basename(store.path) == CLI_DB

    def _not_after(self, store):
        return _stamps.iso_utc(_wal_mtime(store.path, store.mtime), "s")

    def tool_calls(self, store):
        """Every distinct call in the store, once per toolCallId. Never
        raises: a database that cannot be read warns once, is counted and
        yields what was read before it."""
        try:
            with self._open(store) as conn:
                if conn is None:
                    return
                try:
                    reader = (self._cli_calls if self._is_cli(store)
                              else self._editor_calls)
                    for call in reader(store, conn):
                        yield call
                except sqlite3.Error as e:
                    # The class only: what SQLite says can quote a cell.
                    self._bad_store(store, DAMAGED, type(e).__name__)
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    def secret_texts(self, store):
        """Every chat row of the store (see the module notes), each tool
        result on its own and tied to its call. Never the login, never an
        encryption key."""
        try:
            with self._open(store) as conn:
                if conn is None:
                    return
                try:
                    reader = (self._cli_texts if self._is_cli(store)
                              else self._editor_texts)
                    for text in reader(store, conn):
                        yield text
                except sqlite3.Error as e:
                    self._bad_store(store, DAMAGED, type(e).__name__)
        except Exception as e:      # never raise: say so and go on
            self.stopped(store, e)

    # -- the editor ---------------------------------------------------------

    def _rows(self, conn, prefix, tally):
        """(key, decoded value, raw text) for every cursorDiskKV key that
        starts with `prefix`, by key range. A value that is not JSON is
        _BAD (counted as unparsed with tally); an empty one is skipped."""
        low, high = _range(prefix)
        for row in _sqlite.iter_rows(conn, KV, ("key", "value"),
                                     where="key >= ? AND key < ? "
                                           "ORDER BY key",
                                     params=(low, high)):
            key = row["key"]
            if not isinstance(key, str):
                continue
            value = _json(row["value"])
            if value is None:
                continue
            if value is _BAD and tally:
                self.count("unparsed")
            yield key, value, row["value"]

    def _one(self, conn, table, key):
        """The decoded value of one key of `table`, or None."""
        for row in _sqlite.iter_rows(conn, table, ("value",),
                                     where="key = ?", params=(key,)):
            value = _json(row["value"])
            return value if value is not _BAD else None
        return None

    def _heads(self, store, conn):
        """{composerId: workspace folder} from the chat list."""
        out = {}
        user = os.path.dirname(os.path.dirname(store.path))
        workspaces = {}
        for table, key in ((ITEMS, HEADERS_KEY), (KV, HEADERS_KV)):
            if not _sqlite.columns(conn, table):
                continue
            doc = self._one(conn, table, key)
            heads = doc.get("allComposers") if isinstance(doc, dict) else None
            for head in heads if isinstance(heads, list) else ():
                if not isinstance(head, dict):
                    continue
                cid = _string(head.get("composerId"))
                if cid is None or cid in out:
                    continue
                ident = head.get("workspaceIdentifier")
                folder = _workspace(ident)
                if folder is None and isinstance(ident, dict):
                    folder = self._workspace_json(user, ident.get("id"),
                                                  workspaces)
                if folder is None:
                    folder = _repo(head)
                if folder:
                    out[cid] = folder
        return out

    @staticmethod
    def _workspace_json(user, wid, cache):
        """The folder workspaceStorage/<id>/workspace.json names."""
        wid = _string(wid)
        if wid is None or os.sep in wid or "/" in wid or wid in (".", ".."):
            return None
        if wid not in cache:
            doc = _read_small(os.path.join(user, WORKSPACES, wid,
                                           WORKSPACE_JSON))
            found = None
            for key in ("folder", "workspace"):
                value = doc.get(key)
                if isinstance(value, dict):
                    value = value.get("configPath")
                found = local_path(value) if isinstance(value, str) else None
                if found:
                    break
            cache[wid] = found
        return cache[wid]

    def _chats(self, store, conn, heads, tally, inline):
        """{composerId: (project, not_after)} for every chat, and for a
        chat that holds its messages inline, each of them through
        inline(composerId, bubble, chat)."""
        chats = {}
        for key, value, _raw in self._rows(conn, COMPOSER, tally):
            if value is _BAD:
                continue
            if not isinstance(value, dict):
                if tally:
                    self.count("unknown")
                continue
            cid = _string(value.get("composerId")) or key[len(COMPOSER):]
            project = (_workspace(value.get("workspaceIdentifier"))
                       or _repo(value) or heads.get(cid))
            not_after = _stamps.iso_utc(value.get("lastUpdatedAt"), "ms")
            chats[cid] = (project, not_after)
            conversation = value.get("conversation")
            if isinstance(conversation, list):
                bubbles = [b for b in conversation if isinstance(b, dict)]
                for bubble in bubbles:
                    not_after = _later(not_after, self._bubble_stamp(bubble))
                for bubble in bubbles:
                    inline(cid, bubble, (project, not_after))
        return chats

    @staticmethod
    def _bubble_stamp(bubble):
        """A bubble's own time, any bubble's."""
        former = bubble.get("toolFormerData")
        data = (_object(former.get("additionalData"))
                if isinstance(former, dict) else {})
        return _bubble_time(bubble, data)

    def _call(self, store, cid, bubble, chat):
        """The ToolCall a bubble holds, or None (no call, or a stub)."""
        former = bubble.get("toolFormerData")
        if not isinstance(former, dict):
            return None
        name = _string(former.get("name"))
        call_id = _string(former.get("toolCallId"))
        if name is None and call_id is None:
            return None             # a stub on a user bubble
        arguments = _former_args(former)
        result = _decoded(former.get("result"))
        data = _object(former.get("additionalData"))
        kind, known, command, paths, consumed, workdir = classify(
            name or "", arguments, result)
        project, chat_after = chat if chat else (None, None)
        stamp = _bubble_time(bubble, data)
        return ToolCall(
            self.id, store.path, name or "", arguments, kind=kind,
            known=known, session=cid, project=project or workdir,
            timestamp=stamp, tool_call_id=call_id,
            status=DECLINED if declined(former, result, data, kind)
            else None,
            not_after=None if stamp else (chat_after
                                          or self._not_after(store)),
            command=command, workdir=workdir, paths=paths,
            consumed=consumed, output=_output(kind, result))

    def _editor_calls(self, store, conn):
        if not _sqlite.columns(conn, KV):
            if self._first(store):
                self.count("unknown")
            return
        tally = self._first(store)
        heads = self._heads(store, conn)
        seen = set()
        pending = []

        def inline(cid, bubble, chat):
            call = self._call(store, cid, bubble, chat)
            if call is not None:
                pending.append(call)

        chats = self._chats(store, conn, heads, tally, inline)
        held = {}
        for call in pending:
            for out in self._new(call, seen, held):
                yield out
        del pending[:]
        # Rows come in key order, so each chat's bubbles together: its
        # undated calls wait for the newest time of any of its bubbles.
        current, undated, newest = None, [], None
        for key, value, _raw in self._rows(conn, BUBBLE, tally):
            if value is _BAD:
                continue
            if not isinstance(value, dict):
                if tally:
                    self.count("unknown")
                continue
            cid, _bid = _key_parts(key, BUBBLE)
            if cid != current:
                for out in self._flush(undated, newest, seen, held):
                    yield out
                current, undated, newest = cid, [], None
            newest = _later(newest, self._bubble_stamp(value))
            chat = chats.get(cid) or (heads.get(cid), None)
            call = self._call(store, cid, value, chat)
            if call is None:
                continue
            if call.timestamp is None:
                undated.append(call)
                continue
            for out in self._new(call, seen, held):
                yield out
        for out in self._flush(undated, newest, seen, held):
            yield out
        for call_id, call in held.items():
            if call_id not in seen:
                yield call

    def _flush(self, undated, newest, seen, held):
        """One chat's undated calls, each not after the newest time of
        its chat's bubbles when that is later than what it has."""
        out = []
        for call in undated:
            call.not_after = _later(call.not_after, newest) or call.not_after
            out += self._new(call, seen, held)
        return out

    @staticmethod
    def _new(call, seen, held):
        """[call] the first time its id is met (always for none), [] after.
        A declined call, or one with no output yet, is held back until the
        end (held), and dropped if a copy of it with its output is met: a
        stale copy must not hide the one that shows what ran. Of the held
        copies, one that is not declined wins."""
        call_id = call.tool_call_id
        if call_id is None:
            return [call]
        if call_id in seen:
            return []
        if call.status == DECLINED or call.output is None:
            kept = held.get(call_id)
            if kept is None or (kept.status == DECLINED
                                and call.status != DECLINED):
                held[call_id] = call
            return []
        seen.add(call_id)
        held.pop(call_id, None)
        return [call]

    def _bubble_texts(self, store, cid, bubble, chat, where, contents):
        """A bubble's texts: the bubble with its params decoded and its
        result left out, then the result tied to its call. An edit's
        before and after file contents are noted in `contents` (content
        key -> the file edited)."""
        former = bubble.get("toolFormerData")
        if not isinstance(former, dict):
            yield SecretText(bubble, where=where)
            return
        call = self._call(store, cid, bubble, chat)
        rest = dict(former)
        for key in ("params", "rawArgs"):
            if key in rest:
                rest[key] = _decoded(rest[key])
        result = _decoded(rest.pop("result", None))
        node = dict(bubble)
        node["toolFormerData"] = rest
        yield SecretText(node, where=where)
        if result is None or result == "":
            return
        if call is not None and call.kind == "write" and call.paths \
                and isinstance(result, dict):
            for key in ("beforeContentId", "afterContentId"):
                content = _string(result.get(key))
                if content and content.startswith(CONTENT):
                    contents.setdefault(content, call.paths[0])
        yield SecretText(result, call=call, where=where + ", result")

    def _editor_texts(self, store, conn):
        if not _sqlite.columns(conn, KV):
            return
        tally = self._first(store)
        heads = self._heads(store, conn)
        contents = {}
        chats = {}
        for key, value, raw in self._rows(conn, COMPOSER, tally):
            where = "%s %s" % (KV, _shown(key))
            if value is _BAD:
                yield SecretText(_scrubbed(_text(raw)), where=where)
                continue
            value = _without_keys(value, raw)
            if not isinstance(value, dict):
                yield SecretText(value, where=where)
                continue
            cid = _string(value.get("composerId")) or key[len(COMPOSER):]
            chat = (_workspace(value.get("workspaceIdentifier"))
                    or _repo(value) or heads.get(cid),
                    _stamps.iso_utc(value.get("lastUpdatedAt"), "ms"))
            chats[cid] = chat
            conversation = value.get("conversation")
            if isinstance(conversation, list):
                rest = dict(value)
                rest.pop("conversation")
                yield SecretText(rest, where=where)
                for index, bubble in enumerate(conversation):
                    inner = "%s, conversation %d" % (where, index)
                    if isinstance(bubble, dict):
                        for text in self._bubble_texts(
                                store, cid, bubble, chat, inner, contents):
                            yield text
                    else:
                        yield SecretText(bubble, where=inner)
                continue
            yield SecretText(value, where=where)
        for key, value, raw in self._rows(conn, BUBBLE, tally):
            where = "%s %s" % (KV, _shown(key))
            if value is _BAD:
                yield SecretText(_scrubbed(_text(raw)), where=where)
                continue
            if not isinstance(value, dict):
                yield SecretText(value, where=where)
                continue
            cid, _bid = _key_parts(key, BUBBLE)
            chat = chats.get(cid) or (heads.get(cid), None)
            for text in self._bubble_texts(store, cid, value, chat, where,
                                           contents):
                yield text
        # Not tallied: tool_calls does not read these, and a count must
        # not depend on which pass ran first.
        for key, value, raw in self._rows(conn, CONTEXT, False):
            where = "%s %s" % (KV, _shown(key))
            yield SecretText(_scrubbed(_text(raw)) if value is _BAD
                             else _without_keys(value, raw), where=where)
        # A file's text as the agent read or wrote it: a real copy of
        # whatever it holds. Named after the file the edit names.
        low, high = _range(CONTENT)
        for row in _sqlite.iter_rows(conn, KV, ("key", "value"),
                                     where="key >= ? AND key < ?",
                                     params=(low, high)):
            key, text = row["key"], _text(row["value"])
            if not isinstance(key, str) or not text:
                continue
            yield SecretText(text, attached=contents.get(key),
                             where="%s %s" % (KV, _shown(key)))

    # -- the CLI ------------------------------------------------------------

    def _session(self, store, conn):
        """The chat's agentId from meta "0" (hex JSON), else the folder
        name. Nothing else of it is kept: it can hold an encryption key."""
        if not _sqlite.columns(conn, "meta"):
            return store.session
        for row in _sqlite.iter_rows(conn, "meta", ("value",),
                                     where="key = ?", params=("0",)):
            value = _text(row["value"])
            try:
                doc = json.loads(bytes.fromhex(value.strip()).decode("utf-8"))
            except (AttributeError, ValueError, RecursionError):
                return store.session
            agent = doc.get("agentId") if isinstance(doc, dict) else None
            return _string(agent) or store.session
        return store.session

    def _messages(self, store, conn, tally):
        """(index, message) for every JSON blob with a role, in rowid
        order. A protobuf tree node, or anything else that is not a JSON
        object, is passed over; a JSON object with no role is counted as
        unknown and handed to clean as (index, None, object)."""
        if not _sqlite.columns(conn, "blobs"):
            if tally:
                self.count("unknown")
            return
        for index, row in enumerate(
                _sqlite.iter_rows(conn, "blobs", ("data",)), 1):
            data = row["data"]
            if isinstance(data, bytes):
                if data[:1] != b"{":
                    continue
                try:
                    data = data.decode("utf-8")
                except UnicodeDecodeError:
                    continue
            if not isinstance(data, str) or data[:1] != "{":
                continue
            try:
                message = json.loads(data)
            except (ValueError, RecursionError):
                continue
            if not isinstance(message, dict):
                continue
            if not isinstance(message.get("role"), str):
                if tally:
                    self.count("unknown")
                yield index, None, message
                continue
            yield index, message, None

    @staticmethod
    def _blocks(message, kind):
        content = message.get("content")
        if not isinstance(content, list):
            return []
        return [b for b in content
                if isinstance(b, dict) and b.get("type") == kind]

    def _cli_call(self, store, session, name, call_id, arguments):
        arguments = base.decode_input(arguments)
        kind, known, command, paths, consumed, workdir = classify(
            name or "", arguments)
        return ToolCall(
            self.id, store.path, name or "", arguments, kind=kind,
            known=known, session=session, project=store.project or workdir,
            tool_call_id=call_id, not_after=self._not_after(store),
            command=command, workdir=workdir, paths=paths,
            consumed=consumed)

    def _calls_in(self, store, session, message):
        """The ToolCalls an assistant message asks for: AI SDK tool-call
        blocks, or OpenAI-style tool_calls."""
        out = []
        if message.get("role") != "assistant":
            return out
        for block in self._blocks(message, "tool-call"):
            args = block.get("args")
            if args is None:
                args = block.get("input")
            out.append(self._cli_call(store, session,
                                      _string(block.get("toolName")),
                                      _string(block.get("toolCallId")), args))
        calls = message.get("tool_calls")
        for item in calls if isinstance(calls, list) else ():
            fn = item.get("function") if isinstance(item, dict) else None
            if isinstance(fn, dict):
                out.append(self._cli_call(store, session,
                                          _string(fn.get("name")),
                                          _string(item.get("id")),
                                          fn.get("arguments")))
        return out

    @staticmethod
    def _result_text(result):
        """A tool-result's result as text."""
        if isinstance(result, str):
            return result
        if isinstance(result, list):
            texts = [b.get("text") for b in result if isinstance(b, dict)
                     and isinstance(b.get("text"), str)]
            return "\n".join(texts) if texts else None
        return None

    def _results_in(self, message):
        """(toolCallId, result) for each result a tool message holds."""
        if message.get("role") != "tool":
            return []
        out = [(_string(b.get("toolCallId")), b.get("result"))
               for b in self._blocks(message, "tool-result")]
        if not out and "tool_call_id" in message:
            out.append((_string(message.get("tool_call_id")),
                        message.get("content")))
        return out

    def _cli_calls(self, store, conn):
        tally = self._first(store)
        session = self._session(store, conn)
        calls, loose, results = {}, [], {}
        for _index, message, _other in self._messages(store, conn, tally):
            if message is None:
                continue
            for call in self._calls_in(store, session, message):
                if call.tool_call_id is None:
                    loose.append(call)
                elif call.tool_call_id not in calls:
                    calls[call.tool_call_id] = call
            for call_id, result in self._results_in(message):
                if call_id is not None and call_id not in results:
                    results[call_id] = self._result_text(result)
        for call_id, call in calls.items():
            call.output = results.get(call_id)
            yield call
        for call in loose:
            yield call

    def _cli_texts(self, store, conn):
        tally = self._first(store)
        session = self._session(store, conn)
        calls = {}
        for _index, message, _other in self._messages(store, conn, tally):
            if message is not None:
                for call in self._calls_in(store, session, message):
                    if call.tool_call_id and call.tool_call_id not in calls:
                        calls[call.tool_call_id] = call
        for index, message, other in self._messages(store, conn, False):
            where = "blob %d" % index
            if message is None:
                yield SecretText(other, where=where)
                continue
            content = message.get("content")
            if message.get("role") == "tool" and isinstance(content, list):
                kept = []
                for block in content:
                    if (isinstance(block, dict)
                            and block.get("type") == "tool-result"
                            and "result" in block):
                        call = calls.get(_string(block.get("toolCallId")))
                        yield SecretText(block["result"], call=call,
                                         where=where + ", result")
                        block = {k: v for k, v in block.items()
                                 if k != "result"}
                    kept.append(block)
                message = dict(message, content=kept)
            elif message.get("role") == "tool" and "tool_call_id" in message:
                call = calls.get(_string(message.get("tool_call_id")))
                yield SecretText(content, call=call, where=where + ", result")
                message = {k: v for k, v in message.items() if k != "content"}
            elif isinstance(content, list):
                # An image's bytes, as hex, hold no text.
                message = dict(message, content=[
                    dict(b, image={k: v for k, v in b["image"].items()
                                   if k != "hex"})
                    if isinstance(b, dict) and isinstance(b.get("image"), dict)
                    else b for b in content])
            yield SecretText(message, where=where)
