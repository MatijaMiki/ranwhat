"""The Goose adapter (ranwhat/sources/goose.py), checked against v1.53.0.

Fixtures are built field for field from Goose's own writer: sessions.db
made with create_schema's DDL (session_manager.rs, schema version 16), in
WAL mode as Goose opens it, rows inserted as add_message inserts them
(content_json the compact serde_json array of content blocks), and a
v1.10.0 database with the columns it had then. Legacy files are written as
v1.9.3's storage.rs wrote them: the metadata object, then one Message per
line.

Everything runs in temp directories, the home directory and
GOOSE_PATH_ROOT among them, and the real home is never read. Every secret
is synthetic, and token-shaped ones are written as adjacent literals.
"""
import contextlib
import glob
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import clean, watch  # noqa: E402
from ranwhat.sources import _paths, _sqlite  # noqa: E402
from ranwhat.sources import goose as goose_module  # noqa: E402
from ranwhat.sources.base import MaskResult, ToolCall  # noqa: E402
from ranwhat.sources.goose import GooseSource  # noqa: E402

ENV = "GOOSE_PATH_ROOT"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
SECRET2 = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"
EXT_KEY = "sk_" "live_" "Xc4Vb6Nm8Qw2Er4Ty6Ui8Op"     # an extension's env
PW = "Vb6nM3qW" "z8Kt2Lp5Rx"

T0 = 1759257600                 # 2025-09-30T18:40:00Z
ISO0 = "2025-09-30T18:40:00Z"
SID = "20250930_1"
CWD = "/home/dev/app"

DECLINED_TEXT = ("The user has declined to run this tool. DO NOT attempt to "
                 "call this tool again. If there are no alternative methods "
                 "to proceed, clearly explain the situation and STOP.")
# CHAT_MODE_TOOL_SKIPPED_RESPONSE as Rust's line continuations make it
# (tool_execution.rs:139-146); v1.9.3 wrote "Goose chat mode".
SKIPPED_TEXT = ("Let the user know the tool call was skipped in goose chat "
                "mode. DO NOT apologize for skipping the tool call. DO NOT "
                "say sorry. Provide an explanation of what the tool call "
                "would do, structured as a plan for the user. Again, DO NOT "
                "apologize. **Example Plan:**\n 1. **Identify Task Scope** - "
                "Determine the purpose and expected outcome.\n 2. **Outline "
                "Steps** - Break down the steps.\n If needed, adjust the "
                "explanation based on user preferences or questions.")

# create_schema, v1.53.0 session_manager.rs:1010-1130, verbatim.
SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    user_set_name BOOLEAN DEFAULT FALSE,
    session_type TEXT NOT NULL DEFAULT 'user',
    working_dir TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    extension_data TEXT DEFAULT '{}',
    total_tokens INTEGER,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_write_tokens INTEGER,
    accumulated_total_tokens INTEGER,
    accumulated_input_tokens INTEGER,
    accumulated_output_tokens INTEGER,
    accumulated_cache_read_tokens INTEGER,
    accumulated_cache_write_tokens INTEGER,
    accumulated_cost REAL,
    schedule_id TEXT,
    recipe_json TEXT,
    user_recipe_values_json TEXT,
    provider_name TEXT,
    model_config_json TEXT,
    goose_mode TEXT NOT NULL DEFAULT 'auto',
    archived_at TIMESTAMP,
    project_id TEXT,
    parent_session_id TEXT
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    role TEXT NOT NULL,
    content_json TEXT NOT NULL,
    created_timestamp INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tokens INTEGER,
    metadata_json TEXT
);
CREATE TABLE IF NOT EXISTS usage_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_timestamp INTEGER NOT NULL,
    model TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    total_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_write_tokens INTEGER,
    cost REAL,
    cost_source TEXT,
    is_compaction INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages(message_id);
CREATE INDEX IF NOT EXISTS idx_messages_session_created ON messages(session_id, created_timestamp, id);
CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_type ON sessions(session_type);
CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_session_id);
CREATE INDEX IF NOT EXISTS idx_usage_ledger_session ON usage_ledger(session_id);
"""

# v1.10.0's first schema (CURRENT_SCHEMA_VERSION = 2): no name, no
# message_id, no metadata_json.
SCHEMA_1_10 = """
CREATE TABLE schema_version (version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    working_dir TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    extension_data TEXT DEFAULT '{}',
    total_tokens INTEGER, input_tokens INTEGER, output_tokens INTEGER,
    accumulated_total_tokens INTEGER, accumulated_input_tokens INTEGER,
    accumulated_output_tokens INTEGER,
    schedule_id TEXT, recipe_json TEXT, user_recipe_values_json TEXT
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    role TEXT NOT NULL,
    content_json TEXT NOT NULL,
    created_timestamp INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tokens INTEGER
);
"""

# Migration 10's tables (session_manager.rs:1440-1495).
THREADS = """
CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT 'New Chat',
    user_set_name BOOLEAN DEFAULT FALSE, working_dir TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    archived_at TIMESTAMP, metadata_json TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS thread_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id TEXT NOT NULL REFERENCES threads(id),
    session_id TEXT, message_id TEXT, role TEXT NOT NULL,
    content_json TEXT NOT NULL, created_timestamp INTEGER NOT NULL,
    metadata_json TEXT DEFAULT '{}');
"""

META = '{"userVisible":true,"agentVisible":true}'

# An extension as enabled_extensions.v0 keeps it (agents/extension.rs).
EXTENSION_DATA = json.dumps({"enabled_extensions.v0": {"extensions": [
    {"type": "stdio", "name": "stripe", "cmd": "npx",
     "args": ["-y", "@stripe/mcp"], "envs": {"STRIPE_SECRET_KEY": EXT_KEY},
     "env_keys": [], "timeout": 300, "bundled": None}]}},
    separators=(",", ":"))


def _dump(obj):
    """serde_json's compact form."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# -- content blocks, as serde writes them (message.rs) ----------------------

def text(t):
    return {"type": "text", "text": t}


def request(cid, name, arguments):
    return {"type": "toolRequest", "id": cid,
            "toolCall": {"status": "success",
                         "value": {"name": name, "arguments": arguments}}}


def response(cid, out, is_error=False):
    """A current toolResponse: value is a CallToolResult."""
    return {"type": "toolResponse", "id": cid,
            "toolResult": {"status": "success", "value": {
                "resultType": "complete",
                "content": [{"type": "text", "text": out,
                             "annotations": {"priority": 0.0}}],
                "isError": is_error}}}


def legacy_response(cid, out):
    """Before ~v1.10: value is a bare array of content blocks."""
    return {"type": "toolResponse", "id": cid,
            "toolResult": {"status": "success", "value": [
                {"type": "text", "text": out,
                 "annotations": {"audience": ["assistant"], "priority": 0.0}}]}}


def error_response(cid, message):
    return {"type": "toolResponse", "id": cid,
            "toolResult": {"status": "error", "error": "-32603: " + message}}


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _files(path):
    """{suffix: bytes} for the database, its -wal and its -shm."""
    out = {}
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            with open(path + suffix, "rb") as fh:
                out[suffix] = fh.read()
    return out


def _ranwhat_temp_dirs():
    """The copies _sqlite makes (mkdtemp's prefix "ranwhat-" and eight
    characters), not other tests' ranwhat-home-* or ranwhat-account-*."""
    return set(x for x in os.listdir(tempfile.gettempdir())
               if re.match(r"ranwhat-[a-z0-9_]{8}\Z", x))


def rules(call):
    return [h["rule"] for h in watch.judge(call)[0]]


class GooseCase(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="goose-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        patches = [mock.patch.dict(os.environ, {
                       "HOME": self.home, "USERPROFILE": self.home,
                       "APPDATA": os.path.join(self.home, "AppData", "Roaming")}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for name in (ENV, "XDG_DATA_HOME"):
            os.environ.pop(name, None)
        self.backups = os.path.join(self.home, "backups")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        # Where Goose keeps its data on this platform: the first default
        # (on Windows %APPDATA%\\Block\\goose\\data, not ~/.local/share).
        self.data = GooseSource().default_paths(
            os.environ, self.home, _paths.platform_name())[0][0]
        self.folder = os.path.join(self.data, "sessions")
        self.db_path = os.path.join(self.folder, "sessions.db")
        self.src = GooseSource()
        self.temp_before = _ranwhat_temp_dirs()

    def tearDown(self):
        self.assertEqual(_ranwhat_temp_dirs() - self.temp_before, set(),
                         "a ranwhat-* temp directory was left behind")

    # -- fixtures -----------------------------------------------------------

    def database(self, sessions=(), messages=(), schema=SCHEMA, wal=True,
                 path=None):
        """sessions.db with `sessions` ((id, working_dir, name,
        extension_data)) and `messages` ((session, role, blocks, created)),
        inserted as add_message inserts them. Closed: Goose's SQLite then
        checkpoints and removes the -wal and -shm."""
        path = path or self.db_path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        if wal:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(schema)
        self.fill(conn, sessions, messages, schema)
        conn.close()
        return path

    @staticmethod
    def fill(conn, sessions=(), messages=(), schema=SCHEMA):
        for sid, cwd, name, ext in sessions:
            if schema is SCHEMA:
                conn.execute("INSERT INTO sessions (id, name, description, "
                             "working_dir, extension_data) VALUES "
                             "(?, ?, ?, ?, ?)", (sid, name, "", cwd, ext))
            else:
                conn.execute("INSERT INTO sessions (id, description, "
                             "working_dir, extension_data) VALUES "
                             "(?, ?, ?, ?)", (sid, name, cwd, ext))
        for sid, role, blocks, created in messages:
            content = blocks if isinstance(blocks, str) else _dump(blocks)
            if schema is SCHEMA:
                conn.execute("INSERT INTO messages (message_id, session_id, "
                             "role, content_json, created_timestamp, "
                             "metadata_json) VALUES (?, ?, ?, ?, ?, ?)",
                             ("msg_%s_x" % sid, sid, role, content, created,
                              META))
            else:
                conn.execute("INSERT INTO messages (session_id, role, "
                             "content_json, created_timestamp) VALUES "
                             "(?, ?, ?, ?)", (sid, role, content, created))
        conn.commit()

    def legacy(self, name, lines, header=None, age=3600, raw=None):
        """sessions/<name>.jsonl as v1.9.3 wrote it."""
        path = os.path.join(self.folder, name + ".jsonl")
        os.makedirs(self.folder, exist_ok=True)
        if raw is None:
            head = header if header is not None else {
                "working_dir": CWD, "description": "fix the build",
                "schedule_id": None, "message_count": len(lines),
                "total_tokens": None, "input_tokens": None,
                "output_tokens": None, "accumulated_total_tokens": None,
                "accumulated_input_tokens": None,
                "accumulated_output_tokens": None,
                "extension_data": json.loads(EXTENSION_DATA),
                "recipe": None}
            raw = "".join(_dump(x) + "\n" for x in [head] + list(lines))
            raw = raw.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def stores(self, override=None, since_days=None):
        return self.src.stores(self.src.locations(override=override),
                               since_days=since_days)

    def store(self, path):
        for store in self.stores():
            if store.path == path:
                return store
        self.fail("%s is not a store" % path)

    def calls(self, path):
        return list(self.src.tool_calls(self.store(path)))

    def by_id(self, path):
        return {c.tool_call_id: c for c in self.calls(path)}

    def texts(self, path):
        return list(self.src.secret_texts(self.store(path)))

    def found(self, path):
        """{value: origins} as clean finds them in the store."""
        values = {}
        findings, _masks = clean.scan_store(self.src, self.store(path), values)
        return {values[fp]: f["origins"] for fp, f in findings.items()}


def _one(cid, name, arguments, out=None, created=T0, sid=SID, resp=None):
    """A request message and its response message."""
    rows = [(sid, "assistant", [text("ok"), request(cid, name, arguments)],
             created)]
    if resp is not None or out is not None:
        rows.append((sid, "user", [resp or response(cid, out)], created + 1))
    return rows


# --------------------------------------------------------------------------
# Where Goose keeps its sessions
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = GooseSource()

    def test_each_platform(self):
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.local/share/goose", "default")])
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"), [
            ("/Users/u/.local/share/goose", "default"),
            ("/Users/u/Library/Application Support/Block/goose", "probed")])
        self.assertEqual(
            self.src.default_paths({}, "C:\\Users\\u", "win32"),
            [("C:\\Users\\u\\AppData\\Roaming\\Block\\goose\\data", "default")])
        self.assertEqual(
            self.src.default_paths({"APPDATA": "D:\\Roam"}, "C:\\Users\\u",
                                   "win32"),
            [("D:\\Roam\\Block\\goose\\data", "default")])

    def test_xdg_data_home_only_when_absolute(self):
        env = {"XDG_DATA_HOME": "/xdg"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/xdg/goose", "default")])
        self.assertEqual(self.src.default_paths(env, "/Users/u", "darwin")[0],
                         ("/xdg/goose", "default"))
        env = {"XDG_DATA_HOME": "rel/xdg"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/home/u/.local/share/goose", "default")])

    def test_goose_path_root_when_absolute(self):
        self.assertEqual(
            self.src.default_paths({ENV: "/srv/g"}, "/home/u", "linux"),
            [("/srv/g/data", "env " + ENV)])
        self.assertEqual(
            self.src.default_paths({ENV: "/srv/g"}, "/Users/u", "darwin"),
            [("/srv/g/data", "env " + ENV)])
        self.assertEqual(
            self.src.default_paths({ENV: "E:\\goose"}, "C:\\Users\\u",
                                   "win32"),
            [("E:\\goose\\data", "env " + ENV)])

    def test_a_relative_or_empty_goose_path_root_is_ignored(self):
        for value in ("rel/g", "", "~/g"):
            with self.subTest(value=value):
                self.assertEqual(
                    self.src.default_paths({ENV: value}, "/home/u", "linux"),
                    [("/home/u/.local/share/goose", "default")])

    def test_what_every_report_needs(self):
        src = self.src
        self.assertEqual((src.id, src.name, src.unit, src.env, src.checked),
                         ("goose", "Goose", "file", (ENV,), "1.53.0"))
        self.assertEqual(src.path_means,
                         "a Goose data folder (the one holding sessions/)")
        self.assertFalse(src.read_only)


class Discovery(GooseCase):

    def test_the_variable_is_read_at_call_time(self):
        root = os.path.join(self.home, "groot")
        os.environ[ENV] = root
        path = self.database(path=os.path.join(root, "data", "sessions",
                                               "sessions.db"))
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.found),
                         (os.path.join(root, "data"), "env " + ENV, 1))
        self.assertEqual([s.path for s in self.stores()], [path])

    def test_stores_found_newest_first_and_nothing_else(self):
        db = self.database()
        old = self.legacy("20240101_120000", [], age=7200)
        new = self.legacy("named", [], age=60)
        for name in ("x.jsonl.backup", "x.jsonl.tmp", ".hidden.jsonl",
                     "notes.txt", "sessions.db-journal"):
            with open(os.path.join(self.folder, name), "w", encoding="utf-8") as fh:
                fh.write("{}\n")
        os.makedirs(os.path.join(self.folder, "dir.jsonl"))
        os.utime(db, (time.time(), time.time()))
        self.assertEqual([s.path for s in self.stores()], [db, new, old])

    def test_what_each_store_is(self):
        db = self.database()
        path = self.legacy("20240101_120000", [])
        stores = {s.path: s for s in self.stores()}
        self.assertEqual(
            (stores[db].format, stores[db].role, stores[db].unit,
             stores[db].masking, stores[db].why_read_only),
            ("sqlite", "transcript", "database", "read-only",
             goose_module.WHY_READ_ONLY))
        self.assertEqual(goose_module.WHY_READ_ONLY,
                         "Goose keeps this in a database; delete the session "
                         "in Goose.")
        self.assertEqual(
            (stores[path].format, stores[path].role, stores[path].unit,
             stores[path].masking, stores[path].session, stores[path].project),
            ("jsonl", "transcript", "session", "rewrite", "20240101_120000",
             CWD))

    def test_a_missing_root_is_zero_stores(self):
        locations = self.src.locations()
        self.assertTrue(locations)      # macOS probes a second folder
        self.assertEqual({(loc.exists, loc.found) for loc in locations},
                         {(False, 0)})
        self.assertEqual(self.stores(), [])

    def test_path_may_name_the_data_or_the_sessions_folder(self):
        db = self.database()
        for where in (self.data, self.folder):
            with self.subTest(where=where):
                self.assertEqual([s.path for s in self.stores(override=where)],
                                 [db])

    def test_the_database_is_kept_whatever_its_age(self):
        db = self.database()
        old = time.time() - 90 * 86400
        os.utime(db, (old, old))
        self.legacy("ancient", [], age=90 * 86400)
        self.assertEqual([s.path for s in self.stores(since_days=7)], [db])

    @unittest.skipIf(os.name == "nt", "symlinks")
    def test_a_symlink_loop_is_not_a_store(self):
        db = self.database()
        os.symlink("loop.jsonl", os.path.join(self.folder, "loop.jsonl"))
        os.symlink(self.folder, os.path.join(self.folder, "self.jsonl"))
        self.assertEqual([s.path for s in self.stores()], [db])

    def test_a_sessions_db_that_is_a_folder_is_not_a_store(self):
        os.makedirs(self.db_path)
        self.assertEqual(self.stores(), [])


# --------------------------------------------------------------------------
# Tool calls
# --------------------------------------------------------------------------

class ToolCalls(GooseCase):

    def test_the_spec_shell_sample(self):
        db = self.database([(SID, CWD, "Check git status", "{}")], [
            (SID, "assistant", [
                text("Let me check the repo."),
                dict(request("toolu_01AbC", "shell", {
                    "command": "git status && cat ~/.aws/credentials"}),
                    _meta={"goose.toolSummary.title": "Check git status"})],
             T0),
            (SID, "user", [{"type": "toolResponse", "id": "toolu_01AbC",
                            "toolResult": {"status": "success", "value": {
                                "resultType": "complete",
                                "content": [{"type": "text",
                                             "text": "On branch main\n",
                                             "annotations": {"priority": 0.0}}],
                                "structuredContent": {
                                    "stdout": "On branch main\n",
                                    "stderr": "", "exit_code": 0},
                                "isError": False}}}], T0 + 1)])
        [call] = self.calls(db)
        self.assertIsInstance(call, ToolCall)
        self.assertEqual(
            (call.source, call.store, call.tool_name, call.kind, call.known,
             call.command, call.consumed, call.session, call.project,
             call.timestamp, call.tool_call_id, call.output, call.status,
             call.actor, call.not_after),
            ("goose", db, "shell", "shell", True,
             "git status && cat ~/.aws/credentials", frozenset(["command"]),
             SID, CWD, ISO0, "toolu_01AbC", "On branch main\n", None,
             "agent", None))
        self.assertIn("cred.read", rules(call))

    def test_every_mapped_tool(self):
        cases = [
            ("shell", {"command": "ls"}, "shell", True, "ls", ()),
            ("developer__shell", {"command": "ls"}, "shell", True, "ls", ()),
            ("execute_bash", {"command": "ls"}, "shell", True, "ls", ()),
            ("write", {"path": "src/config.py", "content": "x"}, "write",
             True, None, ("src/config.py",)),
            ("edit", {"path": "src/a.rs", "before": "a", "after": "b"},
             "write", True, None, ("src/a.rs",)),
            ("developer__text_editor", {"command": "view", "path": "/p/.env",
                                        "view_range": [1, 40]},
             "read", True, None, ("/p/.env",)),
            ("developer__text_editor", {"command": "write", "path": "/p/a",
                                        "file_text": "x"},
             "write", True, None, ("/p/a",)),
            ("developer__text_editor", {"command": "str_replace",
                                        "path": "/p/a", "old_str": "a",
                                        "new_str": "b"},
             "write", True, None, ("/p/a",)),
            ("developer__text_editor", {"command": "insert", "path": "/p/a",
                                        "insert_line": 1, "new_str": "b"},
             "write", True, None, ("/p/a",)),
            ("developer__text_editor", {"command": "undo_edit",
                                        "path": "/p/a"},
             "write", True, None, ("/p/a",)),
            ("developer__text_editor", {"command": "frob", "path": "/p/a"},
             "other", True, None, ()),
            ("read_image", {"path": "shot.png"}, "read", True, None,
             ("shot.png",)),
            ("developer__image_processor", {"path": "/p/x.png"}, "read",
             True, None, ("/p/x.png",)),
            ("read_image", {"path": "https://example.com/x.png"}, "fetch",
             True, None, ()),
            ("tree", {"path": ".", "depth": 2}, "other", True, None, ()),
            ("github__create_issue", {"title": "t"}, "other", False, None,
             ()),
            ("myserver__shell", {"command": "ls"}, "other", False, None, ()),
            ("todo__write", {"path": "x"}, "other", False, None, ()),
        ]
        rows = []
        for i, (name, args, *_rest) in enumerate(cases):
            rows += _one("c%d" % i, name, args, out="done", created=T0 + 2 * i)
        db = self.database([(SID, CWD, "", "{}")], rows)
        got = self.by_id(db)
        for i, (name, args, kind, known, command, paths) in enumerate(cases):
            with self.subTest(name=name, args=args):
                call = got["c%d" % i]
                self.assertEqual(
                    (call.tool_name, call.kind, call.known, call.command,
                     call.paths, call.tool_input, call.output),
                    (name, kind, known, command, paths, args, "done"))

    def test_an_unknown_tool_is_judged_by_its_name(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("c1", "myserver__shell",
                                {"command": "rm -rf ~/Documents/x"}))
        [call] = self.calls(db)
        self.assertFalse(call.known)
        self.assertIn("fs.destructive", rules(call))

    def test_outputs_in_every_stored_shape(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("a", "shell", {"command": "x"}, out="new")
                           + _one("b", "shell", {"command": "y"},
                                  resp=legacy_response("b", "old"))
                           + _one("c", "shell", {"command": "z"},
                                  resp=error_response("c", "boom"))
                           + _one("d", "shell", {"command": "w"}))
        got = self.by_id(db)
        self.assertEqual({k: (c.output, c.status) for k, c in got.items()},
                         {"a": ("new", None), "b": ("old", None),
                          "c": ("-32603: boom", None), "d": (None, None)})

    def test_a_resource_block_is_output_too(self):
        resp = {"type": "toolResponse", "id": "r", "toolResult": {
            "status": "success", "value": {"content": [
                {"type": "text", "text": "head"},
                {"type": "resource", "resource": {"uri": "file:///p/.env",
                                                  "text": "KEY=v"}},
                {"type": "image", "data": "AAAA", "mimeType": "image/png"}]}}}
        db = self.database([(SID, CWD, "", "{}")],
                           _one("r", "shell", {"command": "x"}, resp=resp))
        [call] = self.calls(db)
        self.assertEqual(call.output, "head\nKEY=v")

    def test_declined_and_skipped_calls(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("d", "shell", {"command": "rm -rf ~/Documents/x"},
                                resp=response("d", DECLINED_TEXT, True))
                           + _one("s", "shell", {"command": "ls"},
                                  resp=response("s", SKIPPED_TEXT))
                           + _one("l", "developer__shell", {"command": "ls"},
                                  resp=legacy_response("l", DECLINED_TEXT))
                           + _one("ran", "shell", {"command": "echo The user "
                                                   "has declined to run this "
                                                   "tool"},
                                  out="x\nThe user has declined to run this "
                                      "tool"))
        got = self.by_id(db)
        self.assertEqual({k: c.status for k, c in got.items()},
                         {"d": "declined", "s": "declined", "l": "declined",
                          "ran": None})
        # still judged: the report says it did not run
        self.assertIn("fs.destructive", rules(got["d"]))

    def test_a_command_whose_output_is_the_declined_text_ran(self):
        # Only Goose's whole text, alone, as Goose writes it: an error
        # result with no structuredContent (every shell result has one).
        cmd = ("echo 'The user has declined to run this tool'; "
               "cat ~/.ssh/id_rsa; false")
        shell = response("e", "The user has declined to run this tool\n"
                         "-----BEGIN\n\nCommand exited with code 1", True)
        shell["toolResult"]["value"]["structuredContent"] = {
            "stdout": "x", "stderr": "", "exit_code": 1}
        exact = response("x", DECLINED_TEXT, True)
        exact["toolResult"]["value"]["structuredContent"] = {
            "stdout": DECLINED_TEXT, "stderr": "", "exit_code": None}
        db = self.database([(SID, CWD, "", "{}")],
                           _one("e", "shell", {"command": cmd}, resp=shell)
                           + _one("x", "shell", {"command": "x"}, resp=exact)
                           + _one("ok", "shell", {"command": "y"},
                                  resp=response("ok", DECLINED_TEXT, False))
                           + _one("two", "developer__shell", {"command": "z"},
                                  resp=legacy_response("two", DECLINED_TEXT
                                                       + " and more")))
        got = self.by_id(db)
        self.assertEqual({k: c.status for k, c in got.items()},
                         {"e": None, "x": None, "ok": None, "two": None})

    def test_the_chat_mode_text_of_version_1_9(self):
        path = self.legacy("20240101_120000", [
            {"role": "assistant", "created": T0, "content": [
                request("k", "developer__shell", {"command": "rm -rf ~/x"})]},
            {"role": "user", "created": T0 + 1, "content": [legacy_response(
                "k", SKIPPED_TEXT.replace("goose chat", "Goose chat"))]}])
        self.assertEqual([c.status for c in self.calls(path)], ["declined"])

    def test_timestamps_seconds_and_milliseconds(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("s", "shell", {"command": "a"}, created=T0)
                           + _one("ms", "shell", {"command": "b"},
                                  created=T0 * 1000 + 500)
                           + _one("bad", "shell", {"command": "c"},
                                  created=0))
        got = self.by_id(db)
        self.assertEqual(got["s"].timestamp, ISO0)
        self.assertEqual(got["ms"].timestamp, ISO0)
        self.assertIsNone(got["bad"].timestamp)
        self.assertIsNotNone(got["bad"].not_after)

    def test_stamp(self):
        self.assertEqual(goose_module.stamp(T0), ISO0)
        self.assertEqual(goose_module.stamp(str(T0)), ISO0)
        self.assertEqual(goose_module.stamp(T0 * 1000), ISO0)
        for bad in (None, True, "x", [], {}, float("nan"), 10 ** 400 // 10 ** 380):
            self.assertIsNone(goose_module.stamp(bad))

    def test_dedupe_and_sessions(self):
        rows = (_one("c1", "shell", {"command": "a"}, out="first")
                + [(SID, "assistant", [request("c1", "shell",
                                              {"command": "again"})], T0 + 5),
                   (SID, "user", [response("c1", "second")], T0 + 6)]
                + _one("c1", "shell", {"command": "other"}, out="other",
                       sid="20250930_2", created=T0 + 10))
        db = self.database([(SID, CWD, "", "{}"),
                            ("20250930_2", "/srv/other", "", "{}")], rows)
        calls = self.calls(db)
        self.assertEqual(
            [(c.session, c.project, c.command, c.output) for c in calls],
            [(SID, CWD, "a", "first"),
             ("20250930_2", "/srv/other", "other", "other")])

    def test_ties_in_one_second_keep_insertion_order(self):
        rows = [(SID, "assistant", [request("c", "shell", {"command": "a"})],
                 T0),
                (SID, "user", [response("c", "out")], T0)]
        db = self.database([(SID, CWD, "", "{}")], rows)
        [call] = self.calls(db)
        self.assertEqual(call.output, "out")

    def test_a_call_whose_arguments_did_not_parse_never_ran(self):
        bad = {"type": "toolRequest", "id": "e",
               "toolCall": {"status": "error", "error": "-32602: bad json"}}
        db = self.database([(SID, CWD, "", "{}")], [
            (SID, "assistant", [bad], T0),
            (SID, "user", [error_response("e", "bad json")], T0 + 1)])
        self.assertEqual(self.calls(db), [])

    def test_a_frontend_tool_request_and_legacy_any_arguments(self):
        rows = [(SID, "assistant", [
            {"type": "frontendToolRequest", "id": "f", "toolCall": {
                "status": "success", "value": {"name": "shell",
                                               "arguments": {"command": "ls"}}}},
            {"type": "toolRequest", "id": "s", "toolCall": {
                "status": "success", "value": {"name": "x__y",
                                               "arguments": "raw text"}}}],
            T0)]
        db = self.database([(SID, CWD, "", "{}")], rows)
        got = self.by_id(db)
        self.assertEqual(got["f"].command, "ls")
        self.assertEqual(got["s"].tool_input, {"_raw": "raw text"})

    def test_a_version_1_10_database(self):
        db = self.database([(SID, CWD, "old title", "{}")],
                           _one("c", "developer__shell",
                                {"command": "cat .env"}, out="KEY=" + SECRET),
                           schema=SCHEMA_1_10, wal=False)
        [call] = self.calls(db)
        self.assertEqual((call.command, call.project, call.output),
                         ("cat .env", CWD, "KEY=" + SECRET))
        self.assertEqual(self.found(db), {SECRET: {".env"}})

    def test_thread_messages_are_read_and_not_counted_twice(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("c", "shell", {"command": "a"}, out="x"))
        conn = sqlite3.connect(db)
        conn.executescript(THREADS)
        conn.execute("INSERT INTO threads (id, working_dir) VALUES ('t1', '/t')")
        for sid, role, blocks, created in (
                _one("c", "shell", {"command": "a"}, out="x")
                + _one("t", "shell", {"command": "b"}, out="y",
                       created=T0 + 9)):
            conn.execute("INSERT INTO thread_messages (thread_id, session_id, "
                         "role, content_json, created_timestamp) VALUES "
                         "('t1', ?, ?, ?, ?)", (sid, role, _dump(blocks),
                                                created))
        conn.commit()
        conn.close()
        self.assertEqual([(c.tool_call_id, c.command) for c in self.calls(db)],
                         [("c", "a"), ("t", "b")])

    def test_a_thread_message_with_no_session_is_its_threads(self):
        db = self.database([(SID, CWD, "", "{}")])
        conn = sqlite3.connect(db)
        conn.executescript(THREADS)
        for _sid, role, blocks, created in _one("t", "shell", {"command": "b"},
                                                out="y"):
            conn.execute("INSERT INTO thread_messages (thread_id, role, "
                         "content_json, created_timestamp) VALUES "
                         "('t1', ?, ?, ?)", (role, _dump(blocks), created))
        conn.commit()
        conn.close()
        [call] = self.calls(db)
        self.assertEqual((call.session, call.project, call.output),
                         ("t1", None, "y"))

    def test_messages_of_a_session_not_in_sessions(self):
        db = self.database([], _one("c", "shell", {"command": "a"}))
        [call] = self.calls(db)
        self.assertEqual((call.session, call.project), (SID, None))


class Legacy(GooseCase):

    LINES = [
        {"id": "msg1", "role": "user", "created": T0,
         "content": [text("Hello")]},
        {"id": "msg2", "role": "assistant", "created": T0 + 1,
         "content": [request("call_9", "developer__text_editor",
                             {"command": "view", "path": "~/.ssh/id_rsa"}),
                     request("call_10", "developer__shell",
                             {"command": "cat .env"})]},
        {"role": "user", "created": T0 + 2,
         "content": [legacy_response("call_9", "-----BEGIN"),
                     legacy_response("call_10", "STRIPE=" + SECRET)]},
    ]

    def test_calls_of_a_legacy_file(self):
        path = self.legacy("20240101_120000", self.LINES)
        got = self.by_id(path)
        self.assertEqual(
            (got["call_9"].kind, got["call_9"].paths, got["call_9"].output,
             got["call_9"].session, got["call_9"].project,
             got["call_9"].timestamp),
            ("read", ("~/.ssh/id_rsa",), "-----BEGIN", "20240101_120000",
             CWD, "2025-09-30T18:40:01Z"))
        self.assertIn("cred.read", rules(got["call_9"]))
        self.assertEqual(got["call_10"].output, "STRIPE=" + SECRET)

    def test_the_spec_sample(self):
        path = self.legacy("20240101_120000", [
            {"id": "msg1", "role": "user", "created": 1704110400,
             "content": [{"type": "text", "text": "Hello"}]},
            {"id": "msg2", "role": "assistant", "created": 1704110401,
             "content": [{"type": "text", "text": "Hi there"}]}],
            header={"description": "test", "id": "20240101_120000",
                    "created_at": "2024-01-01T12:00:00Z",
                    "updated_at": "2024-01-01T12:00:00Z",
                    "extension_data": {}, "message_count": 0,
                    "working_dir": "/home/me/proj"})
        self.assertEqual(self.store(path).project, "/home/me/proj")
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_an_imported_file_is_searched_but_its_calls_are_not_read_twice(self):
        path = self.legacy("20240101_120000", self.LINES)
        db = self.database([("20240101_120000", CWD, "", "{}")],
                           _one("call_10", "developer__shell",
                                {"command": "cat .env"},
                                out="STRIPE=" + SECRET,
                                sid="20240101_120000"))
        # call_10 is read from the database; call_9, which the database
        # does not hold, from the file
        self.assertEqual([c.tool_call_id for c in self.calls(path)],
                         ["call_9"])
        self.assertEqual(len(self.calls(db)), 1)
        self.assertEqual(self.found(path), {SECRET: {".env"}})

    def test_a_call_the_import_dropped_is_read_from_the_file(self):
        # Goose 1.50 and later importing a 1.9 file drop every message that
        # no longer parses (frontendToolRequest was removed), with any
        # toolRequest beside it; the database holds the session all the
        # same.
        sid = "20240101_120000"
        path = self.legacy(sid, [
            {"role": "assistant", "created": T0, "content": [
                request("c_aws", "developer__shell",
                        {"command": "cat ~/.aws/credentials"}),
                {"type": "frontendToolRequest", "id": "c_fe",
                 "toolCall": {"status": "success",
                              "value": {"name": "fe__click",
                                        "arguments": {}}}}]},
            {"role": "user", "created": T0 + 1,
             "content": [legacy_response("c_aws", "[default]")]},
            {"role": "assistant", "created": T0 + 2,
             "content": [request("c_ls", "developer__shell",
                                 {"command": "ls"})]}])
        db = self.database([(sid, CWD, "", "{}")],
                           _one("c_ls", "developer__shell", {"command": "ls"},
                                sid=sid))
        self.assertEqual([c.tool_call_id for c in self.calls(db)], ["c_ls"])
        got = self.by_id(path)
        self.assertEqual(sorted(got), ["c_aws", "c_fe"])
        self.assertEqual(got["c_aws"].command, "cat ~/.aws/credentials")
        self.assertIn("cred.read", rules(got["c_aws"]))

    def test_a_file_not_imported_is_read_beside_a_database(self):
        path = self.legacy("too_big_to_import", self.LINES)
        self.database([(SID, CWD, "", "{}")])
        self.assertEqual(len(self.calls(path)), 2)

    def test_its_configuration_line_is_not_searched(self):
        path = self.legacy("20240101_120000", self.LINES)
        found = self.found(path)
        self.assertNotIn(EXT_KEY, found)
        self.assertEqual(found, {SECRET: {".env"}})
        head = [t for t in self.texts(path) if t.where == "line 1"]
        self.assertEqual(len(head), 1)
        self.assertNotIn("extension_data", head[0].node)
        self.assertEqual(head[0].node["working_dir"], CWD)

    def test_masking_round_trips(self):
        path = self.legacy("20240101_120000", self.LINES, age=3600)
        with open(path, "rb") as fh:
            original = fh.read()
        result = self.src.mask(self.store(path), [SECRET])
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        marker = clean.REDACTION % clean._fingerprint(SECRET)
        with open(path, "rb") as fh:
            after = fh.read()
        self.assertEqual(after, original.replace(SECRET.encode(),
                                                 marker.encode()))
        for line in after.decode("utf-8").splitlines():
            json.loads(line)
        self.assertEqual(self.by_id(path)["call_10"].output,
                         "STRIPE=" + marker)
        self.assertEqual(self.found(path), {})
        self.assertEqual(glob.glob(os.path.join(self.folder, "*.ranwhat-tmp")),
                         [])

    def test_a_file_written_just_now_is_not_masked(self):
        path = self.legacy("20240101_120000", self.LINES, age=5)
        digest = _sha(path)
        self.assertEqual(self.src.mask(self.store(path), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)

    def test_garbage_lines(self):
        raw = (_dump({"working_dir": CWD}) + "\n"
               + "not json " + SECRET2 + "\n"
               + _dump(["a list"]) + "\n"
               + _dump({"role": "robot", "created": T0, "content": [
                   {"type": "mystery"}, "str",
                   request("c", "shell", {"command": "ls"})]}) + "\n"
               + '{"role": "user", "cont').encode("utf-8")
        path = self.legacy("g", [], raw=raw)
        self.assertEqual([c.command for c in self.calls(path)], ["ls"])
        self.assertEqual((self.src.counts["unparsed"],
                          self.src.counts["unknown"]), (1, 4))
        self.assertIn(SECRET2, self.found(path))
        # counted once a run, whichever pass met it first
        list(self.src.tool_calls(self.store(path)))
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_a_file_of_garbage_warns_once(self):
        path = self.legacy("g", [], raw=b"\x00\xff garbage\nmore\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(path), [])
            self.assertEqual(len(self.texts(path)), 2)
        self.assertEqual(err.getvalue().count("warning"), 1)
        self.assertEqual(self.src.counts["unreadable_stores"], 1)


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(GooseCase):

    def test_output_after_cat_env_reaches_clean_with_its_origin(self):
        db = self.database([(SID, CWD, "", EXTENSION_DATA)],
                           _one("c", "shell", {"command": "cat .env"},
                                out="STRIPE_KEY=" + SECRET + "\n")
                           + [(SID, "user", [text("my pw is " + PW)], T0 + 5)])
        found = self.found(db)
        self.assertEqual(found[SECRET], {".env"})
        self.assertEqual(found.get(PW, set()), set())

    def test_the_result_is_tied_to_its_call(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("c", "shell", {"command": "cat .env"},
                                out="K=" + SECRET))
        tied = [t for t in self.texts(db) if t.call is not None]
        self.assertEqual(len(tied), 1)
        self.assertEqual((tied[0].call.tool_call_id, tied[0].call.command),
                         ("c", "cat .env"))
        self.assertIn("K=" + SECRET, json.dumps(tied[0].node))
        # the rest of the message is handed over without the result
        rest = [t for t in self.texts(db)
                if t.call is None and t.where == tied[0].where]
        self.assertEqual(len(rest), 1)
        self.assertNotIn(SECRET, json.dumps(rest[0].node))
        self.assertIn('"id": "c"', json.dumps(rest[0].node))

    def test_session_names_are_searched_and_extension_data_is_not(self):
        db = self.database([(SID, CWD, "deploy with " + SECRET2,
                             EXTENSION_DATA)], [])
        conn = sqlite3.connect(db)
        conn.execute("UPDATE sessions SET recipe_json = ?, description = ?",
                     (_dump({"extensions": [{"envs": {"K": EXT_KEY}}]}),
                      "pw " + PW))
        conn.commit()
        conn.close()
        texts = self.texts(db)
        self.assertEqual([(t.node, t.where) for t in texts],
                         [("deploy with " + SECRET2,
                           "sessions row %s, name" % SID),
                          ("pw " + PW, "sessions row %s, description" % SID)])
        self.assertNotIn(EXT_KEY, self.found(db))
        self.assertIn(SECRET2, self.found(db))

    def test_every_message_and_text_that_is_not_json(self):
        db = self.database([(SID, CWD, "", "{}")], [
            (SID, "user", [text("a " + SECRET)], T0),
            (SID, "user", "not json " + SECRET2, T0 + 1),
            (SID, "assistant", _dump({"odd": PW}), T0 + 2)])
        nodes = [t.node for t in self.texts(db)]
        self.assertEqual(nodes, [[text("a " + SECRET)], "not json " + SECRET2,
                                 {"odd": PW}])
        self.assertEqual((self.src.counts["unparsed"],
                          self.src.counts["unknown"]), (1, 1))

    def test_nothing_outside_sessions_is_read(self):
        config = os.path.join(self.home, ".config", "goose")
        os.makedirs(config)
        with open(os.path.join(config, "secrets.yaml"), "w", encoding="utf-8") as fh:
            fh.write("OPENAI_API_KEY: " + SECRET + "\n")
        self.database([(SID, CWD, "", "{}")])
        with open(os.path.join(self.data, "x.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(_dump({"working_dir": CWD, "k": SECRET}) + "\n")
        for store in self.stores():
            self.assertTrue(store.path.startswith(self.folder))
            self.assertNotIn(SECRET, json.dumps(
                [t.node for t in self.src.secret_texts(store)]))


# --------------------------------------------------------------------------
# A database that is not one, or not all there
# --------------------------------------------------------------------------

class Damaged(GooseCase):

    def write_db(self, raw):
        os.makedirs(self.folder, exist_ok=True)
        with open(self.db_path, "wb") as fh:
            fh.write(raw)
        return self.db_path

    def test_not_a_database_warns_once_and_yields_nothing(self):
        path = self.write_db(b"not a database " + SECRET.encode())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(path), [])
            self.assertEqual(self.texts(path), [])
        self.assertEqual(err.getvalue().count("warning"), 1)
        self.assertNotIn(SECRET, err.getvalue())
        self.assertEqual(self.src.unreadable,
                         {goose_module.NOT_DATABASE: 1})

    def test_an_empty_file_holds_nothing(self):
        path = self.write_db(b"")
        self.assertEqual((self.calls(path), self.texts(path)), ([], []))
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_a_truncated_database(self):
        good = self.database([(SID, CWD, "", "{}")],
                             _one("c", "shell", {"command": "ls"}, out="x")
                             * 50, wal=False)
        with open(good, "rb") as fh:
            raw = fh.read()
        self.write_db(raw[:len(raw) // 2] + b"\x00" * 100)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            list(self.src.tool_calls(self.store(good)))
            list(self.src.secret_texts(self.store(good)))
        self.assertLessEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_database_with_other_tables(self):
        os.makedirs(self.folder)
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE other (x TEXT)")
        conn.execute("INSERT INTO other VALUES (?)", (SECRET,))
        conn.commit()
        conn.close()
        self.assertEqual((self.calls(self.db_path), self.texts(self.db_path)),
                         ([], []))
        self.assertEqual(self.src.counts["unknown"], 1)

    def test_tables_missing_columns(self):
        os.makedirs(self.folder)
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE sessions (x TEXT)")
        conn.execute("CREATE TABLE messages (role TEXT)")
        conn.execute("INSERT INTO messages VALUES ('user')")
        conn.commit()
        conn.close()
        self.assertEqual((self.calls(self.db_path), self.texts(self.db_path)),
                         ([], []))

    def test_wrong_types_everywhere(self):
        weird = [
            None, 1, "s", [], {}, {"type": None},
            {"type": "toolRequest"},
            {"type": "toolRequest", "id": 5, "toolCall": []},
            {"type": "toolRequest", "id": "a", "toolCall": {"status": "success",
                                                            "value": []}},
            {"type": "toolRequest", "id": "b", "toolCall": {
                "status": "success", "value": {"name": 7}}},
            {"type": "toolRequest", "id": "c", "toolCall": {
                "status": "success", "value": {"name": "shell",
                                               "arguments": [1, 2]}}},
            {"type": "toolRequest", "id": "d", "toolCall": {
                "status": "success", "value": {"name": "shell",
                                               "arguments": {"command": 5}}}},
            {"type": "toolRequest", "id": "e", "toolCall": {
                "status": "success", "value": {
                    "name": "developer__text_editor",
                    "arguments": {"command": ["view"], "path": {"x": 1}}}}},
            {"type": "toolResponse"}, {"type": "toolResponse", "id": "c",
                                       "toolResult": "str"},
            {"type": "toolResponse", "id": "d", "toolResult": {
                "status": "success", "value": {"content": "str"}}},
            {"type": "toolResponse", "id": "e", "toolResult": {
                "status": "success", "value": [None, {"type": "text",
                                                      "text": 5}]}},
        ]
        conn_rows = [(SID, "assistant", weird, T0),
                     (SID, "user", _dump(42), "not a time"),
                     (SID, 7, _dump([]), 0)]
        db = self.database([(SID, CWD, "", "{}")], conn_rows)
        conn = sqlite3.connect(db)
        conn.execute("INSERT INTO sessions (id, working_dir, name) "
                     "VALUES (?, ?, ?)", (b"bytes-id", 5, b"\xff\xfe"))
        conn.execute("INSERT INTO messages (session_id, role, content_json, "
                     "created_timestamp) VALUES (?, ?, ?, ?)",
                     (b"\xffbin", "user", b"\xff\xfe[", 1))
        conn.commit()
        conn.close()
        calls = self.by_id(db)
        self.assertEqual(sorted(calls), ["c", "d", "e"])
        self.assertEqual(calls["c"].tool_input, {"_value": [1, 2]})
        self.assertIsNone(calls["d"].command)
        self.assertEqual((calls["e"].kind, calls["e"].paths), ("other", ()))
        self.assertIsNone(calls["e"].output)
        list(self.src.secret_texts(self.store(db)))
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_nested_past_the_stack(self):
        deep = "[" * 100000 + "]" * 100000
        db = self.database([(SID, CWD, "", "{}")],
                           [(SID, "user", deep, T0)]
                           + _one("c", "shell", {"command": "ls"}, out="x"))
        self.assertEqual([c.command for c in self.calls(db)], ["ls"])
        self.assertEqual(len(self.texts(db)), 4)

    def test_a_reader_that_fails_says_what_failed_not_its_message(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("c", "shell", {"command": "ls"}, out="x"))

        def boom(*_a, **_k):
            raise sqlite3.OperationalError("near " + SECRET)

        err = io.StringIO()
        with mock.patch.object(_sqlite, "iter_rows", side_effect=boom), \
                contextlib.redirect_stderr(err):
            self.assertEqual(self.texts(db)[:0], [])
        self.assertIn("OperationalError", err.getvalue())
        self.assertNotIn(SECRET, err.getvalue())

    def test_an_unexpected_error_is_said_and_not_raised(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("c", "shell", {"command": "ls"}, out="x"))
        err = io.StringIO()
        with mock.patch.object(goose_module, "classify",
                               side_effect=RuntimeError(SECRET)), \
                contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(db), [])
            self.assertEqual(len(self.texts(db)), 0)
        self.assertIn("RuntimeError", err.getvalue())
        self.assertNotIn(SECRET, err.getvalue())

    def test_a_locked_database_is_read_from_a_copy_that_is_removed(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("c", "shell", {"command": "cat .env"},
                                out="K=" + SECRET))
        real = sqlite3.connect
        opened = []

        def locked(*args, **kwargs):
            opened.append(args[0])
            if len(opened) == 1:
                raise sqlite3.OperationalError("database is locked")
            return real(*args, **kwargs)

        with mock.patch.object(_sqlite.sqlite3, "connect", side_effect=locked):
            [call] = self.calls(db)
        self.assertEqual(call.output, "K=" + SECRET)
        self.assertNotIn(os.path.dirname(db), opened[1])

    def test_a_reader_that_stops_early_leaves_no_copy(self):
        db = self.database([(SID, CWD, "", "{}")],
                           _one("c", "shell", {"command": "ls"}, out="x") * 3)
        real = sqlite3.connect
        opened = []

        def locked(*args, **kwargs):
            opened.append(args[0])
            if len(opened) == 1:
                raise sqlite3.OperationalError("database is locked")
            return real(*args, **kwargs)

        with mock.patch.object(_sqlite.sqlite3, "connect", side_effect=locked):
            texts = self.src.secret_texts(self.store(db))
            next(texts)
            texts.close()


# --------------------------------------------------------------------------
# The database is never written
# --------------------------------------------------------------------------

def _live(path, sessions, messages, read_after=True):
    """Goose running: the database in WAL mode, its writer open, every row
    committed into the -wal."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    GooseCase.fill(conn, sessions, messages)
    if read_after:
        conn.execute("SELECT count(*) FROM messages").fetchall()
    return conn


class NeverWritten(GooseCase):

    SESSIONS = [(SID, CWD, "", EXTENSION_DATA)]
    ROWS = (_one("c1", "shell", {"command": "cat .env"},
                 out="API_KEY=" + SECRET + "\nDB_PASSWORD=" + PW + "\n")
            + _one("c2", "shell", {"command": "rm -rf ~/Documents/x"},
                   out="", created=T0 + 10))

    def read_everything(self):
        store = self.store(self.db_path)
        calls = list(self.src.tool_calls(store))
        self.assertEqual(len(calls), 2)
        self.assertIn("fs.destructive", rules(calls[1]))
        self.assertGreater(len(list(self.src.secret_texts(store))), 0)
        self.assertEqual(self.found(self.db_path)[SECRET], {".env"})
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(self.db_path, skipped="read-only"))
        # and discovery, and the id lookup a legacy file makes
        self.legacy_check()

    def legacy_check(self):
        path = self.legacy(SID, [])
        try:
            self.assertEqual(self.calls(path), [])
        finally:
            os.remove(path)

    def test_with_its_writer_open(self):
        writer = _live(self.db_path, self.SESSIONS, self.ROWS)
        self.addCleanup(writer.close)
        before = _files(self.db_path)
        self.assertEqual(sorted(before), ["", "-shm", "-wal"])
        self.assertGreater(len(before["-wal"]), 0)
        self.read_everything()
        self.assertEqual(_files(self.db_path), before)
        self.assertEqual(sorted(os.listdir(self.folder)),
                         ["sessions.db", "sessions.db-shm", "sessions.db-wal"])
        self.assertFalse(os.path.exists(self.backups))

    def test_a_commit_its_writer_has_not_read_back(self):
        writer = _live(self.db_path, self.SESSIONS, self.ROWS,
                       read_after=False)
        self.addCleanup(writer.close)
        before = _files(self.db_path)
        self.read_everything()
        after = _files(self.db_path)
        self.assertEqual((after[""], after["-wal"]),
                         (before[""], before["-wal"]))
        changed = [i for i, (a, b) in enumerate(zip(before["-shm"],
                                                    after["-shm"])) if a != b]
        self.assertTrue(all(100 <= i < 120 for i in changed), changed)

    def test_with_its_writer_closed(self):
        _live(self.db_path, self.SESSIONS, self.ROWS).close()
        for suffix in ("-wal", "-shm"):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)
        before = _files(self.db_path)
        self.assertEqual(sorted(before), [""])
        self.read_everything()
        self.assertEqual(_files(self.db_path), before)
        self.assertEqual(os.listdir(self.folder), ["sessions.db"])

    def test_with_a_wal_and_no_shm(self):
        live = os.path.join(self.home, "live", "sessions.db")
        writer = _live(live, self.SESSIONS, self.ROWS)
        try:
            os.makedirs(self.folder)
            for suffix in ("", "-wal"):
                shutil.copy2(live + suffix, self.db_path + suffix)
        finally:
            writer.close()
        before = _files(self.db_path)
        self.assertEqual(sorted(before), ["", "-wal"])
        self.read_everything()
        self.assertEqual(_files(self.db_path), before)
        self.assertEqual(sorted(os.listdir(self.folder)),
                         ["sessions.db", "sessions.db-wal"])


if __name__ == "__main__":
    unittest.main()
