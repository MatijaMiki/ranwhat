"""The Zed adapter (ranwhat/sources/zed.py), checked against Zed's main.

Fixtures are built from Zed's own structs, not captured from a live
database: threads.db made with ThreadsDatabase::new's DDL and its later
ALTER TABLEs (db.rs), one row per thread, data the serde JSON of DbThread
(version "0.3.0"), plain (data_type "json", the legacy form) or zstd. No
zstd encoder is assumed: a frame of raw blocks is written by hand, and a
decoder is needed only by the tests that say so.

Everything runs in temp directories, the home directory and the data
variables among them, and the real home is never read. Every secret is
synthetic, and token-shaped ones are written as adjacent literals.
"""
import contextlib
import io
import json
import os
import re
import shutil
import sqlite3
import struct
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
from ranwhat.sources import _paths, _sqlite, _zstd  # noqa: E402
from ranwhat.sources import zed as zed_module  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.zed import ZedSource  # noqa: E402

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
SECRET2 = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"
KEY = "sk_" "live_" "Xc4Vb6Nm8Qw2Er4Ty6Ui8Op"          # in the model config

TID = "9b0f6c1e-3f7a-4b6e-8d21-5c1e0a7d4f10"
FOLDER = "/home/dev/myproj"
CREATED = "2026-10-20T09:00:00Z"
UPDATED = "2026-10-20T09:14:02Z"

# ThreadsDatabase::new (db.rs), then its idempotent ALTER TABLEs.
SCHEMA = """
CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY,
    summary TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    data_type TEXT NOT NULL,
    data BLOB NOT NULL
);
ALTER TABLE threads ADD COLUMN parent_id TEXT;
ALTER TABLE threads ADD COLUMN folder_paths TEXT;
ALTER TABLE threads ADD COLUMN folder_paths_order TEXT;
ALTER TABLE threads ADD COLUMN created_at TEXT;
"""

# A database from before any of the ALTERs.
SCHEMA_OLD = """
CREATE TABLE threads (id TEXT PRIMARY KEY, summary TEXT NOT NULL,
    updated_at TEXT NOT NULL, data_type TEXT NOT NULL, data BLOB NOT NULL);
"""

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def zstd_raw(data):
    """A zstd frame of raw blocks: valid for any decoder, no encoder
    needed. Window descriptor 0x58 (2 MiB), no checksum."""
    out = bytearray(ZSTD_MAGIC + b"\x00\x58")
    view = memoryview(data)
    step = 1 << 16
    if not len(view):
        out += struct.pack("<I", 1)[:3]
    for i in range(0, len(view), step):
        chunk = view[i:i + step]
        last = 1 if i + step >= len(view) else 0
        out += struct.pack("<I", last | (len(chunk) << 3))[:3]
        out += chunk
    return bytes(out)


# -- the thread, as serde writes it (thread.rs, language_model_core.rs) ------

def tool_use(cid, name, value, kind="json"):
    raw = value if isinstance(value, str) else json.dumps(value)
    return {"ToolUse": {"id": cid, "name": name, "raw_input": raw,
                        "input": {"type": kind, "value": value},
                        "is_input_complete": True, "thought_signature": None}}


def result(cid, name, text, is_error=False, output=None):
    return {"tool_use_id": cid, "tool_name": name, "is_error": is_error,
            "content": [{"Text": text}], "output": output}


def user(text, uid="u1"):
    return {"User": {"id": uid, "content": [{"Text": text}]}}


def agent(content, results=None):
    return {"Agent": {"content": content, "tool_results": results or {},
                      "reasoning_details": None}}


def call_message(cid, name, value, text=None, **kw):
    """An Agent message holding one call and, when `text` is given, its
    result (Zed stores both in the one message)."""
    results = {} if text is None else {cid: result(cid, name, text, **kw)}
    return agent([{"Text": "Running it."}, tool_use(cid, name, value)], results)


def thread(messages, title="Run the tests", **extra):
    doc = {"version": "0.3.0", "title": title, "updated_at": UPDATED,
           "messages": messages, "detailed_summary": None,
           "initial_project_snapshot": None,
           "cumulative_token_usage": {"input_tokens": 1},
           "request_token_usage": {}, "profile": "write",
           "model": {"provider": "anthropic", "model": "claude",
                     "api_key": KEY},
           "subagent_context": None, "speed": None,
           "thinking_enabled": False, "thinking_effort": None,
           "draft_prompt": None, "ui_scroll_position": None,
           "sandboxed_terminal_temp_dir": None, "sandbox_grants": {}}
    doc.update(extra)
    return doc


def _json(doc):
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)


def _files(path):
    out = {}
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            with open(path + suffix, "rb") as fh:
                out[suffix] = fh.read()
    return out


def _ranwhat_temp_dirs():
    return set(x for x in os.listdir(tempfile.gettempdir())
               if re.match(r"ranwhat-[a-z0-9_]{8}\Z", x))


def rules(call):
    return [h["rule"] for h in watch.judge(call)[0]]


class ZedCase(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="zed-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        patches = [mock.patch.dict(os.environ, {
                       "HOME": self.home, "USERPROFILE": self.home,
                       "LOCALAPPDATA": os.path.join(self.home, "AppData",
                                                    "Local")}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for name in (zed_module.ENV, "XDG_DATA_HOME"):
            os.environ.pop(name, None)
        self.backups = os.path.join(self.home, "backups")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.data = ZedSource().default_paths(
            os.environ, self.home, _paths.platform_name())[0][0]
        self.folder = os.path.join(self.data, "threads")
        self.db_path = os.path.join(self.folder, "threads.db")
        self.src = ZedSource()
        self.temp_before = _ranwhat_temp_dirs()

    def tearDown(self):
        self.assertEqual(_ranwhat_temp_dirs() - self.temp_before, set(),
                         "a ranwhat-* temp directory was left behind")

    # -- fixtures -----------------------------------------------------------

    @staticmethod
    def row(doc, tid=TID, summary="Run the tests", zstd=False, folders=FOLDER,
            data_type=None, updated=UPDATED, created=CREATED, cell=None):
        """(id, summary, updated, data_type, data, folders, created) as
        save_thread_sync writes them (zstd), or as a legacy row (json)."""
        if cell is None:
            raw = (doc if isinstance(doc, bytes) else _json(doc).encode("utf-8"))
            cell = zstd_raw(raw) if zstd else raw
        return (tid, summary, updated, data_type or ("zstd" if zstd else "json"),
                cell, folders, created)

    def database(self, rows=(), schema=SCHEMA, path=None, wal=True):
        path = path or self.db_path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        if wal:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(schema)
        self.fill(conn, rows, schema)
        conn.close()
        return path

    @staticmethod
    def fill(conn, rows, schema=SCHEMA):
        for tid, summary, updated, dtype, data, folders, created in rows:
            if schema is SCHEMA:
                conn.execute(
                    "INSERT INTO threads (id, summary, updated_at, data_type, "
                    "data, folder_paths, folder_paths_order, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (tid, summary, updated, dtype, data, folders,
                     "0" if folders else None, created))
            else:
                conn.execute(
                    "INSERT INTO threads (id, summary, updated_at, data_type, "
                    "data) VALUES (?, ?, ?, ?, ?)",
                    (tid, summary, updated, dtype, data))
        conn.commit()

    def one(self, messages, **kw):
        return self.database([self.row(thread(messages), **kw)])

    def stores(self, override=None, since_days=None):
        return self.src.stores(self.src.locations(override=override),
                               since_days=since_days)

    def store(self, path=None):
        path = path or self.db_path
        for store in self.stores() + self.stores(override=path):
            if store.path == path:
                return store
        self.fail("%s is not a store" % path)

    def calls(self, path=None):
        return list(self.src.tool_calls(self.store(path)))

    def by_id(self, path=None):
        return {c.tool_call_id: c for c in self.calls(path)}

    def texts(self, path=None):
        return list(self.src.secret_texts(self.store(path)))

    def found(self, path=None):
        values = {}
        findings, _masks = clean.scan_store(self.src, self.store(path), values)
        return {values[fp]: f["origins"] for fp, f in findings.items()}


# --------------------------------------------------------------------------
# Where Zed keeps its threads
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = ZedSource()

    def test_each_platform(self):
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.local/share/zed", "default")])
        self.assertEqual(
            self.src.default_paths({}, "/Users/u", "darwin"),
            [("/Users/u/Library/Application Support/Zed", "default")])
        self.assertEqual(
            self.src.default_paths({}, "C:\\Users\\u", "win32"),
            [("C:\\Users\\u\\AppData\\Local\\Zed", "default")])
        self.assertEqual(
            self.src.default_paths({"LOCALAPPDATA": "D:\\Loc"},
                                   "C:\\Users\\u", "win32"),
            [("D:\\Loc\\Zed", "default")])

    def test_other_posix_systems_lay_out_like_linux(self):
        self.assertEqual(self.src.default_paths({}, "/home/u", "freebsd13"),
                         [("/home/u/.local/share/zed", "default")])

    def test_xdg_data_home_only_when_absolute(self):
        self.assertEqual(
            self.src.default_paths({"XDG_DATA_HOME": "/xdg"}, "/home/u",
                                   "linux"), [("/xdg/zed", "default")])
        for value in ("rel/xdg", ""):
            with self.subTest(value=value):
                self.assertEqual(
                    self.src.default_paths({"XDG_DATA_HOME": value},
                                           "/home/u", "linux"),
                    [("/home/u/.local/share/zed", "default")])

    def test_the_flatpak_variable_wins_on_linux_only(self):
        env = {zed_module.ENV: "/fp/data", "XDG_DATA_HOME": "/xdg"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/fp/data/zed", "env " + zed_module.ENV)])
        self.assertEqual(
            self.src.default_paths(env, "/Users/u", "darwin"),
            [("/Users/u/Library/Application Support/Zed", "default")])
        self.assertEqual(
            self.src.default_paths(env, "C:\\Users\\u", "win32"),
            [("C:\\Users\\u\\AppData\\Local\\Zed", "default")])

    def test_an_empty_flatpak_variable_is_ignored(self):
        self.assertEqual(
            self.src.default_paths({zed_module.ENV: ""}, "/home/u", "linux"),
            [("/home/u/.local/share/zed", "default")])

    def test_what_every_report_needs(self):
        src = self.src
        self.assertEqual((src.id, src.name, src.unit, src.env),
                         ("zed", "Zed", "database", (zed_module.ENV,)))
        self.assertEqual(
            src.path_means,
            "Zed's data folder (the one holding threads/threads.db)")
        self.assertTrue(src.checked)
        self.assertFalse(src.read_only)


class Discovery(ZedCase):

    def test_the_variable_is_read_at_call_time(self):
        if _paths.platform_name() != "linux":
            self.skipTest("the variable is Linux's")
        root = os.path.join(self.home, "fp")
        os.environ[zed_module.ENV] = root
        path = self.database(path=os.path.join(root, "zed", "threads",
                                               "threads.db"))
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.found),
                         (os.path.join(root, "zed"),
                          "env " + zed_module.ENV, 1))
        self.assertEqual([s.path for s in self.stores()], [path])

    def test_a_missing_variable_is_the_default(self):
        db = self.database()
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (self.data, "default", True, 1))
        self.assertEqual([s.path for s in self.stores()], [db])

    def test_what_the_store_is(self):
        db = self.database()
        [store] = self.stores()
        self.assertEqual(
            (store.path, store.format, store.role, store.unit, store.masking,
             store.why_read_only),
            (db, "sqlite", "transcript", "database", "read-only",
             zed_module.WHY_READ_ONLY))

    def test_a_missing_data_folder_is_zero_stores(self):
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (False, 0))
        self.assertEqual(self.stores(), [])

    def test_path_may_name_the_data_folder_threads_or_the_file(self):
        db = self.database()
        for where in (self.data, self.folder, db):
            with self.subTest(where=where):
                self.assertEqual([s.path for s in self.stores(override=where)],
                                 [db])

    def test_the_database_is_kept_whatever_its_age(self):
        db = self.database()
        old = time.time() - 90 * 86400
        os.utime(db, (old, old))
        self.assertEqual([s.path for s in self.stores(since_days=7)], [db])

    def test_other_files_in_threads_are_not_stores(self):
        self.database()
        for name in ("threads.db-journal", "threads-db.1.mdb", "notes.txt"):
            with open(os.path.join(self.folder, name), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
        self.assertEqual([os.path.basename(s.path) for s in self.stores()],
                         ["threads.db"])

    def test_a_threads_db_that_is_a_folder_is_not_a_store(self):
        os.makedirs(self.db_path)
        self.assertEqual(self.stores(), [])


# --------------------------------------------------------------------------
# Tool calls
# --------------------------------------------------------------------------

class ToolCalls(ZedCase):

    def test_the_spec_sample_a_failed_command(self):
        db = self.database([self.row({
            "version": "0.3.0", "title": "Run the tests",
            "updated_at": UPDATED,
            "messages": [
                user("run cargo test"),
                {"Agent": {"content": [
                    {"Text": "Running it."},
                    {"ToolUse": {"id": "toolu_01", "name": "terminal",
                                 "raw_input": "{\"command\":\"cargo test\","
                                              "\"cd\":\"myproj\"}",
                                 "input": {"type": "json", "value": {
                                     "command": "cargo test",
                                     "cd": "myproj"}},
                                 "is_input_complete": True,
                                 "thought_signature": None}}],
                    "tool_results": {"toolu_01": {
                        "tool_use_id": "toolu_01", "tool_name": "terminal",
                        "is_error": True,
                        "content": [{"Text": "Command \"cargo test\" failed "
                                             "with exit code 101.\n\nboom"}],
                        "output": None}},
                    "reasoning_details": None}}],
            "subagent_context": None})])
        [call] = self.calls(db)
        self.assertEqual(
            (call.source, call.tool_name, call.kind, call.known, call.actor,
             call.tool_call_id, call.command, call.workdir, call.session,
             call.project, call.status),
            ("zed", "terminal", "shell", True, "agent", "toolu_01",
             "cargo test", FOLDER, TID, FOLDER, None))
        self.assertEqual(call.tool_input, {"command": "cargo test",
                                           "cd": "myproj"})
        self.assertEqual(call.consumed, frozenset({"command"}))
        self.assertTrue(call.output.startswith(
            "Command \"cargo test\" failed with exit code 101."))
        self.assertIsNone(call.timestamp)
        self.assertEqual(call.not_after, UPDATED)

    def test_a_shell_command_is_judged(self):
        db = self.one([call_message("c1", "terminal",
                                    {"command": "rm -rf ~/Documents/x",
                                     "cd": "myproj"}, "Command executed "
                                    "successfully.")])
        [call] = self.calls(db)
        self.assertIn("fs.destructive", rules(call))

    def test_the_sandboxed_terminal_is_a_shell_too(self):
        db = self.one([call_message(
            "c1", "sandboxed_terminal",
            {"command": "ls", "cd": FOLDER, "allow_hosts": ["example.com"],
             "unsandboxed": False, "reason": None}, "a\nb")])
        [call] = self.calls(db)
        self.assertEqual((call.kind, call.known, call.command, call.workdir),
                         ("shell", True, "ls", FOLDER))
        self.assertEqual(call.tool_input["allow_hosts"], ["example.com"])

    def test_cd_is_resolved_against_the_threads_folders(self):
        folders = "/a/other\n/home/dev/myproj"
        for cd, want in (("myproj", "/home/dev/myproj"),
                         ("/abs/elsewhere", "/abs/elsewhere"),
                         ("nowhere", "nowhere"),
                         ("C:\\win\\dir", "C:\\win\\dir"),
                         ("other/", "/a/other")):
            with self.subTest(cd=cd):
                db = self.database(
                    [self.row(thread([call_message(
                        "c", "terminal", {"command": "ls", "cd": cd}, "x")]),
                        folders=folders)], path=os.path.join(
                            self.home, cd.replace("/", "_").replace(
                                "\\", "_").replace(":", "_"), "threads.db"))
                [call] = list(self.src.tool_calls(self.store(db)))
                self.assertEqual(call.workdir, want)

    def test_every_mapped_tool(self):
        cases = [
            ("read_file", {"path": "myproj/src/main.rs", "start_line": 1},
             "read", ("myproj/src/main.rs",), frozenset({"path"})),
            ("list_directory", {"path": "myproj/src"}, "read",
             ("myproj/src",), frozenset({"path"})),
            ("edit_file", {"path": "myproj/a.rs", "edits": [
                {"old_text": "a", "new_text": "b"}]}, "write",
             ("myproj/a.rs",), frozenset()),
            ("write_file", {"path": "myproj/b.rs", "content": "x"}, "write",
             ("myproj/b.rs",), frozenset()),
            ("delete_path", {"path": "myproj/old"}, "write",
             ("myproj/old",), frozenset()),
            ("create_directory", {"path": "myproj/new", "reason": None},
             "write", ("myproj/new",), frozenset()),
            ("copy_path", {"source_path": "myproj/a",
                           "destination_path": "myproj/b"}, "write",
             ("myproj/a", "myproj/b"), frozenset()),
            ("move_path", {"source_path": "myproj/a",
                           "destination_path": "/tmp/b"}, "write",
             ("myproj/a", "/tmp/b"), frozenset()),
            ("fetch", {"url": "https://example.com/x"}, "fetch", (),
             frozenset()),
            ("grep", {"regex": "todo", "include_pattern": "**/*.rs"},
             "other", (), frozenset()),
            ("find_path", {"glob": "**/*.toml", "offset": 0}, "other", (),
             frozenset()),
        ]
        db = self.one([call_message("c%d" % i, name, args, "ok")
                       for i, (name, args, *_r) in enumerate(cases)])
        calls = self.by_id(db)
        self.assertEqual(len(calls), len(cases))
        for i, (name, args, kind, paths, consumed) in enumerate(cases):
            with self.subTest(tool=name):
                call = calls["c%d" % i]
                self.assertEqual((call.tool_name, call.kind, call.known,
                                  call.paths, call.consumed),
                                 (name, kind, True, paths, consumed))
                self.assertEqual(call.tool_input, args)
                self.assertIsNone(call.command)

    def test_a_read_tool_is_judged_by_its_path(self):
        db = self.one([call_message(
            "c", "read_file", {"path": "/home/dev/.aws/credentials"}, "k")])
        [call] = self.calls(db)
        self.assertEqual(call.paths, ("/home/dev/.aws/credentials",))
        self.assertIn("cred.read", rules(call))

    def test_an_unknown_tool_is_judged_by_its_name(self):
        db = self.one([call_message("c", "spawn_agent", {"task": "x"}, "ok"),
                       call_message("d", "mcp:github:create_issue",
                                    {"title": "t"}, "ok")])
        for call in self.calls(db):
            self.assertEqual((call.kind, call.known), ("other", False))

    def test_the_input_in_every_stored_shape(self):
        uses = [
            tool_use("a", "terminal", {"command": "ls a"}),
            tool_use("b", "terminal", '{"command":"ls b"}', kind="text"),
            {"ToolUse": {"id": "c", "name": "terminal",
                         "input": {"command": "ls c"}}},        # bare value
            {"ToolUse": {"id": "d", "name": "terminal",
                         "raw_input": "{\"command\":\"ls d\"}",
                         "input": {"type": "json", "value": None}}},
            {"ToolUse": {"id": "e", "name": "terminal",
                         "raw_input": "{\"command\":\"ls e\"}"}},
        ]
        db = self.one([agent(uses)])
        got = {c.tool_call_id: c.command for c in self.calls(db)}
        self.assertEqual(got, {"a": "ls a", "b": "ls b", "c": "ls c",
                               "d": "ls d", "e": "ls e"})

    def test_outputs_in_every_stored_shape(self):
        def res(cid, **kw):
            return dict({"tool_use_id": cid, "tool_name": "terminal",
                         "is_error": False}, **kw)
        uses = [tool_use(c, "terminal", {"command": "ls"}) for c in "abcdefg"]
        results = {
            "a": res("a", content=[{"Text": "one"}, {"Text": "two"}]),
            "b": res("b", content=[{"text": "lower"}]),
            "c": res("c", content={"Text": "bare"}),
            "d": res("d", content="plain string"),
            "e": res("e", content=[], output="from output"),
            "f": res("f", content=[{"Image": {"source": "x"}}]),
            "g": res("g", content=[{"Text": {"text": "wrapped"}}]),
        }
        db = self.one([agent(uses, results)])
        got = {c.tool_call_id: c.output for c in self.calls(db)}
        self.assertEqual(got, {"a": "one\ntwo", "b": "lower", "c": "bare",
                               "d": "plain string", "e": "from output",
                               "f": None, "g": "wrapped"})

    def test_a_cancelled_call_never_ran(self):
        db = self.one([
            call_message("c", "terminal", {"command": "make"},
                         zed_module.CANCELED, is_error=True),
            call_message("d", "terminal", {"command": "make"},
                         "Tool canceled by user\nbut it printed more")])
        calls = self.by_id(db)
        self.assertEqual(calls["c"].status, "declined")
        self.assertIsNone(calls["d"].status)        # a command that ran

    def test_a_call_with_no_result_is_still_a_call(self):
        db = self.one([call_message("c", "terminal", {"command": "sleep 99"})])
        [call] = self.calls(db)
        self.assertEqual((call.command, call.output, call.status),
                         ("sleep 99", None, None))

    def test_a_call_is_yielded_once_per_thread(self):
        db = self.one([call_message("c", "terminal", {"command": "ls"}, "a"),
                       call_message("c", "terminal", {"command": "ls"}, "b")])
        [call] = self.calls(db)
        self.assertEqual(call.output, "a")

    def test_the_same_call_id_in_two_threads_is_two_calls(self):
        msgs = [call_message("c", "terminal", {"command": "ls"}, "x")]
        db = self.database([self.row(thread(msgs), tid="t1"),
                            self.row(thread(msgs), tid="t2")])
        self.assertEqual(sorted(c.session for c in self.calls(db)),
                         ["t1", "t2"])

    def test_a_result_in_a_later_message_is_found(self):
        db = self.one([agent([tool_use("c", "terminal", {"command": "ls"})]),
                       agent([{"Text": "more"}], {"c": result(
                           "c", "terminal", "late")})])
        [call] = self.calls(db)
        self.assertEqual(call.output, "late")

    def test_messages_that_hold_no_call(self):
        db = self.one([user("hi"), "Resume", {"Compaction": {"summary": "s"}},
                       agent([{"Text": "t"}, {"Thinking": {"text": "hm",
                                                           "signature": None}},
                              {"RedactedThinking": "xx"}]),
                       call_message("c", "terminal", {"command": "ls"}, "x")])
        self.assertEqual([c.tool_call_id for c in self.calls(db)], ["c"])
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_threads_without_folders_have_no_project(self):
        db = self.database([self.row(
            thread([call_message("c", "terminal", {"command": "ls",
                                                   "cd": "x"}, "o")]),
            folders=None)])
        [call] = self.calls(db)
        self.assertEqual((call.project, call.workdir), (None, "x"))

    def test_the_first_folder_is_the_project(self):
        db = self.database([self.row(
            thread([call_message("c", "terminal", {"command": "ls"}, "o")]),
            folders="/a/one\n/b/two")])
        [call] = self.calls(db)
        self.assertEqual(call.project, "/a/one")

    def test_not_after_falls_back(self):
        msgs = [call_message("c", "terminal", {"command": "ls"}, "o")]
        db = self.database([self.row(thread(msgs), updated="garbage")])
        [call] = self.calls(db)
        self.assertEqual(call.not_after, UPDATED)       # the JSON's own
        db2 = self.database([self.row(thread(msgs, updated_at=None),
                                      updated="garbage")],
                            path=os.path.join(self.home, "b", "threads.db"))
        [call] = list(self.src.tool_calls(self.store(db2)))
        self.assertRegex(call.not_after, r"^\d{4}-\d\d-\d\dT")

    def test_a_database_from_before_the_added_columns(self):
        db = self.database([self.row(thread([call_message(
            "c", "terminal", {"command": "ls", "cd": "x"}, "o")]))],
            schema=SCHEMA_OLD)
        [call] = self.calls(db)
        self.assertEqual((call.command, call.project, call.session),
                         ("ls", None, TID))

    def test_null_folders_and_created_at(self):
        db = self.database([self.row(
            thread([call_message("c", "terminal", {"command": "ls"}, "o")]),
            folders=None, created=None)])
        self.assertEqual(len(self.calls(db)), 1)

    def test_a_text_cell_holds_the_same_thread(self):
        """TEXT affinity on data: a str, not bytes."""
        doc = thread([call_message("c", "terminal", {"command": "ls"}, "o")])
        db = self.database([self.row(None, cell=_json(doc))])
        [call] = self.calls(db)
        self.assertEqual(call.command, "ls")

    def test_a_bom_and_a_missing_data_type(self):
        doc = thread([call_message("c", "terminal", {"command": "ls"}, "o")])
        raw = b"\xef\xbb\xbf" + _json(doc).encode("utf-8")
        db = self.database([self.row(raw, data_type="")])
        self.assertEqual(len(self.calls(db)), 1)

    def test_many_calls_in_linear_time(self):
        msgs = [call_message("c%d" % i, "terminal", {"command": "echo %d" % i},
                             "o%d" % i) for i in range(3000)]
        db = self.one(msgs)
        start = time.time()
        self.assertEqual(len(self.calls(db)), 3000)
        self.assertLess(time.time() - start, 10)


class Legacy(ZedCase):
    """Rows of Zed's agent-1 format, which Zed upgrades on load."""

    def agent1(self, **extra):
        doc = {"version": "0.2.0", "summary": "old", "updated_at": UPDATED,
               "messages": [
                   {"id": 0, "role": "user", "segments": [
                       {"type": "text", "text": "run it"}],
                    "tool_uses": [], "tool_results": [], "context": ""},
                   {"id": 1, "role": "assistant", "segments": [
                       {"type": "text", "text": "ok"}],
                    "tool_uses": [{"id": "t1", "name": "terminal",
                                   "input": {"command": "ls -la",
                                             "cd": "myproj"}},
                                  {"id": "t2", "name": "edit_file",
                                   "input": {"path": "myproj/a.rs",
                                             "display_description": "d",
                                             "mode": "edit"}}],
                    "tool_results": [], "context": ""},
                   {"id": 2, "role": "user", "segments": [],
                    "tool_uses": [], "tool_results": [
                        {"tool_use_id": "t1", "is_error": False,
                         "content": {"Text": "total 0"}, "output": None}],
                    "context": ""}]}
        doc.update(extra)
        return doc

    def test_the_agent_1_shape(self):
        db = self.database([self.row(self.agent1())])
        calls = self.by_id(db)
        self.assertEqual(
            (calls["t1"].command, calls["t1"].output, calls["t1"].workdir,
             calls["t1"].kind),
            ("ls -la", "total 0", FOLDER, "shell"))
        self.assertEqual((calls["t2"].kind, calls["t2"].paths, calls["t2"].output),
                         ("write", ("myproj/a.rs",), None))

    def test_no_version_at_all(self):
        doc = self.agent1()
        del doc["version"]
        db = self.database([self.row(doc)])
        self.assertEqual(sorted(self.by_id(db)), ["t1", "t2"])

    def test_a_different_version_of_the_current_shape(self):
        doc = thread([call_message("c", "terminal", {"command": "ls"}, "o")],
                     version="0.4.0")
        db = self.database([self.row(doc)])
        self.assertEqual(len(self.calls(db)), 1)

    def test_a_system_message_is_not_a_call(self):
        doc = self.agent1()
        doc["messages"].insert(0, {"id": 9, "role": "system", "segments": [],
                                   "tool_uses": [], "tool_results": []})
        db = self.database([self.row(doc)])
        self.assertEqual(len(self.calls(db)), 2)


class Compressed(ZedCase):

    def test_zstd_by_data_type_and_by_magic(self):
        doc = thread([call_message("c", "terminal", {"command": "ls"}, "o")])
        if not _zstd.available():
            self.skipTest("no zstd decoder here")
        db = self.database([
            self.row(doc, tid="a", zstd=True),
            self.row(doc, tid="b", zstd=True, data_type="json"),   # by magic
            self.row(doc, tid="c")])                               # plain
        self.assertEqual(sorted(c.session for c in self.calls(db)),
                         ["a", "b", "c"])

    def test_a_decoder_that_returns_the_json(self):
        doc = thread([call_message("c", "terminal", {"command": "ls"}, "o")])
        db = self.database([self.row(doc, zstd=True)])
        raw = _json(doc).encode("utf-8")
        with mock.patch.object(_zstd, "available", return_value=True), \
                mock.patch.object(_zstd, "decompress",
                                  return_value=raw) as dec:
            [call] = self.calls(db)
        self.assertEqual(call.command, "ls")
        self.assertTrue(dec.call_args[0][0].startswith(ZSTD_MAGIC))
        self.assertEqual(dec.call_args[0][1], zed_module.MAX_DECODED)
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_no_decoder_counts_the_store_and_still_reads_plain_rows(self):
        doc = thread([call_message("c", "terminal", {"command": "ls"}, "o")])
        db = self.database([self.row(doc, tid="z", zstd=True),
                            self.row(doc, tid="p")])
        err = io.StringIO()
        with mock.patch.object(_zstd, "available", return_value=False), \
                contextlib.redirect_stderr(err):
            calls = self.calls(db)
            self.texts(db)
        self.assertEqual([c.session for c in calls], ["p"])
        self.assertEqual(self.src.unreadable,
                         {"compressed, " + _zstd.NEEDS: 1})
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(err.getvalue().count("warning"), 1)

    def test_a_frame_that_does_not_decompress(self):
        doc = thread([call_message("c", "terminal", {"command": "ls"}, "o")])
        db = self.database([self.row(doc, tid="z", zstd=True),
                            self.row(doc, tid="p")])
        err = io.StringIO()
        with mock.patch.object(_zstd, "available", return_value=True), \
                mock.patch.object(_zstd, "decompress", return_value=None), \
                contextlib.redirect_stderr(err):
            calls = self.calls(db)
        self.assertEqual([c.session for c in calls], ["p"])
        self.assertEqual(self.src.counts["unparsed"], 1)
        self.assertNotIn("ls", err.getvalue().replace("rows", ""))

    def test_truncated_and_garbage_zstd_with_a_real_decoder(self):
        if not _zstd.available():
            self.skipTest("no zstd decoder here")
        doc = thread([call_message("c", "terminal", {"command": "ls"}, "o")])
        good = self.row(doc, tid="p", zstd=True)
        cut = zstd_raw(_json(doc).encode("utf-8"))[:-20]
        db = self.database([self.row(None, tid="a", cell=cut,
                                     data_type="zstd"),
                            self.row(None, tid="b", cell=b"not zstd",
                                     data_type="zstd"),
                            good])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual([c.session for c in self.calls(db)], ["p"])
        self.assertEqual(self.src.counts["unparsed"], 3 - 1)

    def test_the_hand_built_frame_is_a_zstd_frame(self):
        if not _zstd.available():
            self.skipTest("no zstd decoder here")
        data = b"x" * 200000
        self.assertEqual(_zstd.decompress(zstd_raw(data)), data)


# --------------------------------------------------------------------------
# What clean searches
# --------------------------------------------------------------------------

class Secrets(ZedCase):

    def test_output_after_cat_env_reaches_clean_with_its_origin(self):
        db = self.one([
            call_message("c", "terminal", {"command": "cat .env",
                                           "cd": "myproj"},
                         "STRIPE_KEY=" + SECRET + "\n"),
            user("my token is " + SECRET2)])
        found = self.found(db)
        self.assertEqual(found[SECRET], {".env"})
        self.assertIn(SECRET2, found)

    def test_the_result_is_tied_to_its_call(self):
        db = self.one([call_message("c", "terminal", {"command": "cat .env"},
                                    "K=" + SECRET)])
        tied = [t for t in self.texts(db) if t.call is not None]
        self.assertEqual(len(tied), 1)
        self.assertEqual((tied[0].call.tool_call_id, tied[0].call.command),
                         ("c", "cat .env"))
        self.assertIn("K=" + SECRET, json.dumps(tied[0].node))
        rest = [t for t in self.texts(db)
                if t.call is None and t.where == tied[0].where]
        self.assertEqual(len(rest), 1)
        self.assertNotIn(SECRET, json.dumps(rest[0].node))
        self.assertIn('"c"', json.dumps(rest[0].node))

    def test_the_summary_and_the_rest_of_the_thread_are_searched(self):
        db = self.database([self.row(
            thread([user("hi")], draft_prompt="note " + SECRET,
                   detailed_summary="sum " + SECRET2),
            summary="title " + PW)])
        flat = json.dumps([t.node for t in self.texts(db)])
        for value in (PW, SECRET, SECRET2):
            self.assertIn(value, flat)

    def test_the_model_configuration_is_not_searched(self):
        db = self.one([user("hi")])
        self.assertNotIn(KEY, json.dumps([t.node for t in self.texts(db)]))

    def test_a_store_is_read_only(self):
        db = self.one([call_message("c", "terminal", {"command": "cat .env"},
                                    "K=" + SECRET)])
        store = self.store(db)
        before = _files(db)
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(db, skipped="read-only"))
        self.assertEqual(_files(db), before)
        self.assertFalse(os.path.exists(self.backups))


PW = "Vb6nM3qW" "z8Kt2Lp5Rx"


# --------------------------------------------------------------------------
# Damaged stores
# --------------------------------------------------------------------------

class Damaged(ZedCase):

    def write_db(self, raw):
        os.makedirs(self.folder, exist_ok=True)
        with open(self.db_path, "wb") as fh:
            fh.write(raw)
        return self.db_path

    def good(self, tid="good"):
        return self.row(thread([call_message("g", "terminal",
                                             {"command": "ls"}, "o")]),
                        tid=tid)

    def test_not_a_database_warns_once_and_yields_nothing(self):
        path = self.write_db(b"not a database " + SECRET.encode())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(path), [])
            self.assertEqual(self.texts(path), [])
        self.assertEqual(err.getvalue().count("warning"), 1)
        self.assertNotIn(SECRET, err.getvalue())
        self.assertEqual(self.src.unreadable, {zed_module.NOT_DATABASE: 1})

    def test_an_empty_store_holds_nothing(self):
        path = self.write_db(b"")
        self.assertEqual((self.calls(path), self.texts(path)), ([], []))
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_an_empty_table_holds_nothing(self):
        path = self.database()
        self.assertEqual((self.calls(path), self.texts(path)), ([], []))
        self.assertEqual(sum(self.src.counts.values()), 0)

    def test_a_truncated_database(self):
        rows = [self.row(thread([call_message(
            "c%d" % i, "terminal", {"command": "ls %d" % i}, "o" * 500)]),
            tid="t%d" % i) for i in range(60)]
        path = self.database(rows, wal=False)
        with open(path, "rb") as fh:
            raw = fh.read()
        self.write_db(raw[:len(raw) // 2])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self.calls(path)
        self.assertLess(len(calls), 60)
        self.assertNotIn("ooo", err.getvalue())

    def test_a_database_with_other_tables(self):
        os.makedirs(self.folder)
        conn = sqlite3.connect(self.db_path)
        conn.executescript("CREATE TABLE other (x); INSERT INTO other "
                           "VALUES ('%s')" % SECRET)
        conn.commit()
        conn.close()
        self.assertEqual((self.calls(), self.texts()), ([], []))
        self.assertEqual(self.src.counts["unknown"], 1)

    def test_a_table_without_data(self):
        self.database(schema="CREATE TABLE threads (id TEXT, summary TEXT);")
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.src.counts["unknown"], 1)

    def test_a_row_that_is_not_json(self):
        db = self.database([self.row(b"{not json at all", tid="a"),
                            self.row(b"", tid="b"), self.good()])
        self.assertEqual([c.session for c in self.calls(db)], ["good"])
        self.assertEqual(self.src.counts["unparsed"], 2)

    def test_a_truncated_thread(self):
        raw = _json(thread([call_message("c", "terminal", {"command": "ls"},
                                         "o")])).encode("utf-8")
        db = self.database([self.row(raw[:len(raw) // 2], tid="a"),
                            self.good()])
        self.assertEqual([c.session for c in self.calls(db)], ["good"])
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_non_utf8_bytes_are_kept(self):
        doc = thread([call_message("c", "terminal", {"command": "echo hi"},
                                   "caf\u00e9 PLACEHOLDER")])
        raw = _json(doc).encode("utf-8").replace(b"PLACEHOLDER", b"\xff\xfe")
        db = self.database([self.row(raw)])
        [call] = self.calls(db)
        self.assertEqual(call.command, "echo hi")
        self.assertIn("\udcff", call.output)
        self.assertEqual(len(self.texts(db)) > 0, True)

    def test_non_utf8_text_in_a_text_column(self):
        os.makedirs(self.folder)
        conn = sqlite3.connect(self.db_path)
        conn.executescript(SCHEMA)
        doc = _json(thread([call_message("c", "terminal", {"command": "ls"},
                                         "o")]))
        conn.execute("INSERT INTO threads (id, summary, updated_at, "
                     "data_type, data) VALUES (CAST(? AS TEXT), CAST(? AS "
                     "TEXT), ?, 'json', ?)",
                     (b"id\xff", b"sum\xff", UPDATED, doc))
        conn.commit()
        conn.close()
        [call] = self.calls()
        self.assertEqual(call.session, "id\udcff")
        self.assertTrue(self.texts())

    def test_a_document_that_is_not_an_object(self):
        db = self.database([self.row(b"[1, 2]", tid="a"),
                            self.row(b"\"s\"", tid="b"), self.good()])
        self.assertEqual([c.session for c in self.calls(db)], ["good"])
        self.assertEqual(self.src.counts["unknown"], 2)

    def test_wrong_types_everywhere(self):
        msgs = [
            None, 7, "Other", [], {"Agent": None}, {"Agent": {"content": 5}},
            {"Agent": {"content": [None, 3, {"ToolUse": None},
                                   {"ToolUse": {}},
                                   {"ToolUse": {"id": 1, "name": 2}},
                                   {"ToolUse": {"id": "x", "name": "terminal",
                                                "input": 12}}],
                       "tool_results": {"x": "text", "y": None, 3: {}}}},
            {"Agent": {"content": [], "tool_results": [1, None, {}]}},
            {"role": "assistant", "tool_uses": "x", "tool_results": 5},
            {"role": "assistant", "tool_uses": [None, {"id": "q"}]},
            {"Mystery": {}},
            call_message("ok", "terminal", {"command": "ls"}, "o"),
        ]
        db = self.one(msgs)
        calls = self.calls(db)
        self.assertIn("ok", [c.tool_call_id for c in calls])
        self.assertGreater(self.src.counts["unreadable_calls"], 0)
        self.assertGreater(self.src.counts["unknown"], 0)
        self.texts(db)

    def test_messages_that_are_not_a_list(self):
        for value in (None, {}, "x", 4):
            with self.subTest(value=value):
                doc = thread([])
                doc["messages"] = value
                db = self.database(
                    [self.row(doc)],
                    path=os.path.join(self.home, "m%r" % id(value),
                                      "threads.db"))
                store = self.store(db)
                self.assertEqual(list(self.src.tool_calls(store)), [])
                list(self.src.secret_texts(store))

    def test_columns_of_the_wrong_type(self):
        os.makedirs(self.folder)
        conn = sqlite3.connect(self.db_path)
        conn.executescript("CREATE TABLE threads (id, summary, updated_at, "
                           "data_type, data, folder_paths, created_at);")
        doc = _json(thread([call_message("c", "terminal", {"command": "ls"},
                                         "o")]))
        conn.execute("INSERT INTO threads VALUES (5, 6.5, 7, 8, ?, 9, 10)",
                     (doc,))
        conn.execute("INSERT INTO threads VALUES (NULL, NULL, NULL, NULL, "
                     "NULL, NULL, NULL)")
        conn.execute("INSERT INTO threads VALUES ('i', 's', 'u', 'zstd', 42, "
                     "x'ff', 'c')")
        conn.commit()
        conn.close()
        [call] = self.calls()
        self.assertEqual((call.command, call.session, call.project),
                         ("ls", None, None))
        self.texts()

    def test_nested_past_the_stack(self):
        raw = ("[" * 100000 + "]" * 100000).encode("ascii")
        db = self.database([self.row(raw, tid="a"), self.good()])
        self.assertEqual([c.session for c in self.calls(db)], ["good"])

    def test_deep_input_does_not_stop_the_store(self):
        deep = "[" * 3000 + "]" * 3000
        doc = thread([agent([{"ToolUse": {"id": "d", "name": "terminal",
                                          "raw_input": deep}}]),
                      call_message("c", "terminal", {"command": "ls"}, "o")])
        db = self.database([self.row(doc)])
        self.assertIn("c", [c.tool_call_id for c in self.calls(db)])

    def test_an_oversized_thread_is_skipped_not_loaded(self):
        db = self.database([self.row(thread(
            [call_message("c", "terminal", {"command": "ls"}, "x" * 5000)]),
            tid="big"), self.good()])
        err = io.StringIO()
        with mock.patch.object(zed_module, "MAX_STORED", 2000), \
                contextlib.redirect_stderr(err):
            self.assertEqual([c.session for c in self.calls(db)], ["good"])
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_a_large_thread_is_read(self):
        out = "line of output\n" * 200000
        db = self.one([call_message("c", "terminal", {"command": "ls"}, out)])
        [call] = self.calls(db)
        self.assertEqual(len(call.output), len(out))

    def test_a_reader_that_fails_says_what_failed_not_its_message(self):
        db = self.one([call_message("c", "terminal", {"command": "ls"}, "o")])
        store = self.store(db)

        def boom(*_a, **_k):
            raise sqlite3.DatabaseError("malformed near " + SECRET)

        err = io.StringIO()
        with mock.patch.object(_sqlite, "iter_rows", boom), \
                mock.patch.object(_sqlite, "columns", boom), \
                contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertNotIn(SECRET, err.getvalue())
        self.assertEqual(self.src.unreadable, {zed_module.DAMAGED: 1})

    def test_an_unexpected_error_is_said_and_not_raised(self):
        db = self.one([call_message("c", "terminal", {"command": "ls"}, "o")])
        store = self.store(db)
        err = io.StringIO()
        with mock.patch.object(ZedSource, "_call",
                               side_effect=KeyError(SECRET)), \
                contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(list(self.src.secret_texts(store)) != [], True)
        self.assertNotIn(SECRET, err.getvalue())
        self.assertGreaterEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_locked_database_is_read_from_a_copy_that_is_removed(self):
        db = self.one([call_message("c", "terminal", {"command": "ls"},
                                    "K=" + SECRET)])
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
        db = self.database([self.good("a"), self.good("b")])
        real = sqlite3.connect
        opened = []

        def locked(*args, **kwargs):
            opened.append(args[0])
            if len(opened) == 1:
                raise sqlite3.OperationalError("database is locked")
            return real(*args, **kwargs)

        with mock.patch.object(_sqlite.sqlite3, "connect", side_effect=locked):
            calls = self.src.tool_calls(self.store(db))
            next(calls)
            calls.close()

    def test_an_unreadable_file(self):
        db = self.database([self.good()])
        store = self.store(db)
        os.remove(db)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db + suffix):
                os.remove(db + suffix)
        self.assertEqual(list(self.src.tool_calls(store)), [])


# --------------------------------------------------------------------------
# The database is never written
# --------------------------------------------------------------------------

def _live(path, rows):
    """Zed running: the database in WAL mode, its writer open, every row
    committed into the -wal."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    ZedCase.fill(conn, rows)
    conn.execute("SELECT count(*) FROM threads").fetchall()
    return conn


class NeverWritten(ZedCase):

    def rows(self):
        return [self.row(thread([
            call_message("c1", "terminal", {"command": "cat .env"},
                         "API_KEY=" + SECRET + "\n"),
            call_message("c2", "terminal", {"command": "rm -rf ~/Documents/x"},
                         "")]))]

    def read_everything(self):
        store = self.store(self.db_path)
        calls = list(self.src.tool_calls(store))
        self.assertEqual(len(calls), 2)
        self.assertIn("fs.destructive", rules(calls[1]))
        self.assertGreater(len(list(self.src.secret_texts(store))), 0)
        self.assertEqual(self.found(self.db_path)[SECRET], {".env"})
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(self.db_path, skipped="read-only"))

    def test_with_its_writer_open(self):
        writer = _live(self.db_path, self.rows())
        self.addCleanup(writer.close)
        before = _files(self.db_path)
        self.assertEqual(sorted(before), ["", "-shm", "-wal"])
        self.read_everything()
        self.assertEqual(_files(self.db_path), before)
        self.assertEqual(sorted(os.listdir(self.folder)),
                         ["threads.db", "threads.db-shm", "threads.db-wal"])
        self.assertFalse(os.path.exists(self.backups))

    def test_with_its_writer_closed(self):
        _live(self.db_path, self.rows()).close()
        for suffix in ("-wal", "-shm"):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)
        before = _files(self.db_path)
        self.assertEqual(sorted(before), [""])
        self.read_everything()
        self.assertEqual(_files(self.db_path), before)
        self.assertEqual(os.listdir(self.folder), ["threads.db"])

    def test_with_a_wal_and_no_shm(self):
        live = os.path.join(self.home, "live", "threads.db")
        writer = _live(live, self.rows())
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
                         ["threads.db", "threads.db-wal"])


if __name__ == "__main__":
    unittest.main()
