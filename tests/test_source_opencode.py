"""The OpenCode adapter (ranwhat/sources/opencode.py).

Fixtures are built field for field from OpenCode's own source (v2.0.24,
v1.18.35, v1.2.0, v1.1.65): the database's v1 tables (session, message,
part; data columns compact JSON less the ids the columns hold) and v2
tables (session_v2, session_message; data the message less id and type),
and the JSON tree of v1.1.x (storage/session|message|part, pretty-printed
with two spaces, as Bun.write(JSON.stringify(x, null, 2)) writes it).

Everything runs in temp directories: the home directory, XDG_DATA_HOME,
OPENCODE_DB and clean's backup root all point there, and the real home is
never read. Every secret is synthetic, and token-shaped ones are written as
adjacent literals.
"""
import contextlib
import hashlib
import io
import json
import os
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
from ranwhat.sources import _paths, _rewrite  # noqa: E402
from ranwhat.sources import opencode  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.opencode import OpenCodeSource  # noqa: E402

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
SECRET2 = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"
PROVIDER_KEY = "sk-" "ant-" "api03-Hq3nV8xKp2Lw7RtY9mZc4BfDq1Ws2Ed3Rf4"
TOKEN = "gh" "p_" "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Y"

# 2026-10-01T09:00:00Z in milliseconds.
BASE = 1790845200000
SID = "ses_6b2f0c1d9ffeA1b2C3d4E5f6G7"
PID = "4b0ea68d7af9a6031a7ffda7ad66e0cb83315750"
CWD = "/home/alice/src/app"
WINDOWS = os.name == "nt"


def _iso(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000.0))


def _compact(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _files(path):
    """{suffix: bytes} for a database, its -wal and its -shm."""
    out = {}
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            with open(path + suffix, "rb") as fh:
                out[suffix] = fh.read()
    return out


def rules(call):
    return [(h["rule"], h["evidence"]) for h in watch.judge(call)[0]]


# --------------------------------------------------------------------------
# OpenCode's records
# --------------------------------------------------------------------------

def v1_tool(call_id, tool, inp, status="completed", output="", start=BASE,
            error=None, **extra):
    """A v1 ToolPart's data (schema v1/session.ts ToolState)."""
    state = {"status": status, "input": inp}
    if status == "completed":
        state.update(output=output, title="", metadata={"output": output},
                     time={"start": start, "end": start + 1000})
    elif status == "error":
        state.update(error=error, time={"start": start, "end": start + 1000})
    elif status == "running":
        state.update(time={"start": start})
    elif status == "pending":
        state.update(raw="")
    state.update(extra)
    return {"type": "tool", "callID": call_id, "tool": tool, "state": state}


def assistant(parent=None, created=BASE, cwd=CWD):
    msg = {"role": "assistant", "time": {"created": created,
                                         "completed": created + 9000},
           "modelID": "claude-sonnet-4-5", "providerID": "anthropic",
           "mode": "build", "agent": "build",
           "path": {"cwd": cwd, "root": cwd}, "cost": 0.01,
           "tokens": {"input": 1, "output": 1, "reasoning": 0,
                      "cache": {"read": 0, "write": 0}},
           "finish": "tool-calls"}
    if parent:
        msg["parentID"] = parent
    return msg


def user(created=BASE):
    return {"role": "user", "time": {"created": created}, "agent": "build",
            "model": {"providerID": "anthropic", "modelID": "claude-sonnet-4-5"}}


MARKER = {"type": "text", "text": "The following tool was executed by the user",
          "synthetic": True}

V1_DDL = """
CREATE TABLE session (
  id text PRIMARY KEY, project_id text NOT NULL, workspace_id text, parent_id text,
  slug text NOT NULL, directory text NOT NULL, path text, title text NOT NULL, version text NOT NULL,
  share_url text, summary_additions integer, summary_deletions integer, summary_files integer,
  summary_diffs text, metadata text, cost real DEFAULT 0 NOT NULL,
  tokens_input integer DEFAULT 0 NOT NULL, tokens_output integer DEFAULT 0 NOT NULL,
  tokens_reasoning integer DEFAULT 0 NOT NULL, tokens_cache_read integer DEFAULT 0 NOT NULL,
  tokens_cache_write integer DEFAULT 0 NOT NULL, revert text, permission text, agent text, model text,
  time_created integer NOT NULL, time_updated integer NOT NULL, time_compacting integer, time_archived integer);
CREATE TABLE message (id text PRIMARY KEY, session_id text NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL);
CREATE TABLE part (id text PRIMARY KEY, message_id text NOT NULL REFERENCES message(id) ON DELETE CASCADE,
  session_id text NOT NULL, time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL);
CREATE TABLE session_share (session_id text PRIMARY KEY, id text NOT NULL, secret text NOT NULL,
  url text NOT NULL, time_created integer NOT NULL, time_updated integer NOT NULL);
CREATE TABLE credential (id text PRIMARY KEY, integration_id text, label text NOT NULL,
  value text NOT NULL, connector_id text, method_id text, active integer,
  time_created integer NOT NULL, time_updated integer NOT NULL);
CREATE TABLE account (id text PRIMARY KEY, email text NOT NULL, url text NOT NULL,
  access_token text NOT NULL, refresh_token text NOT NULL, token_expiry integer,
  time_created integer NOT NULL, time_updated integer NOT NULL);
CREATE TABLE control_account (email text NOT NULL, url text NOT NULL, access_token text NOT NULL,
  refresh_token text NOT NULL, token_expiry integer, active integer NOT NULL,
  time_created integer NOT NULL, time_updated integer NOT NULL);
CREATE TABLE event (id text PRIMARY KEY, aggregate_id text NOT NULL, seq integer NOT NULL,
  created integer DEFAULT 0 NOT NULL, type text NOT NULL, data text NOT NULL);
CREATE TABLE kv (key text PRIMARY KEY, value text NOT NULL, time_created integer NOT NULL,
  time_updated integer NOT NULL);
"""

V2_DDL = """
CREATE TABLE session_v2 (
  id text PRIMARY KEY, project_id text NOT NULL, workspace_id text, parent_id text,
  fork_session_id text, fork_boundary text, slug text NOT NULL, directory text NOT NULL, path text,
  title text, version text NOT NULL, share_url text, summary_additions integer,
  summary_deletions integer, summary_files integer, summary_diffs text, metadata text,
  cost real DEFAULT 0 NOT NULL, tokens_input integer DEFAULT 0 NOT NULL,
  tokens_output integer DEFAULT 0 NOT NULL, tokens_reasoning integer DEFAULT 0 NOT NULL,
  tokens_cache_read integer DEFAULT 0 NOT NULL, tokens_cache_write integer DEFAULT 0 NOT NULL,
  revert text, permission text, agent text, model text, time_created integer NOT NULL,
  time_updated integer NOT NULL, time_idle integer, time_viewed integer, idle_outcome text,
  time_compacting integer, time_archived integer, time_suspended integer,
  resume_attempts integer DEFAULT 0 NOT NULL);
CREATE TABLE session_message (
  id text PRIMARY KEY, session_id text NOT NULL, type text NOT NULL, seq integer NOT NULL,
  time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL);
CREATE UNIQUE INDEX session_message_session_seq_idx ON session_message (session_id, seq);
"""


class V1Db(object):
    """A v1 opencode.db (v1.2.0 to v1.18.x), rows added as OpenCode
    writes them."""

    def __init__(self, path, v2=False, wal=False):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(path)
        if wal:
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(V1_DDL + (V2_DDL if v2 else ""))
        self.n = 0
        self.seq = {}

    def session(self, sid=SID, directory=CWD, title="Fix failing tests"):
        self.conn.execute(
            "INSERT INTO session (id, project_id, slug, directory, title, "
            "version, time_created, time_updated) VALUES (?,?,?,?,?,?,?,?)",
            (sid, PID, "quiet-river", directory, title, "1.18.35", BASE, BASE))
        return sid

    def message(self, data, sid=SID, mid=None):
        self.n += 1
        mid = mid or "msg_%04dAbC" % self.n
        created = data.get("time", {}).get("created", BASE)
        self.conn.execute("INSERT INTO message VALUES (?,?,?,?,?)",
                          (mid, sid, created, created, _compact(data)))
        return mid

    def part(self, mid, data, sid=SID):
        self.n += 1
        pid = "prt_%04dQwE" % self.n
        self.conn.execute("INSERT INTO part VALUES (?,?,?,?,?,?)",
                          (pid, mid, sid, BASE, BASE, _compact(data)))
        return pid

    def v2_session(self, sid=SID, directory=CWD, title="Fix failing tests"):
        self.conn.execute(
            "INSERT INTO session_v2 (id, project_id, slug, directory, title, "
            "version, time_created, time_updated) VALUES (?,?,?,?,?,?,?,?)",
            (sid, PID, "quiet-river", directory, title, "2.0.24", BASE, BASE))
        return sid

    def row(self, kind, data, sid=SID, created=BASE):
        self.n += 1
        seq = self.seq.get(sid, 0)
        self.seq[sid] = seq + 1
        mid = "msg_%04dXyZ" % self.n
        self.conn.execute("INSERT INTO session_message VALUES (?,?,?,?,?,?,?)",
                          (mid, sid, kind, seq, created, created,
                           _compact(data)))
        return mid

    def close(self):
        self.conn.commit()
        self.conn.close()


def v2_assistant(*tools, created=BASE):
    return {"agent": "build",
            "model": {"id": "claude-sonnet-4-5", "providerID": "anthropic"},
            "time": {"created": created, "completed": created + 9000},
            "content": [{"type": "text", "text": "Working on it."}] + list(tools),
            "finish": "tool-calls"}


def v2_tool(call_id, name, inp, status="completed", text="", created=BASE,
            error=None, metadata=None):
    state = {"status": status, "input": inp}
    if status == "completed":
        state["content"] = [{"type": "text", "text": text}]
    if error is not None:
        state["error"] = error
    if metadata is not None:
        state["metadata"] = metadata
    return {"type": "tool", "id": call_id, "name": name, "state": state,
            "time": {"created": created, "completed": created + 1000}}


# --------------------------------------------------------------------------
# Common setup
# --------------------------------------------------------------------------

class _Case(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="oc-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.data = os.path.join(self.home, ".local", "share", "opencode")
        os.makedirs(self.data)
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for name in ("XDG_DATA_HOME", "OPENCODE_DB"):
            os.environ.pop(name, None)
        self.backups = os.path.join(self.home, "backups")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.src = OpenCodeSource()
        self.err = io.StringIO()
        p = contextlib.redirect_stderr(self.err)
        p.__enter__()
        self.addCleanup(p.__exit__, None, None, None)

    def db(self, name="opencode.db", **kw):
        return V1Db(os.path.join(self.data, name), **kw)

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
        """{value: origins} as clean credits them, for one store."""
        values = {}
        findings, _masks = clean.scan_store(self.src, self.store(path), values)
        return {values[fp]: f["origins"] for fp, f in findings.items()}

    def write_json(self, rel, obj, pretty=True, age=3600, raw=None):
        path = os.path.join(self.data, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if raw is None:
            raw = (json.dumps(obj, indent=2, ensure_ascii=False) if pretty
                   else _compact(obj)).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def json_session(self, sid=SID, messages=(), **kw):
        """storage/ for one v1.1.x session: [(message, [parts])]."""
        path = self.write_json("storage/session/%s/%s.json" % (PID, sid), {
            "id": sid, "slug": "quiet-river", "version": "1.1.65",
            "projectID": PID, "directory": CWD, "title": "Fix failing tests",
            "time": {"created": BASE, "updated": BASE + 1}}, **kw)
        n, last_user = 0, None
        for message, parts in messages:
            n += 1
            mid = "msg_%s%04d" % (sid[-4:], n)
            if message.get("role") == "user":
                last_user = mid
            elif last_user and "parentID" not in message:
                message = dict(message, parentID=last_user)
            self.write_json("storage/message/%s/%s.json" % (sid, mid),
                            dict(message, id=mid, sessionID=sid), **kw)
            for part in parts:
                n += 1
                pid = "prt_%s%04d" % (sid[-4:], n)
                self.write_json("storage/part/%s/%s.json" % (mid, pid),
                                dict(part, id=pid, sessionID=sid,
                                     messageID=mid), **kw)
        return path


# --------------------------------------------------------------------------
# Where OpenCode keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = OpenCodeSource()

    def test_the_same_xdg_rule_on_every_system(self):
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.local/share/opencode", "default")])
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.local/share/opencode", "default")])
        self.assertEqual(self.src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.local\\share\\opencode", "default")])

    def test_xdg_data_home(self):
        env = {"XDG_DATA_HOME": "/srv/data"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/srv/data/opencode", "env XDG_DATA_HOME")])
        self.assertEqual(self.src.default_paths(env, "/Users/u", "darwin"),
                         [("/srv/data/opencode", "env XDG_DATA_HOME")])
        self.assertEqual(
            self.src.default_paths({"XDG_DATA_HOME": "D:\\xdg"}, "C:\\Users\\u",
                                   "win32"),
            [("D:\\xdg\\opencode", "env XDG_DATA_HOME")])
        # empty is unset, as OpenCode's `||` reads it
        self.assertEqual(self.src.default_paths({"XDG_DATA_HOME": ""},
                                                "/home/u", "linux"),
                         [("/home/u/.local/share/opencode", "default")])

    def test_opencode_db(self):
        data = "/home/u/.local/share/opencode"
        self.assertEqual(
            self.src.default_paths({"OPENCODE_DB": "/srv/oc.db"}, "/home/u",
                                   "linux"),
            [(data, "default"), ("/srv/oc.db", "env OPENCODE_DB")])
        self.assertEqual(
            self.src.default_paths({"OPENCODE_DB": "work.db"}, "/home/u",
                                   "linux"),
            [(data, "default"), (data + "/work.db", "env OPENCODE_DB")])
        self.assertEqual(
            self.src.default_paths({"OPENCODE_DB": "D:\\oc.db"}, "C:\\Users\\u",
                                   "win32")[1],
            ("D:\\oc.db", "env OPENCODE_DB"))
        for value in (":memory:", ""):
            self.assertEqual(
                self.src.default_paths({"OPENCODE_DB": value}, "/home/u",
                                       "linux"), [(data, "default")])

    def test_class_attributes(self):
        self.assertEqual((self.src.id, self.src.name, self.src.unit),
                         ("opencode", "OpenCode", "file"))
        self.assertEqual(self.src.env, ("OPENCODE_DB",))
        self.assertFalse(self.src.read_only)
        self.assertTrue(self.src.checked)

    def test_importing_it_imports_neither_watch_nor_clean(self):
        import subprocess
        code = ("import sys; import ranwhat.sources.opencode; "
                "print('ranwhat.watch' in sys.modules, 'ranwhat.clean' in "
                "sys.modules)")
        out = subprocess.run([sys.executable, "-c", code], cwd=REPO,
                             capture_output=True, text=True)
        self.assertEqual(out.stdout.split(), ["False", "False"], out.stderr)


class Discovery(_Case):

    def test_what_is_a_store_and_what_is_not(self):
        for name in ("opencode.db", "opencode-local.db", "opencode-next.db"):
            self.db(name).close()
        for name in ("other.db", "opencode.db-wal", "opencode.db-shm",
                     "auth.json", "mcp-auth.json"):
            with open(os.path.join(self.data, name), "w", encoding="utf-8") as fh:
                fh.write("{}")
        os.makedirs(os.path.join(self.data, "opencode-dir.db"))
        session = self.json_session(messages=[
            (assistant(), [v1_tool("c1", "bash", {"command": "ls"})])])
        self.write_json("storage/session_share/%s.json" % SID,
                        {"id": "x", "secret": SECRET, "url": "https://x"})
        self.write_json("storage/project/%s.json" % PID, {"id": PID})
        diff = self.write_json("storage/session_diff/%s.json" % SID, [])
        todo = self.write_json("storage/todo/%s.json" % SID, [])
        out = os.path.join(self.data, "tool-output", "tool_0123456789abXyZ")
        os.makedirs(os.path.dirname(out))
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("full output\n")
        with open(os.path.join(self.data, "tool-output", "notes.txt"), "w", encoding="utf-8") as fh:
            fh.write("x")
        os.makedirs(os.path.join(self.data, "snapshot", PID))
        with open(os.path.join(self.data, "snapshot", PID, "HEAD"), "w", encoding="utf-8") as fh:
            fh.write("ref")
        got = {os.path.relpath(s.path, self.data).replace(os.sep, "/"):
               (s.format, s.role, s.unit, s.masking) for s in self.stores()}
        parts = [k for k in got if k.startswith("storage/part/")]
        messages = [k for k in got if k.startswith("storage/message/")]
        self.assertEqual(len(parts), 1)
        self.assertEqual(len(messages), 1)
        self.assertEqual(got.pop(parts[0]), ("json", "side", "part", "rewrite"))
        self.assertEqual(got.pop(messages[0]),
                         ("json", "side", "message", "rewrite"))
        self.assertEqual(got, {
            "opencode.db": ("sqlite", "transcript", "database", "read-only"),
            "opencode-local.db": ("sqlite", "transcript", "database",
                                  "read-only"),
            "opencode-next.db": ("sqlite", "transcript", "database",
                                 "read-only"),
            os.path.relpath(session, self.data).replace(os.sep, "/"):
                ("json", "transcript", "session", "rewrite"),
            os.path.relpath(diff, self.data).replace(os.sep, "/"):
                ("json", "side", "session_diff", "rewrite"),
            os.path.relpath(todo, self.data).replace(os.sep, "/"):
                ("json", "side", "todo", "rewrite"),
            "tool-output/tool_0123456789abXyZ":
                ("text", "side", "tool output", "rewrite"),
        })
        store = self.store(session)
        self.assertEqual((store.session, store.project), (SID, CWD))
        self.assertEqual(self.store(os.path.join(self.data, "opencode.db"))
                         .why_read_only, opencode.WHY_READ_ONLY)

    def test_newest_first_and_a_session_as_new_as_its_newest_part(self):
        old = self.json_session(sid="ses_old0000000000000000000001", age=86400 * 40)
        new = self.json_session(sid="ses_new0000000000000000000002", age=60)
        transcripts = [s.path for s in self.stores() if s.role == "transcript"]
        self.assertEqual(transcripts, [new, old])
        # a part written after its session file keeps the session in --days
        old_sid = "ses_old0000000000000000000003"
        path = self.json_session(sid=old_sid, age=86400 * 40, messages=[
            (assistant(), [v1_tool("c9", "bash", {"command": "ls"})])])
        for root, _dirs, names in os.walk(os.path.join(self.data, "storage",
                                                        "part")):
            for name in names:
                os.utime(os.path.join(root, name))
        kept = [s.path for s in self.stores(since_days=7)
                if s.role == "transcript"]
        self.assertIn(path, kept)
        self.assertNotIn(old, kept)

    def test_a_missing_folder_is_no_stores(self):
        shutil.rmtree(self.data)
        self.assertEqual(self.stores(), [])
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (False, 0))

    def test_xdg_data_home_and_opencode_db(self):
        moved = os.path.join(self.home, "xdg")
        V1Db(os.path.join(moved, "opencode", "opencode.db")).close()
        elsewhere = os.path.join(self.home, "elsewhere", "mine.sqlite")
        V1Db(elsewhere).close()
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": moved,
                                          "OPENCODE_DB": elsewhere}):
            locs = self.src.locations()
            self.assertEqual([(l.how, l.found) for l in locs],
                             [("env XDG_DATA_HOME", 1), ("env OPENCODE_DB", 1)])
            self.assertEqual(sorted(s.path for s in self.stores()),
                             sorted([os.path.join(moved, "opencode",
                                                  "opencode.db"), elsewhere]))
        # a bare name is a file in the data folder, whatever it is called
        self.db("work.sqlite").close()
        with mock.patch.dict(os.environ, {"OPENCODE_DB": "work.sqlite"}):
            self.assertIn(os.path.join(self.data, "work.sqlite"),
                          [s.path for s in self.stores()])
        # --path takes a database file too
        self.assertEqual([s.path for s in self.stores(override=elsewhere)],
                         [elsewhere])


# --------------------------------------------------------------------------
# Tool calls: v1 tables
# --------------------------------------------------------------------------

class V1Calls(_Case):

    def test_every_mapped_tool(self):
        db = self.db()
        db.session()
        u = db.message(user())
        m = db.message(assistant(parent=u))
        patch = ("*** Begin Patch\n*** Add File: new.txt\n+hi\n"
                 "*** Update File: src/a.ts\n*** Move to: src/b.ts\n@@\n-x\n+y\n"
                 "*** Delete File: old.txt\n*** End Patch")
        specs = [
            ("bash", {"command": "npm test", "description": "Run tests"}),
            ("bash", {"command": "make", "workdir": "/tmp/w", "description": "d"}),
            ("read", {"filePath": "/home/alice/src/app/.env"}),
            ("write", {"filePath": "a.txt", "content": "x"}),
            ("edit", {"filePath": "b.txt", "oldString": "a", "newString": "b"}),
            ("multiedit", {"filePath": "c.txt", "edits": [
                {"filePath": "c.txt", "oldString": "a", "newString": "b"},
                {"filePath": "d.txt", "oldString": "a", "newString": "b"}]}),
            ("apply_patch", {"patchText": patch}),
            ("webfetch", {"url": "https://example.com", "format": "text"}),
            ("websearch", {"query": "q"}),
            ("glob", {"pattern": "*.py"}),
            ("task", {"description": "d", "prompt": "p", "subagent_type": "general"}),
            ("github_create_issue", {"title": "t"}),
        ]
        for n, (tool, inp) in enumerate(specs):
            db.part(m, v1_tool("c%d" % n, tool, inp, output="out%d" % n,
                               start=BASE + n * 1000))
        db.close()
        got = self.by_id(db.path)
        shape = {cid: (c.tool_name, c.kind, c.known, c.command, c.paths,
                       c.workdir, tuple(sorted(c.consumed)))
                 for cid, c in got.items()}
        self.assertEqual(shape, {
            "c0": ("bash", "shell", True, "npm test", (), CWD, ("command",)),
            "c1": ("bash", "shell", True, "make", (), "/tmp/w", ("command",)),
            "c2": ("read", "read", True, None, ("/home/alice/src/app/.env",),
                   None, ("filePath",)),
            "c3": ("write", "write", True, None, ("a.txt",), None, ()),
            "c4": ("edit", "write", True, None, ("b.txt",), None, ()),
            "c5": ("multiedit", "write", True, None, ("c.txt", "d.txt"), None, ()),
            "c6": ("apply_patch", "write", True, None,
                   ("new.txt", "src/a.ts", "src/b.ts", "old.txt"), None, ()),
            "c7": ("webfetch", "fetch", True, None, (), None, ()),
            "c8": ("websearch", "fetch", True, None, (), None, ()),
            "c9": ("glob", "other", True, None, (), None, ()),
            "c10": ("task", "other", True, None, (), None, ()),
            "c11": ("github_create_issue", "other", False, None, (), None, ()),
        })
        for n in range(len(specs)):
            call = got["c%d" % n]
            self.assertEqual((call.output, call.timestamp, call.session,
                              call.project, call.actor, call.status,
                              call.source, call.store),
                             ("out%d" % n, _iso(BASE + n * 1000), SID, CWD,
                              "agent", None, "opencode", db.path))

    def test_declined_and_not(self):
        db = self.db()
        db.session()
        m = db.message(assistant())
        cases = {
            "rej": ("Error: The user rejected permission to use this specific "
                    "tool call.", "error", {}),
            "rej18": ("The user rejected permission to use this specific tool "
                      "call.", "error", {}),
            "legacy": ("Error: The user rejected permission to use this "
                       "specific tool call. You may try again with different "
                       "parameters.", "error", {}),
            "fb": ("The user rejected permission to use this specific tool "
                   "call with the following feedback: use pnpm", "error", {}),
            "rule": ("The user has specified a rule which prevents you from "
                     "using this specific tool call. Here are some of the "
                     "relevant rules [{\"permission\":\"bash\"}]", "error", {}),
            "pend": ("Tool execution aborted", "error", {"raw": ""}),
            "ran": ("Tool execution aborted", "error",
                    {"metadata": {"interrupted": True}}),
            "fail": ("Command failed: exit 1", "error", {}),
            "custom": ("Error: no, not today", "error", {}),
        }
        for cid, (error, status, extra) in cases.items():
            db.part(m, v1_tool(cid, "bash", {"command": "rm -rf ~/Documents/x"},
                               status=status, error=error, **extra))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual({cid: c.status for cid, c in got.items()}, {
            "rej": "declined", "rej18": "declined", "legacy": "declined",
            "fb": "declined", "rule": "declined", "pend": "declined",
            "ran": None, "fail": None, "custom": None})
        self.assertEqual(got["fail"].output, "Command failed: exit 1")
        # declined or not, watch still sees it
        self.assertEqual(rules(got["rej"]),
                         [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_a_command_the_user_ran(self):
        db = self.db()
        db.session()
        u = db.message(user())
        db.part(u, MARKER)
        a = db.message(assistant(parent=u))
        db.part(a, v1_tool("bang", "bash", {"command": "cat ~/.aws/credentials"},
                           output="[default]"))
        # the same command from the agent, answering an ordinary prompt
        u2 = db.message(user())
        db.part(u2, {"type": "text", "text": "check my aws setup"})
        a2 = db.message(assistant(parent=u2))
        db.part(a2, v1_tool("agent", "bash", {"command": "cat ~/.aws/credentials"}))
        # the marker text not synthetic: typed by the user, not a "!" command
        u3 = db.message(user())
        db.part(u3, dict(MARKER, synthetic=False))
        a3 = db.message(assistant(parent=u3))
        db.part(a3, v1_tool("typed", "bash", {"command": "ls"}))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual({k: c.actor for k, c in got.items()},
                         {"bang": "user", "agent": "agent", "typed": "agent"})
        self.assertEqual(rules(got["bang"]),
                         [("cred.read", "cat ~/.aws/credentials")])

    def test_judged_as_watch_judges_every_agent(self):
        db = self.db()
        db.session()
        m = db.message(assistant())
        db.part(m, v1_tool("rm", "bash", {"command": "rm -rf ~/Documents/x"}))
        db.part(m, v1_tool("ssh", "read", {"filePath": "~/.ssh/id_rsa"}))
        db.part(m, v1_tool("aws", "read", {"filePath": "~/.aws/credentials"}))
        db.part(m, v1_tool("mcp", "srv.bash", {"command": "rm -rf ~/Documents/x"}))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual(rules(got["rm"]),
                         [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(got["ssh"]), [("cred.read", "~/.ssh/id_rsa")])
        self.assertEqual(rules(got["aws"]), [("cred.read", "~/.aws/credentials")])
        # an unknown tool is judged by its name and every string
        self.assertFalse(got["mcp"].known)
        self.assertEqual([r for r, _e in rules(got["mcp"])], ["fs.destructive"])

    def test_code_mode_calls_are_read(self):
        db = self.db()
        db.session()
        m = db.message(assistant())
        db.part(m, v1_tool("x1", "execute", {"code": "await tools.gh.run({})"},
                           output="done", metadata={"toolCalls": [
                               {"tool": "github.delete_repo", "status": "completed",
                                "input": {"repo": "acme/prod"}},
                               "junk",
                               {"tool": "shell.exec", "status": "error",
                                "input": {"cmd": "rm -rf ~/Documents/x"}}]}))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual(sorted(got), ["x1", "x1/1", "x1/3"])
        self.assertEqual((got["x1/1"].tool_name, got["x1/1"].known,
                          got["x1/1"].tool_input, got["x1/1"].timestamp),
                         ("github.delete_repo", False, {"repo": "acme/prod"},
                          _iso(BASE)))
        self.assertEqual([r for r, _e in rules(got["x1/3"])], ["fs.destructive"])

    def test_timestamps_fall_back_to_the_row(self):
        db = self.db()
        db.session()
        m = db.message(assistant())
        db.part(m, v1_tool("p", "bash", {"command": "ls"}, status="pending"))
        db.close()
        [call] = self.calls(db.path)
        self.assertEqual(call.timestamp, _iso(BASE))


# --------------------------------------------------------------------------
# Tool calls: v2 tables, and v1 rows v2 already holds
# --------------------------------------------------------------------------

class V2Calls(_Case):

    def test_every_mapped_tool(self):
        db = self.db(v2=True)
        db.v2_session()
        db.row("user", {"text": "go", "time": {"created": BASE}})
        db.row("assistant", v2_assistant(
            v2_tool("s", "shell", {"command": "npm test", "workdir": "/w"},
                    text="1 failing"),
            v2_tool("r", "read", {"path": ".env"}, text="1: API_KEY=x"),
            v2_tool("w", "write", {"path": "a.txt", "content": "x"}),
            v2_tool("e", "edit", {"path": "b.txt", "oldString": "a",
                                  "newString": "b"}),
            v2_tool("p", "patch", {"patchText": "*** Add File: n.txt\n+x"}),
            v2_tool("f", "webfetch", {"url": "https://example.com"}),
            v2_tool("a", "subagent", {"agent": "general", "prompt": "p",
                                      "description": "d"}),
            v2_tool("u", "linear_create", {"title": "t"}),
            # a v1 call copied into v2 keeps its v1 name and keys
            v2_tool("b", "bash", {"command": "make"}),
            v2_tool("rr", "read", {"filePath": "/etc/hosts"}),
            v2_tool("st", "shell", '{"command": "l', status="streaming")))
        db.close()
        got = self.by_id(db.path)
        shape = {cid: (c.tool_name, c.kind, c.known, c.command, c.paths,
                       c.workdir) for cid, c in got.items()}
        self.assertEqual(shape, {
            "s": ("shell", "shell", True, "npm test", (), "/w"),
            "r": ("read", "read", True, None, (".env",), None),
            "w": ("write", "write", True, None, ("a.txt",), None),
            "e": ("edit", "write", True, None, ("b.txt",), None),
            "p": ("patch", "write", True, None, ("n.txt",), None),
            "f": ("webfetch", "fetch", True, None, (), None),
            "a": ("subagent", "other", True, None, (), None),
            "u": ("linear_create", "other", False, None, (), None),
            "b": ("bash", "shell", True, "make", (), None),
            "rr": ("read", "read", True, None, ("/etc/hosts",), None),
            "st": ("shell", "shell", True, None, (), None),
        })
        self.assertEqual(got["s"].output, "1 failing")
        self.assertEqual(got["st"].tool_input, {"_raw": '{"command": "l'})
        self.assertEqual((got["s"].session, got["s"].project, got["s"].timestamp),
                         (SID, CWD, _iso(BASE)))

    def test_output_joins_the_text_items(self):
        db = self.db(v2=True)
        db.v2_session()
        tool = v2_tool("s", "shell", {"command": "npm test"})
        tool["state"]["content"] = [
            {"type": "text", "text": "> app@1.0.0 test\n1 failing"},
            {"type": "file", "uri": "data:image/png;base64,AAAA", "mime": "image/png"},
            {"type": "text", "text": "Exited with code 1"}]
        db.row("assistant", v2_assistant(tool))
        db.close()
        [call] = self.calls(db.path)
        self.assertEqual(call.output,
                         "> app@1.0.0 test\n1 failing\nExited with code 1")

    def test_declined_and_not(self):
        db = self.db(v2=True)
        db.v2_session()
        cmd = {"command": "rm -rf ~/Documents/x"}
        errors = {
            "dec": {"type": "aborted", "message": "The user declined this tool call"},
            "loc": {"type": "aborted", "message": "Interaction cancelled because "
                    "the location shut down"},
            "deny": {"type": "permission.rejected", "message": "Permission denied: bash"},
            "fb": {"type": "permission.rejected", "message": "use trash instead"},
            "json": {"type": "tool.input-json", "message": "Tool call arguments "
                     "were malformed JSON and were not executed. Retry with "
                     "valid JSON."},
            "mig": {"type": "tool.execution", "message": "Error: The user rejected "
                    "permission to use this specific tool call."},
            "int": {"type": "aborted", "message": "Tool execution interrupted"},
            "exec": {"type": "tool.execution", "message": "exit 1"},
            "old": {"type": "tool.interrupted", "message": "Tool execution was "
                    "interrupted before V2 migration"},
        }
        db.row("assistant", v2_assistant(*[
            v2_tool(cid, "shell", cmd, status="error", error=error)
            for cid, error in errors.items()]))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual({cid: c.status for cid, c in got.items()}, {
            "dec": "declined", "loc": "declined", "deny": "declined",
            "fb": "declined", "json": "declined", "mig": "declined",
            "int": None, "exec": None, "old": None})
        self.assertEqual(got["exec"].output, "exit 1")

    def test_commands_the_user_ran(self):
        db = self.db(v2=True)
        db.v2_session()
        db.row("shell", {"shellID": "sh_1", "command": "cat ~/.aws/credentials",
                         "status": "exited", "exit": 0,
                         "output": {"output": "[default]\n", "cursor": 10,
                                    "size": 10, "truncated": False},
                         "time": {"created": BASE + 5, "completed": BASE + 50}})
        db.row("synthetic", {"text": "The user ran cat", "time": {"created": BASE}})
        # a v1 "!" command copied into v2: synthetic marker, then assistant
        db.row("synthetic", {"text": MARKER["text"], "time": {"created": BASE}})
        db.row("assistant", v2_assistant(v2_tool("mig", "bash",
                                                 {"command": "rm -rf ~/Documents/x"})))
        db.row("user", {"text": "now you", "time": {"created": BASE}})
        db.row("assistant", v2_assistant(v2_tool("own", "bash", {"command": "ls"})))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual({k: (c.actor, c.tool_name) for k, c in got.items()}, {
            "sh_1": ("user", "shell"), "mig": ("user", "bash"),
            "own": ("agent", "bash")})
        shell = got["sh_1"]
        self.assertEqual((shell.command, shell.output, shell.timestamp,
                          shell.kind, shell.known),
                         ("cat ~/.aws/credentials", "[default]\n", _iso(BASE),
                          "shell", True))
        self.assertEqual(rules(shell), [("cred.read", "cat ~/.aws/credentials")])
        self.assertEqual(rules(got["mig"]),
                         [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_v1_rows_v2_holds_are_read_once(self):
        db = self.db(v2=True)
        db.session()
        db.v2_session()
        m = db.message(assistant())
        db.part(m, v1_tool("both", "bash", {"command": "make"}))
        # a v1 binary run after the migration added this one
        db.part(m, v1_tool("later", "bash", {"command": "make install"}))
        db.row("assistant", v2_assistant(v2_tool("both", "bash",
                                                 {"command": "make"})))
        # another session has its own call of the same id
        db.session(sid="ses_other")
        m2 = db.message(assistant(), sid="ses_other")
        db.part(m2, v1_tool("both", "bash", {"command": "pwd"}), sid="ses_other")
        db.close()
        got = [(c.session, c.tool_call_id, c.command) for c in self.calls(db.path)]
        self.assertEqual(sorted(got), sorted([
            (SID, "both", "make"), (SID, "later", "make install"),
            ("ses_other", "both", "pwd")]))

    def test_code_mode_calls_are_read(self):
        db = self.db(v2=True)
        db.v2_session()
        db.row("assistant", v2_assistant(v2_tool(
            "x", "execute", {"code": "return 1"}, text="1",
            metadata={"toolCalls": [{"tool": "opencode.session_rename",
                                     "status": "completed",
                                     "input": {"title": "t"}}]})))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual(sorted(got), ["x", "x/1"])
        self.assertEqual(got["x/1"].tool_name, "opencode.session_rename")


# --------------------------------------------------------------------------
# The JSON tree of v1.1.x
# --------------------------------------------------------------------------

class JsonTree(_Case):

    def _session(self, **kw):
        return self.json_session(messages=[
            (user(), [{"type": "text", "text": "run the tests"}]),
            (assistant(), [
                {"type": "step-start"},
                v1_tool("c1", "bash", {"command": "npm test"}, output="ok"),
                v1_tool("c2", "read", {"filePath": "~/.ssh/id_rsa"},
                        start=BASE + 2000)]),
            (user(), [MARKER]),
            (assistant(), [v1_tool("c3", "bash", {"command": "rm -rf ~/Documents/x"},
                                   start=BASE + 4000)]),
        ], **kw)

    def test_calls_from_its_messages_and_parts(self):
        for pretty in (True, False):
            with self.subTest(pretty=pretty):
                shutil.rmtree(os.path.join(self.data, "storage"), True)
                self.src.reset()
                path = self._session(pretty=pretty)
                got = self.by_id(path)
                self.assertEqual(
                    {k: (c.kind, c.actor, c.timestamp, c.session, c.project,
                         c.workdir) for k, c in got.items()},
                    {"c1": ("shell", "agent", _iso(BASE), SID, CWD, CWD),
                     "c2": ("read", "agent", _iso(BASE + 2000), SID, CWD, None),
                     "c3": ("shell", "user", _iso(BASE + 4000), SID, CWD, CWD)})
                self.assertEqual(got["c1"].output, "ok")
                self.assertEqual(rules(got["c2"]), [("cred.read", "~/.ssh/id_rsa")])
                self.assertEqual(rules(got["c3"]),
                                 [("fs.destructive", "rm -rf ~/Documents/x")])
                # side stores hold no calls of their own
                for store in self.stores():
                    if store.role == "side":
                        self.assertEqual(list(self.src.tool_calls(store)), [])

    def test_a_session_the_database_holds_gives_its_calls_from_there(self):
        path = self.json_session(messages=[
            (assistant(), [v1_tool("c1", "bash", {"command": "cat .env"},
                                   output="STRIPE_KEY=" + SECRET)])])
        db = self.db()
        db.session()
        m = db.message(assistant())
        db.part(m, v1_tool("c1", "bash", {"command": "cat .env"},
                           output="STRIPE_KEY=" + SECRET))
        db.close()
        self.assertEqual(self.calls(path), [])
        self.assertEqual([c.tool_call_id for c in self.calls(db.path)], ["c1"])
        # the stale copy is still searched: it is a copy on disk
        parts = [s for s in self.stores() if s.unit == "part"]
        self.assertEqual(self.found(parts[0].path), {SECRET: {".env"}})
        # a database OPENCODE_DB names in the folder counts too
        os.rename(db.path, os.path.join(self.data, "mine.sqlite"))
        self.src.reset()
        self.assertEqual(len(self.calls(path)), 1)
        self.src.reset()
        with mock.patch.dict(os.environ, {"OPENCODE_DB": "mine.sqlite"}):
            self.assertEqual(self.calls(path), [])

    def test_a_call_only_the_files_hold_is_read_from_them(self):
        # v1.2.0 imported the tree once (a failed batch is dropped, the
        # session row kept), and v1.1 could go on writing the session
        # after; v2 rows count as held too.
        path = self.json_session(messages=[
            (assistant(), [v1_tool("c1", "bash", {"command": "ls"}),
                           v1_tool("c2", "read",
                                   {"filePath": "~/.ssh/id_rsa"}),
                           v1_tool("c3", "bash", {"command": "pwd"})])])
        db = self.db(v2=True)
        db.session()
        m = db.message(assistant())
        db.part(m, v1_tool("c1", "bash", {"command": "ls"}))
        db.v2_session()
        db.row("assistant", v2_assistant(v2_tool("c3", "bash",
                                                 {"command": "pwd"})))
        db.close()
        got = self.calls(path)
        self.assertEqual([c.tool_call_id for c in got], ["c2"])
        self.assertEqual(rules(got[0]), [("cred.read", "~/.ssh/id_rsa")])

    def test_an_id_that_climbs_out_of_storage_is_not_followed(self):
        outside = tempfile.mkdtemp(prefix="oc-outside-")
        self.addCleanup(shutil.rmtree, outside, True)
        up = "../" * 40 + outside.lstrip("/\\")
        path = self.write_json("storage/session/%s/ses_x.json" % PID,
                               {"id": up, "directory": CWD})
        os.makedirs(os.path.join(self.data, "storage", "message"))
        os.makedirs(os.path.join(self.data, "storage", "part"))
        with open(os.path.join(outside, "m.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"id": "m", "role": "assistant"}, fh)
        os.makedirs(os.path.join(self.data, "storage", "part", "m"))
        with open(os.path.join(self.data, "storage", "part", "m", "p.json"),
                  "w", encoding="utf-8") as fh:
            json.dump(v1_tool("planted", "bash", {"command": "x"}), fh)
        self.assertEqual(self.calls(path), [])


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(_Case):

    def test_a_cat_env_output_reaches_clean_with_its_origin(self):
        db = self.db(v2=True)
        db.session()
        m = db.message(assistant())
        db.part(m, v1_tool("c1", "bash", {"command": "cat .env"},
                           output="STRIPE_KEY=" + SECRET + "\n"))
        db.v2_session(sid="ses_v2")
        db.row("assistant", v2_assistant(v2_tool(
            "r1", "read", {"path": "config/.env.local"},
            text="1: GITHUB_TOKEN=" + TOKEN)), sid="ses_v2")
        db.close()
        self.assertEqual(self.found(db.path), {SECRET: {".env"},
                                               TOKEN: {"config/.env.local"}})
        # and in the JSON tree
        self.json_session(sid="ses_json", messages=[
            (assistant(), [v1_tool("j1", "bash", {"command": "cat .env"},
                                   output="STRIPE_KEY=" + SECRET2)])])
        [part] = [s for s in self.stores() if s.unit == "part"]
        self.assertEqual(self.found(part.path), {SECRET2: {".env"}})

    def test_a_users_command_output_is_tied_to_it(self):
        db = self.db(v2=True)
        db.v2_session()
        db.row("shell", {"shellID": "sh_1", "command": "cat .env",
                         "status": "exited",
                         "output": {"output": "STRIPE_KEY=" + SECRET},
                         "time": {"created": BASE}})
        db.close()
        self.assertEqual(self.found(db.path), {SECRET: {".env"}})

    def test_titles_messages_and_text_are_searched(self):
        db = self.db(v2=True)
        db.session(title="deploy with STRIPE_KEY=" + SECRET)
        u = db.message(user())
        db.part(u, {"type": "text", "text": "my token is GITHUB_TOKEN=" + TOKEN})
        db.v2_session(sid="ses_v2")
        db.row("user", {"text": "use STRIPE_KEY=" + SECRET2,
                        "time": {"created": BASE}}, sid="ses_v2")
        db.close()
        self.assertEqual(set(self.found(db.path)), {SECRET, SECRET2, TOKEN})

    def test_logins_and_share_secrets_are_not_searched(self):
        db = self.db(v2=True)
        db.session()
        c = db.conn
        c.execute("INSERT INTO credential VALUES (?,?,?,?,?,?,?,?,?)",
                  ("cr1", None, "anthropic", PROVIDER_KEY, None, None, 1, BASE, BASE))
        c.execute("INSERT INTO account VALUES (?,?,?,?,?,?,?,?)",
                  ("ac1", "a@example.com", "https://x", "ACCESS_TOKEN=" + TOKEN,
                   "REFRESH=" + SECRET, None, BASE, BASE))
        c.execute("INSERT INTO control_account VALUES (?,?,?,?,?,?,?,?)",
                  ("a@example.com", "https://x", "t=" + TOKEN, "r=" + SECRET,
                   None, 1, BASE, BASE))
        c.execute("INSERT INTO session_share VALUES (?,?,?,?,?,?)",
                  (SID, "sh", "SHARE_SECRET=" + SECRET2, "https://opncd.ai/s/x",
                   BASE, BASE))
        c.execute("INSERT INTO event VALUES (?,?,?,?,?,?)",
                  ("ev1", SID, 1, BASE, "x", _compact({"key": "STRIPE_KEY=" + SECRET})))
        c.execute("INSERT INTO kv VALUES (?,?,?,?)",
                  ("k", "STRIPE_KEY=" + SECRET, BASE, BASE))
        db.close()
        for name, value in (("auth.json", {"anthropic": {"type": "api",
                                                         "key": PROVIDER_KEY}}),
                            ("mcp-auth.json", {"srv": {"tokens": {
                                "access_token": TOKEN}}})):
            with open(os.path.join(self.data, name), "w", encoding="utf-8") as fh:
                json.dump(value, fh)
        self.write_json("storage/session_share/%s.json" % SID,
                        {"id": "x", "secret": SECRET2, "url": "https://x"})
        self.assertEqual(self.found(db.path), {})
        texts = json.dumps([t.node for s in self.stores()
                            for t in self.src.secret_texts(s)])
        for value in (PROVIDER_KEY, TOKEN, SECRET, SECRET2):
            self.assertNotIn(value, texts)

    def test_tool_output_files(self):
        out = os.path.join(self.data, "tool-output", "tool_0123456789abXyZ")
        os.makedirs(os.path.dirname(out))
        with open(out, "w", encoding="utf-8", newline="") as fh:
            fh.write("line\n" * 3 + "STRIPE_KEY=" + SECRET + "\n")
        self.assertEqual(set(self.found(out)), {SECRET})
        with mock.patch.object(opencode, "_CHUNK", 7):
            texts = [t.node for t in self.texts(out)]
        self.assertEqual("".join(texts), "line\n" * 3 + "STRIPE_KEY=" + SECRET + "\n")
        self.assertTrue(all(t.endswith("\n") for t in texts))


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

class Masking(_Case):

    def test_a_json_part_round_trips(self):
        for pretty in (True, False):
            with self.subTest(pretty=pretty):
                shutil.rmtree(os.path.join(self.data, "storage"), True)
                self.json_session(pretty=pretty, age=600, messages=[
                    (assistant(), [v1_tool("c1", "bash", {"command": "cat .env"},
                                           output="STRIPE_KEY=" + SECRET)])])
                [store] = [s for s in self.stores() if s.unit == "part"]
                with open(store.path, "rb") as fh:
                    original = fh.read()
                result = self.src.mask(store, [SECRET])
                self.assertEqual((result.changed, result.skipped), (True, None))
                with open(store.path, "rb") as fh:
                    after = fh.read()
                marker = clean.REDACTION % clean._fingerprint(SECRET)
                self.assertEqual(after, original.replace(SECRET.encode(),
                                                         marker.encode()))
                part = json.loads(after.decode("utf-8"))
                self.assertEqual(part["state"]["output"], "STRIPE_KEY=" + marker)
                self.assertEqual(self.found(store.path), {})
                [session] = [s for s in self.stores() if s.role == "transcript"]
                [call] = self.calls(session.path)
                self.assertEqual(call.output, "STRIPE_KEY=" + marker)

    def test_a_file_written_just_now_is_in_use(self):
        self.json_session(age=5, messages=[
            (assistant(), [v1_tool("c1", "bash", {"command": "cat .env"},
                                   output="STRIPE_KEY=" + SECRET)])])
        [store] = [s for s in self.stores() if s.unit == "part"]
        digest = _sha(store.path)
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(store.path, skipped="in use"))
        self.assertEqual(_sha(store.path), digest)

    def test_the_database_is_refused(self):
        db = self.db()
        db.session(title="STRIPE_KEY=" + SECRET)
        db.close()
        store = self.store(db.path)
        before = _sha(db.path)
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(db.path, skipped="read-only"))
        self.assertEqual(_sha(db.path), before)


# --------------------------------------------------------------------------
# The database is never written
# --------------------------------------------------------------------------

def _live(path, wal=True):
    """A database as a running OpenCode leaves it: WAL mode, the writer
    still open, its rows committed into the -wal."""
    db = V1Db(path, v2=True, wal=wal)
    db.session()
    db.v2_session()
    m = db.message(assistant())
    db.part(m, v1_tool("c1", "bash", {"command": "cat .env"},
                       output="STRIPE_KEY=" + SECRET))
    db.conn.commit()
    db.row("assistant", v2_assistant(v2_tool("c2", "shell",
                                             {"command": "rm -rf ~/Documents/x"})))
    db.conn.commit()
    db.conn.execute("SELECT count(*) FROM part").fetchall()
    return db


class NeverWritten(_Case):

    def read_everything(self, path):
        store = self.store(path)
        self.assertEqual(sorted(c.tool_call_id for c in self.src.tool_calls(store)),
                         ["c1", "c2"])
        self.assertEqual(self.found(path), {SECRET: {".env"}})
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(path, skipped="read-only"))

    def test_with_its_writer_open(self):
        path = os.path.join(self.data, "opencode.db")
        db = _live(path)
        self.addCleanup(db.conn.close)
        before = _files(path)
        self.assertEqual(sorted(before), ["", "-shm", "-wal"])
        self.assertGreater(len(before["-wal"]), 0)
        self.read_everything(path)
        self.assertEqual(_files(path), before)
        self.assertEqual(sorted(os.listdir(self.data)),
                         ["opencode.db", "opencode.db-shm", "opencode.db-wal"])

    def test_with_its_writer_closed(self):
        path = os.path.join(self.data, "opencode.db")
        _live(path).conn.close()
        for suffix in ("-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.remove(path + suffix)
        before = _files(path)
        self.read_everything(path)
        self.assertEqual(_files(path), before)
        self.assertEqual(os.listdir(self.data), ["opencode.db"])

    def test_not_in_wal_mode(self):
        path = os.path.join(self.data, "opencode.db")
        _live(path, wal=False).close()
        before = _files(path)
        self.read_everything(path)
        self.assertEqual(_files(path), before)
        self.assertEqual(os.listdir(self.data), ["opencode.db"])


# --------------------------------------------------------------------------
# Damaged stores
# --------------------------------------------------------------------------

class Damaged(_Case):

    def test_a_file_that_is_not_a_database(self):
        path = os.path.join(self.data, "opencode.db")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("not a database STRIPE_KEY=" + SECRET)
        store = self.store(path)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(self.err.getvalue().count("warning:"), 1)
        self.assertNotIn(SECRET, self.err.getvalue())

    def test_an_empty_file_holds_nothing(self):
        path = os.path.join(self.data, "opencode.db")
        open(path, "w", encoding="utf-8").close()
        store = self.store(path)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)
        self.assertEqual(os.listdir(self.data), ["opencode.db"])

    def test_rows_of_the_wrong_shape(self):
        db = self.db(v2=True)
        db.session()
        db.v2_session()
        m = db.message(assistant())
        bad_parts = ["not json", "[1, 2]", _compact({"type": "tool"}),
                     _compact({"type": "tool", "tool": 5, "callID": [1],
                               "state": "x"}),
                     _compact({"type": "tool", "tool": "bash", "callID": "ok",
                               "state": {"input": "not a dict",
                                         "status": "error", "error": {"a": 1},
                                         "time": "now"}}),
                     _compact({"type": "mystery"})]
        for i, raw in enumerate(bad_parts):
            db.conn.execute("INSERT INTO part VALUES (?,?,?,?,?,?)",
                            ("prt_bad%d" % i, m, SID, BASE, BASE, raw))
        # a message row that is not JSON, with a parentID list
        m2 = db.message(dict(assistant(), parentID=["x"]))
        db.part(m2, v1_tool("deep", "bash", {"command": "ls"}))
        for raw, kind in (("not json", "assistant"), ("[]", "assistant"),
                          (_compact({"content": "x"}), "assistant"),
                          (_compact({"content": [5, {"type": "tool"},
                                                 {"type": "tool", "state": 3,
                                                  "time": [], "name": {}}]}),
                           "assistant"),
                          (_compact({"command": 7, "output": [1]}), "shell"),
                          (_compact({}), "brand-new")):
            db.n += 1
            seq = db.seq.get(SID, 0)
            db.seq[SID] = seq + 1
            db.conn.execute("INSERT INTO session_message VALUES (?,?,?,?,?,?,?)",
                            ("msg_bad%d" % db.n, SID, kind, seq, BASE, BASE, raw))
        db.close()
        store = self.store(db.path)
        calls = list(self.src.tool_calls(store))
        texts = list(self.src.secret_texts(store))
        self.assertIn("ok", [c.tool_call_id for c in calls])
        self.assertIn("deep", [c.tool_call_id for c in calls])
        self.assertTrue(texts)
        self.assertGreaterEqual(self.src.counts["unparsed"], 2)
        self.assertGreaterEqual(self.src.counts["unknown"], 2)
        for call in calls:
            watch.judge(call)
        unparsed = self.src.counts["unparsed"]
        list(self.src.tool_calls(store))
        self.assertEqual(self.src.counts["unparsed"], unparsed)

    def test_json_files_of_the_wrong_shape(self):
        path = self.json_session(messages=[
            (assistant(), [v1_tool("c1", "bash", {"command": "ls"})])])
        mid = os.listdir(os.path.join(self.data, "storage", "part"))[0]
        self.write_json("storage/part/%s/prt_zz1.json" % mid, None,
                        raw=b'{"type": "tool", "tool": "bash", "state": {')
        self.write_json("storage/part/%s/prt_zz2.json" % mid, None,
                        raw=b'\xff\xfe not utf-8 STRIPE_KEY=' + SECRET.encode())
        self.write_json("storage/part/%s/prt_zz3.json" % mid, [1, 2])
        self.write_json("storage/part/%s/prt_zz4.json" % mid, None,
                        raw=b"[" * 100000 + b"]" * 100000)
        os.makedirs(os.path.join(self.data, "storage", "part", mid, "prt_dir.json"))
        self.write_json("storage/message/%s/msg_zz.json" % SID, "a string")
        got = self.calls(path)
        self.assertEqual([c.tool_call_id for c in got], ["c1"])
        self.assertEqual(self.src.counts["unparsed"], 3)
        found = set()
        for store in self.stores():
            for text in self.src.secret_texts(store):
                clean._walk(text.node, lambda value, *_r: found.add(value))
        self.assertIn(SECRET, found)
        self.assertEqual(self.src.counts["unparsed"], 3)

    def test_a_session_file_that_is_not_json_still_gives_its_calls(self):
        sid = "ses_broken00000000000000001"
        path = self.json_session(sid=sid, messages=[
            (assistant(), [v1_tool("c1", "bash", {"command": "ls"})])])
        with open(path, "wb") as fh:
            fh.write(b"{ truncated")
        self.assertEqual([c.session for c in self.calls(path)], [sid])

    def test_a_fifo_is_never_opened(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFOs here")
        fifo = os.path.join(self.data, "opencode.db")
        os.mkfifo(fifo)
        self.assertEqual(self.stores(), [])
        with mock.patch.dict(os.environ, {"OPENCODE_DB": fifo}):
            self.assertEqual(self.stores(), [])
        store = self.src._database(fifo)
        self.assertEqual(list(self.src.tool_calls(store)), [])

    def test_a_folder_that_cannot_be_listed(self):
        self.json_session(messages=[(assistant(), [])])
        loop = os.path.join(self.data, "storage", "part", "loop")
        os.makedirs(os.path.dirname(loop), exist_ok=True)
        os.symlink(loop, loop)
        self.assertEqual(len([s for s in self.stores()
                              if s.role == "transcript"]), 1)

    def test_a_locked_database_is_read_from_a_copy_that_is_removed(self):
        db = self.db()
        db.session()
        m = db.message(assistant())
        db.part(m, v1_tool("c1", "bash", {"command": "cat .env"},
                           output="STRIPE_KEY=" + SECRET))
        db.close()
        temps = set(x for x in os.listdir(tempfile.gettempdir())
                    if x.startswith("ranwhat-") and not x.startswith("ranwhat-home-"))
        lock = sqlite3.connect(db.path)
        lock.execute("PRAGMA locking_mode=EXCLUSIVE")
        lock.execute("BEGIN EXCLUSIVE")
        try:
            self.assertEqual([c.tool_call_id for c in self.calls(db.path)], ["c1"])
            self.assertEqual(self.found(db.path), {SECRET: {".env"}})
        finally:
            lock.rollback()
            lock.close()
        self.assertEqual(os.listdir(self.data), ["opencode.db"])
        left = set(x for x in os.listdir(tempfile.gettempdir())
                   if x.startswith("ranwhat-") and not x.startswith("ranwhat-home-"))
        self.assertEqual(left - temps, set())

    def test_names_that_are_not_utf8(self):
        if WINDOWS or sys.platform == "darwin":
            self.skipTest("the file system takes only valid names")
        root = os.fsencode(self.data)
        folder = os.path.join(root, b"storage", b"session", b"proj\xff")
        os.makedirs(folder)
        with open(os.path.join(folder, b"ses_\xfe.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"id": "ses_q", "directory": CWD}, fh)
        folder = os.path.join(root, b"storage", b"message", b"ses_q")
        os.makedirs(folder)
        with open(os.path.join(folder, b"msg_\xff.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(dict(assistant(), id="msg_\udcff"), fh)
        folder = os.path.join(root, b"storage", b"part", b"msg_\xff")
        os.makedirs(folder)
        with open(os.path.join(folder, b"prt_1.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(v1_tool("c1", "bash", {"command": "cat .env"},
                              output="STRIPE_KEY=" + SECRET), fh)
        [session] = [s for s in self.stores() if s.role == "transcript"]
        self.assertEqual([c.tool_call_id for c in self.calls(session.path)],
                         ["c1"])
        [part] = [s for s in self.stores() if s.unit == "part"]
        self.assertEqual(self.found(part.path), {SECRET: {".env"}})

    def test_a_table_that_fails_part_way_names_its_class_only(self):
        db = self.db()
        db.session()
        m = db.message(assistant())
        db.part(m, v1_tool("c1", "bash", {"command": "STRIPE_KEY=" + SECRET}))
        db.close()
        store = self.store(db.path)
        real = opencode.OpenCodeSource._v1_part_call

        def broken(self, *args, **kw):
            raise sqlite3.DatabaseError("cell said STRIPE_KEY=" + SECRET)

        with mock.patch.object(opencode.OpenCodeSource, "_v1_part_call", broken):
            self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertIn("DatabaseError", self.err.getvalue())
        self.assertNotIn(SECRET, self.err.getvalue())
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertIs(real, opencode.OpenCodeSource._v1_part_call)


if __name__ == "__main__":
    unittest.main()
