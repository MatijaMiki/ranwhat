"""The Kilo Code adapter (ranwhat/sources/kilo.py).

Fixtures are built field for field from Kilo's own source (v7.8.15 and
v1.0.25): kilo.db with OpenCode v1.18's session, message and part tables, the
Kilo-only session_message (seq may be NULL) and kilo_board_message, the
json_extract partial indexes; the JSON tree of the 1.0.x CLI; and the parts
the 7.x extension imports from Roo and 4.x/5.x tasks (ses_migrated_ ids).

Everything runs in temp directories: the home directory, XDG_DATA_HOME,
KILO_DB and clean's backup root all point there, and the real home is never
read. Every secret is synthetic, and token-shaped ones are written as
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
from ranwhat.sources import _paths, kilo  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.kilo import KiloSource  # noqa: E402

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"

# 2026-10-01T09:00:00Z in milliseconds.
BASE = 1790845200000
SID = "ses_6b2f0c1d9ffeA1b2C3d4E5f6G7"
PID = "4b0ea68d7af9a6031a7ffda7ad66e0cb83315750"
CWD = "/home/alice/src/app"
WINDOWS = os.name == "nt"


def _compact(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def tool(call_id, name, inp, status="completed", output="", start=BASE,
         error=None, **extra):
    """A v1 ToolPart's data (schema v1/session.ts ToolState)."""
    state = {"status": status, "input": inp}
    if status == "completed":
        state.update(output=output, title="", metadata={"output": output},
                     time={"start": start, "end": start + 1000})
    elif status == "error":
        state.update(error=error, time={"start": start, "end": start + 1000})
    elif status == "pending":
        state.update(raw="")
    state.update(extra)
    return {"type": "tool", "callID": call_id, "tool": name, "state": state}


def assistant(parent=None, created=BASE, cwd=CWD):
    msg = {"role": "assistant", "time": {"created": created,
                                         "completed": created + 9000},
           "modelID": "claude-sonnet-4-5", "providerID": "kilo",
           "mode": "code", "agent": "code",
           "path": {"cwd": cwd, "root": cwd}, "cost": 0.01,
           "finish": "tool-calls"}
    if parent:
        msg["parentID"] = parent
    return msg


MARKER = {"type": "text", "text": "The following tool was executed by the user",
          "synthetic": True}

# Kilo 7.8.15: OpenCode v1.18's tables, as core/src/database/schema.gen.ts
# makes them, plus Kilo's session_message with a nullable seq, kilo_board_message
# and the json_extract partial indexes (recall-part-index.ts).
DDL = """
CREATE TABLE session (
  id text PRIMARY KEY, project_id text NOT NULL, workspace_id text, parent_id text,
  slug text NOT NULL, directory text NOT NULL, path text, title text NOT NULL, version text NOT NULL,
  share_url text, metadata text, cost real DEFAULT 0 NOT NULL, agent text, model text,
  time_created integer NOT NULL, time_updated integer NOT NULL, time_archived integer);
CREATE TABLE message (id text PRIMARY KEY, session_id text NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL);
CREATE TABLE part (id text PRIMARY KEY, message_id text NOT NULL REFERENCES message(id) ON DELETE CASCADE,
  session_id text NOT NULL, time_created integer NOT NULL, time_updated integer NOT NULL, data text NOT NULL);
CREATE TABLE session_message (
  id text PRIMARY KEY, session_id text NOT NULL REFERENCES session(id) ON DELETE CASCADE,
  type text NOT NULL, seq integer, time_created integer NOT NULL, time_updated integer NOT NULL,
  data text NOT NULL);
CREATE TABLE credential (id text PRIMARY KEY, label text NOT NULL, value text NOT NULL);
CREATE TABLE account (id text PRIMARY KEY, email text NOT NULL, access_token text NOT NULL,
  refresh_token text NOT NULL);
CREATE TABLE control_account (email text NOT NULL, access_token text NOT NULL, refresh_token text NOT NULL);
CREATE TABLE session_share (session_id text PRIMARY KEY, id text NOT NULL, secret text NOT NULL);
CREATE TABLE kilo_board_message (id text PRIMARY KEY, board_id text, data text NOT NULL);
CREATE INDEX recall_part_search_idx ON part (session_id)
  WHERE json_valid(data) AND json_extract(data, '$.type') = 'text';
CREATE INDEX recall_message_role_idx ON message (session_id)
  WHERE json_valid(data) AND json_extract(data, '$.role') = 'user';
"""


class KiloDb(object):
    """A kilo.db, rows added as Kilo writes them."""

    def __init__(self, path, wal=False):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(path)
        if wal:
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(DDL)
        self.n = 0

    def session(self, sid=SID, directory=CWD, title="Fix failing tests"):
        self.conn.execute(
            "INSERT INTO session (id, project_id, slug, directory, title, "
            "version, time_created, time_updated) VALUES (?,?,?,?,?,?,?,?)",
            (sid, PID, "quiet-river", directory, title, "7.8.15", BASE, BASE))
        return sid

    def message(self, data, sid=SID):
        self.n += 1
        mid = "msg_%04dAbC" % self.n
        self.conn.execute("INSERT INTO message VALUES (?,?,?,?,?)",
                          (mid, sid, BASE, BASE, _compact(data)))
        return mid

    def part(self, mid, data, sid=SID, raw=None):
        self.n += 1
        pid = "prt_%04dQwE" % self.n
        self.conn.execute("INSERT INTO part VALUES (?,?,?,?,?,?)",
                          (pid, mid, sid, BASE, BASE,
                           _compact(data) if raw is None else raw))
        return pid

    def call(self, *tools, sid=SID, cwd=CWD):
        """One assistant message holding these tool parts."""
        mid = self.message(assistant(cwd=cwd), sid=sid)
        for t in tools:
            self.part(mid, t, sid=sid)
        return mid

    def close(self):
        self.conn.commit()
        self.conn.close()


class _Case(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="kilo-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.data = os.path.join(self.home, ".local", "share", "kilo")
        os.makedirs(self.data)
        for p in (mock.patch.dict(os.environ, {"HOME": self.home,
                                               "USERPROFILE": self.home}),
                  mock.patch.object(_paths, "home", return_value=self.home),
                  mock.patch.object(clean, "BACKUP_ROOT",
                                    os.path.join(self.home, "backups"))):
            p.start()
            self.addCleanup(p.stop)
        for name in ("XDG_DATA_HOME", "KILO_DB"):
            os.environ.pop(name, None)
        self.src = KiloSource()
        self.err = io.StringIO()
        p = contextlib.redirect_stderr(self.err)
        p.__enter__()
        self.addCleanup(p.__exit__, None, None, None)

    def db(self, name="kilo.db", **kw):
        return KiloDb(os.path.join(self.data, name), **kw)

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

    def found(self, path):
        values = {}
        findings, _masks = clean.scan_store(self.src, self.store(path), values)
        return {values[fp]: f["origins"] for fp, f in findings.items()}

    def write_json(self, rel, obj, age=3600, raw=None):
        path = os.path.join(self.data, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if raw is None:
            raw = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def json_session(self, sid=SID, messages=(), age=3600):
        """storage/ of a Kilo 1.0.x session: [(message, [parts])]."""
        path = self.write_json("storage/session/%s/%s.json" % (PID, sid), {
            "id": sid, "slug": "quiet-river", "version": "1.0.25",
            "projectID": PID, "directory": CWD, "title": "Fix failing tests",
            "time": {"created": BASE, "updated": BASE + 1}}, age=age)
        n = 0
        for message, parts in messages:
            n += 1
            mid = "msg_%s%04d" % (sid[-4:], n)
            self.write_json("storage/message/%s/%s.json" % (sid, mid),
                            dict(message, id=mid, sessionID=sid), age=age)
            for part in parts:
                n += 1
                pid = "prt_%s%04d" % (sid[-4:], n)
                self.write_json("storage/part/%s/%s.json" % (mid, pid),
                                dict(part, id=pid, sessionID=sid,
                                     messageID=mid), age=age)
        return path


def rules(call):
    return [(h["rule"], h["evidence"]) for h in watch.judge(call)[0]]


# --------------------------------------------------------------------------
# Where Kilo keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = KiloSource()

    def test_the_same_xdg_rule_on_every_system(self):
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.local/share/kilo", "default")])
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.local/share/kilo", "default")])
        # Windows: %USERPROFILE%\.local\share\kilo, not %APPDATA%
        self.assertEqual(
            self.src.default_paths({"APPDATA": "C:\\Users\\u\\AppData\\Roaming"},
                                   "C:\\Users\\u", "win32"),
            [("C:\\Users\\u\\.local\\share\\kilo", "default")])

    def test_xdg_data_home(self):
        env = {"XDG_DATA_HOME": "/srv/data"}
        for plat in ("linux", "darwin"):
            self.assertEqual(self.src.default_paths(env, "/home/u", plat),
                             [("/srv/data/kilo", "env XDG_DATA_HOME")])
        self.assertEqual(
            self.src.default_paths({"XDG_DATA_HOME": "D:\\xdg"},
                                   "C:\\Users\\u", "win32"),
            [("D:\\xdg\\kilo", "env XDG_DATA_HOME")])
        self.assertEqual(self.src.default_paths({"XDG_DATA_HOME": ""},
                                                "/home/u", "linux"),
                         [("/home/u/.local/share/kilo", "default")])

    def test_kilo_db(self):
        data = "/home/u/.local/share/kilo"
        self.assertEqual(
            self.src.default_paths({"KILO_DB": "/srv/k.db"}, "/home/u",
                                   "linux"),
            [(data, "default"), ("/srv/k.db", "env KILO_DB")])
        self.assertEqual(
            self.src.default_paths({"KILO_DB": "work.db"}, "/home/u", "linux"),
            [(data, "default"), (data + "/work.db", "env KILO_DB")])
        self.assertEqual(
            self.src.default_paths({"KILO_DB": "D:\\k.db"}, "C:\\Users\\u",
                                   "win32")[1], ("D:\\k.db", "env KILO_DB"))
        for value in (":memory:", ""):
            self.assertEqual(
                self.src.default_paths({"KILO_DB": value}, "/home/u", "linux"),
                [(data, "default")])

    def test_the_opencode_variable_is_not_kilos(self):
        self.assertEqual(
            self.src.default_paths({"OPENCODE_DB": "/x.db"}, "/home/u",
                                   "linux"),
            [("/home/u/.local/share/kilo", "default")])

    def test_class_attributes(self):
        self.assertEqual((self.src.id, self.src.name, self.src.unit),
                         ("kilo", "Kilo Code", "file"))
        self.assertEqual(self.src.env, ("KILO_DB",))
        self.assertFalse(self.src.read_only)
        self.assertTrue(self.src.checked)
        self.assertTrue(self.src.path_means)

    def test_importing_it_imports_neither_watch_nor_clean(self):
        import subprocess
        code = ("import sys; import ranwhat.sources.kilo; "
                "print('ranwhat.watch' in sys.modules, 'ranwhat.clean' in "
                "sys.modules)")
        out = subprocess.run([sys.executable, "-c", code], cwd=REPO,
                             capture_output=True, text=True)
        self.assertEqual(out.stdout.split(), ["False", "False"], out.stderr)


class Discovery(_Case):

    def test_which_files_are_stores(self):
        for name in ("kilo.db", "kilo-local.db", "kilo-rc.db",
                     "opencode-local.db"):
            self.db(name).close()
        for name in ("opencode.db", "other.db", "kilo.db-wal", "kilo.db-shm",
                     "kilo.db.json-migration", "kilo.txt"):
            with open(os.path.join(self.data, name), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
        os.makedirs(os.path.join(self.data, "log", "background-process"))
        with open(os.path.join(self.data, "log", "background-process",
                               "x.db"), "w", encoding="utf-8") as fh:
            fh.write("x")
        os.makedirs(os.path.join(self.data, "worktree-pool"))
        names = sorted(os.path.basename(s.path) for s in self.stores())
        self.assertEqual(names, ["kilo-local.db", "kilo-rc.db", "kilo.db",
                                 "opencode-local.db"])

    def test_the_opencode_folder_is_not_read(self):
        other = os.path.join(self.home, ".local", "share", "opencode")
        os.makedirs(other)
        KiloDb(os.path.join(other, "opencode.db")).close()
        self.assertEqual(self.stores(), [])

    def test_a_missing_folder_is_no_stores(self):
        shutil.rmtree(self.data)
        self.assertEqual(self.stores(), [])

    def test_an_empty_folder_is_no_stores(self):
        self.assertEqual(self.stores(), [])

    def test_xdg_data_home_and_kilo_db(self):
        alt = os.path.join(self.home, "xdg")
        os.makedirs(os.path.join(alt, "kilo"))
        KiloDb(os.path.join(alt, "kilo", "kilo.db")).close()
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": alt}):
            self.assertEqual([os.path.basename(s.path) for s in self.stores()],
                             ["kilo.db"])
        elsewhere = os.path.join(self.home, "elsewhere", "mine.db")
        KiloDb(elsewhere).close()
        with mock.patch.dict(os.environ, {"KILO_DB": elsewhere}):
            self.assertEqual([s.path for s in self.stores()], [elsewhere])
        self.db().close()
        with mock.patch.dict(os.environ, {"KILO_DB": ":memory:"}):
            self.assertEqual([os.path.basename(s.path) for s in self.stores()],
                             ["kilo.db"])

    def test_a_path_override_may_be_the_file(self):
        db = self.db("kilo.db")
        db.close()
        self.assertEqual([s.path for s in self.stores(override=db.path)],
                         [db.path])

    def test_json_tree_and_tool_output(self):
        self.json_session(messages=[(assistant(), [])])
        os.makedirs(os.path.join(self.data, "tool-output"))
        with open(os.path.join(self.data, "tool-output", "tool_abc123"), "w",
                  encoding="utf-8") as fh:
            fh.write("STRIPE_KEY=" + SECRET)
        with open(os.path.join(self.data, "tool-output", "other"), "w",
                  encoding="utf-8") as fh:
            fh.write("x")
        units = sorted(s.unit for s in self.stores())
        self.assertEqual(units, ["message", "session", "tool output"])


# --------------------------------------------------------------------------
# Calls
# --------------------------------------------------------------------------

class Calls(_Case):

    def test_a_shell_call_with_its_result(self):
        db = self.db()
        db.session()
        db.call(tool("toolu_01Ab", "bash",
                     {"command": "npm test", "workdir": "/home/alice/src/app",
                      "description": "Run tests"},
                     output="ok\n\n<shell_metadata>exit 0</shell_metadata>"))
        db.close()
        [call] = self.calls(db.path)
        self.assertEqual((call.source, call.kind, call.known),
                         ("kilo", "shell", True))
        self.assertEqual(call.command, "npm test")
        self.assertEqual(call.workdir, "/home/alice/src/app")
        self.assertEqual(call.tool_call_id, "toolu_01Ab")
        self.assertEqual(call.session, SID)
        self.assertEqual(call.project, CWD)
        self.assertEqual(call.timestamp, "2026-10-01T09:00:00Z")
        self.assertIn("exit 0", call.output)
        self.assertIsNone(call.status)
        self.assertEqual(call.actor, "agent")
        self.assertEqual(rules(call), [])

    def test_the_cwd_is_the_workdir_when_none_is_given(self):
        db = self.db()
        db.session()
        db.call(tool("c1", "bash", {"command": "ls"}), cwd="/srv/other")
        db.close()
        [call] = self.calls(db.path)
        self.assertEqual(call.workdir, "/srv/other")

    def test_every_mapped_tool(self):
        db = self.db()
        db.session()
        cases = [
            ("bash", {"command": "ls"}, "shell", True, ()),
            ("read", {"filePath": "/home/alice/.env"}, "read", True,
             ("/home/alice/.env",)),
            ("write", {"filePath": "a.txt", "content": "x"}, "write", True,
             ("a.txt",)),
            ("edit", {"filePath": "b.txt", "oldString": "a",
                      "newString": "b"}, "write", True, ("b.txt",)),
            ("apply_patch", {"patchText": "*** Begin Patch\n*** Add File: "
                             "n.py\n+x\n*** Update File: m.py\n*** End Patch"},
             "write", True, ("n.py", "m.py")),
            ("generate_image", {"prompt": "a cat", "path": "out/cat.png",
                                "image": "in.png"}, "write", True,
             ("out/cat.png",)),
            ("notebook_read", {"path": "a.ipynb"}, "read", True,
             ("a.ipynb",)),
            ("notebook_edit", {"path": "a.ipynb", "action": "insert"},
             "write", True, ("a.ipynb",)),
            ("notebook_execute", {"path": "a.ipynb", "expected_revision": 3,
                                  "index": 0}, "write", True, ("a.ipynb",)),
            ("send_file", {"path": "/home/alice/.ssh/id_rsa"}, "read", True,
             ("/home/alice/.ssh/id_rsa",)),
            ("webfetch", {"url": "https://example.com"}, "fetch", True, ()),
            ("websearch", {"query": "x"}, "fetch", True, ()),
            ("browser_open", {"url": "http://localhost:3000"}, "fetch", True,
             ()),
            ("repo_clone", {"repository": "o/r", "branch": "main"}, "fetch",
             True, ()),
        ]
        others = ["glob", "grep", "task", "todowrite", "question", "skill",
                  "lsp", "invalid", "plan_exit", "execute", "repo_overview",
                  "semantic_search", "kilo_local_recall", "kilo_memory_recall",
                  "kilo_memory_save", "agent_manager", "agent_manager_models",
                  "board_read", "board_post", "goal", "goal_report",
                  "get_context_info", "compact", "chart", "cron_create",
                  "cron_list", "cron_delete", "schedule_wakeup",
                  "cancel_wakeup", "link_pr", "notify_user", "open_plan",
                  "suggest"]
        cases += [(n, {}, "other", True, ()) for n in others]
        cases.append(("acme_lookup", {"q": 1}, "other", False, ()))
        for i, (name, inp, *_rest) in enumerate(cases):
            db.call(tool("c%d" % i, name, inp))
        db.close()
        got = self.by_id(db.path)
        for i, (name, inp, kind, known, paths) in enumerate(cases):
            with self.subTest(tool=name):
                call = got["c%d" % i]
                self.assertEqual((call.kind, call.known), (kind, known))
                self.assertEqual(tuple(call.paths), paths)
        self.assertEqual(got["c9"].consumed, frozenset(["path"]))

    def test_background_process_runs_commands_for_start_and_monitor(self):
        db = self.db()
        db.session()
        db.call(
            tool("b1", "background_process",
                 {"action": "start", "command": "npm run dev",
                  "workdir": "web", "description": "dev server"}),
            tool("b2", "background_process",
                 {"action": "monitor", "command": "tail -f app.log",
                  "workdir": "/var/log"}),
            tool("b3", "background_process", {"action": "list"}),
            tool("b4", "background_process", {"action": "stop", "id": "p1"}),
            tool("b5", "background_process",
                 {"action": "start", "command": "make"}),
            tool("b6", "background_process", {"action": 5, "command": 7}))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual((got["b1"].kind, got["b1"].command,
                          got["b1"].workdir),
                         ("shell", "npm run dev", "/home/alice/src/app/web"))
        self.assertEqual((got["b2"].kind, got["b2"].workdir),
                         ("shell", "/var/log"))
        self.assertEqual(got["b5"].workdir, CWD)
        for cid in ("b3", "b4", "b6"):
            self.assertEqual((got[cid].kind, got[cid].known, got[cid].command),
                             ("other", True, None))

    def test_a_relative_workdir_without_a_cwd_falls_back_to_the_directory(self):
        db = self.db()
        db.session(directory="/srv/proj")
        mid = db.message({"role": "assistant", "time": {"created": BASE}})
        db.part(mid, tool("b1", "background_process",
                          {"action": "start", "command": "ls",
                           "workdir": "sub"}))
        db.close()
        [call] = self.calls(db.path)
        self.assertEqual(call.workdir, "/srv/proj/sub")

    def test_a_dangerous_command_is_judged_as_for_every_agent(self):
        db = self.db()
        db.session()
        db.call(tool("c1", "bash", {"command": "rm -rf ~/Documents/x"}),
                tool("c2", "background_process",
                     {"action": "start", "command": "rm -rf ~/Documents/x"}))
        db.close()
        got = self.by_id(db.path)
        self.assertTrue(rules(got["c1"]))
        self.assertEqual(rules(got["c1"]), rules(got["c2"]))

    def test_declined_and_not(self):
        db = self.db()
        db.session()
        rej = "The user rejected permission to use this specific tool call."
        db.call(
            tool("d1", "generate_image", {"prompt": "x", "path": "a.png"},
                 status="error", error=rej),
            tool("d2", "bash", {"command": "ls"}, status="error",
                 error=rej + " You may try again with different parameters."),
            tool("d3", "bash", {"command": "ls"}, status="error",
                 error="The user rejected permission to use this specific tool "
                       "call with the following feedback: no"),
            tool("d4", "bash", {"command": "ls"}, status="error",
                 error="The user has specified a rule which prevents you from "
                       "using this specific tool call. Rules: x"),
            tool("d5", "bash", {"command": "ls"}, status="error",
                 error="Tool execution aborted", raw=""),
            tool("r1", "bash", {"command": "ls"}, status="error",
                 error="Tool execution aborted",
                 metadata={"interrupted": True}),
            tool("r2", "bash", {"command": "ls"}, status="error",
                 error="command not found"),
            tool("r3", "bash", {"command": "ls"}))
        db.close()
        got = self.by_id(db.path)
        for cid in ("d1", "d2", "d3", "d4", "d5"):
            self.assertEqual(got[cid].status, "declined", cid)
        for cid in ("r1", "r2", "r3"):
            self.assertIsNone(got[cid].status, cid)
        self.assertEqual(got["r2"].output, "command not found")

    def test_a_command_the_user_ran(self):
        db = self.db()
        db.session()
        um = db.message({"role": "user", "time": {"created": BASE}})
        db.part(um, MARKER)
        am = db.message(dict(assistant(parent=um)))
        db.part(am, tool("01JABCDEFULID", "bash", {"command": "git status"},
                         output="clean"))
        am2 = db.message(assistant())
        db.part(am2, tool("c2", "bash", {"command": "ls"}))
        db.close()
        got = self.by_id(db.path)
        self.assertEqual(got["01JABCDEFULID"].actor, "user")
        self.assertEqual(got["c2"].actor, "agent")

    def test_code_mode_nested_calls(self):
        db = self.db()
        db.session()
        db.call(tool("x1", "execute", {"code": "..."},
                     metadata={"toolCalls": [{"tool": "read", "status": "ok",
                                              "input": {"filePath": "a"}},
                                             "junk"]}))
        db.close()
        calls = self.calls(db.path)
        self.assertEqual([c.tool_name for c in calls], ["execute", "read"])
        self.assertFalse(calls[1].known)

    def test_the_experimental_session_message_with_a_null_seq(self):
        db = self.db()
        db.session()
        db.call(tool("sh1", "bash", {"command": "ls"}, output="a"))
        rows = [("m1", "shell", None, {"callID": "sh1", "command": "ls",
                                       "output": "a", "time": {"created": BASE}}),
                ("m2", "shell", None, {"callID": "sh2", "command": "pwd",
                                       "output": "/x", "time": {"created": BASE}}),
                ("m3", "synthetic", 1, {"text": "hello"}),
                ("m4", "compaction", None, {"summary": "s"})]
        for rid, kind, seq, data in rows:
            db.conn.execute("INSERT INTO session_message VALUES (?,?,?,?,?,?,?)",
                            (rid, SID, kind, seq, BASE, BASE, _compact(data)))
        db.close()
        calls = self.calls(db.path)
        self.assertEqual(sorted(c.tool_call_id for c in calls), ["sh1", "sh2"])
        sh2 = [c for c in calls if c.tool_call_id == "sh2"][0]
        self.assertEqual((sh2.actor, sh2.command), ("user", "pwd"))
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_timestamps_fall_back_to_the_row(self):
        db = self.db()
        db.session()
        part = tool("c1", "bash", {"command": "ls"})
        part["state"].pop("time")
        db.call(part)
        db.close()
        [call] = self.calls(db.path)
        self.assertEqual(call.timestamp, "2026-10-01T09:00:00Z")

    def test_several_databases_and_sessions(self):
        a = self.db("kilo.db")
        a.session()
        a.call(tool("a1", "bash", {"command": "ls"}))
        a.close()
        b = self.db("opencode-local.db")
        b.session(sid="ses_other", directory="/srv/o")
        b.call(tool("b1", "bash", {"command": "ls"}), sid="ses_other",
               cwd="/srv/o")
        b.close()
        self.assertEqual([c.tool_call_id for c in self.calls(a.path)], ["a1"])
        [call] = self.calls(b.path)
        self.assertEqual((call.session, call.project), ("ses_other", "/srv/o"))


# --------------------------------------------------------------------------
# Imported tasks, and the older JSON files
# --------------------------------------------------------------------------

class Imported(_Case):

    def test_calls_imported_from_roo_and_older_extensions(self):
        sid = "ses_migrated_0123456789abcdef"
        db = self.db()
        db.session(sid=sid)
        mid = "msg_migrated_aaaaaaaaaaaaaaaa"
        db.conn.execute("INSERT INTO message VALUES (?,?,?,?,?)",
                        (mid, sid, BASE, BASE, _compact(assistant())))
        parts = [
            ("toolu_a", "execute_command", {"command": "npm i", "cwd": "sub"}),
            ("toolu_b", "read_file", {"path": "src/a.ts"}),
            ("toolu_c", "write_to_file", {"path": "src/b.ts", "content": "x"}),
            ("toolu_d", "apply_diff", {"path": "src/c.ts", "diff": "..."}),
            ("toolu_e", "apply_patch", {"patch": "*** Update File: x.py\n"}),
            ("toolu_f", "browser_action", {"action": "launch", "url": "u"}),
            ("toolu_g", "attempt_completion", {"result": "done"}),
            ("toolu_h", "somethingNew", {}),
        ]
        for cid, name, inp in parts:
            # imported status is always "completed", even for a denied call
            db.part(mid, tool(cid, name, inp, output=name), sid=sid)
        db.close()
        got = self.by_id(db.path)
        self.assertEqual((got["toolu_a"].kind, got["toolu_a"].command,
                          got["toolu_a"].workdir),
                         ("shell", "npm i", CWD + "/sub"))
        self.assertEqual((got["toolu_b"].kind, tuple(got["toolu_b"].paths)),
                         ("read", ("src/a.ts",)))
        self.assertEqual((got["toolu_c"].kind, tuple(got["toolu_c"].paths)),
                         ("write", ("src/b.ts",)))
        self.assertEqual(got["toolu_d"].kind, "write")
        self.assertEqual(tuple(got["toolu_e"].paths), ("x.py",))
        self.assertEqual(got["toolu_f"].kind, "fetch")
        self.assertEqual((got["toolu_g"].kind, got["toolu_g"].known),
                         ("other", True))
        self.assertFalse(got["toolu_h"].known)
        self.assertEqual(got["toolu_a"].session, sid)


class JsonTree(_Case):
    """Kilo CLI 1.0.x to 7.0.25: JSON files under storage/."""

    def test_calls_from_its_messages_and_parts(self):
        path = self.json_session(messages=[
            (assistant(), [tool("j1", "bash", {"command": "cat .env"},
                                output="STRIPE_KEY=" + SECRET),
                           tool("j2", "write", {"filePath": "x", "content": ""}),
                           {"type": "text", "text": "hi"}])])
        got = self.by_id(path)
        self.assertEqual(sorted(got), ["j1", "j2"])
        self.assertEqual((got["j1"].kind, got["j1"].workdir, got["j1"].session,
                          got["j1"].project), ("shell", CWD, SID, CWD))
        self.assertEqual(got["j2"].kind, "write")
        self.assertEqual([c.source for c in got.values()], ["kilo", "kilo"])

    def test_a_session_the_database_holds_gives_its_calls_from_there(self):
        path = self.json_session(messages=[
            (assistant(), [tool("j1", "bash", {"command": "ls"}),
                           tool("j2", "bash", {"command": "pwd"})])])
        db = self.db()          # 7.0.26 imported it, and j2 was dropped
        db.session()
        db.call(tool("j1", "bash", {"command": "ls"}))
        db.close()
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["j2"])
        self.assertEqual([c.tool_call_id for c in self.calls(db.path)], ["j1"])

    def test_a_json_part_is_searched_and_masked(self):
        self.json_session(age=600, messages=[
            (assistant(), [tool("j1", "bash", {"command": "cat .env"},
                                output="STRIPE_KEY=" + SECRET)])])
        [store] = [s for s in self.stores() if s.unit == "part"]
        self.assertEqual(self.found(store.path), {SECRET: {".env"}})
        with open(store.path, "rb") as fh:
            original = fh.read()
        result = self.src.mask(store, [SECRET])
        self.assertEqual((result.changed, result.skipped), (True, None))
        with open(store.path, "rb") as fh:
            after = fh.read()
        marker = clean.REDACTION % clean._fingerprint(SECRET)
        self.assertEqual(after, original.replace(SECRET.encode(),
                                                 marker.encode()))
        self.assertEqual(self.found(store.path), {})

    def test_an_id_that_climbs_out_of_storage_is_not_followed(self):
        path = self.json_session(messages=[(assistant(), [])])
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"id": "../../../../outside", "directory": CWD}, fh)
        self.assertEqual(self.calls(path), [])

    def test_a_file_written_just_now_is_in_use(self):
        self.json_session(age=5, messages=[
            (assistant(), [tool("j1", "bash", {"command": "cat .env"},
                                output="STRIPE_KEY=" + SECRET)])])
        [store] = [s for s in self.stores() if s.unit == "part"]
        digest = _sha(store.path)
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(store.path, skipped="in use"))
        self.assertEqual(_sha(store.path), digest)


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(_Case):

    def test_a_cat_env_output_reaches_clean_with_its_origin(self):
        db = self.db()
        db.session()
        db.call(tool("c1", "bash", {"command": "cat .env"},
                     output="STRIPE_KEY=" + SECRET))
        db.close()
        self.assertEqual(self.found(db.path), {SECRET: {".env"}})

    def test_board_messages_and_titles_are_searched(self):
        db = self.db()
        db.session(title="deploy with STRIPE_KEY=" + SECRET)
        db.conn.execute("INSERT INTO kilo_board_message VALUES (?,?,?)",
                        ("kbm_1", "b1", "STRIPE_KEY=" + SECRET))
        db.close()
        self.assertIn(SECRET, self.found(db.path))

    def test_logins_and_share_secrets_are_not_searched(self):
        other = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"
        db = self.db()
        db.session()
        db.conn.execute("INSERT INTO credential VALUES ('c','l',?)", (SECRET,))
        db.conn.execute("INSERT INTO account VALUES ('a','e',?,?)",
                        (SECRET, SECRET))
        db.conn.execute("INSERT INTO control_account VALUES ('e',?,?)",
                        (SECRET, SECRET))
        db.conn.execute("INSERT INTO session_share VALUES (?,?,?)",
                        (SID, "sh", SECRET))
        db.conn.execute("INSERT INTO message VALUES ('m','%s',0,0,?)" % SID,
                        (_compact({"role": "user", "text": other}),))
        db.close()
        self.assertEqual(set(self.found(db.path)), {other})

    def test_tool_output_files(self):
        os.makedirs(os.path.join(self.data, "tool-output"))
        path = os.path.join(self.data, "tool-output", "tool_abc")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("line\nSTRIPE_KEY=" + SECRET + "\n")
        self.assertIn(SECRET, self.found(path))

    def test_the_database_is_refused_for_masking(self):
        db = self.db()
        db.session(title="STRIPE_KEY=" + SECRET)
        db.close()
        before = _sha(db.path)
        self.assertEqual(self.src.mask(self.store(db.path), [SECRET]),
                         MaskResult(db.path, skipped="read-only"))
        self.assertEqual(_sha(db.path), before)


# --------------------------------------------------------------------------
# Never written, and robust
# --------------------------------------------------------------------------

class NeverWritten(_Case):

    def test_with_its_writer_open_in_wal_mode(self):
        db = self.db(wal=True)
        db.session()
        db.call(tool("c1", "bash", {"command": "cat .env"},
                     output="STRIPE_KEY=" + SECRET))
        db.conn.commit()
        before = {sfx: _sha(db.path + sfx) for sfx in ("", "-wal")
                  if os.path.exists(db.path + sfx)}
        self.assertIn("-wal", before)
        self.assertEqual([c.tool_call_id for c in self.calls(db.path)], ["c1"])
        self.assertEqual(self.found(db.path), {SECRET: {".env"}})
        after = {sfx: _sha(db.path + sfx) for sfx in before}
        self.assertEqual(before, after)
        self.assertEqual(sorted(os.listdir(self.data)),
                         ["kilo.db", "kilo.db-shm", "kilo.db-wal"])
        db.conn.close()


class Damaged(_Case):

    def test_a_file_that_is_not_a_database(self):
        path = os.path.join(self.data, "kilo.db")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("not a database STRIPE_KEY=" + SECRET)
        store = self.store(path)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertNotIn(SECRET, self.err.getvalue())

    def test_an_empty_store(self):
        path = os.path.join(self.data, "kilo.db")
        open(path, "w", encoding="utf-8").close()
        self.assertEqual(list(self.src.tool_calls(self.store(path))), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)
        self.assertEqual(os.listdir(self.data), ["kilo.db"])

    def test_a_database_with_no_tables(self):
        path = os.path.join(self.data, "kilo.db")
        sqlite3.connect(path).close()
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_a_truncated_database(self):
        db = self.db()
        db.session()
        for i in range(40):
            db.call(tool("c%d" % i, "bash", {"command": "echo " + "x" * 800}))
        db.close()
        size = os.path.getsize(db.path)
        with open(db.path, "r+b") as fh:
            fh.truncate(size // 2)
        store = self.store(db.path)
        list(self.src.tool_calls(store))      # never raises
        list(self.src.secret_texts(store))

    def test_malformed_rows_are_skipped_and_the_rest_read(self):
        db = self.db()
        db.session()
        m = db.message(assistant())
        for raw in ("not json", "[1, 2]", "", _compact({"type": "tool"}),
                    _compact({"type": "tool", "tool": 5, "callID": [1],
                              "state": "x"}),
                    _compact({"type": "tool", "tool": "bash", "callID": "ok",
                              "state": {"input": "not a dict",
                                        "status": "error", "error": {"a": 1},
                                        "time": "now"}}),
                    '{"type": "tool", "tool": "bash", "state": {',
                    _compact({"type": "mystery"})):
            db.part(m, None, raw=raw)
        db.conn.execute("INSERT INTO message VALUES ('mbad',?,0,0,?)",
                        (SID, "not json"))
        db.part(m, tool("deep", "bash", {"command": "ls"}))
        db.close()
        store = self.store(db.path)
        calls = list(self.src.tool_calls(store))
        self.assertIn("ok", [c.tool_call_id for c in calls])
        self.assertIn("deep", [c.tool_call_id for c in calls])
        self.assertTrue(list(self.src.secret_texts(store)))
        self.assertGreaterEqual(self.src.counts["unparsed"], 2)
        for call in calls:
            watch.judge(call)

    def test_non_utf8_cells_and_files(self):
        db = self.db()
        db.session()
        m = db.message(assistant())
        db.conn.execute("INSERT INTO part VALUES ('prt_bin',?,?,0,0,?)",
                        (m, SID, b'{"type":"tool","tool":"bash","callID":"bin",'
                                 b'"state":{"input":{"command":"ls \xff"}}}'))
        db.call(tool("ok", "bash", {"command": "ls"}))
        db.close()
        store = self.store(db.path)
        ids = [c.tool_call_id for c in self.src.tool_calls(store)]
        self.assertIn("ok", ids)
        list(self.src.secret_texts(store))
        # JSON files with bytes that are not UTF-8
        self.json_session(messages=[(assistant(), [tool("c1", "bash",
                                                        {"command": "ls"})])])
        mid = os.listdir(os.path.join(self.data, "storage", "part"))[0]
        self.write_json("storage/part/%s/prt_zz.json" % mid, None,
                        raw=b'\xff\xfe not utf-8 STRIPE_KEY=' + SECRET.encode())
        found = set()
        for st in self.stores():
            for text in self.src.secret_texts(st):
                clean._walk(text.node, lambda value, *_r: found.add(value))
        self.assertIn(SECRET, found)

    def test_json_files_of_the_wrong_shape(self):
        path = self.json_session(messages=[
            (assistant(), [tool("c1", "bash", {"command": "ls"})])])
        mid = os.listdir(os.path.join(self.data, "storage", "part"))[0]
        self.write_json("storage/part/%s/prt_zz1.json" % mid, None,
                        raw=b'{"type": "tool", "tool": "bash", "state": {')
        self.write_json("storage/part/%s/prt_zz3.json" % mid, [1, 2])
        self.write_json("storage/part/%s/prt_zz4.json" % mid, None,
                        raw=b"[" * 100000 + b"]" * 100000)
        self.write_json("storage/message/%s/msg_zz.json" % SID, "a string")
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["c1"])

    def test_a_truncated_session_file_still_gives_its_calls(self):
        path = self.json_session(messages=[
            (assistant(), [tool("c1", "bash", {"command": "ls"})])])
        with open(path, "wb") as fh:
            fh.write(b'{"id": "%s", "direc' % SID.encode())
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["c1"])

    def test_an_oversized_output_is_read_in_linear_time(self):
        db = self.db()
        db.session()
        big = "A" * (24 << 20) + "STRIPE_KEY=" + SECRET
        db.call(tool("big", "bash", {"command": "cat big"}, output=big))
        db.close()
        start = time.time()
        [call] = self.calls(db.path)
        self.assertEqual(call.tool_call_id, "big")
        self.assertEqual(len(call.output), len(big))
        os.makedirs(os.path.join(self.data, "tool-output"))
        out = os.path.join(self.data, "tool-output", "tool_huge")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("STRIPE_KEY=" + SECRET + "\n")
            for _ in range(10):
                fh.write(("B" * 1023 + "\n") * 4096)
        self.assertIn(SECRET, self.found(out))
        self.assertLess(time.time() - start, 60)

    def test_a_fifo_is_never_opened(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFOs here")
        fifo = os.path.join(self.data, "kilo.db")
        os.mkfifo(fifo)
        self.assertEqual(self.stores(), [])
        store = self.src._database(fifo)
        self.assertEqual(list(self.src.tool_calls(store)), [])

    def test_a_missing_kilo_db_is_no_store_and_no_error(self):
        with mock.patch.dict(os.environ,
                             {"KILO_DB": os.path.join(self.home, "nope.db")}):
            self.assertEqual(self.stores(), [])
        self.assertEqual(self.err.getvalue(), "")

    def test_a_table_that_fails_part_way_names_its_class_only(self):
        db = self.db()
        db.session()
        db.call(tool("c1", "bash", {"command": "STRIPE_KEY=" + SECRET}))
        db.close()
        store = self.store(db.path)

        def broken(self, *args, **kw):
            raise sqlite3.DatabaseError("cell said STRIPE_KEY=" + SECRET)

        with mock.patch.object(KiloSource, "_v1_part_call", broken):
            self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertIn("DatabaseError", self.err.getvalue())
        self.assertNotIn(SECRET, self.err.getvalue())
        self.assertEqual(self.src.counts["unreadable_stores"], 1)


class Classify(unittest.TestCase):

    def test_classify_never_raises_on_odd_arguments(self):
        for name in ("bash", "background_process", "send_file",
                     "generate_image", "execute_command", "read_file",
                     "apply_patch", "unknown", ""):
            for args in ({}, {"command": 5, "path": [], "workdir": {},
                              "action": None, "files": 3, "args": 4,
                              "patch": 7, "patchText": 8, "edits": "x"}):
                kilo.classify(name, args, None)
                kilo.classify(name, args, "C:\\proj")


if __name__ == "__main__":
    unittest.main()
