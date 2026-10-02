"""OpenClaw on the Source interface (design 3.9 and 7.2).

Supported, not promoted: the adapter is last in the registry, and reads
exactly what watch read before the port (test_openclaw.py and the rest
still pin that, unchanged). Its databases are read-only, and it is not
searched for secrets yet: secret_texts yields nothing, and mask refuses.

Every value here is synthetic, and every file is in a temp directory.
"""
import contextlib
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
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
from ranwhat import sources, watch  # noqa: E402
from ranwhat.sources import _paths  # noqa: E402
from ranwhat.sources.base import MaskResult, Store  # noqa: E402
from ranwhat.sources.openclaw import OpenClawSource  # noqa: E402

KEY = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"
DB = os.path.join("agent", "openclaw-agent.sqlite")


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _ranwhat_temp_dirs():
    return set(x for x in os.listdir(tempfile.gettempdir())
               if x.startswith("ranwhat-"))


def body(name, args, kind="tool_use"):
    return json.dumps({"content": [{"type": kind, "name": name, "input": args}]})


class _Case(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="oc-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.state = os.path.join(self.home, ".openclaw")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home,
                                                "OPENCLAW_STATE_DIR": self.state}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.src = OpenClawSource()
        self.temp_before = _ranwhat_temp_dirs()

    def tearDown(self):
        self.assertEqual(_ranwhat_temp_dirs() - self.temp_before, set(),
                         "a ranwhat-* temp directory was left behind")

    def database(self, agent, rows, table="log", age=0):
        """agents/<agent>/agent/openclaw-agent.sqlite with (body, epoch)
        rows in `table`."""
        path = os.path.join(self.state, "agents", agent, DB)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE "%s" (id TEXT, body TEXT, createdAt INTEGER)'
                     % table)
        conn.executemany('INSERT INTO "%s" VALUES (?, ?, ?)' % table,
                         [(str(i), b, t) for i, (b, t) in enumerate(rows)])
        conn.commit()
        conn.close()
        if age:
            when = time.time() - age
            os.utime(path, (when, when))
        return path

    def calls(self, path):
        return list(self.src.tool_calls(self.src.store_at(path)))


class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = OpenClawSource()

    def test_each_os_without_an_override(self):
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.openclaw", "default")])
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.openclaw", "default")])
        self.assertEqual(self.src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.openclaw", "default")])

    def test_openclaw_state_dir(self):
        env = {"OPENCLAW_STATE_DIR": "/srv/oc"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/srv/oc", "env OPENCLAW_STATE_DIR")])

    def test_the_variable_is_read_when_asked(self):
        with mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": "/set/later"}):
            [loc] = self.src.locations()
            self.assertEqual(watch.openclaw_state_dir(), "/set/later")
        self.assertEqual((loc.path, loc.how),
                         (os.path.abspath("/set/later"), "env OPENCLAW_STATE_DIR"))


class Registry(unittest.TestCase):

    def test_last_in_the_registry(self):
        self.assertEqual(sources.ids()[-1], "openclaw")
        src = sources.get("openclaw")
        self.assertIsInstance(src, OpenClawSource)
        self.assertEqual((src.name, src.unit, src.env),
                         ("OpenClaw", "database", ("OPENCLAW_STATE_DIR",)))
        self.assertIn("--state-dir", src.path_means)
        self.assertFalse(src.searched)

    def test_importing_it_imports_neither_watch_nor_clean(self):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                "import ranwhat.sources.openclaw; "
                "print('ranwhat.watch' in sys.modules, "
                "'ranwhat.clean' in sys.modules)")
        out = subprocess.run([sys.executable, "-c", code, REPO],
                             capture_output=True, text=True, encoding="utf-8",
                             timeout=20)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.split(), ["False", "False"])


class Discovery(_Case):

    def test_one_database_per_agent_whatever_its_age(self):
        a = self.database("a1", [(body("bash", {"command": "ls"}), 1758550000)],
                          age=400 * 86400)
        b = self.database("b2", [(body("bash", {"command": "ls"}), 1758550000)])
        found = self.src.stores(self.src.locations(), since_days=30)
        self.assertEqual([s.path for s in found], [b, a])
        store = found[1]
        self.assertEqual(
            (store.source, store.format, store.role, store.unit, store.session,
             store.masking),
            ("openclaw", "sqlite", "transcript", "database", "a1", "read-only"))
        self.assertTrue(store.why_read_only)
        self.assertIsInstance(store, Store)
        self.assertEqual(sorted(s.path for s in found),
                         watch.openclaw_databases(self.state))

    def test_a_missing_state_dir_is_no_stores(self):
        self.assertEqual(self.src.stores(self.src.locations()), [])


class ToolCalls(_Case):

    def test_calls_found_by_shape_with_their_row(self):
        path = self.database("a1", [
            (body("bash", {"command": "rm -rf ~/old"}), 1758550000),
            (json.dumps({"function": {"name": "shell",
                                      "arguments": '{"command": "ls"}'}}),
             1758550000000),
            (json.dumps({"content": [{"type": "text", "text": "rm -rf /"}]}),
             1758550002),
            (json.dumps({"toolName": "exec", "args": '"just text"'}), None)],
            table="weird_entry_log")
        calls = self.calls(path)
        self.assertEqual([(c.tool_name, c.tool_input, c.timestamp) for c in calls], [
            ("bash", {"command": "rm -rf ~/old"}, "2025-09-22T14:06:40Z"),
            ("shell", {"command": "ls"}, "2025-09-22T14:06:40Z"),
            ("exec", {"_value": "just text"}, None)])
        for c in calls:
            self.assertEqual((c.source, c.store, c.session, c.project, c.kind,
                              c.known, c.tool_call_id),
                             ("openclaw", path, "a1", "weird_entry_log", None,
                              False, None))
        self.assertEqual([[h["rule"] for h in watch.judge(c)[0]] for c in calls],
                         [["fs.destructive"], [], []])

    def test_watch_reads_the_same_calls(self):
        path = self.database("a1", [
            (body("bash", {"command": "rm -rf ~/old"}), 1758550000),
            (body("bash", {"command": "rm -rf ~/old"}), 1758550001),
            (body("bash", {"command": "cat ~/.ssh/id_rsa"}), 1758550002)])
        records = watch.scan_openclaw_db(path)
        judged = [(c, watch.judge(c)) for c in self.calls(path)]
        hit = [(c.tool_name, watch._hash(p)) for c, (h, p) in judged if h]
        self.assertEqual(len(hit), 3)
        # one record for each distinct call, as before the port
        self.assertEqual([(r["tool_name"], r["payload_hash"]) for r in records],
                         [hit[0], hit[2]])

    def test_a_file_that_is_not_a_database_warns_and_yields_nothing(self):
        path = os.path.join(self.state, "agents", "a1", DB)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("not a database")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(path), [])
        self.assertIn("warning: cannot read %s" % path, err.getvalue())

    def test_the_database_is_not_changed(self):
        path = self.database("a1", [(body("bash", {"command": "ls"}), 1758550000)])
        before = _sha(path)
        self.calls(path)
        self.assertEqual(_sha(path), before)
        self.assertEqual(sorted(os.listdir(os.path.dirname(path))),
                         ["openclaw-agent.sqlite"])


class NotSearchedForSecrets(_Case):

    def test_no_texts_and_no_mask(self):
        path = self.database("a1", [(body("bash", {"command": "echo " + KEY}),
                                     1758550000)])
        store = self.src.store_at(path)
        self.assertEqual(list(self.src.secret_texts(store)), [])
        before = _sha(path)
        self.assertEqual(self.src.mask(store, [KEY]),
                         MaskResult(path, skipped="read-only"))
        self.assertEqual(_sha(path), before)


if __name__ == "__main__":
    unittest.main()
