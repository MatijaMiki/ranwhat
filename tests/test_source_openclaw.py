"""OpenClaw on the Source interface (design 3.9 and 7.2).

Supported, not promoted: the adapter is last in the registry, and reads
exactly what watch read before the port (test_openclaw.py and the rest
still pin that, unchanged). Its databases are read-only. Since design
3.9's follow-up they are searched for secrets as well, every text cell of
every table watch reads, through the same read-only open; mask refuses,
and the database, its -wal and its -shm are left as they were.

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
from ranwhat import clean, cli, sources, watch  # noqa: E402
from ranwhat.sources import _paths, _sqlite  # noqa: E402
from ranwhat.sources.base import MaskResult, Store  # noqa: E402
from ranwhat.sources.openclaw import OpenClawSource  # noqa: E402

KEY = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"
KEY2 = "sk_" "live_" "Zx8Cv6Bn4Mm2Lk9Jh7Gf5Ds"
PW = "Vb6nM3qW" "z8Kt2Lp5Rx"
# What the report says of a database that holds a secret.
WHY = ("OpenClaw keeps this in a database; delete the session in "
       "OpenClaw.")
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
        self.assertTrue(src.searched)

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
        self.assertEqual(store.why_read_only, WHY)
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


def _wal_database(path, rows, read_after=True):
    """A live agent's database: WAL mode, its writer still open, with
    (body, epoch) rows in table log, committed into the -wal. With
    read_after, the writer reads after its last commit, as an agent that
    shows its own history does, and so holds the -shm read mark a reader
    of that commit takes. The caller closes the writer."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute('CREATE TABLE log (id TEXT, body TEXT, createdAt INTEGER)')
    conn.commit()
    for i, (b, t) in enumerate(rows):
        conn.execute("INSERT INTO log VALUES (?, ?, ?)", (str(i), b, t))
        conn.commit()
    if read_after:
        conn.execute("SELECT count(*) FROM log").fetchall()
    return conn


def _files(path):
    """{name: bytes} for the database, its -wal and its -shm."""
    out = {}
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            with open(path + suffix, "rb") as fh:
                out[suffix] = fh.read()
    return out


def _result(text):
    return json.dumps({"content": [{"type": "tool_result", "content": text}]})


class SearchedForSecrets(_Case):
    """Every text cell of every table watch reads is searched (design 3.9's
    follow-up). Its schema is not documented, so no cell is known to be a
    call's output, and none names the file a value was read out of."""

    def texts(self, path):
        return [(t.node, t.where, t.call, t.attached)
                for t in self.src.secret_texts(self.src.store_at(path))]

    def test_every_text_cell_of_every_table(self):
        path = self.database("a1", [
            (body("bash", {"command": "cat .env"}), 1758550000),
            (_result("API_KEY=" + KEY + "\n"), 1758550001),
            ("not JSON: STRIPE=" + KEY2, 1758550002)])
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE "me""mo" (note VARCHAR(80), raw BLOB, n INTEGER)')
        conn.execute('INSERT INTO "me""mo" VALUES (?, ?, ?)',
                     ("a note", ("bytes " + PW).encode("utf-8"), 7))
        conn.execute('INSERT INTO "me""mo" VALUES (?, ?, ?)', (None, b"", "8"))
        conn.commit()
        conn.close()
        self.assertEqual(self.texts(path), [
            ("0", "log row 1, id", None, None),
            ({"content": [{"type": "tool_use", "name": "bash",
                           "input": {"command": "cat .env"}}]},
             "log row 1, body", None, None),
            ("1", "log row 2, id", None, None),
            ({"content": [{"type": "tool_result",
                           "content": "API_KEY=" + KEY + "\n"}]},
             "log row 2, body", None, None),
            ("2", "log row 3, id", None, None),
            ("not JSON: STRIPE=" + KEY2, "log row 3, body", None, None),
            ("a note", 'me"mo row 1, note', None, None),
            ("bytes " + PW, 'me"mo row 1, raw', None, None)])

    def test_clean_finds_what_it_holds_read_only(self):
        path = self.database("a1", [
            (body("bash", {"command": "cat .env"}), 1758550000),
            (_result("API_KEY=" + KEY + "\nDB_PASSWORD=" + PW + "\n"),
             1758550001)])
        values = {}
        findings, masks = clean.scan_store(self.src, self.src.store_at(path),
                                           values)
        self.assertEqual(sorted(values.values()), sorted([KEY, PW]))
        self.assertEqual(masks, set())
        for finding in findings.values():
            self.assertEqual((finding["files"], finding["sources"],
                              finding["read_only"], finding["origins"]),
                             ({path}, {"openclaw"}, {path}, set()))

    def test_a_file_that_is_not_a_database_warns_and_yields_nothing(self):
        path = os.path.join(self.state, "agents", "a1", DB)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("not a database " + KEY)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.texts(path), [])
        self.assertIn("warning: cannot read %s" % path, err.getvalue())

    def test_a_locked_database_is_read_from_a_copy_that_is_removed(self):
        path = self.database("a1", [(_result("API_KEY=" + KEY), 1758550000)])
        real = sqlite3.connect
        opened = []

        def locked(*args, **kwargs):
            opened.append(args[0])
            if len(opened) == 1:
                raise sqlite3.OperationalError("database is locked")
            return real(*args, **kwargs)

        with mock.patch.object(_sqlite.sqlite3, "connect", side_effect=locked):
            texts = self.texts(path)
        self.assertEqual(len(opened), 2)
        self.assertNotIn(os.path.dirname(path), opened[1])
        self.assertIn(({"content": [{"type": "tool_result",
                                     "content": "API_KEY=" + KEY}]},
                       "log row 1, body", None, None), texts)
        # tearDown: the copy's ranwhat-* temp directory is gone

    def test_a_reader_that_stops_early_leaves_no_copy(self):
        path = self.database("a1", [(_result(KEY), 1758550000)] * 3)
        real = sqlite3.connect
        opened = []

        def locked(*args, **kwargs):
            opened.append(args[0])
            if len(opened) == 1:
                raise sqlite3.OperationalError("database is locked")
            return real(*args, **kwargs)

        with mock.patch.object(_sqlite.sqlite3, "connect", side_effect=locked):
            texts = self.src.secret_texts(self.src.store_at(path))
            next(texts)
            texts.close()

    def test_mask_refuses(self):
        path = self.database("a1", [(_result("API_KEY=" + KEY), 1758550000)])
        store = self.src.store_at(path)
        before = _sha(path)
        self.assertEqual(self.src.mask(store, [KEY]),
                         MaskResult(path, skipped="read-only"))
        self.assertEqual(_sha(path), before)


class NeverWritten(_Case):
    """The database belongs to a running agent. Read for actions and for
    secrets, by the adapter and by every command, masked or not, it is
    left byte for byte as it was: the database, its -wal and its -shm."""

    ROWS = [(body("bash", {"command": "cat .env"}), 1758550000),
            (_result("API_KEY=" + KEY + "\nDB_PASSWORD=" + PW + "\n"), 1758550001),
            (body("bash", {"command": "./deploy.sh prod " + PW
                           + " -e 'DROP DATABASE prod '"}), 1758550002)]

    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.state, "agents", "a1", DB)
        self.backups = os.path.join(self.home, "backups")
        patch = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        patch.start()
        self.addCleanup(patch.stop)

    def read_everything(self):
        store = self.src.store_at(self.path)
        self.assertGreater(len(list(self.src.tool_calls(store))), 0)
        self.assertGreater(len(list(self.src.secret_texts(store))), 0)
        self.assertEqual(self.src.mask(store, [KEY, PW]),
                         MaskResult(self.path, skipped="read-only"))

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = cli.main(list(argv))
            except SystemExit as exit:
                rc = exit.code
        return rc, out.getvalue(), err.getvalue()

    def every_command(self):
        root = tempfile.mkdtemp(prefix="oc-claude-")
        self.addCleanup(shutil.rmtree, root, True)
        where = ["--root", root, "--state-dir", self.state]
        for argv in (["check"], ["check", "--json"], ["watch"],
                     ["watch", "--json"], ["clean", "--no-interactive"],
                     ["clean", "--json"], ["clean", "--apply"],
                     ["clean", "--apply", "--json"]):
            with self.subTest(argv=argv):
                rc, out, err = self.run_cli(*(argv + where))
                self.assertEqual(rc, 0, err)
                self.assertNotIn(PW, out + err)
        return out

    def test_with_its_writer_open(self):
        writer = _wal_database(self.path, self.ROWS)
        self.addCleanup(writer.close)
        before = _files(self.path)
        self.assertEqual(sorted(before), ["", "-shm", "-wal"])
        self.assertGreater(len(before["-wal"]), 0)
        self.read_everything()
        out = self.every_command()
        self.assertEqual(_files(self.path), before)
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.path))),
                         ["openclaw-agent.sqlite", "openclaw-agent.sqlite-shm",
                          "openclaw-agent.sqlite-wal"])
        self.assertFalse(os.path.exists(self.backups))
        doc = json.loads(out)
        self.assertEqual(doc["changed"], [])
        self.assertEqual(set(doc["not_masked"].values()), {"read-only"})
        self.assertEqual(list(doc["not_masked"]), [self.path])

    def test_a_commit_its_writer_has_not_read_back(self):
        """A reader of a WAL database takes a read mark in the -shm (bytes
        100 to 119) when none there names the last commit: SQLite's own
        locking, which every reader of the database does, the agent's too.
        Nothing else in the -shm changes, and the database and its -wal not
        at all."""
        writer = _wal_database(self.path, self.ROWS, read_after=False)
        self.addCleanup(writer.close)
        before = _files(self.path)
        self.read_everything()
        self.every_command()
        after = _files(self.path)
        self.assertEqual((after[""], after["-wal"]), (before[""], before["-wal"]))
        self.assertEqual(len(after["-shm"]), len(before["-shm"]))
        changed = [i for i, (a, b) in enumerate(zip(before["-shm"], after["-shm"]))
                   if a != b]
        self.assertTrue(all(100 <= i < 120 for i in changed), changed)

    def test_not_in_wal_mode(self):
        self.database("a1", self.ROWS)
        before = _files(self.path)
        self.assertEqual(sorted(before), [""])
        self.read_everything()
        self.every_command()
        self.assertEqual(_files(self.path), before)
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.path))),
                         ["openclaw-agent.sqlite"])


if __name__ == "__main__":
    unittest.main()
