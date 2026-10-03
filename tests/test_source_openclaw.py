"""OpenClaw on the Source interface (design 3.9 and 7.2).

Supported, not promoted: the adapter is last in the registry, and reads
what watch read before the port (test_openclaw.py and the rest still pin
that), and now text in a column of any declared type too. Its databases
are read-only. Since design 3.9's follow-up they are searched for secrets
as well, every text cell of every table, through the same read-only open;
mask refuses, and the database, its -wal and its -shm are left as they
were, and nothing is made beside them.

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
from ranwhat.sources import _paths, _sqlite, openclaw  # noqa: E402
from ranwhat.sources.base import MaskResult, Store  # noqa: E402
from ranwhat.sources.openclaw import OpenClawSource  # noqa: E402

KEY = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"
KEY2 = "sk_" "live_" "Zx8Cv6Bn4Mm2Lk9Jh7Gf5Ds"
PW = "Vb6nM3qW" "z8Kt2Lp5Rx"
PW2 = "Tn5GhYw8" "Qa3Zc6Rm1J"
# What the report says of a database that holds a secret.
WHY = ("OpenClaw keeps this in a database; delete the session in "
       "OpenClaw.")
DB = os.path.join("agent", "openclaw-agent.sqlite")


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _ranwhat_temp_dirs():
    """The copies _sqlite makes. Not isolated_home's ranwhat-home-*: any
    test run beside this one makes one of those."""
    return set(x for x in os.listdir(tempfile.gettempdir())
               if x.startswith("ranwhat-") and not x.startswith("ranwhat-home-"))


def body(name, args, kind="tool_use"):
    return json.dumps({"content": [{"type": kind, "name": name, "input": args}]})


def _run_cli(*argv):
    """(exit code, stdout, stderr) of one command, run in this process."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(argv))
        except SystemExit as exit:
            rc = exit.code
    return rc, out.getvalue(), err.getvalue()


# Every command that reads OpenClaw, as NeverWritten runs them.
COMMANDS = (["check"], ["check", "--json"], ["watch"], ["watch", "--json"],
            ["clean", "--no-interactive"], ["clean", "--json"],
            ["clean", "--apply"], ["clean", "--apply", "--json"])


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

    def test_the_variable_is_trimmed_and_an_empty_one_is_unset(self):
        # as OpenClaw reads it
        for value in ("", "  "):
            env = {"OPENCLAW_STATE_DIR": value}
            self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                             [("/home/u/.openclaw", "default")])
            with mock.patch.dict(os.environ, env):
                self.assertEqual(watch.openclaw_state_dir(),
                                 openclaw.STATE_DEFAULT)
        env = {"OPENCLAW_STATE_DIR": " /srv/oc "}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/srv/oc", "env OPENCLAW_STATE_DIR")])


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
    """Every text cell of every table is searched (design 3.9's
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

    def test_it_says_every_store_is_read_only_before_one_is_found(self):
        # `ranwhat sources` and the site say so of OpenClaw without a store.
        self.assertTrue(self.src.read_only)
        path = self.database("a1", [(_result("ok"), 1758550000)])
        self.assertEqual(self.src.store_at(path).masking, "read-only")

    def test_mask_refuses(self):
        path = self.database("a1", [(_result("API_KEY=" + KEY), 1758550000)])
        store = self.src.store_at(path)
        before = _sha(path)
        self.assertEqual(self.src.mask(store, [KEY]),
                         MaskResult(path, skipped="read-only"))
        self.assertEqual(_sha(path), before)


def _not_utf8(text):
    """text as UTF-8, then the bytes a JS writer leaves when it cuts a
    string between the halves of a surrogate pair: not UTF-8."""
    return text.encode("utf-8") + b"\xed\xa0\xbd tail"


DEPLOY = "./deploy.sh prod %s -e 'DROP DATABASE prod '"


class TextThatIsNotUtf8(_Case):
    """A TEXT cell whose bytes are not UTF-8. Python's sqlite3 raised an
    OperationalError quoting the cell, password and all, which check and
    watch printed in a traceback and clean in its warning; the read
    stopped there (on 3.9 and 3.10 losing the row before as well), so
    nothing in that row, the one before or any after was found, and the
    index kept that as all the database held."""

    def make(self):
        path = self.database("a1", [
            (body("bash", {"command": "cat .env"}), 1758550000),
            (_result("DB_PASSWORD=" + PW2 + "\n"), 1758550001)])
        conn = sqlite3.connect(path)
        conn.execute("INSERT INTO log VALUES (?, CAST(? AS TEXT), ?)",
                     ("2", _not_utf8("Saved DB_PASSWORD=" + PW + "\n"),
                      1758550002))
        conn.executemany("INSERT INTO log VALUES (?, ?, ?)", [
            ("3", body("bash", {"command": DEPLOY % PW}), 1758550003),
            ("4", body("bash", {"command": DEPLOY % PW2}), 1758550004)])
        conn.execute("CREATE TABLE memo (note TEXT)")
        conn.execute("INSERT INTO memo VALUES (?)", ("STRIPE=" + KEY2,))
        conn.commit()
        conn.close()
        return path

    def test_every_row_is_read_and_the_cell_as_it_is(self):
        path = self.make()
        store = self.src.store_at(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            texts = {t.where: t.node for t in self.src.secret_texts(store)}
            calls = self.calls(path)
            values = {}
            clean.scan_store(self.src, store, values)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(texts["log row 3, body"],
                         "Saved DB_PASSWORD=" + PW + "\n\udced\udca0\udcbd tail")
        self.assertIn("log row 2, body", texts)
        self.assertEqual(texts["memo row 1, note"], "STRIPE=" + KEY2)
        self.assertEqual([c.tool_input["command"] for c in calls],
                         ["cat .env", DEPLOY % PW, DEPLOY % PW2])
        self.assertEqual(sorted(values.values()), sorted([PW, PW2, KEY2]))
        self.assertEqual(self.src.unreadable, {})

    def test_no_command_prints_what_it_holds(self):
        self.make()
        root = tempfile.mkdtemp(prefix="oc-claude-")
        self.addCleanup(shutil.rmtree, root, True)
        backups = os.path.join(self.home, "backups")
        with mock.patch.object(clean, "BACKUP_ROOT", backups):
            for argv in COMMANDS:
                with self.subTest(argv=argv):
                    rc, out, err = _run_cli(*(argv + ["--root", root,
                                                      "--state-dir", self.state]))
                    self.assertNotIn("Traceback", err)
                    self.assertEqual(rc, 0)
                    for value in (PW, PW2, KEY2):
                        self.assertNotIn(value, out + err)


class EveryColumnIsRead(_Case):
    """SQLite keeps text in a column of any declared type: CLOB, TEXT(64)
    and LONGTEXT have TEXT affinity, and STRING, INTEGER or DATETIME keep a
    string that does not read as a number. Only TEXT, BLOB, JSON, untyped
    and *CHAR* columns were read, so a password in any other was not found,
    and watch printed it whole where another agent typed it."""

    TYPES = ("TEXT", "CLOB", "TEXT(64)", "LONGTEXT", "STRING", "INTEGER",
             "DATETIME", "NUMERIC", "REAL", "BLOB", "")

    def test_text_in_a_column_of_any_type(self):
        path = os.path.join(self.state, "agents", "a1", DB)
        os.makedirs(os.path.dirname(path))
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE kv (%s)" % ", ".join(
            ("c%d %s" % (i, t)).strip() for i, t in enumerate(self.TYPES)))
        cells = ["DB_PASSWORD=%s%d" % (PW, i) for i in range(len(self.TYPES))]
        conn.execute("INSERT INTO kv VALUES (%s)" % ", ".join(
            "?" * len(cells)), cells)
        conn.execute("CREATE TABLE n (a INTEGER, b REAL, c NUMERIC)")
        conn.execute("INSERT INTO n VALUES (7, 1.5, 3)")
        conn.execute("CREATE TABLE calls (payload CLOB, created_at DATETIME)")
        conn.execute("INSERT INTO calls VALUES (?, ?)",
                     (body("bash", {"command": "rm -rf ~/old"}), 1758550000))
        conn.commit()
        conn.close()
        texts = [(t.node, t.where)
                 for t in self.src.secret_texts(self.src.store_at(path))]
        self.assertEqual(texts[:len(cells)], [
            (cell, "kv row 1, c%d" % i) for i, cell in enumerate(cells)])
        self.assertEqual([where for _node, where in texts[len(cells):]],
                         ["calls row 1, payload"])
        values = {}
        clean.scan_store(self.src, self.src.store_at(path), values)
        self.assertEqual(sorted(values.values()),
                         sorted(PW + str(i) for i in range(len(cells))))
        [call] = self.calls(path)
        self.assertEqual((call.tool_input, call.project, call.timestamp),
                         ({"command": "rm -rf ~/old"}, "calls",
                          "2025-09-22T14:06:40Z"))


class StateDirAsOpenClawReadsIt(_Case):
    """OPENCLAW_STATE_DIR and --state-dir read as OpenClaw reads them: "~"
    expanded, the variable trimmed and an empty one unset, and the folder
    taken as it is named. watch read them as given, so in one run sources
    and clean read a folder whose actions watch passed over."""

    def setUp(self):
        super().setUp()
        self.root = tempfile.mkdtemp(prefix="oc-claude-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def rm_rf(self):
        return self.database("a1", [(body("bash", {"command": "rm -rf ~"}),
                                     int(time.time()))])

    def watched(self, *argv):
        rc, out, err = _run_cli("watch", "--json", "--source", "openclaw",
                                "--root", self.root, *argv)
        self.assertEqual(rc, 0, err)
        return [h["rule"] for r in json.loads(out) for h in r["hits"]]

    def found(self, *argv):
        rc, out, err = _run_cli("sources", "--json", "--source", "openclaw",
                                *argv)
        self.assertEqual(rc, 0, err)
        [entry] = json.loads(out)
        return entry["transcripts"]

    def test_a_tilde_in_the_variable_or_the_flag(self):
        self.state = os.path.join(self.home, "oc")
        path = self.rm_rf()
        with mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": "~/oc"}):
            self.assertEqual(watch.openclaw_state_dir(), self.state)
            self.assertEqual(watch.openclaw_databases(), [path])
            self.assertEqual(self.watched(), ["fs.destructive"])
            self.assertEqual(self.found(), 1)
        os.environ.pop("OPENCLAW_STATE_DIR")
        self.assertEqual(watch.openclaw_databases("~/oc"), [path])
        self.assertEqual(self.watched("--state-dir=~/oc"), ["fs.destructive"])
        self.assertEqual(self.found("--state-dir=~/oc"), 1)

    def test_an_empty_variable_reads_the_default(self):
        self.rm_rf()
        with mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": ""}), \
                mock.patch.object(openclaw, "STATE_DEFAULT", self.state):
            self.assertEqual(self.watched(), ["fs.destructive"])
            self.assertEqual(self.found(), 1)

    def test_brackets_in_its_name(self):
        self.state = os.path.join(self.home, "oc [x]")
        path = self.rm_rf()
        self.assertEqual(watch.openclaw_databases(self.state), [path])
        self.assertEqual(self.watched("--state-dir", self.state),
                         ["fs.destructive"])


class _Failing(object):
    """A connection whose SELECT from `table` gives one row and then fails
    as a damaged page does, its message quoting a cell."""

    def __init__(self, conn, table):
        self.conn, self.table = conn, table

    def execute(self, sql, *args):
        cursor = self.conn.execute(sql, *args)
        if sql.startswith("SELECT") and sql.endswith(
                "FROM %s" % _sqlite.quote_ident(self.table)):
            return self._fail(cursor)
        return cursor

    @staticmethod
    def _fail(cursor):
        for i, row in enumerate(cursor):
            if i == 1:
                raise sqlite3.OperationalError(
                    "Could not decode to UTF-8 column 'body' with text "
                    "'DB_PASSWORD=" + PW + "'")
            yield row

    def close(self):
        self.conn.close()


class Unreadable(_Case):
    """A database that cannot be read, or not to its end, warns once a
    run, never with what SQLite said of it (that can quote a cell), and is
    counted, so clean, check and watch say under their report that it was
    not read: "Read OpenClaw: 1 database" and "No secrets found" were all
    they said."""

    def not_a_database(self):
        path = os.path.join(self.state, "agents", "a1", DB)
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("not a database " + KEY)
        return path

    def test_not_a_database_is_counted_once(self):
        path = self.not_a_database()
        store = self.src.store_at(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertEqual(self.src.unreadable, {openclaw.NOT_DATABASE: 1})

    def test_one_that_cannot_be_opened(self):
        path = self.database("a1", [(_result("API_KEY=" + KEY), 1758550000)])
        err = io.StringIO()
        with mock.patch.object(_sqlite, "open_readonly",
                               return_value=(None, None)), \
                contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(path), [])
        self.assertIn("warning: could not open %s" % path, err.getvalue())
        self.assertEqual(self.src.unreadable, {openclaw.NOT_OPENED: 1})

    def test_a_table_that_fails_part_way(self):
        path = self.database("a1", [(_result("API_KEY=" + KEY), 1758550000),
                                    (_result("DB_PASSWORD=" + PW), 1758550001)])
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE memo (note TEXT)")
        conn.execute("INSERT INTO memo VALUES (?)", ("STRIPE=" + KEY2,))
        conn.commit()
        conn.close()
        real = _sqlite.open_readonly

        def failing(p):
            conn, tmp = real(p)
            return _Failing(conn, "log"), tmp

        err = io.StringIO()
        with mock.patch.object(_sqlite, "open_readonly", side_effect=failing), \
                contextlib.redirect_stderr(err):
            texts = [t.where for t in
                     self.src.secret_texts(self.src.store_at(path))]
            self.calls(path)
        self.assertEqual(texts, ["log row 1, id", "log row 1, body",
                                 "memo row 1, note"])
        warning = err.getvalue()
        self.assertEqual(warning.count("warning:"), 1)
        self.assertIn("table log", warning)
        self.assertIn("OperationalError", warning)
        self.assertNotIn(PW, warning)
        self.assertEqual(self.src.unreadable, {openclaw.DAMAGED: 1})

    def test_a_reader_that_fails_says_what_failed_not_its_message(self):
        path = self.database("a1", [(_result("API_KEY=" + KEY), 1758550000)])
        err = io.StringIO()
        with mock.patch.object(openclaw, "SecretText",
                               side_effect=RuntimeError("held " + PW)), \
                contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.secret_texts(
                self.src.store_at(path))), [])
        self.assertIn("RuntimeError", err.getvalue())
        self.assertNotIn(PW, err.getvalue())

    def test_every_report_says_so(self):
        self.not_a_database()
        root = tempfile.mkdtemp(prefix="oc-claude-")
        self.addCleanup(shutil.rmtree, root, True)
        note = "1 OpenClaw file was not read: %s." % openclaw.NOT_DATABASE
        for argv in (["clean", "--no-interactive"], ["check"], ["watch"]):
            with self.subTest(argv=argv):
                rc, out, err = _run_cli(*(argv + ["--root", root,
                                                  "--state-dir", self.state]))
                self.assertEqual(rc, 0, err)
                self.assertIn(note, " ".join(out.split()))
                self.assertEqual(err.count("warning:"), 1, err)
                self.assertNotIn(KEY, out + err)


# Past what json.loads reads on Python 3.9; 3.14 reads it, and then
# json.dumps and str fail on what it read.
DEEP = 100000


def _deep_list():
    """JSON nested DEEP levels, built as a string: building it as a
    structure by recursion would fail the same way."""
    return "[" * DEEP + "]" * DEEP


def _deep_object():
    return '{"a": ' * DEEP + "1" + "}" * DEEP


def _nested():
    """The same as a decoded structure, built in a loop, for a test of
    find_tool_calls on what 3.14 decodes."""
    node = 1
    for _ in range(DEEP):
        node = {"a": node}
    return node


class NestedPastTheStack(_Case):
    """A cell nested deeper than Python's stack ended watch and check with
    a traceback: on 3.9 json.loads raised RecursionError, and on 3.14,
    which reads it, json.dumps and str did. Such a cell, or a string in
    one, is passed over as text that is not JSON is; a call whose input is
    nested so deep is kept; and every other row is still read."""

    BASH = body("bash", {"command": "cat .env"})

    def found(self, agent, *cells):
        path = self.database(agent, [(c, 1758550000) for c in cells])
        return [(c.tool_name, c.tool_input.get("command"))
                for c in self.calls(path)]

    def test_a_cell_nested_past_the_stack_is_skipped_and_the_rest_read(self):
        sibling = {"type": "tool_use", "name": "bash", "input": {"command": "ls"}}
        cells = {
            "a-list": (_deep_list(), []),
            "an-object": (_deep_object(), []),
            "a-string-in-it": (json.dumps({"x": _deep_list(), "call": sibling}),
                               [("bash", "ls")]),
            "a-tool-name": ('{"function": {"name": %s, "arguments": "{}"}}'
                            % _deep_list(), []),
        }
        for agent, (cell, calls) in cells.items():
            with self.subTest(cell=agent):
                self.assertEqual(self.found(agent, cell, self.BASH),
                                 calls + [("bash", "cat .env")])

    def test_a_call_whose_input_is_nested_past_the_stack_is_kept(self):
        cells = {
            "function-arguments": json.dumps({"function": {
                "name": "deploy", "arguments": _deep_object()}}),
            "an-input-string": json.dumps({"type": "tool_use", "name": "deploy",
                                           "input": _deep_object()}),
        }
        for agent, cell in cells.items():
            with self.subTest(cell=agent):
                self.assertEqual(self.found(agent, cell, self.BASH),
                                 [("deploy", None), ("bash", "cat .env")])

    def test_find_tool_calls_passes_over_a_deep_name_and_keeps_deep_arguments_once(self):
        """A name nested so deep is no tool's, and is passed over. An
        OpenAI-style call whose arguments are nested so deep is found twice
        by the walk and kept once."""
        deep = _nested()
        found = openclaw.find_tool_calls([
            {"function": {"name": deep, "arguments": "{}"}},
            {"function": {"name": "deploy", "arguments": deep}},
            {"type": "tool_use", "name": "bash", "input": {"command": "ls"}}])
        self.assertEqual([name for name, _args in found], ["deploy", "bash"])

    def test_watch_check_and_clean_read_past_it(self):
        """Each command as a user runs it, in a Python of its own: it exits
        0 with no traceback, the call and the secret in the rows after the
        deep ones are found, and the database is left as it was."""
        now = int(time.time())
        path = self.database("a1", [(c, now) for c in (
            _deep_list(),
            json.dumps({"function": {"name": "deploy",
                                     "arguments": _deep_object()}}),
            '{"type": "tool_use", "name": "deploy", "input": %s}'
            % _deep_object(),
            self.BASH,
            _result("API_KEY=" + KEY + "\n"))])
        before = _sha(path)
        root = tempfile.mkdtemp(prefix="oc-claude-")
        self.addCleanup(shutil.rmtree, root, True)
        env = dict(os.environ, PYTHONPATH=REPO, PYTHONIOENCODING="utf-8")
        out = {}
        for argv in (["watch", "--json"], ["check"],
                     ["clean", "--json", "--no-interactive"],
                     ["clean", "--apply", "--no-interactive"]):
            with self.subTest(argv=argv):
                run = subprocess.run(
                    [sys.executable, "-m", "ranwhat"] + argv
                    + ["--root", root, "--state-dir", self.state],
                    env=env, capture_output=True, encoding="utf-8",
                    stdin=subprocess.DEVNULL, timeout=120)
                self.assertNotIn("Traceback", run.stderr)
                self.assertEqual(run.returncode, 0, run.stderr[-2000:])
                self.assertNotIn(KEY, run.stdout + run.stderr)
                out[" ".join(argv)] = run.stdout
        self.assertIn("bash", [r["tool_name"]
                               for r in json.loads(out["watch --json"])])
        self.assertEqual(len(json.loads(
            out["clean --json --no-interactive"])["findings"]), 1)
        self.assertEqual(_sha(path), before)


class NeverWritten(_Case):
    """The database belongs to a running agent. Read for actions and for
    secrets, by the adapter and by every command, masked or not, it is
    left byte for byte as it was: the database, its -wal and its -shm,
    and no file is made beside it, with the agent running or not."""

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
        for argv in COMMANDS:
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

    def assertReadAndLeft(self, before, out):
        """Both values found (clean --apply --json, every_command's last),
        and the folder as it was: no file added, none changed."""
        self.assertEqual(len(json.loads(out)["findings"]), 2)
        self.assertEqual(_files(self.path), before)
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.path))),
                         sorted("openclaw-agent.sqlite" + s for s in before))

    def closed(self, writer=None):
        """The database in WAL mode, its writer (made here if not given)
        closed: OpenClaw's SQLite removes the -wal and -shm then, so this
        is how it is whenever the agent is not running."""
        (writer or _wal_database(self.path, self.ROWS)).close()
        for suffix in ("-wal", "-shm"):
            if os.path.exists(self.path + suffix):
                os.remove(self.path + suffix)
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(20)[18:20], b"\x02\x02")

    def test_with_its_writer_closed(self):
        """Opened mode=ro, stock SQLite made an empty -wal and a 32 KB -shm
        beside it (owned by whoever ran ranwhat), and Apple's could not
        open it at all, so its secrets were not found."""
        self.closed()
        before = _files(self.path)
        self.assertEqual(sorted(before), [""])
        self.read_everything()
        self.assertReadAndLeft(before, self.every_command())

    def test_with_a_shm_and_no_wal(self):
        writer = _wal_database(self.path, self.ROWS)
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shm = _files(self.path)["-shm"]
        self.closed(writer)
        with open(self.path + "-shm", "wb") as fh:
            fh.write(shm)
        before = _files(self.path)
        self.assertEqual(sorted(before), ["", "-shm"])
        self.read_everything()
        self.assertReadAndLeft(before, self.every_command())

    def test_with_a_wal_and_no_shm(self):
        """A -wal with no -shm, as a crash or a writer in exclusive locking
        mode leaves it, holds the rows: they are read from a copy."""
        live = os.path.join(self.home, "live", "openclaw-agent.sqlite")
        writer = _wal_database(live, self.ROWS)
        try:
            os.makedirs(os.path.dirname(self.path))
            for suffix in ("", "-wal"):
                shutil.copy2(live + suffix, self.path + suffix)
        finally:
            writer.close()
        before = _files(self.path)
        self.assertEqual(sorted(before), ["", "-wal"])
        self.assertGreater(len(before["-wal"]), 0)
        self.read_everything()
        self.assertReadAndLeft(before, self.every_command())


if __name__ == "__main__":
    unittest.main()
