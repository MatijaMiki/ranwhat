"""What the port of Claude Code and OpenClaw adds around them (design 3.5,
3.6 and 3.9): watch.judge, the sources watch reads named from the
registry, the paths= keyword, clean._named_by_input beside
_named_by_call, and watch's and clean's old names, kept.

Every value here is synthetic, and every file is in a temp directory.
"""
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import clean, known, sources, watch  # noqa: E402
from ranwhat.sources import _sqlite, claude_code, openclaw  # noqa: E402
from ranwhat.sources.base import ToolCall  # noqa: E402

KEY = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"


def _rules(result):
    return [h["rule"] for h in result[0]]


class Judge(unittest.TestCase):
    """design 3.5"""

    def test_a_ported_call_is_judged_by_its_name_as_before(self):
        for name, tool_input in (("Bash", {"command": "rm -rf ~/Documents/x"}),
                                 ("Read", {"file_path": "~/.ssh/id_rsa"}),
                                 ("Write", {"content": "rm -rf /"}),
                                 ("Bash", "rm -rf ~/Documents/x"),
                                 ("exec", {"command": "cat ~/.aws/credentials"})):
            call = ToolCall("claude-code", "/p", name, tool_input, decode=False)
            self.assertEqual(watch.judge(call), watch.evaluate(name, tool_input))

    def test_a_shell_call_is_judged_as_its_command(self):
        call = ToolCall("x", "/p", "exec_command",
                        {"cmd": ["bash", "-lc", "rm -rf ~/Documents/x"],
                         "workdir": "/w", "justification": "tidy"},
                        kind="shell", known=True,
                        command="rm -rf ~/Documents/x", workdir="/w",
                        consumed=("cmd",))
        hits, payload = watch.judge(call)
        self.assertEqual(_rules((hits, payload)), ["fs.destructive"])
        self.assertIn("~/Documents/x", hits[0]["evidence"])
        # what it was judged as: the command, the rest of the input, the
        # working directory, and not the argv the command came from
        self.assertEqual((hits, payload), watch.evaluate(
            "Bash", {"command": "rm -rf ~/Documents/x", "workdir": "/w",
                     "justification": "tidy"}))

    def test_a_read_call_is_judged_by_the_paths_it_opened(self):
        call = ToolCall("x", "/p", "read_file", {"target": "~/.ssh/id_rsa"},
                        kind="read", known=True, paths=["~/.ssh/id_rsa"],
                        consumed=("target",))
        self.assertEqual(_rules(watch.judge(call)), ["cred.read"])

    def test_other_kinds_answer_only_to_what_they_carry(self):
        write = ToolCall("x", "/p", "exec", {"content": "rm -rf /"},
                         kind="write", known=True)
        self.assertEqual(_rules(watch.judge(write)), [])
        leaked = ToolCall("x", "/p", "exec", {"content": "API_KEY=" + KEY},
                          kind="write", known=True)
        self.assertEqual(_rules(watch.judge(leaked)), ["secret.literal"])
        # a shell call whose command was not found is not judged as a shell
        empty = ToolCall("x", "/p", "bash", {"command": "rm -rf ~/x"},
                         kind="shell", known=True)
        self.assertEqual(_rules(watch.judge(empty)), [])

    def test_a_name_the_adapter_does_not_know_is_judged_by_name(self):
        call = ToolCall("x", "/p", "mcp__box__bash", {"command": "rm -rf ~/x"},
                        kind="other", known=False)
        self.assertEqual(_rules(watch.judge(call)), ["fs.destructive"])

    def test_known_values_are_masked_as_evaluate_masks_them(self):
        typed = "hunter2-" + "zz9Qx"
        matcher = known.Matcher.of([typed])
        tool_input = {"command": "rm -rf ~/x; echo " + typed}
        call = ToolCall("claude-code", "/p", "Bash", tool_input, decode=False)
        judged = watch.judge(call, matcher)
        self.assertEqual(judged, watch.evaluate("Bash", tool_input, matcher))
        self.assertNotIn(typed, judged[1])


class RecordedInput(unittest.TestCase):

    def test_decode_false_keeps_the_input_as_recorded(self):
        for value in ('{"command": "ls"}', "ls -la {", ["a"], None, 3,
                      {"k": 1}):
            call = ToolCall("claude-code", "/p", "Bash", value, decode=False)
            self.assertIs(call.tool_input, value)

    def test_decoding_stays_the_default(self):
        self.assertEqual(ToolCall("x", "/p", "t", '{"k": 1}').tool_input, {"k": 1})


class SourcesWatchReads(unittest.TestCase):

    def test_named_from_the_registry_in_its_order(self):
        """Every adapter, now that watch and clean read them all (it was
        the two ported ones until they were wired)."""
        self.assertEqual(watch.SOURCES, sources.ids())
        self.assertEqual(watch.SOURCES[0], "claude-code")
        self.assertIn("openclaw", watch.SOURCES[-2:])
        self.assertEqual(watch._SOURCE_NAMES,
                         {i: sources.get(i).name for i in watch.SOURCES})


def _transcript(root, command):
    proj = os.path.join(root, "-tmp-synthetic")
    os.makedirs(proj)
    with open(os.path.join(proj, "s.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"timestamp": "2026-10-01T12:00:00Z", "message": {
            "content": [{"type": "tool_use", "id": "t1", "name": "Bash",
                         "input": {"command": command}}]}}) + "\n")


def _database(state, command):
    path = os.path.join(state, "agents", "a1", "agent", "openclaw-agent.sqlite")
    os.makedirs(os.path.dirname(path))
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE log (body TEXT, ts INTEGER)")
    conn.execute("INSERT INTO log VALUES (?, ?)", (json.dumps(
        {"name": "bash", "input": {"command": command}}), int(time.time())))
    conn.commit()
    conn.close()


class PathsKeyword(unittest.TestCase):
    """scan_sources_counted keeps its signature; root and state_dir are the
    overrides for the two ported sources, and paths={id: path} carries any
    source's (design 3.9)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="port-paths-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "projects")
        self.state = os.path.join(self.tmp, "openclaw")
        _transcript(self.root, "rm -rf ~/Documents/a")
        _database(self.state, "rm -rf ~/Documents/b")
        self.nowhere = os.path.join(self.tmp, "nowhere")

    def evidence(self, records):
        return sorted(h["evidence"] for r in records for h in r["hits"])

    def test_paths_point_each_source(self):
        records, counts = watch.scan_sources_counted(
            paths={"claude-code": self.root, "openclaw": self.state})
        self.assertEqual(counts, {"claude-code": 1, "openclaw": 1})
        self.assertEqual(len(self.evidence(records)), 2)

    def test_root_and_state_dir_win_over_paths(self):
        records, counts = watch.scan_sources_counted(
            root=self.root, state_dir=self.state,
            paths={"claude-code": self.nowhere, "openclaw": self.nowhere})
        self.assertEqual(counts, {"claude-code": 1, "openclaw": 1})

    def test_the_old_call_is_unchanged(self):
        with_paths = watch.scan_sources_counted(
            ("claude-code", "openclaw"), self.root, self.state, None)
        self.assertEqual(with_paths[1], {"claude-code": 1, "openclaw": 1})


class NamedByInput(unittest.TestCase):
    """design 3.6: _named_by_call, for a ToolCall."""

    def test_a_ported_call_names_what_named_by_call_names(self):
        for tool_input in ({"command": "cat api/.env"},
                           {"command": "cat > notes.md <<'EOF'\nsee .env\nEOF"},
                           {"file_path": "/srv/app/.env"},
                           {"command": "ls"}, "cat .env", ["cat", ".env"]):
            call = ToolCall("claude-code", "/p", "Bash", tool_input, decode=False)
            self.assertEqual(clean._named_by_input(call),
                             clean._named_by_call({"input": tool_input}),
                             tool_input)

    def test_the_command_stands_in_for_what_it_was_made_of(self):
        call = ToolCall("x", "/p", "exec_command",
                        {"cmd": ["bash", "-lc", "cat api/.env"], "workdir": "/w"},
                        kind="shell", known=True, command="cat api/.env",
                        consumed=("cmd",))
        self.assertEqual(clean._named_by_input(call), ["api/.env"])
        heredoc = ToolCall("x", "/p", "exec_command",
                           {"cmd": "ignored"}, kind="shell", known=True,
                           command="cat > t.py <<'EOF'\nload('.env')\nEOF",
                           consumed=("cmd",))
        self.assertEqual(clean._named_by_input(heredoc), [])

    def test_an_unconsumed_command_key_is_kept_beside_it(self):
        call = ToolCall("x", "/p", "run", {"command": "cat a/.env", "c": "x"},
                        kind="shell", known=True, command="cat b/.env",
                        consumed=("c",))
        self.assertEqual(sorted(clean._named_by_input(call)), ["a/.env", "b/.env"])


class OldNamesKept(unittest.TestCase):
    """design 3.9: tests and the CLI use these; each is the adapter's own,
    or a wrapper over it."""

    def test_watch(self):
        for name in ("claude_projects", "CLAUDE_PROJECTS", "discover",
                     "_transcripts", "scan_transcript", "scan_all",
                     "openclaw_state_dir", "OPENCLAW_STATE_DEFAULT",
                     "openclaw_databases", "scan_openclaw_db", "scan_openclaw",
                     "_open_readonly", "_find_tool_calls", "_as_iso",
                     "_parse_stamp", "_quote_ident", "SOURCES", "_SOURCE_NAMES",
                     "scan_sources_counted", "scan_sources", "locations",
                     "render", "_nothing_read", "_scanned_words", "_days",
                     "_shown_path", "transcript_place", "judge"):
            self.assertTrue(hasattr(watch, name), name)
        self.assertIs(watch.discover, claude_code.discover)
        self.assertIs(watch._transcripts, claude_code.transcripts)
        self.assertIs(watch.transcript_place, claude_code.place)
        self.assertIs(watch.openclaw_databases, openclaw.databases)
        self.assertIs(watch._find_tool_calls, openclaw.find_tool_calls)
        self.assertIs(watch._open_readonly, _sqlite.open_readonly)
        self.assertIs(watch._quote_ident, _sqlite.quote_ident)
        self.assertEqual(watch.OPENCLAW_STATE_DEFAULT, openclaw.STATE_DEFAULT)

    def test_clean(self):
        for name in ("scan", "scan_file", "project_path",
                     "_named_by_call", "_named_by_input"):
            self.assertTrue(hasattr(clean, name), name)
        # Kept by the port, gone with design 3.9's follow-up: OpenClaw is
        # searched for secrets, and nothing is left to say it is not.
        self.assertFalse(hasattr(clean, "UNSEARCHED"))


class NoNetworkModule(unittest.TestCase):
    """watch imports the registry now, and check, watch and clean import
    no network module (test_work_done.py): nor may any adapter, even
    reading a database."""

    def test_reading_every_adapter_imports_none(self):
        tmp = tempfile.mkdtemp(prefix="port-net-")
        self.addCleanup(shutil.rmtree, tmp, True)
        # Windows allows no ? in a file name.
        code = ("import sys, sqlite3, os\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "import ranwhat.sources as s\n"
                "from ranwhat.sources import _sqlite\n"
                "d = sys.argv[2]\n"
                "path = os.path.join(d, 'a #%.db' if os.name == 'nt' "
                "else 'a ?#%.db')\n"
                "sqlite3.connect(path).execute('CREATE TABLE t (x)').connection.close()\n"
                "with _sqlite.readonly(path) as conn:\n"
                "    assert _sqlite.tables(conn) == ['t']\n"
                "for src in s.sources():\n"
                "    for loc in src.locations(override=d):\n"
                "        list(src.stores([loc]))\n"
                "print(sorted(m for m in ('urllib.request', 'http.client', 'ssl')"
                " if m in sys.modules))\n")
        out = subprocess.run([sys.executable, "-c", code, REPO, tmp],
                             capture_output=True, text=True, encoding="utf-8",
                             timeout=20)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "[]")


    def test_a_database_uri_is_one_sqlite_reads(self):
        # SQLite takes a URI authority only when it is empty or localhost,
        # so \\server\share is file:////server/share: an empty authority,
        # then the UNC path. pathname2url gave that until Python 3.12 and
        # 3.13 changed it to //server/share, which SQLite refuses.
        for path, url in (
                ("C:\\Users\\a b\\x?.db", "///C:/Users/a%20b/x%3F.db"),
                ("\\\\server\\share\\x #.db", "////server/share/x%20%23.db"),
                ("D:\\%\\y", "///D:/%25/y")):
            self.assertEqual(_sqlite._url_path(path, windows=True), url, path)
        for path, url in (
                ("/a b/x?#%.db", "/a%20b/x%3F%23%25.db"),
                ("/home/u/.openclaw/agents/a1/agent/x.sqlite",
                 "/home/u/.openclaw/agents/a1/agent/x.sqlite")):
            self.assertEqual(_sqlite._url_path(path, windows=False), url, path)

    @unittest.skipIf(os.name == "nt", "a POSIX path stands in for a UNC one")
    def test_sqlite_refuses_a_host_and_reads_an_empty_authority(self):
        tmp = os.path.realpath(tempfile.mkdtemp(prefix="port-uri-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "x.db")
        sqlite3.connect(path).execute("CREATE TABLE t (x)").connection.close()
        conn = sqlite3.connect("file:///" + path + "?mode=ro", uri=True)
        self.addCleanup(conn.close)
        self.assertEqual(_sqlite.tables(conn), ["t"])
        with self.assertRaises(sqlite3.OperationalError):
            sqlite3.connect("file://server" + path + "?mode=ro", uri=True)


class SourcesAreUtf8(unittest.TestCase):
    """test_text_encoding.py reads ranwhat/*.py; the adapters are a level
    down (design 5.3)."""

    def test_every_text_open_names_its_encoding(self):
        import test_text_encoding
        paths = sorted(glob.glob(os.path.join(REPO, "ranwhat", "sources", "*.py")))
        self.assertGreater(len(paths), 10)
        found = {os.path.basename(p): test_text_encoding._unnamed_encodings(p)
                 for p in paths}
        self.assertEqual({k: v for k, v in found.items() if v}, {})


if __name__ == "__main__":
    unittest.main()
