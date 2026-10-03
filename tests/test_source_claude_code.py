"""Claude Code on the Source interface (design 3.9 and 7.1).

The port changes where the reading lives, not what is read: watch and
clean keep their own names for it (test_sources_port.py checks they are
these), and every existing test of them still runs unchanged. These pin
the adapter itself: where it looks on each OS, which files are its stores,
the calls it yields (kind None, the input exactly as recorded, so watch
judges each as it did before the port), and masking through clean's own
re-serialising scan_file.

Every value here is synthetic, and every file is in a temp directory.
"""
import contextlib
import io
import json
import os
import shutil
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
from ranwhat.sources import _paths  # noqa: E402
from ranwhat.sources.base import MaskResult, SecretText, Store  # noqa: E402
from ranwhat.sources.claude_code import ClaudeCodeSource  # noqa: E402

KEY = "sk_" "live_" "Qw3Er5Ty7Ui9Op1As3Df5Gh7"
OTHER = "sk_" "live_" "Zx2Cv4Bn6Mm8Lk0Jh2Gf4Ds6"
SLUG = "-tmp-synthetic-proj"
SID = "0a1b2c3d-1111-2222-3333-444455556666"


def tool_use(command, call_id="toolu_01", stamp="2026-10-01T12:00:00.000Z",
             name="Bash", tool_input=None):
    entry = {"type": "assistant", "sessionId": SID, "message": {
        "role": "assistant", "content": [
            {"type": "tool_use", "id": call_id, "name": name,
             "input": {"command": command} if tool_input is None
             else tool_input}]}}
    if stamp is not None:
        entry["timestamp"] = stamp
    return entry


def tool_result(call_id, text):
    return {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": call_id, "content": text}]}}


class _Case(unittest.TestCase):
    """A temp home whose projects directory is CLAUDE_CONFIG_DIR's."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cc-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.config = os.path.join(self.home, ".claude")
        self.root = os.path.join(self.config, "projects")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home,
                                                "CLAUDE_CONFIG_DIR": self.config}),
                   mock.patch.object(_paths, "home", return_value=self.home),
                   mock.patch.object(clean, "BACKUP_ROOT",
                                     os.path.join(self.home, "backups"))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.src = ClaudeCodeSource()

    def write(self, rel, entries, age=3600):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            for e in entries:
                fh.write((e if isinstance(e, str) else json.dumps(e)) + "\n")
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def stores(self, since_days=None):
        return self.src.stores(self.src.locations(), since_days)


class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = ClaudeCodeSource()

    def test_each_os_without_an_override(self):
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.claude/projects", "default")])
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.claude/projects", "default")])
        self.assertEqual(self.src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.claude\\projects", "default")])

    def test_claude_config_dir_holds_the_projects_directory(self):
        env = {"CLAUDE_CONFIG_DIR": "/srv/claude"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/srv/claude/projects", "env CLAUDE_CONFIG_DIR")])
        env = {"CLAUDE_CONFIG_DIR": "D:\\claude"}
        self.assertEqual(self.src.default_paths(env, "C:\\Users\\u", "win32"),
                         [("D:\\claude\\projects", "env CLAUDE_CONFIG_DIR")])

    def test_an_empty_variable_is_unset(self):
        # watch.claude_projects() has always read it with `or`
        self.assertEqual(self.src.default_paths({"CLAUDE_CONFIG_DIR": ""},
                                                "/home/u", "linux"),
                         [("/home/u/.claude/projects", "default")])

    def test_what_watch_reads_by_default(self):
        for env in ({}, {"CLAUDE_CONFIG_DIR": "/srv/claude"}):
            with mock.patch.dict(os.environ, env, clear=False):
                if not env:
                    os.environ.pop("CLAUDE_CONFIG_DIR", None)
                [loc] = self.src.locations()
                self.assertEqual(loc.path, watch.claude_projects())

    def test_the_variable_is_read_when_asked(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/set/later"}):
            [loc] = self.src.locations()
        self.assertEqual(loc.path, os.path.abspath("/set/later/projects"))
        self.assertEqual(loc.how, "env CLAUDE_CONFIG_DIR")


class Registry(unittest.TestCase):

    def test_first_in_the_registry(self):
        self.assertEqual(sources.ids()[0], "claude-code")
        src = sources.get("claude-code")
        self.assertIsInstance(src, ClaudeCodeSource)
        self.assertEqual((src.name, src.unit, src.env),
                         ("Claude Code", "transcript", ("CLAUDE_CONFIG_DIR",)))
        self.assertIn("--root", src.path_means)
        self.assertTrue(src.searched)

    def test_importing_it_imports_neither_watch_nor_clean(self):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                "import ranwhat.sources.claude_code; "
                "print('ranwhat.watch' in sys.modules, "
                "'ranwhat.clean' in sys.modules)")
        out = subprocess.run([sys.executable, "-c", code, REPO],
                             capture_output=True, text=True, encoding="utf-8",
                             timeout=20)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.split(), ["False", "False"])


class Discovery(_Case):

    def test_sessions_and_subagents_newest_first(self):
        old = self.write(SLUG + "/old.jsonl", [tool_use("ls")], age=7200)
        new = self.write(SLUG + "/" + SID + ".jsonl", [tool_use("ls")], age=60)
        sub = self.write(SLUG + "/" + SID + "/subagents/agent-a1.jsonl",
                         [tool_use("ls")], age=600)
        flow = self.write(SLUG + "/" + SID + "/subagents/wf/r1/agent-b2.jsonl",
                          [tool_use("ls")], age=900)
        self.write(SLUG + "/" + SID + "/subagents/wf/journal.jsonl",
                   [{"result": "not a transcript"}])
        self.write(SLUG + "/notes.txt", ["not a transcript"])
        found = self.stores()
        self.assertEqual([s.path for s in found], [new, sub, flow, old])
        self.assertEqual([s.path for s in found],
                         watch.discover(self.root))

    def test_each_store_says_what_it_is(self):
        path = self.write(SLUG + "/" + SID + ".jsonl", [tool_use("ls")])
        sub = self.write(SLUG + "/" + SID + "/subagents/agent-a1.jsonl",
                         [tool_use("ls")], age=7200)
        first, second = self.stores()
        self.assertEqual(
            (first.source, first.path, first.format, first.role, first.unit,
             first.session, first.project, first.masking),
            ("claude-code", path, "jsonl", "transcript", "transcript", SID,
             SLUG, "rewrite"))
        # a subagent's transcript belongs to its session
        self.assertEqual((second.session, second.project), (SID, SLUG))
        self.assertIsInstance(first, Store)

    def test_the_window_drops_transcripts_last_written_before_it(self):
        self.write(SLUG + "/old.jsonl", [tool_use("ls")], age=40 * 86400)
        recent = self.write(SLUG + "/new.jsonl", [tool_use("ls")])
        self.assertEqual([s.path for s in self.stores(since_days=30)], [recent])
        self.assertEqual(len(self.stores()), 2)

    def test_a_missing_root_is_no_stores(self):
        self.assertEqual(self.stores(), [])
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (False, 0))

    def test_locations_count_what_is_there(self):
        self.write(SLUG + "/a.jsonl", [tool_use("ls")])
        self.write(SLUG + "/b.jsonl", [tool_use("ls")], age=400 * 86400)
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.exists, loc.found),
                         (self.root, True, 2))
        [given] = self.src.locations(override=self.root)
        self.assertEqual((given.how, given.found), ("--path", 2))


class ToolCalls(_Case):

    def calls(self, path):
        return list(self.src.tool_calls(self.src.store_at(path)))

    def test_each_call_as_recorded(self):
        path = self.write(SLUG + "/" + SID + ".jsonl", [
            tool_use("rm -rf ~/Documents/x", "toolu_01"),
            tool_result("toolu_01", "done"),
            tool_use("cat notes.md", "toolu_02", stamp=None, name="Read",
                     tool_input={"file_path": "notes.md"})])
        first, second = self.calls(path)
        self.assertEqual(
            (first.source, first.store, first.session, first.project,
             first.timestamp, first.tool_name, first.tool_call_id, first.kind,
             first.known, first.tool_input),
            ("claude-code", path, SID, SLUG, "2026-10-01T12:00:00.000Z",
             "Bash", "toolu_01", None, False,
             {"command": "rm -rf ~/Documents/x"}))
        self.assertIsNone(second.timestamp)
        self.assertEqual(second.tool_input, {"file_path": "notes.md"})

    def test_an_input_that_is_not_an_object_is_kept_as_it_is(self):
        # watch has always judged it as recorded: a string parsed into an
        # object here would be judged as a different call
        raw = '{"command": "rm -rf ~/Documents/x"}'
        path = self.write(SLUG + "/s.jsonl", [
            tool_use(None, tool_input=raw),
            tool_use(None, "toolu_02", tool_input=["rm", "-rf", "/"])])
        first, second = self.calls(path)
        self.assertEqual(first.tool_input, raw)
        self.assertEqual(second.tool_input, ["rm", "-rf", "/"])
        for call in (first, second):
            self.assertEqual(watch.judge(call),
                             watch.evaluate(call.tool_name, call.tool_input))

    def test_names_ids_and_times_that_are_not_strings(self):
        entry = tool_use("ls", call_id={"odd": 1})
        entry["timestamp"] = 1790000000
        entry["message"]["content"][0]["name"] = {"not": "a name"}
        path = self.write(SLUG + "/s.jsonl", [entry])
        [call] = self.calls(path)
        self.assertEqual((call.tool_name, call.timestamp, call.tool_call_id),
                         ("?", None, {"odd": 1}))

    def test_lines_that_are_not_calls_are_skipped(self):
        path = self.write(SLUG + "/s.jsonl", [
            "not json", "[1, 2]", '"text"', {"message": "text"},
            {"message": {"content": "text"}},
            {"message": {"content": [{"type": "text", "text": "rm -rf /"}]}},
            tool_use("ls"), '{"message": {"content": [{"type": "tool_u'])
        self.assertEqual([c.tool_input for c in self.calls(path)],
                         [{"command": "ls"}])

    def test_a_missing_transcript_yields_nothing_and_says_nothing(self):
        gone = os.path.join(self.root, SLUG, "gone.jsonl")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(gone), [])
        self.assertEqual(err.getvalue(), "")

    def test_judged_as_watch_judges_them(self):
        path = self.write(SLUG + "/" + SID + ".jsonl", [
            tool_use("rm -rf ~/Documents/x", "toolu_01"),
            tool_use("grep -rn 'rm -rf' .", "toolu_02"),
            tool_use(None, "toolu_03", name="Read",
                     tool_input={"file_path": "~/.ssh/id_rsa"}),
            tool_use(None, "toolu_04", name="Write",
                     tool_input={"file_path": "x.sh", "content": "rm -rf /"})])
        rules = [[h["rule"] for h in watch.judge(c)[0]] for c in self.calls(path)]
        self.assertEqual(rules, [["fs.destructive"], [], ["cred.read"], []])
        records = watch.scan_transcript(path)
        self.assertEqual([r["tool_call_id"] for r in records],
                         ["toolu_01", "toolu_03"])
        self.assertEqual([(r["session"], r["project"]) for r in records],
                         [(SID, SLUG)] * 2)


def _deep(depth):
    """JSON text of a list nested depth levels."""
    return "[" * depth + "]" * depth


def _in_place(entry, placeholder, depth):
    """The entry's line with its placeholder string swapped for _deep(depth)."""
    return json.dumps(entry).replace(json.dumps(placeholder), _deep(depth), 1)


class NestedPastTheStack(_Case):
    """A transcript is written by another program, so any value in it may
    be nested deeper than Python recurses. Python 3.9's json stops near
    1,000 levels and 3.14's reads 100,000, so what one let through met
    watch's own walks, and one such call ended the run."""

    def test_a_call_nested_past_the_stack_is_judged_and_the_rest_read(self):
        path = self.write(SLUG + "/s.jsonl", [
            tool_use("rm -rf ~/Documents/before", "toolu_01"),
            _in_place(tool_use(None, "toolu_02", tool_input={
                "command": "rm -rf ~/Documents/deep", "args": "ARGS"}), "ARGS", 100000),
            _in_place(tool_result("toolu_02", "OUT"), "OUT", 100000),
            _deep(100000),
            tool_use("rm -rf ~/Documents/after", "toolu_03"),
            tool_result("toolu_03", "API_KEY=" + KEY)])
        evidence = [r["hits"][0]["evidence"] for r in watch.scan_transcript(path)]
        self.assertIn("rm -rf ~/Documents/before", evidence)
        self.assertIn("rm -rf ~/Documents/after", evidence)
        texts = list(self.src.secret_texts(self.src.store_at(path)))
        self.assertIn(KEY, json.dumps(texts[-1].node))

    def test_an_id_nested_deep_is_cut_in_the_record(self):
        for depth in (900, 100000):
            path = self.write(SLUG + "/s%d.jsonl" % depth, [
                _in_place(tool_use("rm -rf ~/Documents/deep", "ID"), "ID", depth),
                tool_use("rm -rf ~/Documents/after", "toolu_02")])
            with self.subTest(depth=depth):
                records = watch.scan_transcript(path)
                self.assertIn("rm -rf ~/Documents/after",
                              [r["hits"][0]["evidence"] for r in records])
                doc = json.loads(cli._json_text(
                    cli._masked_strings(records, str.strip)))
                for record in doc:
                    node, levels = record["tool_call_id"], 0
                    while isinstance(node, list) and node:
                        node, levels = node[0], levels + 1
                    self.assertLess(levels, 100)


class Secrets(_Case):

    def test_every_line_that_parses_is_a_text(self):
        path = self.write(SLUG + "/s.jsonl", [
            tool_use("cat .env", "toolu_01"),
            tool_result("toolu_01", "API_KEY=" + KEY),
            "not json"])
        texts = list(self.src.secret_texts(self.src.store_at(path)))
        self.assertEqual([t.where for t in texts], ["line 1", "line 2"])
        self.assertIsInstance(texts[1], SecretText)
        self.assertIn(KEY, json.dumps(texts[1].node))


class Masking(_Case):

    def test_mask_goes_through_clean_scan_file(self):
        path = self.write(SLUG + "/s.jsonl", [
            tool_use("cat .env", "toolu_01"),
            tool_result("toolu_01", "API_KEY=%s\nOTHER_KEY=%s" % (KEY, OTHER)),
            tool_use("echo " + KEY, "toolu_02")])
        store = self.src.store_at(path)
        result = self.src.mask(store, [KEY])
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        self.assertIsInstance(result, MaskResult)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn(KEY, text)
        self.assertIn(OTHER, text)
        self.assertEqual(text.count(clean.REDACTION % clean._fingerprint(KEY)), 2)
        for line in text.splitlines():
            json.loads(line)
        self.assertTrue(os.listdir(clean.BACKUP_ROOT))
        again = self.src.mask(store, [KEY])
        self.assertEqual((again.changed, again.skipped), (False, None))


if __name__ == "__main__":
    unittest.main()
