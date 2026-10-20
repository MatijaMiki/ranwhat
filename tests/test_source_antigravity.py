"""The Google Antigravity adapter (ranwhat/sources/antigravity.py).

Fixtures are the records agy 1.4.3 and the google-antigravity SDK harness
0.1.22 wrote (field for field, from the research notes): one JSON object per
trajectory step; a PLANNER_RESPONSE with tool_calls [{name, args}] followed
by one result step per call, paired by position; the compact copy with
every argument value JSON-encoded; both tool-name families.

Everything runs in temp directories. The home directory and the backup root
point there and the real home is never read. Secrets are synthetic and
token-shaped ones are written as adjacent literals.
"""
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

from ranwhat import clean  # noqa: E402
from ranwhat.sources import _paths  # noqa: E402
from ranwhat.sources import antigravity as ag  # noqa: E402
from ranwhat.sources.antigravity import AntigravitySource  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
CID = "9ab7b2e3-c6d5-4c9c-af57-43983afc2593"
T0 = "2026-10-20T05:44:0%dZ"
PLANNER = "PLANNER_RESPONSE"


def dump(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def user(n, text="do it"):
    return {"step_index": n, "source": "USER_EXPLICIT", "type": "USER_INPUT",
            "status": "DONE", "created_at": T0 % 1,
            "content": "<USER_REQUEST>\n%s\n</USER_REQUEST>" % text}


def planner(n, calls, ts=2):
    return {"step_index": n, "source": "MODEL", "type": PLANNER, "status": "DONE",
            "created_at": T0 % ts, "input_tokens": 10, "cache_read_tokens": 0,
            "output_tokens": 5, "content": "ok",
            "tool_calls": [{"name": a, "args": b} for a, b in calls]}


def cortex_result(n, text, exit_code=0):
    return {"step_index": n, "source": "MODEL", "type": "RUN_COMMAND",
            "status": "DONE", "exit_code": exit_code, "created_at": T0 % 3,
            "content": "Created At: x\nCompleted At: x\n\nThe command exited "
                       "with code %s.\nOutput:\n%s\n" % (exit_code, text)}


def generic_result(n, text, status="DONE"):
    return {"step_index": n, "source": "MODEL", "type": "GENERIC",
            "status": status, "created_at": T0 % 3,
            "content": "Created At: x\nCompleted At: x\n" + text}


def compact(line):
    """transcript.jsonl: every tool argument value is a JSON string."""
    line = json.loads(dump(line))
    for c in line.get("tool_calls", []):
        c["args"] = {k: dump(v) for k, v in c["args"].items()}
    return line


SHELL_LINES = [
    user(0),
    planner(1, [("run_command", {"CommandLine": "echo hello && ls",
                                 "Cwd": "/home/u/ws", "WaitMsBeforeAsync": 2000})]),
    cortex_result(2, "hello\r\nfile.txt\r\n"),
]


def secret_lines():
    return [user(0), planner(1, [("run_command", {"CommandLine": "cat .env"})]),
            cortex_result(2, "STRIPE_KEY=" + SECRET)]


class Case(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="ag-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        for p in (mock.patch.dict(os.environ, {"HOME": self.home,
                                               "USERPROFILE": self.home}),
                  mock.patch.object(_paths, "home", return_value=self.home)):
            p.start()
            self.addCleanup(p.stop)
        bk = tempfile.mkdtemp(prefix="ag-bk-")
        self.addCleanup(shutil.rmtree, bk, True)
        p = mock.patch.object(clean, "BACKUP_ROOT", os.path.join(bk, "b"))
        p.start()
        self.addCleanup(p.stop)
        self.root = os.path.join(self.home, ".gemini", "antigravity-cli")
        self.ag = AntigravitySource()

    def logs(self, cid=CID, root=None):
        return os.path.join(root or self.root, "brain", cid,
                            ".system_generated", "logs")

    def write(self, lines, name=ag.FULL, cid=CID, root=None, raw=None, age=3600):
        path = os.path.join(self.logs(cid, root), name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if raw is None:
            raw = "".join((l if isinstance(l, str) else dump(l)) + "\n"
                          for l in lines).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def step_file(self, text, n="2", age=3600):
        step = os.path.join(self.root, "brain", CID, ".system_generated",
                            "steps", n)
        os.makedirs(step, exist_ok=True)
        path = os.path.join(step, "output.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def stores(self, **kw):
        return self.ag.stores(self.ag.locations(), **kw)

    def transcripts(self):
        return [s for s in self.stores() if s.role == "transcript"]

    def calls(self, path=None):
        out = []
        for s in self.transcripts():
            if path is None or s.path == path:
                out += list(self.ag.tool_calls(s))
        return out


class Paths(unittest.TestCase):

    def test_each_platform(self):
        s = AntigravitySource()
        self.assertEqual(
            s.default_paths({}, "/home/u", "linux"),
            [("/home/u/.gemini/antigravity-cli", "default"),
             ("/home/u/.gemini/antigravity", "default"),
             ("/home/u/.gemini/antigravity-ide", "default")])
        self.assertEqual(s.default_paths({}, "/Users/u", "darwin")[0][0],
                         "/Users/u/.gemini/antigravity-cli")
        self.assertEqual(
            s.default_paths({}, "C:\\Users\\u", "win32")[1],
            ("C:\\Users\\u\\.gemini\\antigravity", "default"))

    def test_no_environment_variable_and_a_missing_one_is_harmless(self):
        s = AntigravitySource()
        self.assertEqual(s.env, ())
        self.assertEqual(s.default_paths({"GEMINI_HOME": "/y"}, "/home/u", "linux"),
                         s.default_paths({}, "/home/u", "linux"))

    def test_identity(self):
        s = AntigravitySource()
        self.assertEqual((s.id, s.name), ("antigravity", "Antigravity"))
        self.assertTrue(s.path_means)


class Discovery(Case):

    def test_empty_and_missing_stores(self):
        self.assertEqual(self.stores(), [])
        os.makedirs(os.path.join(self.root, "brain"))
        self.assertEqual(self.stores(), [])
        self.assertEqual([l.exists for l in self.ag.locations()],
                         [True, False, False])

    def test_all_three_app_folders_and_copies_add_no_calls(self):
        for app in ag.APP_DIRS:
            self.write(SHELL_LINES, root=os.path.join(self.home, ".gemini", app),
                       cid="c-" + app)
        cid = "c-antigravity-cli"
        self.write(SHELL_LINES, name=ag.COMPACT, cid=cid)
        self.write(SHELL_LINES, name="chunks/transcript_full/00000000.jsonl",
                   cid=cid)
        self.write(SHELL_LINES, name="chunks/transcript/00000000.jsonl", cid=cid)
        main = self.transcripts()
        self.assertEqual(sorted(s.session for s in main),
                         ["c-antigravity", "c-antigravity-cli", "c-antigravity-ide"])
        self.assertTrue(all(s.path.endswith(ag.FULL) for s in main))
        self.assertEqual(len([s for s in self.stores() if s.role == "side"]), 3)
        self.assertEqual(len(self.calls()), 3)

    def test_compact_is_the_transcript_when_alone(self):
        self.write([compact(l) for l in SHELL_LINES], name=ag.COMPACT)
        [c] = self.calls()
        self.assertEqual(c.command, "echo hello && ls")
        self.assertEqual(c.workdir, "/home/u/ws")
        self.assertEqual(c.tool_input["WaitMsBeforeAsync"], 2000)

    def test_path_override(self):
        other = tempfile.mkdtemp(prefix="ag-other-")
        self.addCleanup(shutil.rmtree, other, True)
        self.write(SHELL_LINES, root=other)
        self.assertEqual(len(self.ag.stores(self.ag.locations(override=other))), 1)

    def test_days_prefilter(self):
        self.write(SHELL_LINES, age=40 * 86400)
        self.assertEqual(self.stores(since_days=7), [])
        self.assertEqual(len(self.stores(since_days=90)), 1)

    def test_project_from_summaries_database_read_only(self):
        self.write(SHELL_LINES)
        db = os.path.join(self.root, ag.SUMMARIES)
        conn = sqlite3.connect(db)
        conn.execute("create table conversation_summaries (conversation_id text,"
                     " title text, workspace_uris text)")
        conn.execute("insert into conversation_summaries values (?,?,?)",
                     (CID, "t", '["file:///home/u/my%20proj"]'))
        conn.commit()
        conn.close()
        with open(db, "rb") as fh:
            before = fh.read()
        [s] = self.transcripts()
        self.assertEqual(s.project, "/home/u/my proj")
        with open(db, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertEqual(sorted(os.listdir(self.root)), ["brain", ag.SUMMARIES])
        self.assertEqual(ag._uri_path("file:///C:/Users/u/p"), "C:/Users/u/p")

    def test_a_broken_summaries_database_is_ignored(self):
        self.write(SHELL_LINES)
        with open(os.path.join(self.root, ag.SUMMARIES), "wb") as fh:
            fh.write(b"not sqlite" * 50)
        [s] = self.transcripts()
        self.assertIsNone(s.project)
        self.assertEqual(self.calls()[0].project, "/home/u/ws")


class ToolCalls(Case):

    def test_shell_command_with_result(self):
        path = self.write(SHELL_LINES)
        [c] = self.calls(path)
        self.assertEqual((c.kind, c.known, c.tool_name, c.actor),
                         ("shell", True, "run_command", "agent"))
        self.assertEqual(c.command, "echo hello && ls")
        self.assertEqual(c.consumed, frozenset(["CommandLine"]))
        self.assertEqual(c.session, CID)
        self.assertEqual(c.tool_call_id, CID + ":1:0")
        self.assertEqual(c.timestamp, "2026-10-20T05:44:02Z")
        self.assertIn("hello", c.output)
        self.assertIsNone(c.status)

    def test_file_tools_of_both_families(self):
        lines = [user(0), planner(1, [
            ("view_file", {"AbsolutePath": "/w/.env"}),
            ("write_to_file", {"TargetFile": "/w/a.py", "CodeContent": "x=1"}),
            ("replace_file_content", {"TargetFile": "/w/b.py"}),
            ("multi_replace_file_content", {"TargetFile": "/w/c.py"}),
            ("read_file", {"Path": "/w/d"}),
            ("write_file", {"Path": "/w/e", "Content": "y"}),
            ("edit_file", {"Path": "/w/f", "Target": "a", "Replacement": "b"}),
            ("read_url_content", {"Url": "https://x.example"}),
            ("search_web", {"query": "q"}),
            ("grep_search", {"SearchPath": "/w", "Query": "q"}),
            ("list_dir", {"DirectoryPath": "/w"}),
            ("invoke_subagent", {"x": 1})])]
        lines += [generic_result(2 + i, "ok") for i in range(12)]
        got = {c.tool_name: (c.kind, c.known, c.paths) for c in
               self.calls(self.write(lines))}
        self.assertEqual(got["view_file"], ("read", True, ("/w/.env",)))
        self.assertEqual(got["read_file"], ("read", True, ("/w/d",)))
        self.assertEqual(got["write_to_file"], ("write", True, ("/w/a.py",)))
        self.assertEqual(got["replace_file_content"][0], "write")
        self.assertEqual(got["multi_replace_file_content"][2], ("/w/c.py",))
        self.assertEqual(got["write_file"], ("write", True, ("/w/e",)))
        self.assertEqual(got["edit_file"], ("write", True, ("/w/f",)))
        self.assertEqual(got["read_url_content"][0], "fetch")
        self.assertEqual(got["search_web"][0], "fetch")
        self.assertEqual(got["grep_search"], ("other", True, ()))
        self.assertEqual(got["list_dir"][0], "other")
        self.assertEqual(got["invoke_subagent"], ("other", False, ()))

    def test_gemini_api_key_family_has_no_cwd_and_text_exit_code(self):
        lines = [user(0), planner(1, [
            ("run_command", {"CommandLine": "echo bad >&2; exit 4",
                             "WaitMsBeforeAsync": 3000, "toolSummary": "fail"})]),
            generic_result(2, "Command exited with code 4.\n\nCommand output:\nbad\r\n")]
        [c] = self.calls(self.write(lines))
        self.assertEqual(c.command, "echo bad >&2; exit 4")
        self.assertIsNone(c.workdir)
        self.assertIn("exited with code 4", c.output)
        self.assertIsNone(c.status)

    def test_parallel_calls_pair_by_position_and_lines_are_sorted(self):
        lines = [planner(7, [("run_command", {"CommandLine": "echo ok"}),
                             ("run_command", {"CommandLine": "exit 4"})]),
                 generic_result(9, "Command exited with code 4."),
                 generic_result(8, "Command exited with code 0.\nok"),
                 user(6)]
        a, b = self.calls(self.write(lines))
        self.assertEqual((a.command, b.command), ("echo ok", "exit 4"))
        self.assertIn("code 0", a.output)
        self.assertIn("code 4", b.output)

    def test_declined_and_invalid_calls(self):
        lines = [user(0),
                 planner(1, [("run_command", {"CommandLine": "rm -rf x"})]),
                 {"step_index": 2, "source": "SYSTEM", "type": "ERROR_MESSAGE",
                  "status": "ERROR", "error": "denied by pre-tool hook: no"},
                 planner(3, [("run_command", {"CommandLine": "bad"})]),
                 generic_result(4, "", status="INVALID"),
                 planner(5, [("run_command", {"CommandLine": "touch f"})]),
                 user(6, "next"),
                 planner(7, [("run_command", {"CommandLine": "ls"})])]
        got = {c.command: c.status for c in self.calls(self.write(lines))}
        self.assertEqual(got, {"rm -rf x": "declined", "bad": "declined",
                               "touch f": "declined", "ls": None})

    def test_a_missing_result_is_not_declined_when_a_line_was_unreadable(self):
        lines = [planner(1, [("run_command", {"CommandLine": "touch f"})]),
                 "{broken", user(3)]
        [c] = self.calls(self.write(lines))
        self.assertIsNone(c.status)

    def test_duplicate_steps_count_once(self):
        self.assertEqual(len(self.calls(self.write(SHELL_LINES + SHELL_LINES))), 1)

    def test_arguments_not_an_object(self):
        lines = [planner(1, [("run_command", "ls -la"), ("view_file", None)]),
                 generic_result(2, "a"), generic_result(3, "b")]
        a, b = self.calls(self.write(lines))
        self.assertIsNone(a.command)
        self.assertEqual(a.tool_input, {"_raw": "ls -la"})
        self.assertEqual(b.paths, ())

    def test_undated_call_falls_back_to_the_files_time(self):
        line = planner(1, [("run_command", {"CommandLine": "ls"})])
        del line["created_at"]
        [c] = self.calls(self.write([line, generic_result(2, "")]))
        self.assertIsNone(c.timestamp)
        self.assertTrue(c.not_after)

    def test_no_tool_calls_means_no_calls(self):
        self.assertEqual(self.calls(self.write([user(0), planner(1, [])])), [])


class Damaged(Case):

    def test_malformed_line_is_counted_and_the_rest_read(self):
        self.write(SHELL_LINES[:2] + ["{not json", SHELL_LINES[2]])
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.ag.counts["unparsed"], 1)
        self.assertEqual(self.ag.counts["unreadable_stores"], 0)

    def test_truncated_file_is_quiet(self):
        raw = "".join(dump(l) + "\n" for l in SHELL_LINES[:2])
        raw += dump(SHELL_LINES[2])[:40]
        self.write(None, raw=raw.encode())
        [c] = self.calls()
        self.assertIsNone(c.status)         # the result may still be coming
        self.assertEqual(self.ag.counts["unparsed"], 0)

    def test_all_garbage_is_one_unreadable_store(self):
        self.write(None, raw=b"garbage\nmore garbage\n")
        with mock.patch("sys.stderr"):
            self.assertEqual(self.calls(), [])
        self.assertEqual(self.ag.counts["unreadable_stores"], 1)

    def test_non_utf8_bytes_and_bom_and_crlf(self):
        line = dump(planner(1, [("run_command", {"CommandLine": "echo @@"})]))
        raw = (b"\xef\xbb\xbf" + line.encode().replace(b"@@", b"\xff\xfe")
               + b"\r\n" + dump(generic_result(2, "\u2028 ok")).encode() + b"\r\n")
        self.write(None, raw=raw)
        [c] = self.calls()
        self.assertEqual(c.command, "echo \udcff\udcfe")
        self.assertIn("\u2028", c.output)

    def test_oversized_line_is_skipped_and_the_rest_read(self):
        with mock.patch.object(ag, "MAX_LINE", 2000):
            big = dump(generic_result(9, "x" * 5000))
            self.write(SHELL_LINES + [big, planner(10, [
                ("run_command", {"CommandLine": "after"})]),
                generic_result(11, "ok")])
            with mock.patch("sys.stderr"):
                cmds = [c.command for c in self.calls()]
        self.assertEqual(cmds, ["echo hello && ls", "after"])
        self.assertEqual(self.ag.counts["unparsed"], 1)

    def test_unknown_types_and_non_objects_are_counted(self):
        self.write(SHELL_LINES + [{"step_index": 5, "type": "NEW_THING"},
                                  [1, 2], "3", {"type": "GENERIC"}])
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.ag.counts["unknown"], 4)

    def test_deeply_nested_line_does_not_stop_the_read(self):
        deep = "[" * 100000 + "]" * 100000
        self.write(SHELL_LINES + ['{"step_index":5,"x":' + deep + "}"])
        self.assertEqual(len(self.calls()), 1)

    def test_vanished_store_warns_once(self):
        path = self.write(SHELL_LINES)
        [s] = self.transcripts()
        os.remove(path)
        with mock.patch("sys.stderr"):
            self.assertEqual(list(self.ag.tool_calls(s)), [])
            self.assertEqual(list(self.ag.tool_calls(s)), [])
        self.assertEqual(self.ag.counts["unreadable_stores"], 1)

    def test_side_stores_yield_no_calls(self):
        self.write(SHELL_LINES)
        self.write(SHELL_LINES, name=ag.COMPACT)
        side = [s for s in self.stores() if s.role == "side"]
        self.assertEqual(len(side), 1)
        self.assertEqual(list(self.ag.tool_calls(side[0])), [])


class Secrets(Case):

    def test_output_is_tied_to_its_call(self):
        self.write(secret_lines())
        [s] = self.transcripts()
        texts = list(self.ag.secret_texts(s))
        tied = [t for t in texts if t.call is not None]
        self.assertEqual(len(tied), 1)
        self.assertEqual(tied[0].call.command, "cat .env")
        self.assertIn(SECRET, tied[0].node)
        rest = [t.node for t in texts if t.call is None]
        self.assertFalse(any(SECRET in json.dumps(n) for n in rest))
        self.assertEqual(len(texts), 4)

    def test_copies_and_tool_output_files_are_searched(self):
        self.write(secret_lines())
        self.write(secret_lines(), name=ag.COMPACT)
        self.step_file(("x" * 3000 + "\n") * 800 + "K=" + SECRET + "\n")
        found = []
        for s in self.stores():
            for t in self.ag.secret_texts(s):
                if SECRET in json.dumps(t.node):
                    found.append((s.role, s.format))
        self.assertEqual(sorted(found), [("side", "jsonl"), ("side", "text"),
                                         ("transcript", "jsonl")])

    def test_a_secret_across_a_text_chunk_boundary_is_whole_in_one_piece(self):
        self.step_file("a" * (ag._CHUNK - 10) + SECRET + "b" * 100, n="3")
        [s] = self.stores()
        pieces = [t.node for t in self.ag.secret_texts(s)]
        self.assertTrue(any(SECRET in p for p in pieces))

    def test_empty_text_file(self):
        self.step_file("", n="3")
        [s] = self.stores()
        self.assertEqual(list(self.ag.secret_texts(s)), [])


class Masking(Case):

    def test_round_trip_and_second_run_changes_nothing(self):
        path = self.write(secret_lines())
        with open(path, "rb") as fh:
            original = fh.read()
        [s] = self.transcripts()
        r = self.ag.mask(s, [SECRET])
        self.assertTrue(r.changed)
        with open(path, "rb") as fh:
            after = fh.read()
        marker = clean.REDACTION % clean._fingerprint(SECRET)
        self.assertEqual(after, original.replace(SECRET.encode(), marker.encode()))
        with open(r.backup, "rb") as fh:
            self.assertEqual(fh.read(), original)
        self.assertEqual(self.ag.mask(s, [SECRET]), MaskResult(path))
        [c] = list(self.ag.tool_calls(s))
        self.assertIn(marker, c.output)

    def test_a_fresh_file_is_in_use(self):
        path = self.write(secret_lines(), age=3)
        [s] = self.stores()
        self.assertEqual(self.ag.mask(s, [SECRET]),
                         MaskResult(path, skipped="in use"))

    def test_a_presence_lock_is_in_use(self):
        path = self.write(secret_lines())
        lock = os.path.join(self.root, "presence", CID + ".lock")
        os.makedirs(os.path.dirname(lock))
        open(lock, "wb").close()
        [s] = self.stores()
        self.assertTrue(self.ag.in_use(s))
        self.assertEqual(self.ag.mask(s, [SECRET]),
                         MaskResult(path, skipped="in use"))

    def test_the_side_text_file_is_masked_too(self):
        p = self.step_file("K=" + SECRET + "\n")
        [s] = self.stores()
        self.assertTrue(self.ag.mask(s, [SECRET]).changed)
        with open(p, encoding="utf-8") as fh:
            self.assertNotIn(SECRET, fh.read())


class Helpers(unittest.TestCase):

    def test_compact_arguments_are_decoded(self):
        self.assertEqual(
            ag._decode_compact({"CommandLine": '"npm test"', "W": "2000",
                                "cut": '"abc'}),
            {"CommandLine": "npm test", "W": 2000, "cut": '"abc'})

    def test_app_dir_of_a_path(self):
        p = "/h/.gemini/antigravity-cli/brain/c/.system_generated/logs/x.jsonl"
        self.assertEqual(ag._app_dir(p), "/h/.gemini/antigravity-cli")
        self.assertIsNone(ag._app_dir("/elsewhere/x.jsonl"))


if __name__ == "__main__":
    unittest.main()
