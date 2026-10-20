"""The CodeBuddy Code adapter (ranwhat/sources/codebuddy.py).

Fixtures are built from the records the 2.170.0 bundle writes
(SessionStore.transformItemForSaveAsync, the Bash tool's result text, the
tools' zod schemas, ToolResultBlobService's <persisted-output> stub) and
from its CHANGELOG, one builder per record kind. Every format version the
research lists has a case: lines with no timestamp (before 2.121.0), the
.meta.json sidecar (2.37.2), the /clear separator (2.97.0), realpath and
hashed folder names (2.140.0, 2.141.0), UUIDv7 session-meta lines (2.146.0).

Everything runs in temp directories: the home directory,
CODEBUDDY_CONFIG_DIR and clean's backup root all point there. Every secret
is synthetic and written as adjacent literals.
"""
import contextlib
import io
import json
import os
import shutil
import stat
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
from ranwhat.sources import _paths  # noqa: E402
from ranwhat.sources import codebuddy as cb_module  # noqa: E402
from ranwhat.sources.base import ToolCall  # noqa: E402
from ranwhat.sources.codebuddy import CodeBuddySource, output_text  # noqa: E402

ENV = "CODEBUDDY_CONFIG_DIR"
WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
SID = "0199fe1a-2b3c-7d4e-8f50-1a2b3c4d5e6f"
CWD = "/home/alice/app"
ENC = "home-alice-app"
T0 = 1760950800000          # 2025-10-20T09:00:00Z


def _dump(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _tempdir(case, prefix):
    path = tempfile.mkdtemp(prefix=prefix)
    case.addCleanup(shutil.rmtree, path, True)
    return path


# -- records, as transformItemForSaveAsync writes them -----------------------

def _id(n):
    return "0199fe1a-0000-7000-8000-%012d" % n


def user(n, text, ts=T0, cwd=CWD):
    item = {"id": _id(n), "timestamp": ts, "type": "message", "role": "user",
            "content": [{"type": "input_text", "text": text}],
            "providerData": {"conversationRequestId": _id(900)}}
    if cwd:
        item["cwd"] = cwd
    if ts is None:
        del item["timestamp"]
    return item


def assistant(n, text, ts=T0 + 1000):
    return {"id": _id(n), "parentId": _id(n - 1), "timestamp": ts,
            "type": "message", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": text}], "cwd": CWD}


def call(n, cid, name, args, ts=T0 + 2000, cwd=CWD, raw_args=None):
    item = {"id": _id(n), "parentId": _id(n - 1), "timestamp": ts,
            "type": "function_call", "callId": cid, "name": name,
            "arguments": raw_args if raw_args is not None else _dump(args),
            "status": "completed", "providerData": {}, "cwd": cwd}
    if ts is None:
        del item["timestamp"]
    return item


def result(n, cid, name, text, ts=T0 + 3000, status="completed", data=None,
           shape="object", kind="function_call_result"):
    out = {"type": "text", "text": text}
    if shape == "string":
        out = text
    elif shape == "list":
        out = [{"type": "text", "text": text}]
    return {"id": _id(n), "parentId": _id(n - 1), "timestamp": ts,
            "type": kind, "name": name, "callId": cid, "status": status,
            "output": out,
            "providerData": data if data is not None
            else {"toolResult": {"content": text}}, "cwd": CWD}


def bash_text(command, stdout="", stderr="(empty)", code=0):
    return ("Command: %s\nStdout: %s\nStderr: %s\nExit Code: %d\n"
            "Signal: (none)" % (command, stdout, stderr, code))


def exchange(n, cid, name, args, text, **kw):
    return [call(n, cid, name, args), result(n + 1, cid, name, text, **kw)]


def spec_sample():
    """The three lines of the research's example."""
    return [
        user(1, "run the tests"),
        call(2, "call_7f3a", "Bash",
             {"command": "npm test", "description": "Run the test suite"},
             ts=T0 + 3512),
        result(3, "call_7f3a", "Bash", bash_text("npm test", "12 passing"),
               ts=T0 + 9876),
    ]


class Case(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "cb-home-")
        for p in (mock.patch.dict(os.environ, {"HOME": self.home,
                                               "USERPROFILE": self.home}),
                  mock.patch.object(_paths, "home", return_value=self.home)):
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ENV, None)
        self.backups = os.path.join(_tempdir(self, "cb-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.root = os.path.join(self.home, ".codebuddy")
        self.cb = CodeBuddySource()

    def write(self, rel, lines=None, raw=None, age=3600, root=None):
        path = os.path.join(root or self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = raw if raw is not None else "".join(
            _dump(l) + "\n" for l in lines).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def session(self, lines=None, sid=SID, enc=ENC, **kw):
        return self.write("projects/%s/%s.jsonl" % (enc, sid), lines, **kw)

    def stores(self, override=None, since_days=None):
        return self.cb.stores(self.cb.locations(override=override),
                              since_days=since_days)

    def store(self, path):
        for s in self.stores():
            if s.path == path:
                return s
        self.fail("%s is not a store" % path)

    def calls(self, path):
        return list(self.cb.tool_calls(self.store(path)))

    def by_id(self, path):
        return {c.tool_call_id: c for c in self.calls(path)}


class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        src = CodeBuddySource()
        self.assertEqual(src.default_paths({}, "/home/me", "linux"),
                         [("/home/me/.codebuddy", "default")])
        self.assertEqual(src.default_paths({}, "/Users/me", "darwin"),
                         [("/Users/me/.codebuddy", "default")])
        self.assertEqual(
            src.default_paths({}, "C:\\Users\\me", "win32"),
            [("C:\\Users\\me\\.codebuddy", "default")])

    def test_xdg_and_appdata_are_not_used(self):
        env = {"XDG_DATA_HOME": "/x", "XDG_CONFIG_HOME": "/y",
               "APPDATA": "C:\\A", "LOCALAPPDATA": "C:\\L"}
        src = CodeBuddySource()
        self.assertEqual(src.default_paths(env, "/home/me", "linux"),
                         [("/home/me/.codebuddy", "default")])
        self.assertEqual(src.default_paths(env, "C:\\Users\\me", "win32"),
                         [("C:\\Users\\me\\.codebuddy", "default")])

    def test_the_env_var_replaces_the_default_on_every_platform(self):
        src = CodeBuddySource()
        for plat, moved in (("linux", "/data/cb"), ("darwin", "/data/cb"),
                            ("win32", "D:\\cb")):
            self.assertEqual(src.default_paths({ENV: moved}, "/h", plat),
                             [(moved, "env " + ENV)])

    def test_a_blank_env_var_is_not_set(self):
        src = CodeBuddySource()
        for blank in ("", "   ", "\t"):
            self.assertEqual(src.default_paths({ENV: blank}, "/home/me", "linux"),
                             [("/home/me/.codebuddy", "default")])

    def test_what_every_report_needs(self):
        src = CodeBuddySource()
        self.assertEqual((src.id, src.name, src.env), ("codebuddy", "CodeBuddy", (ENV,)))
        self.assertTrue(src.path_means)
        self.assertTrue(src.checked)
        self.assertIs(cb_module.CodeBuddySource, CodeBuddySource)


class Discovery(Case):

    def test_a_missing_home_is_zero_stores(self):
        locs = self.cb.locations()
        self.assertEqual([(l.exists, l.found) for l in locs], [(False, 0)])
        self.assertEqual(self.stores(), [])

    def test_an_empty_store(self):
        os.makedirs(os.path.join(self.root, "projects"))
        loc = self.cb.locations()[0]
        self.assertEqual((loc.exists, loc.found), (True, 0))
        empty = self.session(raw=b"")
        self.assertEqual(self.calls(empty), [])
        self.assertEqual(list(self.cb.secret_texts(self.store(empty))), [])

    def test_every_layout_is_found_newest_first(self):
        main = self.session(spec_sample(), age=500)
        sub = self.write("projects/%s/%s/subagents/agent-ab12.jsonl" % (ENC, SID),
                         [user(1, "x")], age=400)
        old = self.session(spec_sample(), sid="0199fe1a-ffff-7000-8000-000000000001",
                           enc="old-symlink-path", age=900)
        results = self.write("projects/%s/%s/tool-results/call_9.txt" % (ENC, SID),
                             raw=b"big output", age=300)
        agent_results = self.write(
            "projects/%s/%s/subagents/agent-ab12/tool-results/call_8.txt" % (ENC, SID),
            raw=b"big output", age=200)
        hist = self.write("history.jsonl", [{"display": "hi", "pastedContents": {},
                                              "timestamp": T0, "project": CWD}],
                          age=100)
        # never stores
        self.write("projects/%s/%s.meta.json" % (ENC, SID), raw=b"{}")
        self.write("file-history/%s/abc@v1" % SID, raw=b"x")
        self.write("traces/123/t.jsonl", [{"a": 1}])
        self.write("blobs/ab/abcd.png", raw=b"x")
        self.write("projects/%s/memory/notes.md" % ENC, raw=b"x")
        stores = self.stores()
        paths = [s.path for s in stores]
        expected = {main, sub, old, results, agent_results, hist}
        self.assertTrue(expected <= set(paths))
        for p in paths:
            self.assertNotIn(".meta.json", p)
            self.assertNotIn("file-history", p)
            self.assertNotIn("blobs", p)
        order = [s.mtime for s in stores]
        self.assertEqual(order, sorted(order, reverse=True))
        kinds = {s.path: (s.format, s.role, s.unit) for s in stores}
        self.assertEqual(kinds[main], ("jsonl", "transcript", "session"))
        self.assertEqual(kinds[sub], ("jsonl", "transcript", "subagent"))
        self.assertEqual(kinds[results], ("text", "side", "tool output"))
        self.assertEqual(kinds[agent_results], ("text", "side", "tool output"))
        self.assertEqual(kinds[hist], ("jsonl", "side", "prompt history"))
        by = {s.path: s for s in stores}
        self.assertEqual(by[main].session, SID)
        self.assertEqual(by[main].project, CWD)
        self.assertEqual(by[sub].session, SID)       # the parent's
        self.assertEqual(by[results].session, SID)

    def test_the_hashed_long_folder_name_is_read_like_any_other(self):
        enc = "a" * 180 + "-1k2j3h4"                       # 2.141.0
        path = self.session(spec_sample(), enc=enc)
        self.assertEqual(len(self.calls(path)), 1)
        self.assertEqual(self.store(path).project, CWD)

    def test_project_comes_from_cwd_not_the_folder_name(self):
        path = self.session(spec_sample(), enc="C-Users-me-proj")
        self.assertEqual(self.store(path).project, CWD)

    def test_a_summary_first_has_no_cwd_so_a_later_line_gives_it(self):
        path = self.session([{"id": _id(1), "type": "summary", "summary": "s"}]
                            + spec_sample())
        self.assertEqual(self.store(path).project, CWD)

    def test_path_may_name_the_home_or_the_projects_folder(self):
        path = self.session(spec_sample())
        for given in (self.root, os.path.join(self.root, "projects")):
            self.assertEqual([s.path for s in self.stores(override=given)], [path])

    def test_env_var_is_read_at_call_time(self):
        elsewhere = _tempdir(self, "cb-else-")
        moved = self.session(spec_sample(), root=elsewhere)
        default = self.session(spec_sample())
        with mock.patch.dict(os.environ, {ENV: elsewhere}):
            locs = self.cb.locations()
            self.assertEqual([l.how for l in locs], ["env " + ENV])
            self.assertEqual([s.path for s in self.cb.stores(locs)], [moved])
        self.assertEqual([s.path for s in self.stores()], [default])

    def test_days_prefilter_by_last_write(self):
        self.session(spec_sample(), age=10 * 86400)
        fresh = self.session(spec_sample(), sid="0199fe1a-0001-7000-8000-000000000002",
                             age=60)
        self.assertEqual([s.path for s in self.stores(since_days=2)], [fresh])


class ToolCalls(Case):

    def test_the_research_sample(self):
        path = self.session(spec_sample())
        (c,) = self.calls(path)
        self.assertEqual((c.source, c.tool_name, c.kind, c.known, c.actor),
                         ("codebuddy", "Bash", "shell", True, "agent"))
        self.assertEqual((c.command, c.workdir, c.tool_call_id, c.session,
                          c.project), ("npm test", CWD, "call_7f3a", SID, CWD))
        self.assertEqual(c.timestamp, "2025-10-20T09:00:03Z")
        self.assertIn("12 passing", c.output)
        self.assertIsNone(c.status)
        self.assertEqual(c.consumed, frozenset(["command"]))
        self.assertEqual(c.tool_input["description"], "Run the test suite")

    def test_every_tool_maps_to_its_kind(self):
        lines = [user(1, "go")]
        table = [
            ("Bash", {"command": "ls"}, "shell", "ls", ()),
            ("PowerShell", {"command": "Get-ChildItem"}, "shell", "Get-ChildItem", ()),
            ("Read", {"file_path": "/etc/hosts"}, "read", None, ("/etc/hosts",)),
            ("Write", {"file_path": "/a/b.txt", "content": "x"}, "write", None, ("/a/b.txt",)),
            ("Edit", {"file_path": "/a/b.txt", "old_string": "a", "new_string": "b"},
             "write", None, ("/a/b.txt",)),
            ("MultiEdit", {"file_path": "/a/c.txt", "edits": []}, "write", None, ("/a/c.txt",)),
            ("NotebookEdit", {"notebook_path": "/a/n.ipynb"}, "write", None, ("/a/n.ipynb",)),
            ("WebFetch", {"url": "https://x.example", "prompt": "p"}, "fetch", None, ()),
            ("WebSearch", {"query": "python"}, "fetch", None, ()),
            ("Grep", {"pattern": "x"}, "other", None, ()),
            ("LS", {"path": "/"}, "other", None, ()),
            ("TodoWrite", {"todos": []}, "other", None, ()),
            ("Agent", {"prompt": "p"}, "other", None, ()),
        ]
        for i, (name, args, *_rest) in enumerate(table):
            lines += exchange(10 + 2 * i, "c%d" % i, name, args, "ok")
        got = self.by_id(self.session(lines))
        for i, (name, args, kind, command, paths) in enumerate(table):
            c = got["c%d" % i]
            self.assertEqual((c.tool_name, c.kind, c.known, c.command, c.paths),
                             (name, kind, True, command, paths), name)
        self.assertEqual(got["c2"].consumed, frozenset(["file_path"]))
        self.assertEqual(got["c3"].consumed, frozenset())    # content is judged

    def test_unknown_and_mcp_tools_are_judged_by_name(self):
        lines = exchange(2, "m1", "mcp__github__create_issue", {"title": "t"}, "ok")
        lines += exchange(4, "m2", "FutureTool", {"command": "rm -rf ~/x"}, "ok")
        got = self.by_id(self.session(lines))
        for c in got.values():
            self.assertEqual((c.kind, c.known, c.command), ("other", False, None))
        self.assertEqual(got["m2"].tool_input, {"command": "rm -rf ~/x"})

    def test_a_call_whose_command_or_path_is_missing_is_counted(self):
        lines = exchange(2, "a", "Bash", {}, "x")
        lines += exchange(4, "b", "Read", {"file_path": 5}, "x")
        lines += exchange(6, "c", "Bash", {"command": ""}, "x")
        got = self.by_id(self.session(lines))
        self.assertEqual([got[k].command for k in "ac"], [None, None])
        self.assertEqual(got["b"].paths, ())
        self.assertEqual(self.cb.counts["unreadable_calls"], 2)

    def test_arguments_in_every_stored_shape(self):
        lines = [call(2, "s", "Bash", None, raw_args=_dump({"command": "ls -la"})),
                 call(3, "d", "Bash", None, raw_args={"command": "pwd"}),
                 call(4, "j", "Bash", None, raw_args="{not json"),
                 call(5, "n", "Bash", None)]
        del lines[3]["arguments"]
        got = self.by_id(self.session(lines))
        self.assertEqual(got["s"].command, "ls -la")
        self.assertEqual(got["d"].command, "pwd")
        self.assertEqual(got["j"].tool_input, {"_raw": "{not json"})
        self.assertIsNone(got["j"].command)
        self.assertEqual(got["n"].tool_input, {})

    def test_outputs_in_every_stored_shape(self):
        lines = []
        for i, shape in enumerate(("object", "string", "list")):
            lines += [call(10 + 2 * i, "o%d" % i, "Bash", {"command": "echo"}),
                      result(11 + 2 * i, "o%d" % i, "Bash", "out-" + shape, shape=shape)]
        lines += [call(30, "legacy", "Bash", {"command": "echo"}),
                  result(31, "legacy", "Bash", "old name",
                         kind="function_call_output")]
        got = self.by_id(self.session(lines))
        self.assertEqual([got["o%d" % i].output for i in range(3)],
                         ["out-object", "out-string", "out-list"])
        self.assertEqual(got["legacy"].output, "old name")
        self.assertEqual(output_text(None), None)
        self.assertEqual(output_text({"type": "image"}), None)
        self.assertEqual(output_text(["a", {"text": "b"}, 3]), "a\nb")

    def test_a_call_with_no_result_is_reported_at_the_end(self):
        path = self.session([call(2, "x", "Bash", {"command": "sleep 1"}),
                             call(3, "y", "Bash", {"command": "ls"}),
                             result(4, "y", "Bash", "ok")])
        got = self.calls(path)
        self.assertEqual([c.tool_call_id for c in got], ["y", "x"])
        self.assertIsNone(got[1].output)
        self.assertIsNone(got[1].status)

    def test_a_call_with_no_id_is_kept_and_a_replayed_one_is_not_repeated(self):
        lines = exchange(2, "same", "Bash", {"command": "ls"}, "first")
        lines += exchange(4, "same", "Bash", {"command": "ls"}, "second")
        noid = call(6, "x", "Bash", {"command": "pwd"})
        del noid["callId"]
        lines.append(noid)
        got = self.calls(self.session(lines))
        self.assertEqual([(c.tool_call_id, c.output) for c in got],
                         [("same", "first"), (None, None)])

    def test_an_orphan_result_makes_no_call(self):
        self.assertEqual(self.calls(self.session([result(2, "ghost", "Bash", "x")])), [])

    def test_time_is_utc_and_an_undated_call_is_bounded_by_the_file(self):
        lines = [call(2, "dated", "Bash", {"command": "ls"}, ts=T0),
                 call(3, "undated", "Bash", {"command": "ls"}, ts=None),   # < 2.121.0
                 call(4, "iso", "Bash", {"command": "ls"}, ts="2025-10-20T09:00:00Z"),
                 call(5, "bool", "Bash", {"command": "ls"}, ts=True)]
        got = self.by_id(self.session(lines, age=3600))
        self.assertEqual(got["dated"].timestamp, "2025-10-20T09:00:00Z")
        self.assertIsNone(got["dated"].not_after)
        self.assertIsNone(got["undated"].timestamp)
        self.assertIsNotNone(got["undated"].not_after)
        for k in ("iso", "bool"):
            self.assertIsNone(got[k].timestamp)

    def test_project_is_each_records_cwd(self):
        lines = [call(2, "a", "Bash", {"command": "ls"}, cwd="/work/one"),
                 call(3, "b", "Bash", {"command": "ls"}, cwd="/work/two")]
        got = self.by_id(self.session(lines))
        self.assertEqual((got["a"].project, got["a"].workdir), ("/work/one", "/work/one"))
        self.assertEqual(got["b"].project, "/work/two")

    def test_side_stores_have_no_calls(self):
        hist = self.write("history.jsonl", [{"display": "rm -rf ~/x", "timestamp": T0}])
        self.assertEqual(list(self.cb.tool_calls(self.store(hist))), [])

    def test_a_subagent_transcript_is_read(self):
        path = self.write("projects/%s/%s/subagents/agent-ab12.jsonl" % (ENC, SID),
                          exchange(2, "sa", "Bash", {"command": "ls"}, "ok"))
        (c,) = self.calls(path)
        self.assertEqual((c.tool_call_id, c.session), ("sa", SID))

    def test_non_call_record_types_are_ignored_and_known_ones_not_counted(self):
        lines = spec_sample() + [
            {"id": _id(20), "type": "reasoning", "content": [], "cwd": CWD},
            {"id": _id(21), "type": "file-history-snapshot", "messageId": _id(1),
             "snapshot": {"messageId": _id(1), "trackedFileBackups": {}},
             "isSnapshotUpdate": False, "cwd": CWD},
            {"id": _id(22), "type": "session-meta", "sessionId": SID,
             "timestamp": T0, "meta": {"title": "t"}},
            {"id": _id(23), "type": "summary", "summary": "s"},
            {"id": _id(24), "type": "topic", "topic": "t"},
            {"id": _id(25), "type": "ai-title", "title": "t"},
            {"id": _id(26), "timestamp": T0, "type": "message", "role": "system",
             "content": [], "providerData": {"isSessionSeparator": True}},  # /clear, 2.97.0
        ]
        path = self.session(lines)
        self.assertEqual(len(self.calls(path)), 1)
        self.assertEqual(self.cb.counts["unknown"], 0)

    def test_an_unlisted_type_is_counted_once_a_run(self):
        lines = spec_sample() + [{"type": "future", "command": "rm -rf ~/x"}, [1, 2]]
        path = self.session(lines)
        self.assertEqual(len(self.calls(path)), 1)
        list(self.cb.secret_texts(self.store(path)))
        self.assertEqual(self.cb.counts["unknown"], 2)      # the dict and the list

    def test_a_command_the_user_ran_with_bang_is_the_users(self):
        lines = [user(1, "<bash-input>git status</bash-input>"),
                 user(2, "<bash-stdout>clean</bash-stdout><bash-stderr></bash-stderr>"),
                 user(3, "<bash-input>ls</bash-input>"),
                 user(4, "thanks")]
        got = self.calls(self.session(lines))
        self.assertEqual([(c.actor, c.kind, c.command, c.output, c.workdir)
                          for c in got],
                         [("user", "shell", "git status", "clean", CWD),
                          ("user", "shell", "ls", None, CWD)])

    def test_a_plain_user_message_is_not_a_call(self):
        self.assertEqual(self.calls(self.session([user(1, "please <bash-input> rm")])), [])
        self.assertEqual(self.calls(self.session(
            [user(1, "<bash-input>   </bash-input>")], sid="x1")), [])


class Declined(Case):

    def test_a_rejected_or_interrupted_call_never_ran(self):
        denied = {"skipRun": True, "error": "The user doesn't want to proceed"}
        lines = exchange(2, "no", "Bash", {"command": "rm -rf build"},
                         "The user doesn't want to proceed with this tool use.",
                         status="incomplete", data=denied)
        lines += exchange(4, "policy", "Bash", {"command": "rm -rf /"}, "blocked",
                          data={"toolResult": {"terminal": {"reason": "policy-denied"}}})
        lines += exchange(6, "ran", "Bash", {"command": "ls"}, bash_text("ls"))
        # incomplete without skipRun: it started, so it is not declined
        lines += exchange(8, "partial", "Bash", {"command": "make"}, "cut off",
                          status="incomplete", data={})
        lines += exchange(10, "weird", "Bash", {"command": "ls"}, "x",
                          status="incomplete", data={"skipRun": "yes"})
        got = self.by_id(self.session(lines))
        self.assertEqual({k: v.status for k, v in got.items()},
                         {"no": "declined", "policy": "declined", "ran": None,
                          "partial": None, "weird": None})

    def test_provider_data_that_is_not_a_dict_is_ignored(self):
        lines = exchange(2, "a", "Bash", {"command": "ls"}, "x", data=[1])
        lines[1]["providerData"] = "oops"
        got = self.by_id(self.session(lines))
        self.assertIsNone(got["a"].status)


class Judged(Case):

    def judge(self, call_):
        return watch.judge(call_)[0]

    def test_a_dangerous_shell_call_is_flagged(self):
        lines = exchange(2, "d", "Bash", {"command": "rm -rf ~/projects"}, "ok")
        (c,) = self.calls(self.session(lines))
        self.assertTrue(self.judge(c))

    def test_a_credential_read_is_flagged_and_an_ordinary_one_is_not(self):
        lines = exchange(2, "r", "Read", {"file_path": "~/.ssh/id_rsa"}, "k")
        lines += exchange(4, "ok", "Read", {"file_path": "/work/README.md"}, "k")
        got = self.by_id(self.session(lines))
        self.assertTrue(self.judge(got["r"]))
        self.assertFalse(self.judge(got["ok"]))

    def test_file_content_written_is_not_an_action(self):
        lines = exchange(2, "w", "Write", {"file_path": "/work/notes.md",
                                           "content": "rm -rf ~/projects"}, "ok")
        (c,) = self.calls(self.session(lines))
        self.assertFalse(self.judge(c))

    def test_an_unknown_tool_is_judged_by_name_and_input(self):
        lines = exchange(2, "u", "FutureShell", {"command": "rm -rf ~/projects"}, "ok")
        (c,) = self.calls(self.session(lines))
        self.assertEqual(c.known, False)


class Secrets(Case):

    def findings(self, path):
        out = []
        for text in self.cb.secret_texts(self.store(path)):
            out.append(text)
        return out

    def test_every_line_and_each_output_reaches_clean(self):
        lines = [user(1, "my key is " + SECRET)]
        lines += exchange(2, "c", "Bash", {"command": "cat .env"},
                          bash_text("cat .env", "KEY=" + SECRET))
        path = self.session(lines)
        texts = self.findings(path)
        blob = json.dumps([t.node for t in texts])
        self.assertEqual(blob.count(SECRET), 3)  # prompt, output, display copy
        tied = [t for t in texts if t.call is not None]
        self.assertEqual(len(tied), 2)
        self.assertTrue(all(t.call.tool_call_id == "c" for t in tied))
        self.assertTrue(all(t.call.command == "cat .env" for t in tied))
        # nothing carrying the output is left on the untied line
        rest = [t.node for t in texts if t.call is None
                and isinstance(t.node, dict) and t.node.get("type") == RESULT]
        self.assertEqual(len(rest), 1)
        self.assertNotIn("output", rest[0])
        self.assertNotIn("toolResult", rest[0]["providerData"])

    def test_unlisted_lines_and_summary_text_are_searched_too(self):
        path = self.session(spec_sample() + [
            {"id": _id(30), "type": "summary", "summary": "key " + SECRET},
            {"type": "something-new", "x": SECRET}])
        blob = json.dumps([t.node for t in self.findings(path)])
        self.assertEqual(blob.count(SECRET), 2)

    def test_where_names_the_line(self):
        path = self.session(spec_sample())
        self.assertEqual([t.where for t in self.findings(path)][:3],
                         ["line 1", "line 2", "line 3"])

    def test_the_prompt_history_is_searched(self):
        hist = self.write("history.jsonl", [{"display": "export K=" + SECRET,
                                              "pastedContents": {}, "timestamp": T0,
                                              "project": CWD}])
        texts = self.findings(hist)
        self.assertEqual(len(texts), 1)
        self.assertIn(SECRET, json.dumps(texts[0].node))

    def test_a_persisted_output_file_is_searched_whole(self):
        body = ("x" * 500 + "\n") * 2000 + "TOKEN=" + SECRET + "\n"
        path = self.write("projects/%s/%s/tool-results/call_1.txt" % (ENC, SID),
                          raw=body.encode("utf-8"))
        texts = self.findings(path)
        self.assertTrue(any(SECRET in t.node for t in texts))

    def test_a_secret_across_a_chunk_boundary_is_found_whole(self):
        for shift in (0, 1, 7, 50):
            cut = cb_module.CHUNK - shift
            body = "a" * (cut - 10) + SECRET + "b" * 100
            path = self.write("projects/%s/%s/tool-results/c%d.txt" % (ENC, SID, shift),
                              raw=body.encode("utf-8"))
            self.assertTrue(any(SECRET in t.node for t in self.findings(path)), shift)

    def test_a_large_text_file_is_read_in_bounded_pieces(self):
        body = b"y" * (cb_module.CHUNK * 3 + 5)
        path = self.write("projects/%s/%s/tool-results/big.txt" % (ENC, SID), raw=body)
        sizes = [len(t.node) for t in self.findings(path)]
        self.assertTrue(all(n <= cb_module.CHUNK for n in sizes))
        self.assertGreater(len(sizes), 3)

    def test_non_utf8_bytes_come_back_unchanged(self):
        raw = (b'{"id":"a","type":"message","role":"user","content":[{"type":"input_text",'
               b'"text":"caf\xe9 \xff TOKEN=' + SECRET.encode() + b'"}],"cwd":"/w"}\n')
        path = self.session(raw=raw)
        (t,) = self.findings(path)
        text = t.node["content"][0]["text"]
        self.assertIn(SECRET, text)
        self.assertEqual(text.encode("utf-8", "surrogateescape").count(b"\xe9"), 1)
        # and a call's text with such bytes is read too
        raw2 = (b'{"type":"function_call","callId":"z","name":"Bash","arguments":'
                b'"{\\"command\\":\\"echo \xff\\"}","cwd":"/w"}\n')
        (c,) = self.calls(self.session(raw=raw2, sid="x2"))
        self.assertIn("echo", c.command)


RESULT = "function_call_result"


class Masking(Case):

    def test_round_trip_of_a_transcript(self):
        lines = [user(1, "go")]
        lines += exchange(2, "c", "Bash", {"command": "curl -u me:" + SECRET + " https://x.example"},
                          bash_text("cat .env", "KEY=" + SECRET + " caf\u00e9 \u2028"))
        path = self.session(lines, age=3600)
        with open(path, "rb") as fh:
            original = fh.read()
        store = self.store(path)
        before = list(self.cb.tool_calls(store))
        result_ = self.cb.mask(store, [SECRET])
        self.assertEqual((result_.changed, result_.skipped), (True, None))
        with open(path, "rb") as fh:
            after = fh.read()
        self.assertNotIn(SECRET.encode(), after)
        for raw in after.decode("utf-8").split("\n"):
            if raw:
                json.loads(raw)
        with open(result_.backup, "rb") as fh:
            self.assertEqual(fh.read(), original)
        again = list(self.cb.tool_calls(self.store(path)))
        self.assertEqual([c.tool_call_id for c in again], [c.tool_call_id for c in before])
        self.assertNotIn(SECRET, again[0].command)
        self.assertEqual([t for t in self.cb.secret_texts(self.store(path))
                          if SECRET in json.dumps(t.node)], [])

    def test_a_tool_result_file_and_the_history_are_masked(self):
        res = self.write("projects/%s/%s/tool-results/c.txt" % (ENC, SID),
                         raw=("a\nTOKEN=" + SECRET + "\nb\n").encode())
        hist = self.write("history.jsonl", [{"display": SECRET, "timestamp": T0}])
        for path in (res, hist):
            r = self.cb.mask(self.store(path), [SECRET])
            self.assertTrue(r.changed, path)
            with open(path, "rb") as fh:
                self.assertNotIn(SECRET.encode(), fh.read())

    def test_a_file_written_just_now_is_in_use(self):
        path = self.session(spec_sample() + [{"x": SECRET}], age=0)
        with open(path, "rb") as fh:
            original = fh.read()
        r = self.cb.mask(self.store(path), [SECRET])
        self.assertFalse(r.changed)
        self.assertIsNotNone(r.skipped)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), original)


class Damaged(Case):

    def test_a_malformed_line_in_the_middle_is_counted_not_fatal(self):
        good = [_dump(l) + "\n" for l in spec_sample()]
        raw = "".join(good[:2]) + "{not json\n" + "".join(good[2:])
        path = self.session(raw=raw.encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(len(self.calls(path)), 1)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.cb.counts["unparsed"], 1)

    def test_a_truncated_last_line_is_skipped_quietly(self):
        good = "".join(_dump(l) + "\n" for l in spec_sample())
        cut = _dump(call(9, "z", "Bash", {"command": "rm -rf ~/x"}))[:40]
        path = self.session(raw=(good + cut).encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self.calls(path)
            list(self.cb.secret_texts(self.store(path)))
        self.assertEqual([c.tool_call_id for c in calls], ["call_7f3a"])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.cb.counts["unparsed"], 0)

    def test_a_file_cut_inside_a_call_and_a_result_missing_still_reads(self):
        text = _dump(call(2, "a", "Bash", {"command": "ls"})) + "\n"
        text += _dump(call(3, "b", "Bash", {"command": "pwd"}))[:25]
        path = self.session(raw=text.encode("utf-8"))
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["a"])

    def test_garbage_warns_once_and_other_stores_are_still_read(self):
        garbage = self.session(raw=b"\x00\xff\xfe not json\n\x89PNG\r\n\x1a\n" * 20,
                               sid="0199fe1a-aaaa-7000-8000-00000000000a")
        good = self.session(spec_sample(), age=7200)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for store in self.stores():
                list(self.cb.tool_calls(store))
                list(self.cb.secret_texts(store))
                list(self.cb.tool_calls(store))
            self.assertEqual(len(self.calls(good)), 1)
        warnings = err.getvalue().splitlines()
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn(garbage, warnings[0])
        self.assertEqual(self.cb.unreadable, {"not JSON Lines": 1})

    def test_records_that_are_not_objects_are_counted_and_skipped(self):
        raw = b'[1,2]\n"str"\n12\nnull\n' + (_dump(spec_sample()[1]) + "\n").encode()
        path = self.session(raw=raw)
        self.assertEqual(len(self.calls(path)), 0 + 1)   # the call, awaiting a result
        self.assertEqual(self.cb.counts["unknown"], 4)

    def test_odd_fields_never_raise(self):
        weird = [
            {"type": "function_call", "callId": {"x": 1}, "name": {"y": 2},
             "arguments": 5, "timestamp": {"t": 1}, "cwd": ["a"]},
            {"type": "function_call", "callId": "k", "name": "Bash",
             "arguments": {"command": ["rm"]}},
            {"type": "function_call_result", "callId": {"x": 1}, "output": 7},
            {"type": "function_call_result", "callId": "k", "output": {"text": 3},
             "providerData": {"toolResult": {"terminal": 4}}, "status": 9},
            {"type": "message", "role": "user", "content": 5},
            {"type": "message", "role": "user", "content": [None, 3]},
        ]
        path = self.session(weird)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            list(self.cb.tool_calls(self.store(path)))
            list(self.cb.secret_texts(self.store(path)))

    def test_deep_nesting_and_a_nested_id_do_not_stop_the_run(self):
        deep = '{"a":' * 900 + '"x"' + "}" * 900
        deeper = "[" * 100000 + "]" * 100000
        good = _dump(spec_sample()[1])
        raw = "\n".join([deep, deeper, good, ""]).encode("utf-8")
        path = self.session(raw=raw)
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["call_7f3a"])
        list(self.cb.secret_texts(self.store(path)))

    def test_an_oversized_line_is_skipped_and_the_rest_read(self):
        big = _dump(call(2, "big", "Bash", {"command": "echo " + "x" * 5000}))
        tail = _dump(call(3, "after", "Bash", {"command": "pwd"}))
        raw = ("%s\n%s\n" % (big, tail)).encode("utf-8")
        path = self.session(raw=raw)
        with mock.patch.object(cb_module, "LINE_MAX", 1000):
            got = self.calls(path)
        self.assertEqual([c.tool_call_id for c in got], ["after"])
        self.assertEqual(self.cb.counts["unparsed"], 1)

    def test_an_oversized_last_line_with_no_newline(self):
        tail = _dump(call(3, "after", "Bash", {"command": "x" * 5000}))
        path = self.session(raw=(_dump(spec_sample()[1]) + "\n" + tail).encode())
        with mock.patch.object(cb_module, "LINE_MAX", 1000):
            got = self.calls(path)
        self.assertEqual([c.tool_call_id for c in got], ["call_7f3a"])

    def test_a_bom_and_crlf_are_tolerated(self):
        raw = b"\xef\xbb\xbf" + b"\r\n".join(
            _dump(l).encode() for l in spec_sample()) + b"\r\n"
        self.assertEqual(len(self.calls(self.session(raw=raw))), 1)

    def test_a_u2028_inside_a_line_does_not_split_it(self):
        lines = exchange(2, "u", "Bash", {"command": "echo a\u2028b"}, "a\u2028b")
        (c,) = self.calls(self.session(lines))
        self.assertEqual(c.command, "echo a\u2028b")

    def test_a_store_that_vanished_warns_once(self):
        path = self.session(spec_sample())
        store = self.store(path)
        os.unlink(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.cb.tool_calls(store)), [])
            self.assertEqual(list(self.cb.secret_texts(store)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertEqual(self.cb.counts["unreadable_stores"], 1)

    @unittest.skipIf(WINDOWS, "POSIX permissions")
    def test_an_unreadable_file_and_folder_are_survived(self):
        path = self.session(spec_sample())
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, stat.S_IRUSR | stat.S_IWUSR)
        if os.access(path, os.R_OK):
            self.skipTest("running as a user who ignores permissions")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.calls(path), [])
        self.assertEqual(self.cb.counts["unreadable_stores"], 1)


class Performance(Case):

    def test_many_calls_read_in_linear_time(self):
        def build(n):
            lines = []
            for i in range(n):
                lines += exchange(2 * i + 1, "c%d" % i, "Bash",
                                  {"command": "grep -rn foo src/%d" % i},
                                  bash_text("grep", "line\n" * 5))
            return self.session(lines, sid="p%d" % n)

        def timed(n):
            path = build(n)
            start = time.perf_counter()
            got = self.calls(path)
            self.assertEqual(len(got), n)
            list(self.cb.secret_texts(self.store(path)))
            return time.perf_counter() - start

        small, large = timed(2000), timed(16000)
        self.assertLess(large, max(small * 8 * 4, 2.0))


if __name__ == "__main__":
    unittest.main()
