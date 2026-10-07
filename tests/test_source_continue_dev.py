"""The Continue adapter (ranwhat/sources/continue_dev.py).

Fixtures are built field for field from the verified format (Continue
v2.1.0-vscode, with v1.0.8-vscode for the legacy shapes): one session
document per file, pretty-printed as JSON.stringify(x, undefined, 2) writes
it, keys in HistoryManager.save's order. IDE sessions carry message ids,
tool definitions on their states and a separate role "tool" item after
each call; `cn` CLI sessions carry none of those, and one "Tool Result"
output item on each state.

Everything runs in temp directories: the home directory, CONTINUE_GLOBAL_DIR
and clean's backup root all point there, and the real home is never read.
Every secret is synthetic, and token-shaped ones are written as adjacent
literals. The adapter is instantiated directly, so these tests pass whether
or not it is in the registry.
"""
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

from ranwhat import clean, watch  # noqa: E402
from ranwhat.sources import _paths, continue_dev  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.continue_dev import ContinueSource, uri_path  # noqa: E402

ENV = "CONTINUE_GLOBAL_DIR"
WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
LOGIN = "ghp_" "Q7mZ2xLk9VbN4cR8tY1wP6sD3fG5hJ0aK2eU"
CONFIG_KEY = "sk-" "ant-api03-" "Vb7Nq2Lm9Xc4Rt8Yp1Wz6Ks3Df5Gh0Ja"

SID = "3f1a2b7c-9d4e-4f60-8a1b-2c3d4e5f6a7b"
CLI_SID = "7e2b1c4d-0000-4000-8000-00000000c11a"
MS = 1790845200000          # 2026-10-01T09:00:00Z


def _pretty(obj):
    """JSON.stringify(obj, undefined, 2)."""
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _tempdir(case, prefix):
    path = tempfile.mkdtemp(prefix=prefix)
    case.addCleanup(shutil.rmtree, path, True)
    return path


# --------------------------------------------------------------------------
# Fixture builders
# --------------------------------------------------------------------------

def session(history, sid=SID, title="Set up deploy script",
            workspace="file:///home/u/proj", **extra):
    doc = {"sessionId": sid, "title": title, "workspaceDirectory": workspace,
           "history": history}
    doc.update(extra)
    return doc


def tool_call(cid, name, arguments):
    raw = arguments if isinstance(arguments, str) else json.dumps(
        arguments, separators=(",", ":"))
    return {"id": cid, "type": "function",
            "function": {"name": name, "arguments": raw}}


def state(cid, name, arguments, status="done", output=None, parsed=None,
          tool=True):
    st = {"toolCallId": cid, "toolCall": tool_call(cid, name, arguments),
          "status": status,
          "parsedArgs": parsed if parsed is not None else (
              arguments if isinstance(arguments, dict) else {})}
    if tool:
        st["tool"] = {"type": "function", "displayTitle": name,
                      "function": {"name": name}}
    if output is not None:
        st["output"] = output
    return st


def user_item(text, mid="u1", context=()):
    return {"message": {"role": "user", "content": text, "id": mid},
            "contextItems": list(context),
            "editorState": {"type": "doc", "content": [
                {"type": "paragraph",
                 "content": [{"type": "text", "text": text}]}]}}


def ide_call(cid, name, arguments, status="done", output=None, mid=None,
             content="", answer=True):
    """An IDE assistant item with one call, and its role "tool" item."""
    items = [{"message": {"role": "assistant", "content": content,
                          "id": mid or "a-" + cid,
                          "toolCalls": [tool_call(cid, name, arguments)]},
              "contextItems": [],
              "toolCallStates": [state(cid, name, arguments, status, output)]}]
    if answer:
        rendered = "\n\n".join(i["content"] for i in output or [])
        items.append({"message": {"role": "tool", "content": rendered,
                                  "toolCallId": cid, "id": "t-" + cid},
                      "contextItems": [dict(i, id={"providerTitle": "toolCall",
                                                   "itemId": cid})
                                       for i in output or []]})
    return items


def terminal(text):
    return [{"name": "Terminal", "description": "Terminal command output",
             "content": text, "status": "Command completed"}]


def cli_result(text):
    return [{"content": text, "name": "Tool Result",
             "description": "Tool execution result"}]


def cli_call(cid, name, arguments, status="done", output=None):
    """A `cn` assistant item: no message id, no tool object, no tool item."""
    st = state(cid, name, arguments, status,
               cli_result(output) if output is not None else None, tool=False)
    return [{"message": {"role": "assistant", "content": "",
                         "toolCalls": [tool_call(cid, name, arguments)]},
             "contextItems": [], "toolCallStates": [st]}]


def cli_user(text):
    return {"message": {"role": "user", "content": text}, "contextItems": [],
            "editorState": text}


def spec_sample():
    """The spec's IDE example session, field for field."""
    history = [user_item("check git status and add a deploy script", "a1")]
    history += ide_call("call_1", "run_terminal_command",
                        {"command": "git status", "waitForCompletion": True},
                        output=terminal("On branch main\nnothing to commit, "
                                        "working tree clean\n"))
    history += ide_call("call_2", "read_file", {"filepath": "package.json"},
                        output=[{"name": "package.json",
                                 "description": "package.json",
                                 "content": "{ \"name\": \"proj\" }",
                                 "uri": {"type": "file", "value":
                                         "file:///home/u/proj/package.json"}}])
    history += ide_call("call_3", "create_new_file",
                        {"filepath": "deploy.sh",
                         "contents": "#!/bin/sh\nrsync -a . prod:/srv\n"},
                        content="Creating the script.",
                        output=[{"name": "deploy.sh",
                                 "description": "/home/u/proj/deploy.sh",
                                 "content": "File created successfuly",
                                 "uri": {"type": "file", "value":
                                         "file:///home/u/proj/deploy.sh"}}])
    history += ide_call("call_4", "run_terminal_command",
                        {"command": "sh deploy.sh", "waitForCompletion": True},
                        status="canceled")
    return session(history, mode="agent", chatModelTitle="Claude Sonnet",
                   usage={"promptTokens": 5200, "completionTokens": 310,
                          "totalCost": 0.02})


# --------------------------------------------------------------------------
# Common setup
# --------------------------------------------------------------------------

class ContinueCase(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "continue-home-")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ENV, None)
        self.backups = os.path.join(_tempdir(self, "continue-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.root = os.path.join(self.home, ".continue")
        self.src = ContinueSource()

    def write(self, rel, doc=None, age=3600, raw=None, root=None):
        path = os.path.join(root or self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if raw is None:
            raw = _pretty(doc).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def session_file(self, doc, sid=None, **kw):
        sid = sid or (doc.get("sessionId") if isinstance(doc, dict) else None) \
            or SID
        return self.write("sessions/%s.json" % sid, doc, **kw)

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

    def findings(self, path):
        found, _masks = clean.scan_store(self.src, self.store(path), {})
        return found


def rules(call):
    return [(h["rule"], h["evidence"]) for h in watch.judge(call)[0]]


# --------------------------------------------------------------------------
# Where Continue keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        s = ContinueSource()
        self.assertEqual(s.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.continue", "default")])
        self.assertEqual(s.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.continue", "default")])
        self.assertEqual(s.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.continue", "default")])

    def test_the_variable_replaces_the_default(self):
        s = ContinueSource()
        for plat, home in (("linux", "/home/u"), ("darwin", "/Users/u"),
                           ("win32", "C:\\Users\\u")):
            self.assertEqual(s.default_paths({ENV: "/srv/continue"}, home, plat),
                             [("/srv/continue", "env " + ENV)])

    def test_an_empty_variable_is_not_set(self):
        s = ContinueSource()
        self.assertEqual(s.default_paths({ENV: ""}, "/home/u", "linux"),
                         [("/home/u/.continue", "default")])

    def test_what_every_report_needs(self):
        s = ContinueSource()
        self.assertEqual((s.id, s.name, s.unit, s.env, s.checked),
                         ("continue", "Continue", "session", (ENV,), "2.1.0"))
        self.assertEqual(s.path_means,
                         "a Continue folder (what CONTINUE_GLOBAL_DIR means)")
        self.assertFalse(s.read_only)

    def test_file_uris_become_paths(self):
        self.assertEqual(uri_path("file:///home/u/proj"), "/home/u/proj")
        self.assertEqual(uri_path("file:///c%3A/Users/u/proj"), "c:/Users/u/proj")
        self.assertEqual(uri_path("file:///C:/Users/u"), "C:/Users/u")
        self.assertEqual(uri_path("file:///home/u/my%20proj"), "/home/u/my proj")
        self.assertEqual(uri_path("file://server/share/x"), "//server/share/x")
        self.assertEqual(uri_path("file://localhost/home/u"), "/home/u")
        self.assertEqual(uri_path("/home/u/proj"), "/home/u/proj")
        self.assertEqual(uri_path("vscode-remote://ssh-remote+h/home/u"),
                         "vscode-remote://ssh-remote+h/home/u")
        self.assertIsNone(uri_path(None))


class Discovery(ContinueCase):

    def test_sessions_are_found_newest_first_and_nothing_else_is(self):
        old = self.session_file(spec_sample(), age=7200)
        new = self.session_file(session([], sid=CLI_SID, workspace="/home/u/cli"),
                                age=60)
        index = self.write("sessions/sessions.json", raw=b"[]", age=30)
        # what is not a session: config and login files, telemetry, logs,
        # dot-files and other names in sessions/, a folder named *.json
        self.write("config.yaml", raw=b"models: []\n")
        self.write("auth.json", raw=b"{}")
        self.write("dev_data/0.2.0/toolUsage.jsonl", raw=b"{}\n")
        self.write("logs/core.log", raw=b"x\n")
        self.write("sessions/.tmp.json", raw=b"{}")
        self.write("sessions/notes.txt", raw=b"x")
        os.makedirs(os.path.join(self.root, "sessions", "dir.json"))
        stores = self.stores()
        self.assertEqual([s.path for s in stores], [index, new, old])
        self.assertEqual([(s.role, s.format, s.masking) for s in stores],
                         [("side", "json", "rewrite"),
                          ("transcript", "json", "rewrite"),
                          ("transcript", "json", "rewrite")])
        self.assertEqual([(s.session, s.project) for s in stores[1:]],
                         [(CLI_SID, "/home/u/cli"), (SID, "/home/u/proj")])
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (self.root, "default", True, 3))

    def test_a_missing_root_is_zero_stores(self):
        self.assertEqual(self.stores(), [])
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (False, 0))

    def test_the_variable_is_read_at_call_time(self):
        moved = _tempdir(self, "continue-moved-")
        path = self.session_file(spec_sample(), root=moved)
        self.session_file(spec_sample(), sid="other")      # in ~/.continue
        os.environ[ENV] = moved
        self.assertEqual([s.path for s in self.stores()], [path])
        [loc] = self.src.locations()
        self.assertEqual(loc.how, "env " + ENV)

    def test_path_override(self):
        moved = _tempdir(self, "continue-path-")
        path = self.session_file(spec_sample(), root=moved)
        self.assertEqual([s.path for s in self.stores(override=moved)], [path])

    def test_session_and_project_fall_back_to_the_file_name(self):
        path = self.write("sessions/abc.json", raw=b"{}")
        [store] = self.stores()
        self.assertEqual((store.path, store.session, store.project),
                         (path, "abc", None))

    def test_days_prefilter_by_last_write(self):
        self.session_file(spec_sample(), age=10 * 86400)
        recent = self.session_file(session([], sid=CLI_SID), age=60)
        self.assertEqual([s.path for s in self.stores(since_days=2)], [recent])

    def test_a_title_cannot_fake_the_project(self):
        doc = session([], title='x\n  "workspaceDirectory": "/evil"')
        self.session_file(doc)
        [store] = self.stores()
        self.assertEqual(store.project, "/home/u/proj")


# --------------------------------------------------------------------------
# Tool calls
# --------------------------------------------------------------------------

class Calls(ContinueCase):

    def test_the_spec_sample(self):
        path = self.session_file(spec_sample())
        calls = self.calls(path)
        self.assertEqual([c.tool_call_id for c in calls],
                         ["call_1", "call_2", "call_3", "call_4"])
        got = {c.tool_call_id: c for c in calls}
        mtime = continue_dev._stamps.iso_utc(os.stat(path).st_mtime, "s")
        for c in calls:
            self.assertEqual((c.source, c.store, c.session, c.project,
                              c.timestamp, c.not_after, c.actor, c.known),
                             ("continue", path, SID, "/home/u/proj", None,
                              mtime, "agent", True))
        c = got["call_1"]
        self.assertEqual((c.kind, c.command, c.consumed, c.status),
                         ("shell", "git status", frozenset({"command"}), None))
        self.assertEqual(c.output,
                         "On branch main\nnothing to commit, working tree clean\n")
        self.assertEqual(c.tool_input,
                         {"command": "git status", "waitForCompletion": True})
        c = got["call_2"]
        self.assertEqual((c.kind, c.paths, c.consumed, c.output),
                         ("read", ("package.json",), frozenset({"filepath"}),
                          '{ "name": "proj" }'))
        c = got["call_3"]
        self.assertEqual((c.kind, c.paths, c.consumed),
                         ("write", ("deploy.sh",), frozenset()))
        c = got["call_4"]
        self.assertEqual((c.kind, c.command, c.status, c.output),
                         ("shell", "sh deploy.sh", "declined", None))

    def test_every_mapped_tool(self):
        names = dict(continue_dev.IDE_TOOLS)
        names.update(continue_dev.CLI_TOOLS)
        names.update({"builtin_" + k: v for k, v in continue_dev.IDE_TOOLS.items()})
        history = []
        for n, name in enumerate(sorted(names)):
            history += ide_call("c%d" % n, name, {"filepath": "/w/f.txt"})
        path = self.session_file(session(history))
        got = {c.tool_name: c for c in self.calls(path)}
        self.assertEqual(set(got), set(names))
        for name, kind in names.items():
            self.assertEqual((got[name].kind, got[name].known), (kind, True), name)
        expected = {"shell": {"run_terminal_command", "Bash"},
                    "read": {"read_file", "read_file_range", "Read"},
                    "write": {"create_new_file", "edit_existing_file",
                              "single_find_and_replace", "multi_edit",
                              "Write", "Edit", "MultiEdit"},
                    "fetch": {"fetch_url_content", "search_web", "Fetch"}}
        for kind, members in expected.items():
            self.assertEqual({k for k, v in continue_dev.IDE_TOOLS.items()
                              if v == kind}
                             | {k for k, v in continue_dev.CLI_TOOLS.items()
                                if v == kind}, members)

    def test_commands_and_paths_of_each_shape(self):
        history = []
        history += cli_call("b", "Bash", {"command": "ls -la", "timeout": 30},
                            output="total 0")
        history += cli_call("r", "Read", {"filepath": "/w/a.py"}, output="x")
        history += cli_call("w", "Write", {"filepath": "/w/b.py", "content": "y"},
                            output="ok")
        history += cli_call("e", "Edit", {"file_path": "/w/c.py",
                                          "old_string": "a", "new_string": "b"},
                            output="ok")
        history += cli_call("m", "MultiEdit", {"file_path": "/w/d.py",
                                               "edits": []}, output="ok")
        history += cli_call("f", "Fetch", {"url": "https://example.com"},
                            output="<html>")
        history += ide_call("rr", "read_file_range",
                            {"filepath": "file:///w/e.py", "startLine": 1,
                             "endLine": 2}, output=terminal("z"))
        history += ide_call("ef", "edit_existing_file",
                            {"filepath": "/w/f.py", "changes": "..."})
        history += ide_call("sw", "search_web", {"query": "q"})
        history += ide_call("nc", "run_terminal_command", {"waitForCompletion": True})
        path = self.session_file(session(history, workspace="/w"))
        got = self.by_id(path)
        self.assertEqual((got["b"].command, got["b"].output, got["b"].project),
                         ("ls -la", "total 0", "/w"))
        self.assertEqual((got["r"].paths, got["r"].consumed),
                         (("/w/a.py",), frozenset({"filepath"})))
        self.assertEqual(got["w"].paths, ("/w/b.py",))
        self.assertEqual(got["e"].paths, ("/w/c.py",))
        self.assertEqual(got["m"].paths, ("/w/d.py",))
        self.assertEqual((got["f"].kind, got["f"].command, got["f"].paths),
                         ("fetch", None, ()))
        self.assertEqual(got["rr"].paths, ("/w/e.py",))
        self.assertEqual((got["ef"].kind, got["ef"].paths), ("write", ("/w/f.py",)))
        self.assertEqual(got["sw"].kind, "fetch")
        self.assertEqual((got["nc"].command, got["nc"].consumed), (None, frozenset()))

    def test_an_unknown_tool_is_judged_by_its_name(self):
        history = ide_call("mcp", "mcp__srv__bash",
                           {"command": "rm -rf ~/Documents/x"})
        history += ide_call("ps", "powershell", {"command": "cat ~/.aws/credentials"})
        got = self.by_id(self.session_file(session(history)))
        for cid in ("mcp", "ps"):
            self.assertEqual((got[cid].kind, got[cid].known), ("other", False))
            self.assertEqual(watch.judge(got[cid]),
                             watch.evaluate(got[cid].tool_name,
                                            got[cid].tool_input))
        self.assertEqual(rules(got["mcp"]),
                         [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_outputs_from_the_state_or_the_tool_item(self):
        history = ide_call("two", "run_terminal_command", {"command": "env"},
                           output=terminal("A=1") + terminal("B=2"))
        # the state lost its output but the tool item has it
        only_item = ide_call("item", "read_file", {"filepath": "x"},
                             output=terminal("from item"))
        del only_item[0]["toolCallStates"][0]["output"]
        history += only_item
        # content as text parts
        parts = ide_call("parts", "read_file", {"filepath": "y"}, answer=False)
        parts.append({"message": {"role": "tool", "toolCallId": "parts",
                                  "content": [{"type": "text", "text": "p1"},
                                              {"type": "imageUrl",
                                               "imageUrl": {"url": "data:"}}]},
                      "contextItems": []})
        history += parts
        got = self.by_id(self.session_file(session(history)))
        self.assertEqual(got["two"].output, "A=1\n\nB=2")
        self.assertEqual(got["item"].output, "from item")
        self.assertEqual(got["parts"].output, "p1")

    def test_arguments_from_the_string_else_parsed_args(self):
        partial = ide_call("p", "run_terminal_command", '{"command":"rm -rf ~/Doc',
                           status="canceled")
        partial[0]["toolCallStates"][0]["parsedArgs"] = {"command": "rm -rf ~/Doc"}
        broken = ide_call("q", "run_terminal_command", "not json")
        broken[0]["toolCallStates"][0]["parsedArgs"] = None
        got = self.by_id(self.session_file(session(partial + broken)))
        self.assertEqual(got["p"].command, "rm -rf ~/Doc")
        self.assertEqual(got["q"].tool_input, {"_raw": "not json"})
        self.assertIsNone(got["q"].command)

    def test_a_tool_call_with_no_state_is_read_from_the_message(self):
        item = {"message": {"role": "assistant", "content": "",
                            "toolCalls": [tool_call("bare", "Bash",
                                                    {"command": "whoami"})]},
                "contextItems": []}
        got = self.by_id(self.session_file(session([item])))
        self.assertEqual((got["bare"].kind, got["bare"].command, got["bare"].status),
                         ("shell", "whoami", None))

    def test_dedupe_by_tool_call_id(self):
        history = ide_call("dup", "Bash", {"command": "ls"}, output=terminal("1"))
        history += ide_call("dup", "Bash", {"command": "ls"}, output=terminal("2"))
        history += [{"message": {"role": "assistant", "content": "",
                                 "toolCalls": [tool_call("noid", "Bash", {})]},
                     "contextItems": []}]
        del history[-1]["message"]["toolCalls"][0]["id"]
        calls = self.calls(self.session_file(session(history)))
        self.assertEqual([c.tool_call_id for c in calls], ["dup", None])
        self.assertEqual(calls[0].output, "1")

    def test_the_legacy_single_state_and_builtin_names(self):
        st = state("old_1", "builtin_run_terminal_command",
                   {"command": "rm -rf ~/Documents/x"})
        st2 = state("old_2", "builtin_read_file", {"filepath": "~/.ssh/id_rsa"},
                    output=[{"name": "id_rsa", "description": "", "content": "k"}])
        history = [{"message": {"role": "assistant", "content": "",
                                "toolCalls": [st["toolCall"]]},
                    "contextItems": [], "toolCallState": st,
                    "isBeforeCheckpoint": False},
                   {"message": {"role": "assistant", "content": "",
                                "toolCalls": [st2["toolCall"]]},
                    "contextItems": [], "toolCallState": st2}]
        got = self.by_id(self.session_file(session(history)))
        self.assertEqual((got["old_1"].kind, got["old_1"].known,
                          got["old_1"].tool_name),
                         ("shell", True, "builtin_run_terminal_command"))
        self.assertEqual(rules(got["old_1"]),
                         [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual((got["old_2"].kind, got["old_2"].paths, got["old_2"].output),
                         ("read", ("~/.ssh/id_rsa",), "k"))

    def test_a_command_the_user_ran_with_a_bang(self):
        cid = "shell-1790845260000-k3x9qa"
        history = [cli_user("hi")] + cli_call(
            cid, "Bash", {"command": "rm -rf ~/Documents/x"}, output="")
        history += cli_call("shell-like", "Bash", {"command": "ls"}, output="")
        history += cli_call("shell-1790845260000-zz", "Read", {"filepath": "x"},
                            output="")
        got = self.by_id(self.session_file(session(history, sid=CLI_SID,
                                                   workspace="/home/u/cli")))
        c = got[cid]
        self.assertEqual((c.actor, c.timestamp, c.not_after, c.kind, c.command),
                         ("user", "2026-10-01T09:01:00Z", None, "shell",
                          "rm -rf ~/Documents/x"))
        self.assertEqual(rules(c), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(got["shell-like"].actor, "agent")
        self.assertEqual(got["shell-1790845260000-zz"].actor, "agent")


class Declined(ContinueCase):

    def test_which_canceled_calls_never_ran(self):
        rejected = [{"icon": "problems", "name": "Tool Call Rejected",
                     "description": "User skipped the tool call",
                     "content": "The user skipped the tool call.\n...",
                     "hidden": True}]
        history = []
        history += ide_call("ide_none", "run_terminal_command", {"command": "a"},
                            status="canceled")
        history += ide_call("ide_empty", "run_terminal_command", {"command": "a"},
                            status="canceled", output=[])
        history += ide_call("ide_rejected", "run_terminal_command",
                            {"command": "a"}, status="canceled", output=rejected)
        # a running terminal command the user stopped: it ran
        history += ide_call("ide_stopped", "run_terminal_command",
                            {"command": "a"}, status="canceled",
                            output=terminal("partial"))
        history += ide_call("ide_streamed_empty", "run_terminal_command",
                            {"command": "a"}, status="canceled",
                            output=terminal(""))
        history += cli_call("cli_denied", "Bash", {"command": "a"},
                            status="canceled", output="Permission denied by user")
        history += cli_call("cli_policy", "Bash", {"command": "a"},
                            status="canceled",
                            output="Command blocked by security policy")
        history += cli_call("cli_other", "Bash", {"command": "a"},
                            status="canceled", output="something else")
        history += cli_call("errored", "Bash", {"command": "a"},
                            status="errored", output="Error executing tool Bash: x")
        history += cli_call("generated", "Bash", {"command": "a"},
                            status="generated")
        history += cli_call("denied_but_done", "Bash", {"command": "a"},
                            status="done", output="Permission denied by user")
        got = self.by_id(self.session_file(session(history)))
        declined = {cid for cid, c in got.items() if c.status == "declined"}
        self.assertEqual(declined, {"ide_none", "ide_empty", "ide_rejected",
                                    "cli_denied", "cli_policy"})

    def test_a_canceled_call_with_a_tool_item_that_has_text_ran(self):
        history = ide_call("c", "run_terminal_command", {"command": "a"},
                           status="canceled", answer=False)
        history.append({"message": {"role": "tool", "toolCallId": "c",
                                    "content": "output"}, "contextItems": []})
        got = self.by_id(self.session_file(session(history)))
        self.assertIsNone(got["c"].status)
        self.assertEqual(got["c"].output, "output")

    def test_a_declined_call_is_still_judged(self):
        history = ide_call("rm", "run_terminal_command",
                           {"command": "rm -rf ~/Documents/x"}, status="canceled")
        [call] = self.calls(self.session_file(session(history)))
        self.assertEqual(call.status, "declined")
        self.assertEqual(rules(call), [("fs.destructive", "rm -rf ~/Documents/x")])


class Judged(ContinueCase):

    def test_dangerous_calls_are_flagged(self):
        history = ide_call("rm", "run_terminal_command",
                           {"command": "rm -rf ~/Documents/x",
                            "waitForCompletion": True})
        history += cli_call("aws", "Bash", {"command": "cat ~/.aws/credentials"})
        history += ide_call("ssh", "read_file", {"filepath": "~/.ssh/id_rsa"})
        history += cli_call("ssh2", "Read", {"filepath": "~/.ssh/id_rsa"})
        history += ide_call("aws2", "read_file_range",
                            {"filepath": "~/.aws/credentials", "startLine": 1,
                             "endLine": 3})
        got = self.by_id(self.session_file(session(history)))
        self.assertEqual(rules(got["rm"]), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(got["aws"]), [("cred.read", "cat ~/.aws/credentials")])
        self.assertEqual(rules(got["ssh"]), [("cred.read", "~/.ssh/id_rsa")])
        self.assertEqual(rules(got["ssh2"]), [("cred.read", "~/.ssh/id_rsa")])
        self.assertEqual([r for r, _e in rules(got["aws2"])], ["cred.read"])

    def test_writing_a_dangerous_script_is_not_running_it(self):
        history = ide_call("w", "create_new_file",
                           {"filepath": "clean.sh", "contents": "rm -rf /\n"})
        history += cli_call("g", "Bash", {"command": "grep -rn 'rm -rf' ."})
        for call in self.calls(self.session_file(session(history))):
            self.assertEqual(rules(call), [], call.tool_call_id)


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(ContinueCase):

    def _cat_env(self):
        history = [cli_user("show me the env")]
        history += ide_call("cat", "run_terminal_command", {"command": "cat .env"},
                            output=terminal("STRIPE_KEY=%s\n" % SECRET))
        return self.session_file(session(history))

    def test_a_secret_in_cat_env_output_has_origin_env(self):
        found = self.findings(self._cat_env())
        [entry] = [e for e in found.values()
                   if e["fingerprint"] == clean._fingerprint(SECRET)]
        self.assertEqual(entry["origins"], {".env"})
        self.assertEqual(entry["sources"], {"continue"})
        self.assertEqual(entry["projects"], {"/home/u/proj"})

    def test_the_output_is_tied_to_its_call(self):
        path = self._cat_env()
        texts = list(self.src.secret_texts(self.store(path)))
        tied = [t for t in texts if t.call is not None]
        self.assertTrue(tied)
        self.assertTrue(all(t.call.tool_call_id == "cat" for t in tied))
        self.assertTrue(any(SECRET in json.dumps(t.node) for t in tied))
        # the rest of the item is handed over without the output
        for t in texts:
            if t.call is None:
                self.assertNotIn(SECRET, json.dumps(t.node))

    def test_a_cli_output_is_tied_too(self):
        history = cli_call("cat", "Bash", {"command": "cat config/.env.local"},
                           output="KEY=%s" % SECRET)
        found = self.findings(self.session_file(session(history)))
        [entry] = found.values()
        self.assertEqual(entry["origins"], {"config/.env.local"})

    def test_an_attached_file_is_its_own_origin(self):
        attached = {"name": ".env", "description": "/home/u/proj/.env",
                    "content": "```\nAPI_KEY=%s\n```" % SECRET,
                    "uri": {"type": "file", "value": "file:///home/u/proj/.env"},
                    "id": {"providerTitle": "file", "itemId": "x"}}
        doc = session([user_item("look", context=[attached])])
        found = self.findings(self.session_file(doc))
        [entry] = found.values()
        self.assertEqual(entry["origins"], {"/home/u/proj/.env"})

    def test_every_string_reaches_clean(self):
        doc = spec_sample()
        doc["title"] = "title " + SECRET
        path = self.session_file(doc)
        strings = []
        for text in self.src.secret_texts(self.store(path)):
            clean._each_string(text.node, lambda s: strings.append(s) or s)
        joined = "\n".join(strings)
        for needle in (SECRET, "Claude Sonnet", "check git status",
                       "working tree clean", "rsync -a . prod:/srv",
                       "File created successfuly", "sh deploy.sh"):
            self.assertIn(needle, joined)

    def test_a_typed_title_in_the_index_is_searched(self):
        index = [{"sessionId": SID, "title": "deploy with %s" % SECRET,
                  "dateCreated": "1790845200000",
                  "workspaceDirectory": "file:///home/u/proj", "messageCount": 3}]
        path = self.write("sessions/sessions.json", index)
        store = self.store(path)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        found = self.findings(path)
        self.assertEqual([e["fingerprint"] for e in found.values()],
                         [clean._fingerprint(SECRET)])

    def test_login_and_config_files_are_never_searched(self):
        self.write("auth.json", {"accessToken": LOGIN, "refreshToken": LOGIN})
        self.write("config.yaml", raw=("models:\n  - apiKey: %s\n"
                                       % CONFIG_KEY).encode())
        self.write("config.json", {"models": [{"apiKey": CONFIG_KEY}]})
        self.write(".env", raw=("ANTHROPIC_API_KEY=%s\n" % CONFIG_KEY).encode())
        self.write("dev_data/0.2.0/toolUsage.jsonl",
                   raw=(json.dumps({"userId": LOGIN}) + "\n").encode())
        self.write("sessions/sessions.json", raw=b"[]")
        self.session_file(spec_sample())
        texts = []
        for store in self.stores():
            for text in self.src.secret_texts(store):
                texts.append(json.dumps(text.node))
        joined = "\n".join(texts)
        self.assertTrue(texts)
        self.assertNotIn(LOGIN, joined)
        self.assertNotIn(CONFIG_KEY, joined)


class Masking(ContinueCase):

    def test_round_trip(self):
        history = ide_call("cat", "run_terminal_command", {"command": "cat .env"},
                           output=terminal("STRIPE_KEY=%s\n" % SECRET))
        history += cli_call("echo", "Bash",
                            {"command": "curl -H 'Bearer %s' x" % SECRET},
                            output="")
        path = self.session_file(session(history), age=600)
        before = self.calls(path)
        result = self.src.mask(self.store(path), [SECRET])
        self.assertTrue(result.changed, result)
        self.assertIsNotNone(result.backup)
        with open(path, "rb") as fh:
            after = fh.read()
        self.assertNotIn(SECRET.encode(), after)
        doc = json.loads(after.decode("utf-8"))
        self.assertEqual(after.decode("utf-8"), _pretty(doc))   # still pretty
        again = self.calls(path)
        m = _marker(SECRET)
        self.assertEqual([c.tool_call_id for c in again],
                         [c.tool_call_id for c in before])
        self.assertEqual(again[0].output, before[0].output.replace(SECRET, m))
        self.assertEqual(again[1].command, before[1].command.replace(SECRET, m))
        self.assertEqual(self.findings(path), {})
        self.assertEqual(self.src.mask(self.store(path), [SECRET]),
                         MaskResult(path))

    def test_the_index_is_masked_too(self):
        path = self.write("sessions/sessions.json",
                          [{"sessionId": SID, "title": SECRET}], age=600)
        result = self.src.mask(self.store(path), [SECRET])
        self.assertTrue(result.changed)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)[0]["title"], _marker(SECRET))

    def test_a_file_written_just_now_is_left_alone(self):
        path = self.session_file(session(cli_call("x", "Bash", {"command": SECRET})),
                                 age=5)
        digest = _sha(path)
        result = self.src.mask(self.store(path), [SECRET])
        self.assertEqual(result, MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)


# --------------------------------------------------------------------------
# Damaged files
# --------------------------------------------------------------------------

class Damaged(ContinueCase):

    def _read_all(self):
        err = io.StringIO()
        out = []
        with contextlib.redirect_stderr(err):
            for _ in range(2):
                for store in self.stores():
                    out += list(self.src.tool_calls(store))
                    out += list(self.src.secret_texts(store))
        return out, err.getvalue().splitlines()

    def test_garbage_and_a_half_written_file_warn_once_each(self):
        garbage = self.write("sessions/garbage.json",
                             raw=b"\x00\xff\xfe not json\x89PNG" * 20)
        whole = _pretty(spec_sample()).encode()
        half = self.write("sessions/half.json", raw=whole[:len(whole) // 2])
        good = self.session_file(spec_sample(), age=7200)
        _out, warnings = self._read_all()
        self.assertEqual(len(warnings), 2, warnings)
        self.assertTrue(any(garbage in w for w in warnings))
        self.assertTrue(any(half in w for w in warnings))
        self.assertEqual(self.src.counts["unreadable_stores"], 2)
        self.assertEqual(self.src.unreadable, {"not JSON": 2})
        self.assertEqual(len(self.calls(good)), 4)

    def test_wrong_shapes_everywhere_do_not_raise(self):
        docs = {
            "a": [1, 2, 3], "b": "text", "c": None, "d": {"history": "no"},
            "e": {"history": [None, 1, "x", [], {"message": None},
                              {"message": {"role": "future"}},
                              {"message": {"role": "assistant", "toolCalls": "x"},
                               "toolCallStates": "x", "toolCallState": 5},
                              {"message": {"role": "assistant",
                                           "toolCalls": [None, 3, {"function": 5},
                                                         {"id": 7, "function":
                                                          {"name": 9,
                                                           "arguments": 4}}]},
                               "toolCallStates": [None, {"toolCall": 3,
                                                         "status": "canceled",
                                                         "output": "x"},
                                                  {"toolCallId": ["x"],
                                                   "parsedArgs": 7,
                                                   "output": [None, {"content": 5}]}],
                               "contextItems": [None, {"uri": "x"},
                                                {"uri": {"type": "file",
                                                         "value": 5}}]},
                              {"message": {"role": "tool", "toolCallId": 5,
                                           "content": {"x": 1}},
                               "contextItems": "x"}],
                  "sessionId": 5, "workspaceDirectory": ["x"]},
        }
        for name, doc in docs.items():
            self.write("sessions/%s.json" % name, doc)
        out, warnings = self._read_all()
        self.assertEqual(warnings, [])
        self.assertGreater(self.src.counts["unknown"], 0)
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_unknown_items_are_counted_once_per_store(self):
        doc = session([{"message": {"role": "future"}}, user_item("x")])
        self.session_file(doc)
        self._read_all()
        self.assertEqual(self.src.counts["unknown"], 1)

    def test_deep_nesting_and_bad_bytes(self):
        deep = b'{"history": ' + b"[" * 100000 + b"]" * 100000 + b"}"
        self.write("sessions/deep.json", raw=deep)
        bad = _pretty(session(cli_call("x", "Bash", {"command": "ls"}))).encode()
        bad = bad.replace(b'\\"ls\\"', b'\\"l\xff\xfes\\"')
        path = self.write("sessions/bad.json", raw=b"\xef\xbb\xbf" + bad)
        _out, warnings = self._read_all()
        self.assertEqual(len(warnings), 1, warnings)
        [call] = self.calls(path)
        self.assertEqual(call.command, "l\udcff\udcfes")

    def test_a_vanished_store_warns_once(self):
        path = self.session_file(spec_sample())
        store = self.store(path)
        os.remove(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(len(err.getvalue().splitlines()), 1)

    @unittest.skipIf(WINDOWS, "symlinks")
    def test_a_symlink_loop_and_a_sessions_file(self):
        os.makedirs(os.path.join(self.root, "sessions"))
        os.symlink(os.path.join(self.root, "sessions", "loop.json"),
                   os.path.join(self.root, "sessions", "loop.json"))
        self.assertEqual(self.stores(), [])
        other = _tempdir(self, "continue-file-")
        with open(os.path.join(other, "sessions"), "w") as fh:
            fh.write("x")
        self.assertEqual(self.stores(override=other), [])

    def test_reading_writes_nothing(self):
        self.session_file(spec_sample())
        self.write("sessions/sessions.json", raw=b"[]")
        before = {os.path.join(d, f): _sha(os.path.join(d, f))
                  for d, _s, fs in os.walk(self.root) for f in fs}
        self._read_all()
        for store in self.stores():
            self.findings(store.path)
        after = {os.path.join(d, f): _sha(os.path.join(d, f))
                 for d, _s, fs in os.walk(self.root) for f in fs}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
