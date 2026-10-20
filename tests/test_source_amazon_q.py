"""The Amazon Q adapter (ranwhat/sources/amazon_q.py), checked against the
IDE language server (aws/language-servers lsp-codewhisperer v0.0.131) and
the legacy Q Developer CLI (v1.19.7).

Fixtures are the records those sources write: a LokiJS database serialised
whole (chatDb.ts, util.ts: tabs collection, answer messages holding
toolUses, the results on the next prompt message's userInputMessageContext)
and a data.sqlite3 with the CLI's conversations table (migration 007,
value the serde_json ConversationState). Everything runs in temp
directories; the real home is never read. Secrets are synthetic and
written as adjacent literals.
"""
import hashlib
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
from ranwhat import clean  # noqa: E402
from ranwhat.sources import _sqlite  # noqa: E402
from ranwhat.sources import amazon_q as aq  # noqa: E402
from ranwhat.sources.amazon_q import AmazonQSource  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
CWD = "/home/alice/proj"
T0 = 1760954460000                  # 2025-10-20T09:41:00Z, epoch ms
ISO0 = "2025-10-20T09:41:00.000Z"
ISO1 = "2025-10-20T09:41:03.000Z"
ISO2 = "2025-10-20T09:41:05.000Z"
HID = "7d0c1f2e-0000-4000-8000-000000000001"


def md5(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -- the IDE: a LokiJS file ------------------------------------------------

def prompt(body, ts=ISO0, results=None):
    msg = {"body": body, "type": "prompt", "origin": "IDE",
           "shouldDisplayMessage": True,
           "userInputMessageContext": {"editorState": {}}}
    if results is not None:
        msg["userInputMessageContext"] = {"toolResults": results}
    if ts:
        msg["timestamp"] = ts
    return msg


def answer(body, uses=(), ts=ISO1):
    msg = {"body": body, "type": "answer", "shouldDisplayMessage": True}
    if uses:
        msg["toolUses"] = list(uses)
    if ts:
        msg["timestamp"] = ts
    return msg


def use(cid, name, **input_):
    return {"toolUseId": cid, "name": name, "input": input_}


def bash_result(cid, stdout, stderr="", status="success", exit_status="0"):
    return {"toolUseId": cid, "status": status, "content": [{"json": {
        "output": {"kind": "json", "success": True, "content": {
            "exitStatus": exit_status, "stdout": stdout,
            "stderr": stderr}}}}]}


def text_result(cid, text, status="error"):
    return {"toolUseId": cid, "status": status, "content": [{"text": text}]}


def tab(messages, history_id=HID, updated=T0 + 5000, conv_updated=ISO2,
        title="run the unit tests", extra=None):
    doc = {"historyId": history_id, "updatedAt": updated, "isOpen": True,
           "tabType": "cwc", "title": title,
           "conversations": [{"conversationId": "c-91", "clientType": "VS Code",
                              "updatedAt": conv_updated,
                              "messages": list(messages)}],
           "meta": {"revision": 2, "created": T0, "version": 0,
                    "updated": T0 + 5000}, "$loki": 1}
    doc.update(extra or {})
    return doc


def loki(tabs, name="chat-history-x.json"):
    return {"filename": name, "collections": [
        {"name": "tabs", "data": list(tabs)},
        {"name": "settings", "data": [{"modelId": "auto", "$loki": 1}]}],
        "databaseVersion": 1.5, "engineVersion": 1.5, "autosave": True,
        "autosaveInterval": 1000, "persistenceMethod": "fs"}


def bash_turn(cid="tooluse_A1", command="npm test", stdout="12 passing"):
    return [prompt("run the unit tests"),
            answer("I'll run the test suite.",
                   [use(cid, "executeBash", command=command, cwd=CWD,
                        explanation="Run the unit tests")]),
            prompt("", ISO2, [bash_result(cid, stdout)])]


# -- the CLI: a conversations table ----------------------------------------

def entry(content, assistant, ts="2025-11-10T09:12:01.123-08:00", ms=None,
          cwd=CWD):
    meta = {"model_id": "claude", "tool_use_ids_and_names": []}
    if ms is not None:
        meta["request_start_timestamp_ms"] = ms
        meta["stream_end_timestamp_ms"] = ms + 2000
    return {"user": {"additional_context": "", "env_context": {"env_state": {
        "operating_system": "linux", "current_working_directory": cwd,
        "environment_variables": []}}, "content": content,
        "timestamp": ts, "images": None},
        "assistant": assistant, "request_metadata": meta}


def cli_prompt(text):
    return {"Prompt": {"prompt": text}}


def cli_results(*results):
    return {"ToolUseResults": {"tool_use_results": list(results)}}


def cli_use(message_id, *tool_uses, content="Running."):
    return {"ToolUse": {"message_id": message_id, "content": content,
                        "tool_uses": list(tool_uses)}}


def cli_tool(cid, name, **args):
    return {"id": cid, "name": name, "orig_name": name, "args": args,
            "orig_args": args}


def cli_ok(cid, **out):
    return {"tool_use_id": cid, "content": [{"Json": out}], "status": "Success"}


def state(history, cid="5b1e0000-0000-4000-8000-000000000001", **extra):
    doc = {"conversation_id": cid, "next_message": None, "history": history,
           "valid_history_range": [0, len(history)], "transcript": [],
           "tools": {}, "context_message_length": None,
           "latest_summary": None, "mcp_enabled": True}
    doc.update(extra)
    return doc


MS0 = 1762794721000


class Base(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ranwhat-aq-")
        self.home = os.path.join(self.tmp, "home")
        self.history = os.path.join(self.home, ".aws", "amazonq", "history")
        self.data = os.path.join(self.home, ".local", "share", "amazon-q")
        self.src = AmazonQSource()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def ide(self, tabs, name=None, age=3600):
        os.makedirs(self.history, exist_ok=True)
        name = name or "chat-history-%s.json" % md5(CWD)
        path = os.path.join(self.history, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(loki(tabs, name), fh)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def raw(self, data, name=None, folder=None):
        folder = folder or self.history
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, name or "chat-history-raw.json")
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def cli(self, rows, age=3600, wal=False):
        os.makedirs(self.data, exist_ok=True)
        path = os.path.join(self.data, "data.sqlite3")
        conn = sqlite3.connect(path)
        if wal:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE conversations (key TEXT PRIMARY KEY, "
                     "value TEXT)")
        conn.execute("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT INTO auth_kv VALUES ('codewhisperer:odic:token',"
                     " ?)", (json.dumps({"access_token": SECRET}),))
        for key, value in rows:
            conn.execute("INSERT INTO conversations VALUES (?, ?)",
                         (key, value if isinstance(value, str)
                          else json.dumps(value)))
        conn.commit()
        conn.close()
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def stores(self, override=None):
        return self.src.stores(self.src.locations(override=override))

    def store(self, path):
        for store in self.stores(path if os.path.isdir(path) else None):
            if store.path == path:
                return store
        self.fail("%s is not a store" % path)

    def only(self, path):
        for store in self.src.stores(self.src.locations(
                override=os.path.dirname(path))):
            if store.path == path:
                return store
        self.fail("%s is not a store" % path)

    def calls(self, path):
        return list(self.src.tool_calls(self.only(path)))


# --------------------------------------------------------------------------
# Where Amazon Q keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = AmazonQSource()

    def test_linux(self):
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"), [
            ("/home/u/.aws/amazonq/history", "default"),
            ("/home/u/.local/share/amazon-q", "default")])

    def test_linux_xdg_data_home_when_absolute(self):
        got = self.src.default_paths({"XDG_DATA_HOME": "/xdg"}, "/home/u",
                                     "linux")
        self.assertEqual(got[1], ("/xdg/amazon-q", "env XDG_DATA_HOME"))
        got = self.src.default_paths({"XDG_DATA_HOME": "rel"}, "/home/u",
                                     "linux")
        self.assertEqual(got[1], ("/home/u/.local/share/amazon-q", "default"))
        got = self.src.default_paths({"XDG_DATA_HOME": ""}, "/home/u", "linux")
        self.assertEqual(got[1][1], "default")

    def test_the_ide_path_has_no_override(self):
        got = self.src.default_paths({"XDG_DATA_HOME": "/xdg",
                                      "AWS_CONFIG_FILE": "/x"}, "/home/u",
                                     "linux")
        self.assertEqual(got[0], ("/home/u/.aws/amazonq/history", "default"))

    def test_macos_ignores_xdg(self):
        got = self.src.default_paths({"XDG_DATA_HOME": "/xdg"}, "/Users/u",
                                     "darwin")
        self.assertEqual(got, [
            ("/Users/u/.aws/amazonq/history", "default"),
            ("/Users/u/Library/Application Support/amazon-q", "default")])

    def test_windows(self):
        got = self.src.default_paths({}, "C:\\Users\\u", "win32")
        self.assertEqual(got, [
            ("C:\\Users\\u\\.aws\\amazonq\\history", "default"),
            ("C:\\Users\\u\\AppData\\Local\\amazon-q", "default")])
        got = self.src.default_paths({"LOCALAPPDATA": "D:\\Local"},
                                     "C:\\Users\\u", "win32")
        self.assertEqual(got[1], ("D:\\Local\\amazon-q", "default"))

    def test_missing_env_var_is_not_an_error(self):
        self.assertEqual(len(self.src.default_paths({}, "/h", "linux")), 2)

    def test_identity(self):
        self.assertEqual(self.src.id, "amazon-q")
        self.assertEqual(self.src.env, ("XDG_DATA_HOME",))

    def test_locations_come_from_the_home_directory(self):
        home = tempfile.mkdtemp(prefix="ranwhat-aq-")
        self.addCleanup(shutil.rmtree, home, True)
        with mock.patch("ranwhat.sources._paths.home", return_value=home), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("XDG_DATA_HOME", None)
            locs = AmazonQSource().locations()
        self.assertEqual(locs[0].path, os.path.join(home, ".aws", "amazonq",
                                                    "history"))
        self.assertFalse(locs[0].exists)


# --------------------------------------------------------------------------
# Finding the stores
# --------------------------------------------------------------------------

class Stores(Base):

    def test_empty_store_dir_and_nothing_there(self):
        self.assertEqual(self.stores(self.tmp), [])
        self.assertEqual(self.stores(os.path.join(self.tmp, "nope")), [])

    def test_every_workspace_file_whatever_its_hash(self):
        a = self.ide([tab(bash_turn())], "chat-history-%s.json" % md5(CWD))
        b = self.ide([tab(bash_turn(), "h2")],
                     "chat-history-%s.json" % sha256("/p/x.code-workspace"))
        c = self.ide([tab(bash_turn(), "h3")], "chat-history-no-workspace.json")
        paths = {s.path for s in self.stores(self.history)}
        self.assertEqual(paths, {a, b, c})

    def test_other_files_are_not_stores(self):
        self.raw(b"{}", "settings.json")
        self.raw(b"x", ".chat-history-hidden.json")
        self.raw(b"x", "chat-history-1.json.tmp")
        self.assertEqual(self.stores(self.history), [])

    def test_store_fields(self):
        path = self.ide([tab(bash_turn())])
        (store,) = self.stores(self.history)
        self.assertEqual((store.source, store.path, store.format),
                         ("amazon-q", path, "json"))
        self.assertEqual(store.masking, "read-only")
        self.assertIn("language server", store.why_read_only)

    def test_cli_database_is_a_read_only_sqlite_store(self):
        path = self.cli([(CWD, state([]))])
        (store,) = self.stores(self.data)
        self.assertEqual((store.path, store.format, store.masking),
                         (path, "sqlite", "read-only"))

    def test_a_parent_folder_finds_history_inside_it(self):
        path = self.ide([tab(bash_turn())])
        amazonq = os.path.dirname(self.history)
        self.assertEqual([s.path for s in self.stores(amazonq)], [path])

    def test_a_file_path_is_taken_as_it_is(self):
        path = self.ide([tab(bash_turn())])
        self.assertEqual([s.path for s in self.stores(path)], [path])
        db = self.cli([])
        self.assertEqual([s.path for s in self.stores(db)], [db])

    def test_both_stores_newest_first(self):
        old = self.ide([tab(bash_turn())], age=9000)
        new = self.cli([(CWD, state([]))], age=10)
        got = self.src.stores(self.src.locations(
            override=[self.history, self.data]))
        self.assertEqual([s.path for s in got], [new, old])


# --------------------------------------------------------------------------
# The IDE: tool calls
# --------------------------------------------------------------------------

class IdeCalls(Base):

    def test_a_shell_call_with_its_result(self):
        path = self.ide([tab(bash_turn())])
        (call,) = self.calls(path)
        self.assertEqual((call.source, call.tool_name, call.kind, call.known),
                         ("amazon-q", "executeBash", "shell", True))
        self.assertEqual(call.command, "npm test")
        self.assertEqual(call.workdir, CWD)
        self.assertEqual(call.project, CWD)
        self.assertEqual(call.session, HID)
        self.assertEqual(call.tool_call_id, "tooluse_A1")
        self.assertEqual(call.timestamp, "2025-10-20T09:41:03Z")
        self.assertIsNone(call.not_after)
        self.assertEqual(call.output, "12 passing")
        self.assertIsNone(call.status)
        self.assertEqual(call.consumed, frozenset(["command"]))
        self.assertEqual(call.tool_input["explanation"], "Run the unit tests")

    def test_stderr_follows_stdout(self):
        msgs = [prompt("go"), answer("x", [use("t", "executeBash",
                                              command="make", cwd=CWD)]),
                prompt("", ISO2, [bash_result("t", "out", "boom", "error",
                                              "2")])]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertEqual(call.output, "out\nboom")

    def test_file_write_and_edit(self):
        msgs = [prompt("write"), answer("ok", [
            use("w", "fsWrite", command="create", path="/p/a.py",
                fileText="x = 1\n"),
            use("r", "fsReplace", path="/p/b.py",
                diffs=[{"oldStr": "a", "newStr": "b"}])]),
            prompt("", ISO2, [
                {"toolUseId": "w", "status": "success",
                 "content": [{"json": {"output": {"kind": "text",
                                                  "content": "created"}}}]},
                {"toolUseId": "r", "status": "success",
                 "content": [{"json": {}}]}])]
        got = {c.tool_call_id: c for c in self.calls(self.ide([tab(msgs)]))}
        self.assertEqual((got["w"].kind, got["w"].paths, got["w"].known),
                         ("write", ("/p/a.py",), True))
        self.assertEqual(got["w"].output, "created")
        self.assertEqual((got["r"].kind, got["r"].paths),
                         ("write", ("/p/b.py",)))
        self.assertEqual(got["w"].consumed, frozenset())

    def test_reads(self):
        msgs = [prompt("look"), answer("ok", [
            use("a", "fsRead", paths=["/p/a", "/p/b", 3, ""]),
            use("b", "listDirectory", path="/p"),
            use("c", "grepSearch", query="TODO", path="/p/src"),
            use("d", "grepSearch", query="TODO"),
            use("e", "fileSearch", queryName="conf", path="/etc")])]
        got = {c.tool_call_id: c for c in self.calls(self.ide([tab(msgs)]))}
        self.assertEqual((got["a"].kind, got["a"].paths),
                         ("read", ("/p/a", "/p/b")))
        self.assertEqual(got["a"].consumed, frozenset(["paths"]))
        self.assertEqual(got["b"].paths, ("/p",))
        self.assertEqual(got["c"].paths, ("/p/src",))
        self.assertEqual((got["d"].kind, got["d"].paths), ("read", ()))
        self.assertEqual(got["e"].paths, ("/etc",))

    def test_unknown_and_mcp_tools_are_judged_by_name(self):
        msgs = [prompt("x"), answer("ok", [
            use("a", "codeReview", fileLevelArtifacts=[]),
            use("b", "my_server___lookup", q="1")])]
        got = {c.tool_call_id: c for c in self.calls(self.ide([tab(msgs)]))}
        self.assertEqual((got["a"].kind, got["a"].known), ("other", True))
        self.assertEqual((got["b"].kind, got["b"].known), ("other", False))

    def test_cancelled_by_the_user_is_declined(self):
        msgs = [prompt("x"), answer("ok", [use("t", "executeBash",
                                              command="rm -rf /x", cwd=CWD)]),
                prompt("", ISO2, [text_result("t", aq.CANCELLED)])]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertEqual(call.status, "declined")
        self.assertEqual(call.output, aq.CANCELLED)

    def test_a_stopped_command_ran(self):
        msgs = [prompt("x"), answer("ok", [use("t", "executeBash",
                                              command="sleep 99", cwd=CWD)]),
                prompt("", ISO2, [text_result("t", "Command stopped by user")])]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertIsNone(call.status)

    def test_cancelled_text_inside_a_longer_output_ran(self):
        msgs = [prompt("x"), answer("ok", [use("t", "executeBash",
                                              command="echo", cwd=CWD)]),
                prompt("", ISO2, [text_result(
                    "t", aq.CANCELLED + " (echoed)")])]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertIsNone(call.status)

    def test_a_success_with_the_cancelled_text_ran(self):
        msgs = [prompt("x"), answer("ok", [use("t", "executeBash",
                                              command="echo", cwd=CWD)]),
                prompt("", ISO2, [text_result("t", aq.CANCELLED, "success")])]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertIsNone(call.status)

    def test_a_call_with_no_result_is_still_yielded(self):
        msgs = [prompt("x"), answer("ok", [use("t", "executeBash",
                                              command="ls", cwd=CWD)])]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertIsNone(call.output)
        self.assertEqual(call.command, "ls")

    def test_a_result_for_an_unknown_call_is_ignored(self):
        msgs = [prompt("", ISO2, [bash_result("ghost", "x")])]
        self.assertEqual(self.calls(self.ide([tab(msgs)])), [])

    def test_legacy_tab_without_timestamps_uses_an_upper_bound(self):
        msgs = [prompt("x", None), answer("ok", [use(
            "t", "executeBash", command="ls", cwd=CWD)], ts=None)]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertIsNone(call.timestamp)
        self.assertEqual(call.not_after, "2025-10-20T09:41:05Z")

    def test_tab_updated_at_as_an_iso_string_is_accepted(self):
        msgs = [answer("ok", [use("t", "executeBash", command="ls", cwd=CWD)],
                       ts=None)]
        doc = tab(msgs, updated="2025-10-20T09:42:00.000Z", conv_updated=None)
        (call,) = self.calls(self.ide([doc]))
        self.assertEqual(call.not_after, "2025-10-20T09:42:00Z")

    def test_no_time_anywhere_falls_back_to_the_files_write(self):
        msgs = [answer("ok", [use("t", "executeBash", command="ls", cwd=CWD)],
                       ts=None)]
        doc = tab(msgs, updated=None, conv_updated=None)
        (call,) = self.calls(self.ide([doc]))
        self.assertIsNotNone(call.not_after)

    def test_legacy_tab_with_no_tool_uses(self):
        msgs = [prompt("hi", None), answer("hello", ts=None)]
        self.assertEqual(self.calls(self.ide([tab(msgs)])), [])

    def test_project_comes_from_a_shell_cwd_in_the_tab(self):
        msgs = [prompt("x"), answer("ok", [
            use("a", "fsRead", paths=["/p/a"]),
            use("b", "executeBash", command="ls", cwd=CWD)])]
        got = {c.tool_call_id: c for c in self.calls(self.ide([tab(msgs)]))}
        self.assertEqual(got["a"].project, CWD)

    def test_many_tabs_and_conversations_each_keep_their_session(self):
        t1 = tab(bash_turn("a1", "ls"), "h-1")
        t2 = tab(bash_turn("b1", "pwd"), "h-2")
        t2["conversations"].append({"conversationId": "c-2", "messages": [
            answer("ok", [use("b2", "executeBash", command="id", cwd=CWD)])]})
        got = self.calls(self.ide([t1, t2]))
        self.assertEqual([(c.session, c.command) for c in got],
                         [("h-1", "ls"), ("h-2", "pwd"), ("h-2", "id")])

    def test_a_call_copied_into_another_tab_counts_once(self):
        t1 = tab(bash_turn("same", "ls"), "h-1")
        t2 = tab(bash_turn("same", "ls"), "h-2")
        self.assertEqual(len(self.calls(self.ide([t1, t2]))), 1)

    def test_input_that_is_a_json_string_is_decoded(self):
        msgs = [answer("ok", [{"toolUseId": "t", "name": "executeBash",
                               "input": json.dumps({"command": "ls",
                                                    "cwd": CWD})}])]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertEqual(call.command, "ls")

    def test_input_that_is_not_an_object(self):
        msgs = [answer("ok", [{"toolUseId": "t", "name": "executeBash",
                               "input": [1]}])]
        (call,) = self.calls(self.ide([tab(msgs)]))
        self.assertEqual(call.tool_input, {"_value": [1]})
        self.assertIsNone(call.command)

    def test_a_huge_output_is_cut(self):
        big = "a" * (aq.OUTPUT_MAX + 5000)
        (call,) = self.calls(self.ide([tab(bash_turn(stdout=big))]))
        self.assertEqual(len(call.output), aq.OUTPUT_MAX)

    def test_the_truncation_marker_is_kept_as_written(self):
        out = "x" * 10 + " ... truncated"
        (call,) = self.calls(self.ide([tab(bash_turn(stdout=out))]))
        self.assertTrue(call.output.endswith(" ... truncated"))


# --------------------------------------------------------------------------
# The IDE: files that are not what the agent writes
# --------------------------------------------------------------------------

class IdeMalformed(Base):

    def test_an_empty_file_holds_nothing(self):
        path = self.raw(b"")
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)
        self.assertEqual(self.calls(self.raw(b"  \n", "chat-history-w.json")),
                         [])

    def test_an_empty_collection_holds_nothing(self):
        path = self.ide([])
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_a_truncated_file_is_not_read_and_is_counted(self):
        path = self.ide([tab(bash_turn())])
        with open(path, "rb") as fh:
            whole = fh.read()
        self.raw(whole[:len(whole) // 2], os.path.basename(path))
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(list(self.src.unreadable), [aq.NOT_JSON])

    def test_a_malformed_file(self):
        path = self.raw(b"this is not json {{{")
        self.assertEqual(self.calls(path), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(list(self.src.secret_texts(self.only(path))), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_file_rewritten_while_it_is_read_is_read_again(self):
        path = self.ide([tab(bash_turn())])
        with open(path, "rb") as fh:
            whole = fh.read()
        store = self.only(path)
        real = os.stat
        state = {"n": 0}

        def stat(p, *a, **k):
            result = real(p, *a, **k)
            if os.path.normpath(str(p)) == os.path.normpath(path):
                state["n"] += 1
                if state["n"] == 2:     # the "after" stat of the first read
                    with open(path, "wb") as fh:
                        fh.write(whole)
                    os.utime(path, (1, 1))
                    return os.stat_result(result[:6] + (result[6] + 1,)
                                          + result[7:])
            return result

        with open(path, "wb") as fh:
            fh.write(whole[:50])
        with mock.patch("ranwhat.sources.amazon_q.os.stat", stat):
            got = list(self.src.tool_calls(store))
        self.assertEqual(len(got), 1)
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_non_utf8_bytes_are_kept_not_fatal(self):
        msgs = [prompt("x"), answer("ok", [use(
            "t", "executeBash", command="echo \u00e9", cwd=CWD)])]
        path = self.ide([tab(msgs)])
        with open(path, "rb") as fh:
            data = fh.read()
        data = data.replace(b'"title": "run the unit tests"',
                            b'"title": "run \xff\xfe tests"')
        self.raw(data, os.path.basename(path))
        (call,) = self.calls(path)
        self.assertEqual(call.command, "echo \u00e9")
        texts = list(self.src.secret_texts(self.only(path)))
        self.assertTrue(any(isinstance(t.node, dict)
                            and "\udcff" in str(t.node.get("title"))
                            for t in texts))

    def test_a_byte_order_mark(self):
        path = self.ide([tab(bash_turn())])
        with open(path, "rb") as fh:
            data = fh.read()
        self.raw(b"\xef\xbb\xbf" + data, os.path.basename(path))
        self.assertEqual(len(self.calls(path)), 1)

    def test_wrong_top_level_shapes(self):
        for i, data in enumerate((b"[]", b"42", b"null", b'"s"',
                                  b'{"collections": 5}',
                                  b'{"collections": [{"name": "tabs"}]}',
                                  b'{"collections": [3]}')):
            src = AmazonQSource()
            path = self.raw(data, "chat-history-s%d.json" % i)
            store = [s for s in src.stores(src.locations(
                override=self.history)) if s.path == path][0]
            self.assertEqual(list(src.tool_calls(store)), [], data)
            self.assertEqual(src.counts["unknown"], 1, data)

    def test_odd_records_are_skipped_and_counted(self):
        doc = loki([tab([
            "a string", {"type": "weird"}, {"type": "answer",
                                            "toolUses": [5, {"name": ""},
                                                         {"toolUseId": "x"}]},
            answer("ok", [use("g", "executeBash", command="ls", cwd=CWD)])]),
            "not a tab"])
        doc["collections"][0]["data"][0]["conversations"].insert(0, "junk")
        path = self.raw(json.dumps(doc).encode("utf-8"))
        (call,) = self.calls(path)
        self.assertEqual(call.tool_call_id, "g")
        self.assertGreaterEqual(self.src.counts["unknown"], 6)

    def test_oversized_file_is_not_read(self):
        path = self.ide([tab(bash_turn())])
        with mock.patch.object(aq, "MAX_FILE", 100):
            self.assertEqual(self.calls(path), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(list(self.src.unreadable), [aq.TOO_LARGE])

    def test_deeply_nested_json_does_not_raise(self):
        data = b"[" * 200000 + b"]" * 200000
        path = self.raw(data)
        self.assertEqual(self.calls(path), [])

    def test_a_huge_message_in_linear_time(self):
        big = "x" * (8 << 20)
        path = self.ide([tab(bash_turn(stdout=big))])
        start = time.time()
        self.assertEqual(len(self.calls(path)), 1)
        list(self.src.secret_texts(self.only(path)))
        self.assertLess(time.time() - start, 20)

    def test_a_directory_named_like_a_store_is_not_one(self):
        os.makedirs(os.path.join(self.history, "chat-history-dir.json"))
        self.assertEqual(self.stores(self.history), [])

    def test_unreadable_file_is_counted(self):
        path = self.ide([tab(bash_turn())])
        store = self.only(path)
        with mock.patch("builtins.open", side_effect=PermissionError):
            self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_nothing_raises_on_an_unexpected_error(self):
        path = self.ide([tab(bash_turn())])
        store = self.only(path)
        with mock.patch.object(AmazonQSource, "_ide_call",
                               side_effect=RuntimeError("boom")):
            self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)


# --------------------------------------------------------------------------
# The IDE: text for clean
# --------------------------------------------------------------------------

class IdeTexts(Base):

    def test_results_come_tied_to_their_call(self):
        path = self.ide([tab(bash_turn(stdout="KEY=" + SECRET))])
        texts = list(self.src.secret_texts(self.only(path)))
        tied = [t for t in texts if t.call is not None]
        self.assertEqual(len(tied), 1)
        self.assertEqual(tied[0].call.command, "npm test")
        self.assertIn(SECRET, json.dumps(tied[0].node))

    def test_every_other_string_is_handed_over(self):
        msgs = [prompt("my key is " + SECRET), answer(
            "ok", [use("t", "executeBash", command="echo " + SECRET,
                       cwd=CWD)])]
        path = self.ide([tab(msgs, title="t " + SECRET)])
        blob = json.dumps([t.node for t in
                           self.src.secret_texts(self.only(path))])
        self.assertEqual(blob.count(SECRET), 3)

    def test_images_are_not_walked(self):
        msgs = [dict(prompt("see"), images=[{"format": "png", "bytes": {
            str(i): i % 256 for i in range(50)}}])]
        path = self.ide([tab(msgs)])
        blob = json.dumps([t.node for t in
                           self.src.secret_texts(self.only(path))])
        self.assertNotIn('"bytes"', blob)

    def test_clean_finds_a_secret_and_cannot_mask_the_file(self):
        path = self.ide([tab(bash_turn(stdout="KEY=" + SECRET))])
        store = self.only(path)
        values = {}
        findings, _masks = clean.scan_store(self.src, store, values)
        self.assertIn(SECRET, values.values())
        result = self.src.mask(store, [SECRET])
        self.assertEqual(result, MaskResult(path, skipped="read-only"))
        with open(path, encoding="utf-8") as fh:
            self.assertIn(SECRET, fh.read())


# --------------------------------------------------------------------------
# The CLI: data.sqlite3
# --------------------------------------------------------------------------

def tests_conversation():
    return state([
        entry(cli_prompt("run the tests"),
              cli_use("m1", cli_tool("tooluse_X", "execute_bash",
                                     command="cargo test", summary="Run"),
                      cli_tool("tooluse_Y", "fs_read", operations=[
                          {"mode": "Line", "path": "/p/Cargo.toml"},
                          {"mode": "Image", "image_paths": ["/p/a.png"]}]),
                      cli_tool("tooluse_Z", "fs_write", command="create",
                               path="/p/new.rs", file_text="fn main(){}")),
              ms=MS0),
        entry(cli_results(
            cli_ok("tooluse_X", exit_status="0", stdout="test result: ok",
                   stderr=""),
            {"tool_use_id": "tooluse_Y", "content": [{"Text": "[package]"}],
             "status": "Success"},
            {"tool_use_id": "tooluse_Z", "content": [{"Text": aq.CANCELLED}],
             "status": "Error"}),
            {"Response": {"message_id": "m2", "content": "All pass."}},
            ts=None)])


class CliCalls(Base):

    def calls_of(self, rows):
        path = self.cli(rows)
        (store,) = self.stores(self.data)
        return {c.tool_call_id: c for c in self.src.tool_calls(store)}

    def test_a_shell_call_with_its_result(self):
        got = self.calls_of([(CWD, tests_conversation())])
        call = got["tooluse_X"]
        self.assertEqual((call.tool_name, call.kind, call.known),
                         ("execute_bash", "shell", True))
        self.assertEqual(call.command, "cargo test")
        self.assertEqual(call.workdir, CWD)
        self.assertEqual(call.project, CWD)
        self.assertEqual(call.session, "5b1e0000-0000-4000-8000-000000000001")
        self.assertEqual(call.timestamp, "2025-11-10T17:12:01Z")
        self.assertEqual(call.output, "test result: ok")
        self.assertIsNone(call.status)

    def test_reads_and_writes_and_declined(self):
        got = self.calls_of([(CWD, tests_conversation())])
        self.assertEqual((got["tooluse_Y"].kind, got["tooluse_Y"].paths),
                         ("read", ("/p/Cargo.toml", "/p/a.png")))
        self.assertEqual(got["tooluse_Y"].output, "[package]")
        self.assertEqual((got["tooluse_Z"].kind, got["tooluse_Z"].paths),
                         ("write", ("/p/new.rs",)))
        self.assertEqual(got["tooluse_Z"].status, "declined")

    def test_cancelled_tool_uses_prompt(self):
        content = {"CancelledToolUses": {"prompt": "no, stop", "tool_use_results": [
            {"tool_use_id": "c1", "content": [{"Text": aq.CANCELLED}],
             "status": "Error"}]}}
        st = state([entry(cli_prompt("x"), cli_use("m", cli_tool(
            "c1", "execute_bash", command="rm -rf /p")), ms=MS0),
            entry(content, {"Response": {"message_id": "m2",
                                         "content": "ok"}})])
        got = self.calls_of([(CWD, st)])
        self.assertEqual(got["c1"].status, "declined")

    def test_windows_shell_name(self):
        st = state([entry(cli_prompt("x"), cli_use("m", cli_tool(
            "w1", "execute_cmd", command="dir")), ms=MS0)])
        call = self.calls_of([("C:\\proj", st)])["w1"]
        self.assertEqual((call.kind, call.command), ("shell", "dir"))
        self.assertEqual(call.project, "C:\\proj")

    def test_other_and_mcp_tools(self):
        st = state([entry(cli_prompt("x"), cli_use(
            "m", cli_tool("o1", "use_aws", service_name="s3"),
            cli_tool("o2", "@srv/tool", a=1)), ms=MS0)])
        got = self.calls_of([(CWD, st)])
        self.assertEqual((got["o1"].kind, got["o1"].known), ("other", True))
        self.assertEqual((got["o2"].kind, got["o2"].known), ("other", False))

    def test_no_request_metadata_time_uses_an_upper_bound(self):
        st = state([entry(cli_prompt("x"), cli_use("m", cli_tool(
            "n1", "execute_bash", command="ls")))])
        call = self.calls_of([(CWD, st)])["n1"]
        self.assertIsNone(call.timestamp)
        self.assertIsNotNone(call.not_after)

    def test_a_call_whose_results_never_arrived(self):
        st = state([entry(cli_prompt("x"), cli_use("m", cli_tool(
            "p1", "execute_bash", command="ls")), ms=MS0)])
        call = self.calls_of([(CWD, st)])["p1"]
        self.assertIsNone(call.output)

    def test_only_the_conversations_table_is_selected(self):
        path = self.cli([(CWD, tests_conversation())])
        (store,) = self.stores(self.data)
        seen = []
        real = _sqlite._connect

        def spy(uri):
            conn = real(uri)
            conn.set_trace_callback(seen.append)
            return conn

        with mock.patch.object(_sqlite, "_connect", spy):
            list(self.src.tool_calls(store))
            list(self.src.secret_texts(store))
        self.assertTrue(seen)
        self.assertFalse([s for s in seen if "auth_kv" in s], seen)
        self.assertEqual(path, store.path)

    def test_the_database_is_never_written(self):
        path = self.cli([(CWD, tests_conversation())], wal=True)
        before = {n: os.stat(os.path.join(self.data, n)).st_mtime_ns
                  for n in os.listdir(self.data)}
        list(self.src.tool_calls(self.stores(self.data)[0]))
        after = {n: os.stat(os.path.join(self.data, n)).st_mtime_ns
                 for n in os.listdir(self.data)}
        self.assertEqual(before, after)
        self.assertTrue(os.path.exists(path))

    def test_auth_tokens_are_never_handed_over(self):
        self.cli([(CWD, tests_conversation())])
        (store,) = self.stores(self.data)
        blob = json.dumps([t.node for t in self.src.secret_texts(store)])
        self.assertNotIn(SECRET, blob)

    def test_texts_tie_results_to_calls_and_keep_the_prompt(self):
        self.cli([(CWD, tests_conversation())])
        (store,) = self.stores(self.data)
        texts = list(self.src.secret_texts(store))
        self.assertTrue(any(t.call and t.call.command == "cargo test"
                            for t in texts))
        blob = json.dumps([t.node for t in texts])
        self.assertIn("run the tests", blob)

    def test_empty_database_and_empty_table(self):
        self.cli([])
        (store,) = self.stores(self.data)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_zero_byte_database(self):
        path = self.raw(b"", "data.sqlite3", self.data)
        store = self.stores(self.data)[0]
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(path, store.path)

    def test_not_a_database(self):
        self.raw(b"definitely not sqlite" * 10, "data.sqlite3", self.data)
        store = self.stores(self.data)[0]
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(list(self.src.unreadable), [aq.NOT_DATABASE])

    def test_truncated_database(self):
        path = self.cli([(CWD, tests_conversation())])
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "wb") as fh:
            fh.write(data[:100])
        store = self.stores(self.data)[0]
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertGreaterEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_database_without_the_table(self):
        os.makedirs(self.data)
        conn = sqlite3.connect(os.path.join(self.data, "data.sqlite3"))
        conn.execute("CREATE TABLE state (key TEXT, value TEXT)")
        conn.commit()
        conn.close()
        store = self.stores(self.data)[0]
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(self.src.counts["unknown"], 1)

    def test_a_value_that_is_not_json_or_not_an_object(self):
        good = ("/good", tests_conversation())
        got = self.calls_of([("/a", "{truncated"), ("/b", "[1,2]"),
                             ("/c", "null"), good])
        self.assertIn("tooluse_X", got)
        self.assertEqual(self.src.counts["unparsed"], 1)
        self.assertGreaterEqual(self.src.counts["unknown"], 2)

    def test_non_utf8_cells(self):
        path = self.cli([])
        conn = sqlite3.connect(path)
        bad = json.dumps(state([entry(cli_prompt("x"), cli_use(
            "m", cli_tool("u1", "execute_bash", command="echo @@")),
            ms=MS0)])).replace("@@", "\u00e9").encode("utf-8")
        conn.execute("INSERT INTO conversations VALUES (?, ?)",
                     ("/u", bad.replace(b"echo", b"echo \xff")))
        conn.commit()
        conn.close()
        (store,) = self.stores(self.data)
        got = {c.tool_call_id: c for c in self.src.tool_calls(store)}
        self.assertIn("\udcff", got["u1"].command)

    def test_an_oversized_row_is_skipped_and_counted(self):
        self.cli([("/big", tests_conversation())])
        (store,) = self.stores(self.data)
        with mock.patch.object(aq, "MAX_ROW", 100):
            self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_odd_history_entries(self):
        st = state(["x", 5, entry(cli_prompt("p"), {"weird": 1}),
                    entry(cli_prompt("p"), cli_use("m", 3, {"name": ""},
                                                   cli_tool("k", "execute_bash",
                                                            command="ls")),
                          ms=MS0)])
        got = self.calls_of([(CWD, st)])
        self.assertEqual(list(got), ["k"])
        self.assertGreaterEqual(self.src.counts["unknown"], 4)

    def test_wal_database_is_read(self):
        self.cli([(CWD, tests_conversation())], wal=True)
        (store,) = self.stores(self.data)
        self.assertEqual(len(list(self.src.tool_calls(store))), 3)

    def test_clean_does_not_mask_the_database(self):
        path = self.cli([(CWD, tests_conversation())])
        (store,) = self.stores(self.data)
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(path, skipped="read-only"))

    def test_clean_finds_a_secret_in_a_result(self):
        st = state([entry(cli_prompt("x"), cli_use("m", cli_tool(
            "s1", "execute_bash", command="cat .env")), ms=MS0),
            entry(cli_results(cli_ok("s1", exit_status="0",
                                     stdout="K=" + SECRET, stderr="")),
                  {"Response": {"message_id": "m2", "content": "ok"}})])
        self.cli([(CWD, st)])
        (store,) = self.stores(self.data)
        values = {}
        clean.scan_store(self.src, store, values)
        self.assertIn(SECRET, values.values())


class Reset(Base):

    def test_counters_start_again(self):
        path = self.raw(b"{{{")
        self.calls(path)
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.src.reset()
        self.assertEqual(self.src.counts["unreadable_stores"], 0)
        self.assertEqual(self.src.unreadable, {})


if __name__ == "__main__":
    unittest.main()
