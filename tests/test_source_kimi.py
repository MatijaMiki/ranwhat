"""The Kimi CLI (legacy Python) adapter, id "kimi" (design section 7.9).

Fixtures are built field for field from the spec's sample: kimi.json,
context.jsonl (special records written by json.dumps, with spaces;
messages by pydantic, without) and wire.jsonl, in a temp share directory.
HOME, KIMI_SHARE_DIR and the backup root all point into a temp directory;
the real home is never read. Every secret is synthetic and written as
adjacent literals.

watch.judge and clean.scan_sources are not wired in yet, so _judge and
_scan below follow design 3.5 and 3.6 on top of watch.evaluate and the
clean helpers that exist today.
"""
import builtins
import contextlib
import hashlib
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

import growth  # noqa: E402
from ranwhat import clean, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite, _stamps, kimi  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402

WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
ROTATED_SECRET = "sk_" "live_" "Pp3kW9dQ2nVb7XcR5tYu"
# Typed into a command. Not ASCII, so the arguments string (json.dumps,
# ASCII) holds it as \u00e4, and the line around it escapes that backslash
# once more: the value sits in the file as Hq8\\u00e4T2pZx9Lm3.
TYPED = "Hq8" "\u00e4" "T2pZx9Lm3"
TYPED_IN_FILE = "Hq8" "\\\\u00e4" "T2pZx9Lm3"

PROJECT = "/Users/me/proj"
OTHER_PROJECT = "/Users/me/remote-proj"
SID = "3f0c7a52-1111-4222-8333-444455556666"
SID_OLD = "0b1e2f3a-aaaa-4bbb-8ccc-ddddeeeeffff"
SID_IMPORTED = "9c8d7e6f-5555-4666-8777-888899990000"


def md5(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Lines, as Kimi CLI writes them
# --------------------------------------------------------------------------

def _spec_context(secret):
    """The spec's context.jsonl sample, line for line."""
    return [
        '{"role": "_system_prompt", "content": "You are Kimi CLI ..."}',
        '{"role": "_checkpoint", "id": 0}',
        '{"role":"user","content":"show me the env file"}',
        '{"role":"assistant","content":"Reading it.","tool_calls":[{"type":'
        '"function","id":"Shell:0","function":{"name":"Shell","arguments":'
        '"{\\"command\\": \\"cat .env\\"}"}}]}',
        '{"role":"tool","content":[{"type":"text","text":"<system>Command '
        'executed successfully.</system>"},{"type":"text","text":"API_KEY='
        + secret + '\\n"}],"tool_call_id":"Shell:0"}',
        '{"role": "_usage", "token_count": 1234}',
    ]


def _spec_wire(secret):
    """The spec's wire.jsonl sample, line for line."""
    return [
        '{"type": "metadata", "protocol_version": "1.10"}',
        '{"timestamp": 1790000000.12, "message": {"type": "TurnBegin", '
        '"payload": {"user_input": "show me the env file"}}}',
        '{"timestamp": 1790000001.5, "message": {"type": "ToolCall", '
        '"payload": {"type": "function", "id": "Shell:0", "function": '
        '{"name": "Shell", "arguments": "{\\"command\\": \\"cat .env\\"}"}, '
        '"extras": null}}}',
        '{"timestamp": 1790000001.9, "message": {"type": "ToolResult", '
        '"payload": {"tool_call_id": "Shell:0", "return_value": {"is_error": '
        'false, "output": "API_KEY=' + secret + '\\n", "message": "Command '
        'executed successfully.", "display": [], "extras": null}}}}',
    ]


WIRE_HEAD = json.dumps({"type": "metadata", "protocol_version": "1.10"})
# Release 1.24.0 wrote protocol 1.5 (wire/protocol.py).
WIRE_HEAD_124 = json.dumps({"type": "metadata", "protocol_version": "1.5"})

# The message of a Shell call that ran (tools/shell/__init__.py).
SHELL_OK = "Command executed successfully."
# ToolRejectedError messages: 1.52 with no feedback, with feedback, and for
# a subagent's call (soul/approval.py rejection_error); and 1.24's
# (tools/utils.py). The result of a rejected call has no output.
REJECTED_152 = ("The tool call is rejected by the user. Stop what you are "
                "doing and wait for the user to tell you how to proceed.")
REJECTED_FEEDBACK = ("The tool call is rejected by the user. User feedback: "
                     "move it to the trash instead")
REJECTED_SUBAGENT = (
    "The tool call is rejected by the user. Try a different approach to "
    "complete your task, or explain the limitation in your summary if no "
    "alternative is available. Do not retry the same tool call, and do not "
    "attempt to bypass this restriction through indirect means.")
REJECTED_124 = ("The tool call is rejected by the user. Please follow the "
                "new instructions from the user.")


def wire(ts, mtype, payload):
    return json.dumps({"timestamp": ts,
                       "message": {"type": mtype, "payload": payload}})


def call_payload(cid, name, args):
    return {"type": "function", "id": cid,
            "function": {"name": name, "arguments": json.dumps(args)},
            "extras": None}


def result_payload(cid, output, message=SHELL_OK, error=False, brief=""):
    """A ToolResult payload: kosong's ToolReturnValue, whose display holds
    one {"type": "brief"} block when the tool gave a brief."""
    return {"tool_call_id": cid,
            "return_value": {"is_error": error, "output": output,
                             "message": message,
                             "display": ([{"type": "brief", "text": brief}]
                                         if brief else []),
                             "extras": None}}


def wire_call(ts, cid, name, args):
    return wire(ts, "ToolCall", call_payload(cid, name, args))


def wire_result(ts, cid, output, message=SHELL_OK, error=False, brief=""):
    return wire(ts, "ToolResult",
                result_payload(cid, output, message, error, brief))


def wire_rejected(ts, cid, message=REJECTED_152, brief="Rejected by user"):
    """The result of a call the user rejected: a ToolRejectedError."""
    return wire_result(ts, cid, "", message=message, error=True, brief=brief)


def sub_event(ts, task_cid, mtype, payload):
    """A SubagentEvent as 1.24 wrote it into the main wire.jsonl
    (tools/multiagent/task.py): the Task call's id and the event."""
    return wire(ts, "SubagentEvent", {
        "task_tool_call_id": task_cid,
        "event": {"type": mtype, "payload": payload}})


def split_call(cid, name, args, cut):
    """A ToolCall the recorder flushed when only `cut` characters of its
    arguments had streamed, and the ToolCallPart that brings the rest
    (wire/__init__.py WireSoulSide): (call payload, part payload)."""
    whole = json.dumps(args)
    call = call_payload(cid, name, args)
    call["function"]["arguments"] = whole[:cut]
    return call, {"arguments_part": whole[cut:]}


def _compact(obj):
    """pydantic's model_dump_json: no spaces, non-ASCII as it is."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def ctx_call(cid, name, args, content=""):
    return _compact({"role": "assistant", "content": content, "tool_calls": [
        {"type": "function", "id": cid,
         "function": {"name": name, "arguments": json.dumps(args)}}]})


def _system(text):
    return {"type": "text", "text": "<system>%s</system>" % text}


def ctx_result(cid, output, message=SHELL_OK, error=False):
    """A tool message as soul/message.py tool_result_to_message builds it,
    written as kosong's Message serializes content: one text part as a
    plain string, more as a list of parts."""
    parts = ([_system("ERROR: " + message)] if error
             else [_system(message)] if message else [])
    if output:
        parts.append({"type": "text", "text": output})
    if not parts:
        parts = [_system("Tool output is empty.")]
    content = parts[0]["text"] if len(parts) == 1 else parts
    return _compact({"role": "tool", "content": content, "tool_call_id": cid})


def ctx_rejected(cid, message=REJECTED_152):
    return ctx_result(cid, "", message=message, error=True)


def _task_spec(command, task_id="bash-k3v9x2mq", cid="Shell:7"):
    """A background bash task's spec.json: TaskSpec (background/models.py)
    as atomic_json_write writes it, json.dump(indent=2, ensure_ascii=False)
    (utils/io.py)."""
    return json.dumps({
        "version": 1, "id": task_id, "kind": "bash", "session_id": SID,
        "description": "print the env", "tool_call_id": cid,
        "owner_role": "root", "created_at": 1790000000.5, "command": command,
        "shell_name": "bash", "shell_path": "/bin/bash", "cwd": PROJECT,
        "timeout_s": None, "kind_payload": None}, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# watch.judge and clean's origin crediting, as design 3.5 and 3.6 say
# --------------------------------------------------------------------------

def _judge(call):
    if call.kind is None or not call.known:
        return watch.evaluate(call.tool_name, call.tool_input)
    rest = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.kind == "shell" and call.command:
        judged = dict(rest, command=call.command)
        if call.workdir:
            judged["workdir"] = call.workdir
        return watch.evaluate("Bash", judged)
    if call.kind == "read" and call.paths:
        return watch.evaluate("Read", dict(rest, paths=list(call.paths)))
    return watch.evaluate("ranwhat:%s" % call.kind, call.tool_input)


def _origin(call):
    """The file a secret in this call's output came from: _origins of the
    call's input, the consumed keys replaced by the command with heredocs
    stripped. The last one wins."""
    rest = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.command:
        rest["command"] = watch._strip_heredocs(call.command)
    named = clean._origins(json.dumps(rest, ensure_ascii=False))
    return named[-1] if named else None


def _scan(src, stores):
    """{value: {"origins", "files", "count"}} over every SecretText."""
    found = {}
    for store in stores:
        for text in src.secret_texts(store):
            origin = _origin(text.call) if text.call is not None else None

            def collect(value, _label, _in=None, _copies=None, origin=origin,
                        path=store.path):
                entry = found.setdefault(value, {"origins": set(),
                                                 "files": set(), "count": 0})
                entry["files"].add(path)
                entry["count"] += 1
                if origin:
                    entry["origins"].add(origin)
            clean._walk(text.node, collect)
    return found


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _deep(depth=100000):
    """JSON objects nested `depth` deep, built as text, since json.dumps
    would need the recursion this is here to test. Python 3.9's parser
    refuses it; 3.14's accepts it, and then encoding it again does not fit."""
    return '{"a":' * depth + "1" + "}" * depth


def _parses(text):
    try:
        json.loads(text)
    except RecursionError:
        return False
    return True


# --------------------------------------------------------------------------
# A temp home and share directory
# --------------------------------------------------------------------------

class KimiCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kimi-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.root = os.path.join(self.home, ".kimi")
        self.backups = os.path.join(self.tmp, "backups")
        patches = [
            mock.patch.dict(os.environ, {"HOME": self.home,
                                         "USERPROFILE": self.home,
                                         "KIMI_SHARE_DIR": self.root}),
            mock.patch.object(_paths, "home", return_value=self.home),
            mock.patch.object(clean, "BACKUP_ROOT", self.backups),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.src = kimi.KimiSource()

    # -- files ---------------------------------------------------------------

    def write(self, rel, lines, age=3600, end="\n"):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(("\n".join(lines) + end).encode("utf-8"))
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def kimi_json(self, *paths):
        work_dirs = [{"path": PROJECT, "kaos": "local", "last_session_id": SID}]
        for path, kaos in paths:
            work_dirs.append({"path": path, "kaos": kaos,
                              "last_session_id": SID_OLD})
        return self.write("kimi.json", [json.dumps({"work_dirs": work_dirs})])

    def session(self, sid=SID, folder=None):
        return "sessions/%s/%s" % (folder or md5(PROJECT), sid)

    def spec_tree(self, secret=SECRET, age=3600):
        """The spec's fixture: kimi.json, a session folder with both
        context.jsonl and wire.jsonl, and the prompt history."""
        self.kimi_json()
        ctx = self.write(self.session() + "/context.jsonl",
                         _spec_context(secret), age=age)
        wire_path = self.write(self.session() + "/wire.jsonl",
                               _spec_wire(secret), age=age)
        hist = self.write("user-history/%s.jsonl" % md5(PROJECT),
                          ['{"content":"show me the env file"}'], age=age)
        return ctx, wire_path, hist

    def typed_tree(self, age=3600):
        """The spec tree, plus a command with a password typed into it (in
        wire.jsonl and context.jsonl), and a rotated context_1.jsonl holding
        a key nothing else holds."""
        ctx, wire_path, hist = self.spec_tree(age=age)
        typed = {"command": "export DB_PASSWORD=" + TYPED + "; ./deploy.sh"}
        with open(wire_path, "a", encoding="utf-8") as fh:
            fh.write(wire_call(1790000010.0, "Shell:1", "Shell", typed) + "\n")
            fh.write(wire_result(1790000010.5, "Shell:1", "deployed\n") + "\n")
        with open(ctx, "a", encoding="utf-8") as fh:
            fh.write(ctx_call("Shell:1", "Shell", typed) + "\n")
            fh.write(ctx_result("Shell:1", "deployed\n") + "\n")
        rotated = self.write(self.session() + "/context_1.jsonl", [
            '{"role": "_system_prompt", "content": "You are Kimi CLI ..."}',
            ctx_call("Shell:0", "Shell", {"command": "cat .env"}),
            ctx_result("Shell:0", "STRIPE_KEY=" + ROTATED_SECRET + "\n"),
        ], age=age)
        for path in (ctx, wire_path):
            when = time.time() - age
            os.utime(path, (when, when))
        return ctx, wire_path, hist, rotated

    def split_tree(self, inside=False, age=3600):
        """A session whose wire.jsonl holds a Shell call the recorder wrote
        in two pieces around a parallel call's result, with SECRET typed
        into its command: cut in two by the pieces, or (inside) whole in
        the second. context.jsonl holds the call whole. (context, wire)."""
        self.kimi_json()
        curl = {"command": "curl -H 'Authorization: Bearer %s' "
                           "https://api.example.com/v1/me" % SECRET}
        at = json.dumps(curl).index(SECRET)
        shell, rest = split_call("Shell:1", "Shell", curl,
                                 at - 3 if inside else at + 10)
        read = {"path": "/Users/me/proj/README.md"}
        wire_path = self.write(self.session() + "/wire.jsonl", [
            WIRE_HEAD,
            wire_call(1790000001.0, "ReadFile:0", "ReadFile", read),
            wire(1790000002.0, "ToolCall", shell),
            wire_result(1790000002.1, "ReadFile:0", "hello\n"),
            wire(1790000002.2, "ToolCallPart", rest),
            wire_result(1790000003.0, "Shell:1", "{}"),
        ], age=age)
        ctx = self.write(self.session() + "/context.jsonl", [
            ctx_call("ReadFile:0", "ReadFile", read),
            ctx_result("ReadFile:0", "hello\n", message=""),
            ctx_call("Shell:1", "Shell", curl), ctx_result("Shell:1", "{}"),
        ], age=age)
        return ctx, wire_path

    # -- reading -------------------------------------------------------------

    def stores(self, **kwargs):
        return self.src.stores(self.src.locations(), **kwargs)

    def store(self, path):
        [store] = [s for s in self.stores() if s.path == path]
        return store

    def calls(self, path=None):
        out = []
        for store in self.stores():
            if path is None or store.path == path:
                out.extend(self.src.tool_calls(store))
        return out


# --------------------------------------------------------------------------
# Where it looks
# --------------------------------------------------------------------------

class DefaultPaths(KimiCase):

    def test_each_platform(self):
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.kimi", "default")])
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.kimi", "default")])
        self.assertEqual(self.src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.kimi", "default")])

    def test_share_dir_variable_replaces_the_default(self):
        for platform, value in (("darwin", "/data/kimi"), ("linux", "/data/kimi"),
                                ("win32", "D:\\kimi")):
            self.assertEqual(
                self.src.default_paths({"KIMI_SHARE_DIR": value}, "/h", platform),
                [(value, "env KIMI_SHARE_DIR")])
        self.assertEqual(self.src.default_paths({"KIMI_SHARE_DIR": ""},
                                                "/home/u", "linux"),
                         [("/home/u/.kimi", "default")])

    def test_variable_is_read_at_call_time(self):
        del os.environ["KIMI_SHARE_DIR"]
        [loc] = self.src.locations()
        self.assertEqual((loc.source, loc.path, loc.how, loc.exists, loc.found),
                         ("kimi", self.root, "default", False, 0))
        moved = os.path.join(self.tmp, "moved-share")
        os.makedirs(os.path.join(moved, "sessions", md5(PROJECT), SID))
        with open(os.path.join(moved, "sessions", md5(PROJECT), SID,
                               "wire.jsonl"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(_spec_wire(SECRET)) + "\n")
        os.environ["KIMI_SHARE_DIR"] = moved        # after import and construction
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (moved, "env KIMI_SHARE_DIR", True, 1))

    def test_path_override(self):
        self.spec_tree()
        [loc] = self.src.locations(override=self.root)
        self.assertEqual((loc.how, loc.exists, loc.found), ("--path", True, 3))
        self.assertTrue(self.src.path_means)
        self.assertEqual(self.src.env, ("KIMI_SHARE_DIR",))


class Discovery(KimiCase):

    def full_tree(self):
        self.kimi_json((OTHER_PROJECT, "remote"))
        s = self.session()
        imp = "imported_sessions/%s" % SID_IMPORTED
        paths = {
            "wire": self.write(s + "/wire.jsonl", _spec_wire(SECRET), age=500),
            "context": self.write(s + "/context.jsonl", _spec_context(SECRET), age=600),
            "rotated": self.write(s + "/context_1.jsonl", _spec_context(SECRET), age=700),
            # before 1.25: a Task subagent's context, and that context
            # rotated by a compaction inside the subagent
            "task_context": self.write(s + "/context_sub_1.jsonl",
                                       _spec_context(SECRET), age=650),
            "task_rotated": self.write(s + "/context_sub_1_1.jsonl",
                                       _spec_context(SECRET), age=675),
            # what a background command printed (1.24 and 1.52 task ids)
            "task_log": self.write(s + "/tasks/bash-k3v9x2mq/output.log",
                                   ["API_KEY=" + SECRET], age=550),
            "task_log_124": self.write(s + "/tasks/b7q2w4e6r/output.log",
                                       ["ok"], age=560),
            # the command, as atomic_json_write writes it (indent=2)
            "task_spec": self.write(s + "/tasks/bash-k3v9x2mq/spec.json",
                                    [_task_spec("cat .env")], age=555, end=""),
            "sub_wire": self.write(s + "/subagents/a1/wire.jsonl",
                                   _spec_wire(SECRET), age=400),
            # a subagent's soul compacts too, rotating its context
            "sub_rotated": self.write(s + "/subagents/a1/context_1.jsonl",
                                      _spec_context(SECRET), age=425),
            # the prompt it was given, and the text and summary it wrote
            "sub_prompt": self.write(s + "/subagents/a1/prompt.txt",
                                     ["use API_KEY=" + SECRET], age=430),
            "sub_output": self.write(s + "/subagents/a1/output",
                                     ["[stage] context_ready", "[tool] Shell",
                                      "[tool_result] success", "",
                                      "[summary]", "API_KEY=" + SECRET],
                                     age=440),
            "sub_context": self.write(s + "/subagents/a2/context.jsonl",
                                      _spec_context(SECRET), age=450),
            "flat": self.write("sessions/%s/%s.jsonl" % (md5(PROJECT), SID_OLD),
                               _spec_context(SECRET), age=900),
            "kaos": self.write(self.session(SID_OLD, "remote_" + md5(OTHER_PROJECT))
                               + "/wire.jsonl", _spec_wire(SECRET), age=300),
            # an imported session is a whole session folder
            "imported": self.write(imp + "/context.jsonl",
                                   _spec_context(SECRET), age=200),
            "imported_rotated": self.write(imp + "/context_1.jsonl",
                                           _spec_context(SECRET), age=210),
            "imported_sub_wire": self.write(imp + "/subagents/a1b2c3/wire.jsonl",
                                            _spec_wire(SECRET), age=220),
            "imported_task_log": self.write(imp + "/tasks/bash-p0o9i8u7/output.log",
                                            ["API_KEY=" + SECRET], age=230),
            "history": self.write("user-history/%s.jsonl" % md5(PROJECT),
                                  ['{"content":"show me the env file"}'], age=100),
        }
        # Files the spec says are never read, beside the ones that are.
        never = [
            self.write(s + "/state.json", ['{"custom_title": "x"}']),
            self.write(s + "/subagents/a1/meta.json", ['{"name": "coder"}']),
            # read only by in_use(), before output.log is masked
            self.write(s + "/tasks/bash-k3v9x2mq/runtime.json",
                       ['{"status": "completed"}']),
            self.write(s + "/tasks/bash-k3v9x2mq/control.json",
                       ['{"kill_requested_at": null}']),
            self.write(s + "/tasks/bash-k3v9x2mq/consumer.json", ['{}']),
            # prompt.txt and output belong to a subagent's folder
            self.write(s + "/prompt.txt", ["API_KEY=" + SECRET]),
            self.write(s + "/context.tmp", _spec_context(SECRET)),
            self.write("logs/kimi.log", ["API_KEY=" + SECRET]),
            self.write(imp + "/state.json", ['{"custom_title": "x"}']),
        ]
        return paths, never

    def test_every_listed_file_its_role_session_and_project(self):
        paths, _never = self.full_tree()
        got = {s.path: (s.role, s.unit, s.session, s.project, s.format, s.masking)
               for s in self.stores()}
        T, S = "transcript", "side"
        self.assertEqual(got, {
            paths["wire"]: (T, "session", SID, PROJECT, "jsonl", "rewrite"),
            paths["context"]: (S, "file", SID, PROJECT, "jsonl", "rewrite"),
            paths["rotated"]: (S, "file", SID, PROJECT, "jsonl", "rewrite"),
            paths["task_context"]: (S, "file", SID, PROJECT, "jsonl", "rewrite"),
            paths["task_rotated"]: (S, "file", SID, PROJECT, "jsonl", "rewrite"),
            paths["task_log"]: (S, "file", SID, PROJECT, "text", "rewrite"),
            paths["task_log_124"]: (S, "file", SID, PROJECT, "text", "rewrite"),
            paths["task_spec"]: (S, "file", SID, PROJECT, "json", "rewrite"),
            paths["sub_wire"]: (T, "session", SID, PROJECT, "jsonl", "rewrite"),
            paths["sub_rotated"]: (S, "file", SID, PROJECT, "jsonl", "rewrite"),
            paths["sub_prompt"]: (S, "file", SID, PROJECT, "text", "rewrite"),
            paths["sub_output"]: (S, "file", SID, PROJECT, "text", "rewrite"),
            paths["sub_context"]: (T, "session", SID, PROJECT, "jsonl", "rewrite"),
            paths["flat"]: (T, "session", SID_OLD, PROJECT, "jsonl", "rewrite"),
            paths["kaos"]: (T, "session", SID_OLD, OTHER_PROJECT, "jsonl", "rewrite"),
            paths["imported"]: (T, "session", SID_IMPORTED, None, "jsonl", "rewrite"),
            paths["imported_rotated"]: (S, "file", SID_IMPORTED, None, "jsonl",
                                        "rewrite"),
            paths["imported_sub_wire"]: (T, "session", SID_IMPORTED, None, "jsonl",
                                         "rewrite"),
            paths["imported_task_log"]: (S, "file", SID_IMPORTED, None, "text",
                                         "rewrite"),
            paths["history"]: (S, "file", None, PROJECT, "jsonl", "rewrite"),
        })

    def test_newest_first_and_the_days_prefilter(self):
        paths, _never = self.full_tree()
        order = [s.path for s in self.stores()]
        self.assertEqual(order, [paths[k] for k in (
            "history", "imported", "imported_rotated", "imported_sub_wire",
            "imported_task_log", "kaos", "sub_wire", "sub_rotated", "sub_prompt",
            "sub_output", "sub_context", "wire", "task_log", "task_spec",
            "task_log_124", "context", "task_context", "task_rotated", "rotated",
            "flat")])
        old = self.write(self.session("11111111-2222-4333-8444-555555555555")
                         + "/wire.jsonl", _spec_wire(SECRET), age=90 * 86400)
        self.assertIn(old, [s.path for s in self.stores()])
        self.assertNotIn(old, [s.path for s in self.stores(since_days=30)])

    def test_a_missing_root_is_no_stores(self):
        self.assertEqual(self.stores(), [])
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (False, 0))
        self.assertEqual(self.src.stores(self.src.locations(
            override=os.path.join(self.tmp, "nowhere"))), [])

    def test_files_it_does_not_list_are_never_opened(self):
        paths, never = self.full_tree()
        opened = []
        real_open = builtins.open

        def spy(file, *args, **kwargs):
            if isinstance(file, str):
                opened.append(os.path.normcase(os.path.abspath(file)))
            return real_open(file, *args, **kwargs)
        with mock.patch("builtins.open", spy):
            for store in self.stores():
                list(self.src.tool_calls(store))
                list(self.src.secret_texts(store))
        for path in never:
            self.assertNotIn(os.path.normcase(path), opened)
        for path in paths.values():
            self.assertIn(os.path.normcase(path), opened)
        self.assertIn(os.path.normcase(os.path.join(self.root, "kimi.json")), opened)

    def test_kimi_json_is_a_map_not_a_store(self):
        self.spec_tree()
        self.assertNotIn(os.path.join(self.root, "kimi.json"),
                         [s.path for s in self.stores()])

    def test_a_folder_that_names_no_known_work_dir_has_no_project(self):
        self.kimi_json()
        path = self.write(self.session(SID, "f" * 32) + "/wire.jsonl",
                          _spec_wire(SECRET))
        self.assertIsNone(self.store(path).project)
        self.assertEqual([c.project for c in self.calls(path)], [None])
        # and with no kimi.json at all
        os.unlink(os.path.join(self.root, "kimi.json"))
        self.assertIsNone(self.store(path).project)


# --------------------------------------------------------------------------
# Tool calls
# --------------------------------------------------------------------------

class ToolCalls(KimiCase):

    def wire_session(self, lines, sid=SID, age=3600, head=WIRE_HEAD):
        self.kimi_json()
        return self.write(self.session(sid) + "/wire.jsonl", [head] + lines,
                          age=age)

    def test_the_spec_fixture(self):
        ctx, wire_path, hist = self.spec_tree()
        [call] = self.calls()
        self.assertEqual(call.store, wire_path)
        self.assertEqual(
            (call.source, call.tool_name, call.tool_call_id, call.kind, call.known,
             call.command, call.paths, call.consumed, call.timestamp,
             call.not_after, call.session, call.project, call.actor,
             call.status, call.workdir),
            ("kimi", "Shell", "Shell:0", "shell", True, "cat .env", (),
             frozenset(["command"]), "2026-09-21T14:13:21Z", None, SID, PROJECT,
             "agent", None, None))
        self.assertEqual(call.tool_input, {"command": "cat .env"})
        self.assertEqual(call.output, "API_KEY=" + SECRET + "\n")
        # side stores give no calls of their own
        self.assertEqual(list(self.src.tool_calls(self.store(ctx))), [])
        self.assertEqual(list(self.src.tool_calls(self.store(hist))), [])

    def test_a_dangerous_shell_call_is_flagged(self):
        self.wire_session([
            wire_call(1790000001.0, "Shell:0", "Shell",
                      {"command": "rm -rf ~/Documents/x", "timeout": 60,
                       "run_in_background": False, "description": "clean up"}),
            wire_result(1790000001.2, "Shell:0", ""),
            wire_call(1790000002.0, "Shell:1", "Shell",
                      {"command": "cat ~/.aws/credentials"}),
            wire_result(1790000002.2, "Shell:1", "[default]\n"),
        ])
        first, second = self.calls()
        hits, payload = _judge(first)
        self.assertEqual([h["rule"] for h in hits], ["fs.destructive"])
        self.assertIn("~/Documents/x", hits[0]["evidence"])
        self.assertTrue(payload)
        hits, _payload = _judge(second)
        self.assertEqual([h["rule"] for h in hits], ["cred.read"])
        self.assertIn("~/.aws/credentials", hits[0]["evidence"])
        # what configures the run stays in the judged input
        self.assertEqual(first.tool_input["timeout"], 60)

    def test_a_credential_read_by_the_read_tool_is_flagged(self):
        # ReadFile's ToolOk output is one string of numbered lines, each
        # line keeping its newline (tools/file/read.py).
        numbered = "     1\t-----BEGIN OPENSSH PRIVATE KEY-----\n"
        self.wire_session([
            wire_call(1790000001.0, "ReadFile:0", "ReadFile",
                      {"path": "/Users/me/.ssh/id_rsa", "line_offset": 1,
                       "n_lines": 200}),
            wire_result(1790000001.1, "ReadFile:0", numbered,
                        message="1 lines read from file starting from line 1."
                                " Total lines in file: 1. End of file reached."),
        ])
        [call] = self.calls()
        self.assertEqual((call.kind, call.known, call.paths, call.consumed),
                         ("read", True, ("/Users/me/.ssh/id_rsa",),
                          frozenset(["path"])))
        hits, _payload = _judge(call)
        self.assertEqual([h["rule"] for h in hits], ["cred.read"])
        self.assertIn("/Users/me/.ssh/id_rsa", hits[0]["evidence"])
        self.assertEqual(call.output, numbered)

    def test_precision_carries_over(self):
        heredoc = "cat <<'EOF' > notes.txt\nrm -rf /\nEOF"
        # StrReplaceFile's edit is one {old, new, replace_all} object or a
        # list of them (tools/file/replace.py).
        self.wire_session([
            wire_call(1790000001.0, "Shell:0", "Shell",
                      {"command": "grep -rn 'rm -rf' ."}),
            wire_call(1790000002.0, "Shell:1", "Shell", {"command": heredoc}),
            wire_call(1790000003.0, "WriteFile:2", "WriteFile",
                      {"path": "/Users/me/proj/clean.sh",
                       "content": "rm -rf /\n", "mode": "overwrite"}),
            wire_call(1790000004.0, "StrReplaceFile:3", "StrReplaceFile",
                      {"path": "/Users/me/proj/run.sh",
                       "edit": {"old": "make clean", "new": "rm -rf /",
                                "replace_all": False}}),
            wire_call(1790000005.0, "StrReplaceFile:4", "StrReplaceFile",
                      {"path": "/Users/me/proj/Makefile",
                       "edit": [{"old": "build", "new": "rm -rf /",
                                 "replace_all": True},
                                {"old": "cat .env", "new": "true",
                                 "replace_all": False}]}),
        ])
        calls = self.calls()
        self.assertEqual([(c.tool_name, c.kind, c.known) for c in calls], [
            ("Shell", "shell", True), ("Shell", "shell", True),
            ("WriteFile", "write", True), ("StrReplaceFile", "write", True),
            ("StrReplaceFile", "write", True)])
        for call in calls:
            self.assertEqual(_judge(call), ([], ""), call.tool_name)
        write, replace, replace_many = calls[2], calls[3], calls[4]
        self.assertEqual((write.paths, write.consumed),
                         (("/Users/me/proj/clean.sh",), frozenset()))
        self.assertEqual(replace.paths, ("/Users/me/proj/run.sh",))
        self.assertEqual(replace_many.paths, ("/Users/me/proj/Makefile",))
        self.assertEqual(replace_many.tool_input["edit"][0]["new"], "rm -rf /")
        self.assertEqual(calls[1].command, heredoc)

    def test_names_it_does_not_know_are_judged_by_name(self):
        """Web, search and agent tools are unverified in the spec, so no
        fetch kind is set: they are "other", known False."""
        self.wire_session([
            wire_call(1790000001.0, "FetchURL:0", "FetchURL",
                      {"url": "https://example.com/docs"}),
            wire_result(1790000001.5, "FetchURL:0", "page text"),
            wire_call(1790000002.0, "Glob:1", "Glob", {"pattern": "**/*.py"}),
            wire_call(1790000003.0, "x:2", "mcp__ops__bash",
                      {"command": "rm -rf ~/Documents/x"}),
            wire_call(1790000004.0, "shell:3", "shell", {"command": "ls"}),
        ])
        fetch, glob_call, mcp, lower = self.calls()
        for call in (fetch, glob_call, mcp, lower):
            self.assertEqual((call.kind, call.known, call.command, call.paths),
                             ("other", False, None, ()), call.tool_name)
        self.assertEqual(fetch.output, "page text")
        self.assertEqual(_judge(fetch), ([], ""))
        self.assertEqual([h["rule"] for h in _judge(mcp)[0]], ["fs.destructive"])

    def test_output_as_a_list_of_parts(self):
        # ReadMediaFile wraps an image in text tags (utils/media_tags.py).
        self.wire_session([
            wire_call(1790000001.0, "ReadMediaFile:0", "ReadMediaFile",
                      {"path": "/Users/me/proj/shot.png"}),
            wire_result(1790000001.5, "ReadMediaFile:0", [
                {"type": "text", "text": '<image path="/Users/me/proj/shot.png">'},
                {"type": "image_url", "image_url": {
                    "url": "data:image/png;base64,iVBORw0KGgo=", "id": None}},
                {"type": "text", "text": "</image>"}],
                message="Loaded image file `/Users/me/proj/shot.png` "
                        "(image/png, 8 bytes)."),
        ])
        [call] = self.calls()
        self.assertEqual((call.kind, call.known), ("other", False))
        self.assertEqual(call.output,
                         '<image path="/Users/me/proj/shot.png"></image>')

    def test_a_rejected_approval_is_declined(self):
        """Before 1.25 (and in wire mode after it), the approval records are
        in wire.jsonl, and the rejected call's result is a ToolRejectedError.
        1.24 wrote no feedback in an ApprovalResponse."""
        approval = {"sender": "Shell", "action": "run shell command",
                    "description": "rm -rf build"}
        self.wire_session([
            wire_call(1790000001.0, "Shell:0", "Shell", {"command": "rm -rf build"}),
            wire(1790000001.1, "ApprovalRequest",
                 dict(approval, id="req-0", tool_call_id="Shell:0")),
            wire(1790000003.0, "ApprovalResponse",
                 {"request_id": "req-0", "response": "reject"}),
            wire_rejected(1790000003.1, "Shell:0", REJECTED_124),
            wire_call(1790000004.0, "Shell:1", "Shell", {"command": "ls build"}),
            wire(1790000004.1, "ApprovalRequest",
                 dict(approval, id="req-1", tool_call_id="Shell:1")),
            wire(1790000004.5, "ApprovalResponse",
                 {"request_id": "req-1", "response": "approve_for_session"}),
            wire_result(1790000004.6, "Shell:1", "x\n"),
            # the call's result never came: the approval alone tells
            wire_call(1790000005.0, "Shell:2", "Shell", {"command": "rm -rf dist"}),
            wire(1790000005.1, "ApprovalRequest",
                 dict(approval, id="req-2", tool_call_id="Shell:2")),
            wire(1790000005.5, "ApprovalRequestResolved",        # legacy name
                 {"request_id": "req-2", "response": "reject"}),
            wire_call(1790000006.0, "Shell:3", "Shell", {"command": "pwd"}),
            wire(1790000006.1, "ApprovalRequest",
                 dict(approval, id="req-3", tool_call_id="Shell:3")),
            wire(1790000006.5, "ApprovalResponse",
                 {"request_id": "req-3", "response": "approve"}),
        ], head=WIRE_HEAD_124)
        calls = self.calls()
        got = {c.tool_call_id: c.status for c in calls}
        self.assertEqual(got, {"Shell:0": "declined", "Shell:1": None,
                               "Shell:2": "declined", "Shell:3": None})
        self.assertEqual(calls[0].output, "")

    def test_a_rejected_call_with_no_approval_records_is_declined(self):
        """From 1.25 the interactive shell keeps approvals off wire.jsonl:
        only the ToolRejectedError result says the call never ran. A
        command that ran and failed is an error too, but not declined."""
        self.wire_session([
            wire_call(1790000001.0, "Shell:0", "Shell",
                      {"command": "rm -rf ~/Documents/x"}),
            wire_rejected(1790000003.0, "Shell:0"),
            wire_call(1790000004.0, "Shell:1", "Shell", {"command": "rm -rf dist"}),
            wire_rejected(1790000005.0, "Shell:1", REJECTED_FEEDBACK,
                          brief="Rejected: move it to the trash instead"),
            wire_call(1790000006.0, "WriteFile:2", "WriteFile",
                      {"path": "/Users/me/proj/a.txt", "content": "x",
                       "mode": "overwrite"}),
            wire_rejected(1790000006.5, "WriteFile:2", REJECTED_124),
            wire_call(1790000007.0, "Shell:3", "Shell", {"command": "false"}),
            wire_result(1790000007.5, "Shell:3", "",
                        message="Command failed with exit code: 1.", error=True,
                        brief="Failed with exit code: 1"),
            wire_call(1790000008.0, "Shell:4", "Shell", {"command": "ls"}),
            wire_result(1790000008.5, "Shell:4", "a.txt\n"),
            # an error whose message only quotes the words is not one
            wire_call(1790000009.0, "Shell:5", "Shell", {"command": "ls"}),
            wire_result(1790000009.5, "Shell:5", "",
                        message="Command failed: The tool call is rejected by "
                                "the user.", error=True, brief="Failed"),
            # nor is a result that ran, whatever its message
            wire_call(1790000010.0, "Shell:6", "Shell", {"command": "ls"}),
            wire_result(1790000010.5, "Shell:6", "", message=REJECTED_152),
        ])
        calls = self.calls()
        self.assertEqual({c.tool_call_id: c.status for c in calls}, {
            "Shell:0": "declined", "Shell:1": "declined",
            "WriteFile:2": "declined", "Shell:3": None, "Shell:4": None,
            "Shell:5": None, "Shell:6": None})
        # still flagged: render says it did not run
        self.assertEqual([h["rule"] for h in _judge(calls[0])[0]],
                         ["fs.destructive"])

    def test_a_rejection_in_a_context_transcript_is_declined(self):
        """With no wire.jsonl, context.jsonl tells it: the tool message's
        first part is "<system>ERROR: The tool call is rejected...". A
        rejection has no output, so that part is the whole content, written
        as a plain string."""
        self.kimi_json()
        ctx = self.write(self.session() + "/context.jsonl", [
            '{"role": "_system_prompt", "content": "You are Kimi CLI ..."}',
            ctx_call("Shell:0", "Shell", {"command": "rm -rf ~/Documents/x"}),
            ctx_rejected("Shell:0"),
            ctx_call("Shell:1", "Shell", {"command": "rm -rf dist"}),
            ctx_rejected("Shell:1", REJECTED_SUBAGENT),
            ctx_call("Shell:2", "Shell", {"command": "false"}),
            ctx_result("Shell:2", "boom\n", "Command failed with exit code: 1.",
                       error=True),
            ctx_call("Shell:3", "Shell", {"command": "true"}),
            ctx_result("Shell:3", ""),
        ])
        with open(ctx, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        self.assertIn('"content":"<system>ERROR: The tool call is rejected by the '
                      'user. Stop what you are doing', lines[2])
        self.assertIn('"content":[{"type":"text","text":"<system>ERROR: Command '
                      'failed', lines[6])
        calls = self.calls(ctx)
        self.assertEqual({c.tool_call_id: (c.status, c.output) for c in calls}, {
            "Shell:0": ("declined", ""), "Shell:1": ("declined", ""),
            "Shell:2": (None, "boom\n"), "Shell:3": (None, "")})

    def test_a_subagent_approval_does_not_decline_a_main_call(self):
        """In wire mode (1.25 on) a subagent's approval reaches the main
        wire.jsonl with its agent_id and the subagent's own call id; that
        call is read from the subagent's wire.jsonl."""
        self.wire_session([
            wire_call(1790000001.0, "Shell:0", "Shell", {"command": "ls"}),
            wire_call(1790000001.1, "Agent:1", "Agent",
                      {"description": "tidy", "prompt": "tidy up"}),
            wire(1790000002.0, "ApprovalRequest", {
                "id": "req-0", "tool_call_id": "Shell:0", "sender": "Shell",
                "action": "run shell command", "description": "rm -rf build",
                "source_kind": "foreground_turn", "agent_id": "a1b2c3",
                "subagent_type": "coder"}),
            wire(1790000003.0, "ApprovalResponse",
                 {"request_id": "req-0", "response": "reject", "feedback": ""}),
            wire_result(1790000003.5, "Shell:0", "a.txt\n"),
        ])
        got = {c.tool_call_id: c.status for c in self.calls()}
        self.assertEqual(got, {"Shell:0": None, "Agent:1": None})

    def test_a_pre_125_task_subagent_is_read_from_its_subagent_events(self):
        """Before 1.25 a Task subagent had no wire file: its calls are
        SubagentEvent records in the main wire.jsonl, its ids count from 0
        again, and its approval requests reached the main wire as they were
        (tools/multiagent/task.py). Its context_sub_<N>.jsonl holds copies."""
        task = {"description": "tidy up", "subagent_name": "coder",
                "prompt": "remove the old docs"}
        approval = {"sender": "Shell", "action": "run shell command",
                    "description": "rm -rf build"}
        path = self.wire_session([
            wire_call(1790000001.0, "Shell:0", "Shell", {"command": "ls"}),
            wire_result(1790000001.5, "Shell:0", "a.txt\n"),
            wire_call(1790000002.0, "Task:1", "Task", task),
            sub_event(1790000003.0, "Task:1", "ToolCall", call_payload(
                "Shell:0", "Shell", {"command": "rm -rf ~/Documents/x"})),
            sub_event(1790000003.5, "Task:1", "ToolResult",
                      result_payload("Shell:0", "")),
            sub_event(1790000004.0, "Task:1", "ToolCall", call_payload(
                "Shell:1", "Shell", {"command": "rm -rf build"})),
            wire(1790000004.1, "ApprovalRequest",
                 dict(approval, id="req-0", tool_call_id="Shell:1")),
            wire(1790000004.5, "ApprovalResponse",
                 {"request_id": "req-0", "response": "reject"}),
            sub_event(1790000004.6, "Task:1", "ToolResult", result_payload(
                "Shell:1", "", REJECTED_124, error=True, brief="Rejected by user")),
            wire_result(1790000009.0, "Task:1", "Removed the old docs.", message=""),
        ], head=WIRE_HEAD_124)
        self.write(self.session() + "/context_sub_1.jsonl", [
            '{"role": "_system_prompt", "content": "You are now running as a subagent."}',
            ctx_call("Shell:0", "Shell", {"command": "rm -rf ~/Documents/x"}),
            ctx_result("Shell:0", ""),
            ctx_call("Shell:1", "Shell", {"command": "rm -rf build"}),
            ctx_rejected("Shell:1", REJECTED_124),
        ])
        calls = self.calls()
        self.assertEqual(sorted((c.tool_call_id, c.command, c.status, c.timestamp)
                                for c in calls), [
            ("Shell:0", "ls", None, "2026-09-21T14:13:21Z"),
            ("Shell:0", "rm -rf ~/Documents/x", None, "2026-09-21T14:13:23Z"),
            ("Shell:1", "rm -rf build", "declined", "2026-09-21T14:13:24Z"),
            ("Task:1", None, None, "2026-09-21T14:13:22Z")])
        # the copies in context_sub_1.jsonl are not calls of their own
        self.assertEqual({c.store for c in calls}, {path})
        [sub] = [c for c in calls if c.command == "rm -rf ~/Documents/x"]
        self.assertEqual((sub.session, sub.project, sub.output), (SID, PROJECT, ""))
        self.assertEqual([h["rule"] for h in _judge(sub)[0]], ["fs.destructive"])

    def test_a_subagent_event_from_125_on_is_a_copy(self):
        """From 1.25 a SubagentEvent carries agent_id and copies the
        subagent's own wire.jsonl, which is read for itself."""
        self.kimi_json()
        event = {"type": "ToolCall", "payload": call_payload(
            "Shell:0", "Shell", {"command": "make test"})}
        main = self.wire_session([
            wire_call(1790000001.0, "Agent:0", "Agent",
                      {"description": "test", "prompt": "run the tests"}),
            wire(1790000002.0, "SubagentEvent", {
                "parent_tool_call_id": "Agent:0", "agent_id": "a1b2c3",
                "subagent_type": "coder", "event": event}),
        ])
        sub = self.write(self.session() + "/subagents/a1b2c3/wire.jsonl", [
            WIRE_HEAD, wire_call(1790000002.0, "Shell:0", "Shell",
                                 {"command": "make test"})], age=60)
        self.assertEqual([(c.store, c.tool_name) for c in self.calls()],
                         [(sub, "Shell"), (main, "Agent")])

    def test_a_session_from_before_059_resumed_later_keeps_its_older_calls(self):
        """Kimi moves a pre-0.59 <id>.jsonl to <id>/context.jsonl and starts
        wire.jsonl only when the session is resumed (session.py). The calls
        from before are in the context files alone: here a /clear after the
        resume rotated them to context_1.jsonl. They are read, undated; the
        calls in both are read once, from wire.jsonl."""
        self.kimi_json()
        folder = self.session(SID_OLD)
        rotated = self.write(folder + "/context_1.jsonl", [
            '{"role": "_checkpoint", "id": 0}',
            ctx_call("Bash:0", "Bash", {"command": "rm -rf ~/Documents/old"}),
            ctx_result("Bash:0", ""),
            ctx_call("Bash:1", "Bash", {"command": "cat ~/.aws/credentials"}),
            ctx_result("Bash:1", "[default]\n"),
            ctx_call("Shell:2", "Shell", {"command": "ls"}),        # resumed
            ctx_result("Shell:2", "a.txt\n"),
        ], age=600)
        ctx = self.write(folder + "/context.jsonl", [
            '{"role": "_checkpoint", "id": 0}',
            ctx_call("Shell:3", "Shell", {"command": "pwd"}),
            ctx_result("Shell:3", "/Users/me/proj\n"),
        ], age=60)
        wire_path = self.write(folder + "/wire.jsonl", [
            WIRE_HEAD,
            wire_call(1790000001.0, "Shell:2", "Shell", {"command": "ls"}),
            wire_result(1790000001.5, "Shell:2", "a.txt\n"),
            wire_call(1790000002.0, "Shell:3", "Shell", {"command": "pwd"}),
            wire_result(1790000002.5, "Shell:3", "/Users/me/proj\n"),
        ], age=60)
        self.assertEqual(self.store(ctx).role, "side")
        calls = self.calls()
        undated = _stamps.iso_utc(os.stat(rotated).st_mtime, "s")
        self.assertEqual([(c.store, c.command, c.timestamp, c.not_after, c.output)
                          for c in calls], [
            (wire_path, "ls", "2026-09-21T14:13:21Z", None, "a.txt\n"),
            (wire_path, "pwd", "2026-09-21T14:13:22Z", None, "/Users/me/proj\n"),
            (rotated, "rm -rf ~/Documents/old", None, undated, ""),
            (rotated, "cat ~/.aws/credentials", None, undated, "[default]\n")])
        self.assertEqual({(c.session, c.project) for c in calls}, {(SID_OLD, PROJECT)})
        self.assertEqual([[h["rule"] for h in _judge(c)[0]] for c in calls[2:]],
                         [["fs.destructive"], ["cred.read"]])
        # and with no /clear, the older calls are in context.jsonl itself
        os.unlink(rotated)
        self.write(folder + "/context.jsonl", [
            ctx_call("Bash:0", "Bash", {"command": "rm -rf ~/Documents/old"}),
            ctx_result("Bash:0", ""),
            ctx_call("Shell:2", "Shell", {"command": "ls"}),
            ctx_result("Shell:2", "a.txt\n"),
            ctx_call("Shell:3", "Shell", {"command": "pwd"}),
            ctx_result("Shell:3", "/Users/me/proj\n"),
        ], age=60)
        self.assertEqual([(c.store, c.command) for c in self.calls()], [
            (wire_path, "ls"), (wire_path, "pwd"), (ctx, "rm -rf ~/Documents/old")])

    def test_the_tools_before_057(self):
        """Up to 0.56 the shell tool was Bash, or CMD on Windows, {command,
        timeout}, and PatchFile {path, diff} edited files; 0.57 renamed Bash
        and CMD to Shell and removed PatchFile."""
        self.kimi_json()
        diff = "--- a/run.sh\n+++ b/run.sh\n@@ -1 +1 @@\n-make clean\n+rm -rf /\n"
        path = self.write("sessions/%s/%s.jsonl" % (md5(PROJECT), SID_OLD), [
            ctx_call("Bash:0", "Bash", {"command": "cat ~/.aws/credentials",
                                        "timeout": 60}),
            ctx_result("Bash:0", "[default]\n"),
            ctx_call("CMD:1", "CMD", {"command": "type .env", "timeout": 60}),
            ctx_result("CMD:1", "DEBUG=1\n"),
            ctx_call("PatchFile:2", "PatchFile",
                     {"path": "/Users/me/proj/run.sh", "diff": diff}),
        ])
        bash, cmd, patch = self.calls(path)
        self.assertEqual(
            [(c.tool_name, c.kind, c.known, c.command, c.paths, c.consumed)
             for c in (bash, cmd, patch)], [
                ("Bash", "shell", True, "cat ~/.aws/credentials", (),
                 frozenset(["command"])),
                ("CMD", "shell", True, "type .env", (), frozenset(["command"])),
                ("PatchFile", "write", True, None, ("/Users/me/proj/run.sh",),
                 frozenset())])
        self.assertEqual([h["rule"] for h in _judge(bash)[0]], ["cred.read"])
        # judged as the shell command it is, not by a name watch does not know
        self.assertEqual([h["rule"] for h in _judge(cmd)[0]], ["cred.read"])
        self.assertEqual(watch.evaluate("CMD", cmd.tool_input)[0], [])
        # a patch's content is not an action
        self.assertEqual(_judge(patch), ([], ""))
        self.assertEqual(bash.tool_input["timeout"], 60)

    def test_a_call_again_with_an_old_id_and_arguments_is_a_new_call(self):
        """The recorder writes each call once, and Kimi's ids count within a
        conversation, so after /clear the same call can come back as
        "Shell:0" with the same arguments: here rejected, then asked for
        again and run. Each is a call of its own, with its own time and
        result; their copies in the rotated and the new context.jsonl are
        copies."""
        rm = {"command": "rm -rf ~/projects/app"}
        path = self.wire_session([
            wire(1790000000.0, "TurnBegin", {"user_input": "delete the app"}),
            wire_call(1790000001.0, "Shell:0", "Shell", rm),
            wire_rejected(1790000005.0, "Shell:0"),
            wire(1790000060.0, "TurnBegin", {"user_input": "/clear"}),
            wire(1790000120.0, "TurnBegin", {"user_input": "ok, delete it"}),
            wire_call(1790000121.0, "Shell:0", "Shell", rm),
            wire_result(1790000125.0, "Shell:0", ""),
            wire_call(1790000130.0, "Shell:1", "Shell", {"command": "ls -la"}),
            wire_result(1790000131.0, "Shell:1", "total 0\n"),
        ])
        self.write(self.session() + "/context_1.jsonl", [
            ctx_call("Shell:0", "Shell", rm), ctx_rejected("Shell:0")])
        self.write(self.session() + "/context.jsonl", [
            ctx_call("Shell:0", "Shell", rm), ctx_result("Shell:0", ""),
            ctx_call("Shell:1", "Shell", {"command": "ls -la"}),
            ctx_result("Shell:1", "total 0\n")])
        calls = self.calls()
        self.assertEqual([(c.store, c.tool_call_id, c.command, c.status,
                           c.output, c.timestamp) for c in calls], [
            (path, "Shell:0", "rm -rf ~/projects/app", "declined", "",
             "2026-09-21T14:13:21Z"),
            (path, "Shell:0", "rm -rf ~/projects/app", None, "",
             "2026-09-21T14:15:21Z"),
            (path, "Shell:1", "ls -la", None, "total 0\n",
             "2026-09-21T14:15:30Z")])

    def test_a_call_whose_arguments_came_in_pieces_is_read_whole(self):
        """The recorder merges a ToolCall with the ToolCallPart records
        streamed after it, but any other record flushes it first
        (wire/__init__.py WireSoulSide): a parallel call's result, a
        subagent's event, a status update. The call is then written with
        only the start of its arguments, often none, and the rest follows.
        The pieces are one call, read whole with its own time, and the
        copy context.jsonl holds is that call."""
        rm = {"command": "rm -rf ~/projects/app"}
        agent = {"description": "tidy", "prompt": "remove the old build"}
        shell, shell_rest = split_call("Shell:1", "Shell", rm, 15)
        task, task_rest = split_call("Agent:2", "Agent", agent, 0)
        middle = len(task_rest["arguments_part"]) // 2
        sub_call, sub_rest = split_call("Shell:0", "Shell", {"command": "pwd"}, 5)
        copy = {"parent_tool_call_id": "Agent:2", "agent_id": "a1b2c3",
                "subagent_type": "coder"}
        path = self.wire_session([
            wire_call(1790000001.0, "ReadFile:0", "ReadFile",
                      {"path": "/Users/me/proj/README.md"}),
            wire(1790000002.0, "ToolCall", shell),
            wire_result(1790000002.1, "ReadFile:0", "hello\n"),
            wire(1790000002.2, "ToolCallPart", shell_rest),
            wire_result(1790000003.0, "Shell:1", ""),
            wire(1790000004.0, "ToolCall", task),
            # from 1.25 a copy of the subagent's own wire.jsonl, pieces too
            wire(1790000004.1, "SubagentEvent", dict(copy, event={
                "type": "ToolCall", "payload": sub_call})),
            wire(1790000004.2, "SubagentEvent", dict(copy, event={
                "type": "ToolCallPart", "payload": sub_rest})),
            wire(1790000004.3, "ToolCallPart",
                 {"arguments_part": task_rest["arguments_part"][:middle]}),
            wire(1790000004.4, "StatusUpdate", {"context_usage": 0.2}),
            wire(1790000004.5, "ToolCallPart",
                 {"arguments_part": task_rest["arguments_part"][middle:]}),
            wire_result(1790000009.0, "Agent:2", "Removed it.", message=""),
        ])
        self.write(self.session() + "/context.jsonl", [
            ctx_call("ReadFile:0", "ReadFile", {"path": "/Users/me/proj/README.md"}),
            ctx_result("ReadFile:0", "hello\n", message=""),
            ctx_call("Shell:1", "Shell", rm), ctx_result("Shell:1", ""),
            ctx_call("Agent:2", "Agent", agent),
            ctx_result("Agent:2", "Removed it.", message=""),
        ])
        calls = self.calls()
        self.assertEqual([(c.store, c.tool_call_id, c.tool_input, c.timestamp,
                           c.output) for c in calls], [
            (path, "ReadFile:0", {"path": "/Users/me/proj/README.md"},
             "2026-09-21T14:13:21Z", "hello\n"),
            (path, "Shell:1", rm, "2026-09-21T14:13:22Z", ""),
            (path, "Agent:2", agent, "2026-09-21T14:13:24Z", "Removed it.")])
        self.assertEqual(calls[1].command, "rm -rf ~/projects/app")
        self.assertEqual([h["rule"] for h in _judge(calls[1])[0]],
                         ["fs.destructive"])

    def test_a_piece_goes_to_the_latest_call_of_its_own_agent(self):
        """Before 1.25 a Task subagent's records reached the main wire.jsonl
        wrapped in SubagentEvent, a piece of its call too, while the main
        agent could still be streaming a call of its own."""
        sub_call, sub_rest = split_call("Shell:0", "Shell",
                                        {"command": "rm -rf ~/Documents/x"}, 10)
        main_call, main_rest = split_call("Shell:2", "Shell",
                                          {"command": "cat ~/.aws/credentials"}, 14)
        task = {"description": "tidy up", "subagent_name": "coder",
                "prompt": "remove the old docs"}
        path = self.wire_session([
            wire_call(1790000001.0, "Task:1", "Task", task),
            sub_event(1790000002.0, "Task:1", "ToolCall", sub_call),
            wire(1790000002.5, "ToolCall", main_call),
            sub_event(1790000003.0, "Task:1", "ToolCallPart", sub_rest),
            wire(1790000003.5, "ToolCallPart", main_rest),
            sub_event(1790000004.0, "Task:1", "ToolResult",
                      result_payload("Shell:0", "")),
            wire_result(1790000005.0, "Shell:2", "[default]\n"),
            wire_result(1790000009.0, "Task:1", "Removed the old docs.", message=""),
        ], head=WIRE_HEAD_124)
        self.write(self.session() + "/context_sub_1.jsonl", [
            ctx_call("Shell:0", "Shell", {"command": "rm -rf ~/Documents/x"}),
            ctx_result("Shell:0", "")])
        calls = self.calls()
        self.assertEqual(sorted((c.tool_call_id, c.command, c.timestamp)
                                for c in calls), [
            ("Shell:0", "rm -rf ~/Documents/x", "2026-09-21T14:13:22Z"),
            ("Shell:2", "cat ~/.aws/credentials", "2026-09-21T14:13:22Z"),
            ("Task:1", None, "2026-09-21T14:13:21Z")])
        self.assertEqual({c.store for c in calls}, {path})

    def test_a_folder_with_both_files_reads_calls_from_wire_only(self):
        ctx, wire_path, _hist = self.spec_tree()
        calls = self.calls()
        self.assertEqual([c.store for c in calls], [wire_path])
        self.assertEqual(self.store(ctx).role, "side")
        # without wire.jsonl, context.jsonl is the transcript
        os.unlink(wire_path)
        [call] = self.calls()
        self.assertEqual((call.store, call.tool_call_id, call.command, call.output,
                          call.timestamp), (ctx, "Shell:0", "cat .env",
                                            "API_KEY=" + SECRET + "\n", None))
        self.assertEqual(self.store(ctx).role, "transcript")

    def test_a_pre_059_flat_file_is_read_undated(self):
        self.kimi_json()
        path = self.write("sessions/%s/%s.jsonl" % (md5(PROJECT), SID_OLD),
                          _spec_context(SECRET), age=7200)
        [call] = self.calls()
        mtime = os.stat(path).st_mtime
        self.assertEqual(
            (call.store, call.session, call.project, call.timestamp, call.not_after,
             call.command, call.kind),
            (path, SID_OLD, PROJECT, None, _stamps.iso_utc(mtime, "s"), "cat .env",
             "shell"))
        self.assertEqual(call.output, "API_KEY=" + SECRET + "\n")

    def test_a_kaos_folder_maps_to_its_project(self):
        self.kimi_json((OTHER_PROJECT, "sshkaos"))
        path = self.write(self.session(SID_OLD, "sshkaos_" + md5(OTHER_PROJECT))
                          + "/wire.jsonl", _spec_wire(SECRET))
        [call] = self.calls(path)
        self.assertEqual((call.project, call.session), (OTHER_PROJECT, SID_OLD))

    def test_subagents_and_imported_sessions(self):
        self.kimi_json()
        sub = self.write(self.session() + "/subagents/coder-1/wire.jsonl",
                         [WIRE_HEAD, wire_call(1790000005.0, "Shell:0", "Shell",
                                               {"command": "make test"})])
        imported = self.write("imported_sessions/%s/wire.jsonl" % SID_IMPORTED,
                              _spec_wire(SECRET))
        [sub_call] = self.calls(sub)
        self.assertEqual((sub_call.session, sub_call.project, sub_call.command,
                          sub_call.output), (SID, PROJECT, "make test", None))
        [imp_call] = self.calls(imported)
        self.assertEqual((imp_call.session, imp_call.project, imp_call.timestamp),
                         (SID_IMPORTED, None, "2026-09-21T14:13:21Z"))
        # an imported session holds its subagents too
        imp_sub = self.write(
            "imported_sessions/%s/subagents/a9/wire.jsonl" % SID_IMPORTED,
            [WIRE_HEAD, wire_call(1790000006.0, "Shell:0", "Shell",
                                  {"command": "cat ~/.aws/credentials"})])
        [imp_sub_call] = self.calls(imp_sub)
        self.assertEqual((imp_sub_call.session, imp_sub_call.command),
                         (SID_IMPORTED, "cat ~/.aws/credentials"))
        self.assertEqual([h["rule"] for h in _judge(imp_sub_call)[0]],
                         ["cred.read"])

    def test_the_window(self):
        """An old call in a store written today keeps its own old time, so
        --days drops it by that time; a call with no time is undated, no
        later than its file's last write."""
        old = wire_call(1600000000.0, "Shell:0", "Shell", {"command": "ls"})
        path = self.wire_session([old], age=60)
        self.assertIn(path, [s.path for s in self.stores(since_days=30)])
        [call] = self.calls(path)
        self.assertEqual(call.timestamp, "2020-09-13T12:26:40Z")
        self.assertIsNone(call.not_after)
        ctx = self.write("imported_sessions/%s/context.jsonl" % SID_IMPORTED,
                         [ctx_call("Shell:0", "Shell", {"command": "ls"})], age=60)
        [undated] = self.calls(ctx)
        self.assertIsNone(undated.timestamp)
        self.assertEqual(undated.not_after,
                         _stamps.iso_utc(os.stat(ctx).st_mtime, "s"))
        # a wire record with no time of its own (the writer always gives one)
        timeless = json.loads(old)
        del timeless["timestamp"]
        bare = self.write(self.session(SID_OLD) + "/wire.jsonl",
                          [WIRE_HEAD, json.dumps(timeless)], age=60)
        [call] = self.calls(bare)
        self.assertEqual((call.timestamp, call.not_after),
                         (None, _stamps.iso_utc(os.stat(bare).st_mtime, "s")))

    def test_shell_input_that_does_not_parse(self):
        self.kimi_json()
        path = self.write(self.session() + "/wire.jsonl", [WIRE_HEAD, wire(
            1790000001.0, "ToolCall", {"type": "function", "id": "Shell:0",
                                       "function": {"name": "Shell",
                                                    "arguments": "{\"comm"}})])
        [call] = self.calls(path)
        self.assertEqual((call.kind, call.known, call.command, call.tool_input),
                         ("shell", True, None, {"_raw": "{\"comm"}))
        self.assertEqual(_judge(call), ([], ""))


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(KimiCase):

    def test_a_key_read_from_env_has_its_origin_and_a_typed_one_has_none(self):
        ctx, wire_path, _hist, rotated = self.typed_tree()
        found = _scan(self.src, self.stores())
        self.assertEqual(set(found), {SECRET, TYPED, ROTATED_SECRET})
        self.assertEqual(found[SECRET]["origins"], {".env"})
        self.assertEqual(found[SECRET]["files"], {ctx, wire_path})
        self.assertEqual(found[TYPED]["origins"], set())
        self.assertEqual(found[TYPED]["files"], {ctx, wire_path})

    def test_a_key_only_in_a_rotated_context_is_found(self):
        _ctx, _wire, _hist, rotated = self.typed_tree()
        found = _scan(self.src, self.stores())
        self.assertEqual(found[ROTATED_SECRET]["files"], {rotated})
        self.assertEqual(found[ROTATED_SECRET]["origins"], {".env"})

    def test_results_carry_their_call_and_calls_carry_none(self):
        _ctx, wire_path, _hist = self.spec_tree()
        texts = list(self.src.secret_texts(self.store(wire_path)))
        self.assertEqual([t.where for t in texts],
                         ["line 1", "line 2", "line 3", "line 4"])
        self.assertEqual([t.call.tool_call_id if t.call else None for t in texts],
                         [None, None, None, "Shell:0"])
        self.assertEqual(texts[3].call.command, "cat .env")
        # the call's arguments are decoded for clean; the record is not changed
        args = texts[2].node["message"]["payload"]["function"]["arguments"]
        self.assertEqual(args, {"command": "cat .env"})

    def test_a_value_cut_in_two_by_the_pieces_of_a_call_is_found(self):
        """Neither piece of a call the recorder wrote in two holds the whole
        value, so the call is given whole, at its result, in place of the
        lines its pieces came in, with no call of its own (what was typed
        has no origin)."""
        ctx, wire_path = self.split_tree()
        texts = list(self.src.secret_texts(self.store(wire_path)))
        self.assertEqual([t.where for t in texts],
                         ["line 1", "line 2", "line 4", "lines 3-5", "line 6"])
        self.assertIsNone(texts[3].call)
        self.assertEqual(texts[4].call.command,
                         "curl -H 'Authorization: Bearer %s' "
                         "https://api.example.com/v1/me" % SECRET)
        self.assertIn(SECRET, texts[3].node["function"]["arguments"]["command"])
        found = _scan(self.src, self.stores())
        self.assertEqual(found[SECRET]["files"], {ctx, wire_path})
        self.assertEqual(found[SECRET]["origins"], set())

    def test_the_pieces_of_a_call_are_searched_only_whole(self):
        """A value inside one piece is found there once, and the start of a
        value cut in two is not a secret of its own."""
        _ctx, wire_path = self.split_tree(inside=True)
        found = _scan(self.src, [self.store(wire_path)])
        self.assertEqual(found[SECRET]["count"], 1)
        key = "sk-" "proj-" "Zq8vR2mT6yLp4WcN0sXe7HbJ" "Pp3kW9dQ2nVb7XcR"
        command = {"command": "export OPENAI_API_KEY=%s && ./run.sh" % key}
        shell, rest = split_call("Shell:0", "Shell", command,
                                 json.dumps(command).index(key) + 25)
        wire_path = self.write(self.session(SID_OLD) + "/wire.jsonl", [
            WIRE_HEAD,
            wire(1790000001.0, "ToolCall", shell),
            wire(1790000001.1, "StatusUpdate", {"context_usage": 0.1}),
            wire(1790000001.2, "ToolCallPart", rest),
            wire_result(1790000002.0, "Shell:0", ""),
        ])
        found = _scan(self.src, [self.store(wire_path)])
        self.assertEqual({value: f["count"] for value, f in found.items()},
                         {key: 1})

    def test_system_prompt_and_prompt_history_are_searched(self):
        self.kimi_json()
        ctx = self.write(self.session() + "/context.jsonl", [
            json.dumps({"role": "_system_prompt",
                        "content": "AGENTS.md says: STRIPE_KEY=" + SECRET})])
        hist = self.write("user-history/%s.jsonl" % md5(PROJECT), [
            _compact({"content": "use the key " + ROTATED_SECRET})])
        found = _scan(self.src, self.stores())
        self.assertEqual(found[SECRET]["files"], {ctx})
        self.assertEqual(found[ROTATED_SECRET]["files"], {hist})
        self.assertEqual(found[ROTATED_SECRET]["origins"], set())

    def test_a_background_commands_output_is_searched_with_its_origin(self):
        """A Shell call run in the background gets back only that the task
        started. What the command printed is in tasks/<id>/output.log, and
        the command in spec.json beside it (background/store.py, worker.py)."""
        self.kimi_json()
        s = self.session()
        log = self.write(s + "/tasks/bash-k3v9x2mq/output.log",
                         ["STRIPE_KEY=" + SECRET])
        spec = self.write(s + "/tasks/bash-k3v9x2mq/spec.json",
                          [_task_spec("cat .env")], end="")
        self.write(s + "/tasks/bash-a8s7d6f5/output.log", ["listening on :3000"])
        typed = self.write(s + "/tasks/bash-a8s7d6f5/spec.json", [_task_spec(
            "API_TOKEN=" + ROTATED_SECRET + " ./serve", "bash-a8s7d6f5",
            "Shell:8")], end="")
        found = _scan(self.src, self.stores())
        self.assertEqual(set(found), {SECRET, ROTATED_SECRET})
        self.assertEqual((found[SECRET]["files"], found[SECRET]["origins"]),
                         ({log}, {".env"}))
        # a key typed into the command has no origin
        self.assertEqual((found[ROTATED_SECRET]["files"],
                          found[ROTATED_SECRET]["origins"]), ({typed}, set()))
        [text] = list(self.src.secret_texts(self.store(log)))
        self.assertEqual((text.where, text.call.store, text.call.tool_name,
                          text.call.tool_call_id, text.call.command,
                          text.call.session, text.call.project),
                         ("line 1", spec, "Shell", "Shell:7", "cat .env", SID,
                          PROJECT))
        # an agent task names no command, so its output carries no call
        agent = self.write(s + "/tasks/agent-q1w2e3r4/output.log", ["done"])
        self.write(s + "/tasks/agent-q1w2e3r4/spec.json", [json.dumps(
            {"version": 1, "id": "agent-q1w2e3r4", "kind": "agent",
             "session_id": SID, "description": "review", "tool_call_id": "Agent:9",
             "command": None}, indent=2)], end="")
        [text] = list(self.src.secret_texts(self.store(agent)))
        self.assertIsNone(text.call)

    def test_a_subagents_prompt_and_output_are_searched(self):
        """subagents/<id>/prompt.txt is the prompt the subagent was given,
        and output the text and summary it wrote (subagents/core.py,
        output.py): copies of what wire.jsonl holds."""
        self.kimi_json()
        a = self.session() + "/subagents/a1b2c3"
        self.write(a + "/wire.jsonl", [WIRE_HEAD])
        prompt = self.write(a + "/prompt.txt",
                            ["Deploy it with STRIPE_KEY=" + SECRET], end="")
        output = self.write(a + "/output", [
            "[stage] context_ready", "Deploying.[tool] Shell",
            "[tool_result] success", "", "[summary]",
            "Deployed with the key " + ROTATED_SECRET])
        found = _scan(self.src, self.stores())
        self.assertEqual((found[SECRET]["files"], found[SECRET]["origins"]),
                         ({prompt}, set()))
        self.assertEqual((found[ROTATED_SECRET]["files"],
                          found[ROTATED_SECRET]["origins"]), ({output}, set()))

    def test_a_key_in_a_subagents_context_files_is_found(self):
        """A Task subagent's context_sub_<N>.jsonl and its rotation (before
        1.25), a 1.25 subagent's rotated context, and an imported session's
        rotated context: clean searches all of them."""
        third = "sk_" "live_" "Bq7mN2xV9cL4kJ8hG3fD"
        fourth = "sk_" "live_" "Wt5yU1iO8pA6sD2fG9hJ"
        self.kimi_json()
        s = self.session()
        self.write(s + "/wire.jsonl", [WIRE_HEAD])

        def leak(key):
            return [ctx_call("Shell:0", "Shell", {"command": "cat .env"}),
                    ctx_result("Shell:0", "API_KEY=" + key + "\n")]
        task = self.write(s + "/context_sub_1.jsonl", leak(SECRET))
        task_rotated = self.write(s + "/context_sub_1_1.jsonl", leak(ROTATED_SECRET))
        sub_rotated = self.write(s + "/subagents/a1/context_1.jsonl", leak(third))
        imp = "imported_sessions/%s" % SID_IMPORTED
        self.write(imp + "/wire.jsonl", [WIRE_HEAD])
        imp_rotated = self.write(imp + "/context_1.jsonl", leak(fourth))
        found = _scan(self.src, self.stores())
        self.assertEqual({k: (v["files"], v["origins"]) for k, v in found.items()}, {
            SECRET: ({task}, {".env"}), ROTATED_SECRET: ({task_rotated}, {".env"}),
            third: ({sub_rotated}, {".env"}), fourth: ({imp_rotated}, {".env"})})

    def test_a_line_that_is_not_json_is_searched_as_text(self):
        self.kimi_json()
        path = self.write(self.session() + "/wire.jsonl", [
            WIRE_HEAD, '{"timestamp": 1, "message": API_KEY=' + SECRET])
        found = _scan(self.src, [self.store(path)])
        self.assertEqual(found[SECRET]["files"], {path})


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

class Masking(KimiCase):

    def _read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def _backups(self):
        return [os.path.join(d, f) for d, _s, files in os.walk(self.backups)
                for f in files]

    def _signature(self):
        return [(c.store, c.tool_call_id, c.tool_name, c.kind, c.timestamp,
                 c.status, c.session, c.project) for c in self.calls()]

    def test_round_trip(self):
        self.typed_tree()
        stores = self.stores()
        if not WINDOWS:
            for store in stores:
                os.chmod(store.path, 0o640)
        values = sorted(_scan(self.src, stores))
        self.assertEqual(values, sorted([SECRET, TYPED, ROTATED_SECRET]))
        before_calls = self._signature()
        original = {s.path: self._read(s.path) for s in stores}
        swaps = [(SECRET, SECRET), (ROTATED_SECRET, ROTATED_SECRET),
                 (TYPED_IN_FILE, TYPED)]
        expected = {}
        for path, data in original.items():
            for form, value in swaps:
                data = data.replace(form.encode("utf-8"),
                                    _marker(value).encode("utf-8"))
            expected[path] = data

        results = {s.path: self.src.mask(s, values) for s in stores}
        for path, result in results.items():
            if original[path] == expected[path]:
                self.assertEqual(result, MaskResult(path), path)
                continue
            self.assertEqual((result.changed, result.skipped), (True, None), path)
            # the backup is the original, byte for byte
            self.assertEqual(self._read(result.backup), original[path])
            # nothing but the secret changed
            after = self._read(path)
            self.assertEqual(after, expected[path], path)
            text = after.decode("utf-8")
            for value in values:
                self.assertEqual([f for f in _rewrite.encodings(value) if f in text],
                                 [], (path, value))
            for line in text.split("\n"):
                if line.strip():
                    json.loads(line)
            if not WINDOWS:
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
        self.assertEqual(len(self._backups()), 3)       # wire, context, context_1

        # the inner JSON still parses, with the marker where the value was
        commands = [c.command for c in self.calls() if c.tool_call_id == "Shell:1"]
        self.assertEqual(commands, ["export DB_PASSWORD=" + _marker(TYPED)
                                    + "; ./deploy.sh"])
        self.assertEqual(self._signature(), before_calls)
        self.assertEqual(_scan(self.src, self.stores()), {})

        # a second run changes nothing
        again = {s.path: self.src.mask(s, values) for s in self.stores()}
        self.assertEqual(again, {p: MaskResult(p) for p in again})
        for path, data in expected.items():
            self.assertEqual(self._read(path), data)
        self.assertEqual(len(self._backups()), 3)

    def test_plain_text_and_json_stores_round_trip(self):
        self.kimi_json()
        s = self.session()
        log = self.write(s + "/tasks/bash-k3v9x2mq/output.log",
                         ["STRIPE_KEY=" + SECRET, "done"])
        spec = self.write(s + "/tasks/bash-k3v9x2mq/spec.json", [_task_spec(
            "API_TOKEN=" + ROTATED_SECRET + " ./serve")], end="")
        self.write(s + "/tasks/bash-k3v9x2mq/runtime.json",
                   [json.dumps({"status": "completed", "exit_code": 0}, indent=2)],
                   end="")
        prompt = self.write(s + "/subagents/a1/prompt.txt",
                            ["Deploy it with STRIPE_KEY=" + SECRET], end="")
        stores = [self.store(p) for p in (log, spec, prompt)]
        values = sorted(_scan(self.src, stores))
        self.assertEqual(values, sorted([SECRET, ROTATED_SECRET]))
        for store in stores:
            original = self._read(store.path)
            expected = original
            for value in values:
                expected = expected.replace(value.encode("utf-8"),
                                            _marker(value).encode("utf-8"))
            result = self.src.mask(store, values)
            self.assertEqual((result.changed, result.skipped), (True, None),
                             store.path)
            self.assertEqual(self._read(store.path), expected)
            self.assertEqual(self._read(result.backup), original)
        with open(spec, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["command"],
                             "API_TOKEN=" + _marker(ROTATED_SECRET) + " ./serve")
        self.assertEqual(_scan(self.src, stores), {})

    def test_a_running_background_tasks_output_is_in_use(self):
        """The worker holds output.log open while the command runs, quiet or
        not (background/worker.py): a file put in its place would miss the
        rest. runtime.json's status tells whether it still runs."""
        self.kimi_json()
        task = self.session() + "/tasks/bash-k3v9x2mq"
        log = self.write(task + "/output.log", ["STRIPE_KEY=" + SECRET])
        spec = self.write(task + "/spec.json", [_task_spec("./serve")], end="")
        before = self._read(log)
        for status in ("created", "starting", "running", "awaiting_approval"):
            self.write(task + "/runtime.json", [json.dumps(
                {"status": status, "worker_pid": 4242}, indent=2)], end="")
            self.assertEqual(self.src.mask(self.store(log), [SECRET]),
                             MaskResult(log, skipped="in use"), status)
        self.assertEqual(self._read(log), before)
        self.assertFalse(os.path.exists(self.backups))
        # spec.json is written whole each time (atomic_json_write)
        self.assertFalse(self.src.in_use(self.store(spec)))
        self.write(task + "/runtime.json", ['{"status": "killed"}'])
        result = self.src.mask(self.store(log), [SECRET])
        self.assertEqual((result.changed, result.skipped), (True, None))
        # no runtime.json (or one that is not JSON) is not known to be in use
        os.unlink(os.path.join(os.path.dirname(log), "runtime.json"))
        self.assertFalse(self.src.in_use(self.store(log)))

    def test_a_value_cut_in_two_by_the_pieces_of_a_call_is_not_masked_there(self):
        """Raw replacement cannot reach a value cut in two by the pieces of
        a call, so that wire.jsonl is refused as a file whose masking would
        change more than the secret, and clean names it as not masked. The
        whole copy in context.jsonl is masked."""
        ctx, wire_path = self.split_tree()
        before = self._read(wire_path)
        result = self.src.mask(self.store(wire_path), [SECRET])
        self.assertEqual(result, MaskResult(
            wire_path, skipped="would alter more than the secret"))
        self.assertEqual(self._read(wire_path), before)
        self.assertEqual(self._backups(), [])
        result = self.src.mask(self.store(ctx), [SECRET])
        self.assertEqual((result.changed, result.skipped), (True, None))
        found = _scan(self.src, self.stores())
        self.assertEqual(found[SECRET]["files"], {wire_path})

    def test_a_value_whole_in_one_piece_is_masked(self):
        ctx, wire_path = self.split_tree(inside=True)
        for path in (wire_path, ctx):
            result = self.src.mask(self.store(path), [SECRET])
            self.assertEqual((result.changed, result.skipped), (True, None))
        text = self._read(wire_path).decode("utf-8")
        self.assertNotIn(SECRET, text)
        self.assertIn(_marker(SECRET), text)
        [shell] = [c for c in self.calls(wire_path) if c.tool_call_id == "Shell:1"]
        self.assertEqual(shell.command, "curl -H 'Authorization: Bearer %s' "
                         "https://api.example.com/v1/me" % _marker(SECRET))

    def test_a_file_written_in_the_last_two_minutes_is_in_use(self):
        _ctx, wire_path, _hist = self.spec_tree(age=5)
        before = self._read(wire_path)
        result = self.src.mask(self.store(wire_path), [SECRET])
        self.assertEqual(result, MaskResult(wire_path, skipped="in use"))
        self.assertEqual(self._read(wire_path), before)
        self.assertFalse(os.path.exists(self.backups))


# --------------------------------------------------------------------------
# Files that do not parse
# --------------------------------------------------------------------------

class Robustness(KimiCase):

    def _quiet(self, func):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = func()
        return out, err.getvalue()

    def test_a_truncated_last_line_is_skipped_without_a_warning(self):
        self.kimi_json()
        lines = _spec_wire(SECRET) + [
            '{"timestamp": 1790000002.0, "message": {"type": "ToolCall", "payl']
        path = self.write(self.session() + "/wire.jsonl", lines, end="")
        calls, err = self._quiet(lambda: self.calls(path))
        self.assertEqual([c.tool_call_id for c in calls], ["Shell:0"])
        self.assertEqual(err, "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_store_of_garbage_warns_once_and_the_others_are_read(self):
        _ctx, good, _hist = self.spec_tree()
        bad = os.path.join(self.root, *self.session(SID_OLD).split("/"), "wire.jsonl")
        os.makedirs(os.path.dirname(bad))
        with open(bad, "wb") as fh:
            fh.write(b"\x00\xff\xfe garbage\n\x13\x37{not json\n\x89PNG\r\n")
        calls, err = self._quiet(lambda: self.calls() + self.calls())
        self.assertEqual([c.store for c in calls], [good, good])
        self.assertEqual(err.count("warning:"), 1)
        self.assertIn(bad, err)
        self.assertNotIn("\u2014", err)
        self.assertEqual(self.src.unreadable, {"not JSON lines": 2})

    def test_unknown_records_are_ignored_and_counted(self):
        self.kimi_json()
        path = self.write(self.session() + "/wire.jsonl", _spec_wire(SECRET) + [
            wire(1790000003.0, "SomethingNew", {"id": "Shell:0"}),
            json.dumps({"kind": "not a wire record"}),
            json.dumps([1, 2, 3]),
            wire(1790000004.0, "ToolCall", {"type": "function", "id": "x"}),
        ])
        calls, err = self._quiet(lambda: self.calls(path))
        self.assertEqual([c.tool_call_id for c in calls], ["Shell:0"])
        self.assertEqual(err, "")
        self.assertEqual(self.src.counts["unknown"], 2)
        self.assertEqual(self.src.counts["unreadable_calls"], 1)
        ctx = self.write("imported_sessions/%s/context.jsonl" % SID_IMPORTED,
                         _spec_context(SECRET) + ['{"no_role": 1}', '"text"'])
        self.src.reset()
        calls, err = self._quiet(lambda: self.calls(ctx))
        self.assertEqual([c.tool_call_id for c in calls], ["Shell:0"])
        self.assertEqual(self.src.counts["unknown"], 2)

    def test_a_store_that_disappears_warns_once(self):
        _ctx, wire_path, _hist = self.spec_tree()
        store = self.store(wire_path)
        os.unlink(wire_path)
        out, err = self._quiet(lambda: (list(self.src.tool_calls(store)),
                                        list(self.src.tool_calls(store)),
                                        list(self.src.secret_texts(store))))
        self.assertEqual(out, ([], [], []))
        self.assertEqual(err.count("warning:"), 1)

    def test_task_and_subagent_files_that_do_not_parse(self):
        """A spec.json that is not JSON is searched as text, and its
        output.log is still searched, with no call; a subagent's output with
        bytes that are not UTF-8 is searched around them."""
        self.kimi_json()
        s = self.session()
        log = self.write(s + "/tasks/bash-k3v9x2mq/output.log",
                         ["STRIPE_KEY=" + SECRET])
        spec = self.write(s + "/tasks/bash-k3v9x2mq/spec.json",
                          ['{"command": "cat .env", API_TOKEN=' + ROTATED_SECRET])
        out = os.path.join(self.root, *s.split("/"), "subagents", "a1", "output")
        os.makedirs(os.path.dirname(out))
        with open(out, "wb") as fh:
            fh.write(b"\xff\xfe [summary]\nkey " + SECRET.encode("ascii") + b"\n")
        (texts, found), err = self._quiet(lambda: (
            list(self.src.secret_texts(self.store(log))),
            _scan(self.src, self.stores())))
        self.assertEqual(err, "")
        self.assertIsNone(texts[0].call)
        self.assertEqual(found[SECRET]["files"], {log, out})
        self.assertEqual(found[ROTATED_SECRET]["files"], {spec})
        self.assertEqual(self.calls(), [])

    def test_a_call_nested_past_the_stack_is_kept_and_the_rest_read(self):
        """A call whose arguments are an object nested too deep for Python
        to encode, in wire.jsonl and again in context.jsonl, and one whose
        arguments string is: nothing escapes, the deep call is read once,
        and the calls and keys around it are still read, the one only
        context.jsonl holds included. Where the parser gives up first (3.9),
        the deep lines are skipped and counted."""
        self.kimi_json()
        deep = _deep()
        as_object = {"type": "function", "id": "Shell:1",
                     "function": {"name": "Shell", "arguments": "@"}}
        self.write(self.session() + "/wire.jsonl", _spec_wire(SECRET) + [
            wire(1790000002.0, "ToolCall", as_object).replace('"@"', deep),
            wire(1790000003.0, "ToolCall", dict(
                as_object, id="Shell:2",
                function={"name": "Shell", "arguments": deep})),
            wire_call(1790000004.0, "Shell:3", "Shell", {"command": "ls"}),
            wire_result(1790000004.5, "Shell:3", "TOKEN=" + ROTATED_SECRET),
        ])
        self.write(self.session() + "/context.jsonl", _spec_context(SECRET) + [
            _compact({"role": "assistant", "content": "",
                      "tool_calls": [as_object]}).replace('"@"', deep),
            ctx_call("Shell:4", "Shell", {"command": "rm -rf build"}),
        ])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ids = sorted(c.tool_call_id for c in self.calls())
            found = _scan(self.src, self.stores())
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.unreadable, {})
        self.assertEqual(found[SECRET]["origins"], {".env"})
        self.assertEqual(found[ROTATED_SECRET]["origins"], set())
        if _parses(deep):
            self.assertEqual(ids, ["Shell:0", "Shell:1", "Shell:2", "Shell:3",
                                   "Shell:4"])
            self.assertEqual(self.src.counts.get("unparsed", 0), 0)
        else:
            self.assertEqual(ids, ["Shell:0", "Shell:2", "Shell:3", "Shell:4"])
            self.assertEqual(self.src.counts["unparsed"], 1)

    def test_a_kimi_json_that_is_not_json_only_loses_projects(self):
        self.spec_tree()
        self.write("kimi.json", ["{not json"])
        self.assertEqual({s.project for s in self.stores()}, {None})
        self.write("kimi.json", ['{"work_dirs": [{"path": 3}, "x", {"kaos": "local"}]}'])
        self.assertEqual({s.project for s in self.stores()}, {None})


# --------------------------------------------------------------------------
# A large file: how reading it grows, on its own interpreter (tests/growth.py)
# --------------------------------------------------------------------------

_CALL = r"""
from ranwhat.sources import kimi
def call(root):
    src = kimi.KimiSource()
    stores = src.stores(src.locations(override=root))
    calls = sum(1 for s in stores for _ in src.tool_calls(s))
    texts = sum(1 for s in stores for _ in src.secret_texts(s))
    return [calls, texts]
"""


class LargeFile(growth.Assertions, KimiCase):

    CALLS = 20000
    PIECES = 20000

    def share(self, n):
        """A share directory whose one session ran n(CALLS) commands."""
        root = tempfile.mkdtemp(prefix="big-share-", dir=self.tmp)
        folder = os.path.join(root, "sessions", "0" * 32, "big")
        os.makedirs(folder)
        out = "x" * 1500 + "\n"
        # context.jsonl holds a copy of every call: none of them is a call
        # of its own
        with open(os.path.join(folder, "wire.jsonl"), "w", encoding="utf-8") as fh, \
                open(os.path.join(folder, "context.jsonl"), "w",
                     encoding="utf-8") as ctx:
            fh.write(json.dumps({"type": "metadata", "protocol_version": "1.10"})
                     + "\n")
            for i in range(n(self.CALLS)):
                cid = "Shell:%d" % i
                args = json.dumps({"command": "cat file%d.txt" % i})
                fh.write(json.dumps({"timestamp": 1790000000.0 + i, "message": {
                    "type": "ToolCall", "payload": {"type": "function", "id": cid,
                    "function": {"name": "Shell", "arguments": args},
                    "extras": None}}}) + "\n")
                fh.write(json.dumps({"timestamp": 1790000000.5 + i, "message": {
                    "type": "ToolResult", "payload": {"tool_call_id": cid,
                    "return_value": {"is_error": False, "output": out,
                    "message": "", "display": [], "extras": None}}}}) + "\n")
                ctx.write(json.dumps({"role": "assistant", "content": "",
                                      "tool_calls": [
                    {"type": "function", "id": cid, "function": {"name": "Shell",
                     "arguments": args}}]}, separators=(",", ":")) + "\n")
                ctx.write(json.dumps({"role": "tool", "content": [
                    {"type": "text",
                     "text": "<system>Command executed successfully.</system>"},
                    {"type": "text", "text": out}], "tool_call_id": cid},
                    separators=(",", ":")) + "\n")
        return root

    def test_a_large_wire_file_is_read_in_linear_time(self):
        env = dict(os.environ, HOME=self.home, USERPROFILE=self.home)
        env.pop("KIMI_SHARE_DIR", None)
        measured, root = growth.measure_apart(self.share, _CALL, env=env)
        size = os.path.getsize(os.path.join(root, "sessions", "0" * 32, "big",
                                            "wire.jsonl"))
        self.assertGreater(size, 30 * 1024 * 1024)
        growth.assert_linear(self, measured, "a %d MB wire file" % (size // 10 ** 6))
        self.assertEqual(measured.result, [self.CALLS, 4 * self.CALLS + 1])

    def pieces(self, n):
        """A share directory whose one session holds a Shell call written in
        n(PIECES) pieces, a status update flushing the call before each."""
        root = tempfile.mkdtemp(prefix="pieces-share-", dir=self.tmp)
        folder = os.path.join(root, "sessions", "0" * 32, "pieces")
        os.makedirs(folder)
        count = n(self.PIECES)
        command = {"command": "echo " + "x" * 59 * count}
        args = json.dumps(command)
        size = len(args) // count + 1
        call, _rest = split_call("Shell:0", "Shell", command, size)
        with open(os.path.join(folder, "wire.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(WIRE_HEAD + "\n" + wire(1790000000.0, "ToolCall", call) + "\n")
            for at in range(size, len(args), size):
                fh.write(wire(1790000000.1, "StatusUpdate", {"context_usage": 0.1})
                         + "\n" + wire(1790000000.2, "ToolCallPart", {
                             "arguments_part": args[at:at + size]}) + "\n")
            fh.write(wire_result(1790000001.0, "Shell:0", "") + "\n")
        return root

    def test_a_call_in_many_pieces_is_read_in_linear_time(self):
        def read(root):
            src = kimi.KimiSource()
            [store] = src.stores(src.locations(override=root))
            [shell] = src.tool_calls(store)
            texts = sum(1 for _ in src.secret_texts(store))
            masked = src.mask(store, [SECRET])
            return len(shell.command), texts, masked.changed
        length, _texts, changed = self.assertScalesLinearly(
            self.pieces, read, "a call in %d pieces" % self.PIECES)
        self.assertEqual((length, changed), (5 + 59 * self.PIECES, False))


if __name__ == "__main__":
    unittest.main()
