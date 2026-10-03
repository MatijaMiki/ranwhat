"""The Gemini CLI adapter (ranwhat/sources/gemini.py), design section 7.4.

Fixtures are built from the spec's verified sample, field for field, in
temp directories: HOME, USERPROFILE, GEMINI_CLI_HOME, _paths.home and the
backup root all point there, so nothing touches the real home. Every
secret is synthetic and written as adjacent literals.

watch.judge and clean.scan_sources are not wired in yet, so _judge and
_findings below follow design 3.5 and 3.6 on top of watch.evaluate and
clean's own detection.
"""
import builtins
import contextlib
import hashlib
import io
import json
import os
import stat
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

import growth  # noqa: E402
from ranwhat import clean, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite, _stamps, gemini  # noqa: E402
from ranwhat.sources.base import MaskResult, Store  # noqa: E402

KEY = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
KEY2 = "sk_" "live_" "Hc3nW7pQ1xVb9TzK5mRd2LsF"
KEY3 = "sk_" "live_" "Ty6uB0eS8kMj3QaX7wNc4GvP"
KEY4 = "sk_" "live_" "Lm2fD9rH5pZx1VbT8nQs6YkW"
KEY5 = "sk_" "live_" "Wd7gK3sN9vRb2XyM6hTq0LcF"
KEY6 = "sk_" "live_" "Pe4jA8zU1cGt7NwB3kVr9SmD"

SESSION = "3f2b8c1e-5d4a-4c1b-9e2f-7a6b5c4d3e2f"
PROJECT = "/Users/alice/proj"
PROJECT_HASH = "2711bd02afc2a28dada0b11e36942882302b3b46acd870d757bdc483b2d6e8b9"
CALL_ID = "run_shell_command__run_shell_command_1790763312900_0"
FIXTURE_NAME = "session-2026-09-30T10-15-3f2b8c1e.jsonl"

WINDOWS = os.name == "nt"

# The spec's sample (7.4), byte for byte, with its example key replaced by
# a synthetic one at @KEY@.
SPEC_LINES = [
    '{"sessionId":"3f2b8c1e-5d4a-4c1b-9e2f-7a6b5c4d3e2f","projectHash":"2711bd02afc2a28dada0b11e36942882302b3b46acd870d757bdc483b2d6e8b9","startTime":"2026-09-30T10:15:02.120Z","lastUpdated":"2026-09-30T10:15:02.120Z"}',
    '{"id":"6c1e0f3a-1b2c-4d5e-8f90-a1b2c3d4e5f1","timestamp":"2026-09-30T10:15:10.500Z","type":"user","content":[{"text":"what is in .env?"}]}',
    '{"$set":{"lastUpdated":"2026-09-30T10:15:10.501Z"}}',
    '{"id":"6c1e0f3a-1b2c-4d5e-8f90-a1b2c3d4e5f2","timestamp":"2026-09-30T10:15:12.900Z","type":"gemini","content":"","thoughts":[],"tokens":{"input":5120,"output":24,"cached":0,"thoughts":0,"tool":0,"total":5144},"model":"gemini-2.5-pro"}',
    '{"$set":{"lastUpdated":"2026-09-30T10:15:12.901Z"}}',
    '{"id":"6c1e0f3a-1b2c-4d5e-8f90-a1b2c3d4e5f2","timestamp":"2026-09-30T10:15:12.900Z","type":"gemini","content":"","thoughts":[],"tokens":{"input":5120,"output":24,"cached":0,"thoughts":0,"tool":0,"total":5144},"model":"gemini-2.5-pro","toolCalls":[{"id":"run_shell_command__run_shell_command_1790763312900_0","name":"run_shell_command","args":{"command":"cat .env"},"result":[{"functionResponse":{"id":"run_shell_command__run_shell_command_1790763312900_0","name":"run_shell_command","response":{"output":"<untrusted_context>\\nOutput: API_KEY=@KEY@\\nProcess Group PGID: 48211\\n</untrusted_context>"}}}],"status":"success","timestamp":"2026-09-30T10:15:13.400Z","resultDisplay":"API_KEY=@KEY@\\n","description":"cat .env","displayName":"Shell","renderOutputAsMarkdown":false}]}',
    '{"id":"6c1e0f3a-1b2c-4d5e-8f90-a1b2c3d4e5f3","timestamp":"2026-09-30T10:15:13.450Z","type":"user","content":[{"functionResponse":{"id":"run_shell_command__run_shell_command_1790763312900_0","name":"run_shell_command","response":{"output":"<untrusted_context>\\nOutput: API_KEY=@KEY@\\nProcess Group PGID: 48211\\n</untrusted_context>"}}}]}',
    '{"$set":{"lastUpdated":"2026-09-30T10:15:13.451Z"}}',
]


def spec_lines(key=KEY):
    return [line.replace("@KEY@", key) for line in SPEC_LINES]


# -- builders for the other shapes, using only the spec's field names -------

def _dump(obj):
    """Compact, like JSON.stringify."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def header(session=SESSION, **extra):
    out = {"sessionId": session, "projectHash": PROJECT_HASH,
           "startTime": "2026-09-30T10:15:02.120Z",
           "lastUpdated": "2026-09-30T10:15:02.120Z"}
    out.update(extra)
    return out


def user(mid, text, ts="2026-09-30T10:15:10.500Z"):
    return {"id": mid, "timestamp": ts, "type": "user",
            "content": [{"text": text}]}


def response_part(call_id, name, output):
    return {"functionResponse": {"id": call_id, "name": name,
                                 "response": {"output": output}}}


def tool_call(call_id, name, args, ts="2026-09-30T10:15:13.400Z",
              output=None, display=None, status="success"):
    out = {"id": call_id, "name": name, "args": args}
    if output is not None:
        out["result"] = [response_part(call_id, name, output)]
    out["status"] = status
    if ts is not None:
        out["timestamp"] = ts
    if display is not None:
        out["resultDisplay"] = display
    return out


def model(mid, calls=None, ts="2026-09-30T10:15:12.900Z", type_="gemini"):
    out = {"id": mid, "timestamp": ts, "type": type_, "content": ""}
    if calls is not None:
        out["toolCalls"] = calls
    return out


def results(mid, calls, ts="2026-09-30T10:15:13.450Z"):
    """The synthetic user message that repeats tool results."""
    return {"id": mid, "timestamp": ts, "type": "user",
            "content": [response_part(c["id"], c["name"],
                                      c["result"][0]["functionResponse"]
                                      ["response"]["output"])
                        for c in calls if "result" in c]}


def shell(call_id, command, output=None, **kw):
    return tool_call(call_id, "run_shell_command", {"command": command},
                     output=output, **kw)


# What a cancelled call's own functionResponse says (v0.62.0). toCancelled
# (scheduler/state-manager.ts) writes "[Operation Cancelled] Reason: " and
# the reason scheduler.ts gave; the executor (tool-executor.ts) writes
# "[Operation Cancelled] " and its own, beside any output, for a call
# cancelled while it ran.
DENIED = "[Operation Cancelled] Reason: User denied execution."
QUEUED = "[Operation Cancelled] Reason: User cancelled operation"
ABORTED = "[Operation Cancelled] Reason: Operation cancelled by user"
STOPPED = "[Operation Cancelled] User cancelled tool execution."


def cancelled(call_id, name, args, error, output=None,
              ts="2026-09-30T10:15:13.400Z"):
    """A cancelled call as recordCompletedToolCalls stores it."""
    response = {"error": error} if output is None else {"output": output,
                                                         "error": error}
    return {"id": call_id, "name": name, "args": args,
            "result": [{"functionResponse": {"id": call_id, "name": name,
                                             "response": response}}],
            "status": "cancelled", "timestamp": ts}


def synced(calls, mid="m1", uid="u1"):
    """A turn of parallel calls, then the history sync that follows it
    (chatRecordingService.ts, updateMessagesFromHistory): the user turn's
    parts become every call's result, appended as $set.messages."""
    turn = [part for c in calls for part in c.get("result", [])]
    user_turn = {"id": uid, "timestamp": "2026-09-30T10:15:13.450Z",
                 "type": "user", "content": turn}
    again = model(mid, [dict(c, result=list(turn)) for c in calls])
    return [model(mid, calls), user_turn,
            {"$set": {"messages": [again, user_turn],
                      "lastUpdated": "2026-09-30T10:15:14.000Z"}}]


# -- terminal output: AnsiOutput (utils/terminalSerializer.ts) ---------------

def token(text, uninitialized=False, **style):
    """An AnsiToken, every field, in the serializer's order."""
    out = {"text": text, "bold": False, "italic": False, "underline": False,
           "dim": False, "inverse": False, "isUninitialized": uninitialized,
           "fg": "", "bg": ""}
    out.update(style)
    return out


def grid(lines, width=80):
    """A PTY shell call's resultDisplay: each printed line (a string, or
    its tokens where the style changes) cut into rows of `width` cells, the
    blank cells after it as one uninitialized token, and the cursor's row
    last."""
    rows = []
    for line in lines:
        tokens = [token(line)] if isinstance(line, str) else line
        row, used, wrapped = [], 0, False
        for tok in tokens:
            text = tok["text"]
            while text:
                piece, text = text[:width - used], text[width - used:]
                row.append(dict(tok, text=piece))
                used += len(piece)
                if used == width:
                    rows.append(row)
                    row, used, wrapped = [], 0, True
        if used or not wrapped:
            row.append(token(" " * (width - used), True))
            rows.append(row)
    rows.append([token(" ", True, inverse=True), token(" " * (width - 1), True)])
    return rows


def untrusted(text):
    """A shell call's own output, as the model got it."""
    return ("<untrusted_context>\nOutput: %s\nProcess Group PGID: 48211\n"
            "</untrusted_context>" % text)


# -- what watch and clean will do with what the adapter yields ---------------

NEUTRAL = "ranwhat:%s"


def _judge(call):
    """watch.judge as design 3.5 defines it."""
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
    return watch.evaluate(NEUTRAL % call.kind, call.tool_input)


def _rules(call):
    hits, _payload = _judge(call)
    return [(h["rule"], h["evidence"]) for h in hits]


def _core_key(call):
    """The cross-store dedupe key the core uses (3.5): a flagged record's
    tool name, payload hash and time."""
    _hits, payload = _judge(call)
    return (call.tool_name, watch._hash(payload), call.timestamp)


def _call_origins(call):
    """Design 3.6: the credential files a call's input names, with the keys
    it consumed replaced by its normalised command, heredocs stripped."""
    if call is None:
        return []
    judged = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.command:
        judged["command"] = watch._strip_heredocs(call.command)
    if call.paths:
        judged["paths"] = list(call.paths)
    return clean._origins(json.dumps(judged, ensure_ascii=False))


def _findings(source, stores):
    """{value: {"label", "count", "origins", "calls"}} over the stores."""
    out = {}
    for store in stores:
        for text in source.secret_texts(store):
            named = _call_origins(text.call)
            origin = named[-1] if named else None

            def collect(value, label, _in=None, _copies=None, text=text,
                        origin=origin):
                entry = out.setdefault(value, {"label": label, "count": 0,
                                               "origins": set(), "calls": set()})
                entry["count"] += 1
                if origin:
                    entry["origins"].add(origin)
                if text.call is not None:
                    entry["calls"].add(text.call.tool_call_id)
            clean._walk(text.node, collect)
    return out


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _without_output(call):
    out = call.as_dict()
    out.pop("output")
    return out


class GeminiCase(unittest.TestCase):
    """A temp home with GEMINI_CLI_HOME pointing into it."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="gemini-home-")
        self.addCleanup(_rmtree, self.home)
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home,
                                                "GEMINI_CLI_HOME": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.backups = os.path.join(self.home, "ranwhat-backups")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.root = os.path.join(self.home, ".gemini")
        self.src = gemini.GeminiSource()

    def write(self, rel, lines=None, text=None, data=None, age=3600, root=None):
        """A file under the .gemini root: JSON Lines from `lines` (strings
        or objects), or `text`, or bytes. Aged an hour by default, past the
        masking quiet period."""
        path = os.path.join(root or self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if lines is not None:
            data = "".join((l if isinstance(l, str) else _dump(l)) + "\n"
                           for l in lines).encode("utf-8")
        elif text is not None:
            data = text.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def fixture(self, key=KEY, age=3600, folder="proj"):
        path = self.write("tmp/%s/chats/%s" % (folder, FIXTURE_NAME),
                          spec_lines(key), age=age)
        self.write("tmp/%s/.project_root" % folder, text=PROJECT)
        return path

    def stores(self, **kw):
        return self.src.stores(self.src.locations(), **kw)

    def store(self, path):
        for s in self.stores():
            if s.path == path:
                return s
        self.fail("%s is not a store" % path)

    def calls(self, path):
        return list(self.src.tool_calls(self.store(path)))

    def session(self, rel, records, **kw):
        return self.write("tmp/proj/chats/" + rel, [header()] + records, **kw)


def _rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


# --------------------------------------------------------------------------
# 1, 2: where to look
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = gemini.GeminiSource()

    def test_every_platform(self):
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"), [
            ("/Users/u/.gemini", "default"),
            ("/Users/u/.cache/.gemini", "default, sandbox")])
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"), [
            ("/home/u/.gemini", "default"),
            ("/home/u/.cache/.gemini", "default, sandbox")])
        self.assertEqual(self.src.default_paths({}, "C:\\Users\\u", "win32"), [
            ("C:\\Users\\u\\.gemini", "default"),
            ("C:\\Users\\u\\.cache\\.gemini", "default, sandbox")])

    def test_gemini_cli_home_replaces_the_home_directory(self):
        env = {"GEMINI_CLI_HOME": "/srv/g"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"), [
            ("/srv/g/.gemini", "env GEMINI_CLI_HOME"),
            ("/srv/g/.cache/.gemini", "env GEMINI_CLI_HOME, sandbox")])
        self.assertEqual(
            self.src.default_paths({"GEMINI_CLI_HOME": "D:\\g"}, "C:\\Users\\u",
                                   "win32"),
            [("D:\\g\\.gemini", "env GEMINI_CLI_HOME"),
             ("D:\\g\\.cache\\.gemini", "env GEMINI_CLI_HOME, sandbox")])
        # Set but empty is not set.
        self.assertEqual(
            self.src.default_paths({"GEMINI_CLI_HOME": ""}, "/home/u", "linux")[0],
            ("/home/u/.gemini", "default"))

    def test_pure(self):
        with mock.patch("os.stat", side_effect=AssertionError("I/O")), \
                mock.patch("os.listdir", side_effect=AssertionError("I/O")):
            self.src.default_paths({}, "/nowhere", "darwin")
            self.src.default_paths({"GEMINI_CLI_HOME": "/x"}, "/nowhere", "win32")

    def test_what_reports_need(self):
        self.assertEqual(self.src.id, "gemini")
        self.assertEqual(self.src.name, "Gemini CLI")
        self.assertEqual(self.src.unit, "session")
        self.assertEqual(self.src.env, ("GEMINI_CLI_HOME",))
        self.assertTrue(self.src.path_means)
        self.assertEqual(self.src.checked, "v0.62.0")
        for text in (self.src.path_means, self.src.clean_note,
                     self.src.mask_note, self.src.name):
            self.assertNotIn("\u2014", text)

    def test_the_report_says_to_close_the_cli_before_masking(self):
        """A running CLI writes whole messages from memory (a changed
        message, a history sync, a rewind) and rewrites shell_history from
        memory, so a masked value can come back."""
        self.assertIn("If Gemini CLI is open in this project, close it first",
                      self.src.mask_note)
        self.assertIn("write the value back", self.src.mask_note)


class Locations(GeminiCase):

    def test_override_variable_is_read_at_call_time(self):
        os.environ.pop("GEMINI_CLI_HOME")
        src = gemini.GeminiSource()             # constructed before the change
        first = src.locations()
        self.assertEqual([(l.path, l.how) for l in first], [
            (os.path.join(self.home, ".gemini"), "default"),
            (os.path.join(self.home, ".cache", ".gemini"), "default, sandbox")])
        moved = os.path.join(self.home, "moved")
        self.write("tmp/p/chats/session-a.jsonl", [header()],
                   root=os.path.join(moved, ".gemini"))
        os.environ["GEMINI_CLI_HOME"] = moved
        locs = src.locations()
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in locs], [
            (os.path.join(moved, ".gemini"), "env GEMINI_CLI_HOME", True, 1),
            (os.path.join(moved, ".cache", ".gemini"),
             "env GEMINI_CLI_HOME, sandbox", False, 0)])

    def test_the_sandbox_root_is_found(self):
        os.environ.pop("GEMINI_CLI_HOME")
        sandbox = os.path.join(self.home, ".cache", ".gemini")
        path = self.write("tmp/proj/chats/" + FIXTURE_NAME, spec_lines(),
                          root=sandbox)
        self.write("tmp/proj/.project_root", text=PROJECT, root=sandbox)
        self.write("projects.json", text='{"projects":{}}', root=sandbox)
        locs = self.src.locations()
        self.assertEqual([(l.how, l.exists, l.found) for l in locs],
                         [("default", False, 0), ("default, sandbox", True, 1)])
        [store] = self.src.stores(locs)
        self.assertEqual((store.path, store.project), (path, PROJECT))
        [call] = self.src.tool_calls(store)
        self.assertEqual(call.command, "cat .env")

    def test_path_override_is_a_gemini_directory(self):
        elsewhere = os.path.join(self.home, "copy", ".gemini")
        path = self.write("tmp/proj/chats/" + FIXTURE_NAME, spec_lines(),
                          root=elsewhere)
        self.fixture()      # the default root has one too; --path replaces it
        locs = self.src.locations(override=elsewhere)
        self.assertEqual([(l.path, l.how, l.found) for l in locs],
                         [(elsewhere, "--path", 1)])
        self.assertEqual([s.path for s in self.src.stores(locs)], [path])


# --------------------------------------------------------------------------
# 3: discovery
# --------------------------------------------------------------------------

class Discovery(GeminiCase):

    def test_every_store_and_nothing_else(self):
        hexdir = hashlib.sha256(PROJECT.encode("utf-8")).hexdigest()
        sub = "7d6c5b4a-3e2f-4a1b-8c9d-0e1f2a3b4c5d"
        expect = {
            # (format, role, unit, project, session)
            "tmp/proj/chats/" + FIXTURE_NAME:
                ("jsonl", "transcript", "session", PROJECT, None),
            "tmp/proj/chats/session-2026-09-30T10-20-2-9a8b7c6d.jsonl":
                ("jsonl", "transcript", "session", PROJECT, None),
            "tmp/proj/chats/%s/%s.jsonl" % (SESSION, sub):
                ("jsonl", "transcript", "session", PROJECT, sub),
            "tmp/proj/chats/session-2025-06-01T09-00-aaaa1111.json":
                ("json", "transcript", "session", PROJECT, None),
            "tmp/proj/chats/%s/legacy-subagent.json" % SESSION:
                ("json", "transcript", "session", PROJECT, None),
            "tmp/%s/chats/session-2025-01-01T09-00-bbbb2222.json" % hexdir:
                ("json", "transcript", "session", PROJECT, None),
            "tmp/proj/logs.json": ("json", "side", "file", PROJECT, None),
            "tmp/proj/checkpoint-mysave.json": ("json", "side", "file", PROJECT, None),
            "tmp/proj/checkpoints/2026-09-30T10-15-x.json":
                ("json", "side", "file", PROJECT, None),
            "tmp/proj/tool-outputs/session-%s/run_shell_command_1.txt" % SESSION:
                ("text", "side", "file", PROJECT, None),
            "tmp/proj/tool-outputs/read_file_2.txt":
                ("text", "side", "file", PROJECT, None),
            "tmp/proj/shell_history": ("text", "side", "file", PROJECT, None),
            "tmp/background-processes/background-4242.log":
                ("text", "side", "file", None, None),
        }
        for age, rel in enumerate(sorted(expect)):
            self.write(rel, text="{}\n" if rel.endswith("json") else "x\n",
                       age=100 + age)
        self.write("tmp/proj/.project_root", text=PROJECT + "\n")
        self.write("projects.json", text=json.dumps({"projects": {PROJECT: "proj"}}))
        # Never stores: config, credentials, the project map, the shadow git
        # repositories, logs/ (format unverified), other agents' folders and
        # files the spec does not list.
        for rel in ("settings.json", ".env", "oauth_creds.json",
                    "google_accounts.json", "history/proj/objects/ab/cdef",
                    "tmp/proj/logs/session.json", "tmp/proj/.env",
                    "tmp/proj/chats/notes.txt", "tmp/proj/chats/other.jsonl",
                    "antigravity/brain/u/.system_generated/logs/transcript.jsonl",
                    "tmp/proj/tool-outputs/session-x/out.log"):
            self.write(rel, text="{}\n")
        os.makedirs(os.path.join(self.root, "tmp", "proj", "chats",
                                 "session-dir.jsonl"))
        found = self.stores()
        got = {os.path.relpath(s.path, self.root).replace(os.sep, "/"):
               (s.format, s.role, s.unit, s.project, s.session) for s in found}
        self.assertEqual(got, expect)
        self.assertTrue(all(s.masking == "rewrite" and s.source == "gemini"
                            for s in found))
        # Newest first.
        self.assertEqual([s.mtime for s in found],
                         sorted((s.mtime for s in found), reverse=True))

    def test_a_missing_root_is_no_stores(self):
        self.assertEqual(self.stores(), [])
        os.makedirs(self.root)                  # a .gemini with no tmp/
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.src.stores(self.src.locations(
            override=os.path.join(self.home, "missing"))), [])

    def test_days_prefilter_by_last_write(self):
        new = self.session("session-new.jsonl", [], age=60)
        self.session("session-old.jsonl", [], age=90 * 86400)
        self.assertEqual([s.path for s in self.stores(since_days=30)], [new])
        self.assertEqual(len(self.stores()), 2)

    def test_reading_never_writes_in_the_agent_folder(self):
        self.fixture()
        self.write("tmp/proj/logs.json", text="[]")
        self.write("tmp/proj/shell_history", text="ls\n")

        def tree():
            out = {}
            for d, _dirs, files in os.walk(self.home):
                for f in files:
                    p = os.path.join(d, f)
                    st = os.stat(p)
                    out[p] = (st.st_size, st.st_mtime_ns, _sha(p))
            return out
        before = tree()
        for s in self.stores():
            list(self.src.tool_calls(s))
            list(self.src.secret_texts(s))
        self.assertEqual(tree(), before)

    def test_only_listed_files_are_opened(self):
        self.fixture()
        self.write("tmp/proj/logs.json", text="[]")
        for rel in ("settings.json", ".env", "oauth_creds.json",
                    "tmp/proj/.env", "tmp/proj/logs/x.json",
                    "history/proj/HEAD"):
            self.write(rel, text="SECRET=" + KEY + "\n")
        opened = []
        real_open = builtins.open

        def spy(file, *args, **kwargs):
            fh = real_open(file, *args, **kwargs)
            opened.append(os.path.relpath(os.fspath(file), self.root)
                          .replace(os.sep, "/"))
            return fh
        with mock.patch("builtins.open", spy):
            for s in self.stores():
                list(self.src.tool_calls(s))
                list(self.src.secret_texts(s))
        self.assertEqual(set(opened), {
            "tmp/proj/.project_root", "tmp/proj/chats/" + FIXTURE_NAME,
            "tmp/proj/logs.json"})


# --------------------------------------------------------------------------
# 4 to 6: what watch sees
# --------------------------------------------------------------------------

class Actions(GeminiCase):

    def one(self, call_record):
        path = self.session("session-a.jsonl", [model("m1", [call_record])])
        [call] = self.calls(path)
        return call

    def test_a_dangerous_shell_call_is_flagged(self):
        call = self.one(shell("c1", "rm -rf ~/Documents/x"))
        self.assertEqual((call.kind, call.known, call.command, call.consumed),
                         ("shell", True, "rm -rf ~/Documents/x",
                          frozenset({"command"})))
        self.assertEqual(_rules(call), [("fs.destructive", "rm -rf ~/Documents/x")])
        call = self.one(shell("c1", "cat ~/.aws/credentials"))
        self.assertEqual(_rules(call), [("cred.read", "cat ~/.aws/credentials")])

    def test_a_credential_read_by_read_file_is_flagged(self):
        call = self.one(tool_call("c1", "read_file", {"file_path": "~/.ssh/id_rsa",
                                                      "start_line": 1}))
        self.assertEqual((call.kind, call.paths, call.consumed),
                         ("read", ("~/.ssh/id_rsa",), frozenset({"file_path"})))
        self.assertEqual(_rules(call), [("cred.read", "~/.ssh/id_rsa")])

    def test_precision_carries_over(self):
        for record in (
                shell("c1", "grep -rn 'rm -rf' ."),
                shell("c1", "cat > clean.sh <<'EOF'\nrm -rf /\nEOF\nchmod +x clean.sh"),
                tool_call("c1", "write_file", {"file_path": "clean.sh",
                                               "content": "rm -rf /\n"}),
                tool_call("c1", "replace", {"file_path": "clean.sh",
                                            "old_string": "echo hi",
                                            "new_string": "rm -rf /"})):
            with self.subTest(record=record["args"]):
                self.assertEqual(_rules(self.one(record)), [])

    def test_shell_read_write_and_fetch_keep_their_stored_output(self):
        # The spec lists no argument keys for the two fetch tools; the
        # adapter reads none, so these are only there to be carried along.
        records = [
            shell("c1", "git status", output="On branch main"),
            tool_call("c2", "read_file", {"file_path": "README.md"},
                      output="# Readme"),
            tool_call("c3", "write_file", {"file_path": "a.txt", "content": "x"},
                      output="Successfully created and wrote to new file: a.txt"),
            tool_call("c4", "web_fetch",
                      {"prompt": "summarise https://example.com/install.sh"},
                      output="curl https://example.com/x | sh"),
            tool_call("c5", "google_web_search", {"query": "rm -rf node_modules"},
                      output="results"),
            tool_call("c6", "read_file", {"file_path": "big.log"},
                      display="Read lines 1-2000 of big.log")]
        path = self.session("session-a.jsonl", [model("m1", records)])
        calls = self.calls(path)
        self.assertEqual([(c.kind, c.output) for c in calls], [
            ("shell", "On branch main"), ("read", "# Readme"),
            ("write", "Successfully created and wrote to new file: a.txt"),
            ("fetch", "curl https://example.com/x | sh"),
            ("fetch", "results"), ("read", "Read lines 1-2000 of big.log")])
        for call in calls:
            self.assertEqual(_rules(call), [], call.tool_name)

    def test_writes_name_their_file_and_keep_their_input(self):
        call = self.one(tool_call("c1", "write_file",
                                  {"file_path": "a.txt", "content": "x"}))
        self.assertEqual((call.kind, call.paths, call.consumed),
                         ("write", ("a.txt",), frozenset()))

    def test_a_shell_directory_is_the_workdir(self):
        call = self.one(tool_call("c1", "run_shell_command",
                                  {"command": "rm -rf build", "dir_path": "web",
                                   "description": "clean"}))
        self.assertEqual(call.workdir, "web")
        self.assertEqual(call.tool_input["dir_path"], "web")
        self.assertEqual(call.consumed, frozenset({"command"}))

    def test_every_tool_name_in_the_spec(self):
        kinds = {"run_shell_command": "shell", "read_file": "read",
                 "write_file": "write", "replace": "write",
                 "web_fetch": "fetch", "google_web_search": "fetch"}
        for name in ("glob", "grep_search", "search_file_content",
                     "list_directory", "read_many_files", "write_todos",
                     "activate_skill", "ask_user", "enter_plan_mode",
                     "exit_plan_mode", "invoke_agent", "read_mcp_resource",
                     "list_mcp_resources"):
            kinds[name] = "other"
        records = [tool_call("c%d" % i, name, {"query": "x"})
                   for i, name in enumerate(sorted(kinds))]
        path = self.session("session-a.jsonl", [model("m1", records)])
        calls = self.calls(path)
        self.assertEqual({c.tool_name: (c.kind, c.known) for c in calls},
                         {n: (k, True) for n, k in kinds.items()})
        for call in calls:
            self.assertEqual(_rules(call), [], call.tool_name)

    def test_names_it_does_not_know_are_judged_by_name(self):
        # Gemini CLI names an MCP tool mcp_<server>_<tool> (mcp-tool.ts), and
        # a discovered tool discovered_tool_<name>.
        records = [
            tool_call("c1", "discovered_tool_deploy", {"target": "prod"}),
            tool_call("c2", "mcp_ops_bash", {"command": "rm -rf ~/Documents/x"}),
            tool_call("c3", "mcp_github_create_issue", {"title": "t"})]
        path = self.session("session-a.jsonl", [model("m1", records)])
        calls = self.calls(path)
        self.assertEqual([(c.kind, c.known, c.tool_name) for c in calls],
                         [("other", False, r["name"]) for r in records])
        for call, record in zip(calls, records):
            self.assertEqual(call.tool_input, record["args"])
            self.assertEqual(call.consumed, frozenset())
            self.assertEqual(_judge(call),
                             watch.evaluate(record["name"], record["args"]))

    @unittest.expectedFailure
    def test_known_gap_an_mcp_shell_tool_is_not_judged_as_a_shell(self):
        """Known gap, for the core to close. watch takes a tool's base name
        after "__" or ".", which is Claude Code's MCP shape; Gemini CLI's
        mcp_ops_bash has neither, so the rm -rf below goes unflagged. The
        adapter cannot split server from tool itself: both may hold "_"."""
        call = self.one(tool_call("c1", "mcp_ops_bash",
                                  {"command": "rm -rf ~/Documents/x"}))
        self.assertEqual(_rules(call), [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_a_shell_call_with_no_command_is_judged_neutrally(self):
        call = self.one(tool_call("c1", "run_shell_command", {"description": "x"}))
        self.assertEqual((call.kind, call.known, call.command), ("shell", True, None))
        self.assertEqual(_judge(call), ([], ""))

    def test_qwen_exec_is_not_a_gemini_name(self):
        # exec is OpenClaw's shell; Gemini CLI has no tool of that name, so
        # it falls through to watch's own judgement by name.
        call = self.one(tool_call("c1", "exec", {"command": "ls"}))
        self.assertFalse(call.known)


# --------------------------------------------------------------------------
# 7: time, session, project
# --------------------------------------------------------------------------

class TimeSessionProject(GeminiCase):

    def test_the_spec_sample(self):
        path = self.fixture()
        [call] = self.calls(path)
        self.assertEqual(call.timestamp, "2026-09-30T10:15:13Z")
        self.assertEqual(call.session, SESSION)
        self.assertEqual(call.project, PROJECT)
        self.assertEqual(call.tool_call_id, CALL_ID)
        self.assertEqual(call.tool_name, "run_shell_command")
        self.assertEqual(call.tool_input, {"command": "cat .env"})
        self.assertEqual(call.output, "<untrusted_context>\nOutput: API_KEY=%s\n"
                         "Process Group PGID: 48211\n</untrusted_context>" % KEY)
        self.assertIsNone(call.not_after)
        self.assertEqual(call.store, path)
        self.assertEqual(call.source, "gemini")

    def test_message_time_when_the_call_has_none_and_zones_become_utc(self):
        path = self.session("session-a.jsonl", [
            model("m1", [shell("c1", "ls", ts=None)],
                  ts="2026-09-30T10:15:12.900Z"),
            model("m2", [shell("c2", "pwd", ts="2026-09-30T12:15:13.400+02:00")])])
        self.assertEqual([c.timestamp for c in self.calls(path)],
                         ["2026-09-30T10:15:12Z", "2026-09-30T10:15:13Z"])

    def test_a_call_with_no_time_is_bounded_by_the_last_write(self):
        path = self.session("session-a.jsonl", [
            {"id": "m1", "type": "gemini", "toolCalls": [
                {"id": "c1", "name": "run_shell_command",
                 "args": {"command": "ls"}, "status": "success"}]}])
        [call] = self.calls(path)
        self.assertIsNone(call.timestamp)
        self.assertEqual(call.not_after,
                         _stamps.iso_utc(os.stat(path).st_mtime, "s"))

    def test_project_from_projects_json_when_there_is_no_project_root(self):
        path = self.session("session-a.jsonl", [model("m1", [shell("c1", "ls")])])
        self.write("projects.json", text=json.dumps(
            {"projects": {"/Users/alice/other": "other", PROJECT: "proj"}}))
        [call] = self.calls(path)
        self.assertEqual(call.project, PROJECT)

    def test_project_root_file_wins(self):
        path = self.session("session-a.jsonl", [model("m1", [shell("c1", "ls")])])
        self.write("projects.json", text=json.dumps({"projects": {"/x": "proj"}}))
        self.write("tmp/proj/.project_root", text=PROJECT + "\n")
        self.assertEqual(self.calls(path)[0].project, PROJECT)

    def test_a_sha256_folder_maps_to_its_project_through_projects_json(self):
        hexdir = hashlib.sha256(PROJECT.encode("utf-8")).hexdigest()
        self.assertEqual(hexdir, PROJECT_HASH)      # what the header records
        path = self.write("tmp/%s/chats/%s" % (hexdir, FIXTURE_NAME), spec_lines())
        self.write("projects.json", text=json.dumps({"projects": {PROJECT: "proj"}}))
        self.assertEqual(self.calls(path)[0].project, PROJECT)

    def test_an_unknown_sha256_folder_has_no_project(self):
        path = self.write("tmp/%s/chats/%s" % ("ab" * 32, FIXTURE_NAME),
                          spec_lines())
        self.write("projects.json", text="not json")
        self.assertIsNone(self.calls(path)[0].project)

    def test_a_subagent_chat(self):
        sub = "7d6c5b4a-3e2f-4a1b-8c9d-0e1f2a3b4c5d"
        path = self.write("tmp/proj/chats/%s/%s.jsonl" % (SESSION, sub), [
            header(sub, kind="subagent"),
            model("m1", [shell("c1", "cat ~/.aws/credentials")])])
        store = self.store(path)
        self.assertEqual(store.session, sub)
        [call] = self.src.tool_calls(store)
        self.assertEqual(call.session, sub)
        self.assertEqual(_rules(call), [("cred.read", "cat ~/.aws/credentials")])


# --------------------------------------------------------------------------
# 8: dedupe
# --------------------------------------------------------------------------

class Dedupe(GeminiCase):

    def test_the_spec_sample_gives_one_call_with_its_result(self):
        [call] = self.calls(self.fixture())
        self.assertIn("Output: API_KEY=", call.output)

    def test_a_message_reappended_three_times_with_growing_calls(self):
        a0 = shell("ca", "ls -la")
        a1 = shell("ca", "ls -la", output="total 0")
        b0 = shell("cb", "cat ~/.aws/credentials", ts="2026-09-30T10:15:14.000Z")
        b1 = shell("cb", "cat ~/.aws/credentials", ts="2026-09-30T10:15:14.000Z",
                   output="[default]")
        path = self.session("session-a.jsonl", [
            model("m1"), model("m1", [a0]), model("m1", [a1]),
            model("m1", [a1, b0]), model("m1", [a1, b1]),
            results("u1", [a1, b1])])
        calls = self.calls(path)
        self.assertEqual([(c.tool_call_id, c.output) for c in calls],
                         [("ca", "total 0"), ("cb", "[default]")])

    def test_a_call_removed_by_rewind_is_still_reported(self):
        path = self.session("session-a.jsonl", [
            user("u1", "clean up"),
            model("m1", [shell("c1", "rm -rf ~/Documents/x", output="")]),
            {"$rewindTo": "u1"},
            user("u2", "never mind"),
            model("m2", [shell("c2", "ls")])])
        calls = self.calls(path)
        self.assertEqual([c.tool_call_id for c in calls], ["c1", "c2"])
        self.assertEqual(_rules(calls[0]), [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_a_set_messages_list_is_read(self):
        early = shell("c1", "ls", output="a")
        only = shell("c2", "rm -rf ~/Documents/x", output="",
                     ts="2026-09-30T10:16:00.000Z")
        path = self.session("session-a.jsonl", [
            model("m1", [early]),
            {"$set": {"messages": [model("m1", [early]), model("m2", [only])],
                      "lastUpdated": "2026-09-30T10:16:01.000Z"}}])
        calls = self.calls(path)
        self.assertEqual([c.tool_call_id for c in calls], ["c1", "c2"])
        self.assertEqual(calls[1].timestamp, "2026-09-30T10:16:00Z")

    def test_the_same_session_in_a_hash_folder_and_a_slug_folder_once(self):
        hexdir = hashlib.sha256(PROJECT.encode("utf-8")).hexdigest()
        records = [header(), model("m1", [shell("c1", "rm -rf ~/Documents/x")])]
        slug = self.write("tmp/proj/chats/" + FIXTURE_NAME, records)
        copy = self.write("tmp/%s/chats/%s" % (hexdir, FIXTURE_NAME), records)
        self.write("tmp/proj/.project_root", text=PROJECT)
        a, b = self.calls(slug), self.calls(copy)
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0].project, b[0].project)
        self.assertEqual(set(map(_core_key, a + b)), {_core_key(a[0])})


# --------------------------------------------------------------------------
# Historical variants
# --------------------------------------------------------------------------

class Variants(GeminiCase):

    def legacy(self, type_="gemini", key=KEY):
        call = shell("c1", "cat .env", output="API_KEY=" + key)
        return dict(header(), messages=[
            user("u1", "what is in .env?"),
            model("m1", [call], type_=type_)])

    def test_a_legacy_json_session(self):
        path = self.write("tmp/proj/chats/session-2025-06-01T09-00-3f2b8c1e.json",
                          text=json.dumps(self.legacy(), indent=2))
        store = self.store(path)
        self.assertEqual(store.format, "json")
        [call] = self.src.tool_calls(store)
        self.assertEqual((call.session, call.command, call.output),
                         (SESSION, "cat .env", "API_KEY=" + KEY))
        self.assertEqual(_findings(self.src, [store])[KEY]["origins"], {".env"})

    def test_a_legacy_record_on_one_line_of_a_jsonl_file(self):
        path = self.write("tmp/proj/chats/session-a.jsonl", [self.legacy()])
        [call] = self.calls(path)
        self.assertEqual((call.session, call.command), (SESSION, "cat .env"))

    def test_a_legacy_subagent_file_one_folder_down(self):
        path = self.write("tmp/proj/chats/%s/agent.json" % SESSION,
                          text=json.dumps(self.legacy(), indent=2))
        self.assertEqual([c.command for c in self.calls(path)], ["cat .env"])

    def test_collision_suffixed_names(self):
        path = self.write("tmp/proj/chats/session-2026-09-30T10-15-2-3f2b8c1e.jsonl",
                          spec_lines())
        self.assertEqual(len(self.calls(path)), 1)

    def test_the_reader_serves_a_fork_with_another_model_type(self):
        """Qwen Code's v0.3.x files are this legacy JSON with type "qwen"."""
        path = self.write("tmp/proj/chats/session-q.json",
                          text=json.dumps(self.legacy("qwen"), indent=2))
        store = self.store(path)
        # Not Gemini's own type: no calls, but every string is still read.
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertIn(KEY, _findings(self.src, [store]))
        fork = gemini.ChatReader(self.src, model_types=("qwen",))
        [call] = fork.tool_calls(store)
        self.assertEqual((call.kind, call.command), ("shell", "cat .env"))


# --------------------------------------------------------------------------
# 9: secrets
# --------------------------------------------------------------------------

class Secrets(GeminiCase):

    def test_a_key_in_output_after_cat_env(self):
        self.fixture()
        found = _findings(self.src, self.stores())
        self.assertEqual(set(found), {KEY})
        # result, resultDisplay and the repeated functionResponse
        self.assertEqual(found[KEY]["count"], 3)
        self.assertEqual(found[KEY]["origins"], {".env"})
        self.assertEqual(found[KEY]["calls"], {CALL_ID})

    def test_a_key_typed_into_a_command_has_no_origin(self):
        typed = shell("c1", "curl -H 'Authorization: Bearer %s' https://api.example.com"
                      % KEY, output="ok")
        self.session("session-a.jsonl", [model("m1", [typed])])
        found = _findings(self.src, self.stores())
        self.assertEqual(found[KEY]["origins"], set())
        self.assertEqual(found[KEY]["calls"], set())

    def test_superseded_and_rewound_copies_are_read(self):
        self.session("session-a.jsonl", [
            user("u1", "deploy with STRIPE_KEY=" + KEY),
            {"$rewindTo": "u1"},
            model("m1", [shell("c1", "env", output="TOKEN=" + KEY2)]),
            model("m1", [shell("c1", "env", output="TOKEN=<masked>")])])
        self.assertEqual(set(_findings(self.src, self.stores())), {KEY, KEY2})

    def test_a_secret_only_in_a_file_diff(self):
        record = tool_call("c1", "replace",
                           {"file_path": "config.py", "instruction": "use env",
                            "old_string": "KEY = load()", "new_string": "KEY = env()"},
                           output="Successfully modified file: config.py",
                           display={"originalContent": 'STRIPE = "%s"\nKEY = load()\n'
                                    % KEY, "newContent": "KEY = env()\n"})
        self.session("session-a.jsonl", [model("m1", [record])])
        found = _findings(self.src, self.stores())
        self.assertEqual(set(found), {KEY})
        self.assertEqual(found[KEY]["calls"], {"c1"})

    def test_side_stores_are_scanned_and_never_yield_calls(self):
        paths = [
            self.write("tmp/proj/shell_history",
                       text="ls\nexport STRIPE_KEY=%s\n" % KEY),
            self.write("tmp/proj/logs.json", text=json.dumps([
                {"sessionId": SESSION, "messageId": 0,
                 "timestamp": "2026-09-30T10:15:10.500Z", "type": "user",
                 "message": "use " + KEY2}], indent=2)),
            self.write("tmp/proj/checkpoint-save.json", text=json.dumps(
                {"history": [{"role": "user", "parts": [{"text": KEY3}]}]})),
            self.write("tmp/proj/checkpoints/a.json", text=json.dumps(
                {"history": [], "clientHistory": [],
                 "toolCall": {"name": "write_file",
                              "args": {"file_path": "x", "content": KEY4}},
                 "commitHash": "abc", "messageId": "m1"})),
            self.write("tmp/proj/tool-outputs/session-%s/run_shell_command_1.txt"
                       % SESSION, text="TOKEN=%s\n" % KEY5),
            self.write("tmp/background-processes/background-4242.log",
                       text="started\nsecret %s\n" % KEY6)]
        stores = self.stores()
        self.assertEqual(sorted(s.path for s in stores), sorted(paths))
        for store in stores:
            self.assertEqual(list(self.src.tool_calls(store)), [], store.path)
        found = _findings(self.src, stores)
        self.assertEqual(set(found), {KEY, KEY2, KEY3, KEY4, KEY5, KEY6})
        self.assertTrue(all(not f["calls"] and not f["origins"]
                            for f in found.values()))

    def test_a_large_text_file_is_read_past_the_first_megabyte(self):
        line = "x" * 99 + "\n"
        filler = line * ((clean.MAX_STRING // len(line)) + 2000)
        self.write("tmp/background-processes/background-1.log",
                   text=filler + "TOKEN=%s\n" % KEY)
        [store] = self.stores()
        texts = list(self.src.secret_texts(store))
        self.assertGreater(len(texts), 1)
        self.assertTrue(all(len(t.node) <= gemini.TEXT_CHUNK + len(line)
                            for t in texts))
        self.assertEqual(set(_findings(self.src, [store])), {KEY})
        self.assertTrue(texts[-1].where.startswith("lines "))


# --------------------------------------------------------------------------
# 10, 13: masking
# --------------------------------------------------------------------------

def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


class Masking(GeminiCase):

    def round_trip(self, path, value, mode=0o600):
        if not WINDOWS:
            os.chmod(path, mode)
        when = time.time() - 3600
        os.utime(path, (when, when))
        with open(path, "rb") as fh:
            before = fh.read()
        store = self.store(path)
        calls_before = list(self.src.tool_calls(store))
        result = self.src.mask(store, [value])
        self.assertTrue(result.changed, result)
        self.assertIsNone(result.skipped)
        with open(path, "rb") as fh:
            after = fh.read()
        self.assertEqual(after, before.replace(value.encode("utf-8"),
                                               _marker(value).encode("utf-8")))
        for form in _rewrite.encodings(value):
            self.assertNotIn(form.encode("utf-8"), after)
        with open(result.backup, "rb") as fh:
            self.assertEqual(fh.read(), before)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), mode)
        store = self.store(path)
        calls_after = list(self.src.tool_calls(store))
        self.assertEqual([_without_output(c) for c in calls_after],
                         [_without_output(c) for c in calls_before])
        self.assertNotIn(value, _findings(self.src, [store]))
        again = self.src.mask(store, [value])
        self.assertEqual(again, MaskResult(path))
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), after)
        return after, calls_after

    def test_the_spec_sample(self):
        after, [call] = self.round_trip(self.fixture(), KEY)
        for line in after.decode("utf-8").splitlines():
            json.loads(line)
        self.assertIn(_marker(KEY), call.output)

    def test_json_inside_an_output_still_parses(self):
        doc = json.dumps({"api_key": KEY, "region": "eu"})
        path = self.session("session-a.jsonl", [
            model("m1", [shell("c1", "cat config.json", output=doc)])])
        after, _calls = self.round_trip(path, KEY)
        line = json.loads(after.decode("utf-8").splitlines()[1])
        inner = json.loads(line["toolCalls"][0]["result"][0]
                           ["functionResponse"]["response"]["output"])
        self.assertEqual(inner, {"api_key": _marker(KEY), "region": "eu"})

    def test_a_file_diff(self):
        record = tool_call("c1", "replace",
                           {"file_path": "config.py", "old_string": "a",
                            "new_string": "b"},
                           output="ok", display={
                               "originalContent": 'STRIPE = "%s"\n' % KEY,
                               "newContent": "STRIPE = env()\n"})
        path = self.session("session-a.jsonl", [model("m1", [record])])
        after, _calls = self.round_trip(path, KEY)
        line = json.loads(after.decode("utf-8").splitlines()[1])
        self.assertEqual(line["toolCalls"][0]["resultDisplay"]["originalContent"],
                         'STRIPE = "%s"\n' % _marker(KEY))

    def test_a_legacy_json_session(self):
        call = shell("c1", "cat .env", output="API_KEY=" + KEY)
        doc = dict(header(), messages=[model("m1", [call])])
        path = self.write("tmp/proj/chats/session-old.json",
                          text=json.dumps(doc, indent=2))
        after, _calls = self.round_trip(path, KEY, mode=0o644)
        json.loads(after.decode("utf-8"))

    def test_side_stores(self):
        history = self.write("tmp/proj/shell_history",
                             text="ls\nexport STRIPE_KEY=%s\n" % KEY)
        logs = self.write("tmp/proj/logs.json", text=json.dumps(
            [{"sessionId": SESSION, "messageId": 0, "type": "user",
              "timestamp": "2026-09-30T10:15:10.500Z", "message": KEY2}]))
        self.round_trip(history, KEY)
        self.round_trip(logs, KEY2)

    def test_a_file_written_recently_is_in_use(self):
        path = self.fixture(age=5)
        digest = _sha(path)
        result = self.src.mask(self.store(path), [KEY])
        self.assertEqual(result, MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))


# --------------------------------------------------------------------------
# 12: files that do not parse
# --------------------------------------------------------------------------

class Unparsable(GeminiCase):

    def run_all(self):
        err = io.StringIO()
        calls = []
        with contextlib.redirect_stderr(err):
            for store in self.stores():
                calls += list(self.src.tool_calls(store))
                list(self.src.secret_texts(store))
        return calls, err.getvalue()

    def test_a_truncated_last_line(self):
        path = self.fixture()
        with open(path, "ab") as fh:
            fh.write(b'{"id":"6c1e0f3a-1b2c-4d5e-8f90-a1b2c3d4e5f4","timest')
        calls, err = self.run_all()
        self.assertEqual(len(calls), 1)
        self.assertEqual(err, "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_bad_line_is_counted_once_and_the_rest_read(self):
        lines = spec_lines()
        self.write("tmp/proj/chats/" + FIXTURE_NAME,
                   lines[:3] + ["not json {"] + lines[3:])
        calls, err = self.run_all()
        self.assertEqual(len(calls), 1)
        self.assertEqual(err, "")
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_garbage_warns_once_and_the_other_stores_are_read(self):
        self.fixture()
        self.write("tmp/proj/chats/session-garbage.jsonl",
                   data=b"\x00\xff\xfe garbage \x80\n" * 50)
        self.write("tmp/proj/chats/session-broken.json", text='{"sessionId": ')
        calls, err = self.run_all()
        self.assertEqual(len(calls), 1)
        self.assertEqual(err.count("warning:"), 2)
        self.assertIn("session-garbage.jsonl", err)
        self.assertIn("session-broken.json", err)
        self.assertNotIn("\u2014", err)
        self.assertEqual(self.src.counts["unreadable_stores"], 2)
        self.assertEqual(self.src.unreadable, {"did not parse": 2})
        self.src.reset()
        _calls, err = self.run_all()
        self.assertEqual(err.count("warning:"), 2)     # once per run

    def test_unknown_records_are_ignored_and_counted(self):
        lines = spec_lines()
        self.write("tmp/proj/chats/" + FIXTURE_NAME, lines[:2] + [
            '{"kind":"telemetry","value":1}', "[1,2,3]", '"text"'] + lines[2:])
        calls, err = self.run_all()
        self.assertEqual(len(calls), 1)
        self.assertEqual(err, "")
        self.assertEqual(self.src.counts["unknown"], 3)

    def test_a_store_that_cannot_be_opened_warns_once(self):
        gone = Store("gemini", os.path.join(self.root, "tmp", "p", "chats",
                                            "session-gone.jsonl"), "jsonl")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(gone)), [])
            self.assertEqual(list(self.src.secret_texts(gone)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertEqual(self.src.unreadable, {"could not be opened": 1})

    def test_an_empty_file_is_nothing(self):
        self.write("tmp/proj/chats/session-new.jsonl", text="")
        self.write("tmp/proj/chats/session-new.json", text="")
        calls, err = self.run_all()
        self.assertEqual((calls, err), ([], ""))


# Python 3.9's json stops near 1,000 levels. 3.14's parses past 100,000
# (on a 16 MB stack), and then comparing the value overflows the stack near
# 42,000 levels and writing it out near 62,000.
DEPTHS = (5000, 50000, 100000)


def deep(depth):
    """JSON text an object `depth` levels deep, built as a string: building
    it as an object would take the recursion it is there to test."""
    return '{"a":' * depth + "1" + "}" * depth


def parses(text):
    """Whether this Python's json can read `text`."""
    try:
        json.loads(text)
    except RecursionError:
        return False
    return True


def _values(nodes):
    """Every value clean finds in these nodes."""
    found = set()
    for node in nodes:
        clean._walk(node, lambda value, *_: found.add(value))
    return found


class DeepNesting(GeminiCase):
    """JSON nested deeper than the stack is read where this Python can read
    it, and is otherwise what a line or file that does not parse is. It
    never stops the rest of its file, the other files, or the run."""

    def deep_lines(self, records, depth):
        """Each record as a chat line, with "@DEEP@" made deep(depth)."""
        return [_dump(r).replace('"@DEEP@"', deep(depth)) for r in records]

    def read_all(self):
        err = io.StringIO()
        calls, nodes = [], []
        with contextlib.redirect_stderr(err):
            for store in self.stores():
                calls += list(self.src.tool_calls(store))
                nodes += [t.node for t in self.src.secret_texts(store)]
        return calls, nodes, err.getvalue()

    def test_a_line_nested_past_the_stack_is_skipped_and_the_rest_read(self):
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self.src.reset()
                odd = [deep(depth), "[" * depth + "]" * depth]
                lines = spec_lines()
                self.write("tmp/proj/chats/" + FIXTURE_NAME,
                           lines[:3] + odd + lines[3:])
                calls, nodes, err = self.read_all()
                self.assertEqual([c.tool_call_id for c in calls], [CALL_ID])
                self.assertIn(KEY, _values(nodes))
                self.assertEqual(err, "")
                unparsed = sum(not parses(line) for line in odd)
                self.assertEqual(self.src.counts["unparsed"], unparsed)
                self.assertEqual(self.src.counts["unknown"], 2 - unparsed)

    def test_a_call_nested_past_the_stack_is_read_or_skipped_and_counted(self):
        """Read like any other call where its line parses; skipped and
        counted where it does not. Input held as a JSON string always
        parses as a line, and is kept as its text where it is too deep."""
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self.src.reset()
                given = tool_call("c2", "run_shell_command",
                                  {"command": "cat .env", "env": "@DEEP@"},
                                  output="API_KEY=" + KEY2)
                shown = shell("c3", "ls", output="@DEEP@", display="@DEEP@")
                lines = self.deep_lines([
                    header(),
                    model("m1", [shell("c1", "cat .env", output="API_KEY=" + KEY)]),
                    model("m2", [given]), model("m3", [shown]),
                    model("m4", [tool_call("c4", "write_file", deep(depth),
                                           output="ok")])], depth)
                path = self.write("tmp/proj/chats/session-a.jsonl", lines)
                calls, nodes, err = self.read_all()
                read = [parses(line) for line in lines]
                self.assertEqual([c.tool_call_id for c in calls],
                                 [i for i, ok in zip(("c1", "c2", "c3", "c4"),
                                                     read[1:]) if ok])
                self.assertEqual([c.store for c in calls], [path] * len(calls))
                found = _values(nodes)
                self.assertIn(KEY, found)
                self.assertEqual(KEY2 in found, read[2])
                self.assertEqual(self.src.counts["unparsed"], read.count(False))
                self.assertEqual(err, "")

    def test_a_whole_file_nested_past_the_stack_and_the_rest_read(self):
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self.src.reset()
                self.fixture()
                text = deep(depth)
                for rel in ("tmp/proj/chats/session-old.json", "tmp/proj/logs.json",
                            "tmp/proj/checkpoint-x.json", "projects.json"):
                    self.write(rel, text=text)
                calls, nodes, err = self.read_all()
                self.assertEqual([(c.tool_call_id, c.project) for c in calls],
                                 [(CALL_ID, PROJECT)])
                self.assertIn(KEY, _values(nodes))
                if parses(text):
                    # A legacy session of no shape it knows; side files whole.
                    self.assertEqual((self.src.counts["unknown"],
                                      self.src.unreadable, err), (1, {}, ""))
                else:
                    self.assertEqual(self.src.unreadable, {"did not parse": 3})
                    self.assertEqual(err.count("warning:"), 3)

    def test_a_terminal_grid_beside_a_value_nested_past_the_stack_is_masked_or_refused(self):
        """A key cut across a grid's rows is masked by writing its line out
        again. Where that overflows the stack the file is refused,
        unchanged; a line too deep to parse at all, or to walk once read,
        is masked as raw text, as any line that does not parse. The next
        file is masked either way."""
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                record = shell("c1", "cat .env", output=untrusted(LINE),
                               display=grid([LINE]))
                plain = self.session("session-plain.jsonl",
                                     [model("m1", [dict(record)])])
                record["description"] = "@DEEP@"
                lines = self.deep_lines([header(), model("m1", [record])], depth)
                path = self.write("tmp/proj/chats/session-deep.jsonl", lines)
                digest = _sha(path)
                result = self.src.mask(self.store(path), [LONG])
                # Where writing it out overflows depends on how much of the C
                # stack is in use, not on the depth alone: either outcome
                # holds, never a secret left in a file that changed.
                if result.changed:
                    with open(path, "rb") as fh:
                        self.assertNotIn(LONG.encode("utf-8"), fh.read())
                else:
                    self.assertTrue(parses(lines[1]), result)
                    self.assertEqual(result,
                                     MaskResult(path, skipped=_rewrite.ALTERED))
                    self.assertEqual(_sha(path), digest)
                self.assertTrue(self.src.mask(self.store(plain), [LONG]).changed)


# --------------------------------------------------------------------------
# 14: the --days window
# --------------------------------------------------------------------------

class Window(GeminiCase):

    def test_calls_keep_their_own_time(self):
        path = self.session("session-a.jsonl", [
            model("m1", [shell("old", "ls", ts="2025-01-02T03:04:05.000Z")],
                  ts="2025-01-02T03:04:00.000Z"),
            {"id": "m2", "type": "gemini", "toolCalls": [
                {"id": "undated", "name": "run_shell_command",
                 "args": {"command": "pwd"}, "status": "success"}]}], age=60)
        [store] = self.stores(since_days=30)       # written recently: kept
        self.assertEqual(store.path, path)
        old, undated = self.src.tool_calls(store)
        cutoff = time.time() - 30 * 86400
        when, _zoned = _stamps.parse_stamp(old.timestamp)
        self.assertLess(when.timestamp(), cutoff)  # the core drops it
        self.assertIsNone(undated.timestamp)       # kept, counted undated
        bound, _zoned = _stamps.parse_stamp(undated.not_after)
        self.assertGreater(bound.timestamp(), cutoff)


# --------------------------------------------------------------------------
# Calls that never ran
# --------------------------------------------------------------------------

class Declined(GeminiCase):

    def statuses(self, records, reader=None):
        path = self.session("session-a.jsonl", records)
        reader = reader or self.src
        return {c.tool_call_id: c for c in reader.tool_calls(self.store(path))}

    def test_a_call_the_user_denied_is_declined(self):
        record = cancelled("c1", "run_shell_command",
                           {"command": "rm -rf ~/Documents/x"}, DENIED)
        call = self.statuses([model("m1", [record])])["c1"]
        self.assertEqual((call.status, call.actor, call.output),
                         ("declined", "agent", None))
        # Still reported; the core says it did not run.
        self.assertEqual(_rules(call), [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_the_calls_queued_behind_a_denial_never_ran_either(self):
        """scheduler.ts: a denial cancels the calls still queued in the
        batch, with their own reason; a call that already ran keeps its
        status."""
        calls = self.statuses([model("m1", [
            shell("c1", "ls", output="a.txt"),
            cancelled("c2", "run_shell_command", {"command": "rm -rf build"},
                      DENIED),
            cancelled("c3", "write_file", {"file_path": "a.txt",
                                           "content": "x"}, QUEUED)])])
        self.assertEqual({k: c.status for k, c in calls.items()},
                         {"c1": None, "c2": "declined", "c3": "declined"})

    def test_a_call_cancelled_any_other_way_is_left_alone(self):
        records = [
            # Ctrl+C while it ran: the executor keeps what it printed.
            cancelled("c1", "run_shell_command", {"command": "rm -rf build"},
                      STOPPED, output="removed build/a.o"),
            # cancelAll: every active call, running ones included.
            cancelled("c2", "run_shell_command", {"command": "rm -rf dist"},
                      ABORTED),
            # An abort before the call started (scheduler.ts). It did not
            # run either, but nobody declined it.
            cancelled("c3", "run_shell_command", {"command": "rm -rf out"},
                      "[Operation Cancelled] Reason: Operation cancelled"),
            # No result to say why.
            shell("c4", "rm -rf tmp", status="cancelled"),
            # The words, with a status that is not "cancelled".
            dict(cancelled("c5", "run_shell_command", {"command": "ls"}, DENIED),
                 status="error"),
            dict(cancelled("c6", "run_shell_command", {"command": "ls"}, DENIED),
                 status="success")]
        calls = self.statuses([model("m1", records)])
        self.assertEqual({c.status for c in calls.values()}, {None})
        self.assertEqual(calls["c1"].output, "removed build/a.o")

    def test_a_denial_synced_into_a_call_that_ran_stays_with_its_own_call(self):
        ran = shell("c1", "cat .env", output="API_KEY=" + KEY)
        denied = cancelled("c2", "run_shell_command", {"command": "rm -rf ~"},
                           DENIED)
        calls = self.statuses(synced([ran, denied]))
        self.assertEqual((calls["c1"].status, calls["c1"].output),
                         (None, "API_KEY=" + KEY))
        self.assertEqual(calls["c2"].status, "declined")

    def test_a_reader_for_a_fork_can_leave_status_alone(self):
        record = cancelled("c1", "run_shell_command", {"command": "ls"}, DENIED)
        fork = gemini.ChatReader(self.src, declined=None)
        self.assertIsNone(self.statuses([model("m1", [record])], fork)["c1"].status)


# --------------------------------------------------------------------------
# Results after a history sync
# --------------------------------------------------------------------------

class SiblingResults(GeminiCase):
    """After a history sync, each call made in parallel has the whole user
    turn as its result: its siblings' responses too."""

    def records(self):
        ca = shell("ca", "cat .env", output="API_KEY=" + KEY)
        cb = tool_call("cb", "read_file", {"file_path": "notes.txt"},
                       output="token " + KEY2)
        return synced([ca, cb])

    def test_each_call_keeps_its_own_output(self):
        path = self.session("session-a.jsonl", self.records())
        self.assertEqual([(c.tool_call_id, c.output) for c in self.calls(path)],
                         [("ca", "API_KEY=" + KEY), ("cb", "token " + KEY2)])

    def test_clean_credits_each_output_to_its_own_call(self):
        self.session("session-a.jsonl", self.records())
        found = _findings(self.src, self.stores())
        self.assertEqual(set(found), {KEY, KEY2})
        self.assertEqual((found[KEY]["origins"], found[KEY]["calls"]),
                         ({".env"}, {"ca"}))
        self.assertEqual((found[KEY2]["origins"], found[KEY2]["calls"]),
                         (set(), {"cb"}))
        # ca's result, the turn, and in the sync: both results and the turn.
        self.assertEqual((found[KEY]["count"], found[KEY2]["count"]), (5, 5))

    def test_a_part_with_no_id_of_its_own(self):
        """Alone with its call's response it is that call's; beside a
        sibling's response it could be either's, and is no call's."""
        note = {"text": "note " + KEY3}
        ca = shell("ca", "cat .env", output="API_KEY=" + KEY)
        ca["result"].append(note)
        alone = self.session("session-a.jsonl", [model("m1", [ca])])
        found = _findings(self.src, [self.store(alone)])
        self.assertEqual((found[KEY3]["origins"], found[KEY3]["calls"]),
                         ({".env"}, {"ca"}))
        cb = tool_call("cb", "read_file", {"file_path": "notes.txt"}, output="x")
        shared = dict(ca, result=ca["result"] + cb["result"])
        path = self.session("session-b.jsonl", [model("m1", [shared, cb])])
        found = _findings(self.src, [self.store(path)])
        self.assertEqual((found[KEY3]["origins"], found[KEY3]["calls"]),
                         (set(), set()))
        self.assertEqual(found[KEY]["calls"], {"ca"})

    def test_a_response_for_a_call_not_in_the_file_has_no_call(self):
        ca = shell("ca", "cat .env", output="API_KEY=" + KEY)
        ca["result"].append(response_part("gone", "read_file", "token " + KEY2))
        path = self.session("session-a.jsonl", [model("m1", [ca])])
        found = _findings(self.src, [self.store(path)])
        self.assertEqual((found[KEY2]["origins"], found[KEY2]["calls"]),
                         (set(), set()))
        self.assertEqual(self.calls(path)[0].output, "API_KEY=" + KEY)


# --------------------------------------------------------------------------
# Sessions from before v0.14.0
# --------------------------------------------------------------------------

class LegacyArguments(GeminiCase):
    """v0.13.0 tools/read-file.ts {absolute_path, offset?, limit?} and
    tools/shell.ts {command, description?, directory?}; v0.14.0 renamed
    them file_path and dir_path."""

    def one(self, record):
        path = self.session("session-a.jsonl", [model("m1", [record])])
        [call] = self.calls(path)
        return call

    def test_read_file_absolute_path(self):
        call = self.one(tool_call("c1", "read_file", {
            "absolute_path": "/Users/alice/.ssh/id_rsa", "offset": 0, "limit": 20}))
        self.assertEqual((call.kind, call.paths, call.consumed),
                         ("read", ("/Users/alice/.ssh/id_rsa",),
                          frozenset({"absolute_path"})))
        self.assertEqual(_rules(call), [("cred.read", "/Users/alice/.ssh/id_rsa")])

    def test_run_shell_command_directory(self):
        call = self.one(tool_call("c1", "run_shell_command", {
            "command": "rm -rf build", "description": "clean",
            "directory": "/Users/alice/proj/web"}))
        self.assertEqual((call.command, call.workdir, call.consumed),
                         ("rm -rf build", "/Users/alice/proj/web",
                          frozenset({"command"})))
        self.assertEqual(call.tool_input["directory"], "/Users/alice/proj/web")

    def test_the_current_key_comes_first(self):
        call = self.one(tool_call("c1", "read_file", {
            "file_path": "README.md", "absolute_path": "/x/README.md"}))
        self.assertEqual((call.paths, call.consumed),
                         (("README.md",), frozenset({"file_path"})))

    def test_a_v0_13_session_left_in_its_sha256_folder(self):
        hexdir = hashlib.sha256(PROJECT.encode("utf-8")).hexdigest()
        doc = dict(header(), messages=[model("m1", [
            tool_call("c1", "read_file", {"absolute_path": "/Users/alice/.ssh/id_rsa"},
                      output="x"),
            tool_call("c2", "run_shell_command",
                      {"command": "cat ~/.aws/credentials", "directory": "/etc"},
                      output="x")])])
        path = self.write("tmp/%s/chats/session-2025-08-01T09-00-3f2b8c1e.json"
                          % hexdir, text=json.dumps(doc, indent=2))
        self.write("projects.json", text=json.dumps({"projects": {PROJECT: "proj"}}))
        read, run = self.calls(path)
        self.assertEqual((read.project, run.project), (PROJECT, PROJECT))
        self.assertEqual(_rules(read), [("cred.read", "/Users/alice/.ssh/id_rsa")])
        self.assertEqual((run.workdir, _rules(run)),
                         ("/etc", [("cred.read", "cat ~/.aws/credentials")]))


# --------------------------------------------------------------------------
# Terminal output (AnsiOutput)
# --------------------------------------------------------------------------

# A key longer than a terminal row once its name is in front of it.
LONG = ("sk_" "live_" "51NzQ8vR2mT6yLp4WcN0sXe7HbJHc3nW7pQ1xVb9TzK5mRd2LsFTy6uB0e"
        "S8kMj3QaX7wNc4GvPLm2fD9rH5pZx1VbT8n")
LINE = "STRIPE_SECRET_KEY=" + LONG


def private_key(lines=6):
    """A synthetic private key: 70-column body lines, shorter than a row."""
    body = [hashlib.sha512(b"gemini-%d" % n).hexdigest()[:70] for n in range(lines)]
    return "\n".join(["-----BEGIN " "OPENSSH PRIVATE KEY-----"] + body
                     + ["-----END " "OPENSSH PRIVATE KEY-----"])


def _texts(rows):
    return [[t["text"] for t in row] for row in rows]


class AnsiText(unittest.TestCase):

    def test_rows_are_joined_back_into_lines(self):
        self.assertGreater(len(LINE), 80)
        rows = grid(["$ cat .env", LINE, "", "done"])
        self.assertEqual(_texts(rows)[1:3], [[LINE[:80]], [LINE[80:], " " * (160 - len(LINE))]])
        self.assertEqual(gemini.ansi_text(rows), "$ cat .env\n%s\n\ndone\n" % LINE)

    def test_a_row_that_ends_blank_or_unwritten_ends_its_line(self):
        rows = [[token("a" * 79 + " ")], [token("b"), token(" " * 79, True)],
                [token("c" * 79), token(" ", True)], [token("d"), token(" " * 79, True)]]
        self.assertEqual(gemini.ansi_text(rows), "a" * 79 + "\nb\n" + "c" * 79 + "\nd")

    def test_a_line_exactly_as_wide_as_the_terminal_joins_the_next(self):
        # The grid does not say which rows wrapped: a known limit.
        self.assertEqual(gemini.ansi_text(grid(["x" * 80, "y"])), "x" * 80 + "y\n")

    def test_tokens_from_before_isUninitialized(self):
        rows = [[{"text": LINE[:80], "bold": False}],
                [{"text": LINE[80:]}, {"text": "   "}]]
        self.assertEqual(gemini.ansi_text(rows), LINE)

    def test_not_a_grid(self):
        for value in ("text", [], [[]], [["x"]], [[{"text": 1}]],
                      {"originalContent": "a", "newContent": "b"}, None):
            self.assertIsNone(gemini.ansi_text(value), value)


class TerminalGrids(GeminiCase):

    def session_with(self, display, output=None, command="cat .env", **kw):
        record = shell("c1", command, output=output, display=display)
        return self.session("session-a.jsonl", [model("m1", [record])], **kw), record

    def masked(self, path, values):
        store = self.store(path)
        with open(path, "rb") as fh:
            before = fh.read()
        result = self.src.mask(store, values)
        with open(path, "rb") as fh:
            after = fh.read()
        return before, result, after

    def test_clean_reads_the_lines_that_were_printed(self):
        """Not the 62-character piece of the key on the first row."""
        self.session_with(grid([LINE]), output=untrusted(LINE))
        found = _findings(self.src, self.stores())
        self.assertEqual(set(found), {LONG})
        self.assertEqual((found[LONG]["count"], found[LONG]["origins"],
                          found[LONG]["calls"]), (2, {".env"}, {"c1"}))

    def test_a_grid_is_the_output_when_there_is_no_result(self):
        path, _record = self.session_with(grid(["$ cat .env", LINE]))
        [call] = self.calls(path)
        self.assertEqual(call.output, "$ cat .env\n%s\n" % LINE)

    def test_a_key_cut_at_the_edge_of_the_terminal_is_masked(self):
        path, record = self.session_with(grid([LINE]), output=untrusted(LINE))
        if not WINDOWS:
            os.chmod(path, 0o640)
        calls_before = self.calls(path)
        before, result, after = self.masked(path, [LONG])
        self.assertTrue(result.changed, result)
        self.assertIsNone(result.skipped)
        marker = _marker(LONG)
        expect = json.loads(json.dumps(record))
        expect["result"][0]["functionResponse"]["response"]["output"] = \
            untrusted("STRIPE_SECRET_KEY=" + marker)
        rows = expect["resultDisplay"]
        rows[0][0]["text"] = "STRIPE_SECRET_KEY=" + marker
        rows[1][0]["text"] = ""
        self.assertEqual(after.decode("utf-8"), "".join(
            _dump(r) + "\n" for r in (header(), model("m1", [expect]))))
        for form in _rewrite.encodings(LONG) + [LONG[:62], LONG[62:]]:
            self.assertNotIn(form.encode("utf-8"), after)
        with open(result.backup, "rb") as fh:
            self.assertEqual(fh.read(), before)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
        store = self.store(path)
        self.assertEqual(_findings(self.src, [store]), {})
        self.assertEqual([_without_output(c) for c in self.src.tool_calls(store)],
                         [_without_output(c) for c in calls_before])
        self.assertEqual(self.src.mask(store, [LONG]), MaskResult(path))

    def test_a_key_split_by_colour_inside_a_row(self):
        """grep --color highlights the match: a new token mid key."""
        cut = LONG.index("live")
        line = [token("3:STRIPE_SECRET_KEY=" + LONG[:cut]),
                token("live", bold=True, fg="#cd0000"),
                token(LONG[cut + 4:40])]
        path, _record = self.session_with(grid([line]))
        self.assertEqual(set(_findings(self.src, self.stores())), {LONG[:40]})
        _before, result, after = self.masked(path, [LONG[:40]])
        self.assertTrue(result.changed, result)
        rows = json.loads(after.decode("utf-8").splitlines()[1])[
            "toolCalls"][0]["resultDisplay"]
        self.assertEqual(_texts(rows)[0][:3],
                         ["3:STRIPE_SECRET_KEY=" + _marker(LONG[:40]), "", ""])
        self.assertEqual(rows[0][1]["fg"], "#cd0000")

    def test_a_private_key_over_many_rows(self):
        pem = private_key()
        path, _record = self.session_with(
            grid(["$ cat ~/.ssh/id_ed25519"] + pem.split("\n")),
            output=untrusted(pem), command="cat ~/.ssh/id_ed25519")
        found = _findings(self.src, self.stores())
        self.assertEqual(set(found), {pem})
        self.assertEqual(found[pem]["origins"], {"~/.ssh/id_ed25519"})
        _before, result, after = self.masked(path, [pem])
        self.assertTrue(result.changed, result)
        for line in pem.split("\n"):
            self.assertNotIn(line.encode("utf-8"), after)
        rows = json.loads(after.decode("utf-8").splitlines()[1])[
            "toolCalls"][0]["resultDisplay"]
        self.assertEqual(gemini.ansi_text(rows), "$ cat ~/.ssh/id_ed25519\n%s%s\n"
                         % (_marker(pem), "\n" * pem.count("\n")))
        self.assertEqual(_findings(self.src, [self.store(path)]), {})

    def test_a_key_in_one_token_is_masked_raw(self):
        path, _record = self.session_with(grid(["API_KEY=" + KEY]),
                                          output=untrusted("API_KEY=" + KEY))
        before, result, after = self.masked(path, [KEY])
        self.assertTrue(result.changed, result)
        self.assertEqual(after, before.replace(KEY.encode("utf-8"),
                                               _marker(KEY).encode("utf-8")))

    def test_a_legacy_json_session(self):
        record = shell("c1", "cat .env", output=untrusted(LINE), display=grid([LINE]))
        doc = dict(header(), messages=[model("m1", [record])])
        path = self.write("tmp/proj/chats/session-old.json",
                          text=json.dumps(doc, indent=2, ensure_ascii=False))
        _before, result, after = self.masked(path, [LONG])
        self.assertTrue(result.changed, result)
        rows = record["resultDisplay"]
        rows[0][0]["text"] = "STRIPE_SECRET_KEY=" + _marker(LONG)
        rows[1][0]["text"] = ""
        record["result"][0]["functionResponse"]["response"]["output"] = \
            untrusted("STRIPE_SECRET_KEY=" + _marker(LONG))
        self.assertEqual(after.decode("utf-8"),
                         json.dumps(doc, indent=2, ensure_ascii=False))

    def test_a_line_the_cli_would_not_have_written_is_refused(self):
        """Written back, it would not be the same bytes (here, escapes
        JSON.stringify never writes), so nothing is changed, not even the
        copies raw replacement could reach."""
        record = shell("c1", "cat .env", output=untrusted(LINE), display=grid([LINE]))
        record["description"] = "cat .env (caf\u00e9)"
        path = self.write("tmp/proj/chats/session-a.jsonl", text="".join(
            json.dumps(r, separators=(",", ":")) + "\n"
            for r in (header(), model("m1", [record]))))
        with open(path, "rb") as fh:
            self.assertIn(b"caf\\u00e9", fh.read())
        digest = _sha(path)
        _before, result, _after = self.masked(path, [LONG])
        self.assertEqual(result, MaskResult(path, skipped=_rewrite.ALTERED))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))
        # The same line as the CLI writes it is masked.
        self.write("tmp/proj/chats/session-a.jsonl", [header(), model("m1", [record])])
        self.assertTrue(self.masked(path, [LONG])[1].changed)

    def test_a_file_written_recently_is_in_use(self):
        path, _record = self.session_with(grid([LINE]), age=5)
        digest = _sha(path)
        self.assertEqual(self.masked(path, [LONG])[1],
                         MaskResult(path, skipped=_rewrite.IN_USE))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))


# --------------------------------------------------------------------------
# Background command logs
# --------------------------------------------------------------------------

class BackgroundLogs(GeminiCase):

    def log(self, pid, age=600):
        return self.write("tmp/background-processes/background-%d.log" % pid,
                          text="started\nAPI_KEY=%s\n" % KEY, age=age)

    def test_the_log_of_a_running_process_is_in_use(self):
        proc = subprocess.Popen([sys.executable, "-c",
                                 "import time; time.sleep(60)"])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        path = self.log(proc.pid)
        store = self.store(path)
        self.assertTrue(self.src.in_use(store))
        digest = _sha(path)
        self.assertEqual(self.src.mask(store, [KEY]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))
        proc.kill()
        proc.wait()
        self.assertFalse(self.src.in_use(store))
        self.assertTrue(self.src.mask(store, [KEY]).changed)

    def test_no_other_store_is_in_use_by_its_name(self):
        with mock.patch.object(gemini, "_pid_alive", return_value=True):
            for rel in ("tmp/proj/chats/session-1234.jsonl",
                        "tmp/proj/tool-outputs/background-1234.log.txt",
                        "tmp/proj/shell_history"):
                path = self.write(rel, text="{}\n")
                self.assertFalse(self.src.in_use(self.store(path)), rel)
            self.assertTrue(self.src.in_use(self.store(self.log(1234))))

    def test_a_process_id_no_process_can_have(self):
        with mock.patch.object(gemini.os, "kill",
                               side_effect=AssertionError("os.kill")):
            for pid in (0, 2 ** 40):
                self.assertFalse(gemini._pid_alive(pid), pid)

    def test_posix_asks_with_signal_zero(self):
        with mock.patch.object(gemini, "_WINDOWS", False):
            for error, alive in ((None, True), (ProcessLookupError(), False),
                                 (PermissionError(), True), (OSError(), True)):
                with mock.patch.object(gemini.os, "kill",
                                       side_effect=error) as kill:
                    self.assertEqual(gemini._pid_alive(4242), alive, error)
                kill.assert_called_once_with(4242, 0)

    def test_windows_asks_tasklist_and_never_os_kill(self):
        found = b'"node.exe","4242","Console","1","51,200 K"\r\n'
        none = b"INFO: No tasks are running which match the specified criteria.\r\n"
        cases = ((subprocess.CompletedProcess([], 0, found, b""), True),
                 (subprocess.CompletedProcess([], 0, none, b""), False),
                 (subprocess.CompletedProcess([], 1, b"", b"denied"), True),
                 (OSError("no tasklist"), True),
                 (subprocess.TimeoutExpired("tasklist", 10), True))
        with mock.patch.object(gemini, "_WINDOWS", True), \
                mock.patch.object(gemini.os, "kill",
                                  side_effect=AssertionError("os.kill on Windows")):
            for outcome, alive in cases:
                with mock.patch.object(gemini.subprocess, "run",
                                       side_effect=[outcome]) as run:
                    self.assertEqual(gemini._pid_alive(4242), alive, outcome)
                argv = run.call_args[0][0]
                self.assertEqual(argv[1:], ["/FI", "PID eq 4242", "/NH", "/FO", "CSV"])
                self.assertEqual(run.call_args[1]["timeout"], 10)


# --------------------------------------------------------------------------
# A large file: how reading it grows, on its own interpreter (tests/growth.py)
# --------------------------------------------------------------------------

# Every turn: a prompt, the model message, the same message again with its
# call and a 2 KB result, the repeated result, and a $set.
TURNS = 6000

_CALL = r"""
from ranwhat.sources import gemini
def call(root):
    src = gemini.GeminiSource()
    [store] = src.stores(src.locations(override=root))
    calls = sum(1 for _ in src.tool_calls(store))
    texts = sum(1 for _ in src.secret_texts(store))
    return [calls, texts]
"""


class LargeFile(GeminiCase):

    BIG = os.path.join("tmp", "proj", "chats", "session-big.jsonl")

    def session(self, n):
        """A .gemini root whose one session has n(TURNS) turns."""
        root = os.path.join(tempfile.mkdtemp(prefix="big-", dir=self.home),
                            ".gemini")
        out = os.path.join(root, self.BIG)
        os.makedirs(os.path.dirname(out))
        blob = ("drwxr-xr-x  12 alice staff  384 Sep 30 10:15 src\n" * 40)[:2048]
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_dump(header()) + "\n")
            for i in range(n(TURNS)):
                ts = "2026-09-30T10:%02d:%02d.000Z" % (i // 60 % 60, i % 60)
                call = shell("c%d" % i, "ls -la src/%d" % i, output=blob, ts=ts)
                for record in (user("u%d" % i, "list it", ts=ts),
                               model("m%d" % i, ts=ts),
                               model("m%d" % i, [call], ts=ts),
                               results("r%d" % i, [call], ts=ts),
                               {"$set": {"lastUpdated": ts}}):
                    fh.write(_dump(record) + "\n")
        return root

    def test_a_large_session_is_read_in_time(self):
        env = dict(os.environ, HOME=self.home, USERPROFILE=self.home,
                   GEMINI_CLI_HOME=self.home)
        measured, root = growth.measure_apart(self.session, _CALL, env=env)
        size = os.path.getsize(os.path.join(root, self.BIG))
        self.assertGreater(size, 20 * 1024 * 1024)
        growth.assert_linear(self, measured, "%.1f MB" % (size / 1e6))
        calls, texts = measured.result
        self.assertEqual(calls, TURNS)
        self.assertGreater(texts, TURNS * 4)


if __name__ == "__main__":
    unittest.main()
