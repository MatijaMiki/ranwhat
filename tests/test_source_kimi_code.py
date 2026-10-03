"""The Kimi Code CLI adapter, id "kimi-code" (design section 7.8).

Fixtures are built field for field from the sample in the spec: a
session_index.jsonl line and a wire.jsonl event journal (metadata line,
then context.append_message and context.append_loop_event records with a
millisecond "time"). Records the spec does not show are built from their
writers in MoonshotAI/kimi-code at 21406fb (packages/agent-core-v2/src
unless named):

- spill files and their pointer lines: toolResultTruncation/
  toolResultTruncationService.ts (tool-results/<stem>-<uuid>.txt, the
  "output_path:" and "next_step:" lines), tools/os/bash/bashTool.ts and
  task/persist.ts, task/taskService.ts (tasks/<taskId>/output.log, the
  main agent's older session-level tasks/), tools/task/task-output/
  taskOutputTool.ts with task/tools/format.ts (TaskOutput's fields);
- approval answers: permissionRules/permissionRulesOps.ts and
  toolApproval/toolApprovalService.ts;
- shell mode: shellCommand/shellCommandService.ts, _base/utils/xml-escape.ts;
- sessions migrated from the Python Kimi CLI (protocol 1.0):
  packages/migration-legacy/src/sessions/wire-writer.ts, translator.ts and
  turn-structure.ts;
- the loop engine's journal: agent/loop/machine/storeJournal.ts,
  human/eventStore/events.ts, human/agent/events.ts and historySchema.ts,
  and upstream's own wire snapshot in test/agent/loop/loop.test.ts (a
  record holds a history entry {message, meta}, the message one level
  down);
- context.clear, context.undo and context.apply_compaction:
  agent/contextMemory/contextEvents.ts;
- ids that come back on a new call: human/llm/toolCallIdNormalizer.ts and
  agent/llmRequester/llmRequesterService.ts (unique only against ids the
  process has seen, seeded once from the current context), with Kimi K2's
  ids functions.<name>:<n> (MoonshotAI/Kimi-K2
  docs/tool_call_guidance.md);
- where an approval answer goes: agent/toolApproval/toolApprovalService.ts
  records it before agent/toolExecutor/toolExecutorService.ts dispatches
  the call's tool.call event, a vetoed call too;
- the folder layout: docs/en/configuration/data-locations.md, and
  logs rotated by _base/log/fileLog.ts with logConfig.ts.

Paths in pointer lines are written with forward slashes, as Kimi Code's
pathe joins write them on every OS. Values are synthetic, and every secret
is written as adjacent literals so a scanner reading the repository does not
take a fixture for a leak.

Everything runs in temp directories: the home directory, KIMI_CODE_HOME and
clean's backup root are all pointed there. The timing check runs in a
subprocess with a 20 s timeout.
"""
import base64
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
from ranwhat.sources import _paths, _rewrite, _stamps  # noqa: E402
from ranwhat.sources.base import MaskResult, Source  # noqa: E402
from ranwhat.sources.kimi_code import KimiCodeSource  # noqa: E402

SECRET = "sk_" "live_" "Kc4vR8mT2yLp6WcN1sXe9HbQ"
TYPED = "ghp_" "Vb7Nq2Lx9Rk4Wd8Ys3Hf6Jm1Tc5Pz0Ga2Ue"
SIDE = "sk_" "live_" "Hs3pX7qD1vN9rB5wK2mF8tLc"
# Every character JSON escapes differently at one and two levels of
# nesting: a quote, a backslash, non-ASCII, & < > and U+2028.
PASSWORD = "pw" '"' "\\" "\u00e4" "&<>" "\u2028" "Kq7" "zW3m"

# What Kimi Code keeps for itself: never a finding, never opened.
OWN_KEY = "sk-" "kimi-" "Zq8Lr2Vt6Np4Hx1Wm9Kd3Bf7"
OWN_TOKEN = "ghp_" "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78"

WORK_DIR = "/Users/me/proj"
KEY = "wd_proj_0123456789ab"
SID = "s_example01"
T0 = 1790000000000              # ms: 2026-09-21T14:13:20Z
UUID = "3f2b8c1e-9d4a-4e6b-8a7c-1d2e3f4a5b6c"   # crypto.randomUUID()
TASK = "bash-k3x9q2m7"          # generateTaskId("bash")

WINDOWS = os.name == "nt"

# A private key spread over lines, as a log would hold it: found whole only
# if the lines of a text file are searched together. The body is random-
# looking bytes from a hash chain, nothing that was ever a key.
_BODY = base64.b64encode(b"".join(
    hashlib.sha256(bytes([i])).digest() for i in range(40))).decode("ascii")
_PEM = ("-----BEGIN " "RSA PRIVATE KEY-----\n"
        + "\n".join(_BODY[i:i + 64] for i in range(0, len(_BODY), 64))
        + "\n-----END " "RSA PRIVATE KEY-----\n")


def _j(obj):
    """One line as the Node writer leaves it: compact, non-ASCII as is."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _meta(t=T0):
    return {"type": "metadata", "protocol_version": "1.5", "created_at": t}


def _user(text, t):
    return {"type": "context.append_message", "agentId": "main",
            "message": {"role": "user",
                        "content": [{"type": "text", "text": text}],
                        "toolCalls": []},
            "time": t}


def _step(n, t):
    return {"type": "context.append_loop_event", "agentId": "main",
            "event": {"type": "step.begin", "uuid": "step-%d" % n,
                      "turnId": "1", "step": n},
            "time": t}


def _call(cid, name, args, t, n=1, agent="main"):
    return {"type": "context.append_loop_event", "agentId": agent,
            "event": {"type": "tool.call", "uuid": "uuid-" + cid,
                      "turnId": "1", "step": n, "stepUuid": "step-%d" % n,
                      "toolCallId": cid, "name": name, "args": args},
            "time": t}


def _result(cid, output, t, agent="main", is_error=False):
    return {"type": "context.append_loop_event", "agentId": agent,
            "event": {"type": "tool.result", "parentUuid": "uuid-" + cid,
                      "toolCallId": cid,
                      "result": {"output": output, "isError": is_error,
                                 "durationMs": 12}},
            "time": t}


def _approval(cid, decision, t, tool="Bash", feedback=None):
    """permission.record_approval_result, written before the call's
    tool.call event."""
    result = {"decision": decision}
    if feedback is not None:
        result["feedback"] = feedback
    return {"type": "permission.record_approval_result", "agentId": "main",
            "turnId": 1, "toolCallId": cid, "toolName": tool,
            "action": "run command", "result": result, "time": t}


def _not_run(tool, decision):
    """The result Kimi Code records for a call whose approval said no."""
    if decision == "cancelled":
        return ('Tool "%s" was not run because the approval request was '
                'cancelled.' % tool)
    return ('Tool "%s" was not run because the user rejected the approval '
            'request.' % tool)


def _interrupted(tool):
    """The result Kimi Code fills in for a call the user interrupted
    (toolExecutorService.ts abortedToolOutput)."""
    return ('The user manually interrupted "%s" (and anything else running '
            'at the same time). This was a deliberate user action, not a '
            'system error, timeout, or capacity limit. Do not retry '
            'automatically or guess at the cause \u2014 wait for the user\'s '
            'next instruction.' % tool)


def _escape_xml(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _shell_in(command, t):
    """A command the user typed in shell mode."""
    return {"type": "context.append_message", "agentId": "main",
            "message": {"role": "user",
                        "content": [{"type": "text", "text": "<bash-input>\n"
                                     + _escape_xml(command)
                                     + "\n</bash-input>"}],
                        "toolCalls": [],
                        "origin": {"kind": "shell_command", "phase": "input"}},
            "time": t}


def _shell_out(stdout, stderr, t, is_error=False):
    origin = {"kind": "shell_command", "phase": "output"}
    if is_error:
        origin["isError"] = True
    text = ("<bash-stdout>" + _escape_xml(stdout) + "</bash-stdout><bash-stderr>"
            + _escape_xml(stderr) + "</bash-stderr>")
    return {"type": "context.append_message", "agentId": "main",
            "message": {"role": "user", "content": [{"type": "text", "text": text}],
                        "toolCalls": [], "origin": origin},
            "time": t}


# The meta of a history entry, per role, as upstream's wire snapshot shows
# it (test/agent/loop/loop.test.ts at 21406fb).
_ENGINE_META = {
    "assistant": {"model": {"provider": "agent-loop", "model": "agent-loop"},
                  "source": "llm",
                  "usage": {"inputOther": 4, "output": 16, "inputCacheRead": 0,
                            "inputCacheCreation": 0},
                  "finish": {"finishReason": "tool_calls",
                             "rawFinishReason": "tool_calls"},
                  "messageId": "mock-1"},
    "tool": {"source": "tool"},
}


def _engine(message, t):
    """The loop engine's journal copy of a message: the message.appended
    event {message: <history entry>, type, time} (human/agent/events.ts,
    human/eventStore/events.ts), written by storeJournal.ts with the record
    type "agent.message.appended" and kind "event". A history entry is
    {message, meta} (historySchema.ts), so the message is one level down."""
    return {"message": {"message": message,
                        "meta": _ENGINE_META.get(message.get("role"), {})},
            "type": "agent.message.appended", "time": t, "kind": "event"}


def _clear(t):
    """context.clear, {agentId} (contextEvents.ts)."""
    return {"type": "context.clear", "agentId": "main", "time": t}


def _undo(count, t):
    """context.undo, {agentId, count} (contextEvents.ts)."""
    return {"type": "context.undo", "agentId": "main", "count": count, "time": t}


def _compaction(t):
    """context.apply_compaction, {agentId, summary, compactedCount}, the
    first of its three shapes (contextEvents.ts)."""
    return {"type": "context.apply_compaction", "agentId": "main",
            "summary": "The user listed the folder.", "compactedCount": 3,
            "time": t}


# Kimi K2's id for the first Bash call of the conversation it sees.
K2_ID = "functions.Bash:0"


def _posix(path):
    """A path as Kimi Code writes one: forward slashes on every OS."""
    return path.replace(os.sep, "/")


def _persisted_pointer(tool, cid, path, total=60000):
    """A result whose whole output went to a file (no media parts)."""
    return "\n".join([
        "Tool output exceeded 50000 characters; the full output was saved "
        "to a file.",
        "tool_name: " + tool,
        "tool_call_id: " + cid,
        "output_size_chars: %d" % total,
        "output_path: " + _posix(path),
        "next_step: Use Read with output_path to page through the saved "
        "output, or Grep to search it.",
        "",
        "[preview: chars [0, 6)]",
        "line 1",
    ])


def _appended_pointer(path):
    """A result shortened line by line, its whole text saved to a file."""
    return "\n".join([
        "[Per-line truncation occurred; the complete output was saved to a "
        "file.",
        "output_path: " + _posix(path),
        "next_step: Use Read with output_path to page through the saved "
        "output, or Grep to search it.]",
    ])


def _task_output(task, path, size):
    """TaskOutput's result: task record fields as "snake_key: value"
    lines, then the preview."""
    return "\n".join(["retrieval_status: success", "task_id: " + task,
                      "output_path: " + _posix(path),
                      "output_size_bytes: %d" % size, "", "[output]", "done"])


def _assistant(tool_calls, t, text="Working on it."):
    """An assistant message; tool_calls is [(id, name, arguments)] with
    arguments a JSON string or None."""
    return {"type": "context.append_message", "agentId": "main",
            "message": {"role": "assistant",
                        "content": [{"type": "text", "text": text}],
                        "toolCalls": [{"type": "function", "id": cid,
                                       "name": name, "arguments": arguments}
                                      for cid, name, arguments in tool_calls]},
            "time": t}


def _sample():
    """The spec's fixture, record for record, with a synthetic key."""
    return [
        _meta(),
        _user("show me the env file", T0 + 100),
        _step(1, T0 + 200),
        _call("call_1", "Bash", {"command": "cat .env"}, T0 + 1500),
        _result("call_1", "API_KEY=" + SECRET + "\n", T0 + 1900),
    ]


def _judge(call):
    """watch.judge when the integration has added it; until then the same
    function as design 3.5 writes it, over watch.evaluate."""
    judge = getattr(watch, "judge", None)
    if judge is not None:
        return judge(call)
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


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _deep(depth=100000):
    """JSON objects nested `depth` deep, built as text, since json.dumps
    would need the recursion this is here to test. Python 3.9's parser
    refuses it; 3.14's accepts it, and then comparing it does not fit."""
    return '{"a":' * depth + "1" + "}" * depth


def _parses(text):
    try:
        json.loads(text)
    except RecursionError:
        return False
    return True


class KimiCodeCase(unittest.TestCase):
    """A temp home, KIMI_CODE_HOME unset, and a temp backup root."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="kimicode-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        env = mock.patch.dict(os.environ, {"HOME": self.home,
                                           "USERPROFILE": self.home})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("KIMI_CODE_HOME", None)
        p = mock.patch.object(_paths, "home", return_value=self.home)
        p.start()
        self.addCleanup(p.stop)
        self.backups = os.path.join(tempfile.mkdtemp(prefix="kimicode-bk-"), "b")
        self.addCleanup(shutil.rmtree, os.path.dirname(self.backups), True)
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.root = os.path.join(self.home, ".kimi-code")
        self.src = KimiCodeSource()

    # -- building a home ----------------------------------------------------

    def _write(self, path, data, age=3600, mode=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(data, list):
            data = "".join(_j(r) + "\n" for r in data)
        if isinstance(data, str):
            data = data.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
        if mode is not None and not WINDOWS:
            os.chmod(path, mode)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def _session_dir(self, sid=SID, key=KEY, root=None):
        return os.path.join(root or self.root, "sessions", key, sid)

    def _wire(self, records, sid=SID, key=KEY, agent="main", age=3600,
              root=None, mode=None):
        path = os.path.join(self._session_dir(sid, key, root), "agents",
                            agent, "wire.jsonl")
        return self._write(path, records, age=age, mode=mode)

    def _index(self, rows, root=None):
        root = root or self.root
        lines = [{"sessionId": sid, "sessionDir": self._session_dir(sid, key, root),
                  "workDir": work_dir} for sid, key, work_dir in rows]
        return self._write(os.path.join(root, "session_index.jsonl"), lines)

    def _tool_results(self, tool, cid, agent="main", sid=SID, uuid=UUID):
        """Where a long result of `tool` goes: <stem>-<uuid>.txt, the stem
        "<tool>-<call id>" with anything outside [A-Za-z0-9._-] made "_"."""
        stem = "".join(c if c.isalnum() or c in "._-" else "_"
                       for c in "%s-%s" % (tool, cid))
        return os.path.join(self._session_dir(sid), "agents", agent,
                            "tool-results", "%s-%s.txt" % (stem, uuid))

    def _task_log(self, task=TASK, agent="main", sid=SID):
        """A task's full output; agent None is the main agent's older,
        session-level place."""
        base = self._session_dir(sid)
        if agent is not None:
            base = os.path.join(base, "agents", agent)
        return os.path.join(base, "tasks", task, "output.log")

    def _own_files(self):
        """Files Kimi Code keeps for itself, at the places its docs and
        writers put them, each holding a value that would be a finding if
        it were ever read. {name: path}."""
        sdir = self._session_dir()
        files = {
            "config": (os.path.join(self.root, "config.toml"),
                       '[providers.kimi]\napi_key = "%s"\n' % OWN_KEY),
            "mcp": (os.path.join(self.root, "mcp.json"),
                    _j({"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": OWN_TOKEN}}}})),
            "credentials": (os.path.join(self.root, "credentials", "kimi-code.json"),
                            _j({"token": OWN_KEY})),
            "mcp_credentials": (os.path.join(self.root, "credentials", "mcp",
                                             "gh-0a1b2c3d.json"),
                                _j({"token": OWN_TOKEN})),
            "goals": (os.path.join(sdir, "upcoming-goals.json"),
                      _j([{"objective": "rotate " + OWN_KEY}])),
            "plan": (os.path.join(sdir, "agents", "main", "plans", "plan_1.md"),
                     "# Plan\nexport KEY=" + OWN_KEY + "\n"),
            "task": (os.path.join(sdir, "tasks", TASK + ".json"),
                     _j({"taskId": TASK, "command": "export K=" + OWN_KEY})),
            "agent_task": (os.path.join(sdir, "agents", "main", "tasks",
                                        TASK + ".json"),
                           _j({"taskId": TASK, "command": "export K=" + OWN_KEY})),
        }
        return dict((name, self._write(path, data))
                    for name, (path, data) in files.items())

    def _stores(self, **kw):
        return self.src.stores(self.src.locations(), **kw)

    def _store(self, path):
        [store] = [s for s in self._stores() if s.path == path]
        return store

    def _calls(self, path):
        return list(self.src.tool_calls(self._store(path)))

    def _read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def _backups(self):
        return [os.path.join(d, f) for d, _s, files in os.walk(self.backups)
                for f in files]

    def _findings(self, stores):
        """{value: set of origins} the way clean credits them (design 3.6):
        a file the store says it is, else the paths the producing call's
        input names (consumed keys replaced by the command), else none."""
        found = {}
        for store in stores:
            for st in self.src.secret_texts(store):
                origin = None
                if st.attached:
                    origin = st.attached
                elif st.call is not None:
                    call = st.call
                    rest = {k: v for k, v in call.tool_input.items()
                            if k not in call.consumed}
                    if call.command:
                        rest["command"] = call.command
                    named = clean._origins(json.dumps(rest, ensure_ascii=False))
                    origin = named[-1] if named else None

                def collect(value, label, _in=None, _copies=None, origin=origin):
                    entry = found.setdefault(value, set())
                    if origin:
                        entry.add(origin)
                clean._walk(st.node, collect)
        return found


# --------------------------------------------------------------------------
# 1, 2: where it looks
# --------------------------------------------------------------------------

class DefaultPaths(KimiCodeCase):

    def test_every_platform(self):
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.kimi-code", "default")])
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.kimi-code", "default")])
        self.assertEqual(self.src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.kimi-code", "default")])

    def test_kimi_code_home_replaces_the_default(self):
        env = {"KIMI_CODE_HOME": "/srv/kimi"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/srv/kimi", "env KIMI_CODE_HOME")])
        env = {"KIMI_CODE_HOME": "D:\\kimi"}
        self.assertEqual(self.src.default_paths(env, "C:\\Users\\u", "win32"),
                         [("D:\\kimi", "env KIMI_CODE_HOME")])
        self.assertEqual(self.src.default_paths({"KIMI_CODE_HOME": ""},
                                                "/home/u", "linux"),
                         [("/home/u/.kimi-code", "default")])

    def test_pure(self):
        with mock.patch("os.stat", side_effect=AssertionError("stat")), \
                mock.patch("os.path.exists", side_effect=AssertionError("exists")):
            self.src.default_paths({}, "/nowhere/u", "darwin")
            self.src.default_paths({"KIMI_CODE_HOME": "/x"}, "C:\\n", "win32")

    def test_what_reports_need(self):
        for field in ("id", "name", "unit", "path_means", "checked"):
            self.assertTrue(getattr(self.src, field), field)
        self.assertEqual(self.src.id, "kimi-code")
        self.assertEqual(self.src.env, ("KIMI_CODE_HOME",))
        self.assertIsInstance(self.src, Source)
        for field in ("name", "path_means"):
            self.assertNotIn("\u2014", getattr(self.src, field))

    def test_the_override_is_read_at_call_time(self):
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (self.root, "default", False, 0))
        moved = os.path.join(self.home, "elsewhere")
        self._wire(_sample(), root=moved)
        os.environ["KIMI_CODE_HOME"] = moved        # after construction
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (moved, "env KIMI_CODE_HOME", True, 1))

    def test_path_override(self):
        moved = os.path.join(self.home, "k")
        wire = self._wire(_sample(), root=moved)
        locs = self.src.locations(override="~/k")
        self.assertEqual([(l.path, l.how, l.found) for l in locs],
                         [(moved, "--path", 1)])
        self.assertEqual([s.path for s in self.src.stores(locs)], [wire])


# --------------------------------------------------------------------------
# 3: discovery
# --------------------------------------------------------------------------

class Discovery(KimiCodeCase):

    def _home(self):
        """Every file the spec lists, the rotated parts of both logs, and
        every file Kimi Code keeps for itself (see _own_files)."""
        made = {}
        made["main"] = self._wire(_sample(), age=60)
        made["sub"] = self._wire([_meta(), _call("sub_1", "Read", {"path": "a.py"},
                                                 T0 + 10, agent="agent-1")],
                                 agent="agent-1", age=120)
        made["other"] = self._wire(_sample(), sid="s_other", key="wd_lib_abcdef012345",
                                   age=7200)
        sdir = self._session_dir()
        made["state"] = self._write(os.path.join(sdir, "state.json"), _j(
            {"title": "env", "lastPrompt": "show me the env file"}), age=30)
        made["slog"] = self._write(os.path.join(sdir, "logs", "kimi-code.log"),
                                   "started\n", age=90)
        made["slog1"] = self._write(os.path.join(sdir, "logs", "kimi-code.log.1"),
                                    "earlier\n", age=100)
        made["log"] = self._write(os.path.join(self.root, "logs", "kimi-code.log"),
                                  "boot\n", age=10)
        made["log1"] = self._write(os.path.join(self.root, "logs", "kimi-code.log.1"),
                                   "boot before\n", age=15)
        digest = hashlib.md5(WORK_DIR.encode("utf-8")).hexdigest()
        made["history"] = self._write(
            os.path.join(self.root, "user-history", digest + ".jsonl"),
            [{"content": "show me the env file"}], age=20)
        self._index([(SID, KEY, WORK_DIR)])
        # A task's full output and a long result's spill file are stores
        # only when a transcript names them (see Spills).
        self._write(self._task_log(), "API_KEY=" + SIDE + "\n")
        self._write(self._tool_results("Bash", "call_1"), "API_KEY=" + SIDE + "\n")
        made.update(("own_" + k, v) for k, v in self._own_files().items())
        return made

    def test_stores_newest_first_with_roles_and_formats(self):
        made = self._home()
        got = [(s.path, s.format, s.role) for s in self._stores()]
        self.assertEqual(got, [
            (made["log"], "text", "side"),
            (made["log1"], "text", "side"),
            (made["history"], "jsonl", "side"),
            (made["state"], "json", "side"),
            (made["main"], "jsonl", "transcript"),
            (made["slog"], "text", "side"),
            (made["slog1"], "text", "side"),
            (made["sub"], "jsonl", "transcript"),
            (made["other"], "jsonl", "transcript"),
        ])
        for store in self._stores():
            self.assertEqual((store.source, store.unit, store.masking),
                             ("kimi-code", "session", "rewrite"))
        [loc] = self.src.locations()
        self.assertEqual(loc.found, 9)

    def test_rotated_logs_are_searched(self):
        """Both logs rotate: the global one keeps .1 to .4, a session's
        .1 and .2. A name that is not the log or a numbered part is not."""
        sdir = self._session_dir()
        logs = [self._write(os.path.join(self.root, "logs", "kimi-code.log.%d" % n),
                            "debug: env K%d=%s\n" % (n, SECRET), age=100 + n)
                for n in range(1, 5)]
        logs += [self._write(os.path.join(sdir, "logs", "kimi-code.log.%d" % n),
                             "debug: env K=%s\n" % SIDE, age=200 + n)
                 for n in (1, 2)]
        for name in ("kimi-code.log.old", "kimi-code.log.1.gz", "other.log",
                     "kimi-code.log.tmp"):
            self._write(os.path.join(self.root, "logs", name), "TOKEN=" + TYPED + "\n")
        stores = self._stores()
        self.assertEqual([s.path for s in stores], logs)
        self.assertEqual(set(s.session for s in stores[4:]), {SID})
        self.assertEqual(set(s.session for s in stores[:4]), {None})
        self.assertEqual(set(self._findings(stores)), {SECRET, SIDE})

    def test_the_index_and_files_kimi_code_keeps_for_itself_are_not_stores(self):
        made = self._home()
        paths = [s.path for s in self._stores()]
        self.assertNotIn(os.path.join(self.root, "session_index.jsonl"), paths)
        for name, path in made.items():
            if name.startswith("own_"):
                self.assertNotIn(path, paths)
        self.assertNotIn(self._task_log(), paths)
        self.assertNotIn(self._tool_results("Bash", "call_1"), paths)

    def test_files_kimi_code_keeps_for_itself_are_never_opened(self):
        """Not even when a tool result names each of them after
        "output_path:", as a fetched page, a cat or a grep of the folder
        can: config.toml and mcp.json hold the agent's own provider keys
        and MCP tokens, and masking them would break its login."""
        made = self._home()
        own = dict((k, v) for k, v in made.items() if k.startswith("own_"))
        page = "".join("output_path: %s\n" % _posix(path)
                       for path in sorted(own.values()))
        self._wire(_sample() + [
            _call("call_9", "FetchURL", {"url": "https://example.invalid/"},
                  T0 + 3000),
            _result("call_9", "page text\n" + page, T0 + 3100),
            _call("call_10", "Grep", {"pattern": "output_path"}, T0 + 3200),
            _result("call_10", [{"type": "text", "text": page}], T0 + 3300),
        ], age=60)
        before = dict((path, _sha(path)) for path in own.values())
        opened, listed = [], []
        real_open, real_scandir = builtins.open, os.scandir

        def spy_open(file, *a, **kw):
            opened.append(os.fspath(file) if not isinstance(file, int) else "")
            return real_open(file, *a, **kw)

        def spy_scandir(path="."):
            listed.append(os.fspath(path))
            return real_scandir(path)

        with mock.patch("builtins.open", spy_open), \
                mock.patch("os.scandir", spy_scandir):
            stores = self._stores()
            found = self._findings(stores)
            for store in stores:
                list(self.src.tool_calls(store))
                self.src.mask(store, [OWN_KEY, OWN_TOKEN])
        self.assertTrue(opened)
        never = [os.path.realpath(p) for p in own.values()]
        never_dirs = [os.path.realpath(os.path.join(self.root, "credentials")),
                      os.path.realpath(os.path.join(self._session_dir(), "tasks")),
                      os.path.realpath(os.path.join(self._session_dir(), "agents",
                                                    "main", "plans"))]
        for path in opened + listed:
            real = os.path.realpath(path)
            self.assertNotIn(real, never, path)
            for folder in never_dirs:
                self.assertFalse(real.startswith(folder), path)
        self.assertNotIn(OWN_KEY, found)
        self.assertNotIn(OWN_TOKEN, found)
        for path, digest in before.items():
            self.assertEqual(_sha(path), digest, path)
            self.assertNotIn(path, [s.path for s in stores])
        self.assertTrue(os.path.exists(made["main"]))

    def test_a_missing_root_is_no_stores(self):
        self.assertEqual(self._stores(), [])
        self.assertEqual(self.src.stores(self.src.locations(override="~/nope")), [])
        self.assertEqual(set(self.src.counts.values()), {0})

    def test_days_prefilter_by_mtime(self):
        self._wire(_sample(), age=60)
        old = self._wire(_sample(), sid="s_old", age=90 * 86400)
        paths = [s.path for s in self._stores(since_days=30)]
        self.assertNotIn(old, paths)
        self.assertEqual(len(paths), 1)


# --------------------------------------------------------------------------
# 4 to 6: tool calls, judged
# --------------------------------------------------------------------------

class Actions(KimiCodeCase):

    def _one(self, name, args):
        path = self._wire([_meta(), _call("c1", name, args, T0 + 10)])
        [call] = self._calls(path)
        return call

    def _rules(self, call):
        hits, _payload = _judge(call)
        return [(h["rule"], h["evidence"]) for h in hits]

    def test_dangerous_shell_calls_are_flagged_with_their_target(self):
        call = self._one("Bash", {"command": "rm -rf ~/Documents/x",
                                  "description": "clean up"})
        self.assertEqual((call.kind, call.known, call.command, call.consumed),
                         ("shell", True, "rm -rf ~/Documents/x",
                          frozenset(["command"])))
        [(rule, evidence)] = self._rules(call)
        self.assertEqual(rule, "fs.destructive")
        self.assertIn("~/Documents/x", evidence)
        call = self._one("Bash", {"command": "cat ~/.aws/credentials",
                                  "timeout": 60})
        [(rule, evidence)] = self._rules(call)
        self.assertEqual(rule, "cred.read")
        self.assertIn("~/.aws/credentials", evidence)

    def test_a_credential_read_by_the_read_tool_is_flagged(self):
        call = self._one("Read", {"path": "~/.ssh/id_rsa", "line_offset": 1,
                                  "n_lines": 200})
        self.assertEqual((call.kind, call.paths, call.consumed),
                         ("read", ("~/.ssh/id_rsa",), frozenset(["path"])))
        [(rule, evidence)] = self._rules(call)
        self.assertEqual(rule, "cred.read")
        self.assertIn("~/.ssh/id_rsa", evidence)

    def test_precision_carries_over(self):
        for args in ({"command": "grep -rn 'rm -rf' ."},
                     {"command": "cat > clean.sh <<'EOF'\nrm -rf /\nEOF"}):
            self.assertEqual(self._rules(self._one("Bash", args)), [], args)
        write = self._one("Write", {"path": "clean.sh", "content": "rm -rf /\n",
                                    "mode": "overwrite"})
        self.assertEqual((write.kind, write.paths, write.consumed),
                         ("write", ("clean.sh",), frozenset()))
        self.assertEqual(self._rules(write), [])
        edit = self._one("Edit", {"path": "run.sh", "old_string": "ls",
                                  "new_string": "rm -rf /", "replace_all": False})
        self.assertEqual((edit.kind, edit.paths), ("write", ("run.sh",)))
        self.assertEqual(self._rules(edit), [])
        grep = self._one("Grep", {"pattern": "cat ~/.aws/credentials"})
        self.assertEqual((grep.kind, grep.known), ("other", True))
        self.assertEqual(self._rules(grep), [])

    def test_the_cwd_of_a_shell_call_is_its_workdir(self):
        call = self._one("Bash", {"command": "rm -rf build", "cwd": "/w/proj",
                                  "run_in_background": False})
        self.assertEqual(call.workdir, "/w/proj")
        self.assertIn("cwd", call.tool_input)
        self.assertNotIn("cwd", call.consumed)

    def test_every_tool_the_spec_names(self):
        kinds = {"Bash": "shell", "Read": "read", "Write": "write",
                 "Edit": "write", "FetchURL": "fetch", "WebSearch": "fetch",
                 "Grep": "other", "Glob": "other", "ReadMediaFile": "other",
                 "Agent": "other", "AgentSwarm": "other", "TaskOutput": "other",
                 "CronCreate": "other"}
        records = [_meta()] + [_call("c%d" % i, name, {}, T0 + i)
                               for i, name in enumerate(sorted(kinds))]
        path = self._wire(records)
        got = {c.tool_name: (c.kind, c.known) for c in self._calls(path)}
        self.assertEqual(got, {n: (k, True) for n, k in kinds.items()})

    def test_a_name_it_does_not_know_is_judged_by_name(self):
        call = self._one("mcp__box__bash", {"command": "rm -rf ~/Documents/x"})
        self.assertEqual((call.kind, call.known, call.command),
                         ("other", False, None))
        [(rule, _evidence)] = self._rules(call)
        self.assertEqual(rule, "fs.destructive")
        # names match exactly: "bash" is not Kimi Code's Bash tool
        call = self._one("bash", {"command": "ls"})
        self.assertEqual((call.kind, call.known), ("other", False))

    def test_a_shell_call_without_a_command_is_not_a_command(self):
        call = self._one("Bash", {"description": "rm -rf ~/Documents/x"})
        self.assertEqual((call.kind, call.command, call.consumed),
                         ("shell", None, frozenset()))
        self.assertEqual(self._rules(call), [])


# --------------------------------------------------------------------------
# 7: time, session, project
# --------------------------------------------------------------------------

class TimeSessionProject(KimiCodeCase):

    def test_the_spec_sample(self):
        self._index([(SID, KEY, WORK_DIR)])
        path = self._wire(_sample())
        [call] = self._calls(path)
        self.assertEqual(call.timestamp, "2026-09-21T14:13:21Z")
        self.assertEqual(_stamps.iso_utc(T0 + 1500, "ms"), call.timestamp)
        self.assertEqual((call.session, call.project, call.not_after),
                         (SID, WORK_DIR, None))
        self.assertEqual((call.source, call.store, call.tool_name,
                          call.tool_call_id, call.actor, call.status),
                         ("kimi-code", path, "Bash", "call_1", "agent", None))
        self.assertEqual(call.output, "API_KEY=" + SECRET + "\n")

    def test_a_sub_agent_is_read_under_its_session(self):
        self._index([(SID, KEY, WORK_DIR)])
        path = self._wire([_meta(), _call("sub_1", "Bash", {"command": "make"},
                                          T0 + 5, agent="agent-2")],
                          agent="agent-2")
        [call] = self._calls(path)
        self.assertEqual((call.session, call.project, call.command),
                         (SID, WORK_DIR, "make"))

    def test_a_session_missing_from_the_index_has_no_project(self):
        self._index([("s_someone_else", KEY, "/elsewhere")])
        [call] = self._calls(self._wire(_sample()))
        self.assertEqual((call.session, call.project), (SID, None))
        os.remove(os.path.join(self.root, "session_index.jsonl"))
        self.src.reset()
        [call] = self._calls(self._wire(_sample()))
        self.assertIsNone(call.project)

    def test_a_work_dir_with_a_lone_surrogate_hides_nothing(self):
        """JSON keeps an unpaired UTF-16 surrogate as an escape, and a
        Windows folder name can hold one. One such index line must not
        hide every session. Its prompt history is named by the md5 Node
        gives it, which hashes U+FFFD for the surrogate: the digest below
        is node's crypto.createHash("md5") of this path."""
        node_md5 = "ec36c1a86d15d881b1431609485d5007"
        self.assertEqual(hashlib.md5("C:/Users/u/proj\ufffd".encode("utf-8"))
                         .hexdigest(), node_md5)
        self._write(os.path.join(self.root, "session_index.jsonl"),
                    '{"sessionId":"s0","sessionDir":"C:/x",'
                    '"workDir":"C:/Users/u/proj\\ud800"}\n'
                    + _j({"sessionId": SID, "sessionDir": self._session_dir(),
                          "workDir": WORK_DIR}) + "\n")
        wire = self._wire([_meta(), _call("c1", "Bash",
                                          {"command": "rm -rf ~/Documents/x"}, T0)])
        hist = self._write(os.path.join(self.root, "user-history",
                                         node_md5 + ".jsonl"), [{"content": "hi"}])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            [loc] = self.src.locations()
            stores = self.src.stores([loc])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(loc.found, 2)
        projects = {s.path: s.project for s in stores}
        self.assertEqual(projects, {wire: WORK_DIR, hist: "C:/Users/u/proj\ud800"})
        [call] = self.src.tool_calls(self._store(wire))
        self.assertEqual(_judge(call)[0][0]["rule"], "fs.destructive")

    def test_prompt_history_maps_to_its_project_by_md5(self):
        self._index([(SID, KEY, WORK_DIR)])
        digest = hashlib.md5(WORK_DIR.encode("utf-8")).hexdigest()
        known = self._write(os.path.join(self.root, "user-history",
                                         digest + ".jsonl"), [{"content": "hi"}])
        other = self._write(os.path.join(self.root, "user-history",
                                         "0" * 32 + ".jsonl"), [{"content": "x"}])
        got = {s.path: s.project for s in self._stores()}
        self.assertEqual((got[known], got[other]), (WORK_DIR, None))


# --------------------------------------------------------------------------
# 8: dedupe, and every record shape the spec lists
# --------------------------------------------------------------------------

class RecordShapes(KimiCodeCase):

    def test_a_call_in_an_event_and_in_a_message_is_reported_once(self):
        path = self._wire([
            _meta(),
            _assistant([("call_1", "Bash", _j({"command": "cat .env"}))], T0 + 1000),
            _call("call_1", "Bash", {"command": "cat .env"}, T0 + 1500),
            _result("call_1", "ok", T0 + 1900),
            _assistant([("call_1", "Bash", _j({"command": "cat .env"}))], T0 + 2000),
        ])
        [call] = self._calls(path)
        self.assertEqual((call.tool_call_id, call.command, call.timestamp,
                          call.output),
                         ("call_1", "cat .env", "2026-09-21T14:13:21Z", "ok"))

    def test_the_event_wins_over_the_message_copy(self):
        path = self._wire([
            _meta(),
            _assistant([("call_1", "Bash", _j({"command": "echo draft"}))], T0 + 1000),
            _call("call_1", "Bash", {"command": "echo ran"}, T0 + 1500),
        ])
        [call] = self._calls(path)
        self.assertEqual(call.command, "echo ran")

    def test_a_call_only_in_a_message_is_read_from_its_arguments(self):
        path = self._wire([
            _meta(),
            _assistant([("call_7", "Bash", _j({"command": "cat ~/.aws/credentials"})),
                        ("call_8", "Glob", None),
                        ("call_9", "Bash", "{not json")], T0 + 1000),
        ])
        calls = {c.tool_call_id: c for c in self._calls(path)}
        self.assertEqual(calls["call_7"].command, "cat ~/.aws/credentials")
        self.assertEqual(calls["call_7"].timestamp, "2026-09-21T14:13:21Z")
        self.assertEqual(_judge(calls["call_7"])[0][0]["rule"], "cred.read")
        self.assertEqual((calls["call_8"].kind, calls["call_8"].tool_input),
                         ("other", {}))
        self.assertEqual((calls["call_9"].command, calls["call_9"].tool_input),
                         (None, {"_raw": "{not json"}))

    def test_a_replayed_call_is_reported_once_with_its_first_time(self):
        path = self._wire([
            _meta(),
            _call("call_1", "Bash", {"command": "ls"}, T0 + 10),
            _call("call_1", "Bash", {"command": "ls"}, T0 + 5000),
            _result("call_1", "a\n", T0 + 20), _result("call_1", "b\n", T0 + 30)])
        [call] = self._calls(path)
        self.assertEqual((call.output, call.timestamp),
                         ("a\n", "2026-09-21T14:13:20Z"))

    def test_calls_on_abandoned_branches_are_still_reported(self):
        path = self._wire([
            _meta(),
            _call("call_1", "Bash", {"command": "rm -rf ~/Documents/x"}, T0 + 10),
            {"type": "context.undo", "time": T0 + 20},
            {"type": "context.apply_compaction", "time": T0 + 30},
            {"type": "context.clear", "time": T0 + 40},
            {"type": "turn.prompt", "time": T0 + 50},
            {"type": "permission.record_approval_result", "time": T0 + 55},
            {"type": "agent.switched", "time": T0 + 60},
            {"type": "forked", "time": T0 + 70},
            {"type": "usage.record", "time": T0 + 80},
            _call("call_2", "Bash", {"command": "ls"}, T0 + 90),
        ])
        calls = self._calls(path)
        self.assertEqual([c.tool_call_id for c in calls], ["call_1", "call_2"])
        self.assertEqual([c.status for c in calls], [None, None])
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_output_as_a_string_or_content_parts(self):
        path = self._wire([
            _meta(),
            _call("a", "Bash", {"command": "cat .env"}, T0 + 1),
            _result("a", [{"type": "text", "text": "one"},
                          {"type": "image_url", "imageUrl": {"url": "x"}},
                          {"type": "text", "text": "two"}], T0 + 2),
            _call("b", "ReadMediaFile", {"path": "p.png"}, T0 + 3),
            _result("b", [{"type": "image_url", "imageUrl": {"url": "y"}}], T0 + 4),
            _call("c", "Bash", {"command": "sleep 99"}, T0 + 5),
        ])
        calls = {c.tool_call_id: c for c in self._calls(path)}
        self.assertEqual(calls["a"].output, "one\ntwo")
        self.assertIsNone(calls["b"].output)
        self.assertIsNone(calls["c"].output)

    def test_optional_fields_may_be_missing(self):
        path = self._wire([
            {"type": "metadata", "protocol_version": "1.5"},
            {"type": "context.append_loop_event",
             "event": {"type": "tool.call", "toolCallId": "x", "name": "Bash",
                       "args": {"command": "ls"}, "stepUuid": "s"},
             "time": T0},
            {"type": "context.append_loop_event",
             "event": {"type": "tool.result", "toolCallId": "x",
                       "result": {"output": "out"}}, "time": T0 + 1},
            {"type": "context.append_loop_event",
             "event": {"type": "tool.call", "name": "Read",
                       "args": {"path": "README.md"}, "extras": {},
                       "display": []}, "time": T0 + 2},
        ])
        calls = self._calls(path)
        self.assertEqual([(c.tool_call_id, c.output) for c in calls],
                         [("x", "out"), (None, None)])

    def test_ordinary_records_are_not_counted_as_unknown(self):
        """Every record type Kimi Code writes in an ordinary session is
        known, so the counter moves only when the format does."""
        path = self._wire(_sample() + [
            {"type": t, "agentId": "main", "time": T0 + 5000 + i}
            for i, t in enumerate((
                "turn.ended", "prompt.completed", "llm.request",
                "token_counting.turn_recorded", "goal.update", "config.update",
                "subagent.spawned", "task.started", "file_history.checkpoint",
                "tools.set_active_tools", "plan_mode.enter", "cron.add",
                "context.undone", "agent.switched", "agent.turn.started",
                "agent.turn.ended", "agent.input.submitted",
                "human.agent.turn.started"))] + [
            {"type": "context.append_loop_event", "agentId": "main",
             "event": {"type": "step.end", "uuid": "step-1", "turnId": "1",
                       "step": 1, "finishReason": "tool_calls"},
             "time": T0 + 6000},
            {"type": "context.append_loop_event", "agentId": "main",
             "event": {"type": "content.part", "stepUuid": "step-1",
                       "part": {"type": "text", "text": "ok"}},
             "time": T0 + 6001},
        ])
        self.assertEqual([c.tool_call_id for c in self._calls(path)], ["call_1"])
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_unknown_record_shapes_are_skipped_and_counted(self):
        path = self._wire(_sample() + [
            {"type": "brand.new.record", "time": T0 + 5000},
            {"type": "agent.brand.new", "time": T0 + 5001},
            {"type": "context.append_loop_event",
             "event": {"type": "tool.batch", "calls": []}, "time": T0 + 5002},
            {"type": "context.append_message", "message": None, "time": T0 + 5003},
            {"timestamp": 1790000001.5, "message": {"role": "user"}},
            ["not", "a", "record"],
        ])
        calls = self._calls(path)
        self.assertEqual([c.tool_call_id for c in calls], ["call_1"])
        self.assertEqual(self.src.counts["unknown"], 6)
        list(self.src.tool_calls(self._store(path)))
        self.assertEqual(self.src.counts["unknown"], 6, "counted once per run")

    def test_a_type_that_is_not_a_string_is_unknown_not_a_crash(self):
        path = self._wire(_sample() + [
            {"type": ["context.append_message"], "time": T0 + 5000},
            {"type": {"name": "x"}, "time": T0 + 5001},
            {"type": "context.append_loop_event",
             "event": {"type": ["tool.call"], "toolCallId": "z"}, "time": T0 + 5002},
            dict(_approval("call_1", "rejected", T0 + 5003),
                 result={"decision": ["rejected"]}),
        ])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self._calls(path)
            texts = list(self.src.secret_texts(self._store(path)))
        self.assertEqual([(c.tool_call_id, c.status) for c in calls],
                         [("call_1", None)])
        self.assertEqual(len(texts), 9)
        self.assertEqual(self.src.counts["unknown"], 3)
        self.assertEqual(err.getvalue(), "")

    def test_a_session_migrated_from_the_kimi_cli(self):
        """Protocol 1.0, as the migrator writes it, until Kimi Code resumes
        the session: calls only in messages, as {type, id, function: {name,
        arguments}}, outputs in tool messages, no time, no agentId. The
        names are the Kimi CLI's, judged by name."""
        path = self._wire([
            {"type": "metadata", "protocol_version": "1.0", "created_at": T0},
            {"type": "turn.prompt", "agentId": "main",
             "input": [{"type": "text", "text": "clean up"}],
             "origin": {"kind": "user"}, "time": T0},
            {"type": "context.append_message",
             "message": {"role": "user", "content": [{"type": "text", "text": "clean up"}],
                         "toolCalls": []}},
            {"type": "context.append_message",
             "message": {"role": "assistant", "content": [], "toolCalls": [
                 {"type": "function", "id": "Shell:0",
                  "function": {"name": "Shell",
                               "arguments": _j({"command": "rm -rf ~/Documents/x"})}},
                 {"type": "function", "id": "Shell:1",
                  "function": {"name": "Shell", "arguments": _j({"command": "cat .env"})}},
                 {"type": "function", "id": "ReadFile:2",
                  "function": {"name": "ReadFile", "arguments": ""}}]}},
            {"type": "context.append_message",
             "message": {"role": "tool", "content": [{"type": "text", "text": "ok"}],
                         "toolCalls": [], "toolCallId": "Shell:0"}},
            {"type": "context.append_message",
             "message": {"role": "tool",
                         "content": [{"type": "text", "text": "API_KEY=" + SECRET}],
                         "toolCalls": [], "toolCallId": "Shell:1"}},
            {"type": "turn.ended", "agentId": "main", "turnId": 0,
             "reason": "completed", "time": T0},
        ])
        store = self._store(path)
        calls = {c.tool_call_id: c for c in self.src.tool_calls(store)}
        self.assertEqual(sorted(calls), ["ReadFile:2", "Shell:0", "Shell:1"])
        rm = calls["Shell:0"]
        self.assertEqual((rm.tool_name, rm.kind, rm.known, rm.tool_input),
                         ("Shell", "other", False, {"command": "rm -rf ~/Documents/x"}))
        self.assertEqual((rm.timestamp, rm.not_after, rm.output),
                         (None, _stamps.iso_utc(store.mtime, "s"), "ok"))
        [hit] = _judge(rm)[0]
        self.assertEqual(hit["rule"], "fs.destructive")
        self.assertIn("~/Documents/x", hit["evidence"])
        self.assertEqual(_judge(calls["Shell:1"])[0][0]["rule"], "cred.read")
        self.assertEqual(calls["Shell:1"].output, "API_KEY=" + SECRET)
        self.assertEqual(calls["ReadFile:2"].tool_input, {"_raw": ""})
        self.assertEqual(self._findings([store]), {SECRET: {".env"}})
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_the_new_shape_wins_over_function(self):
        """A toolCalls entry with its own name and arguments is read from
        them; function is only the 1.0 fallback."""
        path = self._wire([_meta(), {
            "type": "context.append_message", "agentId": "main",
            "message": {"role": "assistant", "content": [], "toolCalls": [
                {"type": "function", "id": "c1", "name": "Bash",
                 "arguments": _j({"command": "ls"}),
                 "function": {"name": "Shell", "arguments": _j({"command": "rm -rf /"})}}]},
            "time": T0}])
        [call] = self._calls(path)
        self.assertEqual((call.tool_name, call.command), ("Bash", "ls"))

    def test_the_engine_journal_copy_of_a_message(self):
        """agent.message.appended carries the same messages: its calls are
        read only for an id no tool.call event has, and its tool messages
        are credited to their call."""
        path = self._wire([
            _meta(),
            _call("call_1", "Bash", {"command": "cat .env"}, T0 + 10),
            _engine({"role": "assistant", "content": [], "toolCalls": [
                {"type": "function", "id": "call_1", "name": "Bash",
                 "arguments": _j({"command": "cat .env"})},
                {"type": "function", "id": "call_2", "name": "Bash",
                 "arguments": _j({"command": "rm -rf ~/Documents/x"})}]}, T0 + 20),
            _engine({"role": "tool", "toolCallId": "call_1",
                     "content": [{"type": "text", "text": "API_KEY=" + SECRET}]},
                    T0 + 30),
            dict(_engine({"role": "tool", "toolCallId": "call_2",
                          "content": [{"type": "text", "text": "done"}]}, T0 + 40),
                 type="human.agent.message.appended"),
        ])
        calls = self._calls(path)
        self.assertEqual([(c.tool_call_id, c.command, c.output) for c in calls],
                         [("call_1", "cat .env", "API_KEY=" + SECRET),
                          ("call_2", "rm -rf ~/Documents/x", "done")])
        self.assertEqual(self._findings([self._store(path)]), {SECRET: {".env"}})
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_the_engine_journal_message_is_read_one_level_down_only(self):
        """record.message is a history entry there; a message placed
        directly at record.message is not a shape Kimi Code writes, so it
        is not read, and is counted."""
        flat = {"role": "assistant", "content": [], "toolCalls": [
            {"type": "function", "id": "call_9", "name": "Bash",
             "arguments": _j({"command": "rm -rf ~/Documents/x"})}]}
        path = self._wire([
            _meta(),
            {"message": flat, "type": "agent.message.appended", "time": T0 + 10,
             "kind": "event"},
            {"message": {"role": "tool", "toolCallId": "call_9",
                         "content": [{"type": "text", "text": "done"}]},
             "type": "agent.message.appended", "time": T0 + 20, "kind": "event"},
            {"message": {"message": "not a message", "meta": {}},
             "type": "agent.message.appended", "time": T0 + 30, "kind": "event"},
        ])
        self.assertEqual(self._calls(path), [])
        self.assertEqual(self.src.counts["unknown"], 3)
        # the nested shape of the same message is read
        path = self._wire([_meta(), _engine(flat, T0 + 10)], sid="s_example02")
        [call] = self._calls(path)
        self.assertEqual((call.tool_call_id, call.command),
                         ("call_9", "rm -rf ~/Documents/x"))


# --------------------------------------------------------------------------
# 8: dedupe when an id comes back on a new call
# --------------------------------------------------------------------------

class ReusedIds(KimiCodeCase):
    """Kimi Code keeps a provider's id unless it has seen it, and each turn
    seeds what it has seen from the context as it is then (human/agent/
    turn.ts). After a clear, an undo or a compaction, Kimi K2 numbers its
    calls from functions.<name>:0 again, so a new call can carry an old
    id."""

    def test_the_same_call_again_after_a_reset_is_a_new_call(self):
        """Here vetoed, then after a reset approved and run a day later,
        then after another run with no answer recorded: three calls, each
        with its own time and answers. An answer still held at a reset,
        whose call was never dispatched, goes to no call after it."""
        rm = {"command": "rm -rf ~/Documents/x"}
        day = 86400000
        for reset in (_clear, lambda t: _undo(1, t), _compaction):
            name = reset(T0)["type"]
            with self.subTest(reset=name):
                path = self._wire([
                    _meta(),
                    _approval(K2_ID, "rejected", T0 + 1000),
                    _call(K2_ID, "Bash", rm, T0 + 1100),
                    _result(K2_ID, _not_run("Bash", "rejected"), T0 + 1200,
                            is_error=True),
                    reset(T0 + 2000),
                    _approval(K2_ID, "approved", T0 + day),
                    _call(K2_ID, "Bash", rm, T0 + day + 100),
                    _result(K2_ID, "", T0 + day + 200),
                    _approval(K2_ID, "rejected", T0 + day + 300),
                    reset(T0 + day + 400),
                    _call(K2_ID, "Bash", rm, T0 + 2 * day),
                    _result(K2_ID, "", T0 + 2 * day + 100),
                ], sid="s_" + name.replace(".", "_"))
                self.assertEqual(
                    [(c.command, c.status, c.timestamp) for c in self._calls(path)],
                    [("rm -rf ~/Documents/x", "declined",
                      _stamps.iso_utc(T0 + 1100, "ms")),
                     ("rm -rf ~/Documents/x", None,
                      _stamps.iso_utc(T0 + day + 100, "ms")),
                     ("rm -rf ~/Documents/x", None,
                      _stamps.iso_utc(T0 + 2 * day, "ms"))])

    def test_a_new_call_with_an_old_id_is_reported(self):
        for reset in (_clear(T0 + 3000), _undo(2, T0 + 3000),
                      _compaction(T0 + 3000)):
            with self.subTest(reset=reset["type"]):
                path = self._wire([
                    _meta(),
                    _call(K2_ID, "Bash", {"command": "ls"}, T0 + 1000),
                    _result(K2_ID, "a\n", T0 + 2000),
                    reset,
                    _call(K2_ID, "Bash", {"command": "rm -rf ~/Documents/x"},
                          T0 + 4000),
                    _result(K2_ID, "", T0 + 5000),
                ], sid="s_" + reset["type"].replace(".", "_"))
                calls = self._calls(path)
                self.assertEqual(
                    [(c.tool_call_id, c.command, c.output, c.timestamp)
                     for c in calls],
                    [(K2_ID, "ls", "a\n", _stamps.iso_utc(T0 + 1000, "ms")),
                     (K2_ID, "rm -rf ~/Documents/x", "",
                      _stamps.iso_utc(T0 + 4000, "ms"))])
                [hit] = _judge(calls[1])[0]
                self.assertEqual(hit["rule"], "fs.destructive")
                self.assertIn("~/Documents/x", hit["evidence"])

    def test_a_call_recorded_again_with_the_same_name_and_args_is_one_call(self):
        path = self._wire([
            _meta(),
            _call(K2_ID, "Bash", {"command": "ls"}, T0 + 1000),
            _result(K2_ID, "a\n", T0 + 2000),
            _call(K2_ID, "Bash", {"command": "ls"}, T0 + 3000),
            _call(K2_ID, "Glob", {"command": "ls"}, T0 + 4000),
        ])
        self.assertEqual([(c.tool_name, c.output) for c in self._calls(path)],
                         [("Bash", "a\n"), ("Glob", None)])

    def test_each_result_line_is_credited_to_the_call_before_it(self):
        self._wire([
            _meta(),
            _call(K2_ID, "Bash", {"command": "ls"}, T0 + 1000),
            _result(K2_ID, "TOKEN=" + TYPED + "\n", T0 + 2000),
            _clear(T0 + 3000),
            _call(K2_ID, "Bash", {"command": "cat .env"}, T0 + 4000),
            _result(K2_ID, "API_KEY=" + SECRET + "\n", T0 + 5000),
        ])
        [store] = self._stores()
        texts = list(self.src.secret_texts(store))
        self.assertEqual([(t.where, t.call.command if t.call else None)
                          for t in texts],
                         [("line 1", None), ("line 2", None), ("line 3", "ls"),
                          ("line 4", None), ("line 5", None),
                          ("line 6", "cat .env")])
        self.assertEqual(self._findings([store]),
                         {SECRET: {".env"}, TYPED: set()})

    def test_an_approval_goes_to_the_call_it_gates(self):
        """Kimi Code records the answer, then the call's tool.call event:
        the answer belongs to the next call with its id, never to an
        earlier one that reused it."""
        path = self._wire([
            _meta(),
            _call(K2_ID, "Bash", {"command": "ls"}, T0 + 1000),
            _result(K2_ID, "a\n", T0 + 2000),
            _clear(T0 + 3000),
            _approval(K2_ID, "rejected", T0 + 4000),
            _call(K2_ID, "Bash", {"command": "rm -rf ~/Documents/x"}, T0 + 4100),
            _result(K2_ID, _not_run("Bash", "rejected"), T0 + 4200, is_error=True),
            _clear(T0 + 5000),
            _call(K2_ID, "Bash", {"command": "rm -rf ~/Documents/y"}, T0 + 6000),
            _result(K2_ID, "", T0 + 6100),
        ])
        self.assertEqual([(c.command, c.status) for c in self._calls(path)],
                         [("ls", None), ("rm -rf ~/Documents/x", "declined"),
                          ("rm -rf ~/Documents/y", None)])

    def test_an_approval_whose_call_was_never_recorded_is_dropped(self):
        path = self._wire([
            _meta(),
            _call(K2_ID, "Bash", {"command": "rm -rf ~/Documents/x"}, T0 + 1000),
            _result(K2_ID, "", T0 + 2000),
            _approval(K2_ID, "rejected", T0 + 3000),
        ])
        [call] = self._calls(path)
        self.assertIsNone(call.status)

    def test_the_engine_copies_of_both_calls_are_copies(self):
        def turn(command, output, t):
            return [
                _call(K2_ID, "Bash", {"command": command}, t),
                _result(K2_ID, output, t + 100),
                _engine({"role": "assistant", "content": [], "toolCalls": [
                    {"type": "function", "id": K2_ID, "name": "Bash",
                     "arguments": _j({"command": command})}]}, t + 200),
                _engine({"role": "tool", "toolCallId": K2_ID,
                         "content": [{"type": "text", "text": output}]}, t + 300),
            ]
        path = self._wire([_meta()] + turn("ls", "a\n", T0 + 1000)
                          + [_clear(T0 + 2000)]
                          + turn("cat .env", "API_KEY=" + SECRET, T0 + 3000))
        calls = self._calls(path)
        self.assertEqual([(c.command, c.output) for c in calls],
                         [("ls", "a\n"), ("cat .env", "API_KEY=" + SECRET)])
        self.assertEqual(self._findings([self._store(path)]), {SECRET: {".env"}})
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_message_calls_with_one_id(self):
        """Calls known only from messages (protocol 1.0): a copy with the
        same name and arguments is one call, a different call is another,
        and each tool message answers the call before it."""
        def assistant(command):
            return {"type": "context.append_message",
                    "message": {"role": "assistant", "content": [], "toolCalls": [
                        {"type": "function", "id": "Shell:0",
                         "function": {"name": "Shell",
                                      "arguments": _j({"command": command})}}]}}

        def tool(text):
            return {"type": "context.append_message",
                    "message": {"role": "tool",
                                "content": [{"type": "text", "text": text}],
                                "toolCalls": [], "toolCallId": "Shell:0"}}
        path = self._wire([
            {"type": "metadata", "protocol_version": "1.0", "created_at": T0},
            assistant("ls"), assistant("ls"), tool("a"),
            assistant("rm -rf ~/Documents/x"), tool("b"),
        ])
        self.assertEqual([(c.tool_input["command"], c.output)
                          for c in self._calls(path)],
                         [("ls", "a"), ("rm -rf ~/Documents/x", "b")])

    def test_an_event_after_an_answered_message_call_is_a_new_call(self):
        """An event replaces a message's call with its id only while that
        call has no output: one that has was already answered, so ran."""
        path = self._wire([
            _meta(),
            _assistant([(K2_ID, "Bash", _j({"command": "ls"}))], T0 + 1000),
            {"type": "context.append_message", "agentId": "main",
             "message": {"role": "tool", "toolCallId": K2_ID, "toolCalls": [],
                         "content": [{"type": "text", "text": "a"}]},
             "time": T0 + 2000},
            _call(K2_ID, "Bash", {"command": "rm -rf ~/Documents/x"}, T0 + 3000),
        ])
        self.assertEqual([(c.command, c.output) for c in self._calls(path)],
                         [("ls", "a"), ("rm -rf ~/Documents/x", None)])

    def test_a_spill_is_credited_to_the_call_whose_result_named_it(self):
        first = self._write(self._tool_results("Bash", K2_ID),
                            "TOKEN=" + TYPED + "\n")
        second = self._write(self._tool_results(
            "Bash", K2_ID, uuid="5a1d7e3c-2b4f-4c6d-9e8f-0a1b2c3d4e5f"),
            "API_KEY=" + SECRET + "\n")
        self._wire([
            _meta(),
            _call(K2_ID, "Bash", {"command": "ls -R"}, T0 + 1000),
            _result(K2_ID, _persisted_pointer("Bash", K2_ID, first), T0 + 2000),
            _clear(T0 + 3000),
            _call(K2_ID, "Bash", {"command": "cat .env"}, T0 + 4000),
            _result(K2_ID, _persisted_pointer("Bash", K2_ID, second), T0 + 5000),
        ])
        stores = {s.path: s for s in self._stores()}
        self.assertEqual(
            [t.call.command for t in self.src.secret_texts(stores[first])]
            + [t.call.command for t in self.src.secret_texts(stores[second])],
            ["ls -R", "cat .env"])
        self.assertEqual(self._findings(stores.values()),
                         {SECRET: {".env"}, TYPED: set()})


# --------------------------------------------------------------------------
# Calls the user declined, and commands the user typed
# --------------------------------------------------------------------------

class Declined(KimiCodeCase):

    def _session(self, decisions):
        """One Bash call per [decision, ...]: the approval answers first,
        then the tool.call event and its result, as Kimi Code writes them."""
        records = [_meta()]
        for i, said in enumerate(decisions):
            cid = "call_%d" % i
            t = T0 + 1000 * i
            records += [_approval(cid, d, t + j) for j, d in enumerate(said)]
            records.append(_call(cid, "Bash", {"command": "rm -rf ~/Documents/x%d" % i},
                                 t + 100))
            ran = "approved" in said or not said
            records.append(_result(cid, "" if ran else _not_run("Bash", said[-1]),
                                   t + 200, is_error=not ran))
        return {c.tool_call_id: c for c in self._calls(self._wire(records))}

    def test_a_rejected_or_cancelled_approval_is_declined(self):
        calls = self._session([["rejected"], ["cancelled"], ["approved"], []])
        self.assertEqual([calls["call_%d" % i].status for i in range(4)],
                         ["declined", "declined", None, None])
        self.assertEqual(calls["call_0"].output,
                         'Tool "Bash" was not run because the user rejected the '
                         'approval request.')
        # still judged: the report says it did not run
        self.assertEqual(_judge(calls["call_0"])[0][0]["rule"], "fs.destructive")
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_declined_only_when_no_answer_approved_it(self):
        calls = self._session([["approved", "rejected"], ["rejected", "approved"],
                               ["rejected", "cancelled"]])
        self.assertEqual([calls["call_%d" % i].status for i in range(3)],
                         [None, None, "declined"])

    def test_an_answer_it_does_not_know_is_not_a_refusal(self):
        path = self._wire([
            _meta(),
            dict(_approval("c1", "rejected", T0), result={"decision": "deferred"}),
            dict(_approval("c2", "rejected", T0), result={}),
            dict(_approval("c3", "rejected", T0), result="rejected"),
            _approval("c4", "rejected", T0, feedback="not this one"),
        ] + [_call(c, "Bash", {"command": "ls"}, T0 + 10)
             for c in ("c1", "c2", "c3", "c4")])
        self.assertEqual([(c.tool_call_id, c.status) for c in self._calls(path)],
                         [("c1", None), ("c2", None), ("c3", None),
                          ("c4", "declined")])

    def test_a_call_only_in_a_message_can_be_declined(self):
        path = self._wire([
            _meta(),
            _assistant([("call_7", "Bash", _j({"command": "rm -rf ~/Documents/x"}))],
                       T0),
            _approval("call_7", "rejected", T0 + 10),
        ])
        [call] = self._calls(path)
        self.assertEqual(call.status, "declined")

    def test_a_call_interrupted_before_it_was_dispatched_never_ran(self):
        """Kimi Code writes a call's tool.call event when it dispatches the
        call. A turn interrupted while the call waits for approval records
        no answer and no event: only the result it fills in for the call
        (loopService.ts backfillAbortedToolResults) and, at the turn's end,
        the assistant message that asked for it (machine.ts). That call
        never ran. One dispatched before the interrupt may have."""
        rm = _j({"command": "rm -rf ~/Documents/x"})
        for said in (_interrupted("Bash"), 'Tool "Bash" was aborted'):
            with self.subTest(said=said[:20]):
                path = self._wire([
                    _meta(),
                    _step(1, T0 + 2),
                    _result(K2_ID, said, T0 + 5000, is_error=True),
                    _engine({"role": "assistant", "content": [], "toolCalls": [
                        {"type": "function", "id": K2_ID, "name": "Bash",
                         "arguments": rm}]}, T0 + 5002),
                    _engine({"role": "tool", "toolCallId": K2_ID,
                             "content": [{"type": "text", "text": said}]},
                            T0 + 5003),
                ])
                [call] = self._calls(path)
                self.assertEqual((call.command, call.output, call.status),
                                 ("rm -rf ~/Documents/x", said, "declined"))
        dispatched = self._wire([
            _meta(),
            _call(K2_ID, "Bash", {"command": "rm -rf ~/Documents/x"}, T0 + 10),
            _result(K2_ID, _interrupted("Bash"), T0 + 5000, is_error=True),
            _engine({"role": "assistant", "content": [], "toolCalls": [
                {"type": "function", "id": K2_ID, "name": "Bash",
                 "arguments": rm}]}, T0 + 5002),
        ], sid="s_dispatched")
        [call] = self._calls(dispatched)
        self.assertIsNone(call.status)
        # another tool's note, or one that only quotes it, is not this one
        for said in (_interrupted("Read"), "Done. " + _interrupted("Bash")):
            with self.subTest(said=said[:20]):
                path = self._wire([
                    _meta(),
                    _assistant([(K2_ID, "Bash", rm)], T0),
                    _result(K2_ID, said, T0 + 10, is_error=True),
                ], sid="s_other")
                [call] = self._calls(path)
                self.assertIsNone(call.status)


class ShellMode(KimiCodeCase):

    def test_a_command_the_user_typed_is_a_user_shell_call(self):
        self._index([(SID, KEY, WORK_DIR)])
        path = self._wire([
            _meta(),
            _shell_in("rm -rf ~/Documents/x", T0 + 100),
            _shell_out("", "", T0 + 200),
            _call("call_1", "Grep", {"pattern": "x"}, T0 + 300),
        ])
        calls = self._calls(path)
        self.assertEqual([c.actor for c in calls], ["user", "agent"])
        typed = calls[0]
        self.assertEqual((typed.tool_name, typed.kind, typed.known, typed.command,
                          typed.consumed, typed.tool_call_id, typed.status),
                         ("Bash", "shell", True, "rm -rf ~/Documents/x",
                          frozenset(["command"]), None, None))
        self.assertEqual((typed.timestamp, typed.session, typed.project),
                         ("2026-09-21T14:13:20Z", SID, WORK_DIR))
        [hit] = _judge(typed)[0]
        self.assertEqual(hit["rule"], "fs.destructive")
        self.assertIn("~/Documents/x", hit["evidence"])

    def test_the_command_is_unescaped_exactly(self):
        commands = ['grep -c "a&b" x.txt && echo \'<ok>\' > out.txt',
                    "echo &lt; &amp;amp; &quot;",
                    "printf 'one\ntwo'\nls -la"]
        path = self._wire([_meta()] + [_shell_in(c, T0 + i)
                                       for i, c in enumerate(commands)])
        self.assertEqual([c.command for c in self._calls(path)], commands)
        raw = self._read(path).decode("utf-8")
        self.assertIn("&amp;amp;amp;", raw)

    def test_the_output_is_credited_to_the_command(self):
        path = self._wire([
            _meta(),
            _shell_in("cat .env", T0 + 100),
            _shell_out("API_KEY=" + SECRET + "\n", "", T0 + 200),
            _shell_in("export TOKEN=" + TYPED, T0 + 300),
            _shell_out("", "", T0 + 400),
        ])
        calls = self._calls(path)
        self.assertEqual(calls[0].output,
                         "<bash-stdout>API_KEY=" + SECRET
                         + "\n</bash-stdout><bash-stderr></bash-stderr>")
        self.assertEqual(self._findings([self._store(path)]),
                         {SECRET: {".env"}, TYPED: set()})

    def test_a_command_sent_to_the_background_has_no_output_message(self):
        """Its output is not the next one: that belongs to the next
        command."""
        path = self._wire([
            _meta(),
            _shell_in("sleep 100 &", T0 + 100),
            _shell_in("cat .env", T0 + 200),
            _shell_out("API_KEY=" + SECRET, "", T0 + 300, is_error=False),
            _shell_out("stray", "", T0 + 400),
        ])
        calls = self._calls(path)
        self.assertEqual([(c.command, c.output is not None) for c in calls],
                         [("sleep 100 &", False), ("cat .env", True)])
        self.assertEqual(self._findings([self._store(path)]), {SECRET: {".env"}})

    def test_a_shell_message_in_another_shape_is_counted_not_read(self):
        bad = _shell_in("ls", T0)
        bad["message"]["content"][0]["text"] = "rm -rf ~/Documents/x"
        empty = _shell_in("", T0 + 1)
        path = self._wire([_meta(), bad, empty])
        self.assertEqual(self._calls(path), [])
        self.assertEqual(self.src.counts["unreadable_calls"], 1)
        self.assertEqual(self.src.counts["unknown"], 0)



# --------------------------------------------------------------------------
# 9: secrets
# --------------------------------------------------------------------------

class Secrets(KimiCodeCase):

    def test_a_key_in_output_after_cat_env_comes_from_env(self):
        self._wire(_sample() + [
            _call("call_2", "Bash", {"command": "export API_KEY=" + TYPED},
                  T0 + 3000),
            _result("call_2", "", T0 + 3100),
            _call("call_3", "Bash", {"command": "cat .env"}, T0 + 4000),
            _result("call_3", "API_KEY=" + SECRET + "\n", T0 + 4100),
        ])
        found = self._findings(self._stores())
        self.assertEqual(found, {SECRET: {".env"}, TYPED: set()})

    def test_the_result_line_carries_its_call_and_the_call_line_does_not(self):
        path = self._wire(_sample())
        texts = list(self.src.secret_texts(self._store(path)))
        self.assertEqual([t.where for t in texts],
                         ["line %d" % n for n in range(1, 6)])
        self.assertEqual([t.call is not None for t in texts],
                         [False, False, False, False, True])
        self.assertEqual(texts[4].call.command, "cat .env")
        self.assertIsNone(texts[4].attached)

    def test_a_message_carrying_a_tool_call_id_is_credited_to_its_call(self):
        self._wire([
            _meta(),
            _call("call_1", "Bash", {"command": "cat .env"}, T0 + 10),
            {"type": "context.append_message", "agentId": "main",
             "message": {"role": "tool", "toolCallId": "call_1", "toolCalls": [],
                         "content": [{"type": "text",
                                      "text": "API_KEY=" + SECRET}]},
             "time": T0 + 20},
        ])
        self.assertEqual(self._findings(self._stores()), {SECRET: {".env"}})

    def test_side_stores_are_searched(self):
        self._index([(SID, KEY, WORK_DIR)])
        sdir = self._session_dir()
        self._write(os.path.join(sdir, "state.json"), _j(
            {"title": "deploy", "lastPrompt": "use STRIPE_KEY=" + SECRET,
             "forkedFrom": None}))
        digest = hashlib.md5(WORK_DIR.encode("utf-8")).hexdigest()
        self._write(os.path.join(self.root, "user-history", digest + ".jsonl"),
                    [{"content": "export GITHUB_TOKEN=" + TYPED}])
        self._write(os.path.join(self.root, "logs", "kimi-code.log"),
                    "info: ran\ndebug: env STRIPE_SECRET=" + SIDE + "\n")
        self._write(os.path.join(sdir, "logs", "kimi-code.log"),
                    "debug: key file\n" + _PEM + "info: done\n")
        found = self._findings(self._stores())
        self.assertEqual(set(found), {SECRET, TYPED, SIDE, _PEM.rstrip("\n")})
        for origins in found.values():
            self.assertEqual(origins, set())



class Spills(KimiCodeCase):
    """Spill files: followed only in the shapes Kimi Code writes them,
    inside the transcript's own session."""

    def test_each_kind_of_spill_file_is_read_and_credited(self):
        grep = self._write(self._tool_results("Grep", "call_3"),
                           "a.env:1:STRIPE_KEY=" + SECRET + "\n")
        bash = self._write(self._task_log(), "line\n" * 3
                           + "AWS_SECRET_ACCESS_KEY=" + SIDE + "\n")
        older = self._write(self._task_log("bash-0p9o8i7u", agent=None),
                            "TOKEN=" + TYPED + "\n")
        self._wire(_sample() + [
            _call("call_2", "Bash", {"command": "cat config/prod.env"}, T0 + 3000),
            _result("call_2", _persisted_pointer("Bash", "call_2", bash)
                    + "\n\ntask_id: " + TASK + "\noutput_size_bytes: 60000",
                    T0 + 3100),
            _call("call_3", "Grep", {"pattern": "KEY"}, T0 + 3200),
            _result("call_3", [{"type": "text", "text": "a.env:1:..."},
                               {"type": "text", "text": _appended_pointer(grep)}],
                    T0 + 3300),
            _call("call_4", "TaskOutput", {"task_id": "bash-0p9o8i7u"}, T0 + 3400),
            _result("call_4", _task_output("bash-0p9o8i7u", older, 20), T0 + 3500),
        ])
        stores = {s.path: s for s in self._stores()}
        for spill in (grep, bash, older):
            self.assertIn(spill, stores)
            self.assertEqual((stores[spill].format, stores[spill].role,
                              stores[spill].session), ("text", "side", SID))
        found = self._findings(stores.values())
        self.assertEqual(found, {SECRET: {".env"}, SIDE: {"config/prod.env"},
                                 TYPED: set()})
        texts = list(self.src.secret_texts(stores[bash]))
        self.assertEqual([(t.call.tool_call_id, t.where) for t in texts],
                         [("call_2", "lines 1-4")])

    def test_a_sub_agent_spill_is_read(self):
        sub = self._write(self._tool_results("Bash", "call_5", agent="agent-2"),
                          "TOKEN=" + SIDE + "\n")
        self._wire([_meta(), _call("call_5", "Bash", {"command": "cat .env"},
                                   T0, agent="agent-2"),
                    _result("call_5", _persisted_pointer("Bash", "call_5", sub),
                            T0 + 1, agent="agent-2")], agent="agent-2")
        self.assertEqual(self._findings(self._stores()), {SIDE: {".env"}})

    def test_only_kimi_code_spill_shapes_in_the_own_session_are_followed(self):
        """Every one of these exists and holds a key, and a tool result
        names it; none is opened."""
        sdir = self._session_dir()
        agent = os.path.join(sdir, "agents", "main")
        named = [
            os.path.join(self.root, "config.toml"),
            os.path.join(self.root, "mcp.json"),
            os.path.join(self.root, "logs", "secret.txt"),
            os.path.join(sdir, "upcoming-goals.json"),
            os.path.join(sdir, "tasks", TASK + ".json"),
            os.path.join(sdir, "tasks", TASK, "notes.txt"),
            os.path.join(sdir, "tasks", "NOT_A_TASK", "output.log"),
            os.path.join(agent, "plans", "plan_1.md"),
            os.path.join(agent, "tasks", TASK + ".json"),
            os.path.join(agent, "tool-results", "notes.txt"),
            os.path.join(agent, "tool-results", "Bash-c1-" + UUID.upper() + ".txt"),
            os.path.join(agent, "tool-results", "Bash-c1-" + UUID + ".log"),
            os.path.join(agent, "tool-results", "deeper", "Bash-c1-" + UUID + ".txt"),
            os.path.join(sdir, "agents", "helper", "tool-results",
                         "Bash-c1-" + UUID + ".txt"),
            os.path.join(sdir, "tool-results", "Bash-c1-" + UUID + ".txt"),
            # the right shape, in another session
            self._tool_results("Bash", "c1", sid="s_other"),
            self._task_log(sid="s_other"),
        ]
        for path in named:
            self._write(path, "TOKEN=" + SIDE + "\n")
        records = _sample()
        for i, path in enumerate(named):
            cid = "c%d" % i
            records += [_call(cid, "Bash", {"command": "cat x"}, T0 + 3000 + i),
                        _result(cid, _persisted_pointer("Bash", cid, path),
                                T0 + 4000 + i)]
        self._wire(records)
        opened = []
        real_open = builtins.open

        def spy_open(file, *a, **kw):
            opened.append(os.path.realpath(os.fspath(file)))
            return real_open(file, *a, **kw)

        with mock.patch("builtins.open", spy_open):
            stores = self._stores()
            found = self._findings(stores)
        self.assertEqual([s.role for s in stores], ["transcript"])
        for path in named:
            self.assertNotIn(os.path.realpath(path), opened, path)
        self.assertNotIn(SIDE, found)

    def test_a_spill_path_outside_the_root_is_not_opened(self):
        outside = tempfile.mkdtemp(prefix="kimicode-out-")
        self.addCleanup(shutil.rmtree, outside, True)
        target = self._write(os.path.join(outside, "secret.txt"),
                             "TOKEN=" + SIDE + "\n")
        config = self._write(os.path.join(self.root, "config.toml"),
                             'api_key = "%s"\n' % OWN_KEY)
        # Symlinks in the right shape, inside the session, to a file
        # outside the root and to the agent's own config.
        link_out = self._tool_results("Bash", "c3")
        link_config = self._tool_results("Bash", "c4")
        os.makedirs(os.path.dirname(link_out))
        can_link = True
        try:
            os.symlink(target, link_out)
            os.symlink(config, link_config)
        except (OSError, NotImplementedError):
            can_link = False
        relative = os.path.join("..", "..", os.path.basename(outside), "secret.txt")
        dotdot = os.path.join(os.path.dirname(link_out), "..", "..", "..", "..",
                              "..", "..", os.path.relpath(target, self.home))
        self._wire(_sample() + [
            _call("c%d" % i, "Bash", {"command": "make"}, T0 + 3000 + i)
            for i in range(5)] + [
            _result("c0", "output_path: " + target, T0 + 4000),
            _result("c1", "output_path: " + relative, T0 + 4001),
            _result("c2", "output_path: " + dotdot, T0 + 4002),
            _result("c3", "output_path: " + link_out, T0 + 4003),
            _result("c4", "output_path: " + link_config, T0 + 4004),
        ])
        opened = []
        real_open = builtins.open

        def spy_open(file, *a, **kw):
            opened.append(os.path.realpath(os.fspath(file)))
            return real_open(file, *a, **kw)

        with mock.patch("builtins.open", spy_open):
            stores = self._stores()
            found = self._findings(stores)
        self.assertEqual([s.role for s in stores], ["transcript"])
        self.assertNotIn(os.path.realpath(target), opened)
        self.assertNotIn(os.path.realpath(config), opened)
        self.assertNotIn(SIDE, found)
        self.assertNotIn(OWN_KEY, found)
        self.assertTrue(can_link or WINDOWS)

    def test_a_relative_spill_path_is_not_followed(self):
        """Whatever the current directory is: here it is the root itself,
        where the relative path would name a real spill file."""
        spill = self._write(self._tool_results("Bash", "c0"), "TOKEN=" + SIDE + "\n")
        rel = os.path.relpath(spill, self.root)
        self._wire(_sample() + [
            _call("c0", "Bash", {"command": "make"}, T0 + 3000),
            _result("c0", "output_path: " + rel, T0 + 3001)])
        here = os.getcwd()
        os.chdir(self.root)
        try:
            stores = self._stores()
        finally:
            os.chdir(here)
        self.assertEqual([s.role for s in stores], ["transcript"])

    def test_a_transcript_is_read_once_for_all_its_spill_files(self):
        """Not once per spill file: a long session with many long outputs
        would otherwise be read over and over."""
        records = _sample()
        keys = {}
        for i in range(40):
            cid = "call_s%d" % i
            keys[cid] = "sk_" "live_" "Kc4vR8mT2yLp6WcN1sXe%04d" % i
            spill = self._write(self._tool_results(
                "Bash", cid, uuid="3f2b8c1e-9d4a-4e6b-8a7c-%012x" % i),
                "KEY=%s\n" % keys[cid])
            records += [_call(cid, "Bash", {"command": "cat conf/s%d.env" % i},
                              T0 + 5000 + i),
                        _result(cid, _persisted_pointer("Bash", cid, spill),
                                T0 + 6000 + i)]
        self._wire(records)
        stores = self._stores()
        self.assertEqual(len(stores), 41)
        with mock.patch.object(self.src, "_collect",
                               wraps=self.src._collect) as spy:
            found = self._findings(stores)
        # once for the transcript's own lines, once for every spill file
        self.assertEqual(spy.call_count, 2)
        for i in range(40):
            self.assertEqual(found[keys["call_s%d" % i]], {"conf/s%d.env" % i})

    def test_a_pointer_written_with_forward_slashes_is_followed(self):
        spill = self._write(self._tool_results("Bash", "c0"), "TOKEN=" + SIDE + "\n")
        self._wire(_sample() + [
            _call("c0", "Bash", {"command": "cat .env"}, T0 + 3000),
            _result("c0", _persisted_pointer("Bash", "c0", spill), T0 + 3001)])
        roles = [s.role for s in self._stores()]
        # as Kimi Code writes it on Windows too: C:/Users/u/.kimi-code/...
        self.assertEqual(roles.count("side"), 1)
        self.assertEqual(self._findings(self._stores())[SIDE], {".env"})


# --------------------------------------------------------------------------
# 10, 13: masking
# --------------------------------------------------------------------------

def _masking_records(secret, password):
    """A transcript holding each value where Kimi Code stores it: typed into
    a call, in a result string, in content parts, and inside a message's
    arguments, a JSON string inside the JSON line."""
    return [
        _meta(),
        _user("deploy with my key", T0 + 100),
        _assistant([("call_1", "Bash", _j({"command": "echo " + password}))],
                   T0 + 200),
        _call("call_1", "Bash", {"command": "echo " + password}, T0 + 300),
        _result("call_1", password + "\n", T0 + 400),
        _assistant([("call_2", "Bash", _j({"command": "cat .env"}))], T0 + 500),
        _result("call_2", [{"type": "text", "text": "API_KEY=" + secret},
                           {"type": "text", "text": "PW=" + password}], T0 + 600),
        _call("call_3", "Write", {"path": "café.env", "content": "K=" + secret,
                                  "mode": "overwrite"}, T0 + 700),
    ]


class Masking(KimiCodeCase):

    def _bytes(self, records, crlf=False):
        end = "\r\n" if crlf else "\n"
        return "".join(_j(r) + end for r in records).encode("utf-8")

    def test_round_trip(self):
        values = [SECRET, PASSWORD]
        original = self._bytes(_masking_records(SECRET, PASSWORD))
        expected = self._bytes(_masking_records(_marker(SECRET), _marker(PASSWORD)))
        path = self._wire(_masking_records(SECRET, PASSWORD), mode=0o640)
        self.assertEqual(self._read(path), original)
        store = self._store(path)
        before = [(c.tool_call_id, c.kind, c.timestamp, c.paths)
                  for c in self.src.tool_calls(store)]

        result = self.src.mask(store, values)
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        after = self._read(path)
        self.assertEqual(after, expected, "a byte other than the secret changed")
        text = after.decode("utf-8")
        for value in values:
            self.assertEqual([f for f in _rewrite.encodings(value) if f in text],
                             [])
        # it still parses, and the arguments inside a line still parse
        lines = [json.loads(line) for line in text.splitlines()]
        args = json.loads(lines[2]["message"]["toolCalls"][0]["arguments"])
        self.assertEqual(args, {"command": "echo " + _marker(PASSWORD)})
        # the same calls, with the values masked
        self.src.reset()
        calls = list(self.src.tool_calls(self._store(path)))
        self.assertEqual([(c.tool_call_id, c.kind, c.timestamp, c.paths)
                          for c in calls], before)
        self.assertEqual(calls[0].command, "echo " + _marker(PASSWORD))
        # the backup is the original, private; the mode is kept
        self.assertEqual(self._backups(), [result.backup])
        self.assertEqual(self._read(result.backup), original)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(result.backup).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
        self.assertFalse(os.path.exists(path + ".ranwhat-tmp"))
        # a second run changes nothing
        self.assertEqual(self.src.mask(self._store(path), values), MaskResult(path))
        self.assertEqual(self._read(path), expected)
        self.assertEqual(len(self._backups()), 1)

    def test_crlf_lines_and_a_partial_last_line_survive(self):
        records = _masking_records(SECRET, PASSWORD)
        tail = b'{"type":"context.append_loop_event","event":{"type":"tool.ca'
        original = self._bytes(records, crlf=True) + tail
        expected = self._bytes(_masking_records(_marker(SECRET), _marker(PASSWORD)),
                               crlf=True) + tail
        path = self._wire(original)
        result = self.src.mask(self._store(path), [SECRET, PASSWORD])
        self.assertTrue(result.changed)
        self.assertEqual(self._read(path), expected)

    def test_side_stores_round_trip(self):
        sdir = self._session_dir()
        state = self._write(os.path.join(sdir, "state.json"),
                            '{\n  "title": "x",\n  "lastPrompt": "KEY=%s"\n}\n'
                            % SECRET)
        log = self._write(os.path.join(self.root, "logs", "kimi-code.log"),
                          "a\nKEY=" + SECRET + "\nb\n")
        hist = self._write(os.path.join(self.root, "user-history", "0" * 32
                                        + ".jsonl"), [{"content": "K=" + SECRET}])
        for path in (state, log, hist):
            original = self._read(path)
            result = self.src.mask(self._store(path), [SECRET])
            self.assertTrue(result.changed, path)
            self.assertEqual(self._read(path),
                             original.replace(SECRET.encode(), _marker(SECRET).encode()))

    def test_a_file_written_in_the_last_two_minutes_is_in_use(self):
        path = self._wire(_masking_records(SECRET, PASSWORD), age=5)
        digest = _sha(path)
        self.assertEqual(self.src.mask(self._store(path), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertEqual(self._backups(), [])
        self.assertGreater(_rewrite.QUIET_SECONDS, 5)


# --------------------------------------------------------------------------
# 12, 14: files that do not parse, and the window
# --------------------------------------------------------------------------

class Damaged(KimiCodeCase):

    def test_a_truncated_last_line_is_skipped_quietly(self):
        path = self._wire(_j(_meta()) + "\n" + _j(_sample()[3]) + "\n"
                          + _j(_sample()[4])[:40])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            [call] = self._calls(path)
            texts = list(self.src.secret_texts(self._store(path)))
        self.assertEqual(call.command, "cat .env")
        self.assertIsNone(call.output)
        self.assertEqual(len(texts), 2)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_garbage_store_warns_once_and_the_others_are_read(self):
        good = self._wire(_sample(), age=60)
        bad = self._wire(b"\x00\xff\xfe binary\n\x89PNG\r\n\x1a\nmore\n",
                         sid="s_bad", age=30)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            stores = self._stores()
            self.assertEqual([s.path for s in stores], [bad, good])
            calls = [c for s in stores for c in self.src.tool_calls(s)]
            texts = [t for s in stores for t in self.src.secret_texts(s)]
        self.assertEqual([c.tool_call_id for c in calls], ["call_1"])
        self.assertEqual(len(texts), 5)
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertIn(bad, err.getvalue())
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(self.src.counts["unparsed"], 4)

    def test_a_store_that_vanished_warns_once(self):
        path = self._wire(_sample())
        store = self._store(path)
        os.remove(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)

    def test_a_state_file_that_is_not_json(self):
        path = self._write(os.path.join(self._session_dir(), "state.json"),
                           "{not json")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.secret_texts(self._store(path))), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)

    def test_a_call_nested_past_the_stack_is_kept_and_the_rest_read(self):
        """A tool.call event recorded twice whose args nest too deep for
        Python to compare, and a message call recorded twice whose
        arguments string does: nothing escapes, and the calls, the key and
        the spill file around them are still read. Where the parser gives
        up first (3.9), the two deep events are skipped and counted."""
        deep = _deep()
        spill = self._write(self._tool_results("Bash", "call_3"),
                            "TOKEN=" + SIDE + "\n")
        event = _j(_call("call_deep", "Bash", "@", T0 + 2000)).replace(
            '"@"', deep)
        message = _assistant([("call_msg", "Bash", deep)], T0 + 2100)
        lines = [_j(r) for r in _sample()] + [event, event] + [
            _j(message), _j(_engine(message["message"], T0 + 2101)),
            _j(_call("call_3", "Bash", {"command": "cat config/prod.env"},
                     T0 + 3000)),
            _j(_result("call_3", _persisted_pointer("Bash", "call_3", spill),
                       T0 + 3100)),
        ]
        path = self._wire("".join(line + "\n" for line in lines))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            ids = [c.tool_call_id for c in self._calls(path)]
            found = self._findings(self._stores())
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(ids[0], "call_1")
        self.assertEqual(ids[-1], "call_3")
        self.assertIn("call_msg", ids)
        self.assertEqual(found, {SECRET: {".env"}, SIDE: {"config/prod.env"}})
        if _parses(deep):
            self.assertIn("call_deep", ids)
            self.assertEqual(self.src.counts["unparsed"], 0)
        else:
            self.assertNotIn("call_deep", ids)
            self.assertEqual(self.src.counts["unparsed"], 2)


class Window(KimiCodeCase):

    def test_old_calls_in_a_recent_store_and_undated_calls(self):
        old_ms = int((time.time() - 400 * 86400) * 1000)
        path = self._wire([
            _meta(),
            _call("old", "Bash", {"command": "ls"}, old_ms),
            {"type": "context.append_loop_event", "agentId": "main",
             "event": {"type": "tool.call", "toolCallId": "undated",
                       "name": "Bash", "args": {"command": "pwd"}}},
            _call("new", "Bash", {"command": "id"}, int(time.time() * 1000)),
        ], age=60)
        store = self._store(path)
        self.assertEqual([s.path for s in self._stores(since_days=30)], [path])
        calls = {c.tool_call_id: c for c in self.src.tool_calls(store)}
        cutoff = time.time() - 30 * 86400

        def inside(call):
            stamp = call.timestamp or call.not_after
            when, _zoned = _stamps.parse_stamp(stamp)
            return when.timestamp() >= cutoff

        self.assertFalse(inside(calls["old"]))
        self.assertTrue(inside(calls["new"]))
        undated = calls["undated"]
        self.assertIsNone(undated.timestamp)
        self.assertEqual(undated.not_after, _stamps.iso_utc(store.mtime, "s"))
        self.assertTrue(inside(undated))
        self.assertIsNone(calls["new"].not_after)


# --------------------------------------------------------------------------
# Timing: how reading a large transcript grows, on its own interpreter
# (tests/growth.py)
# --------------------------------------------------------------------------

_CALL = r"""
from ranwhat.sources.kimi_code import KimiCodeSource
def call(root):
    src = KimiCodeSource()
    stores = src.stores(src.locations(override=root))
    calls = sum(1 for s in stores for c in src.tool_calls(s))
    texts = sum(1 for s in stores for t in src.secret_texts(s))
    return [len(stores), calls, texts]
"""


class Timing(KimiCodeCase):

    PAIRS = 60000

    def transcript(self, n):
        """A Kimi Code home whose one transcript holds n(PAIRS) calls, each
        result naming an output_path, so the spill pass parses each one
        too."""
        root = os.path.join(tempfile.mkdtemp(dir=self.home), ".kimi-code")
        filler = "x" * 300
        path = os.path.join(self._session_dir(root=root), "agents", "main",
                            "wire.jsonl")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(_j(_meta()) + "\n")
            for i in range(n(self.PAIRS)):
                cid = "call_%d" % i
                fh.write(_j(_call(cid, "Bash", {"command": "cat f%d.txt" % i},
                                  T0 + i)) + "\n")
                fh.write(_j(_result(cid, filler + " output_path: none\n",
                                    T0 + i)) + "\n")
        return root

    def test_a_large_transcript_is_read_in_time(self):
        env = dict(os.environ, HOME=self.home, USERPROFILE=self.home)
        env.pop("KIMI_CODE_HOME", None)
        measured, root = growth.measure_apart(self.transcript, _CALL, env=env)
        path = os.path.join(self._session_dir(root=root), "agents", "main",
                            "wire.jsonl")
        self.assertGreater(os.path.getsize(path), 30 * 1024 * 1024)
        growth.assert_linear(self, measured, "a 30 MB transcript")
        pairs = self.PAIRS
        self.assertEqual(measured.result, [1, pairs, 2 * pairs + 1])


if __name__ == "__main__":
    unittest.main()
