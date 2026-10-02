"""The Pi coding agent adapter (ranwhat/sources/pi.py, design 7.11).

Fixtures are built field for field from the spec's sample and from Pi's
own format document and message types (v0.99.2): a session header, then
"message" entries of a tree (id, parentId) whose assistant messages hold
toolCall blocks and whose toolResult messages answer them. Older format
versions are built as Pi wrote them: version 2 says "hookMessage" where 3
says "custom", and version 1 has no version, id or parentId.

Everything runs in temp directories: the home directory, Pi's own
PI_CODING_AGENT_DIR and PI_CODING_AGENT_SESSION_DIR, and clean's backup
root all point there, and the real home is never read. Every secret is
synthetic, and token-shaped ones are written as adjacent literals.

watch.judge and clean.scan_sources are wired in later. Until then, judge()
and findings() below follow design 3.5 and 3.6 to the letter, over
watch.evaluate and clean's own _walk and _origins.
"""
import contextlib
import glob
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
from ranwhat import clean, sources, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite  # noqa: E402
from ranwhat.sources import pi as pi_module  # noqa: E402
from ranwhat.sources.base import MaskResult, ToolCall  # noqa: E402
from ranwhat.sources.pi import (PiSource, output_text,  # noqa: E402
                                session_from_name)

ENV = "PI_CODING_AGENT_DIR"
SESSION_ENV = "PI_CODING_AGENT_SESSION_DIR"
WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
TYPED = "Hq3nV8xKp2" "Lw7RtY9mZc4BfD"           # an API_TOKEN typed by hand
SPEC_VALUE = "EXAMPLE_NOT_A_REAL_KEY"           # the spec sample's value

SID = "5f0c2a8e-0000-4000-8000-000000000000"
FOLDER = "--home-dev-app--"
NAME = "2026-10-01T09-00-00-000Z_" + SID + ".jsonl"

# The spec's fixture, byte for byte.
SPEC_LINES = [
    '{"type":"session","version":3,"id":"5f0c2a8e-0000-4000-8000-000000000000",'
    '"timestamp":"2026-10-01T09:00:00.000Z","cwd":"/home/dev/app"}',
    '{"type":"message","id":"a1b2c3d4","parentId":null,"timestamp":'
    '"2026-10-01T09:00:02.000Z","message":{"role":"assistant","content":'
    '[{"type":"toolCall","id":"call_1","name":"bash","arguments":{"command":'
    '"cat .env"}}],"api":"anthropic-messages","provider":"anthropic","model":'
    '"claude-sonnet-4-5","stopReason":"toolUse","timestamp":1790845202000}}',
    '{"type":"message","id":"b2c3d4e5","parentId":"a1b2c3d4","timestamp":'
    '"2026-10-01T09:00:03.000Z","message":{"role":"toolResult","toolCallId":'
    '"call_1","toolName":"bash","content":[{"type":"text","text":'
    '"API_KEY=EXAMPLE_NOT_A_REAL_KEY"}],"isError":false,"timestamp":'
    '1790845203000}}',
]

# 2026-10-01T09:00:00Z in milliseconds, the base of every fixture's times.
BASE_MS = 1790845200000


# --------------------------------------------------------------------------
# Fixture builders: Pi's records, compact like JSON.stringify writes them
# --------------------------------------------------------------------------

def _dump(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _iso(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms / 1000.0)) + \
        ".%03dZ" % (ms % 1000)


def header(sid=SID, cwd="/home/dev/app", version=3, ms=BASE_MS, **extra):
    line = {"type": "session"}
    if version is not None:
        line["version"] = version
    if sid is not None:
        line["id"] = sid
    line["timestamp"] = _iso(ms)
    if cwd is not None:
        line["cwd"] = cwd
    line.update(extra)
    return line


def eid(n):
    return "%08x" % (0xa0000000 + n)


def entry(n, message, parent="prev", ms=None, ts=True, tree=True):
    """A "message" entry. parent "prev" is the entry before it (n - 1), None
    is a root; tree=False is a version 1 entry, with no id or parentId."""
    ms = BASE_MS + n * 1000 if ms is None else ms
    line = {"type": "message"}
    if tree:
        line["id"] = eid(n)
        line["parentId"] = (eid(n - 1) if parent == "prev" and n > 1
                            else None if parent in ("prev", None) else parent)
    if ts:
        line["timestamp"] = _iso(ms)
    line["message"] = message
    return line


def tool_call(cid, name, arguments):
    return {"type": "toolCall", "id": cid, "name": name, "arguments": arguments}


def assistant(blocks, ms, stop="toolUse", **extra):
    """An assistant message. `stop` is its stopReason (ai/src/types.ts
    StopReason); extra fields (errorMessage) go after it, as Pi orders
    them."""
    message = {"role": "assistant", "content": blocks,
               "api": "anthropic-messages", "provider": "anthropic",
               "model": "claude-sonnet-4-5", "stopReason": stop}
    message.update(extra)
    message["timestamp"] = ms
    return message


def tool_result(cid, name, content, ms, is_error=False, **extra):
    if isinstance(content, str):
        content = [{"type": "text", "text": content}]
    message = {"role": "toolResult", "toolCallId": cid, "toolName": name,
               "content": content, "isError": is_error, "timestamp": ms}
    message.update(extra)
    return message


def bash_execution(command, output, ms, exit_code=0, cancelled=False,
                   truncated=False, **extra):
    """A command the user ran with "!" (core/messages.ts)."""
    message = {"role": "bashExecution", "command": command, "output": output}
    if exit_code is not None:
        message["exitCode"] = exit_code
    message.update({"cancelled": cancelled, "truncated": truncated})
    message.update(extra)
    message["timestamp"] = ms
    return message


def user(text, ms):
    return {"role": "user", "content": text, "timestamp": ms}


class _Nested(dict):
    """A nested call record, and the arguments the call was made with:
    codemode's display copy previews them even when Pi's record leaves
    them out."""
    made_with = None


def nested_record(rid, name, arguments, status="ok", duration=3,
                  error=None, omitted=False):
    """A NestedToolCallRecord as NestedCallRecorder writes it (ai/src/
    types.ts; core/nested-tool-calls.ts start and finish): id, name and
    status, then arguments, or argumentsBytes (their UTF-8 size as JSON)
    when Pi left them out, then durationMs and error once the call has
    finished. An "unfinished" call has neither."""
    record = _Nested(id=rid, name=name, status=status)
    record.made_with = arguments
    if omitted:
        record["argumentsBytes"] = len(_dump(arguments).encode("utf-8"))
    else:
        record["arguments"] = arguments
    if status != "unfinished":
        record["durationMs"] = duration
    if error is not None:
        record["error"] = error
    return record


def _preview(arguments):
    """codemode's previewArgs: compact JSON cut to 200 characters."""
    text = _dump(arguments)
    return text[:197] + "..." if len(text) > 200 else text


def codemode_lines(n, cid, code, records, complete=True, output="",
                   ok=True):
    """A codemode call and its result, as execute.ts and the session write
    them: the script's output after codemode's header; codemode's display
    copy of the calls in details.calls (args previewed, a call cut off
    shown as "cancelled"); then, set by the session on the result message,
    nestedCalls (extensions/codemode/execute.ts; agent-loop.ts
    createToolResultMessage; agent-session.ts _handleAgentEvent)."""
    ms = BASE_MS + n * 1000
    head = ("Script completed" if ok else "Script failed") + \
        "\nWall time 0.1 seconds\nOutput:\n"
    content = [{"type": "text", "text": head}]
    if output:
        content.append({"type": "text", "text": output})
    shown = []
    for r in records:
        if not isinstance(r, dict):
            continue
        made_with = getattr(r, "made_with", r.get("arguments", {}))
        status = r.get("status")
        item = {"id": r.get("id"), "name": r.get("name"),
                "args": _preview(made_with),
                "status": "cancelled" if status == "unfinished" else status}
        if "durationMs" in r:
            item["durationMs"] = r["durationMs"]
        if "error" in r:
            item["error"] = r["error"]
        shown.append(item)
    result = {"role": "toolResult", "toolCallId": cid, "toolName": "codemode",
              "content": content, "details": {"calls": shown},
              "isError": not ok, "timestamp": ms + 1000,
              "nestedCalls": {"calls": records, "complete": complete}}
    return [entry(n, assistant([tool_call(cid, "codemode", {"code": code})],
                               ms)),
            entry(n + 1, result)]


def not_executed(cid, name, ms):
    """The result Pi writes, since 0.80.4, for a call from an assistant
    message that stopped on "length" (agent-loop.ts
    failToolCallsFromTruncatedMessage, createErrorToolResult)."""
    return tool_result(
        cid, name, 'Tool call "%s" was not executed: the response hit the '
        'output token limit, so its arguments may be truncated. Re-issue the '
        'tool call with complete arguments.' % name, ms, is_error=True,
        details={})


def call_lines(n, cid, name, arguments, output=None, is_error=False,
               parent="prev", tree=True, ts=True):
    """An assistant entry holding one toolCall and, when output is given,
    the toolResult entry answering it: the two message lines of the spec's
    sample."""
    ms = BASE_MS + n * 1000
    lines = [entry(n, assistant([tool_call(cid, name, arguments)], ms),
                   parent=parent, tree=tree, ts=ts)]
    if output is not None:
        lines.append(entry(n + 1, tool_result(cid, name, output, ms + 1000,
                                              is_error),
                           tree=tree, ts=ts))
    return lines


def user_lines(n, command, output, **kw):
    ms = BASE_MS + n * 1000
    return [entry(n, bash_execution(command, output, ms, **kw))]


# --------------------------------------------------------------------------
# watch and clean as design 3.5 and 3.6 describe them
# --------------------------------------------------------------------------

NEUTRAL = "ranwhat:%s"


def judge(call):
    """(hits, payload) for one ToolCall: watch.judge once it exists, else
    design 3.5's judge() over today's watch.evaluate."""
    real = getattr(watch, "judge", None)
    if real is not None:
        return real(call)
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


def rules(call):
    return [(h["rule"], h["evidence"]) for h in judge(call)[0]]


def _named_by_input(call):
    """Design 3.6: the call's input with its consumed keys replaced by the
    normalised command (heredocs stripped) or the paths it read."""
    rest = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.command:
        rest["command"] = watch._strip_heredocs(call.command)
    if call.kind == "read" and call.paths:
        rest["paths"] = list(call.paths)
    return clean._origins(json.dumps(rest, ensure_ascii=False))


def findings(source, stores):
    """{value: {"origins", "count", "stores", "where"}} for every secret in
    these stores, crediting origins the way design 3.6 says."""
    found = {}
    for store in stores:
        for text in source.secret_texts(store):
            origin = None
            if text.attached:
                origin = text.attached
            elif text.call is not None:
                named = _named_by_input(text.call)
                origin = named[-1] if named else None

            def collect(value, label, _in=None, _copies=None, origin=origin,
                        store=store, text=text):
                item = found.setdefault(value, {"origins": set(), "count": 0,
                                                "stores": set(), "where": []})
                item["count"] += 1
                item["stores"].add(store.path)
                item["where"].append(text.where)
                if origin:
                    item["origins"].add(origin)
            clean._walk(text.node, collect)
    return found


def _strings(node):
    """Every string value in a decoded JSON structure (keys aside)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _tempdir(case, prefix):
    """A temp directory removed when the test ends."""
    path = tempfile.mkdtemp(prefix=prefix)
    case.addCleanup(shutil.rmtree, path, True)
    return path


# --------------------------------------------------------------------------
# Common setup
# --------------------------------------------------------------------------

class PiCase(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "pi-home-")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ENV, None)
        os.environ.pop(SESSION_ENV, None)
        self.backups = os.path.join(_tempdir(self, "pi-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.root = os.path.join(self.home, ".pi", "agent")
        self.pi = PiSource()

    def write(self, rel, lines, age=3600, root=None, mode=None, raw=None):
        """Write JSON lines (or raw bytes) at root/rel, aged `age` seconds."""
        path = os.path.join(root or self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if raw is None:
            raw = "".join((line if isinstance(line, str) else _dump(line))
                          + "\n" for line in lines).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        if mode is not None and not WINDOWS:
            os.chmod(path, mode)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def session(self, lines, name=NAME, folder=FOLDER, **kw):
        return self.write("sessions/%s/%s" % (folder, name), lines, **kw)

    def stores(self, override=None, since_days=None):
        return self.pi.stores(self.pi.locations(override=override),
                              since_days=since_days)

    def store(self, path):
        for store in self.stores():
            if store.path == path:
                return store
        self.fail("%s is not a store" % path)

    def calls(self, path):
        return list(self.pi.tool_calls(self.store(path)))

    def by_id(self, path):
        return {c.tool_call_id: c for c in self.calls(path)}


# --------------------------------------------------------------------------
# 1, 2, 3: where Pi keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        p = PiSource()
        self.assertEqual(p.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.pi/agent", "default")])
        self.assertEqual(p.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.pi/agent", "default")])
        self.assertEqual(p.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.pi\\agent", "default")])

    def test_the_agent_dir_variable_replaces_the_default(self):
        p = PiSource()
        how = "env " + ENV
        self.assertEqual(p.default_paths({ENV: "/srv/pi"}, "/home/u", "linux"),
                         [("/srv/pi", how)])
        self.assertEqual(p.default_paths({ENV: "/srv/pi"}, "/Users/u", "darwin"),
                         [("/srv/pi", how)])
        self.assertEqual(p.default_paths({ENV: "D:\\pi"}, "C:\\Users\\u", "win32"),
                         [("D:\\pi", how)])

    def test_a_leading_tilde_is_the_home_directory(self):
        # Pi's normalizePath: "~", "~/x" everywhere, and "~\x" on Windows
        p = PiSource()
        how = "env " + ENV
        self.assertEqual(p.default_paths({ENV: "~/pi-alt"}, "/home/u", "linux"),
                         [("/home/u/pi-alt", how)])
        self.assertEqual(p.default_paths({ENV: "~"}, "/home/u", "linux"),
                         [("/home/u", how)])
        self.assertEqual(p.default_paths({ENV: "~\\pi"}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\pi", how)])
        self.assertEqual(p.default_paths({ENV: "~/pi"}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\pi", how)])
        # not a home directory: kept as written
        self.assertEqual(p.default_paths({ENV: "~bob/pi"}, "/home/u", "linux"),
                         [("~bob/pi", how)])
        self.assertEqual(p.default_paths({ENV: "~\\pi"}, "/home/u", "linux"),
                         [("~\\pi", how)])

    def test_the_session_dir_variable_is_looked_at_beside_the_agent_folder(self):
        p = PiSource()
        flat = "env " + SESSION_ENV
        self.assertEqual(
            p.default_paths({SESSION_ENV: "/srv/s"}, "/home/u", "linux"),
            [("/home/u/.pi/agent", "default"), ("/srv/s", flat)])
        self.assertEqual(
            p.default_paths({SESSION_ENV: "~/s", ENV: "/srv/pi"}, "/Users/u",
                            "darwin"),
            [("/srv/pi", "env " + ENV), ("/Users/u/s", flat)])
        self.assertEqual(
            p.default_paths({SESSION_ENV: "E:\\s"}, "C:\\Users\\u", "win32"),
            [("C:\\Users\\u\\.pi\\agent", "default"), ("E:\\s", flat)])

    def test_an_empty_variable_is_not_set(self):
        self.assertEqual(
            PiSource().default_paths({ENV: "", SESSION_ENV: ""}, "/home/u",
                                     "linux"),
            [("/home/u/.pi/agent", "default")])

    def test_what_every_report_needs(self):
        p = PiSource()
        self.assertEqual((p.id, p.name, p.unit, p.env), (
            "pi", "Pi", "session", (ENV, SESSION_ENV)))
        self.assertIn(ENV, p.path_means)
        self.assertEqual(p.checked, "0.99.2")
        for text in (p.path_means, p.mask_note):
            self.assertNotIn("\u2014", text)
        # wired into the registry (ranwhat.sources.ADAPTERS)
        self.assertIn("pi", sources.ids())
        self.assertIsInstance(sources.get("pi"), PiSource)

    def test_path_keys_are_watchs_own(self):
        self.assertEqual(pi_module.PATH_KEYS, watch._PATH_KEYS)

    def test_session_from_a_file_name(self):
        self.assertEqual(session_from_name("/x/" + NAME), SID)
        self.assertEqual(session_from_name("2026-10-01T09-00-00-000Z_my_id.jsonl"),
                         "my_id")
        self.assertEqual(session_from_name("plain.jsonl"), "plain")


class Discovery(PiCase):

    def test_the_agent_dir_variable_is_read_at_call_time(self):
        first = self.pi.locations()
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in first],
                         [(self.root, "default", False, 0)])
        moved = _tempdir(self, "pi-moved-")
        path = self.session(SPEC_LINES, root=moved)
        os.environ[ENV] = moved             # after import and construction
        locs = self.pi.locations()
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in locs],
                         [(moved, "env " + ENV, True, 1)])
        self.assertEqual([s.path for s in self.pi.stores(locs)], [path])

    def test_the_session_dir_variable_is_read_at_call_time(self):
        older = self.session(SPEC_LINES, age=500)
        flat = _tempdir(self, "pi-flat-")
        os.environ[SESSION_ENV] = flat
        name = "2026-10-01T10-00-00-000Z_6a1d3b9f-0000-4000-8000-000000000001.jsonl"
        newer = self.write(name, [header(sid="6a1d3b9f-0000-4000-8000-000000000001",
                                         cwd="/home/dev/other")],
                           root=flat, age=100)
        # a per-cwd folder there is not where Pi writes: not read
        self.write("--home-dev-app--/x.jsonl", [header()], root=flat)
        locs = self.pi.locations()
        self.assertEqual([(l.path, l.how, l.found) for l in locs], [
            (self.root, "default", 1), (flat, "env " + SESSION_ENV, 1)])
        found = self.pi.stores(locs)
        self.assertEqual([s.path for s in found], [newer, older])
        self.assertEqual((found[0].session, found[0].project),
                         ("6a1d3b9f-0000-4000-8000-000000000001", "/home/dev/other"))

    def test_sessions_are_found_newest_first_and_nothing_else_is(self):
        a = self.session(SPEC_LINES, age=500)
        b = self.session([header(sid="11111111-aaaa-4aaa-8aaa-000000000001",
                                 cwd="/home/dev/b")],
                         name="2026-10-01T09-10-00-000Z_11111111-aaaa-4aaa-8aaa-000000000001.jsonl",
                         folder="--home-dev-b--", age=300)
        windows = self.session(
            [header(sid="22222222-bbbb-4bbb-8bbb-000000000002",
                    cwd="C:\\Users\\dev\\app")],
            name="2026-10-01T09-20-00-000Z_22222222-bbbb-4bbb-8bbb-000000000002.jsonl",
            folder="--C--Users-dev-app--", age=200)
        # not stores
        for rel in ("auth.json", "settings.json", "models.json", "pi-debug.log",
                    "x.jsonl", "sessions/loose.jsonl",
                    "sessions/--home-dev-app--/notes.json",
                    "sessions/--home-dev-app--/.hidden.jsonl",
                    "sessions/.cache/y.jsonl",
                    "sessions/--home-dev-app--/deeper/z.jsonl"):
            self.write(rel, [header()], age=10)
        found = self.stores()
        self.assertEqual([s.path for s in found], [windows, b, a])
        for store in found:
            self.assertEqual((store.format, store.role, store.unit, store.masking),
                             ("jsonl", "transcript", "session", "rewrite"))
        self.assertEqual(self.pi.locations()[0].found, 3)

    def test_session_and_project_of_a_store(self):
        spec = self.session(SPEC_LINES)
        bare = self.session([header(sid=None, cwd=None)],
                            name="2026-10-01T09-30-00-000Z_33333333-cccc-4ccc-8ccc-000000000003.jsonl")
        not_a_header = self.session([entry(1, user("hi", BASE_MS))],
                                    name="44444444-dddd-4ddd-8ddd-000000000004.jsonl")
        got = {s.path: (s.session, s.project) for s in self.stores()}
        self.assertEqual(got[spec], (SID, "/home/dev/app"))
        # no id: the file name says it; no cwd: the folder name is not
        # turned back into a path (its dashes are lossy)
        self.assertEqual(got[bare], ("33333333-cccc-4ccc-8ccc-000000000003", None))
        self.assertEqual(got[not_a_header],
                         ("44444444-dddd-4ddd-8ddd-000000000004", None))

    def test_path_means_an_agent_folder(self):
        elsewhere = _tempdir(self, "pi-path-")
        path = self.session(SPEC_LINES, root=elsewhere)
        self.session(SPEC_LINES)                     # the default: not read
        [loc] = self.pi.locations(override=elsewhere)
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (elsewhere, "--path", True, 1))
        self.assertEqual([s.path for s in self.stores(override=elsewhere)], [path])

    def test_a_missing_root_is_zero_stores(self):
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.stores(override=os.path.join(self.home, "nope")), [])
        os.makedirs(os.path.join(self.root, "sessions", FOLDER))
        self.assertEqual(self.stores(), [])
        os.environ[SESSION_ENV] = os.path.join(self.home, "missing")
        self.assertEqual(self.stores(), [])

    def test_days_prefilter_by_last_write(self):
        new = self.session(SPEC_LINES, age=60)
        self.session(SPEC_LINES, name="old.jsonl", age=90 * 86400)
        self.assertEqual([s.path for s in self.stores(since_days=30)], [new])


# --------------------------------------------------------------------------
# Tool calls: kinds, outputs, time, dedupe, every format version
# --------------------------------------------------------------------------

class ToolCalls(PiCase):

    def test_the_spec_sample(self):
        path = self.session(SPEC_LINES)
        self.assertEqual(self.calls(path), [ToolCall(
            "pi", path, "bash", {"command": "cat .env"}, kind="shell",
            known=True, session=SID, project="/home/dev/app",
            timestamp="2026-10-01T09:00:02Z", tool_call_id="call_1",
            command="cat .env", consumed=("command",),
            output="API_KEY=" + SPEC_VALUE)])
        self.assertEqual(self.pi.counts["unknown"], 0)

    def test_every_tool_in_the_spec_maps_to_its_kind(self):
        rows = [
            ("t1", "bash", {"command": "ls -la", "timeout": 30},
             ("shell", True, "ls -la", (), {"command"})),
            ("t2", "read", {"path": "/home/dev/app/a.py", "offset": 1,
                            "limit": 20},
             ("read", True, None, ("/home/dev/app/a.py",), {"path"})),
            ("t3", "write", {"path": "/home/dev/app/b.py", "content": "x"},
             ("write", True, None, ("/home/dev/app/b.py",), set())),
            # Pi's other tools are not in the spec: judged by their names
            ("t4", "edit", {"path": "a.py", "edits": [{"oldText": "a",
                                                       "newText": "b"}]},
             ("other", False, None, (), set())),
            ("t5", "grep", {}, ("other", False, None, (), set())),
            ("t6", "find", {}, ("other", False, None, (), set())),
            ("t7", "ls", {}, ("other", False, None, (), set())),
            ("t8", "powershell", {"command": "dir"},
             ("other", False, None, (), set())),
            ("t9", "mcp__srv__bash", {}, ("other", False, None, (), set())),
            # names match exactly
            ("t10", "Bash", {"command": "ls"}, ("other", False, None, (), set())),
            ("t11", "Read", {"path": "a"}, ("other", False, None, (), set())),
        ]
        lines = [header()]
        for n, (cid, name, arguments, _want) in enumerate(rows):
            lines += call_lines(10 + 2 * n, cid, name, arguments, output="ok")
        got = self.by_id(self.session(lines))
        self.assertEqual(len(got), len(rows))
        for cid, name, arguments, want in rows:
            call = got[cid]
            self.assertEqual((call.tool_name, call.tool_input), (name, arguments))
            self.assertEqual((call.kind, call.known, call.command, call.paths,
                              set(call.consumed)), want, name)
            self.assertEqual(call.output, "ok")
            self.assertEqual((call.actor, call.status, call.workdir),
                             ("agent", None, None))

    def test_read_takes_whichever_of_watchs_path_keys_it_holds(self):
        lines = [header()]
        lines += call_lines(10, "a", "read", {"file_path": "/p/a", "offset": 2})
        lines += call_lines(12, "b", "read", {"paths": ["/p/b", "/p/c", 7],
                                              "path": "/p/d"})
        lines += call_lines(14, "c", "read", {"location": "/p/e"})
        lines += call_lines(16, "d", "read", {"path": ""})
        lines += call_lines(18, "e", "write", {"filePath": "/p/f", "content": "x"})
        got = self.by_id(self.session(lines))
        self.assertEqual((got["a"].paths, got["a"].consumed),
                         (("/p/a",), frozenset({"file_path"})))
        self.assertEqual((got["b"].paths, got["b"].consumed),
                         (("/p/d", "/p/b", "/p/c"), frozenset({"path", "paths"})))
        for cid in "cd":
            self.assertEqual((got[cid].kind, got[cid].known, got[cid].paths,
                              got[cid].consumed), ("read", True, (), frozenset()))
        self.assertEqual((got["e"].paths, got["e"].consumed),
                         (("/p/f",), frozenset()))

    def test_a_leading_at_is_dropped_as_pi_drops_it(self):
        # read and write resolve their path with stripAtPrefix: one leading
        # "@" goes (core/tools/path-utils.ts, utils/paths.ts normalizePath)
        lines = [header()]
        lines += call_lines(10, "env", "read", {"path": "@.env"})
        lines += call_lines(12, "home", "read", {"path": "@~/.ssh/id_rsa"})
        lines += call_lines(14, "twice", "read", {"path": "@@odd"})
        lines += call_lines(16, "bare", "read", {"path": "@"})
        lines += call_lines(18, "inside", "read", {"path": "docs/a@b.md"})
        lines += call_lines(20, "list", "read", {"paths": ["@a.py", "b.py"]})
        lines += call_lines(22, "out", "write", {"path": "@notes/out.md",
                                                 "content": "x"})
        got = self.by_id(self.session(lines))
        self.assertEqual({cid: (c.paths, c.consumed) for cid, c in got.items()}, {
            "env": ((".env",), frozenset({"path"})),
            "home": (("~/.ssh/id_rsa",), frozenset({"path"})),
            "twice": (("@odd",), frozenset({"path"})),
            "bare": ((), frozenset()),
            "inside": (("docs/a@b.md",), frozenset({"path"})),
            "list": (("a.py", "b.py"), frozenset({"paths"})),
            "out": (("notes/out.md",), frozenset())})
        # the input as recorded keeps the "@"
        self.assertEqual(got["env"].tool_input, {"path": "@.env"})

    def test_a_shell_call_whose_command_is_missing(self):
        lines = [header()]
        lines += call_lines(10, "a", "bash", {"timeout": 5})
        lines += call_lines(12, "b", "bash", {"command": ["rm", "-rf", "x"]})
        lines += call_lines(14, "c", "bash", {"command": ""})
        got = self.by_id(self.session(lines))
        for cid in "abc":
            self.assertEqual((got[cid].kind, got[cid].known, got[cid].command,
                              got[cid].consumed), ("shell", True, None, frozenset()))

    def test_arguments_stored_as_a_string_are_decoded(self):
        lines = [header()]
        lines += call_lines(10, "a", "bash", '{"command": "pwd"}')
        lines += call_lines(12, "b", "bash", "not json")
        lines += call_lines(14, "c", "bash", None)
        got = self.by_id(self.session(lines))
        self.assertEqual((got["a"].tool_input, got["a"].command),
                         ({"command": "pwd"}, "pwd"))
        self.assertEqual((got["b"].tool_input, got["b"].command),
                         ({"_raw": "not json"}, None))
        self.assertEqual(got["c"].tool_input, {})

    def test_a_namespaced_tool_is_not_one_of_pis_own(self):
        block = tool_call("ns1", "bash", {"command": "ls"})
        block["namespace"] = "remote_tools"
        lines = [header(), entry(10, assistant([block], BASE_MS))]
        [call] = self.calls(self.session(lines))
        self.assertEqual((call.tool_name, call.kind, call.known, call.command),
                         ("remote_tools.bash", "other", False, None))

    def test_outputs_in_every_stored_shape(self):
        image = {"type": "image", "data": "iVBORw0KGgo=", "mimeType": "image/png"}
        lines = [header()]
        lines += call_lines(10, "ok", "bash", {"command": "ls"}, output="a.py\nb.py")
        lines += call_lines(12, "fail", "bash", {"command": "false"},
                            output="boom\n\nCommand exited with code 1",
                            is_error=True)
        lines += call_lines(14, "blocks", "read", {"path": "/p/x.png"},
                            output=[{"type": "text", "text": "first"}, image,
                                    {"type": "text", "text": "second"}])
        lines += call_lines(16, "image", "read", {"path": "/p/y.png"},
                            output=[image])
        lines += call_lines(18, "empty", "bash", {"command": "true"}, output=[])
        lines += call_lines(20, "none", "bash", {"command": "sleep 100"})
        got = self.by_id(self.session(lines))
        self.assertEqual(got["ok"].output, "a.py\nb.py")
        self.assertEqual(got["fail"].output, "boom\n\nCommand exited with code 1")
        self.assertIsNone(got["fail"].status)          # an error is not "declined"
        self.assertEqual(got["blocks"].output, "first\nsecond")
        self.assertIsNone(got["image"].output)
        self.assertIsNone(got["empty"].output)
        self.assertIsNone(got["none"].output)
        self.assertEqual(output_text("plain"), "plain")
        self.assertIsNone(output_text(None))
        self.assertIsNone(output_text({"text": "x"}))

    def test_a_command_the_user_ran_with_a_bang(self):
        lines = [header()]
        lines += user_lines(10, "git status", "On branch main\n")
        lines += user_lines(11, "sleep 60", "", exit_code=None, cancelled=True)
        lines += user_lines(12, "cat big.log", "tail of it", truncated=True,
                            fullOutputPath="/tmp/pi-bash-1a2b3c.log")
        lines += user_lines(13, "env", "PATH=/bin", excludeFromContext=True)
        got = self.by_id(self.session(lines))
        self.assertEqual(sorted(got), [eid(10), eid(11), eid(12), eid(13)])
        status = got[eid(10)]
        self.assertEqual(status, ToolCall(
            "pi", status.store, "bashExecution", {"command": "git status"},
            kind="shell", known=True, actor="user", session=SID,
            project="/home/dev/app", timestamp="2026-10-01T09:00:10Z",
            tool_call_id=eid(10), command="git status", consumed=("command",),
            output="On branch main\n"))
        # a cancelled command still ran; "!!" keeps it from the model, not
        # from the shell
        for key in (eid(11), eid(12), eid(13)):
            self.assertEqual((got[key].actor, got[key].status, got[key].kind),
                             ("user", None, "shell"))
        self.assertEqual(got[eid(11)].output, "")
        self.assertEqual(got[eid(12)].output, "tail of it")

    def test_time_is_utc_with_the_message_time_as_a_fallback(self):
        lines = [header()]
        lines += call_lines(10, "zulu", "bash", {"command": "a"}, output="")
        zoned = call_lines(12, "zoned", "bash", {"command": "b"}, output="")
        zoned[0]["timestamp"] = "2026-10-01T11:00:12.000+02:00"
        lines += zoned
        lines += call_lines(14, "message", "bash", {"command": "c"}, output="",
                            ts=False)
        bare = call_lines(16, "undated", "bash", {"command": "d"}, ts=False)
        del bare[0]["message"]["timestamp"]
        lines += bare
        path = self.session(lines, age=7200)
        got = self.by_id(path)
        self.assertEqual((got["zulu"].timestamp, got["zulu"].not_after),
                         ("2026-10-01T09:00:10Z", None))
        self.assertEqual(got["zoned"].timestamp, "2026-10-01T09:00:12Z")
        self.assertEqual(got["message"].timestamp, "2026-10-01T09:00:14Z")
        mtime = os.stat(path).st_mtime
        self.assertIsNone(got["undated"].timestamp)
        self.assertEqual(got["undated"].not_after, time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime)))

    def test_session_and_project(self):
        forked = self.session(
            [header(sid="77777777-aaaa-4aaa-8aaa-000000000007", cwd="/home/dev/fork",
                    parentSession="/home/u/.pi/agent/sessions/--home-dev-app--/" + NAME)]
            + call_lines(10, "a", "bash", {"command": "pwd"}, output="/"),
            name="2026-10-01T10-00-00-000Z_77777777-aaaa-4aaa-8aaa-000000000007.jsonl")
        windows = self.session(
            [header(sid="88888888-bbbb-4bbb-8bbb-000000000008",
                    cwd="C:\\Users\\dev\\app")]
            + call_lines(10, "b", "bash", {"command": "dir"}, output=""),
            name="2026-10-01T11-00-00-000Z_88888888-bbbb-4bbb-8bbb-000000000008.jsonl",
            folder="--C--Users-dev-app--")
        bare = self.session(
            [header(sid=None, cwd=None)]
            + call_lines(10, "c", "bash", {"command": "pwd"}, output=""),
            name="2026-10-01T12-00-00-000Z_99999999-cccc-4ccc-8ccc-000000000009.jsonl")
        [a] = self.calls(forked)
        self.assertEqual((a.session, a.project),
                         ("77777777-aaaa-4aaa-8aaa-000000000007", "/home/dev/fork"))
        [b] = self.calls(windows)
        self.assertEqual((b.session, b.project),
                         ("88888888-bbbb-4bbb-8bbb-000000000008", "C:\\Users\\dev\\app"))
        [c] = self.calls(bare)
        self.assertEqual((c.session, c.project),
                         ("99999999-cccc-4ccc-8ccc-000000000009", None))

    def test_both_branches_of_a_tree_are_reported(self):
        # user -> assistant(call_a) -> result; then /tree back to the user
        # entry and a second answer: assistant(call_b) -> result
        lines = [header(), entry(1, user("clean up", BASE_MS + 1000), parent=None)]
        lines += call_lines(2, "call_a", "bash", {"command": "rm -rf build"},
                            output="")
        lines.append({"type": "branch_summary", "id": eid(4), "parentId": eid(1),
                      "timestamp": _iso(BASE_MS + 4000), "fromId": eid(3),
                      "summary": "Tried rm -rf build"})
        lines += call_lines(5, "call_b", "bash", {"command": "make clean"},
                            output="", parent=eid(4))
        calls = self.calls(self.session(lines))
        self.assertEqual([(c.tool_call_id, c.command) for c in calls],
                         [("call_a", "rm -rf build"), ("call_b", "make clean")])
        self.assertEqual(self.pi.counts["unknown"], 0)

    def test_dedupe_by_tool_call_id(self):
        lines = [header()]
        lines += call_lines(10, "call_A", "bash", {"command": "cat .env"},
                            output="first")
        # the same entry copied again (a fork's path written into one file)
        lines += call_lines(10, "call_A", "bash", {"command": "cat .env"},
                            output="second")
        # a call copied before its result arrives
        lines += call_lines(20, "call_B", "read", {"path": "a"})
        lines += call_lines(21, "call_B", "read", {"path": "a"})
        lines.append(entry(22, tool_result("call_B", "read", "text", BASE_MS)))
        # two calls in one message, answered in turn
        lines.append(entry(30, assistant([
            tool_call("call_C", "bash", {"command": "ls"}),
            tool_call("call_D", "bash", {"command": "pwd"})], BASE_MS)))
        lines.append(entry(31, tool_result("call_D", "bash", "/w", BASE_MS)))
        lines.append(entry(32, tool_result("call_C", "bash", "a b", BASE_MS)))
        # a user command copied twice
        lines += user_lines(40, "whoami", "dev")
        lines += user_lines(40, "whoami", "dev")
        calls = self.calls(self.session(lines))
        self.assertEqual(sorted(c.tool_call_id for c in calls),
                         sorted(["call_A", "call_B", "call_C", "call_D", eid(40)]))
        got = {c.tool_call_id: c for c in calls}
        self.assertEqual(got["call_A"].output, "first")
        self.assertEqual(got["call_A"].timestamp, "2026-10-01T09:00:10Z")
        self.assertEqual(got["call_B"].output, "text")
        self.assertEqual((got["call_C"].output, got["call_D"].output), ("a b", "/w"))

    def test_a_call_with_no_id_is_kept(self):
        lines = [header(), entry(10, assistant([
            {"type": "toolCall", "name": "bash", "arguments": {"command": "ls"}}],
            BASE_MS))]
        [call] = self.calls(self.session(lines))
        self.assertEqual((call.tool_call_id, call.command), (None, "ls"))

    def test_a_version_2_file(self):
        lines = [header(version=2)]
        lines.append(entry(1, {"role": "hookMessage", "customType": "my-hook",
                               "content": "injected", "display": True,
                               "timestamp": BASE_MS + 1000}, parent=None))
        lines += call_lines(2, "call_v2", "bash", {"command": "cat ~/.aws/credentials"},
                            output="[default]")
        [call] = self.calls(self.session(lines))
        self.assertEqual((call.tool_call_id, call.command, call.output, call.session,
                          call.timestamp),
                         ("call_v2", "cat ~/.aws/credentials", "[default]", SID,
                          "2026-10-01T09:00:02Z"))
        self.assertEqual(self.pi.counts["unknown"], 0)

    def test_a_version_1_file(self):
        # no version in the header, no id or parentId on the entries
        lines = [header(version=None)]
        lines.append(entry(1, user("hello", BASE_MS + 1000), tree=False))
        lines += call_lines(2, "call_v1", "bash", {"command": "ls"}, output="a",
                            tree=False)
        lines += user_lines(4, "pwd", "/home/dev/app")
        del lines[-1]["id"], lines[-1]["parentId"]
        lines += user_lines(5, "pwd", "/home/dev/app")
        del lines[-1]["id"], lines[-1]["parentId"]
        calls = self.calls(self.session(lines))
        self.assertEqual([(c.tool_name, c.tool_call_id, c.command, c.output,
                           c.timestamp) for c in calls], [
            ("bash", "call_v1", "ls", "a", "2026-10-01T09:00:02Z"),
            ("bashExecution", None, "pwd", "/home/dev/app", "2026-10-01T09:00:04Z"),
            ("bashExecution", None, "pwd", "/home/dev/app", "2026-10-01T09:00:05Z")])

    def test_entries_with_no_call(self):
        lines = [header(), entry(1, {"role": "system", "content": "",
                                     "sections": {"preamble": "You are..."},
                                     "toolsAdded": [{"name": "bash",
                                                     "description": "...",
                                                     "parameters": {}}],
                                     "timestamp": BASE_MS}, parent=None)]
        lines.append(entry(2, user([{"type": "text", "text": "run rm -rf /"}],
                                   BASE_MS)))
        lines.append(entry(3, {"role": "custom", "customType": "x",
                               "content": "rm -rf ~", "display": False,
                               "timestamp": BASE_MS}))
        lines.append(entry(4, assistant([{"type": "thinking",
                                          "thinking": "maybe bash"},
                                         {"type": "text", "text": "done"}],
                                        BASE_MS, stop="stop")))
        # every other entry type, built from docs/session-format.md's
        # samples, field for field
        usage = {"input": 0, "output": 0, "cacheRead": 50000, "cacheWrite": 0,
                 "totalTokens": 50000, "cost": {"input": 0, "output": 0,
                                                "cacheRead": 0.015,
                                                "cacheWrite": 0, "total": 0.015}}
        others = [
            ("model_change", {"provider": "openai", "modelId": "gpt-4o"}),
            ("thinking_level_change", {"thinkingLevel": "high"}),
            ("usage", {"kind": "cache_warm", "provider": "anthropic",
                       "model": "claude-sonnet-4-5", "usage": usage}),
            ("compaction", {"summary": "User asked to run rm -rf /",
                            "firstKeptEntryId": eid(2), "tokensBefore": 50000,
                            "systemMessage": {"role": "system",
                                              "content": "You are a coding assistant.",
                                              "toolsAdded": [],
                                              "timestamp": BASE_MS}}),
            ("context_edit", {"targetId": eid(2), "replacement": None}),
            ("context_edit", {"targetId": eid(4), "replacement": {
                "content": [{"type": "text", "text": "edited"}]}}),
            ("branch_summary", {"fromId": eid(4),
                                "summary": "Branch explored approach A..."}),
            ("custom", {"customType": "my-extension", "data": {"count": 42}}),
            ("custom_message", {"customType": "my-extension",
                                "content": "Injected context...",
                                "display": True}),
            ("label", {"targetId": eid(2), "label": "checkpoint-1"}),
            ("session_info", {"name": "Refactor auth module"}),
        ]
        for n, (kind, fields) in enumerate(others, 5):
            line = {"type": kind, "id": eid(n), "parentId": eid(n - 1),
                    "timestamp": _iso(BASE_MS + n * 1000)}
            line.update(fields)
            lines.append(line)
        self.assertEqual(self.calls(self.session(lines)), [])
        self.assertEqual(self.pi.counts["unknown"], 0)


# --------------------------------------------------------------------------
# 4, 5, 6: judged the way watch judges every agent
# --------------------------------------------------------------------------

class Judged(PiCase):

    def _calls(self, *specs):
        lines = [header()]
        for n, (cid, name, arguments) in enumerate(specs):
            lines += call_lines(10 + 2 * n, cid, name, arguments, output="")
        return self.by_id(self.session(lines))

    def test_a_dangerous_shell_call_is_flagged(self):
        got = self._calls(("rm", "bash", {"command": "rm -rf ~/Documents/x",
                                          "timeout": 30}),
                          ("aws", "bash", {"command": "cat ~/.aws/credentials"}))
        self.assertEqual(rules(got["rm"]), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(got["aws"]), [("cred.read", "cat ~/.aws/credentials")])

    def test_a_dangerous_command_the_user_ran_is_flagged(self):
        lines = [header()] + user_lines(10, "rm -rf ~/Documents/x", "")
        lines += user_lines(11, "cat ~/.aws/credentials", "[default]")
        got = self.by_id(self.session(lines))
        self.assertEqual(rules(got[eid(10)]),
                         [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(got[eid(11)]),
                         [("cred.read", "cat ~/.aws/credentials")])

    def test_a_credential_read_by_the_read_tool_is_flagged(self):
        got = self._calls(("ssh", "read", {"path": "~/.ssh/id_rsa"}),
                          ("env", "read", {"path": "/home/dev/app/.env",
                                           "offset": 1, "limit": 100}),
                          ("odd", "read", {"location": "~/.ssh/id_rsa"}),
                          ("num", "read", {"path": 12}))
        self.assertEqual(rules(got["ssh"]), [("cred.read", "~/.ssh/id_rsa")])
        self.assertEqual([r for r, _e in rules(got["env"])], ["cred.read"])
        # a key that is not one of watch's path keys: not read as a path
        self.assertEqual(rules(got["odd"]), [])
        self.assertEqual(rules(got["num"]), [])

    def test_a_credential_read_with_a_leading_at_is_flagged(self):
        got = self._calls(("env", "read", {"path": "@.env"}),
                          ("ssh", "read", {"path": "@~/.ssh/id_rsa"}))
        self.assertEqual(rules(got["env"]), [("cred.read", ".env")])
        self.assertEqual(rules(got["ssh"]), [("cred.read", "~/.ssh/id_rsa")])

    def test_precision_carries_over(self):
        heredoc = "cat > clean.sh <<'EOF'\nrm -rf /\nEOF"
        got = self._calls(
            ("grep", "bash", {"command": "grep -rn 'rm -rf' ."}),
            ("heredoc", "bash", {"command": heredoc}),
            ("write", "write", {"path": "clean.sh", "content": "rm -rf /\n"}),
            ("edit", "edit", {"path": "clean.sh",
                              "edits": [{"oldText": "echo", "newText": "rm -rf /"}]}))
        for cid, call in got.items():
            self.assertEqual(rules(call), [], cid)

    def test_a_secret_in_any_call_is_still_a_literal(self):
        got = self._calls(
            ("write", "write", {"path": "x.py",
                                "content": "KEY = '" + SECRET + "'\n"}),
            ("shell", "bash", {"command": "curl -H 'Authorization: Bearer "
                               + SECRET + "' https://api.example.com"}))
        for cid in ("write", "shell"):
            self.assertIn("secret.literal", [r for r, _e in rules(got[cid])], cid)

    def test_a_tool_the_adapter_does_not_know_is_judged_by_name(self):
        # design 3.5: an MCP tool named like a shell is still judged as one,
        # and so is Pi's own powershell tool, which the spec does not list
        got = self._calls(
            ("mcp", "mcp__srv__bash", {"command": "rm -rf ~/Documents/x"}),
            ("ps", "powershell", {"command": "cat ~/.aws/credentials"}))
        self.assertFalse(got["mcp"].known)
        self.assertEqual(rules(got["mcp"]), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(got["ps"]), [("cred.read", "cat ~/.aws/credentials")])


# --------------------------------------------------------------------------
# Calls a tool made while it ran (codemode), kept in nestedCalls
# --------------------------------------------------------------------------

CODE = ("await tools.bash({command: 'rm -rf ~/Documents/x'});\n"
        "await tools.read({path: '~/.ssh/id_rsa'});")

ONE_UNREADABLE = (
    "1 Pi tool call made inside another tool (a codemode script, for "
    "example) could not be read: Pi kept no arguments for it, as it does "
    "once they pass 8 KiB for one call or 32 KiB in all.")
ONE_CAPPED = (
    "1 Pi tool call (a codemode script, for example) made 256 calls to other "
    "tools, as many as Pi records for one call. Pi kept nothing of any it "
    "made after those, so they were not checked.")


class NestedCalls(PiCase):

    def test_calls_a_codemode_script_made_are_reported_and_judged(self):
        records = [
            nested_record("cm1/1", "bash", {"command": "rm -rf ~/Documents/x"}),
            nested_record("cm1/2", "read", {"path": "~/.ssh/id_rsa"}),
            nested_record("cm1/3", "bash", {"command": "false"}, status="error",
                          error="Command exited with code 1"),
            nested_record("cm1/4", "edit", {"path": "a.py", "edits": [
                {"oldText": "a", "newText": "b"}]}),
            # an extension tool that itself calls a tool: <its id>/<n>
            nested_record("cm1/5", "my_ext_tool", {"target": "app"}),
            nested_record("cm1/5/1", "read", {"path": "@.env"}),
            nested_record("cm1/6", "bash", {"command": "sleep 100"},
                          status="unfinished"),
        ]
        lines = [header()] + codemode_lines(10, "cm1", CODE, records,
                                            complete=False, output="done")
        calls = self.calls(self.session(lines))
        self.assertEqual([c.tool_call_id for c in calls],
                         ["cm1", "cm1/1", "cm1/2", "cm1/3", "cm1/4", "cm1/5",
                          "cm1/5/1", "cm1/6"])
        outer, rm, ssh, failed, edit, ext, env, unfinished = calls
        # the codemode call itself is not one of the spec's tools
        self.assertEqual((outer.tool_name, outer.kind, outer.known, outer.output),
                         ("codemode", "other", False,
                          "Script completed\nWall time 0.1 seconds\nOutput:\n\ndone"))
        self.assertEqual(rules(outer), [])
        # each nested call: the time, session and project of the result
        # that holds it; its error text as output; never "declined"
        self.assertEqual(rm, ToolCall(
            "pi", rm.store, "bash", {"command": "rm -rf ~/Documents/x"},
            kind="shell", known=True, session=SID, project="/home/dev/app",
            timestamp="2026-10-01T09:00:11Z", tool_call_id="cm1/1",
            command="rm -rf ~/Documents/x", consumed=("command",)))
        self.assertEqual(rules(rm), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual((ssh.kind, ssh.paths), ("read", ("~/.ssh/id_rsa",)))
        self.assertEqual(rules(ssh), [("cred.read", "~/.ssh/id_rsa")])
        self.assertEqual((failed.output, failed.status),
                         ("Command exited with code 1", None))
        self.assertEqual((edit.kind, edit.known, ext.kind, ext.known),
                         ("other", False, "other", False))
        self.assertEqual(env.paths, (".env",))
        self.assertEqual(rules(env), [("cred.read", ".env")])
        # a call still running when the script ended had started
        self.assertEqual((unfinished.command, unfinished.status, unfinished.output),
                         ("sleep 100", None, None))
        # incomplete for a reason other than a full record: nothing counted
        self.assertEqual((self.pi.counts["unreadable_calls"],
                          self.pi.counts["nested_capped"], self.pi.notes()),
                         (0, 0, []))

    def test_a_copied_result_yields_its_nested_calls_once(self):
        records = [nested_record("cm1/1", "bash", {"command": "ls"}),
                   nested_record("cm1/2", "bash", {"command": "pwd"},
                                 omitted=True)]
        lines = [header()] + codemode_lines(10, "cm1", CODE, records,
                                            complete=False)
        lines += [dict(l) for l in lines[1:]]       # a fork's copy
        calls = self.calls(self.session(lines))
        self.assertEqual([c.tool_call_id for c in calls], ["cm1", "cm1/1", "cm1/2"])
        self.assertEqual(self.pi.counts["unreadable_calls"], 1)

    def test_a_call_pi_kept_no_arguments_for_is_counted_and_said(self):
        big = {"command": "echo " + "x" * 9000}
        records = [nested_record("cm1/1", "bash", big, omitted=True),
                   nested_record("cm1/2", "read", {"path": "a.py"})]
        lines = [header()] + codemode_lines(10, "cm1", CODE, records,
                                            complete=False)
        path = self.session(lines)
        self.assertEqual(lines[2]["message"]["nestedCalls"]["calls"][0],
                         {"id": "cm1/1", "name": "bash", "status": "ok",
                          "argumentsBytes": 9019, "durationMs": 3})
        got = self.by_id(path)
        lost = got["cm1/1"]
        # yielded, with nothing to judge
        self.assertEqual((lost.tool_input, lost.kind, lost.known, lost.command),
                         ({}, "shell", True, None))
        self.assertEqual(rules(lost), [])
        self.assertEqual(got["cm1/2"].paths, ("a.py",))
        self.assertEqual(self.pi.counts["unreadable_calls"], 1)
        self.assertEqual(self.pi.notes(), [ONE_UNREADABLE])
        # watch and clean both read the store: counted once per run
        list(self.pi.secret_texts(self.store(path)))
        self.calls(path)
        self.assertEqual(self.pi.counts["unreadable_calls"], 1)
        self.pi.reset()
        self.assertEqual(self.pi.notes(), [])
        self.calls(path)
        self.assertEqual(self.pi.counts["unreadable_calls"], 1)

    def test_several_unreadable_calls_are_said_in_one_line(self):
        records = [nested_record("cm1/%d" % i, "bash", {"command": "x" * 9000},
                                 omitted=True) for i in (1, 2, 3)]
        lines = [header()] + codemode_lines(10, "cm1", CODE, records,
                                            complete=False)
        self.calls(self.session(lines))
        self.assertEqual(self.pi.notes(), [
            "3 Pi tool calls made inside another tool (a codemode script, for "
            "example) could not be read: Pi kept no arguments for them, as it "
            "does once they pass 8 KiB for one call or 32 KiB in all."])

    def test_a_record_that_is_not_an_object_is_counted_unknown(self):
        records = ["cm1/1", nested_record("cm1/2", "bash", {"command": "ls"})]
        lines = [header()] + codemode_lines(10, "cm1", CODE, records)
        self.assertEqual([c.tool_call_id for c in self.calls(self.session(lines))],
                         ["cm1", "cm1/2"])
        self.assertEqual(self.pi.counts["unknown"], 1)

    def test_a_full_incomplete_record_is_counted_and_said(self):
        # Pi records 256 nested calls for one call and drops the rest,
        # marking the record incomplete (nested-tool-calls.ts start)
        full = [nested_record("cm1/%d" % i, "bash", {"command": "cat f%d" % i})
                for i in range(1, 257)]
        lines = [header()] + codemode_lines(10, "cm1", CODE, full, complete=False)
        lines += [dict(l) for l in lines[1:]]       # a copy: counted once
        # 256 calls and complete: nothing was dropped
        lines += codemode_lines(20, "cm2", CODE, [
            nested_record("cm2/%d" % i, "bash", {"command": "ls"})
            for i in range(1, 257)])
        # incomplete for another reason (arguments left out), and not full
        lines += codemode_lines(30, "cm3", CODE, [
            nested_record("cm3/%d" % i, "bash", {"command": "ls"})
            for i in range(1, 255)] + [
            nested_record("cm3/255", "bash", {"command": "x" * 9000},
                          omitted=True)], complete=False)
        path = self.session(lines)
        calls = self.calls(path)
        self.assertEqual(len(calls), 3 + 256 + 256 + 255)
        self.assertEqual((self.pi.counts["nested_capped"],
                          self.pi.counts["unreadable_calls"]), (1, 1))
        self.assertEqual(self.pi.notes(), [ONE_UNREADABLE, ONE_CAPPED])
        # clean reads it too: still once
        list(self.pi.secret_texts(self.store(path)))
        self.assertEqual(self.pi.counts["nested_capped"], 1)

    def test_several_full_records_are_said_in_one_line(self):
        lines = [header()]
        for n, cid in ((10, "cm1"), (20, "cm2")):
            lines += codemode_lines(n, cid, CODE, [
                nested_record("%s/%d" % (cid, i), "bash", {"command": "ls"})
                for i in range(1, 257)], complete=False)
        self.calls(self.session(lines))
        self.assertEqual(self.pi.notes(), [
            "2 Pi tool calls (codemode scripts, for example) each made 256 "
            "calls to other tools, as many as Pi records for one call. Pi kept "
            "nothing of any they made after those, so they were not checked."])

    def test_notes_are_plain(self):
        self.pi.count("unreadable_calls", 2)
        self.pi.count("nested_capped", 2)
        for note in self.pi.notes():
            self.assertNotIn("\u2014", note)
            self.assertTrue(note.isprintable(), note)

    def test_a_secret_in_a_nested_call_reaches_clean(self):
        command = "curl -u me:" + SECRET + " https://x.example"
        records = [nested_record("cm1/1", "bash", {"command": command})]
        lines = [header()] + codemode_lines(10, "cm1", CODE, records)
        found = findings(self.pi, [self.store(self.session(lines))])
        self.assertEqual(set(found), {SECRET})
        # typed into a command: no origin; in nestedCalls and in codemode's
        # display copy of the call
        self.assertEqual((found[SECRET]["origins"], found[SECRET]["count"]),
                         (set(), 2))


# --------------------------------------------------------------------------
# Calls that never ran: "declined"
# --------------------------------------------------------------------------

class Declined(PiCase):

    def test_calls_from_a_message_stopped_by_an_abort_or_an_error(self):
        # agent-loop.ts runLoop returns before running any tool when the
        # assistant message stopped on "aborted" or "error"
        lines = [header()]
        lines.append(entry(10, assistant(
            [tool_call("ab1", "bash", {"command": "rm -rf ~/Documents/x"}),
             tool_call("ab2", "read", {"path": "~/.ssh/id_rsa"})],
            BASE_MS + 10000, stop="aborted",
            errorMessage="Request was aborted")))
        lines.append(entry(11, assistant(
            [tool_call("er1", "bash", {"command": "cat ~/.aws/credentials"})],
            BASE_MS + 11000, stop="error", errorMessage="Connection error.")))
        lines += call_lines(12, "ran", "bash", {"command": "ls"}, output="a")
        got = self.by_id(self.session(lines))
        self.assertEqual({cid: c.status for cid, c in got.items()},
                         {"ab1": "declined", "ab2": "declined",
                          "er1": "declined", "ran": None})
        # still judged: the report says it did not run
        self.assertEqual(rules(got["ab1"]), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(got["er1"]), [("cred.read", "cat ~/.aws/credentials")])

    def test_calls_cut_off_by_the_output_token_limit(self):
        lines = [header()]
        # Pi 0.80.4 and later: every call of the message answered with the
        # not-executed error, none run
        lines.append(entry(10, assistant(
            [tool_call("len1", "bash", {"command": "rm -rf ~/Documents/x"}),
             tool_call("len2", "write", {"path": "a.py", "content": "x"})],
            BASE_MS + 10000, stop="length")))
        lines.append(entry(11, not_executed("len1", "bash", BASE_MS + 11000)))
        lines.append(entry(12, not_executed("len2", "write", BASE_MS + 12000)))
        # earlier versions ran it: an ordinary result
        lines.append(entry(13, assistant(
            [tool_call("old", "bash", {"command": "ls"})], BASE_MS + 13000,
            stop="length")))
        lines.append(entry(14, tool_result("old", "bash", "a.py", BASE_MS + 14000)))
        # no result in the file: unknown, so not declined
        lines.append(entry(15, assistant(
            [tool_call("open", "bash", {"command": "make"})], BASE_MS + 15000,
            stop="length")))
        # the same text, but the message did not stop on "length"
        lines += call_lines(16, "said", "bash", {"command": "echo"})
        lines.append(entry(17, not_executed("said", "bash", BASE_MS + 17000)))
        # the text names another tool
        lines.append(entry(18, assistant(
            [tool_call("other", "bash", {"command": "pwd"})], BASE_MS + 18000,
            stop="length")))
        lines.append(entry(19, not_executed("other", "read", BASE_MS + 19000)))
        # the text, but not an error result
        lines.append(entry(20, assistant(
            [tool_call("fine", "bash", {"command": "id"})], BASE_MS + 20000,
            stop="length")))
        quiet = not_executed("fine", "bash", BASE_MS + 21000)
        quiet["isError"] = False
        lines.append(entry(21, quiet))
        got = self.by_id(self.session(lines))
        self.assertEqual({cid: c.status for cid, c in got.items()}, {
            "len1": "declined", "len2": "declined", "old": None, "open": None,
            "said": None, "other": None, "fine": None})
        self.assertTrue(got["len1"].output.startswith(
            'Tool call "bash" was not executed'))
        self.assertEqual(rules(got["len1"]), [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_a_declined_call_keeps_its_first_copy(self):
        # a copied entry does not undo or redo "declined"
        lines = [header()]
        aborted = entry(10, assistant(
            [tool_call("ab1", "bash", {"command": "rm -rf build"})],
            BASE_MS + 10000, stop="aborted"))
        lines += [aborted, dict(aborted)]
        [call] = self.calls(self.session(lines))
        self.assertEqual((call.tool_call_id, call.status), ("ab1", "declined"))


# --------------------------------------------------------------------------
# 9: secrets, and every string reaches clean
# --------------------------------------------------------------------------

class Secrets(PiCase):

    def test_output_after_cat_env_and_a_typed_key(self):
        lines = [header()]
        lines += call_lines(10, "cat", "bash", {"command": "cat .env"},
                            output="STRIPE_KEY=" + SECRET)
        lines += call_lines(12, "typed", "bash",
                            {"command": "export API_TOKEN=" + TYPED + " && ./run"},
                            output="started")
        lines += call_lines(14, "ls", "bash", {"command": "ls"}, output="a.py")
        # the same key again, in a compaction summary
        lines.append({"type": "compaction", "id": eid(20), "parentId": eid(15),
                      "timestamp": _iso(BASE_MS), "summary": "STRIPE_KEY is " + SECRET,
                      "firstKeptEntryId": eid(14), "tokensBefore": 5000})
        found = findings(self.pi, [self.store(self.session(lines))])
        self.assertEqual(set(found), {SECRET, TYPED})
        self.assertEqual(found[SECRET]["origins"], {".env"})
        self.assertEqual(found[SECRET]["count"], 2)
        self.assertEqual(found[TYPED]["origins"], set())

    def test_the_spec_sample_with_a_real_shaped_key(self):
        # the spec's value is a placeholder clean does not take for a key
        lines = [l.replace(SPEC_VALUE, SECRET) for l in SPEC_LINES]
        found = findings(self.pi, [self.store(self.session(lines))])
        self.assertEqual(set(found), {SECRET})
        self.assertEqual((found[SECRET]["origins"], found[SECRET]["where"]),
                         ({".env"}, ["line 3"]))

    def test_a_read_and_a_bang_command_name_their_file(self):
        lines = [header()]
        lines += call_lines(10, "read", "read", {"path": "/home/dev/app/.env"},
                            output="STRIPE_KEY=" + SECRET)
        lines += user_lines(12, "cat config/.env.local", "API_TOKEN=" + TYPED)
        found = findings(self.pi, [self.store(self.session(lines))])
        self.assertEqual(found[SECRET]["origins"], {"/home/dev/app/.env"})
        self.assertEqual(found[TYPED]["origins"], {"config/.env.local"})

    def test_a_key_typed_into_a_bang_command_has_no_origin(self):
        lines = [header()] + user_lines(
            10, "curl -u me:" + SECRET + " https://x.example", "ok")
        found = findings(self.pi, [self.store(self.session(lines))])
        self.assertEqual(found[SECRET]["origins"], set())

    def test_the_result_is_tied_to_its_call(self):
        lines = [header()] + call_lines(10, "cat", "bash", {"command": "cat .env"},
                                        output="X=1")
        lines += user_lines(12, "cat .env", "Y=2")
        texts = list(self.pi.secret_texts(self.store(self.session(lines))))
        tied = [t for t in texts if t.call is not None]
        self.assertEqual([(t.node, t.call.command, t.call.tool_call_id, t.call.actor,
                           t.where) for t in tied], [
            ([{"type": "text", "text": "X=1"}], "cat .env", "cat", "agent", "line 3"),
            ("Y=2", "cat .env", eid(12), "user", "line 4")])

    def test_every_string_in_a_transcript_reaches_clean(self):
        lines = [l for l in SPEC_LINES]
        more = [
            entry(10, {"role": "system", "content": "", "sections": {
                "preamble": "You are an expert"}, "timestamp": BASE_MS}),
            entry(11, user([{"type": "text", "text": "a prompt"},
                            {"type": "image", "data": "iVBORw0KGgo=",
                             "mimeType": "image/png"}], BASE_MS)),
            entry(12, assistant([{"type": "thinking", "thinking": "hmm",
                                  "thinkingSignature": "sig"},
                                 {"type": "text", "text": "prose"},
                                 tool_call("e1", "edit", {"path": "f", "edits": [
                                     {"oldText": "a", "newText": "b"}]})],
                                BASE_MS)),
            entry(13, tool_result("e1", "edit", "Successfully replaced", BASE_MS,
                                  details={"diff": "-a\n+TOKEN=" + SECRET,
                                           "firstChangedLine": 1})),
            entry(14, bash_execution("cat big.log", "tail", BASE_MS, truncated=True,
                                     fullOutputPath="/tmp/pi-bash-1.log")),
            entry(15, {"role": "custom", "customType": "ext", "content": "ctx",
                       "display": True, "details": {"k": "v"}, "timestamp": BASE_MS}),
            entry(16, {"role": "brandNewRole", "payload": "unknown role"}),
            {"type": "model_change", "id": eid(17), "parentId": eid(16),
             "timestamp": _iso(BASE_MS), "provider": "openai", "modelId": "gpt-x"},
            {"type": "compaction", "id": eid(18), "parentId": eid(17),
             "timestamp": _iso(BASE_MS), "summary": "summary text",
             "firstKeptEntryId": eid(12), "tokensBefore": 1,
             "details": {"readFiles": ["a.py"], "modifiedFiles": []}},
            # a tool result's new content, as appendContextEdit writes it
            {"type": "context_edit", "id": eid(19), "parentId": eid(18),
             "timestamp": _iso(BASE_MS), "targetId": eid(13),
             "replacement": {"content": [{"type": "text",
                                          "text": "replaced text"}]}},
            {"type": "branch_summary", "id": eid(20), "parentId": eid(11),
             "timestamp": _iso(BASE_MS), "fromId": eid(19), "summary": "branch"},
            {"type": "custom_message", "id": eid(21), "parentId": eid(20),
             "timestamp": _iso(BASE_MS), "customType": "ext", "content": "injected",
             "display": True},
            {"type": "label", "id": eid(22), "parentId": eid(21),
             "timestamp": _iso(BASE_MS), "targetId": eid(11), "label": "checkpoint"},
            {"type": "session_info", "id": eid(23), "parentId": eid(22),
             "timestamp": _iso(BASE_MS), "name": "a session name"},
            {"type": "future_record", "payload": {"deep": ["unknown kind"]}},
            ["a", "bare", "array"],
        ]
        lines += [_dump(l) for l in more]
        lines.append("{not json but holding STRIPE_KEY=" + SECRET)
        lines.append(_dump(entry(30, user("after the bad line", BASE_MS))))
        path = self.session(lines)
        expected = set()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    expected.update(_strings(json.loads(line)))
                except ValueError:
                    expected.add(line.rstrip("\n"))
        got = set()
        for text in self.pi.secret_texts(self.store(path)):
            got.update(_strings(text.node))
        self.assertEqual(expected - got, set())
        found = findings(self.pi, [self.store(path)])
        self.assertEqual(sorted(found[SECRET]["where"]), ["line 20", "line 7"])
        self.assertEqual(found[SECRET]["origins"], set())


# --------------------------------------------------------------------------
# 10, 13: masking round trip, and a file in use
# --------------------------------------------------------------------------

class Masking(PiCase):

    def _session_with_secrets(self, **kw):
        lines = [header()]
        lines += call_lines(10, "cat", "bash", {"command": "cat .env"},
                            output="STRIPE_KEY=" + SECRET)
        lines += call_lines(12, "json", "bash", {"command": "cat config.json"},
                            output=json.dumps({"token": SECRET, "n": 1}))
        lines += call_lines(14, "typed", "bash",
                            {"command": "curl -u me:" + SECRET + " https://x.example"},
                            output="caf\u00e9 \u2028 ok")
        lines += user_lines(16, "cat .env", "STRIPE_KEY=" + SECRET + "\n")
        lines.append({"type": "compaction", "id": eid(20), "parentId": eid(16),
                      "timestamp": _iso(BASE_MS), "summary": "key " + SECRET,
                      "firstKeptEntryId": eid(14), "tokensBefore": 1})
        return self.session(lines, mode=0o600, **kw)

    def _assert_masked(self, path, original, value, result, mode=0o600):
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        with open(path, "rb") as fh:
            after = fh.read()
        marker = _marker(value)
        self.assertEqual(after, original.replace(value.encode("utf-8"),
                                                 marker.encode("utf-8")))
        text = after.decode("utf-8")
        self.assertEqual([f for f in _rewrite.encodings(value) if f in text], [])
        with open(result.backup, "rb") as fh:
            self.assertEqual(fh.read(), original)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), mode)
            self.assertEqual(stat.S_IMODE(os.stat(result.backup).st_mode), 0o600)
        self.assertEqual(glob.glob(os.path.join(os.path.dirname(path),
                                                "*.ranwhat-tmp")), [])
        return after

    def test_round_trip_of_a_transcript(self):
        path = self._session_with_secrets()
        with open(path, "rb") as fh:
            original = fh.read()
        store = self.store(path)
        before = list(self.pi.tool_calls(store))
        result = self.pi.mask(store, [SECRET])
        after = self._assert_masked(path, original, SECRET, result)
        # every line still parses, split on \n only (an output holds a raw
        # U+2028), and the JSON inside an output still does
        lines = [json.loads(l) for l in after.decode("utf-8").split("\n") if l]
        inner = lines[4]["message"]["content"][0]["text"]
        self.assertEqual(json.loads(inner), {"token": _marker(SECRET), "n": 1})
        # the adapter reads the same calls, the secret masked in each
        again = list(self.pi.tool_calls(self.store(path)))
        self.assertEqual(
            [(c.tool_call_id, c.tool_name, c.kind, c.actor, c.timestamp, c.session)
             for c in again],
            [(c.tool_call_id, c.tool_name, c.kind, c.actor, c.timestamp, c.session)
             for c in before])
        m = _marker(SECRET)
        self.assertEqual([c.command for c in again],
                         [c.command.replace(SECRET, m) for c in before])
        self.assertEqual([c.output for c in again],
                         [c.output.replace(SECRET, m) for c in before])
        self.assertEqual(findings(self.pi, [self.store(path)]), {})
        # a second run changes nothing and makes no second backup
        self.assertEqual(self.pi.mask(self.store(path), [SECRET]), MaskResult(path))
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), after)
        backups = [f for _d, _s, fs in os.walk(self.backups) for f in fs]
        self.assertEqual(len(backups), 1)

    def test_round_trip_of_the_spec_sample(self):
        path = self.session(SPEC_LINES, mode=0o644)
        with open(path, "rb") as fh:
            original = fh.read()
        result = self.pi.mask(self.store(path), [SPEC_VALUE])
        after = self._assert_masked(path, original, SPEC_VALUE, result, mode=0o644)
        self.assertEqual(len(after.split(b"\n")), 4)
        [call] = self.calls(path)
        self.assertEqual(call.output, "API_KEY=" + _marker(SPEC_VALUE))

    def test_a_file_written_just_now_is_in_use(self):
        path = self._session_with_secrets(age=5)
        digest = _sha(path)
        result = self.pi.mask(self.store(path), [SECRET])
        self.assertEqual(result, MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))


# --------------------------------------------------------------------------
# 12, 14: files that do not parse, and the --days window
# --------------------------------------------------------------------------

class Damaged(PiCase):

    def test_a_truncated_last_line_is_skipped_quietly(self):
        good = "".join(l + "\n" for l in SPEC_LINES)
        partial = _dump(call_lines(9, "call_Z", "bash", {"command": "rm -rf ~/x"})[0])
        path = self.session(None, raw=(good + partial[:60]).encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self.calls(path)
            list(self.pi.secret_texts(self.store(path)))
        self.assertEqual([c.tool_call_id for c in calls], ["call_1"])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.pi.counts["unparsed"], 0)

    def test_garbage_warns_once_and_other_stores_are_still_read(self):
        garbage = self.session(None, name="garbage.jsonl",
                               raw=b"\x00\xff\xfe not json\n\x89PNG\r\n\x1a\n" * 20)
        good = self.session(SPEC_LINES, age=7200)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for store in self.stores():
                list(self.pi.tool_calls(store))
                list(self.pi.secret_texts(store))
                list(self.pi.tool_calls(store))
            self.assertEqual([c.tool_call_id for c in self.calls(good)], ["call_1"])
        warnings = err.getvalue().splitlines()
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn(garbage, warnings[0])
        self.assertEqual(self.pi.counts["unreadable_stores"], 1)
        self.assertEqual(self.pi.unreadable, {"not JSON Lines": 1})

    def test_unknown_records_and_roles_are_ignored_and_counted(self):
        lines = list(SPEC_LINES) + [_dump(l) for l in (
            {"type": "future_record", "command": "rm -rf ~/x"},
            [1, 2, 3],
            entry(20, {"role": "futureRole", "content": [
                tool_call("s1", "bash", {"command": "rm -rf ~/x"})]}),
            entry(21, assistant([{"type": "futureBlock", "id": "s2",
                                  "name": "bash",
                                  "arguments": {"command": "rm -rf ~/x"}}],
                                BASE_MS)),
            {"type": "label", "id": eid(22), "parentId": None,
             "timestamp": _iso(BASE_MS), "targetId": eid(21)},
        )]
        path = self.session(lines)
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["call_1"])
        self.assertEqual(self.pi.counts["unknown"], 3)
        # read again in the same run (clean after watch): counted once
        list(self.pi.secret_texts(self.store(path)))
        self.assertEqual(self.pi.counts["unknown"], 3)
        self.pi.reset()
        list(self.pi.secret_texts(self.store(path)))
        self.assertEqual(self.pi.counts["unknown"], 3)

    def test_a_bad_line_in_the_middle_is_counted_not_fatal(self):
        raw = SPEC_LINES[0] + "\n" + "{not json\n" + "\n".join(SPEC_LINES[1:]) + "\n"
        path = self.session(None, raw=raw.encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(len(self.calls(path)), 1)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.pi.counts["unparsed"], 1)

    def test_a_store_that_vanished_warns_once(self):
        path = self.session(SPEC_LINES)
        store = self.store(path)
        os.unlink(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.pi.tool_calls(store)), [])
            self.assertEqual(list(self.pi.secret_texts(store)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertEqual(self.pi.counts["unreadable_stores"], 1)

    def test_a_byte_order_mark_and_crlf_endings_are_read(self):
        raw = ("\ufeff" + "\r\n".join(SPEC_LINES) + "\r\n").encode("utf-8")
        path = self.session(None, raw=raw)
        [store] = self.stores()
        self.assertEqual((store.session, store.project), (SID, "/home/dev/app"))
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["call_1"])


class Window(PiCase):

    def test_an_old_call_in_a_new_file_and_an_undated_one(self):
        recent_ms = int((time.time() - 3600) * 1000)
        lines = [header()]
        old = call_lines(10, "old", "bash", {"command": "rm -rf ~/Documents/x"},
                         output="")
        old[0]["timestamp"] = "2025-01-02T03:04:05.000Z"
        lines += old
        recent = call_lines(12, "recent", "bash",
                            {"command": "rm -rf ~/Documents/y"}, output="")
        recent[0]["timestamp"] = _iso(recent_ms)
        lines += recent
        undated = call_lines(14, "undated", "bash",
                             {"command": "rm -rf ~/Documents/z"}, ts=False)
        del undated[0]["message"]["timestamp"]
        lines += undated
        path = self.session(lines, age=60)
        [store] = self.stores(since_days=30)
        self.assertEqual(store.path, path)
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                               time.gmtime(time.time() - 30 * 86400))
        kept, undated_kept = [], 0
        for call in self.pi.tool_calls(store):
            # design 3.5: a dated call by its own time; an undated one is
            # kept unless the last write of its store is before the cutoff
            if call.timestamp:
                if call.timestamp >= cutoff:
                    kept.append(call.tool_call_id)
            elif call.not_after and call.not_after >= cutoff:
                kept.append(call.tool_call_id)
                undated_kept += 1
        self.assertEqual(sorted(kept), ["recent", "undated"])
        self.assertEqual(undated_kept, 1)


# --------------------------------------------------------------------------
# A large session: how reading it grows, on its own interpreter
# (tests/growth.py)
# --------------------------------------------------------------------------

READ = r"""
from ranwhat.sources.pi import PiSource
def call(made):
    p = PiSource()
    stores = p.stores(p.locations(override=made["root"]))
    calls = sum(1 for s in stores for _ in p.tool_calls(s))
    texts = sum(1 for s in stores for _ in p.secret_texts(s))
    return {"stores": len(stores), "calls": calls, "texts": texts,
            "counts": p.counts}
"""


class Performance(unittest.TestCase):

    def _session(self, n):
        """A root whose one session is n(30 MB) long, and how many calls it
        holds."""
        root = _tempdir(self, "pi-perf-")
        folder = os.path.join(root, "sessions", FOLDER)
        os.makedirs(folder)
        path = os.path.join(folder, NAME)
        out = ("lorem ipsum dolor sit amet " * 24 + "\n") * 2
        i = 0
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(_dump(header()) + "\n")
            while fh.tell() < n(30 * 1024 * 1024):
                for line in call_lines(i + 1, "call_%08d" % i, "bash",
                                       {"command": "grep -rn foo src/%d" % i},
                                       output=out):
                    fh.write(_dump(line) + "\n")
                i += 2
        return {"root": root, "calls": i // 2}

    def test_a_30mb_session_reads_well_within_budget(self):
        home = _tempdir(self, "pi-perf-home-")
        env = dict(os.environ, HOME=home, USERPROFILE=home)
        env.pop(ENV, None)
        env.pop(SESSION_ENV, None)
        measured, made = growth.measure_apart(self._session, READ, env=env)
        growth.assert_linear(self, measured, "a 30 MB session")
        report = measured.result
        self.assertEqual(report["stores"], 1)
        self.assertEqual(report["calls"], made["calls"])
        self.assertEqual(report["texts"], 1 + 3 * made["calls"])
        self.assertEqual(report["counts"]["unparsed"], 0)


if __name__ == "__main__":
    unittest.main()
