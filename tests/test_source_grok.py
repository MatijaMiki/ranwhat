"""Grok Build (xAI's `grok` CLI): the "grok" source adapter, design 7.7.

Two kinds of fixture. The spec's sample is kept verbatim below, with
placeholders only where the synthetic secret and its byte array go; parts
of it are illustrative (it puts the canonical input on the first line,
which upstream never does), and the adapter must still read it. Every other
call is built the way grok-build writes it at commit 2bdd1d6a, from the
emission sites named on each helper. Every secret is synthetic and written
as adjacent literals.

Everything runs under a temp home: HOME, USERPROFILE, GROK_HOME,
_paths.home() and clean's backup root all point into it.

watch.judge and clean.scan_sources arrive with the wiring step. Until then
judge() below is design 3.5's function, and secrets() credits origins the
way 3.6 says; once watch.judge exists it is used instead.
"""
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
from ranwhat.sources import _paths, _rewrite, _stamps, base  # noqa: E402
from ranwhat.sources.base import MaskResult, Store  # noqa: E402
from ranwhat.sources import grok as grok_module  # noqa: E402
from ranwhat.sources.grok import GrokBuildSource, shape  # noqa: E402

WINDOWS = os.name == "nt"

SID = "0199b6c0-7a1e-7c3d-9f00-000000000001"
ENC = "%2FUsers%2Fme%2Fproj"            # folder name: illustrative, never decoded
CWD = "/Users/me/proj"

SECRET = "sk_" "live_" "Gr0kQ8vR2mT6yLp4WcN0sXe7"
TYPED = "ghp_" "Q8vR2mT6yLp4WcN0sXe7HbJ1aZ9kLm3nOp5r"
ONLY_BYTES = "sk_" "live_" "Byt3sOnlyR2mT6yLp4WcN0sX"

# The spec's updates.jsonl sample (7.7), verbatim except for three
# placeholders: @TEXT@ is the JSON body of the Bash output text (the
# sample's "API_KEY=sk-test-123\nok\n"), @BYTES@ the same output as a byte
# array, @TOTAL@ its byte count (23 in the sample).
SAMPLE_UPDATES = [
    r'{"timestamp":1790000000,"method":"session/update","params":{"sessionId":"0199b6c0-7a1e-7c3d-9f00-000000000001","update":{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"run the tests"}},"_meta":{"eventId":"evt-1","agentTimestampMs":1790000000100}}}',
    r'{"timestamp":1790000002,"method":"session/update","params":{"sessionId":"0199b6c0-7a1e-7c3d-9f00-000000000001","update":{"sessionUpdate":"tool_call","toolCallId":"call_1","title":"run_terminal_cmd","kind":"other","status":"pending","rawInput":{"command":"cat .env; npm test","description":"Run tests","is_background":false},"_meta":{"x.ai/tool":{"version":1,"name":"run_terminal_cmd","kind":"execute","namespace":"grok_build","label":"Bash","read_only":false,"input":{"command":"cat .env; npm test","description":"Run tests"}}}},"_meta":{"eventId":"evt-2","agentTimestampMs":1790000002000}}}',
    r'{"timestamp":1790000002,"method":"session/update","params":{"sessionId":"0199b6c0-7a1e-7c3d-9f00-000000000001","update":{"sessionUpdate":"tool_call_update","toolCallId":"call_1","title":"cat .env; npm test","kind":"execute","rawInput":{"command":"cat .env; npm test","description":"Run tests","is_background":false}},"_meta":{"eventId":"evt-3","agentTimestampMs":1790000002050}}}',
    r'{"timestamp":1790000005,"method":"session/update","params":{"sessionId":"0199b6c0-7a1e-7c3d-9f00-000000000001","update":{"sessionUpdate":"tool_call_update","toolCallId":"call_1","status":"completed","content":[{"type":"content","content":{"type":"text","text":"@TEXT@"}}],"rawOutput":{"type":"Bash","output":@BYTES@,"output_for_prompt":"@TEXT@","exit_code":0,"command":"cat .env; npm test","truncated":false,"signal":null,"timed_out":false,"description":"Run tests","current_dir":"/Users/me/proj","output_file":"/path/to/full-output.log","total_bytes":@TOTAL@}},"_meta":{"eventId":"evt-4","agentTimestampMs":1790000005000}}}',
    r'{"timestamp":1790000006,"method":"session/update","params":{"sessionId":"0199b6c0-7a1e-7c3d-9f00-000000000001","update":{"sessionUpdate":"tool_call","toolCallId":"call_2","title":"read_file","kind":"other","status":"pending","rawInput":{"target_file":"src/config.ts"}},"_meta":{"eventId":"evt-5","agentTimestampMs":1790000006000}}}',
    r'{"timestamp":1790000006,"method":"session/update","params":{"sessionId":"0199b6c0-7a1e-7c3d-9f00-000000000001","update":{"sessionUpdate":"tool_call_update","toolCallId":"call_2","status":"completed","rawOutput":{"type":"ReadFile","FileContent":{"content":"export const key = process.env.KEY;\n","absolute_path":"/Users/me/proj/src/config.ts","offset":null,"raw_output":"export const key = process.env.KEY;\n","total_lines":1}}},"_meta":{"eventId":"evt-6","agentTimestampMs":1790000006200}}}',
    r'{"timestamp":1790000007,"method":"session/update","params":{"sessionId":"0199b6c0-7a1e-7c3d-9f00-000000000001","update":{"sessionUpdate":"tool_call","toolCallId":"call_3","title":"search_replace","kind":"other","status":"pending","rawInput":{"file_path":"/Users/me/proj/notes.md","old_string":"","new_string":"hello\n","replace_all":false}},"_meta":{"eventId":"evt-7","agentTimestampMs":1790000007000}}}',
    r'{"timestamp":1790000007,"method":"session/update","params":{"sessionId":"0199b6c0-7a1e-7c3d-9f00-000000000001","update":{"sessionUpdate":"tool_call_update","toolCallId":"call_3","status":"completed","content":[{"type":"diff","path":"/Users/me/proj/notes.md","oldText":null,"newText":"hello\n"}]},"_meta":{"eventId":"evt-8","agentTimestampMs":1790000007100}}}',
]

# The spec's chat_history.jsonl sample for the same session, verbatim but
# for @TEXT@.
SAMPLE_CHAT = [
    r'{"type":"assistant","content":"","tool_calls":[{"id":"call_1","name":"run_terminal_cmd","arguments":"{\"command\":\"cat .env; npm test\",\"description\":\"Run tests\"}"}],"model_id":"grok-build-0.1"}',
    r'{"type":"tool_result","tool_call_id":"call_1","content":"@TEXT@"}',
]

OUTPUT = "API_KEY=" + SECRET + "\nok\n"


def _body(text):
    return json.dumps(text, ensure_ascii=False)[1:-1]


def _byte_list(text):
    return json.dumps(list(text.encode("utf-8")), separators=(",", ":"))


def sample_updates(text=OUTPUT, byte_text=None, total=None):
    """The sample's lines with `text` as the Bash output (and `byte_text`
    in the byte array, `total` as total_bytes, when given)."""
    byte_text = text if byte_text is None else byte_text
    total = len(byte_text.encode("utf-8")) if total is None else total
    return [line.replace("@TEXT@", _body(text))
                .replace("@BYTES@", _byte_list(byte_text))
                .replace("@TOTAL@", str(total)) for line in SAMPLE_UPDATES]


def sample_chat(text=OUTPUT):
    return [line.replace("@TEXT@", _body(text)) for line in SAMPLE_CHAT]


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------
# Building calls the way grok-build 2bdd1d6a writes them (crates/codegen/)
# --------------------------------------------------------------------------

XAI = "x.ai/tool"

# x.ai/tool label and read_only for each Grok kind: ToolKind's
# presentation_name and is_read_only (xai-grok-tools tool_taxonomy.rs).
KINDS = {"execute": ("Run Command", False), "read": ("Read", True),
         "edit": ("Edit", False), "write": ("Write", False),
         "plan": ("Plan", False), "monitor": ("Monitor", False),
         "web_fetch": ("Web Fetch", True), "other": ("Tool", False)}


def envelope(ts, update, event, ms=None, method="session/update", sid=SID):
    """SessionUpdateEnvelope (xai-grok-shell storage/mod.rs) around a
    notification whose _meta send_update stamps (acp_session_impl
    updates.rs)."""
    meta = {"eventId": event}
    if ms is not None:
        meta["agentTimestampMs"] = ms
    return {"timestamp": ts, "method": method,
            "params": {"sessionId": sid, "update": update, "_meta": meta}}


def xai_tool(name, kind, canon=None, namespace="grok_build"):
    """CanonicalToolMeta (tool_taxonomy.rs): input is left out when None."""
    label, read_only = KINDS[kind]
    tool = {"version": 1, "name": name, "kind": kind, "namespace": namespace,
            "label": label, "read_only": read_only}
    if canon is not None:
        tool["input"] = canon
    return tool


def tool_call(call_id, name, raw_input, kind=None, title=None,
              namespace="grok_build"):
    """Step 1 (acp_session_impl tool_calls.rs prepare_tool_call): title is
    the wire name, kind "other", status "pending", rawInput the model's
    arguments, and x.ai/tool stamped with no input. kind None is a tool the
    toolset does not know (an MCP tool): stamp_tool_meta then writes no
    _meta at all."""
    update = {"sessionUpdate": "tool_call", "toolCallId": call_id,
              "title": name if title is None else title, "kind": "other",
              "status": "pending"}
    if raw_input is not None:
        update["rawInput"] = raw_input
    if kind is not None:
        update["_meta"] = {XAI: xai_tool(name, kind, namespace=namespace)}
    return update


def started(call_id, name, kind, title, acp_kind, variant, fields, canon=None,
            locations=(), content=None, namespace="grok_build"):
    """Step 2 (tool_calls.rs send_tool_call_start, called before the
    permission prompt): title is display text, the ACP kind, locations,
    content when there is any, rawInput the typed ToolInput (serde tag
    "variant", types/tool_io.rs), and x.ai/tool with the canonical input
    (normalization.rs canonical_input; None for tools it does not
    project)."""
    update = {"sessionUpdate": "tool_call_update", "toolCallId": call_id,
              "title": title, "kind": acp_kind,
              "locations": [{"path": p} for p in locations]}
    if content is not None:
        update["content"] = content
    update["rawInput"] = dict([("variant", variant)] + list(fields.items()))
    update["_meta"] = {XAI: xai_tool(name, kind, canon, namespace)}
    return update


def finished(call_id, raw_output=None, content=None, status="completed"):
    """The last line (acp_conversion.rs acp_tool_update): status, content
    and rawOutput (ToolOutput, serde tag "type")."""
    update = {"sessionUpdate": "tool_call_update", "toolCallId": call_id,
              "status": status}
    if content is not None:
        update["content"] = content
    if raw_output is not None:
        update["rawOutput"] = raw_output
    return update


def text_content(text):
    return [{"type": "content", "content": {"type": "text", "text": text}}]


def bash_output(text, command, current_dir=CWD, prompt=True, signal=None):
    """BashOutput (xai-grok-tools types/output.rs), in its field order."""
    data = text.encode("utf-8")
    out = {"type": "Bash", "output": list(data)}
    if prompt:
        out["output_for_prompt"] = text
    out.update({"exit_code": 0, "command": command, "truncated": False,
                "signal": signal, "timed_out": False, "description": "Run it",
                "current_dir": current_dir,
                "output_file": "/path/to/full-output.log",
                "total_bytes": len(data)})
    return out


def shell_lines(call_id, command, t, output="", name="run_terminal_cmd",
                xkind="execute", current_dir=CWD, method="session/update",
                namespace="grok_build", background=False, signal=None,
                model_args=None):
    """A Bash call: the model's arguments (model_args, else the typed
    fields), then ToolInput::Bash (title "Execute `cmd`" and the description
    as content, execute_tool_call_parts), then the output."""
    raw = {"command": command, "description": "Run it",
           "is_background": background}
    canon = {"command": command, "description": "Run it"}
    args = raw if model_args is None else model_args
    return [
        envelope(t, tool_call(call_id, name, args, kind=xkind, namespace=namespace),
                 "e-%s-1" % call_id, t * 1000, method),
        envelope(t, started(call_id, name, xkind, "Execute `%s`" % command,
                            "execute", "Bash", raw, canon,
                            content=text_content("Run it"), namespace=namespace),
                 "e-%s-2" % call_id, t * 1000 + 50, method),
        envelope(t + 1, finished(call_id, bash_output(output, command, current_dir,
                                                      signal=signal),
                                 text_content(output)),
                 "e-%s-3" % call_id, t * 1000 + 1000, method),
    ]


def read_lines(call_id, target, t, absolute=None, content="", error=None,
               name="read_file", namespace="grok_build"):
    """A ReadFile call; the last line's content is the file's text, or the
    error with status failed."""
    if error is not None:
        out = {"type": "ReadFile", "FileNotFound": error}
        last = finished(call_id, out, text_content(error), status="failed")
    else:
        out = {"type": "ReadFile", "FileContent": {
            "content": content, "absolute_path": absolute or target,
            "offset": None, "raw_output": content,
            "total_lines": content.count("\n")}}
        last = finished(call_id, out, text_content(content))
    raw = {"target_file": target}
    return [envelope(t, tool_call(call_id, name, raw, kind="read",
                                  namespace=namespace),
                     "e-%s-1" % call_id, t * 1000),
            envelope(t, started(call_id, name, "read", "Read `%s`" % target, "read",
                                "ReadFile", raw, {"path": target},
                                locations=[target], namespace=namespace),
                     "e-%s-2" % call_id, t * 1000 + 50),
            envelope(t, last, "e-%s-3" % call_id, t * 1000 + 200)]


def write_lines(call_id, file_path, new_string, t):
    """A search_replace that creates a file: the diff block and
    SearchReplace EditsApplied."""
    raw = {"file_path": file_path, "old_string": "", "new_string": new_string,
           "replace_all": False}
    diff = [{"type": "diff", "path": file_path, "oldText": "",
             "newText": new_string}]
    out = {"type": "SearchReplace", "EditsApplied": {
        "old_string": "", "new_string": new_string,
        "tool_output_for_prompt": "Created %s" % file_path,
        "absolute_path": file_path, "edits": {"details": []}}}
    return [envelope(t, tool_call(call_id, "search_replace", raw, kind="edit"),
                     "e-%s-1" % call_id, t * 1000),
            envelope(t, started(call_id, "search_replace", "edit",
                                "Edit `%s`" % file_path, "edit", "SearchReplace",
                                raw, {"path": file_path}, locations=[file_path]),
                     "e-%s-2" % call_id, t * 1000 + 50),
            envelope(t, finished(call_id, out, diff), "e-%s-3" % call_id,
                     t * 1000 + 100)]


def bash_mode_lines(call_id, command, t, exec_wire="run_terminal_command",
                    output="", marker=True):
    """A command the user typed with `!` (acp_session_impl tool_dispatch.rs
    handle_direct_bash_command): one tool_call, already in progress, with
    rawInput the typed Bash input, _meta {"bash_mode": true} plus x.ai/tool
    (with input) only when the toolset has an execute tool (exec_wire),
    then the output. No terminal log is written for it."""
    tool_input = {"variant": "Bash", "command": command, "description": command,
                  "is_background": False}
    meta = {"bash_mode": True} if marker else {}
    if exec_wire is not None:
        meta[XAI] = xai_tool(exec_wire, "execute",
                             {"command": command, "description": command})
    first = {"sessionUpdate": "tool_call", "toolCallId": call_id,
             "title": "Execute `%s`" % command, "kind": "execute",
             "status": "in_progress", "rawInput": tool_input}
    if meta:
        first["_meta"] = meta
    out = bash_output(output, command)
    out["description"] = None
    out["output_file"] = ""
    return [envelope(t, first, "e-%s-1" % call_id, t * 1000),
            envelope(t + 1, finished(call_id, out), "e-%s-2" % call_id,
                     t * 1000 + 900)]


def line(obj):
    """One JSONL line the way serde_json writes it: compact, raw UTF-8."""
    return obj if isinstance(obj, str) else json.dumps(
        obj, separators=(",", ":"), ensure_ascii=False)


# --------------------------------------------------------------------------
# What watch and clean do with a ToolCall (design 3.5 and 3.6)
# --------------------------------------------------------------------------

NEUTRAL = "ranwhat:%s"


def judge(call):
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
    return [h["rule"] for h in judge(call)[0]]


def origin_of(text):
    """3.6: an attached file; else, for a call's output, the last
    credential file the call's input names (the consumed keys replaced by
    the command, heredocs stripped); else none."""
    if text.attached:
        return text.attached
    call = text.call
    if call is None:
        return None
    named = {k: v for k, v in call.tool_input.items() if k not in call.consumed}
    if call.command:
        named["command"] = watch._strip_heredocs(call.command)
    found = clean._origins(json.dumps(named, ensure_ascii=False))
    return found[-1] if found else None


def secrets(source, stores):
    """{value: origins} over every SecretText of these stores, None standing
    for "no origin"."""
    out = {}
    for store in stores:
        for text in source.secret_texts(store):
            origin = origin_of(text)

            def collect(value, _label, _in=None, _copies=None, origin=origin):
                out.setdefault(value, set()).add(origin)
            clean._walk(text.node, collect)
    return out


def in_window(call, days, now=None):
    """3.5's window: a call by its own time; an undated call is kept unless
    its not_after is before the cutoff."""
    cutoff = (time.time() if now is None else now) - days * 86400
    stamp = call.timestamp or call.not_after
    if stamp is None:
        return True
    when, _zoned = _stamps.parse_stamp(stamp)
    return when.timestamp() >= cutoff


def call_key(call):
    return (call.tool_name, call.tool_call_id, call.kind, call.known,
            call.command, call.workdir, call.paths, call.timestamp,
            call.session, call.project)


# --------------------------------------------------------------------------

class _Home(unittest.TestCase):
    """A temp home with GROK_HOME pointed into it."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="grok-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.root = os.path.join(self.home, ".grok")
        self.backups = os.path.join(self.home, "ranwhat-backups")
        patches = [
            mock.patch.dict(os.environ, {"HOME": self.home,
                                         "USERPROFILE": self.home,
                                         "GROK_HOME": self.root}),
            mock.patch.object(_paths, "home", return_value=self.home),
            mock.patch.object(clean, "BACKUP_ROOT", self.backups),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.src = GrokBuildSource()

    def session(self, updates=None, chat=None, summary=True, enc=ENC, sid=SID,
                cwd=CWD, age=3600, root=None, extra=None):
        """Write one session folder; returns it. updates and chat are lists
        of lines (strings or objects); summary True writes the spec's
        {"info": {"id", "cwd"}}, a dict writes that, a str writes it raw."""
        folder = os.path.join(root or self.root, "sessions", enc, sid)
        os.makedirs(folder, exist_ok=True)
        files = {}
        if updates is not None:
            files["updates.jsonl"] = "".join(line(o) + "\n" for o in updates)
        if chat is not None:
            files["chat_history.jsonl"] = "".join(line(o) + "\n" for o in chat)
        if summary is True:
            summary = {"info": {"id": sid, "cwd": cwd}}
        if isinstance(summary, dict):
            files["summary.json"] = json.dumps(summary)
        elif isinstance(summary, str):
            files["summary.json"] = summary
        files.update(extra or {})
        when = time.time() - age
        for name, text in files.items():
            path = os.path.join(folder, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = text if isinstance(text, bytes) else text.encode("utf-8")
            with open(path, "wb") as fh:
                fh.write(data)
            os.utime(path, (when, when))
        return folder

    def stores(self, **kw):
        return self.src.stores(self.src.locations(), **kw)

    def store(self, folder, name="updates.jsonl"):
        path = os.path.join(folder, name)
        [store] = [s for s in self.stores() if s.path == path]
        return store

    def calls(self, folder, name="updates.jsonl"):
        return list(self.src.tool_calls(self.store(folder, name)))


# --------------------------------------------------------------------------
# 5.2 (1, 2): default paths and the override
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_every_os(self):
        src = GrokBuildSource()
        self.assertEqual(src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.grok", "default")])
        self.assertEqual(src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.grok", "default")])
        self.assertEqual(src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.grok", "default")])

    def test_grok_home_replaces_the_default(self):
        src = GrokBuildSource()
        self.assertEqual(src.default_paths({"GROK_HOME": "/srv/grok"}, "/home/u",
                                           "linux"),
                         [("/srv/grok", "env GROK_HOME")])
        self.assertEqual(src.default_paths({"GROK_HOME": "D:\\grok"},
                                           "C:\\Users\\u", "win32"),
                         [("D:\\grok", "env GROK_HOME")])
        self.assertEqual(src.env, ("GROK_HOME",))

    def test_empty_grok_home_means_the_default(self):
        src = GrokBuildSource()
        for platform, home, want in (("darwin", "/Users/u", "/Users/u/.grok"),
                                     ("win32", "C:\\Users\\u", "C:\\Users\\u\\.grok")):
            self.assertEqual(src.default_paths({"GROK_HOME": ""}, home, platform),
                             [(want, "default")])

    def test_what_reports_need(self):
        src = GrokBuildSource()
        self.assertEqual((src.id, src.name, src.unit), ("grok", "Grok Build", "session"))
        self.assertTrue(src.path_means and src.checked)
        self.assertTrue(src.byte_arrays)
        for text in (src.name, src.path_means, src.checked, src.mask_note):
            self.assertNotIn("\u2014", text)


class Override(_Home):

    def test_grok_home_is_read_at_call_time(self):
        os.environ.pop("GROK_HOME")
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (os.path.join(self.home, ".grok"), "default", False, 0))
        moved = os.path.join(self.home, "elsewhere")
        self.session(updates=sample_updates(), root=moved)
        os.environ["GROK_HOME"] = moved          # after import and construction
        [loc] = self.src.locations()
        self.assertEqual((loc.source, loc.path, loc.how, loc.exists, loc.found),
                         ("grok", moved, "env GROK_HOME", True, 2))

    def test_empty_grok_home_reads_the_default_folder(self):
        os.environ["GROK_HOME"] = ""
        folder = self.session(updates=sample_updates(),
                              root=os.path.join(self.home, ".grok"))
        [loc] = self.src.locations()
        self.assertEqual((loc.how, loc.found), ("default", 2))
        self.assertEqual(len(self.calls(folder)), 3)

    def test_path_override_is_a_grok_home(self):
        other = os.path.join(self.home, "copy-of-grok")
        self.session(updates=sample_updates(), root=other)
        [loc] = self.src.locations(override=other)
        self.assertEqual((loc.how, loc.exists, loc.found), ("--path", True, 2))
        self.assertEqual(self.src.stores(self.src.locations(override=os.path.join(
            other, "sessions"))), [], "--path names GROK_HOME, not sessions/")


# --------------------------------------------------------------------------
# 5.2 (3): discovery
# --------------------------------------------------------------------------

class Discovery(_Home):

    def test_stores_roles_session_and_project(self):
        main = self.session(updates=sample_updates(), chat=sample_chat(), age=600)
        only_chat = self.session(chat=sample_chat(), sid="0199b6c0-0000-0000-0000-00000000c4a7",
                                 enc="%2Fsrv%2Fapp", cwd="/srv/app", age=60)
        stores = self.stores()
        got = [(os.path.relpath(s.path, self.root), s.format, s.role, s.session,
                s.project, s.masking) for s in stores]
        self.assertEqual(sorted(got), sorted([
            (os.path.join("sessions", ENC, SID, "updates.jsonl"), "jsonl",
             "transcript", SID, CWD, "rewrite"),
            (os.path.join("sessions", ENC, SID, "chat_history.jsonl"), "jsonl",
             "side", SID, CWD, "rewrite"),
            (os.path.join("sessions", ENC, SID, "summary.json"), "json",
             "side", SID, CWD, "rewrite"),
            (os.path.join("sessions", "%2Fsrv%2Fapp",
                          "0199b6c0-0000-0000-0000-00000000c4a7",
                          "chat_history.jsonl"), "jsonl", "transcript",
             "0199b6c0-0000-0000-0000-00000000c4a7", "/srv/app", "rewrite"),
            (os.path.join("sessions", "%2Fsrv%2Fapp",
                          "0199b6c0-0000-0000-0000-00000000c4a7",
                          "summary.json"), "json", "side",
             "0199b6c0-0000-0000-0000-00000000c4a7", "/srv/app", "rewrite"),
        ]))
        # newest first
        self.assertTrue(all(os.path.dirname(s.path) == only_chat for s in stores[:2]))
        self.assertTrue(all(os.path.dirname(s.path) == main for s in stores[2:]))
        self.assertEqual([s.mtime for s in stores], sorted((s.mtime for s in stores),
                                                           reverse=True))
        self.assertTrue(all(s.source == "grok" and s.unit == "session" for s in stores))

    def test_session_files_the_spec_does_not_name_are_not_stores(self):
        secret_line = '{"note":"KEY=%s"}\n' % SECRET
        folder = self.session(updates=sample_updates(), extra={
            name: secret_line for name in (
                "plan.json", "signals.json", "rewind_points.jsonl",
                "feedback.jsonl", "system_prompt.txt", "prompt_context.json",
                "tool_definitions.json", "compaction_checkpoints/0001.jsonl",
                "subagents/a.jsonl", "updates.jsonl.bak", ".cwd")})
        for name in ("config.toml", "grok.db", os.path.join("logs", "unified.jsonl"),
                     "user-settings.json", os.path.join("sessions", "stray.jsonl")):
            path = os.path.join(self.root, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(secret_line)
        names = sorted(os.path.basename(s.path) for s in self.stores())
        self.assertEqual(names, ["summary.json", "updates.jsonl"])
        self.assertTrue(all(os.path.dirname(s.path) == folder for s in self.stores()))
        # and so login material and logs are never searched
        found = secrets(self.src, self.stores())
        self.assertEqual(set(found), {SECRET})

    def test_a_folder_named_by_slug_and_hash_is_not_decoded(self):
        long_cwd = "/Users/me/" + "deep/" * 60 + "proj"
        folder = self.session(updates=sample_updates(), enc="deep-deep-proj-3f2a9c01",
                              cwd=long_cwd, extra={".cwd": long_cwd})
        self.assertEqual(self.store(folder).project, long_cwd)
        self.assertEqual({c.project for c in self.calls(folder)}, {long_cwd})

    def test_without_summary_the_folder_names_the_session(self):
        folder = self.session(updates=sample_updates(), summary=None,
                              sid="0199b6c0-7a1e-7c3d-9f00-0000000000aa")
        store = self.store(folder)
        self.assertEqual((store.session, store.project),
                         ("0199b6c0-7a1e-7c3d-9f00-0000000000aa", None))
        # the calls still carry the agent's own session id
        self.assertEqual({c.session for c in self.calls(folder)}, {SID})

    def test_child_sessions_sit_in_the_same_tree(self):
        self.session(updates=sample_updates())
        child_id = "0199b6c0-7a1e-7c3d-9f00-00000000c41d"
        child = self.session(updates=sample_updates(), sid=child_id,
                             enc="%2FUsers%2Fme%2Fproj%2F.grok-worktrees%2Fa1",
                             summary={"info": {"id": child_id,
                                               "cwd": CWD + "/.grok-worktrees/a1"},
                                      "title": "subagent", "created_at": 1,
                                      "updated_at": 2,
                                      "current_model_id": "grok-build-0.1",
                                      "parent_session_id": SID, "forked_at": 1})
        store = self.store(child)
        self.assertEqual((store.session, store.project),
                         (child_id, CWD + "/.grok-worktrees/a1"))

    def test_missing_root_and_grok_db_alone_are_zero_stores(self):
        self.assertEqual(self.stores(), [])
        os.makedirs(self.root)
        with open(os.path.join(self.root, "grok.db"), "wb") as fh:
            fh.write(b"SQLite format 3\x00")
        os.makedirs(os.path.join(self.root, "sessions", ENC, SID))
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (True, 0))
        self.assertEqual(self.stores(), [])

    def test_days_prefilter_by_last_write(self):
        self.session(updates=sample_updates(), age=90 * 86400)
        recent = self.session(updates=sample_updates(), sid="0199b6c0-0000-0000-0000-0000000000bb",
                              age=60)
        kept = self.src.stores(self.src.locations(), since_days=30)
        self.assertEqual({os.path.dirname(s.path) for s in kept}, {recent})


# --------------------------------------------------------------------------
# Tool calls: normalised per 7.7, every variant the spec lists
# --------------------------------------------------------------------------

class ToolCalls(_Home):

    def test_the_sample(self):
        folder = self.session(updates=sample_updates())
        shell, read, write = self.calls(folder)

        self.assertEqual(call_key(shell), (
            "run_terminal_cmd", "call_1", "shell", True, "cat .env; npm test",
            CWD, (), "2026-09-21T14:13:22Z", SID, CWD))
        self.assertEqual(shell.consumed, frozenset(["command"]))
        self.assertEqual(shell.tool_input, {"command": "cat .env; npm test",
                                            "description": "Run tests",
                                            "is_background": False})
        self.assertEqual(shell.output, OUTPUT)
        self.assertEqual((shell.actor, shell.status, shell.not_after), ("agent", None, None))

        # no x.ai/tool on this line: named by the step-1 title
        self.assertEqual(call_key(read), (
            "read_file", "call_2", "read", True, None, None,
            ("src/config.ts", "/Users/me/proj/src/config.ts"),
            "2026-09-21T14:13:26Z", SID, CWD))
        self.assertEqual(read.consumed, frozenset(["target_file"]))
        self.assertEqual(read.output, "export const key = process.env.KEY;\n")

        self.assertEqual(call_key(write), (
            "search_replace", "call_3", "write", True, None, None,
            ("/Users/me/proj/notes.md",), "2026-09-21T14:13:27Z", SID, CWD))
        self.assertIsNone(write.output, "a diff block is not output text")
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_named_by_x_ai_tool_never_by_a_later_title(self):
        lines = shell_lines("c1", "rm -rf ~/Documents/x", 1790000100)
        lines[0]["params"]["update"]["title"] = "Run a command"   # step-1 title
        folder = self.session(updates=lines)
        [call] = self.calls(folder)
        self.assertEqual(call.tool_name, "run_terminal_cmd")
        self.assertEqual(call.command, "rm -rf ~/Documents/x")

    def test_time_from_agent_ms_else_the_envelope_seconds(self):
        lines = shell_lines("c1", "ls", 1790000100)
        del lines[0]["params"]["_meta"]["agentTimestampMs"]
        lines[0]["timestamp"] = 1790000099
        folder = self.session(updates=lines + shell_lines("c2", "pwd", 1790000200))
        first, second = self.calls(folder)
        self.assertEqual(first.timestamp, "2026-09-21T14:14:59Z")
        self.assertEqual(second.timestamp, "2026-09-21T14:16:40Z")

    def test_every_shell_name_takes_its_command_and_the_output_directory(self):
        opencode_args = {"command": "cat ~/.aws/credentials", "workdir": "/w/2",
                         "description": "Run it"}
        lines = (shell_lines("a0", "cat ~/.aws/credentials", 1790000100,
                             current_dir="/w/0")
                 + shell_lines("a1", "cat ~/.aws/credentials", 1790000110,
                               name="run_terminal_command", current_dir="/w/1")
                 + shell_lines("a2", "cat ~/.aws/credentials", 1790000120, name="bash",
                               namespace="opencode", current_dir="/w/2",
                               model_args=opencode_args))
        folder = self.session(updates=lines)
        calls = self.calls(folder)
        self.assertEqual([c.tool_name for c in calls],
                         ["run_terminal_cmd", "run_terminal_command", "bash"])
        for i, call in enumerate(calls):
            self.assertEqual((call.kind, call.known, call.command, call.workdir),
                             ("shell", True, "cat ~/.aws/credentials", "/w/%d" % i))
            # the latest rawInput: the typed input, tagged with its variant
            self.assertEqual(call.tool_input, {
                "variant": "Bash", "command": "cat ~/.aws/credentials",
                "description": "Run it", "is_background": False})
            self.assertEqual(call.consumed, frozenset(["command"]))
            self.assertEqual(call.output, "")
            self.assertEqual(rules(call), ["cred.read"])

    def test_canonical_input_is_read_from_the_line_that_carries_it(self):
        """Upstream stamps x.ai/tool.input on the second line, never the
        first. Every first-party read also names its file in rawInput, so
        here a tool whose input keys the adapter does not know (normalization.rs:
        "a harness may add an extra key") shows the canonical path is taken
        from the line that has it."""
        notes = [envelope(1790000100, tool_call("u2", "view_notes", {"note": "x"},
                                                kind="read"), "e1"),
                 envelope(1790000100, started("u2", "view_notes", "read",
                                              "Read notes", "read", "Dynamic",
                                              {"note": "x"},
                                              {"path": "~/.ssh/id_rsa"}), "e2")]
        only_first = [envelope(1790000101, tool_call("u3", "view_notes", {"note": "x"},
                                                     kind="read"), "e3")]
        folder = self.session(updates=notes + only_first)
        read, unread = self.calls(folder)
        self.assertEqual((read.kind, read.known, read.paths, read.consumed),
                         ("read", True, ("~/.ssh/id_rsa",), frozenset()))
        self.assertEqual(rules(read), ["cred.read"])
        # no path on any line: judged by name (3.5)
        self.assertEqual((unread.kind, unread.known), ("other", False))

    def test_read_tools_of_every_toolset(self):
        lines = (read_lines("h1", "~/.ssh/id_rsa", 1790000100, name="hashline_read",
                            namespace="grok_build_hashline")
                 # codex read_file: file_path; no canonical input (CodexReadFile)
                 + [envelope(1790000110, tool_call("c1", "read_file",
                                                   {"file_path": "/Users/me/.ssh/id_rsa"},
                                                   kind="read", namespace="codex"), "e1"),
                    envelope(1790000110, started(
                        "c1", "read_file", "read", "Tool call", "other",
                        "CodexReadFile", {"file_path": "/Users/me/.ssh/id_rsa",
                                          "offset": 1, "limit": 2000, "mode": "slice",
                                          "indentation": None},
                        namespace="codex"), "e2")]
                 # opencode read: camelCase filePath, a Dynamic input, so no
                 # canonical input either
                 + [envelope(1790000120, tool_call("o1", "read",
                                                   {"filePath": "/Users/me/.aws/credentials"},
                                                   kind="read", namespace="opencode"), "e3"),
                    envelope(1790000120, started(
                        "o1", "read", "read", "Dynamic tool call", "other", "Dynamic",
                        {"filePath": "/Users/me/.aws/credentials"},
                        namespace="opencode"), "e4")])
        folder = self.session(updates=lines)
        hashline, codex, opencode = self.calls(folder)
        self.assertEqual((hashline.tool_name, hashline.kind, hashline.known,
                          hashline.paths, hashline.consumed),
                         ("hashline_read", "read", True, ("~/.ssh/id_rsa",),
                          frozenset(["target_file"])))
        self.assertEqual((codex.kind, codex.known, codex.paths, codex.consumed),
                         ("read", True, ("/Users/me/.ssh/id_rsa",),
                          frozenset(["file_path"])))
        self.assertEqual((opencode.kind, opencode.known, opencode.paths, opencode.consumed),
                         ("read", True, ("/Users/me/.aws/credentials",),
                          frozenset(["filePath"])))
        self.assertEqual([rules(c) for c in (hashline, codex, opencode)],
                         [["cred.read"]] * 3)

    def test_write_tools_name_their_file(self):
        p = "/Users/me/proj/f%d.py"
        edits = [{"op": "replace", "anchor": "3:abc:rst", "content": "x"}]
        lines = [
            # codex apply_patch: the patch names its files; no canonical input
            envelope(1790000100, tool_call("w0", "apply_patch",
                                           {"patch": "*** Begin Patch"}, kind="edit",
                                           namespace="codex"), "e0"),
            envelope(1790000100, started("w0", "apply_patch", "edit", "Apply patch",
                                         "edit", "ApplyPatch",
                                         {"patch": "*** Begin Patch"},
                                         namespace="codex"), "e0b"),
            envelope(1790000101, finished("w0", {"type": "ApplyPatch", "Success": {
                "files": [{"path": p % 0, "action": "update", "old_text": "a",
                           "new_text": "b", "move_to": None}]}}), "e0c"),
            # opencode write: file_path, and the canonical path
            envelope(1790000102, tool_call("w1", "write",
                                           {"file_path": p % 1, "content": "x"},
                                           kind="write", namespace="opencode"), "e1"),
            envelope(1790000102, started("w1", "write", "write", "Write `%s`" % (p % 1),
                                         "edit", "Write",
                                         {"file_path": p % 1, "content": "x"},
                                         {"path": p % 1}, locations=[p % 1],
                                         namespace="opencode"), "e1b"),
            # opencode edit: camelCase arguments, then the typed SearchReplace
            envelope(1790000104, tool_call("w2", "edit",
                                           {"filePath": p % 2, "oldString": "a",
                                            "newString": "b"},
                                           kind="edit", namespace="opencode"), "e2"),
            envelope(1790000104, started("w2", "edit", "edit", "Edit `%s`" % (p % 2),
                                         "edit", "SearchReplace",
                                         {"file_path": p % 2, "old_string": "a",
                                          "new_string": "b", "replace_all": False},
                                         {"path": p % 2}, locations=[p % 2],
                                         namespace="opencode"), "e2b"),
            # the same, cut short before its second line
            envelope(1790000106, tool_call("w3", "edit",
                                           {"filePath": p % 3, "oldString": "a",
                                            "newString": "b"},
                                           kind="edit", namespace="opencode"), "e3"),
            # hashline_edit: file_path; no canonical input (HashlineEdit)
            envelope(1790000108, tool_call("w4", "hashline_edit",
                                           {"file_path": p % 4, "edits": edits},
                                           kind="edit", namespace="grok_build_hashline"),
                     "e4"),
            envelope(1790000108, started("w4", "hashline_edit", "edit",
                                         "Edit `%s`" % (p % 4), "edit", "HashlineEdit",
                                         {"file_path": p % 4, "edits": edits},
                                         locations=[p % 4],
                                         namespace="grok_build_hashline"), "e4b"),
        ]
        folder = self.session(updates=lines)
        calls = self.calls(folder)
        self.assertEqual([(c.tool_name, c.kind, c.known, c.paths) for c in calls], [
            ("apply_patch", "write", True, ()),
            ("write", "write", True, (p % 1,)),
            ("edit", "write", True, (p % 2,)),
            ("edit", "write", True, (p % 3,)),
            ("hashline_edit", "write", True, (p % 4,))])
        self.assertTrue(all(rules(c) == [] for c in calls))

    def test_todo_write_is_other_and_known(self):
        folder = self.session(updates=[envelope(1790000100, tool_call(
            "t1", "todo_write", {"todos": [{"content": "rm -rf build"}]},
            kind="plan"), "e1")])
        [call] = self.calls(folder)
        self.assertEqual((call.kind, call.known), ("other", True))
        self.assertEqual(rules(call), [])

    def test_grok_kind_classifies_names_the_spec_does_not_list(self):
        typed = {"command": "rm -rf ~/Documents/x", "description": "d",
                 "is_background": False}
        lines = [
            # a shell under a name a toolset preset gave it, with a renamed
            # argument; the typed input on the second line has "command"
            envelope(1790000100, tool_call("u1", "shell_exec",
                                           {"cmd": "rm -rf ~/Documents/x"},
                                           kind="execute"), "e1"),
            envelope(1790000100, started("u1", "shell_exec", "execute",
                                         "Execute `rm -rf ~/Documents/x`", "execute",
                                         "Bash", typed,
                                         {"command": "rm -rf ~/Documents/x",
                                          "description": "d"}), "e1b"),
            # the same, with only its first line: no command anywhere
            envelope(1790000101, tool_call("u3", "shell_exec", {"script": "x"},
                                           kind="execute"), "e3"),
            envelope(1790000102, tool_call("u4", "web_fetch", {"url": "https://x.test"},
                                           kind="web_fetch"), "e4"),
            envelope(1790000103, tool_call("u5", "mcp__srv__bash",
                                           {"command": "rm -rf ~/Documents/x"}), "e5"),
        ]
        folder = self.session(updates=lines)
        shell, no_command, fetch, mcp = self.calls(folder)
        self.assertEqual((shell.kind, shell.known, shell.command),
                         ("shell", True, "rm -rf ~/Documents/x"))
        self.assertEqual(rules(shell), ["fs.destructive"])
        # no command, and no verified fetch tool: judged by name (3.5)
        for call in (no_command, fetch):
            self.assertEqual((call.kind, call.known), ("other", False))
            self.assertEqual(rules(call), [])
        self.assertEqual((mcp.kind, mcp.known), ("other", False))
        self.assertEqual(rules(mcp), ["fs.destructive"], "an MCP bash is judged by name")

    def test_monitor_runs_a_command(self):
        """monitor (core toolsets, kind "monitor") runs rawInput.command in
        the background; Monitor has no canonical input."""
        lines = []
        for i, command in enumerate(("rm -rf ~/Documents/w", "cat ~/.aws/credentials")):
            call_id = "m%d" % i
            args = {"command": command, "description": "watch"}
            lines += [envelope(1790000100 + i, tool_call(call_id, "monitor", args,
                                                         kind="monitor"), "e%d" % i),
                      envelope(1790000100 + i, started(
                          call_id, "monitor", "monitor", "Start monitor: watch", "other",
                          "Monitor", dict(args, timeout_ms=36000000, persistent=False)),
                          "e%db" % i),
                      envelope(1790000100 + i, finished(call_id, {
                          "type": "Monitor", "taskId": "t%d" % i,
                          "timeoutMs": 36000000, "persistent": False}), "e%dc" % i)]
        folder = self.session(updates=lines)
        calls = self.calls(folder)
        self.assertEqual([(c.tool_name, c.kind, c.known, c.command, c.consumed)
                          for c in calls], [
            ("monitor", "shell", True, "rm -rf ~/Documents/w", frozenset(["command"])),
            ("monitor", "shell", True, "cat ~/.aws/credentials", frozenset(["command"]))])
        self.assertEqual([rules(c) for c in calls], [["fs.destructive"], ["cred.read"]])
        # and in chat_history.jsonl, where there is no Grok kind
        chat = [line({"type": "assistant", "content": "", "tool_calls": [
            {"id": "m9", "name": "monitor", "arguments": json.dumps(
                {"command": "rm -rf ~/Documents/w", "description": "watch"})}],
            "model_id": "grok-build-0.1"})]
        other = self.session(chat=chat, sid="0199b6c0-0000-0000-0000-00000000a0a0")
        [call] = self.calls(other, "chat_history.jsonl")
        self.assertEqual((call.kind, rules(call)), ("shell", ["fs.destructive"]))

    def test_the_x_ai_method_is_read_and_other_methods_are_not(self):
        lines = shell_lines("x1", "ls", 1790000100, method="_x.ai/session/update")
        lines.append({"timestamp": 1790000101, "method": "session/request_permission",
                      "params": {"sessionId": SID, "update": tool_call(
                          "x2", "run_terminal_cmd", {"command": "rm -rf ~/x"})}})
        folder = self.session(updates=lines)
        self.assertEqual([c.tool_call_id for c in self.calls(folder)], ["x1"])
        self.assertEqual(self.src.counts["unknown"], 1)

    def test_outputs_where_stored(self):
        lines = []
        # Bash output with no output_for_prompt: the byte array, decoded
        lines += [envelope(1790000100, tool_call("o1", "run_terminal_cmd",
                                                 {"command": "printf caf\u00e9"},
                                                 kind="execute"), "e1"),
                  envelope(1790000101, finished("o1", bash_output(
                      "caf\u00e9\n", "printf caf\u00e9", prompt=False)), "e2")]
        # failed, content only
        lines += [envelope(1790000102, tool_call("o2", "run_terminal_cmd",
                                                 {"command": "false"},
                                                 kind="execute"), "e3"),
                  envelope(1790000103, finished("o2", content=text_content("boom"),
                                                status="failed"), "e4")]
        # a read that failed: the error variant, no absolute path; its
        # content is the error text
        lines += read_lines("o3", "missing.txt", 1790000104, error="No such file")
        # a search_replace whose completion carries SearchReplace and a diff
        lines += write_lines("o4", "/Users/me/proj/a.py", "b\n", 1790000105)
        # a command still waiting for permission: its second line's content
        # is the description shown for it, not output
        lines += shell_lines("o5", "make", 1790000107)[:2]
        folder = self.session(updates=lines)
        o1, o2, o3, o4, o5 = self.calls(folder)
        self.assertEqual(o1.output, "caf\u00e9\n")
        self.assertEqual(o2.output, "boom")
        self.assertEqual((o3.paths, o3.output), (("missing.txt",), "No such file"))
        self.assertEqual(o4.output, "Created /Users/me/proj/a.py")
        self.assertIsNone(o5.output)

    def test_calls_are_assembled_once_by_id(self):
        lines = shell_lines("d1", "echo first", 1790000100, output="1\n")
        replay = json.loads(json.dumps(lines))
        replay[0]["params"]["_meta"]["agentTimestampMs"] = 1790000900000
        replay[1]["params"]["update"]["rawInput"]["command"] = "echo second"
        folder = self.session(updates=lines + replay[:2])
        [call] = self.calls(folder)
        self.assertEqual(call.timestamp, "2026-09-21T14:15:00Z", "the first step-1 line")
        self.assertEqual(call.tool_input["command"], "echo second", "the latest rawInput")

    def test_updates_without_their_tool_call_line_are_counted_not_guessed(self):
        orphan = [envelope(1790000100, started(
                      "lost", "run_terminal_cmd", "execute", "Execute `rm -rf ~/Documents/x`",
                      "execute", "Bash", {"command": "rm -rf ~/Documents/x",
                                          "description": "d", "is_background": False},
                      {"command": "rm -rf ~/Documents/x", "description": "d"}), "e1"),
                  envelope(1790000100, {"sessionUpdate": "tool_call", "title": "bash"}, "e2")]
        folder = self.session(updates=orphan + shell_lines("ok", "ls", 1790000200))
        self.assertEqual([c.tool_call_id for c in self.calls(folder)], ["ok"])
        self.assertEqual(self.src.counts["unreadable_calls"], 2)

    def test_only_chat_history_gives_undated_calls(self):
        chat = sample_chat() + [
            line({"type": "user", "content": [{"type": "text", "text": "hi"}]}),
            line({"type": "assistant", "content": "", "tool_calls": [
                {"id": "call_2", "name": "read_file",
                 "arguments": json.dumps({"target_file": "../../.ssh/id_rsa"})},
                {"id": "call_3", "name": "search_replace",
                 "arguments": json.dumps({"file_path": "a.sh", "old_string": "",
                                          "new_string": "rm -rf /",
                                          "replace_all": False})},
                {"id": "call_1", "name": "run_terminal_cmd",
                 "arguments": "{\"command\": \"replayed\"}"}],
                  "model_id": "grok-build-0.1"}),
            line({"type": "reasoning", "content": "thinking"})]
        folder = self.session(chat=chat, age=7200)
        store = self.store(folder, "chat_history.jsonl")
        self.assertEqual(store.role, "transcript")
        calls = list(self.src.tool_calls(store))
        self.assertEqual([(c.tool_call_id, c.tool_name, c.kind, c.command, c.paths)
                          for c in calls], [
            ("call_1", "run_terminal_cmd", "shell", "cat .env; npm test", ()),
            ("call_2", "read_file", "read", None, ("../../.ssh/id_rsa",)),
            ("call_3", "search_replace", "write", None, ("a.sh",))])
        mtime = _stamps.iso_utc(os.stat(store.path).st_mtime, "s")
        for call in calls:
            self.assertEqual((call.timestamp, call.not_after, call.session, call.project),
                             (None, mtime, SID, CWD))
        self.assertEqual(calls[0].output, OUTPUT)
        self.assertEqual([rules(c) for c in calls], [["cred.read"], ["cred.read"], []])

    def test_chat_history_beside_updates_yields_no_calls(self):
        folder = self.session(updates=sample_updates(), chat=sample_chat())
        self.assertEqual(self.calls(folder, "chat_history.jsonl"), [])
        self.assertEqual(list(self.src.tool_calls(self.store(folder, "summary.json"))), [])
        self.assertEqual([c.tool_call_id for c in self.calls(folder)],
                         ["call_1", "call_2", "call_3"])

    def test_shape_table(self):
        """The 7.7 table, checked on its own."""
        self.assertEqual(shape("run_terminal_cmd", "execute", {"command": "ls"},
                               {"cwd": "/c"}, out_dir="/o"),
                         {"kind": "shell", "known": True, "command": "ls",
                          "workdir": "/o", "paths": (), "consumed": ("command",)})
        self.assertEqual(shape("read_file", "read", {"target_file": "/a"}, {},
                               out_path="/a")["paths"], ("/a",))
        self.assertEqual(shape("anything", None, {"command": "rm -rf /"}, {}),
                         {"kind": "other", "known": False, "command": None,
                          "workdir": None, "paths": (), "consumed": ()})
        # monitor, by name or by Grok's kind; bash mode whatever the name
        for name, kind in (("monitor", None), ("watch_it", "monitor")):
            self.assertEqual(shape(name, kind, {"command": "ls"}, {})["kind"], "shell")
        self.assertEqual(shape("bash_mode", None, {"variant": "Bash", "command": "ls"},
                               {}, bash_mode=True)["command"], "ls")

    def test_canonical_fallbacks_are_tolerated(self):
        """The canonical vocabulary has command, cwd and directory (7.7).
        At the checked commit no first-party shell projects cwd or
        directory, and the typed input always carries the command; these
        are read only when a line holds them."""
        self.assertEqual(shape("bash", "execute", {"variant": "Bash"},
                               {"command": "ls", "cwd": "/c"}),
                         {"kind": "shell", "known": True, "command": "ls",
                          "workdir": "/c", "paths": (), "consumed": ("command",)})
        self.assertEqual(shape("run_terminal_cmd", None, {}, {"command": "ls",
                                                              "directory": "/d"})["workdir"],
                         "/d")
        self.assertEqual(shape("write", "write", {}, {"path": "/p"})["paths"], ("/p",))


# --------------------------------------------------------------------------
# Bash mode, old lines with no envelope, ids that are not strings
# --------------------------------------------------------------------------

def legacy(obj):
    """An envelope's notification on its own, as old sessions wrote it."""
    return dict(obj["params"])


class BashMode(_Home):

    def test_a_command_typed_with_a_bang_is_a_shell_call_the_user_ran(self):
        lines = (bash_mode_lines("bash-mode-0199b6c0-0001", "cat ~/.aws/credentials",
                                 1790000100, output="[default]\n")
                 # the plan toolset has no shell: only the marker, and the
                 # title is display text
                 + bash_mode_lines("bash-mode-0199b6c0-0002", "rm -rf ~/Documents/y",
                                   1790000110, exec_wire=None))
        folder = self.session(updates=lines)
        stamped, marker_only = self.calls(folder)
        self.assertEqual((stamped.tool_name, stamped.kind, stamped.known, stamped.actor,
                          stamped.command, stamped.workdir, stamped.output),
                         ("run_terminal_command", "shell", True, "user",
                          "cat ~/.aws/credentials", CWD, "[default]\n"))
        self.assertEqual(rules(stamped), ["cred.read"])
        self.assertEqual((marker_only.tool_name, marker_only.kind, marker_only.known,
                          marker_only.actor, marker_only.command),
                         ("bash_mode", "shell", True, "user", "rm -rf ~/Documents/y"))
        self.assertEqual(rules(marker_only), ["fs.destructive"])
        self.assertEqual(marker_only.timestamp, "2026-09-21T14:15:10Z")

    def test_the_id_alone_marks_bash_mode(self):
        lines = bash_mode_lines("bash-mode-0199b6c0-0003", "rm -rf ~/Documents/z",
                                1790000100, exec_wire=None, marker=False)
        [call] = self.calls(self.session(updates=lines))
        self.assertEqual((call.tool_name, call.kind, call.actor),
                         ("bash_mode", "shell", "user"))

    def test_the_agents_calls_stay_the_agents(self):
        [call] = self.calls(self.session(updates=shell_lines("c1", "ls", 1790000100)))
        self.assertEqual(call.actor, "agent")


class OldLines(_Home):
    """Old sessions wrote the notification itself, {sessionId, update,
    _meta}, with no envelope; the reader still replays them
    (storage/mod.rs SessionUpdateEnvelope::from_str)."""

    def test_lines_with_no_envelope_are_read(self):
        old = [legacy(o) for o in shell_lines("L1", "rm -rf ~/Documents/z", 1790000100)]
        undated = [legacy(o) for o in shell_lines("L2", "ls", 1790000110)]
        del undated[0]["_meta"]["agentTimestampMs"]
        new = shell_lines("N1", "cat ~/.aws/credentials", 1790000200)
        folder = self.session(updates=old + undated + new)
        first, second, third = self.calls(folder)
        mtime = _stamps.iso_utc(os.stat(self.store(folder).path).st_mtime, "s")
        self.assertEqual((first.tool_call_id, first.kind, first.command, first.session,
                          first.timestamp, first.not_after),
                         ("L1", "shell", "rm -rf ~/Documents/z", SID,
                          "2026-09-21T14:15:00Z", None))
        self.assertEqual((second.timestamp, second.not_after), (None, mtime))
        self.assertEqual(third.tool_call_id, "N1")
        self.assertEqual([rules(c) for c in (first, second, third)],
                         [["fs.destructive"], [], ["cred.read"]])
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_an_envelope_with_no_method_is_read(self):
        lines = shell_lines("P1", "rm -rf ~/Documents/p", 1790000100)
        for obj in lines:
            del obj["method"]
        [call] = self.calls(self.session(updates=lines))
        self.assertEqual((call.tool_call_id, rules(call)), ("P1", ["fs.destructive"]))

    def test_their_output_is_searched_credited_and_masked(self):
        old = [legacy(o) for o in shell_lines("L1", "cat .env", 1790000100,
                                               output="API_KEY=%s\n" % SECRET)]
        folder = self.session(updates=old)
        self.assertEqual(secrets(self.src, self.stores()), {SECRET: {".env"}})
        store = self.store(folder)
        texts = list(self.src.secret_texts(store))
        self.assertEqual(sorted(set(t.where for t in texts)),
                         ["line 1", "line 2", "line 3"])
        rest = [t.node for t in texts if t.where == "line 3" and t.call is None]
        self.assertEqual(sorted(rest[0]["update"]), ["sessionUpdate", "status", "toolCallId"])
        before = [call_key(c) for c in self.calls(folder)]
        result = self.src.mask(store, [SECRET])
        self.assertTrue(result.changed, result)
        self.assertNotIn(SECRET, _read(store.path).decode("utf-8"))
        self.src.reset()
        self.assertEqual([call_key(c) for c in self.calls(folder)], before)


class OddIds(_Home):

    def test_an_id_that_is_not_a_string_does_not_stop_the_store(self):
        later = "sk_" "live_" "L4terR2mT6yLp4WcN0sXe7Hb"
        in_chat = "sk_" "live_" "Ch4tsR2mT6yLp4WcN0sXe7Hb"
        lines = [envelope(1790000100, {"sessionUpdate": "tool_call_update",
                                       "toolCallId": {}, "content": text_content("x")},
                          "e1"),
                 envelope(1790000101, {"sessionUpdate": "tool_call_update",
                                       "toolCallId": [1],
                                       "rawOutput": {"type": "Bash", "output": [65]}},
                          "e2"),
                 envelope(1790000102, {"sessionUpdate": "agent_message_chunk",
                                       "content": {"type": "text", "text": "use " + later}},
                          "e3")]
        chat = [line({"type": "tool_result", "tool_call_id": [], "content": "x"}),
                line({"type": "tool_result", "tool_call_id": {"a": 1}, "content": "y"}),
                line({"type": "user", "content": "use " + in_chat})]
        self.session(updates=lines, chat=chat)
        self.session(chat=chat, sid="0199b6c0-0000-0000-0000-0000000000ee")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            found = secrets(self.src, self.stores())
            calls = [c for s in self.stores() for c in self.src.tool_calls(s)]
        self.assertEqual(found, {later: {None}, in_chat: {None}})
        self.assertEqual(calls, [])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.counts["unreadable_stores"], 0)
        self.assertEqual(self.src.counts["unreadable_calls"], 2)


# --------------------------------------------------------------------------
# The other copies in a session folder: terminal logs, compaction records
# --------------------------------------------------------------------------

class SideCopies(_Home):
    """terminal/<toolCallId>.log holds a command's whole output, written
    before any truncation (xai-grok-tools bash/mod.rs, xai-grok-shell-terminal
    streaming_local_terminal.rs); terminal/monitor-<id>.log a monitor's
    (monitor/tool.rs); compaction/segment_NNN.md and INDEX.md the turns a
    compaction dropped, tool_response text included
    (xai-compaction-transcript). clean must find a key there and mask it."""

    LOG = "API_KEY=%s\nok\n" % SECRET

    def test_discovery(self):
        folder = self.session(updates=shell_lines("c1", "cat .env", 1790000100), extra={
            "terminal/c1.log": self.LOG,
            "terminal/monitor-m1.log": "tick\n",
            "terminal/notes.txt": self.LOG,
            "terminal/.log": self.LOG,
            "compaction/segment_001.md": "# HISTORICAL -- DO NOT EDIT\n",
            "compaction/INDEX.md": "# Compaction Segment Index\n",
            "compaction/segment_x.md": self.LOG,
            "compaction/notes.md": self.LOG,
        })
        if not WINDOWS:
            outside = os.path.join(self.home, "outside.log")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write(self.LOG)
            os.symlink(outside, os.path.join(folder, "terminal", "link.log"))
        got = sorted((os.path.relpath(s.path, folder), s.format, s.role, s.unit,
                      s.masking, s.session, s.project) for s in self.stores())
        self.assertEqual(got, sorted([
            (os.path.join("compaction", "INDEX.md"), "text", "side",
             "compaction record", "rewrite", SID, CWD),
            (os.path.join("compaction", "segment_001.md"), "text", "side",
             "compaction record", "rewrite", SID, CWD),
            ("summary.json", "json", "side", "session", "rewrite", SID, CWD),
            (os.path.join("terminal", "c1.log"), "text", "side", "terminal log",
             "rewrite", SID, CWD),
            (os.path.join("terminal", "monitor-m1.log"), "text", "side",
             "terminal log", "rewrite", SID, CWD),
            ("updates.jsonl", "jsonl", "transcript", "session", "rewrite", SID, CWD),
        ]))
        log = self.store(folder, os.path.join("terminal", "c1.log"))
        self.assertEqual(list(self.src.tool_calls(log)), [])

    def test_a_key_in_a_terminal_log_is_credited_to_its_call(self):
        # the transcript holds a cut-down output; the log holds it all
        lines = (shell_lines("c1", "cat .env", 1790000100, output="[truncated]\n")
                 + [envelope(1790000102, tool_call("m1", "monitor", {
                        "command": "tail -f config/.env.local", "description": "watch"},
                        kind="monitor"), "em")])
        other = "sk_" "live_" "M0nit0rR2mT6yLp4WcN0sXe7H"
        stray = "sk_" "live_" "StrayR2mT6yLp4WcN0sXe7HbJ"
        folder = self.session(updates=lines, extra={
            "terminal/c1.log": self.LOG,
            "terminal/monitor-m1.log": "KEY=%s\n" % other,
            "terminal/gone.log": "KEY=%s\n" % stray})
        self.assertEqual(secrets(self.src, self.stores()),
                         {SECRET: {".env"}, other: {"config/.env.local"},
                          stray: {None}})
        [text] = list(self.src.secret_texts(self.store(folder, os.path.join(
            "terminal", "c1.log"))))
        self.assertEqual((text.node, text.call.tool_call_id, text.where),
                         (self.LOG, "c1", "lines 1-2"))
        # with only chat_history.jsonl, the log is credited through it
        chat_only = self.session(chat=sample_chat("[truncated]\n"),
                                 sid="0199b6c0-0000-0000-0000-0000000000c1",
                                 extra={"terminal/call_1.log": self.LOG})
        [text] = list(self.src.secret_texts(self.store(chat_only, os.path.join(
            "terminal", "call_1.log"))))
        self.assertEqual(text.call.tool_name, "run_terminal_cmd")
        self.assertEqual(origin_of(text), ".env")

    def test_a_key_in_a_compaction_record_has_no_origin(self):
        segment = ("# HISTORICAL -- DO NOT EDIT\n\n[tool_request: run_terminal_cmd]\n"
                   "- command: cat .env\n[tool_response]\nAPI_KEY=%s\n" % SECRET)
        self.session(updates=shell_lines("c1", "ls", 1790000100), extra={
            "compaction/segment_001.md": segment})
        self.assertEqual(secrets(self.src, self.stores()), {SECRET: {None}})

    def test_masking_leaves_no_copy(self):
        segment = "[tool_response]\nAPI_KEY=%s\n" % SECRET
        folder = self.session(
            updates=shell_lines("c1", "cat .env", 1790000100, output=self.LOG),
            extra={"terminal/c1.log": self.LOG, "compaction/segment_001.md": segment})
        stores = self.stores()
        original = {s.path: _read(s.path) for s in stores}
        results = {s.path: self.src.mask(s, [SECRET]) for s in stores}
        marker = _marker(SECRET)
        for path in (os.path.join(folder, "terminal", "c1.log"),
                     os.path.join(folder, "compaction", "segment_001.md")):
            self.assertTrue(results[path].changed, results[path])
            self.assertEqual(_read(path), original[path].replace(
                SECRET.encode("utf-8"), marker.encode("utf-8")))
            self.assertEqual(_read(results[path].backup), original[path])
        self.assertTrue(results[os.path.join(folder, "updates.jsonl")].changed)
        for store in self.stores():
            self.assertNotIn(SECRET, _read(store.path).decode("utf-8"))
            self.assertEqual(self.src.mask(store, [SECRET]), MaskResult(store.path))
        self.assertEqual(secrets(self.src, self.stores()), {})

    def test_a_log_a_command_may_still_be_writing_is_in_use(self):
        started_bg = shell_lines("bg1", "npm run dev", 1790000100, background=True)[:2] + [
            envelope(1790000101, finished("bg1", {
                "type": "BackgroundTaskStarted", "task_id": "t1", "task_type": "bash",
                "output_file": "terminal/bg1.log", "status": "running",
                "command": "npm run dev", "summary": "npm run dev"}), "e-bg1-3")]
        moved = shell_lines("bg2", "make", 1790000110, signal="backgrounded")
        del moved[2]["params"]["update"]["status"]      # still running: no status
        monitor = [envelope(1790000120, tool_call("m1", "monitor", {
            "command": "tail -f app.log", "description": "watch"}, kind="monitor"), "em")]
        done = shell_lines("fg", "cat .env", 1790000130)
        folder = self.session(updates=started_bg + moved + monitor + done, extra={
            "terminal/%s.log" % name: self.LOG
            for name in ("bg1", "bg2", "monitor-m1", "fg")})
        results = {}
        for name in ("bg1", "bg2", "monitor-m1", "fg"):
            store = self.store(folder, os.path.join("terminal", name + ".log"))
            results[name] = self.src.mask(store, [SECRET])
        for name in ("bg1", "bg2", "monitor-m1"):
            self.assertEqual(results[name].skipped, "in use", name)
            self.assertEqual(_read(os.path.join(folder, "terminal", name + ".log")),
                             self.LOG.encode("utf-8"))
        self.assertTrue(results["fg"].changed, results["fg"])

    def test_a_large_log_is_read_in_overlapping_pieces(self):
        """Pieces end at line ends, so no value is cut in two (a cut one
        would be reported as a second, shorter value); a line longer than a
        piece is cut at a space; a block of lines that crosses a boundary is
        whole in the next piece."""
        key_block = ("-----BEGIN OPENSSH " "PRIVATE KEY-----\n"
                     + "".join("b3BlbnNzaC1rZXktdjEAAAA%d\n" % i for i in range(3))
                     + "-----END OPENSSH PRIVATE KEY-----\n")

        def filler(tag, n):
            return "".join("%s line %03d %s\n" % (tag, i, "x" * 20) for i in range(n))
        long_line = ("KEY " + " ".join("w%02d" % i for i in range(20)) + " " + SECRET
                     + " end\n")
        text = filler("a", 40) + long_line + filler("b", 3) + key_block + filler("c", 40)
        folder = self.session(updates=shell_lines("c1", "cat .env", 1790000100),
                              extra={"terminal/c1.log": text})
        path = os.path.join(folder, "terminal", "c1.log")
        with mock.patch.object(grok_module, "_TEXT_CHUNK", 64), \
                mock.patch.object(grok_module, "_TEXT_OVERLAP", 160):
            pieces = list(grok_module._text_pieces(path))
            found = secrets(self.src, self.stores())
        # each value whole, once: no shorter piece of either
        self.assertEqual(found, {SECRET: {".env"}, key_block.rstrip("\n"): {".env"}})
        self.assertGreater(len(pieces), 10)
        self.assertTrue(any(key_block in p[2] for p in pieces))
        # contiguous pieces of the file, in order, with no gap, numbered by
        # the lines they start and end on
        at = 0
        for first, last, piece in pieces:
            start = text.find(piece, max(0, at - 160))
            self.assertTrue(0 <= start <= at, (start, at))
            self.assertEqual(first, text.count("\n", 0, start) + 1)
            self.assertEqual(last, text.count("\n", 0, start + len(piece) - 1) + 1)
            at = start + len(piece)
        self.assertEqual(at, len(text))
        self.assertEqual(pieces[0][0], 1)

    def test_pieces_of_small_and_empty_files(self):
        folder = self.session(updates=shell_lines("c1", "ls", 1790000100), extra={
            "terminal/a.log": "", "terminal/b.log": "one\ntwo", "terminal/c.log": "x\n"})
        self.assertEqual(list(grok_module._text_pieces(
            os.path.join(folder, "terminal", "a.log"))), [])
        self.assertEqual(list(grok_module._text_pieces(
            os.path.join(folder, "terminal", "b.log"))), [(1, 2, "one\ntwo")])
        self.assertEqual(list(grok_module._text_pieces(
            os.path.join(folder, "terminal", "c.log"))), [(1, 1, "x\n")])


# --------------------------------------------------------------------------
# 5.2 (4, 5, 6): what watch flags through this adapter
# --------------------------------------------------------------------------

class Judging(_Home):

    def _one(self, lines):
        folder = self.session(updates=lines)
        [call] = self.calls(folder)
        return call

    def test_dangerous_shell_calls_name_their_target(self):
        for command, rule, target in (
                ("rm -rf ~/Documents/x", "fs.destructive", "~/Documents/x"),
                ("cat ~/.aws/credentials", "cred.read", ".aws/credentials")):
            call = self._one(shell_lines("s1", command, 1790000100))
            hits, payload = judge(call)
            self.assertEqual([h["rule"] for h in hits], [rule], command)
            self.assertIn(target, hits[0]["evidence"])
            self.assertTrue(payload)
            shutil.rmtree(os.path.join(self.root, "sessions"))

    def test_the_samples_cat_env_is_a_credential_read(self):
        folder = self.session(updates=sample_updates())
        self.assertEqual([rules(c) for c in self.calls(folder)],
                         [["cred.read"], [], []])

    def test_a_credential_read_by_read_file(self):
        call = self._one(read_lines("r1", "~/.ssh/id_rsa", 1790000100,
                                    absolute=self.home + "/.ssh/id_rsa",
                                    content="-----BEGIN OPENSSH PRIVATE KEY-----\n"))
        hits, _ = judge(call)
        self.assertEqual([h["rule"] for h in hits], ["cred.read"])
        self.assertIn(".ssh/id_rsa", hits[0]["evidence"])

    def test_a_relative_read_resolved_under_ssh(self):
        call = self._one(read_lines("r1", "../../.ssh/id_rsa", 1790000100,
                                    absolute="/Users/me/.ssh/id_rsa"))
        self.assertEqual(call.paths, ("../../.ssh/id_rsa", "/Users/me/.ssh/id_rsa"))
        self.assertEqual(rules(call), ["cred.read"])

    def test_precision_carries_over(self):
        heredoc = "cat > clean.sh <<'EOF'\nrm -rf /\nEOF\nchmod +x clean.sh"
        lines = (shell_lines("p1", "grep -rn 'rm -rf' .", 1790000100)
                 + shell_lines("p2", heredoc, 1790000110)
                 + write_lines("p3", "/Users/me/proj/clean.sh", "rm -rf /\n", 1790000120))
        folder = self.session(updates=lines)
        calls = self.calls(folder)
        self.assertEqual([c.kind for c in calls], ["shell", "shell", "write"])
        self.assertEqual([rules(c) for c in calls], [[], [], []])

    def test_a_typed_secret_in_a_command_is_a_literal(self):
        call = self._one(shell_lines("t1", "curl -H 'Authorization: token %s' "
                                     "https://api.github.com/user" % TYPED, 1790000100))
        self.assertEqual(rules(call), ["secret.literal"])


# --------------------------------------------------------------------------
# 5.2 (9): secrets
# --------------------------------------------------------------------------

class Secrets(_Home):

    def test_a_key_after_cat_env_is_found_once_with_its_origin(self):
        self.session(updates=sample_updates(), chat=sample_chat())
        found = secrets(self.src, self.stores())
        self.assertEqual(found, {SECRET: {".env"}})

    def test_the_same_key_typed_into_a_command_has_no_origin(self):
        command = "curl -H 'Authorization: token %s' https://api.github.com/user" % TYPED
        self.session(updates=shell_lines("t1", command, 1790000100, output="{}\n"),
                     chat=[line({"type": "assistant", "content": "", "tool_calls": [
                         {"id": "t1", "name": "run_terminal_cmd",
                          "arguments": json.dumps({"command": command})}],
                         "model_id": "grok-build-0.1"})])
        self.assertEqual(secrets(self.src, self.stores()), {TYPED: {None}})

    def test_a_key_in_a_commands_description_is_not_its_output(self):
        """The second line's content is the description shown for the
        command: part of the call's input, so typed, not read from .env."""
        lines = shell_lines("d1", "cat .env", 1790000100, output="ok\n")
        for obj in lines[:2]:
            update = obj["params"]["update"]
            update["rawInput"]["description"] = "use " + TYPED
            if "content" in update:
                update["content"] = text_content("use " + TYPED)
        self.session(updates=lines)
        self.assertEqual(secrets(self.src, self.stores()), {TYPED: {None}})

    def test_a_key_only_in_the_byte_array_is_found(self):
        out = bash_output("KEY=%s\n" % ONLY_BYTES, "cat .env.local", prompt=False)
        lines = [envelope(1790000100, tool_call("b1", "run_terminal_cmd",
                                                {"command": "cat .env.local"},
                                                kind="execute"), "e1"),
                 envelope(1790000101, finished("b1", out), "e2")]
        folder = self.session(updates=lines)
        self.assertNotIn(ONLY_BYTES, _read(os.path.join(folder, "updates.jsonl"))
                         .decode("utf-8"))
        self.assertEqual(secrets(self.src, self.stores()), {ONLY_BYTES: {".env.local"}})

    def test_every_string_is_searched(self):
        title_key = "sk_" "live_" "T1tl3R2mT6yLp4WcN0sXe7Hb"
        chunk_key = "sk_" "live_" "Chunk9R2mT6yLp4WcN0sXe7H"
        lines = [envelope(1790000100, {"sessionUpdate": "agent_message_chunk",
                                       "content": {"type": "text",
                                                   "text": "use " + chunk_key}}, "e1")]
        self.session(updates=lines, summary={"info": {"id": SID, "cwd": CWD},
                                             "title": "rotate " + title_key})
        self.assertEqual(secrets(self.src, self.stores()),
                         {title_key: {None}, chunk_key: {None}})

    def test_the_output_text_carries_its_call(self):
        folder = self.session(updates=sample_updates())
        texts = list(self.src.secret_texts(self.store(folder)))
        with_call = [t for t in texts if t.call is not None]
        self.assertEqual(len(with_call), 3)
        bash = [t for t in with_call if t.call.tool_call_id == "call_1"]
        self.assertEqual(bash[0].node["rawOutput"]["output"], OUTPUT)
        self.assertEqual(bash[0].where, "line 4")
        # every line is covered, and no line is given twice
        self.assertEqual(sorted(set(int(t.where.split()[1]) for t in texts)),
                         list(range(1, 9)))


# --------------------------------------------------------------------------
# 5.2 (10, 13): masking
# --------------------------------------------------------------------------

class Masking(_Home):

    def _chmod(self, paths):
        if not WINDOWS:
            for path in paths:
                os.chmod(path, 0o640)

    def _backups(self):
        return [os.path.join(d, f) for d, _s, files in os.walk(self.backups)
                for f in files]

    def _no_encoding_left(self, data, value):
        text = data.decode("utf-8")
        self.assertEqual([f for f in _rewrite.encodings(value) if f in text], [])
        self.assertNotIn(_byte_list(value)[1:-1], text)

    def test_round_trip(self):
        marker = _marker(SECRET)
        masked = OUTPUT.replace(SECRET, marker)
        folder = self.session(updates=sample_updates(), chat=sample_chat())
        stores = self.stores()
        paths = [s.path for s in stores]
        self._chmod(paths)
        original = {p: _read(p) for p in paths}
        before = {s.path: [call_key(c) for c in self.src.tool_calls(s)] for s in stores}

        results = {s.path: self.src.mask(s, [SECRET]) for s in stores}

        updates = os.path.join(folder, "updates.jsonl")
        chat = os.path.join(folder, "chat_history.jsonl")
        summary = os.path.join(folder, "summary.json")
        expected = {
            # total_bytes keeps its old number (7.7)
            updates: "".join(l + "\n" for l in sample_updates(
                masked, total=len(OUTPUT.encode("utf-8")))).encode("utf-8"),
            chat: "".join(l + "\n" for l in sample_chat(masked)).encode("utf-8"),
            summary: original[summary],
        }
        for path in paths:
            self.assertEqual(_read(path), expected[path], path)
            self._no_encoding_left(_read(path), SECRET)
        self.assertEqual(results[summary], MaskResult(summary))
        for path in (updates, chat):
            result = results[path]
            self.assertEqual((result.changed, result.skipped), (True, None))
            self.assertEqual(_read(result.backup), original[path])
            if not WINDOWS:
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
                self.assertEqual(stat.S_IMODE(os.stat(result.backup).st_mode), 0o600)
        self.assertEqual(len(self._backups()), 2)
        self.assertTrue(all(b.startswith(self.backups) for b in self._backups()))

        # still parses, the byte array is valid UTF-8 holding the marker,
        # and the adapter yields the same calls
        for raw in _read(updates).decode("utf-8").splitlines():
            json.loads(raw)
        out = json.loads(_read(updates).decode("utf-8").split("\n")[3])
        out = out["params"]["update"]["rawOutput"]
        self.assertEqual(bytes(out["output"]).decode("utf-8", "strict"), masked)
        self.assertEqual(out["output_for_prompt"], masked)
        self.src.reset()
        after = {s.path: [call_key(c) for c in self.src.tool_calls(s)] for s in self.stores()}
        self.assertEqual(after, before)
        self.assertEqual(secrets(self.src, self.stores()), {})

        # a second run changes nothing
        for store in self.stores():
            self.assertEqual(self.src.mask(store, [SECRET]), MaskResult(store.path))
        for path in paths:
            self.assertEqual(_read(path), expected[path])
        self.assertEqual(len(self._backups()), 2)

    def test_a_key_only_in_the_byte_array_is_masked(self):
        text = "KEY=%s\n" % ONLY_BYTES
        out = bash_output(text, "cat .env.local", prompt=False)
        lines = [envelope(1790000100, tool_call("b1", "run_terminal_cmd",
                                                {"command": "cat .env.local"},
                                                kind="execute"), "e1"),
                 envelope(1790000101, finished("b1", out), "e2")]
        folder = self.session(updates=lines)
        store = self.store(folder)
        original = _read(store.path)
        result = self.src.mask(store, [ONLY_BYTES])
        self.assertTrue(result.changed, result)
        data = _read(store.path)
        self._no_encoding_left(data, ONLY_BYTES)
        last = json.loads(data.decode("utf-8").splitlines()[1])
        raw = last["params"]["update"]["rawOutput"]
        self.assertEqual(bytes(raw["output"]).decode("utf-8", "strict"),
                         "KEY=%s\n" % _marker(ONLY_BYTES))
        self.assertEqual(raw["total_bytes"], len(text.encode("utf-8")))
        self.assertEqual(_read(result.backup), original)
        # every other byte is as it was
        want = original.decode("utf-8").replace(
            _byte_list(ONLY_BYTES)[1:-1], _byte_list(_marker(ONLY_BYTES))[1:-1])
        self.assertEqual(data.decode("utf-8"), want)

    def test_nested_json_arguments_still_parse(self):
        command = "export GH=%s; git push" % TYPED
        folder = self.session(chat=[line({"type": "assistant", "content": "",
                                          "tool_calls": [{"id": "n1", "name": "run_terminal_cmd",
                                                          "arguments": json.dumps({"command": command})}],
                                          "model_id": "grok-build-0.1"})])
        store = self.store(folder, "chat_history.jsonl")
        result = self.src.mask(store, [TYPED])
        self.assertTrue(result.changed, result)
        item = json.loads(_read(store.path))
        inner = json.loads(item["tool_calls"][0]["arguments"])
        self.assertEqual(inner, {"command": command.replace(TYPED, _marker(TYPED))})

    def test_a_spaced_byte_array_is_refused_not_half_masked(self):
        out = bash_output(OUTPUT, "cat .env")
        lines = [json.dumps(envelope(1790000100, tool_call(
                     "s1", "run_terminal_cmd", {"command": "cat .env"}, kind="execute"), "e1")),
                 json.dumps(envelope(1790000101, finished("s1", out), "e2"))]
        folder = self.session(updates=lines)
        store = self.store(folder)
        digest = _sha(store.path)
        result = self.src.mask(store, [SECRET])
        self.assertEqual((result.changed, result.skipped),
                         (False, "would alter more than the secret"))
        self.assertEqual(_sha(store.path), digest)
        self.assertEqual(self._backups(), [])

    def test_a_file_written_in_the_last_two_minutes_is_in_use(self):
        folder = self.session(updates=sample_updates(), age=5)
        store = self.store(folder)
        digest = _sha(store.path)
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(store.path, skipped="in use"))
        self.assertEqual(_sha(store.path), digest)
        self.assertFalse(os.path.exists(self.backups))


# --------------------------------------------------------------------------
# 5.2 (12): files that do not parse
# --------------------------------------------------------------------------

class Unparsed(_Home):

    def _all(self):
        calls, texts = [], []
        for store in self.stores():
            calls += list(self.src.tool_calls(store))
            texts += list(self.src.secret_texts(store))
        return calls, texts

    def test_a_truncated_last_line_is_skipped_quietly(self):
        lines = sample_updates()
        folder = self.session(updates=lines)
        path = os.path.join(folder, "updates.jsonl")
        with open(path, "ab") as fh:
            fh.write(lines[1][:57].encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls, _texts = self._all()
        self.assertEqual(len(calls), 3)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_a_garbage_store_warns_once_and_the_others_still_read(self):
        good = self.session(updates=sample_updates())
        self.session(updates=None, sid="0199b6c0-0000-0000-0000-0000000000ff",
                     summary=None, extra={"updates.jsonl": b"\x00\xff\xfe garbage\n" * 40})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls, _texts = self._all()
            self._all()
        self.assertEqual(err.getvalue().count("warning:"), 1, err.getvalue())
        self.assertIn("not JSON Lines", err.getvalue())
        self.assertEqual({c.store for c in calls}, {os.path.join(good, "updates.jsonl")})
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(self.src.counts["unparsed"], 40, "counted once, not per pass")

    def test_a_bad_line_in_the_middle_is_counted(self):
        lines = sample_updates()
        folder = self.session(updates=lines[:4] + ["{not json"] + lines[4:])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(len(self.calls(folder)), 3)
            list(self.src.secret_texts(self.store(folder)))
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_unknown_records_are_ignored(self):
        lines = sample_updates() + [
            line([1, 2, 3]),
            line({"timestamp": 1790000009, "method": "session/update",
                  "params": {"sessionId": SID, "update": {
                      "sessionUpdate": "turn_completed", "modelUsage": {}}}}),
            line({"timestamp": 1790000010, "method": "session/update",
                  "params": {"sessionId": SID, "update": {
                      "sessionUpdate": "some_future_update", "x": 1}}}),
            line({"timestamp": 1790000011, "method": "session/update", "params": 7}),
        ]
        chat = sample_chat() + [line({"type": "some_future_item", "x": 1}),
                                line({"type": "backend_tool_call", "name": "web_search"})]
        folder = self.session(updates=lines, chat=chat)
        self.assertEqual(len(self.calls(folder)), 3)
        list(self.src.secret_texts(self.store(folder, "chat_history.jsonl")))
        self.assertEqual(self.src.counts["unknown"], 3)

    def test_a_summary_that_does_not_parse(self):
        folder = self.session(updates=sample_updates(), summary='{"info": {"id": ')
        store = self.store(folder)
        self.assertEqual((store.session, store.project), (SID, None))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.secret_texts(self.store(folder, "summary.json"))), [])
            self.assertEqual(list(self.src.secret_texts(self.store(folder, "summary.json"))), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)

    def test_a_store_gone_since_discovery_warns_once(self):
        folder = self.session(updates=sample_updates())
        store = self.store(folder)
        os.remove(store.path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)

    def test_bytes_that_are_not_utf8_survive(self):
        lines = shell_lines("u1", "ls", 1790000100, output="ok\n")
        folder = self.session(updates=lines)
        path = os.path.join(folder, "updates.jsonl")
        data = _read(path).replace(b'"Run it"', b'"Run \xff it"')
        with open(path, "wb") as fh:
            fh.write(data)
        [call] = self.calls(folder)
        self.assertEqual(call.tool_input["description"], "Run \udcff it")


# --------------------------------------------------------------------------
# JSON nested deeper than Python's stack
# --------------------------------------------------------------------------

# Past Python's recursion limit. Python 3.9's parser gives up on both; 3.14's
# guards the C stack instead and reads them, so what reads the value next
# must not recurse either.
DEPTHS = [(depth, shape) for depth in (1500, 100000) for shape in ("list", "dict")]


def deep(depth, shape):
    """JSON text nested `depth` levels, built as text: building it as a
    value would need the recursion under test."""
    if shape == "list":
        return "[" * depth + "]" * depth
    return '{"a":' * depth + "1" + "}" * depth


def holding(obj, text):
    """One line: obj with its "@DEEP@" string replaced by the JSON `text`."""
    return line(obj).replace('"@DEEP@"', text)


def parses(text):
    try:
        json.loads(text)
    except RecursionError:
        return False
    return True


class DeepNesting(_Home):
    """A line, or a value in one, nested past the stack never stops the
    store: the calls and keys around it are still read."""

    GOOD = "rm -rf ~/Documents/a"

    def _fresh(self):
        shutil.rmtree(os.path.join(self.root, "sessions"), True)
        self.src.reset()

    def _good(self):
        return shell_lines("good", self.GOOD, 1790000100, output=OUTPUT)

    def _read(self, folder, name="updates.jsonl"):
        """{call id: call} of one store, each call judged as watch judges
        it. Nothing may escape and nothing is warned about, and the good
        call and its key are still found."""
        store = self.store(folder, name)
        found = set()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = {c.tool_call_id: c for c in self.src.tool_calls(store)}
            for call in calls.values():
                judge(call)
            for text in self.src.secret_texts(store):
                clean._walk(text.node, lambda value, *_: found.add(value))
        self.assertEqual(err.getvalue(), "")
        self.assertTrue(judge(calls["good"])[0])
        self.assertIn(SECRET, found)
        return calls

    def test_a_line_nested_past_the_stack_is_counted_and_the_rest_read(self):
        for depth, shape in DEPTHS:
            with self.subTest(depth=depth, shape=shape):
                self._fresh()
                text = deep(depth, shape)
                calls = self._read(self.session(updates=[text] + self._good()))
                self.assertEqual(sorted(calls), ["good"])
                # unparsed where the parser gives up, else a line of no known shape
                self.assertEqual(self.src.counts["unparsed"], 0 if parses(text) else 1)
                self.assertEqual(self.src.counts["unparsed"] + self.src.counts["unknown"], 1)

    def test_a_value_nested_past_the_stack_leaves_its_call_and_the_others(self):
        t = 1790000000
        sites = {
            "rawInput": {"sessionUpdate": "tool_call_update", "toolCallId": "odd",
                         "rawInput": {"command": "ls", "x": "@DEEP@"}},
            "x.ai/tool input": {"sessionUpdate": "tool_call_update", "toolCallId": "odd",
                                "_meta": {XAI: xai_tool("run_terminal_cmd", "execute",
                                                        {"command": "ls", "x": "@DEEP@"})}},
            "Bash byte array": finished("odd", {"type": "Bash", "output": "@DEEP@"}),
            "content": finished("odd", content="@DEEP@"),
            "rawOutput": finished("odd", "@DEEP@"),
            "_meta": {"sessionUpdate": "tool_call_update", "toolCallId": "odd",
                      "_meta": "@DEEP@"},
        }
        first = envelope(t, tool_call("odd", "run_terminal_cmd", {"command": "ls"},
                                      kind="execute"), "e-odd-1", t * 1000)
        for depth, shape in DEPTHS:
            for site, update in sites.items():
                with self.subTest(depth=depth, shape=shape, site=site):
                    self._fresh()
                    odd = holding(envelope(t + 1, update, "e-odd-2"), deep(depth, shape))
                    calls = self._read(self.session(updates=[first, odd] + self._good()))
                    self.assertEqual(sorted(calls), ["good", "odd"])
                    self.assertEqual(self.src.counts["unparsed"], 0 if parses(odd) else 1)

    def test_arguments_nested_past_the_stack_are_kept_as_written(self):
        t = 1790000000
        for depth, shape in DEPTHS:
            text = deep(depth, shape)
            for raw in (text, '{"command":"rm -rf ~/Documents/b","x":%s}' % text):
                with self.subTest(depth=depth, shape=shape, whole=raw is text):
                    self._fresh()
                    folder = self.session(updates=[envelope(
                        t, tool_call("odd", "run_terminal_cmd", raw, kind="execute"),
                        "e-odd-1", t * 1000)] + self._good())
                    calls = self._read(folder)
                    self.assertEqual(sorted(calls), ["good", "odd"])
                    if not parses(raw):
                        self.assertEqual(calls["odd"].tool_input, {"_raw": raw})
                    os.remove(os.path.join(folder, "updates.jsonl"))
                    self.session(chat=[
                        {"type": "assistant", "content": "", "tool_calls": [
                            {"id": "odd", "name": "run_terminal_cmd", "arguments": raw},
                            {"id": "good", "name": "run_terminal_cmd",
                             "arguments": json.dumps({"command": self.GOOD})}]},
                        {"type": "tool_result", "tool_call_id": "good",
                         "content": OUTPUT}])
                    calls = self._read(folder, "chat_history.jsonl")
                    self.assertEqual(sorted(calls), ["good", "odd"])

    def test_a_summary_nested_past_the_stack_is_not_json_and_the_session_still_read(self):
        for depth, shape in DEPTHS:
            with self.subTest(depth=depth, shape=shape):
                self._fresh()
                text = deep(depth, shape)
                folder = self.session(updates=self._good(), summary=text)
                store = self.store(folder)
                self.assertEqual((store.session, store.project), (SID, None))
                self._read(folder)
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    texts = list(self.src.secret_texts(self.store(folder, "summary.json")))
                self.assertEqual(len(texts), 1 if parses(text) else 0)
                self.assertEqual(err.getvalue().count("(not JSON)"), 0 if texts else 1)

    def test_masking_beside_a_line_nested_past_the_stack_never_raises(self):
        for depth, shape in DEPTHS:
            with self.subTest(depth=depth, shape=shape):
                self._fresh()
                text = deep(depth, shape)
                store = self.store(self.session(updates=[text] + self._good()))
                result = self.src.mask(store, [SECRET])
                self.assertIsInstance(result, MaskResult)
                data = _read(store.path)
                self.assertTrue(data.startswith(text.encode("utf-8") + b"\n"))
                if result.changed:
                    self.assertNotIn(SECRET.encode("utf-8"), data)


# --------------------------------------------------------------------------
# 5.2 (14): the --days window
# --------------------------------------------------------------------------

class Window(_Home):

    def test_an_old_call_in_a_recent_store_is_outside(self):
        now = time.time()
        old = int(now - 400 * 86400)
        new = int(now - 3600)
        folder = self.session(updates=shell_lines("old", "rm -rf ~/Documents/a", old)
                              + shell_lines("new", "rm -rf ~/Documents/b", new), age=60)
        self.assertEqual(len(self.src.stores(self.src.locations(), since_days=30)), 2)
        calls = self.calls(folder)
        self.assertEqual([c.tool_call_id for c in calls if in_window(c, 30, now)], ["new"])

    def test_an_undated_call_is_kept_unless_its_store_is_older(self):
        now = time.time()
        recent = self.session(chat=sample_chat(), age=3600)
        stale = self.session(chat=sample_chat(), sid="0199b6c0-0000-0000-0000-0000000000dd",
                             age=90 * 86400)
        [kept] = self.calls(recent, "chat_history.jsonl")
        [dropped] = self.calls(stale, "chat_history.jsonl")
        self.assertIsNone(kept.timestamp)
        self.assertTrue(in_window(kept, 30, now))
        self.assertFalse(in_window(dropped, 30, now))


# --------------------------------------------------------------------------
# Timing: how reading a large session grows, on its own interpreter
# (tests/growth.py)
# --------------------------------------------------------------------------

_CALL = r"""
from ranwhat.sources.grok import GrokBuildSource
def call(root):
    src = GrokBuildSource()
    stores = src.stores(src.locations(override=root))
    calls = texts = 0
    for store in stores:
        calls += sum(1 for _ in src.tool_calls(store))
        texts += sum(1 for _ in src.secret_texts(store))
    return {"stores": len(stores), "calls": calls, "texts": texts}
"""


class Timing(unittest.TestCase):

    CALLS = 2000        # about 57 MB at full size

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="grok-timing-")
        self.addCleanup(shutil.rmtree, self.home, True)

    def session(self, n):
        """A Grok home whose one session ran n(CALLS) commands and reads."""
        root = os.path.join(tempfile.mkdtemp(dir=self.home), ".grok")
        folder = os.path.join(root, "sessions", ENC, SID)
        os.makedirs(folder)
        chunk = line(envelope(1790000000, {"sessionUpdate": "agent_message_chunk",
                                           "content": {"type": "text",
                                                       "text": "word " * 40}}, "c"))
        output = ("x" * 79 + "\n") * 40
        with open(os.path.join(folder, "updates.jsonl"), "w", encoding="utf-8") as fh:
            for i in range(n(self.CALLS)):
                for _ in range(5):
                    fh.write(chunk + "\n")
                for obj in shell_lines("c%d" % i, "cat f%d.txt" % i, 1790000000 + i,
                                       output=output):
                    fh.write(line(obj) + "\n")
                for obj in read_lines("r%d" % i, "src/f%d.ts" % i, 1790000000 + i,
                                      content=output):
                    fh.write(line(obj) + "\n")
        with open(os.path.join(folder, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump({"info": {"id": SID, "cwd": CWD}}, fh)
        return root

    def test_a_large_session_reads_in_bounded_time(self):
        env = dict(os.environ, HOME=self.home, USERPROFILE=self.home)
        env.pop("GROK_HOME", None)
        measured, root = growth.measure_apart(self.session, _CALL, env=env)
        size = os.path.getsize(os.path.join(root, "sessions", ENC, SID,
                                            "updates.jsonl"))
        self.assertGreater(size, 30 * 1024 * 1024)
        growth.assert_linear(self, measured, "a %d MB session" % (size // 10 ** 6))
        result = measured.result
        self.assertEqual((result["stores"], result["calls"]), (2, 2 * self.CALLS))


if __name__ == "__main__":
    unittest.main()
