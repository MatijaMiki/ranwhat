"""The Factory Droid adapter (ranwhat/sources/droid.py, design 7.10).

Fixtures are built field for field from the spec's sample: a session_start
line, then message lines whose content blocks are Anthropic-style tool_use
and tool_result. Fields the spec marks unverified are left out. Where the
spec is silent or wrong, the shape comes from the writer in the official
0.231.0 binary, named beside each builder: Execute's capped result and the
terminal log it names, a background Execute's result and the droid-bg
output it names, the 40,000-character spill of other tools, bash mode's
bash_result messages, agent_turn_outcome lines and the prompt history.

Everything runs in temp directories: the home directory, Droid's own
FACTORY_HOME_OVERRIDE and clean's backup root all point there, and the real
home is never read. Every secret is synthetic, and token-shaped ones are
written as adjacent literals.

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
from ranwhat import clean, sources, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite  # noqa: E402
from ranwhat.sources import droid as droid_module  # noqa: E402
from ranwhat.sources.base import MaskResult, ToolCall  # noqa: E402
from ranwhat.sources.droid import DroidSource, output_text  # noqa: E402

ENV = "FACTORY_HOME_OVERRIDE"
WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
TYPED = "Hq3nV8xKp2" "Lw7RtY9mZc4BfD"           # an API_TOKEN typed by hand
SPEC_VALUE = "not-a-real-secret"                # the spec sample's value

SID = "6f0c2b1e-8d3a-4f5b-9c7d-1e2f3a4b5c6d"
EXIT_0 = "\n\n[Process exited with code 0]"
EXIT_1 = "\n\n[Process exited with code 1]"

# A terminal id (pH(): a v4-shaped UUID) and the folder mkdtemp made for it.
TERMINAL_ID = "8b6f0c1e-4c2d-4e5f-9a0b-1c2d3e4f5a6b"
TERMINAL_DIR = "droid-terminal-AbC123"

# A background process's output file is named after Date.now() when it
# started: 13 digits.
BG_STAMP = 1790888580523
DEV_WARNING = "Dev servers should use appropriate process managers"


# --------------------------------------------------------------------------
# Fixture builders: the spec's records, compact like Droid writes them
# --------------------------------------------------------------------------

def _dump(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def header(sid=SID, cwd="/Users/me/proj", title="Inspect env", legacy=False):
    line = {"type": "session_start", "id": sid}
    line["sessionTitle" if legacy else "title"] = title
    line.update({"owner": "me@example.com", "version": 2})
    if cwd is not None:
        line["cwd"] = cwd
    if sid is None:
        del line["id"]
    return line


def message(n, role, content, ts="2026-09-30T10:00:00.000Z", parent=None):
    line = {"type": "message", "id": "0a1b2c3d-0000-4000-8000-%012d" % n}
    if ts is not None:
        line["timestamp"] = ts
    line["message"] = {"role": role, "content": content}
    if parent:
        line["parentId"] = "0a1b2c3d-0000-4000-8000-%012d" % parent
    return line


def use(cid, name, tool_input):
    return {"type": "tool_use", "id": cid, "name": name, "input": tool_input}


def result(cid, content, is_error=None):
    block = {"type": "tool_result", "tool_use_id": cid}
    if is_error is not None:
        block["is_error"] = is_error
    block["content"] = content
    return block


def call_lines(n, cid, name, tool_input, output=None, ts=None, is_error=None):
    """An assistant tool_use line and, when output is given, the user line
    holding its result: the two lines the spec's sample shows."""
    ts = ts or "2026-09-30T10:%02d:%02d.000Z" % (n // 60 % 60, n % 60)
    lines = [message(n, "assistant", [use(cid, name, tool_input)], ts=ts)]
    if output is not None:
        lines.append(message(n + 1, "user", [result(cid, output, is_error)],
                             ts=ts, parent=n))
    return lines


def size_label(n):
    """The size Execute prints after the path: Lu() in the binary."""
    if n >= 1048576:
        return "%.1fMB" % (n / 1048576)
    return "%dKB" % max(1, int(n / 1024 + 0.5))


def execute_summary(full):
    """What Execute keeps of an output over 16,384 bytes: readSummaryOutput()
    in the binary. 8 KiB of head; 8 KiB of tail less its partial first line;
    the notice counts the bytes neither read."""
    data = full.encode("utf-8")
    head, tail = data[:8192], data[-8192:]
    hidden = len(data) - len(head) - len(tail)
    tail = tail.decode("utf-8")
    cut = tail.find("\n")
    if cut >= 0:
        tail = tail[cut + 1:]
    return ("%s\n\n[... truncated %d bytes from middle section ...]\n\n%s"
            % (head.decode("utf-8"), hidden, tail))


def execute_result(full, log, exit_code=0):
    """Execute's whole result for a long output: the summary (after the
    failure line when it failed), the notice naming the log that holds all
    of it, and the exit marker, as executeCommandWithStreaming() builds
    them."""
    text = execute_summary(full)
    if exit_code:
        text = "Command failed (exit code: %d)\n%s" % (exit_code, text)
    size = size_label(len(full.encode("utf-8")))
    return (text + "\n\nFull command output saved to: %s (%s)" % (log, size)
            + "\n\n[Process exited with code %d]" % exit_code)


def background_result(path, command="npm run dev", pid=4242, completed=False,
                      warning=None, wake=False):
    """A background Execute's result: what ExecuteCli.execute() yields for
    fireAndForget. "PID: <pid>" ("PID: unknown" without one); the Output
    line only when the executor named a file; then the status, and for a
    process still running, its warning (npm run dev, manage.py runserver
    and node get one) and how its end is reported."""
    who = "PID: %s" % (pid or "unknown")
    out = "\nOutput: %s" % path if path else ""
    if completed:
        return ("Background process completed (%s)\nCommand: %s%s\n"
                "Status: Completed successfully" % (who, command, out))
    end = ("The command's result will be delivered automatically when it "
           "finishes." if wake else "Note: Process will continue after CLI "
           "exits. Use 'ps' or 'kill' commands to manage.")
    return ("Background process started (%s)\nCommand: %s%s\n"
            "Status: Running in background%s\n\n%s"
            % (who, command, out, "\nWarning: " + warning if warning else "", end))


def spilled(full, path, limit=40000):
    """A Grep, LS, FetchUrl, ... result over 40,000 characters as the
    transcript keeps it: PN() and Hc() in the binary (75% head, 25% tail,
    then a system reminder naming the file; its closing advice is left
    out here)."""
    def short(n):
        return "%dk" % (n // 1000) if n >= 1000 else "%d" % n
    head_n = limit * 3 // 4
    tail_n = limit - head_n
    head, tail = full[:head_n], full[len(full) - tail_n:]
    return (
        "%s\n\n[... truncated %d characters from middle section ...]\n\n%s\n\n"
        "[Output truncated. Showing first %s characters (%d lines) and last %s "
        "characters (%d lines) out of %s total characters (%d lines)]"
        % (head, len(full) - limit, tail, short(head_n), head.count("\n") + 1,
           short(tail_n), tail.count("\n") + 1, short(len(full)),
           full.count("\n") + 1)
        + "\n\n<system-reminder>\nThis output was truncated. The full result "
          "is saved to %s.\n</system-reminder>" % path)


def bash_result(command, stdout="", stderr="", exit_code=0):
    """The text of a bash mode message: IU() in the binary, JSON.stringify
    of {type, command, stdout, stderr, exitCode}."""
    return _dump({"type": "bash_result", "command": command, "stdout": stdout,
                  "stderr": stderr, "exitCode": exit_code})


def user_shell(n, command, stdout="", stderr="", exit_code=0,
               ts="2026-09-30T10:00:00.000Z"):
    """The user message a bash mode command is stored as: one text block
    (runResolvedUserMessage() with skipAgentLoop)."""
    return message(n, "user", [{"type": "text", "text": bash_result(
        command, stdout, stderr, exit_code)}], ts=ts)


def turn_outcome(turn, kind="text", result=None):
    """An agent_turn_outcome line (its zod schema in the binary)."""
    line = {"type": "agent_turn_outcome", "turnId": turn, "reason": "completed",
            "resultKind": kind}
    if kind == "structured":
        line["result"] = result
        line["schemaFingerprint"] = "sha256:4f1c"
    return line


def prompt(command, when="2026-09-30T10:00:00.000Z", kind="message",
           mode="chat"):
    """One prompt history entry: addCommand() in the binary, its timestamp
    a Date that JSON.stringify writes as an ISO string. kind is
    "message", "slash_command" or "bash_command"; mode "chat" or "bash"."""
    return {"command": command, "timestamp": when, "type": kind, "mode": mode}


def history_file(entries):
    """A prompt history file: JSON.stringify(history, null, 2)."""
    return json.dumps(entries, indent=2, ensure_ascii=False).encode("utf-8")


def spec_sample():
    """The four lines of the spec's fixture, as written there."""
    return [
        header(),
        message(1, "user", [{"type": "text", "text": "print the env file"}],
                ts="2026-09-30T10:00:00.000Z"),
        message(2, "assistant",
                [use("toolu_01ABC", "Execute", {"command": "cat .env"})],
                ts="2026-09-30T10:00:02.000Z", parent=1),
        message(3, "user",
                [result("toolu_01ABC", "EXAMPLE_TOKEN=" + SPEC_VALUE + EXIT_0)],
                ts="2026-09-30T10:00:03.000Z", parent=2),
    ]


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
                entry = found.setdefault(value, {"origins": set(), "count": 0,
                                                 "stores": set(), "where": []})
                entry["count"] += 1
                entry["stores"].add(store.path)
                entry["where"].append(text.where)
                if origin:
                    entry["origins"].add(origin)
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

class DroidCase(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "droid-home-")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ENV, None)
        self.backups = os.path.join(_tempdir(self, "droid-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.root = os.path.join(self.home, ".factory")
        # stands in for the OS temp folder Droid's terminal logs go to
        self.tmp = _tempdir(self, "droid-tmp-")
        self.droid = DroidSource()

    def terminal_log(self, text, terminal_id=TERMINAL_ID, folder=TERMINAL_DIR,
                     age=3600):
        """A terminal log as Execute leaves it: <temp>/droid-terminal-*/
        <terminal id>.log, the folder 0700 and the file 0600."""
        return self.write("%s/%s.log" % (folder, terminal_id), None,
                          raw=text.encode("utf-8"), root=self.tmp, mode=0o600,
                          age=age)

    def background_output(self, text, stamp=BG_STAMP, age=3600):
        """A background process's output as Droid leaves it: the shell's
        redirect target <temp>/droid-bg-<Date.now()>.out."""
        return self.write("droid-bg-%d.out" % stamp, None,
                          raw=text.encode("utf-8"), root=self.tmp, age=age)

    def write(self, rel, lines, age=3600, root=None, mode=None, raw=None):
        """Write JSON lines (or raw bytes) at root/rel, aged `age` seconds."""
        path = os.path.join(root or self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        data = raw if raw is not None else "".join(
            _dump(line) + "\n" for line in lines).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
        if mode is not None and not WINDOWS:
            os.chmod(path, mode)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def session(self, lines, name=SID, folder="-Users-me-proj", **kw):
        rel = "sessions/%s%s.jsonl" % (folder + "/" if folder else "", name)
        return self.write(rel, lines, **kw)

    def stores(self, override=None, since_days=None):
        return self.droid.stores(self.droid.locations(override=override),
                                 since_days=since_days)

    def store(self, path):
        for store in self.stores():
            if store.path == path:
                return store
        self.fail("%s is not a store" % path)

    def calls(self, path):
        return list(self.droid.tool_calls(self.store(path)))

    def by_id(self, path):
        return {c.tool_call_id: c for c in self.calls(path)}


# --------------------------------------------------------------------------
# 1, 2, 3: where Droid keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        d = DroidSource()
        self.assertEqual(d.default_paths({}, "/Users/u", "darwin"), [
            ("/Users/u/.factory", "default"),
            ("/Users/u/.factory-dev", "probed")])
        self.assertEqual(d.default_paths({}, "/home/u", "linux"), [
            ("/home/u/.factory", "default"),
            ("/home/u/.factory-dev", "probed")])
        self.assertEqual(d.default_paths({}, "C:\\Users\\u", "win32"), [
            ("C:\\Users\\u\\.factory", "default"),
            ("C:\\Users\\u\\.factory-dev", "probed")])

    def test_override_replaces_the_home_directory(self):
        d = DroidSource()
        how = "env FACTORY_HOME_OVERRIDE"
        self.assertEqual(d.default_paths({ENV: "/srv/fh"}, "/home/u", "linux"), [
            ("/srv/fh/.factory", how), ("/srv/fh/.factory-dev", how)])
        self.assertEqual(d.default_paths({ENV: "/srv/fh"}, "/Users/u", "darwin"), [
            ("/srv/fh/.factory", how), ("/srv/fh/.factory-dev", how)])
        self.assertEqual(
            d.default_paths({ENV: "D:\\fh"}, "C:\\Users\\u", "win32"), [
                ("D:\\fh\\.factory", how), ("D:\\fh\\.factory-dev", how)])

    def test_an_empty_override_is_not_set(self):
        self.assertEqual(DroidSource().default_paths({ENV: ""}, "/home/u", "linux"),
                         [("/home/u/.factory", "default"),
                          ("/home/u/.factory-dev", "probed")])

    def test_what_every_report_needs(self):
        d = DroidSource()
        self.assertEqual((d.id, d.name, d.unit, d.env), (
            "droid", "Droid", "session", ("FACTORY_HOME_OVERRIDE",)))
        self.assertIn(".factory", d.path_means)
        self.assertEqual(d.checked, "0.231.0")
        self.assertIn("cloudSessionSync", d.mask_note)
        # design 3.7: Droid rewrites its prompt history from memory
        self.assertIn("If Droid is running, close it first", d.mask_note)
        self.assertNotIn("\u2014", d.path_means + d.mask_note)
        # wired into the registry (ranwhat.sources.ADAPTERS)
        self.assertIn("droid", sources.ids())
        self.assertIsInstance(sources.get("droid"), DroidSource)


class Discovery(DroidCase):

    def test_override_is_read_at_call_time(self):
        first = self.droid.locations()
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in first], [
            (self.root, "default", False, 0),
            (os.path.join(self.home, ".factory-dev"), "probed", False, 0)])
        moved = _tempdir(self, "droid-moved-")
        path = self.session(spec_sample(), root=os.path.join(moved, ".factory"))
        os.environ[ENV] = moved             # after import and construction
        locs = self.droid.locations()
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in locs], [
            (os.path.join(moved, ".factory"), "env " + ENV, True, 1),
            (os.path.join(moved, ".factory-dev"), "env " + ENV, False, 0)])
        self.assertEqual([s.path for s in self.droid.stores(locs)], [path])

    def test_every_layout_is_found_newest_first(self):
        legacy = self.session(spec_sample(), name="11111111-aaaa-4aaa-8aaa-000000000001",
                              folder="", age=500)
        project = self.session(spec_sample(), age=400)
        fork = self.session(spec_sample(), name="22222222-bbbb-4bbb-8bbb-000000000002",
                            folder="btw", age=300)
        windows = self.session(
            [header(sid="33333333-cccc-4ccc-8ccc-000000000003",
                    cwd="C:\\Users\\me\\proj")],
            name="33333333-cccc-4ccc-8ccc-000000000003",
            folder="-C-Users-me-proj", age=200)
        # a command's whole output in the temp folder, named by its result
        full = "build line\n" * 3000
        terminal = self.terminal_log(full, age=130)
        long = self.session(
            [header(sid="55555555-eeee-4eee-8eee-000000000005")] + call_lines(
                10, "toolu_01LONG", "Execute", {"command": "make"},
                output=execute_result(full, terminal)),
            name="55555555-eeee-4eee-8eee-000000000005", age=120)
        log = self.write("artifacts/tool-outputs/grep_tool_cli-toolu_01ABC-90012345.log",
                         None, raw=b"big output\n", age=100)
        history = self.write("state/history.json", None, age=50,
                             raw=history_file([prompt("hi")]))
        old_history = self.write("history.json", None, age=40, raw=b"[]")
        # not stores
        self.write("sessions/-Users-me-proj/%s.settings.json" % SID, None, raw=b"{}")
        self.write("sessions/.favorites", None, raw=b"[]")
        self.write("sessions/-Users-me-proj/.hidden.jsonl", [header()])
        self.write("sessions/elsewhere/x.jsonl", [header()])
        self.write("cache/session-index/index.db", None, raw=b"SQLite format 3\0")
        self.write("cache/session-discovery-index.json", None, raw=b"{}")
        self.write("logs/droid.log", None, raw=b"log\n")
        self.write("settings.json", None, raw=b"{}")
        self.write("artifacts/tool-outputs/notes.txt", None, raw=b"x\n")

        found = self.stores()
        self.assertEqual([s.path for s in found],
                         [old_history, history, log, long, terminal, windows,
                          fork, project, legacy])
        shape = {s.path: (s.format, s.role, s.unit, s.masking) for s in found}
        for path in (legacy, project, fork, windows, long):
            self.assertEqual(shape[path], ("jsonl", "transcript", "session", "rewrite"))
        self.assertEqual(shape[log], ("text", "side", "tool output", "rewrite"))
        self.assertEqual(shape[terminal], ("text", "side", "command output", "rewrite"))
        self.assertEqual(shape[history], ("json", "side", "prompt history", "rewrite"))
        self.assertEqual(shape[old_history], ("json", "side", "prompt history", "rewrite"))
        # a command's log belongs to the session that ran it
        got = {s.path: (s.session, s.project) for s in found}
        self.assertEqual(got[terminal], ("55555555-eeee-4eee-8eee-000000000005",
                                         "/Users/me/proj"))
        self.assertEqual(self.droid.locations()[0].found, 9)

    def test_session_and_project_of_a_store(self):
        project = self.session(spec_sample())
        windows = self.session(
            [header(sid="33333333-cccc-4ccc-8ccc-000000000003",
                    cwd="C:\\Users\\me\\proj")],
            name="33333333-cccc-4ccc-8ccc-000000000003", folder="-C-Users-me-proj")
        # no id and no cwd: the stem is the session, the folder name is not
        # turned back into a path
        bare = self.session([header(sid=None, cwd=None, legacy=True)],
                            name="44444444-dddd-4ddd-8ddd-000000000004",
                            folder="-Users-me-other")
        got = {s.path: (s.session, s.project) for s in self.stores()}
        self.assertEqual(got[project], (SID, "/Users/me/proj"))
        self.assertEqual(got[windows], ("33333333-cccc-4ccc-8ccc-000000000003",
                                        "C:\\Users\\me\\proj"))
        self.assertEqual(got[bare], ("44444444-dddd-4ddd-8ddd-000000000004", None))

    def test_development_builds_are_probed(self):
        dev = self.session(spec_sample(), root=os.path.join(self.home, ".factory-dev"))
        self.assertEqual([s.path for s in self.stores()], [dev])

    def test_path_means_a_folder_holding_factory(self):
        elsewhere = _tempdir(self, "droid-path-")
        path = self.session(spec_sample(), root=os.path.join(elsewhere, ".factory"))
        self.session(spec_sample())                  # the default: not read
        [loc] = self.droid.locations(override=elsewhere)
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (elsewhere, "--path", True, 1))
        self.assertEqual([s.path for s in self.stores(override=elsewhere)], [path])
        # pointing at the .factory folder itself works too
        direct = os.path.join(elsewhere, ".factory")
        self.assertEqual([s.path for s in self.stores(override=direct)], [path])

    def test_a_missing_root_is_zero_stores(self):
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.stores(override=os.path.join(self.home, "nope")), [])
        os.makedirs(os.path.join(self.root, "sessions"))
        self.assertEqual(self.stores(), [])

    def test_days_prefilter_by_last_write(self):
        new = self.session(spec_sample(), age=60)
        self.session(spec_sample(), name="55555555-eeee-4eee-8eee-000000000005",
                     age=90 * 86400)
        self.assertEqual([s.path for s in self.stores(since_days=30)], [new])

    def test_days_window_and_terminal_logs(self):
        full = "x\n" * 20000
        fresh = self.terminal_log(full, age=120)
        stale = self.terminal_log(full, terminal_id="9c7d1e2f-0000-4aaa-8bbb-000000000001",
                                  folder="droid-terminal-Old999", age=91 * 86400)
        recent = self.session([header()] + call_lines(
            10, "toolu_new", "Execute", {"command": "make"},
            output=execute_result(full, fresh)), age=60)
        old = self.session([header(sid="66666666-ffff-4fff-8fff-000000000006")]
                           + call_lines(10, "toolu_old", "Execute", {"command": "make"},
                                        output=execute_result(full, stale)),
                           name="66666666-ffff-4fff-8fff-000000000006", age=90 * 86400)
        self.assertEqual([s.path for s in self.stores(since_days=30)], [recent, fresh])
        self.assertEqual([s.path for s in self.stores()], [recent, fresh, old, stale])


# --------------------------------------------------------------------------
# Tool calls: kinds, outputs, time, dedupe
# --------------------------------------------------------------------------

class ToolCalls(DroidCase):

    def test_the_spec_sample(self):
        path = self.session(spec_sample())
        self.assertEqual(self.calls(path), [ToolCall(
            "droid", path, "Execute", {"command": "cat .env"}, kind="shell",
            known=True, session=SID, project="/Users/me/proj",
            timestamp="2026-09-30T10:00:02Z", tool_call_id="toolu_01ABC",
            command="cat .env", consumed=("command",),
            output="EXAMPLE_TOKEN=" + SPEC_VALUE + EXIT_0)])

    def test_every_tool_in_the_spec_maps_to_its_kind(self):
        rows = [
            ("t1", "Execute", {"command": "ls -la", "summary": "list",
                               "timeout": 60, "riskLevel": "low",
                               "riskLevelReason": "read only",
                               "fireAndForget": False},
             ("shell", True, "ls -la", (), {"command"})),
            ("t2", "Read", {"file_path": "/Users/me/proj/a.py", "offset": 1,
                            "limit": 20},
             ("read", True, None, ("/Users/me/proj/a.py",), {"file_path"})),
            ("t3", "Create", {"file_path": "/Users/me/proj/b.py", "content": "x"},
             ("write", True, None, ("/Users/me/proj/b.py",), set())),
            ("t4", "Edit", {"file_path": "/Users/me/proj/a.py", "old_str": "a",
                            "new_str": "b", "change_all": True},
             ("write", True, None, ("/Users/me/proj/a.py",), set())),
            # arguments the spec does not list are left out (5.1)
            ("t5", "MultiEdit", {}, ("write", True, None, (), set())),
            ("t6", "ApplyPatch", {}, ("write", True, None, (), set())),
            ("t7", "FetchUrl", {}, ("fetch", True, None, (), set())),
            ("t8", "WebSearch", {}, ("fetch", True, None, (), set())),
            ("t9", "LS", {}, ("other", True, None, (), set())),
            ("t10", "Glob", {}, ("other", True, None, (), set())),
            ("t11", "Grep", {}, ("other", True, None, (), set())),
            ("t12", "Task", {}, ("other", True, None, (), set())),
            ("t13", "TodoWrite", {}, ("other", True, None, (), set())),
            ("t14", "AskUser", {}, ("other", True, None, (), set())),
            # unverified (Script) or unknown: judged by name. Names match
            # exactly, so "execute" is not Execute.
            ("t15", "Script", {}, ("other", False, None, (), set())),
            ("t16", "mcp__srv__bash", {}, ("other", False, None, (), set())),
            ("t17", "execute", {}, ("other", False, None, (), set())),
        ]
        lines = [header()]
        for n, (cid, name, tool_input, _want) in enumerate(rows):
            lines += call_lines(10 + 2 * n, cid, name, tool_input, output="ok")
        path = self.session(lines)
        got = self.by_id(path)
        self.assertEqual(len(got), len(rows))
        for cid, name, tool_input, want in rows:
            call = got[cid]
            self.assertEqual((call.tool_name, call.tool_input), (name, tool_input))
            self.assertEqual((call.kind, call.known, call.command, call.paths,
                              set(call.consumed)), want, name)
            self.assertEqual(call.output, "ok")
            self.assertEqual((call.actor, call.status, call.workdir),
                             ("agent", None, None))

    def test_a_call_whose_command_or_path_is_missing(self):
        lines = [header()]
        lines += call_lines(10, "a", "Execute", {"summary": "nothing"})
        lines += call_lines(12, "b", "Read", {"offset": 3})
        lines += call_lines(14, "c", "Execute", {"command": ["rm", "-rf", "x"]})
        got = self.by_id(self.session(lines))
        for cid in "abc":
            self.assertEqual((got[cid].command, got[cid].paths, got[cid].consumed),
                             (None, (), frozenset()), cid)
            self.assertTrue(got[cid].known)

    def test_an_input_stored_as_a_json_string_is_decoded(self):
        lines = [header()] + call_lines(10, "a", "Execute", '{"command": "pwd"}')
        [call] = self.calls(self.session(lines))
        self.assertEqual((call.tool_input, call.command), ({"command": "pwd"}, "pwd"))

    def test_outputs_in_every_stored_shape(self):
        full = "".join("line %05d\n" % i for i in range(5000))
        long_out = execute_result(full, os.path.join(self.tmp, TERMINAL_DIR,
                                                     TERMINAL_ID + ".log"))
        spill = spilled("match\n" * 9000, os.path.join(
            self.root, "artifacts", "tool-outputs",
            "grep_tool_cli-grep-90012345.log"))
        lines = [header()]
        lines += call_lines(10, "ok", "Execute", {"command": "ls"},
                            output="a.py\nb.py" + EXIT_0)
        lines += call_lines(12, "fail", "Execute", {"command": "false"},
                            output="Command failed (exit code: 1)\nboom" + EXIT_1,
                            is_error=True)
        lines += call_lines(14, "blocks", "Read", {"file_path": "/p/x.png"},
                            output=[{"type": "text", "text": "first"},
                                    {"type": "image", "source": {
                                        "type": "base64", "media_type": "image/png",
                                        "data": "iVBORw0KGgo="}},
                                    {"type": "text", "text": "second"}])
        lines += call_lines(16, "image", "Read", {"file_path": "/p/y.png"},
                            output=[{"type": "image", "source": {
                                "type": "base64", "media_type": "image/png",
                                "data": "iVBORw0KGgo="}}])
        lines += call_lines(18, "long", "Execute", {"command": "big"}, output=long_out)
        lines += call_lines(20, "none", "Execute", {"command": "sleep 100"})
        lines += call_lines(22, "grep", "Grep", {}, output=spill)
        got = self.by_id(self.session(lines))
        self.assertEqual(got["ok"].output, "a.py\nb.py" + EXIT_0)
        self.assertEqual(got["fail"].output,
                         "Command failed (exit code: 1)\nboom" + EXIT_1)
        self.assertIsNone(got["fail"].status)          # an error is not "declined"
        self.assertEqual(got["blocks"].output, "first\nsecond")
        self.assertIsNone(got["image"].output)
        # Execute keeps at most 16 KiB of a command's output, well below the
        # 40,000-character spill
        self.assertEqual(got["long"].output, long_out)
        self.assertLess(len(long_out), 40000)
        self.assertIn("truncated %d bytes" % (len(full) - 16384), long_out)
        self.assertEqual(got["grep"].output, spill)
        self.assertIsNone(got["none"].output)
        self.assertEqual(output_text(None), None)
        self.assertEqual(output_text({"text": "x"}), None)

    def test_time_is_utc_and_an_undated_call_is_bounded_by_the_file(self):
        lines = [header()]
        lines += call_lines(10, "zulu", "Execute", {"command": "a"}, output="",
                            ts="2026-09-30T10:00:02.123Z")
        lines += call_lines(12, "zoned", "Execute", {"command": "b"}, output="",
                            ts="2026-09-30T12:00:02.000+02:00")
        lines.append(message(14, "assistant", [use("undated", "Execute",
                                                   {"command": "c"})], ts=None))
        path = self.session(lines, age=7200)
        got = self.by_id(path)
        self.assertEqual((got["zulu"].timestamp, got["zulu"].not_after),
                         ("2026-09-30T10:00:02Z", None))
        self.assertEqual(got["zoned"].timestamp, "2026-09-30T10:00:02Z")
        mtime = os.stat(path).st_mtime
        self.assertIsNone(got["undated"].timestamp)
        self.assertEqual(got["undated"].not_after, time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime)))

    def test_session_and_project(self):
        legacy = self.session(
            [header(sid=None, cwd=None, legacy=True)]
            + call_lines(10, "a", "Execute", {"command": "pwd"}, output="/"),
            name="77777777-aaaa-4aaa-8aaa-000000000007", folder="")
        windows = self.session(
            [header(sid="88888888-bbbb-4bbb-8bbb-000000000008",
                    cwd="C:\\Users\\me\\proj")]
            + call_lines(10, "b", "Execute", {"command": "dir"}, output=""),
            name="88888888-bbbb-4bbb-8bbb-000000000008", folder="-C-Users-me-proj")
        fork = self.session(
            [dict(header(sid="99999999-cccc-4ccc-8ccc-000000000009"),
                  parent=SID, callingSessionId=SID, callingToolUseId="toolu_01ABC")]
            + call_lines(10, "c", "Execute", {"command": "pwd"}, output=""),
            name="99999999-cccc-4ccc-8ccc-000000000009", folder="btw")
        [a] = self.calls(legacy)
        self.assertEqual((a.session, a.project),
                         ("77777777-aaaa-4aaa-8aaa-000000000007", None))
        [b] = self.calls(windows)
        self.assertEqual((b.session, b.project),
                         ("88888888-bbbb-4bbb-8bbb-000000000008", "C:\\Users\\me\\proj"))
        [c] = self.calls(fork)
        self.assertEqual((c.session, c.project),
                         ("99999999-cccc-4ccc-8ccc-000000000009", "/Users/me/proj"))

    def test_dedupe_by_tool_use_id(self):
        lines = [header()]
        lines += call_lines(10, "toolu_A", "Execute", {"command": "cat .env"},
                            output="first")
        # a replayed copy of the same call and result, after compaction
        lines.append({"type": "compaction_state", "summaryText": "ran cat .env"})
        lines += call_lines(20, "toolu_A", "Execute", {"command": "cat .env"},
                            output="second")
        # a call copied before its result arrives
        lines.append(message(30, "assistant", [use("toolu_B", "Read",
                                                   {"file_path": "a"})]))
        lines.append(message(31, "assistant", [use("toolu_B", "Read",
                                                   {"file_path": "a"})]))
        lines.append(message(32, "user", [result("toolu_B", "text")]))
        # two calls in one message, answered in one message
        lines.append(message(40, "assistant", [
            use("toolu_C", "Execute", {"command": "ls"}),
            use("toolu_D", "Execute", {"command": "pwd"})]))
        lines.append(message(41, "user", [result("toolu_D", "/w"),
                                          result("toolu_C", "a b")]))
        calls = self.calls(self.session(lines))
        self.assertEqual(sorted(c.tool_call_id for c in calls),
                         ["toolu_A", "toolu_B", "toolu_C", "toolu_D"])
        got = {c.tool_call_id: c for c in calls}
        self.assertEqual(got["toolu_A"].output, "first")
        self.assertEqual(got["toolu_A"].timestamp, "2026-09-30T10:00:10Z")
        self.assertEqual(got["toolu_B"].output, "text")
        self.assertEqual((got["toolu_C"].output, got["toolu_D"].output), ("a b", "/w"))

    def test_a_call_with_no_id_is_kept(self):
        lines = [header(), message(10, "assistant", [
            {"type": "tool_use", "name": "Execute", "input": {"command": "ls"}}])]
        [call] = self.calls(self.session(lines))
        self.assertEqual((call.tool_call_id, call.command), (None, "ls"))

    def test_side_stores_have_no_calls(self):
        self.write("artifacts/tool-outputs/fetch_url-toolu_X-90012345.log", None,
                   raw=b'{"type":"message"}\n')
        self.write("state/history.json", None,
                   raw=history_file([prompt("ls", kind="bash_command", mode="bash")]))
        full = '{"type":"message"}\n' * 1000
        log = self.terminal_log(full)
        self.session([header()] + call_lines(10, "t", "Execute", {"command": "cat x"},
                                             output=execute_result(full, log)))
        sides = [s for s in self.stores() if s.role == "side"]
        self.assertEqual(len(sides), 3)
        for store in sides:
            self.assertEqual(list(self.droid.tool_calls(store)), [])

    def test_a_command_typed_in_bash_mode_is_the_users(self):
        lines = [header(),
                 user_shell(10, "rm -rf ~/Documents/x", ts="2026-09-30T10:00:10.000Z"),
                 user_shell(11, "cat ~/.aws/credentials",
                            stdout="[default]\naws_access_key_id = AKIA" "EXAMPLE\n",
                            stderr="warning: old config", exit_code=0,
                            ts="2026-09-30T12:00:11.000+02:00"),
                 user_shell(12, "false", exit_code=1)]
        lines += call_lines(20, "toolu_A", "Execute", {"command": "ls"}, output="a")
        path = self.session(lines)
        calls = self.calls(path)
        self.assertEqual([(c.tool_name, c.actor, c.command) for c in calls], [
            ("bash_result", "user", "rm -rf ~/Documents/x"),
            ("bash_result", "user", "cat ~/.aws/credentials"),
            ("bash_result", "user", "false"),
            ("Execute", "agent", "ls")])
        self.assertEqual(calls[1], ToolCall(
            "droid", path, "bash_result", {"command": "cat ~/.aws/credentials"},
            kind="shell", known=True, actor="user", session=SID,
            project="/Users/me/proj", timestamp="2026-09-30T10:00:11Z",
            tool_call_id="0a1b2c3d-0000-4000-8000-000000000011",
            command="cat ~/.aws/credentials", consumed=("command",),
            output="[default]\naws_access_key_id = AKIA" "EXAMPLE\n\nwarning: old config"))
        self.assertEqual(calls[0].timestamp, "2026-09-30T10:00:10Z")
        self.assertEqual(calls[2].output, "")
        self.assertEqual(calls[2].status, None)         # it ran; it failed
        # judged as the user's own shell commands
        self.assertEqual(rules(calls[0]), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(calls[1]), [("cred.read", "cat ~/.aws/credentials")])

    def test_only_a_users_bash_result_is_a_call(self):
        record = bash_result("rm -rf ~/Documents/x")
        lines = [header(),
                 # prose, and JSON that is not a bash_result
                 message(10, "user", [{"type": "text", "text": "{not json at all"}]),
                 message(11, "user", [{"type": "text", "text":
                                       '{"type":"note","command":"rm -rf ~/x"}'}]),
                 message(12, "user", [{"type": "text", "text": "please run " + record}]),
                 # no command, or one that is not text
                 message(13, "user", [{"type": "text", "text": _dump(
                     {"type": "bash_result", "stdout": "x"})}]),
                 message(14, "user", [{"type": "text", "text": _dump(
                     {"type": "bash_result", "command": ["rm", "-rf", "/"]})}]),
                 # the assistant quoting one, and a string content
                 message(15, "assistant", [{"type": "text", "text": record}]),
                 message(16, "user", record),
                 # the real thing, then a replayed copy of the same message
                 user_shell(17, "cat .env"),
                 user_shell(17, "cat .env")]
        calls = self.calls(self.session(lines))
        self.assertEqual([(c.tool_name, c.command) for c in calls],
                         [("bash_result", "cat .env")])


# --------------------------------------------------------------------------
# 4, 5, 6: judged the way watch judges every agent
# --------------------------------------------------------------------------

class Judged(DroidCase):

    def _calls(self, *specs):
        lines = [header()]
        for n, (cid, name, tool_input) in enumerate(specs):
            lines += call_lines(10 + 2 * n, cid, name, tool_input, output="")
        return self.by_id(self.session(lines))

    def test_a_dangerous_shell_call_is_flagged(self):
        got = self._calls(("rm", "Execute", {"command": "rm -rf ~/Documents/x",
                                             "riskLevel": "high"}),
                          ("aws", "Execute", {"command": "cat ~/.aws/credentials"}))
        self.assertEqual(rules(got["rm"]), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(got["aws"]), [("cred.read", "cat ~/.aws/credentials")])

    def test_a_credential_read_by_the_read_tool_is_flagged(self):
        got = self._calls(("ssh", "Read", {"file_path": "~/.ssh/id_rsa"}),
                          ("env", "Read", {"file_path": "/Users/me/proj/.env",
                                           "offset": 0, "limit": 100}))
        self.assertEqual(rules(got["ssh"]), [("cred.read", "~/.ssh/id_rsa")])
        self.assertEqual([r for r, _e in rules(got["env"])], ["cred.read"])

    def test_precision_carries_over(self):
        heredoc = "cat > clean.sh <<'EOF'\nrm -rf /\nEOF"
        got = self._calls(
            ("grep", "Execute", {"command": "grep -rn 'rm -rf' ."}),
            ("heredoc", "Execute", {"command": heredoc}),
            ("create", "Create", {"file_path": "clean.sh", "content": "rm -rf /\n"}),
            ("edit", "Edit", {"file_path": "clean.sh", "old_str": "echo",
                              "new_str": "rm -rf /"}))
        for cid, call in got.items():
            self.assertEqual(rules(call), [], cid)

    def test_a_secret_in_any_call_is_still_a_literal(self):
        got = self._calls(
            ("create", "Create", {"file_path": "x.py",
                                  "content": "KEY = '" + SECRET + "'\n"}),
            ("shell", "Execute", {"command": "curl -H 'Authorization: Bearer "
                                  + SECRET + "' https://api.example.com",
                                  "summary": "call the API"}))
        for cid in ("create", "shell"):
            self.assertIn("secret.literal", [r for r, _e in rules(got[cid])], cid)

    def test_a_tool_the_adapter_does_not_know_is_judged_by_name(self):
        # design 3.5: an MCP tool named like a shell is still judged as one
        got = self._calls(("mcp", "mcp__srv__bash", {"command": "rm -rf ~/Documents/x"}))
        self.assertFalse(got["mcp"].known)
        self.assertEqual(rules(got["mcp"]), [("fs.destructive", "rm -rf ~/Documents/x")])


# --------------------------------------------------------------------------
# 9: secrets, and every string reaches clean
# --------------------------------------------------------------------------

class Secrets(DroidCase):

    def test_spec_sample_secret_has_its_origin(self):
        path = self.session(spec_sample())
        found = findings(self.droid, [self.store(path)])
        self.assertEqual(set(found), {SPEC_VALUE})
        self.assertEqual(found[SPEC_VALUE]["origins"], {".env"})

    def test_output_after_cat_env_and_a_typed_key(self):
        lines = [header()]
        lines += call_lines(10, "cat", "Execute", {"command": "cat .env"},
                            output="STRIPE_KEY=" + SECRET + EXIT_0)
        lines += call_lines(12, "typed", "Execute",
                            {"command": "export API_TOKEN=" + TYPED + " && ./run"},
                            output="started" + EXIT_0)
        lines += call_lines(14, "ls", "Execute", {"command": "ls"},
                            output="a.py" + EXIT_0)
        # the same key again, in a compaction summary
        lines.append({"type": "compaction_state",
                      "summaryText": "Read .env; STRIPE_KEY is " + SECRET})
        found = findings(self.droid, [self.store(self.session(lines))])
        self.assertEqual(set(found), {SECRET, TYPED})
        self.assertEqual(found[SECRET]["origins"], {".env"})
        self.assertEqual(found[SECRET]["count"], 2)
        self.assertEqual(found[TYPED]["origins"], set())

    def test_the_result_is_tied_to_its_call(self):
        lines = [header()] + call_lines(10, "cat", "Execute",
                                        {"command": "cat .env"}, output="X=1")
        texts = list(self.droid.secret_texts(self.store(self.session(lines))))
        tied = [t for t in texts if t.call is not None]
        self.assertEqual(len(tied), 1)
        self.assertEqual((tied[0].node, tied[0].call.command, tied[0].call.tool_call_id,
                          tied[0].where), ("X=1", "cat .env", "cat", "line 3"))

    def test_every_string_in_a_transcript_reaches_clean(self):
        lines = spec_sample()
        lines.append({"type": "todo_state", "todos": [{"content": "rotate " + SECRET,
                                                       "status": "pending"}]})
        lines.append({"type": "compaction_state", "summaryText": "summary text"})
        lines.append({"type": "future_record", "payload": {"deep": ["unknown kind"]}})
        lines.append(message(20, "assistant", [
            {"type": "future_block", "note": "a block type not in the spec"},
            {"type": "text", "text": "some prose"},
            use("t9", "Create", {"file_path": "f", "content": "body"})]))
        lines.append(message(21, "user", [
            result("t9", [{"type": "text", "text": "created"}], is_error=False),
            {"type": "text", "text": "and a note"}]))
        lines.append(message(22, "user", [result("orphan", "no call")]))
        lines.append(message(23, "user", "plain string content"))
        lines.append(message(24, "user", ["a bare string beside a result",
                                          result("t9", "again")]))
        lines.append(turn_outcome("turn-1", "structured",
                                  {"summary": "structured result text"}))
        lines.append(user_shell(25, "make deploy", stdout="deployed",
                                stderr="a warning"))
        path = self.session(lines)
        expected = set()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                for string in _strings(json.loads(line)):
                    # a bash_result's text is handed over decoded
                    if string.startswith('{"type":"bash_result"'):
                        expected.update(_strings(json.loads(string)))
                    else:
                        expected.add(string)
        self.assertIn("structured result text", expected)
        self.assertIn("a warning", expected)
        got = set()
        for text in self.droid.secret_texts(self.store(path)):
            got.update(_strings(text.node))
        self.assertEqual(expected - got, set())
        found = findings(self.droid, [self.store(path)])
        self.assertIn(SECRET, found)
        self.assertIn("line 5", found[SECRET]["where"])

    def test_a_long_commands_full_output_is_in_the_temp_folder(self):
        # Execute keeps 8 KiB of head and 8 KiB of tail: the key in the
        # middle is only in the terminal log its result names
        full = ("build line\n" * 3000 + "STRIPE_KEY=" + SECRET + "\n"
                + "build line\n" * 3000)
        log = self.terminal_log(full)
        path = self.session([header()] + call_lines(
            10, "toolu_01BIG", "Execute", {"command": "cat build.log"},
            output=execute_result(full, log)))
        self.assertNotIn(SECRET, findings(self.droid, [self.store(path)]))
        store = self.store(log)
        self.assertEqual((store.format, store.role, store.unit, store.masking),
                         ("text", "side", "command output", "rewrite"))
        found = findings(self.droid, [store])
        self.assertEqual(found[SECRET]["stores"], {log})
        self.assertEqual(found[SECRET]["where"], ["line 1"])
        self.assertEqual(found[SECRET]["origins"], set())   # build.log is not a key file
        # tied to the call that ran: what clean credits an origin from
        texts = list(self.droid.secret_texts(store))
        self.assertEqual({(t.call.tool_call_id, t.call.command) for t in texts},
                         {("toolu_01BIG", "cat build.log")})

    def test_a_terminal_logs_key_gets_its_commands_origin(self):
        full = ("# generated\n" * 2000 + "STRIPE_KEY=" + SECRET + "\n"
                + "FEATURE_FLAG=1\n" * 2000)
        log = self.terminal_log(full)
        self.session([header()] + call_lines(
            10, "toolu_01ENV", "Execute", {"command": "cat deploy/.env.production"},
            output=execute_result(full, log)))
        found = findings(self.droid, [self.store(log)])
        self.assertEqual(found[SECRET]["origins"], {"deploy/.env.production"})
        # a failed command's log is named the same way
        failed = self.terminal_log(full, terminal_id="0d1e2f3a-4b5c-4d6e-8f70-819203a4b5c6",
                                   folder="droid-terminal-Fa1led")
        self.session([header(sid="77777777-aaaa-4aaa-8aaa-000000000007")] + call_lines(
            10, "toolu_01FAIL", "Execute", {"command": "cat deploy/.env.production; false"},
            output=execute_result(full, failed, exit_code=1), is_error=True),
            name="77777777-aaaa-4aaa-8aaa-000000000007")
        found = findings(self.droid, [self.store(failed)])
        self.assertEqual(found[SECRET]["origins"], {"deploy/.env.production"})

    def test_a_notice_is_followed_only_to_a_droid_terminal_log(self):
        secret_line = ("KEY=" + SECRET + "\n").encode("utf-8")
        keyfile = self.write("id_rsa", None, raw=secret_line,
                             root=os.path.join(self.home, ".ssh"))
        named = [
            keyfile,                                                # not a terminal log
            self.write("other/%s.log" % TERMINAL_ID, None, raw=secret_line,
                       root=self.tmp),                              # not its folder
            self.write("droid-terminal-/%s.log" % TERMINAL_ID, None, raw=secret_line,
                       root=self.tmp),                              # no mkdtemp suffix
            self.write("%s/notes.log" % TERMINAL_DIR, None, raw=secret_line,
                       root=self.tmp),                              # not a terminal id
            os.path.join(self.tmp, TERMINAL_DIR, "1f2e3d4c-0000-4000-8000-000000000000.log"),
            os.path.join(TERMINAL_DIR, TERMINAL_ID + ".log"),       # relative
        ]
        real = self.write("droid-terminal-Zz9Yy8/%s.log" % TERMINAL_ID, None,
                          raw=secret_line, root=self.tmp)
        named.append(os.path.join(self.tmp, TERMINAL_DIR, "..", "droid-terminal-Zz9Yy8",
                                  TERMINAL_ID + ".log"))            # by way of ..
        try:                                                        # links
            linked_file = os.path.join(self.tmp, "droid-terminal-Lnk111",
                                       TERMINAL_ID + ".log")
            os.makedirs(os.path.dirname(linked_file))
            os.symlink(keyfile, linked_file)
            linked_dir = os.path.join(self.tmp, "droid-terminal-Dir222")
            os.symlink(os.path.dirname(real), linked_dir)
            named += [linked_file, os.path.join(linked_dir, TERMINAL_ID + ".log")]
        except (OSError, NotImplementedError, AttributeError):
            pass                                # no symbolic links here (Windows)
        lines = [header()]
        for n, path in enumerate(named):
            lines += call_lines(10 + 2 * n, "toolu_%d" % n, "Execute",
                                {"command": "make"},
                                output=execute_result("y\n" * 10000, path))
        # a command's own output printing the notice: still only that file
        lines += call_lines(90, "toolu_echo", "Execute", {"command": "cat notes.txt"},
                            output="Full command output saved to: %s (1KB)" % keyfile
                            + EXIT_0)
        transcript = self.session(lines)
        self.assertEqual([s.path for s in self.stores()], [transcript])
        self.assertNotIn(SECRET, findings(self.droid, self.stores()))
        # the same file named properly is followed
        self.session([header(sid="88888888-bbbb-4bbb-8bbb-000000000008")] + call_lines(
            10, "toolu_ok", "Execute", {"command": "make"},
            output=execute_result("y\n" * 10000, real)),
            name="88888888-bbbb-4bbb-8bbb-000000000008", age=60)
        self.assertIn(real, [s.path for s in self.stores()])

    def test_a_large_result_of_another_tool_is_in_artifacts_tool_outputs(self):
        full = ("src/a.py:1:x\n" * 3000 + "src/env.py:9:STRIPE_KEY=" + SECRET + "\n"
                + "src/b.py:1:y\n" * 3000)
        name = "grep_tool_cli-toolu_01GREP-90012345.log"
        log = self.write("artifacts/tool-outputs/" + name, None,
                         raw=full.encode("utf-8"), mode=0o600)
        path = self.session([header()] + call_lines(
            10, "toolu_01GREP", "Grep", {}, output=spilled(full, log)))
        self.assertNotIn(SECRET, findings(self.droid, [self.store(path)]))
        found = findings(self.droid, [self.store(log)])
        self.assertEqual(found[SECRET]["stores"], {log})
        self.assertEqual(self.store(log).unit, "tool output")

    def _spill(self, cid, key_file, tool="grep_tool_cli", stamp="90012345",
               sid=SID, notice=None):
        """A Grep whose result spilled to artifacts/tool-outputs: the
        file named <tool id>-<call id>-<8 digits>.log as $c() names it,
        holding a grep line for `key_file` among many, and the session
        whose result names it. Returns (log, transcript)."""
        full = ("src/a%d.py:1:x = 1\n" * 3000 % tuple(range(3000))
                + "%s:1:STRIPE_KEY=%s\n" % (key_file, SECRET)
                + "src/b.py:1:y = 2\n" * 3000)
        log = self.write("artifacts/tool-outputs/%s-%s-%s.log" % (tool, cid, stamp),
                         None, raw=full.encode("utf-8"), mode=0o600)
        path = self.session([header(sid=sid)] + call_lines(
            10, cid, "Grep", {"pattern": "KEY", "path": "."},
            output=spilled(full, notice or log)), name=sid)
        return log, path

    def _origins(self, store):
        found, _masks = clean.scan_store(self.droid, store, {})
        [entry] = [e for e in found.values()
                   if e["fingerprint"] == clean._fingerprint(SECRET)]
        return entry["origins"]

    def test_a_spilled_grep_result_gets_the_origin_it_has_in_the_transcript(self):
        # in the transcript, a grep line credits the file in front of it
        path = self.session([header()] + call_lines(
            10, "toolu_01SMALL", "Grep", {"pattern": "KEY", "path": "."},
            output="config/.env.small:1:STRIPE_KEY=%s\n" % SECRET))
        self.assertEqual(self._origins(self.store(path)), {"config/.env.small"})
        # spilled to a log the result names, the same line credits the same
        sid = "99999999-aaaa-4aaa-8aaa-000000000009"
        log, path = self._spill("toolu_01GREP", "config/.env.test", sid=sid)
        store = self.store(log)
        self.assertEqual(self._origins(store), {"config/.env.test"})
        texts = list(self.droid.secret_texts(store))
        self.assertEqual({(t.call.tool_call_id, t.call.tool_name) for t in texts},
                         {("toolu_01GREP", "Grep")})
        # and it belongs to the session that ran it, as a terminal log does
        self.assertEqual((store.session, store.project, store.unit),
                         (sid, "/Users/me/proj", "tool output"))

    def test_a_spill_is_tied_only_where_its_name_carries_the_results_call(self):
        # the notice names a log of another call
        other, _path = self._spill("toolu_01MINE", "config/.env.a",
                                   notice=os.path.join(
                                       self.root, "artifacts", "tool-outputs",
                                       "grep_tool_cli-toolu_01THEIRS-90012345.log"))
        self.write("artifacts/tool-outputs/grep_tool_cli-toolu_01THEIRS-90012345.log",
                   None, raw=("config/.env.b:1:STRIPE_KEY=%s\n" % SECRET).encode("utf-8"))
        theirs = os.path.join(self.root, "artifacts", "tool-outputs",
                              "grep_tool_cli-toolu_01THEIRS-90012345.log")
        for log in (other, theirs):
            store = self.store(log)
            self.assertEqual(self._origins(store), set(), log)
            self.assertEqual([t.call for t in self.droid.secret_texts(store)],
                             [None] * len(list(self.droid.secret_texts(store))))
            self.assertIsNone(store.session)

    def test_a_spill_no_result_names_is_not_tied(self):
        full = "config/.env.c:1:STRIPE_KEY=%s\n" % SECRET
        log = self.write("artifacts/tool-outputs/grep_tool_cli-toolu_01LOST-90012345.log",
                         None, raw=full.encode("utf-8"))
        # a call of that id whose result names no file
        self.session([header()] + call_lines(
            10, "toolu_01LOST", "Grep", {"pattern": "KEY"}, output="no matches"))
        store = self.store(log)
        self.assertEqual(self._origins(store), set())
        self.assertIsNone(store.session)

    def test_a_spill_notice_is_never_followed_outside_tool_outputs(self):
        # the notice is text beside the tool's own output: a file it names
        # that is not one of Droid's tool-output logs is never read
        keyfile = self.write("grep_tool_cli-toolu_01OUT-90012345.log", None,
                             raw=("KEY=" + SECRET + "\n").encode("utf-8"),
                             root=os.path.join(self.home, "elsewhere"))
        transcript = self.session([header()] + call_lines(
            10, "toolu_01OUT", "Grep", {"pattern": "KEY"},
            output=spilled("x\n" * 30000, keyfile)))
        self.assertEqual([s.path for s in self.stores()], [transcript])

    def test_a_moved_droid_folder_still_ties_its_spills(self):
        # The notice names where the log was written; read through --path
        # from a copy, the log of that name in the same folder is the one.
        log, _path = self._spill("toolu_01MOVE", "config/.env.moved",
                                 notice=os.path.join(
                                     "/Users/me/.factory", "artifacts", "tool-outputs",
                                     "grep_tool_cli-toolu_01MOVE-90012345.log"))
        self.assertEqual(self._origins(self.store(log)), {"config/.env.moved"})

    def test_a_bash_mode_commands_output_and_what_was_typed(self):
        path = self.session([
            header(),
            user_shell(10, "cat .env", stdout="STRIPE_KEY=" + SECRET + "\n"),
            user_shell(11, "export API_TOKEN=" + TYPED + " && ./run",
                       stdout="started\n")])
        found = findings(self.droid, [self.store(path)])
        self.assertEqual(set(found), {SECRET, TYPED})
        self.assertEqual((found[SECRET]["origins"], found[SECRET]["count"]),
                         ({".env"}, 1))
        self.assertEqual((found[TYPED]["origins"], found[TYPED]["count"]),
                         (set(), 1))
        tied = [t for t in self.droid.secret_texts(self.store(path)) if t.call]
        self.assertEqual([(t.node, t.call.actor, t.call.command, t.where) for t in tied], [
            ({"stdout": "STRIPE_KEY=" + SECRET + "\n", "stderr": ""}, "user",
             "cat .env", "line 2"),
            ({"stdout": "started\n", "stderr": ""}, "user",
             "export API_TOKEN=" + TYPED + " && ./run", "line 3")])

    def test_a_log_larger_than_one_piece_is_searched_to_the_end(self):
        lines = ["line %d of noise %s" % (i, "n" * 60) for i in range(14000)]
        lines.insert(13500, "TOKEN=" + SECRET)
        text = "\n".join(lines) + "\n"
        # past clean's per-string limit: one string would lose it
        self.assertGreater(text.index(SECRET), clean.MAX_STRING)
        log = self.write("artifacts/tool-outputs/ls-cli-toolu_01LS-90012346.log", None,
                         raw=text.encode("utf-8"))
        pieces = list(self.droid.secret_texts(self.store(log)))
        self.assertGreater(len(pieces), 1)
        self.assertEqual("".join(p.node for p in pieces), text)
        found = findings(self.droid, [self.store(log)])
        self.assertEqual(found[SECRET]["where"], [
            p.where for p in pieces if SECRET in p.node])
        self.assertTrue(all(p.node.endswith("\n") for p in pieces))

    def test_typed_prompts_in_both_history_files(self):
        state = self.write("state/history.json", None, raw=history_file([
            prompt("deploy with " + SECRET, "2026-09-30T10:00:00.000Z"),
            prompt("/help", "2026-09-30T10:00:01.000Z", kind="slash_command"),
            prompt("cat .env", "2026-09-30T10:00:02.000Z", kind="bash_command",
                   mode="bash")]))
        older = self.write("history.json", None, raw=history_file([
            prompt("export API_TOKEN=" + TYPED, "2026-03-01T09:00:00.000Z")]))
        found = findings(self.droid, [self.store(state), self.store(older)])
        self.assertEqual(found[SECRET]["stores"], {state})
        self.assertEqual(found[SECRET]["where"], ["entry 1"])
        self.assertEqual(found[SECRET]["origins"], set())
        self.assertEqual(found[TYPED]["stores"], {older})


# --------------------------------------------------------------------------
# 10, 13: masking round trip, and a file in use
# --------------------------------------------------------------------------

class Masking(DroidCase):

    def _session_with_secrets(self, **kw):
        lines = [header()]
        lines += call_lines(10, "cat", "Execute", {"command": "cat .env"},
                            output="STRIPE_KEY=" + SECRET + EXIT_0)
        lines += call_lines(12, "json", "Execute", {"command": "cat config.json"},
                            output=json.dumps({"token": SECRET, "n": 1}) + EXIT_0)
        lines += call_lines(14, "typed", "Execute",
                            {"command": "curl -u me:" + SECRET + " https://x.example"},
                            output="caf\u00e9 \u2028 ok")
        lines.append({"type": "compaction_state", "summaryText": "key " + SECRET})
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
        self.assertEqual(glob.glob(os.path.join(os.path.dirname(path), "*.ranwhat-tmp")), [])
        return after

    def test_round_trip_of_a_transcript(self):
        path = self._session_with_secrets()
        with open(path, "rb") as fh:
            original = fh.read()
        store = self.store(path)
        before = list(self.droid.tool_calls(store))
        result = self.droid.mask(store, [SECRET])
        after = self._assert_masked(path, original, SECRET, result)
        # every line still parses, and the JSON inside an output still does
        # split on \n only: an output holds a raw U+2028
        lines = [json.loads(l) for l in after.decode("utf-8").split("\n") if l]
        inner = lines[4]["message"]["content"][0]["content"]
        self.assertEqual(json.loads(inner[:-len(EXIT_0)]),
                         {"token": _marker(SECRET), "n": 1})
        # the adapter reads the same calls, the secret masked in each
        again = list(self.droid.tool_calls(self.store(path)))
        self.assertEqual(
            [(c.tool_call_id, c.tool_name, c.kind, c.timestamp, c.session) for c in again],
            [(c.tool_call_id, c.tool_name, c.kind, c.timestamp, c.session) for c in before])
        m = _marker(SECRET)
        self.assertEqual([c.command for c in again],
                         [c.command.replace(SECRET, m) for c in before])
        self.assertEqual([c.output for c in again],
                         [c.output.replace(SECRET, m) for c in before])
        self.assertEqual(findings(self.droid, [self.store(path)]), {})
        # a second run changes nothing and makes no second backup
        self.assertEqual(self.droid.mask(self.store(path), [SECRET]), MaskResult(path))
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), after)
        backups = [f for _d, _s, fs in os.walk(self.backups) for f in fs]
        self.assertEqual(len(backups), 1)

    def test_round_trip_of_the_spec_sample(self):
        path = self.session(spec_sample(), mode=0o644)
        with open(path, "rb") as fh:
            original = fh.read()
        result = self.droid.mask(self.store(path), [SPEC_VALUE])
        after = self._assert_masked(path, original, SPEC_VALUE, result, mode=0o644)
        self.assertEqual(len(after.split(b"\n")), 5)

    def test_round_trip_of_a_log_and_a_history(self):
        log = self.write("artifacts/tool-outputs/fetch_url-toolu_X-90012345.log", None,
                         raw=("build ok\nSTRIPE_KEY=" + SECRET + "\ndone\n").encode("utf-8"),
                         mode=0o600)
        history = self.write("state/history.json", None, mode=0o600, raw=history_file(
            [prompt("use " + SECRET), prompt("ls", kind="bash_command", mode="bash")]))
        full = "build line\n" * 3000 + "STRIPE_KEY=" + SECRET + "\n" + "done\n" * 3000
        terminal = self.terminal_log(full)
        self.session([header()] + call_lines(10, "toolu_01BIG", "Execute",
                                             {"command": "make"},
                                             output=execute_result(full, terminal)))
        for path in (log, history, terminal):
            with open(path, "rb") as fh:
                original = fh.read()
            result = self.droid.mask(self.store(path), [SECRET])
            self._assert_masked(path, original, SECRET, result)
        self.assertEqual(findings(self.droid, [self.store(log), self.store(history),
                                               self.store(terminal)]), {})

    def test_round_trip_of_a_bash_mode_command(self):
        path = self.session([
            header(),
            user_shell(10, "cat .env", stdout="STRIPE_KEY=" + SECRET + "\n",
                       stderr='quoted "' + SECRET + '"'),
            user_shell(11, "curl -u me:" + SECRET + " https://x.example",
                       stdout="café   ok")], mode=0o600)
        with open(path, "rb") as fh:
            original = fh.read()
        before = list(self.droid.tool_calls(self.store(path)))
        self.assertEqual([c.actor for c in before], ["user", "user"])
        result = self.droid.mask(self.store(path), [SECRET])
        self.assertEqual((result.changed, result.skipped), (True, None))
        with open(path, "rb") as fh:
            after = fh.read()
        text = after.decode("utf-8")
        self.assertEqual([f for f in _rewrite.encodings(SECRET) if f in text], [])
        with open(result.backup, "rb") as fh:
            self.assertEqual(fh.read(), original)
        # each record still parses inside its line, the key masked in it
        m = _marker(SECRET)
        lines = [json.loads(l) for l in text.split("\n") if l]
        record = json.loads(lines[1]["message"]["content"][0]["text"])
        self.assertEqual(record, {"type": "bash_result", "command": "cat .env",
                                  "stdout": "STRIPE_KEY=" + m + "\n",
                                  "stderr": 'quoted "' + m + '"', "exitCode": 0})
        again = list(self.droid.tool_calls(self.store(path)))
        self.assertEqual([(c.tool_call_id, c.actor, c.command.replace(SECRET, m),
                           c.output.replace(SECRET, m)) for c in before],
                         [(c.tool_call_id, c.actor, c.command, c.output) for c in again])
        self.assertEqual(findings(self.droid, [self.store(path)]), {})

    def test_a_file_written_just_now_is_in_use(self):
        path = self._session_with_secrets(age=5)
        digest = _sha(path)
        result = self.droid.mask(self.store(path), [SECRET])
        self.assertEqual(result, MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))


# --------------------------------------------------------------------------
# A command run in the background: its whole output in the temp folder
# --------------------------------------------------------------------------

class Background(DroidCase):

    def _ran(self, output, command="npm run dev", cid="toolu_01BG", name=SID,
             age=3600, **kw):
        """A session whose one Execute ran `command` in the background."""
        return self.session([header(sid=name)] + call_lines(
            10, cid, "Execute", {"command": command, "fireAndForget": True},
            output=output), name=name, age=age, **kw)

    def test_a_background_commands_output_is_found_and_searched(self):
        bg = self.background_output("> app@1.0.0 dev\nlistening on :3000\n"
                                    "STRIPE_KEY=" + SECRET + "\n")
        path = self._ran(background_result(bg, warning=DEV_WARNING))
        # the transcript keeps only the file's name
        self.assertNotIn(SECRET, findings(self.droid, [self.store(path)]))
        self.assertEqual([s.path for s in self.stores()], [path, bg])
        store = self.store(bg)
        self.assertEqual((store.format, store.role, store.unit, store.masking),
                         ("text", "side", "background output", "read-only"))
        self.assertEqual(store.why_read_only, droid_module.BACKGROUND_WHY)
        self.assertNotIn("\u2014", store.why_read_only)
        self.assertEqual((store.session, store.project), (SID, "/Users/me/proj"))
        found = findings(self.droid, [store])
        self.assertEqual((found[SECRET]["stores"], found[SECRET]["where"],
                          found[SECRET]["origins"]), ({bg}, ["line 1"], set()))
        # tied to the call that started it
        texts = list(self.droid.secret_texts(store))
        self.assertEqual({(t.call.tool_call_id, t.call.command) for t in texts},
                         {("toolu_01BG", "npm run dev")})
        self.assertEqual(list(self.droid.tool_calls(store)), [])
        # the call itself is an ordinary shell call; its result is its output
        [call] = self.calls(path)
        self.assertEqual((call.kind, call.command, call.consumed, call.tool_input),
                         ("shell", "npm run dev", frozenset({"command"}),
                          {"command": "npm run dev", "fireAndForget": True}))
        self.assertTrue(call.output.startswith("Background process started (PID: 4242)"))

    def test_every_shape_of_the_result_is_followed(self):
        text = "# generated\nSTRIPE_KEY=" + SECRET + "\n"
        command = "sleep 1; cat deploy/.env.production"
        shapes = [
            # finished before the result was written
            lambda bg: background_result(bg, command, completed=True),
            # its end reported back to the session later; no pid known
            lambda bg: background_result(bg, command, pid=None, wake=True),
            # the result as a list of text blocks
            lambda bg: [{"type": "text", "text": background_result(
                bg, command, warning="Node processes should handle SIGTERM "
                                     "properly")}],
        ]
        outputs = []
        for n, shape in enumerate(shapes):
            bg = self.background_output(text, stamp=BG_STAMP + n)
            outputs.append(bg)
            self._ran(shape(bg), command=command, cid="toolu_%d" % n,
                      name="9999999%d-aaaa-4aaa-8aaa-00000000000%d" % (n, n))
        self.assertEqual(set(outputs) & {s.path for s in self.stores()}, set(outputs))
        found = findings(self.droid, [self.store(p) for p in outputs])
        self.assertEqual(found[SECRET]["stores"], set(outputs))
        # a key the command printed from a key file gets that file as origin
        self.assertEqual(found[SECRET]["origins"], {"deploy/.env.production"})

    def test_an_output_line_is_followed_only_to_a_droid_background_file(self):
        secret_line = ("KEY=" + SECRET + "\n").encode("utf-8")
        keyfile = self.write("id_rsa", None, raw=secret_line,
                             root=os.path.join(self.home, ".ssh"))
        real = self.write("droid-bg-%d.out" % BG_STAMP, None, raw=secret_line,
                          root=self.tmp)
        os.makedirs(os.path.join(self.tmp, "droid-bg-1790888580524.out"))
        named = [
            keyfile,                                                # not one
            self.write("droid-bg-179088858052.out", None, raw=secret_line,
                       root=self.tmp),                              # 12 digits
            self.write("droid-bg-%d.log" % BG_STAMP, None, raw=secret_line,
                       root=self.tmp),                              # not .out
            self.write("droid-bg-%d.out.bak" % BG_STAMP, None, raw=secret_line,
                       root=self.tmp),
            self.write("bg-%d.out" % BG_STAMP, None, raw=secret_line,
                       root=self.tmp),
            os.path.join(self.tmp, "droid-bg-1790888580999.out"),   # missing
            os.path.join(self.tmp, "droid-bg-1790888580524.out"),   # a folder
            "droid-bg-%d.out" % BG_STAMP,                           # relative
            os.path.join(self.tmp, "sub", "..", "droid-bg-%d.out" % BG_STAMP),
        ]
        try:                                                        # a link
            linked = os.path.join(self.tmp, "droid-bg-1790888580525.out")
            os.symlink(keyfile, linked)
            named.append(linked)
        except (OSError, NotImplementedError, AttributeError):
            pass                                # no symbolic links here (Windows)
        lines = [header()]
        for n, path in enumerate(named):
            lines += call_lines(10 + 2 * n, "toolu_%d" % n, "Execute",
                                {"command": "npm run dev", "fireAndForget": True},
                                output=background_result(path))
        # an Output line anywhere but in a background result: an ordinary
        # command's output, a start that failed (what that path is was not
        # verified), and prose
        lines += call_lines(60, "toolu_echo", "Execute", {"command": "cat notes.txt"},
                            output="Output: %s\n" % real + EXIT_0)
        lines += call_lines(62, "toolu_fail", "Execute",
                            {"command": "npm run dev", "fireAndForget": True},
                            output="Failed to start background process: spawn "
                                   "bash ENOENT\nOutput: %s" % real, is_error=True)
        lines.append(message(70, "assistant", [{"type": "text", "text":
                                                background_result(real)}]))
        lines.append(message(71, "user", background_result(real)))
        transcript = self.session(lines)
        self.assertEqual([s.path for s in self.stores()], [transcript])
        self.assertNotIn(SECRET, findings(self.droid, self.stores()))
        # the same file named properly is followed
        self._ran(background_result(real), name="88888888-bbbb-4bbb-8bbb-000000000008",
                  age=60)
        self.assertIn(real, [s.path for s in self.stores()])

    def test_masking_a_background_output_is_refused(self):
        bg = self.background_output("STRIPE_KEY=" + SECRET + "\n")
        self._ran(background_result(bg))
        digest = _sha(bg)
        result = self.droid.mask(self.store(bg), [SECRET])
        self.assertEqual(result, MaskResult(bg, skipped="read-only"))
        self.assertEqual(_sha(bg), digest)
        self.assertFalse(os.path.exists(self.backups))
        self.assertEqual(glob.glob(os.path.join(self.tmp, "*.ranwhat-tmp")), [])

    def test_days_window_and_background_outputs(self):
        fresh = self.background_output("x\n", age=120)
        stale = self.background_output("x\n", stamp=BG_STAMP + 1, age=91 * 86400)
        started = {"command": "npm start", "fireAndForget": True}
        recent = self.session([header()] + call_lines(
            10, "toolu_new", "Execute", started, output=background_result(fresh))
            + call_lines(12, "toolu_stale", "Execute", started,
                         output=background_result(stale)), age=60)
        self.assertEqual([s.path for s in self.stores(since_days=30)], [recent, fresh])
        self.assertEqual([s.path for s in self.stores()], [recent, fresh, stale])
        # a process can outlive its session: its output, still written
        # today, is found through a session last written long ago only
        # without --days (the gap stores() documents)
        running = self.background_output("still going\n", stamp=BG_STAMP + 2, age=30)
        old = self._ran(background_result(running), name="77777777-aaaa-4aaa-8aaa-000000000007",
                        age=90 * 86400)
        self.assertEqual([s.path for s in self.stores(since_days=30)], [recent, fresh])
        self.assertEqual([s.path for s in self.stores()],
                         [running, recent, fresh, old, stale])

    def test_an_output_with_no_line_ends_is_read_in_bounded_pieces(self):
        chunk = droid_module._CHUNK
        # a progress bar redrawn with carriage returns, the key at the end
        bar = "".join("building %6d/%d\r" % (i, 60000) for i in range(60000))
        text = bar + "STRIPE_KEY=" + SECRET + "\rdone\n"
        bg = self.background_output(text)
        self._ran(background_result(bg))
        pieces = list(self.droid.secret_texts(self.store(bg)))
        self.assertGreater(len(pieces), 3)
        self.assertEqual("".join(p.node for p in pieces), text)
        self.assertTrue(all(len(p.node.encode("utf-8")) <= chunk for p in pieces))
        self.assertTrue(all(p.node.endswith(("\r", "\n")) for p in pieces))
        found = findings(self.droid, [self.store(bg)])
        self.assertEqual((found[SECRET]["count"], found[SECRET]["where"]),
                         (1, ["line 1"]))
        # no break at all, and a cut that would land inside a two-byte
        # character: cut before it instead
        text = "a" + "\u00e9" * (chunk + 7) + "\n"
        with open(bg, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        pieces = [p.node for p in self.droid.secret_texts(self.store(bg))]
        self.assertEqual("".join(pieces), text)
        self.assertEqual([len(p.encode("utf-8", "surrogateescape")) <= chunk
                          for p in pieces], [True] * len(pieces))
        self.assertFalse(any("\udcc3" in p or "\udca9" in p for p in pieces))


# --------------------------------------------------------------------------
# 12, 14: files that do not parse, and the --days window
# --------------------------------------------------------------------------

class Damaged(DroidCase):

    def test_a_truncated_last_line_is_skipped_quietly(self):
        good = "".join(_dump(l) + "\n" for l in spec_sample())
        partial = _dump(message(9, "assistant", [use("toolu_Z", "Execute",
                                                     {"command": "rm -rf ~/x"})]))
        path = self.session(None, raw=(good + partial[:40]).encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self.calls(path)
            list(self.droid.secret_texts(self.store(path)))
        self.assertEqual([c.tool_call_id for c in calls], ["toolu_01ABC"])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.droid.counts["unparsed"], 0)

    def test_garbage_warns_once_and_other_stores_are_still_read(self):
        garbage = self.session(None, name="aaaaaaaa-0000-4000-8000-00000000000a",
                               raw=b"\x00\xff\xfe not json\n\x89PNG\r\n\x1a\n" * 20)
        good = self.session(spec_sample(), age=7200)
        bad_history = self.write("state/history.json", None, raw=b"[{\"command\": ")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for store in self.stores():
                list(self.droid.tool_calls(store))
                list(self.droid.secret_texts(store))
                list(self.droid.tool_calls(store))
            self.assertEqual([c.tool_call_id for c in self.calls(good)], ["toolu_01ABC"])
        warnings = err.getvalue().splitlines()
        self.assertEqual(len(warnings), 2, warnings)
        self.assertTrue(any(garbage in w for w in warnings))
        self.assertTrue(any(bad_history in w for w in warnings))
        self.assertEqual(self.droid.counts["unreadable_stores"], 2)
        self.assertEqual(self.droid.unreadable, {"not JSON Lines": 1, "not JSON": 1})

    def test_unknown_records_and_blocks_are_ignored_and_counted(self):
        lines = spec_sample() + [
            {"type": "future_record", "command": "rm -rf ~/x"},
            [1, 2, 3],
            message(20, "assistant", [{"type": "future_block", "id": "s1",
                                       "name": "Execute",
                                       "input": {"command": "rm -rf ~/x"}}]),
            {"type": "todo_state", "todos": []},
            {"type": "compaction_state", "summaryText": "s"},
            # written at the end of every turn: known, so not counted
            turn_outcome("turn-1"),
            turn_outcome("turn-2", "null"),
            turn_outcome("turn-3", "structured", {"answer": "rm -rf ~/x"}),
        ]
        path = self.session(lines)
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["toolu_01ABC"])
        self.assertEqual(self.droid.counts["unknown"], 2)
        # read again in the same run (clean after watch): counted once
        list(self.droid.secret_texts(self.store(path)))
        self.assertEqual(self.droid.counts["unknown"], 2)
        self.droid.reset()
        list(self.droid.secret_texts(self.store(path)))
        self.assertEqual(self.droid.counts["unknown"], 2)

    def test_a_bad_line_in_the_middle_is_counted_not_fatal(self):
        good = [_dump(l) + "\n" for l in spec_sample()]
        raw = "".join(good[:2]) + "{not json\n" + "".join(good[2:])
        path = self.session(None, raw=raw.encode("utf-8"))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(len(self.calls(path)), 1)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.droid.counts["unparsed"], 1)

    def test_a_store_that_vanished_warns_once(self):
        path = self.session(spec_sample())
        store = self.store(path)
        os.unlink(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.droid.tool_calls(store)), [])
            self.assertEqual(list(self.droid.secret_texts(store)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)
        self.assertEqual(self.droid.counts["unreadable_stores"], 1)


# --------------------------------------------------------------------------
# JSON nested deeper than Python recurses
# --------------------------------------------------------------------------

# Stands in for deeply nested JSON in a fixture, and is replaced by it in
# the bytes written: building the nesting as an object would take the very
# recursion these tests are about.
DEEP = '"@deep@"'
# Python 3.9's json.loads gives up on both. 3.14's reads both, and leaves
# the recursion to whatever walks the result next.
DEPTHS = (2000, 100000)


def _deep(depth):
    return '{"a":' * depth + "1" + "}" * depth


def _with_deep(data, depth):
    return data.replace(DEEP.encode("utf-8"), _deep(depth).encode("utf-8"))


def _found(texts):
    """Every secret clean's own walk finds in these SecretTexts."""
    out = []
    for text in texts:
        clean._walk(text.node, lambda value, *_: out.append(value))
    return out


class NestedPastTheStack(DroidCase):
    """One line or entry nested deeper than Python recurses stops nothing:
    it is counted or kept as the adapter keeps any it cannot read, and
    everything else in the store is still read."""

    def read(self, path):
        store = self.store(path)
        calls = list(self.droid.tool_calls(store))
        for call in calls:
            judge(call)
        return store, calls, list(self.droid.secret_texts(store))

    def test_a_line_nested_past_the_stack_is_skipped_and_the_rest_read(self):
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self.droid.reset()
                # the first line, where the header is read, and holding the
                # notice stores() parses a line for
                deep = ("[" * depth + _dump(droid_module._SAVED + "/x (1KB)")
                        + "]" * depth + "\n")
                rest = "".join(_dump(l) + "\n" for l in call_lines(
                    2, "toolu_01ABC", "Execute", {"command": "cat .env"},
                    "STRIPE_KEY=" + SECRET + EXIT_0))
                path = self.session(None, name="deep-%d" % depth,
                                    raw=(deep + rest).encode("utf-8"))
                store, calls, texts = self.read(path)
                self.assertEqual((store.session, store.project),
                                 ("deep-%d" % depth, None))
                self.assertEqual([c.tool_call_id for c in calls], ["toolu_01ABC"])
                self.assertIn(SECRET, calls[0].output)
                self.assertIn(SECRET, _found(texts))
                # 3.9 cannot parse it; 3.14 can, and it is not a record
                self.assertEqual(self.droid.counts["unparsed"]
                                 + self.droid.counts["unknown"], 1)

    def test_a_call_nested_past_the_stack_does_not_hide_the_next(self):
        bash = ('{"type":"bash_result","command":"env","stdout":%s,'
                '"stderr":"","exitCode":0}')
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self.droid.reset()
                lines = [
                    header(),
                    message(1, "assistant", [use("toolu_D1", "Execute",
                                                 {"command": "ls", "x": DEEP})]),
                    message(2, "user", [result("toolu_D1", [DEEP])]),
                    message(3, "assistant", [use(
                        "toolu_D2", "Execute",
                        '{"command":"ls","x":%s}' % _deep(depth))]),
                    message(4, "user", [{"type": "text",
                                         "text": bash % _deep(depth)}]),
                ] + call_lines(5, "toolu_01ABC", "Execute",
                               {"command": "cat .env"},
                               "STRIPE_KEY=" + SECRET + EXIT_0)
                raw = "".join(_dump(l) + "\n" for l in lines).encode("utf-8")
                path = self.session(None, name="calls-%d" % depth,
                                    raw=_with_deep(raw, depth))
                _store, calls, texts = self.read(path)
                by_id = {c.tool_call_id: c for c in calls}
                self.assertIn(SECRET, by_id["toolu_01ABC"].output)
                self.assertIn(SECRET, _found(texts))
                # input in a JSON string it cannot decode is kept as text
                kept = by_id["toolu_D2"].tool_input
                self.assertTrue(set(kept) == {"_raw"} or kept["command"] == "ls")

    def test_a_prompt_history_nested_past_the_stack_is_still_searched(self):
        for depth in DEPTHS:
            with self.subTest(depth=depth):
                self.droid.reset()
                path = self.write("state/history.json", None, raw=_with_deep(
                    history_file([prompt("deploy with " + SECRET), "@deep@"]),
                    depth))
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    texts = list(self.droid.secret_texts(self.store(path)))
                self.assertIn(SECRET, _found(texts))
                parsed = [t.where for t in texts] == ["entry 1", "entry 2"]
                self.assertEqual(self.droid.counts["unparsed"], 0 if parsed else 1)
                self.assertEqual(err.getvalue().count("warning:"),
                                 0 if parsed else 1)

    def test_every_command_reads_on_past_a_nested_line(self):
        depth = DEPTHS[0]
        lines = [header(),
                 message(1, "assistant", [use("toolu_D1", "Execute",
                                              {"command": "ls", "x": DEEP})]),
                 message(2, "assistant", [use(
                     "toolu_D2", "Execute",
                     '{"command":"ls","x":%s}' % _deep(depth))])]
        lines += call_lines(3, "toolu_01ABC", "Execute", {"command": "cat .env"},
                            "STRIPE_KEY=" + SECRET + EXIT_0)
        raw = "".join(_dump(l) + "\n" for l in lines).encode("utf-8")
        self.session(None, raw=_with_deep(raw, depth))
        self.write("state/history.json", None, raw=_with_deep(history_file(
            [prompt("export API_TOKEN=" + TYPED), "@deep@"]), depth))
        env = dict(os.environ, HOME=self.home, USERPROFILE=self.home,
                   RANWHAT_HOME=_tempdir(self, "droid-state-"),
                   PYTHONIOENCODING="utf-8")
        flags = ["--source", "droid", "--path", "droid=" + self.home,
                 "--days", "36500"]
        for argv in (["watch"], ["check", "--json"],
                     ["clean", "--no-interactive"],
                     ["clean", "--apply", "--no-interactive"]):
            with self.subTest(argv=argv):
                done = subprocess.run(
                    [sys.executable, "-m", "ranwhat"] + argv + flags, cwd=REPO,
                    env=env, capture_output=True, encoding="utf-8",
                    stdin=subprocess.DEVNULL, timeout=60)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertNotIn("Traceback", done.stderr)
                if argv[0] == "check":
                    found = {f["fingerprint"]
                             for f in json.loads(done.stdout)["secrets"]}
                    self.assertEqual(found, {clean._fingerprint(SECRET),
                                             clean._fingerprint(TYPED)})


class Window(DroidCase):

    def test_an_old_call_in_a_new_file_and_an_undated_one(self):
        lines = [header()]
        lines += call_lines(10, "old", "Execute", {"command": "rm -rf ~/Documents/x"},
                            output="", ts="2025-01-02T03:04:05.000Z")
        lines += call_lines(12, "recent", "Execute", {"command": "rm -rf ~/Documents/y"},
                            output="", ts=time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                                                        time.gmtime(time.time() - 3600)))
        lines.append(message(14, "assistant", [use("undated", "Execute",
                                                   {"command": "rm -rf ~/Documents/z"})],
                             ts=None))
        path = self.session(lines, age=60)
        [store] = self.stores(since_days=30)
        self.assertEqual(store.path, path)
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 30 * 86400))
        kept, undated = [], 0
        for call in self.droid.tool_calls(store):
            # design 3.5: a dated call by its own time; an undated one is
            # kept unless the last write of its store is before the cutoff
            if call.timestamp:
                if call.timestamp >= cutoff:
                    kept.append(call.tool_call_id)
            elif call.not_after and call.not_after >= cutoff:
                kept.append(call.tool_call_id)
                undated += 1
        self.assertEqual(sorted(kept), ["recent", "undated"])
        self.assertEqual(undated, 1)


# --------------------------------------------------------------------------
# A large session: how reading it grows, on its own interpreter
# (tests/growth.py)
# --------------------------------------------------------------------------

READ = r"""
from ranwhat.sources.droid import DroidSource
def call(made):
    d = DroidSource()
    stores = d.stores(d.locations(override=made["home"]))
    calls = sum(1 for s in stores for _ in d.tool_calls(s))
    texts = sum(1 for s in stores for _ in d.secret_texts(s))
    return {"stores": len(stores), "calls": calls, "texts": texts,
            "counts": d.counts}
"""

# Every log a session names, read for clean.
READ_LOGS = r"""
from ranwhat.sources.droid import DroidSource
def call(home):
    d = DroidSource()
    logs = [s for s in d.stores(d.locations(override=home)) if s.role == "side"]
    tied = sum(1 for s in logs for x in d.secret_texts(s) if x.call is not None)
    return [len(logs), tied]
"""


class Performance(unittest.TestCase):

    def _env(self):
        home = _tempdir(self, "droid-perf-home-")
        env = dict(os.environ, HOME=home, USERPROFILE=home)
        env.pop(ENV, None)
        return env

    def _session(self, n):
        """A home whose one session is n(30 MB) long, and how many calls
        it holds."""
        home = _tempdir(self, "droid-perf-")
        folder = os.path.join(home, ".factory", "sessions", "-Users-me-proj")
        os.makedirs(folder)
        path = os.path.join(folder, SID + ".jsonl")
        out = ("lorem ipsum dolor sit amet " * 24 + "\n") * 2 + EXIT_0
        i = 0
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(_dump(header()) + "\n")
            while fh.tell() < n(30 * 1024 * 1024):
                for line in call_lines(i, "toolu_%08d" % i, "Execute",
                                       {"command": "grep -rn foo src/%d" % i,
                                        "summary": "search"}, output=out):
                    fh.write(_dump(line) + "\n")
                i += 2
        return {"home": home, "calls": i // 2}

    def test_a_30mb_session_reads_well_within_budget(self):
        measured, made = growth.measure_apart(self._session, READ,
                                              env=self._env())
        growth.assert_linear(self, measured, "a 30 MB session")
        report = measured.result
        self.assertEqual(report["stores"], 1)
        self.assertEqual(report["calls"], made["calls"])
        self.assertEqual(report["counts"]["unparsed"], 0)

    def _many_logs(self, count):
        """A home whose one session ran `count` long or background commands,
        each leaving the file its result names: half terminal logs, half
        background outputs, in the session's own temp folder."""
        home = _tempdir(self, "droid-logs-")
        folder = os.path.join(home, ".factory", "sessions", "-Users-me-proj")
        terminals = os.path.join(home, "T", "droid-terminal-Perf00")
        os.makedirs(folder)
        os.makedirs(terminals)
        with open(os.path.join(folder, SID + ".jsonl"), "w", encoding="utf-8",
                  newline="") as fh:
            fh.write(_dump(header()) + "\n")
            for i in range(count):
                if i % 2:
                    log = os.path.join(home, "T", "droid-bg-%d.out" % (BG_STAMP + i))
                    output = background_result(log)
                else:
                    log = os.path.join(terminals, "8b6f0c1e-4c2d-4e5f-9a0b-%012d.log" % i)
                    # the summary cut short: only the notice matters here
                    output = ("head\n\n[... truncated 4096 bytes from middle "
                              "section ...]\n\ntail\n\nFull command output saved "
                              "to: %s (20KB)" % log + EXIT_0)
                with open(log, "w", encoding="utf-8") as out:
                    out.write("line %d\n" % i)
                for line in call_lines(2 * i + 10, "toolu_%08d" % i, "Execute",
                                       {"command": "make %d" % i}, output=output):
                    fh.write(_dump(line) + "\n")
        return home

    def test_reading_many_logs_grows_linearly(self):
        # Each Execute whose output passes 16 KiB leaves a terminal log, and
        # nothing clears them but the OS, so a long-lived machine collects
        # thousands. Finding each log's call once used to walk every log.
        logs = 8000
        measured, _home = growth.measure_apart(
            lambda n: self._many_logs(n(logs)), READ_LOGS, env=self._env())
        growth.assert_linear(self, measured, "%d logs" % logs)
        self.assertEqual(measured.result, [logs, logs])


if __name__ == "__main__":
    unittest.main()
