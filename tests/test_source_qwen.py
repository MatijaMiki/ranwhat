"""The Qwen Code adapter (design 7.6), with the common tests of design 5.2.

Fixtures are built field for field from the spec's sample ChatRecords
(v0.24.7) and, for the v0.3.x layout, from the Gemini legacy
ConversationRecord shape with message type "qwen". Fields the spec does not
list are left out. Everything runs in temp directories: the home directory,
QWEN_HOME / QWEN_RUNTIME_DIR and clean's backup root all point there. Every
secret is synthetic and written as adjacent literals.

watch.judge and clean.scan_sources do not exist yet (the wiring comes
later), so judge() and findings() below follow design 3.5 and 3.6 on top
of watch.evaluate and clean's own helpers.
"""
import contextlib
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

from ranwhat import clean, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite, _stamps, qwen  # noqa: E402
from ranwhat.sources.base import MaskResult, Store  # noqa: E402
from ranwhat.sources.qwen import QwenSource  # noqa: E402

SECRET = "sk_" "live_" "Qw3nR2mT6yLp4WcN0sXe7HbJ"      # in an output after cat .env
TYPED = "sk_" "live_" "Ty9eDk4Vb7Nq2Lm5Xc8Zr1Pw"       # typed into a command
DIFF = "ghp_" "Df8kL2mQ9xR4tY7wB3nV6cZ1aS5eH0jU2pK8"   # only in a FileDiff
SIDE = "sk_" "live_" "Hx5bPq8Rt2Wm7Kz4Nc9Ls3Dv"        # in side stores

SESSION = "3b2e6a0c-1d4f-4c8e-9a7b-2f5d8e1c0a93"
PROJECT = "/Users/dev/app"
SANITIZED = "-Users-dev-app"
PROJECT_HASH = hashlib.sha256(PROJECT.encode("utf-8")).hexdigest()

WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------
# Fixture builders (the spec's sample, field for field)
# --------------------------------------------------------------------------

def _uuid(n):
    return "a1b2c3d4-0000-4000-8000-%012d" % n


def _envelope(n, kind, stamp, provenance, session=SESSION):
    record = {"uuid": _uuid(n), "parentUuid": _uuid(n - 1) if n > 1 else None,
              "sessionId": session}
    if stamp is not None:
        record["timestamp"] = stamp
    record.update({"type": kind, "provenance": provenance, "cwd": PROJECT,
                   "version": "0.24.7", "gitBranch": "main"})
    return record


def user(n, stamp, text, **kw):
    record = _envelope(n, "user", stamp, "real_user", **kw)
    record["message"] = {"role": "user", "parts": [{"text": text}]}
    return record


def assistant(n, stamp, *calls, **kw):
    """calls: (id, name, args) for each functionCall part."""
    record = _envelope(n, "assistant", stamp, "assistant_output", **kw)
    record["model"] = "qwen3-coder-plus"
    record["message"] = {"role": "model", "parts": [
        {"functionCall": {"id": i, "name": name, "args": args}}
        for i, name, args in calls]}
    record["usageMetadata"] = {"promptTokenCount": 1200,
                               "candidatesTokenCount": 30,
                               "thoughtsTokenCount": 0,
                               "totalTokenCount": 1230,
                               "cachedContentTokenCount": 0}
    return record


def tool_result(n, stamp, call_id, name, output=None, display=None,
                error=None, **kw):
    record = _envelope(n, "tool_result", stamp, "tool_result", **kw)
    response = {"output": output} if error is None else {"error": error}
    record["message"] = {"role": "user", "parts": [
        {"functionResponse": {"id": call_id, "name": name,
                              "response": response}}]}
    record["toolCallResult"] = {"callId": call_id,
                                "status": "success" if error is None else "error",
                                "resultDisplay": output if display is None else display}
    return record


def shell_output(command, output):
    return ("Command: %s\nDirectory: (root)\nOutput: %s\nError: (none)\n"
            "Exit Code: 0\nSignal: (none)\nProcess Group PGID: 4242"
            % (command, output))


def sample(secret="example-not-a-real-key"):
    """The spec's three sample lines, with `secret` as the key in .env."""
    return [
        user(1, "2026-09-30T10:00:00.000Z", "show me the env file"),
        assistant(2, "2026-09-30T10:00:02.000Z",
                  ("call_0001", "run_shell_command",
                   {"command": "cat .env", "is_background": False,
                    "description": "Print .env"})),
        tool_result(3, "2026-09-30T10:00:03.000Z", "call_0001",
                    "run_shell_command",
                    shell_output("cat .env", "API_KEY=" + secret),
                    display="API_KEY=" + secret),
    ]


def legacy_session(secret, *extra):
    """A v0.3.x tmp/<sha256>/chats/session-*.json: Gemini's legacy
    ConversationRecord, with message type "qwen". extra: more toolCalls
    entries for the same message."""
    call = {"id": "run_shell_command-1727690112900-0",
            "name": "run_shell_command",
            "args": {"command": "cat .env"},
            "result": [{"functionResponse": {
                "id": "run_shell_command-1727690112900-0",
                "name": "run_shell_command",
                "response": {"output": shell_output("cat .env",
                                                    "API_KEY=" + secret)}}}],
            "status": "success",
            "timestamp": "2025-09-30T10:15:13.400Z",
            "resultDisplay": "API_KEY=" + secret + "\n",
            "description": "cat .env",
            "displayName": "Shell",
            "renderOutputAsMarkdown": False}
    return {
        "sessionId": "5e1d2c3b-4a59-4687-9a0b-1c2d3e4f5a6b",
        "projectHash": PROJECT_HASH,
        "startTime": "2025-09-30T10:15:02.120Z",
        "lastUpdated": "2025-09-30T10:15:13.451Z",
        "messages": [
            {"id": "m1", "timestamp": "2025-09-30T10:15:10.500Z",
             "type": "user", "content": [{"text": "what is in .env?"}]},
            {"id": "m2", "timestamp": "2025-09-30T10:15:12.900Z",
             "type": "qwen", "content": "", "toolCalls": [call] + list(extra)},
        ],
    }


def legacy_read(call_id, path, output):
    """A v0.3.x read_file toolCalls entry. Up to v0.12.x read_file took
    absolute_path, not file_path (tools/read-file.ts ReadFileToolParams)."""
    return {"id": call_id, "name": "read_file",
            "args": {"absolute_path": path},
            "result": [{"functionResponse": {"id": call_id, "name": "read_file",
                                             "response": {"output": output}}}],
            "status": "success",
            "timestamp": "2025-09-30T10:15:13.600Z",
            "resultDisplay": "",
            "description": path,
            "displayName": "ReadFile",
            "renderOutputAsMarkdown": True}


def lock_record(pid, session=SESSION, host=None, **fields):
    """A writer lock as SessionWriterLease.acquire writes it at v0.24.7
    (schema 2, active). On Linux it carries this boot and pid namespace, as
    the CLI's own does, so the pid is what decides; elsewhere
    process_start_identity is optional and is left out."""
    record = {"schema_version": 2, "state": "active", "session_id": session,
              "owner_id": "6f0c2a7e-3b1d-4e5f-8a9b-0c1d2e3f4a5b", "pid": pid}
    boot, namespace = qwen._boot_id(), qwen._pid_namespace()
    if sys.platform.startswith("linux") and boot and namespace:
        record["process_start_identity"] = "linux:%s:4242" % boot
        record["pid_namespace_id"] = namespace
    record.update({"hostname": qwen._hostname() if host is None else host,
                   "process_kind": "interactive",
                   "acquired_at": "2026-09-30T10:00:00.000Z",
                   "qwen_version": "0.24.7"})
    record.update(fields)
    return record


def _dead_pid():
    """The id of a process that has exited."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=20)
    return proc.pid


def judge(call):
    """Design 3.5's watch.judge, on top of watch.evaluate."""
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


def findings(source, store):
    """{value: set of origins} as design 3.6 credits them: the output of a
    call goes to the credential file its input names (the consumed keys
    replaced by the normalised command), anything else to no origin."""
    out = {}
    for text in source.secret_texts(store):
        origin = None
        if text.call is not None:
            call = text.call
            named = {k: v for k, v in call.tool_input.items()
                     if k not in call.consumed}
            if call.command:
                named["command"] = watch._strip_heredocs(call.command)
            if call.paths:
                named["paths"] = list(call.paths)
            origins = clean._origins(json.dumps(named, ensure_ascii=False))
            origin = origins[-1] if origins else None
        values = []
        clean._walk(text.node, lambda value, label: values.append(value))
        for value in values:
            out.setdefault(value, set()).add(origin)
    return out


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


class _Home(unittest.TestCase):
    """A temp home with no Qwen variables set, and backups kept there."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="qwen-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        env = mock.patch.dict(os.environ, {"HOME": self.home,
                                           "USERPROFILE": self.home})
        env.start()
        self.addCleanup(env.stop)
        for name in qwen.NAMES:
            os.environ.pop(name, None)       # restored by patch.dict
        p = mock.patch.object(_paths, "home", return_value=self.home)
        p.start()
        self.addCleanup(p.stop)
        backups = tempfile.mkdtemp(prefix="qwen-bk-")
        self.addCleanup(shutil.rmtree, backups, True)
        self.backups = os.path.join(backups, "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.qwen = os.path.join(self.home, ".qwen")
        self.src = QwenSource()

    def write(self, path, data, age=3600, mode=None):
        """Write a file (a list as JSON Lines for a .jsonl file, else a dict
        or list as JSON; str or bytes as is) and date it `age` seconds
        ago."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(data, list) and path.endswith(".jsonl"):
            data = "".join(json.dumps(r, separators=(",", ":")) + "\n"
                           for r in data)
        elif isinstance(data, (dict, list)):
            data = json.dumps(data, indent=2)
        if isinstance(data, str):
            data = data.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
        if mode is not None and not WINDOWS:
            os.chmod(path, mode)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def chat(self, records, name=SESSION + ".jsonl", base=None, age=3600, *sub):
        base = base or self.qwen
        return self.write(os.path.join(base, "projects", SANITIZED, "chats",
                                       *(sub + (name,))), records, age=age)

    def only_store(self, path):
        [store] = [s for s in self.src.stores(self.src.locations())
                   if s.path == path]
        return store

    def calls(self, path):
        return list(self.src.tool_calls(self.only_store(path)))


# --------------------------------------------------------------------------
# 1, 2. Where Qwen Code keeps its history
# --------------------------------------------------------------------------

class Identity(unittest.TestCase):

    def test_what_every_report_needs(self):
        src = QwenSource()
        self.assertEqual((src.id, src.name, src.unit, src.checked),
                         ("qwen", "Qwen Code", "session", "v0.24.7"))
        self.assertEqual(src.env, ("QWEN_RUNTIME_DIR", "QWEN_HOME"))
        self.assertTrue(src.path_means)
        for text in (src.path_means, qwen.FILE_HISTORY_WHY):
            self.assertNotIn("\u2014", text)

    def test_text_is_handed_over_in_pieces_clean_can_take(self):
        self.assertEqual(qwen.MAX_TEXT, clean.MAX_STRING)


class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = QwenSource()

    def test_each_platform(self):
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.qwen", "default")])
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.qwen", "default")])
        self.assertEqual(self.src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.qwen", "default")])

    def test_qwen_home(self):
        self.assertEqual(
            self.src.default_paths({"QWEN_HOME": "/q"}, "/home/u", "linux"),
            [("/q", "env QWEN_HOME"), ("/home/u/.qwen", "default")])
        self.assertEqual(
            self.src.default_paths({"QWEN_HOME": "D:\\q"}, "C:\\Users\\u", "win32"),
            [("D:\\q", "env QWEN_HOME"), ("C:\\Users\\u\\.qwen", "default")])

    def test_runtime_dir_beats_qwen_home(self):
        """The runtime folder comes first; QWEN_HOME stays, since edit
        backups live there whatever the runtime folder is."""
        env = {"QWEN_RUNTIME_DIR": "/r", "QWEN_HOME": "/q"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"), [
            ("/r", "env QWEN_RUNTIME_DIR"), ("/q", "env QWEN_HOME"),
            ("/home/u/.qwen", "default")])
        self.assertEqual(
            self.src.default_paths({"QWEN_RUNTIME_DIR": "/r"}, "/Users/u", "darwin"),
            [("/r", "env QWEN_RUNTIME_DIR"), ("/Users/u/.qwen", "default")])

    def test_an_empty_variable_is_unset(self):
        env = {"QWEN_RUNTIME_DIR": "", "QWEN_HOME": ""}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/home/u/.qwen", "default")])

    def test_dotenv_values_and_the_environment_wins(self):
        dotenv = {"QWEN_RUNTIME_DIR": ("/r", "/home/u/.qwen/.env"),
                  "QWEN_HOME": ("/q", "/home/u/.env")}
        self.assertEqual(
            self.src.default_paths({}, "/home/u", "linux", dotenv), [
                ("/r", "QWEN_RUNTIME_DIR in /home/u/.qwen/.env"),
                ("/q", "QWEN_HOME in /home/u/.env"),
                ("/home/u/.qwen", "default")])
        self.assertEqual(
            self.src.default_paths({"QWEN_HOME": "/env-q"}, "/home/u", "linux",
                                   dotenv), [
                ("/r", "QWEN_RUNTIME_DIR in /home/u/.qwen/.env"),
                ("/env-q", "env QWEN_HOME"),
                ("/home/u/.qwen", "default")])

    def test_pure(self):
        with mock.patch("os.stat", side_effect=AssertionError("stat")), \
                mock.patch("os.path.exists", side_effect=AssertionError("exists")), \
                mock.patch("builtins.open", side_effect=AssertionError("open")):
            self.src.default_paths({"QWEN_HOME": "/q"}, "/home/u", "linux")


class Locations(_Home):

    def test_the_variable_is_read_at_call_time(self):
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (self.qwen, "default", False, 0))
        moved = os.path.join(self.home, "moved")
        self.chat(sample(), base=moved)
        os.environ["QWEN_HOME"] = moved          # after import and construction
        locs = self.src.locations()
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in locs], [
            (moved, "env QWEN_HOME", True, 1),
            (self.qwen, "default", False, 0)])
        self.assertEqual(locs[0].source, "qwen")

    def test_dotenv_is_read_at_call_time_for_two_names_only(self):
        runtime = os.path.join(self.home, "runtime")
        qhome = os.path.join(self.home, "qhome")
        self.chat(sample(), base=runtime)
        env_file = self.write(os.path.join(self.qwen, ".env"), "\n".join([
            "OPENAI_API_KEY=" + SIDE,
            "QWEN_RUNTIME_DIR=" + runtime,
            "export QWEN_HOME=/replaced/by/the/last/line",
            "QWEN_HOME_EXTRA=/not/read",
            "XQWEN_HOME=/not/read",
            "# QWEN_HOME=/not/read",
            "QWEN_HOME='%s'" % qhome,
            ""]))
        self.write(os.path.join(self.home, ".env"),
                   "QWEN_HOME=/loses\nQWEN_RUNTIME_DIR=/loses\n")
        found = self.src.dotenv(self.home)
        self.assertEqual(found, {"QWEN_RUNTIME_DIR": (runtime, env_file),
                                 "QWEN_HOME": (qhome, env_file)})
        self.assertLessEqual(len(found), 2)
        self.assertNotIn(SIDE, repr(found))
        locs = self.src.locations()
        self.assertEqual([(l.path, l.how, l.found) for l in locs], [
            (runtime, "QWEN_RUNTIME_DIR in %s" % env_file, 1),
            (qhome, "QWEN_HOME in %s" % env_file, 0),
            (self.qwen, "default", 0)])
        os.environ["QWEN_RUNTIME_DIR"] = qhome    # the environment wins
        self.assertEqual(self.src.locations()[0].how, "env QWEN_RUNTIME_DIR")

    def test_home_env_file_is_used_when_the_qwen_one_does_not_say(self):
        qhome = os.path.join(self.home, "qhome")
        self.write(os.path.join(self.qwen, ".env"), "OTHER=1\n")
        home_env = self.write(os.path.join(self.home, ".env"),
                              "QWEN_HOME=%s\n" % qhome)
        self.assertEqual(self.src.dotenv(self.home),
                         {"QWEN_HOME": (qhome, home_env)})

    def test_export_and_indented_lines_count_as_dotenv_reads_them(self):
        """dotenv 17, which the CLI parses these files with, allows leading
        whitespace and an `export ` prefix."""
        qhome = os.path.join(self.home, "qhome")
        path = self.chat(sample(), base=qhome)
        env_file = os.path.join(self.qwen, ".env")
        for line in ("export QWEN_HOME=%s" % qhome, "  QWEN_HOME=%s" % qhome,
                     "\texport  QWEN_HOME = '%s'  # moved" % qhome,
                     "QWEN_HOME=`%s`" % qhome):
            self.write(env_file, "OPENAI_API_KEY=%s\n%s\n" % (SIDE, line))
            found = self.src.dotenv(self.home)
            self.assertEqual(found, {"QWEN_HOME": (qhome, env_file)}, line)
            self.assertEqual([s.path for s in self.src.stores(self.src.locations())],
                             [path], line)

    def test_a_runtime_dir_set_in_the_qwen_home_env_file(self):
        """QWEN_HOME in the environment: the CLI reads $QWEN_HOME/.env
        first (preResolveHomeEnvOverrides)."""
        qhome = os.path.join(self.home, "q")
        runtime = os.path.join(self.home, "r")
        path = self.chat(sample(), base=runtime)
        env_file = self.write(os.path.join(qhome, ".env"),
                              "QWEN_RUNTIME_DIR=%s\n" % runtime)
        os.environ["QWEN_HOME"] = qhome
        locs = self.src.locations()
        self.assertEqual([(l.path, l.how, l.found) for l in locs], [
            (runtime, "QWEN_RUNTIME_DIR in %s" % env_file, 1),
            (qhome, "env QWEN_HOME", 0),
            (self.qwen, "default", 0)])
        self.assertEqual([s.path for s in self.src.stores(locs)], [path])

    def test_a_qwen_home_found_in_a_file_has_its_own_env_file_read(self):
        """QWEN_HOME from ~/.env: the CLI then reads the .env in that
        folder too, where QWEN_RUNTIME_DIR may be."""
        qhome = os.path.join(self.home, "q")
        runtime = os.path.join(self.home, "r")
        path = self.chat(sample(), base=runtime)
        home_env = self.write(os.path.join(self.home, ".env"),
                              "QWEN_HOME=%s\n" % qhome)
        q_env = self.write(os.path.join(qhome, ".env"),
                           "QWEN_RUNTIME_DIR=%s\nQWEN_HOME=/not/read\n" % runtime)
        self.assertEqual(self.src.dotenv(self.home), {
            "QWEN_HOME": (qhome, home_env),
            "QWEN_RUNTIME_DIR": (runtime, q_env)})
        self.assertEqual([s.path for s in self.src.stores(self.src.locations())],
                         [path])

    def test_the_order_the_cli_reads_the_files_in(self):
        """First to set a name wins. QWEN_HOME unset: ~/.qwen/.env, ~/.env,
        then the found QWEN_HOME's .env. QWEN_HOME set: its .env, the legacy
        ~/.qwen/.env, then ~/.env (loadEnvironment)."""
        qhome = os.path.join(self.home, "q")
        legacy = os.path.join(self.qwen, ".env")
        home_env = os.path.join(self.home, ".env")
        q_env = os.path.join(qhome, ".env")
        self.write(legacy, "QWEN_HOME=%s\n" % qhome)
        self.write(home_env, "QWEN_RUNTIME_DIR=/from/home\n")
        self.write(q_env, "QWEN_RUNTIME_DIR=/from/q\n")
        self.assertEqual(self.src.dotenv(self.home), {
            "QWEN_HOME": (qhome, legacy),
            "QWEN_RUNTIME_DIR": ("/from/home", home_env)})
        env = {"QWEN_HOME": qhome}
        self.write(legacy, "QWEN_RUNTIME_DIR=/from/legacy\n")
        self.assertEqual(self.src.dotenv(self.home, env=env),
                         {"QWEN_RUNTIME_DIR": ("/from/q", q_env)})
        os.remove(q_env)
        self.assertEqual(self.src.dotenv(self.home, env=env),
                         {"QWEN_RUNTIME_DIR": ("/from/legacy", legacy)})
        os.remove(legacy)
        self.assertEqual(self.src.dotenv(self.home, env=env),
                         {"QWEN_RUNTIME_DIR": ("/from/home", home_env)})

    def test_a_qwen_home_with_a_tilde(self):
        runtime = os.path.join(self.home, "r")
        q_env = self.write(os.path.join(self.home, "q", ".env"),
                           "QWEN_RUNTIME_DIR=%s\n" % runtime)
        self.assertEqual(self.src.dotenv(self.home, env={"QWEN_HOME": "~/q"}),
                         {"QWEN_RUNTIME_DIR": (runtime, q_env)})

    def test_no_file_is_opened_when_both_names_are_set(self):
        self.write(os.path.join(self.qwen, ".env"), "QWEN_HOME=/x\n")
        env = {"QWEN_HOME": "/q", "QWEN_RUNTIME_DIR": "/r"}
        with mock.patch("builtins.open", side_effect=AssertionError("open")):
            self.assertEqual(self.src.dotenv(self.home, env=env), {})

    def test_path_override_wins(self):
        elsewhere = os.path.join(self.home, "elsewhere")
        path = self.chat(sample(), base=elsewhere)
        os.environ["QWEN_HOME"] = os.path.join(self.home, "ignored")
        [loc] = self.src.locations(override=elsewhere)
        self.assertEqual((loc.path, loc.how, loc.found), (elsewhere, "--path", 1))
        self.assertEqual([s.path for s in self.src.stores([loc])], [path])


class DotenvLines(unittest.TestCase):
    """_dotenv_keys reads a line as dotenv 17's LINE grammar does, for the
    two names only."""

    def setUp(self):
        folder = tempfile.mkdtemp(prefix="qwen-env-")
        self.addCleanup(shutil.rmtree, folder, True)
        self.path = os.path.join(folder, ".env")

    def keys(self, data):
        with open(self.path, "wb") as fh:
            fh.write(data.encode("utf-8"))
        return qwen._dotenv_keys(self.path, qwen.NAMES)

    def test_value_forms(self):
        cases = [
            ("QWEN_HOME=/a/b", "/a/b"),
            ("QWEN_HOME=/a/b   # moved here", "/a/b"),
            ("QWEN_HOME=/a/b#c", "/a/b"),             # unquoted ends at #
            ("QWEN_HOME='/a #b'", "/a #b"),
            ('QWEN_HOME="/a/b"', "/a/b"),
            ("QWEN_HOME=`/a/b`", "/a/b"),
            ("QWEN_HOME: /a/b", "/a/b"),
            ("   export   QWEN_HOME=/a/b", "/a/b"),
            ("QWEN_HOME =  /a/b  ", "/a/b"),
            ("QWEN_HOME=", ""),
        ]
        for line, value in cases:
            self.assertEqual(self.keys(line + "\n"), {"QWEN_HOME": value}, line)

    def test_only_the_two_names_and_the_last_setting_wins(self):
        found = self.keys("\ufeffOPENAI_API_KEY=%s\r\n"
                          "QWEN_HOME=/first\r\n"
                          "QWEN_HOME_EXTRA=/x\rMY_QWEN_HOME=/x\n"
                          "exported QWEN_HOME=/x\n"
                          "qwen_home=/x\n"
                          "# QWEN_RUNTIME_DIR=/x\n"
                          "QWEN_RUNTIME_DIR=/r\n"
                          "QWEN_HOME=/last\n" % SIDE)
        self.assertEqual(found, {"QWEN_HOME": "/last", "QWEN_RUNTIME_DIR": "/r"})
        self.assertNotIn(SIDE, repr(found))

    def test_a_missing_file_or_a_folder(self):
        self.assertEqual(qwen._dotenv_keys(self.path, qwen.NAMES), {})
        os.mkdir(self.path)
        self.assertEqual(qwen._dotenv_keys(self.path, qwen.NAMES), {})


# --------------------------------------------------------------------------
# 3. Discovery
# --------------------------------------------------------------------------

class Discovery(_Home):

    def tree(self):
        q = self.qwen
        chats = os.path.join(q, "projects", SANITIZED, "chats")
        tmp = os.path.join(q, "tmp", PROJECT_HASH)
        made = {}

        def put(rel, data, age):
            made[rel] = self.write(os.path.join(q, *rel.split("/")), data, age=age)

        put("projects/%s/chats/%s.jsonl" % (SANITIZED, SESSION), sample(), 100)
        put("projects/%s/chats/archive/0f1e2d3c-4b5a-4968-8776-655443322110.jsonl"
            % SANITIZED, sample(), 200)
        put("projects/%s/subagents/%s/agent-a7.jsonl" % (SANITIZED, SESSION),
            sample(), 300)
        put("tmp/%s/chats/session-2025-09-30T10-15-5e1d2c3b.json" % PROJECT_HASH,
            legacy_session("x"), 400)
        put("tmp/%s/run_shell_command_9f3a.output" % PROJECT_HASH, "out\n", 500)
        put("tmp/%s/grep_search_0a1b2c3d4e5f.output" % PROJECT_HASH, "out\n", 510)
        put("tmp/%s/web_fetch_0a1b2c3d4e5f.output" % PROJECT_HASH, "out\n", 520)
        put("tmp/%s/mcp__db__query_0a1b2c3d4e5f.output" % PROJECT_HASH,
            "out\n", 530)
        put("tmp/%s/tool-results/call_0001.txt" % PROJECT_HASH, "out\n", 600)
        put("tmp/%s/logs.json" % PROJECT_HASH, [], 700)
        put("tmp/%s/checkpoint-before-fix.json" % PROJECT_HASH, [], 800)
        put("tmp/%s/checkpoints/2025-06-22T10-00-00_000Z-config.py-write_file.json"
            % PROJECT_HASH, {}, 850)
        put("tmp/%s/shell_history" % PROJECT_HASH, "ls\n", 900)
        put("debug/%s.txt" % SESSION, "debug\n", 1000)
        put("file-history/%s/1/app.py" % SESSION, "x = 1\n", 1100)
        # Not stores: excluded by name, or not in the spec.
        for rel in ["projects/%s/chats/%s.ledger.jsonl" % (SANITIZED, SESSION),
                    "projects/%s/chats/%s.runtime.json" % (SANITIZED, SESSION),
                    "projects/%s/chats/%s.jsonl.stream" % (SANITIZED, SESSION),
                    "projects/%s/chats/notes.jsonl" % SANITIZED,
                    "projects/%s/subagents/%s/agent-a7.meta.json" % (SANITIZED, SESSION),
                    "tmp/not-a-hash/logs.json",
                    "tmp/not-a-hash/grep_search_0a1b2c3d4e5f.output",
                    "tmp/%s/other.txt" % PROJECT_HASH,
                    "tmp/%s/checkpoints/notes.txt" % PROJECT_HASH,
                    "tmp/session-writer-locks/%s.lock" % SESSION,
                    ".env", "settings.json", "oauth_creds.json"]:
            self.write(os.path.join(q, *rel.split("/")), "{}\n", age=50)
        self.assertTrue(os.path.isdir(chats) and os.path.isdir(tmp))
        return made

    def test_every_store_the_spec_lists_and_nothing_else(self):
        made = self.tree()
        stores = self.src.stores(self.src.locations())
        rel = lambda p: os.path.relpath(p, self.qwen).replace(os.sep, "/")
        got = [(rel(s.path), s.format, s.role, s.masking, s.session)
               for s in stores]
        self.assertEqual(got, [
            ("projects/%s/chats/%s.jsonl" % (SANITIZED, SESSION),
             "jsonl", "transcript", "rewrite", SESSION),
            ("projects/%s/chats/archive/0f1e2d3c-4b5a-4968-8776-655443322110.jsonl"
             % SANITIZED, "jsonl", "transcript", "rewrite",
             "0f1e2d3c-4b5a-4968-8776-655443322110"),
            ("projects/%s/subagents/%s/agent-a7.jsonl" % (SANITIZED, SESSION),
             "jsonl", "transcript", "rewrite", SESSION),
            ("tmp/%s/chats/session-2025-09-30T10-15-5e1d2c3b.json" % PROJECT_HASH,
             "json", "transcript", "rewrite", None),
            ("tmp/%s/run_shell_command_9f3a.output" % PROJECT_HASH,
             "text", "side", "rewrite", None),
            ("tmp/%s/grep_search_0a1b2c3d4e5f.output" % PROJECT_HASH,
             "text", "side", "rewrite", None),
            ("tmp/%s/web_fetch_0a1b2c3d4e5f.output" % PROJECT_HASH,
             "text", "side", "rewrite", None),
            ("tmp/%s/mcp__db__query_0a1b2c3d4e5f.output" % PROJECT_HASH,
             "text", "side", "rewrite", None),
            ("tmp/%s/tool-results/call_0001.txt" % PROJECT_HASH,
             "text", "side", "rewrite", None),
            ("tmp/%s/logs.json" % PROJECT_HASH, "json", "side", "rewrite", None),
            ("tmp/%s/checkpoint-before-fix.json" % PROJECT_HASH,
             "json", "side", "rewrite", None),
            ("tmp/%s/checkpoints/2025-06-22T10-00-00_000Z-config.py-write_file.json"
             % PROJECT_HASH, "json", "side", "rewrite", None),
            ("tmp/%s/shell_history" % PROJECT_HASH, "text", "side", "rewrite", None),
            ("debug/%s.txt" % SESSION, "text", "side", "rewrite", SESSION),
            ("file-history/%s/1/app.py" % SESSION, "text", "side", "read-only",
             SESSION),
        ])
        self.assertEqual(sorted(rel(p) for p in made.values()),
                         sorted(g[0] for g in got))
        for store in stores:
            self.assertEqual(store.source, "qwen")
            self.assertIsNone(store.project)     # <sanitized> cannot be reversed
            self.assertEqual(store.unit,
                             "session" if store.role == "transcript" else "file")
        self.assertEqual(stores[-1].why_read_only, qwen.FILE_HISTORY_WHY)

    def test_a_missing_root_is_no_stores(self):
        self.assertEqual(self.src.stores(self.src.locations()), [])
        self.assertEqual(
            self.src.stores(self.src.locations(override="~/nowhere")), [])

    def test_days_prefilter_by_last_write(self):
        new = self.chat(sample(), age=60)
        self.chat(sample(), name="0f1e2d3c-4b5a-4968-8776-655443322110.jsonl",
                  age=90 * 86400)
        self.assertEqual(
            [s.path for s in self.src.stores(self.src.locations(), since_days=30)],
            [new])

    def test_one_folder_reached_two_ways_is_read_once(self):
        path = self.chat(sample())
        os.environ["QWEN_RUNTIME_DIR"] = self.qwen + os.sep
        os.environ["QWEN_HOME"] = os.path.join(self.home, ".", ".qwen")
        self.assertEqual([s.path for s in self.src.stores(self.src.locations())],
                         [path])

    def test_a_home_with_glob_characters(self):
        if WINDOWS:
            self.skipTest("* is not allowed in a Windows file name")
        base = os.path.join(self.home, "we[ir]d*")
        path = self.chat(sample(), base=base)
        self.assertEqual(
            [s.path for s in self.src.stores(self.src.locations(override=base))],
            [path])


# --------------------------------------------------------------------------
# 7, 8, 14. Normalised calls: kinds, outputs, time, session, project, dedupe
# --------------------------------------------------------------------------

class ToolCalls(_Home):

    def test_the_spec_sample(self):
        path = self.chat(sample())
        [call] = self.calls(path)
        self.assertEqual(call.as_dict(), {
            "source": "qwen", "store": path, "session": SESSION,
            "project": PROJECT, "timestamp": "2026-09-30T10:00:02Z",
            "tool_name": "run_shell_command", "tool_call_id": "call_0001",
            "kind": "shell", "known": True, "actor": "agent", "status": None,
            "not_after": None, "command": "cat .env", "workdir": None,
            "paths": [],
            "tool_input": {"command": "cat .env", "is_background": False,
                           "description": "Print .env"},
            "consumed": ["command"],
            "output": shell_output("cat .env", "API_KEY=example-not-a-real-key"),
        })

    def test_shell_read_write_and_fetch_with_their_outputs(self):
        records = [
            assistant(1, "2026-09-30T11:00:00.000Z",
                      ("c1", "run_shell_command",
                       {"command": "npm test", "is_background": False,
                        "directory": "packages/api"})),
            tool_result(2, "2026-09-30T11:00:01.000Z", "c1", "run_shell_command",
                        shell_output("npm test", "ok")),
            assistant(3, "2026-09-30T11:00:02.000Z",
                      ("c2", "read_file", {"file_path": "/Users/dev/app/a.py",
                                           "offset": 0, "limit": 20})),
            tool_result(4, "2026-09-30T11:00:03.000Z", "c2", "read_file",
                        "print('a')"),
            assistant(5, "2026-09-30T11:00:04.000Z",
                      ("c3", "write_file", {"file_path": "/Users/dev/app/b.py",
                                            "content": "b = 2\n"}),
                      ("c4", "edit", {"file_path": "/Users/dev/app/a.py",
                                      "old_string": "a", "new_string": "c"})),
            tool_result(6, "2026-09-30T11:00:05.000Z", "c3", "write_file",
                        "Successfully created and wrote to new file: "
                        "/Users/dev/app/b.py."),
            tool_result(7, "2026-09-30T11:00:05.500Z", "c4", "edit",
                        "The file: /Users/dev/app/a.py has been updated.",
                        display={"originalContent": "a", "newContent": "c"}),
            assistant(8, "2026-09-30T11:00:06.000Z",
                      ("c5", "web_fetch", {}), ("c6", "web_search", {})),
            tool_result(9, "2026-09-30T11:00:07.000Z", "c5", "web_fetch",
                        error="Request failed with status 404"),
        ]
        calls = self.calls(self.chat(records))
        self.assertEqual(
            [(c.tool_call_id, c.tool_name, c.kind, c.known, c.command,
              c.workdir, c.paths, sorted(c.consumed), c.output) for c in calls], [
                ("c1", "run_shell_command", "shell", True, "npm test",
                 "packages/api", (), ["command"], shell_output("npm test", "ok")),
                ("c2", "read_file", "read", True, None, None,
                 ("/Users/dev/app/a.py",), ["file_path"], "print('a')"),
                ("c3", "write_file", "write", True, None, None,
                 ("/Users/dev/app/b.py",), [],
                 "Successfully created and wrote to new file: /Users/dev/app/b.py."),
                ("c4", "edit", "write", True, None, None,
                 ("/Users/dev/app/a.py",), [],
                 "The file: /Users/dev/app/a.py has been updated."),
                ("c5", "web_fetch", "fetch", True, None, None, (), [],
                 "Request failed with status 404"),
                ("c6", "web_search", "fetch", True, None, None, (), [], None),
            ])
        self.assertEqual([c.timestamp for c in calls], [
            "2026-09-30T11:00:00Z", "2026-09-30T11:00:02Z",
            "2026-09-30T11:00:04Z", "2026-09-30T11:00:04Z",
            "2026-09-30T11:00:06Z", "2026-09-30T11:00:06Z"])

    def test_monitor_is_read_as_a_shell_command(self):
        """monitor (tools/monitor.ts) runs `command` in a shell, in
        `directory` when given."""
        args = {"command": "tail -f logs/app.log", "description": "watch log",
                "max_events": 50, "idle_timeout_ms": 60000,
                "directory": "/Users/dev/app/api"}
        records = [
            assistant(1, "2026-09-30T11:00:00.000Z", ("m1", "monitor", dict(args))),
            tool_result(2, "2026-09-30T11:00:01.000Z", "m1", "monitor",
                        "Monitor started"),
        ]
        [call] = self.calls(self.chat(records))
        self.assertEqual(
            (call.tool_name, call.kind, call.known, call.command, call.workdir,
             call.paths, sorted(call.consumed), call.tool_input, call.output),
            ("monitor", "shell", True, "tail -f logs/app.log",
             "/Users/dev/app/api", (), ["command"], args, "Monitor started"))

    def test_read_file_took_absolute_path_up_to_v0_12(self):
        """v0.4.0 to v0.12.x wrote JSONL sessions whose read_file calls name
        the file in absolute_path."""
        records = [assistant(1, "2026-09-30T11:00:00.000Z",
                             ("r1", "read_file",
                              {"absolute_path": "/Users/dev/app/a.py",
                               "offset": 0, "limit": 20}),
                             ("r2", "read_file",
                              {"file_path": "/Users/dev/app/b.py",
                               "absolute_path": "/Users/dev/app/c.py"}))]
        calls = self.calls(self.chat(records))
        self.assertEqual([(c.kind, c.paths, sorted(c.consumed)) for c in calls], [
            ("read", ("/Users/dev/app/a.py",), ["absolute_path"]),
            ("read", ("/Users/dev/app/b.py",), ["file_path"])])

    def test_the_other_known_tools_and_unknown_names(self):
        others = ["exec", "grep_search", "glob", "list_directory", "todo_write",
                  "save_memory", "agent", "skill"]
        records = [assistant(i + 1, "2026-09-30T12:00:00.000Z",
                             ("o%d" % i, name, {}))
                   for i, name in enumerate(others + ["mcp__files__bash",
                                                      "Read_File"])]
        calls = self.calls(self.chat(records))
        self.assertEqual([(c.tool_name, c.kind, c.known) for c in calls],
                         [(n, "other", True) for n in others]
                         + [("mcp__files__bash", "other", False),
                            ("Read_File", "other", False)])

    def test_a_call_with_no_command_or_path_is_still_its_kind(self):
        records = [assistant(1, "2026-09-30T12:00:00.000Z",
                             ("s", "run_shell_command", {"is_background": True}),
                             ("r", "read_file", {"pages": "1-2"}),
                             ("x", None, {"command": "rm -rf ~/x"}))]
        calls = self.calls(self.chat(records))
        self.assertEqual([(c.kind, c.command, c.paths, c.consumed) for c in calls],
                         [("shell", None, (), frozenset()),
                          ("read", None, (), frozenset())])
        self.assertEqual(self.src.counts["unreadable_calls"], 1)

    def test_records_without_calls_and_unknown_types(self):
        records = sample() + [
            {"uuid": _uuid(9), "parentUuid": _uuid(3), "sessionId": SESSION,
             "timestamp": "2026-09-30T10:00:09.000Z", "type": "system",
             "subtype": "chat_compression", "provenance": "system",
             "cwd": PROJECT, "version": "0.24.7"},
            {"uuid": _uuid(10), "sessionId": SESSION, "type": "progress_v9",
             "timestamp": "2026-09-30T10:00:10.000Z"},
            ["not", "a", "record"],
        ]
        calls = self.calls(self.chat(records))
        self.assertEqual([c.tool_call_id for c in calls], ["call_0001"])
        self.assertEqual(self.src.counts["unknown"], 2)

    def test_dedupe_by_call_id(self):
        """A record copied into the same file again (a resumed or forked
        session) is one call."""
        records = sample()
        copy = dict(records[1], uuid=_uuid(4))
        records = records + [copy, dict(records[2], uuid=_uuid(5))]
        calls = self.calls(self.chat(records))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].timestamp, "2026-09-30T10:00:02Z")

    def test_subagent_and_archived_sessions(self):
        sub = [dict(r, agentId="a7", agentName="explorer", isSidechain=True)
               for r in sample()]
        path = self.write(os.path.join(self.qwen, "projects", SANITIZED,
                                       "subagents", SESSION, "agent-a7.jsonl"),
                          sub)
        [call] = self.calls(path)
        self.assertEqual((call.session, call.command), (SESSION, "cat .env"))
        archived = self.chat(sample(), "0f1e2d3c-4b5a-4968-8776-655443322110.jsonl",
                             None, 3600, "archive")
        [call] = self.calls(archived)
        self.assertEqual(call.tool_call_id, "call_0001")

    def test_window_an_old_call_keeps_its_own_time_an_undated_one_its_file_time(self):
        records = [
            assistant(1, "2025-01-01T00:00:00.000Z",
                      ("old", "run_shell_command", {"command": "ls"})),
            assistant(2, None, ("undated", "run_shell_command",
                                {"command": "pwd"})),
            assistant(3, "2026-09-30T10:00:00+02:00",
                      ("zoned", "run_shell_command", {"command": "id"})),
        ]
        path = self.chat(records, age=60)
        store = self.only_store(path)
        old, undated, zoned = self.src.tool_calls(store)
        self.assertEqual((old.timestamp, old.not_after),
                         ("2025-01-01T00:00:00Z", None))
        self.assertEqual((undated.timestamp, undated.not_after),
                         (None, _stamps.iso_utc(store.mtime, "s")))
        self.assertEqual(zoned.timestamp, "2026-09-30T08:00:00Z")


# --------------------------------------------------------------------------
# 4, 5, 6. Judged as watch will judge them
# --------------------------------------------------------------------------

class Judging(_Home):

    def judged(self, *calls):
        records = [assistant(i + 1, "2026-09-30T10:00:00.000Z", c)
                   for i, c in enumerate(calls)]
        return [judge(c)[0] for c in self.calls(self.chat(records))]

    def test_a_dangerous_shell_call_is_flagged_with_its_target(self):
        rm, cat = self.judged(
            ("1", "run_shell_command", {"command": "rm -rf ~/Documents/x",
                                        "is_background": False}),
            ("2", "run_shell_command", {"command": "cat ~/.aws/credentials",
                                        "is_background": False,
                                        "description": "show creds"}))
        self.assertEqual(rm[0]["rule"], "fs.destructive")
        self.assertIn("~/Documents/x", rm[0]["evidence"])
        self.assertEqual(cat[0]["rule"], "cred.read")
        self.assertIn("~/.aws/credentials", cat[0]["evidence"])

    def test_a_credential_read_by_read_file_is_flagged(self):
        [hits] = self.judged(("1", "read_file", {"file_path": "~/.ssh/id_rsa"}))
        self.assertEqual(hits[0]["rule"], "cred.read")
        self.assertIn(".ssh/id_rsa", hits[0]["evidence"])

    def test_a_credential_read_by_an_older_read_file_is_flagged(self):
        [hits] = self.judged(("1", "read_file",
                              {"absolute_path": "/Users/dev/.ssh/id_rsa"}))
        self.assertEqual(hits[0]["rule"], "cred.read")
        self.assertIn(".ssh/id_rsa", hits[0]["evidence"])

    def test_a_dangerous_monitor_command_is_flagged_with_its_target(self):
        rm, tail = self.judged(
            ("m1", "monitor", {"command": "rm -rf ~/Documents/x"}),
            ("m2", "monitor", {"command": "tail -f ~/.aws/credentials",
                               "description": "watch creds"}))
        self.assertEqual(rm[0]["rule"], "fs.destructive")
        self.assertIn("~/Documents/x", rm[0]["evidence"])
        self.assertEqual(tail[0]["rule"], "cred.read")
        self.assertIn("~/.aws/credentials", tail[0]["evidence"])

    def test_precision_carries_over(self):
        hits = self.judged(
            ("1", "run_shell_command", {"command": "grep -rn 'rm -rf' ."}),
            ("2", "run_shell_command",
             {"command": "cat <<'EOF' > notes.md\nrm -rf /\nEOF"}),
            ("3", "write_file", {"file_path": "clean.sh", "content": "rm -rf /\n"}),
            ("4", "edit", {"file_path": "clean.sh", "old_string": "echo",
                           "new_string": "rm -rf /"}),
            ("5", "run_shell_command", {"command": "ls",
                                        "description": "then rm -rf /"}))
        self.assertEqual(hits, [[], [], [], [], []])

    def test_exec_is_not_a_shell_here_but_still_is_for_openclaw(self):
        danger = {"command": "rm -rf ~/Documents/x"}
        [hits] = self.judged(("1", "exec", dict(danger)))
        self.assertEqual(hits, [])
        [hits] = self.judged(("1", "monitor", {"command": "grep -rn 'rm -rf' ."}))
        self.assertEqual(hits, [])
        self.assertEqual(watch.evaluate("exec", dict(danger))[0][0]["rule"],
                         "fs.destructive")

    def test_an_unknown_name_is_judged_by_name(self):
        [hits] = self.judged(("1", "mcp__files__bash",
                              {"command": "rm -rf ~/Documents/x"}))
        self.assertEqual(hits[0]["rule"], "fs.destructive")

    def test_a_workdir_keeps_deletion_judged_conservatively(self):
        [call] = self.calls(self.chat([assistant(
            1, "2026-09-30T10:00:00.000Z",
            ("1", "run_shell_command", {"command": "rm -rf build",
                                        "directory": "/tmp/x"}))]))
        self.assertEqual(call.workdir, "/tmp/x")
        self.assertIn("directory", call.tool_input)   # not consumed


# --------------------------------------------------------------------------
# 9. Secrets
# --------------------------------------------------------------------------

class Secrets(_Home):

    def test_output_after_cat_env_has_origin_env_and_a_typed_key_none(self):
        records = sample(SECRET) + [
            assistant(4, "2026-09-30T10:01:00.000Z",
                      ("call_0002", "run_shell_command",
                       {"command": "curl -H 'Authorization: Bearer %s' "
                                   "https://api.example.com" % TYPED,
                        "is_background": False})),
            tool_result(5, "2026-09-30T10:01:01.000Z", "call_0002",
                        "run_shell_command", shell_output("curl", "{}")),
        ]
        store = self.only_store(self.chat(records))
        self.assertEqual(findings(self.src, store),
                         {SECRET: {".env"}, TYPED: {None}})
        texts = [t for t in self.src.secret_texts(store) if t.call is not None]
        self.assertEqual(sorted(set(t.call.tool_call_id for t in texts)),
                         ["call_0001", "call_0002"])
        self.assertEqual(sorted(set(t.where for t in texts)), ["line 3", "line 5"])

    def test_every_string_on_disk_including_replaced_copies(self):
        records = sample() + [
            tool_result(4, "2026-09-30T10:00:05.000Z", "call_0009", "edit",
                        "The file: /Users/dev/app/config.py has been updated.",
                        display={"originalContent": "TOKEN = '%s'\n" % DIFF,
                                 "newContent": "TOKEN = os.environ['T']\n"}),
            {"uuid": _uuid(5), "parentUuid": _uuid(4), "sessionId": SESSION,
             "timestamp": "2026-09-30T10:00:06.000Z", "type": "system",
             "subtype": "rewind", "provenance": "system", "cwd": PROJECT,
             "version": "0.24.7", "systemPayload": {"note": "KEY=" + SIDE}},
        ]
        found = findings(self.src, self.only_store(self.chat(records)))
        self.assertEqual(found, {DIFF: {None}, SIDE: {None}})

    def test_side_stores_are_searched_with_no_call(self):
        tmp = os.path.join(self.qwen, "tmp", PROJECT_HASH)
        paths = [
            self.write(os.path.join(tmp, "run_shell_command_9f3a.output"),
                       "line 1\nAPI_KEY=%s\n" % SIDE, mode=0o600),
            self.write(os.path.join(tmp, "grep_search_0a1b2c3d4e5f.output"),
                       "config/.env:1:API_KEY=%s\n" % SIDE, mode=0o600),
            self.write(os.path.join(tmp, "mcp__db__query_0a1b2c3d4e5f.output"),
                       "token | %s\n" % SIDE, mode=0o600),
            self.write(os.path.join(
                tmp, "checkpoints",
                "2025-06-22T10-00-00_000Z-config.py-write_file.json"),
                {"history": [{"type": "user", "text": "fix config"}],
                 "clientHistory": [
                     {"role": "user", "parts": [{"text": "fix config"}]},
                     {"role": "user", "parts": [{"functionResponse": {
                         "id": "call_0001", "name": "run_shell_command",
                         "response": {"output": "API_KEY=" + SIDE}}}]}],
                 "toolCall": {"name": "write_file",
                              "args": {"file_path": "/Users/dev/app/config.py",
                                       "content": "API_KEY = None\n"}},
                 "promptId": "p-1",
                 "filePath": "/Users/dev/app/config.py"}),
            self.write(os.path.join(tmp, "tool-results", "call_0001.txt"),
                       "API_KEY=%s\n" % SIDE),
            self.write(os.path.join(tmp, "logs.json"),
                       [{"sessionId": SESSION, "messageId": 0,
                         "timestamp": "2026-09-30T10:00:00.000Z",
                         "type": "user", "message": "use " + SIDE}]),
            self.write(os.path.join(tmp, "checkpoint-fix.json"),
                       [{"role": "user", "parts": [{"text": SIDE}]}]),
            self.write(os.path.join(tmp, "shell_history"), "export K=%s\n" % SIDE),
            self.write(os.path.join(self.qwen, "debug", SESSION + ".txt"),
                       "[DEBUG] header %s\n" % SIDE),
            self.write(os.path.join(self.qwen, "file-history", SESSION, "v1",
                                    ".env"), "KEY=%s\n" % SIDE),
        ]
        for path in paths:
            store = self.only_store(path)
            self.assertEqual(store.role, "side", path)
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(findings(self.src, store), {SIDE: {None}}, path)

    def test_a_large_text_store_comes_in_pieces_of_whole_lines(self):
        line = "x" * 999 + "\n"
        count = qwen.MAX_TEXT // len(line) * 2 + 5
        path = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH,
                                       "run_shell_command_ab.output"),
                          line * count + "KEY=%s\n" % SIDE)
        texts = list(self.src.secret_texts(self.only_store(path)))
        self.assertEqual(len(texts), 3)
        self.assertTrue(all(len(t.node) <= qwen.MAX_TEXT for t in texts))
        self.assertEqual("".join(t.node for t in texts),
                         line * count + "KEY=%s\n" % SIDE)
        self.assertEqual(texts[0].where, "lines 1-1000")
        self.assertEqual(texts[-1].where, "lines 2001-%d" % (count + 1))

    def test_an_edit_backup_is_read_up_to_max_text(self):
        path = self.write(os.path.join(self.qwen, "file-history", SESSION,
                                       "big.bin"),
                          b"a" * (qwen.MAX_TEXT + 10) + SIDE.encode("ascii"))
        [text] = self.src.secret_texts(self.only_store(path))
        self.assertEqual(len(text.node), qwen.MAX_TEXT)

    def test_a_symlink_in_file_history_is_not_followed(self):
        if WINDOWS:
            self.skipTest("symlinks need privileges on Windows")
        outside = self.write(os.path.join(self.home, "outside", "secret.txt"),
                             "KEY=%s\n" % SIDE)
        folder = os.path.join(self.qwen, "file-history", SESSION)
        os.makedirs(folder)
        os.symlink(outside, os.path.join(folder, "link.txt"))
        os.symlink(os.path.dirname(outside), os.path.join(folder, "dirlink"))
        self.assertEqual(self.src.stores(self.src.locations()), [])


# --------------------------------------------------------------------------
# 10, 11, 13. Masking
# --------------------------------------------------------------------------

class Masking(_Home):

    def backup_files(self):
        return [os.path.join(d, f) for d, _s, files in os.walk(self.backups)
                for f in files]

    def round_trip(self, path, store_format):
        original = _read(path)
        store = self.only_store(path)
        self.assertEqual((store.format, store.masking), (store_format, "rewrite"))
        before = [(c.tool_name, c.tool_call_id, c.command, c.paths, c.timestamp,
                   c.session, c.project) for c in self.src.tool_calls(store)]
        if not WINDOWS:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        result = self.src.mask(store, [SECRET])
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        after = _read(path)
        self.assertEqual(after, original.replace(SECRET.encode("ascii"),
                                                 _marker(SECRET).encode("ascii")))
        text = after.decode("utf-8")
        self.assertEqual([f for f in _rewrite.encodings(SECRET) if f in text], [])
        self.assertEqual(_read(result.backup), original)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), mode)
        store = self.only_store(path)
        self.assertEqual([(c.tool_name, c.tool_call_id, c.command, c.paths,
                           c.timestamp, c.session, c.project)
                          for c in self.src.tool_calls(store)], before)
        self.assertNotIn(SECRET, repr(findings(self.src, store)))
        again = self.src.mask(store, [SECRET])
        self.assertEqual(again, MaskResult(path))
        self.assertEqual(len(self.backup_files()), 1)
        return after

    def test_jsonl_round_trip(self):
        path = self.chat(sample(SECRET))
        if not WINDOWS:
            os.chmod(path, 0o640)
            when = time.time() - 3600
            os.utime(path, (when, when))
        after = self.round_trip(path, "jsonl")
        for line in after.decode("utf-8").splitlines():
            json.loads(line)

    def test_legacy_json_round_trip(self):
        path = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH, "chats",
                                       "session-2025-09-30T10-15-5e1d2c3b.json"),
                          legacy_session(SECRET))
        json.loads(self.round_trip(path, "json").decode("utf-8"))

    def test_a_spill_file_keeps_its_0600_mode(self):
        path = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH,
                                       "run_shell_command_9f3a.output"),
                          "API_KEY=%s\n" % SECRET, mode=0o600)
        self.round_trip(path, "text")

    def test_a_checkpoint_round_trip(self):
        path = self.write(os.path.join(
            self.qwen, "tmp", PROJECT_HASH, "checkpoints",
            "2025-06-22T10-00-00_000Z-config.py-write_file.json"),
            {"clientHistory": [{"role": "user", "parts": [
                {"text": "API_KEY=" + SECRET}]}],
             "toolCall": {"name": "write_file",
                          "args": {"file_path": "config.py", "content": ""}},
             "filePath": "config.py"})
        json.loads(self.round_trip(path, "json").decode("utf-8"))

    def test_a_file_written_recently_is_in_use(self):
        path = self.chat(sample(SECRET), age=10)
        digest = _sha(path)
        self.assertEqual(self.src.mask(self.only_store(path), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)
        self.assertEqual(self.backup_files(), [])

    def test_an_edit_backup_is_read_only(self):
        path = self.write(os.path.join(self.qwen, "file-history", SESSION, "v1",
                                       "config.py"), "TOKEN = '%s'\n" % SECRET)
        digest = _sha(path)
        store = self.only_store(path)
        self.assertEqual((store.masking, store.why_read_only),
                         ("read-only", qwen.FILE_HISTORY_WHY))
        self.assertEqual(findings(self.src, store), {SECRET: {None}})
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(path, skipped="read-only"))
        self.assertEqual(_sha(path), digest)
        self.assertFalse(os.path.exists(self.backups))


class WriterLock(_Home):
    """A session whose writer lease is held is not rewritten (13): the CLI
    would find the inode and length changed and stop recording it."""

    def lock(self, record, base=None, session=SESSION):
        """Write the session's lock as the CLI does: compact JSON, at
        <base>/tmp/session-writer-locks/<session>.lock."""
        data = record if isinstance(record, str) else json.dumps(
            record, separators=(",", ":"))
        return self.write(os.path.join(base or self.qwen, "tmp",
                                       "session-writer-locks",
                                       session + ".lock"), data, age=200)

    def masked(self, path):
        return self.src.mask(self.only_store(path), [SECRET])

    def test_the_lock_sits_under_the_base_folder_of_the_transcript(self):
        base = os.path.join(self.home, "r")
        locks = os.path.join(base, "tmp", "session-writer-locks")
        project = os.path.join(base, "projects", SANITIZED)
        for path in (os.path.join(project, "chats", SESSION + ".jsonl"),
                     os.path.join(project, "chats", "archive", SESSION + ".jsonl"),
                     os.path.join(project, "subagents", SESSION, "agent-a7.jsonl")):
            self.assertEqual(QwenSource.lock_path(path),
                             os.path.join(locks, SESSION + ".lock"), path)
        for path in (os.path.join(base, "tmp", PROJECT_HASH, "chats",
                                  "session-x.json"),
                     os.path.join(base, "debug", SESSION + ".txt"),
                     os.path.join(base, "elsewhere", "chats", SESSION + ".jsonl")):
            self.assertIsNone(QwenSource.lock_path(path), path)

    def test_a_live_writer_keeps_the_session_unmasked(self):
        path = self.chat(sample(SECRET), age=200)
        archived = self.chat(sample(SECRET), SESSION + ".jsonl", None, 200, "archive")
        sub = self.write(os.path.join(self.qwen, "projects", SANITIZED, "subagents",
                                      SESSION, "agent-a7.jsonl"),
                         sample(SECRET), age=200)
        other = self.chat(sample(SECRET), "0f1e2d3c-4b5a-4968-8776-655443322110.jsonl",
                          None, 200)
        self.lock(lock_record(os.getpid()))
        for held in (path, archived, sub):
            digest = _sha(held)
            self.assertTrue(self.src.in_use(self.only_store(held)), held)
            self.assertEqual(self.masked(held), MaskResult(held, skipped="in use"))
            self.assertEqual(_sha(held), digest)
        self.assertEqual(self.backup_files(), [])
        self.assertFalse(self.src.in_use(self.only_store(other)))
        self.assertTrue(self.masked(other).changed)

    def test_a_dead_writer_does_not_block_masking(self):
        if sys.platform.startswith("linux") and not (qwen._boot_id()
                                                     and qwen._pid_namespace()):
            self.skipTest("no /proc: the CLI too takes every lock for live")
        path = self.chat(sample(SECRET), age=200)
        self.lock(lock_record(_dead_pid()))
        self.assertFalse(self.src.in_use(self.only_store(path)))
        self.assertTrue(self.masked(path).changed)

    def test_no_lock_is_not_in_use(self):
        path = self.chat(sample(SECRET), age=200)
        self.assertFalse(self.src.in_use(self.only_store(path)))

    def test_a_lock_under_the_runtime_folder(self):
        runtime = os.path.join(self.home, "r")
        os.environ["QWEN_RUNTIME_DIR"] = runtime
        path = self.chat(sample(SECRET), base=runtime, age=200)
        self.lock(lock_record(os.getpid()))             # under ~/.qwen: not it
        self.assertFalse(self.src.in_use(self.only_store(path)))
        self.lock(lock_record(os.getpid()), base=runtime)
        self.assertTrue(self.src.in_use(self.only_store(path)))

    def test_locks_that_count_as_held_whatever_their_pid(self):
        """Taken on another host; sealed for a hand-over (the next writer
        checks the transcript's sha256 and length); unreadable or not a lock
        record. Unsure is in use."""
        path = self.chat(sample(SECRET), age=200)
        dead = _dead_pid()
        sealed = lock_record(dead, state="sealed",
                             sealed_at="2026-09-30T10:05:00.000Z",
                             transcript={"relative_path": "projects/x/chats/y.jsonl",
                                         "exists": True, "byte_length": 10,
                                         "sha256": "0" * 64})
        for record in (lock_record(dead, host="another-host.example"),
                       sealed,
                       lock_record(dead, state="unknown"),
                       lock_record("4242"), lock_record(True), lock_record(0),
                       lock_record(dead, hostname=""),
                       ["not", "a", "record"], "{not json", ""):
            self.lock(record)
            self.assertTrue(self.src.in_use(self.only_store(path)), record)
        os.remove(self.lock(""))
        os.makedirs(os.path.join(self.qwen, "tmp", "session-writer-locks",
                                 SESSION + ".lock"))
        self.assertTrue(self.src.in_use(self.only_store(path)))

    def test_side_stores_and_legacy_sessions_have_no_lease(self):
        self.lock(lock_record(os.getpid()))
        for path in (
                self.write(os.path.join(self.qwen, "debug", SESSION + ".txt"),
                           "KEY=%s\n" % SECRET, age=200),
                self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH, "chats",
                                        "session-a.json"),
                           legacy_session(SECRET), age=200)):
            self.assertFalse(self.src.in_use(self.only_store(path)), path)

    def test_a_linux_writer_from_another_boot_or_namespace_is_live(self):
        """As the CLI's lockStateForRecord: on Linux a lock is judged by its
        pid only when it was taken in this boot and pid namespace."""
        dead = _dead_pid()
        record = lock_record(dead, process_start_identity="linux:abc-123:99",
                             pid_namespace_id=4026531836)
        with mock.patch.object(qwen, "_boot_id", return_value="ABC-123"), \
                mock.patch.object(qwen, "_pid_namespace", return_value=4026531836):
            self.assertFalse(qwen._writer_live(record, "linux"))
            self.assertTrue(qwen._writer_live(dict(record, pid_namespace_id=7),
                                              "linux"))
            self.assertTrue(qwen._writer_live(
                dict(record, process_start_identity="linux:def-456:99"), "linux"))
            no_identity = dict(record)
            del no_identity["process_start_identity"]
            self.assertTrue(qwen._writer_live(no_identity, "linux"))
            self.assertFalse(qwen._writer_live(no_identity, "darwin"))
        with mock.patch.object(qwen, "_boot_id", return_value=None):
            self.assertTrue(qwen._writer_live(record, "linux"))

    def test_the_host_name_is_the_one_node_records(self):
        """Node's os.hostname() is gethostname(); so is Python's
        socket.gethostname(), which the adapter does not import."""
        import socket
        self.assertEqual(qwen._hostname(), socket.gethostname())
        record = lock_record(_dead_pid())
        self.assertFalse(qwen._writer_live(record, "darwin"))
        with mock.patch.object(qwen, "_hostname", return_value=None):
            self.assertTrue(qwen._writer_live(record, "darwin"))   # unsure

    def test_pid_edge_cases(self):
        self.assertTrue(qwen._pid_alive(os.getpid()))
        self.assertFalse(qwen._pid_alive(0))
        self.assertFalse(qwen._pid_alive(-5))
        self.assertFalse(qwen._pid_alive(2 ** 40))

    def test_the_windows_check_never_signals_the_process(self):
        def answer(stdout, code=0):
            return subprocess.CompletedProcess([], code, stdout=stdout, stderr=b"")
        cases = [
            (answer(b'"node.exe","4242","Console","1","51,000 K"\r\n'), True),
            (answer(b"INFO: No tasks are running which match the criteria.\r\n"),
             False),
            (answer(b'"x.exe","42420","Console","1","1 K"\r\n'), False),
            (answer(b"", code=1), True),            # unsure: alive
            (OSError("no tasklist"), True),
        ]
        for outcome, alive in cases:
            kw = ({"side_effect": outcome} if isinstance(outcome, Exception)
                  else {"return_value": outcome})
            with mock.patch.object(qwen.subprocess, "run", **kw) as run_, \
                    mock.patch.object(qwen.os, "kill") as kill:
                with mock.patch.object(qwen.os, "name", "nt"):
                    self.assertEqual(qwen._pid_alive(4242), alive, outcome)
                kill.assert_not_called()
                self.assertEqual(run_.call_args[0][0][:3],
                                 ["tasklist", "/FI", "PID eq 4242"])

    def backup_files(self):
        return [os.path.join(d, f) for d, _s, files in os.walk(self.backups)
                for f in files]


# --------------------------------------------------------------------------
# 12. Files that do not parse
# --------------------------------------------------------------------------

class Unparsable(_Home):

    def test_a_truncated_last_line_is_skipped_quietly(self):
        data = "".join(json.dumps(r) + "\n" for r in sample())
        data += json.dumps(assistant(4, "2026-09-30T10:00:05.000Z",
                                     ("c9", "run_shell_command",
                                      {"command": "ls"})))[:60]
        path = self.chat(data)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            calls = self.calls(path)
            list(self.src.secret_texts(self.only_store(path)))
        self.assertEqual([c.tool_call_id for c in calls], ["call_0001"])
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_garbage_warns_once_and_the_other_stores_are_still_read(self):
        good = self.chat(sample())
        bad = self.chat(b"\x00\xff garbage\n\x9c more garbage\n",
                        name="0f1e2d3c-4b5a-4968-8776-655443322110.jsonl")
        legacy = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH, "chats",
                                         "session-x.json"), b"\x00{not json")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            stores = self.src.stores(self.src.locations())
            calls = [c for s in stores for c in self.src.tool_calls(s)]
            texts = [t for s in stores for t in self.src.secret_texts(s)]
        self.assertEqual(sorted(s.path for s in stores), sorted([good, bad, legacy]))
        self.assertEqual([c.store for c in calls], [good])
        self.assertTrue(texts)
        self.assertEqual(err.getvalue().count("warning:"), 2)
        self.assertIn(bad, err.getvalue())
        self.assertIn(legacy, err.getvalue())
        self.assertEqual(self.src.counts["unreadable_stores"], 2)
        self.assertEqual(self.src.unreadable, {"not JSON Lines": 1, "not JSON": 1})

    def test_a_store_that_vanished_warns_once(self):
        gone = Store("qwen", os.path.join(self.qwen, "gone.jsonl"), "jsonl")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(gone)), [])
            self.assertEqual(list(self.src.secret_texts(gone)), [])
        self.assertEqual(err.getvalue().count("warning:"), 1)

    def test_legacy_shapes_it_does_not_know_are_tolerated(self):
        doc = legacy_session(SECRET)
        doc["messages"].append({"id": "m3", "type": "gemini",
                                "toolCalls": [{"id": "g", "name": "run_shell_command",
                                               "args": {"command": "ls"}}]})
        doc["messages"].append("not a message")
        path = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH, "chats",
                                       "session-y.json"), doc)
        calls = self.calls(path)
        self.assertEqual([c.tool_call_id for c in calls],
                         ["run_shell_command-1727690112900-0"])
        weird = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH, "chats",
                                        "session-z.json"), ["a", "list"])
        self.assertEqual(self.calls(weird), [])


# --------------------------------------------------------------------------
# The v0.3.x layout
# --------------------------------------------------------------------------

class Legacy(_Home):

    def test_a_qwen_typed_session_file(self):
        path = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH, "chats",
                                       "session-2025-09-30T10-15-5e1d2c3b.json"),
                          legacy_session(SECRET))
        store = self.only_store(path)
        self.assertEqual((store.format, store.role), ("json", "transcript"))
        [call] = self.src.tool_calls(store)
        self.assertEqual(
            (call.tool_name, call.kind, call.known, call.command, call.session,
             call.project, call.timestamp, call.tool_call_id),
            ("run_shell_command", "shell", True, "cat .env",
             "5e1d2c3b-4a59-4687-9a0b-1c2d3e4f5a6b", None,
             "2025-09-30T10:15:13Z", "run_shell_command-1727690112900-0"))
        self.assertEqual(call.output, shell_output("cat .env", "API_KEY=" + SECRET))
        self.assertEqual(findings(self.src, store), {SECRET: {".env"}})

    def test_a_legacy_read_file_names_its_file_in_absolute_path(self):
        doc = legacy_session(SECRET, legacy_read(
            "read_file-1727690113000-1", "/Users/dev/.aws/credentials",
            "[default]\naws_secret_access_key = " + SIDE))
        path = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH, "chats",
                                       "session-2025-09-30T10-15-5e1d2c3b.json"),
                          doc)
        store = self.only_store(path)
        shell, read = self.src.tool_calls(store)
        self.assertEqual((read.tool_name, read.kind, read.paths,
                          sorted(read.consumed), read.timestamp),
                         ("read_file", "read", ("/Users/dev/.aws/credentials",),
                          ["absolute_path"], "2025-09-30T10:15:13Z"))
        hits, _payload = judge(read)
        self.assertEqual(hits[0]["rule"], "cred.read")
        self.assertIn(".aws/credentials", hits[0]["evidence"])
        self.assertEqual(findings(self.src, store),
                         {SECRET: {".env"}, SIDE: {"/Users/dev/.aws/credentials"}})

    def test_a_legacy_call_with_no_time_takes_its_message_time(self):
        doc = legacy_session("x")
        del doc["messages"][1]["toolCalls"][0]["timestamp"]
        path = self.write(os.path.join(self.qwen, "tmp", PROJECT_HASH, "chats",
                                       "session-a.json"), doc)
        [call] = self.calls(path)
        self.assertEqual(call.timestamp, "2025-09-30T10:15:12Z")


# --------------------------------------------------------------------------
# A large file, in a subprocess with a time limit
# --------------------------------------------------------------------------

_LARGE = r"""
import sys, time
sys.path.insert(0, sys.argv[1])
from ranwhat.sources.qwen import QwenSource
src = QwenSource()
[store] = src.stores(src.locations(override=sys.argv[2]))
start = time.time()
calls = list(src.tool_calls(store))
texts = sum(1 for _ in src.secret_texts(store))
print(len(calls), sum(1 for c in calls if c.output), texts,
      round(time.time() - start, 2))
"""


class LargeFile(_Home):

    def test_a_large_session_is_read_in_bounded_time(self):
        pairs = 20000
        call = json.dumps(assistant(2, "2026-09-30T10:00:02.000Z",
                                    ("@ID@", "run_shell_command",
                                     {"command": "cat src/file_@ID@.py",
                                      "is_background": False})),
                          separators=(",", ":"))
        result = json.dumps(tool_result(3, "2026-09-30T10:00:03.000Z", "@ID@",
                                        "run_shell_command",
                                        shell_output("cat src/file_@ID@.py",
                                                     "x = 1\\n" * 40)),
                            separators=(",", ":"))
        path = os.path.join(self.qwen, "projects", SANITIZED, "chats",
                            SESSION + ".jsonl")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8", newline="") as fh:
            for i in range(pairs):
                ident = "call_%06d" % i
                fh.write(call.replace("@ID@", ident) + "\n")
                fh.write(result.replace("@ID@", ident) + "\n")
        self.assertGreater(os.path.getsize(path), 20 * 1024 * 1024)
        env = dict(os.environ, HOME=self.home, USERPROFILE=self.home)
        out = subprocess.run([sys.executable, "-c", _LARGE, REPO, self.qwen],
                             cwd=REPO, env=env, capture_output=True, text=True,
                             encoding="utf-8", timeout=20)
        self.assertEqual(out.returncode, 0, out.stderr)
        calls, with_output, texts, _seconds = out.stdout.split()
        self.assertEqual((int(calls), int(with_output), int(texts)),
                         (pairs, pairs, pairs * 4))


if __name__ == "__main__":
    unittest.main()
