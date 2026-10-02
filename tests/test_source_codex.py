"""The Codex adapter (ranwhat/sources/codex.py), design sections 7.3 and 5.2.

Fixtures are built field for field from the samples in section 7.3, and
the builder is checked against the sample's own text. Fields the spec does
not list are left out. Every secret is synthetic and written as adjacent
literals. Everything runs in temp directories: HOME, CODEX_HOME and the
backup root all point there.

watch.judge and clean.scan_sources are not wired in yet, so judging goes
through judge() below, which is watch.judge when it exists and otherwise
the design's own judge (3.5), and origins through origin(), the design's
rule (3.6) reduced to what the adapter decides.
"""
import contextlib
import glob
import hashlib
import io
import json
import os
import shutil
import sqlite3
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
from ranwhat import sources  # noqa: E402
from ranwhat.sources import _paths, _rewrite, _shell, _stamps, _zstd, codex  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.codex import CodexSource  # noqa: E402

SECRET = "sk_" "live_" "Ab7Qw2Er9Ty4Ui1Op6As3Df"
TYPED = "sk_" "live_" "Hn5Jk8Lz2Xc6Vb9Nm3Qw7Er"
SHELL_SECRET = "ghp_" "Rt5Yu8Io2Pa6Sd9Fg3Hj7Kl1Zx4Cv0Bn2Mq"
# A password every escape level treats differently: a quote, a backslash,
# non-ASCII, & < > and U+2028.
PASSWORD = "pw" '"' "\\" "\u00e4" "&<>" "\u2028" "Tq9" "vX2r"

THREAD = "0199a0b2-1c3d-7e4f-8a5b-6c7d8e9f0a1b"
TURN = "0199a0b2-2222-7000-8000-000000000001"
DAY = "sessions/2026/10/01/"
ROLLOUT = DAY + "rollout-2026-10-01T14-00-00-" + THREAD + ".jsonl"
HEADER = ("Chunk ID: 3f9a1c\nWall time: 0.0104 seconds\nProcess exited with "
          "code 0\nOriginal token count: 7\nOutput:\n")

WINDOWS = os.name == "nt"


def _j(obj):
    """Compact JSON, non-ASCII as is: what serde_json writes."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def line(ts, typ, payload, ordinal=None):
    obj = {"timestamp": ts}
    if ordinal is not None:
        obj["ordinal"] = ordinal
    obj["type"] = typ
    obj["payload"] = payload
    return _j(obj)


def meta(mode="legacy", thread=THREAD, cwd="/home/dev/app", forked_from=None,
         cli="0.159.3", start_ordinal=None):
    """A SessionMeta payload, keys in the struct's order (protocol.rs
    SessionMeta): forked_from_id after id, subagent_history_start_ordinal
    after history_mode."""
    out = {"session_id": thread, "id": thread}
    if forked_from:
        out["forked_from_id"] = forked_from
    out.update({"timestamp": "2026-10-01T12:00:00.123Z", "cwd": cwd,
                "originator": "codex_cli_rs", "cli_version": cli,
                "source": "cli", "model_provider": "openai",
                "base_instructions": {"text": "You are Codex."},
                "history_mode": mode})
    if start_ordinal is not None:
        out["subagent_history_start_ordinal"] = start_ordinal
    return out


def fcall(name, args, call_id, **extra):
    item = {"type": "function_call", "name": name,
            "arguments": args if isinstance(args, str) else _j(args),
            "call_id": call_id}
    item.update(extra)
    return item


def fout(call_id, output):
    return {"type": "function_call_output", "call_id": call_id,
            "output": output}


def user_message(text):
    return {"type": "message", "role": "user",
            "content": [{"type": "input_text", "text": text}]}


def legacy_lines(secret):
    """Section 7.3's legacy-mode rollout."""
    return [
        line("2026-10-01T12:00:00.123Z", "session_meta", meta()),
        line("2026-10-01T12:00:05.001Z", "response_item",
             user_message("what is in .env?")),
        line("2026-10-01T12:00:07.250Z", "response_item",
             fcall("exec_command", {"cmd": "cat .env",
                                    "workdir": "/home/dev/app"}, "call_0001")),
        line("2026-10-01T12:00:07.300Z", "response_item",
             fout("call_0001", HEADER + "API_KEY=" + secret + "\n")),
    ]


def command_item(command, source, status="completed", output="",
                 item_id="call_0001", printed=False):
    """A CommandExecution item. printed=True gives every field Codex sets on
    a completed user command (protocol items.rs CommandExecutionItem, filled
    in core tasks/user_shell.rs): stdout, stderr, aggregated_output,
    exit_code, duration (a std Duration, {secs, nanos}) and formatted_output
    (the aggregated output as the model saw it), in the struct's order.
    Without it, the subset section 7.3's sample shows."""
    item = {"type": "CommandExecution", "id": item_id, "command": command,
            "cwd": "file:///home/dev/app", "parsed_cmd": [], "source": source,
            "status": status}
    if printed:
        item.update([("stdout", output), ("stderr", ""),
                     ("aggregated_output", output), ("exit_code", 0),
                     ("duration", {"secs": 0, "nanos": 10000000}),
                     ("formatted_output", output)])
    else:
        item.update([("aggregated_output", output), ("exit_code", 0)])
    return item


def user_shell_record(command, output="", kinds=("shell.user_command",)):
    """The user message Codex records for a command the user ran with `!`
    (core context/user_shell_command.rs, rendered by context-fragments
    fragment.rs). kinds=None: an older message with no classification."""
    text = ("<user_shell_command>\n<command>\n%s\n</command>\n<result>\n"
            "Exit code: 0\nDuration: 0.0100 seconds\nOutput:\n%s\n</result>\n"
            "</user_shell_command>" % (command, output))
    item = {"type": "message", "role": "user",
            "content": [{"type": "input_text", "text": text}]}
    if kinds is not None:
        item["internal_chat_message_metadata_passthrough"] = {
            "content_item_kinds": list(kinds)}
    return item


def settings_applied(thread):
    """event_msg thread_settings_applied (protocol.rs
    ThreadSettingsAppliedEvent), a few of its settings."""
    return {"type": "thread_settings_applied", "thread_id": thread,
            "thread_settings": {"model": "gpt-5-codex",
                                "model_provider_id": "openai",
                                "cwd": "/home/dev/app"}}


def completed(item, at_ms=1790856007300):
    return {"type": "item_completed", "thread_id": THREAD, "turn_id": TURN,
            "item": item, "completed_at_ms": at_ms}


def paginated_lines(secret):
    """The same rollout in paginated mode, with section 7.3's
    item_completed line."""
    lines = []
    for ordinal, text in enumerate(legacy_lines(secret)):
        obj = json.loads(text)
        if obj["type"] == "session_meta":
            obj["payload"]["history_mode"] = "paginated"
        lines.append(line(obj["timestamp"], obj["type"], obj["payload"],
                          ordinal))
    lines.append(line("2026-10-01T12:00:07.301Z", "event_msg", completed(
        command_item(["/bin/zsh", "-lc", "cat .env"], "agent",
                     output="API_KEY=" + secret + "\n")), 4))
    return lines


# Section 7.3's samples, verbatim but for the secret.
SPEC_KEY = "sk-" "test-NOT-A-REAL-KEY"
SPEC_LEGACY = [
    '{"timestamp":"2026-10-01T12:00:00.123Z","type":"session_meta","payload":{"session_id":"0199a0b2-1c3d-7e4f-8a5b-6c7d8e9f0a1b","id":"0199a0b2-1c3d-7e4f-8a5b-6c7d8e9f0a1b","timestamp":"2026-10-01T12:00:00.123Z","cwd":"/home/dev/app","originator":"codex_cli_rs","cli_version":"0.159.3","source":"cli","model_provider":"openai","base_instructions":{"text":"You are Codex."},"history_mode":"legacy"}}',  # noqa: E501
    '{"timestamp":"2026-10-01T12:00:05.001Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"what is in .env?"}]}}',  # noqa: E501
    '{"timestamp":"2026-10-01T12:00:07.250Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\\"cmd\\":\\"cat .env\\",\\"workdir\\":\\"/home/dev/app\\"}","call_id":"call_0001"}}',  # noqa: E501
    '{"timestamp":"2026-10-01T12:00:07.300Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_0001","output":"Chunk ID: 3f9a1c\\nWall time: 0.0104 seconds\\nProcess exited with code 0\\nOriginal token count: 7\\nOutput:\\nAPI_KEY=' + SPEC_KEY + '\\n"}}',  # noqa: E501
]
SPEC_PAGINATED = (
    '{"timestamp":"2026-10-01T12:00:07.301Z","ordinal":4,"type":"event_msg","payload":{"type":"item_completed","thread_id":"0199a0b2-1c3d-7e4f-8a5b-6c7d8e9f0a1b","turn_id":"0199a0b2-2222-7000-8000-000000000001","item":{"type":"CommandExecution","id":"call_0001","command":["/bin/zsh","-lc","cat .env"],"cwd":"file:///home/dev/app","parsed_cmd":[],"source":"agent","status":"completed","aggregated_output":"API_KEY=' + SPEC_KEY + '\\n","exit_code":0},"completed_at_ms":1790856007300}}')  # noqa: E501
SPEC_HISTORY = ('{"session_id":"0199a0b2-1c3d-7e4f-8a5b-6c7d8e9f0a1b",'
                '"ts":1790856005,"text":"what is in .env?"}')


def history_line(text, ts=1790856005):
    return _j({"session_id": THREAD, "ts": ts, "text": text})


def judge(call):
    """watch.judge once it exists; until then the design's judge (3.5)."""
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
    return watch.evaluate("ranwhat:%s" % call.kind, call.tool_input)


def rules(call):
    return [h["rule"] for h in judge(call)[0]]


def origin(text):
    """The origin of a secret in this SecretText, per design 3.6: the file
    it is attached as; for a call's output, the last credential path that
    call's input names (its command normalised, heredocs stripped);
    otherwise none (typed, said, or unknown)."""
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


def found_secrets(texts):
    """[(value, origin, where)] for every secret clean finds in them."""
    out = []
    for text in texts:
        values = []
        clean._walk(text.node, lambda value, _label, *_: values.append(value))
        out.extend((v, origin(text), text.where) for v in values)
    return out


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _ranwhat_temp_dirs():
    return set(x for x in os.listdir(tempfile.gettempdir())
               if x.startswith("ranwhat-"))


def _compress(data):
    """zstd bytes for `data`, or None when this machine cannot make them."""
    if _zstd._stdlib is not None:
        return _zstd._stdlib.compress(data)
    exe = shutil.which("zstd")
    if exe is None:
        return None
    return subprocess.run([exe, "-q", "-c", "--"], input=data,
                          capture_output=True, timeout=20, check=True).stdout


class _Case(unittest.TestCase):
    """A temp home with CODEX_HOME in it, and a temp backup root."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="codex-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.root = os.path.join(self.home, ".codex")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home,
                                                "CODEX_HOME": self.root}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("CODEX_SQLITE_HOME", None)
        self.backup_root = os.path.join(tempfile.mkdtemp(prefix="codex-bk-"), "b")
        self.addCleanup(shutil.rmtree, os.path.dirname(self.backup_root), True)
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backup_root)
        p.start()
        self.addCleanup(p.stop)
        self.src = CodexSource()

    def write(self, rel, content, age=3600, root=None, mode=None):
        """Write lines (a list), text or bytes under the root, aged."""
        path = os.path.join(root or self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(content, list):
            content = "".join(text + "\n" for text in content)
        if isinstance(content, str):
            content = content.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(content)
        if mode is not None and not WINDOWS:
            os.chmod(path, mode)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def store_for(self, path):
        matches = [s for s in self.src.stores(self.src.locations())
                   if s.path == path]
        self.assertEqual(len(matches), 1, path)
        return matches[0]

    def calls(self, path):
        return list(self.src.tool_calls(self.store_for(path)))

    def texts(self, path):
        return list(self.src.secret_texts(self.store_for(path)))

    def backups(self):
        return [os.path.join(d, f) for d, _s, files in os.walk(self.backup_root)
                for f in files]

    def quiet(self, fn, *args):
        """fn(*args) and what it printed on stderr."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            result = fn(*args)
        return result, err.getvalue()


# --------------------------------------------------------------------------
# The fixtures are the spec's samples
# --------------------------------------------------------------------------

class Fixtures(unittest.TestCase):

    def test_builders_reproduce_the_spec_samples(self):
        self.assertEqual(legacy_lines(SPEC_KEY), SPEC_LEGACY)
        self.assertEqual(paginated_lines(SPEC_KEY)[-1], SPEC_PAGINATED)
        self.assertEqual(history_line("what is in .env?"), SPEC_HISTORY)
        # the spec's history line time is the user message's time
        self.assertEqual(_stamps.iso_utc(1790856005, "s"), "2026-10-01T12:00:05Z")

    def test_the_adapter_says_what_reports_need(self):
        src = CodexSource()
        self.assertEqual((src.id, src.name, src.unit), ("codex", "Codex", "session"))
        self.assertEqual(src.env, ("CODEX_HOME", "CODEX_SQLITE_HOME"))
        self.assertTrue(src.path_means)
        self.assertEqual(src.checked, "rust-v0.159.3")
        if "codex" in sources.ids():            # once it is wired in
            self.assertIsInstance(sources.get("codex"), CodexSource)
            return
        try:
            sources.register(CodexSource)     # what the registry checks
            self.assertIsInstance(sources.get("codex"), CodexSource)
        finally:
            sources.unregister("codex")

    def test_user_facing_strings_have_no_em_dash(self):
        with open(codex.__file__, encoding="utf-8") as fh:
            self.assertNotIn("\u2014", fh.read())


# --------------------------------------------------------------------------
# 1, 2. Where Codex keeps things
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        src = CodexSource()
        self.assertEqual(src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.codex", "default")])
        self.assertEqual(src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.codex", "default")])
        self.assertEqual(src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.codex", "default")])

    def test_codex_home_replaces_the_default(self):
        src = CodexSource()
        self.assertEqual(src.default_paths({"CODEX_HOME": "/srv/codex"},
                                           "/home/u", "linux"),
                         [("/srv/codex", "env CODEX_HOME")])
        self.assertEqual(src.default_paths({"CODEX_HOME": "D:\\codex"},
                                           "C:\\Users\\u", "win32"),
                         [("D:\\codex", "env CODEX_HOME")])
        self.assertEqual(src.default_paths({"CODEX_HOME": ""}, "/home/u", "linux"),
                         [("/home/u/.codex", "default")])

    def test_sqlite_home_is_looked_at_beside_the_root(self):
        src = CodexSource()
        self.assertEqual(
            src.default_paths({"CODEX_SQLITE_HOME": "/var/codex-db"},
                              "/Users/u", "darwin"),
            [("/Users/u/.codex", "default"),
             ("/var/codex-db", "env CODEX_SQLITE_HOME")])
        self.assertEqual(
            src.default_paths({"CODEX_HOME": "/c", "CODEX_SQLITE_HOME": "/d"},
                              "/home/u", "linux"),
            [("/c", "env CODEX_HOME"), ("/d", "env CODEX_SQLITE_HOME")])

    def test_pure(self):
        with mock.patch("os.stat", side_effect=AssertionError("stat")), \
                mock.patch("os.path.exists", side_effect=AssertionError("exists")), \
                mock.patch("builtins.open", side_effect=AssertionError("open")):
            CodexSource().default_paths({"CODEX_SQLITE_HOME": "/d"}, "/nowhere",
                                        "linux")
            CodexSource().default_paths({}, "C:\\nowhere", "win32")


class Locations(_Case):

    def test_default_home_when_codex_home_is_unset(self):
        del os.environ["CODEX_HOME"]
        [loc] = self.src.locations()
        self.assertEqual((loc.source, loc.path, loc.how, loc.exists, loc.found),
                         ("codex", self.root, "default", False, 0))
        self.write(ROLLOUT, legacy_lines(SECRET))
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (True, 1))

    def test_override_variable_is_read_at_call_time(self):
        src = CodexSource()             # constructed before the change
        moved = os.path.join(self.home, "elsewhere")
        self.write(ROLLOUT, legacy_lines(SECRET), root=moved)
        os.environ["CODEX_HOME"] = moved
        [loc] = src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (moved, "env CODEX_HOME", True, 1))
        os.environ["CODEX_SQLITE_HOME"] = os.path.join(self.home, "db")
        locs = src.locations()
        self.assertEqual([(l.path, l.how) for l in locs], [
            (moved, "env CODEX_HOME"),
            (os.path.join(self.home, "db"), "env CODEX_SQLITE_HOME")])

    def test_codex_home_pointing_at_a_file(self):
        path = os.path.join(self.home, "codex-file")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("not a directory\n")
        os.environ["CODEX_HOME"] = path
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.exists, loc.found), (path, False, 0))
        self.assertEqual(self.src.stores([loc]), [])
        [note] = self.src.notes([loc])
        self.assertIn(path, note)
        self.assertIn("not a directory", note)
        self.assertNotIn("\u2014", note)

    def test_path_override_is_a_codex_home(self):
        os.environ["CODEX_SQLITE_HOME"] = os.path.join(self.home, "live-db")
        other = os.path.join(self.home, "copy")
        self.write(ROLLOUT, legacy_lines(SECRET), root=other)
        locs = self.src.locations(override="~/copy")
        self.assertEqual([(l.path, l.how, l.exists, l.found) for l in locs],
                         [(other, "--path", True, 1)])

    def test_locations_never_raise(self):
        with mock.patch.object(CodexSource, "default_paths",
                               side_effect=KeyError("HOME")):
            result, err = self.quiet(self.src.locations)
        self.assertEqual(result, [])
        self.assertEqual(err.count("warning:"), 1)


# --------------------------------------------------------------------------
# 3. Discovery
# --------------------------------------------------------------------------

EARLY = "0199a0b2-0000-7000-8000-00000000e001"
TS_ID = "0199a0b2-0000-7000-8000-00000000f001"
FORKED = "0199a0b2-3333-7000-8000-000000000003"
ARCHIVED = "0199a0b2-4444-7000-8000-000000000004"


def early_rust_lines():
    """An early Rust rollout: a bare header, then bare ResponseItems."""
    return [
        _j({"id": EARLY, "timestamp": "2025-05-30T10:00:00.000Z",
            "instructions": None}),
        _j(fcall("shell", {"command": ["bash", "-lc", "cat .env"]}, "call_e1")),
        _j(fout("call_e1", "API_KEY=" + SECRET + "\n")),
    ]


def typescript_doc():
    """The TypeScript CLI's rollout-*.json."""
    return _j({"session": {"timestamp": "2025-04-20T09:00:00.000Z",
                           "id": TS_ID, "instructions": ""},
               "items": [user_message("list files"),
                         fcall("shell", {"command": ["bash", "-lc",
                                                     "rm -rf ~/Documents/x"]},
                               "call_t1"),
                         fout("call_t1", _j({"output": "",
                                             "metadata": {"exit_code": 0,
                                                          "duration_seconds": 0.1}}))]})


class Discovery(_Case):

    def _tree(self):
        made = {
            "dated": self.write(ROLLOUT, legacy_lines(SECRET), age=60),
            "reverted": self.write(
                DAY + "rollout-2026-10-01T15-00-00-" + FORKED + "_"
                + "0199a0b2-5555-7000-8000-000000000005.jsonl",
                [line("2026-10-01T13:00:00.000Z", "session_meta",
                      meta(thread=FORKED, cwd="/home/dev/other"))], age=120),
            "early": self.write("sessions/rollout-2025-05-30T10-00-00-"
                                + EARLY + ".jsonl", early_rust_lines(),
                                age=400 * 86400),
            "typescript": self.write("sessions/rollout-2025-04-20-" + TS_ID
                                     + ".json", typescript_doc(),
                                     age=500 * 86400),
            "archived": self.write("archived_sessions/rollout-2026-09-01T10-00-00-"
                                   + ARCHIVED + ".jsonl",
                                   [line("2026-09-01T08:00:00.000Z",
                                         "session_meta", meta(thread=ARCHIVED))],
                                   age=30 * 86400),
            "history": self.write("history.jsonl", [history_line("hi")], age=10),
            "snapshot": self.write("shell_snapshots/" + THREAD + ".1a2b3c.sh",
                                   "# exports (native declarations)\n"
                                   "export GITHUB_TOKEN=" + SHELL_SECRET + "\n",
                                   age=200),
            "snapshot_ps": self.write("shell_snapshots/" + THREAD + ".4d5e6f.ps1",
                                      "$env:PATH = 'C:\\bin'\n", age=210),
        }
        for name in ("thread_history_1.sqlite", "state_5.sqlite"):
            path = os.path.join(self.root, name)
            sqlite3.connect(path).close()
            made[name] = path
        # Files Codex keeps that are never opened.
        for rel in ("auth.json", "session_index.jsonl", "logs_2.sqlite",
                    "log/codex-tui.log", "config.toml", DAY + "notes.txt",
                    DAY + "rollout-draft.txt", "sessions/2026/10/01/x.jsonl",
                    "shell_snapshots/readme.md", "version.json"):
            self.write(rel, "{}\n")
        return made

    def test_every_store_and_nothing_else(self):
        made = self._tree()
        stores = self.src.stores(self.src.locations())
        by_path = {s.path: s for s in stores}
        self.assertEqual(set(by_path), set(made.values()))
        expect = {
            "dated": ("jsonl", "transcript", "session", "rewrite"),
            "reverted": ("jsonl", "transcript", "session", "rewrite"),
            "early": ("jsonl", "transcript", "session", "rewrite"),
            "typescript": ("json", "transcript", "session", "rewrite"),
            "archived": ("jsonl", "transcript", "session", "rewrite"),
            "history": ("jsonl", "side", "prompt history", "rewrite"),
            "snapshot": ("text", "side", "shell snapshot", "read-only"),
            "snapshot_ps": ("text", "side", "shell snapshot", "read-only"),
            "thread_history_1.sqlite": ("sqlite", "side", "database", "read-only"),
            "state_5.sqlite": ("sqlite", "side", "database", "read-only"),
        }
        for key, (fmt, role, unit, masking) in expect.items():
            s = by_path[made[key]]
            self.assertEqual((s.source, s.format, s.role, s.unit, s.masking),
                             ("codex", fmt, role, unit, masking), key)
        # newest first, by mtime
        self.assertEqual([s.mtime for s in stores],
                         sorted((s.mtime for s in stores), reverse=True))
        self.assertEqual(by_path[made["snapshot"]].why_read_only, codex.WHY_SNAPSHOT)
        self.assertEqual(by_path[made["state_5.sqlite"]].why_read_only,
                         codex.WHY_SQLITE)
        [loc] = self.src.locations()
        self.assertEqual(loc.found, len(made))

    def test_session_and_project_from_the_store(self):
        made = self._tree()
        by_path = {s.path: s for s in self.src.stores(self.src.locations())}
        self.assertEqual((by_path[made["dated"]].session,
                          by_path[made["dated"]].project),
                         (THREAD, "/home/dev/app"))
        self.assertEqual((by_path[made["reverted"]].session,
                          by_path[made["reverted"]].project),
                         (FORKED, "/home/dev/other"))
        self.assertEqual((by_path[made["early"]].session,
                          by_path[made["early"]].project), (EARLY, None))
        self.assertEqual(by_path[made["snapshot"]].session, THREAD)
        self.assertIsNone(by_path[made["history"]].session)

    def test_a_missing_root_is_no_stores(self):
        os.environ["CODEX_HOME"] = os.path.join(self.home, "missing")
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (False, 0))
        self.assertEqual(self.src.stores([loc]), [])

    def test_days_prefilter_drops_old_files_never_databases(self):
        made = self._tree()
        old = os.path.join(self.root, "thread_history_1.sqlite")
        when = time.time() - 900 * 86400
        os.utime(old, (when, when))
        kept = set(s.path for s in self.src.stores(self.src.locations(),
                                                   since_days=7))
        self.assertIn(made["dated"], kept)
        self.assertIn(old, kept)
        self.assertNotIn(made["early"], kept)
        self.assertNotIn(made["archived"], kept)

    def test_sqlite_home_from_the_environment(self):
        made = self._tree()
        db_home = os.path.join(self.home, "codex-db")
        os.makedirs(db_home)
        moved = os.path.join(db_home, "state_5.sqlite")
        sqlite3.connect(moved).close()
        os.environ["CODEX_SQLITE_HOME"] = db_home
        locs = self.src.locations()
        self.assertEqual([(l.how, l.found) for l in locs],
                         [("env CODEX_HOME", len(made) - 2),
                          ("env CODEX_SQLITE_HOME", 1)])
        paths = set(s.path for s in self.src.stores(locs))
        self.assertIn(moved, paths)
        self.assertNotIn(made["state_5.sqlite"], paths)
        self.assertNotIn(made["thread_history_1.sqlite"], paths)

    @unittest.skipUnless(codex._tomllib(), "tomllib is Python 3.11+")
    def test_sqlite_home_from_config_toml(self):
        db_home = os.path.join(self.home, "db from config")
        os.makedirs(db_home)
        sqlite3.connect(os.path.join(db_home, "thread_history_1.sqlite")).close()
        config = self.write("config.toml",
                            'model = "o4"\nsqlite_home = %s\n\n[mcp_servers.x]\n'
                            'env = { TOKEN = "%s" }\n'
                            % (json.dumps(db_home), TYPED))
        self.write(ROLLOUT, legacy_lines(SECRET))
        locs = self.src.locations()
        self.assertEqual([(l.path, l.how, l.found) for l in locs],
                         [(self.root, "env CODEX_HOME", 1),
                          (db_home, "config " + config, 1)])
        # Codex takes config.toml's sqlite_home ahead of CODEX_SQLITE_HOME
        # (core config/mod.rs: cfg.sqlite_home.or(sqlite_home_env))
        os.environ["CODEX_SQLITE_HOME"] = os.path.join(self.home, "env-db")
        self.assertEqual([(l.path, l.how) for l in self.src.locations()],
                         [(self.root, "env CODEX_HOME"),
                          (db_home, "config " + config)])

    @unittest.skipUnless(codex._tomllib(), "tomllib is Python 3.11+")
    def test_config_wins_over_the_environment_for_the_stores_too(self):
        cfg_db = os.path.join(self.home, "cfgdb")
        env_db = os.path.join(self.home, "envdb")
        for folder in (cfg_db, env_db):
            os.makedirs(folder)
            sqlite3.connect(os.path.join(folder, "state_5.sqlite")).close()
        self.write("config.toml", "sqlite_home = %s\n" % json.dumps(cfg_db))
        os.environ["CODEX_SQLITE_HOME"] = env_db
        found = [s.path for s in self.src.stores(self.src.locations())
                 if s.format == "sqlite"]
        self.assertEqual(found, [os.path.join(cfg_db, "state_5.sqlite")])

    @unittest.skipUnless(codex._tomllib(), "tomllib is Python 3.11+")
    def test_sqlite_home_is_resolved_as_codex_resolves_it(self):
        """A relative value is taken from the folder that holds config.toml,
        and a leading ~ is the home directory (utils/absolute-path, config
        loader layer_io.rs). A file that does not parse sets nothing."""
        self.write(ROLLOUT, legacy_lines(SECRET))
        cases = [('sqlite_home = "db"\n', os.path.join(self.root, "db")),
                 ('sqlite_home = "../cfgdb"\n', os.path.join(self.home, "cfgdb")),
                 ('sqlite_home = "~/dbs/codex"\n',
                  os.path.join(self.home, "dbs", "codex")),
                 ("sqlite_home = '~'\n", self.home)]
        for text, expected in cases:
            self.write("config.toml", text)
            locs = self.src.locations()
            self.assertEqual([(l.path, l.how) for l in locs][1:],
                             [(expected, "config " + os.path.join(
                                 self.root, "config.toml"))], text)
        for text in ('sqlite_home = [\n', 'x = 1\n', 'sqlite_home = 7\n'):
            self.write("config.toml", text)
            self.assertEqual([l.how for l in self.src.locations()],
                             ["env CODEX_HOME"], text)

    def test_the_environment_value_is_trimmed_and_taken_from_here(self):
        """Codex trims CODEX_SQLITE_HOME and resolves a relative one against
        its working directory (core config/mod.rs resolve_sqlite_home_env)."""
        src = CodexSource()
        self.assertEqual(src.default_paths({"CODEX_SQLITE_HOME": "  /d \n"},
                                           "/home/u", "linux"),
                         [("/home/u/.codex", "default"),
                          ("/d", "env CODEX_SQLITE_HOME")])
        self.assertEqual(src.default_paths({"CODEX_SQLITE_HOME": " \t"},
                                           "/home/u", "linux"),
                         [("/home/u/.codex", "default")])
        os.environ["CODEX_SQLITE_HOME"] = " rel-db "
        locs = self.src.locations()
        self.assertEqual([(l.path, l.how) for l in locs][1:],
                         [(os.path.join(os.getcwd(), "rel-db"),
                           "env CODEX_SQLITE_HOME")])

    @unittest.skipIf(codex._tomllib(), "tomllib reads config.toml here")
    def test_config_toml_is_not_read_before_python_3_11(self):
        db_home = os.path.join(self.home, "db")
        self.write("config.toml", "sqlite_home = %s\n" % json.dumps(db_home))
        self.write(ROLLOUT, legacy_lines(SECRET))
        locs = self.src.locations()
        self.assertEqual([l.how for l in locs], ["env CODEX_HOME"])
        [note] = self.src.notes(locs)
        self.assertIn("sqlite_home", note)
        self.assertIn("3.11", note)


# --------------------------------------------------------------------------
# 4 to 8. Tool calls, judged
# --------------------------------------------------------------------------

def shape_lines():
    """One line per historical call shape, after the spec's legacy rollout."""
    t = "2026-10-01T12:%02d:00.000Z"
    return legacy_lines(SECRET) + [
        line(t % 1, "turn_context", {"cwd": "/home/dev/app/api"}),
        # shell (rust-v0.50 to 0.80): an argv, and a JSON-encoded output
        line(t % 2, "response_item", fcall(
            "shell", {"command": ["bash", "-lc", "rm -rf ~/Documents/x"],
                      "workdir": "/home/dev/app"}, "call_0101")),
        line(t % 2, "response_item", fout("call_0101", _j(
            {"output": "removed\n",
             "metadata": {"exit_code": 0, "duration_seconds": 0.2}}))),
        # shell_command (rust-v0.80)
        line(t % 3, "response_item", fcall(
            "shell_command", {"command": "cat ~/.aws/credentials",
                              "workdir": "/home/dev/app"}, "call_0201")),
        line(t % 3, "response_item", fout(
            "call_0201", [{"type": "input_text", "text": "[default]"},
                          {"type": "input_image", "image_url": "data:x"},
                          {"type": "input_text", "text": "region = eu"}])),
        # local_shell_call
        # models.rs LocalShellCall {call_id, status, action}; the action is
        # tagged "type" (LocalShellAction::Exec) and its unset options are
        # written as null
        line(t % 4, "response_item", {
            "type": "local_shell_call", "call_id": "call_0301",
            "status": "completed",
            "action": {"type": "exec",
                       "command": ["/bin/zsh", "-lc", "cat .env"],
                       "timeout_ms": None,
                       "working_directory": "/home/dev/app", "env": None,
                       "user": None}}),
        line(t % 4, "response_item", fout("call_0301", "API_KEY=" + SECRET)),
        # interactive input to a running process
        line(t % 5, "response_item", fcall(
            "write_stdin", {"session_id": 7, "chars": "rm -rf /\n"},
            "call_0401")),
        # apply_patch: the custom (freeform) form, and a function form
        line(t % 6, "response_item", {
            "type": "custom_tool_call", "name": "apply_patch",
            "call_id": "call_0501",
            "input": "*** Begin Patch\n*** Add File: clean.sh\n+rm -rf /\n"
                     "*** End Patch\n"}),
        line(t % 6, "response_item", {
            "type": "custom_tool_call_output", "call_id": "call_0501",
            "output": "Success. Updated the following files:\nA clean.sh\n"}),
        line(t % 7, "response_item", fcall(
            "apply_patch", {"input": "*** Begin Patch\n*** End Patch\n"},
            "call_0601")),
        # web search
        line(t % 8, "response_item", {"type": "web_search_call",
                                      "status": "completed",
                                      "action": {"type": "search",
                                                 "query": "codex rollout"}}),
        # an MCP tool, with a namespace
        line(t % 9, "response_item", fcall(
            "read_file", {"path": "~/.ssh/id_rsa"}, "call_0701",
            namespace="mcp__fs")),
    ]


class ToolCalls(_Case):

    def _calls(self, lines=None, rel=ROLLOUT, **kwargs):
        path = self.write(rel, lines if lines is not None else shape_lines(),
                          **kwargs)
        return path, {c.tool_call_id or c.tool_name: c for c in self.calls(path)}

    def test_the_spec_sample(self):
        path, calls = self._calls(legacy_lines(SECRET))
        [call] = calls.values()
        self.assertEqual(
            (call.source, call.store, call.session, call.project,
             call.timestamp, call.tool_name, call.tool_call_id, call.kind,
             call.known, call.actor, call.status, call.not_after,
             call.command, call.workdir, call.paths, call.consumed),
            ("codex", path, THREAD, "/home/dev/app", "2026-10-01T12:00:07Z",
             "exec_command", "call_0001", "shell", True, "agent", None, None,
             "cat .env", "/home/dev/app", (), frozenset(["cmd"])))
        self.assertEqual(call.tool_input, {"cmd": "cat .env",
                                           "workdir": "/home/dev/app"})
        self.assertEqual(call.output, HEADER + "API_KEY=" + SECRET + "\n")
        self.assertEqual(rules(call), ["cred.read"])

    def test_every_shape(self):
        _path, calls = self._calls()
        self.assertEqual(len(calls), 9)
        shell = calls["call_0101"]
        self.assertEqual((shell.tool_name, shell.kind, shell.command,
                          shell.workdir, shell.consumed, shell.output),
                         ("shell", "shell", "rm -rf ~/Documents/x",
                          "/home/dev/app", frozenset(["command"]), "removed\n"))
        sc = calls["call_0201"]
        self.assertEqual((sc.kind, sc.command, sc.output),
                         ("shell", "cat ~/.aws/credentials",
                          "[default]\nregion = eu"))
        local = calls["call_0301"]
        self.assertEqual((local.tool_name, local.kind, local.command,
                          local.workdir, local.consumed, local.output),
                         ("local_shell_call", "shell", "cat .env",
                          "/home/dev/app", frozenset(["command"]),
                          "API_KEY=" + SECRET))
        self.assertEqual(local.tool_input["working_directory"], "/home/dev/app")
        stdin = calls["call_0401"]
        self.assertEqual((stdin.kind, stdin.known, stdin.command),
                         ("other", True, None))
        patch = calls["call_0501"]
        self.assertEqual((patch.tool_name, patch.kind, patch.known, patch.paths),
                         ("apply_patch", "write", True, ()))
        self.assertEqual(set(patch.tool_input), {"input"})
        self.assertTrue(patch.output.startswith("Success."))
        self.assertEqual((calls["call_0601"].kind, calls["call_0601"].known),
                         ("write", True))
        web = calls["web_search_call"]
        self.assertEqual((web.kind, web.known, web.tool_call_id), ("fetch", True, None))
        self.assertEqual(web.tool_input, {"status": "completed",
                                          "action": {"type": "search",
                                                     "query": "codex rollout"}})
        mcp = calls["call_0701"]
        self.assertEqual((mcp.tool_name, mcp.kind, mcp.known),
                         ("mcp__fs.read_file", "other", False))
        # the turn's working directory is the project from that turn on
        self.assertEqual(calls["call_0001"].project, "/home/dev/app")
        self.assertEqual(shell.project, "/home/dev/app/api")

    def test_dangerous_shell_calls_are_flagged_naming_the_target(self):
        _path, calls = self._calls()
        hits, payload = judge(calls["call_0101"])
        [hit] = hits
        self.assertEqual(hit["rule"], "fs.destructive")
        self.assertIn("~/Documents/x", hit["evidence"])
        self.assertTrue(payload)
        hits, _ = judge(calls["call_0201"])
        self.assertEqual([h["rule"] for h in hits], ["cred.read"])
        self.assertIn(".aws/credentials", hits[0]["evidence"])
        self.assertEqual(rules(calls["call_0301"]), ["cred.read"])

    def test_an_argv_is_judged_as_the_script_it_ran(self):
        """["bash", "-lc", "rm -rf ~/Documents/x"] is rm -rf ~/Documents/x,
        not the words "bash -lc rm -rf ~/Documents/x"."""
        _path, calls = self._calls()
        self.assertEqual(calls["call_0101"].command, "rm -rf ~/Documents/x")
        self.assertNotIn("command", {k for k in calls["call_0101"].tool_input
                                     if k not in calls["call_0101"].consumed})

    def test_a_credential_read_through_a_read_tool_is_flagged(self):
        """Codex has no read tool of its own; an MCP one falls through to
        judgment by name, as an unknown name should."""
        _path, calls = self._calls()
        hits, _ = judge(calls["call_0701"])
        self.assertEqual([h["rule"] for h in hits], ["cred.read"])
        self.assertIn(".ssh/id_rsa", hits[0]["evidence"])

    def test_precision_carries_over(self):
        heredoc = ("cat > clean.sh <<'EOF'\nrm -rf /\nrm -rf ~/Documents\n"
                   "EOF\nchmod +x clean.sh")
        lines = [line("2026-10-01T12:00:00.123Z", "session_meta", meta()),
                 line("2026-10-01T12:00:01.000Z", "response_item", fcall(
                     "exec_command", {"cmd": "grep -rn 'rm -rf' ."}, "c1")),
                 line("2026-10-01T12:00:02.000Z", "response_item", fcall(
                     "exec_command", {"cmd": heredoc}, "c2")),
                 line("2026-10-01T12:00:03.000Z", "response_item", fcall(
                     "shell", {"command": ["bash", "-lc", "grep -rn 'rm -rf' ."]},
                     "c3"))]
        _path, calls = self._calls(lines + shape_lines()[4:])
        for cid in ("c1", "c2", "c3", "call_0501", "call_0401"):
            self.assertEqual(rules(calls[cid]), [], cid)

    def test_a_workdir_keeps_the_conservative_deletion_reading(self):
        script = 'B=/tmp/x/data ; rm -rf "$B"'
        lines = [line("2026-10-01T12:00:00.123Z", "session_meta", meta()),
                 line("2026-10-01T12:00:01.000Z", "response_item", fcall(
                     "exec_command", {"cmd": script}, "c1")),
                 line("2026-10-01T12:00:02.000Z", "response_item", fcall(
                     "exec_command", {"cmd": script, "workdir": "/home/dev/app"},
                     "c2"))]
        _path, calls = self._calls(lines)
        self.assertEqual(rules(calls["c1"]), [])
        self.assertEqual(calls["c2"].workdir, "/home/dev/app")
        self.assertEqual(rules(calls["c2"]), ["fs.destructive"])

    def test_a_typed_secret_is_flagged(self):
        lines = [line("2026-10-01T12:00:00.123Z", "session_meta", meta()),
                 line("2026-10-01T12:00:01.000Z", "response_item", fcall(
                     "exec_command", {"cmd": "export STRIPE_KEY=" + TYPED},
                     "c1"))]
        _path, calls = self._calls(lines)
        self.assertEqual(rules(calls["c1"]), ["secret.literal"])

    def test_user_shell_commands_are_the_users_own(self):
        t = "2026-10-01T12:05:%02d.000Z"
        lines = paginated_lines(SECRET) + [
            line(t % 1, "event_msg", completed(command_item(
                ["/bin/zsh", "-lc", "rm -rf ~/Documents/x"], "user_shell",
                item_id="u1", printed=True), at_ms=1790856301000), 5),
            # paginated mode records the same command as a message too
            line(t % 1, "response_item",
                 user_shell_record("rm -rf ~/Documents/x"), 5),
            line(t % 2, "event_msg", completed(command_item(
                ["/bin/zsh", "-lc", "cat ~/.ssh/id_rsa"], "user_shell",
                status="declined", item_id="u2"), at_ms=1790856302000), 6),
            # older Extended mode
            line(t % 3, "event_msg", {"type": "exec_command_end",
                                      "command": ["bash", "-lc", "ls -la"],
                                      "cwd": "/home/dev/app",
                                      "source": "user_shell"}, 7),
            line(t % 4, "event_msg", {"type": "exec_command_end",
                                      "command": ["bash", "-lc", "ls"],
                                      "cwd": "/home/dev/app",
                                      "source": "agent"}, 8),
        ]
        _path, calls = self._calls(lines)
        # The agent's CommandExecution and exec_command_end twin its
        # function_call line, which is the one reported.
        self.assertEqual(sorted(calls), ["call_0001", "u1", "u2", "user_shell"])
        ran = calls["u1"]
        self.assertEqual(
            (ran.tool_name, ran.kind, ran.known, ran.actor, ran.status,
             ran.command, ran.workdir, ran.timestamp, ran.consumed),
            ("user_shell", "shell", True, "user", None, "rm -rf ~/Documents/x",
             _shell.file_uri_to_path("file:///home/dev/app"),
             "2026-10-01T12:05:01Z", frozenset(["command"])))
        self.assertEqual(ran.output, "")
        self.assertEqual(rules(ran), ["fs.destructive"])
        declined = calls["u2"]
        self.assertEqual((declined.actor, declined.status), ("user", "declined"))
        old = calls["user_shell"]
        self.assertEqual((old.actor, old.command, old.workdir, old.timestamp),
                         ("user", "ls -la", "/home/dev/app",
                          "2026-10-01T12:05:03Z"))

    def test_time_session_project(self):
        _path, calls = self._calls()
        for call in calls.values():
            self.assertEqual(call.session, THREAD)
            self.assertTrue(call.timestamp.endswith("Z"), call.timestamp)
            self.assertIsNone(call.not_after)
        self.assertEqual(calls["call_0001"].timestamp, "2026-10-01T12:00:07Z")
        self.assertEqual(calls["call_0101"].timestamp, "2026-10-01T12:02:00Z")

    def test_paginated_mode_is_read(self):
        _path, calls = self._calls(paginated_lines(SECRET))
        self.assertEqual(list(calls), ["call_0001"])
        self.assertEqual(calls["call_0001"].command, "cat .env")

    def test_compacted_history_and_copied_lines_are_reported_once(self):
        lines = shape_lines()
        copy = [json.loads(lines[2])["payload"], json.loads(lines[3])["payload"],
                json.loads(lines[-4])["payload"],     # the web search
                {"type": "function_call", "name": "exec_command",
                 "arguments": _j({"cmd": "ls"}), "call_id": "call_only_here"}]
        lines += [line("2026-10-01T13:00:00.000Z", "compacted",
                       {"replacement_history": copy}),
                  lines[2],                         # a fork's copy of the line
                  line("2026-10-01T13:00:01.000Z", "response_item",
                       {"type": "web_search_call", "status": "completed",
                        "action": {"type": "search", "query": "again"}})]
        path = self.write(ROLLOUT, lines)
        calls = self.calls(path)
        ids = [c.tool_call_id or c.tool_input["action"]["query"] for c in calls]
        self.assertEqual(sorted(ids), sorted([
            "call_0001", "call_0101", "call_0201", "call_0301", "call_0401",
            "call_0501", "call_0601", "call_0701", "codex rollout", "again",
            "call_only_here"]))
        first = [c for c in calls if c.tool_call_id == "call_0001"][0]
        self.assertEqual(first.timestamp, "2026-10-01T12:00:07Z")
        only = [c for c in calls if c.tool_call_id == "call_only_here"][0]
        self.assertEqual((only.timestamp, only.not_after),
                         (None, "2026-10-01T13:00:00Z"))

    def test_a_flat_early_rust_file(self):
        path = self.write("sessions/rollout-2025-05-30T10-00-00-" + EARLY
                          + ".jsonl", early_rust_lines())
        [call] = self.calls(path)
        mtime = _stamps.iso_utc(os.stat(path).st_mtime, "s")
        self.assertEqual((call.session, call.tool_name, call.command,
                          call.timestamp, call.not_after, call.output),
                         (EARLY, "shell", "cat .env", None, mtime,
                          "API_KEY=" + SECRET + "\n"))
        self.assertEqual(rules(call), ["cred.read"])

    def test_a_typescript_document(self):
        path = self.write("sessions/rollout-2025-04-20-" + TS_ID + ".json",
                          typescript_doc())
        [call] = self.calls(path)
        mtime = _stamps.iso_utc(os.stat(path).st_mtime, "s")
        self.assertEqual((call.session, call.command, call.timestamp,
                          call.not_after, call.output),
                         (TS_ID, "rm -rf ~/Documents/x", None, mtime, ""))
        self.assertEqual(rules(call), ["fs.destructive"])

    def test_side_stores_have_no_calls(self):
        path = self.write("history.jsonl", [history_line("rm -rf ~")])
        self.assertEqual(self.calls(path), [])

    def test_a_record_of_the_wrong_shape_does_not_stop_the_file(self):
        lines = legacy_lines(SECRET)
        lines.insert(2, line("2026-10-01T12:00:06.000Z", "response_item", {
            "type": "function_call", "name": ["exec_command"],
            "arguments": _j({"cmd": "ls"}), "call_id": {"odd": 1}}))
        lines.insert(3, line("2026-10-01T12:00:06.500Z", "compacted",
                             {"replacement_history": ["not an item", 7]}))
        lines.insert(4, line("2026-10-01T12:00:06.700Z", "event_msg",
                             {"type": "item_completed", "item": "odd"}))
        path, calls = self._calls(lines)
        self.assertEqual(sorted(calls), ["call_0001", "function_call"])
        self.assertEqual(calls["function_call"].known, False)
        found = found_secrets(self.texts(path))
        self.assertEqual([(v, o) for v, o, _w in found], [(SECRET, ".env")])

    def test_unknown_records_are_ignored_and_counted(self):
        lines = legacy_lines(SECRET) + [
            line("2026-10-01T12:09:00.000Z", "a_future_record", {"x": 1}),
            line("2026-10-01T12:09:01.000Z", "response_item",
                 {"type": "a_future_item", "cmd": "rm -rf ~"}),
            line("2026-10-01T12:09:02.000Z", "event_msg",
                 {"type": "agent_message", "message": "done"}),
            "[1, 2]",
        ]
        _path, calls = self._calls(lines)
        self.assertEqual(list(calls), ["call_0001"])
        self.assertEqual(self.src.counts["unknown"], 3)
        self.assertEqual(self.src.counts["unparsed"], 0)


# --------------------------------------------------------------------------
# 9. Secrets
# --------------------------------------------------------------------------

class Secrets(_Case):

    def test_a_key_read_out_of_env_is_found_once_with_its_origin(self):
        lines = paginated_lines(SECRET) + [
            line("2026-10-01T12:01:00.000Z", "response_item", fcall(
                "exec_command", {"cmd": "echo STRIPE_KEY=" + TYPED}, "c9"), 5),
            line("2026-10-01T12:01:00.100Z", "response_item",
                 fout("c9", "STRIPE_KEY=" + TYPED + "\n"), 6)]
        path = self.write(ROLLOUT, lines)
        found = found_secrets(self.texts(path))
        self.assertEqual(set(v for v, _o, _w in found), {SECRET, TYPED})
        from_env = [(o, w) for v, o, w in found if v == SECRET]
        # the output line, and the paginated copy of the same output
        self.assertEqual(from_env, [(".env", "line 4"), (".env", "line 5")])
        typed = [(o, w) for v, o, w in found if v == TYPED]
        self.assertEqual(typed, [(None, "line 6"), (None, "line 7")])

    def test_every_shape_gives_its_output_an_origin(self):
        lines = shape_lines() + [
            line("2026-10-01T12:10:00.000Z", "event_msg", completed(command_item(
                ["/bin/zsh", "-lc", "cat .env"], "user_shell", item_id="u1",
                output="API_KEY=" + SECRET + "\n", printed=True))),
            line("2026-10-01T12:11:00.000Z", "event_msg", {
                "type": "exec_command_end", "command": ["bash", "-lc", "cat .env"],
                "cwd": "/home/dev/app", "source": "user_shell"})]
        path = self.write(ROLLOUT, lines)
        texts = self.texts(path)
        found = [(v, o) for v, o, _w in found_secrets(texts)]
        self.assertEqual(set(found), {(SECRET, ".env")})
        # each output came with the call that produced it
        outputs = [t for t in texts if t.call is not None]
        self.assertEqual(sorted(t.call.tool_call_id or t.call.tool_name
                                for t in outputs),
                         ["call_0001", "call_0101", "call_0201", "call_0301",
                          "call_0501", "u1", "user_shell"])

    def test_json_in_strings_is_read_decoded(self):
        lines = legacy_lines(SECRET) + [
            line("2026-10-01T12:02:00.000Z", "response_item", fcall(
                "shell", {"command": ["bash", "-lc", "cat .env"]}, "c5")),
            line("2026-10-01T12:02:00.100Z", "response_item", fout("c5", _j(
                {"output": "DB_PASSWORD=" + PASSWORD + "x9Lk2Qw8\n",
                 "metadata": {"exit_code": 0, "duration_seconds": 0.01}})))]
        path = self.write(ROLLOUT, lines)
        texts = self.texts(path)
        call_line = [t for t in texts if t.where == "line 5"][0]
        self.assertEqual(call_line.node["payload"]["arguments"],
                         {"command": ["bash", "-lc", "cat .env"]})
        out = [t for t in texts if t.where == "line 6"][0]
        self.assertEqual(out.node["payload"]["output"]["output"],
                         "DB_PASSWORD=" + PASSWORD + "x9Lk2Qw8\n")
        self.assertEqual(out.call.command, "cat .env")

    def test_encrypted_content_is_never_scanned(self):
        blob = "gAAAAB" + SECRET + "-" + TYPED
        lines = legacy_lines(SECRET) + [
            line("2026-10-01T12:03:00.000Z", "response_item",
                 {"type": "reasoning", "encrypted_content": blob}),
            line("2026-10-01T12:04:00.000Z", "compacted", {
                "replacement_history": [
                    {"type": "reasoning", "encrypted_content": blob},
                    {"type": "compaction", "encrypted_content": blob}]})]
        path = self.write(ROLLOUT, lines)
        texts = self.texts(path)
        dumped = json.dumps([t.node for t in texts])
        self.assertNotIn(TYPED, dumped)
        self.assertNotIn("encrypted_content", dumped)
        self.assertEqual(set(v for v, _o, _w in found_secrets(texts)), {SECRET})

    def test_side_stores(self):
        history = self.write("history.jsonl", [
            history_line("what is in .env?"),
            history_line("use STRIPE_KEY=" + TYPED + " for this")])
        snapshot = self.write("shell_snapshots/" + THREAD + ".1a2b3c.sh",
                              "# exports (native declarations)\n"
                              "export GITHUB_TOKEN=" + SHELL_SECRET + "\n")
        self.assertEqual([(v, o) for v, o, _w in
                          found_secrets(self.texts(history))], [(TYPED, None)])
        self.assertEqual([(v, o, w) for v, o, w in
                          found_secrets(self.texts(snapshot))],
                         [(SHELL_SECRET, None, "whole file")])

    def test_databases_are_read_in_full(self):
        writer = _databases(self.root)
        try:
            found = []
            for name in ("thread_history_1.sqlite", "state_5.sqlite"):
                found += found_secrets(self.texts(os.path.join(self.root, name)))
        finally:
            writer.close()
        self.assertEqual(sorted((v, w) for v, _o, w in found), sorted([
            (SECRET, "thread_items row 1, item_json"),
            (SECRET, "thread_items row 3, item_json"),
            (TYPED, "threads row 1, first_user_message")]))


def _databases(folder):
    """Codex's two databases with the spec's tables and columns, the first
    left open by a writer so its rows are still in the -wal."""
    path = os.path.join(folder, "thread_history_1.sqlite")
    os.makedirs(folder, exist_ok=True)
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("CREATE TABLE thread_items (item_json TEXT)")
    writer.commit()
    writer.close()
    writer = sqlite3.connect(path)
    writer.executemany("INSERT INTO thread_items VALUES (?)", [
        (_j(fout("call_0001", "API_KEY=" + SECRET)),),
        (_j({"type": "reasoning", "encrypted_content": "gAAAAB" + TYPED}),),
        ("API_KEY=" + SECRET + " not json",),
        (None,)])
    writer.commit()
    state = os.path.join(folder, "state_5.sqlite")
    conn = sqlite3.connect(state)
    conn.execute("CREATE TABLE threads (title TEXT, first_user_message TEXT)")
    conn.execute("INSERT INTO threads VALUES (?, ?)",
                 ("Set up Stripe", "use STRIPE_KEY=" + TYPED))
    conn.commit()
    conn.close()
    return writer


# --------------------------------------------------------------------------
# 10. Masking round trip
# --------------------------------------------------------------------------

def masked_rollout(secret, password):
    """The spec's rollout, a password typed into a command, and the same
    command in a compacted copy: the password sits two JSON levels deep."""
    typed = fcall("exec_command", {"cmd": "mysql -p'" + password + "' app",
                                   "workdir": "/home/dev/app"}, "call_0002")
    return legacy_lines(secret) + [
        line("2026-10-01T12:01:00.000Z", "response_item", typed),
        line("2026-10-01T12:01:00.050Z", "response_item",
             fout("call_0002", HEADER + "ERROR 1045\n")),
        line("2026-10-01T12:02:00.000Z", "compacted",
             {"replacement_history": [typed]}),
    ]


class Masking(_Case):

    def _round_trip(self, rel, build, values, kind_check):
        original = build(*values)
        path = self.write(rel, original, mode=0o640)
        raw = self.read(path)
        expected = build(*[_marker(v) for v in values])
        expected = ("".join(t + "\n" for t in expected)
                    if isinstance(expected, list) else expected).encode("utf-8")
        before = [(c.tool_name, c.tool_call_id, c.timestamp, c.kind)
                  for c in self.calls(path)]
        store = self.store_for(path)
        result = self.src.mask(store, values)
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        after = self.read(path)
        self.assertEqual(after, expected, "a byte other than the secret changed")
        text = after.decode("utf-8")
        for value in values:
            for form in _rewrite.encodings(value):
                self.assertNotIn(form, text)
        kind_check(text)
        self.assertEqual([(c.tool_name, c.tool_call_id, c.timestamp, c.kind)
                          for c in self.calls(path)], before)
        self.assertEqual(self.backups(), [result.backup])
        self.assertEqual(self.read(result.backup), raw)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(os.stat(result.backup).st_mode), 0o600)
        self.assertEqual(glob.glob(path + "*.ranwhat-tmp"), [])
        again = self.src.mask(self.store_for(path), values)
        self.assertEqual(again, MaskResult(path))
        self.assertEqual(self.read(path), expected)
        self.assertEqual(len(self.backups()), 1)
        return path

    def test_a_rollout(self):
        def check(text):
            lines = text.split("\n")
            self.assertEqual(lines[-1], "")
            for raw in lines[:-1]:
                json.loads(raw)
            args = json.loads(json.loads(lines[4])["payload"]["arguments"])
            self.assertEqual(args["cmd"], "mysql -p'%s' app" % _marker(PASSWORD))
            copy = json.loads(lines[6])["payload"]["replacement_history"][0]
            self.assertEqual(json.loads(copy["arguments"])["cmd"], args["cmd"])
        path = self._round_trip(ROLLOUT, masked_rollout, [SECRET, PASSWORD], check)
        calls = {c.tool_call_id: c for c in self.calls(path)}
        self.assertEqual(calls["call_0001"].output,
                         HEADER + "API_KEY=" + _marker(SECRET) + "\n")
        self.assertEqual(calls["call_0002"].command,
                         "mysql -p'%s' app" % _marker(PASSWORD))

    def test_history_jsonl(self):
        def build(value):
            return [history_line("what is in .env?"),
                    history_line("use STRIPE_KEY=" + value)]

        def check(text):
            self.assertEqual(json.loads(text.split("\n")[1])["text"],
                             "use STRIPE_KEY=" + _marker(TYPED))
        self._round_trip("history.jsonl", build, [TYPED], check)

    def test_a_typescript_document(self):
        def build(value):
            doc = json.loads(typescript_doc())
            doc["items"][2]["output"] = _j({"output": "KEY=" + value,
                                            "metadata": {"exit_code": 0}})
            return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"

        def check(text):
            out = json.loads(json.loads(text)["items"][2]["output"])
            self.assertEqual(out["output"], "KEY=" + _marker(PASSWORD))
        self._round_trip("sessions/rollout-2025-04-20-" + TS_ID + ".json",
                         build, [PASSWORD], check)

    def test_a_user_shell_record(self):
        def build(value):
            return legacy_lines("x") + [line(
                "2026-10-01T12:20:00.000Z", "response_item",
                user_shell_record("cat .env", "API_KEY=" + value))]

        def check(text):
            item = json.loads(text.split("\n")[4])["payload"]
            self.assertEqual(item, user_shell_record(
                "cat .env", "API_KEY=" + _marker(SECRET)))
        path = self._round_trip(ROLLOUT, build, [SECRET], check)
        [ran] = [c for c in self.calls(path) if c.actor == "user"]
        self.assertEqual(ran.output, "API_KEY=" + _marker(SECRET))


# --------------------------------------------------------------------------
# 11. Read-only stores
# --------------------------------------------------------------------------

class ReadOnly(_Case):

    def test_databases_are_never_written(self):
        before = _ranwhat_temp_dirs()
        writer = _databases(self.root)
        path = os.path.join(self.root, "thread_history_1.sqlite")
        try:
            self.assertGreater(os.path.getsize(path + "-wal"), 0)
            files = [p for p in (path, path + "-wal",
                                 os.path.join(self.root, "state_5.sqlite"))]
            hashes = {p: _sha(p) for p in files}
            with open(path + "-shm", "rb") as fh:
                shm = fh.read()
            stores = [s for s in self.src.stores(self.src.locations())
                      if s.format == "sqlite"]
            self.assertEqual(len(stores), 2)
            for store in stores:
                self.assertEqual(store.why_read_only, codex.WHY_SQLITE)
                list(self.src.secret_texts(store))
                result = self.src.mask(store, [SECRET, TYPED])
                self.assertEqual(result, MaskResult(store.path, skipped="read-only"))
            self.assertEqual({p: _sha(p) for p in files}, hashes)
            with open(path + "-shm", "rb") as fh:
                after = fh.read()
            # every reader takes a read mark in the -shm (bytes 100 to 119)
            changed = [i for i in range(len(shm)) if shm[i] != after[i]]
            self.assertTrue(all(100 <= i < 120 for i in changed), changed)
        finally:
            writer.close()
        self.assertEqual(self.backups(), [])
        self.assertEqual(_ranwhat_temp_dirs() - before, set())

    def test_shell_snapshots_are_never_written(self):
        path = self.write("shell_snapshots/" + THREAD + ".1a2b3c.sh",
                          "export GITHUB_TOKEN=" + SHELL_SECRET + "\n")
        digest = _sha(path)
        store = self.store_for(path)
        with mock.patch.object(_rewrite, "rewrite_file",
                               side_effect=AssertionError("rewrite")):
            self.assertEqual(self.src.mask(store, [SHELL_SECRET]),
                             MaskResult(path, skipped="read-only"))
        self.assertEqual(_sha(path), digest)
        self.assertIn("rotate", store.why_read_only)

    def test_a_compressed_rollout_is_read_and_never_written(self):
        packed = _compress("".join(t + "\n" for t in legacy_lines(SECRET))
                           .encode("utf-8"))
        if packed is None:
            self.skipTest("no zstd decoder here")
        path = self.write(ROLLOUT + ".zst", packed)
        store = self.store_for(path)
        self.assertEqual((store.format, store.masking, store.why_read_only),
                         ("jsonl.zst", "read-only", codex.WHY_ZST))
        [call] = self.src.tool_calls(store)
        self.assertEqual((call.session, call.command, call.output),
                         (THREAD, "cat .env", HEADER + "API_KEY=" + SECRET + "\n"))
        found = found_secrets(self.src.secret_texts(store))
        self.assertEqual([(v, o) for v, o, _w in found], [(SECRET, ".env")])
        with mock.patch("builtins.open", side_effect=AssertionError("open")):
            self.assertEqual(self.src.mask(store, [SECRET]),
                             MaskResult(path, skipped="read-only"))
        self.assertEqual(self.read(path), packed)

    def test_a_compressed_rollout_without_a_decoder_is_counted_not_read(self):
        path = self.write("archived_sessions/rollout-2026-09-01T10-00-00-"
                          + ARCHIVED + ".jsonl.zst", b"(\xb5/\xfd not really")
        store = self.store_for(path)
        with mock.patch.object(_zstd, "available", return_value=False):
            calls, err = self.quiet(list, self.src.tool_calls(store))
            texts, err2 = self.quiet(list, self.src.secret_texts(store))
        self.assertEqual((calls, texts, err, err2), ([], [], "", ""))
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(self.src.unreadable,
                         {"compressed, " + _zstd.NEEDS: 1})

    def test_a_compressed_file_that_is_not_zstd_warns_once(self):
        if not _zstd.available():
            self.skipTest("no zstd decoder here")
        path = self.write(ROLLOUT + ".zst", b"not zstd at all\n")
        store = self.store_for(path)
        calls, err = self.quiet(list, self.src.tool_calls(store))
        texts, err2 = self.quiet(list, self.src.secret_texts(store))
        self.assertEqual((calls, texts), ([], []))
        self.assertEqual((err + err2).count("warning:"), 1)
        self.assertEqual(self.src.unreadable, {codex.NOT_DECOMPRESSED: 1})


# --------------------------------------------------------------------------
# 12. Files that do not parse; files that move
# --------------------------------------------------------------------------

class Damaged(_Case):

    def test_a_truncated_last_line(self):
        partial = line("2026-10-01T12:05:00.000Z", "response_item", fcall(
            "exec_command", {"cmd": "rm -rf ~/x"}, "c9"))[:60]
        path = self.write(ROLLOUT, "".join(t + "\n" for t in legacy_lines(SECRET))
                          + partial)
        calls, err = self.quiet(self.calls, path)
        self.assertEqual([c.tool_call_id for c in calls], ["call_0001"])
        self.assertEqual(err, "")
        self.assertEqual(self.src.counts["unparsed"], 0)

    def test_garbage_warns_once_and_the_rest_is_read(self):
        good = self.write(ROLLOUT, legacy_lines(SECRET))
        bad = self.write(DAY + "rollout-2026-10-01T16-00-00-" + FORKED + ".jsonl",
                         b"\x00\xff\xfe garbage\n\x89PNG\r\n\x1a\nmore\n")
        ts = self.write("sessions/rollout-2025-04-20-" + TS_ID + ".json",
                        b"{\"session\": ")
        state = self.write("state_5.sqlite", b"this is not a database")
        out, err = self.quiet(self._read_all)
        self.assertEqual(out[good], 1)
        self.assertEqual((out[bad], out[ts], out[state]), (0, 0, 0))
        self.assertEqual(err.count("warning:"), 3, err)
        for path in (bad, ts, state):
            self.assertEqual(err.count(path), 1, path)
        self.assertEqual(self.src.counts["unreadable_stores"], 3)
        # four bad lines, and the document that does not parse
        self.assertEqual(self.src.counts["unparsed"], 5)

    def _read_all(self):
        out = {}
        for store in self.src.stores(self.src.locations()):
            calls = list(self.src.tool_calls(store))
            texts = list(self.src.secret_texts(store))
            out[store.path] = len(calls) if store.role == "transcript" else len(
                found_secrets(texts))
            # a second pass (watch, then clean) warns and counts nothing more
            list(self.src.tool_calls(store))
            list(self.src.secret_texts(store))
        return out

    def test_an_unknown_table_is_ignored(self):
        path = os.path.join(self.root, "state_5.sqlite")
        os.makedirs(self.root)
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE threads_v9 (title TEXT)")
        conn.execute("INSERT INTO threads_v9 VALUES (?)", ("KEY=" + TYPED,))
        conn.commit()
        conn.close()
        texts, err = self.quiet(self.texts, path)
        self.assertEqual((texts, err), ([], ""))
        self.assertEqual(self.src.counts["unknown"], 1)
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_a_bad_line_in_the_middle_is_still_searched(self):
        lines = legacy_lines(SECRET)
        lines.insert(2, "not json STRIPE_KEY=" + TYPED)
        path = self.write(ROLLOUT, lines)
        self.assertEqual(len(self.calls(path)), 1)
        found = found_secrets(self.texts(path))
        self.assertIn((TYPED, None, "line 3"), found)
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_a_rollout_compressed_while_it_is_read(self):
        path = self.write(ROLLOUT, legacy_lines(SECRET))
        store = self.store_for(path)
        packed = _compress(self.read(path))
        os.unlink(path)
        if packed is not None and _zstd.available():
            self.write(ROLLOUT + ".zst", packed)
            [call] = self.src.tool_calls(store)
            self.assertEqual(call.command, "cat .env")
            self.assertEqual(self.src.mask(store, [SECRET]),
                             MaskResult(path, skipped="read-only"))
            os.unlink(path + ".zst")
        calls, err = self.quiet(list, self.src.tool_calls(store))
        texts, err2 = self.quiet(list, self.src.secret_texts(store))
        self.assertEqual((calls, texts, err, err2), ([], [], "", ""))
        self.assertEqual(self.src.mask(store, [SECRET]), MaskResult(path))

    def test_a_restored_rollout_is_read_under_its_plain_name(self):
        packed = _compress(b"{}\n")
        if packed is None or not _zstd.available():
            self.skipTest("no zstd here")
        zst = self.write(ROLLOUT + ".zst", packed)
        store = self.store_for(zst)
        os.unlink(zst)
        self.write(ROLLOUT, legacy_lines(SECRET))
        self.assertEqual([c.command for c in self.src.tool_calls(store)],
                         ["cat .env"])


# --------------------------------------------------------------------------
# 13, 14. In use; the window
# --------------------------------------------------------------------------

class InUseAndWindow(_Case):

    def test_a_file_written_recently_is_not_masked(self):
        path = self.write(ROLLOUT, legacy_lines(SECRET), age=5)
        before = self.read(path)
        self.assertEqual(self.src.mask(self.store_for(path), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(self.read(path), before)
        self.assertEqual(self.backups(), [])

    def test_calls_carry_their_own_time(self):
        """An old call in a recently written store keeps its old time, so the
        window drops it; an undated one says when it can be no later than."""
        old = [line("2025-01-01T08:00:00.000Z", "session_meta", meta()),
               line("2025-01-01T08:00:01.000Z", "response_item", fcall(
                   "exec_command", {"cmd": "rm -rf ~/Documents/old"}, "c1")),
               line("2026-10-01T12:00:00.000Z", "response_item", fcall(
                   "exec_command", {"cmd": "rm -rf ~/Documents/new"}, "c2"))]
        path = self.write(ROLLOUT, old, age=60)
        early = self.write("sessions/rollout-2025-05-30T10-00-00-" + EARLY
                           + ".jsonl", early_rust_lines(), age=60)
        cutoff = "2026-09-01T00:00:00Z"

        def in_window(call):
            when = call.timestamp or call.not_after
            return when is None or when >= cutoff

        calls = {c.tool_call_id: c for c in self.calls(path) + self.calls(early)}
        self.assertEqual(calls["c1"].timestamp, "2025-01-01T08:00:01Z")
        self.assertFalse(in_window(calls["c1"]))
        self.assertTrue(in_window(calls["c2"]))
        undated = calls["call_e1"]
        self.assertIsNone(undated.timestamp)
        self.assertEqual(undated.not_after,
                         _stamps.iso_utc(os.stat(early).st_mtime, "s"))
        self.assertTrue(in_window(undated))
        when = time.time() - 400 * 86400
        os.utime(early, (when, when))
        [undated] = self.calls(early)
        self.assertFalse(in_window(undated))


# --------------------------------------------------------------------------
# A thread Codex still holds is not masked
# --------------------------------------------------------------------------

class WriterLock(_Case):
    """rollout/src/writer_lock.rs: a live writer holds
    <CODEX_HOME>/thread-writer-locks/<thread id>.lock for as long as it owns
    the thread, idle or not."""

    def lock(self, thread=THREAD):
        return self.write("thread-writer-locks/%s.lock" % thread, b"", age=900)

    def test_a_locked_thread_is_in_use_however_quiet_its_rollout(self):
        path = self.write(ROLLOUT, legacy_lines(SECRET), age=600)
        before = self.read(path)
        self.lock()
        store = self.store_for(path)
        self.assertEqual(self.src.mask(store, [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(self.read(path), before)
        self.assertEqual(self.backups(), [])
        os.unlink(os.path.join(self.root, "thread-writer-locks",
                               THREAD + ".lock"))
        result = self.src.mask(store, [SECRET])
        self.assertEqual((result.changed, result.skipped), (True, None))

    def test_another_threads_lock_does_not_count(self):
        path = self.write(ROLLOUT, legacy_lines(SECRET), age=600)
        self.lock(FORKED)
        self.assertFalse(self.src.in_use(self.store_for(path)))
        self.assertTrue(self.src.mask(self.store_for(path), [SECRET]).changed)

    def test_every_rollout_layout_finds_its_lock(self):
        self.lock(THREAD)
        self.lock(EARLY)
        self.lock(ARCHIVED)
        self.lock(FORKED)
        paths = [
            self.write(ROLLOUT, legacy_lines(SECRET), age=600),
            self.write("sessions/rollout-2025-05-30T10-00-00-" + EARLY
                       + ".jsonl", early_rust_lines(), age=600),
            self.write("archived_sessions/rollout-2026-09-01T10-00-00-"
                       + ARCHIVED + ".jsonl",
                       [line("2026-09-01T08:00:00.000Z", "session_meta",
                             meta(thread=ARCHIVED))], age=600),
            # after a revert: <thread>_<rollout>, the lock is the thread's
            self.write(DAY + "rollout-2026-10-01T15-00-00-" + FORKED + "_"
                       + "0199a0b2-5555-7000-8000-000000000005.jsonl",
                       [line("2026-10-01T13:00:00.000Z", "session_meta",
                             meta(thread=FORKED))], age=600)]
        for path in paths:
            self.assertTrue(self.src.in_use(self.store_for(path)), path)

    def test_the_lock_is_only_looked_at(self):
        path = self.write(ROLLOUT, legacy_lines(SECRET), age=600)
        lock = self.lock()
        store = self.store_for(path)
        before = os.stat(lock)
        with mock.patch("builtins.open", side_effect=AssertionError("open")), \
                mock.patch("os.open", side_effect=AssertionError("os.open")):
            self.assertTrue(self.src.in_use(store))
        after = os.stat(lock)
        self.assertEqual((before.st_mtime_ns, before.st_size),
                         (after.st_mtime_ns, after.st_size))
        self.assertEqual(os.listdir(os.path.dirname(lock)), [THREAD + ".lock"])

    def test_side_stores_and_strange_ids_are_not_locked(self):
        history = self.write("history.jsonl", [history_line("hi")], age=600)
        self.lock()
        self.assertFalse(self.src.in_use(self.store_for(history)))
        odd = self.write(DAY + "rollout-odd.jsonl", [line(
            "2026-10-01T12:00:00.000Z", "session_meta",
            meta(thread="../../" + THREAD))], age=600)
        self.assertFalse(self.src.in_use(self.store_for(odd)))


# --------------------------------------------------------------------------
# A copy of an ancestor's history is not this thread's
# --------------------------------------------------------------------------

PARENT = "0199a0b2-6666-7000-8000-000000000006"
CHILD = "0199a0b2-7777-7000-8000-000000000007"
CHILD_ROLLOUT = DAY + "rollout-2026-10-01T17-30-00-" + CHILD + ".jsonl"


def forked_lines(cli="0.159.3", marker_id=CHILD):
    """A fork made from a rollout path (core thread_manager.rs
    fork_thread_from_history, ForkPersistence::Copied): the child's
    session_meta, then the parent's rollout copied in one append and
    stamped with the time of the copy (rollout recorder.rs), ending with
    the child's own thread_settings_applied (core session/mod.rs); then
    the child's own turns."""
    copy = "2026-10-01T15:30:00.%03dZ"
    return [
        line(copy % 0, "session_meta", meta(thread=CHILD, forked_from=PARENT,
                                            cli=cli)),
        line(copy % 1, "session_meta", meta(thread=PARENT)),
        line(copy % 1, "response_item", user_message("clean up")),
        line(copy % 2, "response_item", fcall(
            "exec_command", {"cmd": "rm -rf ~/Documents/old"}, "call_p1")),
        line(copy % 2, "response_item", fout("call_p1", "")),
        # the parent's own settings checkpoint, copied with its owner's id
        line(copy % 3, "event_msg", settings_applied(PARENT)),
        line(copy % 3, "response_item",
             user_shell_record("cat ~/.ssh/id_rsa", "-----BEGIN")),
        line(copy % 4, "response_item", fcall(
            "exec_command", {"cmd": "cat .env"}, "call_p2")),
        line(copy % 4, "response_item", fout("call_p2", "API_KEY=" + SECRET)),
        line(copy % 5, "event_msg", settings_applied(marker_id)),
        line("2026-10-01T15:31:00.000Z", "turn_context",
             {"cwd": "/home/dev/app"}),
        line("2026-10-01T15:31:01.000Z", "response_item", fcall(
            "exec_command", {"cmd": "rm -rf ~/Documents/new"}, "c1")),
        line("2026-10-01T15:31:01.100Z", "response_item", fout("c1", "")),
        line("2026-10-01T15:31:02.000Z", "response_item",
             user_shell_record("ls ~/Documents")),
    ]


class Copies(_Case):

    def ids(self, calls):
        return sorted(c.tool_call_id or c.command for c in calls)

    def test_a_forks_copy_of_its_parent_is_not_reported(self):
        path = self.write(CHILD_ROLLOUT, forked_lines())
        calls = self.calls(path)
        self.assertEqual(self.ids(calls), ["c1", "ls ~/Documents"])
        for call in calls:
            self.assertEqual(call.session, CHILD)

    def test_a_later_copy_of_an_inherited_call_is_still_inherited(self):
        lines = forked_lines() + [
            line("2026-10-01T16:00:00.000Z", "compacted", {
                "message": "", "replacement_history": [
                    fcall("exec_command", {"cmd": "rm -rf ~/Documents/old"},
                          "call_p1"),
                    user_shell_record("cat ~/.ssh/id_rsa", "-----BEGIN"),
                    fcall("exec_command", {"cmd": "rm -rf ~/Documents/new"},
                          "c1")]})]
        path = self.write(CHILD_ROLLOUT, lines)
        self.assertEqual(self.ids(self.calls(path)), ["c1", "ls ~/Documents"])

    def test_the_copy_is_still_searched_for_secrets(self):
        path = self.write(CHILD_ROLLOUT, forked_lines())
        found = found_secrets(self.texts(path))
        self.assertEqual([(v, o) for v, o, _w in found], [(SECRET, ".env")])

    def test_a_release_without_the_end_marker_keeps_every_call(self):
        """Before 0.152.0 a copy did not end with the thread's own id, so
        where it ends cannot be told: every call is reported, as before."""
        for cli in ("0.151.0", "0.152.0-alpha.3", "0.0.0", None):
            path = self.write(CHILD_ROLLOUT, forked_lines(cli=cli,
                                                          marker_id=None))
            self.assertEqual(self.ids(self.calls(path)), [
                "c1", "call_p1", "call_p2", "cat ~/.ssh/id_rsa",
                "ls ~/Documents"], cli)
        path = self.write(CHILD_ROLLOUT, forked_lines(cli="0.152.0"))
        self.assertEqual(self.ids(self.calls(path)), ["c1", "ls ~/Documents"])

    def test_a_fork_with_nothing_copied_keeps_its_own_calls(self):
        """A fork cut before the parent's first message copies nothing and
        writes no marker; a later settings change does not hide anything."""
        lines = [
            line("2026-10-01T15:30:00.000Z", "session_meta",
                 meta(thread=CHILD, forked_from=PARENT)),
            line("2026-10-01T15:31:01.000Z", "response_item", fcall(
                "exec_command", {"cmd": "rm -rf ~/Documents/new"}, "c1")),
            line("2026-10-01T15:32:00.000Z", "event_msg",
                 settings_applied(CHILD)),
            line("2026-10-01T15:33:01.000Z", "response_item", fcall(
                "exec_command", {"cmd": "ls"}, "c2"))]
        path = self.write(CHILD_ROLLOUT, lines)
        self.assertEqual(self.ids(self.calls(path)), ["c1", "c2"])

    def test_a_paginated_subagents_inherited_context_is_not_reported(self):
        """session_meta.subagent_history_start_ordinal: earlier records are
        inherited model context (protocol.rs SessionMeta)."""
        lines = [
            line("2026-10-01T15:30:00.000Z", "session_meta",
                 meta(mode="paginated", thread=CHILD, forked_from=PARENT,
                      start_ordinal=4), 0),
            line("2026-10-01T15:30:00.001Z", "response_item",
                 user_shell_record("cat ~/.ssh/id_rsa"), 1),
            line("2026-10-01T15:30:00.002Z", "compacted", {
                "message": "", "replacement_history": [fcall(
                    "exec_command", {"cmd": "rm -rf ~/Documents/old"},
                    "call_p1")]}, 2),
            line("2026-10-01T15:30:00.003Z", "event_msg",
                 settings_applied(CHILD), 3),
            line("2026-10-01T15:31:01.000Z", "response_item", fcall(
                "exec_command", {"cmd": "rm -rf ~/Documents/new"}, "c1"), 4),
            line("2026-10-01T15:31:01.100Z", "response_item", fout("c1", ""), 5)]
        path = self.write(CHILD_ROLLOUT, lines)
        self.assertEqual(self.ids(self.calls(path)), ["c1"])


# --------------------------------------------------------------------------
# Commands the user ran with `!`
# --------------------------------------------------------------------------

class UserShellRecords(_Case):
    """core tasks/user_shell.rs: the command is recorded as a user message
    in every mode; paginated mode also writes its CommandExecution item;
    legacy mode, the default (protocol.rs ThreadHistoryMode), does not
    (rollout policy.rs)."""

    def legacy(self, *items):
        t = "2026-10-01T12:20:%02d.000Z"
        return legacy_lines(SECRET) + [line(t % i, "response_item", item)
                                       for i, item in enumerate(items)]

    def test_a_legacy_record_is_the_users_own_call(self):
        path = self.write(ROLLOUT, self.legacy(
            user_shell_record("rm -rf ~/Documents/x", "")))
        calls = {c.tool_call_id or c.tool_name: c for c in self.calls(path)}
        ran = calls["user_shell"]
        self.assertEqual(
            (ran.kind, ran.known, ran.actor, ran.status, ran.command,
             ran.timestamp, ran.session, ran.project, ran.tool_call_id,
             ran.consumed, ran.output),
            ("shell", True, "user", None, "rm -rf ~/Documents/x",
             "2026-10-01T12:20:00Z", THREAD, "/home/dev/app", None,
             frozenset(["command"]), ""))
        self.assertEqual(rules(ran), ["fs.destructive"])

    def test_each_run_is_reported_and_a_compacted_copy_is_not(self):
        record = user_shell_record("cat ~/.aws/credentials", "[default]")
        lines = self.legacy(record, record) + [
            line("2026-10-01T12:30:00.000Z", "compacted",
                 {"message": "", "replacement_history": [record]})]
        path = self.write(ROLLOUT, lines)
        shells = [c for c in self.calls(path) if c.actor == "user"]
        self.assertEqual([(c.command, c.timestamp, c.output) for c in shells],
                         [("cat ~/.aws/credentials", "2026-10-01T12:20:00Z",
                           "[default]"),
                          ("cat ~/.aws/credentials", "2026-10-01T12:20:01Z",
                           "[default]")])
        self.assertEqual(rules(shells[0]), ["cred.read"])

    def test_paginated_mode_reports_the_item_not_its_message(self):
        lines = paginated_lines(SECRET) + [
            line("2026-10-01T12:20:00.000Z", "event_msg", completed(
                command_item(["/bin/zsh", "-lc", "rm -rf ~/Documents/x"],
                             "user_shell", item_id="u1", printed=True),
                at_ms=1790857200000), 5),
            line("2026-10-01T12:20:00.001Z", "response_item",
                 user_shell_record("rm -rf ~/Documents/x"), 6),
            # cancelled: the message is written before the item
            line("2026-10-01T12:21:00.000Z", "response_item",
                 user_shell_record("sleep 100", "command aborted by user"), 7),
            line("2026-10-01T12:21:00.001Z", "event_msg", completed(
                command_item(["/bin/zsh", "-lc", "sleep 100"], "user_shell",
                             status="failed", item_id="u2", printed=True,
                             output="command aborted by user"),
                at_ms=1790857260001), 8)]
        path = self.write(ROLLOUT, lines)
        shells = [c for c in self.calls(path) if c.actor == "user"]
        self.assertEqual(sorted((c.tool_call_id, c.command) for c in shells),
                         [("u1", "rm -rf ~/Documents/x"), ("u2", "sleep 100")])

    def test_only_a_record_is_a_command(self):
        typed = dict(user_shell_record("rm -rf ~/Documents/x"),
                     internal_chat_message_metadata_passthrough={
                         "content_item_kinds": ["generic"]})
        said = user_message("run <user_shell_command> for me")
        assistant = dict(user_shell_record("rm -rf ~/x", kinds=None),
                         role="assistant")
        older = user_shell_record("rm -rf ~/Documents/y", kinds=None)
        path = self.write(ROLLOUT, self.legacy(typed, said, assistant, older))
        shells = [c.command for c in self.calls(path) if c.actor == "user"]
        self.assertEqual(shells, ["rm -rf ~/Documents/y"])
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_what_it_printed_has_an_origin_and_what_was_typed_has_none(self):
        path = self.write(ROLLOUT, [line(
            "2026-10-01T12:00:00.123Z", "session_meta", meta())] + [
            line("2026-10-01T12:20:00.000Z", "response_item",
                 user_shell_record("cat .env", "API_KEY=" + SECRET)),
            line("2026-10-01T12:21:00.000Z", "response_item",
                 user_shell_record("export STRIPE_KEY=" + TYPED, ""))])
        found = found_secrets(self.texts(path))
        self.assertEqual(sorted((v, o) for v, o, _w in found),
                         sorted([(SECRET, ".env"), (TYPED, None)]))


class CommandOutputs(_Case):

    def test_every_copy_of_what_a_command_printed_has_its_call(self):
        """stdout, aggregated_output and formatted_output all hold the
        output of a completed user command (core tasks/user_shell.rs)."""
        lines = [line("2026-10-01T12:00:00.123Z", "session_meta",
                      meta(mode="paginated"), 0)] + [
            line("2026-10-01T12:20:00.000Z", "event_msg", completed(
                command_item(["/bin/zsh", "-lc", "cat .env"], "user_shell",
                             item_id="u1", printed=True,
                             output="API_KEY=" + SECRET + "\n")), 1),
            line("2026-10-01T12:20:00.001Z", "response_item",
                 user_shell_record("cat .env", "API_KEY=" + SECRET + "\n"), 2)]
        path = self.write(ROLLOUT, lines)
        texts = self.texts(path)
        found = found_secrets(texts)
        self.assertEqual([(v, o, w) for v, o, w in found],
                         [(SECRET, ".env", "line 2")] * 3
                         + [(SECRET, ".env", "line 3")])
        [call] = self.calls(path)
        self.assertEqual((call.tool_call_id, call.output),
                         ("u1", "API_KEY=" + SECRET + "\n"))


class RecordTypes(_Case):

    ENVELOPES = ("inter_agent_communication",
                 "inter_agent_communication_metadata", "token_usage_record",
                 "world_state", "retained_context", "security_risk_score",
                 "realtime_item")
    ITEMS = ("agent_message", "tool_search_call", "tool_search_output",
             "image_generation_call", "configuration_update",
             "context_compaction", "compaction_summary")

    def test_what_the_current_release_writes_is_not_unknown(self):
        """history rollout_payload.rs (the envelope types) and protocol
        models.rs (ResponseItem); payloads are left empty here, since
        nothing in them is read."""
        t = "2026-10-01T12:30:%02d.000Z"
        lines = legacy_lines(SECRET)
        for i, kind in enumerate(self.ENVELOPES):
            payload = ({"trigger_turn": True}
                       if kind == "inter_agent_communication_metadata" else {})
            lines.append(line(t % i, kind, payload))
        for i, kind in enumerate(self.ITEMS):
            lines.append(line(t % (20 + i), "response_item", {"type": kind}))
        path = self.write(ROLLOUT, lines)
        self.assertEqual([c.tool_call_id for c in self.calls(path)],
                         ["call_0001"])
        self.assertEqual(self.src.counts["unknown"], 0)
        self.assertEqual(len(self.texts(path)), len(lines))


# --------------------------------------------------------------------------
# A large file: how reading it grows, on its own interpreter (tests/growth.py)
# --------------------------------------------------------------------------

LARGE_CALL = r"""
from ranwhat.sources.codex import CodexSource
def call(root):
    src = CodexSource()
    [store] = [s for s in src.stores(src.locations(override=root))
               if s.role == "transcript"]
    calls = sum(1 for _ in src.tool_calls(store))
    texts = sum(1 for _ in src.secret_texts(store))
    return {"calls": calls, "texts": texts}
"""


class LargeFile(_Case):

    CALLS = 20000

    def rollout(self, n):
        """A Codex home whose one rollout holds n(CALLS) calls."""
        root = tempfile.mkdtemp(prefix="codex-large-", dir=self.home)
        out = os.path.join(root, *ROLLOUT.split("/"))
        os.makedirs(os.path.dirname(out))
        body = "x" * 1500 + "\n"
        with open(out, "w", encoding="utf-8", newline="") as fh:
            fh.write(line("2026-10-01T12:00:00.123Z", "session_meta", meta()) + "\n")
            for i in range(n(self.CALLS)):
                cid = "call_%06d" % i
                fh.write(line("2026-10-01T12:00:01.000Z", "response_item", fcall(
                    "exec_command", {"cmd": "cat src/file%d.py" % i,
                                     "workdir": "/home/dev/app"}, cid)) + "\n")
                fh.write(line("2026-10-01T12:00:01.100Z", "response_item",
                              fout(cid, HEADER + body * 2)) + "\n")
                if i % 50 == 0:
                    fh.write(line("2026-10-01T12:00:01.200Z", "response_item",
                                  {"type": "reasoning",
                                   "encrypted_content": "gAAAA" + "z" * 4000})
                             + "\n")
        return root

    def test_a_large_rollout_is_read_in_bounded_time(self):
        env = dict(os.environ, HOME=self.home, USERPROFILE=self.home)
        measured, root = growth.measure_apart(self.rollout, LARGE_CALL, env=env)
        out = os.path.join(root, *ROLLOUT.split("/"))
        self.assertGreater(os.path.getsize(out), 50 * 1000 * 1000)
        growth.assert_linear(self, measured, "a 50 MB rollout")
        self.assertEqual(measured.result["calls"], self.CALLS)
        self.assertEqual(measured.result["texts"],
                         2 * self.CALLS + self.CALLS // 50 + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
