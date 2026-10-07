"""The Roo Code adapter (ranwhat/sources/roo.py, over _cline_tasks.py).

Fixtures are built field for field from the verified format (Roo Code
v3.54.0 for native calls, v3.36.0 and v3.20.0 for the XML protocol): a task
folder's api_conversation_history.json, ui_messages.json and
history_item.json are compact JSON as safeWriteJson writes them, and a
long command's output is command-output/cmd-<ts>.txt.

Everything runs in temp directories: the home directory, the editor
variables and clean's backup root point there, and the real home is never
read. Every secret is synthetic, and token-shaped ones are written as
adjacent literals. The adapter is instantiated directly, so these tests
pass whether or not it is in the registry.
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
from ranwhat.sources import _paths  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.roo import RooSource  # noqa: E402

ENVS = ("VSCODE_PORTABLE", "VSCODE_APPDATA", "XDG_CONFIG_HOME", "APPDATA")
WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
LOGIN = "sk-" "ant-api03-" "Vb7Nq2Lm9Xc4Rt8Yp1Wz6Ks3Df5Gh0Ja"

TASK = "0199b3a0-7c2e-7d4f-9a1b-2c3d4e5f6a7b"
MS = 1791380000000           # 2026-10-07T13:33:20Z
CWD = "/home/u/proj"
DENIED = '{"status":"denied","message":"The user denied this operation."}'


def _compact(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _iso(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000.0))


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _marker(value):
    return clean.REDACTION % clean._fingerprint(value)


def _tempdir(case, prefix):
    path = tempfile.mkdtemp(prefix=prefix)
    case.addCleanup(shutil.rmtree, path, True)
    return path


def rules(call):
    return [(h["rule"], h["evidence"]) for h in watch.judge(call)[0]]


# --------------------------------------------------------------------------
# Fixture builders
# --------------------------------------------------------------------------

def env_details(cwd=CWD):
    return {"type": "text", "text": "<environment_details>\n# Current Workspace"
            " Directory (%s) Files\nsrc/\n.env\n</environment_details>" % cwd}


def first_user(text="fix the build", cwd=CWD):
    return {"role": "user", "ts": MS + 200, "content": [
        {"type": "text", "text": "<user_message>\n%s\n</user_message>" % text},
        env_details(cwd)]}


def tool_use(cid, name, input_):
    return {"type": "tool_use", "id": cid, "name": name, "input": input_}


def assistant(blocks, ts=None):
    if isinstance(blocks, str):
        blocks = [{"type": "text", "text": blocks}]
    msg = {"role": "assistant", "content": blocks}
    if ts is not None:
        msg["ts"] = ts
    return msg


def user(*blocks, ts=None):
    msg = {"role": "user", "content": list(blocks)}
    if ts is not None:
        msg["ts"] = ts
    return msg


def result(cid, content):
    return {"type": "tool_result", "tool_use_id": cid, "content": content}


def xml(name, **params):
    inner = "".join("<%s>%s</%s>\n" % (k, v, k) for k, v in params.items())
    return "<%s>\n%s</%s>" % (name, inner, name)


def xml_result(desc, body):
    """Roo's XML-mode result: the header block, then the result block."""
    return [{"type": "text", "text": "%s Result:" % desc},
            {"type": "text", "text": body}]


def spec_native():
    """The spec's section 6.4, field for field."""
    return [
        first_user(),
        assistant([{"type": "text", "text": "Let me look."},
                   tool_use("toolu_01A", "execute_command",
                            {"command": "cat ~/.ssh/id_rsa", "cwd": None,
                             "timeout": None})], ts=MS + 500),
        user(result("toolu_01A", DENIED), env_details(), ts=MS + 900),
        assistant([tool_use("toolu_01B", "execute_command",
                            {"command": "npm run build", "cwd": None,
                             "timeout": None})], ts=MS + 1500),
        user(result("toolu_01B", "Command executed in terminal within working "
                    "directory '/home/u/proj'. Exit code: 0\nOutput:\n> build\n"
                    "done"), ts=MS + 1900),
        assistant([tool_use("toolu_01C", "read_file", {"path": ".env"})],
                  ts=MS + 2500),
        user(result("toolu_01C", "File: .env\n1 | STRIPE_KEY=%s" % SECRET),
             ts=MS + 2900),
        assistant([tool_use("toolu_01D", "write_to_file",
                            {"path": "src/a.ts", "content": "export {}\n"})],
                  ts=MS + 3500),
        user(result("toolu_01D", "…"), ts=MS + 3900),
    ]


def ui_log():
    return [
        {"ts": MS, "type": "say", "say": "text", "text": "fix the build"},
        {"ts": MS + 100, "type": "say", "say": "api_req_started",
         "text": _compact({"apiProtocol": "anthropic", "tokensIn": 1200,
                           "tokensOut": 80, "cost": 0.004})},
        {"ts": MS + 700, "type": "ask", "ask": "command",
         "text": "cat ~/.ssh/id_rsa"},
        {"ts": MS + 900, "type": "say", "say": "user_feedback", "text": "no"},
        {"ts": MS + 1600, "type": "ask", "ask": "command", "text": "cat .env"},
        {"ts": MS + 1800, "type": "say", "say": "command_output",
         "text": "STRIPE_KEY=%s" % SECRET},
    ]


def history_item(workspace=CWD, task=TASK):
    return {"id": task, "number": 1, "ts": MS, "task": "fix the build",
            "tokensIn": 1200, "tokensOut": 80, "totalCost": 0.004,
            "workspace": workspace, "mode": "code", "status": "completed"}


# --------------------------------------------------------------------------
# Common setup
# --------------------------------------------------------------------------

class RooCase(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "roo-home-")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for name in ENVS:
            os.environ.pop(name, None)
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.home, ".config")
        os.environ["APPDATA"] = os.path.join(self.home, "AppData", "Roaming")
        self.backups = os.path.join(_tempdir(self, "roo-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        parent = _paths.editor_parent(os.environ, self.home,
                                      _paths.platform_name())
        self.gs = os.path.join(parent, "Code", "User", "globalStorage",
                               "rooveterinaryinc.roo-cline")
        self.cli = os.path.join(self.home, ".vscode-mock", "global-storage")
        self.src = RooSource()

    def write(self, path, raw, age=3600):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def task_file(self, name, doc, task=TASK, root=None, age=3600, raw=None):
        path = os.path.join(root or self.gs, "tasks", task, *name.split("/"))
        return self.write(path, raw if raw is not None else _compact(doc), age)

    def task(self, messages, task=TASK, root=None, age=3600, raw=None,
             item=True):
        if item:
            self.task_file("history_item.json", history_item(task=task),
                           task=task, root=root, age=age)
        return self.task_file("api_conversation_history.json", messages,
                              task=task, root=root, age=age, raw=raw)

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


# --------------------------------------------------------------------------
# Where Roo Code keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        s = RooSource()
        self.assertEqual(s.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.config", "default"),
                          ("/home/u/.vscode-mock/global-storage", "default")])
        self.assertEqual(s.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/Library/Application Support", "default"),
                          ("/Users/u/.vscode-mock/global-storage", "default")])
        self.assertEqual(s.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\AppData\\Roaming", "default"),
                          ("C:\\Users\\u\\.vscode-mock\\global-storage",
                           "default")])

    def test_editor_variables(self):
        s = RooSource()
        got = s.default_paths({"VSCODE_PORTABLE": "/p", "VSCODE_APPDATA": "/a",
                               "XDG_CONFIG_HOME": "/cfg"}, "/home/u", "linux")
        self.assertEqual(got[:3], [
            ("/p/user-data/User/globalStorage/rooveterinaryinc.roo-cline",
             "env VSCODE_PORTABLE"), ("/a", "env VSCODE_APPDATA"),
            ("/cfg", "default")])

    def test_what_every_report_needs(self):
        s = RooSource()
        self.assertEqual((s.id, s.name, s.unit, s.env, s.checked),
                         ("roo", "Roo Code", "task", (), "3.54.0"))
        self.assertIn("customStoragePath", s.path_means)
        self.assertFalse(s.read_only)
        self.assertTrue(s.mask_note)


class Discovery(RooCase):

    def test_an_absent_agent_costs_a_stat_or_two(self):
        import builtins
        n = [0]
        real = {k: getattr(os, k) for k in ("stat", "lstat", "listdir",
                                             "scandir")}
        real_open = builtins.open

        def counted(fn):
            def inner(*a, **k):
                n[0] += 1
                return fn(*a, **k)
            return inner
        patches = [mock.patch.object(os, k, counted(f)) for k, f in real.items()]
        patches.append(mock.patch.object(builtins, "open", counted(real_open)))
        for p in patches:
            p.start()
        try:
            locations = self.src.locations()
            present = [loc for loc in locations if loc.exists]
            self.src.stores(present)
        finally:
            for p in patches:
                p.stop()
        self.assertLessEqual(n[0], 4)

    def test_every_store_is_found_newest_first_and_nothing_else(self):
        api = self.task(spec_native(), age=7200)
        ui = self.task_file("ui_messages.json", ui_log(), age=7100)
        out = self.task_file("command-output/cmd-%d.txt" % (MS + 1600), None,
                             raw="STRIPE_KEY=%s\n" % SECRET, age=7000)
        cli = self.task(spec_native(), task="cli-task", root=self.cli, age=60)
        fork = self.task(spec_native(), task="fork", age=50, root=os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(self.gs)))), "VSCodium", "User",
            "globalStorage", "rooveterinaryinc.roo-cline"))
        # an id that is not Roo's own is not looked at
        self.task(spec_native(), task="other-id", root=os.path.join(
            os.path.dirname(self.gs), "roovscode.roo-cline"))
        # never stores
        for rel in ("_index.json", "_index.json.lock/x",
                    TASK + "/task_metadata.json",
                    TASK + "/api_conversation_history.json.lock/x",
                    TASK + "/.api_conversation_history.json.new_1_2.tmp",
                    TASK + "/checkpoints/api_conversation_history.json",
                    TASK + "/command-output/notes.txt", ".hidden/ui_messages.json"):
            self.write(os.path.join(self.gs, "tasks", *rel.split("/")), "[]")
        self.write(os.path.join(self.cli, "secrets.json"), "{}")
        self.write(os.path.join(self.gs, "settings", "mcp_settings.json"), "{}")
        got = self.stores()
        self.assertEqual([s.path for s in got], [fork, cli, out, ui, api])
        by = {s.path: s for s in got}
        self.assertEqual((by[api].format, by[api].role, by[api].session,
                          by[api].project), ("json", "transcript", TASK, CWD))
        self.assertEqual((by[ui].role, by[ui].unit), ("side", "task log"))
        self.assertEqual((by[out].format, by[out].role, by[out].unit),
                         ("text", "side", "command output"))
        self.assertEqual(by[cli].session, "cli-task")

    def test_project_from_the_history_item_else_the_environment_details(self):
        api = self.task(spec_native())
        self.task_file("history_item.json", history_item("/srv/elsewhere"))
        self.assertEqual(self.store(api).project, "/srv/elsewhere")
        other = self.task([first_user(cwd="/srv/env")], task="t2", item=False)
        self.assertEqual(self.store(other).project, "/srv/env")
        self.task_file("history_item.json", None, task="t3", raw="{broken")
        third = self.task([first_user(cwd="/srv/env3")], task="t3", item=False)
        self.assertEqual(self.store(third).project, "/srv/env3")

    def test_path_override_and_a_missing_root(self):
        custom = _tempdir(self, "roo-custom-")
        path = self.task(spec_native(), root=custom)
        self.assertEqual([s.path for s in self.stores(override=custom)], [path])
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.stores(override=os.path.join(custom, "x")), [])

    def test_days_prefilter_by_last_write(self):
        self.task(spec_native(), age=10 * 86400)
        new = self.task(spec_native(), task="new", age=60)
        self.assertEqual([s.path for s in self.stores(since_days=2)], [new])


# --------------------------------------------------------------------------
# Tool calls
# --------------------------------------------------------------------------

class Calls(RooCase):

    def test_the_spec_sample(self):
        got = self.by_id(self.task(spec_native()))
        self.assertEqual(list(got), ["toolu_01A", "toolu_01B", "toolu_01C",
                                     "toolu_01D"])
        a, b, c, d = (got[k] for k in got)
        self.assertEqual((a.kind, a.command, a.status, a.output),
                         ("shell", "cat ~/.ssh/id_rsa", "declined", DENIED))
        self.assertEqual((a.workdir, a.project, a.session, a.timestamp),
                         (CWD, CWD, TASK, _iso(MS + 500)))
        self.assertEqual(a.consumed, frozenset(["command"]))
        self.assertIsNone(b.status)
        self.assertTrue(b.output.startswith("Command executed in terminal"))
        self.assertEqual((c.kind, c.paths, c.consumed),
                         ("read", (".env",), frozenset(["path"])))
        self.assertEqual((d.kind, d.paths), ("write", ("src/a.ts",)))
        self.assertTrue(all(x.known and x.source == "roo" for x in got.values()))

    def test_every_tool(self):
        cases = [
            ("execute_command", {"command": "ls", "cwd": "sub", "timeout": None},
             "shell", "ls", ()),
            ("read_file", {"path": "a.py", "mode": "slice"}, "read", None,
             ("a.py",)),
            ("read_file", {"files": [{"path": "a.py", "line_ranges": []},
                                     {"path": "b.py"}]}, "read", None,
             ("a.py", "b.py")),
            ("write_to_file", {"path": "w", "content": "x"}, "write", None,
             ("w",)),
            ("apply_diff", {"path": "d", "diff": "x"}, "write", None, ("d",)),
            ("insert_content", {"path": "i", "line": "1", "content": "x"},
             "write", None, ("i",)),
            ("search_and_replace", {"path": "s", "operations": []}, "write",
             None, ("s",)),
            ("edit", {"file_path": "e", "old_string": "a", "new_string": "b"},
             "write", None, ("e",)),
            ("search_replace", {"file_path": "r", "old_string": "a",
                                "new_string": "b"}, "write", None, ("r",)),
            ("edit_file", {"file_path": "f", "old_string": "a",
                           "new_string": "b"}, "write", None, ("f",)),
            ("apply_patch", {"patch": "*** Begin Patch\n*** Add File: p\n+x\n"
                             "*** End Patch"}, "write", None, ("p",)),
            ("generate_image", {"prompt": "x", "path": "g.png", "image": None},
             "write", None, ("g.png",)),
            ("browser_action", {"action": "launch", "url": "http://x"},
             "fetch", None, ()),
        ]
        others = ["read_command_output", "search_files", "list_files",
                  "list_code_definition_names", "use_mcp_tool",
                  "access_mcp_resource", "ask_followup_question",
                  "attempt_completion", "switch_mode", "new_task",
                  "fetch_instructions", "codebase_search", "update_todo_list",
                  "run_slash_command", "skill", "custom_tool"]
        cases += [(n, {"path": "x"}, "other", None, ()) for n in others]
        messages = [first_user()] + [
            assistant([tool_use("t%d" % n, name, args)])
            for n, (name, args, _k, _c, _p) in enumerate(cases)]
        calls = self.calls(self.task(messages))
        self.assertEqual(len(calls), len(cases))
        for call, (name, _a, kind, command, paths) in zip(calls, cases):
            self.assertEqual((call.tool_name, call.kind, call.known,
                              call.command, call.paths),
                             (name, kind, True, command, paths), name)
        self.assertEqual(calls[0].workdir, CWD + "/sub")

    def test_a_command_s_own_working_directory(self):
        messages = [first_user()] + [
            assistant([tool_use("c%d" % n, "execute_command",
                                {"command": "ls", "cwd": cwd})])
            for n, cwd in enumerate([None, "", "/abs", "../x", 5])]
        got = [c.workdir for c in self.calls(self.task(messages))]
        self.assertEqual(got, [CWD, CWD, "/abs", "/home/u/x", CWD])

    def test_the_xml_protocol_of_3_20(self):
        read = ("<read_file>\n<args>\n<file>\n<path>.env</path>\n</file>\n"
                "<file>\n<path>~/.ssh/id_rsa</path>\n<line_range>1-2"
                "</line_range>\n</file>\n</args>\n</read_file>")
        messages = [
            first_user(),
            assistant("I'll read them.\n" + read, ts=MS + 500),
            user(*xml_result("[read_file for '.env', '~/.ssh/id_rsa']",
                             "<files><file><path>.env</path><content>1 | K=%s"
                             "</content></file></files>" % SECRET)
                 + [env_details()], ts=MS + 600),
            assistant(xml("execute_command", command="rm -rf ~/Documents/x",
                          cwd="/tmp")),
            user(*xml_result("[execute_command for 'rm -rf ~/Documents/x']",
                             "The user denied this operation and provided the "
                             "following feedback:\n<feedback>\nno\n"
                             "</feedback>")),
            assistant(xml("write_to_file", path="a.txt",
                          content="\n  indented\n", line_count="1")),
            user(*xml_result("[write_to_file for 'a.txt']", "ok")),
        ]
        path = self.task(messages)
        read_call, rm, write = self.calls(path)
        self.assertEqual((read_call.tool_call_id, read_call.kind,
                          read_call.paths, read_call.consumed),
                         ("xml-1-0-0", "read", (".env", "~/.ssh/id_rsa"),
                          frozenset(["args"])))
        self.assertIn(SECRET, read_call.output)
        self.assertEqual([r for r, _e in rules(read_call)], ["cred.read"])
        self.assertEqual((rm.status, rm.workdir), ("declined", "/tmp"))
        self.assertEqual(rules(rm), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(write.tool_input["content"], "  indented")
        self.assertEqual(write.output, "ok")
        # a read of several files: the secret is credited to the last
        # credential file the call names, as clean credits any call
        [entry] = self.findings(path).values()
        self.assertEqual(entry["origins"], {"~/.ssh/id_rsa"})

    def test_mcp_tools_are_judged_by_name(self):
        messages = [first_user(), assistant([tool_use(
            "m", "mcp--srv--bash", {"command": "rm -rf ~/Documents/x"})])]
        [call] = self.calls(self.task(messages))
        self.assertEqual((call.kind, call.known), ("other", False))
        self.assertEqual(watch.judge(call),
                         watch.evaluate(call.tool_name, call.tool_input))

    def test_dedupe_and_time(self):
        messages = [first_user(),
                    assistant([tool_use("a", "execute_command",
                                        {"command": "a"})], ts=MS + 10),
                    user(result("a", "A")),
                    assistant([tool_use("a", "execute_command",
                                        {"command": "b"})], ts=MS + 20),
                    assistant([tool_use("c", "execute_command",
                                        {"command": "c"})]),
                    user(result("c", "C"), ts=MS + 40)]
        a, c = self.calls(self.task(messages))
        self.assertEqual((a.command, a.output, a.timestamp),
                         ("a", "A", _iso(MS + 10)))
        self.assertEqual((c.timestamp, c.not_after), (None, _iso(MS + 40)))


class Declined(RooCase):

    def test_the_agents_own_texts(self):
        cases = [
            (DENIED, True),
            ('{"status":"denied","feedback":"no"}', True),
            ('{"status":"denied","message":"The user denied this operation and '
             'provided the following feedback","feedback":"no"}', True),
            ('{"status":"error","type":"access_denied","message":"Access blocked'
             ' by .rooignore","path":".env"}', True),
            ("Skipping tool [execute_command for 'x'] due to user rejecting a "
             "previous tool.", True),
            ("Tool [execute_command for 'x'] was interrupted and not executed "
             "due to user rejecting a previous tool.", True),
            ("Tool [execute_command] was not executed because a tool has "
             "already been used in this message. Only one tool may be used per "
             "message.", True),
            ('{"status":"approved","feedback":"go"}\n\nCommand executed', False),
            ('{"status":"error","message":"The tool execution failed",'
             '"error":"boom"}', False),
            ("Task was interrupted before this tool call could be completed.",
             False),
            ("Command executed in terminal within working directory '/x'. Exit "
             "code: 0\nOutput:\n" + DENIED, False),
        ]
        messages = [first_user()]
        for n, (text, _d) in enumerate(cases):
            messages += [assistant([tool_use("d%d" % n, "execute_command",
                                             {"command": "x"})]),
                         user(result("d%d" % n, text))]
        calls = self.calls(self.task(messages))
        self.assertEqual([c.status == "declined" for c in calls],
                         [d for _t, d in cases])


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(RooCase):

    def test_a_secret_in_cat_env_output_has_origin_env(self):
        messages = [first_user(),
                    assistant([tool_use("cat", "execute_command",
                                        {"command": "cat .env", "cwd": None})]),
                    user(result("cat", "Command executed in terminal within "
                                "working directory '/home/u/proj'. Exit code: "
                                "0\nOutput:\nSTRIPE_KEY=%s" % SECRET))]
        found = self.findings(self.task(messages))
        [entry] = found.values()
        self.assertEqual(entry["origins"], {".env"})
        self.assertEqual(entry["sources"], {"roo"})
        self.assertEqual(entry["projects"], {CWD})

    def test_a_spilled_output_is_tied_to_its_command(self):
        name = "cmd-%d.txt" % (MS + 1600)
        messages = [first_user(),
                    assistant([tool_use("big", "execute_command",
                                        {"command": "cat config/.env.local"})]),
                    user(result("big", "Command executed in '/home/u/proj'. "
                                "Exit code: 0\n\nOutput (2.1 MB) persisted. "
                                "Artifact ID: %s\n\nPreview:\nA=1\n\nUse "
                                "read_command_output tool to view full output "
                                "if needed." % name))]
        self.task(messages)
        out = self.task_file("command-output/" + name, None,
                             raw="A=1\nSTRIPE_KEY=%s\n" % SECRET)
        store = self.store(out)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        [text] = list(self.src.secret_texts(store))
        self.assertEqual(text.call.tool_call_id, "big")
        [entry] = self.findings(out).values()
        self.assertEqual(entry["origins"], {"config/.env.local"})
        # an output nothing names is still searched
        lone = self.task_file("command-output/cmd-1.txt", None,
                              raw="K=%s\n" % SECRET)
        [text] = list(self.src.secret_texts(self.store(lone)))
        self.assertIsNone(text.call)
        self.assertEqual(len(self.findings(lone)), 1)

    def test_the_ui_log_is_searched(self):
        path = self.task_file("ui_messages.json", ui_log())
        self.assertEqual(list(self.src.tool_calls(self.store(path))), [])
        self.assertEqual([e["fingerprint"] for e in self.findings(path).values()],
                         [clean._fingerprint(SECRET)])

    def test_the_result_is_tied_to_its_call(self):
        path = self.task(spec_native())
        for t in self.src.secret_texts(self.store(path)):
            if SECRET in json.dumps(t.node):
                self.assertEqual(t.call.tool_call_id, "toolu_01C")

    def test_the_cli_s_secrets_file_is_never_searched(self):
        self.write(os.path.join(self.cli, "secrets.json"),
                   _compact({"roo_cline_config_api_config":
                             _compact({"apiKey": LOGIN})}))
        self.write(os.path.join(self.cli, "global-state.json"),
                   _compact({"x": LOGIN}))
        self.write(os.path.join(self.cli, "settings", "mcp_settings.json"),
                   _compact({"mcpServers": {"x": {"env": {"T": LOGIN}}}}))
        self.write(os.path.join(self.cli, "tasks", "_index.json"),
                   _compact({"version": 1, "entries": [{"task": LOGIN}]}))
        self.task(spec_native(), root=self.cli)
        self.task_file("ui_messages.json", ui_log(), root=self.cli)
        texts = []
        for store in self.stores():
            for text in self.src.secret_texts(store):
                texts.append(json.dumps(text.node))
        joined = "\n".join(texts)
        self.assertIn(SECRET, joined)
        self.assertNotIn(LOGIN, joined)


class Masking(RooCase):

    def test_round_trip(self):
        path = self.task(spec_native(), age=600)
        before = self.calls(path)
        result_ = self.src.mask(self.store(path), [SECRET])
        self.assertTrue(result_.changed, result_)
        with open(path, encoding="utf-8") as fh:
            after = fh.read()
        self.assertNotIn(SECRET, after)
        self.assertEqual(after, _compact(json.loads(after)))
        again = self.calls(path)
        self.assertEqual(again[2].output,
                         before[2].output.replace(SECRET, _marker(SECRET)))
        self.assertEqual(self.findings(path), {})

    def test_a_command_output_is_masked_as_text(self):
        out = self.task_file("command-output/cmd-1.txt", None,
                             raw="a\nK=%s\nb\n" % SECRET, age=600)
        self.assertTrue(self.src.mask(self.store(out), [SECRET]).changed)
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "a\nK=%s\nb\n" % _marker(SECRET))

    def test_a_locked_file_is_in_use(self):
        path = self.task(spec_native(), age=600)
        os.makedirs(path + ".lock")
        digest = _sha(path)
        self.assertEqual(self.src.mask(self.store(path), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)

    def test_a_file_written_just_now_is_left_alone(self):
        path = self.task(spec_native(), age=5)
        self.assertEqual(self.src.mask(self.store(path), [SECRET]),
                         MaskResult(path, skipped="in use"))


# --------------------------------------------------------------------------
# Damaged files
# --------------------------------------------------------------------------

class Damaged(RooCase):

    def _read_all(self):
        err = io.StringIO()
        out = []
        with contextlib.redirect_stderr(err):
            for _ in range(2):
                for store in self.stores():
                    out += list(self.src.tool_calls(store))
                    out += list(self.src.secret_texts(store))
        return out, err.getvalue().splitlines()

    def test_garbage_warns_once_and_the_rest_is_read(self):
        garbage = self.task(None, task="g", raw=b"\x00\xff garbage" * 9)
        self.task_file("command-output/cmd-1.txt", None, task="g",
                       raw=b"\xff\xfe K=x")
        good = self.task(spec_native(), age=7200)
        _out, warnings = self._read_all()
        self.assertEqual(len(warnings), 1, warnings)
        self.assertIn(garbage, warnings[0])
        self.assertEqual(self.src.unreadable, {"not JSON": 1})
        self.assertEqual(len(self.calls(good)), 4)

    def test_wrong_shapes_everywhere_do_not_raise(self):
        docs = [{"a": 1}, None, [None, {"role": 5}, {"role": "assistant",
                                                    "content": [
            {"type": "tool_use", "id": "x", "name": "read_file",
             "input": {"files": "x", "args": 5, "path": ["x"]}},
            {"type": "tool_use", "id": "y", "name": "execute_command",
             "input": {"command": ["x"], "cwd": {"a": 1}}},
            {"type": "tool_use", "id": "z", "name": "apply_patch",
             "input": {"patch": 5}},
            {"type": "text", "text": "<read_file><args>5</args></read_file>"}]},
            {"role": "user", "content": [{"type": "tool_result",
                                          "tool_use_id": "x",
                                          "content": "{\"status\": [1]}"},
                                         {"type": "tool_result",
                                          "tool_use_id": "y",
                                          "content": "[1, 2]"}]}]]
        for n, doc in enumerate(docs):
            self.task(doc, task="w%d" % n, item=False)
            self.task_file("history_item.json", [1, 2], task="w%d" % n)
        self.task_file("ui_messages.json", "x", task="w0")
        _out, warnings = self._read_all()
        self.assertEqual(warnings, [])
        self.assertGreater(self.src.counts["unknown"], 0)

    def test_deep_nesting(self):
        self.task(None, task="deep", raw=b"[" * 100000 + b"]" * 100000)
        self.task_file("command-output/cmd-2.txt", None, task="deep",
                       raw="Artifact ID: cmd-2.txt")
        _out, warnings = self._read_all()
        self.assertEqual(len(warnings), 1, warnings)

    @unittest.skipIf(WINDOWS, "symlinks")
    def test_symlink_loops_and_folders_where_files_belong(self):
        tasks = os.path.join(self.gs, "tasks")
        os.makedirs(os.path.join(tasks, "t1", "api_conversation_history.json"))
        os.makedirs(os.path.join(tasks, "t1", "command-output", "cmd-1.txt"))
        os.makedirs(os.path.join(tasks, "t1", "history_item.json"))
        os.symlink(os.path.join(tasks, "loop"), os.path.join(tasks, "loop"))
        self.assertEqual(self.stores(), [])

    def test_reading_writes_nothing(self):
        self.task(spec_native())
        self.task_file("ui_messages.json", ui_log())
        self.task_file("command-output/cmd-1.txt", None, raw="x")
        before = {os.path.join(d, f): _sha(os.path.join(d, f))
                  for d, _s, fs in os.walk(self.home) for f in fs}
        dirs = sorted(d for d, _s, _f in os.walk(self.home))
        self._read_all()
        for store in self.stores():
            self.findings(store.path)
        after = {os.path.join(d, f): _sha(os.path.join(d, f))
                 for d, _s, fs in os.walk(self.home) for f in fs}
        self.assertEqual(before, after)
        self.assertEqual(dirs, sorted(d for d, _s, _f in os.walk(self.home)))


class Review(RooCase):

    def test_a_stray_folder_in_the_editor_parent_hides_nothing(self):
        parent = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.dirname(self.gs))))
        for stray in ("sessions", "tasks"):
            os.makedirs(os.path.join(parent, stray, "other"), exist_ok=True)
        path = self.task(spec_native())
        self.assertIn(path, [s.path for s in self.stores()])

    @unittest.skipIf(os.name == "nt", "no FIFOs")
    def test_a_fifo_history_item_does_not_block(self):
        path = self.task(spec_native(), item=False)
        os.mkfifo(os.path.join(os.path.dirname(path), "history_item.json"))
        done = []
        import threading
        t = threading.Thread(target=lambda: done.append(self.stores()),
                             daemon=True)
        t.start()
        t.join(5)
        self.assertTrue(done, "stores() blocked on a FIFO")
        self.assertIn(path, [s.path for s in done[0]])

    def test_xml_in_a_native_message_is_not_a_call(self):
        messages = [first_user(),
                    assistant([{"type": "text", "text": "Not this: " + xml(
                        "execute_command", command="rm -rf ~")},
                        tool_use("t1", "read_file", {"path": "a"})], ts=MS + 1),
                    user(result("t1", "x"))]
        self.assertEqual([c.tool_name for c in self.calls(self.task(messages))],
                         ["read_file"])

    def test_a_skipped_multi_line_command_is_declined(self):
        messages = [first_user(),
                    assistant(xml("read_file", path="a") + "\n" + xml(
                        "execute_command", command="echo a\nrm -rf b"),
                        ts=MS + 1),
                    user(*xml_result("[read_file for 'a']",
                                     "The user denied this operation."),
                         {"type": "text", "text": "Skipping tool "
                          "[execute_command for 'echo a\nrm -rf b'] due to "
                          "user rejecting a previous tool."})]
        self.assertEqual([(c.tool_name, c.status)
                          for c in self.calls(self.task(messages))],
                         [("read_file", "declined"),
                          ("execute_command", "declined")])

    def test_xml_args_paths_stay_linear(self):
        from ranwhat.sources import roo
        started = time.time()
        self.assertEqual(roo._paths_in({"args": "<path>" + " " * 20000
                                        + "x </path>"}), (("x",), ("args",)))
        self.assertEqual(roo._paths_in({"args": "<path>x" * 20000}), ((), ()))
        self.assertLess(time.time() - started, 5)


if __name__ == "__main__":
    unittest.main()
