"""The Cline adapter (ranwhat/sources/cline.py, over _cline_tasks.py).

Fixtures are built field for field from the verified formats (Cline
v3.89.2 and v4.1.23, with v3.0.0 for the two-block XML result): a task
folder's api_conversation_history.json and ui_messages.json are compact
JSON.stringify output; an SDK session's manifest and messages file are
JSON.stringify(x, null, 2) plus a newline.

Everything runs in temp directories: the home directory, every Cline and
editor variable and clean's backup root point there, and the real home is
never read. Every secret is synthetic, and token-shaped ones are written as
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
from ranwhat.sources import _cline_tasks, _paths  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.cline import (ClineSource, read_files,  # noqa: E402
                                   run_commands)

ENVS = ("CLINE_DATA_DIR", "CLINE_DIR", "CLINE_SESSION_DATA_DIR",
        "VSCODE_PORTABLE", "VSCODE_APPDATA", "XDG_CONFIG_HOME", "APPDATA")
WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
LOGIN = "ghp_" "Q7mZ2xLk9VbN4cR8tY1wP6sD3fG5hJ0aK2eU"
PROVIDER_KEY = "sk-" "ant-api03-" "Vb7Nq2Lm9Xc4Rt8Yp1Wz6Ks3Df5Gh0Ja"

TASK = "1791380000000"
SID = "1791380000123_k3j9a"
MS = 1791380000000           # 2026-10-07T13:33:20Z
CWD = "/home/u/proj"
DENIED = "The user denied this operation."
REJECTED = ('{"error":"This tool call was rejected by the user and not '
            'executed. -- NOT a tool or system failure. Clarify with user '
            'before proceeding."}')


def _compact(obj):
    """JSON.stringify(obj)."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _pretty(obj):
    """JSON.stringify(obj, null, 2) + "\\n"."""
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


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
    return {"type": "text", "text": "<environment_details>\n# Current Working "
            "Directory (%s) Files\nsrc/\n.env\n</environment_details>" % cwd}


def first_user(task="fix the build", cwd=CWD):
    return {"role": "user", "content": [
        {"type": "text", "text": "<task>\n%s\n</task>" % task},
        env_details(cwd)], "ts": MS}


def xml(name, **params):
    """A tool written as Cline writes it in XML mode."""
    inner = "".join("<%s>%s</%s>\n" % (k, v, k) for k, v in params.items())
    return "<%s>\n%s</%s>" % (name, inner, name)


def assistant(text_or_blocks, ts=None, **extra):
    content = ([{"type": "text", "text": text_or_blocks}]
               if isinstance(text_or_blocks, str) else text_or_blocks)
    msg = {"role": "assistant", "content": content}
    if ts is not None:
        msg["ts"] = ts
    msg.update(extra)
    return msg


def result_text(desc, body):
    """One XML-mode result block, Cline 3.2x and later."""
    return {"type": "text", "text": "%s Result:\n%s" % (desc, body)}


def user(*blocks, ts=None):
    msg = {"role": "user", "content": list(blocks)}
    if ts is not None:
        msg["ts"] = ts
    return msg


def tool_use(cid, name, input_):
    return {"type": "tool_use", "id": cid, "name": name, "input": input_,
            "call_id": cid}


def tool_result(cid, content, **extra):
    block = {"type": "tool_result", "tool_use_id": cid, "call_id": cid,
             "content": content}
    block.update(extra)
    return block


def spec_xml():
    """The spec's section 6.1, field for field."""
    return [
        first_user(),
        assistant("Let me look.\n" + xml("execute_command",
                                         command="cat ~/.ssh/id_rsa",
                                         requires_approval="true"),
                  ts=MS + 500, id="req_01",
                  modelInfo={"providerId": "anthropic",
                             "modelId": "claude-sonnet-4-5", "mode": "act"},
                  metrics={"tokens": {"prompt": 1200, "completion": 80,
                                      "cached": 0}, "cost": 0.004}),
        user(result_text("[execute_command for 'cat ~/.ssh/id_rsa']", DENIED),
             {"type": "text", "text": "The user provided the following "
              "feedback:\n<feedback>\nno\n</feedback>"},
             {"type": "text", "text": "<environment_details>…"
              "</environment_details>"}, ts=MS + 900),
        assistant(xml("execute_command", command="npm run build",
                      requires_approval="false"), ts=MS + 1500),
        user(result_text("[execute_command for 'npm run build']",
                         "Command executed successfully (exit code 0).\n"
                         "Output:\n> build\ndone"), ts=MS + 1900),
        assistant(xml("read_file", path=".env"), ts=MS + 2500),
        user(result_text("[read_file for '.env']",
                         "STRIPE_KEY=%s" % SECRET), ts=MS + 2900),
        assistant(xml("write_to_file", path="src/a.ts",
                      content="export {}\n"), ts=MS + 3500),
        user(result_text("[write_to_file for 'src/a.ts']",
                         "The content was successfully saved to src/a.ts."),
             ts=MS + 3900),
    ]


def spec_native():
    """The spec's section 6.2."""
    return [
        first_user(),
        assistant([{"type": "text", "text": "Let me look.", "call_id": "m1"},
                   tool_use("toolu_01A", "execute_command",
                            {"command": "cat ~/.ssh/id_rsa",
                             "requires_approval": True})], ts=MS + 500),
        user(tool_result("toolu_01A", "[execute_command for 'cat ~/.ssh/id_rsa']"
                         " Result:\n" + DENIED), ts=MS + 900),
        assistant([tool_use("toolu_01B", "execute_command",
                            {"command": "npm run build",
                             "requires_approval": False})]),
        user(tool_result("toolu_01B", "[execute_command for 'npm run build'] "
                         "Result:\nCommand executed successfully (exit code "
                         "0).\nOutput:\ndone"), ts=MS + 1900),
        assistant([tool_use("toolu_01C", "read_file", {"path": ".env"})],
                  ts=MS + 2500),
        user(tool_result("toolu_01C", "[read_file for '.env'] Result:\n"
                         "STRIPE_KEY=%s" % SECRET)),
        assistant([tool_use("toolu_01D", "write_to_file",
                            {"path": "src/a.ts", "content": "export {}\n"})],
                  ts=MS + 3500),
    ]


def ui_log():
    """The spec's ui_messages.json, with the request duplicated in
    api_req_started."""
    return [
        {"ts": MS, "type": "say", "say": "task", "text": "fix the build"},
        {"ts": MS + 100, "type": "say", "say": "api_req_started",
         "text": _compact({"request": "<task>\nfix the build\n</task>\n\n"
                           "[read_file for '.env'] Result:\nSTRIPE_KEY=%s"
                           % SECRET, "tokensIn": 1200, "tokensOut": 80,
                           "cost": 0.004})},
        {"ts": MS + 700, "type": "ask", "ask": "command",
         "text": "cat ~/.ssh/id_rsa"},
        {"ts": MS + 900, "type": "say", "say": "user_feedback", "text": "no"},
        {"ts": MS + 2600, "type": "say", "say": "tool",
         "text": _compact({"tool": "readFile", "path": ".env",
                           "content": "/home/u/proj/.env",
                           "operationIsLocatedInWorkspace": True})},
    ]


def manifest(sid=SID, cwd=CWD):
    return {"version": 1, "session_id": sid, "source": "vscode", "pid": 4242,
            "started_at": "2026-10-07T10:00:00.123Z", "status": "completed",
            "interactive": True, "provider": "anthropic",
            "model": "claude-sonnet-4-5", "cwd": cwd, "workspace_root": cwd,
            "enable_tools": True, "enable_spawn": False, "enable_teams": False,
            "prompt": "fix the build", "metadata": {"title": "fix the build"},
            "messages_path": "/home/u/.cline/data/sessions/%s/%s.messages.json"
            % (sid, sid)}


def sdk_doc(messages, sid=SID):
    return {"version": 1, "updated_at": "2026-10-07T10:00:09.000Z",
            "agent": "lead", "sessionId": sid,
            "origin": {"source": "vscode", "mode": "user", "sessionId": sid},
            "messages": messages}


def sdk_spec():
    """The spec's section 6.3 messages."""
    return [
        {"id": "msg_m1", "role": "user", "ts": MS + 200, "content": [
            {"type": "text", "text": "<user_input mode=\"act\">fix the build"
             "</user_input>"}]},
        {"id": "msg_m2", "role": "assistant", "ts": MS + 500,
         "modelInfo": {"id": "claude-sonnet-4-5", "provider": "anthropic"},
         "metrics": {"inputTokens": 1200, "outputTokens": 80, "cost": 0.004},
         "content": [{"type": "tool_use", "id": "toolu_01A",
                      "name": "run_commands",
                      "input": {"commands": ["cat ~/.ssh/id_rsa"]}}]},
        {"id": "msg_m3", "role": "user", "ts": MS + 900, "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01A",
             "name": "run_commands", "content": REJECTED, "is_error": True}]},
        {"id": "msg_m4", "role": "assistant", "ts": MS + 1500, "content": [
            {"type": "tool_use", "id": "toolu_01B", "name": "run_commands",
             "input": {"commands": ["cat .env"]}}]},
        {"id": "msg_m5", "role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01B",
             "name": "run_commands",
             "content": [{"query": "cat .env",
                          "result": "STRIPE_KEY=%s\n" % SECRET,
                          "success": True}]}]},
        {"id": "msg_m6", "role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_01C", "name": "read_files",
             "input": {"files": [{"path": "/home/u/proj/.env"}]}}]},
        {"id": "msg_m7", "role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01C",
             "name": "read_files",
             "content": [{"query": "/home/u/proj/.env",
                          "result": "AWS_SECRET_ACCESS_KEY=x",
                          "success": True}]}]},
        {"id": "msg_m8", "role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_01D", "name": "editor",
             "input": {"path": "/home/u/proj/src/a.ts",
                       "new_text": "export {}\n"}}]},
        {"id": "msg_m9", "role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01D",
             "name": "editor",
             "content": "{\"query\":\"edit:/home/u/proj/src/a.ts\","
                        "\"result\":\"ok\",\"success\":true}"}]},
    ]


# --------------------------------------------------------------------------
# Common setup
# --------------------------------------------------------------------------

class ClineCase(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "cline-home-")
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
        self.backups = os.path.join(_tempdir(self, "cline-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.data = os.path.join(self.home, ".cline", "data")
        parent = _paths.editor_parent(os.environ, self.home,
                                      _paths.platform_name())
        self.gs = os.path.join(parent, "Code", "User", "globalStorage",
                               "saoudrizwan.claude-dev")
        self.src = ClineSource()

    def write(self, path, raw, age=3600):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def task(self, messages, task=TASK, root=None, age=3600, raw=None):
        path = os.path.join(root or self.data, "tasks", task,
                            "api_conversation_history.json")
        return self.write(path, raw if raw is not None else _compact(messages),
                          age)

    def ui(self, items, task=TASK, root=None, age=3600):
        return self.write(os.path.join(root or self.data, "tasks", task,
                                       "ui_messages.json"), _compact(items), age)

    def session(self, messages, sid=SID, age=3600, raw=None, folder=None,
                with_manifest=True, stem=None):
        folder = folder or os.path.join(self.data, "sessions", sid)
        if with_manifest:
            self.write(os.path.join(folder, sid + ".json"),
                       _pretty(manifest(sid)), age)
        path = os.path.join(folder, (stem or sid) + ".messages.json")
        return self.write(path, raw if raw is not None
                          else _pretty(sdk_doc(messages, sid)), age)

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

    def strings(self, path):
        out = []
        for text in self.src.secret_texts(self.store(path)):
            clean._each_string(text.node, lambda s: out.append(s) or s)
        return "\n".join(out)


# --------------------------------------------------------------------------
# Where Cline keeps its history
# --------------------------------------------------------------------------

class DefaultPaths(unittest.TestCase):

    def test_each_platform(self):
        s = ClineSource()
        self.assertEqual(s.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.cline/data", "default"),
                          ("/home/u/.config", "default")])
        self.assertEqual(s.default_paths({"XDG_CONFIG_HOME": "/cfg"},
                                         "/home/u", "linux")[1],
                         ("/cfg", "default"))
        self.assertEqual(s.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.cline/data", "default"),
                          ("/Users/u/Library/Application Support", "default")])
        self.assertEqual(s.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.cline\\data", "default"),
                          ("C:\\Users\\u\\AppData\\Roaming", "default")])

    def test_variables(self):
        s = ClineSource()
        got = s.default_paths({"CLINE_DATA_DIR": "  /srv/cline  ",
                               "CLINE_DIR": "/opt/c"}, "/home/u", "linux")
        self.assertEqual(got[:2], [("/srv/cline", "env CLINE_DATA_DIR"),
                                   ("/home/u/.cline/data", "default")])
        got = s.default_paths({"CLINE_DIR": "/opt/c"}, "/home/u", "linux")
        self.assertEqual(got[:2], [("/opt/c/data", "env CLINE_DIR"),
                                   ("/home/u/.cline/data", "default")])
        got = s.default_paths({"CLINE_DIR": "D:\\c"}, "C:\\Users\\u", "win32")
        self.assertEqual(got[0], ("D:\\c\\data", "env CLINE_DIR"))
        got = s.default_paths({"CLINE_SESSION_DATA_DIR": "/s"}, "/home/u",
                              "linux")
        self.assertEqual(got[1], ("/s", "env CLINE_SESSION_DATA_DIR"))
        got = s.default_paths({"VSCODE_PORTABLE": "/p", "VSCODE_APPDATA": "/a"},
                              "/home/u", "linux")
        self.assertEqual(got[1:], [
            ("/p/user-data/User/globalStorage/saoudrizwan.claude-dev",
             "env VSCODE_PORTABLE"), ("/a", "env VSCODE_APPDATA"),
            ("/home/u/.config", "default")])

    def test_an_empty_variable_is_not_set(self):
        s = ClineSource()
        got = s.default_paths({"CLINE_DATA_DIR": " ", "CLINE_DIR": "",
                               "CLINE_SESSION_DATA_DIR": ""}, "/home/u", "linux")
        self.assertEqual(got[0], ("/home/u/.cline/data", "default"))
        self.assertFalse([h for _p, h in got if h.startswith("env CLINE")])

    def test_what_every_report_needs(self):
        s = ClineSource()
        self.assertEqual((s.id, s.name, s.unit, s.env, s.checked),
                         ("cline", "Cline", "task",
                          ("CLINE_DATA_DIR", "CLINE_DIR",
                           "CLINE_SESSION_DATA_DIR"), "4.1.23"))
        self.assertIn("CLINE_DATA_DIR", s.path_means)
        self.assertFalse(s.read_only)
        self.assertTrue(s.mask_note)


class Discovery(ClineCase):

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
        api = self.task(spec_xml(), age=7200)
        ui = self.ui(ui_log(), age=7100)
        old = self.write(os.path.join(self.data, "tasks", TASK,
                                      "claude_messages.json"), "[]", age=7000)
        gs_api = self.task(spec_native(), task="1791380009999", root=self.gs,
                           age=60)
        sdk = self.session(sdk_spec(), age=30)
        nightly = self.task(spec_xml(), task="1791380008888", age=25,
                            root=os.path.join(os.path.dirname(os.path.dirname(
                                os.path.dirname(os.path.dirname(self.gs)))),
                                "Cursor", "User", "globalStorage",
                                "saoudrizwan.cline-nightly"))
        sub = self.session(sdk_spec(), stem="agent_7", with_manifest=False,
                           age=20)
        # things that are never stores
        for rel in ("secrets.json", "settings/providers.json",
                    "settings/cline_mcp_settings.json", "globalState.json",
                    "tasks/notes.json", "tasks/%s/task_metadata.json" % TASK,
                    "tasks/%s/settings.json" % TASK,
                    "tasks/%s/context_history.json" % TASK,
                    "tasks/%s/api_conversation_history.json.tmp.1.2.json" % TASK,
                    "tasks/.hidden/api_conversation_history.json",
                    "sessions/%s/%s.compaction.json" % (SID, SID),
                    "db/sessions.db", "state/taskHistory.json"):
            self.write(os.path.join(self.data, *rel.split("/")), "[]")
        self.write(os.path.join(self.gs, "checkpoints", "x",
                                "api_conversation_history.json"), "[]")
        got = self.stores()
        self.assertEqual([s.path for s in got],
                         [sub, nightly, sdk, gs_api, old, ui, api])
        by = {s.path: s for s in got}
        self.assertEqual((by[api].format, by[api].role, by[api].session,
                          by[api].masking), ("json", "transcript", TASK,
                                             "rewrite"))
        self.assertEqual((by[ui].role, by[ui].unit), ("side", "task log"))
        self.assertEqual(by[old].role, "side")
        self.assertEqual((by[sdk].role, by[sdk].unit, by[sdk].session,
                          by[sdk].project), ("transcript", "session", SID, CWD))
        self.assertEqual((by[sub].session, by[sub].project), ("agent_7", CWD))
        self.assertEqual(by[gs_api].project, CWD)

    def test_project_from_the_task_index_else_the_environment_details(self):
        api = self.task(spec_xml())
        other = self.task([first_user(cwd="/srv/other")], task="17913800005")
        self.write(os.path.join(self.data, "state", "taskHistory.json"),
                   _compact([{"id": TASK, "ts": MS, "task": "fix the build",
                              "tokensIn": 1, "tokensOut": 1, "totalCost": 0,
                              "cwdOnTaskInitialization": "/home/u/indexed"}]))
        self.assertEqual(self.store(api).project, "/home/u/indexed")
        self.assertEqual(self.store(other).project, "/srv/other")
        calls = self.calls(api)
        self.assertTrue(all(c.project == "/home/u/indexed" for c in calls))

    def test_a_windows_working_directory(self):
        api = self.task([first_user(cwd="C:/Users/u/proj"),
                         assistant(xml("execute_command", command="dir"))])
        self.assertEqual(self.store(api).project, "C:/Users/u/proj")

    def test_a_multi_root_header_is_not_a_directory(self):
        msg = first_user()
        msg["content"][1]["text"] = msg["content"][1]["text"].replace(
            "(%s)" % CWD, "(Primary: proj)")
        api = self.task([msg])
        self.assertIsNone(self.store(api).project)

    def test_the_session_dir_variable_is_read_at_call_time(self):
        flat = os.path.join(_tempdir(self, "cline-flat-"))
        path = self.session(sdk_spec(), folder=os.path.join(flat, SID))
        self.assertEqual(self.stores(), [])
        os.environ["CLINE_SESSION_DATA_DIR"] = flat
        self.assertEqual([s.path for s in self.stores()], [path])

    def test_the_data_dir_variables(self):
        moved = _tempdir(self, "cline-moved-")
        path = self.task(spec_xml(), root=moved)
        self.assertEqual(self.stores(), [])
        os.environ["CLINE_DATA_DIR"] = moved
        self.assertEqual([s.path for s in self.stores()], [path])
        del os.environ["CLINE_DATA_DIR"]
        os.environ["CLINE_DIR"] = os.path.dirname(moved)
        self.assertEqual(self.stores(), [])
        top = _tempdir(self, "cline-top-")
        path = self.task(spec_xml(), root=os.path.join(top, "data"))
        os.environ["CLINE_DIR"] = top
        self.assertEqual([s.path for s in self.stores()], [path])

    def test_path_override_and_a_missing_root(self):
        other = _tempdir(self, "cline-other-")
        path = self.task(spec_xml(), root=other)
        self.assertEqual([s.path for s in self.stores(override=other)], [path])
        self.assertEqual(self.stores(override=os.path.join(other, "nope")), [])
        self.assertEqual(self.stores(), [])
        [loc] = self.src.locations(override=other)
        self.assertEqual((loc.exists, loc.found), (True, 1))

    def test_days_prefilter_by_last_write(self):
        self.task(spec_xml(), age=10 * 86400)
        new = self.session(sdk_spec(), age=60)
        self.assertEqual([s.path for s in self.stores(since_days=2)], [new])


# --------------------------------------------------------------------------
# Tool calls
# --------------------------------------------------------------------------

class Calls(ClineCase):

    def test_the_xml_spec_sample(self):
        calls = self.calls(self.task(spec_xml()))
        self.assertEqual([(c.tool_call_id, c.tool_name, c.kind, c.known)
                          for c in calls],
                         [("xml-1-0-0", "execute_command", "shell", True),
                          ("xml-3-0-0", "execute_command", "shell", True),
                          ("xml-5-0-0", "read_file", "read", True),
                          ("xml-7-0-0", "write_to_file", "write", True)])
        cat, build, read, write = calls
        self.assertEqual((cat.command, cat.status, cat.output),
                         ("cat ~/.ssh/id_rsa", "declined", DENIED))
        self.assertEqual(cat.tool_input, {"command": "cat ~/.ssh/id_rsa",
                                          "requires_approval": "true"})
        self.assertEqual(cat.consumed, frozenset(["command"]))
        self.assertEqual((cat.workdir, cat.project, cat.session),
                         (CWD, CWD, TASK))
        self.assertEqual(cat.timestamp, _iso(MS + 500))
        self.assertIsNone(cat.not_after)
        self.assertIsNone(build.status)
        self.assertEqual(build.output, "Command executed successfully (exit "
                         "code 0).\nOutput:\n> build\ndone")
        self.assertEqual((read.paths, read.consumed),
                         ((".env",), frozenset(["path"])))
        self.assertEqual(read.output, "STRIPE_KEY=%s" % SECRET)
        self.assertEqual((write.paths, write.consumed), (("src/a.ts",),
                                                         frozenset()))
        self.assertEqual(write.tool_input["content"], "export {}")
        self.assertTrue(all(c.source == "cline" for c in calls))

    def test_the_native_spec_sample(self):
        got = self.by_id(self.task(spec_native()))
        self.assertEqual(list(got), ["toolu_01A", "toolu_01B", "toolu_01C",
                                     "toolu_01D"])
        self.assertEqual((got["toolu_01A"].status, got["toolu_01A"].output),
                         ("declined", DENIED))
        self.assertIsNone(got["toolu_01B"].status)
        self.assertEqual(got["toolu_01B"].output, "Command executed "
                         "successfully (exit code 0).\nOutput:\ndone")
        self.assertEqual(got["toolu_01C"].paths, (".env",))
        self.assertEqual(got["toolu_01D"].kind, "write")
        self.assertIsNone(got["toolu_01D"].output)
        self.assertEqual(got["toolu_01A"].tool_input,
                         {"command": "cat ~/.ssh/id_rsa",
                          "requires_approval": True})

    def test_the_sdk_spec_sample(self):
        got = self.by_id(self.session(sdk_spec()))
        self.assertEqual(list(got), ["toolu_01A", "toolu_01B", "toolu_01C",
                                     "toolu_01D"])
        a, b, c, d = (got[k] for k in got)
        self.assertEqual((a.kind, a.command, a.status, a.consumed),
                         ("shell", "cat ~/.ssh/id_rsa", "declined",
                          frozenset(["commands"])))
        self.assertEqual((b.command, b.status, b.output),
                         ("cat .env", None, "STRIPE_KEY=%s\n" % SECRET))
        self.assertEqual((c.kind, c.paths, c.consumed),
                         ("read", ("/home/u/proj/.env",), frozenset(["files"])))
        self.assertEqual(c.output, "AWS_SECRET_ACCESS_KEY=x")
        self.assertEqual((d.kind, d.paths), ("write", ("/home/u/proj/src/a.ts",)))
        self.assertEqual((a.session, a.project, a.workdir), (SID, CWD, CWD))
        self.assertEqual(a.timestamp, _iso(MS + 500))

    def test_every_classic_tool(self):
        cases = [
            ("execute_command", {"command": "ls -la", "requires_approval": "false"},
             "shell", "ls -la", ()),
            ("read_file", {"path": "src/x.py"}, "read", None, ("src/x.py",)),
            ("read_file", {"path": "@web:src/x.py"}, "read", None, ("src/x.py",)),
            ("write_to_file", {"path": "a.txt", "content": "x"}, "write", None,
             ("a.txt",)),
            ("write_to_file", {"absolutePath": "/abs/a.txt", "content": "x"},
             "write", None, ("/abs/a.txt",)),
            ("replace_in_file", {"path": "b.txt", "diff": "-x\n+y"}, "write",
             None, ("b.txt",)),
            ("new_rule", {"path": ".clinerules/r.md", "content": "x"}, "write",
             None, (".clinerules/r.md",)),
            ("apply_patch", {"input": "*** Begin Patch\n*** Update File: a.py\n"
                             "@@\n-x\n+y\n*** Add File: b.py\n+z\n"
                             "*** End Patch"}, "write", None, ("a.py", "b.py")),
            ("web_fetch", {"url": "https://example.com"}, "fetch", None, ()),
            ("web_search", {"query": "x"}, "fetch", None, ()),
            ("browser_action", {"action": "launch", "url": "http://localhost"},
             "fetch", None, ()),
        ]
        others = ["search_files", "list_files", "list_code_definition_names",
                  "use_mcp_tool", "access_mcp_resource",
                  "load_mcp_documentation", "ask_followup_question",
                  "attempt_completion", "new_task", "plan_mode_respond",
                  "act_mode_respond", "focus_chain", "condense",
                  "summarize_task", "report_bug", "generate_explanation",
                  "use_skill", "use_subagents"]
        cases += [(n, {"path": "x"}, "other", None, ()) for n in others]
        for native in (True, False):
            messages = [first_user()]
            for n, (name, args, _k, _c, _p) in enumerate(cases):
                if native:
                    messages.append(assistant([tool_use("t%d" % n, name, args)]))
                else:
                    messages.append(assistant(xml(name, **args)))
            calls = self.calls(self.task(messages, task="t%s" % native))
            self.assertEqual(len(calls), len(cases))
            for call, (name, _a, kind, command, paths) in zip(calls, cases):
                self.assertEqual((call.tool_name, call.kind, call.known,
                                  call.command, call.paths),
                                 (name, kind, True, command, paths),
                                 (native, name))

    def test_every_sdk_tool(self):
        cases = [
            ("run_commands", {"commands": ["ls"]}, "shell", "ls", ()),
            ("read_files", {"files": [{"path": "/a"}, {"path": "/b",
                                                       "start_line": 2}]},
             "read", None, ("/a", "/b")),
            ("editor", {"path": "/c", "old_text": "x", "new_text": "y"},
             "write", None, ("/c",)),
            ("apply_patch", {"input": "*** Begin Patch\n*** Delete File: d\n"
                             "*** End Patch"}, "write", None, ("d",)),
            ("apply_patch", "*** Begin Patch\n*** Update File: e\n*** Move to:"
             " f\n*** End Patch", "write", None, ("e", "f")),
            ("fetch_web_content", {"requests": [{"url": "https://x",
                                                 "prompt": "sum"}]},
             "fetch", None, ()),
            ("search_codebase", {"queries": ["x"]}, "other", None, ()),
            ("skills", {"skill": "s"}, "other", None, ()),
            ("ask_question", {"question": "q"}, "other", None, ()),
            ("submit_and_exit", {}, "other", None, ()),
        ]
        messages = [{"role": "assistant", "content": [
            {"type": "tool_use", "id": "s%d" % n, "name": name, "input": args}]}
            for n, (name, args, _k, _c, _p) in enumerate(cases)]
        calls = self.calls(self.session(messages))
        for call, (name, _a, kind, command, paths) in zip(calls, cases):
            self.assertEqual((call.tool_name, call.kind, call.known,
                              call.command, call.paths),
                             (name, kind, True, command, paths), name)
        # a classic name in an SDK session is not one of the SDK's tools
        [call] = self.calls(self.session(
            [assistant([tool_use("x", "execute_command", {"command": "ls"})])],
            sid="1791380000999_zzzzz"))
        self.assertEqual((call.kind, call.known), ("other", False))

    def test_run_commands_in_every_shape(self):
        self.assertEqual(run_commands({"commands": ["a", "b"]}),
                         (["a", "b"], ("commands",)))
        self.assertEqual(run_commands({"commands": "a"}), (["a"], ("commands",)))
        self.assertEqual(run_commands({"command": "a"}), (["a"], ("command",)))
        self.assertEqual(run_commands({"cmd": "a"}), (["a"], ("cmd",)))
        self.assertEqual(run_commands("rm -rf x"), (["rm -rf x"], ("_raw",)))
        self.assertEqual(run_commands(["a", "b"]), (["a", "b"], ("_value",)))
        self.assertEqual(run_commands({"command": "git", "args": [
            "commit", "-m", "two words", 'say "hi"']}),
            (['git commit -m "two words" "say \\"hi\\""'],
             ("command", "args")))
        self.assertEqual(run_commands({"commands": [
            {"command": "ls"}, {"command": "rm", "args": ["-rf", "x"]}]}),
            (["ls", "rm -rf x"], ("commands",)))
        # a heredoc the model split over entries is run as one command
        self.assertEqual(run_commands({"commands": [
            "cat > a <<'EOF'", "line", "EOF", "ls"]}),
            (["cat > a <<'EOF'\nline\nEOF", "ls"], ("commands",)))
        for odd in (None, 5, {}, {"commands": [None, 3]}, {"x": 1}, []):
            self.assertEqual(run_commands(odd)[0], [])

    def test_read_files_in_every_shape(self):
        self.assertEqual(read_files({"files": [{"path": "/a"}, "/b"]}),
                         (("/a", "/b"), ("files",)))
        self.assertEqual(read_files({"files": {"file_path": "/a"}}),
                         (("/a",), ("files",)))
        self.assertEqual(read_files({"file_paths": ["/a"]}), (("/a",),
                                                              ("file_paths",)))
        self.assertEqual(read_files({"paths": "/a"}), (("/a",), ("paths",)))
        self.assertEqual(read_files({"filePath": "/a"}), (("/a",), ("filePath",)))
        self.assertEqual(read_files("/a"), (("/a",), ("_raw",)))
        self.assertEqual(read_files(["/a", {"path": "/b"}]),
                         (("/a", "/b"), ("_value",)))
        self.assertEqual(read_files({"x": 1}), ((), ()))

    def test_several_commands_are_one_call_each_with_its_output(self):
        messages = [
            {"role": "assistant", "ts": MS, "content": [
                tool_use("rc", "run_commands", {"commands": [
                    "cat .env", "rm -rf ~/Documents/x"]})]},
            {"role": "user", "content": [tool_result("rc", [
                {"query": "cat .env", "result": "K=%s" % SECRET,
                 "success": True},
                {"query": "rm -rf ~/Documents/x", "result": "",
                 "error": "Command failed: exit 1", "success": False}],
                name="run_commands")]}]
        path = self.session(messages)
        got = self.by_id(path)
        self.assertEqual(list(got), ["rc#1", "rc#2"])
        self.assertEqual(got["rc#1"].output, "K=%s" % SECRET)
        self.assertEqual(got["rc#2"].output, "Command failed: exit 1")
        self.assertEqual(rules(got["rc#2"]),
                         [("fs.destructive", "rm -rf ~/Documents/x")])
        found = self.findings(path)
        [entry] = found.values()
        self.assertEqual(entry["origins"], {".env"})

    def test_an_unknown_tool_is_judged_by_its_name(self):
        messages = [first_user(), assistant([tool_use(
            "mcp", "mcp__srv__bash", {"command": "rm -rf ~/Documents/x"})]),
            assistant("<rm_everything><path>/</path></rm_everything>")]
        calls = self.calls(self.task(messages))
        [call] = calls      # an XML tag of no Cline tool is text
        self.assertEqual((call.kind, call.known), ("other", False))
        self.assertEqual(watch.judge(call),
                         watch.evaluate(call.tool_name, call.tool_input))
        self.assertEqual(rules(call), [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_the_two_block_result_of_cline_3_0(self):
        messages = [first_user(),
                    assistant(xml("read_file", path=".env")),
                    user({"type": "text", "text": "[read_file for '.env'] Result:"},
                         {"type": "text", "text": "K=%s" % SECRET},
                         env_details())]
        path = self.task(messages)
        [call] = self.calls(path)
        self.assertEqual(call.output, "K=%s" % SECRET)
        texts = list(self.src.secret_texts(self.store(path)))
        tied = [t for t in texts if t.call is not None]
        self.assertEqual(len(tied), 2)
        [entry] = self.findings(path).values()
        self.assertEqual(entry["origins"], {".env"})

    def test_xml_as_the_agent_parses_it(self):
        text = ("I will run <execute_command><command>ls -la</command>"
                "</execute_command> and then <read_file>\n<path> a.txt </path>"
                "\n</read_file> done. <bogus>x</bogus> "
                "<write_to_file><path>w.html</path><content>\n<p>"
                "</content></p>\n</content></write_to_file>"
                " <list_files> no params, never closed")
        calls = self.calls(self.task([first_user(), assistant(text)]))
        self.assertEqual([(c.tool_call_id, c.tool_name) for c in calls],
                         [("xml-1-0-0", "execute_command"),
                          ("xml-1-0-1", "read_file"),
                          ("xml-1-0-2", "write_to_file")])
        self.assertEqual(calls[1].paths, ("a.txt",))
        self.assertEqual(calls[2].tool_input["content"], "<p></content></p>")

    def test_an_unclosed_tool_with_a_parameter_ran(self):
        text = "<execute_command>\n<command>rm -rf ~/Documents/x</command>\n"
        [call] = self.calls(self.task([first_user(), assistant(text)]))
        self.assertEqual(call.command, "rm -rf ~/Documents/x")
        text = "<execute_command>\n<command>rm -rf ~/Documents/x"
        [call] = self.calls(self.task([first_user(), assistant(text)]))
        self.assertEqual(call.command, "rm -rf ~/Documents/x")

    def test_a_string_content_and_a_user_message_are_read(self):
        messages = [{"role": "user", "content": "<task>x</task>"},
                    {"role": "assistant", "content": xml("execute_command",
                                                         command="ls")},
                    {"role": "user", "content": "[execute_command for 'ls'] "
                     "Result:\nfile"},
                    user({"type": "text",
                          "text": xml("execute_command", command="rm -rf /")})]
        [call] = self.calls(self.task(messages))
        self.assertEqual((call.tool_call_id, call.output), ("xml-1-0-0", "file"))

    def test_dedupe(self):
        dup = [first_user(),
               assistant([tool_use("same", "execute_command", {"command": "a"})]),
               user(tool_result("same", "[execute_command for 'a'] Result:\nA")),
               assistant([tool_use("same", "execute_command", {"command": "b"})]),
               user(tool_result("same", "[execute_command for 'b'] Result:\nB"))]
        path = self.task(dup)
        [call] = self.calls(path)
        self.assertEqual((call.command, call.output), ("a", "A"))
        self.assertEqual([c.tool_call_id for c in self.calls(path)], ["same"])

    def test_time(self):
        messages = [first_user(),
                    assistant(xml("execute_command", command="a"), ts=MS + 10),
                    user(result_text("[execute_command for 'a']", "x"),
                         ts=MS + 20),
                    assistant(xml("execute_command", command="b")),
                    user(result_text("[execute_command for 'b']", "x"),
                         ts=MS + 30000),
                    assistant(xml("execute_command", command="c")),
                    user(result_text("[execute_command for 'c']", "x"))]
        path = self.task(messages)
        a, b, c = self.calls(path)
        self.assertEqual((a.timestamp, a.not_after), (_iso(MS + 10), None))
        self.assertEqual((b.timestamp, b.not_after), (None, _iso(MS + 30000)))
        self.assertIsNone(c.timestamp)
        self.assertEqual(c.not_after,
                         time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                       time.gmtime(os.stat(path).st_mtime)))


class Declined(ClineCase):

    def test_the_agents_own_texts(self):
        def answered(n, text, native):
            name = "execute_command"
            if native:
                return [assistant([tool_use("n%d" % n, name, {"command": "x"})]),
                        user(tool_result("n%d" % n, text))]
            return [assistant(xml(name, command="x")),
                    user({"type": "text", "text": text})]

        texts = [
            ("[execute_command for 'x'] Result:\n" + DENIED, True),
            ("[execute_command for 'x'] Result:\nThe user denied this operation"
             " and provided the following feedback:\n<feedback>\nno\n"
             "</feedback>", True),
            ("[execute_command for 'x'] Result:\nThe tool execution failed with"
             " the following error:\n<error>\nCommand execution blocked by "
             "CLINE_COMMAND_PERMISSIONS: nope. You must try a different "
             "approach.\n</error>", True),
            ("[execute_command for 'x'] Result:\nThe tool execution failed with"
             " the following error:\n<error>\nAccess to .env is blocked by the "
             ".clineignore file settings. You must try...\n</error>", True),
            ("[execute_command for 'x'] Result:\nThe tool execution failed with"
             " the following error:\n<error>\nboom\n</error>", False),
            ("[execute_command for 'x'] Result:\nCommand executed.", False),
            ("[execute_command for 'x'] Result:\nCommand executed.\nOutput:\n"
             "The user denied this operation.", False),
        ]
        for native in (True, False):
            messages = [first_user()]
            for n, (text, _d) in enumerate(texts):
                messages += answered(n, text, native)
            calls = self.calls(self.task(messages, task="d%s" % native))
            self.assertEqual([c.status == "declined" for c in calls],
                             [d for _t, d in texts], native)

    def test_calls_skipped_after_a_rejection_or_a_first_tool(self):
        # native: Cline answers later calls of the message as plain text
        messages = [first_user(),
                    assistant([tool_use("a", "execute_command", {"command": "a"}),
                               tool_use("b", "read_file", {"path": "~/.ssh/id_rsa"}),
                               tool_use("c", "execute_command", {"command": "c"})]),
                    user(tool_result("a", "[execute_command for 'a'] Result:\n"
                                     + DENIED),
                         {"type": "text", "text": "Skipping tool due to user "
                          "rejecting a previous tool. [read_file for "
                          "'~/.ssh/id_rsa']"},
                         {"type": "text", "text": "Tool [execute_command] was not"
                          " executed because a tool has already been used in "
                          "this message. Only one tool may be used per message."
                          " You must assess the first tool's result before "
                          "proceeding to use the next tool."})]
        got = self.by_id(self.task(messages))
        self.assertEqual([got[k].status for k in "abc"], ["declined"] * 3)
        # XML: the second tool of a message never ran
        text = (xml("execute_command", command="ls") + "\n"
                + xml("execute_command", command="rm -rf ~/Documents/x"))
        messages = [first_user(), assistant(text),
                    user(result_text("[execute_command for 'ls']", "a b"),
                         {"type": "text", "text": "Tool [execute_command] was "
                          "not executed because a tool has already been used in "
                          "this message. Only one tool may be used per message."})]
        ls, rm = self.calls(self.task(messages, task="x2"))
        self.assertEqual((ls.status, ls.output), (None, "a b"))
        self.assertEqual(rm.status, "declined")
        # a declined call is still judged
        self.assertEqual(rules(rm), [("fs.destructive", "rm -rf ~/Documents/x")])

    def test_sdk_refusals(self):
        def call(n, content, is_error=True):
            return [{"role": "assistant", "content": [{
                "type": "tool_use", "id": "s%d" % n, "name": "run_commands",
                "input": {"commands": ["x"]}}]},
                {"role": "user", "content": [dict(tool_result(
                    "s%d" % n, content, name="run_commands"),
                    is_error=is_error)]}]

        cases = [
            (REJECTED, True, True),
            ('{"error":"Tool approval request timed out -- NOT a tool or system'
             ' failure. Clarify with user before proceeding."}', True, True),
            ('{"error":"Tool \\"run_commands\\" is disabled by policy"}', True,
             True),
            ('{"error":"Tool run_commands was blocked by a runtime hook"}',
             True, True),
            ('{"error":"Unknown tool: run_commands"}', True, True),
            ('{"error":"Command failed: boom"}', True, False),
            (REJECTED, False, False),
            ([{"query": "x", "result": REJECTED, "success": True}], False,
             False),
        ]
        messages = []
        for n, (content, is_error, _d) in enumerate(cases):
            messages += call(n, content, is_error)
        calls = self.calls(self.session(messages))
        self.assertEqual([c.status == "declined" for c in calls],
                         [d for _c, _e, d in cases])


class Judged(ClineCase):

    def test_dangerous_calls_are_flagged(self):
        messages = [first_user(),
                    assistant(xml("execute_command",
                                  command="rm -rf ~/Documents/x")),
                    assistant([tool_use("ssh", "read_file",
                                        {"path": "~/.ssh/id_rsa"})]),
                    assistant(xml("read_file", path="~/.aws/credentials"))]
        rm, ssh, aws = self.calls(self.task(messages))
        self.assertEqual(rules(rm), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(ssh), [("cred.read", "~/.ssh/id_rsa")])
        self.assertEqual(rules(aws), [("cred.read", "~/.aws/credentials")])
        messages = [{"role": "assistant", "content": [
            tool_use("a", "run_commands", {"commands": ["cat ~/.aws/credentials"]}),
            tool_use("b", "read_files", {"files": [{"path": "/home/u/.ssh/id_rsa"}]})]}]
        a, b = self.calls(self.session(messages))
        self.assertEqual(rules(a), [("cred.read", "cat ~/.aws/credentials")])
        self.assertEqual([r for r, _e in rules(b)], ["cred.read"])

    def test_writing_a_dangerous_script_is_not_running_it(self):
        messages = [first_user(),
                    assistant(xml("write_to_file", path="clean.sh",
                                  content="rm -rf /\n")),
                    assistant(xml("execute_command",
                                  command="grep -rn 'rm -rf' ."))]
        for call in self.calls(self.task(messages)):
            self.assertEqual(rules(call), [], call.tool_name)


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(ClineCase):

    def test_a_secret_in_cat_env_output_has_origin_env(self):
        messages = [first_user(),
                    assistant(xml("execute_command", command="cat .env")),
                    user(result_text("[execute_command for 'cat .env']",
                                     "Command executed.\nOutput:\nSTRIPE_KEY="
                                     + SECRET))]
        for path in (self.task(messages),
                     self.task(spec_native(), task="n"),
                     self.session(sdk_spec())):
            found = self.findings(path)
            [entry] = [e for e in found.values()
                       if e["fingerprint"] == clean._fingerprint(SECRET)]
            self.assertEqual(entry["origins"], {".env"}, path)
            self.assertEqual(entry["sources"], {"cline"})
            self.assertEqual(entry["projects"], {CWD})

    def test_the_result_is_tied_to_its_call(self):
        path = self.task(spec_native())
        texts = list(self.src.secret_texts(self.store(path)))
        tied = [t for t in texts if t.call is not None]
        self.assertEqual(sorted(set(t.call.tool_call_id for t in tied)),
                         ["toolu_01A", "toolu_01B", "toolu_01C"])
        for t in texts:
            if SECRET in json.dumps(t.node):
                self.assertEqual(t.call.tool_call_id, "toolu_01C")

    def test_the_ui_log_is_searched(self):
        path = self.ui(ui_log())
        store = self.store(path)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        found = self.findings(path)
        self.assertEqual([e["fingerprint"] for e in found.values()],
                         [clean._fingerprint(SECRET)])

    def test_every_string_reaches_clean(self):
        joined = self.strings(self.task(spec_xml()))
        for needle in (SECRET, "fix the build", "claude-sonnet-4-5",
                       "cat ~/.ssh/id_rsa", "export {}", "no", "req_01"):
            self.assertIn(needle, joined)
        joined = self.strings(self.session(sdk_spec()))
        for needle in (SECRET, "AWS_SECRET_ACCESS_KEY", "lead", "msg_m9",
                       "edit:/home/u/proj/src/a.ts"):
            self.assertIn(needle, joined)

    def test_login_material_is_never_searched(self):
        self.write(os.path.join(self.data, "secrets.json"),
                   _compact({"apiKey": PROVIDER_KEY, "clineAccountId": LOGIN}))
        self.write(os.path.join(self.data, "settings", "providers.json"),
                   _pretty({"providers": {"anthropic": {
                       "apiKey": PROVIDER_KEY,
                       "auth": {"accessToken": LOGIN, "refreshToken": LOGIN}}}}))
        self.write(os.path.join(self.data, "settings",
                                "cline_mcp_settings.json"),
                   _pretty({"mcpServers": {"gh": {"env": {"TOKEN": LOGIN}}}}))
        self.write(os.path.join(self.data, "globalState.json"),
                   _compact({"x": LOGIN}))
        self.write(os.path.join(self.data, "state", "taskHistory.json"),
                   _compact([{"id": TASK, "task": LOGIN}]))
        self.write(os.path.join(self.gs, "settings", "cline_mcp_settings.json"),
                   _pretty({"mcpServers": {"gh": {"env": {"TOKEN": LOGIN}}}}))
        self.task(spec_xml())
        self.ui(ui_log())
        self.session(sdk_spec())
        texts = []
        for store in self.stores():
            for text in self.src.secret_texts(store):
                texts.append(json.dumps(text.node))
        joined = "\n".join(texts)
        self.assertIn(SECRET, joined)
        self.assertNotIn(LOGIN, joined)
        self.assertNotIn(PROVIDER_KEY, joined)


class Masking(ClineCase):

    def test_round_trip_of_a_task(self):
        path = self.task(spec_xml(), age=600)
        before = self.calls(path)
        result = self.src.mask(self.store(path), [SECRET])
        self.assertTrue(result.changed, result)
        self.assertIsNotNone(result.backup)
        with open(path, "rb") as fh:
            after = fh.read().decode("utf-8")
        self.assertNotIn(SECRET, after)
        self.assertEqual(after, _compact(json.loads(after)))   # still compact
        again = self.calls(path)
        self.assertEqual([c.tool_call_id for c in again],
                         [c.tool_call_id for c in before])
        self.assertEqual(again[2].output,
                         before[2].output.replace(SECRET, _marker(SECRET)))
        self.assertEqual(self.findings(path), {})
        self.assertEqual(self.src.mask(self.store(path), [SECRET]),
                         MaskResult(path))

    def test_round_trip_of_an_sdk_session(self):
        path = self.session(sdk_spec(), age=600)
        result = self.src.mask(self.store(path), [SECRET])
        self.assertTrue(result.changed, result)
        with open(path, encoding="utf-8") as fh:
            after = fh.read()
        self.assertEqual(after, _pretty(json.loads(after)))     # still pretty
        self.assertNotIn(SECRET, after)
        self.assertEqual(len(self.calls(path)), 4)

    def test_the_ui_log_is_masked_too(self):
        path = self.ui(ui_log(), age=600)
        self.assertTrue(self.src.mask(self.store(path), [SECRET]).changed)
        self.assertEqual(self.findings(path), {})

    def test_a_file_written_just_now_is_left_alone(self):
        path = self.task(spec_xml(), age=5)
        digest = _sha(path)
        self.assertEqual(self.src.mask(self.store(path), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_sha(path), digest)


# --------------------------------------------------------------------------
# Damaged files
# --------------------------------------------------------------------------

class Damaged(ClineCase):

    def _read_all(self):
        err = io.StringIO()
        out = []
        with contextlib.redirect_stderr(err):
            for _ in range(2):
                for store in self.stores():
                    out += list(self.src.tool_calls(store))
                    out += list(self.src.secret_texts(store))
        return out, err.getvalue().splitlines()

    def test_garbage_and_a_half_written_session_warn_once_each(self):
        garbage = self.task(None, task="g", raw=b"\x00\xff\xfe not json" * 20)
        whole = _pretty(sdk_doc(sdk_spec())).encode()
        half = self.session(None, raw=whole[:len(whole) // 2])
        good = self.task(spec_xml(), age=7200)
        _out, warnings = self._read_all()
        self.assertEqual(len(warnings), 2, warnings)
        self.assertTrue(any(garbage in w for w in warnings))
        self.assertTrue(any(half in w for w in warnings))
        self.assertEqual(self.src.counts["unreadable_stores"], 2)
        self.assertEqual(self.src.unreadable, {"not JSON": 2})
        self.assertEqual(len(self.calls(good)), 4)

    def test_wrong_shapes_everywhere_do_not_raise(self):
        docs = [
            {"a": 1}, "text", None, 5, [None, 1, "x", []],
            [{"role": "future"}, {"role": "assistant", "content": 5},
             {"role": "assistant", "content": [None, 3, "x", {"type": 5},
                                              {"type": "tool_use", "id": 5,
                                               "name": ["x"], "input": "{"},
                                              {"type": "tool_use", "id": "i",
                                               "name": "execute_command",
                                               "input": [1, 2]},
                                              {"type": "text", "text": 7}],
              "ts": "soon"},
             {"role": "user", "content": [
                 {"type": "tool_result", "tool_use_id": ["i"], "content": 3},
                 {"type": "tool_result", "tool_use_id": "i", "content": {"x": 1}},
                 {"type": "text", "text": "[ Result:"},
                 {"type": "text", "text": "[execute_command] Result:"}],
              "ts": -5},
             {"role": "user", "content": [{"type": "text",
                                           "text": "Skipping tool due to user "
                                           "rejecting a previous tool."}]}],
        ]
        for n, doc in enumerate(docs):
            self.task(doc, task="w%d" % n)
        sdk = [{"messages": "x"}, {"messages": [None, {"role": "assistant",
                                                       "content": [{
                                                           "type": "tool_use",
                                                           "id": "r",
                                                           "name": "run_commands",
                                                           "input": {"commands":
                                                                     {"x": 1}}}]},
                                                {"role": "user", "content": [
                                                    {"type": "tool_result",
                                                     "tool_use_id": "r",
                                                     "content": [None, 5]}]}]},
               [1, 2], "x"]
        for n, doc in enumerate(sdk):
            self.session(None, sid="1791380000000_w%d" % n,
                         raw=_pretty(doc))
        self.ui({"not": "a list"}, task="w0")
        self.write(os.path.join(self.data, "state", "taskHistory.json"),
                   _compact({"id": 5}))
        self.write(os.path.join(self.data, "sessions", "1791380000000_w0",
                                "1791380000000_w0.json"), "[1]")
        _out, warnings = self._read_all()
        self.assertEqual(warnings, [])
        self.assertGreater(self.src.counts["unknown"], 0)
        self.assertEqual(self.src.counts["unreadable_stores"], 0)

    def test_unknown_messages_are_counted_once_per_store(self):
        self.task([first_user(), {"role": "future"}, 7])
        self._read_all()
        self.assertEqual(self.src.counts["unknown"], 2)

    def test_deep_nesting_and_bad_bytes(self):
        self.task(None, task="deep", raw=b"[" * 100000 + b"]" * 100000)
        bad = _compact([first_user(), assistant(xml("execute_command",
                                                    command="lXs"))]).encode()
        bad = bad.replace(b"lXs", b"l\xff\xfes")
        path = self.task(None, task="bad", raw=b"\xef\xbb\xbf" + bad)
        _out, warnings = self._read_all()
        self.assertEqual(len(warnings), 1, warnings)
        [call] = self.calls(path)
        self.assertEqual(call.command, "l\udcff\udcfes")

    def test_a_huge_text_is_parsed_in_linear_time(self):
        text = "<execute_command>" + "<command>" * 50000 + "x" * 200000
        start = time.time()
        self.calls(self.task([first_user(), assistant(text)]))
        self.assertLess(time.time() - start, 5)

    def test_a_vanished_store_warns_once(self):
        path = self.task(spec_xml())
        store = self.store(path)
        os.remove(path)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(len(err.getvalue().splitlines()), 1)

    @unittest.skipIf(WINDOWS, "symlinks")
    def test_symlink_loops_and_folders_where_files_belong(self):
        tasks = os.path.join(self.data, "tasks")
        os.makedirs(os.path.join(tasks, "t1", "api_conversation_history.json"))
        os.makedirs(os.path.join(tasks, "t1", "ui_messages.json"))
        os.symlink(os.path.join(tasks, "loop"), os.path.join(tasks, "loop"))
        os.makedirs(os.path.join(tasks, "t2"))
        os.symlink(os.path.join(tasks, "t2", "api_conversation_history.json"),
                   os.path.join(tasks, "t2", "api_conversation_history.json"))
        sessions = os.path.join(self.data, "sessions", SID)
        os.makedirs(os.path.join(sessions, SID + ".messages.json"))
        os.makedirs(os.path.join(sessions, SID + ".json"))
        self.assertEqual(self.stores(), [])
        other = _tempdir(self, "cline-file-")
        with open(os.path.join(other, "tasks"), "w", encoding="utf-8") as fh:
            fh.write("x")
        self.assertEqual(self.stores(override=other), [])

    def test_reading_writes_nothing(self):
        self.task(spec_xml())
        self.ui(ui_log())
        self.session(sdk_spec())
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


class Parser(unittest.TestCase):

    def test_parse_xml_mirrors_the_agents(self):
        tools = _cline_tasks.alternation(["read_file", "execute_command"])
        params = _cline_tasks.alternation(["path", "command", "content"])
        self.assertEqual(_cline_tasks.parse_xml(
            "a <read_file><path> x </path></read_file> b", tools, params),
            [("read_file", {"path": "x"}, True)])
        # a parameter runs to its own closing tag, tags inside it are text
        self.assertEqual(_cline_tasks.parse_xml(
            "<execute_command><command>echo '<path>p</path>'</command>"
            "</execute_command>", tools, params),
            [("execute_command", {"command": "echo '<path>p</path>'"}, True)])
        # Roo keeps a content's inner whitespace but one newline each side
        self.assertEqual(_cline_tasks.parse_xml(
            "<read_file><content>\n  x  \n\n</content></read_file>", tools,
            params, newline_content=True),
            [("read_file", {"content": "  x  \n"}, True)])
        self.assertEqual(_cline_tasks.parse_xml("<read_file>", tools, params), [])

    def test_result_headers(self):
        rb = _cline_tasks.result_body
        self.assertEqual(rb("[read_file for 'a'] Result:\nx"), ("read_file", "x"))
        self.assertEqual(rb("[attempt_completion] Result:"),
                         ("attempt_completion", ""))
        self.assertEqual(rb("[search_files for 'x' in '*.py'] Result:\ny"),
                         ("search_files", "y"))
        self.assertEqual(rb("plain"), (None, None))
        self.assertEqual(rb("[x]\nsomething] Result:\n"), (None, None))


if __name__ == "__main__":
    unittest.main()
