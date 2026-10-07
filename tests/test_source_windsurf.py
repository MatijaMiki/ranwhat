"""The Windsurf adapter (ranwhat/sources/windsurf.py).

Fixtures are built field for field from the transcripts Windsurf's
post_cascade_response_with_transcript hook writes, as its hooks docs show
them and as the one real transcript published (git-ai's tests/fixtures/
windsurf-session-simple.jsonl) has them: one compact JSON object a line,
keys sorted, and <, > and & escaped the way Go's encoding/json escapes them.

Everything runs in temp directories: the home directory and clean's backup
root point there, and the real home is never read. Every secret is
synthetic, and token-shaped ones are written as adjacent literals.
"""
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

from ranwhat import clean, watch  # noqa: E402
from ranwhat.sources import _paths, _rewrite  # noqa: E402
from ranwhat.sources import windsurf  # noqa: E402
from ranwhat.sources.base import MaskResult  # noqa: E402
from ranwhat.sources.windsurf import (WindsurfSource, local_path,  # noqa: E402
                                      session_from_name)

WINDOWS = os.name == "nt"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
AWS = "AKIA" "QW3RT5YU7IO9PA1S"
TRAJECTORY = "64944513-a64d-410b-af09-426251271f8b"
CWD = "/Users/dev/proj"


# --------------------------------------------------------------------------
# Fixture builders: Windsurf's steps, as Go's encoding/json writes them
# --------------------------------------------------------------------------

def _go(obj):
    """Compact JSON, keys sorted, with Go's HTML escapes."""
    text = json.dumps(obj, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False)
    return (text.replace("&", "\\u0026").replace("<", "\\u003c")
            .replace(">", "\\u003e"))


def step(kind, payload, status="done"):
    return {"status": status, "type": kind, kind: payload}


def user_input(text, rules=None):
    payload = {"user_response": text}
    if rules is not None:
        payload["rules_applied"] = rules
    return step("user_input", payload)


def planner(text):
    return step("planner_response", {"response": text})


def run_command(command, output=None, cwd=CWD, exit_code=0, rejected=False,
                status="done"):
    payload = {"command": command, "cwd": cwd, "exit_code": exit_code,
               "user_rejected": rejected}
    if output is not None:
        payload["output"] = output
    return step("run_command", payload, status)


def view_file(path, content, end=10):
    return step("view_file", {"content": content, "end_line": end,
                              "path": path, "start_line": 0})


def code_action(path, new, original=""):
    return step("code_action", {
        "acknowledgement_type": "ACKNOWLEDGEMENT_TYPE_ACCEPT",
        "new_content": new, "original_content": original, "path": path})


def uri(path):
    return "file://" + path


def sample(secret=SECRET):
    """A conversation as the real transcript has it, with a .env read."""
    return [
        user_input("check the config"),
        planner("I'll look at the config."),
        view_file(uri(CWD + "/README.md"),
                  '<file name="%s/README.md" start_line="0">\n# App\n</file>'
                  % CWD),
        run_command("cat .env", "API_KEY=%s\n" % secret),
        run_command("clear"),
        code_action(uri(CWD + "/notes.md"), "# Notes\n", "# Old\n"),
        step("list_directory", {"path": uri(CWD)}),
        step("find", {"output": CWD + "/a.md\n", "pattern": "*.md",
                      "search_directory": CWD, "total_results": 1}),
        step("grep_search", {"query": "song", "search_path": uri(CWD),
                             "total_results": 0}),
        step("list_resources", {"server_name": "memory"}, "error"),
        planner("Done."),
    ]


def rules(call):
    return [(h["rule"], h["evidence"]) for h in watch.judge(call)[0]]


def origins(source, store):
    """{value: origins} as clean credits what it finds in this store."""
    out = {}
    for _fp, entry in clean.scan_store(source, store, {})[0].items():
        out.setdefault(entry["hint"], set()).update(entry["origins"])
    return out


def found_values(source, store):
    values = {}
    clean.scan_store(source, store, values)
    return set(values.values())


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


class _Home(unittest.TestCase):
    """A temp home, and backups kept apart from it."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="windsurf-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        env = mock.patch.dict(os.environ, {"HOME": self.home,
                                           "USERPROFILE": self.home})
        env.start()
        self.addCleanup(env.stop)
        p = mock.patch.object(_paths, "home", return_value=self.home)
        p.start()
        self.addCleanup(p.stop)
        backups = tempfile.mkdtemp(prefix="windsurf-bk-")
        self.addCleanup(shutil.rmtree, backups, True)
        self.backups = os.path.join(backups, "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        self.root = os.path.join(self.home, ".windsurf", "transcripts")
        self.src = WindsurfSource()

    def write(self, path, data, age=3600):
        """Write a file (a list as Windsurf's JSON Lines; str or bytes as
        is) and date it `age` seconds ago."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(data, list):
            data = "".join(_go(r) + "\n" for r in data)
        if isinstance(data, str):
            data = data.encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(data)
        if not WINDOWS:
            os.chmod(path, 0o600)       # as Windsurf writes them
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def transcript(self, steps, name=TRAJECTORY, age=3600):
        return self.write(os.path.join(self.root, name + ".jsonl"), steps,
                          age=age)

    def only_store(self, path):
        [store] = [s for s in self.src.stores(self.src.locations())
                   if s.path == path]
        return store

    def calls(self, path):
        return list(self.src.tool_calls(self.only_store(path)))

    def quiet(self):
        """Warnings go to stderr; keep them for checking."""
        err = io.StringIO()
        p = mock.patch.object(sys, "stderr", err)
        p.start()
        self.addCleanup(p.stop)
        return err


# --------------------------------------------------------------------------
# Who it is, and where it looks
# --------------------------------------------------------------------------

class Identity(unittest.TestCase):

    def test_what_every_report_needs(self):
        src = WindsurfSource()
        self.assertEqual((src.id, src.name, src.unit, src.env),
                         ("windsurf", "Windsurf", "transcript", ()))
        self.assertEqual(src.path_means, "a Windsurf transcripts folder "
                                         "(~/.windsurf/transcripts)")
        self.assertIn("2026-10-07", src.checked)
        self.assertFalse(src.read_only)
        self.assertTrue(src.mask_note)
        for text in (src.path_means, src.checked, src.mask_note):
            self.assertNotIn("\u2014", text)

    def test_its_path_keys_are_watchs(self):
        # The only key Windsurf names a file by is "path", one of watch's.
        self.assertIn("path", watch._PATH_KEYS)


class DefaultPaths(unittest.TestCase):

    def setUp(self):
        self.src = WindsurfSource()

    def test_each_platform(self):
        self.assertEqual(self.src.default_paths({}, "/Users/u", "darwin"),
                         [("/Users/u/.windsurf/transcripts", "default")])
        self.assertEqual(self.src.default_paths({}, "/home/u", "linux"),
                         [("/home/u/.windsurf/transcripts", "default")])
        self.assertEqual(self.src.default_paths({}, "C:\\Users\\u", "win32"),
                         [("C:\\Users\\u\\.windsurf\\transcripts", "default")])

    def test_no_variable_moves_it(self):
        env = {"WINDSURF_HOME": "/x", "CODEIUM_HOME": "/y",
               "XDG_DATA_HOME": "/z", "APPDATA": "C:\\AD"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/home/u/.windsurf/transcripts", "default")])

    def test_default_paths_touch_nothing(self):
        with mock.patch.object(os, "stat", side_effect=AssertionError), \
                mock.patch.object(os, "scandir", side_effect=AssertionError):
            self.src.default_paths({}, "/home/u", "linux")
            WindsurfSource.cascade_folders("/home/u", "linux")

    def test_cascade_folders_each_platform(self):
        self.assertEqual(WindsurfSource.cascade_folders("/home/u", "linux"), [
            "/home/u/.codeium/windsurf/cascade",
            "/home/u/.codeium/windsurf-next/cascade",
            "/home/u/.codeium/windsurf-insiders/cascade"])
        self.assertEqual(
            WindsurfSource.cascade_folders("C:\\Users\\u", "win32")[0],
            "C:\\Users\\u\\.codeium\\windsurf\\cascade")


class Names(unittest.TestCase):

    def test_session_is_the_file_name(self):
        self.assertEqual(session_from_name("/x/%s.jsonl" % TRAJECTORY),
                         TRAJECTORY)

    def test_local_path(self):
        self.assertEqual(local_path("file:///Users/u/a.md"), "/Users/u/a.md")
        self.assertEqual(local_path("file://localhost/Users/u/a.md"),
                         "/Users/u/a.md")
        self.assertEqual(local_path("file:///Users/u/my%20notes.md"),
                         "/Users/u/my notes.md")
        self.assertEqual(local_path("file:///c%3A/Users/u/a.md"),
                         "c:/Users/u/a.md")
        self.assertEqual(local_path("file:///C:/Users/u/a.md"),
                         "C:/Users/u/a.md")
        self.assertEqual(local_path("/path/to/file.py"), "/path/to/file.py")
        self.assertEqual(local_path("FILE:///x"), "/x")
        # A Windows network share (or \\wsl.localhost) is its UNC path.
        self.assertEqual(local_path("file://server/share/a.md"),
                         "//server/share/a.md")
        self.assertEqual(local_path("file://wsl.localhost/Ubuntu/home/u/.env"),
                         "//wsl.localhost/Ubuntu/home/u/.env")
        self.assertIsNone(local_path("file://server"))
        self.assertIsNone(local_path(""))
        self.assertIsNone(local_path(None))
        self.assertIsNone(local_path(["file:///x"]))


class Discovery(_Home):

    def test_finds_transcripts_newest_first(self):
        old = self.transcript(sample(), name="aaaa", age=7200)
        new = self.transcript(sample(), name="bbbb", age=60)
        stores = self.src.stores(self.src.locations())
        self.assertEqual([s.path for s in stores], [new, old])
        self.assertEqual([(s.session, s.format, s.role, s.unit, s.masking)
                          for s in stores],
                         [("bbbb", "jsonl", "transcript", "transcript",
                           "rewrite"),
                          ("aaaa", "jsonl", "transcript", "transcript",
                           "rewrite")])
        [loc] = self.src.locations()
        self.assertEqual((loc.path, loc.how, loc.exists, loc.found),
                         (self.root, "default", True, 2))

    def test_ignores_what_is_not_a_transcript(self):
        keep = self.transcript(sample())
        self.write(os.path.join(self.root, "notes.txt"), "x")
        self.write(os.path.join(self.root, ".hidden.jsonl"), sample())
        self.write(os.path.join(self.root, "sub", "deep.jsonl"), sample())
        os.makedirs(os.path.join(self.root, "dir.jsonl"))
        self.assertEqual([s.path for s in self.src.stores(
            self.src.locations())], [keep])

    def test_since_days(self):
        self.transcript(sample(), name="old", age=10 * 86400)
        new = self.transcript(sample(), name="new", age=60)
        self.assertEqual([s.path for s in self.src.stores(
            self.src.locations(), since_days=1)], [new])

    def test_missing_root(self):
        [loc] = self.src.locations()
        self.assertEqual((loc.exists, loc.found), (False, 0))
        self.assertEqual(self.src.stores([loc]), [])

    def test_path_override_folder_and_file(self):
        other = os.path.join(self.home, "elsewhere")
        path = self.write(os.path.join(other, "t1.jsonl"), sample())
        self.assertEqual([s.path for s in self.src.stores(
            self.src.locations(other))], [path])
        self.assertEqual([s.path for s in self.src.stores(
            self.src.locations(path))], [path])

    @unittest.skipIf(WINDOWS, "symlinks")
    def test_symlink_loop_and_dangling_link(self):
        keep = self.transcript(sample())
        os.symlink("loop.jsonl", os.path.join(self.root, "loop.jsonl"))
        os.symlink(self.root, os.path.join(self.root, "up.jsonl"))
        os.symlink("/nonexistent/x", os.path.join(self.root, "gone.jsonl"))
        os.mkfifo(os.path.join(self.root, "pipe.jsonl"))   # never opened
        self.assertEqual([s.path for s in self.src.stores(
            self.src.locations())], [keep])
        self.assertEqual(self.src.stores(self.src.locations(
            os.path.join(self.root, "pipe.jsonl"))), [])


# --------------------------------------------------------------------------
# What is in a transcript
# --------------------------------------------------------------------------

class Calls(_Home):

    def test_every_step_type(self):
        path = self.transcript(sample())
        calls = self.calls(path)
        self.assertEqual([(c.tool_name, c.kind, c.known) for c in calls], [
            ("view_file", "read", True),
            ("run_command", "shell", True),
            ("run_command", "shell", True),
            ("code_action", "write", True),
            ("list_directory", "other", True),
            ("find", "other", True),
            ("grep_search", "other", True),
            ("list_resources", "other", True)])
        read, cat, clear, write, ls, find, grep, mcp = calls
        self.assertEqual((read.paths, read.consumed, read.command),
                         ((CWD + "/README.md",), frozenset(["path"]), None))
        self.assertIn("# App", read.output)
        self.assertNotIn("content", read.tool_input)
        # The input names the file, not its URI; the line keeps the URI.
        self.assertEqual(read.tool_input["path"], CWD + "/README.md")
        self.assertIn(uri(CWD + "/README.md"), repr(
            [t.node for t in self.src.secret_texts(self.only_store(path))]))
        self.assertEqual((cat.command, cat.workdir, cat.project, cat.consumed),
                         ("cat .env", CWD, CWD, frozenset(["command"])))
        self.assertEqual(cat.output, "API_KEY=%s\n" % SECRET)
        self.assertNotIn("output", cat.tool_input)
        self.assertEqual(cat.tool_input, {"command": "cat .env", "cwd": CWD,
                                          "exit_code": 0,
                                          "user_rejected": False})
        self.assertIsNone(clear.output)         # it printed nothing
        self.assertEqual((write.paths, write.consumed, write.output),
                         ((CWD + "/notes.md",), frozenset(), None))
        self.assertEqual(write.tool_input["new_content"], "# Notes\n")
        self.assertNotIn("original_content", write.tool_input)
        self.assertEqual(find.output, CWD + "/a.md\n")
        self.assertNotIn("output", find.tool_input)
        self.assertEqual(mcp.tool_input, {"server_name": "memory"})
        self.assertIsNone(mcp.status)           # "error" is not "declined"
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_shared_fields(self):
        path = self.transcript(sample(), age=3600)
        mtime = os.stat(path).st_mtime
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
        for call in self.calls(path):
            self.assertEqual((call.source, call.store, call.session),
                             ("windsurf", path, TRAJECTORY))
            self.assertEqual((call.timestamp, call.not_after),
                             (None, stamp))
            self.assertIsNone(call.tool_call_id)
            self.assertEqual(call.actor, "agent")

    def test_project_is_the_last_cwd_seen(self):
        path = self.transcript([
            view_file(uri("/a/x"), "x"),
            run_command("ls", cwd="/p1"),
            view_file(uri("/a/y"), "y"),
            run_command("ls", cwd="/p2"),
            code_action("/a/z", "z")])
        self.assertEqual([c.project for c in self.calls(path)],
                         [None, "/p1", "/p1", "/p2", "/p2"])

    def test_declined(self):
        path = self.transcript([
            run_command("rm -rf ~/Documents/x", rejected=True),
            run_command("ls", rejected=False),
            run_command("false", exit_code=1, status="error")])
        self.assertEqual([c.status for c in self.calls(path)],
                         ["declined", None, None])

    def test_docs_example_plain_path(self):
        path = self.transcript([
            user_input("create a hello world file",
                       {"always_on": ["my-rule.md"]}),
            planner("I'll create a hello world file for you."),
            step("code_action", {"new_content": "print('hello world')\n",
                                 "path": "/path/to/file.py"}),
            planner("I created the file for you.")])
        [call] = self.calls(path)
        self.assertEqual((call.kind, call.paths), ("write", ("/path/to/file.py",)))
        self.assertEqual(self.src.counts["unknown"], 0)

    def test_unknown_type_is_judged_by_name(self):
        payload = {"command": "rm -rf ~/Documents/x"}
        path = self.transcript([step("execute_shell", payload),
                                {"type": "user_input"},     # no payload
                                ["not", "an", "object"],
                                {"status": "done"}])
        [call] = self.calls(path)
        self.assertEqual((call.tool_name, call.kind, call.known),
                         ("execute_shell", "other", False))
        self.assertEqual(call.tool_input, payload)
        self.assertEqual(watch.judge(call),
                         watch.evaluate("execute_shell", payload))
        self.assertEqual(self.src.counts["unknown"], 4)
        list(self.src.secret_texts(self.only_store(path)))
        self.assertEqual(self.src.counts["unknown"], 4)     # once a run

    def test_a_known_type_without_its_payload(self):
        path = self.transcript([{"status": "done", "type": "run_command",
                                 "run_command": "ls"},
                                step("view_file", {"path": 7})])
        [read] = self.calls(path)
        self.assertEqual((read.kind, read.paths), ("read", ()))
        self.assertEqual(self.src.counts["unknown"], 1)

    def test_wrong_types_in_fields(self):
        path = self.transcript([
            step("run_command", {"command": ["ls"], "cwd": 3, "output": 5,
                                 "user_rejected": "true"}),
            step("view_file", {"path": None, "content": {"a": 1}}),
            step("code_action", {"path": {"x": 1}, "new_content": 1}),
            step("find", {"output": ["x"]})])
        calls = self.calls(path)
        self.assertEqual([(c.command, c.workdir, c.paths, c.output, c.status)
                          for c in calls],
                         [(None, None, (), None, None)] * 4)
        store = self.only_store(path)
        self.assertTrue(list(self.src.secret_texts(store)))

    def test_nothing_is_deduplicated_away(self):
        path = self.transcript([run_command("ls"), run_command("ls")])
        self.assertEqual(len(self.calls(path)), 2)


class Judged(_Home):

    def test_rules(self):
        path = self.transcript([
            run_command("rm -rf ~/Documents/x"),
            run_command("cat ~/.aws/credentials", "[default]\n"),
            view_file(uri("/Users/dev/.ssh/id_rsa"), "-----"),
            view_file("~/.ssh/id_rsa", "-----"),
            code_action(uri(CWD + "/clean.sh"), "rm -rf ~/Documents/x\n"),
            view_file(uri(CWD + "/notes.md"), "rm -rf ~/Documents/x"),
            run_command("echo hi", "rm -rf ~/Documents/x")])
        rm, aws, ssh_uri, ssh, write, read, echo = self.calls(path)
        self.assertEqual(rules(rm), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(rules(aws), [("cred.read", "cat ~/.aws/credentials")])
        self.assertEqual([r for r, _e in rules(ssh_uri)], ["cred.read"])
        self.assertEqual(rules(ssh), [("cred.read", "~/.ssh/id_rsa")])
        # What a file holds, or a command printed, is not an action.
        self.assertEqual(rules(write), [])
        self.assertEqual(rules(read), [])
        self.assertEqual(rules(echo), [])

    def test_a_credential_on_a_network_share_is_flagged(self):
        path = self.transcript([
            view_file("file://wsl.localhost/Ubuntu/home/u/proj/.env", "A=1"),
            view_file("file://server/share/u/.ssh/id_rsa", "-----")])
        env, ssh = self.calls(path)
        self.assertEqual(env.paths, ("//wsl.localhost/Ubuntu/home/u/proj/.env",))
        self.assertEqual([r for r, _e in rules(env)], ["cred.read"])
        self.assertEqual([r for r, _e in rules(ssh)], ["cred.read"])

    def test_a_declined_rm_is_still_flagged_and_marked(self):
        path = self.transcript([run_command("rm -rf ~/Documents/x",
                                            rejected=True)])
        [call] = self.calls(path)
        self.assertEqual(rules(call), [("fs.destructive", "rm -rf ~/Documents/x")])
        self.assertEqual(call.status, "declined")


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(_Home):

    def test_cat_env_output_is_credited_to_env(self):
        path = self.transcript(sample())
        self.assertIn(SECRET, found_values(self.src, self.only_store(path)))
        got = origins(self.src, self.only_store(path))
        [(hint, where)] = [(h, o) for h, o in got.items()]
        self.assertEqual(where, {".env"})

    def test_view_file_of_env_is_credited_to_it(self):
        path = self.transcript([view_file(uri(CWD + "/.env"),
                                          "API_KEY=%s\n" % SECRET)])
        got = origins(self.src, self.only_store(path))
        self.assertEqual(list(got.values()), [{CWD + "/.env"}])

    def test_code_action_content_is_the_files(self):
        path = self.transcript([code_action(uri(CWD + "/.env"),
                                            "API_KEY=%s\n" % SECRET,
                                            "AWS_KEY=%s\n" % AWS)])
        store = self.only_store(path)
        self.assertEqual(found_values(self.src, store) >= {SECRET, AWS}, True)
        for where in origins(self.src, store).values():
            self.assertEqual(where, {CWD + "/.env"})

    def test_texts_cover_every_line(self):
        path = self.transcript(sample())
        texts = list(self.src.secret_texts(self.only_store(path)))
        lines = set(t.where for t in texts)
        self.assertEqual(lines, set("line %d" % n for n in range(1, 12)))
        [out] = [t for t in texts if t.node == "API_KEY=%s\n" % SECRET]
        self.assertEqual(out.call.command, "cat .env")
        self.assertNotIn(SECRET, repr([t.node for t in texts
                                       if t is not out]))

    def test_a_typed_secret_has_no_origin(self):
        path = self.transcript([user_input("use API_KEY=%s please" % SECRET)])
        store = self.only_store(path)
        self.assertIn(SECRET, found_values(self.src, store))
        self.assertEqual(list(origins(self.src, store).values()), [set()])

    def test_no_login_material_is_read(self):
        """Windsurf's encrypted conversations, its hooks.json, the editor's
        state and Devin Local's database are never opened."""
        planted = {
            os.path.join(self.home, ".codeium", "windsurf", "cascade",
                         "c1.pb"): "API_KEY=%s\n" % SECRET,
            os.path.join(self.home, ".codeium", "windsurf",
                         "hooks.json"): '{"token": "%s"}' % SECRET,
            os.path.join(self.home, ".config", "Windsurf", "User",
                         "globalStorage", "state.vscdb"): SECRET,
            os.path.join(self.home, ".local", "share", "devin", "cli",
                         "sessions.db"): SECRET,
            os.path.join(self.root, "auth.json"): '{"t": "%s"}' % SECRET,
        }
        for path, text in planted.items():
            self.write(path, text)
        self.transcript([user_input("hello")])
        opened = []
        real = open

        def spy(path, *a, **k):
            opened.append(os.path.abspath(path))
            return real(path, *a, **k)
        with mock.patch("builtins.open", spy):
            values = set()
            for store in self.src.stores(self.src.locations()):
                values |= found_values(self.src, store)
                list(self.src.tool_calls(store))
            self.src.notes(self.src.locations())
        self.assertNotIn(SECRET, values)
        for path in planted:
            self.assertNotIn(os.path.abspath(path), opened)


# --------------------------------------------------------------------------
# Bad stores
# --------------------------------------------------------------------------

class BadStores(_Home):

    def test_garbage_warns_once_and_yields_nothing(self):
        err = self.quiet()
        path = self.write(os.path.join(self.root, "bad.jsonl"),
                          b"\x00\xff\xfe garbage\nmore {{{\n")
        store = self.only_store(path)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        texts = list(self.src.secret_texts(store))
        self.assertEqual(len(texts), 2)         # handed to clean as text
        self.assertEqual(err.getvalue().count("could not read Windsurf"), 1)
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(self.src.counts["unparsed"], 2)
        self.assertEqual(self.src.unreadable, {"not JSON Lines": 1})

    def test_a_bad_line_among_good_ones(self):
        err = self.quiet()
        good = "".join(_go(r) + "\n" for r in sample())
        path = self.write(os.path.join(self.root, "mixed.jsonl"),
                          "{oops\n" + good + '{"partial":')
        store = self.only_store(path)
        self.assertEqual(len(list(self.src.tool_calls(store))), 8)
        list(self.src.secret_texts(store))
        self.assertEqual(self.src.counts["unparsed"], 1)    # not the last
        self.assertEqual(self.src.counts["unreadable_stores"], 0)
        self.assertEqual(err.getvalue(), "")

    def test_a_store_gone_before_it_is_read(self):
        err = self.quiet()
        path = self.transcript(sample())
        store = self.only_store(path)
        os.remove(path)
        self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)
        self.assertEqual(err.getvalue().count("could not read Windsurf"), 1)

    def test_deep_nesting_and_non_utf8(self):
        self.quiet()
        deep = "[" * 100000 + "]" * 100000
        path = self.write(os.path.join(self.root, "deep.jsonl"),
                          deep.encode() + b"\n" + _go(run_command(
                              "echo \udcff".encode("utf-8", "surrogatepass")
                              .decode("utf-8", "replace"))).encode()
                          + b"\n" + b'{"type":"run_command","run_command":'
                          b'{"command":"ls \xff"}}\n')
        store = self.only_store(path)
        calls = list(self.src.tool_calls(store))
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1].command, "ls \udcff")
        list(self.src.secret_texts(store))
        for call in calls:
            watch.judge(call)

    def test_reading_writes_nothing(self):
        path = self.transcript(sample())
        before = (_read(path), os.stat(path).st_mtime, sorted(os.listdir(
            self.root)))
        store = self.only_store(path)
        list(self.src.tool_calls(store))
        list(self.src.secret_texts(store))
        self.src.notes(self.src.locations())
        self.assertEqual((_read(path), os.stat(path).st_mtime,
                          sorted(os.listdir(self.root))), before)
        self.assertFalse(os.path.exists(self.backups))


# --------------------------------------------------------------------------
# Masking
# --------------------------------------------------------------------------

class Masking(_Home):

    def test_round_trip(self):
        steps = sample() + [view_file(uri(CWD + "/a.html"),
                                      "<b>%s</b> & more" % SECRET)]
        path = self.transcript(steps)
        original = _read(path)
        self.assertIn(b"\\u003cb\\u003e", original)
        store = self.only_store(path)
        before = [(c.tool_name, c.command, c.paths) for c in
                  self.src.tool_calls(store)]
        result = self.src.mask(store, [SECRET])
        self.assertEqual((result.path, result.changed, result.skipped),
                         (path, True, None))
        after = _read(path)
        marker = clean.REDACTION % clean._fingerprint(SECRET)
        self.assertEqual(after, original.replace(SECRET.encode("ascii"),
                                                 marker.encode("ascii")))
        for line in after.decode("utf-8").splitlines():
            json.loads(line)
        self.assertEqual(_read(result.backup), original)
        if not WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        store = self.only_store(path)
        self.assertEqual([(c.tool_name, c.command, c.paths) for c in
                          self.src.tool_calls(store)], before)
        self.assertNotIn(SECRET, found_values(self.src, store))
        self.assertEqual([f for f in _rewrite.encodings(SECRET)
                          if f in after.decode("utf-8")], [])

    def test_a_file_written_recently_is_left_alone(self):
        path = self.transcript(sample(), age=5)
        original = _read(path)
        self.assertEqual(self.src.mask(self.only_store(path), [SECRET]),
                         MaskResult(path, skipped="in use"))
        self.assertEqual(_read(path), original)


# --------------------------------------------------------------------------
# Notes: the encrypted Cascade store
# --------------------------------------------------------------------------

class Notes(_Home):

    def cascade(self, n, channel="windsurf"):
        folder = os.path.join(self.home, ".codeium", channel, "cascade")
        os.makedirs(folder, exist_ok=True)
        for i in range(n):
            self.write(os.path.join(folder, "c%d.pb" % i), b"\x8f\x01")
        return folder

    def test_nothing_without_the_folder(self):
        self.assertEqual(self.src.notes(self.src.locations()), [])
        self.assertEqual(self.src.notes(), [])

    def test_an_empty_folder_says_nothing(self):
        folder = self.cascade(0)
        self.write(os.path.join(folder, "notes.txt"), "x")
        os.makedirs(os.path.join(folder, "dir.pb"))
        self.assertEqual(self.src.notes(self.src.locations()), [])

    def test_no_transcripts(self):
        folder = self.cascade(3)
        self.assertEqual(self.src.notes(self.src.locations()), [
            "3 Windsurf Cascade conversations in %s are kept encrypted, so "
            "ranwhat did not read them. Turning on Windsurf's "
            "post_cascade_response_with_transcript hook makes Windsurf write "
            "each conversation as a plaintext transcript to "
            "~/.windsurf/transcripts, which ranwhat reads." % folder])

    def test_one(self):
        folder = self.cascade(1)
        self.assertEqual(self.src.notes([]), [
            "1 Windsurf Cascade conversation in %s is kept encrypted, so "
            "ranwhat did not read it. Turning on Windsurf's "
            "post_cascade_response_with_transcript hook makes Windsurf write "
            "each conversation as a plaintext transcript to "
            "~/.windsurf/transcripts, which ranwhat reads." % folder])

    def test_with_transcripts(self):
        folder = self.cascade(2)
        self.transcript(sample())
        self.assertEqual(self.src.notes(self.src.locations()), [
            "2 Windsurf Cascade conversations in %s are kept encrypted, so "
            "ranwhat did not read them there. It read the plaintext "
            "transcripts Windsurf's post_cascade_response_with_transcript "
            "hook writes to ~/.windsurf/transcripts, which hold only "
            "conversations had while the hook was on, the latest 100 at "
            "most." % folder])

    def test_each_channel(self):
        stable = self.cascade(1)
        nxt = self.cascade(2, "windsurf-next")
        notes = self.src.notes([])
        self.assertEqual(len(notes), 2)
        self.assertIn(stable, notes[0])
        self.assertIn(nxt, notes[1])

    def test_never_opens_a_pb_file(self):
        self.cascade(2)
        with mock.patch("builtins.open", side_effect=AssertionError):
            self.assertEqual(len(self.src.notes([])), 1)

    @unittest.skipIf(WINDOWS or os.geteuid() == 0, "permissions")
    def test_an_unlistable_folder_says_nothing(self):
        folder = self.cascade(2)
        os.chmod(folder, 0)
        self.addCleanup(os.chmod, folder, 0o755)
        self.assertEqual(self.src.notes([]), [])


if __name__ == "__main__":
    unittest.main()
