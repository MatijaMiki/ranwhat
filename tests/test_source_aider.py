"""The Aider adapter (ranwhat/sources/aider.py).

Fixtures are built line for line from Aider v0.86.2's writers (io.py
append_chat_history, user_input, tool_output, confirm_ask; base_coder.py
handle_shell_commands; commands.py) as the verified spec lays them out:
every "#### " and "> " line ends in two spaces, a session starts with
"\\n# aider chat started at <local time>\\n\\n", and the model's reply is
raw Markdown. SPEC is the spec's example file, byte for byte (its one key
replaced by a synthetic one).

Everything runs in temp directories: the home directory, the current
directory, AIDER_CHAT_HISTORY_FILE and clean's backup root all point there,
and the real home is never read. Every secret is synthetic, and
token-shaped ones are written as adjacent literals.
"""
import hashlib
import io
import os
import shutil
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, REPO)
sys.path.insert(0, TESTS)

import isolated_home  # noqa: E402,F401
from ranwhat import agents, clean, watch  # noqa: E402
from ranwhat.sources import _paths  # noqa: E402
from ranwhat.sources.aider import AiderSource, resolve  # noqa: E402

ENV = "AIDER_CHAT_HISTORY_FILE"
CHAT = ".aider.chat.history.md"
INPUT = ".aider.input.history"

SECRET = "sk_" "live_" "Zq8vR2mT6yLp4WcN0sXe7HbJ"
TYPED = "Hq3nV8xKp2" "Lw7RtY9mZc4BfD"
OTHER = "sk_" "live_" "Pm4Tq9Wx2Ls7Nd3Kf8Hj6Rv"

H = "  "    # Aider's hard break


def header(stamp):
    return ["", "# aider chat started at " + stamp, ""]


def said(*lines):
    """Aider's own lines: "> " and the hard break."""
    return ["> " + l + H for l in lines]


def typed(*lines):
    """One input as user_input writes it: a blank line, then "#### " on
    each of its lines."""
    return [""] + ["#### " + l + H for l in lines]


def reply(*lines):
    """The model's reply as ai_output writes it: raw, a blank line on each
    side."""
    return [""] + list(lines) + [""]


Q_SHELL = "Run shell command? (Y)es/(N)o/(D)on't ask again [Yes]: "
Q_SHELLS = "Run shell commands? (Y)es/(N)o/(D)on't ask again [Yes]: "
Q_FILE = "Add file to the chat? (Y)es/(N)o/(D)on't ask again [Yes]: "
Q_URL = "Add URL to the chat? (Y)es/(N)o/(D)on't ask again [Yes]: "

# The spec's example (research/aider-example.chat.history.md), line for line.
SPEC = (
    header("2026-10-07 14:02:51")
    + said("You can skip this check with --no-gitignore",
           "Add .env to .gitignore (recommended)? (Y)es/(N)o [Yes]: n",
           "/home/alice/.local/bin/aider --model sonnet --anthropic-api-key ...Q7xA",
           "Aider v0.86.2",
           "Main model: anthropic/claude-sonnet-4-20250514 with diff edit format, "
           "infinite output",
           "Weak model: anthropic/claude-3-5-haiku-20241022",
           "Git repo: .git with 14 files",
           "Repo-map: using 4096 tokens, auto refresh")
    + typed("add a /health endpoint to app.py")
    + said("app.py", Q_FILE + "y")
    + reply("I'll add a `/health` route that returns a JSON status, then you "
            "can run the tests.",
            "",
            "app.py",
            "```python",
            "<<<<<<< SEARCH",
            "from flask import Flask",
            "=======",
            "from flask import Flask, jsonify",
            ">>>>>>> REPLACE",
            "```",
            "",
            "app.py",
            "```python",
            "<<<<<<< SEARCH",
            'if __name__ == "__main__":',
            "=======",
            '@app.route("/health")',
            "def health():",
            '    return jsonify(status="ok")',
            "",
            "",
            'if __name__ == "__main__":',
            ">>>>>>> REPLACE",
            "```",
            "",
            "Run the test suite to confirm nothing broke:",
            "",
            "```bash",
            "pytest -q",
            "```")
    + said("Tokens: 3.1k sent, 214 received. Cost: $0.01 message, $0.01 session.",
           "Applied edit to app.py",
           "Commit 3f9c2ab feat: Add /health endpoint returning JSON status",
           "pytest -q",
           Q_SHELL + "y",
           "Running pytest -q",
           "Add command output to the chat? (Y)es/(N)o/(D)on't ask again [Yes]: n",
           "You can use /undo to undo and discard each aider commit.")
    + typed("/run ls")
    + said("Add 0.1k tokens of command output to the chat? (Y)es/(N)o [Yes]: y",
           "Added 4 lines of output to the chat.")
    + typed("!git status --short")
    + said("Add 0.0k tokens of command output to the chat? (Y)es/(N)o [Yes]: n")
    + typed("/add .env")
    + said("Added .env to the chat")
    + typed("/read-only ~/.ssh/id_rsa")
    + said("Added /home/alice/.ssh/id_rsa to read-only files.")
    + typed("/add ~/.aws/credentials")
    + said("Can not add /home/alice/.aws/credentials, which is not within "
           "/home/alice/proj")
    + typed("clean up the build artifacts", "and the egg-info dir")
    + reply("Those are untracked build outputs, so they can simply be deleted:",
            "",
            "```bash",
            "rm -rf build/ dist/ *.egg-info",
            "```")
    + said("Tokens: 3.6k sent, 41 received. Cost: $0.01 message, $0.02 session.",
           "rm -rf build/ dist/ *.egg-info",
           Q_SHELL + "n")
    + [">" + H, ">" + H] + said("^C again to exit") + [">" + H, ">" + H]
    + said("^C KeyboardInterrupt")
    + header("2026-10-07 15:10:04")
    + said("/home/alice/.local/bin/aider --api-key openai=" + SECRET
           + " --read /home/alice/.netrc",
           "Aider v0.86.2",
           "Model: gpt-4.1 with diff edit format",
           "Git repo: .git with 14 files",
           "Repo-map: using 4096 tokens, auto refresh",
           "Added ../.netrc to the chat (read-only).")
    + typed("/exit"))


def text_of(lines, crlf=False):
    out = "\n".join(lines) + "\n"
    return out.replace("\n", "\r\n") if crlf else out


def _tempdir(case, prefix):
    path = tempfile.mkdtemp(prefix=prefix)
    case.addCleanup(shutil.rmtree, path, True)
    return path


def _snapshot(folder):
    """{relative path: sha256} of every file under folder."""
    out = {}
    for root, _dirs, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            with open(path, "rb") as fh:
                out[os.path.relpath(path, folder)] = hashlib.sha256(
                    fh.read()).hexdigest()
    return out


def findings(source, stores):
    """{value: {"origins", "where"}} for every secret clean finds in these
    stores, origins credited as clean credits them (_origin_of)."""
    found = {}
    for store in stores:
        for text in source.secret_texts(store):
            origin = clean._origin_of(text)

            def collect(value, label, _in=None, _copies=None, text=text,
                        origin=origin):
                item = found.setdefault(value, {"origins": set(), "where": []})
                item["where"].append(text.where)
                if origin and origin != clean._GREP_LINE:
                    item["origins"].add(origin)
            clean._walk(text.node, collect)
    return found


def rules(call):
    return sorted(h["rule"] for h in watch.judge(call)[0])


class AiderCase(unittest.TestCase):

    def setUp(self):
        self.home = _tempdir(self, "aider-home-")
        patches = [mock.patch.dict(os.environ, {"HOME": self.home,
                                                "USERPROFILE": self.home}),
                   mock.patch.object(_paths, "home", return_value=self.home)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(ENV, None)
        self.backups = os.path.join(_tempdir(self, "aider-bk-"), "b")
        p = mock.patch.object(clean, "BACKUP_ROOT", self.backups)
        p.start()
        self.addCleanup(p.stop)
        # The current directory is somewhere with no history and no .git.
        self.elsewhere = _tempdir(self, "aider-cwd-")
        cwd = os.getcwd()
        os.chdir(self.elsewhere)
        self.addCleanup(os.chdir, cwd)
        self.repo = os.path.join(self.home, "proj")
        os.makedirs(os.path.join(self.repo, ".git"))
        self.src = AiderSource()

    def write(self, lines, folder=None, name=CHAT, age=3600, raw=None,
              crlf=False):
        path = os.path.join(folder or self.repo, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if raw is None:
            raw = text_of(lines, crlf).encode("utf-8")
        with open(path, "wb") as fh:
            fh.write(raw)
        when = time.time() - age
        os.utime(path, (when, when))
        return path

    def stores(self, override=None, since_days=None):
        return self.src.stores(self.src.locations(override=override),
                               since_days=since_days)

    def store(self, path):
        for store in self.stores(override=path):
            if store.path == os.path.abspath(path):
                return store
        self.fail("%s is not a store" % path)

    def calls(self, lines, **kw):
        return list(self.src.tool_calls(self.store(self.write(lines, **kw))))

    def session(self, *lines):
        """Calls of one session made of these lines."""
        body = header("2026-10-07 14:02:51") + said("Aider v0.86.2")
        for part in lines:
            body += part
        return self.calls(body)

    def brief(self, calls):
        return [(c.tool_name, c.kind, c.actor, c.status, c.command,
                 c.paths) for c in calls]


# --------------------------------------------------------------------------
# Where Aider keeps its history
# --------------------------------------------------------------------------

class Where(unittest.TestCase):

    def setUp(self):
        self.src = AiderSource()

    def test_each_platform(self):
        for home, platform in (("/home/u", "linux"), ("/Users/u", "darwin"),
                               ("C:\\Users\\u", "win32")):
            self.assertEqual(self.src.default_paths({}, home, platform),
                             [(_paths.join(platform, home, CHAT),
                               "default")])

    def test_the_variable_names_the_file(self):
        env = {ENV: "/srv/logs/chat.md"}
        self.assertEqual(self.src.default_paths(env, "/home/u", "linux"),
                         [("/srv/logs/chat.md", "env " + ENV),
                          ("/home/u/" + CHAT, "default")])
        env = {ENV: "D:\\logs\\chat.md"}
        self.assertEqual(self.src.default_paths(env, "C:\\Users\\u", "win32"),
                         [("D:\\logs\\chat.md", "env " + ENV),
                          ("C:\\Users\\u\\" + CHAT, "default")])

    def test_an_empty_variable_is_not_set(self):
        self.assertEqual(self.src.default_paths({ENV: ""}, "/home/u", "linux"),
                         [("/home/u/" + CHAT, "default")])

    def test_what_every_report_needs(self):
        self.assertEqual((self.src.id, self.src.name, self.src.unit,
                          self.src.env, self.src.checked),
                         ("aider", "Aider", "chat history", (ENV,), "0.86.2"))
        self.assertIn(".aider.chat.history.md", self.src.path_means)
        self.assertEqual(agents.plural(2, self.src.unit), "2 chat histories")
        self.assertFalse(self.src.read_only)

    def test_project_paths_for_later(self):
        self.assertEqual(self.src.project_paths(["/a", "", None]),
                         [("/a", "project")])

    def test_slash_words_resolve_as_aider_resolves_them(self):
        self.assertEqual(resolve("/run"), "/run")
        self.assertEqual(resolve("/ru"), "/run")
        self.assertEqual(resolve("/r"), None)            # ambiguous
        self.assertEqual(resolve("/edit"), "/edit")      # exact beats /editor
        self.assertEqual(resolve("/gi"), "/git")
        self.assertEqual(resolve("/nope"), None)


class Discovery(AiderCase):

    def test_a_folder_holds_the_log_and_the_input_history(self):
        chat = self.write(SPEC, age=100)
        hist = self.write(["", "# 2026-10-07 14:03:02.418273", "+ls"],
                          name=INPUT, age=50)
        self.write(["x"], name="notes.md")
        self.write(["x"], name=".aider.llm.history")
        self.write(["x"], name=".env")
        stores = self.stores(override=self.repo)
        self.assertEqual([(s.path, s.role, s.unit, s.format, s.project)
                          for s in stores],
                         [(hist, "side", "input history", "text", self.repo),
                          (chat, "transcript", "chat history", "text",
                           self.repo)])
        self.assertTrue(all(s.masking == "rewrite" for s in stores))

    def test_a_file_override_with_any_name(self):
        path = self.write(SPEC, folder=os.path.join(self.home, "logs"),
                          name="chat.md")
        stores = self.stores(override=path)
        self.assertEqual([(s.path, s.project) for s in stores], [(path, None)])

    def test_the_variable_names_a_file(self):
        path = self.write(SPEC, folder=os.path.join(self.home, "logs"),
                          name="chat.md")
        with mock.patch.dict(os.environ, {ENV: path}):
            locations = self.src.locations()
            self.assertIn((path, "env " + ENV, True, 1),
                          [(l.path, l.how, l.exists, l.found) for l in locations])
            self.assertIn(path, [s.path for s in self.src.stores(locations)])

    def test_the_home_directory(self):
        path = self.write(SPEC, folder=self.home)
        locations = self.src.locations()
        self.assertEqual([(l.path, l.how, l.found) for l in locations][0],
                         (os.path.join(self.home, CHAT), "default", 1))
        self.assertEqual([s.path for s in self.src.stores(locations)], [path])

    def test_the_current_directory_and_its_git_root(self):
        chat = self.write(SPEC)
        sub = os.path.join(self.repo, "src", "pkg")
        os.makedirs(sub)
        sub_chat = self.write(SPEC, folder=sub, age=10)
        os.chdir(sub)
        locations = self.src.locations()
        real = [(os.path.realpath(l.path), l.how, l.found) for l in locations]
        self.assertEqual(real[1:], [
            (os.path.join(os.path.realpath(sub), CHAT), "current directory", 1),
            (os.path.join(os.path.realpath(self.repo), CHAT),
             "current directory", 1)])
        self.assertEqual([os.path.realpath(s.path)
                          for s in self.src.stores(locations)],
                         [os.path.realpath(sub_chat), os.path.realpath(chat)])

    def test_the_current_directory_is_read_at_call_time(self):
        self.write(SPEC)
        self.assertEqual(self.src.stores(self.src.locations()), [])
        os.chdir(self.repo)
        self.assertEqual(len(self.src.stores(self.src.locations())), 1)

    def test_the_current_directory_once_when_it_is_the_home(self):
        os.chdir(self.home)
        paths = [os.path.realpath(l.path) for l in self.src.locations()]
        self.assertEqual(len(paths), len(set(paths)))

    def test_no_current_directory_with_an_override(self):
        os.chdir(self.repo)
        self.assertEqual([l.how for l in self.src.locations(override=self.home)],
                         ["--path"])

    def test_a_vanished_current_directory_does_not_raise(self):
        with mock.patch.object(os, "getcwd", side_effect=FileNotFoundError):
            with redirect_stderr(io.StringIO()):
                locations = self.src.locations()
        self.assertEqual([l.how for l in locations], ["default"])

    def test_a_missing_root_is_zero_stores(self):
        missing = os.path.join(self.home, "nowhere")
        self.assertEqual(self.stores(override=missing), [])
        self.assertEqual(self.stores(override=os.path.join(missing, CHAT)), [])

    def test_a_folder_named_like_the_log_is_not_one(self):
        os.makedirs(os.path.join(self.repo, CHAT))
        self.assertEqual(self.stores(override=self.repo), [])

    def test_an_input_history_with_no_chat_log_beside_it(self):
        # AIDER_CHAT_HISTORY_FILE moves only the chat log: the input
        # history stays where Aider runs, and is still found there.
        moved = self.write(SPEC, folder=os.path.join(self.home, "logs"),
                           name="chat.md")
        hist = self.write(["", "# 2026-10-07 14:03:02.418273", "+ls"],
                          folder=self.home, name=INPUT)
        os.chdir(self.repo)
        alone = self.write(["", "# 2026-10-07 14:03:02.418273", "+ls"],
                           name=INPUT)
        with mock.patch.dict(os.environ, {ENV: moved}):
            locations, stores = agents._discover(self.src, None, None)
        home = [l for l in locations if l.how == "default"][0]
        self.assertEqual((home.exists, home.found), (True, 1))
        self.assertEqual(
            sorted(os.path.realpath(s.path) for s in stores),
            sorted(os.path.realpath(p) for p in (moved, hist, alone)))
        # with --path too, and an absent agent is still nothing
        self.assertEqual([s.path for s in self.stores(
            override=os.path.join(self.home, CHAT))], [hist])
        os.remove(hist)
        self.assertEqual(self.stores(override=os.path.join(self.home, CHAT)), [])

    def test_days_prefilter_by_last_write(self):
        self.write(SPEC, age=40 * 86400)
        self.assertEqual(self.stores(override=self.repo, since_days=30), [])
        self.assertEqual(len(self.stores(override=self.repo, since_days=60)), 1)


# --------------------------------------------------------------------------
# Calls
# --------------------------------------------------------------------------

class SpecExample(AiderCase):

    def test_every_call_in_the_spec_example(self):
        calls = self.calls(SPEC)
        self.assertEqual(self.brief(calls), [
            ("file mention", "read", "user", None, None, ("app.py",)),
            ("edit", "write", "agent", None, None, ("app.py",)),
            ("shell command", "shell", "agent", None, "pytest -q", ()),
            ("/run", "shell", "user", None, "ls", ()),
            ("!", "shell", "user", None, "git status --short", ()),
            ("/add", "read", "user", None, None, (".env",)),
            ("/read-only", "read", "user", None, None,
             ("/home/alice/.ssh/id_rsa",)),
            ("/add", "read", "user", "declined", None,
             ("/home/alice/.aws/credentials",)),
            ("shell command", "shell", "agent", "declined",
             "rm -rf build/ dist/ *.egg-info", ()),
            ("launch", "read", "user", None, None, ("../.netrc",)),
        ])
        self.assertTrue(all(c.known and c.output is None and c.timestamp is None
                            for c in calls))
        self.assertTrue(all(c.project == self.repo for c in calls))
        self.assertEqual(calls[2].workdir, self.repo)
        self.assertEqual(calls[2].consumed, frozenset(["command"]))
        self.assertEqual(calls[5].consumed, frozenset(["path"]))
        ids = [c.tool_call_id for c in calls]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[:3], ["line 14", "line 49", "line 51"])

    def test_sessions_and_latest_times(self):
        path = self.write(SPEC)
        calls = list(self.src.tool_calls(self.store(path)))
        first, last = calls[:-1], calls[-1]
        self.assertEqual({c.session for c in first}, {"2026-10-07 14:02:51"})
        self.assertEqual({c.not_after for c in first}, {"2026-10-07 15:10:04"})
        self.assertEqual(last.session, "2026-10-07 15:10:04")
        mtime = os.stat(path).st_mtime
        self.assertEqual(last.not_after, time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime)))

    def test_the_same_calls_from_a_crlf_file(self):
        lf = self.brief(self.calls(SPEC))
        crlf = self.brief(self.calls(SPEC, crlf=True))
        self.assertEqual(lf, crlf)

    def test_calls_are_read_again_the_same(self):
        store = self.store(self.write(SPEC))
        self.assertEqual(list(self.src.tool_calls(store)),
                         list(self.src.tool_calls(store)))


class Shell(AiderCase):

    def test_commands_the_user_ran(self):
        calls = self.session(typed("/run make clean"), typed("!ls -la"),
                             typed("/ru echo hi"), typed("/test pytest -x"),
                             typed("/git log -1"), said("commit abc"))
        self.assertEqual([(c.tool_name, c.command, c.actor) for c in calls], [
            ("/run", "make clean", "user"), ("!", "ls -la", "user"),
            ("/run", "echo hi", "user"), ("/test", "pytest -x", "user"),
            ("/git", "git log -1", "user")])

    def test_inputs_that_run_nothing(self):
        calls = self.session(typed("/r ls"), typed(" /run ls"), typed("/run"),
                             typed("!"), typed("/test"), typed("/ls"),
                             typed("run ls please"), typed("<blank>"),
                             typed("/drop .env"))
        self.assertEqual(calls, [])

    def test_a_multi_line_input_is_one_command(self):
        calls = self.session(typed("/run echo a", "echo b"))
        self.assertEqual([c.command for c in calls], ["echo a\necho b"])

    def test_commands_from_a_load_file(self):
        calls = self.session(typed("/load cmds.txt"),
                             said("Executing: /run make", "Executing: /add x.py",
                                  "Added x.py to the chat",
                                  "Executing: !rm -rf ~/Documents/x"))
        self.assertEqual(self.brief(calls), [
            ("/run", "shell", "user", None, "make", ()),
            ("/add", "read", "user", None, None, ("x.py",)),
            ("!", "shell", "user", None, "rm -rf ~/Documents/x", ())])

    def test_git_output_is_its_output(self):
        calls = self.session(
            typed("/git show HEAD:.env"),
            ["> STRIPE_KEY=" + SECRET, "", "OTHER=1" + H],
            typed("/run ls"))
        self.assertEqual([(c.command, c.output) for c in calls], [
            ("git show HEAD:.env", "STRIPE_KEY=" + SECRET + "\n\nOTHER=1"),
            ("ls", None)])

    def test_git_output_at_the_end_of_a_session(self):
        calls = self.calls(header("2026-10-07 14:02:51") + typed("/git status")
                           + said("On branch main")
                           + header("2026-10-07 15:00:00") + typed("/run ls"))
        self.assertEqual([(c.command, c.output, c.session) for c in calls], [
            ("git status", "On branch main", "2026-10-07 14:02:51"),
            ("ls", None, "2026-10-07 15:00:00")])

    def test_a_suggested_command_ran_or_was_declined(self):
        for answer, status in (("y", None), ("n", "declined"),
                               ("d", "declined")):
            calls = self.session(said("make build", Q_SHELL + answer))
            self.assertEqual(self.brief(calls), [
                ("shell command", "shell", "agent", status, "make build", ())])

    def test_several_suggested_commands_in_one_block(self):
        # one subject: the first line quoted, the others raw and padded
        subject = ["> # build it        ", "make build         ",
                   "                  ", "rm -rf ~/Documents/x" + H]
        calls = self.session(subject, said(Q_SHELLS + "y"),
                             said("Running make build",
                                  "Running rm -rf ~/Documents/x"))
        self.assertEqual([(c.command, c.status, c.tool_call_id) for c in calls], [
            ("make build", None, "line 6"),
            ("rm -rf ~/Documents/x", None, "line 8")])

    def test_skip_all_echoed_as_typed_input(self):
        q = ("Run shell command? (Y)es/(N)o/(S)kip all/(D)on't ask again "
             "[Yes]: ")
        calls = self.session(said("make a", q + "s"), said("make b"),
                             typed(q + "skip"), said(q + "s"))
        self.assertEqual([(c.command, c.status) for c in calls],
                         [("make a", "declined"), ("make b", "declined")])

    def test_yes_always_declines_explicit_commands(self):
        calls = self.session(said("make a", Q_SHELL + "n"))
        self.assertEqual([c.status for c in calls], ["declined"])

    def test_an_answer_not_taken_is_asked_again(self):
        # confirm_ask logs tool_error between the subject and the question
        # it asks again; the subject is still the command.
        retry = "Please answer with one of: yes, no, skip, all, don't"
        calls = self.session(said("rm -rf ~/", retry, retry, Q_SHELL + "y"))
        self.assertEqual(self.brief(calls), [
            ("shell command", "shell", "agent", None, "rm -rf ~/", ())])
        calls = self.session(reply("see config.py"),
                             said("config.py", retry, Q_FILE + "n"))
        self.assertEqual(self.brief(calls), [
            ("file mention", "read", "agent", "declined", None,
             ("config.py",))])

    def test_a_question_with_no_subject_is_counted(self):
        self.src.reset()
        calls = self.session(reply("text"), [">" + Q_SHELL + "y" + H])
        self.assertEqual(calls, [])
        self.src.reset()
        calls = self.session(reply("text"), said(Q_SHELL + "y"))
        self.assertEqual(calls, [])
        self.assertEqual(self.src.counts["unknown"], 1)


class Files(AiderCase):

    def test_reads_and_refused_reads(self):
        calls = self.session(
            typed("/add src/*.py"), said("Added src/a.py to the chat",
                                         "Added src/b.py to the chat"),
            typed("/add .env"), said("Can't add /home/u/proj/.env which is in "
                                     "gitignore"),
            typed("/add secret.txt"), said("Skipping /home/u/proj/secret.txt due "
                                           "to aiderignore or --subtree-only."),
            typed("/read-only ~/.ssh"),
            said("Added 3 files from directory /home/u/.ssh to read-only files."),
            typed("/run ls"), said("Added 4 lines of output to the chat."))
        self.assertEqual(self.brief(calls), [
            ("/add", "read", "user", None, None, ("src/a.py",)),
            ("/add", "read", "user", None, None, ("src/b.py",)),
            ("/add", "read", "user", "declined", None, ("/home/u/proj/.env",)),
            ("/add", "read", "user", "declined", None,
             ("/home/u/proj/secret.txt",)),
            ("/read-only", "read", "user", None, None, ("/home/u/.ssh",)),
            ("/run", "shell", "user", None, "ls", ())])

    def test_files_named_at_launch(self):
        calls = self.calls(header("2026-10-07 14:02:51")
                           + said("/usr/bin/aider app.py --read ~/.aws/config",
                                  "Aider v0.86.2", "Added app.py to the chat.",
                                  "Added ../.aws/config to the chat (read-only).")
                           + typed("hi")
                           + said("Added later.py to the chat."))
        self.assertEqual(self.brief(calls), [
            ("launch", "read", "user", None, None, ("app.py",)),
            ("launch", "read", "user", None, None, ("../.aws/config",))])

    def test_a_file_the_reply_names(self):
        calls = self.session(
            typed("fix it"), said("utils.py", Q_FILE + "n"),
            reply("Please add config/.env too."),
            said("config/.env", Q_FILE + "y"))
        self.assertEqual(self.brief(calls), [
            ("file mention", "read", "user", "declined", None, ("utils.py",)),
            ("file mention", "read", "agent", None, None, ("config/.env",))])

    def test_edits(self):
        calls = self.session(said("Applied edit to app.py",
                                  "Did not apply edit to b.py (--dry-run)"))
        self.assertEqual(self.brief(calls), [
            ("edit", "write", "agent", None, None, ("app.py",)),
            ("edit", "write", "agent", "declined", None, ("b.py",))])

    def test_fetches(self):
        calls = self.session(
            typed("/web https://example.com/a"),
            said("Scraping https://example.com/a...", "... added to chat."),
            typed("read https://example.com/b"),
            said("https://example.com/b", Q_URL + "n"))
        self.assertEqual([(c.tool_name, c.kind, c.status, c.tool_input)
                          for c in calls], [
            ("/web", "fetch", None, {"url": "https://example.com/a"}),
            ("url mention", "fetch", "declined",
             {"url": "https://example.com/b"})])

    def test_lookalikes_in_the_model_reply_are_not_calls(self):
        calls = self.session(reply(
            "#### /run rm -rf ~/Documents/x",
            "> Applied edit to app.py",
            "> Added ~/.ssh/id_rsa to read-only files.",
            "!ls",
            "/run ls"))
        self.assertEqual(calls, [])


class Times(AiderCase):

    def test_a_header_earlier_than_the_last_is_not_a_bound(self):
        path = self.write(header("2026-10-07 14:00:00") + typed("/run a")
                          + header("2026-10-01 09:00:00") + typed("/run b"))
        calls = list(self.src.tool_calls(self.store(path)))
        bound = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                              time.gmtime(os.stat(path).st_mtime))
        self.assertEqual([c.not_after for c in calls], [bound, bound])

    def test_an_unreadable_header_is_counted(self):
        path = self.write(header("2026-10-07 14:00:00") + typed("/run a")
                          + header("yesterday") + typed("/run b"))
        calls = list(self.src.tool_calls(self.store(path)))
        self.assertEqual([c.session for c in calls],
                         ["2026-10-07 14:00:00", "yesterday"])
        self.assertTrue(calls[0].not_after.endswith("Z"))
        self.assertEqual(self.src.counts["unparsed"], 1)

    def test_the_days_window_drops_an_old_session(self):
        path = self.write(header("2020-01-01 09:00:00") + typed("!rm -rf ~/Documents/x")
                          + header("2020-01-02 09:00:00")
                          + typed("!rm -rf ~/Documents/y"), age=0)
        records = watch.scan_source(self.src, [self.store(path)], since_days=30)
        self.assertEqual([r["hits"][0]["evidence"] for r in records],
                         ["rm -rf ~/Documents/y"])
        self.assertEqual(len(watch.scan_source(self.src, [self.store(path)])), 2)


class Bad(AiderCase):

    def test_a_file_that_is_not_a_chat_log(self):
        path = self.write(None, raw=b"\x00\xff garbage\n{\"a\": 1}\n> x  \n")
        store = self.store(path)
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(list(self.src.tool_calls(store)), [])
            self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(err.getvalue().count("warning"), 1)
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_an_input_history_that_is_not_one(self):
        self.write(SPEC)
        path = self.write(None, name=INPUT, raw=b"garbage\n")
        store = [s for s in self.stores(override=self.repo) if s.path == path][0]
        with redirect_stderr(io.StringIO()):
            self.assertEqual(list(self.src.secret_texts(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_bytes_that_are_not_utf8(self):
        lines = SPEC + typed("/run echo caf\udce9")
        raw = text_of(lines).encode("utf-8", "surrogateescape")
        calls = self.calls(None, raw=raw)
        self.assertEqual(calls[-1].command, "echo caf\udce9")

    def test_an_empty_file(self):
        self.assertEqual(self.calls(None, raw=b""), [])

    def test_a_file_removed_before_reading(self):
        path = self.write(SPEC)
        store = self.store(path)
        os.remove(path)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(list(self.src.tool_calls(store)), [])
        self.assertEqual(self.src.counts["unreadable_stores"], 1)

    def test_a_truncated_last_line(self):
        raw = text_of(SPEC).encode()[:-3]
        self.assertEqual(len(self.calls(None, raw=raw)), 10)


# --------------------------------------------------------------------------
# Judged the way watch judges every agent
# --------------------------------------------------------------------------

class Judged(AiderCase):

    def test_a_destructive_command_is_flagged(self):
        for part in (typed("!rm -rf ~/Documents/x"),
                     typed("/run rm -rf ~/Documents/x"),
                     said("rm -rf ~/Documents/x", Q_SHELL + "y")):
            calls = self.session(part)
            self.assertIn("fs.destructive", rules(calls[0]))

    def test_credential_reads_are_flagged(self):
        calls = self.calls(SPEC)
        flagged = [c.paths[0] for c in calls if "cred.read" in rules(c)]
        for path in ("/home/alice/.ssh/id_rsa", "/home/alice/.aws/credentials",
                     ".env", "../.netrc"):
            self.assertIn(path, flagged)
        calls = self.session(typed("/read-only ~/.aws/credentials"),
                             said("Added /home/u/.aws/credentials to read-only "
                                  "files."))
        self.assertEqual(rules(calls[0]), ["cred.read"])

    def test_a_declined_call_is_reported_as_declined(self):
        calls = self.session(said("rm -rf ~/Documents/x", Q_SHELL + "n"))
        records = watch.scan_source(self.src, [self.store(
            os.path.join(self.repo, CHAT))])
        self.assertEqual(calls[0].status, "declined")
        self.assertEqual(records[0]["status"], "declined")
        self.assertNotIn("actor", records[0])

    def test_a_user_command_is_reported_as_the_users(self):
        self.session(typed("!rm -rf ~/Documents/x"))
        records = watch.scan_source(self.src, [self.store(
            os.path.join(self.repo, CHAT))])
        self.assertEqual((records[0]["actor"], records[0]["kind"],
                          records[0]["source"]), ("user", "shell", "aider"))


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

class Secrets(AiderCase):

    def test_every_line_reaches_clean(self):
        store = self.store(self.write(SPEC))
        texts = list(self.src.secret_texts(store))
        self.assertEqual([t.node for t in texts], SPEC)
        self.assertEqual(texts[0].where, "line 1")

    def test_a_key_on_the_launch_line(self):
        found = findings(self.src, [self.store(self.write(SPEC))])
        self.assertEqual(set(found), {SECRET})
        self.assertEqual(found[SECRET]["where"], ["line 94"])
        self.assertEqual(found[SECRET]["origins"], set())

    def test_an_edited_env_file_is_credited_to_env(self):
        found = findings(self.src, [self.store(self.write(
            header("2026-10-07 14:02:51") + typed("rotate the key")
            + reply("Here:", "", ".env", "```", "<<<<<<< SEARCH",
                    "STRIPE_KEY=" + SECRET, "=======", "STRIPE_KEY=" + OTHER,
                    ">>>>>>> REPLACE", "```", "", "Done. TOKEN=" + TYPED)))])
        self.assertEqual(found[SECRET]["origins"], {".env"})
        self.assertEqual(found[OTHER]["origins"], {".env"})
        self.assertEqual(found[TYPED]["origins"], set())

    def test_git_output_is_credited_to_the_file_it_showed(self):
        found = findings(self.src, [self.store(self.write(
            header("2026-10-07 14:02:51") + typed("/git show HEAD:.env")
            + said("STRIPE_KEY=" + SECRET) + typed("ok")))])
        self.assertEqual(found[SECRET]["origins"], {".env"})

    def test_a_cat_env_by_the_user_has_no_logged_output(self):
        # /run's output is never written to the log: nothing to find
        found = findings(self.src, [self.store(self.write(
            header("2026-10-07 14:02:51") + typed("/run cat .env")
            + said("Add 0.1k tokens of command output to the chat? (Y)es/(N)o "
                   "[Yes]: y", "Added 1 line of output to the chat.")))])
        self.assertEqual(found, {})

    def test_the_input_history(self):
        self.write(SPEC)
        hist = self.write(["", "# 2026-10-07 14:03:02.418273",
                           "+export STRIPE_KEY=" + SECRET,
                           "", "# 2026-10-07 14:03:03",
                           "+{", "+line two " + TYPED, "+}"], name=INPUT)
        store = [s for s in self.stores(override=self.repo) if s.path == hist][0]
        self.assertEqual(list(self.src.tool_calls(store)), [])
        texts = list(self.src.secret_texts(store))
        self.assertEqual([t.node for t in texts][:2],
                         ["# 2026-10-07 14:03:02.418273",
                          "export STRIPE_KEY=" + SECRET])
        found = findings(self.src, [store])
        self.assertEqual(found[SECRET]["where"], ["line 3"])

    def test_a_private_key_across_lines(self):
        # Each line of a key is a line of the log: pasted as one input,
        # shown by /git, or in an edit block. Each is found whole.
        body = ["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
                "QyNTUxOQAAACB" "q7Zx4Kd9Lm2Pw8Rt5Vy1Nc6Hb3Jf0Gs7Ta4Xe9Ui2Ow5Mr8AAAA",
                "kPh3Wn7Qs2Ly8Dk4Tf9Bx6Mr1Vc5Ga0Jz3Ne7Ku2Hp9Rw4Ys6Lt1Fq8Ab5Cm0Ix3Eo7"]
        key = (["-----BEGIN OPENSSH PRIVATE KEY-----"] + body
               + ["-----END OPENSSH PRIVATE KEY-----"])
        joined = "\n".join(key)
        lines = (header("2026-10-07 14:02:51") + typed(*(["use this:"] + key))
                 + typed("/git show HEAD:id_rsa") + ["> " + key[0]] + key[1:-1]
                 + [key[-1] + H]
                 + reply("id_rsa", "```", "<<<<<<< SEARCH", "=======")
                 [:-1] + key + [">>>>>>> REPLACE", "```", ""])
        path = self.write(lines, age=600)
        store = self.store(path)
        found = findings(self.src, [store])
        self.assertEqual(set(found), {joined})
        self.assertEqual(found[joined]["origins"], {"id_rsa"})
        hist_lines = ["", "# 2026-10-07 14:03:02.418273"] + ["+" + l for l in key]
        hist = self.write(hist_lines, name=INPUT, age=600)
        hstore = [s for s in self.stores(override=self.repo) if s.path == hist][0]
        self.assertEqual(set(findings(self.src, [hstore])), {joined})
        # and masked line by line, every other byte kept
        for st in (store, hstore):
            self.assertTrue(self.src.mask(st, [joined]).changed)
            self.assertEqual(findings(self.src, [st]), {})
        with open(path, "r", encoding="utf-8") as fh:
            masked = fh.read()
        expect = text_of(lines)
        for line in body:
            expect = expect.replace(line, clean.REDACTION % clean._fingerprint(line))
        self.assertEqual(masked, expect)

    def test_credential_files_beside_the_log_are_not_read(self):
        self.write(SPEC)
        self.write(["OPENAI_API_KEY=" + OTHER], name=".env")
        self.write(["openai-api-key: " + OTHER], name=".aider.conf.yml")
        self.write(["USER " + OTHER], name=".aider.llm.history")
        found = findings(self.src, self.stores(override=self.repo))
        self.assertNotIn(OTHER, found)
        self.assertEqual(set(found), {SECRET})

    def test_masking_keeps_every_other_byte(self):
        hist_lines = ["", "# 2026-10-07 14:03:02.418273", "+key " + SECRET]
        for crlf in (False, True):
            path = self.write(SPEC, crlf=crlf, age=600)
            hist = self.write(hist_lines, name=INPUT, age=600)
            stores = self.stores(override=self.repo)
            before = self.brief(self.calls(SPEC, crlf=crlf, age=600))
            for store in stores:
                result = self.src.mask(store, [SECRET])
                self.assertTrue(result.changed, store.path)
            marker = clean.REDACTION % clean._fingerprint(SECRET)
            with open(path, "rb") as fh:
                masked = fh.read()
            expected = text_of(SPEC, crlf).replace(SECRET, marker).encode()
            self.assertEqual(masked, expected)
            with open(hist, "rb") as fh:
                self.assertEqual(fh.read(), text_of(hist_lines).replace(
                    SECRET, marker).encode())
            store = self.store(path)
            self.assertEqual(self.brief(self.src.tool_calls(store)), before)
            self.assertEqual(findings(self.src, [store]), {})

    def test_a_log_written_just_now_is_not_masked(self):
        store = self.store(self.write(SPEC, age=0))
        self.assertEqual(self.src.mask(store, [SECRET]).skipped, "in use")

    def test_reading_writes_nothing(self):
        self.write(SPEC)
        self.write(["", "# 2026-10-07 14:03:02", "+x"], name=INPUT)
        before = _snapshot(self.home)
        listing = sorted(os.listdir(self.repo))
        for store in self.stores(override=self.repo):
            list(self.src.tool_calls(store))
            list(self.src.secret_texts(store))
        self.assertEqual(_snapshot(self.home), before)
        self.assertEqual(sorted(os.listdir(self.repo)), listing)


if __name__ == "__main__":
    unittest.main()
