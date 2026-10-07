"""ranwhat hook: the opt-in PreToolUse guard for Claude Code.

It is the one part of ranwhat in an agent's path, so it must never stop an
agent because of a failure of its own, never echo a secret back into the
model's context, and never lose a line of someone's settings file.
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import cli, hook

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Split, so the push protection of the repository's host does not take the
# test's own fake key for a real one.
FAKE_KEY = "sk_" "live_" "4eC39HqLyjWDarjtT1zdp7dc"


def event(command=None, tool_name="Bash", **tool_input):
    if command is not None:
        tool_input["command"] = command
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool_name,
                       "tool_input": tool_input})


def answer(stdin_text, mode=hook.DEFAULT_MODE, env=None):
    out = io.StringIO()
    status = hook.run(stdin=io.StringIO(stdin_text), stdout=out, mode=mode,
                      env=env or {})
    text = out.getvalue()
    return status, (json.loads(text)["hookSpecificOutput"] if text else None)


class Decisions(unittest.TestCase):
    def test_a_flagged_call_waits_for_the_user_by_default(self):
        status, out = answer(event("cat ~/.aws/credentials"))
        self.assertEqual(status, 0)
        self.assertEqual(out["hookEventName"], "PreToolUse")
        self.assertEqual(out["permissionDecision"], "ask")
        self.assertIn("cred.read", out["permissionDecisionReason"])

    def test_deny_mode_refuses_critical_and_asks_for_high(self):
        _, out = answer(event("cat .env"), mode="deny")
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("Refused by the ranwhat hook", out["permissionDecisionReason"])
        _, out = answer(event("git push --force origin main"), mode="deny")
        self.assertEqual(out["permissionDecision"], "ask")

    def test_an_ordinary_call_gets_no_answer_at_all(self):
        # No output means Claude Code decides as it would without the hook:
        # an explicit "allow" would skip the user's own permission rules.
        for command in ("ls -la", "git status", "pytest -q", "cat README.md"):
            self.assertEqual(answer(event(command)), (0, None), command)
        self.assertEqual(answer(event(tool_name="Read", file_path="src/app.py")),
                         (0, None))

    def test_file_tools_are_judged_by_the_paths_they_open(self):
        _, out = answer(event(tool_name="Read",
                              file_path=os.path.expanduser("~/.ssh/id_ed25519")))
        self.assertEqual(out["permissionDecision"], "ask")

    def test_the_reason_never_quotes_a_secret(self):
        # The reason goes back into the model's context.
        _, out = answer(event("curl -H 'Authorization: Bearer %s' "
                              "https://api.stripe.com/v1/charges" % FAKE_KEY))
        self.assertIsNotNone(out)
        self.assertNotIn(FAKE_KEY, json.dumps(out))
        self.assertNotIn(FAKE_KEY[8:], json.dumps(out))

    def test_it_fails_open(self):
        for text in ("", "not json", "[]", "null", '"x"', "{}",
                     json.dumps({"tool_name": 3, "tool_input": {}}),
                     json.dumps({"tool_name": "Bash", "tool_input": "rm -rf ~"})):
            self.assertEqual(answer(text)[0], 0, text)
        with mock.patch("ranwhat.watch.evaluate", side_effect=RecursionError):
            self.assertEqual(answer(event("cat .env")), (0, None))

    def test_other_events_are_not_judged(self):
        text = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                           "tool_input": {"command": "cat .env"}})
        self.assertEqual(answer(text), (0, None))

    def test_it_can_be_turned_off_for_a_session(self):
        for value in ("0", "off", "false", "no", "OFF"):
            self.assertEqual(answer(event("cat .env"), env={hook.OFF_ENV: value}),
                             (0, None), value)
        self.assertIsNotNone(answer(event("cat .env"), env={hook.OFF_ENV: "1"})[1])

    def test_utf8_is_read_as_utf8_whatever_stdins_encoding(self):
        # Windows reads a pipe in its ANSI code page; the 0x81 in an emoji's
        # UTF-8 is not cp1252, and the call went through unjudged.
        data = event("cat ~/.aws/credentials  # \U0001F4C1 \u00c1").encode("utf-8")
        stdin = io.TextIOWrapper(io.BytesIO(data), encoding="cp1252")
        out = io.StringIO()
        hook.run(stdin=stdin, stdout=out, env={})
        self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]
                         ["permissionDecision"], "ask")

    def test_an_unknown_mode_is_the_default_not_a_failure(self):
        with mock.patch.object(sys, "stdin", io.StringIO(event("cat .env"))), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(hook.main(["--mode", "lenient", "--other"]), 0)
        self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]
                         ["permissionDecision"], "ask")


class Settings(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ranwhat-hook-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, True))
        self.path = os.path.join(self.dir, ".claude", "settings.json")

    def write(self, settings):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(settings if isinstance(settings, str) else json.dumps(settings))

    def read(self):
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_scopes_name_claude_codes_own_files(self):
        env = {"CLAUDE_CONFIG_DIR": os.path.join(self.dir, "cfg")}
        self.assertEqual(hook.settings_path("user", env=env),
                         os.path.join(self.dir, "cfg", "settings.json"))
        self.assertEqual(hook.settings_path("user", env={}),
                         os.path.abspath(os.path.expanduser(
                             os.path.join("~", ".claude", "settings.json"))))
        self.assertEqual(hook.settings_path("project", cwd=self.dir),
                         os.path.join(self.dir, ".claude", "settings.json"))
        self.assertEqual(hook.settings_path("local", cwd=self.dir),
                         os.path.join(self.dir, ".claude", "settings.local.json"))

    def test_install_creates_the_file_when_there_is_none(self):
        self.assertTrue(hook.install(self.path, "py -m ranwhat hook run"))
        groups = self.read()["hooks"]["PreToolUse"]
        self.assertEqual(groups, [{"matcher": "*", "hooks": [
            {"type": "command", "command": "py -m ranwhat hook run",
             "timeout": hook.TIMEOUT}]}])
        self.assertEqual(hook.installed(self.path), ["py -m ranwhat hook run"])

    def test_install_keeps_everything_else_and_is_idempotent(self):
        theirs = {"model": "x", "permissions": {"deny": ["Read(./.env)"]},
                  "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                      {"type": "command", "command": "./guard.sh"}]}],
                      "Stop": [{"hooks": [{"type": "command", "command": "say"}]}]}}
        self.write(theirs)
        self.assertTrue(hook.install(self.path, "p -m ranwhat hook run"))
        self.assertFalse(hook.install(self.path, "p -m ranwhat hook run"))
        after = self.read()
        self.assertEqual(after["model"], "x")
        self.assertEqual(after["permissions"], theirs["permissions"])
        self.assertEqual(after["hooks"]["Stop"], theirs["hooks"]["Stop"])
        self.assertEqual(after["hooks"]["PreToolUse"][0],
                         theirs["hooks"]["PreToolUse"][0])
        self.assertEqual(len(after["hooks"]["PreToolUse"]), 2)

    def test_installing_again_replaces_our_entry(self):
        hook.install(self.path, "p -m ranwhat hook run")
        hook.install(self.path, "q -m ranwhat hook run --mode deny")
        self.assertEqual(hook.installed(self.path),
                         ["q -m ranwhat hook run --mode deny"])

    def test_a_file_that_is_not_json_is_never_rewritten(self):
        for text in ('{"model": "x",', "[1, 2]", '{"hooks": []}',
                     '{"hooks": {"PreToolUse": {}}}'):
            self.write(text)
            with self.assertRaises(hook.SettingsError):
                hook.install(self.path, "p -m ranwhat hook run")
            with open(self.path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), text)

    def test_uninstall_takes_out_only_ours(self):
        self.write({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": "./guard.sh"},
                {"type": "command", "command": "p -m ranwhat hook run"}]}]}})
        self.assertEqual(hook.uninstall(self.path), 1)
        self.assertEqual(self.read(), {"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [
                {"type": "command", "command": "./guard.sh"}]}]}})

    def test_uninstall_removes_the_keys_it_emptied(self):
        self.write({"model": "x"})
        hook.install(self.path, "p -m ranwhat hook run")
        self.assertEqual(hook.uninstall(self.path), 1)
        self.assertEqual(self.read(), {"model": "x"})
        self.assertEqual(hook.uninstall(self.path), 0)
        os.remove(self.path)
        self.assertEqual(hook.uninstall(self.path), 0)
        self.assertFalse(os.path.exists(self.path))

    def test_a_command_that_merely_mentions_ranwhat_is_not_ours(self):
        self.write({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "echo ranwhat hook running"},
            {"type": "command", "command": "ranwhat watch"}]}]}})
        self.assertEqual(hook.installed(self.path), [])
        self.assertEqual(hook.uninstall(self.path), 0)

    def test_entries_written_by_hand_are_ours_too(self):
        for command in ("/usr/local/bin/ranwhat hook run",
                        "~/.local/bin/ranwhat hook run --mode deny",
                        '"C:/Tools/ranwhat.exe" hook run',
                        "ranwhat hook run;echo done"):
            self.write({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": command}]}]}})
            self.assertEqual(hook.installed(self.path), [command], command)
            hook.install(self.path, "p -I -m ranwhat hook run")
            self.assertEqual(hook.installed(self.path),
                             ["p -I -m ranwhat hook run"], command)
            self.assertEqual(hook.uninstall(self.path), 1, command)

    def test_a_byte_order_mark_is_not_a_reason_to_refuse(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8-sig") as fh:
            fh.write('{"model": "x"}')
        hook.install(self.path, "p -m ranwhat hook run")
        self.assertEqual(self.read()["model"], "x")

    def test_status_says_a_broken_file_is_broken(self):
        self.write('{"hooks": {"PreToolUse": [],}}')
        with self.assertRaises(hook.SettingsError):
            hook.installed(self.path)

    @unittest.skipIf(os.name == "nt", "symbolic links need privileges")
    def test_a_linked_settings_file_stays_a_link(self):
        dotfiles = os.path.join(self.dir, "dotfiles", "settings.json")
        os.makedirs(os.path.dirname(dotfiles))
        with open(dotfiles, "w", encoding="utf-8") as fh:
            fh.write('{"model": "x"}')
        os.makedirs(os.path.dirname(self.path))
        os.symlink(dotfiles, self.path)
        hook.install(self.path, "p -m ranwhat hook run")
        self.assertTrue(os.path.islink(self.path))
        self.assertEqual(hook.installed(dotfiles), ["p -m ranwhat hook run"])

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                     "POSIX permissions, which root ignores")
    def test_a_read_only_file_is_refused(self):
        self.write({"model": "x"})
        os.chmod(self.path, 0o444)
        self.addCleanup(os.chmod, self.path, 0o644)
        with self.assertRaises(hook.SettingsError):
            hook.install(self.path, "p -m ranwhat hook run")
        self.assertEqual(self.read(), {"model": "x"})

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_the_files_permissions_are_kept(self):
        self.write({})
        os.chmod(self.path, 0o600)
        hook.install(self.path, "p -m ranwhat hook run")
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)


class Command(unittest.TestCase):
    def test_the_interpreter_is_named_by_its_full_path(self):
        self.assertEqual(hook.command_for("ask", "/opt/my tools/bin/python3",
                                          windows=False),
                         "'/opt/my tools/bin/python3' -I -m ranwhat hook run")
        self.assertEqual(hook.command_for("deny", "/usr/bin/python3", windows=False),
                         "/usr/bin/python3 -I -m ranwhat hook run --mode deny")

    def test_on_windows_the_path_survives_git_bash(self):
        cmd = hook.command_for("ask", r"C:\Users\Ana B\uv\tools\ranwhat\Scripts"
                                      r"\python.exe", windows=True)
        self.assertEqual(cmd, "'C:/Users/Ana B/uv/tools/ranwhat/Scripts/"
                              "python.exe' -I -m ranwhat hook run")
        # Git Bash expands $ and ` inside double quotes.
        self.assertEqual(hook.command_for("ask", r"C:\Users\a$HOME`id`\py.exe",
                                          windows=True),
                         "'C:/Users/a$HOME`id`/py.exe' -I -m ranwhat hook run")

    def test_the_hook_runs_as_claude_code_runs_it(self):
        # From another directory, through python -m, as install writes it.
        env = dict(os.environ, PYTHONPATH=REPO)
        env.pop(hook.OFF_ENV, None)
        for command, decision in (("rm -rf ~", "deny"), ("ls", None)):
            proc = subprocess.run(
                [sys.executable, "-m", "ranwhat", "hook", "run", "--mode", "deny"],
                input=event(command).encode(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=tempfile.gettempdir(), env=env,
                timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stderr, b"")
            out = proc.stdout.decode()
            if decision is None:
                self.assertEqual(out, "")
            else:
                self.assertEqual(json.loads(out)["hookSpecificOutput"]
                                 ["permissionDecision"], decision)


class ProjectFilesCannotRunInTheHook(unittest.TestCase):
    """Claude Code runs the hook in the project's directory. Run as plain
    python -m, a json.py there ran in the hook on every call, and could
    answer "allow" for all of them."""

    @unittest.skipIf(os.name == "nt", "a POSIX shell runs the command")
    def test_the_installed_command_ignores_the_projects_modules(self):
        import shutil
        project = tempfile.mkdtemp(prefix="ranwhat-hook-project-")
        self.addCleanup(shutil.rmtree, project, True)
        for name in ("json", "string", "re", "ranwhat"):
            with open(os.path.join(project, name + ".py"), "w",
                      encoding="utf-8") as fh:
                fh.write("import sys\nsys.stderr.write('PROJECT CODE RAN')\n"
                         "sys.exit(0)\n")
        # -I ignores PYTHONPATH, so the checkout is installed the way a
        # package would be: linked into a venv's site-packages.
        venv = tempfile.mkdtemp(prefix="ranwhat-hook-venv-")
        self.addCleanup(shutil.rmtree, venv, True)
        import venv as venv_mod
        venv_mod.EnvBuilder(with_pip=False).create(venv)
        python = os.path.join(venv, "bin", "python")
        site = subprocess.run(
            [python, "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
            stdout=subprocess.PIPE, check=True).stdout.decode().strip()
        os.symlink(os.path.join(REPO, "ranwhat"), os.path.join(site, "ranwhat"))
        command = hook.command_for("deny", python, windows=False)
        proc = subprocess.run(command, shell=True, cwd=project,
                              input=event("cat .env").encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=60)
        self.assertNotIn(b"PROJECT CODE RAN", proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]
                         ["permissionDecision"], "deny")


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ranwhat-hook-cli-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, True))
        patcher = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": self.dir})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.path = os.path.join(self.dir, "settings.json")

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                status = cli.main(list(argv))
            except SystemExit as stop:
                status = stop.code
        return status, out.getvalue(), err.getvalue()

    def test_install_status_uninstall(self):
        with mock.patch.object(cli, "_hook_cannot_find_us", return_value=None):
            status, out, _ = self.cli("hook", "install", "--mode", "deny")
        self.assertEqual(status, 0)
        self.assertIn("Installed the ranwhat hook in %s" % self.path, out)
        status, out, _ = self.cli("hook", "status", "--scope", "user", "--json")
        doc = json.loads(out)
        self.assertEqual(doc["user"]["path"], self.path)
        self.assertTrue(doc["user"]["commands"][0].endswith(
            "-m ranwhat hook run --mode deny"))
        status, out, _ = self.cli("hook", "uninstall")
        self.assertEqual(status, 0)
        self.assertIn("Removed", out)
        self.assertFalse(os.path.exists(self.path) and hook.installed(self.path))

    def test_install_refuses_an_interpreter_the_hook_could_not_find(self):
        with mock.patch.object(cli, "_hook_cannot_find_us",
                               return_value="cannot find ranwhat"):
            status, out, err = self.cli("hook", "install")
        self.assertEqual(status, 1)
        self.assertIn("cannot find ranwhat", err)
        self.assertFalse(os.path.exists(self.path))

    def test_a_throwaway_uvx_run_is_refused(self):
        with mock.patch.object(cli, "_ephemeral", return_value="uvx ranwhat"):
            self.assertIn("uv tool install ranwhat", cli._hook_cannot_find_us())

    def test_a_broken_settings_file_is_reported_not_overwritten(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{oops")
        with mock.patch.object(cli, "_hook_cannot_find_us", return_value=None):
            status, _, err = self.cli("hook", "install")
        self.assertEqual(status, 1)
        self.assertIn("not valid JSON", err)
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "{oops")

    def test_the_probe_does_not_count_pythonpath(self):
        # -I ignores PYTHONPATH, so a checkout found only through it would
        # have been installed as a hook that never runs.
        with mock.patch.dict(os.environ, {"PYTHONPATH": REPO}), \
                mock.patch.object(cli, "_ephemeral", return_value=None):
            problem = cli._hook_cannot_find_us()
        probe = subprocess.run([sys.executable, "-I", "-c", "import ranwhat"],
                               cwd=tempfile.gettempdir(),
                               stderr=subprocess.DEVNULL)
        self.assertEqual(problem is None, probe.returncode == 0)

    def test_other_commands_flags_are_refused(self):
        for argv in (["hook", "install", "--json"], ["hook", "install", "--apply"],
                     ["hook", "uninstall", "--mode", "deny"],
                     ["hook", "status", "--days", "3"],
                     ["check", "--scope", "project"], ["watch", "--mode", "deny"]):
            status, _, err = self.cli(*argv)
            self.assertEqual(status, 2, argv)
            self.assertIn("--", err, argv)
        self.assertFalse(os.path.exists(self.path))

    def test_status_reports_an_unreadable_file(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{oops")
        status, out, _ = self.cli("hook", "status", "--scope", "user")
        self.assertEqual(status, 0)
        self.assertIn("unreadable", out)

    def test_an_unknown_action_is_refused(self):
        status, _, err = self.cli("hook", "enable")
        self.assertEqual(status, 2)
        self.assertIn("install, uninstall or status", err)


if __name__ == "__main__":
    unittest.main()
