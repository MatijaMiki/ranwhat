"""What the CLI says about itself.

The overview said nothing is transmitted and `update` claimed to be the only
command that touches the network, while `live` and --pull-usage send each
token to its provider. --days and --root were documented as watch-only while
also driving check and clean. A finding told the reader to "Run
--pull-usage", which is a flag, not a command.
"""
import ast
import contextlib
import errno
import io
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import cli, report, score, term

ANSI = re.compile(r"\033\[[0-9;]*m")


def overview(width=80):
    out = io.StringIO()
    with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(width)}), \
         mock.patch.object(cli, "invocation", return_value="uvx ranwhat"), \
         contextlib.redirect_stdout(out):
        cli._overview(None)
    return ANSI.sub("", out.getvalue())


def parser_help():
    out = io.StringIO()
    with contextlib.redirect_stdout(out), mock.patch.dict(
            os.environ, {"COLUMNS": "200"}):
        try:
            cli.main(["--help"])
        except SystemExit:
            pass
    return out.getvalue()


class Overview(unittest.TestCase):

    def test_lists_every_command(self):
        text = overview()
        for command in ("check", "watch", "clean", "scan", "live", "demo",
                        "update"):
            self.assertTrue(re.search(r"^  %s +\S" % command, text, re.M),
                            command)

    def test_names_what_goes_online(self):
        prose = " ".join(overview().split())
        self.assertNotIn("nothing is transmitted", prose.lower())
        for name in ("live", "--pull-usage", "update"):
            self.assertIn(name, prose.split("Start here")[1])
        self.assertIn("provider", prose)

    def test_fits_a_narrow_terminal(self):
        for width in (46, 50, 80):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(width)}):
                limit = term.width()
            for line in overview(width).split("\n"):
                self.assertLessEqual(len(line), limit, (width, line))
                self.assertEqual(line, line.rstrip(), (width, line))

    def test_a_wrapped_description_stays_in_its_column(self):
        lines = overview(46).split("\n")
        i = next(i for i, l in enumerate(lines) if l.startswith("  clean "))
        self.assertRegex(lines[i + 1], r"^ {11}\S", lines[i:i + 2])

    def test_check_claims_only_what_it_reads(self):
        # It reads watch's and clean's sources, not "everything on this
        # machine", which made an empty result read as a clean machine.
        lines = overview().split("\n")
        i = next(i for i, l in enumerate(lines) if l.startswith("  check "))
        what = " ".join(" ".join(lines[i:i + 2])[len("  check "):].split())
        self.assertNotIn("everything", what)
        self.assertIn("watch and clean", what)

    def test_update_docstring_no_longer_claims_to_be_alone(self):
        self.assertNotIn("only command", cli._update.__doc__)


class Help(unittest.TestCase):

    def test_description_is_the_tagline(self):
        text = " ".join(parser_help().split())
        self.assertIn("Flight recorder and authority scanner for AI agents.",
                      text)
        self.assertNotIn("transmits nothing", text)

    def test_days_and_root_name_every_command_they_drive(self):
        text = " ".join(parser_help().split())
        for flag in ("--days DAYS", "--root PATH"):
            help_text = text.split(flag, 2)[2].split(" --", 1)[0]
            for command in ("check", "watch", "clean"):
                self.assertIn(command, help_text, flag)
        state = text.split("--state-dir PATH", 2)[2].split(" --", 1)[0]
        self.assertIn("check", state)


class PullUsageAdvice(unittest.TestCase):

    def self_attested(self, result):
        return next(f for f in result["findings"]
                    if f["title"].startswith("Usage is self-attested"))

    def profile(self):
        return {"agent": "t", "credentials": [
            {"provider": "stripe", "scopes": ["refunds:write"],
             "scopes_used": ["refunds:write"]}]}

    def test_without_a_file_there_is_no_command_to_copy(self):
        # demo has no profile on disk. `<profile>` in a command is shell
        # redirection, and the reader has nothing to put there.
        with mock.patch.object(cli, "invocation", return_value="uvx ranwhat"):
            body = self.self_attested(score.scan(self.profile()))["body"]
        self.assertNotIn("<profile>", body)
        self.assertNotIn("`", body)
        self.assertNotIn("Run --pull-usage", body)
        self.assertIn("your own profile", body)
        self.assertIn("--pull-usage", body)

    def test_demo_says_it_applies_to_your_own_scan(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "80"}), \
             contextlib.redirect_stdout(out):
            cli.main(["demo"])
        text = " ".join(ANSI.sub("", out.getvalue()).split())
        self.assertIn("Usage is self-attested", text)
        self.assertNotIn("<profile>", text)
        self.assertNotRegex(text.split("Usage is self-attested")[1],
                            r"ranwhat scan\b")
        self.assertIn("your own profile", text)

    def test_uses_the_path_that_was_scanned(self):
        with mock.patch.object(cli, "invocation", return_value="ranwhat"):
            body = self.self_attested(
                score.scan(self.profile(), path="my agent.json"))["body"]
        # Quoted for the reader's shell: cmd and PowerShell take double quotes.
        quoted = '"my agent.json"' if os.name == "nt" else "'my agent.json'"
        self.assertIn("ranwhat scan %s --pull-usage" % quoted, body)

    def test_windows_quoting_is_what_cmd_and_powershell_read(self):
        with mock.patch.object(cli.os, "name", "nt"):
            self.assertEqual(cli._quote("my agent.json"), '"my agent.json"')
            self.assertEqual(cli._quote(r"C:\agents\a.json"), r"C:\agents\a.json")

    def test_a_path_in_home_is_written_under_tilde(self):
        # Shorter, so the command is likelier to fit the line. Neither cmd
        # nor PowerShell reads ~ as home, so there the path is whole.
        home = os.path.expanduser("~")
        path = os.path.join(home, "my agent.json")
        with mock.patch.object(cli, "invocation", return_value="ranwhat"):
            body = self.self_attested(score.scan(self.profile(), path=path))["body"]
        if os.name == "nt":
            self.assertIn("ranwhat scan %s --pull-usage" % cli._quote(path), body)
        else:
            self.assertIn("ranwhat scan ~/'my agent.json' --pull-usage", body)

    def test_names_what_each_provider_needs(self):
        profile = self.profile()
        profile["credentials"] += [
            {"provider": "github", "scopes": ["repo"], "scopes_used": []},
            {"provider": "aws", "scopes": ["s3:GetObject"],
             "scopes_used": []}]
        with mock.patch.object(cli, "invocation", return_value="ranwhat"):
            body = self.self_attested(score.scan(profile, path="p.json"))["body"]
        for name in ("RANWHAT_STRIPE_TOKEN", "RANWHAT_GITHUB_TOKEN"):
            self.assertIn(name, body)
        self.assertNotIn("RANWHAT_AWS_TOKEN", body)
        self.assertIn("AWS CLI", body)
        # GitHub reports usage only in an organisation's audit log
        self.assertIn("--github-org", body)

    def test_a_provider_with_no_pull_is_not_promised_one(self):
        # usage.PULLS has no slack: --pull-usage cannot evidence it.
        profile = self.profile()
        profile["credentials"].append(
            {"provider": "slack", "scopes": ["chat:write"],
             "scopes_used": ["chat:write"]})
        for path in (None, "p.json"):
            with mock.patch.object(cli, "invocation", return_value="ranwhat"):
                finding = self.self_attested(score.scan(profile, path=path))
            self.assertIn("slack", finding["evidence"])
            body = finding["body"]
            self.assertNotIn("RANWHAT_SLACK_TOKEN", body)
            self.assertRegex(body, r"no usage pull for slack\b")
            pulled = body.split("--pull-usage", 1)[1].split(".")[0]
            self.assertNotIn("slack", pulled)

    def test_after_a_pull_it_does_not_advise_the_same_command(self):
        with mock.patch.object(cli, "invocation", return_value="ranwhat"):
            body = self.self_attested(score.scan(
                self.profile(), path="p.json", pulled=True))["body"]
        self.assertNotIn("scan p.json --pull-usage", body)
        self.assertNotIn("`", body)
        self.assertIn("stripe", body)

    def test_scan_command_passes_its_path(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json",
                                         delete=False) as fh:
            json.dump(self.profile(), fh)
        self.addCleanup(os.unlink, fh.name)
        out = io.StringIO()
        with mock.patch.object(cli, "invocation", return_value="ranwhat"), \
             contextlib.redirect_stdout(out):
            cli.main(["scan", fh.name, "--json"])
        body = self.self_attested(json.loads(out.getvalue()))["body"]
        self.assertIn("ranwhat scan %s --pull-usage" % fh.name, body)


def _demo_profile_file(test):
    import tempfile
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json",
                                     delete=False) as fh:
        json.dump(cli._bundled("support-copilot.json"), fh)
    test.addCleanup(os.unlink, fh.name)
    return fh.name


def _run(argv, **env):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


class PullUsageSaysWhatItSkipped(unittest.TestCase):
    """With no RANWHAT_*_TOKEN set, --pull-usage skipped github, google and
    stripe without a word, then advised running the command just run, and
    its footer said each token went to its provider when none had gone."""

    def run_pull(self):
        path = _demo_profile_file(self)
        env = {k: v for k, v in os.environ.items()
               if not (k.startswith("RANWHAT_") and k.endswith("_TOKEN"))}
        env["RANWHAT_WIDTH"] = "80"
        refuse = {name: mock.Mock(side_effect=AssertionError(name))
                  for name in cli.usage_mod.PULLS}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.dict(cli.usage_mod.PULLS, refuse), \
             mock.patch.object(cli.usage_mod, "aws_usage", refuse["aws"]), \
             mock.patch.object(cli.usage_mod, "github_usage",
                               refuse["github"]), \
             mock.patch.object(cli.shutil, "which", return_value=None), \
             mock.patch.object(cli, "invocation", return_value="ranwhat"):
            rc, out, err = _run(["scan", path, "--pull-usage"])
        self.assertEqual(rc, 0)
        return path, ANSI.sub("", out), " ".join(err.split())

    def test_each_skip_names_what_would_enable_it(self):
        _, _, err = self.run_pull()
        for name in ("github", "google", "stripe"):
            self.assertRegex(err, r"usage: %s +skipped\b.*?RANWHAT_%s_TOKEN"
                             % (name, name.upper()))
        self.assertRegex(err, r"usage: aws +skipped\b.*?aws CLI")
        self.assertRegex(err, r"usage: slack +\S")

    def test_nothing_sent_so_the_footer_says_so(self):
        _, out, _ = self.run_pull()
        lines = out.split("\n")
        self.assertIn(term.FOOTER, lines)
        self.assertNotIn(report.ONLINE_FOOTER, lines)

    def test_the_command_just_run_is_not_advised_again(self):
        path, out, _ = self.run_pull()
        self.assertIn("Usage is self-attested", out)
        self.assertNotIn("%s --pull-usage" % path, " ".join(out.split()))

    def test_every_stderr_line_fits(self):
        path = _demo_profile_file(self)
        env = {k: v for k, v in os.environ.items()
               if not (k.startswith("RANWHAT_") and k.endswith("_TOKEN"))}
        env["RANWHAT_WIDTH"] = "46"
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(cli.shutil, "which", return_value=None):
            _, _, err = _run(["scan", path, "--pull-usage", "--json"])
            limit = term.width()
        for line in err.rstrip("\n").split("\n"):
            self.assertLessEqual(len(line), limit, line)


class GithubUsageNeedsAnOrganisation(unittest.TestCase):
    """With RANWHAT_GITHUB_TOKEN set and no --github-org, github_usage
    returned before sending anything, yet the pull counted as asked: stderr
    said "usage: github none" and the report ended "Each token went only to
    its own provider." with nothing sent. The advice never named the flag."""

    def run_pull(self, *extra):
        path = _demo_profile_file(self)
        env = {k: v for k, v in os.environ.items()
               if not (k.startswith("RANWHAT_") and k.endswith("_TOKEN"))}
        env.update(RANWHAT_WIDTH="80", RANWHAT_GITHUB_TOKEN="synthetic")
        github = mock.Mock(return_value=([], cli.usage_mod.Coverage(
            "github", cli.usage_mod.Coverage.FULL, "", 90)))
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(cli.usage_mod, "github_usage", github), \
             mock.patch.object(cli.shutil, "which", return_value=None), \
             mock.patch.object(cli, "invocation", return_value="ranwhat"):
            rc, out, err = _run(["scan", path, "--pull-usage"] + list(extra))
        self.assertEqual(rc, 0)
        return github, ANSI.sub("", out).split("\n"), " ".join(err.split())

    def test_without_an_org_it_is_skipped_and_says_how(self):
        github, out, err = self.run_pull()
        github.assert_not_called()
        self.assertRegex(err, r"usage: github +skipped\b.*?--github-org")
        self.assertIn(term.FOOTER, out)
        self.assertNotIn(report.ONLINE_FOOTER, out)

    def test_with_an_org_it_is_asked(self):
        github, out, _ = self.run_pull("--github-org", "synthetic-org")
        github.assert_called_once()
        self.assertEqual(github.call_args[1]["org"], "synthetic-org")
        self.assertIn(report.ONLINE_FOOTER, out)


class HtmlIsForTheAuthorityReport(unittest.TestCase):
    """--html was documented with no command named, and check, watch and
    clean ignored it: exit 0, no file, no word. With --json, the "html
    report:" notice went to stdout after the JSON, which then would not
    parse."""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="html-scope-")

    def test_check_watch_clean_refuse_it_before_reading_anything(self):
        for command in ("check", "watch", "clean", "update"):
            path = os.path.join(self.dir, command + ".html")
            with mock.patch.object(cli.watch_mod, "scan_sources_counted",
                                   side_effect=AssertionError("scanned")), \
                 mock.patch.object(cli.clean_mod, "scan",
                                   side_effect=AssertionError("scanned")), \
                 mock.patch.object(cli.feed_mod, "fetch",
                                   side_effect=AssertionError("fetched")):
                rc, out, err = _run([command, "--html", path,
                                     "--root", "/nonexistent/ranwhat-root",
                                     "--state-dir", "/nonexistent/x"])
            self.assertEqual(rc, 2, command)
            self.assertEqual(out, "", command)
            self.assertIn("--html", err, command)
            self.assertIn(command, err.split("error:", 1)[1], command)
            self.assertFalse(os.path.exists(path), command)

    def test_json_stays_parseable(self):
        for argv in (["demo"], ["scan", _demo_profile_file(self)]):
            path = os.path.join(self.dir, argv[0] + ".html")
            rc, out, err = _run(argv + ["--json", "--html", path])
            self.assertEqual(rc, 0)
            json.loads(out)
            self.assertIn("html report: %s" % path, err)
            self.assertTrue(os.path.exists(path))

    def test_without_json_the_notice_stays_with_the_report(self):
        path = os.path.join(self.dir, "demo-text.html")
        rc, out, err = _run(["demo", "--html", path])
        self.assertEqual(rc, 0)
        self.assertIn("html report: %s" % path, out)
        self.assertNotIn("html report", err)

    def test_help_names_the_commands_it_is_for(self):
        text = " ".join(parser_help().split())
        help_text = text.split("--html PATH", 2)[2].split(" --", 1)[0]
        for command in ("demo", "scan", "live"):
            self.assertIn(command, help_text)
        for command in ("check", "watch", "clean"):
            self.assertNotIn(command, help_text)


class AFollowUpCommandRunsInPowerShell(unittest.TestCase):
    """PowerShell reads a quoted first word as a string, not a command to
    run, so a suggested `"C:\\Program Files\\Python313\\python.exe" -m
    ranwhat` failed there with "Unexpected token '-m'": the spelling of
    every next step check suggested after `py -m ranwhat`."""

    EXE = r"C:\Program Files\Python313\python.exe"

    def spelled(self, exe, on_path, starts):
        """_python_m on Windows, with `on_path` {name: what PATH finds}
        and `starts` whether a launcher asked starts this interpreter."""
        with mock.patch.object(cli.shutil, "which",
                               side_effect=lambda name, path=None: on_path.get(name)), \
                mock.patch.object(cli, "_launches", return_value=starts) as asked:
            return cli._python_m(exe, "", windows=True), asked

    def test_py_when_it_starts_this_interpreter(self):
        got, asked = self.spelled(self.EXE, {"py": r"C:\Windows\py.exe"}, True)
        self.assertEqual(got, "py -m ranwhat")
        asked.assert_called_once_with(r"C:\Windows\py.exe", self.EXE)

    def test_never_a_quoted_first_word(self):
        store = r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\python3.exe"
        for on_path, starts in (({}, True),
                                ({"py": r"C:\Windows\py.exe"}, False),
                                ({"python3": store}, True)):
            with self.subTest(on_path=on_path):
                got, asked = self.spelled(self.EXE, on_path, starts)
                self.assertEqual(got, "uvx ranwhat")
                # Python's own names may be the Store's alias, which opens
                # the Store when it is run: only py is ever asked.
                for call in asked.call_args_list:
                    self.assertTrue(call[0][0].endswith("py.exe"), call)
        got, _ = self.spelled(r"C:\Python313\python.exe", {}, False)
        self.assertEqual(got, r"C:\Python313\python.exe -m ranwhat")


class _Tty(io.StringIO):
    def isatty(self):
        return True

    def fileno(self):
        return 1


class _Console(object):
    """kernel32's console calls, for a console in `mode`, that takes a new
    one when `takes`."""

    def __init__(self, mode, takes):
        self.mode, self.takes, self.set = mode, takes, []

    def GetConsoleMode(self, handle, ref):
        ref._obj.value = self.mode
        return 1

    def SetConsoleMode(self, handle, mode):
        self.set.append(mode)
        return 1 if self.takes else 0


class AClassicWindowsConsoleGetsNoEscapes(unittest.TestCase):
    """cmd and Windows PowerShell 5.1 in a classic conhost window show an
    escape as ←[1m unless it is turned on, and nothing turned it on: every
    report there was strewn with them, and the progress line never
    erased."""

    def on_windows(self, console):
        import ctypes
        windll = mock.Mock()
        windll.kernel32 = console
        return [mock.patch.object(term.os, "name", "nt"),
                mock.patch.dict(os.environ, {}, clear=False),
                mock.patch.object(ctypes, "windll", windll, create=True),
                mock.patch.dict(sys.modules, {"msvcrt": mock.Mock(
                    get_osfhandle=lambda fd: 7)})]

    def test_a_console_that_takes_escapes_gets_colour(self):
        console = _Console(mode=3, takes=True)
        with contextlib.ExitStack() as stack:
            for patch in self.on_windows(console):
                stack.enter_context(patch)
            for name in ("NO_COLOR", "TERM", "COLORTERM"):
                os.environ.pop(name, None)
            self.assertEqual(term._colour_depth(_Tty()), 8)
            self.assertTrue(term.Progress(_Tty()).enabled)
        self.assertEqual(console.set[0], 3 | 4)

    def test_one_that_does_not_gets_plain_text(self):
        for console in (_Console(mode=3, takes=False), None):
            with self.subTest(console=console), contextlib.ExitStack() as stack:
                for patch in self.on_windows(console):
                    stack.enter_context(patch)
                for name in ("NO_COLOR", "TERM", "COLORTERM"):
                    os.environ.pop(name, None)
                self.assertEqual(term._colour_depth(_Tty()), 0)
                self.assertEqual(term.paint("1", "x", _Tty()), "x")
                self.assertFalse(term.Progress(_Tty()).enabled)


class AFileThatCannotBeOpenedIsNamed(unittest.TestCase):
    """Windows gives EINVAL for a name holding ? * < > |, as it does for a
    write to a pipe whose reader has gone, and main() took every EINVAL for
    the pipe: `scan profile?.json` exited 1 and said nothing at all."""

    def test_only_an_error_naming_no_file_is_the_pipe(self):
        self.assertTrue(cli._closed_pipe(
            OSError(errno.EINVAL, "Invalid argument"), windows=True))
        self.assertFalse(cli._closed_pipe(
            OSError(errno.EINVAL, "Invalid argument", "profile?.json"),
            windows=True))

    def test_scan_says_which_file_and_why(self):
        bad = OSError(errno.EINVAL, "Invalid argument", "profile?.json")
        with mock.patch.object(cli, "open", side_effect=bad, create=True), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                cli.main(["scan", "profile?.json"])
        self.assertEqual(stopped.exception.code,
                         "ranwhat: cannot read profile?.json (Invalid argument)")


class LiveNamesTheVersionThatIsRunning(unittest.TestCase):
    """live and --pull-usage told every provider they asked that this was
    ranwhat/0.1, whatever version it was."""

    def test_the_user_agent_is_this_version(self):
        import urllib.error
        import ranwhat
        from ranwhat import introspect
        sent = []

        def offline(req, *a, **kw):
            sent.append(req.get_header("User-agent"))
            raise urllib.error.URLError("offline")

        with mock.patch("urllib.request.urlopen", offline):
            with self.assertRaises(introspect.IntrospectionError):
                introspect.github("ghp_" "FAKEFAKEFAKE1234")
        self.assertEqual(sent, ["ranwhat/%s (read-only introspection)" % ranwhat.__version__])


class NoEmDashes(unittest.TestCase):
    """The site's rule (tests/test_site_claims.py) holds for the terminal
    too. The rotation advice in `clean`'s review had sixteen. Every string
    literal in the package is read, docstrings included, since argparse
    prints some of them."""

    def test_no_string_in_the_package_has_one(self):
        pkg = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "ranwhat")
        names = sorted(n for n in os.listdir(pkg) if n.endswith(".py"))
        self.assertIn("clean.py", names)
        for name in names:
            with open(os.path.join(pkg, name), encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), name)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn("\u2014", node.value,
                                     "%s:%d" % (name, node.lineno))


if __name__ == "__main__":
    unittest.main(verbosity=2)
