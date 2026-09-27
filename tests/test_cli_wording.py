"""What the CLI says about itself.

The overview said nothing is transmitted and `update` claimed to be the only
command that touches the network, while `live` and --pull-usage send each
token to its provider. --days and --root were documented as watch-only while
also driving check and clean. A finding told the reader to "Run
--pull-usage", which is a flag, not a command.
"""
import contextlib
import io
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import cli, score, term

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

    def test_names_a_command_the_reader_can_run(self):
        with mock.patch.object(cli, "invocation", return_value="uvx ranwhat"):
            body = self.self_attested(score.scan(self.profile()))["body"]
        self.assertIn("uvx ranwhat scan <profile> --pull-usage", body)
        self.assertNotIn("Run --pull-usage", body)

    def test_uses_the_path_that_was_scanned(self):
        with mock.patch.object(cli, "invocation", return_value="ranwhat"):
            body = self.self_attested(
                score.scan(self.profile(), path="my agent.json"))["body"]
        self.assertIn("ranwhat scan 'my agent.json' --pull-usage", body)

    def test_scan_command_passes_its_path(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(self.profile(), fh)
        self.addCleanup(os.unlink, fh.name)
        out = io.StringIO()
        with mock.patch.object(cli, "invocation", return_value="ranwhat"), \
             contextlib.redirect_stdout(out):
            cli.main(["scan", fh.name, "--json"])
        body = self.self_attested(json.loads(out.getvalue()))["body"]
        self.assertIn("ranwhat scan %s --pull-usage" % fh.name, body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
