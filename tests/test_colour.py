"""Colour is one decision, made in term, and NO_COLOR turns all of it off.

report._c asked only whether stdout was a terminal, so NO_COLOR and
TERM=dumb reached the wordmark and nothing else: on a terminal with
NO_COLOR=1, demo still printed about two hundred escape codes and check
about six hundred. Every colour now asks term.colour(), which honours
NO_COLOR set to anything but the empty string (no-color.org), TERM=dumb,
and a stream that is not a terminal.

Every value here is synthetic.
"""
# Token-shaped fixtures are written as adjacent literals, as in
# tests/test_fixtures.py, so a secret scanner reading this source does not
# take one for a leak.
import builtins
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import clean, cli, term

DAY = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
STRIPE = "STRIPE=sk_" "live_" "4eC39HqLyjWDarjtT1zdp7dc"


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


def make_root():
    root = tempfile.mkdtemp(prefix="colour-t-")
    proj = os.path.join(root, "-tmp-synthetic-proj")
    os.makedirs(proj)
    rows = [
        {"timestamp": DAY + "T10:01:00Z", "message": {
            "role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "rm -rf ~/Documents/archive"}}]}},
        {"timestamp": DAY + "T10:02:30Z", "message": {
            "role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1",
                 "content": STRIPE + "\n"}]}}]
    with open(os.path.join(proj, "s1.jsonl"), "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return root, tempfile.mkdtemp(prefix="colour-oc-")


class NoColor(unittest.TestCase):

    def setUp(self):
        root, st = make_root()
        where = ["--root", root, "--state-dir", st]
        self.commands = {
            "demo": ["demo"],
            "check": ["check"] + where,
            "watch": ["watch"] + where,
            "clean": ["clean", "--no-interactive"] + where,
        }

    def run_on_a_terminal(self, argv, **env):
        base = {"TERM": "xterm-256color", "RANWHAT_WIDTH": "80"}
        base.update(env)
        out = FakeTTY()
        with mock.patch.dict(os.environ, base), \
             contextlib.redirect_stdout(out), \
             contextlib.redirect_stderr(io.StringIO()), \
             mock.patch("sys.stdin", io.StringIO()):
            for name in ("NO_COLOR", "COLORTERM"):
                if name not in env:
                    os.environ.pop(name, None)
            try:
                cli.main(argv)
            except SystemExit:
                pass
        return out.getvalue()

    def test_a_terminal_gets_colour(self):
        # Without this, "no escapes" below could pass on a stream that
        # never engaged colour at all.
        for name, argv in self.commands.items():
            self.assertIn("\033[", self.run_on_a_terminal(argv), name)

    def test_no_color_turns_off_every_escape(self):
        for name, argv in self.commands.items():
            out = self.run_on_a_terminal(argv, NO_COLOR="1")
            self.assertNotIn("\033", out, name)
            self.assertIn("ranwhat", out, name)

    def test_any_non_empty_value_counts(self):
        out = self.run_on_a_terminal(self.commands["demo"], NO_COLOR="0")
        self.assertNotIn("\033", out)

    def test_an_empty_no_color_is_not_set(self):
        out = self.run_on_a_terminal(self.commands["demo"], NO_COLOR="")
        self.assertIn("\033[", out)

    def test_dumb_terminal(self):
        for name, argv in self.commands.items():
            out = self.run_on_a_terminal(argv, TERM="dumb")
            self.assertNotIn("\033", out, name)

    def test_the_review_session_too(self):
        root, _ = make_root()
        findings, scanned, _ = clean.scan(root=root)
        self.assertEqual(len(findings), 1)
        out = FakeTTY()
        with mock.patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": "1"}), \
             contextlib.redirect_stdout(out), \
             mock.patch.object(builtins, "input",
                               side_effect=["list", "rotate", EOFError]):
            clean.review(findings, scanned)
        self.assertIn("Stripe", out.getvalue())
        self.assertNotIn("\033", out.getvalue())


class OneDecision(unittest.TestCase):

    def colour(self, stream, **env):
        with mock.patch.dict(os.environ, env):
            for name in ("NO_COLOR", "TERM"):
                if name not in env:
                    os.environ.pop(name, None)
            return term.colour(stream), term.paint("1", "x", stream)

    def test_terminal(self):
        self.assertEqual(self.colour(FakeTTY(), TERM="xterm"),
                         (True, "\033[1mx\033[0m"))

    def test_off(self):
        for stream, env in ((io.StringIO(), {"TERM": "xterm"}),
                            (FakeTTY(), {"TERM": "xterm", "NO_COLOR": "1"}),
                            (FakeTTY(), {"TERM": "dumb"})):
            self.assertEqual(self.colour(stream, **env), (False, "x"), env)

    def test_a_closed_stream_is_not_a_terminal(self):
        class Closed(io.StringIO):
            def isatty(self):
                raise ValueError("I/O operation on closed file")
        self.assertEqual(self.colour(Closed(), TERM="xterm"), (False, "x"))

    def test_report_colours_ask_it(self):
        from ranwhat import report
        out = FakeTTY()
        with mock.patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": "1"}), \
             contextlib.redirect_stdout(out):
            self.assertEqual(report.BOLD("x"), "x")
            self.assertEqual(report.RED("x"), "x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
