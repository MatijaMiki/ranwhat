"""What `scan`, `live` and `demo` print.

The unused-scope list was sorted by the authority *string*, so "write" came
before "financial" and "destructive" and the ten-row cut dropped exactly the
scopes that can move money or destroy data. Finding bodies were folded at a
fixed 72 columns with a space left on the end of every line, whatever the
terminal. And the footer said no credential left the machine on the one
command that sends each token to its provider.

Every profile here is the bundled demo or synthetic.
"""
import contextlib
import io
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import cli, report, term
from ranwhat.catalog import AUTHORITY_RANK, DESTRUCTIVE, FINANCIAL

ANSI = re.compile(r"\033\[[0-9;]*m")


def demo():
    return cli.run_scan(cli._bundled("support-copilot.json"))


def at(width, result=None, **kw):
    with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(width)}):
        return ANSI.sub("", report.render(result or demo(), **kw))


def unused_section(text):
    lines = text.split("\n")
    start = lines.index("  Granted but never exercised") + 1
    end = lines.index("", start)
    return lines[start:end]


class MostDangerousUnusedFirst(unittest.TestCase):

    def test_financial_and_destructive_survive_the_cut(self):
        result = demo()
        dangerous = [r["scope"] for r in result["scopes"]
                     if r["usage"] == "unused"
                     and r["authority"] in (FINANCIAL, DESTRUCTIVE)]
        self.assertIn("charges:write", dangerous)
        self.assertIn("transfers:write", dangerous)
        self.assertGreater(result["counts"]["unused"], 10)
        section = "\n".join(unused_section(at(96, result)))
        for scope in dangerous:
            self.assertIn(scope, section)

    def test_rows_run_from_most_to_least_dangerous(self):
        result = demo()
        by_scope = {r["scope"]: r for r in result["scopes"]}
        shown = [l.split()[1] for l in unused_section(at(96, result))
                 if not l.startswith("     ") and not l.strip().startswith("…")]
        ranks = [(AUTHORITY_RANK[by_scope[s]["authority"]],
                  not by_scope[s]["reversible"]) for s in shown]
        self.assertEqual(ranks, sorted(ranks, reverse=True), shown)
        self.assertEqual(by_scope[shown[0]]["authority"], DESTRUCTIVE)

    def test_the_cut_says_how_many_were_left_out(self):
        result = demo()
        section = unused_section(at(96, result))
        self.assertEqual(section[-1].strip(),
                         "… and %d more" % (result["counts"]["unused"] - 10))


class FitsTheTerminal(unittest.TestCase):

    def results(self):
        live = demo()
        live["verdict"] = {"status": "IMPAIRED",
                           "headline": "Priceable, but expect loaded pricing",
                           "composite": 55, "grade": "C", "detail": ""}
        return [demo(), cli.run_scan(cli._bundled("well-configured.json")), live]

    def test_no_line_ends_in_whitespace(self):
        for width in (50, 60, 80, 96):
            for result in self.results():
                for line in at(width, result).split("\n"):
                    self.assertEqual(line, line.rstrip(), (width, line))

    def test_no_line_is_wider_than_the_report(self):
        # The report's own measure, the one its rules are drawn to.
        for width in (46, 50, 60, 80, 96):
            with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": str(width)}):
                limit = term.width()
            for result in self.results():
                for line in at(width, result).split("\n"):
                    self.assertLessEqual(len(line), limit, (width, line))

    def test_a_cut_scope_keeps_the_end_that_names_it(self):
        section = "\n".join(unused_section(at(50)))
        self.assertIn("…", section)
        self.assertIn("auth/drive\n", section)
        self.assertIn("auth/calendar\n", section)

    def test_finding_bodies_are_wrapped_not_lost(self):
        result = demo()
        text = at(50, result)
        folded = " ".join(text.split())
        for f in result["findings"]:
            self.assertIn(" ".join(f["body"].split()), folded, f["title"])
            self.assertIn(" ".join(f["title"].split()), folded)

    def test_a_wider_terminal_uses_fewer_lines(self):
        self.assertLess(len(at(96).split("\n")), len(at(50).split("\n")))


class Footer(unittest.TestCase):

    def test_offline_footer_is_the_shared_one(self):
        lines = at(80).split("\n")
        self.assertEqual(lines.count(term.FOOTER), 1)
        self.assertEqual(lines[-2:], [term.FOOTER, ""])

    def test_live_does_not_claim_nothing_left(self):
        text = at(80, online=True)
        self.assertNotIn(term.FOOTER, text)
        self.assertNotIn("left this machine", text)
        self.assertIn("provider", text.split("\n")[-2])

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(argv)
        return rc, out.getvalue()

    def test_demo_and_scan_say_nothing_was_transmitted(self):
        rc, out = self.run_cli(["demo"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.split("\n").count(term.FOOTER), 1)

    def test_live_says_where_the_token_went(self):
        cred = {"provider": "github", "label": "synthetic",
                "scopes": ["repo"], "scopes_used": None}
        with mock.patch.dict(cli.introspect.PROVIDERS,
                             {"github": lambda token: cred}, clear=True), \
             mock.patch.dict(os.environ, {"RANWHAT_GITHUB_TOKEN": "synthetic"}):
            rc, out = self.run_cli(["live"])
        self.assertEqual(rc, 0)
        self.assertNotIn(term.FOOTER, out.split("\n"))
        self.assertIn("provider", out.rstrip("\n").split("\n")[-1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
