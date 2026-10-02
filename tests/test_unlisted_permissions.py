"""A credential whose provider will not say what it may do.

introspect returned a note for a fine-grained GitHub token and a restricted
Stripe key, each with no scopes, and nothing read the note: score added no
rows for either, so `live` scored them as tokens that may do nothing and
printed no finding. The Stripe note also told people to pass --scopes, a
flag the CLI has never had.

Every token here is synthetic and every provider call is mocked.
"""
import contextlib
import email.message
import io
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat import cli, html_report, introspect, report, score

ANSI = re.compile(r"\033\[[0-9;]*m")

FINE_GRAINED = "github_pat_" + "S" * 30
CLASSIC = "ghp_" + "S" * 36
RESTRICTED = "rk_test_" + "S" * 24
SECRET = "sk_test_" + "S" * 24


def github_answering(response_headers):
    def request(url, **kw):
        return 200, response_headers, json.dumps({"login": "octo-synthetic"})
    return mock.patch.object(introspect, "_request", request)


def unlisted(result):
    return [f for f in result["findings"]
            if f["title"].startswith("Permissions could not be listed")]


def folded(text):
    return " ".join(ANSI.sub("", text).split())


class IntrospectSaysWhenItCannotList(unittest.TestCase):

    def test_fine_grained_github_token(self):
        with github_answering({"x-oauth-scopes": ""}):
            cred = introspect.github(FINE_GRAINED)
        self.assertEqual(cred["scopes"], [])
        self.assertIs(cred["scopes_known"], False)
        self.assertIn("Fine-grained", cred["note"])

    def test_classic_token_with_no_scope_is_known_to_have_none(self):
        """An empty header on a classic token means no scope was chosen."""
        with github_answering({"x-oauth-scopes": ""}):
            cred = introspect.github(CLASSIC)
        self.assertEqual(cred["scopes"], [])
        self.assertTrue(cred.get("scopes_known", True))
        self.assertNotIn("note", cred)

    def test_classic_token_without_the_header_is_not_known(self):
        with github_answering({}):
            cred = introspect.github(CLASSIC)
        self.assertIs(cred["scopes_known"], False)

    def test_classic_scopes_are_listed(self):
        with github_answering({"x-oauth-scopes": "repo, delete_repo"}):
            cred = introspect.github(CLASSIC)
        self.assertEqual(cred["scopes"], ["repo", "delete_repo"])
        self.assertTrue(cred.get("scopes_known", True))

    def test_header_names_are_read_whatever_their_case(self):
        """dict(resp.headers) kept the case the server sent, so a lower-case
        x-oauth-scopes read as absent and every classic token as empty."""
        msg = email.message.Message()
        msg["x-oauth-scopes"] = "repo"

        class Response(object):
            status = 200
            headers = msg

            def read(self):
                return b'{"login": "octo-synthetic"}'

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with mock.patch.object(introspect.urllib.request, "urlopen",
                               lambda req, timeout=None: Response()):
            self.assertEqual(introspect.github(CLASSIC)["scopes"], ["repo"])

    def test_restricted_stripe_key(self):
        cred = introspect.stripe(RESTRICTED)
        self.assertEqual(cred["scopes"], [])
        self.assertIs(cred["scopes_known"], False)
        self.assertIn("Dashboard", cred["note"])

    def test_unrestricted_stripe_key_is_known(self):
        cred = introspect.stripe(SECRET)
        self.assertEqual(cred["scopes"], ["all"])
        self.assertTrue(cred.get("scopes_known", True))

    def test_no_note_names_a_flag_the_cli_does_not_have(self):
        with github_answering({"x-oauth-scopes": ""}):
            notes = [introspect.github(FINE_GRAINED)["note"],
                     introspect.github("ghu_" + "S" * 36)["note"]]
        notes.append(introspect.stripe(RESTRICTED)["note"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["--help"])
        for note in notes:
            self.assertNotIn("--scopes", note)
            for flag in re.findall(r"--[a-z][\w-]*", note):
                self.assertIn(flag, out.getvalue(), note)


class TheReportSaysSo(unittest.TestCase):

    def profile(self, **cred):
        base = {"provider": "github", "label": "octo-synthetic", "scopes": [],
                "scopes_known": False, "note": "Fine-grained token. Synthetic."}
        base.update(cred)
        return {"agent": "synthetic", "credentials": [base],
                "controls": {"trace_retention_days": 400,
                             "tool_call_attributes": True,
                             "human_approval": "all", "kill_switch": True,
                             "spend_cap_usd": 50}}

    def test_a_finding_carries_the_note(self):
        found = unlisted(score.scan(self.profile()))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "high")
        self.assertIn("octo-synthetic (github)", found[0]["title"])
        self.assertIn("Fine-grained token. Synthetic.", found[0]["body"])
        self.assertIn("profile", found[0]["body"])

    def test_without_it_the_report_was_empty(self):
        """What live printed before: a clean bill and no finding."""
        result = score.scan(self.profile())
        others = [f for f in result["findings"] if f not in unlisted(result)]
        self.assertEqual(others, [])
        self.assertEqual(result["counts"]["total"], 0)

    def test_a_note_is_not_needed_for_the_finding(self):
        found = unlisted(score.scan(self.profile(note=None)))
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0]["body"].startswith("The scores"))

    def test_declared_scopes_answer_it(self):
        self.assertEqual(unlisted(score.scan(self.profile(scopes=["repo"]))), [])

    def test_a_credential_known_to_hold_nothing_is_not_flagged(self):
        profile = self.profile()
        del profile["credentials"][0]["scopes_known"]
        self.assertEqual(unlisted(score.scan(profile)), [])
        for known in (True, None):
            self.assertEqual(
                unlisted(score.scan(self.profile(scopes_known=known))), [])

    def test_shapes_are_checked(self):
        for bad in ({"scopes_known": "no"}, {"scopes_known": 0},
                    {"note": ["x"]}):
            with self.subTest(bad=bad):
                with self.assertRaises(score.ProfileError):
                    score.scan(self.profile(**bad))

    def test_findings_stay_most_severe_first(self):
        profile = self.profile()
        profile["controls"] = {}
        profile["credentials"].append(
            {"provider": "github", "label": "other", "scopes": ["made_up:thing"]})
        order = [score._SEVERITY_ORDER[f["severity"]]
                 for f in score.scan(profile)["findings"]]
        self.assertEqual(order, sorted(order))

    def test_terminal_json_and_html(self):
        result = score.scan(self.profile())
        with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "80"}):
            text = folded(report.render(result))
        self.assertIn("Permissions could not be listed for octo-synthetic "
                      "(github)", text)
        self.assertIn("Fine-grained token. Synthetic.", text)
        self.assertIn("Fine-grained token. Synthetic.",
                      json.dumps(result))
        page = html_report.build_html(result)
        self.assertIn("Permissions could not be listed for octo-synthetic "
                      "(github)", page)
        self.assertIn("Fine-grained token. Synthetic.", page)


class LiveEndToEnd(unittest.TestCase):

    def run_live(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        env = {"RANWHAT_GITHUB_TOKEN": FINE_GRAINED,
               "RANWHAT_STRIPE_TOKEN": RESTRICTED, "RANWHAT_WIDTH": "80"}
        with github_answering({"x-oauth-scopes": ""}), \
             mock.patch.dict(os.environ, env), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["live"] + list(extra))
        return rc, out.getvalue()

    def test_live_prints_both(self):
        rc, out = self.run_live()
        self.assertEqual(rc, 0)
        text = folded(out)
        self.assertIn("could not be listed for octo-synthetic (github)", text)
        self.assertIn("could not be listed for stripe-restricted-key (stripe)",
                      text)
        self.assertIn("Fine-grained token.", text)
        self.assertIn("Restricted key.", text)
        self.assertNotIn("--scopes", text)
        for token in (FINE_GRAINED, RESTRICTED):
            self.assertNotIn(token, out)

    def test_live_json(self):
        rc, out = self.run_live("--json")
        self.assertEqual(rc, 0)
        titles = [f["title"] for f in unlisted(json.loads(out))]
        self.assertEqual(len(titles), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
