"""ranwhat revoke, and revoke N in clean's review.

Both change something real: a settings file, or a token that stops working
everywhere. So most of these are about what must not happen: a change made
without --apply or without a yes, a file rewritten with no copy kept, a
token sent to anyone but its issuer, or a token quoted in a message.
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import isolated_home  # noqa: E402,F401  ranwhat's state, never ~/.ranwhat
from ranwhat import clean, cli, revoke  # noqa: E402

# Split, so push protection never sees a whole token-shaped literal.
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
SLACK = "xox" + "b-1234567890-abcdefABCDEF"
GOOGLE = "ya29" + ".a0AfH6SMBexample-token_value"
STRIPE = "sk_" + "live_" + "51Hexample0000000000000000"


class Rules(unittest.TestCase):

    def test_risky_allow_rules(self):
        for rule in ("Bash", "Bash(*)", "Bash(curl:*)", "Bash(curl *)",
                     "Bash(rm -rf:*)", "Bash(git push:*)", "Bash(npm publish)",
                     "Read(~/.ssh/**)", "Read(./.env)", "Edit(**/.aws/credentials)",
                     "Write(*)"):
            self.assertTrue(revoke._risky_rule(rule), rule)

    def test_ordinary_allow_rules_stay(self):
        for rule in ("Bash(npm test:*)", "Bash(git status)", "Bash(ls:*)",
                     "Bash(git diff:*)", "Read(./src/**)", "Edit(./src/**)",
                     "WebFetch(domain:docs.python.org)", "mcp__github__get_issue",
                     "Bash(gitk)", 5, None):
            self.assertIsNone(revoke._risky_rule(rule), rule)


class Settings(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "settings.json")
        self.settings = {
            "permissions": {"defaultMode": "bypassPermissions",
                            "allow": ["Bash(npm test:*)", "Bash(curl:*)",
                                      "Read(~/.ssh/**)"],
                            "deny": ["Read(./.env)"]},
            "enableAllProjectMcpServers": True,
            "model": "opus",
        }
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.settings, fh)

    def read(self):
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def test_plan_lists_and_changes_nothing(self):
        whats = [i["what"] for i in revoke.plan(self.path)]
        self.assertIn('permissions.defaultMode "bypassPermissions"', whats)
        self.assertIn("allow Bash(curl:*)", whats)
        self.assertIn("allow Read(~/.ssh/**)", whats)
        self.assertIn("enableAllProjectMcpServers true", whats)
        self.assertNotIn("allow Bash(npm test:*)", whats)
        self.assertEqual(self.read(), self.settings)

    def test_apply_takes_back_only_those_and_keeps_a_copy(self):
        backup = revoke.apply(self.path, revoke.plan(self.path))
        after = self.read()
        self.assertNotIn("defaultMode", after["permissions"])
        self.assertEqual(after["permissions"]["allow"], ["Bash(npm test:*)"])
        self.assertEqual(after["permissions"]["deny"], ["Read(./.env)"])
        self.assertIs(after["enableAllProjectMcpServers"], False)
        self.assertEqual(after["model"], "opus")
        with open(backup, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), self.settings)

    def test_apply_with_nothing_writes_nothing(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"permissions": {"allow": ["Bash(ls:*)"]}}, fh)
        self.assertIsNone(revoke.apply(self.path, revoke.plan(self.path)))
        self.assertFalse(os.path.exists(self.path + revoke.BACKUP_SUFFIX))

    def test_broken_json_is_reported_not_rewritten(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        entries = revoke.local(("user",), env={"CLAUDE_CONFIG_DIR": self.dir})
        self.assertIn("not valid JSON", entries[0]["error"])


class Cli(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.user = os.path.join(self.dir, "settings.json")
        with open(self.user, "w", encoding="utf-8") as fh:
            json.dump({"permissions": {"allow": ["Bash(curl:*)"]}}, fh)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": self.dir}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli._main(argv)
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_without_apply_nothing_changes(self):
        code, out, _ = self.run_cli(["revoke", "--scope", "user"])
        self.assertEqual(code, 0)
        self.assertIn("Bash(curl:*)", out)
        self.assertIn("Nothing was changed", " ".join(out.split()))
        with open(self.user, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["permissions"]["allow"], ["Bash(curl:*)"])

    def test_apply_changes_it(self):
        code, out, _ = self.run_cli(["revoke", "--scope", "user", "--apply", "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["applied"])
        with open(self.user, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["permissions"]["allow"], [])

    def test_other_commands_flags_are_refused(self):
        code, _, err = self.run_cli(["revoke", "--days", "5"])
        self.assertEqual(code, 2)
        self.assertIn("revoke takes only", err)

    def test_mode_is_still_only_for_hook(self):
        code, _, _ = self.run_cli(["revoke", "--mode", "deny"])
        self.assertEqual(code, 2)


class Provider(unittest.TestCase):

    def fake(self, status, text=""):
        sent = []

        def post(url, body, headers):
            sent.append((url, body, headers))
            return status, text
        return post, sent

    def test_which_provider(self):
        self.assertEqual(revoke.provider_for(GH), "github")
        self.assertEqual(revoke.provider_for(SLACK), "slack")
        self.assertEqual(revoke.provider_for(GOOGLE), "google")
        self.assertIsNone(revoke.provider_for(STRIPE))
        self.assertIsNone(revoke.provider_for(""))

    def test_github_unauthenticated_json_202(self):
        post, sent = self.fake(202)
        self.assertEqual(revoke.revoke_token(GH, post=post), "GitHub")
        url, body, headers = sent[0]
        self.assertEqual(url, "https://api.github.com/credentials/revoke")
        self.assertEqual(json.loads(body), {"credentials": [GH]})
        self.assertNotIn("Authorization", headers)

    def test_github_anything_but_202_is_an_error_without_the_token(self):
        post, _ = self.fake(422)
        with self.assertRaises(revoke.RevokeError) as e:
            revoke.revoke_token(GH, post=post)
        self.assertNotIn(GH, str(e.exception))

    def test_slack_needs_ok(self):
        post, sent = self.fake(200, '{"ok": true, "revoked": true}')
        self.assertEqual(revoke.revoke_token(SLACK, post=post), "Slack")
        self.assertEqual(sent[0][0], "https://slack.com/api/auth.revoke")
        self.assertEqual(sent[0][2]["Authorization"], "Bearer " + SLACK)
        post, _ = self.fake(200, '{"ok": false, "error": "invalid_auth"}')
        with self.assertRaises(revoke.RevokeError) as e:
            revoke.revoke_token(SLACK, post=post)
        self.assertIn("invalid_auth", str(e.exception))

    def test_google(self):
        post, sent = self.fake(200)
        self.assertEqual(revoke.revoke_token(GOOGLE, post=post), "Google")
        self.assertEqual(sent[0][0], "https://oauth2.googleapis.com/revoke")

    def test_each_token_goes_to_its_own_issuer_only(self):
        for token, host in ((GH, "api.github.com"), (SLACK, "slack.com"),
                            (GOOGLE, "oauth2.googleapis.com")):
            post, sent = self.fake(202 if token == GH else 200, '{"ok": true}')
            revoke.revoke_token(token, post=post)
            self.assertEqual(len(sent), 1)
            self.assertIn("//%s/" % host, sent[0][0])

    def test_unsupported_is_never_sent(self):
        post, sent = self.fake(200)
        with self.assertRaises(revoke.RevokeError):
            revoke.revoke_token(STRIPE, post=post)
        self.assertEqual(sent, [])


def _finding(n, label, hint):
    return {"fingerprint": "%012x" % n, "label": label, "length": 40,
            "hint": hint, "files": {"/x/s.jsonl"}, "origins": set(),
            "projects": {"/p"}, "count": 1}


class Review(unittest.TestCase):

    def setUp(self):
        self.findings = {f["fingerprint"]: f for f in (
            _finding(1, "GitHub personal access token", "ghp_...r8"),
            _finding(2, "Stripe secret key", "sk_...00"))}
        self.values = {"%012x" % 1: GH, "%012x" % 2: STRIPE}

    def review(self, *commands):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"RANWHAT_WIDTH": "120"}), \
                mock.patch("builtins.input",
                           side_effect=list(commands) + [EOFError()]):
            clean.review(self.findings, 1, stream=out, values=self.values)
        return out.getvalue()

    def test_yes_revokes(self):
        with mock.patch.object(revoke, "revoke_token", return_value="GitHub") as r:
            text = self.review("revoke 1", "yes")
        r.assert_called_once_with(GH)
        self.assertIn("Revoked at GitHub", text)
        self.assertIn("tells the token's owner", " ".join(text.split()))
        self.assertNotIn(GH, text)

    def test_anything_but_yes_does_not(self):
        with mock.patch.object(revoke, "revoke_token") as r:
            text = self.review("revoke 1", "y")
        r.assert_not_called()
        self.assertIn("Not revoked", text)

    def test_unsupported_points_at_open(self):
        with mock.patch.object(revoke, "revoke_token") as r:
            text = self.review("revoke 2")
        r.assert_not_called()
        self.assertIn("open 2", text)

    def test_a_provider_refusal_is_said(self):
        with mock.patch.object(revoke, "revoke_token",
                               side_effect=revoke.RevokeError("GitHub answered 422")):
            text = self.review("revoke 1", "yes")
        self.assertIn("Not revoked: GitHub answered 422", text)

    def test_no_value_in_hand(self):
        self.values = {}
        with mock.patch.object(revoke, "revoke_token") as r:
            text = self.review("revoke 1")
        r.assert_not_called()
        self.assertIn("does not have this value", text)


if __name__ == "__main__":
    unittest.main()
